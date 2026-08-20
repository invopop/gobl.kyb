package repos

import (
	"context"
	"errors"
	"fmt"
	"time"

	kivik "github.com/go-kivik/kivik/v4"
	"github.com/invopop/couch"
	"github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// Verifications is the case store, backed by a single CouchDB database
// (the couch client's prefix) holding four document families:
//
//	verification:<address>       the live case
//	attempt:<address>:<seq>      superseded attempts, kept for the
//	                             cost and decline history
//	event:<event_id>             the callback idempotency ledger
//	decision:<session_id>        raw provider verdicts, purged on
//	                             their own retention schedule
//
// Two views back the lookups the pipeline needs: by_token for the
// status page, and by_poll for the reconciler's sweep of cases still
// waiting on the provider.
type Verifications struct {
	db *kivik.DB
}

const (
	designName  = "verifications"
	designDocID = "_design/verifications"
	viewByToken = "by_token"
	viewByPoll  = "by_poll"
)

// NewVerifications opens (creating if needed) the database on the
// provided couch client, syncs the design document, and returns a
// ready-to-use store.
func NewVerifications(ctx context.Context, client *couch.Client) (*Verifications, error) {
	if client == nil {
		return nil, errors.New("repos: couch client is required")
	}
	db := client.DB("") // single database, named by the client's prefix
	if err := client.Create(ctx, db); err != nil {
		return nil, fmt.Errorf("repos: create database: %w", err)
	}
	if err := client.SyncDesigns(ctx, db, []*couch.Design{verificationsDesign()}); err != nil {
		return nil, fmt.Errorf("repos: sync designs: %w", err)
	}
	return &Verifications{db: db}, nil
}

// Close releases the underlying CouchDB connection.
func (r *Verifications) Close() error {
	if r.db == nil {
		return nil
	}
	return r.db.Close()
}

// verificationsDesign builds the design document behind the lookups.
func verificationsDesign() *couch.Design {
	d := couch.NewDesign(designName)
	d.SetView(viewByToken, &couch.View{
		Map: `function(doc) {
			if (doc._id.indexOf("verification:") === 0 && doc.token) {
				emit(doc.token, null);
			}
		}`,
	})
	// Cases still waiting on the provider, keyed by when they are next
	// due a poll. A missing next_poll_at sorts first: a case that has
	// never been scheduled is overdue by definition.
	d.SetView(viewByPoll, &couch.View{
		Map: `function(doc) {
			if (doc._id.indexOf("verification:") !== 0) { return; }
			var open = {
				received: true, awaiting_payment: true, session_open: true,
				in_review: true, matching: true, approved: true,
				delivery_failed: true
			};
			if (open[doc.status]) {
				emit(doc.next_poll_at || "", null);
			}
		}`,
	})
	return d
}

// Put creates or updates the case. On a revision conflict it returns
// ErrConflict so the caller can re-Get and retry.
func (r *Verifications) Put(ctx context.Context, v *models.Verification) error {
	if err := v.Validate(); err != nil {
		return err
	}
	if err := couch.Store(ctx, r.db, v); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			return ErrConflict
		}
		return fmt.Errorf("repos: store verification: %w", err)
	}
	return nil
}

// Get returns the case for an address or ErrNotFound.
func (r *Verifications) Get(ctx context.Context, address net.Address) (*models.Verification, error) {
	v := new(models.Verification)
	v.ID = models.VerificationDocID(address)
	if err := couch.Fetch(ctx, r.db, v); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repos: fetch verification: %w", err)
	}
	return v, nil
}

// GetByToken returns the case whose status token matches, or
// ErrNotFound.
func (r *Verifications) GetByToken(ctx context.Context, token string) (*models.Verification, error) {
	rows := r.db.Query(ctx, designDocID, viewByToken, kivik.Params(map[string]any{
		"key":          token,
		"include_docs": true,
		"limit":        1,
	}))
	defer rows.Close() //nolint:errcheck
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("repos: couchdb view: %w", err)
		}
		return nil, ErrNotFound
	}
	v := new(models.Verification)
	if err := rows.ScanDoc(v); err != nil {
		return nil, fmt.Errorf("repos: couchdb view scan: %w", err)
	}
	return v, nil
}

// DuePolling returns up to limit non-terminal cases whose next poll is
// due at or before now, oldest first. It is the reconciler's work
// queue — the net under a callback the provider gave up retrying.
func (r *Verifications) DuePolling(ctx context.Context, now time.Time, limit int) ([]*models.Verification, error) {
	rows := r.db.Query(ctx, designDocID, viewByPoll, kivik.Params(map[string]any{
		"endkey":       now.UTC().Format(time.RFC3339Nano),
		"include_docs": true,
		"limit":        limit,
	}))
	defer rows.Close() //nolint:errcheck
	var out []*models.Verification
	for rows.Next() {
		v := new(models.Verification)
		if err := rows.ScanDoc(v); err != nil {
			return nil, fmt.Errorf("repos: couchdb view scan: %w", err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("repos: couchdb view: %w", err)
	}
	return out, nil
}

// ClaimEvent records a provider callback, returning ErrConflict when
// the event has already been seen.
//
// This is the whole idempotency mechanism. Callbacks are retried and
// arrive out of order, and a create-only write on the event ID is a
// cheap, exact, durable "have I already handled this?" — far better
// than a list on the case document that would grow without bound and
// race between replicas.
func (r *Verifications) ClaimEvent(ctx context.Context, e *models.Event) error {
	if e.ID == "" {
		return errors.New("repos: event id is required")
	}
	// Deliberately no _rev: an existing document must collide.
	e.Rev = ""
	if err := couch.Store(ctx, r.db, e); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			return ErrConflict
		}
		return fmt.Errorf("repos: store event: %w", err)
	}
	return nil
}

// PutDecision stores a raw provider verdict. Re-storing the same
// session's decision overwrites it: a decision can legitimately be
// re-fetched, and the latest is the one the match ran against.
func (r *Verifications) PutDecision(ctx context.Context, d *models.Decision) error {
	if d.ID == "" {
		return errors.New("repos: decision id is required")
	}
	if err := couch.Store(ctx, r.db, d); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			// Fetch the current revision and overwrite.
			cur := new(models.Decision)
			cur.ID = d.ID
			if ferr := couch.Fetch(ctx, r.db, cur); ferr != nil {
				return fmt.Errorf("repos: store decision: %w", err)
			}
			d.Rev = cur.Rev
			if serr := couch.Store(ctx, r.db, d); serr != nil {
				return fmt.Errorf("repos: store decision: %w", serr)
			}
			return nil
		}
		return fmt.Errorf("repos: store decision: %w", err)
	}
	return nil
}

// GetDecision returns a stored raw verdict or ErrNotFound.
func (r *Verifications) GetDecision(ctx context.Context, sessionID string) (*models.Decision, error) {
	d := new(models.Decision)
	d.ID = models.DecisionDocID(sessionID)
	if err := couch.Fetch(ctx, r.db, d); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("repos: fetch decision: %w", err)
	}
	return d, nil
}

// Archive writes a superseded attempt to its own document. The live
// case is then reset by the caller. Archives are the record of what an
// address has cost and of every decline it has collected, so they
// outlive the case they came from.
func (r *Verifications) Archive(ctx context.Context, v *models.Verification) error {
	a := *v
	a.ID = models.AttemptDocID(v.Address, v.Attempt)
	a.Rev = ""
	if err := couch.Store(ctx, r.db, &a); err != nil {
		if errors.Is(err, couch.ErrAlreadyExists) {
			// Already archived — the caller crashed between the
			// archive and the reset, and is now retrying.
			return nil
		}
		return fmt.Errorf("repos: archive attempt: %w", err)
	}
	return nil
}

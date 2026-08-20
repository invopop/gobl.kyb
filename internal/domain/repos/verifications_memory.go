package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync"
	"time"

	"github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// MemoryVerifications is a thread-safe in-process case store for tests
// and local development. It reproduces _rev-style optimistic
// concurrency and the create-only semantics of the event ledger, so a
// caller exercising the conflict paths behaves exactly as it would
// against CouchDB — those paths are where the money-safety rules live,
// and they must not be exercised only in production.
type MemoryVerifications struct {
	mu        sync.Mutex
	records   map[string]*models.Verification
	attempts  map[string]*models.Verification
	events    map[string]*models.Event
	decisions map[string]*models.Decision
}

// NewMemoryVerifications returns an empty in-memory store.
func NewMemoryVerifications() *MemoryVerifications {
	return &MemoryVerifications{
		records:   make(map[string]*models.Verification),
		attempts:  make(map[string]*models.Verification),
		events:    make(map[string]*models.Event),
		decisions: make(map[string]*models.Decision),
	}
}

// Put creates or updates the case.
func (m *MemoryVerifications) Put(_ context.Context, v *models.Verification) error {
	if err := v.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	prev, exists := m.records[v.ID]
	if exists {
		if v.Rev != prev.Rev {
			return ErrConflict
		}
	} else if v.Rev != "" {
		return ErrConflict
	}
	v.UpdateTimestamps() // parity with couch.Store
	v.Rev = newRev()
	clone := *v
	m.records[v.ID] = &clone
	return nil
}

// Get returns the case for an address or ErrNotFound.
func (m *MemoryVerifications) Get(_ context.Context, address net.Address) (*models.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.records[models.VerificationDocID(address)]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *v
	return &clone, nil
}

// GetByToken returns the case whose status token matches, or
// ErrNotFound.
func (m *MemoryVerifications) GetByToken(_ context.Context, token string) (*models.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.records {
		if v.Token == token {
			clone := *v
			return &clone, nil
		}
	}
	return nil, ErrNotFound
}

// DuePolling returns non-terminal cases due for a poll, oldest first.
func (m *MemoryVerifications) DuePolling(_ context.Context, now time.Time, limit int) ([]*models.Verification, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.Verification
	for _, v := range m.records {
		if v.Status.Terminal() {
			continue
		}
		if v.NextPollAt != nil && v.NextPollAt.After(now) {
			continue
		}
		clone := *v
		out = append(out, &clone)
	}
	sort.Slice(out, func(i, j int) bool {
		return pollKey(out[i]).Before(pollKey(out[j]))
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// pollKey orders the reconciler queue. A case with no schedule sorts
// first: never having been scheduled means it is overdue.
func pollKey(v *models.Verification) time.Time {
	if v.NextPollAt == nil {
		return time.Time{}
	}
	return *v.NextPollAt
}

// ClaimEvent records a callback, returning ErrConflict when the event
// has already been seen.
func (m *MemoryVerifications) ClaimEvent(_ context.Context, e *models.Event) error {
	if e.ID == "" {
		return ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.events[e.ID]; exists {
		return ErrConflict
	}
	e.UpdateTimestamps()
	e.Rev = newRev()
	clone := *e
	m.events[e.ID] = &clone
	return nil
}

// PutDecision stores a raw provider verdict, overwriting any earlier
// one for the same session.
func (m *MemoryVerifications) PutDecision(_ context.Context, d *models.Decision) error {
	if d.ID == "" {
		return ErrNotFound
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	d.UpdateTimestamps()
	d.Rev = newRev()
	clone := *d
	m.decisions[d.ID] = &clone
	return nil
}

// GetDecision returns a stored raw verdict or ErrNotFound.
func (m *MemoryVerifications) GetDecision(_ context.Context, sessionID string) (*models.Decision, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.decisions[models.DecisionDocID(sessionID)]
	if !ok {
		return nil, ErrNotFound
	}
	clone := *d
	return &clone, nil
}

// Archive stores a superseded attempt.
func (m *MemoryVerifications) Archive(_ context.Context, v *models.Verification) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := models.AttemptDocID(v.Address, v.Attempt)
	if _, exists := m.attempts[id]; exists {
		return nil
	}
	clone := *v
	clone.ID = id
	clone.Rev = newRev()
	m.attempts[id] = &clone
	return nil
}

// Attempts returns the archived attempts for an address, for tests
// asserting on the cost ceiling.
func (m *MemoryVerifications) Attempts(address net.Address) []*models.Verification {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*models.Verification
	for _, v := range m.attempts {
		if v.Address == address {
			clone := *v
			out = append(out, &clone)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Attempt < out[j].Attempt })
	return out
}

// newRev generates an opaque revision string. Format mirrors CouchDB's
// "1-<hex>" shape just for parity; the leading integer is purely
// informational.
func newRev() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal; surface so tests notice.
		panic("repos: crypto/rand unavailable: " + err.Error())
	}
	return "1-" + hex.EncodeToString(b[:])
}

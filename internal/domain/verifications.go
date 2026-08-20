package domain

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/l10n"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb/internal/domain/delivery"
	"github.com/invopop/gobl.kyb/internal/domain/mailer"
	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
	"github.com/invopop/gobl.kyb/internal/domain/repos"
)

const (
	// deliveryTimeout bounds a single outbound POST to the authority's
	// inbox, and a single email submission.
	deliveryTimeout = 30 * time.Second

	// statusTokenTTL bounds how long a status link works. It outlives
	// the session it reports on so a customer can still see why a
	// verification failed.
	statusTokenTTL = 60 * 24 * time.Hour

	// maxIncomingSignatures refuses envelopes already close to gobl's
	// 32-signature ceiling. Each verification round-trip appends
	// signatures, and an envelope that arrives near the limit would
	// come back over it — at which point VerifyAuthority rejects it and
	// the party's endorsement is unusable. Better to say so now, with
	// a message that explains it, than to produce the signature that
	// breaks the document.
	maxIncomingSignatures = 24
	// warnIncomingSignatures is where the operator wants to know.
	warnIncomingSignatures = 16

	// pollOpen and pollReview pace the reconciler. An open session is
	// waiting on a human filling in a form; a session under provider
	// review is waiting on their analyst and can take days, so polling
	// it briskly achieves nothing but rate-limit pressure.
	pollOpen   = 15 * time.Minute
	pollReview = 6 * time.Hour
	// pollRetry paces retries of our own failed work.
	pollRetry = 5 * time.Minute
)

// VerificationStore is the persistence contract the verifications
// service depends on. repos.Verifications (CouchDB) and
// repos.MemoryVerifications (tests) both satisfy it.
type VerificationStore interface {
	Put(ctx context.Context, v *models.Verification) error
	Get(ctx context.Context, address goblnet.Address) (*models.Verification, error)
	GetByToken(ctx context.Context, token string) (*models.Verification, error)
	DuePolling(ctx context.Context, now time.Time, limit int) ([]*models.Verification, error)
	ClaimEvent(ctx context.Context, e *models.Event) error
	PutDecision(ctx context.Context, d *models.Decision) error
	GetDecision(ctx context.Context, sessionID string) (*models.Decision, error)
	Archive(ctx context.Context, v *models.Verification) error
}

// Options tunes the verification pipeline.
type Options struct {
	// Authority is the registration authority this verifier works for.
	Authority goblnet.Address
	// PublicBaseURL is the canonical https URL of this service.
	PublicBaseURL string
	// WebhookPath is where the provider posts status updates.
	WebhookPath string
	// SupportedCountries limits which registry countries are accepted.
	// Empty allows all.
	SupportedCountries []string
	// Match is the policy applied to provider decisions.
	Match MatchPolicy
	// PaymentMode gates the payment stage.
	PaymentMode string
	// KYBResultTTL is how long a completed check may re-endorse an
	// unchanged set of facts without paying again.
	KYBResultTTL time.Duration
	// SessionTTL is when an untouched open session is swept as
	// abandoned.
	SessionTTL time.Duration
	// DeclineCooldown is how long a declined address is refused.
	DeclineCooldown time.Duration
	// MaxSessionsPerAddress and MaxSessionsWindow cap what one address
	// can cost.
	MaxSessionsPerAddress int
	MaxSessionsWindow     time.Duration
}

// Verifications runs the verification choreography: accepting a
// registered envelope, opening a provider check, matching the result
// against the party, and countersigning what passes.
type Verifications struct {
	store    VerificationStore
	identity *Identity
	client   *goblnet.Client
	sender   delivery.Sender
	mailer   mailer.Mailer
	provider provider.Provider
	payments PaymentGate
	opts     Options
	opsEmail string
	log      *slog.Logger
}

// newVerifications instantiates the verifications domain service.
func newVerifications(store VerificationStore, identity *Identity, client *goblnet.Client, sender delivery.Sender, m mailer.Mailer, p provider.Provider, gate PaymentGate, opts Options, log *slog.Logger) *Verifications {
	if canon, err := goblnet.ParseAddress(string(opts.Authority)); err == nil {
		opts.Authority = canon
	}
	return &Verifications{
		store:    store,
		identity: identity,
		client:   client,
		sender:   sender,
		mailer:   m,
		provider: p,
		payments: gate,
		opts:     opts,
		log:      log,
	}
}

// Authority returns the registration authority this verifier works for.
func (d *Verifications) Authority() goblnet.Address { return d.opts.Authority }

// Receive processes an incoming verification request: a registered
// envelope containing the subject's org.Party, countersigned by the
// registration authority.
//
// The gate is deliberately strict, and every rejection here is cheap
// compared with what it prevents. A KYB check costs real money the
// moment a session opens, so anything we can tell in advance will make
// the check pointless — a missing tax identity, an unsupported
// jurisdiction, an envelope that cannot carry another signature — is
// refused before the provider is ever called.
func (d *Verifications) Receive(ctx context.Context, env *gobl.Envelope) (*models.Verification, error) {
	subject, party, err := d.admit(ctx, env)
	if err != nil {
		return nil, err
	}

	facts, err := SubjectFactsFrom(party)
	if err != nil {
		d.log.Warn("inbox.rejected", "reason", "incomplete_party", "caller", string(subject), "error", err.Error())
		return nil, ErrValidation.WithMessage("%s", err.Error())
	}
	if !d.countrySupported(facts.Country) {
		d.log.Warn("inbox.rejected", "reason", "country_unsupported", "caller", string(subject), "country", string(facts.Country))
		// A policy refusal, not a malformed document (spec §8.3): the
		// envelope is perfectly well formed and there is nothing the
		// subject could edit to make it acceptable. The supported list
		// goes in the message so the caller can tell its user where
		// this verifier does work, instead of only that it does not
		// work here.
		return nil, ErrForbidden.WithMessage(
			"this verifier does not cover the registry country %s; supported: %s",
			facts.Country, strings.Join(d.opts.SupportedCountries, ", "))
	}

	email := partyEmail(party)
	if email == "" {
		d.log.Warn("inbox.rejected", "reason", "no_email", "caller", string(subject))
		return nil, ErrValidation.WithMessage("party must publish an email address to be verified")
	}

	prev, err := d.store.Get(ctx, subject)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		prev = nil
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}

	if prev != nil && prev.FactsHash == facts.Hash() {
		return d.resubmit(ctx, prev, env, email)
	}
	return d.start(ctx, prev, subject, facts, env, email)
}

// admit runs the protocol-level checks every submission must pass,
// returning the verified subject and its party document.
func (d *Verifications) admit(ctx context.Context, env *gobl.Envelope) (goblnet.Address, *org.Party, error) {
	if err := env.Validate(); err != nil {
		d.log.Warn("inbox.rejected", "reason", "validation", "error", err.Error())
		return "", nil, ErrValidation.WithMessage("envelope failed validation: %s", err.Error())
	}

	// Party envelopes are bearer documents (spec §8.3): the subject is
	// the address the party document itself declares, attested by a
	// valid self-signature. The request token carries delivery intent,
	// and the authority countersignature below is what gates
	// eligibility.
	subject, err := d.client.VerifyParty(ctx, env)
	if err != nil {
		switch {
		case errors.Is(err, goblnet.ErrUnavailable):
			d.log.Warn("inbox.rejected", "reason", "verify_unavailable", "error", err.Error())
			return "", nil, ErrUnavailable.WithMessage("could not reach the subject's key endpoint; retry later")
		case errors.Is(err, goblnet.ErrPartyMissing):
			d.log.Warn("inbox.rejected", "reason", "not_a_party", "error", err.Error())
			return "", nil, ErrValidation.WithMessage("verification envelope must contain an org.Party declaring a gobl: endpoint")
		}
		d.log.Warn("inbox.rejected", "reason", "verify_failed", "error", err.Error())
		return "", nil, ErrUnauthorized.WithMessage("signature verification failed")
	}

	// Any signature claiming this verifier's address must actually be
	// ours: renewals return with our earlier countersignature aboard,
	// and a broken or forged copy means the envelope is not the one we
	// attested to.
	if err := d.verifyOwnSignatures(env); err != nil {
		d.log.Warn("inbox.rejected", "reason", "own_signature_invalid", "caller", string(subject), "error", err.Error())
		return "", nil, ErrUnauthorized.WithMessage("envelope carries an invalid countersignature claiming this verifier")
	}

	// Only registered envelopes are eligible: the authority's
	// countersignature both proves registration and tells us the
	// registry will accept our countersignature for this exact
	// uuid + digest.
	if _, err := d.client.VerifyAuthority(ctx, env); err != nil {
		if errors.Is(err, goblnet.ErrUnavailable) {
			d.log.Warn("inbox.rejected", "reason", "authority_unavailable", "caller", string(subject), "error", err.Error())
			return "", nil, ErrUnavailable.WithMessage("could not reach the registration authority's key endpoint; retry later")
		}
		d.log.Warn("inbox.rejected", "reason", "authority_missing", "caller", string(subject), "error", err.Error())
		return "", nil, ErrForbidden.WithMessage("envelope must carry a valid registration countersignature from %s", d.opts.Authority)
	}

	// Refuse an envelope that cannot survive another round of
	// signatures. gobl caps verification at 32 and every round-trip
	// adds one; producing the signature that pushes a document over
	// the line would leave the party with an endorsement nobody can
	// verify.
	switch n := len(env.Signatures); {
	case n > maxIncomingSignatures:
		d.log.Warn("inbox.rejected", "reason", "too_many_signatures", "caller", string(subject), "signatures", n)
		return "", nil, ErrValidation.WithMessage(
			"envelope already carries %d signatures; re-register the party to get a freshly signed document before verifying", n)
	case n > warnIncomingSignatures:
		d.log.Warn("inbox.signature_count_high", "caller", string(subject), "signatures", n)
	}

	// VerifyParty guarantees the document is an org.Party.
	party, _ := env.Extract().(*org.Party)
	if party == nil {
		return "", nil, ErrValidation.WithMessage("verification envelope must contain an org.Party")
	}
	return subject, party, nil
}

// resubmit handles a submission whose verifiable facts are unchanged.
//
// This is where the service refuses to spend money twice. The
// registration authority drops a party's verifier claim whenever the
// party envelope changes at all, so an ordinary edit — a new phone
// number, a corrected postal address — sends the party back here.
// Nothing about the company was altered, the check that was already
// paid for still holds, and re-running it would charge the customer
// for an answer we have.
func (d *Verifications) resubmit(ctx context.Context, rec *models.Verification, env *gobl.Envelope, email string) (*models.Verification, error) {
	now := time.Now().UTC()

	// Always adopt the newer envelope: the endorsement belongs on what
	// the party publishes now, not on whatever opened the session.
	rec.SetEnvelope(env)
	rec.Email = email

	switch {
	case rec.Status == models.StatusReceived || rec.Status == models.StatusAwaitingPayment:
		// Accepted, but no session was ever opened — the process died
		// between persisting the case and calling the provider. Nothing
		// has been spent, so this is safe to finish, and it has to
		// happen here: the reconciler deliberately never opens a
		// session, so a case left in this state would otherwise sit
		// forever answering 202 to every re-submission.
		if err := d.save(ctx, rec); err != nil {
			return nil, err
		}
		d.log.Info("inbox.resuming_session", "address", string(rec.Address), "status", string(rec.Status))
		if err := d.openSession(ctx, rec, factsFromModel(rec.Facts)); err != nil {
			return nil, err
		}
		if err := d.notifyStart(ctx, rec); err != nil {
			return nil, ErrUnavailable.WithMessage("verification started but the notification email could not be sent; retry later")
		}
		return rec, nil

	case rec.Status.Open():
		// A check is already running for exactly these facts. Re-send
		// the link rather than buying a second session.
		if err := d.save(ctx, rec); err != nil {
			return nil, err
		}
		if rec.Provider.URL != "" {
			// A failed re-send is not worth failing the delivery over:
			// the session is already open and the customer can reach it
			// from the status link they were sent first time round.
			_ = d.notifyStart(ctx, rec)
		}
		d.log.Info("inbox.session_reused",
			"address", string(rec.Address),
			"status", string(rec.Status),
			"session", rec.Provider.ID,
		)
		return rec, nil

	case rec.Status == models.StatusApproved || rec.Status == models.StatusDelivered || rec.Status == models.StatusDeliveryFailed:
		// The facts were verified and the result is still fresh:
		// re-endorse the new envelope for free.
		if rec.Decision == nil || now.Sub(rec.Decision.FetchedAt) > d.opts.KYBResultTTL {
			d.log.Info("inbox.result_expired", "address", string(rec.Address))
			return d.start(ctx, rec, rec.Address, factsFromModel(rec.Facts), env, email)
		}
		rec.Status = models.StatusApproved
		if err := d.save(ctx, rec); err != nil {
			return nil, err
		}
		if err := d.deliver(ctx, rec); err != nil {
			return nil, ErrUnavailable.WithMessage("verification is valid but the result could not be delivered to the registration authority; retry later")
		}
		d.log.Info("inbox.reendorsed", "address", string(rec.Address), "envelope", rec.EnvelopeUUID.String())
		return rec, nil

	case rec.Status == models.StatusDeclined:
		if rec.DeclinedAt != nil && now.Sub(*rec.DeclinedAt) < d.opts.DeclineCooldown {
			d.log.Warn("inbox.rejected", "reason", "declined_cooldown", "address", string(rec.Address))
			return nil, ErrForbidden.WithMessage(
				"verification for %s was declined; re-submitting the same company details will not change that — contact support", rec.Address)
		}
		return d.start(ctx, rec, rec.Address, factsFromModel(rec.Facts), env, email)

	case rec.Status == models.StatusMismatch || rec.Status == models.StatusError:
		d.log.Warn("inbox.rejected", "reason", "needs_operator", "address", string(rec.Address), "status", string(rec.Status))
		// Also a policy refusal rather than a conflict: 409 is not one
		// of the statuses the spec gives the inbox, and a caller
		// implementing to it has handling for 403 and not for this.
		return nil, ErrForbidden.WithMessage(
			"verification for %s needs manual review before it can continue; contact support", rec.Address)

	default: // expired
		return d.start(ctx, rec, rec.Address, factsFromModel(rec.Facts), env, email)
	}
}

// start opens a new paid check, archiving any previous attempt.
func (d *Verifications) start(ctx context.Context, prev *models.Verification, subject goblnet.Address, facts SubjectFacts, env *gobl.Envelope, email string) (*models.Verification, error) {
	now := time.Now().UTC()

	attempt := 1
	var rev string
	if prev != nil {
		if err := d.enforceSessionCeiling(prev, now); err != nil {
			return nil, err
		}
		if err := d.store.Archive(ctx, prev); err != nil {
			return nil, ErrInternal.WithCause(err)
		}
		attempt = prev.Attempt + 1
		rev = prev.Rev
	}

	rec := models.NewVerification(subject, email, env)
	rec.Rev = rev
	rec.Attempt = attempt
	rec.Authority = d.opts.Authority
	rec.Facts = facts.model()
	rec.FactsHash = facts.Hash()

	token, err := newToken()
	if err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	rec.Token = token
	rec.TokenExpiresAt = now.Add(statusTokenTTL)

	// The payment gate. With PAYMENT_MODE none it settles immediately
	// and no case ever rests in awaiting_payment; the stage sits here,
	// between accepting the envelope and opening a paid session,
	// because that is where taking money would have to happen.
	rec.Status = models.StatusAwaitingPayment
	payment, err := d.payments.Require(ctx, rec)
	if err != nil {
		d.log.Warn("payment.required", "address", string(subject), "error", err.Error())
		return nil, ErrValidation.WithMessage("payment is required before this verification can start")
	}
	rec.Payment = payment
	if payment.Status != PaymentSkipped && payment.Status != PaymentSettled {
		// Outstanding payment: the case waits here, and nothing is
		// spent with the provider until it settles.
		if err := d.save(ctx, rec); err != nil {
			return nil, err
		}
		return rec, nil
	}
	rec.Status = models.StatusReceived

	if err := d.save(ctx, rec); err != nil {
		return nil, err
	}

	if err := d.openSession(ctx, rec, facts); err != nil {
		return nil, err
	}

	if err := d.notifyStart(ctx, rec); err != nil {
		// The session is open and billed. Losing the email must not
		// lose the session: keep it, record the failure, and let the
		// sender retry — the facts rule above makes that retry re-send
		// the same link instead of buying another check.
		return nil, ErrUnavailable.WithMessage("verification started but the notification email could not be sent; retry later")
	}
	return rec, nil
}

// enforceSessionCeiling refuses to open a session for an address that
// has already had too many. A hosted check is billed whether or not
// anybody completes it, so an address that keeps starting and
// abandoning verifications is either confused or hostile; either way a
// human should look before more money is spent.
func (d *Verifications) enforceSessionCeiling(prev *models.Verification, now time.Time) error {
	if d.opts.MaxSessionsPerAddress <= 0 {
		return nil
	}
	if prev.Attempt < d.opts.MaxSessionsPerAddress {
		return nil
	}
	// Attempts are counted within a rolling window: an address that
	// exhausted its allowance a year ago is not still barred.
	if d.opts.MaxSessionsWindow > 0 && now.Sub(prev.ReceivedAt) > d.opts.MaxSessionsWindow {
		return nil
	}
	d.log.Warn("inbox.rejected", "reason", "session_ceiling", "address", string(prev.Address), "attempts", prev.Attempt)
	return ErrForbidden.WithMessage(
		"verification for %s has been started %d times already; contact support before trying again", prev.Address, prev.Attempt)
}

// openSession asks the provider for a hosted check.
//
// The ordering here is deliberate and load-bearing: the intent to call
// is persisted *before* the call. A create that times out may still
// have opened — and billed — a session, so an unconfirmed attempt must
// leave a durable trace instead of vanishing. It is never retried
// automatically for the same reason.
func (d *Verifications) openSession(ctx context.Context, rec *models.Verification, facts SubjectFacts) error {
	now := time.Now().UTC()
	ref := fmt.Sprintf("%s#%d", rec.Address, rec.Attempt)
	rec.Provider = models.ProviderSession{
		Name:        string(d.provider.Name()),
		Reference:   ref,
		RequestedAt: now,
	}
	if err := d.save(ctx, rec); err != nil {
		return err
	}

	sess, err := d.provider.CreateSession(ctx, provider.SessionRequest{
		Reference:    ref,
		Subject:      facts.subject(rec),
		CallbackURL:  strings.TrimSuffix(d.opts.PublicBaseURL, "/") + d.opts.WebhookPath,
		ContactEmail: rec.Email,
	})
	if err != nil {
		rec.Provider.Unconfirmed = true
		rec.Status = models.StatusError
		rec.LastError = err.Error()
		d.schedule(rec, now.Add(pollRetry))
		if serr := d.save(ctx, rec); serr != nil {
			d.log.Error("session.persist_failed", "address", string(rec.Address), "error", serr.Error())
		}
		d.log.Error("session.create_failed",
			"address", string(rec.Address),
			"attempt", rec.Attempt,
			"error", err.Error(),
		)
		if errors.Is(err, provider.ErrRejected) {
			return ErrValidation.WithMessage("the verification provider cannot check this company: %s", err.Error())
		}
		return ErrUnavailable.WithMessage("could not start the verification check; retry later")
	}

	rec.Provider.ID = sess.ID
	rec.Provider.Number = sess.Number
	rec.Provider.URL = sess.URL
	rec.Provider.ExpiresAt = sess.ExpiresAt
	rec.Provider.CreatedAt = &now
	rec.Status = models.StatusSessionOpen
	rec.LastError = ""
	d.schedule(rec, now.Add(pollOpen))
	if err := d.save(ctx, rec); err != nil {
		return err
	}
	d.log.Info("session.created",
		"address", string(rec.Address),
		"attempt", rec.Attempt,
		"session", sess.ID,
		"provider", rec.Provider.Name,
	)
	return nil
}

// HandleEvent processes a provider callback: verify, claim, apply.
//
// Everything about this path assumes callbacks are unreliable. They
// are retried a couple of times and then abandoned, they arrive out of
// order, and they may be replayed. So the event is claimed exactly
// once, older events are discarded rather than applied, and a terminal
// case is never disturbed.
func (d *Verifications) HandleEvent(ctx context.Context, raw []byte, header http.Header) error {
	now := time.Now().UTC()
	ev, err := d.provider.ParseEvent(raw, header, now)
	switch {
	case errors.Is(err, provider.ErrSignature):
		d.log.Warn("webhook.rejected", "reason", "signature")
		return ErrUnauthorized.WithMessage("callback signature verification failed")
	case errors.Is(err, provider.ErrStale):
		d.log.Warn("webhook.rejected", "reason", "stale")
		return ErrUnauthorized.WithMessage("callback timestamp is outside the accepted window")
	case err != nil:
		d.log.Warn("webhook.rejected", "reason", "unparseable", "error", err.Error())
		return ErrValidation.WithMessage("callback could not be read")
	}

	addr, attempt, err := parseReference(ev.Reference)
	if err != nil {
		// Nothing we can route. Answer 200 anyway: this is a payload
		// we do not understand, not a failure the provider can fix by
		// retrying.
		d.log.Warn("webhook.unroutable", "reference", ev.Reference, "event", ev.ID)
		return nil
	}

	// Claim the event before doing anything with it. A conflict means
	// a retry of one we have already applied.
	claim := &models.Event{
		Address:    addr,
		SessionID:  ev.SessionID,
		Type:       ev.Type,
		Status:     string(ev.Status),
		At:         ev.At,
		ReceivedAt: now,
	}
	claim.ID = models.EventDocID(ev.ID)
	switch err := d.store.ClaimEvent(ctx, claim); {
	case errors.Is(err, repos.ErrConflict):
		d.log.Debug("webhook.duplicate", "event", ev.ID, "address", string(addr))
		return nil
	case err != nil:
		// Persistence failed — the one case where the provider should
		// retry, so surface it.
		return ErrInternal.WithCause(err)
	}

	rec, err := d.store.Get(ctx, addr)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		d.log.Warn("webhook.unknown_address", "address", string(addr), "event", ev.ID)
		return nil
	case err != nil:
		return ErrInternal.WithCause(err)
	}

	if rec.Attempt != attempt || (rec.Provider.ID != "" && ev.SessionID != "" && rec.Provider.ID != ev.SessionID) {
		// An event for a superseded attempt. Recorded, not applied.
		d.log.Info("webhook.superseded",
			"address", string(addr),
			"event_attempt", attempt,
			"current_attempt", rec.Attempt,
		)
		return nil
	}

	rec.Provider.LastEventID = ev.ID
	rec.Provider.LastEventAt = &now
	return d.applyProviderStatus(ctx, rec, ev.Status, ev.At)
}

// applyProviderStatus moves a case in response to a provider verdict,
// whether it arrived by callback or by polling. Both paths funnel
// through here so the guards cannot be bypassed by whichever one
// happens to win.
func (d *Verifications) applyProviderStatus(ctx context.Context, rec *models.Verification, status provider.Status, at time.Time) error {
	now := time.Now().UTC()

	// A terminal case is settled. A later contradicting status is
	// worth an alert, never an edit: we do not withdraw a signature we
	// have published, and we do not approve after a decline without a
	// human deciding to.
	if rec.Status.Terminal() {
		if status != provider.StatusUnknown && !sameOutcome(rec.Status, status) {
			d.log.Warn("provider.contradiction",
				"address", string(rec.Address),
				"case_status", string(rec.Status),
				"provider_status", string(status),
				"session", rec.Provider.ID,
			)
		}
		return nil
	}

	// Discard a callback older than the state we already hold: it is a
	// retry that lost a race, and applying it would walk the case
	// backwards into a state the provider has already left.
	if !at.IsZero() && rec.Provider.StatusAt != nil && at.Before(*rec.Provider.StatusAt) {
		d.log.Debug("provider.stale_status",
			"address", string(rec.Address),
			"seen_at", rec.Provider.StatusAt,
			"event_at", at,
		)
		return nil
	}

	if status == provider.StatusUnknown {
		// Record it and move on. An unfamiliar status is not a
		// decision, and must never be mistaken for one.
		d.log.Warn("provider.unknown_status", "address", string(rec.Address), "session", rec.Provider.ID)
		return d.save(ctx, rec)
	}

	rec.Provider.Status = string(status)
	if !at.IsZero() {
		rec.Provider.StatusAt = &at
	}

	switch status {
	case provider.StatusPending:
		rec.Status = models.StatusSessionOpen
		d.schedule(rec, now.Add(pollOpen))
		return d.save(ctx, rec)

	case provider.StatusReview:
		if rec.Status != models.StatusInReview {
			rec.ReviewStartedAt = &now
			d.notifyInReview(ctx, rec)
		}
		rec.Status = models.StatusInReview
		d.schedule(rec, now.Add(pollReview))
		return d.save(ctx, rec)

	case provider.StatusExpired:
		rec.Status = models.StatusExpired
		rec.NextPollAt = nil
		if err := d.save(ctx, rec); err != nil {
			return err
		}
		d.notifyExpired(ctx, rec)
		return nil

	case provider.StatusDeclined:
		rec.Status = models.StatusDeclined
		rec.DeclinedAt = &now
		rec.NextPollAt = nil
		// Record the decision for the audit trail, but never
		// countersign.
		if dec, err := d.fetchDecision(ctx, rec); err == nil && dec != nil {
			rec.Decision.Reason = dec.Reason
		}
		if err := d.save(ctx, rec); err != nil {
			return err
		}
		d.log.Info("verification.declined", "address", string(rec.Address), "session", rec.Provider.ID)
		d.notifyDeclined(ctx, rec)
		return nil

	case provider.StatusApproved:
		// Persist the intermediate state before doing the work: a
		// process that dies between here and the countersignature
		// leaves a case the reconciler will finish, rather than an
		// approval nobody acts on.
		rec.Status = models.StatusMatching
		d.schedule(rec, now.Add(pollRetry))
		if err := d.save(ctx, rec); err != nil {
			return err
		}
		return d.settle(ctx, rec)
	}
	return d.save(ctx, rec)
}

// settle turns a provider approval into a countersignature, or into a
// held mismatch. It is the point at which this service stops relaying
// somebody else's opinion and states one of its own.
func (d *Verifications) settle(ctx context.Context, rec *models.Verification) error {
	now := time.Now().UTC()

	dec, err := d.fetchDecision(ctx, rec)
	if err != nil {
		rec.LastError = err.Error()
		d.schedule(rec, now.Add(pollRetry))
		return d.save(ctx, rec)
	}
	if dec.Status != provider.StatusApproved {
		// The decision disagrees with the event that brought us here.
		// Trust the decision — it is the authoritative record.
		return d.applyProviderStatus(ctx, rec, dec.Status, dec.DecidedAt)
	}

	// Re-derive the facts from the envelope about to be signed rather
	// than trusting the ones stored when the session opened. This is
	// what closes the swap: open a check with clean company details,
	// substitute a different party while it runs, collect an
	// endorsement for a company nobody verified.
	facts, err := d.currentFacts(rec)
	if err != nil {
		rec.Status = models.StatusError
		rec.LastError = err.Error()
		d.schedule(rec, now.Add(pollRetry))
		d.log.Error("settle.facts_unavailable", "address", string(rec.Address), "error", err.Error())
		return d.save(ctx, rec)
	}
	if facts.Hash() != rec.FactsHash {
		rec.Status = models.StatusMismatch
		rec.NextPollAt = nil
		rec.Match = &models.MatchReport{
			At:       now,
			Passed:   false,
			Failures: []string{"envelope_changed"},
			Reasons:  []string{"the stored envelope no longer describes the company that was checked"},
		}
		d.log.Warn("settle.envelope_changed", "address", string(rec.Address), "session", rec.Provider.ID)
		if err := d.save(ctx, rec); err != nil {
			return err
		}
		d.alertOps(ctx, rec, "the party document changed while its verification was running")
		return nil
	}

	report := Match(facts, dec.Company, d.opts.Match)
	rec.Match = report.model(now)

	if !report.Passed {
		rec.Status = models.StatusMismatch
		rec.NextPollAt = nil
		d.log.Warn("match.failed",
			"address", string(rec.Address),
			"session", rec.Provider.ID,
			"failures", strings.Join(report.failureStrings(), ","),
			"name_score", report.NameScore,
			"reviewable", report.Reviewable,
		)
		if err := d.save(ctx, rec); err != nil {
			return err
		}
		// The subject is told the verification could not be completed
		// and nothing more. Showing them the registry data we saw
		// would leak the provider's data and coach anyone probing for
		// what we compare against.
		d.notifyMismatch(ctx, rec)
		d.alertOps(ctx, rec, strings.Join(report.Reasons, "; "))
		return nil
	}

	rec.Status = models.StatusApproved
	rec.ApprovedAt = &now
	rec.LastError = ""
	if err := d.save(ctx, rec); err != nil {
		return err
	}
	d.log.Info("match.passed",
		"address", string(rec.Address),
		"session", rec.Provider.ID,
		"matched_on", report.MatchedOn,
		"name_score", report.NameScore,
	)

	if err := d.deliver(ctx, rec); err != nil {
		return nil // recorded on the case; the reconciler retries
	}
	d.notifyApproved(ctx, rec)
	return nil
}

// fetchDecision retrieves and stores the provider's verdict. The raw
// payload goes to its own document — it is the evidence behind a
// public signature, and it carries personal data that must not spread
// through a record rewritten on every callback.
func (d *Verifications) fetchDecision(ctx context.Context, rec *models.Verification) (*provider.Decision, error) {
	if rec.Provider.ID == "" {
		return nil, errors.New("case has no provider session")
	}
	dec, err := d.provider.Decision(ctx, rec.Provider.ID)
	if err != nil {
		d.log.Warn("decision.fetch_failed", "address", string(rec.Address), "session", rec.Provider.ID, "error", err.Error())
		return nil, err
	}
	// A decision is only evidence about the session it came from.
	if dec.SessionID != "" && dec.SessionID != rec.Provider.ID {
		return nil, fmt.Errorf("decision names session %q, expected %q", dec.SessionID, rec.Provider.ID)
	}

	now := time.Now().UTC()
	stored := &models.Decision{
		Address:   rec.Address,
		SessionID: rec.Provider.ID,
		Status:    string(dec.Status),
		FetchedAt: now,
		Raw:       dec.Raw,
	}
	stored.ID = models.DecisionDocID(rec.Provider.ID)
	if err := d.store.PutDecision(ctx, stored); err != nil {
		d.log.Error("decision.persist_failed", "address", string(rec.Address), "error", err.Error())
	}
	rec.Decision = &models.DecisionRef{
		DocID:     stored.ID,
		SessionID: rec.Provider.ID,
		Status:    string(dec.Status),
		Reason:    dec.Reason,
		FetchedAt: now,
	}
	return dec, nil
}

// currentFacts re-derives the verifiable facts from the stored
// envelope.
func (d *Verifications) currentFacts(rec *models.Verification) (SubjectFacts, error) {
	if rec.Envelope == nil {
		return SubjectFacts{}, errors.New("case has no stored envelope")
	}
	party, ok := rec.Envelope.Extract().(*org.Party)
	if !ok || party == nil {
		return SubjectFacts{}, errors.New("stored envelope no longer contains an org.Party")
	}
	return SubjectFactsFrom(party)
}

// Reconcile drives cases the provider has stopped talking to us about.
//
// It is not a nicety. Callbacks are retried twice and then dropped, and
// a case held for analyst review may sit for days with no callback at
// all, so without this loop a verification can be silently lost after
// the customer has already paid for it. It also sweeps sessions nobody
// completed — but never one under review, where the money is spent and
// a human is still working.
func (d *Verifications) Reconcile(ctx context.Context, limit int) (int, error) {
	now := time.Now().UTC()
	due, err := d.store.DuePolling(ctx, now, limit)
	if err != nil {
		return 0, ErrInternal.WithCause(err)
	}
	done := 0
	for _, rec := range due {
		if err := d.reconcileOne(ctx, rec, now); err != nil {
			d.log.Warn("reconcile.failed", "address", string(rec.Address), "error", err.Error())
			continue
		}
		done++
	}
	return done, nil
}

// reconcileOne advances a single case.
func (d *Verifications) reconcileOne(ctx context.Context, rec *models.Verification, now time.Time) error {
	// A lease keeps two replicas from working the same case. It is
	// advisory — worst case both act, and every downstream step is
	// idempotent — but it saves the conflict churn.
	if rec.ReconcileLeaseUntil != nil && rec.ReconcileLeaseUntil.After(now) {
		return nil
	}
	lease := now.Add(2 * time.Minute)
	rec.ReconcileLeaseUntil = &lease
	if err := d.save(ctx, rec); err != nil {
		return err
	}

	switch rec.Status {
	case models.StatusApproved, models.StatusDeliveryFailed:
		return d.deliver(ctx, rec)

	case models.StatusMatching:
		return d.settle(ctx, rec)

	case models.StatusError:
		// An unconfirmed session create may already have been billed,
		// so it is never repeated automatically. An operator decides.
		if rec.Provider.Unconfirmed {
			d.log.Warn("reconcile.unconfirmed_session",
				"address", string(rec.Address),
				"attempt", rec.Attempt,
				"requested_at", rec.Provider.RequestedAt,
			)
			rec.NextPollAt = nil
			return d.save(ctx, rec)
		}
		return nil

	case models.StatusSessionOpen:
		// Sweep an abandoned session — but only one nobody is working.
		if d.opts.SessionTTL > 0 && rec.Provider.CreatedAt != nil &&
			now.Sub(*rec.Provider.CreatedAt) > d.opts.SessionTTL {
			rec.Status = models.StatusExpired
			rec.NextPollAt = nil
			if err := d.save(ctx, rec); err != nil {
				return err
			}
			d.log.Info("session.expired", "address", string(rec.Address), "session", rec.Provider.ID)
			d.notifyExpired(ctx, rec)
			return nil
		}
	}

	if rec.Provider.ID == "" {
		return nil
	}
	dec, err := d.provider.Decision(ctx, rec.Provider.ID)
	if err != nil {
		if errors.Is(err, provider.ErrUnavailable) {
			d.schedule(rec, now.Add(pollRetry))
			return d.save(ctx, rec)
		}
		return err
	}
	return d.applyProviderStatus(ctx, rec, dec.Status, dec.DecidedAt)
}

// deliver countersigns the stored envelope and POSTs it to the
// authority's inbox.
func (d *Verifications) deliver(ctx context.Context, rec *models.Verification) error {
	now := time.Now().UTC()
	env, err := d.countersignedCopy(rec)
	if err != nil {
		rec.Status = models.StatusDeliveryFailed
		rec.LastDeliveryError = err.Error()
		d.schedule(rec, now.Add(pollRetry))
		d.log.Error("deliver.countersign_failed", "address", string(rec.Address), "error", err.Error())
		if perr := d.save(ctx, rec); perr != nil {
			d.log.Error("deliver.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}

	rec.DeliveryAttempts++
	rec.LastDeliveryAt = &now
	sendCtx, cancel := context.WithTimeout(ctx, deliveryTimeout)
	defer cancel()
	if err := d.sender.Send(sendCtx, d.opts.Authority, env); err != nil {
		rec.Status = models.StatusDeliveryFailed
		rec.LastDeliveryError = err.Error()
		d.schedule(rec, now.Add(pollRetry))
		d.log.Warn("deliver.failed",
			"address", string(rec.Address),
			"envelope", rec.EnvelopeUUID.String(),
			"attempts", rec.DeliveryAttempts,
			"error", err.Error(),
		)
		if perr := d.save(ctx, rec); perr != nil {
			d.log.Error("deliver.persist_failed", "address", string(rec.Address), "error", perr.Error())
		}
		return err
	}

	rec.Status = models.StatusDelivered
	rec.DeliveredAt = &now
	rec.LastDeliveryError = ""
	rec.NextPollAt = nil
	d.log.Info("deliver.sent", "address", string(rec.Address), "envelope", rec.EnvelopeUUID.String())
	if err := d.save(ctx, rec); err != nil {
		d.log.Error("deliver.persist_failed", "address", string(rec.Address), "error", err.Error())
	}
	return nil
}

// countersignedCopy countersigns a fresh copy of the stored envelope.
// The stored envelope is never signed directly: Envelope.Sign clears
// every signature when post-sign validation fails, and each delivery
// should carry a freshly-stamped exp anyway.
func (d *Verifications) countersignedCopy(rec *models.Verification) (*gobl.Envelope, error) {
	if rec.Envelope == nil {
		return nil, errors.New("verification has no stored envelope")
	}
	data, err := json.Marshal(rec.Envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal stored envelope: %w", err)
	}
	env := new(gobl.Envelope)
	if err := json.Unmarshal(data, env); err != nil {
		return nil, fmt.Errorf("decode stored envelope: %w", err)
	}
	if err := d.identity.CounterSign(env, rec.Address); err != nil {
		return nil, fmt.Errorf("countersign envelope: %w", err)
	}
	return env, nil
}

// verifyOwnSignatures checks every signature claiming this verifier's
// address against its own published keys. Returns an error when one
// claims an unknown key or fails verification; envelopes without any
// such signature (a first submission) pass untouched.
func (d *Verifications) verifyOwnSignatures(env *gobl.Envelope) error {
	for _, sig := range env.Signatures {
		p, err := head.SignedPayload(sig)
		if err != nil {
			continue
		}
		iss, err := goblnet.ParseAddress(p.Iss)
		if err != nil || iss != d.identity.Address() {
			continue
		}
		pub := d.identity.FindKey(sig.KeyID())
		if pub == nil {
			return fmt.Errorf("signature claims this verifier with unknown key %q", sig.KeyID())
		}
		if err := env.Head.Verify(sig, pub); err != nil {
			return fmt.Errorf("signature claiming this verifier does not verify: %w", err)
		}
	}
	return nil
}

// save persists the case, resolving a lost revision race by re-reading
// and reapplying rather than failing the request.
func (d *Verifications) save(ctx context.Context, rec *models.Verification) error {
	err := d.store.Put(ctx, rec)
	if errors.Is(err, repos.ErrConflict) {
		// Another replica wrote first. Adopt its revision and retry
		// once: our own fields are the authority on what we just did.
		cur, gerr := d.store.Get(ctx, rec.Address)
		if gerr != nil {
			return ErrInternal.WithCause(err)
		}
		rec.Rev = cur.Rev
		err = d.store.Put(ctx, rec)
	}
	if err != nil {
		d.log.Error("case.persist_failed", "address", string(rec.Address), "error", err.Error())
		return ErrInternal.WithCause(err)
	}
	return nil
}

// schedule sets when the reconciler should next look at a case and
// clears any lease so another replica may pick it up.
func (d *Verifications) schedule(rec *models.Verification, at time.Time) {
	t := at.UTC()
	rec.NextPollAt = &t
	rec.ReconcileLeaseUntil = nil
}

// countrySupported reports whether the registry country is one this
// verifier will accept. Checked at the inbox, before a session is
// opened: discovering an unsupported jurisdiction after the fact means
// having paid for a check that can only fail.
func (d *Verifications) countrySupported(c l10n.Code) bool {
	if len(d.opts.SupportedCountries) == 0 {
		return true
	}
	return slices.ContainsFunc(d.opts.SupportedCountries, func(s string) bool {
		return strings.EqualFold(s, string(c))
	})
}

// Case returns the case behind a status token.
func (d *Verifications) Case(ctx context.Context, token string) (*models.Verification, error) {
	if token == "" {
		return nil, ErrNotFound
	}
	rec, err := d.store.GetByToken(ctx, token)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		return nil, ErrNotFound
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}
	if rec.TokenExpired(time.Now().UTC()) {
		return nil, ErrGone.WithMessage("this status link has expired")
	}
	return rec, nil
}

// Find returns the case for an address, for the operator commands.
func (d *Verifications) Find(ctx context.Context, addr goblnet.Address) (*models.Verification, error) {
	rec, err := d.store.Get(ctx, addr)
	switch {
	case errors.Is(err, repos.ErrNotFound):
		return nil, ErrNotFound.WithMessage("no verification for %s", addr)
	case err != nil:
		return nil, ErrInternal.WithCause(err)
	}
	return rec, nil
}

// Redeliver re-countersigns and delivers an approved case — the
// recovery path when delivery to the authority failed.
func (d *Verifications) Redeliver(ctx context.Context, addr goblnet.Address, actor string) (*models.Verification, error) {
	rec, err := d.Find(ctx, addr)
	if err != nil {
		return nil, err
	}
	switch rec.Status {
	case models.StatusApproved, models.StatusDelivered, models.StatusDeliveryFailed:
	default:
		return nil, ErrValidation.WithMessage("verification for %s is %s, not approved", addr, rec.Status)
	}
	rec.RecordOperatorAction("redeliver", actor, "")
	if err := d.deliver(ctx, rec); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	return rec, nil
}

// Approve releases a case held on a name mismatch.
//
// It refuses anything else on purpose. A country, identifier or status
// failure means the provider verified a different or unfit company, and
// no amount of operator confidence turns that into something this
// service should sign its name to. Only the fuzzy axis is a judgement
// call a human is better placed to make.
func (d *Verifications) Approve(ctx context.Context, addr goblnet.Address, actor, reason string) (*models.Verification, error) {
	rec, err := d.Find(ctx, addr)
	if err != nil {
		return nil, err
	}
	if rec.Status != models.StatusMismatch {
		return nil, ErrValidation.WithMessage("verification for %s is %s, not held for review", addr, rec.Status)
	}
	if rec.Match == nil || !rec.Match.Reviewable {
		return nil, ErrForbidden.WithMessage(
			"the mismatch for %s is not reviewable: %s", addr, strings.Join(reasonsOf(rec.Match), "; "))
	}
	if reason == "" {
		return nil, ErrValidation.WithMessage("a reason is required to release a held verification")
	}

	now := time.Now().UTC()
	rec.Status = models.StatusApproved
	rec.ApprovedAt = &now
	rec.RecordOperatorAction("approve", actor, reason)
	if err := d.save(ctx, rec); err != nil {
		return nil, err
	}
	d.log.Info("verification.operator_approved", "address", string(addr), "actor", actor, "reason", reason)
	if err := d.deliver(ctx, rec); err != nil {
		return nil, ErrInternal.WithCause(err)
	}
	d.notifyApproved(ctx, rec)
	return rec, nil
}

// Reject closes a held case without countersigning.
func (d *Verifications) Reject(ctx context.Context, addr goblnet.Address, actor, reason string) (*models.Verification, error) {
	rec, err := d.Find(ctx, addr)
	if err != nil {
		return nil, err
	}
	if rec.Status.Terminal() && rec.Status != models.StatusMismatch {
		return nil, ErrValidation.WithMessage("verification for %s is already %s", addr, rec.Status)
	}
	if reason == "" {
		return nil, ErrValidation.WithMessage("a reason is required to reject a verification")
	}
	now := time.Now().UTC()
	rec.Status = models.StatusDeclined
	rec.DeclinedAt = &now
	rec.NextPollAt = nil
	rec.RecordOperatorAction("reject", actor, reason)
	if err := d.save(ctx, rec); err != nil {
		return nil, err
	}
	d.log.Info("verification.operator_rejected", "address", string(addr), "actor", actor, "reason", reason)
	d.notifyDeclined(ctx, rec)
	return rec, nil
}

// Resend re-sends the hosted flow link to the party's published
// address.
func (d *Verifications) Resend(ctx context.Context, addr goblnet.Address, actor string) (*models.Verification, error) {
	rec, err := d.Find(ctx, addr)
	if err != nil {
		return nil, err
	}
	if rec.Provider.URL == "" {
		return nil, ErrValidation.WithMessage("verification for %s has no open session link", addr)
	}
	rec.RecordOperatorAction("resend", actor, "")
	if err := d.notifyStart(ctx, rec); err != nil {
		return nil, ErrUnavailable.WithMessage("could not send the email; retry later")
	}
	return rec, nil
}

// sameOutcome reports whether a provider status agrees with a settled
// case status, so only genuine contradictions are alerted on.
func sameOutcome(caseStatus models.Status, s provider.Status) bool {
	switch caseStatus {
	case models.StatusDelivered:
		return s == provider.StatusApproved
	case models.StatusDeclined:
		return s == provider.StatusDeclined
	case models.StatusMismatch:
		return s == provider.StatusApproved
	case models.StatusExpired:
		return s == provider.StatusExpired
	}
	return false
}

// parseReference splits a provider reference back into its address and
// attempt number.
func parseReference(ref string) (goblnet.Address, int, error) {
	addr, attempt, ok := strings.Cut(ref, "#")
	if !ok {
		return "", 0, fmt.Errorf("reference %q has no attempt", ref)
	}
	a, err := goblnet.ParseAddress(addr)
	if err != nil {
		return "", 0, fmt.Errorf("reference %q has no valid address: %w", ref, err)
	}
	n := 0
	if _, err := fmt.Sscanf(attempt, "%d", &n); err != nil || n < 1 {
		return "", 0, fmt.Errorf("reference %q has no valid attempt", ref)
	}
	return a, n, nil
}

// reasonsOf safely reads a match report's reasons.
func reasonsOf(m *models.MatchReport) []string {
	if m == nil {
		return []string{"no match report"}
	}
	return m.Reasons
}

// partyEmail returns the party's first published email address, or "".
func partyEmail(party *org.Party) string {
	for _, e := range party.Emails {
		if e != nil && e.Address != "" {
			return e.Address
		}
	}
	return ""
}

// newToken mints an unguessable status-link token.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

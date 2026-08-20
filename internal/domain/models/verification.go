package models

import (
	"errors"
	"fmt"
	"time"

	"github.com/invopop/couch"
	"github.com/invopop/gobl"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/uuid"
)

// Status is where a verification case sits in the pipeline.
type Status string

// Pipeline states.
const (
	// StatusReceived means the envelope was accepted and validated but
	// no provider session exists yet. Nothing has been spent. A case
	// found here after a crash is safe to drive forward.
	StatusReceived Status = "received"
	// StatusAwaitingPayment holds a case at the payment gate. It is
	// unreachable while PAYMENT_MODE is none; the state exists from
	// the start so enabling payment later is an adapter rather than a
	// migration of every stored case.
	StatusAwaitingPayment Status = "awaiting_payment"
	// StatusSessionOpen means a provider session exists and its link
	// has been emailed. This is where the money has been spent.
	StatusSessionOpen Status = "session_open"
	// StatusInReview means a human analyst at the provider holds the
	// case. It has its own state because it behaves differently from
	// every other open session: it is polled slowly, never swept as
	// abandoned, and eventually nagged about.
	StatusInReview Status = "in_review"
	// StatusMatching means the provider approved and our own match
	// check is in flight. It is persisted rather than kept on the
	// stack so a process that dies mid-check leaves a case the
	// reconciler can pick up, instead of an approval nobody acts on.
	StatusMatching Status = "matching"
	// StatusApproved means the provider approved and the match
	// passed. A countersignature is owed to the authority.
	StatusApproved Status = "approved"
	// StatusDelivered means the countersigned envelope was accepted
	// by the authority's inbox.
	StatusDelivered Status = "delivered"
	// StatusDeliveryFailed means the case was approved but delivery
	// did not land. Retryable, and retried.
	StatusDeliveryFailed Status = "delivery_failed"
	// StatusDeclined means the provider refused the company.
	StatusDeclined Status = "declined"
	// StatusMismatch means the provider approved a company that is not
	// the subject of the envelope. Never countersigned; always worth a
	// human's attention, because it is either bad party data or an
	// attempt to borrow someone else's verification.
	StatusMismatch Status = "mismatch"
	// StatusExpired means an open session lapsed unused.
	StatusExpired Status = "expired"
	// StatusError means an internal or provider failure the pipeline
	// could not resolve on its own.
	StatusError Status = "error"
)

// Terminal reports whether a case has reached a resting state. A
// terminal case is never moved by an incoming provider callback: we do
// not un-approve what we have already signed, and we do not re-approve
// after a decline without an operator saying so.
func (s Status) Terminal() bool {
	switch s {
	case StatusDelivered, StatusDeclined, StatusMismatch, StatusExpired:
		return true
	}
	return false
}

// Open reports whether a case is waiting on the provider.
func (s Status) Open() bool {
	switch s {
	case StatusSessionOpen, StatusInReview, StatusMatching:
		return true
	}
	return false
}

// ProviderSession records the vendor session opened for a case.
type ProviderSession struct {
	// Name is the provider implementation that owns the session.
	Name string `json:"name"`
	// Reference is what we told the provider to echo back on every
	// callback: "<address>#<attempt>".
	Reference string `json:"reference"`
	// ID and Number identify the session to the provider and to their
	// support team respectively.
	ID     string `json:"id,omitempty"`
	Number string `json:"number,omitempty"`
	// URL is the hosted flow link handed to the business contact.
	URL string `json:"url,omitempty"`
	// RequestedAt is stamped *before* the create call, so a session
	// that was billed but whose response never arrived still leaves a
	// trace to reconcile against.
	RequestedAt time.Time `json:"requested_at"`
	// CreatedAt is when the provider confirmed the session.
	CreatedAt *time.Time `json:"created_at,omitempty"`
	// Unconfirmed marks a create call that failed without telling us
	// whether a session exists — a timeout, most often. It may have
	// been charged, so it is never retried automatically.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
	// Status is the last provider status seen, and StatusAt is the
	// provider's own timestamp for it. Callbacks older than StatusAt
	// are discarded: they are retries that lost a race, and applying
	// them would walk the case backwards.
	Status   string     `json:"status,omitempty"`
	StatusAt *time.Time `json:"status_at,omitempty"`
	// ExpiresAt bounds the hosted link, when the provider says.
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	// LastEventID and LastEventAt record the most recent callback.
	LastEventID string     `json:"last_event_id,omitempty"`
	LastEventAt *time.Time `json:"last_event_at,omitempty"`
}

// DecisionRef points at the stored raw provider decision without
// dragging its personal data into the case document, which is
// rewritten on every callback.
type DecisionRef struct {
	// DocID is the decision document holding the raw payload.
	DocID string `json:"doc_id"`
	// SessionID is the session the decision belongs to.
	SessionID string `json:"session_id"`
	// Status is the normalised verdict.
	Status string `json:"status"`
	// Reason is the provider's coarse explanation.
	Reason string `json:"reason,omitempty"`
	// FetchedAt is when we retrieved it, and the clock the free
	// re-endorsement window runs on.
	FetchedAt time.Time `json:"fetched_at"`
}

// Payment records the payment stage's outcome. With PAYMENT_MODE none
// it is settled as skipped the moment a case is created.
type Payment struct {
	Mode      string     `json:"mode"`
	Status    string     `json:"status"`
	Reference string     `json:"reference,omitempty"`
	SettledAt *time.Time `json:"settled_at,omitempty"`
}

// OperatorAction records a manual intervention. For a service whose
// product is trustworthiness, "who released this hold, and why" has to
// be answerable long after the fact.
type OperatorAction struct {
	At      time.Time `json:"at"`
	Command string    `json:"command"`
	Actor   string    `json:"actor,omitempty"`
	Reason  string    `json:"reason,omitempty"`
}

// Verification is the live case for one GOBL Net address, stored at
// "verification:<address>" so re-submissions land as new revisions of
// one row. Superseded attempts are archived to their own documents;
// raw provider decisions live in theirs.
type Verification struct {
	couch.Model

	// Address is the subject being verified.
	Address net.Address `json:"address"`
	// Status is the pipeline state.
	Status Status `json:"status"`
	// Attempt counts paid checks for this address. It is part of the
	// provider reference, so a late callback for a superseded attempt
	// is recognisable and ignorable.
	Attempt int `json:"attempt"`

	// FactsHash fingerprints the verified facts. It — not the
	// envelope digest — decides whether a re-submission needs a new
	// paid check.
	FactsHash string `json:"facts_hash"`
	// Facts is the fingerprinted tuple itself, kept readable for
	// operators and for the match check.
	Facts SubjectFacts `json:"facts"`

	// Envelope is the registered envelope as received, never mutated:
	// every delivery countersigns a fresh copy. It is replaced by any
	// later submission carrying the same facts, so the endorsement
	// always lands on the party's current document.
	Envelope       *gobl.Envelope `json:"envelope"`
	EnvelopeUUID   uuid.UUID      `json:"envelope_uuid"`
	EnvelopeDigest string         `json:"envelope_digest"`
	ReceivedAt     time.Time      `json:"received_at"`
	// Authority is the registration authority whose countersignature
	// admitted this envelope.
	Authority net.Address `json:"authority"`

	// Email is the party's published address, where the hosted link
	// and the outcome notices go.
	Email          string     `json:"email"`
	EmailSentAt    *time.Time `json:"email_sent_at,omitempty"`
	EmailAttempts  int        `json:"email_attempts,omitempty"`
	LastEmailError string     `json:"last_email_error,omitempty"`

	// Token secures the status page link.
	Token          string    `json:"token"`
	TokenExpiresAt time.Time `json:"token_expires_at"`

	// Payment records the payment gate.
	Payment Payment `json:"payment"`

	// Provider is the vendor session.
	Provider ProviderSession `json:"provider"`

	// Decision references the stored provider verdict.
	Decision *DecisionRef `json:"decision,omitempty"`
	// Match is the result of checking that verdict against Facts. It
	// is persisted on every outcome, pass or fail — it is the
	// justification for a public signature.
	Match *MatchReport `json:"match,omitempty"`

	// ReviewStartedAt stamps entry into analyst review, so a case
	// stuck there can be nagged about.
	ReviewStartedAt *time.Time `json:"review_started_at,omitempty"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	DeclinedAt      *time.Time `json:"declined_at,omitempty"`

	DeliveryAttempts  int        `json:"delivery_attempts,omitempty"`
	LastDeliveryAt    *time.Time `json:"last_delivery_at,omitempty"`
	LastDeliveryError string     `json:"last_delivery_error,omitempty"`
	DeliveredAt       *time.Time `json:"delivered_at,omitempty"`

	// NextPollAt paces the reconciler, and ReconcileLeaseUntil keeps
	// two replicas from working the same case at once.
	NextPollAt          *time.Time `json:"next_poll_at,omitempty"`
	ReconcileLeaseUntil *time.Time `json:"reconcile_lease_until,omitempty"`
	LastError           string     `json:"last_error,omitempty"`

	// OperatorActions is the manual-intervention audit trail.
	OperatorActions []OperatorAction `json:"operator_actions,omitempty"`
}

// SubjectFacts mirrors domain.SubjectFacts for storage. It lives here
// rather than in the domain package because models may not import the
// domain — the dependency runs the other way — and the two are
// converted at the boundary.
type SubjectFacts struct {
	LegalName          string `json:"legal_name"`
	Country            string `json:"country"`
	TaxCode            string `json:"tax_code"`
	RegistrationNumber string `json:"registration_number"`
	NumberSource       string `json:"number_source"`
}

// MatchReport mirrors domain.MatchReport for storage.
type MatchReport struct {
	At         time.Time `json:"at"`
	Passed     bool      `json:"passed"`
	Reviewable bool      `json:"reviewable"`
	Failures   []string  `json:"failures,omitempty"`
	Reasons    []string  `json:"reasons,omitempty"`
	NameScore  float64   `json:"name_score"`
	MatchedOn  string    `json:"matched_on,omitempty"`
	Observed   Observed  `json:"observed"`
}

// Observed is the registry record the provider returned, flattened for
// storage and for the operator's `status` output.
type Observed struct {
	LegalName          string `json:"legal_name,omitempty"`
	Country            string `json:"country,omitempty"`
	RegistrationNumber string `json:"registration_number,omitempty"`
	TaxCode            string `json:"tax_code,omitempty"`
	VATNumber          string `json:"vat_number,omitempty"`
	LegalForm          string `json:"legal_form,omitempty"`
	Status             string `json:"status,omitempty"`
	Address            string `json:"address,omitempty"`
}

// VerificationDocID returns the CouchDB document ID for an address.
func VerificationDocID(addr net.Address) string {
	return "verification:" + string(addr)
}

// AttemptDocID returns the archive document ID for a superseded
// attempt.
func AttemptDocID(addr net.Address, attempt int) string {
	return fmt.Sprintf("attempt:%s:%d", addr, attempt)
}

// NewVerification builds a fresh case for a received envelope. The
// caller fills in the token, facts and payment stage before storing.
func NewVerification(addr net.Address, email string, env *gobl.Envelope) *Verification {
	v := &Verification{
		Address:    addr,
		Email:      email,
		Status:     StatusReceived,
		Attempt:    1,
		Envelope:   env,
		ReceivedAt: time.Now().UTC(),
	}
	v.SetEnvelope(env)
	v.ID = VerificationDocID(addr)
	return v
}

// SetEnvelope replaces the stored envelope and its derived fields. A
// later submission carrying the same facts supersedes the earlier
// document, so the endorsement is always applied to what the party
// currently publishes rather than to whatever opened the session.
func (v *Verification) SetEnvelope(env *gobl.Envelope) {
	v.Envelope = env
	if env == nil || env.Head == nil {
		v.EnvelopeUUID = uuid.Empty
		v.EnvelopeDigest = ""
		return
	}
	v.EnvelopeUUID = env.Head.UUID
	v.EnvelopeDigest = ""
	if env.Head.Digest != nil {
		v.EnvelopeDigest = string(env.Head.Digest.Algorithm) + ":" + env.Head.Digest.Value
	}
}

// Validate reports whether the record is internally consistent before
// it is written.
func (v *Verification) Validate() error {
	if v == nil {
		return errors.New("models: nil verification")
	}
	if v.Address == "" {
		return errors.New("models: verification address is required")
	}
	if v.ID == "" {
		return errors.New("models: verification _id is required")
	}
	if expected := VerificationDocID(v.Address); v.ID != expected {
		return fmt.Errorf("models: verification _id %q does not match address %q", v.ID, expected)
	}
	if v.Status == "" {
		return errors.New("models: verification status is required")
	}
	if v.Email == "" {
		return errors.New("models: verification email is required")
	}
	if v.Token == "" {
		return errors.New("models: verification token is required")
	}
	if v.FactsHash == "" {
		return errors.New("models: verification facts hash is required")
	}
	return nil
}

// TokenExpired reports whether the status link has lapsed.
func (v *Verification) TokenExpired(now time.Time) bool {
	return !v.TokenExpiresAt.IsZero() && !now.Before(v.TokenExpiresAt)
}

// RecordOperatorAction appends to the intervention audit trail.
func (v *Verification) RecordOperatorAction(command, actor, reason string) {
	v.OperatorActions = append(v.OperatorActions, OperatorAction{
		At:      time.Now().UTC(),
		Command: command,
		Actor:   actor,
		Reason:  reason,
	})
}

// Event is the webhook idempotency ledger. Callbacks are retried and
// may arrive out of order, so each one is claimed by creating this
// document: a conflict on the ID *is* the "already processed" signal,
// which costs nothing and never grows the case document.
type Event struct {
	couch.Model

	// Address and SessionID tie the event to its case.
	Address   net.Address `json:"address"`
	SessionID string      `json:"session_id"`
	// Type and Status are the provider's own wording, for the audit
	// trail.
	Type   string `json:"type,omitempty"`
	Status string `json:"status,omitempty"`
	// At is the provider's timestamp, ReceivedAt ours.
	At         time.Time `json:"at"`
	ReceivedAt time.Time `json:"received_at"`
}

// EventDocID returns the ledger document ID for a provider event.
func EventDocID(eventID string) string {
	return "event:" + eventID
}

// Decision holds a raw provider verdict. It is a separate document
// because it carries personal data about directors and beneficial
// owners: the case document is rewritten constantly and must stay
// clean, while this one is written once and purged on its own
// retention schedule.
type Decision struct {
	couch.Model

	Address   net.Address `json:"address"`
	SessionID string      `json:"session_id"`
	Status    string      `json:"status"`
	FetchedAt time.Time   `json:"fetched_at"`
	// Raw is the provider payload, verbatim. It is the evidence
	// behind a countersignature.
	Raw []byte `json:"raw"`
}

// DecisionDocID returns the document ID for a session's decision.
func DecisionDocID(sessionID string) string {
	return "decision:" + sessionID
}

// Package provider defines the seam between this service's
// verification choreography and whichever KYB vendor actually performs
// the checks.
//
// Everything crossing this boundary is expressed in the domain's own
// terms. No vendor status string, field name or JSON shape appears
// outside an implementation sub-package, so replacing the vendor —
// which the service's provider-neutral GOBL Net address is chosen to
// allow — is a new sub-package and a config value rather than a
// rewrite of the state machine.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/invopop/gobl/l10n"
)

// Sentinel errors, classified by what the caller should do about them.
// They follow the same split as gobl/net: a failure that might succeed
// on retry must never be reported as a definitive rejection, because a
// verification refused for an unreachable vendor is a customer turned
// away for our outage.
var (
	// ErrUnavailable is a transient failure — network, timeout, 429 or
	// 5xx. Retryable.
	ErrUnavailable = errors.New("provider unavailable")
	// ErrRejected is a definitive refusal by the provider, such as an
	// unsupported jurisdiction. Retrying the same request will not
	// help.
	ErrRejected = errors.New("provider rejected the request")
	// ErrNotFound means the provider has no such session.
	ErrNotFound = errors.New("provider session not found")
	// ErrSignature means a callback failed signature verification and
	// must be treated as forged.
	ErrSignature = errors.New("callback signature invalid")
	// ErrStale means a callback's timestamp is outside the accepted
	// freshness window — a replay, or a badly skewed clock.
	ErrStale = errors.New("callback timestamp is stale")
)

// Name identifies a provider implementation.
type Name string

// Status is the provider-neutral state of a verification session.
type Status string

// Session states. Vendor vocabularies are mapped onto these; the
// domain never sees anything else.
const (
	// StatusPending covers everything before a decision exists:
	// created, not started, in progress, or resubmitted after a
	// request for more information.
	StatusPending Status = "pending"
	// StatusReview means a human analyst at the provider holds the
	// case. It can last days and there is no API to hurry it.
	StatusReview Status = "review"
	// StatusApproved means the provider verified a company. It does
	// *not* mean that company is the subject — see domain.Match.
	StatusApproved Status = "approved"
	// StatusDeclined means the provider refused the company.
	StatusDeclined Status = "declined"
	// StatusExpired means the session lapsed unused.
	StatusExpired Status = "expired"
	// StatusUnknown is a status the mapping did not recognise. It is
	// never acted on, only recorded — an unfamiliar state must not be
	// mistaken for a decision.
	StatusUnknown Status = "unknown"
)

// Terminal reports whether a status can still change of its own
// accord.
func (s Status) Terminal() bool {
	return s == StatusApproved || s == StatusDeclined || s == StatusExpired
}

// Subject is what the domain asks a provider to check: the
// KYB-relevant facts derived from the party, and nothing else.
type Subject struct {
	// LegalName is the company's registered name.
	LegalName string
	// Country is the registry country, ISO 3166-1 alpha-2.
	Country l10n.Code
	// RegistrationNumber is the company registry number, normalised.
	RegistrationNumber string
	// TaxCode is the tax/VAT identity code, normalised.
	TaxCode string
	// Context carries non-authoritative detail for a human analyst —
	// the GOBL Net address, the envelope it came from, registry
	// inscription details. Never used for matching.
	Context map[string]string
}

// SessionRequest opens a verification.
type SessionRequest struct {
	// Reference is our own identifier for this attempt. The provider
	// echoes it on every callback, and it is how a callback finds its
	// case.
	Reference string
	// Subject is the company to verify.
	Subject Subject
	// CallbackURL receives the provider's signed status updates.
	CallbackURL string
	// ContactEmail is the human the hosted flow link is sent to.
	ContactEmail string
	// Locale is an optional BCP 47 language preference.
	Locale string
}

// Session is a verification the provider has opened — and, with a
// pay-per-check vendor, has already charged for.
type Session struct {
	// ID identifies the session to the provider.
	ID string
	// Number is a human-friendly reference for support conversations.
	Number string
	// URL is the hosted flow the business contact completes.
	URL string
	// ExpiresAt bounds the URL's life, when the provider says.
	ExpiresAt *time.Time
}

// CompanyRecord is the registry data a provider resolved. It is always
// what the provider *found*, never what we asked it to look for —
// keeping that distinction is what makes the match check meaningful.
type CompanyRecord struct {
	// LegalName is the registered name as the registry holds it.
	LegalName string
	// AlternativeNames are other names the registry records for the
	// same entity: former names, trading names, transliterations.
	AlternativeNames []string
	// Country is the registry country as the provider reports it,
	// which may still be in a tax-only form.
	Country l10n.Code
	// RegistrationNumber is the company registry number.
	RegistrationNumber string
	// TaxCode and VATNumber are the fiscal identifiers, which some
	// registries report separately and some do not distinguish.
	TaxCode   string
	VATNumber string
	// LegalForm is the entity type, when reported separately from the
	// name.
	LegalForm string
	// Active reports whether the registry still lists the entity as
	// trading. Nil means the registry did not say, which is not the
	// same as saying no.
	Active *bool
	// Status is the registry's own status wording, for the operator.
	Status string
	// Address is the registered address, for the audit record.
	Address string
	// IncorporatedAt is the date of incorporation, when reported.
	IncorporatedAt *time.Time
}

// Decision is a provider's verdict on a session.
type Decision struct {
	// SessionID ties the decision to the session that produced it.
	// It is checked against the case's current session before any
	// countersignature: a decision for a superseded attempt is not
	// evidence about this one.
	SessionID string
	// Status is the verdict.
	Status Status
	// DecidedAt is when the provider reached it.
	DecidedAt time.Time
	// Company is the registry record the provider resolved.
	Company CompanyRecord
	// Reason is the provider's coarse explanation, mainly useful on a
	// decline.
	Reason string
	// Raw is the untouched provider payload. It is the evidence
	// behind a countersignature and is stored separately from the
	// case, under its own retention clock, because it carries
	// personal data about directors and beneficial owners.
	Raw json.RawMessage
}

// Event is a verified provider callback.
type Event struct {
	// ID is the provider's event identifier, used for idempotency —
	// callbacks are retried and may arrive out of order.
	ID string
	// Reference is the SessionRequest.Reference echoed back.
	Reference string
	// SessionID names the session the event concerns.
	SessionID string
	// Status is the session's new state.
	Status Status
	// Type is the provider's event name, kept for logs only.
	Type string
	// At is when the provider emitted the event. Used to discard
	// callbacks that arrive after a newer one has already been
	// applied.
	At time.Time
}

// Provider performs KYB checks.
type Provider interface {
	// Name identifies the implementation.
	Name() Name

	// CreateSession opens a verification and returns the hosted flow
	// handle.
	//
	// Callers MUST treat this as non-idempotent: with a pay-per-check
	// vendor an error — a timeout above all — may still mean a
	// session was created and billed. Never retry it automatically.
	CreateSession(ctx context.Context, req SessionRequest) (*Session, error)

	// Decision fetches the current verdict for a session. It is the
	// backstop for dropped callbacks and the only way to follow a
	// case held for analyst review.
	Decision(ctx context.Context, sessionID string) (*Decision, error)

	// ParseEvent verifies and decodes a raw callback. Signature
	// verification lives behind this method so the HTTP layer stays
	// provider-agnostic and never has to know how a given vendor
	// canonicalises what it signs.
	ParseEvent(raw []byte, header http.Header, now time.Time) (*Event, error)
}

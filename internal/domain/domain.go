// Package domain handles the business logic for the KYB verification
// service: accepting registered party envelopes from the registration
// authority's subjects, running a real KYB check through an external
// provider, deciding whether what the provider verified is actually the
// party in the envelope, and — only then — countersigning that envelope
// and delivering it back to the authority's inbox.
//
// Setup wires the repositories and domain services together and is the
// single object handed to the transport adapters in interfaces/.
package domain

import (
	"log/slog"
	"time"

	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain/delivery"
	"github.com/invopop/gobl.kyb/internal/domain/mailer"
	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// Deps bundles the constructed resources handed to New. The transport
// adapters never see these directly — they talk to the domain services
// exposed by Setup.
type Deps struct {
	// Identity is the verifier's loaded GOBL Net identity.
	Identity *models.Identity
	// Verifications persists verification cases.
	Verifications VerificationStore
	// Client verifies incoming envelopes and their authority
	// countersignatures (FetchKey + crypto). It must be constructed
	// with the Authority as its only trusted authority.
	Client *goblnet.Client
	// Sender delivers the countersigned envelope to the authority.
	Sender delivery.Sender
	// Mailer sends the notification emails.
	Mailer mailer.Mailer
	// Provider performs the KYB checks.
	Provider provider.Provider
	// Payments gates the (currently free) payment stage. Defaults to
	// NoopGate.
	Payments PaymentGate
	// Options tunes the pipeline.
	Options Options
	// EndorsementTTL is the lifetime stamped on this verifier's
	// countersignatures. Zero uses DefaultEndorsementTTL.
	EndorsementTTL time.Duration
	// OpsAlertEmail receives mismatch and error notices.
	OpsAlertEmail string
	// Logger receives domain event logs. Defaults to slog.Default().
	Logger *slog.Logger
}

// Setup holds all the domain resources together.
type Setup struct {
	identity      *Identity
	verifications *Verifications
	publicBaseURL string
	webhookPath   string
}

// New prepares the domain setup from its constructed dependencies.
func New(d Deps) *Setup {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	s := new(Setup)
	s.identity = newIdentity(d.Identity, d.Client, d.EndorsementTTL, d.Logger)

	// Resolve the effective public base URL here (defaulting to
	// https://<domain>) so both the domain and callers observe the same
	// value — the empty case is not visible downstream.
	opts := d.Options
	if opts.PublicBaseURL == "" {
		opts.PublicBaseURL = "https://" + string(s.identity.Address())
	}
	if opts.WebhookPath == "" {
		opts.WebhookPath = "/webhooks/didit"
	}
	if opts.Match.NameThreshold == 0 {
		opts.Match = DefaultMatchPolicy()
	}
	s.publicBaseURL = opts.PublicBaseURL
	s.webhookPath = opts.WebhookPath

	if d.Payments == nil {
		d.Payments = NoopGate{}
	}
	if opts.PaymentMode == "" {
		opts.PaymentMode = d.Payments.Mode()
	}

	s.verifications = newVerifications(d.Verifications, s.identity, d.Client, d.Sender, d.Mailer, d.Provider, d.Payments, opts, d.Logger)
	s.verifications.opsEmail = d.OpsAlertEmail
	return s
}

// Identity returns the identity domain service.
func (s *Setup) Identity() *Identity { return s.identity }

// Verifications returns the verifications domain service.
func (s *Setup) Verifications() *Verifications { return s.verifications }

// PublicBaseURL returns the effective canonical URL used for the
// emailed links and the provider callback.
func (s *Setup) PublicBaseURL() string { return s.publicBaseURL }

// WebhookPath returns the route the provider posts callbacks to.
func (s *Setup) WebhookPath() string { return s.webhookPath }

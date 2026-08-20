package domain

import (
	"context"
	"fmt"
	"time"

	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// The payment stage.
//
// The service launches free: KYB checks are cheap enough against a funnel
// already gated by a registered address and a published mailbox, and
// charging on day one would mean pricing, VAT, invoicing and refunds for
// failed checks before there is any demand to price against.
//
// The stage exists anyway, with a single no-op implementation, because the
// alternative is worse. Payment is not a step that can be bolted onto the
// end: it has to sit between accepting an envelope and opening a paid
// session, which is the middle of the state machine and the middle of the
// re-submission rules. Carving it out now — a status cases can rest in, a
// record of how it was settled, and one interface with one call site — is
// what makes enabling it later an adapter and a config value rather than a
// migration of every stored case.
//
// The registration authority's own flow assumes this: its documented
// verification path puts payment on the verifier's side, partly because
// cardholder data is itself a fraud signal and partly to keep the registry
// free.

// Payment settlement states.
const (
	// PaymentSkipped means the stage was configured away.
	PaymentSkipped = "skipped"
	// PaymentSettled means payment completed.
	PaymentSettled = "settled"
	// PaymentPending means payment was requested and is outstanding.
	PaymentPending = "pending"
)

// PaymentGate decides whether a verification may proceed to a paid
// provider check, and records how that was settled.
type PaymentGate interface {
	// Mode names the configured behaviour, stored on the case.
	Mode() string

	// Require settles the payment stage for a case. It returns the
	// state to record, and an error if the verification must not
	// proceed. Implementations that take money are expected to return
	// PaymentPending and drive the case forward out of band.
	Require(ctx context.Context, rec *models.Verification) (models.Payment, error)
}

// NoopGate settles the payment stage immediately: the service is free.
type NoopGate struct{}

// Mode reports the configured payment behaviour.
func (NoopGate) Mode() string { return "none" }

// Require settles at once, so no case ever rests in awaiting_payment.
func (NoopGate) Require(_ context.Context, _ *models.Verification) (models.Payment, error) {
	now := time.Now().UTC()
	return models.Payment{Mode: "none", Status: PaymentSkipped, SettledAt: &now}, nil
}

// NewPaymentGate selects the gate for a configured mode. Only "none" is
// implemented; the others are named so an unimplemented mode fails at
// startup with a clear message rather than silently behaving as free.
func NewPaymentGate(mode string) (PaymentGate, error) {
	switch mode {
	case "", "none":
		return NoopGate{}, nil
	case "setup", "charge":
		return nil, fmt.Errorf("domain: payment mode %q is not implemented yet", mode)
	default:
		return nil, fmt.Errorf("domain: unknown payment mode %q", mode)
	}
}

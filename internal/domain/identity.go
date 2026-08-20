package domain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// DefaultEndorsementTTL is the lifetime of every verifier
// countersignature this service issues, carried as the signed `exp`
// claim. Verifier signatures are deliberately long-lived — in the
// spirit of EV TLS certificates (spec §5.3) — since the verification
// they attest to is independent of the registration cycle.
//
// It is configurable (ENDORSEMENT_TTL) rather than fixed, because the
// right answer early in a service's life is shorter than the right
// answer later: a mistake in the match policy is only as durable as
// the signatures it produced.
const DefaultEndorsementTTL = 365 * 24 * time.Hour

// Identity is the domain service wrapping the verifier's loaded
// identity. It owns the signing behaviour (countersigning subject
// envelopes, signing the service's own party), backs the GET /who
// lookup, and exposes the identity's published-key data to the
// transport layer.
type Identity struct {
	model          *models.Identity
	client         *goblnet.Client
	endorsementTTL time.Duration
	log            *slog.Logger

	partyOnce sync.Once
	partyData []byte
	partyErr  error
}

// newIdentity wraps a loaded identity model.
func newIdentity(m *models.Identity, client *goblnet.Client, ttl time.Duration, log *slog.Logger) *Identity {
	if ttl <= 0 {
		ttl = DefaultEndorsementTTL
	}
	return &Identity{model: m, client: client, endorsementTTL: ttl, log: log}
}

// Model returns the underlying identity data.
func (d *Identity) Model() *models.Identity { return d.model }

// Address returns the verifier's GOBL Net address.
func (d *Identity) Address() goblnet.Address { return d.model.Address() }

// URI returns the gobl: URI form of the verifier's address.
func (d *Identity) URI() cbc.URI { return d.model.URI() }

// FindKey returns the published key with the given kid, or nil.
func (d *Identity) FindKey(kid string) *dsig.PublicKey { return d.model.FindKey(kid) }

// JWKS returns the published keys as an RFC 7517 JWK Set.
func (d *Identity) JWKS() ([]byte, error) { return d.model.JWKS() }

// PublicKeys returns every key the verifier has published.
func (d *Identity) PublicKeys() []*dsig.PublicKey { return d.model.PublicKeys }

// VerifyRequest verifies the Authorization header of an inbound who
// or inbox request (a bearer request token, spec §5.5) and returns
// the verified requester address. The token's audience must be this
// verifier and its freshness window must include the current time.
func (d *Identity) VerifyRequest(ctx context.Context, header string) (goblnet.Address, error) {
	return d.client.VerifyAuthorization(ctx, header, d.Address())
}

// PartyEnvelope returns the JSON of the verifier's party wrapped in a
// self-signed envelope (iss = the verifier's address, no aud), served
// at GET /.well-known/gobl/who. The response is a static document:
// it is signed once per process and cached.
func (d *Identity) PartyEnvelope() ([]byte, error) {
	d.partyOnce.Do(func() {
		env, err := gobl.Envelop(d.model.Party)
		if err != nil {
			d.partyErr = fmt.Errorf("identity: envelop party: %w", err)
			return
		}
		if err := env.Sign(d.model.PrivateKey, head.WithIssuer(d.Address().String())); err != nil {
			d.partyErr = fmt.Errorf("identity: sign party: %w", err)
			return
		}
		d.partyData, d.partyErr = json.Marshal(env)
	})
	return d.partyData, d.partyErr
}

// CounterSign adds a fresh verifier countersignature to env: iss =
// this verifier, aud = the subject whose identity was verified, and a
// long-lived exp (endorsementTTL). No `verifier` claim — that pointer
// is the registration authority's to set (spec §5.3). The envelope's
// UUID and Digest are unchanged — only the Signatures slice grows.
func (d *Identity) CounterSign(env *gobl.Envelope, subject goblnet.Address) error {
	if env == nil || env.Head == nil {
		return errors.New("identity: cannot countersign a nil envelope")
	}
	// Supersede earlier rounds: the fresh countersignature replaces
	// any of this verifier's own (spec §5.3). Other parties'
	// signatures are never touched.
	sigs := make([]*dsig.Signature, 0, len(env.Signatures)+1)
	for _, sig := range env.Signatures {
		if p, err := head.SignedPayload(sig); err == nil {
			if iss, ierr := goblnet.ParseAddress(p.Iss); ierr == nil && iss == d.Address() {
				continue
			}
		}
		sigs = append(sigs, sig)
	}
	env.Signatures = sigs
	return env.Sign(d.model.PrivateKey,
		head.WithIssuer(d.Address().String()),
		head.WithAudience(subject.String()),
		head.WithExpiration(time.Now().Add(d.endorsementTTL)),
	)
}

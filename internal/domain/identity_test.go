package domain_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/head"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/note"
	"github.com/invopop/gobl/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/repos"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// newTestIdentity scaffolds a verifier identity in a tempdir and
// returns the wrapping domain service.
func newTestIdentity(t *testing.T) *domain.Identity {
	t.Helper()
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("kyb.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	setup := domain.New(domain.Deps{
		Identity: id,
		Options:  domain.Options{Authority: "lookup.example"},
		Logger:   discardLogger(),
	})
	return setup.Identity()
}

func TestPartyEnvelopeIsSelfSigned(t *testing.T) {
	id := newTestIdentity(t)

	data, err := id.PartyEnvelope()
	require.NoError(t, err)
	env := new(gobl.Envelope)
	require.NoError(t, json.Unmarshal(data, env))
	require.Len(t, env.Signatures, 1)

	p, err := head.SignedPayload(env.Signatures[0])
	require.NoError(t, err)
	assert.Equal(t, id.Address().String(), p.Iss)
	assert.Empty(t, p.Aud, "a GET who response has no caller to bind to")

	// The envelope is signed once and cached: a second call returns
	// the identical bytes.
	again, err := id.PartyEnvelope()
	require.NoError(t, err)
	assert.Equal(t, data, again)
}

func TestCounterSign(t *testing.T) {
	id := newTestIdentity(t)

	// Build an envelope that already carries a self-signature.
	msg := &note.Message{Content: "party doc"}
	msg.SetUUID(uuid.V7())
	env, err := gobl.Envelop(msg)
	require.NoError(t, err)
	require.NoError(t, env.Sign(id.Model().PrivateKey,
		head.WithIssuer("alice.example"),
		head.WithAudience("lookup.example")))

	// Verifier countersignature.
	require.NoError(t, id.CounterSign(env, net.Address("alice.example")))
	require.Len(t, env.Signatures, 2)

	p, err := head.SignedPayload(env.Signatures[1])
	require.NoError(t, err)
	assert.Equal(t, id.Address().String(), p.Iss)
	assert.Equal(t, "alice.example", p.Aud)
	assert.Empty(t, p.Verifier, "verifier signatures never carry the verifier claim")
	assert.Greater(t, p.ExpiresAt, time.Now().Add(364*24*time.Hour).Unix(), "year-long endorsement")
	assert.Less(t, p.ExpiresAt, time.Now().Add(366*24*time.Hour).Unix())
}

func TestCounterSignNilEnvelope(t *testing.T) {
	id := newTestIdentity(t)
	err := id.CounterSign(nil, "alice.example")
	require.Error(t, err)
}

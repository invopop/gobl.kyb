package didit

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// serveFixture replays a captured decision payload.
func serveFixture(t *testing.T, path string) *Client {
	t.Helper()
	body, err := os.ReadFile(path)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	return testClient(t, func(cfg *Config) {
		cfg.BaseURL = srv.URL
		cfg.Environment = "sandbox"
	})
}

// The golden test. Every field name below was guessed from published
// documentation until this payload was captured from a real session,
// and two of them were wrong. Pinning the mapping against the actual
// bytes is the only way that stays true.
func TestDecisionMapsACapturedPayload(t *testing.T) {
	c := serveFixture(t, "testdata/decision_sandbox_declined.json")

	dec, err := c.Decision(context.Background(), "57fde0f7-8866-407c-b9bc-66b5b6995f45")
	require.NoError(t, err)

	assert.Equal(t, "57fde0f7-8866-407c-b9bc-66b5b6995f45", dec.SessionID)
	assert.Equal(t, provider.StatusDeclined, dec.Status, `the API spells it "Declined", not DECLINED`)
	assert.NotEmpty(t, dec.Raw, "the untouched payload is the evidence behind a countersignature")

	t.Run("company", func(t *testing.T) {
		co := dec.Company
		assert.Equal(t, "Sandbox Holdings Ltd", co.LegalName)
		assert.Equal(t, "SANDBOX-0001", co.RegistrationNumber)
		assert.Equal(t, "ES", string(co.Country))
		assert.Equal(t, "GB-SANDBOX-VAT-0001", co.TaxCode)
		assert.Equal(t, "Private Limited Company", co.LegalForm)
		assert.Equal(t, "1 Sandbox Way, Sandbox City", co.Address)
		require.NotNil(t, co.IncorporatedAt)
		assert.Equal(t, 2010, co.IncorporatedAt.Year())

		// registry_status is "active"; company.status is "Declined" and
		// is the *check* result. Reading the latter as a registry
		// status would report a live company as one of unknown
		// standing.
		assert.Equal(t, "active", co.Status)
		require.NotNil(t, co.Active)
		assert.True(t, *co.Active)
	})

	t.Run("reason comes from the warnings", func(t *testing.T) {
		// There is no decision_reason_code on a real response. Only
		// the warning logged as an error bears on the outcome; the two
		// informational ones do not.
		assert.Equal(t, "KYB_REGISTRY_DATA_MISMATCH_WITH_EXPECTED", dec.Reason)
	})

	t.Run("key people carry their provenance", func(t *testing.T) {
		require.Len(t, dec.KeyPeople, 1)
		p := dec.KeyPeople[0]

		assert.Equal(t, "Test Person", p.Name)
		assert.Equal(t, provider.PersonSourceApplicant, p.Source,
			"the registry disclosed nobody; this person was typed in by the applicant")
		assert.True(t, p.HasRole("director"))
		assert.True(t, p.HasRole("ubo", "shareholder"))
		assert.Equal(t, provider.StatusApproved, p.KYCStatus)
		assert.True(t, p.RequiresVerification)
		assert.False(t, p.Skipped)
	})
}

// The payload demonstrates the gap this service exists to close, so it
// is worth asserting as a property rather than leaving as a comment.
//
// The registry returned no officers and no beneficial owners. The only
// person in the flow was invented by whoever completed it, and they
// passed a full identity check with liveness — so the provider's key
// people check reports Approved. Read naively, that is "a verified
// director of this company". It is nothing of the sort, and the
// provenance field is the only thing that says so.
func TestCapturedPayloadShowsWhyProvenanceMatters(t *testing.T) {
	c := serveFixture(t, "testdata/decision_sandbox_declined.json")
	dec, err := c.Decision(context.Background(), "s")
	require.NoError(t, err)

	var registrySourced int
	for _, p := range dec.KeyPeople {
		if p.Source == provider.PersonSourceRegistry {
			registrySourced++
		}
	}
	assert.Zero(t, registrySourced,
		"nobody in this decision is registry-disclosed, despite an approved KYC")
}

// A decision whose environment does not match is refused before any of
// it is read, so a sandbox payload can never be mapped by a live
// client.
func TestCapturedPayloadIsRefusedByALiveClient(t *testing.T) {
	body, err := os.ReadFile("testdata/decision_sandbox_declined.json")
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	live := testClient(t, func(cfg *Config) {
		cfg.BaseURL = srv.URL
		cfg.Environment = "live"
	})
	_, err = live.Decision(context.Background(), "s")
	require.ErrorIs(t, err, provider.ErrRejected)
}

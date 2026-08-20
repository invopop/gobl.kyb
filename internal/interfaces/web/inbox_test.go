package web_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/tax"

	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

func TestInboxOpensASessionForARegisteredParty(t *testing.T) {
	f := newFixture(t)

	resp := f.submit(f.registeredEnvelope(f.newParty()))
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	rec := f.record()
	assert.Equal(t, models.StatusSessionOpen, rec.Status)
	assert.Equal(t, 1, rec.Attempt)
	assert.NotEmpty(t, rec.Provider.ID)
	assert.Equal(t, 1, f.provider.Sessions())

	msgs := f.mail.records()
	require.Len(t, msgs, 1)
	assert.Contains(t, msgs[0].Text, rec.Provider.URL, "the opening email must carry the hosted link")
}

// The provider search is pre-filled from the party so the business
// does not have to retype what we already know — and so an analyst can
// see where the request came from.
func TestInboxPrefillsTheProviderSearch(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)

	req, ok := f.provider.Request(f.record().Provider.ID)
	require.True(t, ok)
	assert.Equal(t, "Acme Widgets SL", req.Subject.LegalName)
	assert.Equal(t, "ES", string(req.Subject.Country))
	assert.Equal(t, "B12345674", req.Subject.TaxCode)
	assert.Equal(t, "alice@example.com", req.ContactEmail)
	assert.Equal(t, "https://kyb.example/webhooks/didit", req.CallbackURL)
	assert.Equal(t, string(f.subAddr), req.Subject.Context["gobl_address"])
}

// Every one of these refusals happens before a session is opened.
// Discovering the problem after the fact means having paid for a check
// that could only fail.
func TestInboxRefusesBeforeSpendingMoney(t *testing.T) {
	tests := []struct {
		name  string
		party func(*org.Party)
		want  int
	}{
		{
			name:  "no published email",
			party: func(p *org.Party) { p.Emails = nil },
			want:  http.StatusUnprocessableEntity,
		},
		{
			name:  "no legal name",
			party: func(p *org.Party) { p.Name = "" },
			want:  http.StatusUnprocessableEntity,
		},
		{
			name:  "no tax identity",
			party: func(p *org.Party) { p.TaxID = nil },
			want:  http.StatusUnprocessableEntity,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			resp := f.submit(f.registeredEnvelope(f.newParty(tt.party)))
			assert.Equal(t, tt.want, resp.StatusCode)
			assert.Zero(t, f.provider.Sessions(), "no session may be opened for a party we cannot check")
		})
	}
}

// An unsupported jurisdiction is a policy refusal, not a malformed
// document: 403 per spec §8.3, so a caller can tell the difference
// between "fix your party" and "this verifier will never do this". The
// message names the jurisdictions that do work, so whoever is driving
// the submission can say something useful instead of just "no".
func TestInboxRefusesAnUnsupportedCountryWith403(t *testing.T) {
	f := newFixture(t, func(o *domain.Options) {
		o.SupportedCountries = []string{"PT", "FR"}
	})
	resp := f.submit(f.registeredEnvelope(f.newParty()))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, f.provider.Sessions())

	body := readBody(t, resp)
	assert.Contains(t, body, "ES", "names the country that was refused")
	assert.Contains(t, body, "PT, FR", "names the countries that would work")
}

// The reverse: an incomplete party is 422, because editing the document
// is exactly what would fix it.
func TestInboxDistinguishesPolicyFromMalformed(t *testing.T) {
	f := newFixture(t)
	resp := f.submit(f.registeredEnvelope(f.newParty(func(p *org.Party) { p.Emails = nil })))
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
}

func TestInboxRefusesAnUnregisteredParty(t *testing.T) {
	f := newFixture(t)

	// Self-signed only: no authority countersignature.
	env, err := gobl.Envelop(f.newParty())
	require.NoError(t, err)
	require.NoError(t, env.Sign(f.subject, head.WithIssuer(f.subAddr.String())))

	resp := f.submit(env)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Zero(t, f.provider.Sessions())
}

func TestInboxRequiresARequestToken(t *testing.T) {
	f := newFixture(t)
	body, err := json.Marshal(f.registeredEnvelope(f.newParty()))
	require.NoError(t, err)

	resp := f.do(http.MethodPost, goblnet.InboxPath, body, "", "")
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// An unreachable key endpoint means "we could not check", which is not
// the same as "invalid" — the sender must be told to retry, not turned
// away.
func TestInboxAnswers503WhenAKeyEndpointIsUnreachable(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())

	f.fetcher.errs[f.regAddr.KeyURL(f.registry.ID())] = goblnet.ErrUnavailable

	resp := f.submit(env)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.Zero(t, f.provider.Sessions())
}

func TestInboxRefusesAForgedOwnCountersignature(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())

	// A signature claiming to be ours, made with someone else's key.
	impostor := dsig.NewES256Key()
	require.NoError(t, env.Sign(impostor,
		head.WithIssuer(f.verifier.Address().String()),
		head.WithAudience(f.subAddr.String())))

	resp := f.submit(env)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	assert.Zero(t, f.provider.Sessions())
}

// gobl refuses to verify an envelope carrying more than 32 signatures.
// Producing the one that crosses the line would leave the party with
// an endorsement nobody can check, so we refuse earlier and say why.
func TestInboxRefusesAnEnvelopeNearTheSignatureCeiling(t *testing.T) {
	f := newFixture(t)
	env := f.registeredEnvelope(f.newParty())
	for len(env.Signatures) <= 24 {
		key := dsig.NewES256Key()
		require.NoError(t, env.Sign(key, head.WithIssuer("bystander.example")))
	}

	resp := f.submit(env)
	assert.Equal(t, http.StatusUnprocessableEntity, resp.StatusCode)
	assert.Zero(t, f.provider.Sessions())
}

// The money rule. The authority drops a party's verifier claim on any
// envelope change at all, so ordinary edits send parties straight back
// here — and each one treated as new is another paid check.
func TestResubmissionDoesNotBuyASecondCheck(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)
	first := f.record()

	// The customer adds a phone number and re-registers.
	edited := f.newParty(func(p *org.Party) {
		p.Telephones = []*org.Telephone{{Number: "+34 600 000 000"}}
	})
	resp := f.submit(f.registeredEnvelope(edited))
	require.Equal(t, http.StatusAccepted, resp.StatusCode)

	assert.Equal(t, 1, f.provider.Sessions(), "a cosmetic edit must not cost another check")
	after := f.record()
	assert.Equal(t, first.Provider.ID, after.Provider.ID, "the same session is re-used")
	assert.Equal(t, 1, after.Attempt)
	assert.NotEqual(t, first.EnvelopeDigest, after.EnvelopeDigest,
		"the newer envelope is adopted, so the endorsement lands on what the party publishes now")
}

func TestChangedCompanyDetailsDoBuyANewCheck(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)

	changed := f.newParty(func(p *org.Party) {
		p.TaxID = &tax.Identity{Country: "ES", Code: "B87654323"}
	})
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(changed)).StatusCode)

	assert.Equal(t, 2, f.provider.Sessions(), "different company details must be checked again")
	rec := f.record()
	assert.Equal(t, 2, rec.Attempt)
	assert.Len(t, f.store.Attempts(f.subAddr), 1, "the superseded attempt is archived")
}

// An address that keeps starting and abandoning checks is either
// confused or hostile. Either way a human should look before more
// money is spent.
func TestSessionCeilingStopsRunawaySpending(t *testing.T) {
	f := newFixture(t, func(o *domain.Options) { o.MaxSessionsPerAddress = 2 })

	codes := []cbc.Code{"B11111119", "B22222228", "B33333337"}
	for i, code := range codes {
		p := f.newParty(func(p *org.Party) {
			p.TaxID = &tax.Identity{Country: "ES", Code: code}
		})
		resp := f.submit(f.registeredEnvelope(p))
		if i < 2 {
			require.Equal(t, http.StatusAccepted, resp.StatusCode, "attempt %d", i+1)
		} else {
			assert.Equal(t, http.StatusForbidden, resp.StatusCode, "the third attempt is refused")
		}
	}
	assert.Equal(t, 2, f.provider.Sessions())
}

// A check that succeeded still holds. Re-endorsing an edited party
// against a fresh decision costs nothing and must not open a session.
func TestReEndorsementAfterApprovalIsFree(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)
	require.Equal(t, http.StatusOK, f.approve(verifiedCompany()).StatusCode)
	require.Equal(t, models.StatusDelivered, f.record().Status)
	require.Len(t, f.sender.records(), 1)

	edited := f.newParty(func(p *org.Party) {
		p.Websites = []*org.Website{{URL: "https://acme.example"}}
	})
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(edited)).StatusCode)

	assert.Equal(t, 1, f.provider.Sessions(), "no new check")
	sent := f.sender.records()
	require.Len(t, sent, 2, "the edited envelope is countersigned and delivered again")
	assert.Equal(t, models.StatusDelivered, f.record().Status)
}

// A decline is not retryable by re-posting the same company details.
func TestDeclinedAddressIsRefusedDuringCooldown(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)

	rec := f.record()
	f.provider.SetDecision(rec.Provider.ID, provider.Decision{Status: provider.StatusDeclined})
	require.Equal(t, http.StatusOK, f.callback(rec, provider.StatusDeclined).StatusCode)
	require.Equal(t, models.StatusDeclined, f.record().Status)

	resp := f.submit(f.registeredEnvelope(f.newParty()))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, 1, f.provider.Sessions())
}

// A mismatch means a human has to look. Letting the party retry past
// it would let them keep trying until something stuck.
func TestMismatchedAddressNeedsAnOperator(t *testing.T) {
	f := newFixture(t)
	require.Equal(t, http.StatusAccepted, f.submit(f.registeredEnvelope(f.newParty())).StatusCode)
	require.Equal(t, http.StatusOK, f.approve(verifiedCompany(func(c *provider.CompanyRecord) {
		c.RegistrationNumber = "B98765431"
		c.TaxCode = "ESB98765431"
	})).StatusCode)
	require.Equal(t, models.StatusMismatch, f.record().Status)

	resp := f.submit(f.registeredEnvelope(f.newParty()))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"409 is not one of the statuses the spec gives the inbox; a held case is a policy refusal")
	assert.Equal(t, 1, f.provider.Sessions())
}

// The opening email is the only way the customer reaches a check we
// have already paid for. Losing it must surface to the sender, and the
// retry must re-use the session rather than buy another.
func TestEmailFailureDoesNotStrandAPaidSession(t *testing.T) {
	f := newFixture(t)
	f.mail.setErr(errSendFailed{})

	resp := f.submit(f.registeredEnvelope(f.newParty()))
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	require.Equal(t, 1, f.provider.Sessions())

	f.mail.setErr(nil)
	resp = f.submit(f.registeredEnvelope(f.newParty()))
	assert.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.Equal(t, 1, f.provider.Sessions(), "the retry re-sends the same link")
	assert.NotEmpty(t, f.mail.records())
}

// errSendFailed stands in for any mail-transport failure.
type errSendFailed struct{}

func (errSendFailed) Error() string { return "smtp unavailable" }

// A process that dies between accepting an envelope and calling the
// provider leaves a case with no session. The reconciler deliberately
// never opens one — that is the only place money is spent — so the
// next submission has to finish the job, or the case answers 202
// forever and is never checked.
func TestResubmissionFinishesACaseThatNeverOpenedASession(t *testing.T) {
	f := newFixture(t)
	f.provider.CreateErr = provider.ErrUnavailable
	resp := f.submit(f.registeredEnvelope(f.newParty()))
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)

	// Pretend the process died before the provider was reached at all.
	rec := f.record()
	rec.Status = models.StatusReceived
	rec.Provider = models.ProviderSession{}
	require.NoError(t, f.store.Put(t.Context(), rec))
	require.Zero(t, f.provider.Sessions())

	resp = f.submit(f.registeredEnvelope(f.newParty()))
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
	assert.Equal(t, 1, f.provider.Sessions())
	assert.Equal(t, models.StatusSessionOpen, f.record().Status)
}

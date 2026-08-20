package web_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/head"
	goblnet "github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/tax"

	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/mailer"
	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
	"github.com/invopop/gobl.kyb/internal/domain/provider/mock"
	"github.com/invopop/gobl.kyb/internal/domain/repos"
	"github.com/invopop/gobl.kyb/internal/interfaces/web"
)

// mockFetcher serves a map[url]bytes, with optional per-URL errors.
// Used by the goblnet.Client the domain uses to verify incoming
// envelopes and their authority countersignatures.
type mockFetcher struct {
	data map[string][]byte
	errs map[string]error
}

func (m *mockFetcher) Fetch(_ context.Context, url string, _ http.Header) ([]byte, error) {
	if err, ok := m.errs[url]; ok {
		return nil, err
	}
	if d, ok := m.data[url]; ok {
		return d, nil
	}
	return nil, goblnet.ErrFetchFailed
}

func (m *mockFetcher) Post(_ context.Context, _ string, _ []byte, _ http.Header) error {
	return goblnet.ErrFetchFailed
}

// mockSender records deliveries to the authority's inbox.
type mockSender struct {
	mu   sync.Mutex
	sent []sentEnvelope
	err  error
}

type sentEnvelope struct {
	to  goblnet.Address
	env *gobl.Envelope
}

func (m *mockSender) Send(_ context.Context, addr goblnet.Address, env *gobl.Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, sentEnvelope{to: addr, env: env})
	return nil
}

func (m *mockSender) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockSender) records() []sentEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]sentEnvelope, len(m.sent))
	copy(out, m.sent)
	return out
}

// mockMailer records messages.
type mockMailer struct {
	mu   sync.Mutex
	sent []mailer.Message
	err  error
}

func (m *mockMailer) Send(_ context.Context, msg mailer.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.sent = append(m.sent, msg)
	return nil
}

func (m *mockMailer) setErr(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.err = err
}

func (m *mockMailer) records() []mailer.Message {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mailer.Message, len(m.sent))
	copy(out, m.sent)
	return out
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// fixture wires a verifier identity in a tempdir, an in-memory store,
// a mock KYB provider and a fetcher serving the subject's and the
// authority's published keys — the whole service, minus the network
// and minus any spending.
type fixture struct {
	t        *testing.T
	verifier *models.Identity
	subject  *dsig.PrivateKey
	subAddr  goblnet.Address
	registry *dsig.PrivateKey
	regAddr  goblnet.Address
	fetcher  *mockFetcher
	store    *repos.MemoryVerifications
	sender   *mockSender
	mail     *mockMailer
	provider *mock.Provider
	setup    *domain.Setup
	mux      http.Handler
}

func newFixture(t *testing.T, mods ...func(*domain.Options)) *fixture {
	t.Helper()
	dir := t.TempDir()
	verifier, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    goblnet.Address("kyb.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	subKey := dsig.NewES256Key()
	subPub, _ := json.Marshal(subKey.Public())
	subAddr := goblnet.Address("alice.example")

	regKey := dsig.NewES256Key()
	regPub, _ := json.Marshal(regKey.Public())
	regAddr := goblnet.Address("lookup.example")

	fetcher := &mockFetcher{
		data: map[string][]byte{
			subAddr.KeyURL(subKey.ID()): subPub,
			regAddr.KeyURL(regKey.ID()): regPub,
		},
		errs: map[string]error{},
	}
	client := goblnet.NewClient(
		goblnet.WithFetcher(fetcher),
		goblnet.WithAuthorities(regAddr),
	)
	store := repos.NewMemoryVerifications()
	send := &mockSender{}
	mail := &mockMailer{}
	prov := mock.New()

	opts := domain.Options{
		Authority:             regAddr,
		PublicBaseURL:         "https://kyb.example",
		WebhookPath:           "/webhooks/didit",
		Match:                 domain.DefaultMatchPolicy(),
		PaymentMode:           "none",
		KYBResultTTL:          365 * 24 * time.Hour,
		SessionTTL:            14 * 24 * time.Hour,
		DeclineCooldown:       90 * 24 * time.Hour,
		MaxSessionsPerAddress: 3,
		MaxSessionsWindow:     30 * 24 * time.Hour,
	}
	for _, m := range mods {
		m(&opts)
	}

	setup := domain.New(domain.Deps{
		Identity:      verifier,
		Verifications: store,
		Client:        client,
		Sender:        send,
		Mailer:        mail,
		Provider:      prov,
		Options:       opts,
		Logger:        discardLogger(),
	})
	mux := web.NewMux(setup, discardLogger())
	return &fixture{
		t: t, verifier: verifier,
		subject: subKey, subAddr: subAddr,
		registry: regKey, regAddr: regAddr,
		fetcher: fetcher, store: store, sender: send, mail: mail,
		provider: prov, setup: setup, mux: mux,
	}
}

// newParty builds the subject's party: a verifiable Spanish company
// with a published email.
func (f *fixture) newParty(mods ...func(*org.Party)) *org.Party {
	p := &org.Party{
		Name:      "Acme Widgets SL",
		TaxID:     &tax.Identity{Country: "ES", Code: "B12345674"},
		Endpoints: []*org.Endpoint{{URI: f.subAddr.URI()}},
		Emails:    []*org.Email{{Address: "alice@example.com"}},
	}
	for _, m := range mods {
		m(p)
	}
	return p
}

// registeredEnvelope signs the party as the subject and countersigns
// as the authority — exactly the envelope a registered subject
// forwards to a verifier.
func (f *fixture) registeredEnvelope(party *org.Party) *gobl.Envelope {
	f.t.Helper()
	env, err := gobl.Envelop(party)
	require.NoError(f.t, err)
	require.NoError(f.t, env.Sign(f.subject,
		head.WithIssuer(f.subAddr.String()),
		head.WithAudience(f.regAddr.String())))
	f.counterSignAsRegistry(env)
	return env
}

func (f *fixture) counterSignAsRegistry(env *gobl.Envelope) {
	f.t.Helper()
	require.NoError(f.t, env.Sign(f.registry,
		head.WithIssuer(f.regAddr.String()),
		head.WithAudience(f.subAddr.String()),
		head.WithExpiration(time.Now().Add(90*24*time.Hour))))
}

// submit posts a registered envelope to the inbox.
func (f *fixture) submit(env *gobl.Envelope) *http.Response {
	f.t.Helper()
	body, err := json.Marshal(env)
	require.NoError(f.t, err)
	return f.do(http.MethodPost, goblnet.InboxPath, body, f.bearer(), "")
}

// approve drives the current session to an approved decision carrying
// the given registry record, then delivers the callback.
func (f *fixture) approve(company provider.CompanyRecord) *http.Response {
	f.t.Helper()
	rec := f.record()
	f.provider.SetDecision(rec.Provider.ID, provider.Decision{
		Status:  provider.StatusApproved,
		Company: company,
	})
	return f.callback(rec, provider.StatusApproved)
}

// callback delivers a provider event for the case's current session.
func (f *fixture) callback(rec *models.Verification, status provider.Status) *http.Response {
	f.t.Helper()
	return f.callbackWith(provider.Event{
		ID:        "evt-" + rec.Provider.ID + "-" + string(status) + "-" + time.Now().Format("150405.000000000"),
		Reference: rec.Provider.Reference,
		SessionID: rec.Provider.ID,
		Status:    status,
		At:        time.Now().UTC(),
	})
}

// callbackWith delivers a specific provider event.
func (f *fixture) callbackWith(ev provider.Event) *http.Response {
	f.t.Helper()
	f.provider.Enqueue(ev)
	return f.do(http.MethodPost, "/webhooks/didit", []byte(`{}`), "", "application/json")
}

// record returns the stored case for the subject.
func (f *fixture) record() *models.Verification {
	f.t.Helper()
	rec, err := f.store.Get(context.Background(), f.subAddr)
	require.NoError(f.t, err)
	return rec
}

// bearer mints a request token from the subject for the verifier.
func (f *fixture) bearer() string {
	f.t.Helper()
	token, err := goblnet.NewToken(f.subject, f.subAddr, f.verifier.Address(), 0)
	require.NoError(f.t, err)
	return "Bearer " + token
}

func (f *fixture) do(method, path string, body []byte, auth, contentType string) *http.Response {
	f.t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, bytes.NewReader(body))
		if contentType == "" {
			contentType = "application/json"
		}
		req.Header.Set("Content-Type", contentType)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec.Result()
}

// verifiedCompany is the registry record that matches the fixture's
// party exactly.
func verifiedCompany(mods ...func(*provider.CompanyRecord)) provider.CompanyRecord {
	active := true
	c := provider.CompanyRecord{
		LegalName:          "Acme Widgets SL",
		Country:            "ES",
		RegistrationNumber: "B12345674",
		TaxCode:            "ESB12345674",
		Status:             "Active",
		Active:             &active,
	}
	for _, m := range mods {
		m(&c)
	}
	return c
}

// readBody reads a response body as a string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close() //nolint:errcheck
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(data)
}

// due backdates a case's poll schedule, standing in for the wait
// between the reconciler's ticks.
func (f *fixture) due(rec *models.Verification) {
	f.t.Helper()
	cur, err := f.store.Get(context.Background(), rec.Address)
	require.NoError(f.t, err)
	past := time.Now().UTC().Add(-time.Hour)
	cur.NextPollAt = &past
	cur.ReconcileLeaseUntil = nil
	require.NoError(f.t, f.store.Put(context.Background(), cur))
}

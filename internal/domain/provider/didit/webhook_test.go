package didit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

const testSecret = "shhh"

func testClient(t *testing.T, mods ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		APIKey:        "key",
		WorkflowID:    "wf",
		WebhookSecret: testSecret,
		ClockSkew:     5 * time.Minute,
	}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := New(cfg)
	require.NoError(t, err)
	return c
}

// sign produces the signature Didit would send for a payload, using
// the canonical form.
func sign(t *testing.T, secret string, raw []byte) string {
	t.Helper()
	canon, err := canonicalJSON(raw)
	require.NoError(t, err)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(canon)
	return hex.EncodeToString(mac.Sum(nil))
}

func headers(t *testing.T, secret string, raw []byte, now time.Time) http.Header {
	t.Helper()
	h := http.Header{}
	h.Set(headerSignatureV2, sign(t, secret, raw))
	h.Set(headerTimestamp, strconv.FormatInt(now.Unix(), 10))
	return h
}

func payload() []byte {
	return []byte(`{
	  "event_id": "evt-1",
	  "webhook_type": "status.updated",
	  "timestamp": 1750000000,
	  "environment": "live",
	  "status": "APPROVED",
	  "session_kind": "business",
	  "business_session_id": "sess-1",
	  "vendor_data": "acme.invopop.net#1"
	}`)
}

func TestParseEventAcceptsAValidCallback(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()

	ev, err := c.ParseEvent(raw, headers(t, testSecret, raw, now), now)
	require.NoError(t, err)
	assert.Equal(t, "evt-1", ev.ID)
	assert.Equal(t, "acme.invopop.net#1", ev.Reference)
	assert.Equal(t, "sess-1", ev.SessionID)
	assert.Equal(t, provider.StatusApproved, ev.Status)
	assert.Equal(t, int64(1750000000), ev.At.Unix())
}

func TestParseEventRejectsATamperedPayload(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()
	h := headers(t, testSecret, raw, now)

	// Same signature, different body: the classic forgery.
	tampered := []byte(`{"event_id":"evt-1","status":"APPROVED","vendor_data":"victim.invopop.net#1"}`)
	_, err := c.ParseEvent(tampered, h, now)
	require.ErrorIs(t, err, provider.ErrSignature)
}

func TestParseEventRejectsTheWrongSecret(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()

	h := http.Header{}
	h.Set(headerSignatureV2, sign(t, "not-the-secret", raw))
	h.Set(headerTimestamp, strconv.FormatInt(now.Unix(), 10))

	_, err := c.ParseEvent(raw, h, now)
	require.ErrorIs(t, err, provider.ErrSignature)
}

func TestParseEventRejectsAStaleTimestamp(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()

	old := now.Add(-10 * time.Minute)
	_, err := c.ParseEvent(raw, headers(t, testSecret, raw, old), now)
	require.ErrorIs(t, err, provider.ErrStale)

	future := now.Add(10 * time.Minute)
	_, err = c.ParseEvent(raw, headers(t, testSecret, raw, future), now)
	require.ErrorIs(t, err, provider.ErrStale, "a badly skewed clock is just as suspicious in either direction")
}

func TestParseEventRejectsAMissingTimestamp(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()

	h := http.Header{}
	h.Set(headerSignatureV2, sign(t, testSecret, raw))
	_, err := c.ParseEvent(raw, h, now)
	require.ErrorIs(t, err, provider.ErrStale)
}

// Without an event id there is no idempotency key, and the provider
// retries every callback — so an unkeyed one would be applied twice.
func TestParseEventRejectsACallbackWithNoEventID(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := []byte(`{"webhook_type":"status.updated","status":"APPROVED","vendor_data":"acme.invopop.net#1"}`)

	_, err := c.ParseEvent(raw, headers(t, testSecret, raw, now), now)
	require.ErrorContains(t, err, "event_id")
}

// Rotating the callback secret must not drop deliveries signed with
// the outgoing one while the change propagates.
func TestParseEventAcceptsThePreviousSecretDuringRotation(t *testing.T) {
	c := testClient(t, func(cfg *Config) {
		cfg.WebhookSecret = "new"
		cfg.WebhookSecretPrevious = "old"
	})
	now := time.Now()
	raw := payload()

	for _, secret := range []string{"new", "old"} {
		h := http.Header{}
		h.Set(headerSignatureV2, sign(t, secret, raw))
		h.Set(headerTimestamp, strconv.FormatInt(now.Unix(), 10))
		_, err := c.ParseEvent(raw, h, now)
		require.NoError(t, err, "secret %q", secret)
	}
}

// The raw-byte signature scheme is accepted too, so a payload that
// arrives already canonical verifies whichever header carries it.
func TestParseEventAcceptsARawByteSignature(t *testing.T) {
	c := testClient(t)
	now := time.Now()
	raw := payload()

	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(raw)

	h := http.Header{}
	h.Set(headerSignature, hex.EncodeToString(mac.Sum(nil)))
	h.Set(headerTimestamp, strconv.FormatInt(now.Unix(), 10))

	_, err := c.ParseEvent(raw, h, now)
	require.NoError(t, err)
}

// The canonicalisation is where this integration most easily breaks:
// every one of these cases produces a valid-looking signature that
// simply never matches, and none of them shows up until real traffic
// arrives.
func TestCanonicalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "keys are sorted and whitespace removed",
			in:   `{"b": 1, "a": 2}`,
			want: `{"a":2,"b":1}`,
		},
		{
			name: "nested objects are sorted too",
			in:   `{"z":{"y":1,"x":2},"a":[{"q":1,"p":2}]}`,
			want: `{"a":[{"p":2,"q":1}],"z":{"x":2,"y":1}}`,
		},
		{
			name: "numbers keep their original text",
			in:   `{"a":1e3,"b":1.10,"c":0.30000000000000004}`,
			want: `{"a":1e3,"b":1.10,"c":0.30000000000000004}`,
		},
		{
			name: "HTML characters are not escaped",
			in:   `{"name":"Smith & Sons <Holdings>"}`,
			want: `{"name":"Smith & Sons <Holdings>"}`,
		},
		{
			name: "accented company names stay literal",
			in:   `{"name":"Müller & Söhne"}`,
			want: `{"name":"Müller & Söhne"}`,
		},
		{
			name: "non-Latin scripts stay literal",
			in:   `{"name":"Ελληνική Εταιρεία"}`,
			want: `{"name":"Ελληνική Εταιρεία"}`,
		},
		{
			name: "control characters are escaped",
			in:   `{"a":"line\nbreak\ttab"}`,
			want: `{"a":"line\nbreak\ttab"}`,
		},
		{
			name: "quotes and backslashes are escaped",
			in:   `{"a":"say \"hi\" c:\\path"}`,
			want: `{"a":"say \"hi\" c:\\path"}`,
		},
		{
			name: "null, booleans and empty containers",
			in:   `{"a":null,"b":true,"c":false,"d":[],"e":{}}`,
			want: `{"a":null,"b":true,"c":false,"d":[],"e":{}}`,
		},
		{
			name: "array order is preserved",
			in:   `{"a":[3,1,2]}`,
			want: `{"a":[3,1,2]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalJSON([]byte(tt.in))
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestCanonicalJSONIsStableUnderKeyOrder(t *testing.T) {
	a, err := canonicalJSON([]byte(`{"one":1,"two":{"x":1,"y":2}}`))
	require.NoError(t, err)
	b, err := canonicalJSON([]byte(`{"two":{"y":2,"x":1},"one":1}`))
	require.NoError(t, err)
	assert.Equal(t, string(a), string(b),
		"the same payload must reproduce the same signature whatever order it arrives in")
}

func TestMapStatus(t *testing.T) {
	tests := map[string]provider.Status{
		"NOT_STARTED": provider.StatusPending,
		"IN_PROGRESS": provider.StatusPending,
		// Not a fresh start: the applicant supplied more information
		// for a check already running and already paid for.
		"RESUBMITTED": provider.StatusPending,
		"IN_REVIEW":   provider.StatusReview,
		"APPROVED":    provider.StatusApproved,
		"DECLINED":    provider.StatusDeclined,
		"EXPIRED":     provider.StatusExpired,
		"":            provider.StatusUnknown,
		"SOMETHING":   provider.StatusUnknown,
	}
	for in, want := range tests {
		assert.Equal(t, want, mapStatus(in), "status %q", in)
	}
}

func TestRegistryActive(t *testing.T) {
	tests := []struct {
		status string
		active bool
		known  bool
	}{
		{"Active", true, true},
		{"REGISTERED", true, true},
		{"In Business", true, true},
		{"Dissolved", false, true},
		{"Struck off", false, true},
		{"In liquidation", false, true},
		// "Active liquidation" contains both words. A company being
		// wound up is not one to endorse, so the negative reading wins.
		{"Active liquidation", false, true},
		{"", false, false},
		{"Something nobody has seen", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.status, func(t *testing.T) {
			active, known := registryActive(tt.status)
			assert.Equal(t, tt.known, known)
			assert.Equal(t, tt.active, active)
		})
	}
}

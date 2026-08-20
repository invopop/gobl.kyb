package didit

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// Callback headers.
const (
	// headerSignatureV2 signs the canonicalised payload and is the one
	// to prefer: it survives any proxy that reformats JSON on the way
	// in, which signing the raw bytes does not.
	headerSignatureV2 = "X-Signature-V2"
	// headerSignature signs the exact bytes on the wire.
	headerSignature = "X-Signature"
	// headerTimestamp carries the dispatch time, in unix seconds.
	headerTimestamp = "X-Timestamp"
)

// eventPayload is the callback envelope.
type eventPayload struct {
	EventID           string `json:"event_id"`
	WebhookType       string `json:"webhook_type"`
	Timestamp         any    `json:"timestamp"`
	Environment       string `json:"environment"`
	Status            string `json:"status"`
	SessionID         string `json:"session_id"`
	BusinessSessionID string `json:"business_session_id"`
	SessionKind       string `json:"session_kind"`
	VendorData        string `json:"vendor_data"`
}

// ParseEvent verifies a callback's signature and freshness, then
// decodes it.
//
// The signature is computed over Didit's *canonical* form of the
// payload — keys sorted, no whitespace, unicode left unescaped — and
// not over the bytes on the wire. Reproducing that form byte for byte
// is the whole difficulty, and getting it subtly wrong rejects every
// live callback while passing any test written against our own
// encoder. The details that matter are all in canonicalJSON below.
//
// The raw-byte signature is accepted as well, so a payload that
// happens to arrive already canonical verifies either way.
func (c *Client) ParseEvent(raw []byte, header http.Header, now time.Time) (*provider.Event, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("didit: empty callback body")
	}

	// Freshness first: it is the cheaper check, and a stale delivery
	// is not worth the hashing. The window still permits a replay
	// inside it, which is why the event ledger — not this — is the
	// real defence against duplicates.
	if err := c.checkTimestamp(header.Get(headerTimestamp), now); err != nil {
		return nil, err
	}

	if err := c.verifySignature(raw, header); err != nil {
		return nil, err
	}

	var p eventPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("didit: decode callback: %w", err)
	}
	if p.EventID == "" {
		// Without an event id there is no idempotency key, and a
		// retried callback would be applied twice.
		return nil, fmt.Errorf("didit: callback carries no event_id")
	}

	ev := &provider.Event{
		ID:        p.EventID,
		Reference: p.VendorData,
		SessionID: firstNonEmpty(p.BusinessSessionID, p.SessionID),
		Status:    mapStatus(p.Status),
		Type:      p.WebhookType,
	}
	if secs, ok := numericSeconds(p.Timestamp); ok {
		ev.At = time.Unix(secs, 0).UTC()
	}
	return ev, nil
}

// checkTimestamp rejects a callback whose dispatch time is too far
// from ours.
func (c *Client) checkTimestamp(value string, now time.Time) error {
	if value == "" {
		return fmt.Errorf("%w: no %s header", provider.ErrStale, headerTimestamp)
	}
	secs, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return fmt.Errorf("%w: unparseable %s", provider.ErrStale, headerTimestamp)
	}
	drift := now.Sub(time.Unix(secs, 0))
	if drift < 0 {
		drift = -drift
	}
	if drift > c.cfg.ClockSkew {
		return fmt.Errorf("%w: %s is %s away from now", provider.ErrStale, headerTimestamp, drift.Truncate(time.Second))
	}
	return nil
}

// verifySignature checks the payload against every accepted secret.
func (c *Client) verifySignature(raw []byte, header http.Header) error {
	secrets := make([][]byte, 0, 2)
	if c.cfg.WebhookSecret != "" {
		secrets = append(secrets, []byte(c.cfg.WebhookSecret))
	}
	if c.cfg.WebhookSecretPrevious != "" {
		secrets = append(secrets, []byte(c.cfg.WebhookSecretPrevious))
	}
	if len(secrets) == 0 {
		return fmt.Errorf("didit: no webhook secret configured")
	}

	// Two payloads are acceptable: the canonical form (V2) and the
	// bytes as received. Computing both and testing every secret
	// against both keeps a secret rotation and a proxy that reformats
	// JSON from being able to break deliveries between them.
	payloads := [][]byte{raw}
	if canon, err := canonicalJSON(raw); err == nil && !bytes.Equal(canon, raw) {
		payloads = append(payloads, canon)
	}

	provided := []string{
		header.Get(headerSignatureV2),
		header.Get(headerSignature),
	}
	for _, sig := range provided {
		want, err := hex.DecodeString(strings.TrimSpace(sig))
		if err != nil || len(want) == 0 {
			continue
		}
		for _, secret := range secrets {
			for _, payload := range payloads {
				mac := hmac.New(sha256.New, secret)
				mac.Write(payload)
				if hmac.Equal(mac.Sum(nil), want) {
					return nil
				}
			}
		}
	}
	return provider.ErrSignature
}

// canonicalJSON re-serialises a payload into the form Didit signs:
// object keys sorted, no whitespace, and no escaping beyond what JSON
// strictly requires.
//
// Three details decide whether this works against real traffic, and
// each of them is a silent total failure if missed:
//
//   - Numbers keep their original text. Decoding into float64 would
//     turn 1e3 into 1000 and 1.10 into 1.1, and the hash would never
//     match. json.Decoder.UseNumber is what preserves them.
//   - `<`, `>` and `&` stay literal. Go's encoder escapes them to
//     < and friends by default; the signer does not.
//   - Non-ASCII stays literal UTF-8. A company name with an accent in
//     it must not become é — and accented company names are the
//     norm, not the exception, across the registries this service
//     serves.
func canonicalJSON(raw []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := writeCanonical(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// writeCanonical emits one value in canonical form.
func writeCanonical(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case json.Number:
		b.WriteString(t.String())
	case string:
		writeCanonicalString(b, t)
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeCanonical(b, item); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		// Byte order over UTF-8 is codepoint order, which is what a
		// sort-by-unicode signer produces.
		sort.Strings(keys)
		b.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			writeCanonicalString(b, k)
			b.WriteByte(':')
			if err := writeCanonical(b, t[k]); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	default:
		return fmt.Errorf("didit: cannot canonicalise %T", v)
	}
	return nil
}

// writeCanonicalString emits a JSON string escaping only what the
// format requires: quote, backslash, and the C0 control characters.
// Everything else — including `<`, `>`, `&` and every non-ASCII rune —
// is written through unchanged.
func writeCanonicalString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}

// numericSeconds reads a unix timestamp that may arrive as a number or
// a string.
func numericSeconds(v any) (int64, bool) {
	switch t := v.(type) {
	case float64:
		if math.IsNaN(t) || math.IsInf(t, 0) {
			return 0, false
		}
		return int64(t), true
	case json.Number:
		if n, err := t.Int64(); err == nil {
			return n, true
		}
	case string:
		if n, err := strconv.ParseInt(strings.TrimSpace(t), 10, 64); err == nil {
			return n, true
		}
	}
	return 0, false
}

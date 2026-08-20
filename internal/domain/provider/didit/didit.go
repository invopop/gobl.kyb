// Package didit implements the KYB provider interface against
// didit.me's verification API.
//
// Everything vendor-specific is confined here: the endpoint shapes,
// the status vocabulary, the JSON field names and the callback
// signature scheme. The domain sees only provider.Provider, so
// replacing this vendor means adding a sibling package, not touching
// the verification choreography.
package didit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/invopop/gobl/l10n"

	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// Name identifies this provider.
const Name provider.Name = "didit"

// DefaultBaseURL is the verification API root.
const DefaultBaseURL = "https://verification.didit.me"

// maxResponseBody caps what is read from the provider. Decisions carry
// officers and beneficial owners and can be large, but not unbounded.
const maxResponseBody = 4 << 20 // 4 MiB

// Config holds the credentials and endpoints for a Didit client.
type Config struct {
	// BaseURL overrides the API root, for tests.
	BaseURL string
	// APIKey authenticates API calls.
	APIKey string
	// WorkflowID names the KYB workflow configured in Didit's console.
	// It decides which checks run, so it is part of what this
	// service's countersignature means.
	WorkflowID string
	// WebhookSecret is the HMAC key for callback signatures.
	WebhookSecret string
	// WebhookSecretPrevious lets a secret rotation overlap: both are
	// accepted while the change propagates, so rotating costs no
	// downtime and no lost callbacks.
	WebhookSecretPrevious string
	// ClockSkew bounds how stale a callback timestamp may be.
	ClockSkew time.Duration
	// Timeout bounds a single API call.
	Timeout time.Duration
	// HTTPClient overrides the transport, for tests.
	HTTPClient *http.Client
}

// Client is the Didit provider implementation.
type Client struct {
	cfg  Config
	http *http.Client
}

// New builds a Didit client.
func New(cfg Config) (*Client, error) {
	if cfg.APIKey == "" {
		return nil, errors.New("didit: api key is required")
	}
	if cfg.WorkflowID == "" {
		return nil, errors.New("didit: workflow id is required")
	}
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 5 * time.Minute
	}
	c := &Client{cfg: cfg, http: cfg.HTTPClient}
	if c.http == nil {
		c.http = &http.Client{Timeout: cfg.Timeout}
	}
	return c, nil
}

// Name identifies the implementation.
func (c *Client) Name() provider.Name { return Name }

// createSessionRequest is the POST /v3/session/ body.
type createSessionRequest struct {
	WorkflowID      string            `json:"workflow_id"`
	VendorData      string            `json:"vendor_data,omitempty"`
	CallbackURL     string            `json:"callback_url,omitempty"`
	ContactEmail    string            `json:"contact_email,omitempty"`
	Language        string            `json:"language,omitempty"`
	ExpectedDetails *expectedDetails  `json:"expected_details,omitempty"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// expectedDetails pre-fills the hosted flow's registry search. It is a
// hint, not a constraint: the fields stay editable, which is exactly
// why the returned decision has to be matched rather than trusted.
type expectedDetails struct {
	CompanyName        string `json:"company_name,omitempty"`
	RegistryCountry    string `json:"registry_country,omitempty"`
	RegistrationNumber string `json:"registration_number,omitempty"`
}

// createSessionResponse is what POST /v3/session/ returns.
type createSessionResponse struct {
	SessionID     string `json:"session_id"`
	SessionNumber any    `json:"session_number"`
	URL           string `json:"url"`
	SessionURL    string `json:"session_url"`
	ExpiresAt     string `json:"expires_at"`
}

// CreateSession opens a hosted KYB check.
//
// This call spends money. The caller must treat it as
// non-idempotent — a timeout may still have created and billed a
// session — which is why nothing here retries.
func (c *Client) CreateSession(ctx context.Context, req provider.SessionRequest) (*provider.Session, error) {
	body := createSessionRequest{
		WorkflowID:   c.cfg.WorkflowID,
		VendorData:   req.Reference,
		CallbackURL:  req.CallbackURL,
		ContactEmail: req.ContactEmail,
		Language:     req.Locale,
		Metadata:     req.Subject.Context,
		ExpectedDetails: &expectedDetails{
			CompanyName:        req.Subject.LegalName,
			RegistryCountry:    string(req.Subject.Country),
			RegistrationNumber: req.Subject.RegistrationNumber,
		},
	}

	var out createSessionResponse
	if err := c.do(ctx, http.MethodPost, "/v3/session/", body, &out); err != nil {
		return nil, err
	}
	if out.SessionID == "" {
		return nil, fmt.Errorf("%w: response carried no session id", provider.ErrUnavailable)
	}
	url := out.URL
	if url == "" {
		url = out.SessionURL
	}
	if url == "" {
		return nil, fmt.Errorf("%w: response carried no session url", provider.ErrUnavailable)
	}
	s := &provider.Session{
		ID:     out.SessionID,
		Number: stringify(out.SessionNumber),
		URL:    url,
	}
	if t, ok := parseTime(out.ExpiresAt); ok {
		s.ExpiresAt = &t
	}
	return s, nil
}

// decisionResponse is the part of GET /v3/session/{id}/decision/ this
// service reads. The payload is far larger — officers, beneficial
// owners, AML hits, document OCR — and all of it is preserved verbatim
// in Decision.Raw for the audit record; only the fields the match
// check needs are decoded here.
type decisionResponse struct {
	SessionID  string `json:"session_id"`
	Status     string `json:"status"`
	VendorData string `json:"vendor_data"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	Reason     string `json:"decision_reason_code"`
	Reviews    []struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
		Date    string `json:"date"`
	} `json:"reviews"`
	RegistryChecks []struct {
		Status  string  `json:"status"`
		Company company `json:"company"`
	} `json:"registry_checks"`
}

// company mirrors registry_checks[].company.
type company struct {
	CompanyName        string   `json:"company_name"`
	AlternativeNames   []string `json:"alternative_names"`
	RegistrationNumber string   `json:"registration_number"`
	CountryCode        string   `json:"country_code"`
	CompanyType        string   `json:"company_type"`
	TaxNumber          string   `json:"tax_number"`
	VATNumber          string   `json:"vat_number"`
	RegistryStatus     string   `json:"registry_status"`
	Status             string   `json:"status"`
	RegisteredAddress  string   `json:"registered_address"`
	IncorporationDate  string   `json:"incorporation_date"`
	IsFromRegistry     *bool    `json:"is_from_registry"`
	VerificationStatus string   `json:"verification_status"`
}

// Decision fetches the provider's verdict.
func (c *Client) Decision(ctx context.Context, sessionID string) (*provider.Decision, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("%w: no session id", provider.ErrNotFound)
	}
	raw, err := c.get(ctx, "/v3/session/"+sessionID+"/decision/")
	if err != nil {
		return nil, err
	}
	var out decisionResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("didit: decode decision: %w", err)
	}

	dec := &provider.Decision{
		SessionID: out.SessionID,
		Status:    mapStatus(out.Status),
		Reason:    out.Reason,
		Raw:       raw,
	}
	if dec.SessionID == "" {
		dec.SessionID = sessionID
	}
	if t, ok := parseTime(out.UpdatedAt); ok {
		dec.DecidedAt = t
	} else if t, ok := parseTime(out.CreatedAt); ok {
		dec.DecidedAt = t
	}
	dec.Company = mapCompany(out)
	return dec, nil
}

// mapCompany flattens the registry check onto the domain's record.
//
// Only registry-sourced data is offered as evidence. Didit's hosted
// flow lets the business type its own company details when a registry
// lookup comes up empty, and those are recorded in the same shape —
// but an endorsement built on what the applicant typed about
// themselves would be worth nothing. Where the payload distinguishes
// the two, the user-provided variant is dropped.
func mapCompany(out decisionResponse) provider.CompanyRecord {
	for _, rc := range out.RegistryChecks {
		co := rc.Company
		if co.CompanyName == "" && co.RegistrationNumber == "" {
			continue
		}
		if co.IsFromRegistry != nil && !*co.IsFromRegistry {
			continue
		}
		rec := provider.CompanyRecord{
			LegalName:          co.CompanyName,
			AlternativeNames:   co.AlternativeNames,
			Country:            l10n.Code(strings.ToUpper(co.CountryCode)),
			RegistrationNumber: co.RegistrationNumber,
			TaxCode:            co.TaxNumber,
			VATNumber:          co.VATNumber,
			LegalForm:          co.CompanyType,
			Status:             firstNonEmpty(co.RegistryStatus, co.Status),
			Address:            co.RegisteredAddress,
		}
		if active, known := registryActive(rec.Status); known {
			rec.Active = &active
		}
		if t, ok := parseTime(co.IncorporationDate); ok {
			rec.IncorporatedAt = &t
		}
		return rec
	}
	return provider.CompanyRecord{}
}

// activeStatuses and inactiveStatuses interpret a registry's own
// status wording. Registries do not agree on vocabulary, so this is
// necessarily a list, and anything unrecognised is reported as
// *unknown* rather than guessed at: "we could not tell" must never be
// silently rendered as "not active", which would decline a good
// company, nor as "active", which would endorse a dissolved one.
var (
	activeStatuses = []string{
		"active", "registered", "in business", "live", "current",
		"good standing", "trading", "operating", "normal",
	}
	inactiveStatuses = []string{
		"dissolved", "liquidation", "liquidated", "struck", "closed",
		"inactive", "terminated", "cancelled", "canceled", "revoked",
		"bankrupt", "insolvent", "ceased", "deregistered", "removed",
		"suspended", "expired", "wound up", "winding up",
	}
)

// registryActive reports whether a registry status means the company
// is trading, and whether that could be determined at all.
func registryActive(status string) (active, known bool) {
	s := strings.ToLower(strings.TrimSpace(status))
	if s == "" {
		return false, false
	}
	// Inactive wins on a tie: "active liquidation" is not a trading
	// company, and the conservative reading is the safe one.
	for _, k := range inactiveStatuses {
		if strings.Contains(s, k) {
			return false, true
		}
	}
	for _, k := range activeStatuses {
		if strings.Contains(s, k) {
			return true, true
		}
	}
	return false, false
}

// mapStatus translates Didit's session vocabulary.
//
// RESUBMITTED deserves a note: it means the applicant was asked for
// more information and supplied it, so the check is running again. It
// is emphatically not a fresh start — treating it as one would open a
// second billed session for a check already in flight.
func mapStatus(s string) provider.Status {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "NOT_STARTED", "IN_PROGRESS", "RESUBMITTED":
		return provider.StatusPending
	case "IN_REVIEW":
		return provider.StatusReview
	case "APPROVED":
		return provider.StatusApproved
	case "DECLINED", "REJECTED":
		return provider.StatusDeclined
	case "EXPIRED", "ABANDONED":
		return provider.StatusExpired
	case "":
		return provider.StatusUnknown
	default:
		return provider.StatusUnknown
	}
}

// do performs a JSON API call.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("didit: encode request: %w", err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.cfg.BaseURL+path, reader)
	if err != nil {
		return fmt.Errorf("didit: build request: %w", err)
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	raw, err := c.send(req)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("didit: decode response: %w", err)
	}
	return nil
}

// get performs a GET and returns the raw body.
func (c *Client) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("didit: build request: %w", err)
	}
	req.Header.Set("x-api-key", c.cfg.APIKey)
	req.Header.Set("Accept", "application/json")
	return c.send(req)
}

// send executes a request and classifies the outcome.
//
// The classification is the point. A 5xx, a 429 or a dropped
// connection is retryable and must never be reported as a rejection —
// a company turned away because the vendor had a bad minute is a
// customer we lost to our own error handling. A definitive 4xx is the
// opposite: retrying it wastes time and, on the create path, money.
func (c *Client) send(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", provider.ErrUnavailable, err)
	}
	defer resp.Body.Close() //nolint:errcheck

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("%w: read response: %s", provider.ErrUnavailable, err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return raw, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", provider.ErrNotFound, req.URL.Path)
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, fmt.Errorf("%w: status %d: %s", provider.ErrUnavailable, resp.StatusCode, snippet(raw))
	default:
		return nil, fmt.Errorf("%w: status %d: %s", provider.ErrRejected, resp.StatusCode, snippet(raw))
	}
}

// snippet trims an error body for a log line.
func snippet(raw []byte) string {
	const limit = 240
	s := strings.TrimSpace(string(raw))
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// stringify renders a JSON value that may arrive as a number or a
// string.
func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		return fmt.Sprintf("%.0f", t)
	default:
		return fmt.Sprint(t)
	}
}

// timeLayouts are the shapes dates arrive in. Registries report
// incorporation as a plain date; the API reports timestamps in RFC
// 3339, sometimes without a zone.
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

// parseTime accepts any of the shapes above.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

// Package config defines the runtime configuration for the KYB
// verification service. Values are resolved from environment variables
// (the mechanism the cluster uses to inject config and secrets) and may
// be overridden by the command-line flags in cmd/gobl.kyb.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/invopop/couch"
)

// DefaultAuthority is the registration authority this verifier serves
// by default: incoming envelopes must carry its countersignature, and
// completed verifications are delivered back to its inbox.
const DefaultAuthority = "lookup.gobl.org"

// Provider names selectable through PROVIDER.
const (
	// ProviderDidit runs real KYB checks through didit.me.
	ProviderDidit = "didit"
	// ProviderMock drives the state machine without spending money —
	// for local development and the test suite.
	ProviderMock = "mock"
)

// Payment modes selectable through PAYMENT_MODE. Only PaymentNone is
// implemented; the others exist so the state machine carries the stage
// from day one and enabling it later is an adapter, not a redesign.
const (
	// PaymentNone skips the payment stage entirely.
	PaymentNone = "none"
	// PaymentSetup captures a card without charging it.
	PaymentSetup = "setup"
	// PaymentCharge takes a payment before the check runs.
	PaymentCharge = "charge"
)

// DefaultWebhookPath is where the provider posts session updates. It is
// configurable, but the path is never a security control — the payload
// signature is.
const DefaultWebhookPath = "/webhooks/didit"

// Config holds the options shared by the serve and operator commands.
//
// CouchDB may be configured in two ways: a single connection URL
// (CouchURL, from --couchdb / COUCHDB_URL — convenient for local dev),
// or the split parts (CouchScheme/Host/Port/Username/Password, from the
// COUCHDB_* env vars — the cluster convention, so the password can be
// injected from a secret separately). CouchURL, when set, wins.
type Config struct {
	// ConfigDir is the directory holding the verifier identity
	// (private.jwk + party.json + keys/).
	ConfigDir string

	// CouchURL is an explicit full CouchDB connection URL. When set it
	// takes precedence over the split Couch* fields.
	CouchURL string
	// Split CouchDB connection parts (used when CouchURL is empty).
	CouchScheme   string
	CouchHost     string
	CouchPort     string
	CouchUsername string
	CouchPassword string
	// CouchDatabase is the CouchDB database name.
	CouchDatabase string

	// HTTPPort is the port the serve command listens on.
	HTTPPort int
	// PublicBaseURL is the canonical https URL of this service. It is
	// the base of the emailed links and of the callback URL handed to
	// the provider, so it must be reachable from the public internet.
	// Empty defaults to https://<domain>.
	PublicBaseURL string
	// Authority is the GOBL Net address of the registration authority
	// this verifier works for: envelopes must arrive carrying its
	// countersignature, and completed verifications are POSTed back to
	// its inbox.
	Authority string

	// Provider selects the KYB provider implementation.
	Provider string
	// DiditEnvironment is the Didit environment this deployment talks
	// to: "live" or "sandbox". A decision reporting a different
	// environment is refused, so a credential mix-up cannot turn
	// mocked sandbox checks into real endorsements.
	DiditEnvironment string
	// DiditBaseURL is the provider API root.
	DiditBaseURL string
	// DiditAPIKey authenticates API calls (the x-api-key header).
	DiditAPIKey string
	// DiditWorkflowID names the KYB workflow configured in the
	// provider's console.
	DiditWorkflowID string
	// DiditWebhookSecret is the HMAC key for callback signatures.
	DiditWebhookSecret string
	// DiditWebhookSecretPrevious lets a secret rotation overlap: both
	// are accepted while the change propagates.
	DiditWebhookSecretPrevious string
	// DiditWebhookPath is the callback route.
	DiditWebhookPath string
	// DiditTimeout bounds a single provider API call.
	DiditTimeout time.Duration
	// WebhookClockSkew bounds how stale a callback timestamp may be.
	WebhookClockSkew time.Duration

	// SupportedCountries limits which registry countries are accepted.
	// Empty allows every country. Rejecting at the inbox matters: an
	// unsupported jurisdiction discovered later has already been paid
	// for.
	SupportedCountries []string
	// MatchNameThreshold is the similarity floor for the soft legal
	// name axis of the match check.
	MatchNameThreshold float64
	// MatchRequireActive refuses to endorse a company the registry no
	// longer lists as active.
	MatchRequireActive bool

	// PaymentMode gates the (currently unimplemented) payment stage.
	PaymentMode string

	// EndorsementTTL is the lifetime stamped on this verifier's
	// countersignature.
	EndorsementTTL time.Duration
	// KYBResultTTL is how long a completed check may be reused to
	// re-endorse an unchanged set of facts without paying again.
	KYBResultTTL time.Duration
	// SessionTTL is when an untouched open session is swept as
	// abandoned. Never applied to sessions under provider review.
	SessionTTL time.Duration
	// InReviewAlertAfter is when a session still under provider review
	// starts nagging the operators.
	InReviewAlertAfter time.Duration
	// DeclineCooldown is how long a declined address is refused before
	// it may try again.
	DeclineCooldown time.Duration
	// MaxSessionsPerAddress and MaxSessionsWindow cap what a single
	// address can cost.
	MaxSessionsPerAddress int
	MaxSessionsWindow     time.Duration

	// ResyncInterval is the reconciler's tick. Zero disables the
	// in-process loop, leaving the resync command.
	ResyncInterval time.Duration
	// DecisionRetentionDays bounds how long raw provider decisions —
	// which carry personal data about directors and owners — are kept.
	DecisionRetentionDays int
	// OpsAlertEmail receives mismatch, error and stuck-review notices.
	OpsAlertEmail string

	// SMTPHost is the mail submission host. Empty selects the
	// log-only mailer (development).
	SMTPHost string
	// SMTPPort is the mail submission port (STARTTLS is negotiated
	// when the server offers it).
	SMTPPort int
	// SMTPUsername and SMTPPassword configure PLAIN authentication;
	// both empty means an unauthenticated relay.
	SMTPUsername string
	SMTPPassword string
	// EmailFrom is the From header of verification emails, e.g.
	// "GOBL KYB <kyb@gobl.org>". Required when SMTPHost is set.
	EmailFrom string

	// ShutdownTimeout bounds graceful shutdown of the HTTP server.
	ShutdownTimeout time.Duration
	// JSONLogs switches operator logs from text to JSON.
	JSONLogs bool
}

// FromEnv builds a Config from environment variables, applying the
// service defaults. Command flags layer on top of this (flag set →
// overrides env; flag unset → keeps the env/default value).
func FromEnv() Config {
	return Config{
		ConfigDir: Env("CONFIG_DIR", ""),

		CouchURL:      Env("COUCHDB_URL", ""),
		CouchScheme:   Env("COUCHDB_SCHEME", "http"),
		CouchHost:     Env("COUCHDB_HOST", ""),
		CouchPort:     Env("COUCHDB_PORT", "5984"),
		CouchUsername: Env("COUCHDB_USERNAME", "admin"),
		CouchPassword: Env("COUCHDB_PASSWORD", ""),
		CouchDatabase: Env("COUCHDB_DATABASE", "gobl_kyb"),

		HTTPPort:      httpPortFromEnv(),
		PublicBaseURL: Env("PUBLIC_BASE_URL", ""),
		Authority:     Env("AUTHORITY", DefaultAuthority),

		Provider:                   Env("PROVIDER", ProviderDidit),
		DiditEnvironment:           Env("DIDIT_ENVIRONMENT", "live"),
		DiditBaseURL:               Env("DIDIT_BASE_URL", "https://verification.didit.me"),
		DiditAPIKey:                Env("DIDIT_API_KEY", ""),
		DiditWorkflowID:            Env("DIDIT_WORKFLOW_ID", ""),
		DiditWebhookSecret:         Env("DIDIT_WEBHOOK_SECRET", ""),
		DiditWebhookSecretPrevious: Env("DIDIT_WEBHOOK_SECRET_PREVIOUS", ""),
		DiditWebhookPath:           Env("DIDIT_WEBHOOK_PATH", DefaultWebhookPath),
		DiditTimeout:               EnvDuration("DIDIT_TIMEOUT", 20*time.Second),
		WebhookClockSkew:           EnvDuration("WEBHOOK_CLOCK_SKEW", 5*time.Minute),

		SupportedCountries: EnvList("SUPPORTED_COUNTRIES"),
		MatchNameThreshold: EnvFloat("MATCH_NAME_THRESHOLD", 0.90),
		MatchRequireActive: EnvBool("MATCH_REQUIRE_ACTIVE", true),

		PaymentMode: Env("PAYMENT_MODE", PaymentNone),

		EndorsementTTL:        EnvDuration("ENDORSEMENT_TTL", 365*24*time.Hour),
		KYBResultTTL:          EnvDuration("KYB_RESULT_TTL", 365*24*time.Hour),
		SessionTTL:            EnvDuration("SESSION_TTL", 14*24*time.Hour),
		InReviewAlertAfter:    EnvDuration("IN_REVIEW_ALERT_AFTER", 5*24*time.Hour),
		DeclineCooldown:       EnvDuration("DECLINE_COOLDOWN", 90*24*time.Hour),
		MaxSessionsPerAddress: EnvInt("MAX_SESSIONS_PER_ADDRESS", 3),
		MaxSessionsWindow:     EnvDuration("MAX_SESSIONS_WINDOW", 30*24*time.Hour),

		ResyncInterval:        EnvDuration("RESYNC_INTERVAL", 15*time.Minute),
		DecisionRetentionDays: EnvInt("DECISION_RETENTION_DAYS", 1825),
		OpsAlertEmail:         Env("OPS_ALERT_EMAIL", ""),

		SMTPHost:     Env("SMTP_HOST", ""),
		SMTPPort:     EnvInt("SMTP_PORT", 587),
		SMTPUsername: Env("SMTP_USERNAME", ""),
		SMTPPassword: Env("SMTP_PASSWORD", ""),
		EmailFrom:    Env("EMAIL_FROM", ""),

		ShutdownTimeout: 10 * time.Second,
		JSONLogs:        EnvBool("LOG_JSON", false),
	}
}

// Validate reports configuration that would let the service start but
// fail on its first real request — better refused at boot than
// discovered by a customer. It deliberately does not check the identity
// or CouchDB: those fail loudly on their own when loaded.
func (c Config) Validate() error {
	switch c.Provider {
	case ProviderMock:
	case ProviderDidit:
		if c.DiditAPIKey == "" {
			return errors.New("config: DIDIT_API_KEY is required with PROVIDER=didit")
		}
		if c.DiditWorkflowID == "" {
			return errors.New("config: DIDIT_WORKFLOW_ID is required with PROVIDER=didit")
		}
		if c.DiditWebhookSecret == "" {
			return errors.New("config: DIDIT_WEBHOOK_SECRET is required with PROVIDER=didit")
		}
	default:
		return fmt.Errorf("config: unknown PROVIDER %q", c.Provider)
	}

	switch c.DiditEnvironment {
	case "live", "sandbox":
	default:
		return fmt.Errorf("config: DIDIT_ENVIRONMENT must be live or sandbox, got %q", c.DiditEnvironment)
	}

	switch c.PaymentMode {
	case PaymentNone:
	case PaymentSetup, PaymentCharge:
		return fmt.Errorf("config: PAYMENT_MODE %q is not implemented yet", c.PaymentMode)
	default:
		return fmt.Errorf("config: unknown PAYMENT_MODE %q", c.PaymentMode)
	}

	// The provider has to reach the callback, and it will not post to
	// plain HTTP. An http:// base URL is therefore a silently broken
	// deployment: sessions open and never resolve.
	if c.PublicBaseURL != "" && c.Provider != ProviderMock {
		u, err := url.Parse(c.PublicBaseURL)
		if err != nil {
			return fmt.Errorf("config: PUBLIC_BASE_URL is not a URL: %w", err)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("config: PUBLIC_BASE_URL must be https, got %q", c.PublicBaseURL)
		}
	}

	if c.MatchNameThreshold < 0 || c.MatchNameThreshold > 1 {
		return fmt.Errorf("config: MATCH_NAME_THRESHOLD must be between 0 and 1, got %v", c.MatchNameThreshold)
	}
	if c.SMTPHost != "" && c.EmailFrom == "" {
		return errors.New("config: EMAIL_FROM is required when SMTP_HOST is set")
	}
	return nil
}

// WebhookURL is the callback address handed to the provider.
func (c Config) WebhookURL(baseURL string) string {
	return strings.TrimSuffix(baseURL, "/") + c.DiditWebhookPath
}

// CouchDBURL resolves the CouchDB connection URL: the explicit
// CouchURL if set, otherwise one assembled from the split Couch* parts.
// Returns "" when neither a URL nor a host is configured.
func (c Config) CouchDBURL() string {
	if c.CouchURL != "" {
		return c.CouchURL
	}
	if c.CouchHost == "" {
		return ""
	}
	scheme := c.CouchScheme
	if scheme == "" {
		scheme = "http"
	}
	host := c.CouchHost
	if c.CouchPort != "" {
		host = net.JoinHostPort(c.CouchHost, c.CouchPort)
	}
	u := &url.URL{Scheme: scheme, Host: host}
	if c.CouchUsername != "" {
		if c.CouchPassword != "" {
			u.User = url.UserPassword(c.CouchUsername, c.CouchPassword)
		} else {
			u.User = url.User(c.CouchUsername)
		}
	}
	return u.String()
}

// CouchConfig builds a *couch.Config from the resolved connection. The
// database name (COUCHDB_DATABASE) is used as the couch prefix; the
// repos open the single database named by that prefix.
func (c Config) CouchConfig() (*couch.Config, error) {
	raw := c.CouchDBURL()
	if raw == "" {
		return nil, errors.New("config: no CouchDB connection configured")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	cc := &couch.Config{
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   u.Port(),
		Prefix: c.CouchDatabase,
	}
	if cc.Port == "" {
		cc.Port = "5984"
	}
	if u.User != nil {
		cc.Username = u.User.Username()
		if pw, ok := u.User.Password(); ok {
			cc.Password = pw
		}
	}
	return cc, nil
}

// CouchDBRedacted returns the resolved CouchDB URL with any credentials
// stripped — safe for logging.
func (c Config) CouchDBRedacted() string {
	raw := c.CouchDBURL()
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	u.User = nil
	return u.String()
}

// Env returns the value of the environment variable key, or fallback
// when it is unset or empty.
func Env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

// EnvList parses a comma-separated environment variable into a slice,
// trimming whitespace and dropping empty entries.
func EnvList(key string) []string {
	var out []string
	for _, v := range strings.Split(os.Getenv(key), ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// EnvBool parses a boolean environment variable, falling back on unset
// or unparseable values.
func EnvBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}

// EnvInt parses an integer environment variable, falling back on unset
// or unparseable values.
func EnvInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

// EnvFloat parses a floating-point environment variable, falling back
// on unset or unparseable values.
func EnvFloat(key string, fallback float64) float64 {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

// EnvDuration parses a Go duration environment variable ("15m", "72h"),
// falling back on unset or unparseable values. A zero value is
// meaningful for the intervals that use it, so it is accepted.
func EnvDuration(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

// DefaultHTTPPort is the port the server listens on when neither
// HTTP_PORT/PORT nor --http-port is set. 8080 (not 80) so the
// unprivileged container user can bind it without extra capabilities.
const DefaultHTTPPort = 8080

// httpPortFromEnv resolves the listen port from HTTP_PORT, then PORT,
// then DefaultHTTPPort.
func httpPortFromEnv() int {
	for _, key := range []string{"HTTP_PORT", "PORT"} {
		if v, ok := os.LookupEnv(key); ok && v != "" {
			if p, err := strconv.Atoi(v); err == nil {
				return p
			}
		}
	}
	return DefaultHTTPPort
}

package config_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/invopop/gobl.kyb/internal/config"
)

func TestFromEnvReadsCouchParts(t *testing.T) {
	t.Setenv("CONFIG_DIR", "/etc/kyb")
	t.Setenv("COUCHDB_HOST", "couchdb-svc.default")
	t.Setenv("COUCHDB_USERNAME", "kyb")
	t.Setenv("COUCHDB_PASSWORD", "s3cr3t/p@ss")
	t.Setenv("PUBLIC_BASE_URL", "https://kyb.example")

	cfg := config.FromEnv()
	assert.Equal(t, "/etc/kyb", cfg.ConfigDir)
	assert.Equal(t, "gobl_kyb", cfg.CouchDatabase, "default database name")
	assert.Equal(t, "https://kyb.example", cfg.PublicBaseURL)
	assert.Equal(t, config.DefaultAuthority, cfg.Authority, "default authority")

	// Assembled URL uses the defaults for scheme/port and encodes the
	// password's special characters.
	u := cfg.CouchDBURL()
	assert.Equal(t, "http://kyb:s3cr3t%2Fp%40ss@couchdb-svc.default:5984", u)

	// Redacted form drops the credentials — safe for logging.
	assert.Equal(t, "http://couchdb-svc.default:5984", cfg.CouchDBRedacted())
}

func TestFromEnvReadsMail(t *testing.T) {
	t.Setenv("AUTHORITY", "registry.example")
	t.Setenv("SMTP_HOST", "smtp.example")
	t.Setenv("SMTP_PORT", "2525")
	t.Setenv("SMTP_USERNAME", "mailer")
	t.Setenv("SMTP_PASSWORD", "pw")
	t.Setenv("EMAIL_FROM", "KYB <kyb@example.com>")

	cfg := config.FromEnv()
	assert.Equal(t, "registry.example", cfg.Authority)
	assert.Equal(t, "smtp.example", cfg.SMTPHost)
	assert.Equal(t, 2525, cfg.SMTPPort)
	assert.Equal(t, "mailer", cfg.SMTPUsername)
	assert.Equal(t, "pw", cfg.SMTPPassword)
	assert.Equal(t, "KYB <kyb@example.com>", cfg.EmailFrom)
}

func TestCouchURLTakesPrecedence(t *testing.T) {
	cfg := config.Config{
		CouchURL:  "http://admin:pass@localhost:5984",
		CouchHost: "ignored.example",
	}
	assert.Equal(t, "http://admin:pass@localhost:5984", cfg.CouchDBURL())
	assert.Equal(t, "http://localhost:5984", cfg.CouchDBRedacted())
}

func TestCouchDBURLEmptyWithoutHostOrURL(t *testing.T) {
	assert.Empty(t, config.Config{}.CouchDBURL())
	assert.Empty(t, config.Config{}.CouchDBRedacted())
}

func TestCouchDBURLUsernameOnly(t *testing.T) {
	cfg := config.Config{CouchScheme: "https", CouchHost: "db.example", CouchPort: "6984", CouchUsername: "u"}
	assert.Equal(t, "https://u@db.example:6984", cfg.CouchDBURL())
}

func TestHTTPPortPrecedence(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		assert.Equal(t, config.DefaultHTTPPort, config.FromEnv().HTTPPort)
	})
	t.Run("PORT", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		assert.Equal(t, 8080, config.FromEnv().HTTPPort)
	})
	t.Run("HTTP_PORT wins over PORT", func(t *testing.T) {
		t.Setenv("PORT", "8080")
		t.Setenv("HTTP_PORT", "9090")
		assert.Equal(t, 9090, config.FromEnv().HTTPPort)
	})
}

func TestEnvBool(t *testing.T) {
	assert.False(t, config.EnvBool("KYB_MISSING_VAR", false))
	assert.True(t, config.EnvBool("KYB_MISSING_VAR", true))
	t.Setenv("KYB_FLAG", "true")
	assert.True(t, config.EnvBool("KYB_FLAG", false))
	t.Setenv("KYB_FLAG", "0")
	assert.False(t, config.EnvBool("KYB_FLAG", true))
	t.Setenv("KYB_FLAG", "garbage")
	assert.True(t, config.EnvBool("KYB_FLAG", true), "unparseable falls back")
}

func TestEnvInt(t *testing.T) {
	assert.Equal(t, 587, config.EnvInt("KYB_MISSING_VAR", 587))
	t.Setenv("KYB_PORT", "2525")
	assert.Equal(t, 2525, config.EnvInt("KYB_PORT", 587))
	t.Setenv("KYB_PORT", "garbage")
	assert.Equal(t, 587, config.EnvInt("KYB_PORT", 587), "unparseable falls back")
}

func TestEnv(t *testing.T) {
	assert.Equal(t, "fallback", config.Env("KYB_MISSING_VAR", "fallback"))
	t.Setenv("KYB_SET", "value")
	assert.Equal(t, "value", config.Env("KYB_SET", "fallback"))
	t.Setenv("KYB_SET", "")
	assert.Equal(t, "fallback", config.Env("KYB_SET", "fallback"), "empty treated as unset")
}

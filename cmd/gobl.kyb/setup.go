package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/invopop/couch"
	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/config"
	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/delivery"
	"github.com/invopop/gobl.kyb/internal/domain/mailer"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
	"github.com/invopop/gobl.kyb/internal/domain/provider/didit"
	"github.com/invopop/gobl.kyb/internal/domain/provider/mock"
	"github.com/invopop/gobl.kyb/internal/domain/repos"
)

// buildDomain wires the domain setup from configuration: it loads the
// identity, connects to CouchDB, and constructs the verification
// store, GOBL Net client, mailer, and outbound sender. The returned
// cleanup closes the CouchDB connection and must be called by the
// caller.
func buildDomain(ctx context.Context, cfg config.Config) (*domain.Setup, func(), error) {
	id, err := repos.LoadIdentity(cfg.ConfigDir)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}

	authority, err := goblnet.ParseAddress(cfg.Authority)
	if err != nil {
		return nil, nil, gobl.ErrInput.WithReason("invalid authority address %q", cfg.Authority)
	}

	couchConf, err := cfg.CouchConfig()
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}
	client, err := couch.New(couchConf)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(fmt.Errorf("couch client: %w", err))
	}
	if err := client.Ping(ctx); err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(fmt.Errorf("couch ping: %w", err))
	}
	store, err := repos.NewVerifications(ctx, client)
	if err != nil {
		return nil, nil, gobl.ErrInternal.WithCause(err)
	}

	prov, err := buildProvider(cfg)
	if err != nil {
		_ = store.Close()
		return nil, nil, err
	}

	payments, err := domain.NewPaymentGate(cfg.PaymentMode)
	if err != nil {
		_ = store.Close()
		return nil, nil, gobl.ErrInput.WithCause(err)
	}

	setup := domain.New(domain.Deps{
		Identity:      id,
		Verifications: store,
		// The client trusts exactly the configured registration
		// authority; incoming envelopes must carry its countersignature.
		// Client and sender authenticate outbound requests as the
		// verifier itself (bearer request tokens, spec §5.5).
		Client: goblnet.NewClient(
			goblnet.WithIdentity(id.Address(), id.PrivateKey),
			goblnet.WithAuthorities(authority),
		),
		Sender:   delivery.New(id.Address(), id.PrivateKey),
		Mailer:   buildMailer(cfg),
		Provider: prov,
		Payments: payments,
		Options: domain.Options{
			Authority: authority,
			// domain.New defaults this to https://<domain> when empty.
			PublicBaseURL:      strings.TrimRight(cfg.PublicBaseURL, "/"),
			WebhookPath:        cfg.DiditWebhookPath,
			SupportedCountries: cfg.SupportedCountries,
			Match: domain.MatchPolicy{
				NameThreshold:            cfg.MatchNameThreshold,
				RequireActive:            cfg.MatchRequireActive,
				AllowTaxIDAsRegistration: true,
			},
			PaymentMode:           cfg.PaymentMode,
			KYBResultTTL:          cfg.KYBResultTTL,
			SessionTTL:            cfg.SessionTTL,
			DeclineCooldown:       cfg.DeclineCooldown,
			MaxSessionsPerAddress: cfg.MaxSessionsPerAddress,
			MaxSessionsWindow:     cfg.MaxSessionsWindow,
		},
		EndorsementTTL: cfg.EndorsementTTL,
		OpsAlertEmail:  cfg.OpsAlertEmail,
		Logger:         slog.Default(),
	})
	cleanup := func() { _ = store.Close() }
	return setup, cleanup, nil
}

// buildProvider selects the KYB provider implementation.
func buildProvider(cfg config.Config) (provider.Provider, error) {
	switch cfg.Provider {
	case config.ProviderMock:
		// Never in production: config.Validate refuses an http base
		// URL for a real provider, but nothing stops an operator
		// pointing this one at a live deployment, so it says so
		// loudly.
		slog.Warn("using the mock KYB provider: no real checks will be performed (set PROVIDER=didit)")
		return mock.New(), nil
	case config.ProviderDidit:
		return didit.New(didit.Config{
			BaseURL:               cfg.DiditBaseURL,
			APIKey:                cfg.DiditAPIKey,
			WorkflowID:            cfg.DiditWorkflowID,
			WebhookSecret:         cfg.DiditWebhookSecret,
			WebhookSecretPrevious: cfg.DiditWebhookSecretPrevious,
			ClockSkew:             cfg.WebhookClockSkew,
			Timeout:               cfg.DiditTimeout,
		})
	default:
		return nil, gobl.ErrInput.WithReason("unknown provider %q", cfg.Provider)
	}
}

// buildMailer selects the email transport: SMTP when a host is
// configured, otherwise the log-only development mailer.
func buildMailer(cfg config.Config) mailer.Mailer {
	if cfg.SMTPHost == "" {
		slog.Warn("no SMTP host configured: verification emails will only be logged (set SMTP_HOST for real delivery)")
		return mailer.NewLogMailer(slog.Default())
	}
	return mailer.NewSMTP(cfg.SMTPHost, cfg.SMTPPort, cfg.SMTPUsername, cfg.SMTPPassword, cfg.EmailFrom)
}

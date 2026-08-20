package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.kyb/internal/config"
	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/interfaces/web"
)

// reconcileBatch bounds how many cases one reconciliation pass moves,
// so a backlog is drained steadily rather than in one burst against
// the provider's rate limits.
const reconcileBatch = 100

func serveCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the KYB verification HTTP server",
		Long: `Run the KYB verification server. Loads the identity from
--config-dir, connects to CouchDB, and serves the standard GOBL Net
well-known endpoints, the provider callback, and the /status/<token>
page behind the emailed links.

It also runs the reconciler: a periodic sweep that polls the provider
for cases it has stopped sending callbacks about. Callbacks are
retried only twice before the provider gives up, and a case held for
analyst review may produce none at all for days, so without this loop
a verification the customer has already paid for can be silently
lost. Set RESYNC_INTERVAL=0 to run it out of process with the resync
command instead.

Configuration is read from the environment (CONFIG_DIR, COUCHDB_*,
PUBLIC_BASE_URL, AUTHORITY, DIDIT_*, SMTP_*, EMAIL_FROM,
HTTP_PORT/PORT); the flags below override it. Without SMTP_HOST the
emails are logged instead of sent — development only.

NOTE: This binary terminates HTTP only (no built-in TLS). Deploy
behind a reverse proxy that handles TLS termination.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfg.ConfigDir == "" {
				return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
			}
			if cfg.CouchDBURL() == "" {
				return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
			}
			// Refuse a configuration that would start cleanly and then
			// fail on its first real request — a missing API key, a
			// callback URL the provider cannot reach. Those are worth
			// far more as a boot failure than as a customer's stuck
			// verification.
			if err := cfg.Validate(); err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			ctx := cmd.Context()

			setup, cleanup, err := buildDomain(ctx, cfg)
			if err != nil {
				return err
			}
			defer cleanup()

			mux := web.NewMux(setup, slog.Default())

			addr := fmt.Sprintf(":%d", cfg.HTTPPort)
			srv := &http.Server{
				Addr:              addr,
				Handler:           mux,
				ReadHeaderTimeout: 10 * time.Second,
			}

			stopReconciler := startReconciler(ctx, setup, cfg.ResyncInterval)
			defer stopReconciler()

			errCh := make(chan error, 1)
			go func() {
				slog.Info("GOBL KYB listening",
					"addr", addr,
					"domain", string(setup.Identity().Address()),
					"authority", string(setup.Verifications().Authority()),
					"public_base_url", setup.PublicBaseURL(),
					"webhook_path", setup.WebhookPath(),
					"provider", cfg.Provider,
					"payment_mode", cfg.PaymentMode,
					"couchdb", cfg.CouchDBRedacted(),
				)
				errCh <- srv.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				if err != nil && err != http.ErrServerClosed {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			case <-ctx.Done():
				shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
				defer cancel()
				slog.Info("shutting down")
				if err := srv.Shutdown(shutdownCtx); err != nil {
					return gobl.ErrInternal.WithCause(err)
				}
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the verifier identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL, e.g. http://admin:pass@localhost:5984 (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().IntVar(&cfg.HTTPPort, "http-port", cfg.HTTPPort, "HTTP listen port (env HTTP_PORT or PORT)")
	cmd.Flags().StringVar(&cfg.PublicBaseURL, "public-base-url", cfg.PublicBaseURL, "canonical https URL for the emailed links and the provider callback, defaults to https://<domain> (env PUBLIC_BASE_URL)")
	cmd.Flags().StringVar(&cfg.Authority, "authority", cfg.Authority, "registration authority this verifier works for (env AUTHORITY)")
	cmd.Flags().StringVar(&cfg.Provider, "provider", cfg.Provider, "KYB provider: didit or mock (env PROVIDER)")
	cmd.Flags().DurationVar(&cfg.ResyncInterval, "resync-interval", cfg.ResyncInterval, "how often to poll the provider for stalled cases; 0 disables the in-process loop (env RESYNC_INTERVAL)")
	cmd.Flags().StringVar(&cfg.SMTPHost, "smtp-host", cfg.SMTPHost, "SMTP submission host; empty logs emails instead of sending (env SMTP_HOST)")
	cmd.Flags().IntVar(&cfg.SMTPPort, "smtp-port", cfg.SMTPPort, "SMTP submission port (env SMTP_PORT)")
	cmd.Flags().StringVar(&cfg.SMTPUsername, "smtp-username", cfg.SMTPUsername, "SMTP username; empty skips authentication (env SMTP_USERNAME)")
	cmd.Flags().StringVar(&cfg.EmailFrom, "email-from", cfg.EmailFrom, `From header of verification emails, e.g. "GOBL KYB <kyb@gobl.org>" (env EMAIL_FROM)`)
	return cmd
}

// startReconciler runs the reconciliation loop until the context ends,
// returning a function that waits for it to stop.
//
// It is safe to run on every replica. Cases are leased before they are
// worked, and every step it drives — countersigning, delivering,
// applying a provider status — is idempotent, so the worst a race
// costs is a wasted request.
func startReconciler(ctx context.Context, setup *domain.Setup, interval time.Duration) func() {
	if interval <= 0 {
		slog.Warn("reconciler disabled: stalled verifications will only advance when the resync command is run")
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		slog.Info("reconciler started", "interval", interval.String())
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := setup.Verifications().Reconcile(ctx, reconcileBatch)
				if err != nil {
					slog.Warn("reconcile.pass_failed", "error", err.Error())
					continue
				}
				if n > 0 {
					slog.Info("reconcile.pass", "cases", n)
				}
			}
		}
	}()
	return func() { <-done }
}

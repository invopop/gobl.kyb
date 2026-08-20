package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	goblnet "github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/config"
	"github.com/invopop/gobl.kyb/internal/domain"
)

// The operator commands.
//
// A verification service needs these more than most: a case can stall
// on a dropped callback, on an analyst at the provider, or on a
// registry name that does not quite agree with the party's, and none
// of those resolve themselves. Every command that changes a case
// records who ran it and why, because the question people will ask
// about a countersignature years later is not "what did the provider
// say" but "who decided, and on what basis".

// storeFlags adds the connection flags every operator command needs.
func storeFlags(cmd *cobra.Command, cfg *config.Config) {
	cmd.Flags().StringVar(&cfg.ConfigDir, "config-dir", cfg.ConfigDir, "directory holding the verifier identity (env CONFIG_DIR)")
	cmd.Flags().StringVar(&cfg.CouchURL, "couchdb", cfg.CouchURL, "full CouchDB URL (env COUCHDB_URL; overrides the COUCHDB_* parts)")
	cmd.Flags().StringVar(&cfg.CouchDatabase, "couchdb-database", cfg.CouchDatabase, "CouchDB database name (env COUCHDB_DATABASE)")
	cmd.Flags().StringVar(&cfg.Authority, "authority", cfg.Authority, "registration authority (env AUTHORITY)")
}

// withDomain resolves the shared preconditions and builds the domain.
func withDomain(ctx context.Context, cfg config.Config, fn func(*domain.Setup) error) error {
	if cfg.ConfigDir == "" {
		return gobl.ErrInput.WithReason("identity directory required: set --config-dir or CONFIG_DIR")
	}
	if cfg.CouchDBURL() == "" {
		return gobl.ErrInput.WithReason("CouchDB connection required: set --couchdb / COUCHDB_URL, or COUCHDB_HOST (+ COUCHDB_USERNAME / COUCHDB_PASSWORD)")
	}
	setup, cleanup, err := buildDomain(ctx, cfg)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(setup)
}

// mapDomainErr turns a domain error into the CLI's own vocabulary, so
// an operator mistake reads as bad input rather than a crash.
func mapDomainErr(err error) error {
	switch {
	case errors.Is(err, domain.ErrNotFound),
		errors.Is(err, domain.ErrValidation),
		errors.Is(err, domain.ErrForbidden),
		errors.Is(err, domain.ErrConflict):
		return gobl.ErrInput.WithCause(err)
	default:
		return gobl.ErrInternal.WithCause(err)
	}
}

// actor identifies whoever is running the command, for the audit
// trail.
func actor(flag string) string {
	if flag != "" {
		return flag
	}
	if v := os.Getenv("OPERATOR"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return "unknown"
}

func statusCmd() *cobra.Command {
	cfg := config.FromEnv()
	cmd := &cobra.Command{
		Use:   "status <address>",
		Short: "Show the verification case for an address",
		Long: `Print everything known about the verification of <address>: the
pipeline state, the provider session, the decision reference, and the
match report that justified — or blocked — a countersignature.

This is the first thing to run when a customer asks why their identity
is not verified yet.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				rec, err := setup.Verifications().Find(cmd.Context(), addr)
				if err != nil {
					return mapDomainErr(err)
				}
				enc := json.NewEncoder(stdOut(cmd))
				enc.SetIndent("", "  ")
				// The stored envelope dwarfs everything else and is
				// never what the operator is looking at.
				rec.Envelope = nil
				return enc.Encode(rec)
			})
		},
	}
	storeFlags(cmd, &cfg)
	return cmd
}

func resyncCmd() *cobra.Command {
	cfg := config.FromEnv()
	var limit int
	cmd := &cobra.Command{
		Use:   "resync",
		Short: "Poll the provider for cases still waiting on it",
		Long: `Run one reconciliation pass: for every case still waiting on the
provider, fetch its current decision and drive it forward.

The serve command does this on a timer. Running it by hand is for
incidents — a run of dropped callbacks, a provider outage that has
just ended — and for deployments where the in-process loop is turned
off.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				n, err := setup.Verifications().Reconcile(cmd.Context(), limit)
				if err != nil {
					return mapDomainErr(err)
				}
				_, _ = fmt.Fprintf(stdOut(cmd), "reconciled %d case(s)\n", n)
				return nil
			})
		},
	}
	storeFlags(cmd, &cfg)
	cmd.Flags().IntVar(&limit, "limit", 100, "maximum cases to process in this pass")
	return cmd
}

func redeliverCmd() *cobra.Command {
	cfg := config.FromEnv()
	var who string
	cmd := &cobra.Command{
		Use:   "redeliver <address>",
		Short: "Re-deliver an approved verification to the registration authority",
		Long: `Countersign a fresh copy of the stored envelope (iss=<verifier>,
aud=<address>, a long exp) and POST it to the registration authority's
/inbox.

Delivery happens automatically when a verification passes; this is the
recovery path for when it did not land. It is safe to repeat: the
authority treats a redelivery of the same digest as a renewal.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				rec, err := setup.Verifications().Redeliver(cmd.Context(), addr, actor(who))
				if err != nil {
					return mapDomainErr(err)
				}
				_, _ = fmt.Fprintf(stdOut(cmd), "delivered verification of %s to %s (envelope %s)\n",
					addr, setup.Verifications().Authority(), rec.EnvelopeUUID)
				return nil
			})
		},
	}
	storeFlags(cmd, &cfg)
	cmd.Flags().StringVar(&who, "actor", "", "who is running this command (env OPERATOR)")
	return cmd
}

func resendCmd() *cobra.Command {
	cfg := config.FromEnv()
	var who string
	cmd := &cobra.Command{
		Use:   "resend <address>",
		Short: "Re-send the verification link to the party's published address",
		Long: `Email the hosted verification link again.

This never opens a new provider session — it re-sends the link for the
one already paid for — so it is the right answer when a customer says
the email never arrived.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				rec, err := setup.Verifications().Resend(cmd.Context(), addr, actor(who))
				if err != nil {
					return mapDomainErr(err)
				}
				_, _ = fmt.Fprintf(stdOut(cmd), "re-sent the verification link for %s to %s\n", addr, rec.Email)
				return nil
			})
		},
	}
	storeFlags(cmd, &cfg)
	cmd.Flags().StringVar(&who, "actor", "", "who is running this command (env OPERATOR)")
	return cmd
}

func approveCmd() *cobra.Command {
	cfg := config.FromEnv()
	var who, reason string
	cmd := &cobra.Command{
		Use:   "approve <address>",
		Short: "Release a verification held on a legal-name mismatch",
		Long: `Countersign a verification the provider approved but whose legal
name did not match the party's closely enough to pass automatically.

Only a name mismatch can be released this way. A country, identifier
or registry-status failure means the provider verified a different or
unfit company, and no operator judgement turns that into something
this service should sign its name to — those cases are refused here
and must be rejected instead.

A reason is required and is recorded on the case permanently.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			if reason == "" {
				return gobl.ErrInput.WithReason("--reason is required: it is recorded as the justification for the countersignature")
			}
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				rec, err := setup.Verifications().Approve(cmd.Context(), addr, actor(who), reason)
				if err != nil {
					return mapDomainErr(err)
				}
				_, _ = fmt.Fprintf(stdOut(cmd), "approved and delivered verification of %s (envelope %s)\n", addr, rec.EnvelopeUUID)
				return nil
			})
		},
	}
	storeFlags(cmd, &cfg)
	cmd.Flags().StringVar(&who, "actor", "", "who is running this command (env OPERATOR)")
	cmd.Flags().StringVar(&reason, "reason", "", "why this verification is being released (required)")
	return cmd
}

func rejectCmd() *cobra.Command {
	cfg := config.FromEnv()
	var who, reason string
	cmd := &cobra.Command{
		Use:   "reject <address>",
		Short: "Close a verification without countersigning it",
		Long: `Mark a verification as declined. Nothing is countersigned and the
subject is notified that the check could not be completed.

A reason is required and is recorded on the case permanently.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, err := goblnet.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			if reason == "" {
				return gobl.ErrInput.WithReason("--reason is required")
			}
			return withDomain(cmd.Context(), cfg, func(setup *domain.Setup) error {
				if _, err := setup.Verifications().Reject(cmd.Context(), addr, actor(who), reason); err != nil {
					return mapDomainErr(err)
				}
				_, _ = fmt.Fprintf(stdOut(cmd), "rejected verification of %s\n", addr)
				return nil
			})
		},
	}
	storeFlags(cmd, &cfg)
	cmd.Flags().StringVar(&who, "actor", "", "who is running this command (env OPERATOR)")
	cmd.Flags().StringVar(&reason, "reason", "", "why this verification is being rejected (required)")
	return cmd
}

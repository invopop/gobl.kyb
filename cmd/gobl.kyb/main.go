// gobl.kyb is a KYB verification provider for GOBL Net. It accepts
// registered party envelopes on the standard `/inbox` endpoint, runs a
// real business verification through an external provider, checks that
// what the provider verified is actually the party in the envelope,
// and — only then — countersigns that envelope and posts it back to
// the registration authority's `/inbox`. Cases are backed by CouchDB.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"

	"github.com/invopop/gobl.kyb/internal/config"
)

var (
	// Populated at build time via -ldflags.
	version = "dev"
	date    = ""
)

func main() {
	if err := run(); err != nil {
		printError(err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return rootCmd().ExecuteContext(ctx)
}

func rootCmd() *cobra.Command {
	opts := &rootOpts{}
	cmd := &cobra.Command{
		Use:   "gobl.kyb",
		Short: "KYB verification provider for GOBL Net",
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			slog.SetDefault(newLogger(opts.jsonLogs))
			return nil
		},
	}
	cmd.PersistentFlags().BoolVar(&opts.jsonLogs, "json", config.EnvBool("LOG_JSON", false),
		"emit logs as structured JSON on stderr (env LOG_JSON)")
	cmd.AddCommand(initCmd())
	cmd.AddCommand(serveCmd())
	cmd.AddCommand(statusCmd())
	cmd.AddCommand(resyncCmd())
	cmd.AddCommand(redeliverCmd())
	cmd.AddCommand(resendCmd())
	cmd.AddCommand(approveCmd())
	cmd.AddCommand(rejectCmd())
	cmd.AddCommand(versionCmd())
	return cmd
}

type rootOpts struct {
	jsonLogs bool
}

func newLogger(jsonMode bool) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	var h slog.Handler
	if jsonMode {
		h = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		h = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the service version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := struct {
				Version string `json:"version"`
				Core    string `json:"core"`
				Date    string `json:"date,omitempty"`
			}{
				Version: serviceVersion(),
				Core:    coreVersion(),
				Date:    date,
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "\t")
			return enc.Encode(out)
		},
	}
}

func serviceVersion() string {
	if version != "" && version != "dev" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return version
}

func coreVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path != "github.com/invopop/gobl" {
				continue
			}
			if d.Replace != nil && d.Replace.Version != "" {
				return d.Replace.Version
			}
			if d.Version != "" && d.Version != "(devel)" {
				return d.Version
			}
		}
	}
	return string(gobl.VERSION)
}

func printError(err error) {
	var ge *gobl.Error
	if !errors.As(err, &ge) {
		ge = gobl.ErrInternal.WithCause(err)
	}
	attrs := []any{"key", ge.Key().String()}
	if msg := ge.Message(); msg != "" {
		attrs = append(attrs, "message", msg)
	}
	if faults := ge.Faults(); faults != nil {
		attrs = append(attrs, "faults", faults)
	}
	slog.Error("command failed", attrs...)
}

// stdOut is a small shim so the init and operator commands can write
// human-readable output to stdout without going through slog.
func stdOut(cmd *cobra.Command) io.Writer {
	return cmd.OutOrStdout()
}

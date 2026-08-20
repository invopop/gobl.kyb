package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/invopop/gobl"
	"github.com/invopop/gobl/net"

	"github.com/invopop/gobl.kyb/internal/domain/repos"
)

type initOpts struct {
	configDir string
	name      string
	force     bool
}

func initCmd() *cobra.Command {
	opts := &initOpts{}
	cmd := &cobra.Command{
		Use:   "init <domain>",
		Short: "Scaffold a new verifier identity (keypair + party.json)",
		Long: `Generate an ES256 keypair and a party.json template for a new
verifier deployment.  The on-disk layout matches gobl.dev's node
convention:

  <config-dir>/
    private.jwk
    party.json
    keys/<kid>.json

After init, run "gobl.kyb serve" pointing at the same
--config-dir to start the verification service.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, err := net.ParseAddress(args[0])
			if err != nil {
				return gobl.ErrInput.WithCause(err)
			}
			dir := opts.configDir
			if dir == "" {
				dir = defaultConfigDir(string(domain))
			}
			id, err := repos.InitIdentity(repos.ScaffoldOptions{
				Domain:    domain,
				ConfigDir: dir,
				Force:     opts.force,
				PartyName: opts.name,
			})
			if err != nil {
				return gobl.ErrInternal.WithCause(err)
			}
			slog.Info("initialised verifier identity",
				"domain", string(domain),
				"config_dir", dir,
				"kid", id.PrivateKey.ID(),
			)
			_, _ = fmt.Fprintf(stdOut(cmd), "verifier identity created at %s\n", dir)
			return nil
		},
	}
	cmd.Flags().StringVar(&opts.configDir, "config-dir", "", "base directory for the verifier identity (default ~/.config/gobl.kyb/<domain>)")
	cmd.Flags().StringVar(&opts.name, "name", "", "party name to seed into party.json")
	cmd.Flags().BoolVarP(&opts.force, "force", "f", false, "overwrite an existing non-empty directory")
	return cmd
}

// defaultConfigDir resolves the standard XDG-style config path for
// the verifier binary. If $HOME is unavailable (e.g. some
// containers), falls back to a relative path under the cwd so the
// command never panics.
func defaultConfigDir(domain string) string {
	home, err := os.UserConfigDir()
	if err != nil || home == "" {
		return filepath.Join(".config", "gobl.kyb", domain)
	}
	return filepath.Join(home, "gobl.kyb", domain)
}

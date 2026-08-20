package repos

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/invopop/gobl/cal"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb/internal/domain/models"
)

// The identity is loaded from and scaffolded onto disk. The on-disk
// layout matches gobl.dev's node convention so operators get a
// familiar mental model:
//
//	~/.config/gobl.kyb/
//	├── private.jwk        active signing key (mode 0600)
//	├── party.json         the verifier's own org.Party (served at /who)
//	└── keys/<kid>.json    each published JWK (served at /keys/<kid>)
const (
	PrivateKeyFile = "private.jwk"
	PartyFile      = "party.json"
	KeysDirName    = "keys"
)

// LoadIdentity reads an identity from configDir. Returns an error if
// the directory is missing or any required file is absent / malformed.
func LoadIdentity(configDir string) (*models.Identity, error) {
	id := new(models.Identity)

	// Domain is derived from the party's first `gobl:` endpoint
	// (single-tenant is the common case).
	pdata, err := os.ReadFile(filepath.Join(configDir, PartyFile))
	if err != nil {
		return nil, fmt.Errorf("repos: read party.json: %w", err)
	}
	id.Party = new(org.Party)
	if err := json.Unmarshal(pdata, id.Party); err != nil {
		return nil, fmt.Errorf("repos: parse party.json: %w", err)
	}
	ep := id.Party.Endpoint(net.Scheme)
	if ep == nil {
		return nil, errors.New("repos: party.json has no gobl: endpoint — set one before serving")
	}
	addr, err := net.ParseAddress(ep.URI.Opaque())
	if err != nil {
		return nil, fmt.Errorf("repos: party gobl endpoint %q is not a valid address: %w", ep.URI, err)
	}
	id.Domain = addr

	pkdata, err := os.ReadFile(filepath.Join(configDir, PrivateKeyFile))
	if err != nil {
		return nil, fmt.Errorf("repos: read private.jwk: %w", err)
	}
	id.PrivateKey = new(dsig.PrivateKey)
	if err := json.Unmarshal(pkdata, id.PrivateKey); err != nil {
		return nil, fmt.Errorf("repos: parse private.jwk: %w", err)
	}
	if err := id.PrivateKey.Validate(); err != nil {
		return nil, fmt.Errorf("repos: private.jwk invalid: %w", err)
	}

	keys, err := loadKeys(filepath.Join(configDir, KeysDirName))
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("repos: no published keys found under keys/")
	}
	// The active private key's kid MUST appear in the published set.
	found := false
	for _, k := range keys {
		if k.ID() == id.PrivateKey.ID() {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("repos: active private.jwk kid %q is not in keys/", id.PrivateKey.ID())
	}
	id.PublicKeys = keys

	return id, nil
}

// ScaffoldOptions configure InitIdentity.
type ScaffoldOptions struct {
	Domain    net.Address
	ConfigDir string
	Force     bool   // overwrite existing files
	PartyName string // optional name to seed into party.json
}

// InitIdentity scaffolds a fresh identity directory: generates an
// ES256 keypair, writes private.jwk (0600) and keys/<kid>.json with
// valid_from=now, and writes a party.json template carrying the
// gobl:<domain> endpoint.
func InitIdentity(opts ScaffoldOptions) (*models.Identity, error) {
	if opts.Domain == "" {
		return nil, errors.New("repos: InitIdentity requires a Domain")
	}
	if err := opts.Domain.Validate(); err != nil {
		return nil, fmt.Errorf("repos: %w", err)
	}
	if opts.ConfigDir == "" {
		return nil, errors.New("repos: InitIdentity requires a ConfigDir")
	}

	if !opts.Force {
		if entries, _ := os.ReadDir(opts.ConfigDir); len(entries) > 0 {
			return nil, fmt.Errorf("repos: %s already exists and is not empty (use Force to overwrite)", opts.ConfigDir)
		}
	}
	if err := os.MkdirAll(filepath.Join(opts.ConfigDir, KeysDirName), 0o700); err != nil {
		return nil, fmt.Errorf("repos: create dirs: %w", err)
	}

	priv := dsig.NewES256Key()
	pub := priv.Public()
	// Floor valid_from to the second: signature `iat` claims carry
	// whole seconds, so a sub-second valid_from would reject a
	// signature made within the same second the key was generated.
	from := cal.TimestampOf(time.Now().UTC().Truncate(time.Second))
	pub.ValidFrom = &from

	if err := writeJSON(filepath.Join(opts.ConfigDir, PrivateKeyFile), priv, 0o600); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(opts.ConfigDir, KeysDirName, pub.ID()+".json"), pub, 0o644); err != nil {
		return nil, err
	}

	party := &org.Party{
		Endpoints: []*org.Endpoint{{URI: opts.Domain.URI()}},
	}
	if opts.PartyName != "" {
		party.Name = opts.PartyName
	}
	if err := writeJSON(filepath.Join(opts.ConfigDir, PartyFile), party, 0o644); err != nil {
		return nil, err
	}

	return LoadIdentity(opts.ConfigDir)
}

func loadKeys(dir string) ([]*dsig.PublicKey, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("repos: read keys dir: %w", err)
	}
	out := make([]*dsig.PublicKey, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("repos: read keys/%s: %w", e.Name(), err)
		}
		pk := new(dsig.PublicKey)
		if err := json.Unmarshal(data, pk); err != nil {
			return nil, fmt.Errorf("repos: parse keys/%s: %w", e.Name(), err)
		}
		// The kid is taken from the JWK itself; the filename is only a
		// convention (Init writes <kid>.json), so any *.json is accepted.
		// This lets deployments mount the key at a fixed path without
		// having to encode the kid in the filename.
		if pk.ID() == "" {
			return nil, fmt.Errorf("repos: keys/%s has no kid", e.Name())
		}
		out = append(out, pk)
	}
	return out, nil
}

func writeJSON(path string, v any, mode os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("repos: marshal %s: %w", path, err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("repos: write %s: %w", path, err)
	}
	return nil
}

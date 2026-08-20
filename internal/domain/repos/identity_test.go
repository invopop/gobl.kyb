package repos_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl.kyb/internal/domain/repos"
)

func TestInitRoundTrip(t *testing.T) {
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
		PartyName: "Lookup Service",
	})
	require.NoError(t, err)
	assert.Equal(t, net.Address("lookup.example"), id.Address())
	assert.Equal(t, cbc.URI("gobl:lookup.example"), id.URI())
	assert.NotNil(t, id.PrivateKey)
	assert.Len(t, id.PublicKeys, 1)
	assert.Equal(t, "Lookup Service", id.Party.Name)

	// Reload from disk; should recover the same identity.
	id2, err := repos.LoadIdentity(dir)
	require.NoError(t, err)
	assert.Equal(t, id.PrivateKey.ID(), id2.PrivateKey.ID())
	assert.Equal(t, id.Domain, id2.Domain)
}

func TestInitRejectsExistingDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker"), []byte("hi"), 0o644))
	_, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists and is not empty")
}

func TestInitForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "marker"), []byte("hi"), 0o644))
	_, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
		Force:     true,
	})
	require.NoError(t, err)
}

func TestInitRejectsInvalidDomain(t *testing.T) {
	dir := t.TempDir()
	_, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("not a domain"),
		ConfigDir: dir,
	})
	require.Error(t, err)
}

func TestLoadMissingPartyFails(t *testing.T) {
	dir := t.TempDir()
	_, err := repos.LoadIdentity(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read party.json")
}

func TestLoadRejectsPartyWithoutGoblEndpoint(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, repos.KeysDirName), 0o755))
	party := &org.Party{
		Endpoints: []*org.Endpoint{{URI: cbc.URI("mailto:x@y.example")}},
	}
	data, _ := json.Marshal(party)
	require.NoError(t, os.WriteFile(filepath.Join(dir, repos.PartyFile), data, 0o644))

	_, err := repos.LoadIdentity(dir)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no gobl: endpoint")
}

func TestLoadAcceptsAnyKeyFilename(t *testing.T) {
	// The key file need not be named after its kid; the kid comes from the
	// JWK content, so a deployment can mount it at a fixed path.
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	kid := id.PrivateKey.ID()
	keysDir := filepath.Join(dir, repos.KeysDirName)
	require.NoError(t, os.Rename(
		filepath.Join(keysDir, kid+".json"),
		filepath.Join(keysDir, "public.json"),
	))

	id2, err := repos.LoadIdentity(dir)
	require.NoError(t, err)
	assert.NotNil(t, id2.FindKey(kid), "key still loaded, keyed by its JWK kid")
}

func TestFindKey(t *testing.T) {
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)
	require.NotNil(t, id.FindKey(id.PrivateKey.ID()))
	assert.Nil(t, id.FindKey("missing"))
}

func TestJWKSContainsPublishedKeys(t *testing.T) {
	dir := t.TempDir()
	id, err := repos.InitIdentity(repos.ScaffoldOptions{
		Domain:    net.Address("lookup.example"),
		ConfigDir: dir,
	})
	require.NoError(t, err)

	data, err := id.JWKS()
	require.NoError(t, err)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(data, &set))
	require.Len(t, set.Keys, 1)
}

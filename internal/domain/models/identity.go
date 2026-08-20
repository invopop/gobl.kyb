package models

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/dsig"
	"github.com/invopop/gobl/net"
	"github.com/invopop/gobl/org"
)

// Identity holds this verifier's signing identity, its advertised
// party, and every public key it has ever published
// (active + retired). It is loaded from disk by repos.Identity and
// wrapped by the domain.Identity service, which adds the signing
// behaviour (countersigning, party envelopes).
type Identity struct {
	// Domain is the verifier's GOBL Net address (e.g. "kyb.gobl.org").
	Domain net.Address
	// PrivateKey is the active signing key. Its kid MUST appear in
	// PublicKeys.
	PrivateKey *dsig.PrivateKey
	// PublicKeys are every key this verifier has published, served at
	// /.well-known/gobl/keys/<kid> and aggregated at /.well-known/jwks.json.
	PublicKeys []*dsig.PublicKey
	// Party is the verifier's own org.Party served at
	// /.well-known/gobl/who.
	// Stored unsigned on disk; signed once at first serve.
	Party *org.Party
}

// Address returns the verifier's address.
func (i *Identity) Address() net.Address { return i.Domain }

// URI returns the gobl: scheme form of the verifier's address, for
// multi-scheme contexts such as org.Endpoint lists. Signed claims
// carry the bare address instead.
func (i *Identity) URI() cbc.URI { return i.Domain.URI() }

// FindKey returns the public key whose kid matches, or nil.
func (i *Identity) FindKey(kid string) *dsig.PublicKey {
	for _, k := range i.PublicKeys {
		if k.ID() == kid {
			return k
		}
	}
	return nil
}

// JWKS marshals the published keys into a single RFC 7517 JWK Set
// document, newest first (sorted by ValidFrom descending; keys with
// no ValidFrom sort last). Used by the /.well-known/jwks.json
// handler.
func (i *Identity) JWKS() ([]byte, error) {
	type set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	out := set{Keys: make([]json.RawMessage, 0, len(i.PublicKeys))}
	keys := append([]*dsig.PublicKey(nil), i.PublicKeys...)
	sort.SliceStable(keys, func(a, b int) bool {
		ka, kb := keys[a], keys[b]
		switch {
		case ka.ValidFrom != nil && kb.ValidFrom != nil:
			if !ka.ValidFrom.Equal(kb.ValidFrom.Time) {
				return ka.ValidFrom.After(kb.ValidFrom.Time)
			}
		case ka.ValidFrom != nil && kb.ValidFrom == nil:
			return true
		case ka.ValidFrom == nil && kb.ValidFrom != nil:
			return false
		}
		return ka.ID() > kb.ID()
	})
	for _, k := range keys {
		b, err := json.Marshal(k)
		if err != nil {
			return nil, fmt.Errorf("models: marshal jwks entry: %w", err)
		}
		out.Keys = append(out.Keys, b)
	}
	return json.Marshal(out)
}

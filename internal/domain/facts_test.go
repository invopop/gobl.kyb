package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl/cbc"
	"github.com/invopop/gobl/l10n"
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/tax"

	"github.com/invopop/gobl.kyb/internal/domain"
)

func party(mods ...func(*org.Party)) *org.Party {
	p := &org.Party{
		Name:   "Acme Widgets SL",
		TaxID:  &tax.Identity{Country: "ES", Code: "B12345674"},
		Emails: []*org.Email{{Address: "finance@acme.example"}},
	}
	for _, m := range mods {
		m(p)
	}
	return p
}

func TestSubjectFactsFromParty(t *testing.T) {
	t.Run("derives from the tax identity", func(t *testing.T) {
		f, err := domain.SubjectFactsFrom(party())
		require.NoError(t, err)
		assert.Equal(t, "Acme Widgets SL", f.LegalName)
		assert.Equal(t, l10n.Code("ES"), f.Country)
		assert.Equal(t, "B12345674", f.TaxCode)
		assert.Equal(t, "B12345674", f.RegistrationNumber)
		assert.Equal(t, domain.NumberSourceTaxID, f.NumberSource,
			"a VAT number is not a registry number and must be flagged as a fallback")
	})

	t.Run("prefers a legal-scope identity for the registration number", func(t *testing.T) {
		f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
			p.Identities = []*org.Identity{
				{Scope: org.IdentityScopeLegal, Country: "ES", Code: "M-123456"},
			}
		}))
		require.NoError(t, err)
		assert.Equal(t, "M123456", f.RegistrationNumber)
		assert.Equal(t, domain.NumberSourceLegal, f.NumberSource)
		assert.Equal(t, "B12345674", f.TaxCode, "the tax code is still carried for matching")
	})

	t.Run("normalises identifiers", func(t *testing.T) {
		f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
			p.TaxID = &tax.Identity{Country: "ES", Code: "ES B-1234567-4"}
		}))
		require.NoError(t, err)
		assert.Equal(t, "B12345674", f.TaxCode,
			"punctuation and a redundant country prefix must not change the identifier")
	})

	t.Run("rejects a party with no legal name", func(t *testing.T) {
		_, err := domain.SubjectFactsFrom(party(func(p *org.Party) { p.Name = "" }))
		require.ErrorContains(t, err, "legal name")
	})

	t.Run("rejects a party with no identifiers at all", func(t *testing.T) {
		_, err := domain.SubjectFactsFrom(party(func(p *org.Party) { p.TaxID = nil }))
		require.Error(t, err,
			"without a country there is no registry to query, and a paid check could only fail")
	})

	t.Run("does not fall back to the postal address for the country", func(t *testing.T) {
		_, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
			p.TaxID = nil
			p.Addresses = []*org.Address{{Country: "DE", Locality: "Berlin"}}
		}))
		require.Error(t, err,
			"a postal address is not evidence of which registry holds the company")
	})

	t.Run("ignores the trading alias", func(t *testing.T) {
		f, err := domain.SubjectFactsFrom(party(func(p *org.Party) { p.Alias = "Acme" }))
		require.NoError(t, err)
		assert.Equal(t, "Acme Widgets SL", f.LegalName,
			"a registry lookup on a trading name finds nothing")
	})

	t.Run("ignores the Spanish registry inscription", func(t *testing.T) {
		f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
			p.Registration = &org.Registration{Office: "Madrid", Book: "1234", Sheet: "M-99"}
		}))
		require.NoError(t, err)
		assert.Equal(t, "B12345674", f.RegistrationNumber,
			"org.Registration identifies an entry in a register, not a company")
	})
}

// Greece and Northern Ireland file taxes under codes that are not ISO
// country codes. A KYB provider indexes registries by ISO, so getting
// this wrong means querying the wrong registry — or none — for two
// whole jurisdictions.
func TestSubjectFactsNormalisesTaxOnlyCountryCodes(t *testing.T) {
	tests := []struct {
		name string
		tax  l10n.TaxCountryCode
		want l10n.Code
	}{
		{"Greece files under EL", "EL", "GR"},
		{"Northern Ireland files under XI", "XI", "GB"},
		{"Great Britain files under XU", "XU", "GB"},
		{"an ISO code passes through", "DE", "DE"},
		{"Greece's own ISO code passes through", "GR", "GR"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
				p.TaxID = &tax.Identity{Country: tt.tax, Code: "123456789"}
			}))
			require.NoError(t, err)
			assert.Equal(t, tt.want, f.Country)
		})
	}

	t.Run("the EU code names no registry", func(t *testing.T) {
		_, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
			p.TaxID = &tax.Identity{Country: "EU", Code: "123456789"}
		}))
		require.ErrorContains(t, err, "no ISO equivalent")
	})
}

// The facts hash is what decides whether a re-submission costs money.
// The authority drops a party's verifier claim on any envelope change
// at all, so parties come back here after edits that have nothing to
// do with the company — and each one that is treated as new is another
// paid check.
func TestFactsHashIgnoresChangesThatAreNotVerifiable(t *testing.T) {
	base, err := domain.SubjectFactsFrom(party())
	require.NoError(t, err)

	unchanged := []struct {
		name string
		mod  func(*org.Party)
	}{
		{"a new phone number", func(p *org.Party) {
			p.Telephones = []*org.Telephone{{Number: "+34 600 000 000"}}
		}},
		{"a corrected postal address", func(p *org.Party) {
			p.Addresses = []*org.Address{{Country: "ES", Locality: "Barcelona"}}
		}},
		{"a different contact email", func(p *org.Party) {
			p.Emails = []*org.Email{{Address: "billing@acme.example"}}
		}},
		{"a website", func(p *org.Party) {
			p.Websites = []*org.Website{{URL: "https://acme.example"}}
		}},
		{"a trading alias", func(p *org.Party) { p.Alias = "Acme" }},
	}
	for _, tt := range unchanged {
		t.Run(tt.name+" does not buy a new check", func(t *testing.T) {
			f, err := domain.SubjectFactsFrom(party(tt.mod))
			require.NoError(t, err)
			assert.Equal(t, base.Hash(), f.Hash())
		})
	}

	changed := []struct {
		name string
		mod  func(*org.Party)
	}{
		{"a different legal name", func(p *org.Party) { p.Name = "Acme Holdings SL" }},
		{"a different tax code", func(p *org.Party) {
			p.TaxID = &tax.Identity{Country: "ES", Code: "B87654323"}
		}},
		{"a different country", func(p *org.Party) {
			p.TaxID = &tax.Identity{Country: "DE", Code: "B12345674"}
		}},
		{"a newly published registry number", func(p *org.Party) {
			p.Identities = []*org.Identity{
				{Scope: org.IdentityScopeLegal, Country: "ES", Code: "M123456"},
			}
		}},
	}
	for _, tt := range changed {
		t.Run(tt.name+" requires a new check", func(t *testing.T) {
			f, err := domain.SubjectFactsFrom(party(tt.mod))
			require.NoError(t, err)
			assert.NotEqual(t, base.Hash(), f.Hash())
		})
	}
}

func TestFactsHashIsStable(t *testing.T) {
	a, err := domain.SubjectFactsFrom(party())
	require.NoError(t, err)
	b, err := domain.SubjectFactsFrom(party())
	require.NoError(t, err)
	assert.Equal(t, a.Hash(), b.Hash())
	assert.Len(t, a.Hash(), 64)
}

func TestSubjectFactsIgnoresNonLegalIdentities(t *testing.T) {
	f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
		p.Identities = []*org.Identity{
			{Key: cbc.Key("duns"), Code: "123456789"},
		}
	}))
	require.NoError(t, err)
	assert.Equal(t, domain.NumberSourceTaxID, f.NumberSource,
		"a D-U-N-S is a Dun & Bradstreet number, not a company registry number")
}

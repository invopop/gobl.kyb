package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/invopop/gobl/org"

	"github.com/invopop/gobl.kyb/internal/domain"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

func expectedFacts() domain.SubjectFacts {
	f, err := domain.SubjectFactsFrom(party())
	if err != nil {
		panic(err)
	}
	return f
}

func ptr[T any](v T) *T { return &v }

func registry(mods ...func(*provider.CompanyRecord)) provider.CompanyRecord {
	c := provider.CompanyRecord{
		LegalName:          "Acme Widgets SL",
		Country:            "ES",
		RegistrationNumber: "B12345674",
		TaxCode:            "ESB12345674",
		Status:             "Active",
		Active:             ptr(true),
	}
	for _, m := range mods {
		m(&c)
	}
	return c
}

func TestMatchPassesOnAnExactCompany(t *testing.T) {
	r := domain.Match(expectedFacts(), registry(), domain.DefaultMatchPolicy())
	require.True(t, r.Passed, "reasons: %v", r.Reasons)
	assert.NotEmpty(t, r.MatchedOn)
	assert.False(t, r.Reviewable)
}

// The hard axes. A failure on any of these means the provider verified
// a different company, or one nobody should accept documents from, and
// no operator judgement should be able to turn it into a signature.
func TestMatchRefusesADifferentCompany(t *testing.T) {
	tests := []struct {
		name     string
		observed provider.CompanyRecord
		axis     domain.MatchAxis
	}{
		{
			name:     "a different registry country",
			observed: registry(func(c *provider.CompanyRecord) { c.Country = "PT" }),
			axis:     domain.MatchAxisCountry,
		},
		{
			name: "a different registration number",
			observed: registry(func(c *provider.CompanyRecord) {
				c.RegistrationNumber = "B98765431"
				c.TaxCode = "ESB98765431"
			}),
			axis: domain.MatchAxisIdentifier,
		},
		{
			name: "no identifiers at all",
			observed: registry(func(c *provider.CompanyRecord) {
				c.RegistrationNumber = ""
				c.TaxCode = ""
			}),
			axis: domain.MatchAxisIdentifier,
		},
		{
			name: "a conflicting legal form",
			observed: registry(func(c *provider.CompanyRecord) {
				c.LegalName = "Acme Widgets SA"
			}),
			axis: domain.MatchAxisLegalForm,
		},
		{
			name: "a dissolved company",
			observed: registry(func(c *provider.CompanyRecord) {
				c.Status = "Dissolved"
				c.Active = ptr(false)
			}),
			axis: domain.MatchAxisStatus,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := domain.Match(expectedFacts(), tt.observed, domain.DefaultMatchPolicy())
			require.False(t, r.Passed)
			assert.Contains(t, r.Failures, tt.axis)
			assert.False(t, r.Reviewable,
				"a hard failure must never be releasable by an operator")
			assert.NotEmpty(t, r.Reasons)
		})
	}
}

// The soft axis. Legal names drift between registries,
// transliterations and abbreviations, so a name miss holds the case
// for a human rather than declining it — auto-declining would burn the
// customer's money on a check that actually succeeded.
func TestMatchHoldsANameMismatchForReview(t *testing.T) {
	r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
		c.LegalName = "Totally Different Company SL"
	}), domain.DefaultMatchPolicy())

	require.False(t, r.Passed)
	assert.Equal(t, []domain.MatchAxis{domain.MatchAxisName}, r.Failures)
	assert.True(t, r.Reviewable, "a name-only miss is the one an operator may release")
}

func TestMatchToleratesCosmeticNameDifferences(t *testing.T) {
	tests := []struct {
		name     string
		observed string
	}{
		{"case", "ACME WIDGETS SL"},
		{"punctuation in the legal form", "Acme Widgets, S.L."},
		{"a comma", "Acme Widgets, SL"},
		{"extra whitespace", "Acme   Widgets  SL"},
		{"an accent the registry does not carry", "Ácme Widgets SL"},
		{"no legal form at all", "Acme Widgets"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
				c.LegalName = tt.observed
			}), domain.DefaultMatchPolicy())
			assert.True(t, r.Passed, "reasons: %v (score %.3f)", r.Reasons, r.NameScore)
		})
	}
}

func TestMatchAcceptsAnAlternativeRegistryName(t *testing.T) {
	r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
		c.LegalName = "Sociedad Anonima Antigua SL"
		c.AlternativeNames = []string{"Acme Widgets SL"}
	}), domain.DefaultMatchPolicy())
	assert.True(t, r.Passed, "a former or trading name recorded by the registry still identifies the company; reasons: %v", r.Reasons)
}

func TestMatchNormalisesIdentifiersOnBothSides(t *testing.T) {
	r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
		c.RegistrationNumber = "B-1234567-4"
		c.TaxCode = ""
		c.VATNumber = "ES B12345674"
	}), domain.DefaultMatchPolicy())
	assert.True(t, r.Passed, "reasons: %v", r.Reasons)
}

func TestMatchAcceptsATaxOnlyCountryCodeFromTheProvider(t *testing.T) {
	f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
		p.TaxID.Country = "EL"
		p.TaxID.Code = "123456789"
	}))
	require.NoError(t, err)

	r := domain.Match(f, provider.CompanyRecord{
		LegalName:          "Acme Widgets SL",
		Country:            "EL", // the provider echoed the tax form
		RegistrationNumber: "123456789",
		Status:             "Active",
		Active:             ptr(true),
	}, domain.DefaultMatchPolicy())
	assert.True(t, r.Passed, "both sides must be normalised before comparison; reasons: %v", r.Reasons)
}

// "Not stated" is not "not active". A registry that declines to report
// a status must not cause a good company to be refused.
func TestMatchAcceptsAnUnknownRegistryStatus(t *testing.T) {
	r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
		c.Status = ""
		c.Active = nil
	}), domain.DefaultMatchPolicy())
	assert.True(t, r.Passed, "reasons: %v", r.Reasons)
}

func TestMatchAllowsATruncatedNameOnlyWithAnIdentifierHit(t *testing.T) {
	t.Run("with an identifier hit", func(t *testing.T) {
		r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
			c.LegalName = "Acme Widgets Europe Holdings SL"
		}), domain.DefaultMatchPolicy())
		assert.True(t, r.Passed, "reasons: %v (score %.3f)", r.Reasons, r.NameScore)
	})

	t.Run("without one", func(t *testing.T) {
		r := domain.Match(expectedFacts(), registry(func(c *provider.CompanyRecord) {
			c.LegalName = "Acme Widgets Europe Holdings SL"
			c.RegistrationNumber = "B98765431"
			c.TaxCode = "ESB98765431"
			c.VATNumber = ""
		}), domain.DefaultMatchPolicy())
		require.False(t, r.Passed)
		assert.Contains(t, r.Failures, domain.MatchAxisIdentifier,
			"a name relationship is far too weak to identify a company on its own")
	})
}

func TestMatchRefusesATaxIDPosingAsARegistryNumber(t *testing.T) {
	f, err := domain.SubjectFactsFrom(party(func(p *org.Party) {
		p.Identities = []*org.Identity{
			{Scope: org.IdentityScopeLegal, Country: "ES", Code: "M123456"},
		}
	}))
	require.NoError(t, err)

	r := domain.Match(f, registry(func(c *provider.CompanyRecord) {
		// The registry returns a different registration number but the
		// same tax code — enough to match on the tax axis.
		c.RegistrationNumber = "M999999"
	}), domain.DefaultMatchPolicy())
	assert.True(t, r.Passed,
		"a tax-code hit is still an exact identifier match; reasons: %v", r.Reasons)

	r2 := domain.Match(f, registry(func(c *provider.CompanyRecord) {
		c.RegistrationNumber = "M999999"
		c.TaxCode = "ESB98765431"
		c.VATNumber = ""
	}), domain.DefaultMatchPolicy())
	require.False(t, r2.Passed)
	assert.Contains(t, r2.Failures, domain.MatchAxisIdentifier)
}

func TestMatchRecordsBothSidesForTheAuditTrail(t *testing.T) {
	observed := registry(func(c *provider.CompanyRecord) { c.LegalName = "Something Else SL" })
	r := domain.Match(expectedFacts(), observed, domain.DefaultMatchPolicy())
	assert.Equal(t, expectedFacts(), r.Expected)
	assert.Equal(t, observed, r.Observed)
	assert.Greater(t, r.NameScore, 0.0)
}

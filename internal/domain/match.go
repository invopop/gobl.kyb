package domain

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/invopop/gobl/l10n"

	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// The match check is what makes this service's countersignature worth
// anything.
//
// A provider verifies *a company somebody searched for*. Nothing in a
// hosted verification flow forces that to be the company named in the
// envelope we were asked to endorse: the pre-filled search fields stay
// editable, and a human analyst may correct them during review. So an
// APPROVED decision is evidence that some real, active legal entity was
// checked — not evidence that it was *this* one. Establishing that is
// our job, not the provider's, and it happens here.
//
// The policy is deliberately asymmetric. Identifiers are hard: a
// registry number either matches or it does not, and a miss means we
// are looking at a different company. Names are soft: legal names drift
// between registries, transliterations and abbreviations, so a name
// miss holds the case for a human instead of declining it. Auto-
// declining on a fuzzy name would burn the customer's money on a check
// that actually succeeded.

// MatchAxis names one of the checks in a Report.
type MatchAxis string

// The axes of a match, in the order they are evaluated.
const (
	MatchAxisCountry    MatchAxis = "country"
	MatchAxisIdentifier MatchAxis = "identifier"
	MatchAxisLegalForm  MatchAxis = "legal_form"
	MatchAxisName       MatchAxis = "name"
	MatchAxisStatus     MatchAxis = "status"
)

// MatchPolicy holds the tunable parts of the check.
type MatchPolicy struct {
	// NameThreshold is the similarity floor, between 0 and 1, above
	// which two legal names are considered the same company.
	NameThreshold float64
	// RequireActive refuses to endorse a company the registry no
	// longer lists as active. A dissolved company that "matches" is
	// still not one anybody should accept documents from.
	RequireActive bool
	// AllowTaxIDAsRegistration lets an observed registration number
	// match a tax code we only have because the party published no
	// legal identity. Some registries return the tax number in that
	// field.
	AllowTaxIDAsRegistration bool
}

// DefaultMatchPolicy returns the policy used when none is configured.
func DefaultMatchPolicy() MatchPolicy {
	return MatchPolicy{
		NameThreshold:            0.90,
		RequireActive:            true,
		AllowTaxIDAsRegistration: true,
	}
}

// MatchReport records what was compared and what was concluded. It is
// persisted on every outcome, pass or fail: a countersignature is a
// public claim, and "why did you attest to this?" has to be answerable
// years later.
type MatchReport struct {
	// Passed reports whether the observed company may be endorsed as
	// the subject.
	Passed bool `json:"passed"`
	// Failures lists the axes that did not pass, in evaluation order.
	Failures []MatchAxis `json:"failures,omitempty"`
	// Reasons explains each failure in words, for the operator.
	Reasons []string `json:"reasons,omitempty"`
	// Reviewable reports whether an operator may reasonably override
	// the result. Only a name miss is: a country, identifier or status
	// failure means a different or unfit company, which no amount of
	// human confidence should turn into a signature.
	Reviewable bool `json:"reviewable"`
	// NameScore is the similarity of the two legal names, 0 to 1.
	NameScore float64 `json:"name_score"`
	// Expected and Observed record the two sides of the comparison.
	Expected SubjectFacts           `json:"expected"`
	Observed provider.CompanyRecord `json:"observed"`
	// MatchedOn names the identifier comparison that succeeded.
	MatchedOn string `json:"matched_on,omitempty"`
}

// fail records a failed axis on the report.
func (r *MatchReport) fail(axis MatchAxis, format string, args ...any) {
	r.Failures = append(r.Failures, axis)
	r.Reasons = append(r.Reasons, fmt.Sprintf(format, args...))
}

// Match compares the company a provider says it verified against the
// facts derived from the party we were asked to endorse. It is a pure
// function: no clock, no network, no store — so the policy can be
// reviewed and table-tested on its own.
func Match(expected SubjectFacts, observed provider.CompanyRecord, p MatchPolicy) MatchReport {
	r := MatchReport{Expected: expected, Observed: observed}

	// Country — hard, exact. The registry country decides which
	// registry was queried; a different one is a different company by
	// construction, whatever the numbers look like.
	obsCountry, err := isoCountry(observed.Country)
	switch {
	case err != nil:
		r.fail(MatchAxisCountry, "provider returned an unusable registry country %q: %v", observed.Country, err)
	case obsCountry != expected.Country:
		r.fail(MatchAxisCountry, "registry country %s does not match the party's %s", obsCountry, expected.Country)
	}

	// Identifier — hard, at least one exact hit after normalisation.
	if matchedOn := matchIdentifier(expected, observed, obsCountry, p); matchedOn != "" {
		r.MatchedOn = matchedOn
	} else {
		r.fail(MatchAxisIdentifier,
			"no identifier matched: party has %s %q, registry returned registration %q and tax %q",
			expected.NumberSource, expected.RegistrationNumber,
			observed.RegistrationNumber, observed.TaxCode)
	}

	// Legal form — hard when both sides state one and they conflict.
	// "Acme SL" and "Acme SA" are two different legal entities that
	// happen to share a trading name, and no name-similarity score
	// should be allowed to paper over that.
	expName, expForm := splitLegalForm(expected.LegalName)
	obsName, obsForm := splitLegalForm(observed.LegalName)
	if expForm != "" && obsForm != "" && expForm != obsForm {
		r.fail(MatchAxisLegalForm, "legal form %s does not match the registry's %s", expForm, obsForm)
	}

	// Name — soft, thresholded, and reviewable. Compared on the cores,
	// with the legal form already split off.
	r.NameScore = nameScore(expName, obsName, observed.AlternativeNames)
	nameOK := r.NameScore >= p.NameThreshold
	// A truncated or extended trading name ("Acme" vs "Acme Europe")
	// is only trusted when an identifier matched exactly — on its own
	// it is far too weak.
	if !nameOK && r.MatchedOn != "" && namePrefixRelated(expName, obsName) {
		nameOK = true
	}
	if !nameOK {
		r.fail(MatchAxisName, "legal name %q does not match the registry's %q (score %.2f, threshold %.2f)",
			expected.LegalName, observed.LegalName, r.NameScore, p.NameThreshold)
	}

	// Status — hard. Never endorse a company the registry has struck
	// off. A nil Active means the registry did not say, which is not
	// the same as saying no.
	if p.RequireActive && observed.Active != nil && !*observed.Active {
		r.fail(MatchAxisStatus, "registry does not list the company as active (%s)", observed.Status)
	}

	r.Passed = len(r.Failures) == 0
	// Reviewable exactly when the name is the only thing standing in
	// the way.
	r.Reviewable = !r.Passed && len(r.Failures) == 1 && r.Failures[0] == MatchAxisName
	return r
}

// matchIdentifier reports which identifier comparison succeeded, or "".
//
// Both sides are normalised the same way — upper case, punctuation
// stripped, a redundant country prefix removed — so "ESB12345678" and
// "B-12345678" compare equal.
func matchIdentifier(expected SubjectFacts, observed provider.CompanyRecord, obsCountry l10n.Code, p MatchPolicy) string {
	obsReg := normalizeCode(observed.RegistrationNumber, obsCountry)
	obsTax := normalizeCode(observed.TaxCode, obsCountry)
	obsVAT := normalizeCode(observed.VATNumber, obsCountry)

	if expected.NumberSource == NumberSourceLegal && expected.RegistrationNumber != "" {
		if obsReg != "" && obsReg == expected.RegistrationNumber {
			return "registration_number"
		}
	}
	if expected.TaxCode != "" {
		if obsTax != "" && obsTax == expected.TaxCode {
			return "tax_code"
		}
		if obsVAT != "" && obsVAT == expected.TaxCode {
			return "vat_number"
		}
		// Several registries return the tax number in the
		// registration field. Accepting that is safe when the party
		// gave us nothing better to compare against.
		if p.AllowTaxIDAsRegistration && expected.NumberSource == NumberSourceTaxID &&
			obsReg != "" && obsReg == expected.TaxCode {
			return "registration_number_as_tax_code"
		}
	}
	return ""
}

// legalForms are the entity-type tokens stripped off a legal name
// before comparison, and compared separately. Multi-word forms are
// matched after punctuation removal collapses them ("S.L." → "SL",
// "SP. Z O.O." → "SPZOO").
var legalForms = map[string]bool{
	"SL": true, "SLU": true, "SA": true, "SAU": true, "SCP": true, "SC": true,
	"GMBH": true, "UG": true, "AG": true, "KG": true, "OHG": true, "EV": true,
	"LTD": true, "LIMITED": true, "PLC": true, "LLP": true,
	"LLC": true, "INC": true, "CORP": true, "CO": true,
	"BV": true, "NV": true, "VOF": true,
	"SARL": true, "SAS": true, "SASU": true, "SCI": true, "EURL": true,
	"SPA": true, "SRL": true, "SRLS": true, "SNC": true,
	"OY": true, "OYJ": true, "AB": true, "ASA": true, "AS": true, "APS": true,
	"KFT": true, "ZRT": true, "NYRT": true, "BT": true,
	"SPZOO": true, "SPZOOSKA": true, "SP": true,
	"DOO": true, "AD": true, "EOOD": true, "OOD": true,
	"LDA": true, "UNIPESSOAL": true,
}

// splitLegalForm separates a normalised legal name from its trailing
// entity-type token, e.g. "ACME WIDGETS SL" → ("ACME WIDGETS", "SL").
func splitLegalForm(name string) (core, form string) {
	fields := strings.Fields(normalizeName(name))
	if len(fields) == 0 {
		return "", ""
	}
	// Only a trailing form is meaningful: a leading "SA" is part of
	// the name in plenty of countries.
	last := fields[len(fields)-1]
	if len(fields) > 1 && legalForms[last] {
		return strings.Join(fields[:len(fields)-1], " "), last
	}
	return strings.Join(fields, " "), ""
}

// normalizeName folds a legal name to a comparable form: accents
// removed, upper case, punctuation reduced to spaces, runs of
// whitespace collapsed.
func normalizeName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevSpace := true
	for _, r := range name {
		r = foldRune(r)
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(unicode.ToUpper(r))
			prevSpace = false
		case !prevSpace:
			b.WriteByte(' ')
			prevSpace = true
		}
	}
	return strings.TrimSpace(b.String())
}

// foldTable maps the accented Latin letters that appear in European
// company names onto their unaccented forms, so "MÜLLER" and "MULLER"
// compare equal.
var foldTable = func() map[rune]rune {
	const (
		accented = "ÀÁÂÃÄÅàáâãäåÈÉÊËèéêëÌÍÎÏìíîïÒÓÔÕÖØòóôõöøÙÚÛÜùúûüÑñÇçÝýŸÿŠšŽžŁłĐđ"
		plain    = "AAAAAAaaaaaaEEEEeeeeIIIIiiiiOOOOOOooooooUUUUuuuuNnCcYyYySsZzLlDd"
	)
	from, to := []rune(accented), []rune(plain)
	if len(from) != len(to) {
		panic("domain: fold table length mismatch")
	}
	m := make(map[rune]rune, len(from))
	for i, r := range from {
		m[r] = to[i]
	}
	return m
}()

// foldRune strips the accent from a Latin letter. Anything outside the
// table is returned unchanged.
func foldRune(r rune) rune {
	if f, ok := foldTable[r]; ok {
		return f
	}
	return r
}

// nameScore is the best similarity between the expected name and any
// name the registry offered — the legal name or one of its recorded
// alternatives.
func nameScore(expected, observed string, alternatives []string) float64 {
	best := jaroWinkler(expected, observed)
	for _, alt := range alternatives {
		core, _ := splitLegalForm(alt)
		if s := jaroWinkler(expected, core); s > best {
			best = s
		}
	}
	return best
}

// namePrefixRelated reports whether one name is a whole-token prefix
// of the other — the shape a truncated registry entry or an extended
// trading name takes. Only ever consulted alongside an exact
// identifier match.
func namePrefixRelated(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	fa, fb := strings.Fields(a), strings.Fields(b)
	if len(fa) > len(fb) {
		fa, fb = fb, fa
	}
	for i := range fa {
		if fa[i] != fb[i] {
			return false
		}
	}
	return true
}

// jaroWinkler returns the Jaro-Winkler similarity of two strings, 0 to
// 1. It favours strings that agree at the start, which suits company
// names: the distinguishing word comes first and the generic tail
// ("HOLDINGS", "EUROPE") comes last.
func jaroWinkler(a, b string) float64 {
	j := jaro(a, b)
	if j == 0 {
		return 0
	}
	// Standard Winkler boost: up to four leading characters, scaling
	// factor 0.1.
	ra, rb := []rune(a), []rune(b)
	prefix := 0
	for prefix < len(ra) && prefix < len(rb) && prefix < 4 && ra[prefix] == rb[prefix] {
		prefix++
	}
	return j + float64(prefix)*0.1*(1-j)
}

// jaro returns the Jaro similarity of two strings, 0 to 1.
func jaro(a, b string) float64 {
	ra, rb := []rune(a), []rune(b)
	la, lb := len(ra), len(rb)
	if la == 0 && lb == 0 {
		return 1
	}
	if la == 0 || lb == 0 {
		return 0
	}

	window := max(la, lb)/2 - 1
	if window < 0 {
		window = 0
	}

	matchedA := make([]bool, la)
	matchedB := make([]bool, lb)
	matches := 0
	for i := range ra {
		lo := max(0, i-window)
		hi := min(lb-1, i+window)
		for k := lo; k <= hi; k++ {
			if matchedB[k] || ra[i] != rb[k] {
				continue
			}
			matchedA[i], matchedB[k] = true, true
			matches++
			break
		}
	}
	if matches == 0 {
		return 0
	}

	// Transpositions: matched characters that appear in a different
	// order on each side, counted in pairs.
	transpositions := 0
	k := 0
	for i := range ra {
		if !matchedA[i] {
			continue
		}
		for !matchedB[k] {
			k++
		}
		if ra[i] != rb[k] {
			transpositions++
		}
		k++
	}

	m := float64(matches)
	return (m/float64(la) + m/float64(lb) + (m-float64(transpositions)/2)/m) / 3
}

// failureStrings renders the failed axes for logging.
func (r MatchReport) failureStrings() []string {
	out := make([]string, len(r.Failures))
	for i, f := range r.Failures {
		out[i] = string(f)
	}
	return out
}

// model converts the report into its stored form. It is stored on
// every outcome, pass or fail: a countersignature is a public claim
// about a company, and the evidence for it has to outlive the process
// that made it.
func (r MatchReport) model(at time.Time) *models.MatchReport {
	active := ""
	if r.Observed.Active != nil {
		active = "inactive"
		if *r.Observed.Active {
			active = "active"
		}
	}
	if r.Observed.Status != "" {
		active = r.Observed.Status
	}
	return &models.MatchReport{
		At:         at,
		Passed:     r.Passed,
		Reviewable: r.Reviewable,
		Failures:   r.failureStrings(),
		Reasons:    r.Reasons,
		NameScore:  r.NameScore,
		MatchedOn:  r.MatchedOn,
		Observed: models.Observed{
			LegalName:          r.Observed.LegalName,
			Country:            string(r.Observed.Country),
			RegistrationNumber: r.Observed.RegistrationNumber,
			TaxCode:            r.Observed.TaxCode,
			VATNumber:          r.Observed.VATNumber,
			LegalForm:          r.Observed.LegalForm,
			Status:             active,
			Address:            r.Observed.Address,
		},
	}
}

package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/invopop/gobl/l10n"
	"github.com/invopop/gobl/org"
	"github.com/invopop/gobl/tax"

	"github.com/invopop/gobl.kyb/internal/domain/models"
	"github.com/invopop/gobl.kyb/internal/domain/provider"
)

// NumberSource records where a subject's registration number came
// from. It is not bookkeeping: in most jurisdictions a VAT number is
// not the company registry number (DE USt-IdNr vs HRB, FR TVA vs
// SIREN), so a number taken from the tax identity has to be matched
// more permissively than one taken from a legal identity.
type NumberSource string

// Registration number provenance.
const (
	// NumberSourceLegal means the number came from an org.Identity
	// with the "legal" scope — GOBL's designated slot for a company
	// registry number.
	NumberSourceLegal NumberSource = "legal_identity"
	// NumberSourceTaxID means the number fell back to the party's tax
	// identity code because no legal identity was published.
	NumberSourceTaxID NumberSource = "tax_id"
	// NumberSourceNone means the party published neither.
	NumberSourceNone NumberSource = "none"
)

// SubjectFacts is the tuple of KYB-relevant facts derived from an
// org.Party: exactly what is sent to the provider and exactly what is
// checked when its decision comes back. Nothing else about the party
// influences a verification.
//
// The distinction matters commercially. A KYB check costs real money,
// and the registration authority drops a party's verifier claim
// whenever the party envelope's digest changes — any edit, a phone
// number included. Keying re-use on the envelope digest would
// therefore buy a fresh check every time a customer corrects a
// typo. Keying it on this fingerprint means only a change to the facts
// that were actually verified is worth paying to re-verify.
type SubjectFacts struct {
	// LegalName is the party's registered legal name, verbatim.
	LegalName string `json:"legal_name"`
	// Country is the registry country as an ISO 3166-1 alpha-2 code,
	// normalised away from the tax-only forms (EL, XI, XU).
	Country l10n.Code `json:"country"`
	// TaxCode is the party's tax identity code, normalised.
	TaxCode string `json:"tax_code"`
	// RegistrationNumber is the company registry number, normalised.
	RegistrationNumber string `json:"registration_number"`
	// NumberSource records where RegistrationNumber came from.
	NumberSource NumberSource `json:"number_source"`
}

// Hash fingerprints the facts. Field order is fixed by the struct, so
// encoding/json gives a canonical form without any extra machinery.
func (f SubjectFacts) Hash() string {
	data, err := json.Marshal(f)
	if err != nil {
		// Every field is a string; Marshal cannot fail.
		panic("domain: marshal subject facts: " + err.Error())
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// SubjectFactsFrom derives the verifiable facts from a party, or
// explains which published detail is missing. Every failure here is a
// 422 at the inbox: it is far better to refuse a party we cannot check
// than to open a paid session that can only end in a mismatch.
func SubjectFactsFrom(party *org.Party) (SubjectFacts, error) {
	var f SubjectFacts
	if party == nil {
		return f, fmt.Errorf("party is missing")
	}

	// The legal name, not the alias: org.Party documents Name as the
	// "legal name or representation of the organization" and Alias as
	// an "alternate short name". A registry lookup on a trading name
	// finds nothing.
	f.LegalName = strings.TrimSpace(party.Name)
	if f.LegalName == "" {
		return f, fmt.Errorf("party must publish a legal name (`name`) to be verified")
	}

	legal := legalIdentity(party)

	country, err := registryCountry(party, legal)
	if err != nil {
		return f, err
	}
	f.Country = country

	if party.TaxID != nil {
		f.TaxCode = normalizeCode(string(party.TaxID.Code), party.TaxID.Country.Code())
	}

	switch {
	case legal != nil && legal.Code != "":
		f.RegistrationNumber = normalizeCode(string(legal.Code), legal.Country.Code())
		f.NumberSource = NumberSourceLegal
	case f.TaxCode != "":
		// A tax code is a weak stand-in for a registry number, but it
		// is enough for the provider to find the company in most
		// jurisdictions. Flagging the source is what stops the match
		// check from treating it as a registry number later.
		f.RegistrationNumber = f.TaxCode
		f.NumberSource = NumberSourceTaxID
	default:
		f.NumberSource = NumberSourceNone
	}

	if f.RegistrationNumber == "" {
		return f, fmt.Errorf("party must publish a tax identity (`tax_id`) or a legal identity to be verified")
	}
	return f, nil
}

// legalIdentity returns the party's company registry identity — the
// org.Identity carrying the "legal" scope — or nil. GOBL allows at
// most one per party, so the first hit is the only one.
func legalIdentity(party *org.Party) *org.Identity {
	for _, id := range party.Identities {
		if id != nil && id.Scope == org.IdentityScopeLegal && id.Code != "" {
			return id
		}
	}
	return nil
}

// registryCountry resolves the country whose registry holds this
// company, in ISO 3166-1 alpha-2 form.
//
// A postal address is deliberately not a fallback: the registry
// country decides which registry is queried, and guessing it wrong
// costs a paid check that can only fail.
func registryCountry(party *org.Party, legal *org.Identity) (l10n.Code, error) {
	if party.TaxID != nil && !party.TaxID.Country.Empty() {
		return isoCountry(party.TaxID.Country.Code())
	}
	if legal != nil && !legal.Country.Empty() {
		return isoCountry(legal.Country.Code())
	}
	return "", fmt.Errorf("party must publish a tax identity country or a legal identity country to be verified")
}

// isoCountry maps a tax country code onto its ISO 3166-1 alpha-2
// equivalent. GOBL's tax country codes are a superset of ISO: Greece
// files under EL, Northern Ireland under XI, Great Britain under XU.
// KYB providers index registries by ISO code, so those have to be
// translated. The mapping is GOBL's own — a non-ISO country definition
// names its ISO equivalent in AltCode.
func isoCountry(code l10n.Code) (l10n.Code, error) {
	if code.Empty() {
		return "", fmt.Errorf("country code is empty")
	}
	def := l10n.Countries().Code(code)
	if def == nil {
		return "", fmt.Errorf("unknown country code %q", code)
	}
	if def.ISO {
		return def.Code, nil
	}
	// A non-ISO code (EL, XI, XU) points at its ISO equivalent; EU
	// names a union rather than a country and has none.
	if def.AltCode.Empty() {
		return "", fmt.Errorf("country code %q has no ISO equivalent to look up a registry with", code)
	}
	return def.AltCode, nil
}

// normalizeCode reduces an identifier to a comparable form: upper
// case, stripped of everything outside GOBL's own tax code alphabet
// (so dots, dashes and spaces disappear), and without a leading
// country prefix that merely repeats the country. "ES B-12345678" and
// "esb12345678" both become "B12345678".
func normalizeCode(code string, country l10n.Code) string {
	c := tax.IdentityCodeBadCharsRegexp.ReplaceAllString(strings.ToUpper(strings.TrimSpace(code)), "")
	if country.Empty() {
		return c
	}
	prefix := strings.ToUpper(string(country))
	// Only strip a prefix that leaves something behind — a code that
	// *is* its country code is not a prefixed code.
	if len(c) > len(prefix) && strings.HasPrefix(c, prefix) {
		return c[len(prefix):]
	}
	return c
}

// model converts the facts into their stored form.
func (f SubjectFacts) model() models.SubjectFacts {
	return models.SubjectFacts{
		LegalName:          f.LegalName,
		Country:            string(f.Country),
		TaxCode:            f.TaxCode,
		RegistrationNumber: f.RegistrationNumber,
		NumberSource:       string(f.NumberSource),
	}
}

// factsFromModel converts stored facts back into their domain form.
func factsFromModel(m models.SubjectFacts) SubjectFacts {
	return SubjectFacts{
		LegalName:          m.LegalName,
		Country:            l10n.Code(m.Country),
		TaxCode:            m.TaxCode,
		RegistrationNumber: m.RegistrationNumber,
		NumberSource:       NumberSource(m.NumberSource),
	}
}

// subject builds the provider request from the facts, adding the
// non-authoritative context a human analyst may find useful. Nothing
// in Context is ever matched against — it is there so an analyst
// looking at an ambiguous registry entry can see which GOBL Net
// address and which document the request came from.
func (f SubjectFacts) subject(rec *models.Verification) provider.Subject {
	ctx := map[string]string{
		"gobl_address":    string(rec.Address),
		"envelope_uuid":   rec.EnvelopeUUID.String(),
		"envelope_digest": rec.EnvelopeDigest,
		"authority":       string(rec.Authority),
		"attempt":         strconv.Itoa(rec.Attempt),
	}
	if rec.Envelope != nil {
		if party, ok := rec.Envelope.Extract().(*org.Party); ok && party != nil {
			if r := party.Registration; r != nil {
				// Registry inscription details (office, book, volume,
				// sheet…) are not a lookup key — they identify an entry
				// in a national register, not the company — but they
				// help a human confirm they are looking at the right
				// one.
				for k, v := range map[string]string{
					"registration_office":  r.Office,
					"registration_book":    r.Book,
					"registration_volume":  r.Volume,
					"registration_sheet":   r.Sheet,
					"registration_section": r.Section,
					"registration_page":    r.Page,
					"registration_entry":   r.Entry,
				} {
					if v != "" {
						ctx[k] = v
					}
				}
			}
			if a := party.Addresses; len(a) > 0 && a[0] != nil {
				if !a[0].Country.Empty() {
					ctx["party_address_country"] = string(a[0].Country)
				}
				if a[0].Locality != "" {
					ctx["party_address_locality"] = a[0].Locality
				}
			}
		}
	}
	return provider.Subject{
		LegalName:          f.LegalName,
		Country:            f.Country,
		RegistrationNumber: f.RegistrationNumber,
		TaxCode:            f.TaxCode,
		Context:            ctx,
	}
}

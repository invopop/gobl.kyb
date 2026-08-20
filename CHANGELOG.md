# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial implementation of the live GOBL Net KYB verifier. It receives a
  registered party envelope on the standard inbox, runs a business
  verification through Didit, and countersigns the envelope back to
  `lookup.gobl.org` when — and only when — the company the provider
  verified is established to be the party in the envelope.

- A **match check** between the provider's decision and the party
  (`internal/domain/match.go`). An approval from a KYB vendor is evidence
  that some real company was checked, not that it was this one: the hosted
  flow's pre-filled search fields stay editable and an analyst may change
  them during review. Country, identifier, legal form and registry status
  are compared strictly; the legal name is compared with tolerance and, when
  it alone falls short, the case is held for an operator rather than
  declined. Auto-declining on a fuzzy name would burn the customer's money
  on a check that actually succeeded. The full comparison is stored on every
  outcome — a countersignature is a public claim, and its justification has
  to outlive the process that made it.

- A **facts fingerprint** (`internal/domain/facts.go`) keyed on the legal
  name, registry country, tax code and registration number — the tuple that
  is sent to the provider and checked on its return. Session re-use is keyed
  on this rather than on the envelope digest, because the registration
  authority drops a party's verifier claim whenever the envelope changes at
  all: without it, a customer correcting a phone number would buy another
  KYB check. Tax-only country codes (`EL`, `XI`, `XU`) are normalised to
  their ISO equivalents, since registries are indexed by ISO.

- A **provider seam** (`internal/domain/provider`) with a Didit
  implementation and a mock. The mock is not a convenience: every real
  provider bills per check, so the tests that matter most — re-submission,
  session re-use, the cost ceiling — are exactly the ones that would
  otherwise cost money to run.

- A **reconciler** that polls the provider for cases it has gone quiet
  about. Callbacks are retried twice and then dropped forever, and a case
  under analyst review may produce none for days, so without it a
  verification the customer has already paid for can be silently lost.

- Operator commands (`status`, `resync`, `redeliver`, `resend`, `approve`,
  `reject`), each recording who ran it and why.

### Changed

- Inbox rejections now follow spec §8.3's split between the two kinds of
  refusal, so a caller can act on the status rather than only on the
  message. **`403`** is "this verifier will not act on this envelope" —
  unregistered, an uncovered jurisdiction, a decline still in cooldown,
  too many attempts, a case held for an operator — and nothing the
  subject edits changes the answer. **`422`** is "the document is missing
  something verification needs", which re-registering a corrected party
  fixes. An unsupported registry country was previously `422`, which said
  the envelope was malformed when it was perfectly well formed; a case
  held for review was `409`, which is not one of the statuses the spec
  gives the inbox at all.

  Both are decided synchronously, before a provider session exists, so a
  caller learns immediately and nothing has been billed. The `403` for an
  uncovered jurisdiction names the countries that *are* covered, so
  whoever drives the submission can say something more useful than "no".

### Security

- Provider callbacks are authenticated by an HMAC over the vendor's
  canonical form of the payload, verified in constant time against a set of
  secrets so rotation costs no downtime, with a freshness window on the
  dispatch timestamp and a create-only event ledger for idempotency. The
  canonicalisation preserves original number text, leaves `<`, `>` and `&`
  unescaped and keeps non-ASCII literal — getting any of those wrong
  rejects every live callback while passing tests written against our own
  encoder.

- Before countersigning, the verifiable facts are re-derived from the
  envelope about to be signed and compared with the ones that were checked.
  This closes the swap: open a session with clean company details,
  substitute a different party while it runs, collect an endorsement for a
  company nobody verified.

- Envelopes arriving with more than 24 signatures are refused. `gobl` caps
  verification at 32 and every round-trip appends one, so producing the
  signature that crosses the line would leave the party holding an
  endorsement nobody can verify.

- Session creation is never retried automatically. A create call that fails
  without saying whether a session exists may already have been billed.

- Messages to the subject never repeat the registry data the provider
  returned, or name the comparison that failed. The detail goes to the
  operators instead.

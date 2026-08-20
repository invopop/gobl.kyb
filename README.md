# gobl.kyb

A **KYB verification provider** for [GOBL Net](https://github.com/invopop/gobl/tree/main/net),
hosted at `kyb.gobl.org`.

> ⚠️ **EXPERIMENTAL** — GOBL Net is under active development and the wire
> protocol may change without notice.

GOBL Net separates two trust roles. The **registration authority**
(`lookup.gobl.org`) confirms that a party controls its address. A
**verifier** — which the spec requires to be a different participant —
establishes who is *behind* that address, and countersigns the party's
envelope to say so. Receivers require that countersignature before they will
accept documents from a sender, so without a verifier a registered identity
can receive but never send.

This service is that verifier for the live network. It receives a registered
party envelope on its inbox, runs a real business verification through an
external KYB provider, checks that the company the provider verified is
actually the party named in the envelope, and — only then — countersigns the
envelope and returns it to the authority.

The provider is deliberately not part of the design. [Didit](https://didit.me)
is the first one implemented, and the one the live deployment currently uses,
but it sits behind an interface the rest of the service is written against —
see [Providers](#providers).

The service is free to use. The checks behind it are not, which shapes a
number of decisions below.

## What `verifier: kyb.gobl.org` means

This section is the point of the document. The address is deliberately
provider-neutral, so the name alone does not tell you which checks ran —
this is where that is written down, and it is updated in lockstep with any
change to the provider or the policy.

An endorsement naming `kyb.gobl.org` asserts that, at the time it was
issued:

1. A company matching the party's **legal name**, **registry country** and
   at least one of its **tax or company registration numbers** was found in
   an official company registry.
2. That registry did not list the company as dissolved, struck off, in
   liquidation or otherwise not trading.
3. The provider's own checks — beneficial ownership, officers, AML
   screening against sanctions, PEP and adverse-media lists, and any
   supporting documents its workflow required — completed without a
   refusal.
4. A human with access to the party's **published email address** started
   the verification and completed the provider's flow.

It does **not** assert that the person who completed the flow is authorised
to act for the company, that the company is solvent or reputable, or
anything at all about the documents that party subsequently sends. The
endorsement expires after a year (`ENDORSEMENT_TTL`), and is dropped by the
registration authority whenever the party's published details change.

### The matching rules

A provider verifies *a company somebody searched for*. Nothing in a hosted
verification flow forces that to be the company in the envelope we were
asked to endorse — the pre-filled search fields stay editable, and an
analyst may correct them during review. Establishing the connection is this
service's job, not the provider's, and the policy is deliberately
asymmetric:

| Axis | Rule | On failure |
|---|---|---|
| Registry country | Exact, after normalising tax-only codes (`EL`→`GR`, `XI`/`XU`→`GB`) | Refused |
| Identifier | At least one exact hit — registration number, tax code or VAT number — after stripping punctuation and a redundant country prefix | Refused |
| Legal form | Two stated forms that conflict (`SL` vs `SA`) are different entities | Refused |
| Legal name | Accent-folded, case-folded, legal form split off, then compared; `MATCH_NAME_THRESHOLD` (0.90) similarity, or a whole-token prefix relation when an identifier matched exactly | **Held for review** |
| Registry status | Must not be one of the inactive vocabularies; an unreported status is *unknown*, not *inactive* | Refused |

Identifiers are hard because a registry number either matches or it does
not. Names are soft because legal names drift between registries,
transliterations and abbreviations — so a name-only miss holds the case for
an operator rather than declining it. Auto-declining there would burn the
customer's money on a check that actually succeeded.

Only a name miss can be released by an operator (`gobl.kyb approve`), and
only with a recorded reason. A country, identifier or status failure means a
different or unfit company, and no amount of human confidence turns that
into something this service will sign.

The full comparison — both sides, per axis, with the name score — is stored
on every case, pass or fail. A countersignature is a public claim, and "why
did you attest to this?" has to be answerable years later.

## How a verification runs

The service is a standard GOBL Net participant: one inbox, published keys, a
`/who` identity. The only non-protocol surfaces are the provider callback
and the status page behind the emailed link.

1. **Receive.** The subject delivers its *registered* envelope — its own
   signed `org.Party`, countersigned by `lookup.gobl.org` — to
   `POST /.well-known/gobl/inbox` with a request token. The inbox refuses
   anything it can already tell will make a paid check pointless: an
   envelope without a valid authority countersignature (`403`), an
   unsupported registry country (`403`), a party with no published email, no
   legal name or no tax identity (`422`), and an envelope already close to
   gobl's 32-signature ceiling (`422`).

   The split between the two follows spec §8.3 and is worth relying on:
   **`403` means this verifier will not act on this envelope** — not
   registered with our authority, a jurisdiction we do not cover, a previous
   decline still in cooldown, too many attempts, or a case held for an
   operator. Nothing the subject edits will change the answer. **`422` means
   the document is missing something verification needs** — a contact
   address, a legal name, a tax identity — and re-registering a corrected
   party is exactly the fix. `401` is authentication or signatures, and
   `503` means a check could not be *performed*, not that it failed, so the
   sender should retry.

   Every one of these is decided synchronously, before a provider session
   exists, so a caller learns immediately and nothing has been billed. The
   `403` for an unsupported jurisdiction names the countries that *are*
   covered, so whoever is driving the submission can tell their user
   something more useful than "no".
2. **Open a session.** The party's verifiable facts are sent to the provider
   to pre-fill its registry search, and the hosted flow link it returns is
   emailed to the party's published address. This is the point at which
   money is spent.
3. **Wait.** The provider reports progress by signed callback. A case it
   escalates to an analyst gets its own state: polled slowly, never swept as
   abandoned, and eventually flagged to the operators. Callbacks are retried
   twice and then dropped forever, so a reconciler polls anything the
   provider has gone quiet about.
4. **Match.** On approval the decision is fetched, stored as evidence, and
   checked against the party under the rules above.
5. **Countersign and return.** A case that passes is countersigned —
   `iss=kyb.gobl.org`, `aud=<subject>`, a year-long `exp`, and **no**
   `verifier` claim, since that pointer is the authority's to set — and
   POSTed to `lookup.gobl.org`'s inbox. The envelope's `uuid` and digest are
   unchanged: what is signed is exactly what was checked.
6. **Authority auto-verify.** The registry recognises the countersignature
   (this address must be on its `VERIFIERS` list), re-countersigns naming
   `verifier: kyb.gobl.org`, and delivers the result to the subject, who
   publishes it at their own `/who`.

### Re-submission and cost

A KYB check is billed per company, whether or not anybody completes it. The
registration authority drops a party's verifier claim whenever the party
envelope changes **at all** — a corrected phone number is enough — so
parties come back here after edits that have nothing to do with the company.

Re-use is therefore keyed on a fingerprint of the **verifiable facts**
(legal name, registry country, tax code, registration number), not on the
envelope digest:

| Situation | What happens |
|---|---|
| Same facts, a check already running | The same link is re-sent. No new session. |
| Same facts, already verified and the result is within `KYB_RESULT_TTL` | The new envelope is countersigned against the existing decision. Free. |
| Same facts, previously declined | Refused for `DECLINE_COOLDOWN`. |
| Same facts, held as a mismatch | Refused until an operator resolves it. |
| Different facts | The previous attempt is archived and a new check starts. |

On top of that, `MAX_SESSIONS_PER_ADDRESS` (3) within
`MAX_SESSIONS_WINDOW` (30 days) is a hard ceiling. A session-create call
that fails without telling us whether a session exists — a timeout, most
often — is **never retried automatically**; it is left for an operator,
because the alternative is paying twice.

## Providers

The checks themselves are bought in. Which vendor performs them is a
deployment choice (`PROVIDER`), not an assumption baked into the flow: the
choreography above, the match policy, the state machine and the cost rules
are all written against the `Provider` interface in
`internal/domain/provider`. A vendor's endpoint shapes, status vocabulary,
JSON field names and callback signature scheme never leave its own
sub-package.

Didit is the first implementation and the one the live deployment uses. A
`mock` implementation exists for development and the test suite — every real
provider bills per check, so the tests that matter most here would otherwise
cost money to run.

### What the service needs from a provider

Three operations, and none of them is optional:

- **Open a session** and return a link a human can complete. This is the
  billable act, and it is never retried automatically: a create call that
  fails without saying whether a session exists may already have been
  charged.
- **Fetch a decision** for a session on demand. This is the backstop for
  dropped callbacks and the only way to follow a case sitting with an
  analyst, so a provider that only pushes results and cannot be asked is not
  usable here.
- **Verify and decode a signed callback**, carrying a stable event ID for
  idempotency and a dispatch timestamp for ordering. Callbacks arrive out of
  order and get retried; without those two fields the same result gets
  applied twice or an older one overwrites a newer one.

And the decision has to carry enough to run the match policy above:

- Registry-sourced **legal name, country, registration number, tax or VAT
  number and registry status**, plus any alternative names the registry
  holds.
- Those values **distinguishable from whatever the applicant typed in**.
  This is the one requirement with no workaround. A hosted flow lets the
  business correct or add company details, and an endorsement built on what
  the applicant said about themselves is worth nothing — so a provider that
  merges registry and self-reported data into one indistinguishable blob
  cannot support this service's policy, whatever else it offers.
- **Key people** with their roles, their source, and their individual
  verification status.

### Setting up Didit

Two credentials and a workflow. The credentials go in the environment; the
workflow is configured in Didit's Business Console and has no public API, so
it is a manual step and a reviewable one.

**In the console:**

1. Create a **Business Verification (KYB)** workflow.
2. Enable the **registry check**. It is the base of every axis of the match.
3. Enable **Company AML** — sanctions, PEP and adverse media. Cheap, and not
   really optional for a network that gates document exchange.
4. Under **Key People**, enable the governance roles and set **require KYC**
   on `director`, `authorized_signatory`, `representative` and
   `company_officer`, with **skip disabled** for each. Set the ownership
   threshold (25% is the EU/UK/US norm) for the UBO side. This is what turns
   "a real company exists" into "a person the registry names as running it
   presented ID" — see the caveat below.
5. Enable **document collection** if the jurisdictions you serve need it.
6. **Publish** the workflow and copy its ID into `DIDIT_WORKFLOW_ID`.
7. Add a **webhook destination** pointing at
   `<PUBLIC_BASE_URL>/webhooks/didit`, subscribed to **`status.updated`**,
   and copy its signing secret into `DIDIT_WEBHOOK_SECRET`. That is the only
   event this service acts on — it moves a case only on a status
   transition. `data.updated` and the `business.*` events are safe to send
   (they are recorded and ignored) but there is no reason to.

Workflows are draft/publish versioned: published versions are immutable and
each session records the version that created it, so editing a workflow
cannot retroactively change what an already-issued endorsement covered. But
it does change what the *next* one covers. **The workflow defines which
checks ran, so it is part of what `verifier: kyb.gobl.org` means** — treat a
change to it as a change to the published policy above, not as a settings
tweak.

Do all of this in Didit's **sandbox** environment first and drive a session
end to end before pointing anything at live.

> **Caveat, and it is a real one.** The service does not yet verify that a
> completed officer KYC was performed on a *registry-disclosed* person
> rather than one the applicant added themselves — the two arrive in
> separate buckets with no automated reconciliation. Until it does, the
> console setting above is a control Didit applies and this service takes on
> trust, which is why the policy section stops short of claiming the person
> who completed the flow is authorised to act for the company.

### Adding a provider

A new vendor is a package under `internal/domain/provider/<name>`
implementing the interface, a case in `buildProvider`, and a `PROVIDER`
value. Nothing in the domain changes. Three things to get right:

- **Map the status vocabulary carefully.** In particular, a vendor status
  meaning "the applicant supplied more information and the check is running
  again" maps to *pending*, not to a fresh start — treating it as new opens a
  second billed session for a check already in flight.
- **Preserve the registry/applicant distinction** through the mapping, and
  fail closed: anything that cannot be positively identified as
  registry-sourced must not count as evidence.
- **Write golden tests from a captured real payload.** Field-name guesswork
  passes every test written against your own encoder and fails against live
  traffic.

Because the GOBL Net address stays `kyb.gobl.org` across a provider change,
receivers have no way to tell from the name that anything moved. The policy
section of this README is the only place they can find out, so it and the
provider have to change together.

## Endpoints

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /.well-known/gobl/inbox` | request token | receive registered envelopes |
| `GET /.well-known/gobl/who` | request token | the service's own signed party |
| `GET /.well-known/gobl/keys/<kid>` | open | published signing keys |
| `GET /.well-known/jwks.json` | open | keys as an RFC 7517 set |
| `POST /webhooks/didit` | payload signature | provider status callbacks |
| `GET /status/<token>` | link token | verification status page |
| `GET /healthz` | open | readiness/liveness |

Three different authentication schemes meet here and they are not
interchangeable. GOBL Net participants present a bearer request token. Key
discovery is open, so that verifying a token can never recurse into needing
one. The provider cannot mint a GOBL Net token at all, so its callback is
authenticated by an HMAC over the payload. The status page is authenticated
by the unguessable token in its URL.

The status page never shows the customer what the registry returned, or
which check failed. Whoever holds the link controls the party's published
mailbox, which is not the same as being entitled to a third party's registry
record — and naming the failing comparison would tell anyone probing the
service exactly what to adjust.

## Configuration

Environment variables (flags on `serve` override them):

| Variable | Default | Purpose |
|---|---|---|
| `CONFIG_DIR` | — | identity directory (`private.jwk`, `party.json`, `keys/`) |
| `COUCHDB_URL` or `COUCHDB_{SCHEME,HOST,PORT,USERNAME,PASSWORD}` | — | CouchDB connection (URL wins) |
| `COUCHDB_DATABASE` | `gobl_kyb` | database name |
| `AUTHORITY` | `lookup.gobl.org` | required countersigner in, delivery destination out |
| `PUBLIC_BASE_URL` | `https://<domain>` | base of the emailed links and the provider callback; must be https |
| `PROVIDER` | `didit` | `didit` or `mock` (development only) |
| `DIDIT_*` (below) | — | the Didit adapter's own settings; another provider brings its own set |
| `DIDIT_API_KEY` | — | **secret** |
| `DIDIT_WORKFLOW_ID` | — | the KYB workflow in Didit's console — it decides which checks run, so it is part of what an endorsement means |
| `DIDIT_WEBHOOK_SECRET` | — | **secret**, HMAC key for callbacks |
| `DIDIT_WEBHOOK_SECRET_PREVIOUS` | — | accepted alongside the current one, so rotation costs no downtime |
| `DIDIT_WEBHOOK_PATH` | `/webhooks/didit` | callback route |
| `DIDIT_BASE_URL` | `https://verification.didit.me` | API root |
| `DIDIT_TIMEOUT` | `20s` | per-call timeout |
| `WEBHOOK_CLOCK_SKEW` | `5m` | callback freshness window |
| `SUPPORTED_COUNTRIES` | *(all)* | comma-separated ISO codes; refused at the inbox, before spending |
| `MATCH_NAME_THRESHOLD` | `0.90` | legal-name similarity floor |
| `MATCH_REQUIRE_ACTIVE` | `true` | never endorse a dissolved company |
| `ENDORSEMENT_TTL` | `8760h` | lifetime of this verifier's countersignature |
| `KYB_RESULT_TTL` | `8760h` | how long a completed check re-endorses unchanged facts for free |
| `SESSION_TTL` | `336h` | when an abandoned session is swept (never applied to one under review) |
| `IN_REVIEW_ALERT_AFTER` | `120h` | when to chase the provider about a stuck review |
| `DECLINE_COOLDOWN` | `2160h` | how long a declined address is refused |
| `MAX_SESSIONS_PER_ADDRESS` / `MAX_SESSIONS_WINDOW` | `3` / `720h` | hard cost ceiling |
| `RESYNC_INTERVAL` | `15m` | reconciler tick; `0` disables the in-process loop |
| `DECISION_RETENTION_DAYS` | `1825` | retention for raw provider decisions |
| `OPS_ALERT_EMAIL` | — | mismatch, error and stuck-review notices |
| `PAYMENT_MODE` | `none` | payment stage; only `none` is implemented |
| `SMTP_HOST` | — | mail submission host; empty logs emails instead (development) |
| `SMTP_PORT` | `587` | submission port (STARTTLS when offered) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | — | PLAIN auth; empty for an unauthenticated relay |
| `EMAIL_FROM` | — | e.g. `GOBL KYB <kyb@gobl.org>`; required with `SMTP_HOST` |
| `HTTP_PORT` / `PORT` | `8080` | listen port |
| `LOG_JSON` | `false` | JSON logs |

`serve` refuses to start on a configuration that would fail on its first
real request: a missing provider credential, or a `PUBLIC_BASE_URL` that is
not https — the provider will not post a callback to plain HTTP, and a
service that starts anyway just opens sessions that never resolve.

Email is plain SMTP so any provider works — hosted senders (Resend, SES,
Postmark, …) all expose an SMTP submission endpoint.

## Commands

| Command | Purpose |
|---|---|
| `init <domain>` | scaffold a signing identity |
| `serve` | HTTP server and the reconciler |
| `status <address>` | everything known about a case — the first thing to run when a customer asks why they are not verified |
| `resync` | one reconciliation pass, for incidents |
| `redeliver <address>` | re-deliver an approved verification to the authority |
| `resend <address>` | re-send the hosted link; never opens a new session |
| `approve <address> --reason` | release a case held on a legal-name mismatch |
| `reject <address> --reason` | close a case without countersigning |
| `version` | build and core versions |

Every mutating command records who ran it and why. For a service whose
product is trustworthiness, that is not bookkeeping — it is the answer to
the only question anyone will ask about a countersignature later.

## Running locally

```sh
docker compose up -d            # CouchDB on :5984
go run ./cmd/gobl.kyb init kyb.gobl.org --name "GOBL KYB"
PROVIDER=mock go run ./cmd/gobl.kyb serve \
  --config-dir ~/.config/gobl.kyb/kyb.gobl.org \
  --couchdb http://admin:pass@localhost:5984
```

`PROVIDER=mock` drives the whole state machine without contacting a real
provider or spending anything, and without `SMTP_HOST` the emails — links
included — are written to the log. That is all a local loop needs.

To exercise the authority handshake, run
[gobl.lookup](https://github.com/invopop/gobl.lookup) locally with
`--verifiers kyb.gobl.org` and point `AUTHORITY` at it.

```sh
go test -race ./...   # no external services required
mage check            # lint + race tests, the pre-PR gate
```

## Deployment notes

- The registration authority must list this service in its `VERIFIERS`
  configuration. Without it the registry still accepts the returned envelope
  (`202`) but re-registers **without** the `verifier` claim — the flow
  silently degrades to registered-only.
- The identity is scaffolded once with `init` and mounted as a secret. It is
  its own keypair, never shared with any lookup identity.
- The binary terminates HTTP only; run it behind a TLS-terminating proxy.
- The reconciler is safe on every replica: cases are leased before they are
  worked and every step it drives is idempotent.
- Raw provider decisions carry personal data about directors and beneficial
  owners. They are stored in their own documents, apart from the case
  records, so they can be purged on their own schedule.

## Known limitations

- **Analyst review is out of our hands.** A case the provider escalates sits
  in *their* console until *their* analyst decides, with no API to hurry it.
  Running this service is therefore an operational commitment to watch that
  queue.
- **Abandoned sessions still cost.** Session re-use and the per-address
  ceiling bound the exposure, but a business that starts a check and walks
  away has spent our money.
- **Registry status vocabularies vary.** An unrecognised status is treated as
  *unknown* rather than guessed at, which means a registry with unusual
  wording will not block a dissolved company on that axis alone.
- **A provider change changes what the name means.** The address is
  deliberately provider-neutral, which is what lets the vendor be swapped —
  but it also means a receiver cannot tell from the name that anything
  changed. This README is the only place they can find out, so the policy
  section and the configured provider have to move together.
- **The officer check is configured, not yet enforced.** Requiring a
  registry-disclosed officer to complete a KYC is a provider-side setting
  this service currently takes on trust; see
  [Setting up Didit](#setting-up-didit).

## License

Released under the Apache 2.0 LICENSE, Copyright 2026 Invopop S.L.

# sealform design

Status: approved 2026-10-29, revised the same day for the admin dashboard, private contract links,
site controls and international verification hooks. Built in phases; see the end.

## Why

The Plinkwick Studios tester agreement is signed through a Tally embed. Tally captures a drawn
signature, but the operator holds no evidence of their own: no hash tying the signature to the exact
agreement text, no server-recorded IP or timestamp, and no way to show a record was not edited later.
sealform produces signing records the operator controls and anyone can verify.

It is a library first. Plinkwick testing is the first consumer; later ones are partner and contractor
agreements, waivers and release forms.

## What "legally binding" means here

Code cannot make a signature binding everywhere. It can meet the elements e-signature laws look for
and keep strong evidence for each. Under US ESIGN/UETA, the UK Electronic Communications Act and
similar laws, a simple electronic signature with this evidence is generally valid. Under EU eIDAS it is
a Simple Electronic Signature: admissible, not presumed equal to handwriting. Some documents need more
(see Jurisdictions).

| Element | Evidence sealform keeps |
| --- | --- |
| Consent to sign electronically | Required checkbox; the disclosure text version and hash go in the record |
| Intent to sign | Typed legal name, drawn signature, explicit "Sign" action |
| Association with the record | SHA-256 of the exact document bytes, recomputed on the server, must match the published version |
| Attribution | Server-recorded IP, user agent, language, timestamp; receipt to the signer's email; optional stronger checks |
| Integrity | Canonical record hash, an Ed25519 seal by the operator key, a hash chain across records |
| Signer keeps a copy | PDF certificate on screen and attached to the receipt email |

sealform's copy and docs never claim guaranteed enforceability.

## Goals

- A reusable TypeScript package, `sealform`, in its own repo `realKeehan/sealform`, safe to make public.
- Runs as a Node.js app on cPanel (Passenger) or any Node 22.13+ host. Nothing host-specific.
- Versioned, immutable documents, with translations hashed per language.
- Every record verifiable from the record, the published public keys and the chain.
- An admin dashboard for accounts, sign-ins, the audit log, documents, submissions, private contract
  links and site controls.
- Stronger identity checks designed in from the start, disabled until configured.
- Pluggable storage, mail, bot check and verification providers.
- The embedded form looks native to the host site: themed with CSS custom properties,
  `prefers-reduced-motion` respected.

## Non-goals (v1)

- Running any identity provider. The hooks exist; the providers are off.
- Dragging fields onto PDF templates. Documents are text (Markdown) with a field schema.
- Post-quantum seals. The record names its algorithm so a second seal can be added later.

## Anti-goals

- Trusting time or network facts from the browser. Client values are kept as "client reported" next
  to the server's, never instead of them.
- Collecting more than the host's privacy notice discloses.
- Deleting signed evidence on request, or keeping personal data forever with no reason (see Retention).
- Anything operator-specific in the public repo: no keys, data, configs, emails or document texts.

## Architecture

One package with subpath exports:

| Export | Runs in | Does |
| --- | --- | --- |
| `sealform/core` | browser and Node | Record types, RFC 8785 canonical JSON, SHA-256, ULIDs, Ed25519 seal and verify, chain verify, tombstones |
| `sealform/server` | Node | `createSealform(config)`: one `(req, res)` handler for the signing API, the admin API and dashboard, and the site layer |
| `sealform/client` | browser | `mountSealform(el, options)`: the signing form |
| `sealform` CLI | Node | `keygen`, `verify`, `verify-chain`, `admin create`, `export`, `tombstone` |

Runtime dependencies: `signature_pad` (client) and `pdf-lib` (server). Built in: `node:crypto` (Ed25519,
scrypt, HMAC for TOTP), `node:sqlite`, Web Crypto. Dev: `typescript`, `esbuild` (bundles the browser
code), `sass`, `@types/node`. Tests use `node:test`.

### Storage

`Store` is an interface. v1 ships `SqliteStore` on `node:sqlite` (no native build step, which matters on
shared hosting). Record JSON, signature PNGs and PDFs are also written as files under the data
directory, so evidence survives even if the database is lost. A `MySqlStore` can follow; it needs
`mysql2`. The data directory must sit outside the web root.

Unverified: which Node versions the Namecheap plan offers. `node:sqlite` needs 22.13+ to run without a
flag. Check in cPanel's Node.js selector before the move.

### Signing flow

1. `GET /api/documents/:docId?lang=xx` returns the published version's text in that language, its
   SHA-256, the e-sign disclosure and its hash, the field schema, the required checks, and a signing
   session (random id and server open time, held server side).
2. The client renders it and, on submit, hashes the text it displayed and sends that with the answers.
3. `POST /api/sign`: bot check, per-IP rate limit, schema validation with size caps, displayed hash
   must equal the server hash, every required check passed, then server facts are captured, the record
   is built, canonicalized, hashed, chained, sealed and stored. The PDF is rendered and the receipt
   queued.
4. The client shows the record id and hash and offers the PDF.

### Record format

```jsonc
{
  "format": "sealform/record@1",
  "id": "sf_01J...",                       // ULID
  "document": { "id": "studio-tester", "version": "PLINKWICK-TEST-2026-11-v3", "lang": "en", "sha256": "..." },
  "disclosure": { "version": "esign-1", "lang": "en", "sha256": "..." },
  "envelope": { "id": "env_...", "role": "counterparty", "order": 1 },   // contract links only
  "fields": { "legalName": "...", "email": "...", "country": "DE" },
  "consent": { "esign": true, "acceptVersion": true },
  "signature": { "typedName": "...", "vector": [], "pngSha256": "..." },
  "assurance": { "level": "ses", "checks": [{ "kind": "email-receipt", "status": "queued" }] },
  "server": { "receivedAt": "...", "sessionOpenedAt": "...", "ip": "...", "userAgent": "...", "acceptLanguage": "..." },
  "client": { "reportedAt": "...", "timeZone": "...", "screen": "390x844", "locale": "..." },
  "chain": { "seq": 41, "prevHash": "..." },
  "hash": "...",
  "seal": { "alg": "Ed25519", "kid": "plinkwick-2026-11", "sig": "..." }
}
```

- `hash` is SHA-256 over the RFC 8785 form of everything except `hash` and `seal`.
- `seal.sig` is Ed25519 over `sealform-seal-v1:<hash>`. The private key stays outside the web root.
  Public keys are served at `/.well-known/sealform-keys.json` by `kid`, so rotation never orphans old
  records.
- `chain.prevHash` is the previous record's hash; the first record links to 64 zeros. Appends are
  serialized in a database transaction.
- A tombstone keeps `id`, `chain`, `hash` and `seal` and drops everything else. The seal still verifies
  against the kept hash, so the chain stays provable after personal data is gone.

### PDF certificate

pdf-lib renders the document text, answers, signature image, server facts, hash, seal and a "how to
verify" line. The PDF's SHA-256 is stored with the record. The PDF is the human copy; the sealed record
is the evidence.

## Retention and legal hold

Signed records are evidence, so they are never deleted on request and never by an ordinary admin
action. Privately sent agreements are still covered by GDPR and UK GDPR: those laws apply to any
business handling personal data of people in the EU or UK, and the only carve-out is for an
individual's purely personal or household activity. GDPR does not get in the way of keeping a signed
agreement, though. Performing the contract and defending legal claims are lawful reasons to hold it,
and erasure does not apply while it is needed for a claim. What GDPR asks for is an end date tied to
that reason, normally the longest limitation period that could apply plus a margin. A published notice
(Plinkwick's says up to four years after participation ends) is also a promise. The rules:

- Each document version sets `retainSignedFor`, defaulting to the longest limitation period among the
  jurisdiction profiles that apply (see below), and `purgeUnsignedAfter` (abandoned sessions, rejected
  applications; Plinkwick uses 90 days). For example, `retainSignedFor: P4Y` after the relationship ends, and
  `purgeUnsignedAfter` (abandoned sessions, rejected applications; Plinkwick uses 90 days).
- An erasure request against a signed record is logged and answered with the legal-claims exception
  (GDPR Art. 17(3)(e)); the record stays.
- **Legal hold** on a record, a signer or a document blocks every purge until released. Placing and
  releasing a hold needs the owner role and is audit-logged.
- When retention ends and there is no hold, the owner confirms a tombstone. Nothing is purged silently.

## Jurisdictions and stronger checks

### Jurisdiction profiles

A profile is a versioned data file per country (and per region where it matters, such as US states or
Canadian provinces). Choosing a country in the form loads its profile, and the profile drives the rest:

| Profile field | What it does in the form or record |
| --- | --- |
| `eSignLaw` | Name and citation of the e-signature law, shown in the disclosure and saved in the record |
| `signatureLevelDefault` | The level a simple e-signature reaches there (for example "SES under eIDAS") |
| `formRequirements` | Document types that need more than a simple e-signature (written form, notarization, qualified signature). The form blocks or upgrades checks when a document's `category` matches |
| `ageOfMajority` | Minimum age for contracts, with regional overrides. Drives the adult confirmation wording |
| `requiredFields` | Extra fields the record should carry there, such as region or state, or a tax id for paid contracts |
| `notices` | Local text to show before signing: consumer rights, withdrawal periods, privacy rights, data transfer notice, language rights |
| `languages` | Languages the profile expects a translation in, and whether the local language must be offered |
| `privacyRegime` | GDPR, UK GDPR, Argentina's Law 25,326, CCPA and so on. Drives retention defaults and the transfer notice |
| `limitationPeriod` | Longest contract claim period, used for the retention default |
| `checks` | Checks to require or recommend, such as `email-otp` |
| `sources` | URL, title and "checked on" date for every fact above |

The record saves the profile id and version that applied, so evidence shows what rules the signer was
shown at the time. A country with no profile falls back to a cautious default profile, and the admin
lists signers who fell back to it.

**When the studio countersigns.** On a contract envelope, the dashboard shows the counterparty's
profile before you sign: what level the signature reaches there, any form requirement the document
category triggers, required fields that are missing, and the notices the signer saw. The studio's own
profile (California for Plinkwick) is applied to your side. A conflict, such as a document that needs a
qualified signature in the counterparty's country, blocks countersigning until it is resolved or
overridden with a logged reason.

**Profiles shipped.** The library ships the profile format, the default profile and profiles for the
countries its first operator needs: US (with California), UK, Germany, Latvia, Argentina, Japan, South
Africa, the Netherlands and Belgium. Every fact
is sourced from primary law or a government site and dated. Profiles are data, not legal advice, and
they go stale: the dashboard flags any profile whose sources were checked more than a year ago.
More countries are added as files, without code changes.

### Per document version

- `category`, such as `nda`, `tester-agreement`, `services-contract` or `waiver`, matched against
  profiles' `formRequirements`.
- `allowedCountries` / `blockedCountries`, checked against the signer's declared country.
- `requiredChecks`, globally or per country, for example `{ "default": [], "DE": ["email-otp"] }`.
- `excludedUse`: a warning list shown in the admin when a document is a type many laws exclude from
  simple e-signatures (wills, real-estate transfers, family-law matters, negotiable instruments, some
  consumer notices). sealform warns; it does not decide.
- `minimumAge`, raised to the profile's `ageOfMajority` where that is higher. Self-attested by the signer.
- Translations: each language is its own hashed text. The record stores which language was shown, and
  a `governingLang` decides which text controls.

Verification providers sit behind one `Check` interface. Each declares the assurance level it adds.
All ship disabled; a disabled check required by a document blocks publishing that document.

| Check | What it adds | Ships |
| --- | --- | --- |
| `email-receipt` | Delivery of the copy to the stated address | on |
| `email-otp` | Control of the mailbox before signing | off |
| `sms-otp` | Control of a phone number | off, needs a provider |
| `passkey` | WebAuthn binding to a device the signer controls | off |
| `id-document` | Government ID plus liveness (Stripe Identity, Persona, Veriff style) | off, provider stub |
| `qes` | Qualified signature through an eIDAS trust provider (CSC API) | off, provider stub |
| `tsa` | RFC 3161 trusted timestamp on the record hash | off |
| `pades` | Certificate signature on the PDF itself, so PDF readers show it as signed | off |

## Admin dashboard

Served by the same handler under a configurable, non-obvious path (for example `/_sf/`), never linked
from the public site, `noindex` and `frame-ancestors 'none'`.

- **Auth:** accounts created with `sealform admin create` (first owner) or by an owner. Passwords hashed
  with scrypt (built in; argon2id would need a native package). TOTP two-factor, required for owners.
  HttpOnly, Secure, SameSite=Strict session cookies, rotated on login. Login rate-limited per IP and
  per account, with backoff and lockout (WEB-REFERENCES §1.1 Auth). CSRF token on every write.
- **Roles:** `owner` (everything, keys, holds, tombstones, site controls), `admin` (documents, links,
  submissions), `reviewer` (read submissions, set application status).
- **Sign-ins:** every login, failure and lockout listed with IP and user agent; active sessions can be
  revoked.
- **Audit log:** every admin write, hash-chained and sealed like records. Read-only in the UI.
- **Documents:** draft, publish, close, new version from old, translations, field schema editor,
  required checks, retention, preview. Published versions are immutable.
- **Submissions:** filter by document, version, status, country, date. View the record, signature, PDF
  and verification result. Set an application status (`pending`, `accepted`, `rejected`, `withdrawn`).
  Export CSV and record bundles. Legal hold.
- **Private signing links (contracts):** an envelope names one or more signers, each with a single-use,
  expiring link token (stored hashed). Optional prefilled name and email that the signer cannot change.
  Optional operator countersignature as the last step. Each signer's record carries the envelope; a
  final envelope record lists all signer hashes and is sealed. Links can be revoked. Envelope documents
  are never listed publicly.
- **Site controls:** see below.

The dashboard is plain TypeScript and SCSS bundled by esbuild, rendered from templates in the package.
It uses the operator's own colors through CSS custom properties.

## Site layer (optional)

When the Node app also serves the site (cPanel setup), `createSealform` can serve a static build
directory with:

- **Page visibility:** per path or prefix, `public`, `hidden` (404), or `private` (needs an admin
  session). Rules are stored and edited in the dashboard, audit-logged.
- **Parking mode:** one switch that serves a parking page (HTTP 503 with `Retry-After`) for every public
  path except an allowlist (the parking page's assets, `/.well-known/`, the admin path). The parking page
  is the host site's `parked/index.html` if it exists, else a plain built-in one.
- **Site info:** read-only status in the dashboard: build time, version, record count, chain head, key
  ids, mail outbox size, disabled checks.

## Security

Per WEB-REFERENCES §1.1: schema validation at every server boundary, size caps, rate limits, Turnstile on
public signing, CSRF tokens, a CORS allowlist, strict CSP on dashboard pages, no personal data in logs,
secrets and data outside the web root, parameterized SQL only, link tokens and session ids stored as
hashes, constant-time comparisons.

## Public repo hygiene

- `.gitignore` covers `data/`, `keys/`, `outbox/`, `.env*`, `*.key`, `*.pem`, `*.jwk.json`.
- `npm run check` includes a secret scan of tracked files (private-key JWK `"d"` members, PEM blocks,
  common token prefixes). It runs before tests.
- Examples use placeholder values and `example.com`. No operator document text in the repo.
- `SECURITY.md` explains reporting and what the threat model does and does not cover.

## Plinkwick changes

Made in `plinkwick-web` and `fishing-game/Docs/Legal`, not here.

- **Now:** `/testing/` drops the Tally iframe and script and shows the agreement with a disabled form
  and a "signing reopens soon" note. CSP drops `tally.so`. The tester privacy text that describes Tally
  changes in `Docs/Legal` and is synced. Keehan closes Tally form `1WPdRW`. A Plinkwick parking page
  (`src/parked/`) is added for the site layer to use after the move.
- **At the cPanel move:** agreement v3 (new provider, new data collected, new record location), a
  sealform deployment config (kept private, outside this repo), the form mounted on `/testing/`, the
  public key published.

## Phases

Each phase ends with the diff and a stop.

1. Repo scaffold, README, SECURITY, secret scan, `sealform/core`, CLI `keygen` / `verify` /
   `verify-chain`, tests.
2. Server signing: `SqliteStore`, handler, documents and sessions, Turnstile, rate limits, PDF,
   outbox mailer, `Check` interface with disabled providers, retention and holds.
3. Client signing form and a local demo.
4. Admin: auth, TOTP, roles, sign-ins, audit log, documents, submissions.
5. Jurisdiction profiles: format, default profile, the nine sourced profiles, form behaviour.
6. Admin: envelopes and private links, countersignature with the profile review.
7. Site layer: page visibility, parking mode, site info.
8. Plinkwick "form disabled" switch and parking page (can run any time).
9. At the move: v3 legal text, Plinkwick integration, cPanel deploy.

## Calls made (check these)

- Node.js only; no PHP adapter.
- SQLite by default, evidence files mirrored on disk; MySQL later.
- scrypt for passwords, because argon2id needs a native build on shared hosting.
- Turnstile on public signing (works on any host). Keys created when phase 2 needs them.
- RFC 3161 timestamps and PDF certificate signatures are designed in but off.
- MIT license for the public repo.
- Framework-free browser code (plain TypeScript), bundled with esbuild.
- "Parking page" means a site-wide holding page the owner can switch on from the dashboard.

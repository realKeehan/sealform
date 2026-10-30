# sealform

Self-hosted electronic signatures that hold up to scrutiny. Someone reads a versioned document, signs
it, and you keep a sealed record proving what they saw, when they signed, and that nobody has edited
the record since. Anyone can check it with nothing but the record and your public key.

Built for small operators who need waivers, tester agreements and contracts without a per-envelope
bill: one Node.js app, no external database, no vendor holding your records.

> **Status: early.** Everything on the [roadmap](#roadmap) except real-world deployment is built and
> tested: the core, the command line, the signing server, the embeddable form, the admin dashboard,
> jurisdiction profiles, private contract links and the site layer. It has not been deployed or used
> for real signatures yet, and the jurisdiction profiles have not been reviewed by a lawyer.

## How a signature becomes evidence

```text
 signer's browser                         your server                              anyone, later
 ────────────────                         ───────────                              ─────────────
 reads document v3  ──── text hash ────▶  hash must match the published v3
 ticks e-sign consent                     records IP, user agent, time (server clock)
 types name, draws signature ──────────▶  builds the record, canonical JSON
                                          SHA-256  ─▶  Ed25519 seal  ─▶  chain to previous
                                          stores it, emails the signer a PDF copy
                                                                    record + public key ──▶ sealform verify
```

Every record carries:

| Part | Why it matters |
| --- | --- |
| Document id, version, language and SHA-256 | Ties the signature to the exact text shown |
| Consent flags and the e-sign disclosure hash | Shows agreement to sign electronically, and to which disclosure |
| Typed name, signature vectors, PNG hash | Shows intent to sign |
| Server-recorded time, IP, user agent, language | Attribution, from your server, not from the browser |
| Assurance checks | Which identity checks ran, if any |
| Chain link (`seq`, `prevHash`) | A removed or reordered record is detectable |
| `hash` and `seal` | Any edit after signing is detectable, and only your key could have sealed it |

## Is it legally binding?

sealform is built to meet what electronic-signature laws such as the US ESIGN Act and UETA look for:
consent to sign electronically, intent to sign, association of the signature with the record, and a
record that can be retained and reproduced. Under EU eIDAS this is a *simple* electronic signature:
admissible as evidence, not automatically equal to a handwritten one.

It is not legal advice and it does not make every document signable. Many countries exclude some
documents (wills, property transfers, family matters) from simple e-signatures, and some contracts
need a qualified signature. Ask a lawyer about yours. sealform's job is to make sure that when the
question comes up, the evidence is there and checks out.

## Quick start

Requires Node.js 22.13 or newer.

```bash
npm install
npm run build

# Create a sealing key. The private key file must stay secret and outside your web root.
npx sealform keygen --kid myproject-2026-11 --dir ./keys

# Publish keys/sealform-keys.json at https://your-site/.well-known/sealform-keys.json

# Verify a single record, or a whole chain exported one record per line
npx sealform verify record.json --keys ./keys/sealform-keys.json
npx sealform verify-chain records.jsonl --keys https://your-site/.well-known/sealform-keys.json
```

`verify` exits with 0 when the record checks out, 1 when it does not, and 2 on bad input.

### Using the core in code

```ts
import { verifyEntry, type KeySet } from 'sealform/core';

const keyset: KeySet = await (await fetch('https://example.com/.well-known/sealform-keys.json')).json();
const result = await verifyEntry(record, keyset);
// result.ok, result.hash ('ok' | 'mismatch' | ...), result.seal ('ok' | 'invalid' | ...), result.errors
```

`sealform/core` runs in browsers and Node alike (Web Crypto only), so you can build a "check my
signed copy" page with the same code the server uses.

### Running the signing server

```js
// app.js, the startup file for cPanel "Setup Node.js App", or any Node host
import { createServer } from 'node:http';
import { createSealform, TurnstileCheck } from 'sealform/server';

const sealform = await createSealform({
  dataDir: '/home/you/sealform-data',              // outside public_html
  documentsDir: '/home/you/sealform-documents',
  sealingKey: '/home/you/keys/myproject-2026-11.private.jwk.json',
  keySet: '/home/you/keys/sealform-keys.json',
  publicOrigin: 'https://example.com',
  operator: { name: 'Example Studio', email: 'legal@example.com' },
  botCheck: new TurnstileCheck(process.env.TURNSTILE_SECRET),
  clientIp: 'x-forwarded-for',                     // only behind a proxy you control
});

createServer(sealform.handler).listen(process.env.PORT ?? 3000);
```

Each document version is a folder: `<id>/<version>/document.json` (title, fields, consent wording,
retention, required checks) plus one Markdown file per language. Published versions are hashed at
startup, and a signature is only sealed when the text and form the signer saw match those hashes.
See `test/fixtures/documents` for a complete example.

### Embedding the signing form

```html
<link rel="stylesheet" href="/vendor/sealform.css" />
<div id="sign"></div>
<script type="module">
  import { mountSealform } from '/vendor/sealform.js';
  mountSealform(document.getElementById('sign'), {
    endpoint: '/sealform',
    documentId: 'tester-agreement',
    turnstileSiteKey: '0x4AAA...',     // when the server uses TurnstileCheck
  });
</script>
```

Copy `sealform.js` and `sealform.css` from `node_modules/sealform/dist/client/`, or import
`sealform/client` from a bundler. The form renders the document, a consent disclosure, the fields,
a drawn signature pad (finger, stylus or mouse) next to the typed legal name, and a receipt with
download links. A drawing is required; offer people who cannot draw an alternative through your
support contact. It inherits the page font; set `--sf-accent`, `--sf-ink`,
`--sf-paper`, `--sf-line`, `--sf-radius` and friends to match your site. Every label can be
replaced through the `labels` option for translations.

Try it locally with `npm run build && npm run demo`, then open http://localhost:5180.

### Jurisdiction profiles

The signer's country picks a profile from `profiles/`: the e-signature law that applies, the age of
majority, notices to show before signing, extra fields the country needs, and which kinds of document
(wills, property transfers, suretyships and so on) the law excludes from a simple electronic signature.
The form fetches the profile when a country is chosen, and the server refuses to seal unless the
signer was shown that exact profile: its hash is stored in the record, so the evidence shows which
rules and notices applied. A document whose `category` a country excludes is refused there with the
reason. Countries without a profile get a cautious default, and the record says so.

The dashboard also compares how long a document keeps signed records with the usual claim period in
each signer's country (the document page flags a retention that is shorter), and `operatorJurisdiction`
(for example `'US-CA'`) makes contract creation check your own side's law as well as the signer's. Both
are flags for a decision, not rules: retention is also limited by data protection law.

Profiles ship for the US (and California), UK, Germany, Latvia, Argentina, Japan, South Africa, the
Netherlands and Belgium. They are plain JSON, so adding a country is a file:
`id`, `eSignLaw`, `ageOfMajority`, `formRequirements`, `requiredFields`, `notices`, `sources` and so on
(see `src/server/profiles.ts` for the checked shape, and point `profilesDir` at your own folder).

> **Read this before relying on a profile.** The profiles were written from public sources and general
> knowledge, with every source listed, but they have **not been reviewed by a lawyer** and were not
> re-checked against the live sources when written. `reviewedBy` is `null` until someone sets it, and the
> dashboard flags unreviewed profiles and any older than a year. They are evidence settings, not
> legal advice.

### Private contract links

For agreements with partners and other people, a document with `"public": false` is never listed. An
owner or admin makes a link for one named signer from the dashboard's **Contracts** page: choose the
document, the signer's name and email (fixed on their form), an expiry and whether you will
countersign. The link is shown once; only a hash of it is stored. It works once, can be cancelled, and
its hosted signing page needs no site of yours. Entering the signer's country checks the document
against that country's profile first; if the law there excludes this kind of document, creating the link
needs a stated reason, which is kept in the audit log.

Countersigning is a sealed entry in the audit log naming the account, the signer's record hash and a
final hash of the whole agreement, and it emails the signer a confirmation. It is a decision recorded
under your account, not a drawn signature.

### Serving the website too

On a host where one Node app serves everything (the usual cPanel setup), give sealform the built site
and it serves it, with two controls a static host does not have:

```js
const sealform = await createSealform({
  /* ... */
  adminPath: '/_sf',
  site: { dir: '/home/you/site/dist', headers: { 'content-security-policy': "default-src 'self'" } },
});
```

- **Hidden and private pages.** In the dashboard's **Site** page (owners), add a path. *Hidden* answers
  404 to everyone; *private* answers 404 unless you are signed in to the dashboard. A path covers
  everything under it, and `/about` and `/about/` are one rule.
- **Parking.** One switch holds the whole site behind your `parked/index.html` (or a plain built-in
  page) with HTTP 503 and `Retry-After`, except `/parked/`, `/assets/`, `/.well-known/`,
  `/favicon.ico`, `/robots.txt` and any `parkingAllow` paths you add. The signing form, contract links
  and the dashboard are not part of the site and keep working while it is parked.
- **Site info.** Last build time, whether the parked and 404 pages exist, the record count and chain
  head, the sealing and published keys, and which checks are not configured.

Static serving refuses dotfiles, `..` in any encoding, and symlinks that leave the folder; it sets
`nosniff`, ETags and cache headers. Rules and the parking switch live in the database and every change
is in the audit log. Private pages recognise the dashboard session cookie, which is why that cookie is
scoped to the whole host (it stays HttpOnly and SameSite=Strict).

### The admin dashboard

Set `adminPath` to turn it on, and pick a path that nothing links to:

```js
const sealform = await createSealform({ /* ... */ adminPath: '/_sf' });
```

To put Turnstile on the sign-in page, give the dashboard your public site key. The secret is the same
one the public form uses. With Turnstile as the bot check, the dashboard refuses to start without the
key, so it is never left unprotected by accident:

```js
const sealform = await createSealform({
  /* ... */
  adminPath: '/_sf',
  botCheck: new TurnstileCheck(process.env.TURNSTILE_SECRET),
  adminTurnstileSiteKey: '0x4AAA...',
});
```

The check runs before any account lookup or password work, so a bot learns nothing and cannot lock
the real account by hammering it. Only the sign-in page loads Cloudflare's script; every other
dashboard page keeps a policy that forbids scripts. To try it locally without an account, run the demo
with Cloudflare's test keys: `TURNSTILE_SITE_KEY=1x00000000000000000000AA
TURNSTILE_SECRET=1x0000000000000000000000000000000AA npm run demo`.

To use **Cloudflare Access with Google** instead of passwords, set `adminAccess` with your team domain
and application audience. sealform then verifies Cloudflare's signed token on every dashboard request
and matches its email to a dashboard account. Setup steps are in
[docs/CLOUDFLARE-ACCESS.md](docs/CLOUDFLARE-ACCESS.md).

Create the first owner from the command line. The temporary password is printed once:

```bash
npx sealform admin create --data /home/you/sealform-data   --key /home/you/keys/myproject-2026-11.private.jwk.json   --email you@example.com --name "Your Name" --role owner
```

| Page | Who | What |
| --- | --- | --- |
| Overview | everyone | Counts by status, what is open for signing, the chain head, checks not configured |
| Submissions | everyone | Search and filter, per-record view with the signature, answers and all captured evidence, per-record verification, PDF and record downloads, application status |
| Documents | owner, admin | Versions, languages, hashes, publish and close (publishing closes the previous version) |
| Contracts | owner, admin | Private signing links: create, cancel, countersign, and the country check |
| Site | owner | Parking switch, hidden and private page rules, site info (when `site` is set) |
| Accounts | owner | Create accounts with a temporary password, change roles, disable, reset |
| Sign-ins | everyone (owners see all) | Every attempt with IP and browser, successful or not |
| Audit log | owner | Every dashboard change, hash-chained and sealed like records, exportable and checkable with `sealform verify-chain` |
| My account | everyone | Password, two-factor setup, active sessions you can sign out |

Roles: **reviewers** read submissions and set their status. **Admins** also manage documents and
export CSV. **Owners** also manage accounts, place legal holds and read the audit log.

How it is protected: scrypt password hashes; TOTP two-factor that owners cannot turn off, with codes
that cannot be replayed; an account locks for 15 minutes after five failures; sessions live in
HttpOnly, SameSite=Strict cookies, idle out after 2 hours and end after 12; every change needs a CSRF
token and a same-origin request; pages are server-rendered with escaping everywhere and a CSP that
forbids scripts. The last active owner cannot be demoted or disabled.

Signing stores the record in SQLite and as files, renders a PDF copy, and writes the receipt email
to an outbox folder until a mail transport is configured.

## Retention

Signed records are evidence, so sealform never deletes them on request. They are not kept forever
either: each document sets how long signed records are retained, legal holds block any removal, and
when retention ends the owner turns a record into a *tombstone*. A tombstone keeps only the id, chain
link, hash and seal, so the chain still verifies while the personal data is gone.

## Roadmap

| Part | State |
| --- | --- |
| `sealform/core`: canonical JSON, hashing, Ed25519 seals, chain and tombstone verification | done |
| CLI: `keygen`, `verify`, `verify-chain` | done |
| Signing server: documents, sessions, bot check, rate limits, PDF copy, email receipt | done |
| Unicode fonts in the PDF copy (names in Japanese, Greek, Cyrillic and so on print as "?" today; the sealed record is exact) | planned |
| Retention, legal holds and tombstoning from the CLI | planned |
| Embeddable signing form (`signature_pad`), themeable, reduced-motion aware | done |
| Admin dashboard: accounts, two-factor sign-in, sign-in history, sealed audit log, documents, submissions | done |
| Jurisdiction profiles: nine countries plus a default, notices, required fields, excluded document types, hash in the record (not lawyer-reviewed) | done |
| Private signing links for contracts, with countersignature | done |
| Site layer: serve the built site, hidden and private pages, parking mode, site info | done |
| Optional checks: email one-time code, SMS, passkeys, ID verification, qualified signatures, RFC 3161 timestamps, signed PDFs | designed, off by default |

The full design is in [docs/DESIGN.md](docs/DESIGN.md).

## Development

```bash
npm run check   # secret scan, typecheck, tests
```

Before committing, `npm run secrets` checks every file git would commit for keys and tokens. List
strings that are private to you (a personal email, an internal hostname) in `.secretscan-blocklist`,
which is git-ignored, so the scan catches them without publishing them.

## Security

See [SECURITY.md](SECURITY.md) for what sealform protects, what it does not, and how to report a
problem privately.

## License

[MIT](LICENSE)

# sealform

Self-hosted electronic signatures that hold up to scrutiny. Someone reads a versioned document, signs
it, and you keep a sealed record proving what they saw, when they signed, and that nobody has edited
the record since. Anyone can check it with nothing but the record and your public key.

Built for small operators who need waivers, tester agreements and contracts without a per-envelope
bill: one Node.js app, no external database, no vendor holding your records.

> **Status: early.** The core (hashing, sealing, verification), the command line, the signing
> server, the embeddable form and the admin dashboard are done and tested. Private contract links,
> jurisdiction profiles and site controls are next. See the [roadmap](#roadmap).

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

### The admin dashboard

Set `adminPath` to turn it on, and pick a path that nothing links to:

```js
const sealform = await createSealform({ /* ... */ adminPath: '/_sf' });
```

Create the first owner from the command line. The temporary password is printed once:

```bash
npx sealform admin create --data /home/you/sealform-data   --key /home/you/keys/myproject-2026-11.private.jwk.json   --email you@example.com --name "Your Name" --role owner
```

| Page | Who | What |
| --- | --- | --- |
| Overview | everyone | Counts by status, what is open for signing, the chain head, checks not configured |
| Submissions | everyone | Search and filter, per-record view with the signature, answers and all captured evidence, per-record verification, PDF and record downloads, application status |
| Documents | owner, admin | Versions, languages, hashes, publish and close (publishing closes the previous version) |
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
| Jurisdiction profiles: the signer's country sets the law cited, age rules, notices, required fields and checks, all sourced and dated | planned |
| Private signing links for contracts, with countersignature | planned |
| Site controls: hide pages, parking mode | planned |
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

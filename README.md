# sealform

Self-hosted electronic signatures that hold up to scrutiny. Someone reads a versioned document, signs
it, and you keep a sealed record proving what they saw, when they signed, and that nobody has edited
the record since. Anyone can check it with nothing but the record and your public key.

Built for small operators who need waivers, tester agreements and contracts without a per-envelope
bill: one Node.js app, no external database, no vendor holding your records.

> **Status: early.** The core (hashing, sealing, verification) and the command line are done and
> tested. The signing server, the embeddable form and the admin dashboard are in progress. See the
> [roadmap](#roadmap).

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
| Signing server: documents, sessions, bot check, rate limits, PDF copy, email receipt | next |
| Embeddable signing form (`signature_pad`), themeable, reduced-motion aware | planned |
| Admin dashboard: accounts, two-factor sign-in, sign-in history, audit log, documents, submissions | planned |
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

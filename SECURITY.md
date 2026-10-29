# Security

## Reporting a problem

Please report vulnerabilities privately through GitHub's "Report a vulnerability" button on this
repository (Security tab), not in a public issue. Include what you found, how to reproduce it and what
an attacker gains. You will get a reply, and a fix or an explanation, before anything is disclosed.

## What sealform protects

- **Integrity.** A record's content is hashed (SHA-256 over RFC 8785 canonical JSON) and the hash is
  sealed with the operator's Ed25519 key. Changing any byte of a record, or recomputing its hash
  after an edit, fails verification.
- **Completeness.** Records form a hash chain. Removing, inserting or reordering a record breaks the
  chain at that point. Compare the chain head with a copy kept elsewhere to detect truncation of the
  newest records.
- **Association.** The record carries the SHA-256 of the exact document text shown to the signer,
  checked against the published version on the server before sealing.

## What it does not protect against

- **A stolen sealing key.** Whoever holds the private key can seal new, valid-looking records. Keep it
  outside the web root with owner-only permissions, rotate it if it may have leaked, and publish the
  retirement date in the key set.
- **Rewriting the whole chain.** An operator with the private key could rebuild every record. Publishing
  the chain head regularly, or adding RFC 3161 timestamps (designed, off by default), limits this.
- **Identity.** A simple electronic signature shows that someone with this email, on this network and
  device, signed this text. It does not prove who that person is. Stronger checks (one-time codes,
  passkeys, ID verification, qualified signatures) are designed as optional providers.
- **Legal advice.** sealform keeps evidence. Whether a given agreement is enforceable where a signer
  lives is a question for a lawyer.

## Operator checklist

- Data directory and keys outside the web root, readable only by the app user.
- `npm run secrets` passes before every commit. Put strings private to you in `.secretscan-blocklist`.
- HTTPS only, with HSTS.
- The admin path is not linked from the public site, and owners use two-factor sign-in.

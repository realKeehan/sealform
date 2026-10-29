// Fails if any file git would commit looks like it holds a secret.
//
// Generic patterns live here. Strings that are private to one operator (a personal email, a
// hostname) must not be written into this public file: list them one per line in
// .secretscan-blocklist (git-ignored) or in the SEALFORM_SECRETSCAN_BLOCKLIST environment variable,
// separated by commas.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';

const PATTERNS = [
  ['private key block', /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
  ['private JWK member "d"', /"d"\s*:\s*"[A-Za-z0-9_-]{40,}"/],
  ['sealform private key file', /sealform\/private-key@1/],
  ['OpenAI-style key', /\bsk-[A-Za-z0-9_-]{20,}/],
  ['AWS access key id', /\bAKIA[0-9A-Z]{16}\b/],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/],
  ['Slack token', /\bxox[abprs]-[A-Za-z0-9-]{10,}/],
  ['Stripe secret key', /\b[sr]k_live_[A-Za-z0-9]{20,}/],
  ['Resend key', /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/],
  ['private key in assignment', /(PRIVATE_KEY|SECRET|PASSWORD|TOKEN)\s*=\s*['"][^'"\s]{12,}['"]/],
];

// Files that legitimately mention the patterns above.
const ALLOW = new Set(['scripts/check-secrets.mjs', 'src/core/keys.ts', 'SECURITY.md', 'docs/DESIGN.md']);

const blocklist = [
  ...(existsSync('.secretscan-blocklist') ? readFileSync('.secretscan-blocklist', 'utf8').split(/\r?\n/) : []),
  ...(process.env.SEALFORM_SECRETSCAN_BLOCKLIST ?? '').split(','),
]
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith('#'));

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard', '-z'], { encoding: 'utf8' })
  .split('\0')
  .filter(Boolean);

const findings = [];
for (const file of files) {
  if (!existsSync(file)) continue;
  const buffer = readFileSync(file);
  if (buffer.includes(0)) continue; // binary
  const text = buffer.toString('utf8');
  if (!ALLOW.has(file)) {
    for (const [name, pattern] of PATTERNS) if (pattern.test(text)) findings.push(`${file}: ${name}`);
  }
  for (const needle of blocklist) if (text.toLowerCase().includes(needle.toLowerCase())) findings.push(`${file}: blocklisted string`);
}

if (findings.length) {
  console.error(`Secret scan failed (${findings.length}):`);
  for (const finding of findings) console.error(`  ${finding}`);
  process.exit(1);
}
console.log(`Secret scan passed: ${files.length} files, ${PATTERNS.length} patterns, ${blocklist.length} blocklisted strings.`);

#!/usr/bin/env node
// sealform command line. Phase 1: keygen, verify, verify-chain.

import { constants } from 'node:fs';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { parseArgs } from 'node:util';
import {
  emptyKeySet,
  generateKeyPair,
  KEYSET_FORMAT,
  verifyChain,
  verifyEntry,
  type ChainEntry,
  type EntryResult,
  type KeySet,
} from '../core/index.ts';

const USAGE = `sealform <command> [options]

Commands
  keygen --kid <id> [--dir <path>]       Create an Ed25519 sealing key. Writes <id>.private.jwk.json
                                         (keep it secret, outside the web root) and adds the public
                                         key to sealform-keys.json in the same directory.
  admin create --data <dir> --key <private-key-file> --email <e> --name <n> [--role owner|admin|reviewer]
                                         Create a dashboard account with a one-time temporary password,
                                         printed once. The first account should be an owner.
  tombstone <id> --data <dir> --key <private-key-file> --confirm <id> --offline
                                         Remove one record's personal data, preserving its chain proof.
                                         Pause all signing writers first. Legal holds block removal.
  verify <record.json> --keys <src>      Verify one record, tombstone or audit entry.
  verify-chain <records.jsonl> --keys <src> [--start-seq <n>] [--start-prev <hash>]
                                         Verify every entry and the links between them.

  <src> is a key set file path or an https URL such as
  https://example.com/.well-known/sealform-keys.json

Options
  --json      Print machine-readable results.
  --help      Show this help.

Exit codes: 0 verified, 1 verification failed, 2 usage or input error.`;

async function main(argv: string[]): Promise<number> {
  const [command, ...rest] = argv;
  if (!command || command === '--help' || command === 'help') {
    console.log(USAGE);
    return command ? 0 : 2;
  }
  switch (command) {
    case 'keygen':
      return keygen(rest);
    case 'admin':
      return admin(rest);
    case 'tombstone':
      return tombstoneCommand(rest);
    case 'verify':
      return verify(rest);
    case 'verify-chain':
      return verifyChainCommand(rest);
    default:
      console.error(`Unknown command "${command}".\n\n${USAGE}`);
      return 2;
  }
}

async function keygen(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, options: { kid: { type: 'string' }, dir: { type: 'string', default: 'keys' } } });
  if (!values.kid) throw new UsageError('keygen needs --kid, for example --kid studio-2026-11');
  const dir = resolve(values.dir);
  await mkdir(dir, { recursive: true });
  const privatePath = join(dir, `${values.kid}.private.jwk.json`);
  const keysetPath = join(dir, 'sealform-keys.json');
  if (await exists(privatePath)) throw new UsageError(`${privatePath} already exists. Pick a new --kid; never overwrite a key.`);

  const keyset = (await exists(keysetPath)) ? await readKeySet(keysetPath) : emptyKeySet();
  if (keyset.keys.some((key) => key.kid === values.kid)) throw new UsageError(`Key id ${values.kid} is already in ${keysetPath}`);

  const { privateFile, publicEntry } = await generateKeyPair(values.kid);
  await writeFile(privatePath, JSON.stringify(privateFile, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  keyset.keys.push(publicEntry);
  await writeFile(keysetPath, JSON.stringify(keyset, null, 2) + '\n');

  console.log(`Private key: ${privatePath}`);
  console.log('  Keep it outside the web root and out of git. Anyone holding it can seal records as you.');
  console.log(`Public key set: ${keysetPath}`);
  console.log('  Publish it at /.well-known/sealform-keys.json. Keep old keys in it after rotation.');
  return 0;
}

async function admin(args: string[]): Promise<number> {
  const [sub, ...rest] = args;
  if (sub !== 'create') throw new UsageError('Usage: sealform admin create --data <dir> --key <private-key-file> --email <e> --name <n> [--role owner]');
  const { values } = parseArgs({
    args: rest,
    options: { data: { type: 'string' }, key: { type: 'string' }, email: { type: 'string' }, name: { type: 'string' }, role: { type: 'string', default: 'owner' } },
  });
  if (!values.data || !values.key || !values.email || !values.name) throw new UsageError('admin create needs --data, --key, --email and --name');
  // Loaded on demand so verifying records never needs the server code or SQLite.
  const { SqliteStore, AdminStore, ROLES, hashPassword } = await import('../server/index.ts');
  const { importSealingKey } = await import('../core/index.ts');
  if (!ROLES.includes(values.role as never)) throw new UsageError(`--role must be one of ${ROLES.join(', ')}`);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(values.email)) throw new UsageError('--email is not a valid address');

  const key = await importSealingKey(JSON.parse(await readFile(values.key, 'utf8')));
  const store = await SqliteStore.open(resolve(values.data));
  try {
    const db = new AdminStore(store.database, store.dataDir);
    if (db.accountByEmail(values.email)) throw new UsageError(`An account for ${values.email} already exists`);
    const password = randomPassword();
    const account = db.createAccount({
      email: values.email,
      name: values.name,
      role: values.role as 'owner' | 'admin' | 'reviewer',
      passwordHash: await hashPassword(password),
      mustChangePassword: true,
      now: new Date().toISOString(),
    });
    await db.audit(key, { at: new Date().toISOString(), actor: 'system', action: 'account.create', target: account.id, details: { email: account.email, role: account.role, via: 'cli' }, ip: 'cli' });
    console.log(`Created ${account.role} ${account.email}.`);
    console.log(`Temporary password (shown once, change it at first sign-in): ${password}`);
    if (account.role === 'owner') console.log('Owners must also set up two-factor sign-in before using the dashboard.');
  } finally {
    store.close();
  }
  return 0;
}

async function tombstoneCommand(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: {
    data: { type: 'string' }, key: { type: 'string' }, confirm: { type: 'string' }, offline: { type: 'boolean', default: false },
  } });
  const [id] = positionals;
  if (!id || !values.data || !values.key || values.confirm !== id || !values.offline) {
    throw new UsageError('tombstone needs <id>, --data, --key, --confirm <id> and --offline; pause all signing writers first');
  }
  const { SqliteStore, AdminStore } = await import('../server/index.ts');
  const { importSealingKey } = await import('../core/index.ts');
  const key = await importSealingKey(JSON.parse(await readFile(values.key, 'utf8')));
  // Refuse a mistyped data path instead of creating an empty store.
  await access(join(resolve(values.data), 'sealform.sqlite'), constants.R_OK | constants.W_OK);
  const store = await SqliteStore.open(resolve(values.data));
  try {
    const db = new AdminStore(store.database, store.dataDir);
    if (!store.summary(id)) throw new UsageError('No such record');
    await db.audit(key, { at: new Date().toISOString(), actor: 'system', action: 'record.tombstone.requested', target: id, details: { via: 'cli' }, ip: 'cli' });
    const result = await store.tombstone(id);
    await db.audit(key, { at: new Date().toISOString(), actor: 'system', action: 'record.tombstone.completed', target: id, details: { via: 'cli', hash: result.hash }, ip: 'cli' });
    console.log('Tombstoned ' + id + '; chain proof retained.');
  } finally {
    store.close();
  }
  return 0;
}

function randomPassword(): string {
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(25));
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join('').match(/.{5}/g)!.join('-');
}

async function verify(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, allowPositionals: true, options: { keys: { type: 'string' }, json: { type: 'boolean', default: false } } });
  const [file] = positionals;
  if (!file || !values.keys) throw new UsageError('verify needs a record file and --keys');
  const keyset = await loadKeySet(values.keys);
  const entry = parseJson(await readFile(file, 'utf8'), file) as ChainEntry;
  const result = await verifyEntry(entry, keyset);
  if (values.json) console.log(JSON.stringify(result, null, 2));
  else printEntry(result);
  return result.ok ? 0 : 1;
}

async function verifyChainCommand(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args,
    allowPositionals: true,
    options: {
      keys: { type: 'string' },
      json: { type: 'boolean', default: false },
      'start-seq': { type: 'string' },
      'start-prev': { type: 'string' },
    },
  });
  const [file] = positionals;
  if (!file || !values.keys) throw new UsageError('verify-chain needs a records file and --keys');
  const keyset = await loadKeySet(values.keys);
  const lines = (await readFile(file, 'utf8')).split(/\r?\n/).filter((line) => line.trim() !== '');
  const entries = lines.map((line, i) => parseJson(line, `${file} line ${i + 1}`) as ChainEntry);

  const options: { startSeq?: number; startPrevHash?: string } = {};
  if (values['start-seq'] !== undefined) {
    const n = Number(values['start-seq']);
    if (!Number.isSafeInteger(n) || n < 0) throw new UsageError('--start-seq must be a non-negative integer');
    options.startSeq = n;
  }
  if (values['start-prev'] !== undefined) options.startPrevHash = values['start-prev'];

  const result = await verifyChain(entries, keyset, options);
  if (values.json) {
    console.log(JSON.stringify(result, null, 2));
  } else {
    for (const entry of result.entries) printEntry(entry);
    console.log('');
    console.log(`${result.ok ? 'CHAIN OK' : 'CHAIN BROKEN'}: ${result.length} entries, head ${result.head}`);
    for (const brk of result.breaks) console.log(`  at #${brk.index} (${brk.id}): ${brk.reason}`);
  }
  return result.ok ? 0 : 1;
}

function printEntry(result: EntryResult): void {
  console.log(`${result.ok ? 'OK  ' : 'FAIL'} ${result.kind} ${result.id} seq=${String(result.seq)} hash=${result.hash} seal=${result.seal}`);
  for (const error of result.errors) console.log(`       ${error}`);
}

async function loadKeySet(source: string): Promise<KeySet> {
  if (/^https:\/\//i.test(source)) {
    const response = await fetch(source, { headers: { accept: 'application/json' } });
    if (!response.ok) throw new UsageError(`Could not fetch key set: HTTP ${response.status}`);
    return checkKeySet(await response.json(), source);
  }
  if (/^http:\/\//i.test(source)) throw new UsageError('Key sets must be fetched over https');
  return readKeySet(source);
}

async function readKeySet(path: string): Promise<KeySet> {
  return checkKeySet(parseJson(await readFile(path, 'utf8'), path), path);
}

function checkKeySet(value: unknown, source: string): KeySet {
  const keyset = value as Partial<KeySet>;
  if (keyset?.format !== KEYSET_FORMAT || !Array.isArray(keyset.keys)) throw new UsageError(`${source} is not a sealform key set`);
  return keyset as KeySet;
}

function parseJson(text: string, source: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`${source} is not valid JSON`);
  }
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}

class UsageError extends Error {}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  },
);

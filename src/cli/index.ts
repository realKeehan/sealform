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
  verify <record.json> --keys <src>      Verify one record or tombstone.
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

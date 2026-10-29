import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { importSealingKey, sealRecord, type PrivateKeyFile } from '../src/core/index.ts';
import { body } from './helpers.ts';

const CLI = fileURLToPath(new URL('../src/cli/index.ts', import.meta.url));
let dir = '';

function run(...args: string[]) {
  return spawnSync(process.execPath, ['--experimental-strip-types', '--disable-warning=ExperimentalWarning', CLI, ...args], { encoding: 'utf8' });
}

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sealform-cli-'));
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

test('keygen writes a private key and a public key set, and never prints the private key', async () => {
  const result = run('keygen', '--kid', 'cli-test', '--dir', dir);
  assert.equal(result.status, 0, result.stderr);
  const privateFile = JSON.parse(await readFile(join(dir, 'cli-test.private.jwk.json'), 'utf8')) as PrivateKeyFile;
  assert.ok(privateFile.jwk.d);
  assert.equal(result.stdout.includes(privateFile.jwk.d!), false);
  const keyset = JSON.parse(await readFile(join(dir, 'sealform-keys.json'), 'utf8'));
  assert.equal(keyset.keys[0].kid, 'cli-test');
  assert.equal(JSON.stringify(keyset).includes(privateFile.jwk.d!), false);
  if (process.platform !== 'win32') assert.equal((await stat(join(dir, 'cli-test.private.jwk.json'))).mode & 0o077, 0);
});

test('keygen refuses to overwrite a key', () => {
  const result = run('keygen', '--kid', 'cli-test', '--dir', dir);
  assert.equal(result.status, 2);
  assert.match(result.stderr, /already exists/);
});

test('verify and verify-chain pass on good records and fail on edited ones', async () => {
  const privateFile = JSON.parse(await readFile(join(dir, 'cli-test.private.jwk.json'), 'utf8')) as PrivateKeyFile;
  const key = await importSealingKey(privateFile);
  const first = await sealRecord(body(0, '0'.repeat(64)), key);
  const second = await sealRecord(body(1, first.hash), key);
  const keys = join(dir, 'sealform-keys.json');

  await writeFile(join(dir, 'record.json'), JSON.stringify(first));
  assert.equal(run('verify', join(dir, 'record.json'), '--keys', keys).status, 0);

  await writeFile(join(dir, 'chain.jsonl'), `${JSON.stringify(first)}\n${JSON.stringify(second)}\n`);
  const chain = run('verify-chain', join(dir, 'chain.jsonl'), '--keys', keys);
  assert.equal(chain.status, 0, chain.stdout);
  assert.match(chain.stdout, /CHAIN OK: 2 entries/);

  const edited = { ...first, fields: { ...first.fields, country: 'US' } };
  await writeFile(join(dir, 'edited.json'), JSON.stringify(edited));
  const bad = run('verify', join(dir, 'edited.json'), '--keys', keys);
  assert.equal(bad.status, 1);
  assert.match(bad.stdout, /changed after sealing/);
});

test('plain http key sets are refused', () => {
  const result = run('verify', 'x.json', '--keys', 'http://example.com/keys.json');
  assert.equal(result.status, 2);
});

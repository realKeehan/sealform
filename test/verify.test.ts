import assert from 'node:assert/strict';
import { test } from 'node:test';
import { computeRecordHash, sealRecord, toTombstone, ulid, verifyChain, verifyEntry, type ChainEntry } from '../src/core/index.ts';
import { body, chainOf, makeKey } from './helpers.ts';

test('a sealed record verifies', async () => {
  const { key, keyset } = await makeKey();
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  const result = await verifyEntry(record, keyset);
  assert.equal(result.ok, true, result.errors.join('; '));
  assert.equal(result.hash, 'ok');
  assert.equal(result.seal, 'ok');
});

test('the record survives a JSON round trip with reordered keys', async () => {
  const { key, keyset } = await makeKey();
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  const reordered = Object.fromEntries(Object.entries(JSON.parse(JSON.stringify(record))).reverse()) as ChainEntry;
  assert.equal((await verifyEntry(reordered, keyset)).ok, true);
});

test('changing one character of the content is detected', async () => {
  const { key, keyset } = await makeKey();
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  const edited = structuredClone(record);
  edited.fields.legalName = 'Ada Exampl3';
  const result = await verifyEntry(edited, keyset);
  assert.equal(result.ok, false);
  assert.equal(result.hash, 'mismatch');
});

test('recomputing the hash after editing is caught by the seal', async () => {
  const { key, keyset } = await makeKey();
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  const forged = structuredClone(record);
  forged.server.ip = '198.51.100.1';
  forged.hash = await computeRecordHash(forged);
  const result = await verifyEntry(forged, keyset);
  assert.equal(result.hash, 'ok');
  assert.equal(result.seal, 'invalid');
  assert.equal(result.ok, false);
});

test('a record sealed by a different key is rejected', async () => {
  const signer = await makeKey('real');
  const impostor = await makeKey('real');
  const record = await sealRecord(body(0, '0'.repeat(64)), impostor.key);
  assert.equal((await verifyEntry(record, signer.keyset)).seal, 'invalid');
});

test('an unknown key id is reported', async () => {
  const { key } = await makeKey('a');
  const other = await makeKey('b');
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  assert.equal((await verifyEntry(record, other.keyset)).seal, 'unknown-key');
});

test('records sealed after their key was retired fail', async () => {
  const { key, keyset } = await makeKey();
  keyset.keys[0]!.retiredAt = '2026-11-01T00:00:00.000Z';
  const record = await sealRecord(body(0, '0'.repeat(64)), key);
  assert.equal((await verifyEntry(record, keyset)).ok, false);
});

test('a clean chain verifies and reports its head', async () => {
  const { key, keyset } = await makeKey();
  const records = await chainOf(5, key);
  const result = await verifyChain(records, keyset);
  assert.equal(result.ok, true, JSON.stringify(result.breaks));
  assert.equal(result.head, records[4]!.hash);
});

test('a deleted record breaks the chain', async () => {
  const { key, keyset } = await makeKey();
  const records = await chainOf(5, key);
  records.splice(2, 1);
  const result = await verifyChain(records, keyset);
  assert.equal(result.ok, false);
  assert.equal(result.breaks[0]!.index, 2);
});

test('reordered records break the chain', async () => {
  const { key, keyset } = await makeKey();
  const records = await chainOf(4, key);
  [records[1], records[2]] = [records[2]!, records[1]!];
  assert.equal((await verifyChain(records, keyset)).ok, false);
});

test('a tombstone keeps the chain provable without the personal data', async () => {
  const { key, keyset } = await makeKey();
  const records: ChainEntry[] = await chainOf(3, key);
  const tomb = toTombstone(records[1] as Parameters<typeof toTombstone>[0]);
  records[1] = tomb;
  assert.equal(JSON.stringify(tomb).includes('Ada'), false);
  const result = await verifyChain(records, keyset);
  assert.equal(result.ok, true, JSON.stringify(result.breaks));
  assert.equal(result.entries[1]!.kind, 'tombstone');
  assert.equal(result.entries[1]!.hash, 'not-recomputable');
});

test('a forged tombstone hash fails the seal', async () => {
  const { key, keyset } = await makeKey();
  const [record] = await chainOf(1, key);
  const tomb = toTombstone(record!);
  tomb.hash = 'f'.repeat(64);
  assert.equal((await verifyEntry(tomb, keyset)).seal, 'invalid');
});

test('a partial chain verifies from a known checkpoint', async () => {
  const { key, keyset } = await makeKey();
  const records = await chainOf(5, key);
  const result = await verifyChain(records.slice(3), keyset, { startSeq: 3, startPrevHash: records[2]!.hash });
  assert.equal(result.ok, true, JSON.stringify(result.breaks));
});

test('ulids sort by time and are 26 characters', () => {
  const a = ulid(1_700_000_000_000);
  const b = ulid(1_700_000_000_001);
  assert.equal(a.length, 26);
  assert.ok(a < b);
});

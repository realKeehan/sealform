import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile, mkdir, access } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { sealRecord, verifyChain, type ChainEntry } from '../src/core/index.ts';
import { SqliteStore } from '../src/server/store.ts';
import { AdminStore } from '../src/server/admin/db.ts';
import { body, makeKey } from './helpers.ts';

async function fixture() {
  const dir = await mkdtemp(join(tmpdir(), 'sealform-tombstone-'));
  const store = await SqliteStore.open(dir);
  const keys = await makeKey();
  for (let n = 0; n < 3; n++) await store.append(link => sealRecord(body(link.seq, link.prevHash), keys.key), {
    signerName: 'Ada Example', email: 'ada@example.com', country: 'DE', receiptTokenHash: 'receipt-' + n,
  });
  for (const extension of ['.pdf', '.png']) await writeFile(join(store.recordsDir, 'sf_TEST1' + extension), 'personal data');
  return { dir, store, keys, async close() { store.close(); await rm(dir, { recursive: true, force: true }); } };
}

test('tombstoning revokes receipts, removes personal mirrors and preserves the complete chain', async () => {
  const f = await fixture();
  try {
    const original = f.store.getEntry('sf_TEST1')!;
    const removed = await f.store.tombstone('sf_TEST1');
    assert.equal(removed.hash, original.hash);
    assert.deepEqual(removed.seal, original.seal);
    assert.equal(f.store.findByReceiptToken('receipt-1'), undefined);
    for (const field of ['signerName', 'email', 'country', 'receivedAt', 'pdfSha256'] as const) assert.equal(f.store.summary('sf_TEST1')![field], null);
    assert.equal(f.store.summary('sf_TEST1')!.applicationStatus, 'withdrawn');
    for (const extension of ['.pdf', '.png']) await assert.rejects(access(join(f.store.recordsDir, 'sf_TEST1' + extension)));
    const mirror = JSON.parse(await readFile(join(f.store.recordsDir, 'sf_TEST1.json'), 'utf8'));
    assert.deepEqual(mirror, removed);
    assert.equal(JSON.stringify(mirror).includes('Ada'), false);
    const entries = (await readFile(join(f.dir, 'chain.jsonl'), 'utf8')).trim().split('\n').map(s => JSON.parse(s) as ChainEntry);
    assert.equal((await verifyChain(entries, f.keys.keyset)).ok, true);
    await f.store.append(link => sealRecord(body(link.seq, link.prevHash), f.keys.key), { signerName: null, email: null, country: null, receiptTokenHash: 'receipt-3' });
    assert.equal((await verifyChain(f.store.entries(), f.keys.keyset)).ok, true);
    assert.equal(f.store.count(), 4);
  } finally { await f.close(); }
});

test('legal holds and unknown ids fail without changing records or files', async () => {
  const f = await fixture();
  try {
    f.store.database.prepare('UPDATE records SET hold = 1 WHERE id = ?').run('sf_TEST1');
    await assert.rejects(f.store.tombstone('sf_TEST1'), /legal hold/);
    await assert.rejects(f.store.tombstone('sf_MISSING'), /No such record/);
    await assert.rejects(f.store.tombstone('../sf_TEST1'), /Invalid record id/);
    assert.equal(f.store.getEntry('sf_TEST1')!.format, 'sealform/record@1');
    assert.equal(f.store.summary('sf_TEST1')!.email, 'ada@example.com');
    assert.equal(await readFile(join(f.store.recordsDir, 'sf_TEST1.pdf'), 'utf8'), 'personal data');
  } finally { await f.close(); }
});

test('an interrupted mirror cleanup is repairable and keeps its original tombstone timestamp', async () => {
  const f = await fixture();
  try {
    const mirror = join(f.store.recordsDir, 'sf_TEST1.json');
    await rm(mirror); await mkdir(mirror);
    const when = new Date('2026-10-30T19:00:00Z');
    await assert.rejects(f.store.tombstone('sf_TEST1', when));
    assert.equal(f.store.findByReceiptToken('receipt-1'), undefined);
    await rm(mirror, { recursive: true });
    const repaired = await f.store.tombstone('sf_TEST1', new Date('2027-01-01'));
    assert.equal(repaired.tombstonedAt, when.toISOString());
    assert.equal((await verifyChain(f.store.entries(), f.keys.keyset)).ok, true);
    assert.equal(await readFile(mirror, 'utf8'), JSON.stringify(repaired) + '\n');
  } finally { await f.close(); }
});

test('CLI requires explicit confirmation and records the completed maintenance operation in the sealed audit log', async () => {
  const f = await fixture();
  try {
    const keyFile = join(f.dir, 'maintenance.private.jwk.json');
    await writeFile(keyFile, JSON.stringify(f.keys.privateFile));
    const cli = fileURLToPath(new URL('../src/cli/index.ts', import.meta.url));
    const args = ['--experimental-strip-types', '--disable-warning=ExperimentalWarning', cli, 'tombstone', 'sf_TEST1', '--data', f.dir, '--key', keyFile];
    const refused = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(refused.status, 2);
    assert.equal(f.store.getEntry('sf_TEST1')!.format, 'sealform/record@1');
    const result = spawnSync(process.execPath, [...args, '--confirm', 'sf_TEST1', '--offline'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout.includes('ada@example.com'), false);
    const admin = new AdminStore(f.store.database, f.dir);
    const audit = admin.auditEntries();
    assert.deepEqual(audit.map(a => a.action), ['record.tombstone.requested', 'record.tombstone.completed']);
    assert.equal((await verifyChain(audit, f.keys.keyset)).ok, true);
    assert.equal(f.store.getEntry('sf_TEST1')!.format, 'sealform/tombstone@1');
  } finally { await f.close(); }
});

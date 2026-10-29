// Independent verification. Needs only the records and the published public keys, never the
// operator's database or private key, so a signer, a lawyer or a court expert can run it.

import { fromBase64Url } from './encoding.ts';
import { isSha256Hex, ZERO_HASH } from './hash.ts';
import { findKey, importPublicKey, SEAL_ALG, type KeySet } from './keys.ts';
import { computeRecordHash, isTombstone, RECORD_FORMAT, sealMessage, TOMBSTONE_FORMAT, type ChainEntry } from './record.ts';

export type HashStatus = 'ok' | 'mismatch' | 'not-recomputable';
export type SealStatus = 'ok' | 'invalid' | 'unknown-key' | 'malformed';

export interface EntryResult {
  id: string;
  seq: number | null;
  kind: 'record' | 'tombstone' | 'unknown';
  ok: boolean;
  hash: HashStatus;
  seal: SealStatus;
  errors: string[];
}

export async function verifyEntry(entry: ChainEntry, keyset: KeySet): Promise<EntryResult> {
  const errors: string[] = [];
  const raw = entry as Partial<ChainEntry> & { [key: string]: unknown };
  const id = typeof raw.id === 'string' ? raw.id : '(no id)';
  const seq = typeof raw.chain?.seq === 'number' ? raw.chain.seq : null;
  const kind = raw.format === RECORD_FORMAT ? 'record' : raw.format === TOMBSTONE_FORMAT ? 'tombstone' : 'unknown';
  if (kind === 'unknown') errors.push(`Unknown format ${JSON.stringify(raw.format)}`);
  if (!isSha256Hex(raw.hash)) errors.push('Missing or malformed hash');

  let hash: HashStatus = 'not-recomputable';
  if (kind === 'record' && isSha256Hex(raw.hash)) {
    const computed = await computeRecordHash(entry as Parameters<typeof computeRecordHash>[0]);
    hash = computed === raw.hash ? 'ok' : 'mismatch';
    if (hash === 'mismatch') errors.push('Content does not match its hash: the record was changed after sealing');
  }

  const seal = await checkSeal(entry, keyset, errors);
  const ok = errors.length === 0 && seal === 'ok' && (hash === 'ok' || kind === 'tombstone');
  return { id, seq, kind, ok, hash, seal, errors };
}

async function checkSeal(entry: ChainEntry, keyset: KeySet, errors: string[]): Promise<SealStatus> {
  const seal = (entry as { seal?: unknown }).seal as { alg?: unknown; kid?: unknown; sig?: unknown } | undefined;
  if (!seal || seal.alg !== SEAL_ALG || typeof seal.kid !== 'string' || typeof seal.sig !== 'string' || !isSha256Hex(entry.hash)) {
    errors.push('Missing or malformed seal');
    return 'malformed';
  }
  const entryKey = findKey(keyset, seal.kid);
  if (!entryKey) {
    errors.push(`Sealed with key ${seal.kid}, which is not in the key set`);
    return 'unknown-key';
  }
  let sig: Uint8Array<ArrayBuffer>;
  try {
    sig = fromBase64Url(seal.sig);
  } catch {
    errors.push('Seal signature is not base64url');
    return 'malformed';
  }
  const key = await importPublicKey(entryKey);
  const valid = await crypto.subtle.verify({ name: SEAL_ALG }, key, sig, sealMessage(entry.hash));
  if (!valid) {
    errors.push('Seal signature does not verify: the hash was not sealed by this key');
    return 'invalid';
  }
  if (!isTombstone(entry) && entryKey.retiredAt && entry.server?.receivedAt > entryKey.retiredAt) {
    errors.push(`Sealed at ${entry.server.receivedAt}, after key ${entryKey.kid} was retired at ${entryKey.retiredAt}`);
    return 'invalid';
  }
  return 'ok';
}

export interface ChainBreak {
  index: number;
  id: string;
  reason: string;
}

export interface ChainResult {
  ok: boolean;
  length: number;
  /** Hash of the last entry, to compare against a published or remembered chain head. */
  head: string;
  entries: EntryResult[];
  breaks: ChainBreak[];
}

export interface ChainOptions {
  /** Sequence number of the first entry given. Defaults to 0, the start of the chain. */
  startSeq?: number;
  /** prevHash expected on the first entry given. Defaults to the genesis value (64 zeros). */
  startPrevHash?: string;
}

/** Verifies every entry and the links between them. Entries must be in sequence order. */
export async function verifyChain(entries: ChainEntry[], keyset: KeySet, options: ChainOptions = {}): Promise<ChainResult> {
  const results: EntryResult[] = [];
  const breaks: ChainBreak[] = [];
  let expectedSeq = options.startSeq ?? 0;
  let expectedPrev = options.startPrevHash ?? ZERO_HASH;

  for (const [index, entry] of entries.entries()) {
    const result = await verifyEntry(entry, keyset);
    results.push(result);
    if (!result.ok) breaks.push({ index, id: result.id, reason: result.errors.join('; ') || 'Entry failed verification' });
    if (result.seq !== expectedSeq) {
      breaks.push({ index, id: result.id, reason: `Expected seq ${expectedSeq}, found ${String(result.seq)}: an entry is missing, duplicated or out of order` });
    }
    if (entry.chain?.prevHash !== expectedPrev) {
      breaks.push({ index, id: result.id, reason: 'prevHash does not match the previous entry: the chain was cut or reordered here' });
    }
    expectedSeq = (result.seq ?? expectedSeq) + 1;
    expectedPrev = entry.hash;
  }

  return { ok: breaks.length === 0, length: entries.length, head: expectedPrev, entries: results, breaks };
}

// The signing record: what was signed, by whom, with which evidence, sealed by the operator key.
// See docs/DESIGN.md "Record format" for the meaning of each part.

import type { JsonValue } from './canonical.ts';
import { sha256Canonical } from './hash.ts';
import { toBase64Url, utf8 } from './encoding.ts';
import { SEAL_ALG, type SealingKey } from './keys.ts';

export const RECORD_FORMAT = 'sealform/record@1';
export const TOMBSTONE_FORMAT = 'sealform/tombstone@1';
export const AUDIT_FORMAT = 'sealform/audit@1';
export const SEAL_DOMAIN = 'sealform-seal-v1:';

export interface DocumentRef {
  id: string;
  version: string;
  lang: string;
  /** SHA-256 of the exact UTF-8 text shown to the signer. */
  sha256: string;
  /**
   * SHA-256 of the canonical document manifest: title, field labels and consent wording. Ties the
   * checkbox text the signer agreed to into the record, not only the body text.
   */
  manifestSha256?: string;
}

export interface EnvelopeRef {
  id: string;
  role: string;
  order: number;
}

export interface SignatureEvidence {
  typedName: string;
  /** signature_pad point groups, kept as vector data. */
  vector: JsonValue;
  /** SHA-256 of the PNG rendering stored next to the record. */
  pngSha256: string;
}

export type CheckStatus = 'passed' | 'failed' | 'queued' | 'skipped';

export interface AssuranceCheck {
  kind: string;
  status: CheckStatus;
  at?: string;
  /** Provider-specific, non-secret reference such as a verification session id. */
  ref?: string;
}

export interface Assurance {
  /** "ses" for a simple electronic signature; providers may raise it. */
  level: string;
  checks: AssuranceCheck[];
}

export interface ServerFacts {
  receivedAt: string;
  sessionOpenedAt: string;
  ip: string;
  userAgent: string;
  acceptLanguage: string;
}

export interface ChainLink {
  seq: number;
  prevHash: string;
}

/** Everything the hash covers. */
export interface RecordBody {
  format: typeof RECORD_FORMAT;
  id: string;
  document: DocumentRef;
  disclosure: DocumentRef;
  envelope?: EnvelopeRef;
  /** The jurisdiction profile shown to the signer; its hash binds the notices into the record. */
  jurisdiction?: { profile: string; version: number; sha256: string; fallback: boolean };
  fields: { [name: string]: JsonValue };
  consent: { [name: string]: boolean };
  signature: SignatureEvidence;
  assurance: Assurance;
  server: ServerFacts;
  /** Values the browser reported. Kept for context, never trusted over `server`. */
  client: { [name: string]: JsonValue };
  chain: ChainLink;
}

export interface Seal {
  alg: typeof SEAL_ALG;
  kid: string;
  /** Ed25519 signature over SEAL_DOMAIN + hash, base64url. */
  sig: string;
}

export interface SealformRecord extends RecordBody {
  hash: string;
  seal: Seal;
}

/** What remains of a record after its retention period: enough to keep the chain provable. */
export interface Tombstone {
  format: typeof TOMBSTONE_FORMAT;
  id: string;
  chain: ChainLink;
  hash: string;
  seal: Seal;
  tombstonedAt: string;
}

/** One administrative action, chained and sealed like records so the log itself is tamper-evident. */
export interface AuditBody {
  format: typeof AUDIT_FORMAT;
  id: string;
  at: string;
  /** Account id and email of whoever acted, or "system". */
  actor: { id: string; email: string } | 'system';
  action: string;
  target: string;
  details: { [key: string]: JsonValue };
  ip: string;
  chain: ChainLink;
}

export interface AuditEntry extends AuditBody {
  hash: string;
  seal: Seal;
}

export type ChainEntry = SealformRecord | Tombstone | AuditEntry;

export function computeRecordHash(record: RecordBody | SealformRecord | AuditBody | AuditEntry): Promise<string> {
  const { hash: _hash, seal: _seal, ...body } = record as SealformRecord;
  return sha256Canonical(body);
}

export function sealMessage(hash: string): Uint8Array<ArrayBuffer> {
  return utf8(SEAL_DOMAIN + hash);
}

export async function sealRecord(body: RecordBody, key: SealingKey): Promise<SealformRecord>;
export async function sealRecord(body: AuditBody, key: SealingKey): Promise<AuditEntry>;
export async function sealRecord(body: RecordBody | AuditBody, key: SealingKey): Promise<SealformRecord | AuditEntry> {
  const hash = await computeRecordHash(body);
  const sig = new Uint8Array(await crypto.subtle.sign({ name: SEAL_ALG }, key.privateKey, sealMessage(hash)));
  return { ...body, hash, seal: { alg: SEAL_ALG, kid: key.kid, sig: toBase64Url(sig) } } as SealformRecord | AuditEntry;
}

export function toTombstone(record: SealformRecord, now: Date = new Date()): Tombstone {
  return {
    format: TOMBSTONE_FORMAT,
    id: record.id,
    chain: record.chain,
    hash: record.hash,
    seal: record.seal,
    tombstonedAt: now.toISOString(),
  };
}

export function isTombstone(entry: ChainEntry): entry is Tombstone {
  return entry.format === TOMBSTONE_FORMAT;
}

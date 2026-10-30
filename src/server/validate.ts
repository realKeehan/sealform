// Validation of the public signing request. Nothing from the request reaches a record without
// passing through here, and everything has a size cap.

import { isCountryCode, type JsonValue } from '../core/index.ts';
import type { DocumentManifest, FieldSpec } from './documents.ts';

export interface SignRequest {
  sessionId: string;
  documentId: string;
  version: string;
  lang: string;
  textSha256: string;
  manifestSha256: string;
  fields: Record<string, string | boolean>;
  consents: Record<string, boolean>;
  signature: { typedName: string; vector: JsonValue; png: Uint8Array };
  client: Record<string, JsonValue>;
  botToken?: string;
}

export class ValidationError extends Error {
  readonly issues: Record<string, string>;

  constructor(issues: Record<string, string>) {
    super('The submission has problems: ' + Object.entries(issues).map(([k, v]) => `${k}: ${v}`).join('; '));
    this.issues = issues;
  }
}

const MAX_PNG_BYTES = 300_000;
const MAX_POINTS = 6000;
const MAX_GROUPS = 200;
// A tap or a tick is not a signature. Require some real movement, measured in CSS pixels.
const MIN_POINTS = 8;
const MIN_EXTENT = 12;
const PNG_MAGIC = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const HEX64 = /^[0-9a-f]{64}$/;
const EMAIL = /^[^\s@<>()[\]\\,;:"]+@[^\s@<>()[\]\\,;:"]+\.[^\s@<>()[\]\\,;:"]{2,}$/;
export function parseSignRequest(body: unknown, manifest: DocumentManifest): SignRequest {
  const issues: Record<string, string> = {};
  const b = (body ?? {}) as Record<string, unknown>;
  const str = (key: string, max: number, pattern?: RegExp): string => {
    const value = b[key];
    if (typeof value !== 'string' || value.length === 0 || value.length > max || (pattern && !pattern.test(value))) {
      issues[key] = 'missing or invalid';
      return '';
    }
    return value;
  };

  const request: SignRequest = {
    sessionId: str('sessionId', 64, /^[A-Za-z0-9_-]+$/),
    documentId: str('documentId', 64),
    version: str('version', 64),
    lang: str('lang', 35),
    textSha256: str('textSha256', 64, HEX64),
    manifestSha256: str('manifestSha256', 64, HEX64),
    fields: {},
    consents: {},
    signature: { typedName: '', vector: [], png: new Uint8Array() },
    client: {},
  };
  if (typeof b.botToken === 'string') request.botToken = b.botToken.slice(0, 2048);

  const fields = isObject(b.fields) ? b.fields : {};
  for (const spec of manifest.fields) {
    const result = checkField(spec, fields[spec.name]);
    if (typeof result === 'string') issues[`fields.${spec.name}`] = result;
    else if (result.value !== undefined) request.fields[spec.name] = result.value;
  }
  for (const key of Object.keys(fields)) if (!manifest.fields.some((f) => f.name === key)) issues[`fields.${key}`] = 'unknown field';

  const consents = isObject(b.consents) ? b.consents : {};
  for (const spec of manifest.consents) {
    const value = consents[spec.name];
    if (value !== undefined && typeof value !== 'boolean') issues[`consents.${spec.name}`] = 'must be true or false';
    else if (spec.required && value !== true) issues[`consents.${spec.name}`] = 'required';
    else request.consents[spec.name] = value === true;
  }
  for (const key of Object.keys(consents)) if (!manifest.consents.some((c) => c.name === key)) issues[`consents.${key}`] = 'unknown consent';

  const signature = isObject(b.signature) ? b.signature : {};
  const typedName = typeof signature.typedName === 'string' ? signature.typedName.trim() : '';
  if (!typedName || typedName.length > 200) issues['signature.typedName'] = 'type your full name to sign';
  request.signature.typedName = typedName;
  const signerField = manifest.fields.find((f) => f.role === 'signerName');
  if (typedName && signerField && normalizeName(typedName) !== normalizeName(String(request.fields[signerField.name] ?? ''))) {
    issues['signature.typedName'] = `must match ${signerField.label}`;
  }

  // A drawn signature is required. Signers who cannot draw arrange an alternative with the operator.
  if (signature.mode !== undefined) issues['signature.mode'] = 'only drawn signatures are accepted';
  const vector = normalizeVector(signature.vector);
  if (!vector) issues['signature.vector'] = 'draw your signature (a dot or a short tick is not enough)';
  else request.signature.vector = vector;

  const png = decodePng(signature.png);
  if (!png) issues['signature.png'] = 'missing or invalid signature image';
  else request.signature.png = png;

  request.client = pickClient(b.client);

  if (Object.keys(issues).length) throw new ValidationError(issues);
  return request;
}

function checkField(spec: FieldSpec, raw: unknown): { value: string | boolean | undefined } | string {
  if (spec.type === 'checkbox') {
    if (raw !== undefined && typeof raw !== 'boolean') return 'must be true or false';
    if (spec.required && raw !== true) return 'required';
    return { value: raw === true };
  }
  if (raw === undefined || raw === null || raw === '') return spec.required ? 'required' : { value: undefined };
  if (typeof raw !== 'string') return 'must be text';
  const value = raw.normalize('NFC').trim();
  const max = spec.maxLength ?? (spec.type === 'textarea' ? 4000 : 200);
  if (value.length > max) return `at most ${max} characters`;
  if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) return 'contains control characters';
  if (spec.type !== 'textarea' && /[\r\n]/.test(value)) return 'must be one line';
  if (spec.type === 'email' && (value.length > 254 || !EMAIL.test(value))) return 'not a valid email address';
  if (spec.type === 'country' && !isCountryCode(value)) return 'not a valid country';
  if (spec.type === 'select' && !spec.options!.includes(value)) return 'not one of the options';
  if (spec.required && value === '') return 'required';
  return { value };
}

function normalizeName(name: string): string {
  return name.normalize('NFKC').trim().replace(/\s+/g, ' ').toLocaleLowerCase();
}

/** Keeps only signature_pad point data: groups of { x, y, time, pressure }. */
function normalizeVector(raw: unknown): JsonValue | null {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > MAX_GROUPS) return null;
  let total = 0;
  let minX = Infinity;
  let maxX = -Infinity;
  let minY = Infinity;
  let maxY = -Infinity;
  const groups: JsonValue[] = [];
  for (const group of raw) {
    const points = isObject(group) && Array.isArray(group.points) ? group.points : null;
    if (!points || points.length === 0) return null;
    total += points.length;
    if (total > MAX_POINTS) return null;
    const clean: JsonValue[] = [];
    for (const point of points) {
      if (!isObject(point)) return null;
      const { x, y, time, pressure } = point;
      if (![x, y, time].every((n) => typeof n === 'number' && Number.isFinite(n))) return null;
      minX = Math.min(minX, x as number);
      maxX = Math.max(maxX, x as number);
      minY = Math.min(minY, y as number);
      maxY = Math.max(maxY, y as number);
      clean.push({ x: round(x as number), y: round(y as number), time: time as number, ...(typeof pressure === 'number' && Number.isFinite(pressure) ? { pressure: round(pressure) } : {}) });
    }
    groups.push({ points: clean });
  }
  if (total < MIN_POINTS || Math.max(maxX - minX, maxY - minY) < MIN_EXTENT) return null;
  return groups;
}

function decodePng(raw: unknown): Uint8Array | null {
  if (typeof raw !== 'string' || !raw.startsWith('data:image/png;base64,')) return null;
  const base64 = raw.slice('data:image/png;base64,'.length);
  if (base64.length > Math.ceil((MAX_PNG_BYTES * 4) / 3) + 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(base64)) return null;
  const bytes = new Uint8Array(Buffer.from(base64, 'base64'));
  if (bytes.length > MAX_PNG_BYTES || !PNG_MAGIC.every((byte, i) => bytes[i] === byte)) return null;
  return bytes;
}

const CLIENT_KEYS = ['reportedAt', 'timeZone', 'screen', 'viewport', 'locale', 'timeOnPageMs', 'pointer'] as const;

function pickClient(raw: unknown): Record<string, JsonValue> {
  const out: Record<string, JsonValue> = {};
  if (!isObject(raw)) return out;
  for (const key of CLIENT_KEYS) {
    const value = raw[key];
    if (typeof value === 'string') out[key] = value.slice(0, 100);
    else if (typeof value === 'number' && Number.isFinite(value)) out[key] = value;
  }
  return out;
}

function round(n: number): number {
  return Math.round(n * 100) / 100;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

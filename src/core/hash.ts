import { canonicalize } from './canonical.ts';
import { toHex, utf8 } from './encoding.ts';

/** Lowercase hex SHA-256 of bytes or of a string's UTF-8 encoding. */
export async function sha256Hex(input: Uint8Array<ArrayBuffer> | string): Promise<string> {
  const bytes = typeof input === 'string' ? utf8(input) : input;
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return toHex(new Uint8Array(digest));
}

/** SHA-256 of a value's RFC 8785 canonical form. */
export function sha256Canonical(value: unknown): Promise<string> {
  return sha256Hex(canonicalize(value));
}

export const ZERO_HASH = '0'.repeat(64);

export function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

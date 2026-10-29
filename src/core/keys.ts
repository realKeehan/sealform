// Ed25519 operator keys, through Web Crypto so the same code runs in Node and in browsers.

import { fromBase64Url } from './encoding.ts';

export const KEYSET_FORMAT = 'sealform/keys@1';
export const SEAL_ALG = 'Ed25519';

/** One public key as published at /.well-known/sealform-keys.json. */
export interface PublicKeyEntry {
  kid: string;
  alg: typeof SEAL_ALG;
  /** Raw 32-byte public key, base64url (the JWK "x" member). */
  x: string;
  createdAt: string;
  /** Set when the key stops sealing new records. Records sealed before this stay valid. */
  retiredAt?: string;
}

export interface KeySet {
  format: typeof KEYSET_FORMAT;
  keys: PublicKeyEntry[];
}

/** The private key file written by `sealform keygen`. Keep it outside the web root. */
export interface PrivateKeyFile {
  format: 'sealform/private-key@1';
  kid: string;
  createdAt: string;
  jwk: JsonWebKey;
}

export interface SealingKey {
  kid: string;
  privateKey: CryptoKey;
}

export async function generateKeyPair(kid: string, now: Date = new Date()): Promise<{ privateFile: PrivateKeyFile; publicEntry: PublicKeyEntry }> {
  assertKid(kid);
  const pair = (await crypto.subtle.generateKey({ name: SEAL_ALG }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  if (!jwk.x || !jwk.d) throw new Error('Exported Ed25519 key is incomplete');
  const createdAt = now.toISOString();
  return {
    privateFile: { format: 'sealform/private-key@1', kid, createdAt, jwk: { kty: 'OKP', crv: SEAL_ALG, x: jwk.x, d: jwk.d } },
    publicEntry: { kid, alg: SEAL_ALG, x: jwk.x, createdAt },
  };
}

export async function importSealingKey(file: PrivateKeyFile): Promise<SealingKey> {
  if (file.format !== 'sealform/private-key@1') throw new Error('Not a sealform private key file');
  assertKid(file.kid);
  const privateKey = await crypto.subtle.importKey('jwk', { ...file.jwk, key_ops: ['sign'] }, { name: SEAL_ALG }, false, ['sign']);
  return { kid: file.kid, privateKey };
}

export async function importPublicKey(entry: PublicKeyEntry): Promise<CryptoKey> {
  if (entry.alg !== SEAL_ALG) throw new Error(`Unsupported key algorithm ${String(entry.alg)}`);
  if (fromBase64Url(entry.x).length !== 32) throw new Error(`Key ${entry.kid} is not a 32-byte Ed25519 key`);
  return crypto.subtle.importKey('jwk', { kty: 'OKP', crv: SEAL_ALG, x: entry.x }, { name: SEAL_ALG }, false, ['verify']);
}

export function emptyKeySet(): KeySet {
  return { format: KEYSET_FORMAT, keys: [] };
}

export function findKey(keyset: KeySet, kid: string): PublicKeyEntry | undefined {
  return keyset.keys.find((key) => key.kid === kid);
}

export function assertKid(kid: string): void {
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(kid)) throw new Error('Key id must be 1-64 characters of A-Z, a-z, 0-9, dot, underscore or hyphen');
}

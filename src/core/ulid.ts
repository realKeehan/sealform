// ULIDs: 48 bits of millisecond time and 80 random bits, Crockford base32. Sortable by creation time.

const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function ulid(now: number = Date.now()): string {
  if (!Number.isSafeInteger(now) || now < 0 || now > 2 ** 48 - 1) throw new RangeError('Time out of ULID range');
  let time = '';
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = ALPHABET[t % 32] + time;
    t = Math.floor(t / 32);
  }
  const random = crypto.getRandomValues(new Uint8Array(16));
  let rand = '';
  for (const byte of random) rand += ALPHABET[byte % 32];
  return time + rand;
}

export function prefixedId(prefix: string, now?: number): string {
  return `${prefix}_${ulid(now)}`;
}

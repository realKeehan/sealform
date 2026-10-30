// Cloudflare Access sign-in. Access does the login (Google, one-time PIN, whatever the Access policy
// allows) at Cloudflare's edge and forwards each request with a signed JWT in Cf-Access-Jwt-Assertion.
// The dashboard must not trust that header blindly: anyone who reaches the origin directly can send
// any header. So the token's RS256 signature, issuer, audience and expiry are checked here against the
// team's published keys, exactly as Cloudflare documents.

import { fromBase64Url, utf8 } from '../../core/index.ts';

export interface AccessConfig {
  /** Your Zero Trust team domain, such as myteam.cloudflareaccess.com. */
  teamDomain: string;
  /** The Application Audience (AUD) tag of the Access application that protects the dashboard. */
  audience: string;
  /** For tests or a proxy; defaults to the global fetch. */
  fetch?: typeof fetch;
}

export interface AccessIdentity {
  email: string;
  sub: string;
  expiresAt: number;
}

const TEAM_DOMAIN = /^[a-z0-9][a-z0-9-]{0,62}\.cloudflareaccess\.com$/;
const KEY_TTL_MS = 60 * 60_000;
const REFETCH_MIN_MS = 60_000;
const SKEW_S = 30;

interface Jwk {
  kid?: string;
  kty?: string;
  n?: string;
  e?: string;
}

export class CloudflareAccess {
  readonly teamDomain: string;
  readonly audience: string;
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private keys = new Map<string, CryptoKey>();
  private fetchedAt = 0;
  private attemptedAt = 0;

  constructor(config: AccessConfig, now: () => number = Date.now) {
    const domain = config.teamDomain.trim().toLowerCase();
    if (!TEAM_DOMAIN.test(domain)) throw new Error('adminAccess.teamDomain must look like myteam.cloudflareaccess.com');
    if (!config.audience || !/^[A-Za-z0-9]{16,128}$/.test(config.audience)) throw new Error('adminAccess.audience must be the Application Audience (AUD) tag from your Access application');
    this.teamDomain = domain;
    this.audience = config.audience;
    this.fetchImpl = config.fetch ?? fetch;
    this.now = now;
  }

  /** Where signing out of Access happens; the dashboard sends signers here. */
  get logoutUrl(): string {
    return `https://${this.teamDomain}/cdn-cgi/access/logout`;
  }

  /** Returns who the token is for, or null if it is missing, forged, expired or for another app. */
  async verify(token: string | undefined): Promise<AccessIdentity | null> {
    if (!token || token.length > 8192) return null;
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part))) return null;
    const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

    let header: { alg?: unknown; kid?: unknown };
    let payload: { iss?: unknown; aud?: unknown; exp?: unknown; nbf?: unknown; iat?: unknown; email?: unknown; sub?: unknown };
    try {
      header = JSON.parse(new TextDecoder().decode(fromBase64Url(headerPart)));
      payload = JSON.parse(new TextDecoder().decode(fromBase64Url(payloadPart)));
    } catch {
      return null;
    }
    // Only RS256. Refusing everything else closes the "alg: none" and HMAC-with-the-public-key tricks.
    if (header.alg !== 'RS256' || typeof header.kid !== 'string') return null;

    const key = await this.key(header.kid);
    if (!key) return null;
    let valid = false;
    try {
      valid = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, key, fromBase64Url(signaturePart), utf8(`${headerPart}.${payloadPart}`));
    } catch {
      return null;
    }
    if (!valid) return null;

    const nowS = Math.floor(this.now() / 1000);
    if (payload.iss !== `https://${this.teamDomain}`) return null;
    const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!audiences.includes(this.audience)) return null;
    if (typeof payload.exp !== 'number' || payload.exp + SKEW_S < nowS) return null;
    if (typeof payload.nbf === 'number' && payload.nbf - SKEW_S > nowS) return null;
    if (typeof payload.iat === 'number' && payload.iat - SKEW_S > nowS) return null;
    // Service tokens carry no email; the dashboard is for people.
    if (typeof payload.email !== 'string' || !/^[^\s@]+@[^\s@]+$/.test(payload.email)) return null;
    return { email: payload.email.trim().toLowerCase(), sub: typeof payload.sub === 'string' ? payload.sub : '', expiresAt: payload.exp * 1000 };
  }

  private async key(kid: string): Promise<CryptoKey | null> {
    const now = this.now();
    const fresh = now - this.fetchedAt < KEY_TTL_MS;
    const known = this.keys.get(kid);
    if (known && fresh) return known;
    // An unknown kid may mean Cloudflare rotated keys; refetch, but never more than once a minute so
    // a stream of junk tokens cannot make this server hammer Cloudflare.
    if (now - this.attemptedAt >= REFETCH_MIN_MS) await this.refresh();
    return this.keys.get(kid) ?? null;
  }

  private async refresh(): Promise<void> {
    this.attemptedAt = this.now();
    try {
      const response = await this.fetchImpl(`https://${this.teamDomain}/cdn-cgi/access/certs`, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000) });
      if (!response.ok) return;
      const body = (await response.json()) as { keys?: Jwk[] };
      const next = new Map<string, CryptoKey>();
      for (const jwk of body.keys ?? []) {
        if (jwk.kty !== 'RSA' || !jwk.kid || !jwk.n || !jwk.e) continue;
        next.set(jwk.kid, await crypto.subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']));
      }
      if (next.size) {
        this.keys = next;
        this.fetchedAt = this.now();
      }
    } catch {
      // Keep whatever keys we have; a network blip must not lock the owner out of a cached key.
    }
  }
}

export function accessToken(headers: Record<string, string | string[] | undefined>): string | undefined {
  const value = headers['cf-access-jwt-assertion'];
  return typeof value === 'string' ? value : undefined;
}

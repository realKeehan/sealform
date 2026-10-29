// Abuse protection for public endpoints: bot checks and rate limits.

export interface BotCheck {
  readonly name: string;
  /** Resolves true when the token proves a human-driven browser. */
  verify(token: string | undefined, ip: string): Promise<boolean>;
}

export class NoBotCheck implements BotCheck {
  readonly name = 'none';
  verify(): Promise<boolean> {
    return Promise.resolve(true);
  }
}

/** Cloudflare Turnstile. Works on any host; only the widget script and this API call touch Cloudflare. */
export class TurnstileCheck implements BotCheck {
  readonly name = 'turnstile';
  private readonly secret: string;
  private readonly fetchImpl: typeof fetch;
  private readonly expectedHostname: string | undefined;

  constructor(secret: string, fetchImpl: typeof fetch = fetch, expectedHostname?: string) {
    if (!secret) throw new Error('TurnstileCheck needs a secret key');
    this.secret = secret;
    this.fetchImpl = fetchImpl;
    this.expectedHostname = expectedHostname;
  }

  async verify(token: string | undefined, ip: string): Promise<boolean> {
    if (!token || token.length > 2048) return false;
    const body = new URLSearchParams({ secret: this.secret, response: token, remoteip: ip });
    try {
      const response = await this.fetchImpl('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
        method: 'POST',
        body,
        signal: AbortSignal.timeout(8000),
      });
      if (!response.ok) return false;
      const result = (await response.json()) as { success?: boolean; hostname?: string };
      if (result.success !== true) return false;
      return !this.expectedHostname || result.hostname === this.expectedHostname;
    } catch {
      return false;
    }
  }
}

/**
 * Fixed-window counter per key, in memory. Under Passenger several processes may run, each with its
 * own counters, so the effective limit is per process. Good enough for a signing form; swap in a
 * shared limiter for heavier abuse.
 */
export class RateLimiter {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly max: number;
  private readonly windowMs: number;
  private readonly now: () => number;

  constructor(max: number, windowMs: number, now: () => number = Date.now) {
    this.max = max;
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Returns seconds to wait when over the limit, or 0 when the request may proceed. */
  take(key: string): number {
    const now = this.now();
    if (this.hits.size > 10_000) {
      for (const [k, v] of this.hits) if (v.resetAt <= now) this.hits.delete(k);
    }
    const entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.set(key, { count: 1, resetAt: now + this.windowMs });
      return 0;
    }
    entry.count++;
    return entry.count > this.max ? Math.ceil((entry.resetAt - now) / 1000) : 0;
  }
}

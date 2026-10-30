// The admin dashboard: sign-in with two-factor, accounts and roles, sign-in history, the sealed audit
// log, documents and submissions. Server-rendered HTML with no client scripts, so the CSP can forbid
// scripts entirely.

import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { COUNTRY_CODES, isCountryCode, sha256Canonical, verifyChain, verifyEntry, type ChainEntry, type JsonValue, type KeySet, type SealformRecord, type SealingKey } from '../../core/index.ts';
import type { Check } from '../checks.ts';
import { hasPlaceholder, type DocumentRegistry, type DocumentStatus, type LoadedDocument } from '../documents.ts';
import { RateLimiter, type BotCheck } from '../guards.ts';
import { header, HttpError } from '../http.ts';
import { profileHealth, retentionReview, type LoadedProfile, type ProfileRegistry } from '../profiles.ts';
import { normalizePrefix, type SiteLayer } from '../site.ts';
import type { SqliteStore } from '../store.ts';
import {
  decoy,
  hashPassword,
  hashToken,
  newToken,
  newTotpSecret,
  otpauthUri,
  passwordProblem,
  safeEqual,
  verifyPassword,
  verifyTotp,
} from './auth.ts';
import { accessToken, type AccessIdentity, type CloudflareAccess } from './access.ts';
import { AdminStore, ROLES, type Account, type AdminSession, type Envelope, type Role } from './db.ts';
import type { Mailer } from '../mailer.ts';
import { csrfField, html, layout, raw, shortDate, type Raw } from './html.ts';
import { renderDocumentMarkdown } from './markdown.ts';

export interface AdminOptions {
  base: string;
  origin: string;
  operatorName: string;
  store: SqliteStore;
  documents: DocumentRegistry;
  sealingKey: SealingKey;
  keySet: KeySet;
  checks: Map<string, Check>;
  profiles: ProfileRegistry;
  /** The profile for the operator's own side of a contract, checked at link creation. */
  operatorProfile: LoadedProfile | undefined;
  /** Set when sealform also serves the website; the Site page manages it. */
  siteInfo: (() => ReturnType<SiteLayer['info']>) | undefined;
  /** Where the public signing API is mounted, used to build private signing links. */
  signBase: string;
  mailer: Mailer;
  operator: { name: string; email: string };
  /** Checked on the sign-in form before any password work, so bots cannot probe or lock accounts. */
  botCheck: BotCheck;
  /** Public Turnstile site key; the widget is shown on the sign-in page when set. */
  turnstileSiteKey: string | undefined;
  /** When set, Cloudflare Access does the sign-in and password and two-factor are not used. */
  access: CloudflareAccess | undefined;
  now: () => Date;
  log: (message: string) => void;
}

const COOKIE = 'sf_admin';
const PENDING_TTL = 5 * 60_000;
const IDLE_TTL = 2 * 60 * 60_000;
const ABSOLUTE_TTL = 12 * 60 * 60_000;
const LOCK_AFTER = 5;
const LOCK_FOR = 15 * 60_000;
export const APPLICATION_STATUSES = ['pending', 'accepted', 'rejected', 'withdrawn'];

const MESSAGES: Record<string, { kind: 'ok' | 'error'; text: string }> = {
  saved: { kind: 'ok', text: 'Saved.' },
  password: { kind: 'ok', text: 'Password changed. Other sessions were signed out.' },
  totp: { kind: 'ok', text: 'Two-factor sign-in is on.' },
  totpoff: { kind: 'ok', text: 'Two-factor sign-in is off.' },
  revoked: { kind: 'ok', text: 'Session signed out.' },
  need2fa: { kind: 'error', text: 'Owners must turn on two-factor sign-in before using the dashboard.' },
  mustchange: { kind: 'error', text: 'Choose a new password before continuing.' },
};

type Ctx = {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  path: string;
  ip: string;
  /** Set by the sign-in page, which alone is allowed to load the Turnstile script. */
  turnstile?: boolean;
  account?: Account;
  session?: AdminSession;
};

export async function createAdmin(options: AdminOptions) {
  const { base, store, documents } = options;
  const db = new AdminStore(store.database, store.dataDir);
  for (const row of db.documentStatuses()) documents.restoreStatus(row.documentId, row.version, row.status);
  const loginLimiter = new RateLimiter(20, 10 * 60_000, () => options.now().getTime());
  const secure = options.origin.startsWith('https:');
  const sso = options.access;
  const cssPath = fileURLToPath(new URL('./admin.css', import.meta.url));
  let css: string | undefined;

  const nowIso = () => options.now().toISOString();
  const actorOf = (ctx: Ctx) => (ctx.account ? { id: ctx.account.id, email: ctx.account.email } : ('system' as const));
  const audit = (ctx: Ctx, action: string, target: string, details: Record<string, JsonValue> = {}) =>
    db.audit(options.sealingKey, { at: nowIso(), actor: actorOf(ctx), action, target, details, ip: ctx.ip });

  // Responses ------------------------------------------------------------------------------------

  const securityHeaders = {
    'content-security-policy': "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
    'x-frame-options': 'DENY',
    'x-content-type-options': 'nosniff',
    // Not "no-referrer": with that policy browsers send "Origin: null" on form posts, which the
    // same-origin check would then refuse. "same-origin" still sends nothing to other sites.
    'referrer-policy': 'same-origin',
    'cache-control': 'no-store',
    'x-robots-tag': 'noindex, nofollow',
  };

  const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';
  const turnstileHeaders = {
    ...securityHeaders,
    'content-security-policy': `${securityHeaders['content-security-policy']}; script-src ${TURNSTILE_ORIGIN}; frame-src ${TURNSTILE_ORIGIN}; connect-src ${TURNSTILE_ORIGIN}`,
  };

  function page(ctx: Ctx, title: string, nav: string, body: Raw, status = 200): void {
    const flash = MESSAGES[ctx.url.searchParams.get('m') ?? ''];
    const text = layout({
      base,
      title,
      body,
      nav,
      flash,
      operatorName: options.operatorName,
      // A session that has only passed the password step gets the bare page, not the admin nav.
      ...(ctx.account && ctx.session?.stage === 'active' ? { user: { email: ctx.account.email, role: ctx.account.role } } : {}),
      ...(ctx.session?.stage === 'active' ? { csrf: ctx.session.csrf } : {}),
    });
    ctx.res.writeHead(status, { ...(ctx.turnstile ? turnstileHeaders : securityHeaders), 'content-type': 'text/html; charset=utf-8' });
    ctx.res.end(text);
  }

  function redirect(ctx: Ctx, to: string, cookie?: string): void {
    ctx.res.writeHead(303, { ...securityHeaders, location: `${base}${to}`, ...(cookie ? { 'set-cookie': cookie } : {}) });
    ctx.res.end();
  }

  function download(ctx: Ctx, type: string, filename: string, body: string | Uint8Array): void {
    ctx.res.writeHead(200, { ...securityHeaders, 'content-type': type, 'content-disposition': `attachment; filename="${filename}"` });
    ctx.res.end(body);
  }

  function cookie(token: string, maxAgeSeconds: number): string {
    // Path=/ so private site pages can recognise a signed-in admin; the cookie is HttpOnly and SameSite=Strict.
    return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSeconds}${secure ? '; Secure' : ''}`;
  }

  // Sessions and guards --------------------------------------------------------------------------

  function readCookie(req: IncomingMessage): string | undefined {
    for (const part of (req.headers.cookie ?? '').split(';')) {
      const [name, ...rest] = part.trim().split('=');
      if (name === COOKIE) return rest.join('=');
    }
    return undefined;
  }

  function loadSession(ctx: Ctx, stage: 'pending' | 'active'): boolean {
    const token = readCookie(ctx.req);
    if (!token) return false;
    const session = db.sessionByToken(hashToken(token));
    const now = options.now();
    if (!session || session.stage !== stage || session.expiresAt < now.toISOString()) return false;
    if (stage === 'active' && now.getTime() - Date.parse(session.lastSeenAt) > IDLE_TTL) {
      db.deleteSession(session.id);
      return false;
    }
    const account = db.account(session.accountId);
    if (!account || account.disabled) return false;
    ctx.session = session;
    ctx.account = account;
    if (stage === 'active') db.touchSession(session.id, now.toISOString());
    return true;
  }

  function startSession(ctx: Ctx, account: Account, stage: 'pending' | 'active'): string {
    const token = newToken();
    const now = options.now();
    const ttl = stage === 'pending' ? PENDING_TTL : ABSOLUTE_TTL;
    db.createSession(hashToken(token), {
      id: newToken().slice(0, 22),
      accountId: account.id,
      stage,
      csrf: newToken(),
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      expiresAt: new Date(now.getTime() + ttl).toISOString(),
      ip: ctx.ip,
      userAgent: header(ctx.req, 'user-agent', 300),
    });
    return cookie(token, ttl / 1000);
  }

  async function readForm(ctx: Ctx): Promise<URLSearchParams> {
    const type = ctx.req.headers['content-type'] ?? '';
    if (!type.startsWith('application/x-www-form-urlencoded')) throw new HttpError(415, 'Send a form');
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of ctx.req) {
      size += (chunk as Buffer).length;
      if (size > 64_000) throw new HttpError(413, 'Form too large');
      chunks.push(chunk as Buffer);
    }
    return new URLSearchParams(Buffer.concat(chunks).toString('utf8'));
  }

  /** Same-origin check plus the per-session CSRF token, for every state-changing request. */
  function checkPost(ctx: Ctx, form: URLSearchParams): void {
    const origin = header(ctx.req, 'origin') || (header(ctx.req, 'referer') ? new URL(header(ctx.req, 'referer')).origin : '');
    if (origin !== options.origin) throw new HttpError(403, 'Cross-site request refused');
    if (ctx.session && !safeEqual(form.get('csrf') ?? '', ctx.session.csrf)) throw new HttpError(403, 'Your form expired. Go back, reload and try again.');
  }

  function need(ctx: Ctx, ...roles: Role[]): void {
    if (!ctx.account || !roles.includes(ctx.account.role)) throw new HttpError(403, 'Your role cannot do this');
  }

  // Login ----------------------------------------------------------------------------------------

  /**
   * Cloudflare Access already proved who this is. The email must also belong to an enabled dashboard
   * account, so an Access policy that is too loose cannot let a stranger in. Creates the session and
   * lets the current request carry on.
   */
  function ssoSignIn(ctx: Ctx, identity: AccessIdentity): void {
    const account = db.accountByEmail(identity.email);
    const log = (result: string) =>
      db.logSignIn({ at: nowIso(), accountId: account?.id ?? null, email: identity.email, ip: ctx.ip, userAgent: header(ctx.req, 'user-agent'), result });
    if (!account || account.disabled) {
      log(account ? 'access-disabled' : 'access-no-account');
      throw new HttpError(403, `Cloudflare Access recognised ${identity.email}, but there is no active dashboard account for that address. Ask an owner to add it.`);
    }
    db.purgeSessions(nowIso());
    const setCookie = startSession(ctx, account, 'active');
    const token = setCookie.split(';')[0]!.slice(COOKIE.length + 1);
    ctx.session = db.sessionByToken(hashToken(token))!;
    ctx.account = account;
    ctx.res.setHeader('set-cookie', setCookie);
    log('access-ok');
  }

  function loginPage(ctx: Ctx, error?: string, status = 200): void {
    if (options.turnstileSiteKey) ctx.turnstile = true;
    page(
      ctx,
      'Sign in',
      '',
      html`<section class="card narrow">
        <h1>Sign in</h1>
        ${error ? html`<p class="flash flash--error" role="alert">${error}</p>` : ''}
        <form method="post" action="${base}" class="stack">
          <label>Email <input type="email" name="email" autocomplete="username" required></label>
          <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
          ${options.turnstileSiteKey
            ? html`<div class="cf-turnstile" data-sitekey="${options.turnstileSiteKey}"></div>
              <script src="${TURNSTILE_ORIGIN}/turnstile/v0/api.js" async defer></script>
              <noscript><p class="flash flash--error">Signing in needs JavaScript for the bot check.</p></noscript>`
            : ''}
          <button type="submit">Sign in</button>
        </form>
      </section>`,
      status,
    );
  }

  async function login(ctx: Ctx): Promise<void> {
    if (loginLimiter.take(`login:${ctx.ip}`) > 0) return loginPage(ctx, 'Too many attempts from this network. Wait a few minutes.', 429);
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const email = (form.get('email') ?? '').trim().toLowerCase().slice(0, 254);
    const password = form.get('password') ?? '';
    // Before any account lookup or password hashing: a bot learns nothing and cannot cause a lockout.
    if (options.turnstileSiteKey && !(await options.botCheck.verify(form.get('cf-turnstile-response') ?? undefined, ctx.ip))) {
      db.logSignIn({ at: nowIso(), accountId: null, email, ip: ctx.ip, userAgent: header(ctx.req, 'user-agent'), result: 'bot-check-failed' });
      return loginPage(ctx, 'The bot check did not pass. Please try again.', 403);
    }
    const account = db.accountByEmail(email);
    const log = (result: string) => db.logSignIn({ at: nowIso(), accountId: account?.id ?? null, email, ip: ctx.ip, userAgent: header(ctx.req, 'user-agent'), result });
    const generic = 'That email and password do not match an account.';

    if (!account) {
      await verifyPassword(password, await decoy());
      log('unknown-account');
      return loginPage(ctx, generic, 401);
    }
    if (account.lockedUntil && account.lockedUntil > nowIso()) {
      log('locked');
      return loginPage(ctx, 'This account is locked after too many attempts. Try again in 15 minutes.', 423);
    }
    if (!(await verifyPassword(password, account.passwordHash))) {
      const lock = account.failedLogins + 1 >= LOCK_AFTER ? new Date(options.now().getTime() + LOCK_FOR).toISOString() : null;
      db.recordFailure(account.id, lock);
      log(lock ? 'bad-password-locked' : 'bad-password');
      return loginPage(ctx, generic, 401);
    }
    if (account.disabled) {
      log('disabled');
      return loginPage(ctx, generic, 401);
    }
    if (account.totpSecret) {
      log('password-ok');
      return redirect(ctx, '/2fa', startSession(ctx, account, 'pending'));
    }
    db.clearFailures(account.id);
    log('ok');
    return redirect(ctx, '/', startSession(ctx, account, 'active'));
  }

  function twoFactorPage(ctx: Ctx, error?: string, status = 200): void {
    page(
      ctx,
      'Two-factor code',
      '',
      html`<section class="card narrow">
        <h1>Enter your code</h1>
        <p>Open your authenticator app and enter the 6-digit code for ${options.operatorName}.</p>
        ${error ? html`<p class="flash flash--error" role="alert">${error}</p>` : ''}
        <form method="post" action="${base}/2fa" class="stack">
          <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" required autofocus></label>
          <button type="submit">Continue</button>
        </form>
      </section>`,
      status,
    );
  }

  async function twoFactor(ctx: Ctx): Promise<void> {
    if (!loadSession(ctx, 'pending')) return redirect(ctx, '/');
    if (ctx.req.method === 'GET') return twoFactorPage(ctx);
    if (loginLimiter.take(`login:${ctx.ip}`) > 0) return twoFactorPage(ctx, 'Too many attempts. Wait a few minutes.', 429);
    const form = await readForm(ctx);
    const origin = header(ctx.req, 'origin');
    if (origin && origin !== options.origin) throw new HttpError(403, 'Cross-site request refused');
    const account = ctx.account!;
    const log = (result: string) => db.logSignIn({ at: nowIso(), accountId: account.id, email: account.email, ip: ctx.ip, userAgent: header(ctx.req, 'user-agent'), result });
    if (account.lockedUntil && account.lockedUntil > nowIso()) {
      log('locked');
      return twoFactorPage(ctx, 'This account is locked after too many attempts. Try again in 15 minutes.', 423);
    }
    const step = verifyTotp(account.totpSecret!, form.get('code') ?? '', options.now().getTime(), account.totpLastStep);
    if (step === null) {
      const lock = account.failedLogins + 1 >= LOCK_AFTER ? new Date(options.now().getTime() + LOCK_FOR).toISOString() : null;
      db.recordFailure(account.id, lock);
      log('bad-code');
      return twoFactorPage(ctx, 'That code did not work. Codes change every 30 seconds.', 401);
    }
    db.useTotpStep(account.id, step);
    db.clearFailures(account.id);
    db.deleteSession(ctx.session!.id);
    log('ok');
    return redirect(ctx, '/', startSession(ctx, account, 'active'));
  }

  // Pages ----------------------------------------------------------------------------------------

  function overview(ctx: Ctx): void {
    const counts = db.countsByStatus();
    const total = store.count();
    const head = store.head();
    const published = documents.all().filter((doc) => documents.status(doc) === 'published' && doc.manifest.category !== 'disclosure');
    const disabled = [...options.checks.values()].filter((check) => !check.enabled);
    page(
      ctx,
      'Overview',
      'home',
      html`<h1>Overview</h1>
      <div class="tiles">
        <div class="tile"><span class="tile__n">${total}</span> signed records</div>
        ${APPLICATION_STATUSES.map((s) => html`<a class="tile" href="${base}/submissions?status=${s}"><span class="tile__n">${counts[s] ?? 0}</span> ${s}</a>`)}
      </div>
      <section class="card">
        <h2>Open for signing</h2>
        ${published.length
          ? html`<ul>${published.map((doc) => html`<li>${doc.manifest.title} <span class="muted">${doc.manifest.id}@${doc.manifest.version}${doc.manifest.public ? '' : ', private links only'}</span></li>`)}</ul>`
          : html`<p class="muted">Nothing is published.</p>`}
      </section>
      <section class="card">
        <h2>Evidence chain</h2>
        <p>${total} ${total === 1 ? 'entry' : 'entries'}. Head <code>${head.hash}</code></p>
        <p>Sealing key <code>${options.sealingKey.kid}</code>. <a href="${base}/verify">Verify the full chain now</a></p>
      </section>
      <section class="card">
        <h2>Jurisdiction profiles</h2>
        <p class="muted">Facts about e-signature law by country, written from public sources. None has been reviewed by a lawyer unless it says so.</p>
        <div class="table-wrap"><table>
          <thead><tr><th>Profile</th><th>Law</th><th>Drafted</th><th>Review</th></tr></thead>
          <tbody>${options.profiles.all().map(({ profile }) => {
            const health = profileHealth(profile, options.now());
            return html`<tr class="${health.stale ? 'row-warn' : ''}"><td>${profile.id} ${profile.name}</td><td>${profile.eSignLaw.name}</td><td>${profile.drafted}${health.stale ? ' (older than a year)' : ''}</td><td>${profile.reviewedBy ? `${profile.reviewedBy.name}, ${profile.reviewedBy.on}` : 'not reviewed'}</td></tr>`;
          })}</tbody>
        </table></div>
      </section>
      <section class="card">
        <h2>Identity checks not configured</h2>
        <ul>${disabled.map((check) => html`<li><strong>${check.kind}</strong>: ${check.description}</li>`)}</ul>
      </section>`,
    );
  }

  async function verifyAll(ctx: Ctx): Promise<void> {
    const records = await verifyChain(store.entries(), options.keySet);
    const auditLog = await verifyChain(db.auditEntries(), options.keySet);
    const report = (name: string, result: Awaited<ReturnType<typeof verifyChain>>) =>
      html`<section class="card"><h2>${name}</h2>
        <p class="${result.ok ? 'good' : 'bad'}">${result.ok ? 'Intact' : 'Broken'}: ${result.length} entries, head <code>${result.head}</code></p>
        ${result.breaks.length ? html`<ul>${result.breaks.map((b) => html`<li>#${b.index} ${b.id}: ${b.reason}</li>`)}</ul>` : ''}
      </section>`;
    page(ctx, 'Verify', 'home', html`<h1>Chain verification</h1>${report('Signed records', records)}${report('Audit log', auditLog)}`);
  }

  function submissionsFilter(url: URL) {
    const pageNo = Math.max(1, Number(url.searchParams.get('page') ?? 1) || 1);
    const filter = {
      documentId: url.searchParams.get('doc') || undefined,
      status: url.searchParams.get('status') || undefined,
      country: (url.searchParams.get('country') || '').toUpperCase().slice(0, 2) || undefined,
      query: (url.searchParams.get('q') || '').trim().slice(0, 100) || undefined,
    };
    return { pageNo, filter };
  }

  function submissions(ctx: Ctx): void {
    const { pageNo, filter } = submissionsFilter(ctx.url);
    const size = 50;
    const { rows, total } = db.submissions({ ...stripUndefined(filter), limit: size, offset: (pageNo - 1) * size });
    const ids = [...new Set(documents.all().filter((d) => d.manifest.category !== 'disclosure').map((d) => d.manifest.id))];
    const query = new URLSearchParams(stripUndefined({ doc: filter.documentId, status: filter.status, country: filter.country, q: filter.query }) as Record<string, string>);
    const pages = Math.max(1, Math.ceil(total / size));
    page(
      ctx,
      'Submissions',
      'submissions',
      html`<h1>Submissions</h1>
      <form method="get" action="${base}/submissions" class="filters">
        <label>Document <select name="doc"><option value="">All</option>${ids.map((id) => html`<option ${id === filter.documentId ? raw('selected') : ''}>${id}</option>`)}</select></label>
        <label>Status <select name="status"><option value="">All</option>${APPLICATION_STATUSES.map((s) => html`<option ${s === filter.status ? raw('selected') : ''}>${s}</option>`)}</select></label>
        <label>Country <input name="country" maxlength="2" size="3" value="${filter.country ?? ''}"></label>
        <label>Name, email or id <input name="q" value="${filter.query ?? ''}"></label>
        <button type="submit">Filter</button>
        ${ctx.account!.role !== 'reviewer' ? html`<a class="button-link" href="${base}/submissions.csv?${query.toString()}">Export CSV</a>` : ''}
      </form>
      <p class="muted">${total} matching.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Signed</th><th>Name</th><th>Email</th><th>Country</th><th>Document</th><th>Status</th></tr></thead>
        <tbody>${rows.map((row) => html`<tr>
          <td><a href="${base}/submissions/${row.id as string}">${shortDate(row.received_at as string)}</a></td>
          <td>${row.tombstoned_at ? html`<span class="muted">removed</span>` : (row.signer_name as string)}${row.hold ? html` <span class="pill">hold</span>` : ''}</td>
          <td>${row.email as string}</td>
          <td>${row.country as string}</td>
          <td>${row.document_id as string}@${row.document_version as string}</td>
          <td>${row.application_status as string}</td>
        </tr>`)}</tbody>
      </table></div>
      <nav class="pager" aria-label="Pages">
        ${pageNo > 1 ? html`<a href="${base}/submissions?${withPage(query, pageNo - 1)}">Previous</a>` : ''}
        <span>Page ${pageNo} of ${pages}</span>
        ${pageNo < pages ? html`<a href="${base}/submissions?${withPage(query, pageNo + 1)}">Next</a>` : ''}
      </nav>`,
    );
  }

  function submissionsCsv(ctx: Ctx): void {
    need(ctx, 'owner', 'admin');
    const { filter } = submissionsFilter(ctx.url);
    const { rows } = db.submissions({ ...stripUndefined(filter), limit: 100_000, offset: 0 });
    const head = ['id', 'signed_at', 'name', 'email', 'country', 'document', 'version', 'status', 'hold', 'hash'];
    const lines = [head.join(',')].concat(
      rows.map((row) =>
        [row.id, row.received_at, row.signer_name, row.email, row.country, row.document_id, row.document_version, row.application_status, row.hold ? 'yes' : 'no', row.hash].map(csvCell).join(','),
      ),
    );
    void audit(ctx, 'submissions.export', 'submissions', { count: rows.length, filter: stripUndefined(filter) as Record<string, JsonValue> });
    download(ctx, 'text/csv; charset=utf-8', `submissions-${nowIso().slice(0, 10)}.csv`, 'ï»¿' + lines.join('\r\n') + '\r\n');
  }

  async function submission(ctx: Ctx, id: string): Promise<void> {
    const summary = store.summary(id);
    const entry = store.getEntry(id);
    if (!summary || !entry) throw new HttpError(404, 'No such submission');
    const verdict = await verifyEntry(entry, options.keySet);
    const role = ctx.account!.role;
    const csrf = csrfField(ctx.session!.csrf);
    const doc = documents.get(summary.documentId, summary.documentVersion);
    const record = 'fields' in entry ? (entry as SealformRecord) : undefined;

    page(
      ctx,
      record ? `Submission from ${summary.signerName ?? id}` : 'Removed submission',
      'submissions',
      html`<p><a href="${base}/submissions">Back to submissions</a></p>
      <h1>${record ? summary.signerName ?? id : 'Removed submission'}</h1>
      <p class="${verdict.ok ? 'good' : 'bad'}">${verdict.ok ? 'Verified: content, hash and seal all check out.' : `Verification failed: ${verdict.errors.join('; ')}`}</p>
      <div class="grid2">
        <section class="card">
          <h2>Review</h2>
          <form method="post" action="${base}/submissions/${id}/status" class="inline">${csrf}
            <label>Application status <select name="status">${APPLICATION_STATUSES.map((s) => html`<option ${s === summary.applicationStatus ? raw('selected') : ''}>${s}</option>`)}</select></label>
            <button type="submit">Save</button>
          </form>
          ${role === 'owner'
            ? html`<form method="post" action="${base}/submissions/${id}/hold" class="inline">${csrf}
                <input type="hidden" name="hold" value="${summary.hold ? 'off' : 'on'}">
                <p>Legal hold is <strong>${summary.hold ? 'on' : 'off'}</strong>. A hold blocks removal of this record when its retention period ends.</p>
                <button type="submit">${summary.hold ? 'Release hold' : 'Place legal hold'}</button>
              </form>`
            : html`<p>Legal hold: <strong>${summary.hold ? 'on' : 'off'}</strong></p>`}
          ${record
            ? html`<p><a href="${base}/submissions/${id}/pdf">PDF copy</a> Â· <a href="${base}/submissions/${id}/record.json">Sealed record</a></p>`
            : ''}
        </section>
        ${record
          ? html`<section class="card">
            <h2>Signature</h2>
            <img class="signature" src="${base}/submissions/${id}/signature.png" alt="Drawn signature of ${record.signature.typedName}">
            <p>Typed name: ${record.signature.typedName}</p>
          </section>`
          : ''}
      </div>
      ${record
        ? html`<section class="card">
          <h2>Answers</h2>
          <dl class="facts">${(doc?.manifest.fields ?? Object.keys(record.fields).map((name) => ({ name, label: name }))).map(
            (field) => html`<dt>${field.label}</dt><dd>${formatValue(record.fields[field.name])}</dd>`,
          )}</dl>
          <h2>Agreed to</h2>
          <ul>${Object.entries(record.consent).map(([name, value]) => html`<li>${value ? 'Yes' : 'No'}: ${doc?.manifest.consents.find((c) => c.name === name)?.label ?? name}</li>`)}</ul>
        </section>
        <section class="card">
          <h2>Evidence</h2>
          <dl class="facts">
            <dt>Signed at</dt><dd>${record.server.receivedAt}</dd>
            <dt>Form opened</dt><dd>${record.server.sessionOpenedAt}</dd>
            <dt>IP address</dt><dd>${record.server.ip}</dd>
            <dt>Browser</dt><dd>${record.server.userAgent}</dd>
            <dt>Languages</dt><dd>${record.server.acceptLanguage}</dd>
            <dt>Client reported</dt><dd>${Object.entries(record.client).map(([k, v]) => `${k}: ${String(v)}`).join(', ')}</dd>
            <dt>Checks</dt><dd>${record.assurance.checks.map((c) => `${c.kind}: ${c.status}`).join(', ') || 'none'}</dd>
            <dt>Jurisdiction</dt><dd>${record.jurisdiction ? `${record.jurisdiction.profile} v${record.jurisdiction.version}${record.jurisdiction.fallback ? ' (default, no country profile)' : ''}` : 'none'}</dd>
            <dt>Document</dt><dd>${record.document.id}@${record.document.version} (${record.document.lang}) <code>${record.document.sha256}</code></dd>
            <dt>Chain</dt><dd>#${record.chain.seq}, previous <code>${record.chain.prevHash}</code></dd>
            <dt>Record hash</dt><dd><code>${record.hash}</code></dd>
            <dt>Seal</dt><dd>${record.seal.alg}, key ${record.seal.kid}</dd>
          </dl>
        </section>`
        : html`<section class="card"><p>The personal data in this record was removed at the end of its retention period. Its hash and seal remain so the chain still verifies.</p></section>`}`,
    );
  }

  async function submissionFile(ctx: Ctx, id: string, kind: string): Promise<void> {
    const summary = store.summary(id);
    if (!summary || summary.tombstonedAt) throw new HttpError(404, 'No such file');
    if (kind === 'record.json') return download(ctx, 'application/json', `${id}.json`, JSON.stringify(store.getEntry(id), null, 2));
    const file = kind === 'pdf' ? `${id}.pdf` : `${id}.png`;
    const bytes = await readFile(join(store.recordsDir, file));
    if (kind === 'pdf') return download(ctx, 'application/pdf', file, bytes);
    ctx.res.writeHead(200, { ...securityHeaders, 'content-type': 'image/png' });
    ctx.res.end(bytes);
  }

  async function setStatus(ctx: Ctx, id: string): Promise<void> {
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const status = form.get('status') ?? '';
    if (!APPLICATION_STATUSES.includes(status)) throw new HttpError(400, 'Unknown status');
    const before = store.summary(id);
    if (!before || !db.setApplicationStatus(id, status)) throw new HttpError(404, 'No such submission');
    await audit(ctx, 'submission.status', id, { from: before.applicationStatus, to: status });
    redirect(ctx, `/submissions/${id}?m=saved`);
  }

  async function setHold(ctx: Ctx, id: string): Promise<void> {
    need(ctx, 'owner');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const hold = form.get('hold') === 'on';
    if (!db.setHold(id, hold)) throw new HttpError(404, 'No such submission');
    await audit(ctx, hold ? 'submission.hold' : 'submission.release', id);
    redirect(ctx, `/submissions/${id}?m=saved`);
  }

  function documentsPage(ctx: Ctx): void {
    need(ctx, 'owner', 'admin');
    const counts = new Map<string, number>();
    for (const row of db.submissions({ limit: 1_000_000, offset: 0 }).rows) {
      const key = `${row.document_id as string}@${row.document_version as string}`;
      counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    const docs = documents.all().sort((a, b) => a.manifest.id.localeCompare(b.manifest.id) || b.manifest.version.localeCompare(a.manifest.version));
    page(
      ctx,
      'Documents',
      'documents',
      html`<h1>Documents</h1>
      <p class="muted">Document text lives in the documents folder on the server. A published version never changes; new terms go in a new version folder.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>Document</th><th>Version</th><th>Status</th><th>Languages</th><th>Listed</th><th>Signed</th></tr></thead>
        <tbody>${docs.map((doc) => html`<tr>
          <td><a href="${base}/documents/${doc.manifest.id}/${doc.manifest.version}">${doc.manifest.title}</a></td>
          <td>${doc.manifest.version}</td>
          <td><span class="pill pill--${documents.status(doc)}">${documents.status(doc)}</span></td>
          <td>${doc.manifest.languages.join(', ')}</td>
          <td>${doc.manifest.category === 'disclosure' ? 'disclosure' : doc.manifest.public ? 'public' : 'private links'}</td>
          <td>${counts.get(`${doc.manifest.id}@${doc.manifest.version}`) ?? 0}</td>
        </tr>`)}</tbody>
      </table></div>`,
    );
  }

  function documentPage(ctx: Ctx, doc: LoadedDocument): void {
    need(ctx, 'owner', 'admin');
    const status = documents.status(doc);
    const csrf = csrfField(ctx.session!.csrf);
    const missing = doc.manifest.requiredChecks.filter((kind) => !options.checks.get(kind)?.enabled);
    const unfinished = hasPlaceholder(doc);
    const signedFrom = new Set<string>();
    for (const row of db.submissions({ documentId: doc.manifest.id, limit: 1_000_000, offset: 0 }).rows) {
      if (row.document_version === doc.manifest.version && typeof row.country === 'string' && row.country) signedFrom.add(row.country);
    }
    const review = retentionReview(doc.manifest.retention.signed, [...signedFrom].map((country) => options.profiles.resolve(country)));
    const action = (to: DocumentStatus, label: string) =>
      html`<form method="post" action="${base}/documents/${doc.manifest.id}/${doc.manifest.version}/status" class="inline">${csrf}<input type="hidden" name="status" value="${to}"><button type="submit">${label}</button></form>`;
    page(
      ctx,
      doc.manifest.title,
      'documents',
      html`<p><a href="${base}/documents">Back to documents</a></p>
      <h1>${doc.manifest.title}</h1>
      <section class="card">
        <dl class="facts">
          <dt>Id and version</dt><dd>${doc.manifest.id}@${doc.manifest.version}</dd>
          <dt>Status</dt><dd><span class="pill pill--${status}">${status}</span></dd>
          <dt>Category</dt><dd>${doc.manifest.category}</dd>
          <dt>Languages</dt><dd>${doc.manifest.languages.join(', ')} (governing: ${doc.manifest.governingLang})</dd>
          <dt>Retention</dt><dd>signed ${doc.manifest.retention.signed}, unsigned ${doc.manifest.retention.unsigned}</dd>
          <dt>Claim periods</dt><dd>${review.rows.length
            ? html`${review.rows.map((r) => html`${r.name}${r.fallback ? ' (default)' : ''}: ${r.period}<br>`)}`
            : 'No signatures yet, so no countries to compare.'}</dd>
          <dt>Required checks</dt><dd>${doc.manifest.requiredChecks.join(', ') || 'none'}</dd>
          <dt>Form hash</dt><dd><code>${doc.manifestSha256}</code></dd>
        </dl>
        ${review.tooShort ? html`<p class="bad">Signed records are kept for ${doc.manifest.retention.signed}, shorter than the usual claim period in ${review.longest!.name} (${review.longest!.period}). A late claim could arrive after the record is gone. This is a flag, not a rule: retention is also limited by data protection law, so decide with advice.</p>` : ''}
        ${missing.length ? html`<p class="bad">Cannot be published until these checks are configured: ${missing.join(', ')}</p>` : ''}
        ${unfinished ? html`<p class="bad">Cannot be published: the text still has a [TO CONFIRM: ...] marker for something that must be filled in first.</p>` : ''}
        <div class="actions">
          ${status !== 'published' && !missing.length && !unfinished && doc.manifest.category !== 'disclosure' ? action('published', 'Publish this version') : ''}
          ${status === 'published' ? action('closed', 'Close to new signatures') : ''}
          ${status === 'closed' ? action('draft', 'Return to draft') : ''}
        </div>
        ${status !== 'published' ? html`<p class="muted">Publishing closes any other published version of ${doc.manifest.id}.</p>` : ''}
      </section>
      ${[...doc.texts.values()].map(
        (text) => html`<section class="card"><h2>Text (${text.lang})</h2><p class="muted">SHA-256 <code>${text.sha256}</code></p><article class="doc-preview" lang="${text.lang}">${renderDocumentMarkdown(text.text)}</article><details><summary>View exact Markdown source</summary><pre class="doc-text">${text.text}</pre></details></section>`,
      )}`,
    );
  }

  async function setDocumentStatus(ctx: Ctx, doc: LoadedDocument): Promise<void> {
    need(ctx, 'owner', 'admin');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const status = form.get('status') as DocumentStatus;
    if (!['draft', 'published', 'closed'].includes(status)) throw new HttpError(400, 'Unknown status');
    let changes;
    try {
      changes = documents.setStatus(doc.manifest.id, doc.manifest.version, status);
    } catch (error) {
      throw new HttpError(409, error instanceof Error ? error.message : String(error));
    }
    for (const change of changes) {
      db.saveDocumentStatus(change.id, change.version, change.to);
      await audit(ctx, 'document.status', `${change.id}@${change.version}`, { from: change.from, to: change.to });
    }
    redirect(ctx, `/documents/${doc.manifest.id}/${doc.manifest.version}?m=saved`);
  }

  // Site: hidden and private pages, parking, site info ----------------------------------------------

  async function sitePage(ctx: Ctx, error?: string): Promise<void> {
    need(ctx, 'owner');
    const csrf = csrfField(ctx.session!.csrf);
    const info = options.siteInfo ? await options.siteInfo() : undefined;
    const parked = db.setting('parking') === 'on';
    page(
      ctx,
      'Site',
      'site',
      html`<h1>Site</h1>
      ${error ? html`<p class="flash flash--error" role="alert">${error}</p>` : ''}
      ${info
        ? html`<section class="card">
        <h2>Parking</h2>
        <p>The site is <strong>${parked ? 'parked' : 'open'}</strong>. ${parked ? 'Visitors see the "back soon" page (HTTP 503) everywhere except the paths listed below.' : 'Switch it on to hold every page behind a "back soon" page.'}</p>
        <form method="post" action="${base}/site/parking" class="inline">${csrf}<input type="hidden" name="parking" value="${parked ? 'off' : 'on'}"><button type="submit">${parked ? 'Open the site' : 'Park the site'}</button></form>
        <p class="muted">Stays reachable while parked: ${info.allow.map((p) => html`<code>${p}</code> `)}. The signing form, contract links and this dashboard are not part of the site and keep working. The parked page is <code>parked/index.html</code> in the site folder${info.hasParkedPage ? '' : ' (not found, so a plain built-in page is shown)'}.</p>
      </section>
      <section class="card">
        <h2>Hidden and private pages</h2>
        <p class="muted">A path covers everything under it. <strong>Hidden</strong> answers 404 to everyone. <strong>Private</strong> answers 404 unless you are signed in to this dashboard. The longest matching path wins.</p>
        ${db.siteRules().length === 0 ? html`<p class="muted">No rules yet. Every page of the site is public.</p>` : ''}
        <div class="table-wrap" ${db.siteRules().length === 0 ? raw('hidden') : ''}><table>
          <thead><tr><th>Path</th><th>Mode</th><th>Set by</th><th></th></tr></thead>
          <tbody>${db.siteRules().map((rule) => html`<tr><td><code>${rule.prefix}</code></td><td>${rule.mode}</td><td>${rule.createdBy}, ${shortDate(rule.createdAt)}</td>
            <td><form method="post" action="${base}/site/rules/delete" class="inline">${csrf}<input type="hidden" name="prefix" value="${rule.prefix}"><button type="submit">Remove</button></form></td></tr>`)}</tbody>
        </table></div>
        <form method="post" action="${base}/site/rules" class="stack narrow">${csrf}
          <label>Path <input name="prefix" required maxlength="200" placeholder="/press/internal/"></label>
          <label>Mode <select name="mode"><option>hidden</option><option>private</option></select></label>
          <button type="submit">Add or change a rule</button>
        </form>
      </section>
      <section class="card">
        <h2>Site info</h2>
        <dl class="facts">
          <dt>Folder</dt><dd><code>${info.dir}</code>${info.exists ? '' : html` <span class="bad">not found</span>`}</dd>
          <dt>Last build</dt><dd>${info.builtAt ? shortDate(info.builtAt) : 'no index.html found'}</dd>
          <dt>404 page</dt><dd>${info.hasNotFoundPage ? 'yes' : 'plain text'}</dd>
          <dt>Signed records</dt><dd>${store.count()}, chain head <code>${store.head().hash}</code></dd>
          <dt>Audit entries</dt><dd>${db.auditEntries().length}</dd>
          <dt>Sealing key</dt><dd>${options.sealingKey.kid}; published keys: ${options.keySet.keys.map((k) => `${k.kid}${k.retiredAt ? ' (retired)' : ''}`).join(', ')}</dd>
          <dt>Checks not configured</dt><dd>${[...options.checks.values()].filter((c) => !c.enabled).map((c) => c.kind).join(', ') || 'none'}</dd>
        </dl>
      </section>`
        : html`<section class="card"><p>sealform is not serving the website. Set <code>site: { dir: '/path/to/dist' }</code> in the configuration to manage parking and page visibility here.</p></section>`}`,
    );
  }

  async function siteAction(ctx: Ctx, action: string): Promise<void> {
    need(ctx, 'owner');
    if (!options.siteInfo) throw new HttpError(404, 'The site is not served by sealform');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    if (action === 'parking') {
      const on = form.get('parking') === 'on';
      db.saveSetting('parking', on ? 'on' : 'off');
      await audit(ctx, on ? 'site.park' : 'site.open', 'site');
    } else if (action === 'rules') {
      const prefix = normalizePrefix(form.get('prefix') ?? '');
      const mode = form.get('mode');
      if (!prefix || prefix === '/' || (mode !== 'hidden' && mode !== 'private')) return sitePage(ctx, 'Enter a path such as /press/internal/ and choose hidden or private. The whole site (/) cannot be hidden here; use parking.');
      db.setSiteRule(prefix, mode, ctx.account!.email, nowIso());
      await audit(ctx, 'site.rule.set', prefix, { mode });
    } else if (action === 'rules/delete') {
      const prefix = normalizePrefix(form.get('prefix') ?? '');
      if (!prefix || !db.deleteSiteRule(prefix)) throw new HttpError(404, 'No such rule');
      await audit(ctx, 'site.rule.delete', prefix);
    } else {
      throw new HttpError(404, 'Not found');
    }
    redirect(ctx, '/site?m=saved');
  }

  // Contracts: private signing links ---------------------------------------------------------------

  const EXPIRY_DAYS = [7, 14, 30, 60, 90];
  const countryNames = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'code' });

  function envelopeState(env: Envelope): string {
    return (env.status === 'open' || env.status === 'signing') && env.expiresAt < nowIso() ? 'expired' : env.status;
  }

  function contractsPage(ctx: Ctx, extra?: { created?: { link: string; label: string; email: string }; error?: string }, status = 200): void {
    need(ctx, 'owner', 'admin');
    const csrf = csrfField(ctx.session!.csrf);
    const docs = documents.all().filter((d) => documents.status(d) === 'published' && !d.manifest.public && d.manifest.category !== 'disclosure');
    page(
      ctx,
      'Contracts',
      'contracts',
      html`<h1>Contracts</h1>
      <p class="muted">Send a private link to one person to sign a document that is not listed publicly. The link works once, expires, and fixes the signer's name and email.</p>
      ${options.operatorProfile ? html`<p class="muted">Your side is checked against <strong>${options.operatorProfile.profile.name}</strong>: ${options.operatorProfile.profile.levelNote}</p>` : ''}
      ${extra?.error ? html`<p class="flash flash--error" role="alert">${extra.error}</p>` : ''}
      ${extra?.created
        ? html`<section class="card notice" role="status"><h2>Link for ${extra.created.email}</h2>
          <p>Send it to them privately. It is shown only once; sealform keeps only a hash of it, so it cannot be shown again. If it is lost, cancel this contract and make a new one.</p>
          <p><code class="secret">${extra.created.link}</code></p></section>`
        : ''}
      <div class="table-wrap"><table>
        <thead><tr><th>Contract</th><th>Signer</th><th>Document</th><th>Status</th><th>Expires</th></tr></thead>
        <tbody>${db.envelopes().map((env) => html`<tr>
          <td><a href="${base}/contracts/${env.id}">${env.label}</a></td>
          <td>${env.signerName} (${env.signerEmail})</td>
          <td>${env.documentId}@${env.documentVersion}</td>
          <td><span class="pill pill--${envelopeState(env) === 'complete' ? 'published' : envelopeState(env)}">${envelopeState(env)}</span></td>
          <td>${shortDate(env.expiresAt)}</td>
        </tr>`)}</tbody>
      </table></div>
      <section class="card">
        <h2>New contract link</h2>
        ${docs.length
          ? html`<form method="post" action="${base}/contracts" class="stack narrow">${csrf}
          <label>Document <select name="document" required>${docs.map((d) => html`<option value="${d.manifest.id}@${d.manifest.version}">${d.manifest.title} (${d.manifest.version})</option>`)}</select></label>
          <label>Label for your records <input name="label" required maxlength="120"></label>
          <label>Signer's full legal name <input name="name" required maxlength="200"></label>
          <label>Signer's email <input type="email" name="email" required maxlength="254"></label>
          <label>Signer's country, to check the rules there <select name="country"><option value="">Not sure yet</option>${COUNTRY_CODES.map((code) => html`<option value="${code}">${countryNames.of(code) ?? code}</option>`)}</select></label>
          <label>Link expires in <select name="days">${EXPIRY_DAYS.map((d) => html`<option value="${d}" ${d === 14 ? raw('selected') : ''}>${d} days</option>`)}</select></label>
          <label class="check"><input type="checkbox" name="counter" value="1"> I will countersign after they sign</label>
          <label>Reason, only if the country check below blocks this <input name="override" maxlength="300"></label>
          <button type="submit">Create the link</button>
        </form>`
          : html`<p class="muted">No private document is published. A document is private when its <code>public</code> setting is false; publish one from Documents first.</p>`}
      </section>`,
      status,
    );
  }

  async function createContract(ctx: Ctx): Promise<void> {
    need(ctx, 'owner', 'admin');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const [docId, version] = (form.get('document') ?? '').split('@');
    const doc = docId && version ? documents.get(docId, version) : undefined;
    if (!doc || documents.status(doc) !== 'published' || doc.manifest.public || doc.manifest.category === 'disclosure') throw new HttpError(400, 'Pick a published private document');
    const label = (form.get('label') ?? '').trim();
    const name = (form.get('name') ?? '').trim();
    const email = (form.get('email') ?? '').trim().toLowerCase();
    const days = Number(form.get('days'));
    const country = (form.get('country') ?? '').trim();
    if (!label || label.length > 120 || !name || name.length > 200 || !/^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$/.test(email) || email.length > 254 || !EXPIRY_DAYS.includes(days) || (country && !isCountryCode(country))) {
      throw new HttpError(400, 'Label, name, a valid email and an expiry from the list are needed');
    }
    // Review the signer's country before a link exists. A document the law there excludes from simple
    // e-signatures needs a stated reason to proceed, and the reason is kept in the audit log.
    const override = (form.get('override') ?? '').trim().slice(0, 300);
    // Your own side first: the law where you operate can exclude a document type too.
    const ours = options.operatorProfile?.profile.formRequirements.find((r) => r.category === doc.manifest.category);
    if (ours && !override) {
      return contractsPage(ctx, { error: `Where you operate (${options.operatorProfile!.profile.name}), a ${doc.manifest.category} document needs ${ours.requires}, not a simple electronic signature. ${ours.note} Enter a reason to send it anyway.` }, 409);
    }
    if (country) {
      const { loaded } = options.profiles.resolve(country);
      const needs = loaded.profile.formRequirements.find((r) => r.category === doc.manifest.category);
      if (needs && !override) {
        return contractsPage(ctx, { error: `In ${loaded.profile.name}, a ${doc.manifest.category} document needs ${needs.requires}, not a simple electronic signature. ${needs.note} Enter a reason to send it anyway.` }, 409);
      }
    }
    const token = newToken();
    const created = options.now();
    const env = db.createEnvelope({
      tokenHash: hashToken(token),
      documentId: doc.manifest.id,
      documentVersion: doc.manifest.version,
      label,
      signerName: name,
      signerEmail: email,
      signerCountry: country || null,
      counterRequired: form.get('counter') === '1',
      createdBy: ctx.account!.email,
      createdAt: created.toISOString(),
      expiresAt: new Date(created.getTime() + days * 86_400_000).toISOString(),
      overrideReason: override || null,
    });
    await audit(ctx, 'envelope.create', env.id, { document: `${doc.manifest.id}@${doc.manifest.version}`, signer: email, expiresAt: env.expiresAt, countersign: env.counterRequired, country: country || null, operatorProfile: options.operatorProfile?.profile.id ?? null, override: override || null });
    contractsPage(ctx, { created: { link: `${options.origin}${options.signBase}/c/${token}`, label, email } });
  }

  function contractPage(ctx: Ctx, env: Envelope): void {
    need(ctx, 'owner', 'admin');
    const csrf = csrfField(ctx.session!.csrf);
    const state = envelopeState(env);
    page(
      ctx,
      env.label,
      'contracts',
      html`<p><a href="${base}/contracts">Back to contracts</a></p>
      <h1>${env.label}</h1>
      <section class="card">
        <dl class="facts">
          <dt>Status</dt><dd><span class="pill pill--${state === 'complete' ? 'published' : state}">${state}</span></dd>
          <dt>Document</dt><dd>${env.documentId}@${env.documentVersion}</dd>
          <dt>Signer</dt><dd>${env.signerName} (${env.signerEmail})${env.signerCountry ? `, ${countryNames.of(env.signerCountry) ?? env.signerCountry}` : ''}</dd>
          <dt>Created</dt><dd>${shortDate(env.createdAt)} by ${env.createdBy}</dd>
          <dt>Expires</dt><dd>${shortDate(env.expiresAt)}</dd>
          <dt>Countersignature</dt><dd>${env.counterRequired ? 'you will countersign' : 'not needed'}</dd>
          ${env.overrideReason ? html`<dt>Country check overridden</dt><dd>${env.overrideReason}</dd>` : ''}
          ${env.recordId ? html`<dt>Signed</dt><dd>${shortDate(env.signedAt)}, <a href="${base}/submissions/${env.recordId}">view the signed record</a></dd>` : ''}
          ${env.countersignedAt ? html`<dt>Countersigned</dt><dd>${shortDate(env.countersignedAt)} by ${env.countersignedBy}</dd>` : ''}
          ${env.finalHash ? html`<dt>Final hash</dt><dd><code>${env.finalHash}</code></dd>` : ''}
          ${env.revokedAt ? html`<dt>Cancelled</dt><dd>${shortDate(env.revokedAt)}</dd>` : ''}
        </dl>
        <div class="actions">
          ${env.status === 'awaiting-countersignature' ? html`<form method="post" action="${base}/contracts/${env.id}/countersign" class="inline">${csrf}<button type="submit">Countersign as ${ctx.account!.email}</button></form>` : ''}
          ${env.status === 'open' || env.status === 'signing' ? html`<form method="post" action="${base}/contracts/${env.id}/revoke" class="inline">${csrf}<button type="submit">Cancel this link</button></form>` : ''}
        </div>
        ${env.status === 'awaiting-countersignature' ? html`<p class="muted">Countersigning seals your decision into the audit log with the signer's record hash, and emails the signer a confirmation.</p>` : ''}
      </section>`,
    );
  }

  async function contractAction(ctx: Ctx, id: string, action: string): Promise<void> {
    need(ctx, 'owner', 'admin');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const env = db.envelope(id);
    if (!env) throw new HttpError(404, 'No such contract');
    const at = nowIso();
    if (action === 'revoke') {
      if (!db.revokeEnvelope(id, at)) throw new HttpError(409, 'Only a link that has not been signed can be cancelled');
      await audit(ctx, 'envelope.revoke', id, { signer: env.signerEmail });
    } else if (action === 'countersign') {
      if (env.status !== 'awaiting-countersignature' || !env.recordId || !env.recordHash) throw new HttpError(409, 'This contract is not waiting for a countersignature');
      const finalHash = await sha256Canonical({ envelope: env.id, document: `${env.documentId}@${env.documentVersion}`, signerRecord: { id: env.recordId, hash: env.recordHash }, countersignedBy: ctx.account!.email, countersignedAt: at });
      if (!db.countersignEnvelope(id, ctx.account!.email, at, finalHash)) throw new HttpError(409, 'This contract was already countersigned');
      await audit(ctx, 'envelope.countersign', id, { record: env.recordId, recordHash: env.recordHash, finalHash, document: `${env.documentId}@${env.documentVersion}` });
      options.mailer
        .send({
          to: env.signerEmail,
          from: `${options.operator.name.replace(/[<>"\r\n]/g, '')} <${options.operator.email}>`,
          replyTo: options.operator.email,
          subject: `Countersigned: ${env.label}`,
          text: [`${options.operator.name} countersigned "${env.label}" on ${at} UTC.`, '', `Your signed record: ${env.recordId}`, `Record SHA-256: ${env.recordHash}`, `Final SHA-256 of the completed agreement: ${finalHash}`, '', `Questions: ${options.operator.email}`].join('\n'),
        })
        .catch((error: unknown) => options.log(`countersign notice for ${id} not sent: ${error instanceof Error ? error.message : String(error)}`));
    } else {
      throw new HttpError(404, 'Not found');
    }
    redirect(ctx, `/contracts/${id}?m=saved`);
  }

  function accountsPage(ctx: Ctx, created?: { email: string; password: string }): void {
    need(ctx, 'owner');
    const csrf = csrfField(ctx.session!.csrf);
    page(
      ctx,
      'Accounts',
      'accounts',
      html`<h1>Accounts</h1>
      ${created
        ? html`<section class="card notice" role="status"><h2>Temporary password for ${created.email}</h2>
          <p>Send it privately. It is shown only once, and they must change it at first sign-in.</p>
          <p><code class="secret">${created.password}</code></p></section>`
        : ''}
      <div class="table-wrap"><table>
        <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Two-factor</th><th>State</th><th>Actions</th></tr></thead>
        <tbody>${db.accounts().map((acct) => html`<tr>
          <td>${acct.name}</td>
          <td>${acct.email}</td>
          <td>${acct.id === ctx.account!.id
            ? acct.role
            : html`<form method="post" action="${base}/accounts/${acct.id}/role" class="inline">${csrf}<select name="role" aria-label="Role for ${acct.email}">${ROLES.map((r) => html`<option ${r === acct.role ? raw('selected') : ''}>${r}</option>`)}</select><button type="submit">Set</button></form>`}</td>
          <td>${acct.totpSecret ? 'on' : 'off'}</td>
          <td>${acct.disabled ? 'disabled' : acct.lockedUntil && acct.lockedUntil > nowIso() ? 'locked' : 'active'}</td>
          <td class="actions">${acct.id === ctx.account!.id
            ? html`<span class="muted">you</span>`
            : html`<form method="post" action="${base}/accounts/${acct.id}/${acct.disabled ? 'enable' : 'disable'}" class="inline">${csrf}<button type="submit">${acct.disabled ? 'Enable' : 'Disable'}</button></form>
              <form method="post" action="${base}/accounts/${acct.id}/reset" class="inline">${csrf}<button type="submit">Reset password and two-factor</button></form>`}</td>
        </tr>`)}</tbody>
      </table></div>
      <section class="card">
        <h2>Add an account</h2>
        <form method="post" action="${base}/accounts" class="stack narrow">${csrf}
          <label>Name <input name="name" required maxlength="100"></label>
          <label>Email <input type="email" name="email" required maxlength="254"></label>
          <label>Role <select name="role">${ROLES.map((r) => html`<option ${r === 'reviewer' ? raw('selected') : ''}>${r}</option>`)}</select></label>
          <p class="muted">Reviewers read submissions and set their status. Admins also manage documents and export. Owners also manage accounts, legal holds and the audit log.</p>
          <button type="submit">Create with a temporary password</button>
        </form>
      </section>`,
    );
  }

  async function accountAction(ctx: Ctx, id: string | undefined, action: string): Promise<void> {
    need(ctx, 'owner');
    const form = await readForm(ctx);
    checkPost(ctx, form);
    if (!id) {
      const email = (form.get('email') ?? '').trim().toLowerCase();
      const name = (form.get('name') ?? '').trim();
      const role = form.get('role') as Role;
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !name || !ROLES.includes(role)) throw new HttpError(400, 'Name, a valid email and a role are needed');
      if (db.accountByEmail(email)) throw new HttpError(409, 'An account with that email exists');
      const password = temporaryPassword();
      const acct = db.createAccount({ email, name, role, passwordHash: await hashPassword(password), mustChangePassword: true, now: nowIso() });
      await audit(ctx, 'account.create', acct.id, { email, role });
      return accountsPage(ctx, { email, password });
    }
    const target = db.account(id);
    if (!target) throw new HttpError(404, 'No such account');
    if (target.id === ctx.account!.id) throw new HttpError(400, 'Use My account to change your own account');
    const losingOwner = target.role === 'owner' && !target.disabled && db.activeOwnerCount() <= 1;
    if (action === 'role') {
      const role = form.get('role') as Role;
      if (!ROLES.includes(role)) throw new HttpError(400, 'Unknown role');
      if (losingOwner && role !== 'owner') throw new HttpError(409, 'At least one active owner must remain');
      db.setRole(id, role);
      db.deleteSessionsFor(id);
      await audit(ctx, 'account.role', id, { from: target.role, to: role });
    } else if (action === 'disable' || action === 'enable') {
      if (action === 'disable' && losingOwner) throw new HttpError(409, 'At least one active owner must remain');
      db.setDisabled(id, action === 'disable');
      db.deleteSessionsFor(id);
      await audit(ctx, `account.${action}`, id);
    } else if (action === 'reset') {
      const password = temporaryPassword();
      db.setPassword(id, await hashPassword(password), true);
      db.disableTotp(id);
      db.clearFailures(id);
      db.deleteSessionsFor(id);
      await audit(ctx, 'account.reset', id);
      return accountsPage(ctx, { email: target.email, password });
    } else {
      throw new HttpError(404, 'Not found');
    }
    redirect(ctx, '/accounts?m=saved');
  }

  function myAccount(ctx: Ctx, error?: string, status = 200): void {
    const acct = ctx.account!;
    const csrf = csrfField(ctx.session!.csrf);
    const pending = db.pendingTotp(acct.id);
    const sessions = db.sessionsFor(acct.id, nowIso());
    page(
      ctx,
      'My account',
      'account',
      html`<h1>My account</h1>
      ${error ? html`<p class="flash flash--error" role="alert">${error}</p>` : ''}
      <p>${acct.name}, ${acct.email}, role ${acct.role}.</p>
      ${sso
        ? html`<section class="card"><h2>Sign-in</h2><p>Sign-in is handled by Cloudflare Access. Your password and two-factor settings are not used here; manage them with your Access identity provider.</p></section>`
        : html`      <section class="card">
        <h2>Password</h2>
        <form method="post" action="${base}/account/password" class="stack narrow">${csrf}
          <label>Current password <input type="password" name="current" autocomplete="current-password" required></label>
          <label>New password <input type="password" name="next" autocomplete="new-password" minlength="12" required></label>
          <label>New password again <input type="password" name="again" autocomplete="new-password" minlength="12" required></label>
          <button type="submit">Change password</button>
        </form>
      </section>
      <section class="card">
        <h2>Two-factor sign-in</h2>
        ${acct.totpSecret
          ? html`<p>On. You enter a code from your authenticator app after your password.</p>
            ${acct.role === 'owner'
              ? html`<p class="muted">Owners must keep two-factor sign-in on.</p>`
              : html`<form method="post" action="${base}/account/2fa/off" class="stack narrow">${csrf}
                <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
                <button type="submit">Turn off</button></form>`}`
          : pending
            ? html`<ol>
                <li>Open an authenticator app (1Password, Bitwarden, Google Authenticator, Aegis).</li>
                <li>Add an account by entering this key: <code class="secret">${pending.replace(/(.{4})/g, '$1 ').trim()}</code>
                  <br><a href="${otpauthUri(pending, acct.email, options.operatorName)}">or open it in an authenticator on this device</a></li>
                <li>Enter the 6-digit code it shows.</li>
              </ol>
              <form method="post" action="${base}/account/2fa/confirm" class="stack narrow">${csrf}
                <label>Code <input name="code" inputmode="numeric" autocomplete="one-time-code" required></label>
                <button type="submit">Turn on</button>
              </form>`
            : html`<p>Off. ${acct.role === 'owner' ? 'Owners must turn it on.' : 'Recommended.'}</p>
              <form method="post" action="${base}/account/2fa/start" class="inline">${csrf}<button type="submit">Set up two-factor sign-in</button></form>`}
      </section>`}
      <section class="card">
        <h2>Where you are signed in</h2>
        <div class="table-wrap"><table>
          <thead><tr><th>Since</th><th>Last active</th><th>IP</th><th>Browser</th><th></th></tr></thead>
          <tbody>${sessions.map((s) => html`<tr>
            <td>${shortDate(s.createdAt)}</td><td>${shortDate(s.lastSeenAt)}</td><td>${s.ip}</td><td>${s.userAgent}</td>
            <td>${s.id === ctx.session!.id ? html`<span class="muted">this browser</span>` : html`<form method="post" action="${base}/account/sessions/${s.id}/revoke" class="inline">${csrf}<button type="submit">Sign out</button></form>`}</td>
          </tr>`)}</tbody>
        </table></div>
      </section>`,
      status,
    );
  }

  async function myAccountAction(ctx: Ctx, action: string, sessionId?: string): Promise<void> {
    const form = await readForm(ctx);
    checkPost(ctx, form);
    const acct = ctx.account!;
    if (sso && (action === 'password' || action.startsWith('2fa/'))) throw new HttpError(404, 'Not found');
    if (action === 'password') {
      const next = form.get('next') ?? '';
      if (!(await verifyPassword(form.get('current') ?? '', acct.passwordHash))) return myAccount(ctx, 'Your current password is not right.', 400);
      if (next !== form.get('again')) return myAccount(ctx, 'The new passwords do not match.', 400);
      const problem = passwordProblem(next);
      if (problem) return myAccount(ctx, problem, 400);
      db.setPassword(acct.id, await hashPassword(next), false);
      db.deleteSessionsFor(acct.id, ctx.session!.id);
      await audit(ctx, 'account.password', acct.id);
      return redirect(ctx, '/account?m=password');
    }
    if (action === '2fa/start') {
      db.setPendingTotp(acct.id, newTotpSecret());
      return redirect(ctx, '/account');
    }
    if (action === '2fa/confirm') {
      const pending = db.pendingTotp(acct.id);
      const step = pending ? verifyTotp(pending, form.get('code') ?? '', options.now().getTime(), null) : null;
      if (!pending || step === null) return myAccount(ctx, 'That code did not work. Check the key and your device clock.', 400);
      db.enableTotp(acct.id, pending, step);
      await audit(ctx, 'account.2fa.on', acct.id);
      return redirect(ctx, '/account?m=totp');
    }
    if (action === '2fa/off') {
      if (acct.role === 'owner') throw new HttpError(409, 'Owners must keep two-factor sign-in on');
      if (!(await verifyPassword(form.get('password') ?? '', acct.passwordHash))) return myAccount(ctx, 'Your password is not right.', 400);
      db.disableTotp(acct.id);
      await audit(ctx, 'account.2fa.off', acct.id);
      return redirect(ctx, '/account?m=totpoff');
    }
    if (action === 'revoke' && sessionId) {
      const mine = db.sessionsFor(acct.id, nowIso()).some((s) => s.id === sessionId);
      if (!mine) throw new HttpError(404, 'No such session');
      db.deleteSession(sessionId);
      await audit(ctx, 'account.session.revoke', acct.id, { session: sessionId });
      return redirect(ctx, '/account?m=revoked');
    }
    throw new HttpError(404, 'Not found');
  }

  function signInsPage(ctx: Ctx): void {
    const all = ctx.account!.role === 'owner';
    const rows = db.signIns(all ? null : ctx.account!.id);
    page(
      ctx,
      'Sign-ins',
      'sign-ins',
      html`<h1>${all ? 'Sign-in history' : 'Your sign-in history'}</h1>
      <p class="muted">The latest 200 attempts, successful or not.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>When</th><th>Email</th><th>Result</th><th>IP</th><th>Browser</th></tr></thead>
        <tbody>${rows.map((row) => html`<tr class="${row.result === 'ok' ? '' : 'row-warn'}"><td>${shortDate(row.at)}</td><td>${row.email}</td><td>${row.result}</td><td>${row.ip}</td><td>${row.userAgent}</td></tr>`)}</tbody>
      </table></div>`,
    );
  }

  function auditPage(ctx: Ctx): void {
    need(ctx, 'owner');
    const entries = db.auditEntries(200);
    page(
      ctx,
      'Audit log',
      'audit',
      html`<h1>Audit log</h1>
      <p class="muted">Every change made in this dashboard, newest first. Entries are hash-chained and sealed with the same key as signed records. <a href="${base}/audit.jsonl">Export the full log</a> and check it with <code>sealform verify-chain</code>.</p>
      <div class="table-wrap"><table>
        <thead><tr><th>When</th><th>Who</th><th>Action</th><th>Target</th><th>Details</th></tr></thead>
        <tbody>${entries.map((entry) => html`<tr><td>${shortDate(entry.at)}</td><td>${entry.actor === 'system' ? 'system' : entry.actor.email}</td><td>${entry.action}</td><td>${entry.target}</td><td><code>${JSON.stringify(entry.details)}</code></td></tr>`)}</tbody>
      </table></div>`,
    );
  }

  // Routing --------------------------------------------------------------------------------------

  async function route(req: IncomingMessage, res: ServerResponse, ip: string): Promise<boolean> {
    const url = new URL(req.url ?? '/', options.origin);
    if (url.pathname !== base && !url.pathname.startsWith(`${base}/`)) return false;
    const path = url.pathname.slice(base.length) || '/';
    const ctx: Ctx = { req, res, url, path, ip };
    const method = req.method ?? 'GET';

    try {
      if (path === '/admin.css') {
        css ??= await readFile(cssPath, 'utf8').catch(() => '');
        res.writeHead(200, { 'content-type': 'text/css; charset=utf-8', 'cache-control': 'public, max-age=300', 'x-content-type-options': 'nosniff' });
        res.end(css);
        return true;
      }
      if (sso) {
        // Every request must carry a valid Access token, and the session must belong to that person.
        const identity = await sso.verify(accessToken(req.headers));
        if (!identity) throw new HttpError(403, 'This dashboard is only reachable through Cloudflare Access. Open it from its normal address and sign in there.');
        if (!loadSession(ctx, 'active') || ctx.account!.email !== identity.email) {
          if (ctx.session) db.deleteSession(ctx.session.id);
          delete ctx.session;
          delete ctx.account;
          ssoSignIn(ctx, identity);
        }
      } else {
        // The dashboard's own address is the sign-in: /login when adminPath is "/login". The code
        // step is <adminPath>/2fa.
        if (path === '/' && method === 'POST') {
          await login(ctx);
          return true;
        }
        if (path === '/2fa') {
          await twoFactor(ctx);
          return true;
        }
        // The earlier <adminPath>/login addresses are deleted, not redirected.
        if (path === '/login' || path === '/login/2fa') throw new HttpError(404, 'Not found');

        if (!loadSession(ctx, 'active')) {
          if (method === 'GET' && path === '/') loginPage(ctx);
          else if (method === 'GET') redirect(ctx, '/');
          else throw new HttpError(401, 'Sign in again');
          return true;
        }
      }

      if (path === '/logout' && method === 'POST') {
        const form = await readForm(ctx);
        checkPost(ctx, form);
        db.deleteSession(ctx.session!.id);
        if (sso) {
          // Ending only the dashboard session would sign straight back in; end the Access session too.
          res.writeHead(303, { ...securityHeaders, location: sso.logoutUrl, 'set-cookie': cookie('', 0) });
          res.end();
        } else {
          redirect(ctx, '/', cookie('', 0));
        }
        return true;
      }

      const acct = ctx.account!;
      const onAccountPage = path === '/account' || path.startsWith('/account/');
      if (!sso && acct.mustChangePassword && !(path === '/account' || path === '/account/password')) {
        redirect(ctx, '/account?m=mustchange');
        return true;
      }
      if (!sso && acct.role === 'owner' && !acct.totpSecret && !onAccountPage) {
        redirect(ctx, '/account?m=need2fa');
        return true;
      }

      const parts = path.split('/').filter(Boolean);
      if (method === 'GET') {
        if (path === '/') overview(ctx);
        else if (path === '/verify') await verifyAll(ctx);
        else if (path === '/submissions') submissions(ctx);
        else if (path === '/submissions.csv') submissionsCsv(ctx);
        else if (parts[0] === 'submissions' && parts.length === 2) await submission(ctx, parts[1]!);
        else if (parts[0] === 'submissions' && parts.length === 3 && ['pdf', 'record.json', 'signature.png'].includes(parts[2]!)) await submissionFile(ctx, parts[1]!, parts[2]!);
        else if (path === '/documents') documentsPage(ctx);
        else if (path === '/contracts') contractsPage(ctx);
        else if (path === '/site') await sitePage(ctx);
        else if (parts[0] === 'contracts' && parts.length === 2) contractPage(ctx, db.envelope(parts[1]!) ?? (() => { throw new HttpError(404, 'No such contract'); })());
        else if (parts[0] === 'documents' && parts.length === 3) documentPage(ctx, findDoc(parts[1]!, parts[2]!));
        else if (path === '/accounts') accountsPage(ctx);
        else if (path === '/account') myAccount(ctx);
        else if (path === '/sign-ins') signInsPage(ctx);
        else if (path === '/audit') auditPage(ctx);
        else if (path === '/audit.jsonl') {
          need(ctx, 'owner');
          download(ctx, 'application/x-ndjson', `audit-${nowIso().slice(0, 10)}.jsonl`, db.auditEntries().map((e) => JSON.stringify(e)).join('\n') + '\n');
        } else throw new HttpError(404, 'Not found');
      } else if (method === 'POST') {
        if (parts[0] === 'submissions' && parts.length === 3 && parts[2] === 'status') await setStatus(ctx, parts[1]!);
        else if (parts[0] === 'submissions' && parts.length === 3 && parts[2] === 'hold') await setHold(ctx, parts[1]!);
        else if (parts[0] === 'documents' && parts.length === 4 && parts[3] === 'status') await setDocumentStatus(ctx, findDoc(parts[1]!, parts[2]!));
        else if (path === '/contracts') await createContract(ctx);
        else if (parts[0] === 'site' && parts.length >= 2) await siteAction(ctx, parts.slice(1).join('/'));
        else if (parts[0] === 'contracts' && parts.length === 3) await contractAction(ctx, parts[1]!, parts[2]!);
        else if (path === '/accounts') await accountAction(ctx, undefined, 'create');
        else if (parts[0] === 'accounts' && parts.length === 3) await accountAction(ctx, parts[1]!, parts[2]!);
        else if (parts[0] === 'account' && parts[1] === 'sessions' && parts[3] === 'revoke') await myAccountAction(ctx, 'revoke', parts[2]!);
        else if (parts[0] === 'account' && parts.length >= 2) await myAccountAction(ctx, parts.slice(1).join('/'));
        else throw new HttpError(404, 'Not found');
      } else {
        throw new HttpError(405, 'Method not allowed');
      }
    } catch (error) {
      if (res.headersSent) throw error;
      const status = error instanceof HttpError ? error.status : 500;
      if (!(error instanceof HttpError)) options.log(`admin error on ${method} ${path}: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
      const message = error instanceof HttpError ? error.message : 'Something went wrong. Nothing was changed.';
      page(ctx, 'Problem', '', html`<section class="card narrow"><h1>${message}</h1><p><a href="${base}/">Back to the dashboard</a></p></section>`, status);
    }
    return true;
  }

  function findDoc(id: string, version: string): LoadedDocument {
    const doc = documents.get(id, version);
    if (!doc) throw new HttpError(404, 'No such document');
    return doc;
  }

  /** True when the request carries a valid, active dashboard session. Used for private site pages. */
  function isSignedIn(req: IncomingMessage): boolean {
    const token = readCookie(req);
    if (!token) return false;
    const session = db.sessionByToken(hashToken(token));
    if (!session || session.stage !== 'active' || session.expiresAt < nowIso()) return false;
    if (options.now().getTime() - Date.parse(session.lastSeenAt) > IDLE_TTL) return false;
    const account = db.account(session.accountId);
    return !!account && !account.disabled;
  }

  return { route, db, isSignedIn };
}

function stripUndefined<T extends Record<string, unknown>>(value: T): { [K in keyof T]: Exclude<T[K], undefined> } {
  return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as { [K in keyof T]: Exclude<T[K], undefined> };
}

function withPage(query: URLSearchParams, pageNo: number): string {
  const next = new URLSearchParams(query);
  next.set('page', String(pageNo));
  return next.toString();
}

/** Quotes a CSV cell and defuses spreadsheet formulas (=, +, -, @ at the start). */
function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? '' : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function formatValue(value: unknown): string {
  if (value === undefined || value === '') return '(blank)';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}

function temporaryPassword(): string {
  // Five groups of five from an unambiguous alphabet: about 120 bits.
  const alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
  const bytes = newToken();
  let out = '';
  for (let i = 0; i < 25; i++) out += alphabet[bytes.charCodeAt(i) % alphabet.length];
  return out.match(/.{5}/g)!.join('-');
}

export { hashPassword, passwordProblem, verifyTotp, hotp, totpCounter } from './auth.ts';
export { AdminStore, ROLES, type Role } from './db.ts';

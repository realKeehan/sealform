import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, KEYSET_FORMAT, toBase64Url, utf8, verifyChain, type KeySet, type SealformRecord } from '../src/core/index.ts';
import { CloudflareAccess, createSealform, hashPassword } from '../src/server/index.ts';
import { base32Encode, hotp, newTotpSecret, verifyTotp } from '../src/server/admin/auth.ts';

const FIXTURES = fileURLToPath(new URL('./fixtures/documents', import.meta.url));
const ORIGIN = 'https://sign.example.com';
const BASE = '/_sf';
const PASSWORD = 'correct horse battery staple';

let dir = '';
let keyset: KeySet;
let privateFile: Awaited<ReturnType<typeof generateKeyPair>>['privateFile'];
let clock = Date.parse('2026-11-02T18:00:00.000Z');

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sealform-admin-'));
  const pair = await generateKeyPair('admin-test');
  privateFile = pair.privateFile;
  keyset = { format: KEYSET_FORMAT, keys: [pair.publicEntry] };
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

// RFC 6238 appendix B, SHA-1 secret "12345678901234567890", last six digits of the 8-digit values.
test('TOTP matches the RFC 6238 test vectors', () => {
  const secret = base32Encode(Buffer.from('12345678901234567890'));
  assert.equal(secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
  assert.equal(hotp(secret, Math.floor(59 / 30)), '287082');
  assert.equal(hotp(secret, Math.floor(1111111109 / 30)), '081804');
  assert.equal(hotp(secret, Math.floor(2000000000 / 30)), '279037');
});

test('a TOTP code is accepted once and not replayed', () => {
  const secret = newTotpSecret();
  const now = 1_700_000_000_000;
  const code = hotp(secret, Math.floor(now / 30000));
  const step = verifyTotp(secret, code, now, null);
  assert.notEqual(step, null);
  assert.equal(verifyTotp(secret, code, now, step), null, 'same code twice');
  assert.equal(verifyTotp(secret, '000000', now, null), null);
  assert.equal(verifyTotp(secret, 'abcdef', now, null), null);
  const old = hotp(secret, Math.floor(now / 30000) - 3);
  assert.equal(verifyTotp(secret, old, now, null), null, 'three steps old');
});

async function start(name: string, overrides: Partial<Parameters<typeof createSealform>[0]> = {}) {
  const sealform = await createSealform({
    dataDir: join(dir, name),
    documentsDir: FIXTURES,
    sealingKey: privateFile,
    keySet: keyset,
    publicOrigin: ORIGIN,
    operator: { name: 'Example Studio', email: 'legal@example.com' },
    adminPath: BASE,
    log: () => {},
    now: () => new Date(clock),
    limits: { signPerWindow: 1000 },
    ...overrides,
  });
  const server = createServer(sealform.handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const admin = sealform.admin!;
  const owner = admin.createAccount({ email: 'owner@example.com', name: 'Olive Owner', role: 'owner', passwordHash: await hashPassword(PASSWORD), mustChangePassword: false, now: new Date(clock).toISOString() });
  return {
    sealform,
    admin,
    owner,
    url,
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      sealform.close();
    },
  };
}

type App = Awaited<ReturnType<typeof start>>;

/** A tiny browser: keeps cookies, sends same-origin headers, never follows redirects. */
class Browser {
  cookie = '';
  readonly app: App;
  constructor(app: App) {
    this.app = app;
  }

  async get(path: string, headers: Record<string, string> = {}) {
    return this.send('GET', path, undefined, headers);
  }

  async post(path: string, form: Record<string, string>, headers: Record<string, string> = {}) {
    return this.send('POST', path, new URLSearchParams(form).toString(), headers);
  }

  private async send(method: string, path: string, body?: string, headers: Record<string, string> = {}) {
    const response = await fetch(`${this.app.url}${BASE}${path}`, {
      method,
      redirect: 'manual',
      headers: { origin: ORIGIN, 'user-agent': 'admin-test', ...(this.cookie ? { cookie: this.cookie } : {}), ...(body ? { 'content-type': 'application/x-www-form-urlencoded' } : {}), ...headers },
      ...(body ? { body } : {}),
    });
    for (const set of response.headers.getSetCookie()) {
      const pair = set.split(';')[0]!;
      this.cookie = pair.endsWith('=') ? '' : pair;
    }
    const text = response.status >= 300 && response.status < 400 ? '' : await response.text();
    return { status: response.status, location: response.headers.get('location'), text, headers: response.headers };
  }

  async csrf(path = '/account'): Promise<string> {
    const page = await this.get(path);
    const match = /name="csrf" value="([^"]+)"/.exec(page.text);
    assert.ok(match, `no csrf field on ${path} (status ${page.status})`);
    return match[1]!;
  }

  async login(email: string, password = PASSWORD, code?: string) {
    const first = await this.post('/login', { email, password });
    if (code === undefined) return first;
    assert.equal(first.location, `${BASE}/login/2fa`);
    return this.post('/login/2fa', { code });
  }
}

test('the dashboard is closed until you sign in, and the login page leaks nothing', async () => {
  const app = await start('closed');
  try {
    const browser = new Browser(app);
    const home = await browser.get('/');
    assert.equal(home.status, 303);
    assert.equal(home.location, `${BASE}/login`);
    assert.equal((await browser.get('/submissions')).status, 303);
    const login = await browser.get('/login');
    assert.equal(login.status, 200);
    assert.match(login.headers.get('content-security-policy')!, /default-src 'none'/);
    assert.equal(login.headers.get('x-frame-options'), 'DENY');
    assert.match(login.headers.get('x-robots-tag')!, /noindex/);
    assert.equal((await browser.post('/logout', {})).status, 401);
  } finally {
    await app.stop();
  }
});

test('wrong passwords and unknown emails get the same answer, and five failures lock the account', async () => {
  const app = await start('lockout');
  try {
    const browser = new Browser(app);
    const unknown = await browser.post('/login', { email: 'nobody@example.com', password: 'whatever whatever' });
    const wrong = await browser.post('/login', { email: 'owner@example.com', password: 'not the password' });
    assert.equal(unknown.status, 401);
    assert.equal(wrong.status, 401);
    assert.equal(unknown.text.match(/do not match an account/)?.[0], wrong.text.match(/do not match an account/)?.[0]);

    // One failure so far; the fifth locks the account.
    for (let i = 0; i < 4; i++) await browser.post('/login', { email: 'owner@example.com', password: 'not the password' });
    const locked = await browser.post('/login', { email: 'owner@example.com', password: PASSWORD });
    assert.equal(locked.status, 423, 'correct password refused while locked');

    clock += 16 * 60_000;
    const after = await browser.post('/login', { email: 'owner@example.com', password: PASSWORD });
    assert.equal(after.status, 303);

    const results = app.admin.signIns(null).map((row) => row.result);
    assert.ok(results.includes('unknown-account'));
    assert.ok(results.includes('bad-password-locked'));
    assert.ok(results.includes('locked'));
    assert.ok(results.includes('ok'));
  } finally {
    await app.stop();
  }
});

test('an owner is forced to set up two-factor, and then must supply a fresh code to sign in', async () => {
  const app = await start('2fa');
  try {
    const browser = new Browser(app);
    assert.equal((await browser.login('owner@example.com')).location, `${BASE}/`);

    const gate = await browser.get('/submissions');
    assert.equal(gate.location, `${BASE}/account?m=need2fa`);

    const csrf = await browser.csrf();
    await browser.post('/account/2fa/start', { csrf });
    const secret = app.admin.pendingTotp(app.owner.id)!;
    assert.ok(secret);
    const wrong = await browser.post('/account/2fa/confirm', { csrf, code: '000000' });
    assert.equal(wrong.status, 400);

    clock += 30_000;
    const code = hotp(secret, Math.floor(clock / 30000));
    assert.equal((await browser.post('/account/2fa/confirm', { csrf, code })).location, `${BASE}/account?m=totp`);
    assert.equal((await browser.get('/submissions')).status, 200, 'dashboard opens once two-factor is on');

    const owners2fa = await browser.post('/account/2fa/off', { csrf, password: PASSWORD });
    assert.equal(owners2fa.status, 409, 'owners cannot turn it off');

    // A new sign-in now needs a code, and the code just used cannot be used again.
    const second = new Browser(app);
    const step1 = await second.post('/login', { email: 'owner@example.com', password: PASSWORD });
    assert.equal(step1.location, `${BASE}/login/2fa`);
    assert.equal((await second.get('/submissions')).status, 303, 'password alone is not enough');
    const pendingPage = await second.get('/login/2fa');
    assert.equal(pendingPage.status, 200);
    assert.doesNotMatch(pendingPage.text, /Sign out|href="\/_sf\/submissions"/, 'no admin chrome before the code is entered');
    const replay = await second.post('/login/2fa', { code });
    assert.equal(replay.status, 401, 'same code is refused');
    clock += 30_000;
    const fresh = hotp(secret, Math.floor(clock / 30000));
    const ok = await second.post('/login/2fa', { code: fresh });
    assert.equal(ok.location, `${BASE}/`);
    assert.equal((await second.get('/submissions')).status, 200);
  } finally {
    await app.stop();
  }
});

async function ownerSession(app: App): Promise<Browser> {
  const browser = new Browser(app);
  await browser.login('owner@example.com');
  const csrf = await browser.csrf();
  await browser.post('/account/2fa/start', { csrf });
  clock += 30_000;
  await browser.post('/account/2fa/confirm', { csrf, code: hotp(app.admin.pendingTotp(app.owner.id)!, Math.floor(clock / 30000)) });
  return browser;
}

test('state changes need the CSRF token and a same-origin request', async () => {
  const app = await start('csrf');
  try {
    const browser = await ownerSession(app);
    const csrf = await browser.csrf();
    const noToken = await browser.post('/accounts', { name: 'X', email: 'x@example.com', role: 'reviewer' });
    assert.equal(noToken.status, 403);
    const crossSite = await browser.post('/accounts', { csrf, name: 'X', email: 'x@example.com', role: 'reviewer' }, { origin: 'https://evil.example.net' });
    assert.equal(crossSite.status, 403);
    const noOrigin = await fetch(`${app.url}${BASE}/accounts`, { method: 'POST', redirect: 'manual', headers: { cookie: browser.cookie, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ csrf, name: 'X', email: 'x@example.com', role: 'reviewer' }) });
    assert.equal(noOrigin.status, 403, 'a POST with no Origin or Referer is refused');
    assert.equal(app.admin.accountByEmail('x@example.com'), undefined);
  } finally {
    await app.stop();
  }
});

test('roles gate what each account can see and do', async () => {
  const app = await start('roles');
  try {
    const owner = await ownerSession(app);
    const csrf = await owner.csrf('/accounts');
    const created = await owner.post('/accounts', { csrf, name: 'Rae Reviewer', email: 'rae@example.com', role: 'reviewer' });
    assert.equal(created.status, 200);
    const temp = /class="secret">([a-z0-9-]+)</.exec(created.text)![1]!;
    assert.match(temp, /^[a-z0-9]{5}(-[a-z0-9]{5}){4}$/);
    assert.equal(app.admin.accountByEmail('rae@example.com')!.mustChangePassword, true);

    const reviewer = new Browser(app);
    await reviewer.login('rae@example.com', temp);
    assert.equal((await reviewer.get('/submissions')).location, `${BASE}/account?m=mustchange`, 'forced to change password first');
    const rcsrf = await reviewer.csrf();
    const changed = await reviewer.post('/account/password', { csrf: rcsrf, current: temp, next: 'a brand new passphrase', again: 'a brand new passphrase' });
    assert.equal(changed.location, `${BASE}/account?m=password`);

    assert.equal((await reviewer.get('/submissions')).status, 200);
    assert.equal((await reviewer.get('/accounts')).status, 403);
    assert.equal((await reviewer.get('/audit')).status, 403);
    assert.equal((await reviewer.get('/documents')).status, 403);
    assert.equal((await reviewer.get('/submissions.csv')).status, 403);
    assert.doesNotMatch((await reviewer.get('/')).text, /href="\/_sf\/accounts"|href="\/_sf\/audit"/);
    const forged = await reviewer.post('/accounts', { csrf: await reviewer.csrf(), name: 'Evil', email: 'evil@example.com', role: 'owner' });
    assert.equal(forged.status, 403);
    assert.equal(app.admin.accountByEmail('evil@example.com'), undefined);
  } finally {
    await app.stop();
  }
});

test('the last active owner cannot be demoted or disabled, and disabling signs sessions out', async () => {
  const app = await start('owners');
  try {
    const owner = await ownerSession(app);
    const csrf = await owner.csrf('/accounts');
    const second = app.admin.createAccount({ email: 'co@example.com', name: 'Co Owner', role: 'owner', passwordHash: await hashPassword(PASSWORD), mustChangePassword: false, now: new Date(clock).toISOString() });

    const demote = await owner.post(`/accounts/${second.id}/role`, { csrf, role: 'admin' });
    assert.equal(demote.location, `${BASE}/accounts?m=saved`, 'two owners: demoting one is fine');
    assert.equal(app.admin.account(second.id)!.role, 'admin');

    const selfDisable = await owner.post(`/accounts/${app.owner.id}/disable`, { csrf });
    assert.equal(selfDisable.status, 400, 'cannot act on your own account here');

    const admin = new Browser(app);
    await admin.login('co@example.com');
    assert.equal((await admin.get('/documents')).status, 200);
    await owner.post(`/accounts/${second.id}/disable`, { csrf });
    assert.equal((await admin.get('/documents')).status, 303, 'disabled account loses its session');
    assert.equal((await new Browser(app).login('co@example.com')).status, 401);
  } finally {
    await app.stop();
  }
});

function png(): string {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(body));
    return Buffer.concat([len, body, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(4, 0);
  ihdr.writeUInt32BE(2, 4);
  ihdr.set([8, 6, 0, 0, 0], 8);
  const rows = Buffer.concat([0, 1].map(() => Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0x40)])));
  return `data:image/png;base64,${Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]).toString('base64')}`;
}

async function sign(app: App, name: string, email: string) {
  const open = (await (await fetch(`${app.url}/sealform/api/documents/example-agreement?lang=en`)).json()) as {
    document: { id: string; version: string; lang: string; sha256: string; manifestSha256: string };
    session: { id: string };
  };
  const response = await fetch(`${app.url}/sealform/api/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'signer' },
    body: JSON.stringify({
      sessionId: open.session.id,
      documentId: open.document.id,
      version: open.document.version,
      lang: open.document.lang,
      textSha256: open.document.sha256,
      manifestSha256: open.document.manifestSha256,
      profileSha256: ((await (await fetch(`${app.url}/sealform/api/profile/DE`)).json()) as { sha256: string }).sha256,
      fields: { legalName: name, email, country: 'DE', adult: true },
      consents: { esign: true, acceptVersion: true },
      signature: { typedName: name, vector: [{ points: Array.from({ length: 20 }, (_, i) => ({ x: i * 5, y: 20 + Math.sin(i / 3) * 10, time: i * 20 })) }], png: png() },
      client: {},
    }),
  });
  assert.equal(response.status, 201, await response.clone().text());
  return ((await response.json()) as { id: string }).id;
}

test('submissions are listed, escaped, reviewable, exportable and verifiable', async () => {
  const app = await start('submissions');
  try {
    const hostile = '<script>alert(1)</script> "x" & Co';
    const first = await sign(app, hostile, 'a@example.com');
    const second = await sign(app, '=HYPERLINK("http://evil","click")', 'b@example.com');
    const owner = await ownerSession(app);

    const list = await owner.get('/submissions');
    assert.equal(list.status, 200);
    assert.doesNotMatch(list.text, /<script>alert/);
    assert.match(list.text, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(list.text, /2 matching/);

    const filtered = await owner.get('/submissions?q=b%40example');
    assert.match(filtered.text, /1 matching/);
    const sqlish = await owner.get(`/submissions?q=${encodeURIComponent("' OR 1=1 --")}`);
    assert.match(sqlish.text, /0 matching/);

    const detail = await owner.get(`/submissions/${first}`);
    assert.equal(detail.status, 200);
    assert.match(detail.text, /Verified: content, hash and seal all check out/);
    assert.doesNotMatch(detail.text, /<script>alert/);
    assert.equal((await owner.get(`/submissions/${first}/pdf`)).status, 200);
    assert.equal((await owner.get(`/submissions/${first}/signature.png`)).headers.get('content-type'), 'image/png');
    assert.equal((await owner.get('/submissions/sf_NOPE')).status, 404);
    assert.equal((await owner.get('/submissions/..%2F..%2Fetc/pdf')).status, 404);

    const csrf = await owner.csrf(`/submissions/${first}`);
    assert.equal((await owner.post(`/submissions/${first}/status`, { csrf, status: 'accepted' })).location, `${BASE}/submissions/${first}?m=saved`);
    assert.equal((await owner.post(`/submissions/${first}/status`, { csrf, status: 'bogus' })).status, 400);
    assert.equal(app.sealform.store.summary(first)!.applicationStatus, 'accepted');

    assert.equal((await owner.post(`/submissions/${second}/hold`, { csrf, hold: 'on' })).location, `${BASE}/submissions/${second}?m=saved`);
    assert.equal(app.sealform.store.summary(second)!.hold, true);

    const csv = await owner.get('/submissions.csv');
    assert.equal(csv.status, 200);
    assert.match(csv.headers.get('content-disposition')!, /attachment/);
    assert.match(csv.text, /'=HYPERLINK/, 'formula is defused');
    assert.doesNotMatch(csv.text, /,=HYPERLINK/);

    const verify = await owner.get('/verify');
    assert.match(verify.text, /Intact: 2 entries/);
  } finally {
    await app.stop();
  }
});

test('every admin change lands in a sealed, verifiable audit chain', async () => {
  const app = await start('audit');
  try {
    const id = await sign(app, 'Ada Example', 'ada@example.com');
    const owner = await ownerSession(app);
    const csrf = await owner.csrf(`/submissions/${id}`);
    await owner.post(`/submissions/${id}/status`, { csrf, status: 'rejected' });
    await owner.post(`/submissions/${id}/hold`, { csrf, hold: 'on' });
    await owner.post('/accounts', { csrf, name: 'Rae', email: 'rae@example.com', role: 'reviewer' });

    const entries = app.admin.auditEntries();
    assert.deepEqual(
      entries.map((e) => e.action),
      ['account.2fa.on', 'submission.status', 'submission.hold', 'account.create'],
    );
    assert.equal(entries[1]!.details.to, 'rejected');
    assert.equal(entries[1]!.actor !== 'system' && entries[1]!.actor.email, 'owner@example.com');
    assert.equal(JSON.stringify(entries).includes('"password'), false, 'no passwords in the log');
    assert.equal(JSON.stringify(entries).includes('scrypt$'), false);

    const result = await verifyChain(entries, keyset);
    assert.equal(result.ok, true, JSON.stringify(result.breaks));

    const tampered = structuredClone(entries);
    tampered[1]!.details = { from: 'pending', to: 'accepted' };
    assert.equal((await verifyChain(tampered, keyset)).ok, false);
    const cut = [entries[0]!, entries[2]!, entries[3]!];
    assert.equal((await verifyChain(cut, keyset)).ok, false);

    const exported = await owner.get('/audit.jsonl');
    assert.equal(exported.text.trim().split('\n').length, 4);
    assert.match((await owner.get('/audit')).text, /submission\.hold/);
  } finally {
    await app.stop();
  }
});

test('publishing a document version closes the previous one, and the status survives a restart', async () => {
  const app = await start('docs');
  try {
    const owner = await ownerSession(app);
    const csrf = await owner.csrf('/documents');
    const list = await owner.get('/documents');
    assert.match(list.text, /Example Participation Agreement/);

    const close = await owner.post('/documents/example-agreement/EXAMPLE-1/status', { csrf, status: 'closed' });
    assert.equal(close.location, `${BASE}/documents/example-agreement/EXAMPLE-1?m=saved`);
    const closed = await fetch(`${app.url}/sealform/api/documents/example-agreement`);
    assert.equal(closed.status, 404, 'a closed document is not offered for signing');

    assert.equal((await owner.post('/documents/example-agreement/EXAMPLE-1/status', { csrf, status: 'published' })).status, 303);
    assert.equal((await fetch(`${app.url}/sealform/api/documents/example-agreement`)).status, 200);
    assert.equal((await owner.post('/documents/example-agreement/EXAMPLE-1/status', { csrf, status: 'nonsense' })).status, 400);
    assert.equal((await owner.get('/documents/nope/EXAMPLE-1')).status, 404);

    await owner.post('/documents/example-agreement/EXAMPLE-1/status', { csrf, status: 'closed' });
    const actions = app.admin.auditEntries().filter((e) => e.action === 'document.status').map((e) => e.details.to);
    assert.deepEqual(actions, ['closed', 'published', 'closed']);
  } finally {
    await app.stop();
  }

  // Same data directory, new process: the closed status is restored from the database.
  const again = await createSealform({
    dataDir: join(dir, 'docs'),
    documentsDir: FIXTURES,
    sealingKey: privateFile,
    keySet: keyset,
    publicOrigin: ORIGIN,
    operator: { name: 'Example Studio', email: 'legal@example.com' },
    adminPath: BASE,
    log: () => {},
  });
  try {
    assert.equal(again.documents.current('example-agreement'), undefined);
  } finally {
    again.close();
  }
});

test('changing the password signs out other sessions and logging out ends the session', async () => {
  const app = await start('sessions');
  try {
    const first = await ownerSession(app);
    const other = new Browser(app);
    await other.login('owner@example.com').then(async (step) => {
      assert.equal(step.location, `${BASE}/login/2fa`);
    });
    // Sign in fully on a second browser using a fresh code.
    clock += 30_000;
    const secret = app.admin.account(app.owner.id)!.totpSecret!;
    assert.equal((await other.post('/login/2fa', { code: hotp(secret, Math.floor(clock / 30000)) })).location, `${BASE}/`);
    assert.equal((await other.get('/sign-ins')).status, 200);

    const csrf = await first.csrf();
    const changed = await first.post('/account/password', { csrf, current: PASSWORD, next: 'another long passphrase here', again: 'another long passphrase here' });
    assert.equal(changed.location, `${BASE}/account?m=password`);
    assert.equal((await other.get('/sign-ins')).status, 303, 'other browser was signed out');
    assert.equal((await first.get('/sign-ins')).status, 200, 'this one stays');

    const weak = await first.post('/account/password', { csrf, current: 'another long passphrase here', next: 'short', again: 'short' });
    assert.equal(weak.status, 400);

    await first.post('/logout', { csrf });
    assert.equal((await first.get('/sign-ins')).status, 303);
  } finally {
    await app.stop();
  }
});

test('the signing API still works beside the dashboard, and unknown dashboard paths are 404', async () => {
  const app = await start('coexist');
  try {
    assert.equal((await fetch(`${app.url}/sealform/api/documents/example-agreement`)).status, 200);
    const owner = await ownerSession(app);
    assert.equal((await owner.get('/nope')).status, 404);
    assert.equal((await owner.get('/admin.css')).headers.get('content-type'), 'text/css; charset=utf-8');
    assert.equal((await fetch(`${app.url}/_sfx/login`)).status, 404, 'a path that merely starts with the admin path is not the admin');
  } finally {
    await app.stop();
  }
});

class StubBotCheck {
  readonly name = 'turnstile';
  seen: (string | undefined)[] = [];
  verify(token: string | undefined): Promise<boolean> {
    this.seen.push(token);
    return Promise.resolve(token === 'good-token');
  }
}

test('with Turnstile on, the sign-in page loads the widget and a bot never reaches the password check', async () => {
  const bot = new StubBotCheck();
  const sealform = await createSealform({
    dataDir: join(dir, 'turnstile'),
    documentsDir: FIXTURES,
    sealingKey: privateFile,
    keySet: keyset,
    publicOrigin: ORIGIN,
    operator: { name: 'Example Studio', email: 'legal@example.com' },
    adminPath: BASE,
    botCheck: bot,
    adminTurnstileSiteKey: '1x00000000000000000000AA',
    log: () => {},
    now: () => new Date(clock),
  });
  const server = createServer(sealform.handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const admin = sealform.admin!;
  admin.createAccount({ email: 'owner@example.com', name: 'Olive', role: 'owner', passwordHash: await hashPassword(PASSWORD), mustChangePassword: false, now: new Date(clock).toISOString() });
  const app = { sealform, admin, url, owner: admin.accountByEmail('owner@example.com')!, stop: async () => {} } as unknown as App;
  try {
    const browser = new Browser(app);
    const page = await browser.get('/login');
    assert.match(page.text, /class="cf-turnstile" data-sitekey="1x00000000000000000000AA"/);
    assert.match(page.text, /challenges\.cloudflare\.com\/turnstile\/v0\/api\.js/);
    const csp = page.headers.get('content-security-policy')!;
    assert.match(csp, /script-src https:\/\/challenges\.cloudflare\.com/);
    assert.match(csp, /frame-src https:\/\/challenges\.cloudflare\.com/);

    // Other dashboard pages keep the strict policy with no script source at all.
    const twoFa = await browser.get('/login/2fa');
    assert.equal((twoFa.headers.get('content-security-policy') ?? '').includes('script-src'), false);

    // No token, or a bad one: refused before the password is looked at, and logged.
    const missing = await browser.post('/login', { email: 'owner@example.com', password: PASSWORD });
    assert.equal(missing.status, 403);
    assert.match(missing.text, /bot check did not pass/);
    const bad = await browser.post('/login', { email: 'owner@example.com', password: PASSWORD, 'cf-turnstile-response': 'bad-token' });
    assert.equal(bad.status, 403);
    assert.equal(browser.cookie, '', 'no session was issued');

    // Bots cannot lock the real account by hammering it.
    for (let i = 0; i < 8; i++) await browser.post('/login', { email: 'owner@example.com', password: 'wrong wrong wrong', 'cf-turnstile-response': 'bad-token' });
    assert.equal(admin.account(app.owner.id)!.failedLogins, 0);
    assert.equal(admin.signIns(null).every((row) => row.result === 'bot-check-failed'), true);

    // A passing token reaches the normal password check.
    const wrongPassword = await browser.post('/login', { email: 'owner@example.com', password: 'wrong wrong wrong', 'cf-turnstile-response': 'good-token' });
    assert.equal(wrongPassword.status, 401);
    const ok = await browser.post('/login', { email: 'owner@example.com', password: PASSWORD, 'cf-turnstile-response': 'good-token' });
    assert.equal(ok.status, 303);
    assert.ok(bot.seen.includes('good-token'));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    sealform.close();
  }
});

test('Turnstile settings that would leave the dashboard unprotected or unverifiable are refused at startup', async () => {
  const base = { documentsDir: FIXTURES, sealingKey: privateFile, keySet: keyset, publicOrigin: ORIGIN, operator: { name: 'E', email: 'e@example.com' }, log: () => {} };
  const { TurnstileCheck } = await import('../src/server/index.ts');
  await assert.rejects(createSealform({ ...base, dataDir: join(dir, 'ts-a'), adminPath: BASE, botCheck: new TurnstileCheck('secret') }), /adminTurnstileSiteKey is required/);
  await assert.rejects(createSealform({ ...base, dataDir: join(dir, 'ts-b'), adminPath: BASE, adminTurnstileSiteKey: 'key' }), /botCheck is not a TurnstileCheck/);
  const ok = await createSealform({ ...base, dataDir: join(dir, 'ts-c'), adminPath: BASE, botCheck: new TurnstileCheck('secret'), adminTurnstileSiteKey: 'key' });
  ok.close();
});


// Cloudflare Access ---------------------------------------------------------------------------------

const TEAM = 'example-team.cloudflareaccess.com';
const AUD = 'a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2';
const KID = 'access-key-1';

async function rsaKey() {
  return (await crypto.subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
}

const accessKeys = await rsaKey();
const otherKeys = await rsaKey();
const accessJwk = { ...(await crypto.subtle.exportKey('jwk', accessKeys.publicKey)), kid: KID, alg: 'RS256', use: 'sig' };

function certsFetch() {
  const stub = {
    calls: 0,
    fetch: (async (url: string | URL | Request) => {
      stub.calls++;
      assert.equal(String(url), `https://${TEAM}/cdn-cgi/access/certs`);
      return new Response(JSON.stringify({ keys: [accessJwk] }), { status: 200 });
    }) as typeof fetch,
  };
  return stub;
}

function b64(value: unknown): string {
  return toBase64Url(utf8(JSON.stringify(value)));
}

async function jwt(
  claims: Record<string, unknown> = {},
  options: { key?: CryptoKey; header?: Record<string, unknown>; tamper?: boolean } = {},
): Promise<string> {
  const nowS = Math.floor(clock / 1000);
  const payload = { iss: `https://${TEAM}`, aud: [AUD], email: 'owner@example.com', sub: 'user-1', iat: nowS, nbf: nowS, exp: nowS + 3600, ...claims };
  const header = { alg: 'RS256', kid: KID, typ: 'JWT', ...options.header };
  const signed = `${b64(header)}.${b64(payload)}`;
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'RSASSA-PKCS1-v1_5' }, options.key ?? accessKeys.privateKey, utf8(signed)));
  const token = `${signed}.${toBase64Url(sig)}`;
  if (options.tamper) {
    const [h, , s] = token.split('.');
    return `${h}.${b64({ ...payload, email: 'attacker@example.com' })}.${s}`;
  }
  return token;
}

test('Access tokens are accepted only when signature, issuer, audience, expiry and email all check out', async () => {
  const stub = certsFetch();
  const access = new CloudflareAccess({ teamDomain: TEAM, audience: AUD, fetch: stub.fetch }, () => clock);
  const good = await access.verify(await jwt());
  assert.equal(good?.email, 'owner@example.com');
  assert.equal((await access.verify(await jwt({ aud: AUD, email: 'Ada@Example.COM' })))?.email, 'ada@example.com', 'string aud accepted, email lowercased');

  const bad: [string, string][] = [
    ['wrong audience', await jwt({ aud: ['someone-elses-app'] })],
    ['wrong issuer', await jwt({ iss: 'https://evil.cloudflareaccess.com' })],
    ['expired', await jwt({ exp: Math.floor(clock / 1000) - 3600 })],
    ['not yet valid', await jwt({ nbf: Math.floor(clock / 1000) + 3600 })],
    ['no email (service token)', await jwt({ email: undefined })],
    ['not an email', await jwt({ email: 'nope' })],
    ['signed by another key', await jwt({}, { key: otherKeys.privateKey })],
    ['tampered payload', await jwt({}, { tamper: true })],
    ['unknown key id', await jwt({}, { header: { kid: 'other-kid' } })],
    ['alg none', await jwt({}, { header: { alg: 'none' } })],
    ['alg HS256', await jwt({}, { header: { alg: 'HS256' } })],
    ['garbage', 'not.a.jwt'],
    ['empty signature', `${b64({ alg: 'RS256', kid: KID })}.${b64({})}.`],
  ];
  for (const [name, token] of bad) assert.equal(await access.verify(token), null, name);
  assert.equal(await access.verify(undefined), null);
  assert.equal(await access.verify('x'.repeat(9000)), null);
});

test('Access keys are cached, and junk tokens cannot make the server hammer Cloudflare', async () => {
  const stub = certsFetch();
  const access = new CloudflareAccess({ teamDomain: TEAM, audience: AUD, fetch: stub.fetch }, () => clock);
  for (let i = 0; i < 5; i++) await access.verify(await jwt());
  assert.equal(stub.calls, 1, 'keys fetched once');
  const unknown = await jwt({}, { header: { kid: 'rotated' } });
  for (let i = 0; i < 5; i++) await access.verify(unknown);
  assert.equal(stub.calls, 1, 'unknown kid does not refetch within a minute');
  clock += 61_000;
  await access.verify(unknown);
  assert.equal(stub.calls, 2, 'one refetch after a minute');
});

test('Access settings that are wrong fail at startup', async () => {
  assert.throws(() => new CloudflareAccess({ teamDomain: 'example.com', audience: AUD }), /myteam\.cloudflareaccess\.com/);
  assert.throws(() => new CloudflareAccess({ teamDomain: 'evil.com/x.cloudflareaccess.com', audience: AUD }), /myteam/);
  assert.throws(() => new CloudflareAccess({ teamDomain: TEAM, audience: 'short' }), /Application Audience/);
  const base = { documentsDir: FIXTURES, sealingKey: privateFile, keySet: keyset, publicOrigin: ORIGIN, operator: { name: 'E', email: 'e@example.com' }, log: () => {} };
  await assert.rejects(createSealform({ ...base, dataDir: join(dir, 'acc-a'), adminAccess: { teamDomain: TEAM, audience: AUD } }), /adminPath is not/);
  await assert.rejects(createSealform({ ...base, dataDir: join(dir, 'acc-b'), adminPath: BASE, adminTurnstileSiteKey: 'k', adminAccess: { teamDomain: TEAM, audience: AUD } }), /no effect with adminAccess/);
});

test('behind Cloudflare Access the dashboard needs a valid token, signs in by email, and skips passwords', async () => {
  const stub = certsFetch();
  const app = await start('access', { adminAccess: { teamDomain: TEAM, audience: AUD, fetch: stub.fetch } });
  try {
    const browser = new Browser(app);
    const as = async (email: string, claims: Record<string, unknown> = {}) => ({ 'cf-access-jwt-assertion': await jwt({ email, ...claims }) });

    // No token, a forged token, or a token for another app: refused, with nothing about accounts leaked.
    const none = await browser.get('/');
    assert.equal(none.status, 403);
    assert.match(none.text, /only reachable through Cloudflare Access/);
    assert.equal((await browser.get('/', { 'cf-access-jwt-assertion': await jwt({}, { key: otherKeys.privateKey }) })).status, 403);
    assert.equal((await browser.get('/', await as('owner@example.com', { aud: ['other-app'] }))).status, 403);
    assert.equal((await browser.get('/admin.css')).status, 200, 'the stylesheet is public');

    // A real Access identity with a dashboard account signs straight in: no password, no two-factor.
    const home = await browser.get('/', await as('owner@example.com'));
    assert.equal(home.status, 200);
    assert.match(home.text, /Overview/);
    assert.notEqual(browser.cookie, '');
    assert.equal((await browser.get('/submissions', await as('owner@example.com'))).status, 200, 'owner needs no two-factor here');
    assert.equal((await browser.get('/login', await as('owner@example.com'))).location, `${BASE}/`);
    assert.equal((await browser.post('/login', { email: 'owner@example.com', password: PASSWORD }, await as('owner@example.com'))).status, 404, 'password form is gone');

    const results = app.admin.signIns(null).map((row) => row.result);
    assert.deepEqual(results.filter((r) => r.startsWith('access')), ['access-ok'], 'one sign-in logged, not one per request');

    // A real Google identity with no dashboard account is refused.
    const stranger = new Browser(app);
    const refused = await stranger.get('/', await as('stranger@example.com'));
    assert.equal(refused.status, 403);
    assert.match(refused.text, /no active dashboard account/);
    assert.ok(app.admin.signIns(null).some((r) => r.result === 'access-no-account'));
    assert.equal(stranger.cookie, '');

    // Disabled accounts are refused even with a valid Access identity.
    const rae = app.admin.createAccount({ email: 'rae@example.com', name: 'Rae', role: 'reviewer', passwordHash: await hashPassword(PASSWORD), mustChangePassword: true, now: new Date(clock).toISOString() });
    const raeBrowser = new Browser(app);
    assert.equal((await raeBrowser.get('/submissions', await as('rae@example.com'))).status, 200, 'must-change-password is ignored in Access mode');
    assert.equal((await raeBrowser.get('/accounts', await as('rae@example.com'))).status, 403, 'roles still apply');
    app.admin.setDisabled(rae.id, true);
    assert.equal((await raeBrowser.get('/submissions', await as('rae@example.com'))).status, 403);

    // A session cannot be carried to a different identity.
    const swap = new Browser(app);
    await swap.get('/account', await as('owner@example.com'));
    const swapped = await swap.get('/account', await as('co@example.com'));
    assert.equal(swapped.status, 403, 'cookie from one person plus a token for someone without an account');

    // The account page explains where sign-in lives and offers no password or two-factor forms.
    const account = await browser.get('/account', await as('owner@example.com'));
    assert.match(account.text, /handled by Cloudflare Access/);
    assert.doesNotMatch(account.text, /Change password|Set up two-factor/);
    const csrf = /name="csrf" value="([^"]+)"/.exec(account.text)![1]!;
    assert.equal((await browser.post('/account/password', { csrf, current: 'x', next: 'y', again: 'y' }, await as('owner@example.com'))).status, 404);

    // Signing out ends the Access session too, otherwise the next request would sign straight back in.
    const out = await browser.post('/logout', { csrf }, await as('owner@example.com'));
    assert.equal(out.status, 303);
    assert.equal(out.location, `https://${TEAM}/cdn-cgi/access/logout`);
    assert.equal(browser.cookie, '');
  } finally {
    await app.stop();
  }
});

test('with Access on, the public signing API and key set stay open', async () => {
  const stub = certsFetch();
  const app = await start('access-public', { adminAccess: { teamDomain: TEAM, audience: AUD, fetch: stub.fetch } });
  try {
    assert.equal((await fetch(`${app.url}/sealform/api/documents/example-agreement`)).status, 200);
    assert.equal((await fetch(`${app.url}/.well-known/sealform-keys.json`)).status, 200);
    assert.equal((await fetch(`${app.url}${BASE}/`, { redirect: 'manual' })).status, 403);
  } finally {
    await app.stop();
  }
});


// Private contract links ----------------------------------------------------------------------------

function stroke() {
  return Array.from({ length: 20 }, (_, i) => ({ x: i * 5, y: 20 + Math.sin(i / 3) * 10, time: i * 20 }));
}

async function createLink(owner: Browser, fields: Record<string, string> = {}) {
  const csrf = await owner.csrf('/contracts');
  const response = await owner.post('/contracts', { csrf, document: 'partner-contract@PARTNER-1', label: 'Acme services', name: 'Pat Partner', email: 'pat@example.org', days: '14', counter: '1', country: 'DE', ...fields });
  const token = /\/sealform\/c\/([A-Za-z0-9_-]{43})</.exec(response.text)?.[1];
  return { response, token, csrf };
}

async function signLink(app: App, token: string, overrides: Record<string, unknown> = {}, country = 'DE') {
  type Opened = { document?: { id: string; version: string; lang: string; sha256: string; manifestSha256: string }; session?: { id: string } };
  const fetched = (await (await fetch(`${app.url}/sealform/api/envelopes/${token}`)).json()) as Opened;
  // A used, cancelled or expired link has nothing to open; still post to prove signing is refused too.
  const open = {
    document: fetched.document ?? { id: 'partner-contract', version: 'PARTNER-1', lang: 'en', sha256: '0'.repeat(64), manifestSha256: '0'.repeat(64) },
    session: fetched.session ?? { id: 'x'.repeat(32) },
  };
  const profile = (await (await fetch(`${app.url}/sealform/api/profile/${country}`)).json()) as { sha256: string };
  return fetch(`${app.url}/sealform/api/sign`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': 'partner-browser' },
    body: JSON.stringify({
      envelopeToken: token,
      sessionId: open.session.id,
      documentId: open.document.id,
      version: open.document.version,
      lang: open.document.lang,
      textSha256: open.document.sha256,
      manifestSha256: open.document.manifestSha256,
      profileSha256: profile.sha256,
      fields: { legalName: 'Pat Partner', email: 'pat@example.org', country },
      consents: { esign: true, acceptVersion: true },
      signature: { typedName: 'Pat Partner', vector: [{ points: stroke() }], png: png() },
      client: {},
      ...overrides,
    }),
  });
}

test('a private link is created once, signs exactly once, and is countersigned from the dashboard', async () => {
  const app = await start('contracts');
  try {
    const owner = await ownerSession(app);
    const { response, token, csrf } = await createLink(owner);
    assert.equal(response.status, 200);
    assert.ok(token, 'the link is shown on creation');
    const env = app.admin.envelopes()[0]!;
    assert.equal(env.status, 'open');
    assert.equal(JSON.stringify(env).includes(token), false, 'only a hash of the token is stored');

    // The hosted page and its assets work under a strict policy; the document is not public.
    const page = await fetch(`${app.url}/sealform/c/${token}`);
    assert.equal(page.status, 200);
    assert.match(page.headers.get('content-security-policy')!, /script-src 'self'/);
    assert.equal(page.headers.get('referrer-policy'), 'no-referrer');
    assert.match(await page.text(), new RegExp(`data-token="${token}"`));
    assert.equal((await fetch(`${app.url}/sealform/assets/contract.js`)).status, 200);
    assert.equal((await fetch(`${app.url}/sealform/api/documents/partner-contract`)).status, 404);
    assert.equal((await fetch(`${app.url}/sealform/c/short`)).status, 404);
    assert.equal((await fetch(`${app.url}/sealform/api/envelopes/${'A'.repeat(43)}`)).status, 404);

    const opened = (await (await fetch(`${app.url}/sealform/api/envelopes/${token}`)).json()) as { prefill: Record<string, string>; botCheck: string; envelope: { label: string } };
    assert.deepEqual(opened.prefill, { legalName: 'Pat Partner', email: 'pat@example.org' });
    assert.equal(opened.botCheck, 'none');

    // Name and email are fixed by the link.
    const swapped = await signLink(app, token!, { fields: { legalName: 'Someone Else', email: 'pat@example.org', country: 'DE' }, signature: { typedName: 'Someone Else', vector: [{ points: stroke() }], png: png() } });
    assert.equal(swapped.status, 422);
    assert.ok((((await swapped.json()) as { fields: Record<string, string> }).fields)['fields.legalName']);
    assert.equal(app.admin.envelope(env.id)!.status, 'open', 'a refused attempt releases the link');

    const signed = await signLink(app, token!);
    assert.equal(signed.status, 201, await signed.clone().text());
    const { id: recordId } = (await signed.json()) as { id: string };
    const record = app.sealform.store.getEntry(recordId) as SealformRecord;
    assert.deepEqual(record.envelope, { id: env.id, role: 'signer', order: 1 });
    assert.equal(app.admin.envelope(env.id)!.status, 'awaiting-countersignature');
    assert.equal(app.admin.envelope(env.id)!.recordHash, record.hash);

    // One use only.
    assert.equal((await fetch(`${app.url}/sealform/api/envelopes/${token}`)).status, 409);
    assert.equal((await signLink(app, token!)).status, 409);

    // Countersign: sealed into the audit log, confirmed to the signer by email.
    const detail = await owner.get(`/contracts/${env.id}`);
    assert.match(detail.text, /Countersign as owner@example.com/);
    const done = await owner.post(`/contracts/${env.id}/countersign`, { csrf });
    assert.equal(done.location, `${BASE}/contracts/${env.id}?m=saved`);
    const finished = app.admin.envelope(env.id)!;
    assert.equal(finished.status, 'complete');
    assert.equal(finished.countersignedBy, 'owner@example.com');
    assert.match(finished.finalHash!, /^[0-9a-f]{64}$/);
    assert.notEqual(finished.finalHash, record.hash);
    assert.equal((await owner.post(`/contracts/${env.id}/countersign`, { csrf })).status, 409, 'cannot countersign twice');

    const audit = app.admin.auditEntries().filter((e) => e.action.startsWith('envelope.'));
    assert.deepEqual(audit.map((e) => e.action), ['envelope.create', 'envelope.countersign']);
    assert.equal(audit[1]!.details.recordHash, record.hash);
    assert.equal((await verifyChain(app.admin.auditEntries(), keyset)).ok, true);
    await new Promise((resolve) => setTimeout(resolve, 80));
    const { readdir, readFile } = await import('node:fs/promises');
    const mails = await Promise.all((await readdir(join(dir, 'contracts', 'outbox'))).map((f) => readFile(join(dir, 'contracts', 'outbox', f), 'utf8')));
    assert.ok(mails.some((m) => /Subject: Countersigned: Acme services/.test(m) && /To: pat@example.org/.test(m)));
    assert.equal(JSON.stringify(app.admin.auditEntries()).includes(token), false, 'the token never reaches the audit log');
  } finally {
    await app.stop();
  }
});

test('a link without countersignature completes on signing; cancelled and expired links stop working', async () => {
  const app = await start('contracts-lifecycle');
  try {
    const owner = await ownerSession(app);
    const plain = await createLink(owner, { counter: '' });
    assert.equal((await signLink(app, plain.token!)).status, 201);
    const env = app.admin.envelopes().find((e) => e.status === 'complete')!;
    assert.equal(env.finalHash, env.recordHash, 'with no countersignature the record hash is final');

    const cancelled = await createLink(owner, { label: 'To cancel', email: 'c@example.org' });
    const target = app.admin.envelopes().find((e) => e.label === 'To cancel')!;
    assert.equal((await owner.post(`/contracts/${target.id}/revoke`, { csrf: cancelled.csrf })).status, 303);
    assert.equal((await fetch(`${app.url}/sealform/api/envelopes/${cancelled.token}`)).status, 410);
    assert.equal((await signLink(app, cancelled.token!)).status, 410);
    assert.equal((await owner.post(`/contracts/${target.id}/revoke`, { csrf: cancelled.csrf })).status, 409);

    const short = await createLink(owner, { label: 'Short', email: 's@example.org', days: '7' });
    clock += 8 * 86_400_000;
    assert.equal((await fetch(`${app.url}/sealform/api/envelopes/${short.token}`)).status, 410);
  } finally {
    await app.stop();
  }
});

test('contract links are for private documents, need an owner or admin, and review the signer country first', async () => {
  const docs = join(dir, 'docs-contract');
  const { cp, readFile, writeFile } = await import('node:fs/promises');
  await cp(FIXTURES, docs, { recursive: true });
  const manifestPath = join(docs, 'partner-contract', 'PARTNER-1', 'document.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.category = 'suretyship';
  await writeFile(manifestPath, JSON.stringify(manifest));
  const app = await start('contracts-review', { documentsDir: docs });
  try {
    const owner = await ownerSession(app);
    const csrf = await owner.csrf('/contracts');

    const publicDoc = await owner.post('/contracts', { csrf, document: 'example-agreement@EXAMPLE-1', label: 'x', name: 'X Y', email: 'x@example.org', days: '14' });
    assert.equal(publicDoc.status, 400, 'public documents are signed through the public form');

    const blocked = await owner.post('/contracts', { csrf, document: 'partner-contract@PARTNER-1', label: 'Surety', name: 'Pat Partner', email: 'pat@example.org', days: '14', country: 'DE' });
    assert.equal(blocked.status, 409);
    assert.match(blocked.text, /In Germany.*suretyship document needs wet-ink.*Section 766/);
    assert.equal(app.admin.envelopes().length, 0);

    const allowed = await owner.post('/contracts', { csrf, document: 'partner-contract@PARTNER-1', label: 'Surety', name: 'Pat Partner', email: 'pat@example.org', days: '14', country: 'DE', override: 'Signed copy also sent by post' });
    assert.equal(allowed.status, 200);
    assert.equal(app.admin.envelopes()[0]!.overrideReason, 'Signed copy also sent by post');
    assert.equal(app.admin.auditEntries().find((e) => e.action === 'envelope.create')!.details.override, 'Signed copy also sent by post');

    const reviewer = app.admin.createAccount({ email: 'rae@example.com', name: 'Rae', role: 'reviewer', passwordHash: await hashPassword(PASSWORD), mustChangePassword: false, now: new Date(clock).toISOString() });
    assert.ok(reviewer);
    const rae = new Browser(app);
    await rae.login('rae@example.com');
    assert.equal((await rae.get('/contracts')).status, 403);
    assert.equal((await rae.post('/contracts', { csrf, document: 'partner-contract@PARTNER-1' })).status, 403);
  } finally {
    await app.stop();
  }
});

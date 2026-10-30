import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, KEYSET_FORMAT, verifyChain, type KeySet } from '../src/core/index.ts';
import { createSealform, hashPassword } from '../src/server/index.ts';
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

async function start(name: string) {
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

  async get(path: string) {
    return this.send('GET', path);
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

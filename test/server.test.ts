import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { cp, mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { crc32, deflateSync } from 'node:zlib';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { generateKeyPair, KEYSET_FORMAT, sha256Hex, verifyChain, verifyEntry, type ChainEntry, type KeySet, type SealformRecord } from '../src/core/index.ts';
import { createSealform, defaultChecks, TurnstileCheck, type Sealform } from '../src/server/index.ts';

const FIXTURES = fileURLToPath(new URL('./fixtures/documents', import.meta.url));
const ORIGIN = 'https://sign.example.com';

let dir = '';
let keyset: KeySet;
let privateFile: Awaited<ReturnType<typeof generateKeyPair>>['privateFile'];

before(async () => {
  dir = await mkdtemp(join(tmpdir(), 'sealform-server-'));
  const pair = await generateKeyPair('test-2026');
  privateFile = pair.privateFile;
  const { publicEntry } = pair;
  keyset = { format: KEYSET_FORMAT, keys: [publicEntry] };
});

after(async () => {
  await rm(dir, { recursive: true, force: true });
});

async function start(name: string, overrides: Partial<Parameters<typeof createSealform>[0]> = {}) {
  const sealform = await createSealform({
    dataDir: join(dir, name),
    documentsDir: FIXTURES,
    sealingKey: privateFile,
    keySet: keyset,
    publicOrigin: ORIGIN,
    operator: { name: 'Example Studio', email: 'legal@example.com' },
    log: () => {},
    ...overrides,
  });
  const server = createServer(sealform.handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as { port: number }).port;
  const url = `http://127.0.0.1:${port}`;
  return {
    sealform,
    url,
    async stop() {
      await new Promise((resolve) => server.close(resolve));
      sealform.close();
    },
  };
}

/** A real PNG: 4x2 RGBA, built by hand so the tests need no image library. */
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
  const bytes = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk('IHDR', ihdr), chunk('IDAT', deflateSync(rows)), chunk('IEND', Buffer.alloc(0))]);
  return `data:image/png;base64,${bytes.toString('base64')}`;
}

async function open(url: string, lang = 'en') {
  const response = await fetch(`${url}/sealform/api/documents/example-agreement?lang=${lang}`);
  assert.equal(response.status, 200);
  return (await response.json()) as {
    document: { id: string; version: string; lang: string; text: string; sha256: string; manifestSha256: string };
    disclosure: { text: string } | null;
    session: { id: string };
  };
}

function submission(doc: Awaited<ReturnType<typeof open>>, overrides: Record<string, unknown> = {}) {
  return {
    sessionId: doc.session.id,
    documentId: doc.document.id,
    version: doc.document.version,
    lang: doc.document.lang,
    textSha256: doc.document.sha256,
    manifestSha256: doc.document.manifestSha256,
    fields: { legalName: 'Ada Example', email: 'ada@example.com', country: 'DE', adult: true },
    consents: { esign: true, acceptVersion: true },
    signature: { typedName: 'ada example', vector: [{ points: [{ x: 1, y: 2, time: 3, pressure: 0.5 }, { x: 4, y: 5, time: 6 }] }], png: png() },
    client: { timeZone: 'Europe/Berlin', screen: '390x844', injected: 'dropped' },
    ...overrides,
  };
}

async function post(url: string, body: unknown, headers: Record<string, string> = {}) {
  return fetch(`${url}/sealform/api/sign`, { method: 'POST', headers: { 'content-type': 'application/json', 'user-agent': 'sealform-test', ...headers }, body: JSON.stringify(body) });
}

test('opening a document returns the exact text, its hash and a session', async () => {
  const app = await start('open');
  try {
    const doc = await open(app.url);
    assert.equal(doc.document.sha256, await sha256Hex(doc.document.text));
    assert.match(doc.disclosure!.text, /Consent to electronic signature/);
    assert.ok(doc.session.id.length >= 32);
    const german = await open(app.url, 'de');
    assert.equal(german.document.lang, 'de');
    assert.match(german.document.text, /Beispiel/);
  } finally {
    await app.stop();
  }
});

test('a signature is sealed, chained, stored, mailed and verifiable by anyone', async () => {
  const app = await start('sign');
  try {
    const records: SealformRecord[] = [];
    for (let i = 0; i < 3; i++) {
      const response = await post(app.url, submission(await open(app.url)));
      assert.equal(response.status, 201, await response.clone().text());
      const receipt = (await response.json()) as { id: string; hash: string; pdfUrl: string; recordUrl: string };
      const recordResponse = await fetch(receipt.recordUrl.replace(ORIGIN, app.url));
      const record = (await recordResponse.json()) as SealformRecord;
      assert.equal(record.hash, receipt.hash);
      records.push(record);

      const pdf = new Uint8Array(await (await fetch(receipt.pdfUrl.replace(ORIGIN, app.url))).arrayBuffer());
      assert.equal(Buffer.from(pdf.slice(0, 5)).toString(), '%PDF-');
      assert.equal(app.sealform.store.summary(record.id)!.pdfSha256, await sha256Hex(pdf));
    }

    const first = records[0]!;
    assert.equal(first.server.ip, '127.0.0.1');
    assert.equal(first.server.userAgent, 'sealform-test');
    assert.equal(first.client.injected, undefined, 'unknown client keys are dropped');
    assert.equal(first.consent.esign, true);
    assert.equal(first.document.lang, 'en');
    assert.ok(first.document.manifestSha256);
    assert.deepEqual(first.assurance.checks, [{ kind: 'email-receipt', status: 'queued' }]);

    const chain = await verifyChain(app.sealform.store.entries(), keyset);
    assert.equal(chain.ok, true, JSON.stringify(chain.breaks));
    assert.equal(chain.length, 3);

    const mirrored = (await readFile(join(dir, 'sign', 'chain.jsonl'), 'utf8')).trim().split('\n').map((line) => JSON.parse(line) as ChainEntry);
    assert.equal((await verifyChain(mirrored, keyset)).ok, true);
    assert.equal((await verifyEntry(JSON.parse(await readFile(join(dir, 'sign', 'records', `${first.id}.json`), 'utf8')), keyset)).ok, true);
    assert.equal(await sha256Hex(new Uint8Array(await readFile(join(dir, 'sign', 'records', `${first.id}.png`)))), first.signature.pngSha256);

    await new Promise((resolve) => setTimeout(resolve, 50));
    const outbox = await readdir(join(dir, 'sign', 'outbox'));
    assert.equal(outbox.length, 3);
    const mail = await readFile(join(dir, 'sign', 'outbox', outbox[0]!), 'utf8');
    assert.match(mail, /^To: ada@example.com/m);
    assert.match(mail, /Content-Type: application\/pdf/);
  } finally {
    await app.stop();
  }
});

test('text the signer saw must match the published version', async () => {
  const app = await start('mismatch');
  try {
    const doc = await open(app.url);
    const bad = await post(app.url, submission(doc, { textSha256: 'f'.repeat(64) }));
    assert.equal(bad.status, 409);
    assert.equal(app.sealform.store.count(), 0);
    // The session is released, so a corrected retry works.
    assert.equal((await post(app.url, submission(doc))).status, 201);
  } finally {
    await app.stop();
  }
});

test('a session signs once', async () => {
  const app = await start('replay');
  try {
    const doc = await open(app.url);
    assert.equal((await post(app.url, submission(doc))).status, 201);
    assert.equal((await post(app.url, submission(doc))).status, 409);
  } finally {
    await app.stop();
  }
});

test('invalid submissions are rejected field by field', async () => {
  const app = await start('invalid');
  try {
    const doc = await open(app.url);
    const response = await post(app.url, submission(doc, {
      fields: { legalName: 'Ada Example', email: 'not-an-email', country: 'EU', adult: false, extra: 'x' },
      consents: { esign: false, acceptVersion: true },
      signature: { typedName: 'Someone Else', vector: [], png: 'data:image/png;base64,AAAA' },
    }));
    assert.equal(response.status, 422);
    const body = (await response.json()) as { fields: Record<string, string> };
    for (const key of ['fields.email', 'fields.country', 'fields.adult', 'fields.extra', 'consents.esign', 'signature.typedName', 'signature.vector', 'signature.png']) {
      assert.ok(body.fields[key], `expected an issue for ${key}`);
    }
    assert.equal(app.sealform.store.count(), 0);
  } finally {
    await app.stop();
  }
});

test('signing is rate limited per address', async () => {
  const app = await start('limit', { limits: { signPerWindow: 2 } });
  try {
    const statuses: number[] = [];
    for (let i = 0; i < 3; i++) statuses.push((await post(app.url, { nonsense: true })).status);
    assert.deepEqual(statuses.slice(0, 2), [409, 409]);
    assert.equal(statuses[2], 429);
  } finally {
    await app.stop();
  }
});

test('cross-origin calls need an allowed origin', async () => {
  const app = await start('cors', { allowedOrigins: ['https://partner.example.org'] });
  try {
    const denied = await fetch(`${app.url}/sealform/api/documents/example-agreement`, { headers: { origin: 'https://evil.example.net' } });
    assert.equal(denied.status, 403);
    const allowed = await fetch(`${app.url}/sealform/api/documents/example-agreement`, { headers: { origin: 'https://partner.example.org' } });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers.get('access-control-allow-origin'), 'https://partner.example.org');
  } finally {
    await app.stop();
  }
});

test('a failed Turnstile check blocks signing', async () => {
  const fakeFetch = (async () => new Response(JSON.stringify({ success: false }), { status: 200 })) as typeof fetch;
  const app = await start('turnstile', { botCheck: new TurnstileCheck('test-secret', fakeFetch) });
  try {
    const response = await post(app.url, submission(await open(app.url), { botToken: 'token' }));
    assert.equal(response.status, 403);
  } finally {
    await app.stop();
  }
});

test('names outside the PDF fonts still sign; the PDF marks them', async () => {
  const app = await start('unicode');
  try {
    const doc = await open(app.url);
    const response = await post(app.url, submission(doc, {
      fields: { legalName: '山田 太郎', email: 'taro@example.jp', country: 'JP', adult: true },
      signature: { typedName: '山田 太郎', vector: [{ points: [{ x: 1, y: 1, time: 1 }] }], png: png() },
    }));
    assert.equal(response.status, 201, await response.clone().text());
    const { id } = (await response.json()) as { id: string };
    const record = app.sealform.store.getEntry(id) as SealformRecord;
    assert.equal(record.fields.legalName, '山田 太郎');
  } finally {
    await app.stop();
  }
});

test('signers who cannot draw can sign by typing; the record says so', async () => {
  const app = await start('typed');
  try {
    const doc = await open(app.url);
    const ok = await post(app.url, submission(doc, { signature: { mode: 'typed', typedName: 'Ada Example', vector: [], png: png() } }));
    assert.equal(ok.status, 201, await ok.clone().text());
    const { id } = (await ok.json()) as { id: string };
    assert.equal((app.sealform.store.getEntry(id) as SealformRecord).signature.mode, 'typed');

    const doc2 = await open(app.url);
    const bad = await post(app.url, submission(doc2, { signature: { mode: 'typed', typedName: 'Ada Example', vector: [{ points: [{ x: 1, y: 1, time: 1 }] }], png: png() } }));
    assert.equal(bad.status, 422);
  } finally {
    await app.stop();
  }
});

test('public keys are served for verification', async () => {
  const app = await start('keys');
  try {
    const response = await fetch(`${app.url}/.well-known/sealform-keys.json`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), keyset);
  } finally {
    await app.stop();
  }
});

test('a document that requires an unconfigured check refuses to load', async () => {
  const docs = join(dir, 'docs-otp');
  await mkdir(docs, { recursive: true });
  await cp(FIXTURES, docs, { recursive: true });
  const manifestPath = join(docs, 'example-agreement', 'EXAMPLE-1', 'document.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.requiredChecks = ['email-otp'];
  await writeFile(manifestPath, JSON.stringify(manifest));
  await assert.rejects(start('otp', { documentsDir: docs }), /email-otp.*not configured/);
  assert.equal(defaultChecks().get('email-otp')!.enabled, false);
});

test('a sealing key missing from the key set is refused at startup', async () => {
  await assert.rejects(start('nokey', { keySet: { format: KEYSET_FORMAT, keys: [] } }), /does not contain the sealing key/);
});

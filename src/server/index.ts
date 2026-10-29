// sealform server. createSealform() returns a plain Node (req, res, next?) handler that works under
// Passenger (cPanel "Setup Node.js App"), Express or node:http.
//
// Public routes, under basePath (default /sealform):
//   GET  {base}/api/documents/:id?lang=xx    current published version, opens a signing session
//   POST {base}/api/sign                     seal a signature
//   GET  {base}/api/receipts/:token.pdf      the signer's PDF copy
//   GET  {base}/api/receipts/:token.json     the signer's sealed record
//   GET  /.well-known/sealform-keys.json     public keys for verification

import { createHash, randomBytes } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  importSealingKey,
  KEYSET_FORMAT,
  prefixedId,
  RECORD_FORMAT,
  sealRecord,
  sha256Hex,
  type AssuranceCheck,
  type KeySet,
  type PrivateKeyFile,
  type SealformRecord,
  type SealingKey,
} from '../core/index.ts';
import { defaultChecks, type Check } from './checks.ts';
import { DocumentRegistry, type LoadedDocument } from './documents.ts';
import { NoBotCheck, RateLimiter, type BotCheck } from './guards.ts';
import { clientIp, header, HttpError, readJson, sendBytes, sendJson, type ClientIpSource } from './http.ts';
import { OutboxMailer, type Mailer } from './mailer.ts';
import { renderCertificate } from './pdf.ts';
import { SqliteStore } from './store.ts';
import { parseSignRequest, ValidationError } from './validate.ts';

export interface SealformConfig {
  /** Records, database and outbox. Must be outside the web root. */
  dataDir: string;
  /** Folder of versioned documents: <id>/<version>/document.json and <lang>.md. */
  documentsDir: string;
  /** Path to the file written by `sealform keygen`, or its parsed contents. */
  sealingKey: string | PrivateKeyFile;
  /** Path to sealform-keys.json, or its parsed contents. Served at /.well-known/sealform-keys.json. */
  keySet: string | KeySet;
  /** Public origin of the site, such as https://example.com. Used in links in receipts and PDFs. */
  publicOrigin: string;
  operator: { name: string; email: string };
  basePath?: string;
  /** Origins allowed to call the API from another site. Same-origin calls are always allowed. */
  allowedOrigins?: string[];
  clientIp?: ClientIpSource;
  botCheck?: BotCheck;
  mailer?: Mailer;
  checks?: Map<string, Check>;
  limits?: { signPerWindow?: number; readPerWindow?: number; windowMs?: number };
  sessionTtlMs?: number;
  /** Errors are reported here without personal data. */
  log?: (message: string) => void;
  now?: () => Date;
}

export interface Sealform {
  handler: (req: IncomingMessage, res: ServerResponse, next?: (error?: unknown) => void) => void;
  store: SqliteStore;
  documents: DocumentRegistry;
  close(): void;
}

const MAX_BODY = 1_200_000;

export async function createSealform(config: SealformConfig): Promise<Sealform> {
  const base = (config.basePath ?? '/sealform').replace(/\/+$/, '');
  const origin = new URL(config.publicOrigin).origin;
  const now = config.now ?? (() => new Date());
  const log = config.log ?? ((message: string) => console.error(`[sealform] ${message}`));
  const checks = config.checks ?? defaultChecks();
  const botCheck = config.botCheck ?? new NoBotCheck();
  const mailer = config.mailer ?? new OutboxMailer(join(config.dataDir, 'outbox'));
  const ipSource = config.clientIp ?? 'socket';
  const windowMs = config.limits?.windowMs ?? 10 * 60_000;
  const signLimiter = new RateLimiter(config.limits?.signPerWindow ?? 10, windowMs, () => now().getTime());
  const readLimiter = new RateLimiter(config.limits?.readPerWindow ?? 120, windowMs, () => now().getTime());
  const sessionTtl = config.sessionTtlMs ?? 2 * 60 * 60_000;
  const allowedOrigins = new Set([origin, ...(config.allowedOrigins ?? []).map((o) => new URL(o).origin)]);

  const sealingKey: SealingKey = await importSealingKey(typeof config.sealingKey === 'string' ? await readJsonFile(config.sealingKey) : config.sealingKey);
  const keySet: KeySet = typeof config.keySet === 'string' ? await readJsonFile(config.keySet) : config.keySet;
  if (keySet.format !== KEYSET_FORMAT) throw new Error('keySet is not a sealform key set');
  const activeKey = keySet.keys.find((key) => key.kid === sealingKey.kid);
  if (!activeKey) throw new Error(`The key set does not contain the sealing key ${sealingKey.kid}; records would not verify`);
  if (activeKey.retiredAt) throw new Error(`Sealing key ${sealingKey.kid} is retired`);

  const documents = await DocumentRegistry.load(config.documentsDir, checks);
  const store = await SqliteStore.open(config.dataDir);
  const keysUrl = `${origin}/.well-known/sealform-keys.json`;

  async function getDocument(req: IncomingMessage, res: ServerResponse, id: string, url: URL): Promise<void> {
    const doc = documents.current(id);
    if (!doc || !doc.manifest.public) throw new HttpError(404, 'No such document');
    const lang = pickLanguage(doc, url.searchParams.get('lang'), header(req, 'accept-language'));
    const text = doc.texts.get(lang)!;
    const disclosure = disclosureOf(doc);
    const opened = now();
    const session = { id: randomBytes(24).toString('base64url'), documentId: doc.manifest.id, documentVersion: doc.manifest.version, lang, openedAt: opened.toISOString(), expiresAt: new Date(opened.getTime() + sessionTtl).toISOString() };
    store.createSession(session);
    if (Math.random() < 0.02) store.purgeExpiredSessions(opened.toISOString());
    const disclosureText = disclosure ? (disclosure.texts.get(lang) ?? disclosure.texts.get(disclosure.manifest.governingLang)!) : undefined;
    sendJson(res, 200, {
      document: { id: doc.manifest.id, version: doc.manifest.version, title: doc.manifest.title, category: doc.manifest.category, lang, languages: doc.manifest.languages, governingLang: doc.manifest.governingLang, text: text.text, sha256: text.sha256, manifestSha256: doc.manifestSha256 },
      disclosure: disclosure && disclosureText ? { id: disclosure.manifest.id, version: disclosure.manifest.version, lang: disclosureText.lang, text: disclosureText.text, sha256: disclosureText.sha256 } : null,
      fields: doc.manifest.fields,
      consents: doc.manifest.consents,
      requiredChecks: doc.manifest.requiredChecks,
      session: { id: session.id, expiresAt: session.expiresAt },
      botCheck: botCheck.name,
    });
  }

  async function sign(req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
    const body = (await readJson(req, MAX_BODY)) as Record<string, unknown>;
    const doc = documents.get(String(body?.documentId ?? ''), String(body?.version ?? ''));
    if (!doc || doc.manifest.status !== 'published' || !doc.manifest.public) {
      throw new HttpError(409, 'This document version is no longer open for signing. Reload the page to get the current version.');
    }
    const request = parseSignRequest(body, doc.manifest);
    if (!(await botCheck.verify(request.botToken, ip))) throw new HttpError(403, 'The bot check failed. Please try again.');

    const session = store.getSession(request.sessionId);
    const receivedAt = now();
    if (!session || session.documentId !== doc.manifest.id || session.documentVersion !== doc.manifest.version || session.lang !== request.lang) {
      throw new HttpError(409, 'This signing session does not match the document. Reload the page.');
    }
    if (session.expiresAt < receivedAt.toISOString()) throw new HttpError(409, 'This signing session expired. Reload the page and sign again.');
    if (!store.useSession(session.id, receivedAt.toISOString())) throw new HttpError(409, 'This signing session was already used.');

    try {
      const text = doc.texts.get(request.lang);
      if (!text || text.sha256 !== request.textSha256) throw new HttpError(409, 'The text you saw does not match the published version. Reload the page.');
      if (doc.manifestSha256 !== request.manifestSha256) throw new HttpError(409, 'The form you saw does not match the published version. Reload the page.');
      const disclosure = disclosureOf(doc);
      const disclosureText = disclosure ? (disclosure.texts.get(request.lang) ?? disclosure.texts.get(disclosure.manifest.governingLang)!) : undefined;

      const id = prefixedId('sf', receivedAt.getTime());
      const assurance: AssuranceCheck[] = [];
      for (const kind of doc.manifest.requiredChecks) assurance.push(await checks.get(kind)!.run({ recordId: id, fields: request.fields }));
      const emailField = doc.manifest.fields.find((field) => field.role === 'receiptEmail');
      const receiptTo = emailField ? (request.fields[emailField.name] as string | undefined) : undefined;
      if (receiptTo && !assurance.some((check) => check.kind === 'email-receipt')) assurance.push({ kind: 'email-receipt', status: 'queued' });

      const pngSha256 = await sha256Hex(new Uint8Array(request.signature.png));
      await writeFile(join(store.recordsDir, `${id}.png`), request.signature.png, { mode: 0o600 });
      const receiptToken = randomBytes(32).toString('base64url');
      const nameField = doc.manifest.fields.find((field) => field.role === 'signerName');
      const countryField = doc.manifest.fields.find((field) => field.type === 'country' || field.role === 'country');

      const record = await store.append(
        (chain) =>
          sealRecord(
            {
              format: RECORD_FORMAT,
              id,
              document: { id: doc.manifest.id, version: doc.manifest.version, lang: request.lang, sha256: text.sha256, manifestSha256: doc.manifestSha256 },
              disclosure: disclosure && disclosureText
                ? { id: disclosure.manifest.id, version: disclosure.manifest.version, lang: disclosureText.lang, sha256: disclosureText.sha256, manifestSha256: disclosure.manifestSha256 }
                : { id: 'none', version: 'none', lang: request.lang, sha256: '0'.repeat(64) },
              fields: request.fields,
              consent: request.consents,
              signature: { typedName: request.signature.typedName, vector: request.signature.vector, pngSha256 },
              assurance: { level: 'ses', checks: assurance },
              server: {
                receivedAt: receivedAt.toISOString(),
                sessionOpenedAt: session.openedAt,
                ip,
                userAgent: header(req, 'user-agent'),
                acceptLanguage: header(req, 'accept-language', 200),
              },
              client: request.client,
              chain,
            },
            sealingKey,
          ),
        {
          signerName: nameField ? String(request.fields[nameField.name] ?? '') : null,
          email: receiptTo ?? null,
          country: countryField ? String(request.fields[countryField.name] ?? '') || null : null,
          receiptTokenHash: hashToken(receiptToken),
        },
      );

      const pdf = await renderCertificate({
        record,
        manifest: doc.manifest,
        documentText: text.text,
        ...(disclosureText ? { disclosureText: disclosureText.text } : {}),
        png: request.signature.png,
        operatorName: config.operator.name,
        keysUrl,
      });
      await writeFile(join(store.recordsDir, `${id}.pdf`), pdf, { mode: 0o600 });
      store.setPdfHash(id, await sha256Hex(new Uint8Array(pdf)));

      const receiptBase = `${origin}${base}/api/receipts/${receiptToken}`;
      if (receiptTo) {
        mailer
          .send(receiptMail(record, doc, receiptTo, config.operator, receiptBase, keysUrl, pdf))
          .catch((error: unknown) => log(`receipt for ${id} not sent: ${error instanceof Error ? error.message : String(error)}`));
      }

      sendJson(res, 201, {
        id: record.id,
        hash: record.hash,
        seal: { alg: record.seal.alg, kid: record.seal.kid },
        chain: record.chain,
        receivedAt: record.server.receivedAt,
        pdfUrl: `${receiptBase}.pdf`,
        recordUrl: `${receiptBase}.json`,
        keysUrl,
      });
    } catch (error) {
      store.releaseSession(session.id);
      throw error;
    }
  }

  async function receipt(res: ServerResponse, token: string, kind: 'pdf' | 'json'): Promise<void> {
    const summary = /^[A-Za-z0-9_-]{43}$/.test(token) ? store.findByReceiptToken(hashToken(token)) : undefined;
    if (!summary || summary.tombstonedAt) throw new HttpError(404, 'No such receipt');
    if (kind === 'json') {
      sendJson(res, 200, store.getEntry(summary.id), { 'content-disposition': `attachment; filename="${summary.id}.json"` });
      return;
    }
    const pdf = await readFile(join(store.recordsDir, `${summary.id}.pdf`));
    sendBytes(res, 200, 'application/pdf', pdf, { 'content-disposition': `attachment; filename="${summary.id}.pdf"` });
  }

  function disclosureOf(doc: LoadedDocument): LoadedDocument | undefined {
    const ref = doc.manifest.disclosure;
    return ref ? documents.get(ref.id, ref.version) : undefined;
  }

  async function route(req: IncomingMessage, res: ServerResponse): Promise<boolean> {
    const url = new URL(req.url ?? '/', origin);
    const path = url.pathname;
    const ip = clientIp(req, ipSource);

    if (path === '/.well-known/sealform-keys.json') {
      if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed', undefined, { allow: 'GET' });
      sendJson(res, 200, keySet, { 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*' });
      return true;
    }
    if (!path.startsWith(`${base}/api/`)) return false;

    const requestOrigin = header(req, 'origin');
    const cors: Record<string, string> = {};
    if (requestOrigin) {
      if (!allowedOrigins.has(requestOrigin)) throw new HttpError(403, 'Origin not allowed');
      Object.assign(cors, { 'access-control-allow-origin': requestOrigin, vary: 'Origin' });
    }
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...cors, 'access-control-allow-methods': 'GET, POST', 'access-control-allow-headers': 'content-type', 'access-control-max-age': '600' });
      res.end();
      return true;
    }
    for (const [name, value] of Object.entries(cors)) res.setHeader(name, value);

    const rest = path.slice(`${base}/api/`.length);
    const docMatch = /^documents\/([A-Za-z0-9._-]{1,64})$/.exec(rest);
    const receiptMatch = /^receipts\/([A-Za-z0-9_-]+)\.(pdf|json)$/.exec(rest);

    if (docMatch && req.method === 'GET') {
      limit(readLimiter, `read:${ip}`);
      await getDocument(req, res, docMatch[1]!, url);
    } else if (rest === 'sign' && req.method === 'POST') {
      limit(signLimiter, `sign:${ip}`);
      await sign(req, res, ip);
    } else if (receiptMatch && req.method === 'GET') {
      limit(readLimiter, `read:${ip}`);
      await receipt(res, receiptMatch[1]!, receiptMatch[2] as 'pdf' | 'json');
    } else {
      throw new HttpError(404, 'Not found');
    }
    return true;
  }

  const handler: Sealform['handler'] = (req, res, next) => {
    route(req, res).then(
      (handled) => {
        if (handled) return;
        if (next) next();
        else sendJson(res, 404, { error: 'Not found' });
      },
      (error: unknown) => {
        if (res.headersSent) {
          res.destroy();
          return;
        }
        if (error instanceof ValidationError) {
          sendJson(res, 422, { error: 'Please fix the highlighted fields.', fields: error.issues });
        } else if (error instanceof HttpError) {
          sendJson(res, error.status, { error: error.message, ...error.details }, error.headers);
        } else {
          log(`unexpected error on ${req.method} ${(req.url ?? '').split('?')[0]?.replace(/receipts\/[^/]+/, 'receipts/***')}: ${error instanceof Error ? error.stack ?? error.message : String(error)}`);
          sendJson(res, 500, { error: 'Something went wrong. Nothing was signed; please try again.' });
        }
      },
    );
  };

  return { handler, store, documents, close: () => store.close() };
}

function limit(limiter: RateLimiter, key: string): void {
  const wait = limiter.take(key);
  if (wait > 0) throw new HttpError(429, 'Too many attempts. Please wait and try again.', undefined, { 'retry-after': String(wait) });
}

function pickLanguage(doc: LoadedDocument, requested: string | null, acceptLanguage: string): string {
  const available = doc.manifest.languages;
  if (requested && available.includes(requested)) return requested;
  for (const part of acceptLanguage.split(',')) {
    const tag = part.split(';')[0]!.trim();
    if (available.includes(tag)) return tag;
    const primary = tag.split('-')[0]!;
    const match = available.find((lang) => lang === primary || lang.startsWith(`${primary}-`));
    if (match) return match;
  }
  return doc.manifest.governingLang;
}

function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

async function readJsonFile<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, 'utf8')) as T;
}

function receiptMail(
  record: SealformRecord,
  doc: LoadedDocument,
  to: string,
  operator: { name: string; email: string },
  receiptBase: string,
  keysUrl: string,
  pdf: Uint8Array,
) {
  const text = [
    `You signed "${doc.manifest.title}" (version ${doc.manifest.version}) on ${record.server.receivedAt} UTC.`,
    '',
    'Your signed copy is attached as a PDF. Keep it for your records.',
    '',
    `Record id: ${record.id}`,
    `Record SHA-256: ${record.hash}`,
    `Sealed with key: ${record.seal.kid} (${keysUrl})`,
    '',
    `Download the PDF again: ${receiptBase}.pdf`,
    `Download the sealed record: ${receiptBase}.json`,
    'Anyone can check the sealed record with: npx sealform verify <record.json> --keys ' + keysUrl,
    '',
    `To ask for a paper copy, to withdraw consent to sign electronically for future documents, or if you did not sign this, contact ${operator.email}.`,
    '',
    operator.name,
  ].join('\n');
  return {
    to,
    from: `${operator.name.replace(/[<>"\r\n]/g, '')} <${operator.email}>`,
    replyTo: operator.email,
    subject: `Your signed copy: ${doc.manifest.title}`,
    text,
    attachments: [{ filename: `${record.id}.pdf`, contentType: 'application/pdf', content: pdf }],
  };
}

export { defaultChecks, CheckNotConfiguredError, type Check } from './checks.ts';
export { DocumentRegistry, type DocumentManifest, type FieldSpec, type ConsentSpec } from './documents.ts';
export { NoBotCheck, RateLimiter, TurnstileCheck, type BotCheck } from './guards.ts';
export { OutboxMailer, toMime, type Mailer, type MailMessage } from './mailer.ts';
export { SqliteStore, type RecordSummary } from './store.ts';
export { isCountryCode, ValidationError } from './validate.ts';

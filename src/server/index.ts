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
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import {
  importSealingKey,
  isCountryCode,
  KEYSET_FORMAT,
  prefixedId,
  RECORD_FORMAT,
  sealRecord,
  sha256Hex,
  sha256Canonical,
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
import { CloudflareAccess, type AccessConfig } from './admin/access.ts';
import type { Envelope } from './admin/db.ts';
import { createAdmin } from './admin/index.ts';
import { renderCertificate } from './pdf.ts';
import { ProfileRegistry, signerVisible as profileVisible } from './profiles.ts';
import { SiteLayer, type SiteConfig } from './site.ts';
import { AdminStore } from './admin/db.ts';
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
  /**
   * Mounts the admin dashboard at this path. "/login" is a good choice: the dashboard's own address is
   * then its sign-in page. Leave it unset to turn the dashboard off. The path is not a secret; the
   * sign-in is what protects it.
   */
  adminPath?: string;
  /**
   * Also serve the built website from a folder, with hidden and private pages and a parking switch
   * managed from the dashboard. Requests the signing API and dashboard do not handle fall through to it.
   */
  site?: SiteConfig;
  /** Folder of jurisdiction profile JSON files. Defaults to the profiles shipped with sealform. */
  profilesDir?: string;
  /**
   * The profile id that applies to your own side of a contract, such as "US-CA". The dashboard checks it
   * when a contract link is created, the same way it checks the signer's country.
   */
  operatorJurisdiction?: string;
  /**
   * Public Turnstile site key for the dashboard sign-in page. Required when the dashboard is on and
   * `botCheck` is a TurnstileCheck, so the dashboard is never left unprotected by accident. Uses the
   * same secret as the public form.
   */
  adminTurnstileSiteKey?: string;
  /**
   * Put the dashboard behind Cloudflare Access (Google sign-in or whatever your Access policy allows).
   * Access does the login; the dashboard verifies Cloudflare's signed token on every request and
   * matches its email to a dashboard account. Passwords and two-factor are then not used.
   */
  adminAccess?: AccessConfig;
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
  /** Admin tables, present when adminPath is set. Used by the CLI and tests. */
  admin: AdminStore | undefined;
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
  // Validate configuration before opening anything, so a bad config does not leave the database open.
  // Checked first so a typo in the team domain or audience fails before anything is opened.
  const access = config.adminAccess ? new CloudflareAccess(config.adminAccess, () => now().getTime()) : undefined;
  if (access && !config.adminPath) throw new Error('adminAccess is set but adminPath is not, so there is no dashboard to protect');
  if (access && config.adminTurnstileSiteKey) throw new Error('adminTurnstileSiteKey has no effect with adminAccess: there is no password form to protect');
  if (config.adminPath && !access && botCheck.name === 'turnstile' && !config.adminTurnstileSiteKey) {
    throw new Error('adminTurnstileSiteKey is required when the dashboard is on and botCheck is Turnstile');
  }
  if (config.adminTurnstileSiteKey && botCheck.name !== 'turnstile') {
    throw new Error('adminTurnstileSiteKey is set but botCheck is not a TurnstileCheck, so the widget could never be verified');
  }
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
  const profiles = await ProfileRegistry.load(config.profilesDir);
  if (config.operatorJurisdiction && !profiles.get(config.operatorJurisdiction)) throw new Error(`operatorJurisdiction ${config.operatorJurisdiction} is not a loaded profile`);
  const store = await SqliteStore.open(config.dataDir);
  const keysUrl = `${origin}/.well-known/sealform-keys.json`;
  // The dashboard shows site info and the site layer needs the dashboard's database, so one is bound late.
  let site: SiteLayer | undefined;
  const admin = config.adminPath
    ? await createAdmin({
        base: config.adminPath.replace(/\/+$/, ''),
        origin,
        operatorName: config.operator.name,
        store,
        documents,
        sealingKey,
        keySet,
        checks,
        profiles,
        operatorProfile: config.operatorJurisdiction ? profiles.get(config.operatorJurisdiction) : undefined,
        siteInfo: config.site ? () => site!.info() : undefined,
        siteParking: config.site ? (on) => site!.setParking(on) : undefined,
        signBase: base,
        mailer,
        operator: config.operator,
        botCheck,
        turnstileSiteKey: config.adminTurnstileSiteKey,
        access,
        now,
        log,
      })
    : undefined;

  /** The fields a private link fixes for the signer: name and email, matched by role. */
  function envelopePrefill(doc: LoadedDocument, envelope: Envelope): Record<string, string> {
    const out: Record<string, string> = {};
    for (const field of doc.manifest.fields) {
      if (field.role === 'signerName') out[field.name] = envelope.signerName;
      if (field.role === 'receiptEmail') out[field.name] = envelope.signerEmail;
    }
    return out;
  }

  /** A link that can still be used to sign, or the reason it cannot. */
  function openEnvelope(token: string): Envelope {
    const found = admin && /^[A-Za-z0-9_-]{43}$/.test(token) ? admin.db.envelopeByTokenHash(hashToken(token)) : undefined;
    if (!found) throw new HttpError(404, 'This signing link is not valid.');
    if (found.status === 'revoked') throw new HttpError(410, 'This signing link was cancelled. Ask the sender for a new one.');
    if (found.status === 'awaiting-countersignature' || found.status === 'complete') throw new HttpError(409, 'This agreement has already been signed.');
    if (found.expiresAt < now().toISOString()) throw new HttpError(410, 'This signing link has expired. Ask the sender for a new one.');
    const party = admin!.db.counterSignerForChild(found.id);
    if (party && admin!.db.envelope(party.parentId)?.status !== 'awaiting-countersignature') throw new HttpError(409, 'The original contract is not awaiting Studio signatures');
    return found;
  }

  async function getEnvelope(req: IncomingMessage, res: ServerResponse, token: string, url: URL): Promise<void> {
    const envelope = openEnvelope(token);
    const doc = documents.get(envelope.documentId, envelope.documentVersion);
    const isCounter = !!admin!.db.counterSignerForChild(envelope.id);
    if (!doc || (documents.status(doc) !== 'published' && !(isCounter && documents.status(doc) === 'closed'))) throw new HttpError(410, 'This agreement is no longer open for signing. Ask the sender.');
    if (isCounter) {
      const party = admin!.db.counterSignerForChild(envelope.id)!;
      const parent = admin!.db.envelope(party.parentId)!;
      const primary = parent.recordId ? store.getEntry(parent.recordId) : undefined;
      if (!primary || primary.format !== RECORD_FORMAT) throw new HttpError(409, 'The original signed record is unavailable');
      url.searchParams.set('lang', primary.document.lang);
    }
    return serveDocument(req, res, doc, url, envelope);
  }

  site = config.site
    ? new SiteLayer(config.site, { db: admin?.db, isAdmin: (req) => admin?.isSignedIn(req) ?? false, operatorName: config.operator.name })
    : undefined;
  await site?.syncParking();

  async function getDocument(req: IncomingMessage, res: ServerResponse, id: string, url: URL): Promise<void> {
    const doc = documents.current(id);
    if (!doc || !doc.manifest.public) throw new HttpError(404, 'No such document');
    return serveDocument(req, res, doc, url);
  }

  async function serveDocument(req: IncomingMessage, res: ServerResponse, doc: LoadedDocument, url: URL, envelope?: Envelope): Promise<void> {
    const lang = pickLanguage(doc, url.searchParams.get('lang'), header(req, 'accept-language'));
    const text = doc.texts.get(lang)!;
    const disclosure = disclosureOf(doc);
    const opened = now();
    const session = { id: randomBytes(24).toString('base64url'), documentId: doc.manifest.id, documentVersion: doc.manifest.version, lang, openedAt: opened.toISOString(), expiresAt: new Date(opened.getTime() + sessionTtl).toISOString() };
    store.createSession(session);
    if (Math.random() < 0.02) store.purgeExpiredSessions(opened.toISOString());
    const disclosureText = disclosure ? (disclosure.texts.get(lang) ?? disclosure.texts.get(disclosure.manifest.governingLang)!) : undefined;
    sendJson(res, 200, {
      document: { id: doc.manifest.id, version: doc.manifest.version, title: doc.manifest.title, category: doc.manifest.category, lang, languages: envelope && admin!.db.counterSignerForChild(envelope.id) ? [lang] : doc.manifest.languages, governingLang: doc.manifest.governingLang, text: text.text, sha256: text.sha256, manifestSha256: doc.manifestSha256 },
      disclosure: disclosure && disclosureText ? { id: disclosure.manifest.id, version: disclosure.manifest.version, lang: disclosureText.lang, text: disclosureText.text, sha256: disclosureText.sha256 } : null,
      fields: doc.manifest.fields,
      consents: doc.manifest.consents,
      requiredChecks: doc.manifest.requiredChecks,
      session: { id: session.id, expiresAt: session.expiresAt },
      botCheck: envelope ? 'none' : botCheck.name,
      ...(envelope ? { prefill: envelopePrefill(doc, envelope), envelope: { label: envelope.label, expiresAt: envelope.expiresAt } } : {}),
    });
  }

  async function sign(req: IncomingMessage, res: ServerResponse, ip: string): Promise<void> {
    const body = (await readJson(req, MAX_BODY)) as Record<string, unknown>;
    // A private link names its own document, and the link itself is the secret; there is no bot check.
    const envelope = typeof body?.envelopeToken === 'string' ? openEnvelope(body.envelopeToken) : undefined;
    const doc = envelope ? documents.get(envelope.documentId, envelope.documentVersion) : documents.get(String(body?.documentId ?? ''), String(body?.version ?? ''));
    const counterParty = envelope ? admin!.db.counterSignerForChild(envelope.id) : undefined;
    const parentEnvelope = counterParty ? admin!.db.envelope(counterParty.parentId) : undefined;
    if (!doc || (documents.status(doc) !== 'published' && !(counterParty && documents.status(doc) === 'closed')) || (!envelope && !doc.manifest.public) || (envelope && (body.documentId !== doc.manifest.id || body.version !== doc.manifest.version))) {
      throw new HttpError(409, 'This document version is no longer open for signing. Reload the page to get the current version.');
    }
    // The signer's country picks the jurisdiction profile, which can add required fields.
    const countrySpec = doc.manifest.fields.find((field) => field.role === 'country' || field.type === 'country');
    const rawCountry = countrySpec ? ((body.fields ?? {}) as Record<string, unknown>)[countrySpec.name] : undefined;
    const jurisdiction = typeof rawCountry === 'string' && isCountryCode(rawCountry) ? profiles.resolve(rawCountry) : undefined;
    const effective = jurisdiction
      ? { ...doc.manifest, fields: [...doc.manifest.fields, ...jurisdiction.loaded.profile.requiredFields.filter((extra) => !doc.manifest.fields.some((own) => own.name === extra.name)).map((extra) => ({ ...extra }))] }
      : doc.manifest;
    const request = parseSignRequest(body, effective);
    if (!envelope && !(await botCheck.verify(request.botToken, ip))) throw new HttpError(403, 'The bot check failed. Please try again.');
    if (envelope) {
      const fixed = Object.entries(envelopePrefill(doc, envelope)).filter(([name, value]) => request.fields[name] !== value);
      if (fixed.length) throw new ValidationError(Object.fromEntries(fixed.map(([name]) => [`fields.${name}`, 'is fixed by this link and cannot be changed'])));
    }

    const session = store.getSession(request.sessionId);
    const receivedAt = now();
    if (!session || session.documentId !== doc.manifest.id || session.documentVersion !== doc.manifest.version || session.lang !== request.lang) {
      throw new HttpError(409, 'This signing session does not match the document. Reload the page.');
    }
    if (session.expiresAt < receivedAt.toISOString()) throw new HttpError(409, 'This signing session expired. Reload the page and sign again.');
    if (!store.useSession(session.id, receivedAt.toISOString())) throw new HttpError(409, 'This signing session was already used.');
    if (envelope && !admin!.db.claimEnvelope(envelope.id, receivedAt.toISOString(), new Date(receivedAt.getTime() - 5 * 60_000).toISOString())) {
      store.releaseSession(session.id);
      throw new HttpError(409, 'This signing link is already being used.');
    }

    try {
      const text = doc.texts.get(request.lang);
      if (!text || text.sha256 !== request.textSha256) throw new HttpError(409, 'The text you saw does not match the published version. Reload the page.');
      if (counterParty) {
        const primary = parentEnvelope?.recordId ? store.getEntry(parentEnvelope.recordId) : undefined;
        if (parentEnvelope?.status !== 'awaiting-countersignature' || !primary || primary.format !== RECORD_FORMAT || primary.hash !== parentEnvelope.recordHash || primary.document.lang !== request.lang || primary.document.sha256 !== text.sha256 || primary.document.manifestSha256 !== doc.manifestSha256) throw new HttpError(409, 'The original signed agreement does not match this Studio signing request');
      }
      if (doc.manifestSha256 !== request.manifestSha256) throw new HttpError(409, 'The form you saw does not match the published version. Reload the page.');
      if (jurisdiction) {
        const needs = jurisdiction.loaded.profile.formRequirements.find((r) => r.category === doc.manifest.category);
        if (needs) throw new HttpError(422, `This kind of document cannot be signed with a simple electronic signature in ${jurisdiction.loaded.profile.name}. ${needs.note}`);
        if (request.profileSha256 !== jurisdiction.loaded.sha256) throw new HttpError(409, 'The notices shown for your country are out of date. Reload the page.');
      }
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
              ...(envelope ? { envelope: { id: envelope.id, role: counterParty ? 'countersigner' : 'signer', order: counterParty ? counterParty.position + 2 : 1, ...(counterParty && parentEnvelope?.recordHash ? { parentEnvelopeId: parentEnvelope.id, parentRecordHash: parentEnvelope.recordHash } : {}) } } : {}),
              ...(jurisdiction ? { jurisdiction: { profile: jurisdiction.loaded.profile.id, version: jurisdiction.loaded.profile.version, sha256: jurisdiction.loaded.sha256, fallback: jurisdiction.fallback } } : {}),
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
        manifest: effective,
        documentText: text.text,
        ...(disclosureText ? { disclosureText: disclosureText.text } : {}),
        png: request.signature.png,
        operatorName: config.operator.name,
        keysUrl,
      });
      await writeFile(join(store.recordsDir, `${id}.pdf`), pdf, { mode: 0o600 });
      store.setPdfHash(id, await sha256Hex(new Uint8Array(pdf)));

      if (envelope) admin!.db.finishEnvelope(envelope.id, record.id, record.hash, receivedAt.toISOString(), envelope.counterRequired);
      if (counterParty && parentEnvelope) {
        const parties = admin!.db.counterSigners(parentEnvelope.id);
        const signatures = parties.map((party) => ({ party, child: party.childId ? admin!.db.envelope(party.childId) : undefined }));
        if (signatures.every(({ child }) => child?.status === 'complete' && child.recordId && child.recordHash)) {
          const completedAt = receivedAt.toISOString();
          const finalHash = await sha256Canonical({ envelope: parentEnvelope.id, document: `${doc.manifest.id}@${doc.manifest.version}`,
            signerRecord: { id: parentEnvelope.recordId, hash: parentEnvelope.recordHash },
            studioSignatures: signatures.map(({ party, child }) => ({ name: party.name, email: party.email, country: party.country, record: child!.recordId, hash: child!.recordHash })), completedAt });
          if (admin!.db.completeDrawnCountersignatures(parentEnvelope.id, parties.map((p) => p.email).join(', '), completedAt, finalHash)) {
            await admin!.db.audit(sealingKey, { at: completedAt, actor: 'system', action: 'envelope.countersign', target: parentEnvelope.id,
              details: { recordHash: parentEnvelope.recordHash, finalHash, studioRecords: signatures.map(({ child }) => child!.recordId!), drawnSignatures: true }, ip });
            await mailer.send({ to: parentEnvelope.signerEmail, from: `${config.operator.name.replace(/[<>"\r\n]/g, '')} <${config.operator.email}>`, replyTo: config.operator.email,
              subject: `Countersigned: ${parentEnvelope.label}`, text: [`All required Studio signers have drawn their signatures for "${parentEnvelope.label}".`, `Original record: ${parentEnvelope.recordId}`, `Final SHA-256: ${finalHash}`,
              ...signatures.map(({ party, child }) => `${party.name}: ${child!.recordId} (SHA-256 ${child!.recordHash})`)].join('\n') }).catch(() => config.log?.('Completed-contract notice could not be delivered'));
          }
        }
      }
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
      if (envelope) admin!.db.releaseEnvelope(envelope.id);
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
    const contract = new RegExp(`^${base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/c/([A-Za-z0-9_-]{43})$`).exec(path);
    if (admin && req.method === 'GET' && contract) {
      limit(readLimiter, `read:${ip}`);
      sendBytes(res, 200, 'text/html; charset=utf-8', Buffer.from(await contractPage(base, contract[1]!)), CONTRACT_HEADERS);
      return true;
    }
    if (admin && req.method === 'GET' && path.startsWith(`${base}/assets/`)) {
      const asset = await contractAsset(path.slice(`${base}/assets/`.length));
      if (!asset) throw new HttpError(404, 'Not found');
      sendBytes(res, 200, asset.type, asset.body, { ...CONTRACT_HEADERS, 'cache-control': 'public, max-age=300' });
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
    const envelopeMatch = /^envelopes\/([A-Za-z0-9_-]{43})$/.exec(rest);
    const profileMatch = /^profile\/([A-Za-z-]{2,5})$/.exec(rest);
    const receiptMatch = /^receipts\/([A-Za-z0-9_-]+)\.(pdf|json)$/.exec(rest);

    if (docMatch && req.method === 'GET') {
      limit(readLimiter, `read:${ip}`);
      await getDocument(req, res, docMatch[1]!, url);
    } else if (envelopeMatch && req.method === 'GET') {
      limit(readLimiter, `read:${ip}`);
      await getEnvelope(req, res, envelopeMatch[1]!, url);
    } else if (profileMatch && req.method === 'GET') {
      limit(readLimiter, `read:${ip}`);
      const { loaded, fallback } = profiles.resolve(profileMatch[1]!.toUpperCase());
      sendJson(res, 200, { profile: profileVisible(loaded.profile), sha256: loaded.sha256, fallback });
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
    const handled = admin ? admin.route(req, res, clientIp(req, ipSource)) : Promise.resolve(false);
    handled.then((done) => (done ? true : route(req, res))).then(
      (handled) => {
        if (handled) return;
        if (site && config.site?.serve !== false) {
          site.handle(req, res).catch((error: unknown) => {
            log(`site error: ${error instanceof Error ? error.message : String(error)}`);
            if (!res.headersSent) res.writeHead(500).end();
            else res.destroy();
          });
          return;
        }
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

  return { handler, store, documents, admin: admin?.db, close: () => store.close() };
}

const CONTRACT_HEADERS = {
  'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow',
};

/** The hosted signing page for a private link. No inline script or style, so the CSP can forbid both. */
async function contractPage(base: string, token: string): Promise<string> {
  const revision = await contractAssetRevision();
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><link rel="icon" href="data:,"><title>Sign agreement</title><link rel="stylesheet" href="${base}/assets/sealform.css?v=${revision}"><link rel="stylesheet" href="${base}/assets/contract.css?v=${revision}"></head><body><main><div id="sign" data-endpoint="${base}" data-token="${token}"></div><noscript><p>Signing needs JavaScript.</p></noscript></main><script type="module" src="${base}/assets/contract.js?v=${revision}"></script></body></html>`;
}

const CONTRACT_JS = "const { mountSealform } = await import('./sealform.js' + new URL(import.meta.url).search);\nconst el = document.getElementById('sign');\nmountSealform(el, { endpoint: el.dataset.endpoint, envelopeToken: el.dataset.token });\n";
const CONTRACT_CSS = 'body{margin:0;background:#fbfaf7;font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}main{max-width:46rem;margin:0 auto;padding:2rem 1rem}';

let assetRevision: Promise<string> | undefined;
function contractAssetRevision(): Promise<string> {
  return assetRevision ??= Promise.all(['sealform.js', 'sealform.css'].map(contractAsset)).then((assets) => {
    const hash = createHash('sha256').update(CONTRACT_JS).update(CONTRACT_CSS);
    for (const asset of assets) { if (!asset) throw new Error('Build the signing client before serving private links'); hash.update(asset.body); }
    return hash.digest('hex').slice(0, 16);
  });
}

async function contractAsset(name: string): Promise<{ type: string; body: Uint8Array } | undefined> {
  if (name === 'contract.js') return { type: 'text/javascript; charset=utf-8', body: Buffer.from(CONTRACT_JS) };
  if (name === 'contract.css') return { type: 'text/css; charset=utf-8', body: Buffer.from(CONTRACT_CSS) };
  const files: Record<string, string> = { 'sealform.js': 'text/javascript; charset=utf-8', 'sealform.css': 'text/css; charset=utf-8', 'sealform.js.LEGAL.txt': 'text/plain; charset=utf-8' };
  if (!files[name]) return undefined;
  // Built package: dist/server -> dist/client. Running from source: src/server -> dist/client.
  for (const relative of ['../client/', '../../dist/client/']) {
    try {
      return { type: files[name]!, body: await readFile(fileURLToPath(new URL(`${relative}${name}`, import.meta.url))) };
    } catch {
      // try the next layout
    }
  }
  return undefined;
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
export { hashPassword, passwordProblem, ROLES, type Role } from './admin/index.ts';
export { CloudflareAccess, type AccessConfig, type AccessIdentity } from './admin/access.ts';
export { AdminStore } from './admin/db.ts';
export { DocumentRegistry, type DocumentManifest, type FieldSpec, type ConsentSpec } from './documents.ts';
export { NoBotCheck, RateLimiter, TurnstileCheck, type BotCheck } from './guards.ts';
export { OutboxMailer, toMime, type Mailer, type MailMessage } from './mailer.ts';
export { SqliteStore, type RecordSummary } from './store.ts';
export { SiteLayer, normalizePrefix, DEFAULT_PARKING_ALLOW, type SiteConfig } from './site.ts';
export { ProfileRegistry, durationYears, profileHealth, retentionReview, type Profile, type LoadedProfile } from './profiles.ts';
export { ValidationError } from './validate.ts';
export { isCountryCode } from '../core/index.ts';

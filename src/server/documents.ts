// Versioned documents. Each version is a folder: <documentsDir>/<id>/<version>/document.json plus one
// <lang>.md text per language. A published version is immutable: its text and manifest hashes are
// computed at load and every signature is checked against them.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sha256Canonical, sha256Hex } from '../core/index.ts';
import type { Check } from './checks.ts';

export type FieldType = 'text' | 'email' | 'country' | 'select' | 'textarea' | 'checkbox';

export interface FieldSpec {
  name: string;
  label: string;
  type: FieldType;
  required?: boolean;
  maxLength?: number;
  /** For select fields. */
  options?: string[];
  help?: string;
  /** signerName: the typed signature must match it. receiptEmail: where the receipt goes. */
  role?: 'signerName' | 'receiptEmail' | 'country';
}

export interface ConsentSpec {
  name: string;
  label: string;
  required: boolean;
}

export type DocumentStatus = 'draft' | 'published' | 'closed';

export interface DocumentManifest {
  id: string;
  version: string;
  title: string;
  /** Matched against jurisdiction form requirements, for example "nda" or "services-contract". */
  category: string;
  status: DocumentStatus;
  languages: string[];
  governingLang: string;
  /** The e-sign disclosure the signer must accept, itself a document in the same registry. */
  disclosure?: { id: string; version: string };
  fields: FieldSpec[];
  consents: ConsentSpec[];
  requiredChecks: string[];
  retention: { signed: string; unsigned: string };
  /** Only listed in the public API when true. Contract documents use private links instead. */
  public: boolean;
}

export interface LoadedText {
  lang: string;
  text: string;
  sha256: string;
}

export interface LoadedDocument {
  manifest: DocumentManifest;
  manifestSha256: string;
  texts: Map<string, LoadedText>;
}

const ID = /^[a-z0-9][a-z0-9._-]{0,63}$/i;
const LANG = /^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$/;
const DURATION = /^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?$/;

export class DocumentRegistry {
  private readonly versions = new Map<string, Map<string, LoadedDocument>>();
  /** Status set from the admin dashboard; it overrides the status in document.json. */
  private readonly overrides = new Map<string, DocumentStatus>();
  private checks = new Map<string, Check>();

  static async load(dir: string, checks: Map<string, Check>): Promise<DocumentRegistry> {
    const registry = new DocumentRegistry();
    registry.checks = checks;
    for (const id of await subdirs(dir)) {
      for (const version of await subdirs(join(dir, id))) {
        const doc = await loadVersion(join(dir, id, version), checks);
        if (doc.manifest.id !== id || doc.manifest.version !== version) {
          throw new Error(`${join(dir, id, version)}: folder names must match the manifest id and version`);
        }
        registry.add(doc);
      }
    }
    for (const doc of registry.all()) {
      const ref = doc.manifest.disclosure;
      if (ref && !registry.get(ref.id, ref.version)) throw new Error(`${doc.manifest.id}@${doc.manifest.version}: disclosure ${ref.id}@${ref.version} not found`);
    }
    return registry;
  }

  add(doc: LoadedDocument): void {
    const byVersion = this.versions.get(doc.manifest.id) ?? new Map<string, LoadedDocument>();
    byVersion.set(doc.manifest.version, doc);
    this.versions.set(doc.manifest.id, byVersion);
  }

  get(id: string, version: string): LoadedDocument | undefined {
    return this.versions.get(id)?.get(version);
  }

  status(doc: LoadedDocument): DocumentStatus {
    return this.overrides.get(key(doc.manifest.id, doc.manifest.version)) ?? doc.manifest.status;
  }

  /** Applies saved overrides without the publish checks; used when loading from the database. */
  restoreStatus(id: string, version: string, status: DocumentStatus): void {
    if (this.get(id, version)) this.overrides.set(key(id, version), status);
  }

  /**
   * Publishes, closes or returns a version to draft. Publishing closes any other published version of
   * the same document, so exactly one is open at a time. Returns every change made, for the audit log.
   */
  setStatus(id: string, version: string, status: DocumentStatus): { id: string; version: string; from: DocumentStatus; to: DocumentStatus }[] {
    const doc = this.get(id, version);
    if (!doc) throw new Error(`No document ${id}@${version}`);
    if (status === 'published') {
      for (const kind of doc.manifest.requiredChecks) {
        if (!this.checks.get(kind)?.enabled) throw new Error(`Cannot publish: check "${kind}" is not configured`);
      }
    }
    const changes: { id: string; version: string; from: DocumentStatus; to: DocumentStatus }[] = [];
    if (status === 'published') {
      for (const other of this.versions.get(id)!.values()) {
        if (other !== doc && this.status(other) === 'published') {
          changes.push({ id, version: other.manifest.version, from: 'published', to: 'closed' });
          this.overrides.set(key(id, other.manifest.version), 'closed');
        }
      }
    }
    const from = this.status(doc);
    if (from !== status) {
      changes.push({ id, version, from, to: status });
      this.overrides.set(key(id, version), status);
    }
    return changes;
  }

  /** The one published version of a document. Two published versions at once is a config error. */
  current(id: string): LoadedDocument | undefined {
    const published = [...(this.versions.get(id)?.values() ?? [])].filter((doc) => this.status(doc) === 'published');
    if (published.length > 1) throw new Error(`${id} has more than one published version; close the old one`);
    return published[0];
  }

  all(): LoadedDocument[] {
    return [...this.versions.values()].flatMap((byVersion) => [...byVersion.values()]);
  }
}

async function loadVersion(dir: string, checks: Map<string, Check>): Promise<LoadedDocument> {
  const manifest = validateManifest(JSON.parse(await readFile(join(dir, 'document.json'), 'utf8')), dir);
  if (manifest.status === 'published') {
    for (const kind of manifest.requiredChecks) {
      const check = checks.get(kind);
      if (!check) throw new Error(`${dir}: requires unknown check "${kind}"`);
      if (!check.enabled) throw new Error(`${dir}: requires check "${kind}", which is not configured. It cannot be published until it is.`);
    }
  }
  const texts = new Map<string, LoadedText>();
  for (const lang of manifest.languages) {
    // Normalize line endings so a checkout on Windows hashes the same as one on Linux.
    const text = (await readFile(join(dir, `${lang}.md`), 'utf8')).replace(/\r\n?/g, '\n');
    texts.set(lang, { lang, text, sha256: await sha256Hex(text) });
  }
  return { manifest, manifestSha256: await sha256Canonical(signerVisible(manifest)), texts };
}

/**
 * The part of a manifest the signer sees. Only this is hashed into records, so operational settings
 * (status, retention, listing) can change without breaking the hash older records point to.
 */
export function signerVisible(manifest: DocumentManifest) {
  const { id, version, title, category, languages, governingLang, disclosure, fields, consents } = manifest;
  return { id, version, title, category, languages, governingLang, disclosure, fields, consents };
}

function validateManifest(value: unknown, where: string): DocumentManifest {
  const fail = (message: string): never => {
    throw new Error(`${where}/document.json: ${message}`);
  };
  const m = value as Partial<DocumentManifest>;
  if (!m || typeof m !== 'object') fail('not an object');
  if (typeof m.id !== 'string' || !ID.test(m.id)) fail('id must be 1-64 letters, digits, dot, underscore or hyphen');
  if (typeof m.version !== 'string' || !ID.test(m.version)) fail('version must be 1-64 letters, digits, dot, underscore or hyphen');
  if (typeof m.title !== 'string' || !m.title.trim()) fail('title is required');
  if (typeof m.category !== 'string' || !m.category) fail('category is required');
  if (!['draft', 'published', 'closed'].includes(m.status as string)) fail('status must be draft, published or closed');
  if (!Array.isArray(m.languages) || m.languages.length === 0 || !m.languages.every((l) => typeof l === 'string' && LANG.test(l))) fail('languages must list language tags');
  if (typeof m.governingLang !== 'string' || !m.languages!.includes(m.governingLang)) fail('governingLang must be one of languages');
  if (!Array.isArray(m.fields)) fail('fields must be an array');
  if (!Array.isArray(m.consents)) fail('consents must be an array');
  if (!Array.isArray(m.requiredChecks)) fail('requiredChecks must be an array');
  if (typeof m.public !== 'boolean') fail('public must be true or false');
  if (!m.retention || !DURATION.test(m.retention.signed ?? '') || !DURATION.test(m.retention.unsigned ?? '')) fail('retention.signed and retention.unsigned must be ISO 8601 durations such as P4Y');

  const names = new Set<string>();
  for (const field of m.fields!) {
    if (!field || typeof field.name !== 'string' || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(field.name)) fail('every field needs a name of letters, digits and underscores');
    if (names.has(field.name)) fail(`duplicate field ${field.name}`);
    names.add(field.name);
    if (typeof field.label !== 'string' || !field.label) fail(`field ${field.name} needs a label`);
    if (!['text', 'email', 'country', 'select', 'textarea', 'checkbox'].includes(field.type)) fail(`field ${field.name} has unknown type ${String(field.type)}`);
    if (field.type === 'select' && (!Array.isArray(field.options) || field.options.length === 0)) fail(`select field ${field.name} needs options`);
  }
  for (const role of ['signerName', 'receiptEmail'] as const) {
    if (m.fields!.filter((field) => field.role === role).length > 1) fail(`only one field can have role ${role}`);
  }
  if (m.status !== 'draft' && m.category !== 'disclosure' && !m.fields!.some((field) => field.role === 'signerName')) fail('a signable document needs a field with role "signerName"');
  for (const consent of m.consents!) {
    if (!consent || typeof consent.name !== 'string' || typeof consent.label !== 'string' || typeof consent.required !== 'boolean') fail('every consent needs name, label and required');
  }
  return m as DocumentManifest;
}

function key(id: string, version: string): string {
  return `${id}@${version}`;
}

async function subdirs(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  return entries.filter((entry) => entry.isDirectory() && !entry.name.startsWith('.')).map((entry) => entry.name).sort();
}

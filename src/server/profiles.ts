// Jurisdiction profiles: one JSON file per country (or region) describing how a simple electronic
// signature is treated there, what the signer should be shown, and which kinds of document need more.
// The signer's declared country picks the profile; its hash goes into the record so the evidence shows
// exactly which rules and notices applied. Profiles are data, not legal advice.

import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isCountryCode, sha256Canonical } from '../core/index.ts';

export interface FormRequirement {
  /** Matches a document's `category`, such as "will", "real-estate" or "family". */
  category: string;
  /** What the law asks for instead of (or beyond) a simple electronic signature. */
  requires: 'qes' | 'wet-ink' | 'notarization' | 'witness';
  note: string;
}

export interface ProfileField {
  name: string;
  label: string;
  type: 'text' | 'select' | 'checkbox';
  required?: boolean;
  options?: string[];
  maxLength?: number;
}

export interface ProfileSource {
  title: string;
  url: string;
}

export interface Profile {
  id: string;
  version: number;
  name: string;
  parent?: string;
  eSignLaw: { name: string; citation: string };
  level: 'ses';
  levelNote: string;
  ageOfMajority: number;
  ageNote?: string;
  formRequirements: FormRequirement[];
  /** Extra fields shown and required for signers in this country. */
  requiredFields: ProfileField[];
  /** Text shown to the signer before signing; its hash is stored in the record. */
  notices: string[];
  privacyRegime: string;
  /** Usual period for contract claims, as an ISO 8601 duration. Outer caps are in the note. */
  limitationPeriod: string;
  limitationNote: string;
  /** Date the facts were written down. */
  drafted: string;
  /** Who reviewed it, and when. Null until a lawyer has. */
  reviewedBy: { name: string; on: string } | null;
  sources: ProfileSource[];
}

export interface LoadedProfile {
  profile: Profile;
  /** SHA-256 of the part the signer sees. */
  sha256: string;
}

export const BUILTIN_PROFILES_DIR = fileURLToPath(new URL('../../profiles/', import.meta.url));

const ID = /^(default|[A-Z]{2}(-[A-Z0-9]{1,3})?)$/;
const DURATION = /^P(?!$)(\d+Y)?(\d+M)?(\d+W)?(\d+D)?$/;
const REQUIRES = ['qes', 'wet-ink', 'notarization', 'witness'];

/** What the signer sees. Operational fields (sources, review state) are not part of the hash. */
export function signerVisible(p: Profile) {
  return { id: p.id, version: p.version, name: p.name, eSignLaw: p.eSignLaw, level: p.level, levelNote: p.levelNote, ageOfMajority: p.ageOfMajority, ageNote: p.ageNote ?? null, formRequirements: p.formRequirements, requiredFields: p.requiredFields, notices: p.notices };
}

export class ProfileRegistry {
  private readonly byId = new Map<string, LoadedProfile>();

  static async load(dir: string = BUILTIN_PROFILES_DIR): Promise<ProfileRegistry> {
    const registry = new ProfileRegistry();
    for (const file of (await readdir(dir)).filter((f) => f.endsWith('.json')).sort()) {
      const profile = validate(JSON.parse(await readFile(join(dir, file), 'utf8')), file);
      if (registry.byId.has(profile.id)) throw new Error(`${file}: duplicate profile ${profile.id}`);
      registry.byId.set(profile.id, { profile, sha256: await sha256Canonical(signerVisible(profile)) });
    }
    if (!registry.byId.has('default')) throw new Error(`${dir} needs a default.json profile for countries without their own`);
    for (const { profile } of registry.byId.values()) {
      if (profile.parent && !registry.byId.has(profile.parent)) throw new Error(`${profile.id}: parent ${profile.parent} not found`);
    }
    return registry;
  }

  get(id: string): LoadedProfile | undefined {
    return this.byId.get(id);
  }

  /** The profile for a declared country, or the cautious default when there is none. */
  resolve(country: string): { loaded: LoadedProfile; fallback: boolean } {
    const own = isCountryCode(country) ? this.byId.get(country) : undefined;
    return own ? { loaded: own, fallback: false } : { loaded: this.byId.get('default')!, fallback: true };
  }

  all(): LoadedProfile[] {
    return [...this.byId.values()].sort((a, b) => a.profile.id.localeCompare(b.profile.id));
  }
}

/** Flags for the dashboard: facts go stale, and nothing here is reviewed until someone says so. */
export function profileHealth(profile: Profile, now: Date): { stale: boolean; unreviewed: boolean } {
  const reference = new Date(profile.reviewedBy?.on ?? profile.drafted);
  return { stale: now.getTime() - reference.getTime() > 365 * 24 * 3600 * 1000, unreviewed: profile.reviewedBy === null };
}

function validate(value: unknown, file: string): Profile {
  const fail = (message: string): never => {
    throw new Error(`${file}: ${message}`);
  };
  const p = value as Partial<Profile>;
  if (!p || typeof p !== 'object') fail('not an object');
  if (typeof p.id !== 'string' || !ID.test(p.id)) fail('id must be default, a country code like DE, or a region like US-CA');
  if (p.id !== 'default' && !isCountryCode(p.id!.slice(0, 2))) fail('id does not start with an official country code');
  if (file !== `${p.id}.json`) fail(`file name must be ${p.id}.json`);
  if (!Number.isInteger(p.version) || p.version! < 1) fail('version must be a positive integer');
  for (const key of ['name', 'levelNote', 'privacyRegime', 'limitationNote'] as const) if (typeof p[key] !== 'string' || !p[key]) fail(`${key} is required`);
  if (!p.eSignLaw || typeof p.eSignLaw.name !== 'string' || typeof p.eSignLaw.citation !== 'string') fail('eSignLaw needs name and citation');
  if (p.level !== 'ses') fail('level must be ses; stronger levels come from checks, not profiles');
  if (!Number.isInteger(p.ageOfMajority) || p.ageOfMajority! < 14 || p.ageOfMajority! > 25) fail('ageOfMajority must be a plausible whole number');
  if (typeof p.limitationPeriod !== 'string' || !DURATION.test(p.limitationPeriod)) fail('limitationPeriod must be an ISO 8601 duration');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(p.drafted ?? '')) fail('drafted must be a YYYY-MM-DD date');
  if (!Array.isArray(p.notices) || !p.notices.length || !p.notices.every((n) => typeof n === 'string' && n)) fail('notices must be a non-empty list of text');
  if (!Array.isArray(p.formRequirements)) fail('formRequirements must be a list');
  for (const r of p.formRequirements!) if (!r || typeof r.category !== 'string' || !REQUIRES.includes(r.requires) || typeof r.note !== 'string') fail('every form requirement needs category, requires and note');
  if (!Array.isArray(p.requiredFields)) fail('requiredFields must be a list');
  for (const f of p.requiredFields!) {
    if (!f || !/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(f.name) || typeof f.label !== 'string' || !['text', 'select', 'checkbox'].includes(f.type)) fail('every required field needs a name, label and type');
    if (f.type === 'select' && (!Array.isArray(f.options) || !f.options.length)) fail(`select field ${f.name} needs options`);
  }
  if (!Array.isArray(p.sources) || !p.sources.length || !p.sources.every((s) => s && typeof s.title === 'string' && /^https:\/\//.test(s.url))) fail('sources need a title and an https url');
  if (p.reviewedBy !== null && !(p.reviewedBy && typeof p.reviewedBy.name === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(p.reviewedBy.on))) fail('reviewedBy must be null or { name, on }');
  return p as Profile;
}

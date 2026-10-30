// Admin tables, in the same SQLite file as the records.

import type { DatabaseSync } from 'node:sqlite';
import { appendFile } from 'node:fs/promises';
import { join } from 'node:path';
import { AUDIT_FORMAT, prefixedId, sealRecord, ZERO_HASH, type AuditEntry, type JsonValue, type SealingKey } from '../../core/index.ts';
import type { DocumentStatus } from '../documents.ts';

export type Role = 'owner' | 'admin' | 'reviewer';
export const ROLES: Role[] = ['owner', 'admin', 'reviewer'];

export interface Account {
  id: string;
  email: string;
  name: string;
  role: Role;
  passwordHash: string;
  totpSecret: string | null;
  totpLastStep: number | null;
  failedLogins: number;
  lockedUntil: string | null;
  disabled: boolean;
  mustChangePassword: boolean;
  createdAt: string;
}

export interface AdminSession {
  id: string;
  accountId: string;
  /** "pending" between password and two-factor code, "active" after. */
  stage: 'pending' | 'active';
  csrf: string;
  createdAt: string;
  lastSeenAt: string;
  expiresAt: string;
  ip: string;
  userAgent: string;
}

export interface SignIn {
  at: string;
  accountId: string | null;
  email: string;
  ip: string;
  userAgent: string;
  result: string;
}

export interface SubmissionFilter {
  documentId?: string;
  status?: string;
  country?: string;
  query?: string;
  limit: number;
  offset: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE COLLATE NOCASE,
  name TEXT NOT NULL,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  totp_secret TEXT,
  totp_pending TEXT,
  totp_last_step INTEGER,
  failed_logins INTEGER NOT NULL DEFAULT 0,
  locked_until TEXT,
  disabled INTEGER NOT NULL DEFAULT 0,
  must_change_password INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS admin_sessions (
  token_hash TEXT PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  stage TEXT NOT NULL,
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sign_ins (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  account_id TEXT,
  email TEXT NOT NULL,
  ip TEXT NOT NULL,
  user_agent TEXT NOT NULL,
  result TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sign_ins_account ON sign_ins (account_id, seq);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  at TEXT NOT NULL,
  actor_email TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  hash TEXT NOT NULL,
  entry_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS document_status (
  document_id TEXT NOT NULL,
  version TEXT NOT NULL,
  status TEXT NOT NULL,
  PRIMARY KEY (document_id, version)
);
`;

export class AdminStore {
  private readonly db: DatabaseSync;
  private readonly dataDir: string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(db: DatabaseSync, dataDir: string) {
    this.db = db;
    this.dataDir = dataDir;
    this.db.exec(SCHEMA);
  }

  // Accounts -------------------------------------------------------------------------------------

  accountCount(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM accounts').get() as { n: number }).n;
  }

  createAccount(input: { email: string; name: string; role: Role; passwordHash: string; mustChangePassword: boolean; now: string }): Account {
    const id = prefixedId('acct');
    this.db
      .prepare('INSERT INTO accounts (id, email, name, role, password_hash, must_change_password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, input.email.trim().toLowerCase(), input.name.trim(), input.role, input.passwordHash, input.mustChangePassword ? 1 : 0, input.now);
    return this.account(id)!;
  }

  account(id: string): Account | undefined {
    return toAccount(this.db.prepare('SELECT * FROM accounts WHERE id = ?').get(id));
  }

  accountByEmail(email: string): Account | undefined {
    return toAccount(this.db.prepare('SELECT * FROM accounts WHERE email = ?').get(email.trim().toLowerCase()));
  }

  accounts(): Account[] {
    return (this.db.prepare('SELECT * FROM accounts ORDER BY created_at').all() as unknown[]).map((row) => toAccount(row)!);
  }

  activeOwnerCount(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM accounts WHERE role = 'owner' AND disabled = 0").get() as { n: number }).n;
  }

  recordFailure(id: string, lockUntil: string | null): void {
    this.db.prepare('UPDATE accounts SET failed_logins = failed_logins + 1, locked_until = COALESCE(?, locked_until) WHERE id = ?').run(lockUntil, id);
  }

  clearFailures(id: string): void {
    this.db.prepare('UPDATE accounts SET failed_logins = 0, locked_until = NULL WHERE id = ?').run(id);
  }

  setPassword(id: string, passwordHash: string, mustChange: boolean): void {
    this.db.prepare('UPDATE accounts SET password_hash = ?, must_change_password = ? WHERE id = ?').run(passwordHash, mustChange ? 1 : 0, id);
  }

  setRole(id: string, role: Role): void {
    this.db.prepare('UPDATE accounts SET role = ? WHERE id = ?').run(role, id);
  }

  setDisabled(id: string, disabled: boolean): void {
    this.db.prepare('UPDATE accounts SET disabled = ? WHERE id = ?').run(disabled ? 1 : 0, id);
  }

  setPendingTotp(id: string, secret: string | null): void {
    this.db.prepare('UPDATE accounts SET totp_pending = ? WHERE id = ?').run(secret, id);
  }

  pendingTotp(id: string): string | null {
    return (this.db.prepare('SELECT totp_pending FROM accounts WHERE id = ?').get(id) as { totp_pending: string | null } | undefined)?.totp_pending ?? null;
  }

  enableTotp(id: string, secret: string, step: number): void {
    this.db.prepare('UPDATE accounts SET totp_secret = ?, totp_pending = NULL, totp_last_step = ? WHERE id = ?').run(secret, step, id);
  }

  disableTotp(id: string): void {
    this.db.prepare('UPDATE accounts SET totp_secret = NULL, totp_pending = NULL, totp_last_step = NULL WHERE id = ?').run(id);
  }

  useTotpStep(id: string, step: number): void {
    this.db.prepare('UPDATE accounts SET totp_last_step = ? WHERE id = ?').run(step, id);
  }

  // Sessions -------------------------------------------------------------------------------------

  createSession(tokenHash: string, session: AdminSession): void {
    this.db
      .prepare('INSERT INTO admin_sessions (token_hash, id, account_id, stage, csrf, created_at, last_seen_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(tokenHash, session.id, session.accountId, session.stage, session.csrf, session.createdAt, session.lastSeenAt, session.expiresAt, session.ip, session.userAgent);
  }

  sessionByToken(tokenHash: string): AdminSession | undefined {
    return toSession(this.db.prepare('SELECT * FROM admin_sessions WHERE token_hash = ?').get(tokenHash));
  }

  touchSession(id: string, at: string): void {
    this.db.prepare('UPDATE admin_sessions SET last_seen_at = ? WHERE id = ?').run(at, id);
  }

  sessionsFor(accountId: string, now: string): AdminSession[] {
    return (this.db.prepare("SELECT * FROM admin_sessions WHERE account_id = ? AND expires_at > ? AND stage = 'active' ORDER BY last_seen_at DESC").all(accountId, now) as unknown[]).map((row) => toSession(row)!);
  }

  deleteSession(id: string): void {
    this.db.prepare('DELETE FROM admin_sessions WHERE id = ?').run(id);
  }

  deleteSessionsFor(accountId: string, exceptId?: string): void {
    this.db.prepare('DELETE FROM admin_sessions WHERE account_id = ? AND id != ?').run(accountId, exceptId ?? '');
  }

  purgeSessions(now: string): void {
    this.db.prepare('DELETE FROM admin_sessions WHERE expires_at < ?').run(now);
  }

  // Sign-ins -------------------------------------------------------------------------------------

  logSignIn(entry: SignIn): void {
    this.db.prepare('INSERT INTO sign_ins (at, account_id, email, ip, user_agent, result) VALUES (?, ?, ?, ?, ?, ?)').run(entry.at, entry.accountId, entry.email.slice(0, 254), entry.ip, entry.userAgent.slice(0, 300), entry.result);
  }

  signIns(accountId: string | null, limit = 200): SignIn[] {
    const rows = accountId
      ? this.db.prepare('SELECT * FROM sign_ins WHERE account_id = ? ORDER BY seq DESC LIMIT ?').all(accountId, limit)
      : this.db.prepare('SELECT * FROM sign_ins ORDER BY seq DESC LIMIT ?').all(limit);
    return (rows as Record<string, unknown>[]).map((row) => ({
      at: row.at as string,
      accountId: (row.account_id as string | null) ?? null,
      email: row.email as string,
      ip: row.ip as string,
      userAgent: row.user_agent as string,
      result: row.result as string,
    }));
  }

  // Audit log ------------------------------------------------------------------------------------

  /** Appends a sealed entry to the audit chain. Entries are also mirrored to audit.jsonl. */
  audit(
    key: SealingKey,
    input: { at: string; actor: { id: string; email: string } | 'system'; action: string; target: string; details?: Record<string, JsonValue>; ip: string },
  ): Promise<AuditEntry> {
    const run = async (): Promise<AuditEntry> => {
      this.db.exec('BEGIN IMMEDIATE');
      let entry: AuditEntry;
      try {
        const head = this.db.prepare('SELECT seq, hash FROM audit ORDER BY seq DESC LIMIT 1').get() as { seq: number; hash: string } | undefined;
        const chain = head ? { seq: head.seq + 1, prevHash: head.hash } : { seq: 0, prevHash: ZERO_HASH };
        entry = await sealRecord(
          { format: AUDIT_FORMAT, id: prefixedId('aud'), at: input.at, actor: input.actor, action: input.action, target: input.target, details: input.details ?? {}, ip: input.ip, chain },
          key,
        );
        this.db
          .prepare('INSERT INTO audit (seq, id, at, actor_email, action, target, hash, entry_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
          .run(chain.seq, entry.id, entry.at, input.actor === 'system' ? 'system' : input.actor.email, entry.action, entry.target, entry.hash, JSON.stringify(entry));
        this.db.exec('COMMIT');
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
      await appendFile(join(this.dataDir, 'audit.jsonl'), JSON.stringify(entry) + '\n', { mode: 0o600 });
      return entry;
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  auditEntries(limit?: number): AuditEntry[] {
    const rows = limit
      ? this.db.prepare('SELECT entry_json FROM audit ORDER BY seq DESC LIMIT ?').all(limit)
      : this.db.prepare('SELECT entry_json FROM audit ORDER BY seq').all();
    return (rows as { entry_json: string }[]).map((row) => JSON.parse(row.entry_json) as AuditEntry);
  }

  // Document status ------------------------------------------------------------------------------

  documentStatuses(): { documentId: string; version: string; status: DocumentStatus }[] {
    return (this.db.prepare('SELECT * FROM document_status').all() as Record<string, string>[]).map((row) => ({
      documentId: row.document_id!,
      version: row.version!,
      status: row.status as DocumentStatus,
    }));
  }

  saveDocumentStatus(documentId: string, version: string, status: DocumentStatus): void {
    this.db
      .prepare('INSERT INTO document_status (document_id, version, status) VALUES (?, ?, ?) ON CONFLICT (document_id, version) DO UPDATE SET status = excluded.status')
      .run(documentId, version, status);
  }

  // Submissions ----------------------------------------------------------------------------------

  submissions(filter: SubmissionFilter): { rows: Record<string, unknown>[]; total: number } {
    const where: string[] = [];
    const params: (string | number)[] = [];
    if (filter.documentId) {
      where.push('document_id = ?');
      params.push(filter.documentId);
    }
    if (filter.status) {
      where.push('application_status = ?');
      params.push(filter.status);
    }
    if (filter.country) {
      where.push('country = ?');
      params.push(filter.country);
    }
    if (filter.query) {
      where.push("(signer_name LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR id = ?)");
      const like = `%${filter.query.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
      params.push(like, like, filter.query);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    const total = (this.db.prepare(`SELECT COUNT(*) AS n FROM records ${clause}`).get(...params) as { n: number }).n;
    const rows = this.db
      .prepare(`SELECT seq, id, document_id, document_version, signer_name, email, country, received_at, hash, hold, application_status, tombstoned_at FROM records ${clause} ORDER BY seq DESC LIMIT ? OFFSET ?`)
      .all(...params, filter.limit, filter.offset) as Record<string, unknown>[];
    return { rows, total };
  }

  setApplicationStatus(id: string, status: string): boolean {
    return Number(this.db.prepare('UPDATE records SET application_status = ? WHERE id = ?').run(status, id).changes) === 1;
  }

  setHold(id: string, hold: boolean): boolean {
    return Number(this.db.prepare('UPDATE records SET hold = ? WHERE id = ?').run(hold ? 1 : 0, id).changes) === 1;
  }

  countsByStatus(): Record<string, number> {
    const rows = this.db.prepare('SELECT application_status AS s, COUNT(*) AS n FROM records GROUP BY application_status').all() as { s: string; n: number }[];
    return Object.fromEntries(rows.map((row) => [row.s, row.n]));
  }
}

function toAccount(row: unknown): Account | undefined {
  if (!row) return undefined;
  const r = row as Record<string, unknown>;
  return {
    id: r.id as string,
    email: r.email as string,
    name: r.name as string,
    role: r.role as Role,
    passwordHash: r.password_hash as string,
    totpSecret: (r.totp_secret as string | null) ?? null,
    totpLastStep: (r.totp_last_step as number | null) ?? null,
    failedLogins: r.failed_logins as number,
    lockedUntil: (r.locked_until as string | null) ?? null,
    disabled: r.disabled === 1,
    mustChangePassword: r.must_change_password === 1,
    createdAt: r.created_at as string,
  };
}

function toSession(row: unknown): AdminSession | undefined {
  if (!row) return undefined;
  const r = row as Record<string, string>;
  return {
    id: r.id!,
    accountId: r.account_id!,
    stage: r.stage as 'pending' | 'active',
    csrf: r.csrf!,
    createdAt: r.created_at!,
    lastSeenAt: r.last_seen_at!,
    expiresAt: r.expires_at!,
    ip: r.ip!,
    userAgent: r.user_agent!,
  };
}

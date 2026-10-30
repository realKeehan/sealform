// Storage. SQLite through node:sqlite (no native build, which matters on shared hosting), with every
// sealed entry mirrored to files so the evidence survives losing the database:
//   <dataDir>/sealform.sqlite
//   <dataDir>/records/<id>.json | .png | .pdf
//   <dataDir>/chain.jsonl            one entry per line, in sequence order

import { appendFile, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { ZERO_HASH, type ChainEntry, type ChainLink, type SealformRecord } from '../core/index.ts';

export interface SessionRow {
  id: string;
  documentId: string;
  documentVersion: string;
  lang: string;
  openedAt: string;
  expiresAt: string;
  usedAt: string | null;
}

export interface RecordSummary {
  seq: number;
  id: string;
  documentId: string;
  documentVersion: string;
  signerName: string | null;
  email: string | null;
  country: string | null;
  receivedAt: string | null;
  hash: string;
  pdfSha256: string | null;
  hold: boolean;
  applicationStatus: string;
  tombstonedAt: string | null;
}

export interface AppendMeta {
  signerName: string | null;
  email: string | null;
  country: string | null;
  receiptTokenHash: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS records (
  seq INTEGER PRIMARY KEY,
  id TEXT NOT NULL UNIQUE,
  document_id TEXT NOT NULL,
  document_version TEXT NOT NULL,
  signer_name TEXT,
  email TEXT,
  country TEXT,
  received_at TEXT,
  hash TEXT NOT NULL,
  entry_json TEXT NOT NULL,
  pdf_sha256 TEXT,
  receipt_token_hash TEXT UNIQUE,
  hold INTEGER NOT NULL DEFAULT 0,
  application_status TEXT NOT NULL DEFAULT 'pending',
  tombstoned_at TEXT
);
CREATE INDEX IF NOT EXISTS records_document ON records (document_id, document_version);
CREATE INDEX IF NOT EXISTS records_email ON records (email);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  document_id TEXT NOT NULL,
  document_version TEXT NOT NULL,
  lang TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);
CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions (expires_at);
`;

export class SqliteStore {
  readonly dataDir: string;
  readonly recordsDir: string;
  private readonly db: DatabaseSync;
  private queue: Promise<unknown> = Promise.resolve();

  private constructor(dataDir: string) {
    this.dataDir = dataDir;
    this.recordsDir = join(dataDir, 'records');
    this.db = new DatabaseSync(join(dataDir, 'sealform.sqlite'));
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;');
    this.db.exec(SCHEMA);
  }

  static async open(dataDir: string): Promise<SqliteStore> {
    await mkdir(join(dataDir, 'records'), { recursive: true, mode: 0o700 });
    return new SqliteStore(dataDir);
  }

  close(): void {
    this.db.close();
  }

  /** The underlying connection, shared with the admin tables. */
  get database(): DatabaseSync {
    return this.db;
  }

  // Sessions -------------------------------------------------------------------------------------

  createSession(row: Omit<SessionRow, 'usedAt'>): void {
    this.db
      .prepare('INSERT INTO sessions (id, document_id, document_version, lang, opened_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)')
      .run(row.id, row.documentId, row.documentVersion, row.lang, row.openedAt, row.expiresAt);
  }

  getSession(id: string): SessionRow | undefined {
    const row = this.db.prepare('SELECT * FROM sessions WHERE id = ?').get(id) as Record<string, string | null> | undefined;
    if (!row) return undefined;
    return {
      id: row.id!,
      documentId: row.document_id!,
      documentVersion: row.document_version!,
      lang: row.lang!,
      openedAt: row.opened_at!,
      expiresAt: row.expires_at!,
      usedAt: row.used_at ?? null,
    };
  }

  /** Marks a session used. False when it was already used, so a session signs exactly once. */
  useSession(id: string, at: string): boolean {
    return Number(this.db.prepare('UPDATE sessions SET used_at = ? WHERE id = ? AND used_at IS NULL').run(at, id).changes) === 1;
  }

  /** Releases a session after a failed signing attempt so the signer can retry. */
  releaseSession(id: string): void {
    this.db.prepare('UPDATE sessions SET used_at = NULL WHERE id = ?').run(id);
  }

  purgeExpiredSessions(now: string): number {
    return Number(this.db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(now).changes);
  }

  // Records --------------------------------------------------------------------------------------

  head(): ChainLink & { hash: string } {
    const row = this.db.prepare('SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1').get() as { seq: number; hash: string } | undefined;
    return row ? { seq: row.seq + 1, prevHash: row.hash, hash: row.hash } : { seq: 0, prevHash: ZERO_HASH, hash: ZERO_HASH };
  }

  /**
   * Appends a record to the chain. `build` receives the next chain link and returns the sealed
   * record. Appends are serialized inside this process and by SQLite's write lock across processes,
   * so two signatures can never claim the same position.
   */
  append(build: (link: ChainLink) => Promise<SealformRecord>, meta: AppendMeta): Promise<SealformRecord> {
    const run = async (): Promise<SealformRecord> => {
      this.db.exec('BEGIN IMMEDIATE');
      let record: SealformRecord;
      try {
        const { seq, prevHash } = this.head();
        record = await build({ seq, prevHash });
        if (record.chain.seq !== seq || record.chain.prevHash !== prevHash) throw new Error('Record was built for a different chain position');
        this.db
          .prepare(
            `INSERT INTO records (seq, id, document_id, document_version, signer_name, email, country, received_at, hash, entry_json, receipt_token_hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(seq, record.id, record.document.id, record.document.version, meta.signerName, meta.email, meta.country, record.server.receivedAt, record.hash, JSON.stringify(record), meta.receiptTokenHash);
        this.db.exec('COMMIT');
      } catch (error) {
        this.db.exec('ROLLBACK');
        throw error;
      }
      const line = JSON.stringify(record);
      await writeFile(join(this.recordsDir, `${record.id}.json`), line + '\n', { mode: 0o600 });
      await appendFile(join(this.dataDir, 'chain.jsonl'), line + '\n', { mode: 0o600 });
      return record;
    };
    const result = this.queue.then(run, run);
    this.queue = result.catch(() => undefined);
    return result;
  }

  getEntry(id: string): ChainEntry | undefined {
    const row = this.db.prepare('SELECT entry_json FROM records WHERE id = ?').get(id) as { entry_json: string } | undefined;
    return row ? (JSON.parse(row.entry_json) as ChainEntry) : undefined;
  }

  findByReceiptToken(tokenHash: string): RecordSummary | undefined {
    const row = this.db.prepare('SELECT * FROM records WHERE receipt_token_hash = ?').get(tokenHash) as Record<string, unknown> | undefined;
    return row ? toSummary(row) : undefined;
  }

  /** Every entry in sequence order, for chain verification and export. */
  entries(fromSeq = 0): ChainEntry[] {
    return (this.db.prepare('SELECT entry_json FROM records WHERE seq >= ? ORDER BY seq').all(fromSeq) as { entry_json: string }[]).map(
      (row) => JSON.parse(row.entry_json) as ChainEntry,
    );
  }

  setPdfHash(id: string, sha256: string): void {
    this.db.prepare('UPDATE records SET pdf_sha256 = ? WHERE id = ?').run(sha256, id);
  }

  summary(id: string): RecordSummary | undefined {
    const row = this.db.prepare('SELECT * FROM records WHERE id = ?').get(id) as Record<string, unknown> | undefined;
    return row ? toSummary(row) : undefined;
  }

  count(): number {
    return (this.db.prepare('SELECT COUNT(*) AS n FROM records').get() as { n: number }).n;
  }
}

function toSummary(row: Record<string, unknown>): RecordSummary {
  return {
    seq: row.seq as number,
    id: row.id as string,
    documentId: row.document_id as string,
    documentVersion: row.document_version as string,
    signerName: (row.signer_name as string | null) ?? null,
    email: (row.email as string | null) ?? null,
    country: (row.country as string | null) ?? null,
    receivedAt: (row.received_at as string | null) ?? null,
    hash: row.hash as string,
    pdfSha256: (row.pdf_sha256 as string | null) ?? null,
    hold: row.hold === 1,
    applicationStatus: row.application_status as string,
    tombstonedAt: (row.tombstoned_at as string | null) ?? null,
  };
}

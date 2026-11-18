// Policy change notices: one email per signer, queued in the database and sent at a capped hourly rate,
// so a restart resumes where it stopped and the mail server's sending limit is never exceeded.

import { randomUUID } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { DatabaseSync } from 'node:sqlite';
import type { Mailer } from '../mailer.ts';

export interface NoticeConfig {
  /** Sends the notices. Defaults to the main mailer. */
  mailer?: Mailer;
  /** The From header, for example "Example Studio <noreply@example.com>". */
  from: string;
  /** Where replies go; the From address is usually not read. */
  replyTo: string;
  /** Extra addresses that get one copy of each notice, for your records. */
  copyTo?: string[];
  /** Emails sent per rolling hour at most. Keep it under the mail server's limit. Default 60. */
  perHour?: number;
  /** Shortest notice period, in days, unless a reason is given. Default 30. */
  minNoticeDays?: number;
  /**
   * Folder of draft notices (one JSON file each), written and synced from the policy repository. The
   * Notices page lists the ones not yet sent; nothing is emailed until an owner approves one.
   */
  draftsDir: string;
}

/** A draft notice file: `{ "id", "subject", "policies": [{ "name", "url" }], "summary", "effectiveOn" }`. */
export interface NoticeDraft {
  id: string;
  subject: string;
  policies: { name: string; url: string }[];
  summary: string;
  /** YYYY-MM-DD. Left out, the change takes effect the day the notice is approved. */
  effectiveOn?: string;
}

export interface Notice {
  id: string;
  /** The draft id it was approved from. */
  source: string;
  subject: string;
  summary: string;
  policies: { name: string; url: string }[];
  effectiveOn: string;
  createdBy: string;
  createdAt: string;
  total: number;
  sent: number;
  failed: number;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS notices (
  id TEXT PRIMARY KEY,
  source TEXT NOT NULL UNIQUE,
  subject TEXT NOT NULL,
  summary TEXT NOT NULL,
  policies_json TEXT NOT NULL,
  effective_on TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notice_deliveries (
  notice_id TEXT NOT NULL REFERENCES notices(id),
  email TEXT NOT NULL COLLATE NOCASE,
  status TEXT NOT NULL DEFAULT 'queued',
  attempts INTEGER NOT NULL DEFAULT 0,
  sent_at TEXT,
  last_error TEXT,
  PRIMARY KEY (notice_id, email)
);
CREATE INDEX IF NOT EXISTS notice_deliveries_queue ON notice_deliveries (status, notice_id);
`;

const MAX_ATTEMPTS = 3;

export class NoticeStore {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    this.db.exec(SCHEMA);
  }

  /** Everyone with a signed record that has not been withdrawn or tombstoned, one entry per email. */
  signerEmails(): string[] {
    const rows = this.db
      .prepare("SELECT DISTINCT lower(email) AS email FROM records WHERE email IS NOT NULL AND email <> '' AND tombstoned_at IS NULL AND application_status <> 'withdrawn' ORDER BY 1")
      .all() as { email: string }[];
    return rows.map((r) => r.email);
  }

  create(input: { source: string; subject: string; summary: string; policies: { name: string; url: string }[]; effectiveOn: string; createdBy: string; createdAt: string; recipients: string[] }): Notice {
    const id = randomUUID();
    const recipients = [...new Set(input.recipients.map((e) => e.trim().toLowerCase()).filter(Boolean))];
    this.db.exec('BEGIN IMMEDIATE');
    try {
      this.db
        .prepare('INSERT INTO notices (id, source, subject, summary, policies_json, effective_on, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
        .run(id, input.source, input.subject, input.summary, JSON.stringify(input.policies), input.effectiveOn, input.createdBy, input.createdAt);
      const add = this.db.prepare('INSERT INTO notice_deliveries (notice_id, email) VALUES (?, ?)');
      for (const email of recipients) add.run(id, email);
      this.db.exec('COMMIT');
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
    return this.get(id)!;
  }

  get(id: string): Notice | undefined {
    return this.list().find((n) => n.id === id);
  }

  list(): Notice[] {
    const rows = this.db
      .prepare(
        `SELECT n.*, COUNT(d.email) AS total,
           SUM(CASE WHEN d.status = 'sent' THEN 1 ELSE 0 END) AS sent,
           SUM(CASE WHEN d.status = 'failed' THEN 1 ELSE 0 END) AS failed
         FROM notices n LEFT JOIN notice_deliveries d ON d.notice_id = n.id
         GROUP BY n.id ORDER BY n.created_at DESC`,
      )
      .all() as Record<string, unknown>[];
    return rows.map((r) => ({
      id: r.id as string,
      source: r.source as string,
      subject: r.subject as string,
      summary: r.summary as string,
      policies: JSON.parse(r.policies_json as string) as { name: string; url: string }[],
      effectiveOn: r.effective_on as string,
      createdBy: r.created_by as string,
      createdAt: r.created_at as string,
      total: Number(r.total ?? 0),
      sent: Number(r.sent ?? 0),
      failed: Number(r.failed ?? 0),
    }));
  }

  sentSince(iso: string): number {
    return Number((this.db.prepare("SELECT COUNT(*) AS n FROM notice_deliveries WHERE status = 'sent' AND sent_at > ?").get(iso) as { n: number }).n);
  }

  queued(limit: number): { noticeId: string; email: string; attempts: number }[] {
    return (this.db
      .prepare("SELECT d.notice_id AS noticeId, d.email, d.attempts FROM notice_deliveries d JOIN notices n ON n.id = d.notice_id WHERE d.status = 'queued' ORDER BY n.created_at, d.email LIMIT ?")
      .all(limit) as { noticeId: string; email: string; attempts: number }[]);
  }

  markSent(noticeId: string, email: string, at: string): void {
    this.db.prepare("UPDATE notice_deliveries SET status = 'sent', sent_at = ?, attempts = attempts + 1, last_error = NULL WHERE notice_id = ? AND email = ?").run(at, noticeId, email);
  }

  markFailed(noticeId: string, email: string, error: string): void {
    this.db
      .prepare(`UPDATE notice_deliveries SET attempts = attempts + 1, last_error = ?, status = CASE WHEN attempts + 1 >= ${MAX_ATTEMPTS} THEN 'failed' ELSE 'queued' END WHERE notice_id = ? AND email = ?`)
      .run(error.slice(0, 200), noticeId, email);
  }

  /** Puts failed deliveries of a notice back in the queue. */
  retryFailed(noticeId: string): number {
    return Number(this.db.prepare("UPDATE notice_deliveries SET status = 'queued', attempts = 0 WHERE notice_id = ? AND status = 'failed'").run(noticeId).changes);
  }
}

const DRAFT_ID = /^[a-z0-9][a-z0-9-]{2,79}$/;

/** Reads and checks every draft. A bad file is reported, not skipped silently. */
export async function loadDrafts(dir: string): Promise<{ drafts: NoticeDraft[]; problems: string[] }> {
  const drafts: NoticeDraft[] = [];
  const problems: string[] = [];
  let files: string[] = [];
  try {
    files = (await readdir(dir)).filter((f) => f.endsWith('.json')).sort();
  } catch {
    return { drafts, problems: [`The drafts folder cannot be read`] };
  }
  for (const file of files) {
    try {
      const d = JSON.parse(await readFile(join(dir, file), 'utf8')) as Partial<NoticeDraft>;
      const why = draftProblem(d, file);
      if (why) problems.push(`${file}: ${why}`);
      else drafts.push(d as NoticeDraft);
    } catch {
      problems.push(`${file}: not valid JSON`);
    }
  }
  return { drafts, problems };
}

function draftProblem(d: Partial<NoticeDraft>, file: string): string | null {
  if (typeof d.id !== 'string' || !DRAFT_ID.test(d.id) || `${d.id}.json` !== file) return 'id must be lowercase letters, digits and hyphens, and match the file name';
  if (typeof d.subject !== 'string' || !d.subject.trim() || d.subject.length > 150 || /[\r\n]/.test(d.subject)) return 'subject must be one line of 1 to 150 characters';
  if (!Array.isArray(d.policies) || !d.policies.length || d.policies.length > 10 || !d.policies.every((p) => p && typeof p.name === 'string' && p.name.trim() && typeof p.url === 'string' && /^https:\/\/[^\s]+$/.test(p.url))) return 'policies must list 1 to 10 entries with a name and an https url';
  if (typeof d.summary !== 'string' || !d.summary.trim() || d.summary.length > 4000) return 'summary must be 1 to 4000 characters';
  if (d.effectiveOn !== undefined && (typeof d.effectiveOn !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d.effectiveOn) || Number.isNaN(Date.parse(`${d.effectiveOn}T00:00:00Z`)))) return 'effectiveOn, when given, must be a date like 2026-12-31';
  return null;
}

/** The email text: plain text, no tracking or images, in the style of a short product update. */
export function noticeText(notice: { summary: string; policies: { name: string; url: string }[]; effectiveOn: string }, operatorName: string, replyTo: string): string {
  const date = new Date(`${notice.effectiveOn}T00:00:00Z`).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
  const names = notice.policies.map((p) => p.name);
  const list = names.length > 1 ? `${names.slice(0, -1).join(', ')} and ${names.at(-1)}` : names[0];
  const one = notice.policies.length === 1;
  return [
    'Hello,',
    '',
    `On ${date}, we're making changes to our ${list}. Here's what's changing:`,
    '',
    notice.summary.trim(),
    '',
    `You can read the updated ${one ? 'version' : 'versions'} here:`,
    ...notice.policies.map((p) => `- ${p.name}: ${p.url}`),
    '',
    `You are getting this email because you signed an agreement with ${operatorName}. Where your agreement includes our policies, the changes apply to you from ${date}, as it explains, and never to anything before then. If you do not agree, you can stop working with us or taking part at any time.`,
    '',
    `This is a notice about your agreement, not marketing. Replies to this address are not read. Questions: ${replyTo}`,
    '',
    `Thank you for being part of ${operatorName}!`,
  ].join('\n');
}

/**
 * Sends what the hourly cap allows now. Returns the number sent. Called on a timer, and directly by tests.
 */
export async function sendQueued(input: { notices: NoticeStore; config: NoticeConfig; mailer: Mailer; operatorName: string; now: () => Date; log: (message: string) => void; max?: number }): Promise<number> {
  const perHour = input.config.perHour ?? 60;
  const now = input.now();
  const budget = Math.min(input.max ?? Infinity, perHour - input.notices.sentSince(new Date(now.getTime() - 3_600_000).toISOString()));
  if (budget <= 0) return 0;
  const byId = new Map(input.notices.list().map((n) => [n.id, n]));
  let sent = 0;
  for (const job of input.notices.queued(budget)) {
    const notice = byId.get(job.noticeId);
    if (!notice) continue;
    try {
      await input.mailer.send({ to: job.email, from: input.config.from, replyTo: input.config.replyTo, subject: notice.subject, text: noticeText(notice, input.operatorName, input.config.replyTo) });
      input.notices.markSent(job.noticeId, job.email, input.now().toISOString());
      sent++;
    } catch (error) {
      // No address in the log: the dashboard shows which delivery failed.
      input.notices.markFailed(job.noticeId, job.email, error instanceof Error ? error.message : String(error));
      input.log(`notice ${job.noticeId}: a delivery failed`);
    }
  }
  return sent;
}

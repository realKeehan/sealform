// Outgoing mail. OutboxMailer writes complete RFC 5322 messages to a folder, so receipts are kept
// even before a mail server is configured; an SMTP mailer can send the same messages later.

import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

export interface Attachment {
  filename: string;
  contentType: string;
  content: Uint8Array;
}

export interface MailMessage {
  to: string;
  from: string;
  replyTo?: string;
  subject: string;
  text: string;
  attachments?: Attachment[];
}

export interface Mailer {
  send(message: MailMessage): Promise<{ id: string }>;
}

export class OutboxMailer implements Mailer {
  private readonly dir: string;

  constructor(dir: string) {
    this.dir = dir;
  }

  async send(message: MailMessage): Promise<{ id: string }> {
    await mkdir(this.dir, { recursive: true });
    const id = `${Date.now()}-${randomUUID()}`;
    await writeFile(join(this.dir, `${id}.eml`), toMime(message, id), { mode: 0o600 });
    return { id };
  }
}

export function toMime(message: MailMessage, id: string): string {
  for (const address of [message.to, message.from, message.replyTo]) {
    if (address !== undefined && /[\r\n]/.test(address)) throw new Error('Header injection attempt in address');
  }
  const boundary = `sealform-${id}`;
  const domain = message.from.split('@')[1]?.replace(/[>\s]/g, '') || 'localhost';
  const headers = [
    `From: ${message.from}`,
    `To: ${message.to}`,
    ...(message.replyTo ? [`Reply-To: ${message.replyTo}`] : []),
    `Subject: ${encodeHeader(message.subject)}`,
    `Date: ${new Date().toUTCString()}`,
    `Message-ID: <${id}@${domain}>`,
    'MIME-Version: 1.0',
    `Content-Type: multipart/mixed; boundary="${boundary}"`,
  ];
  const parts = [
    [`--${boundary}`, 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: base64', '', wrap(Buffer.from(message.text, 'utf8').toString('base64'))].join('\r\n'),
    ...(message.attachments ?? []).map((file) =>
      [
        `--${boundary}`,
        `Content-Type: ${file.contentType}; name="${safeFilename(file.filename)}"`,
        'Content-Transfer-Encoding: base64',
        `Content-Disposition: attachment; filename="${safeFilename(file.filename)}"`,
        '',
        wrap(Buffer.from(file.content).toString('base64')),
      ].join('\r\n'),
    ),
  ];
  return `${headers.join('\r\n')}\r\n\r\n${parts.join('\r\n')}\r\n--${boundary}--\r\n`;
}

function encodeHeader(value: string): string {
  const clean = value.replace(/[\r\n]+/g, ' ');
  return /^[\x20-\x7e]*$/.test(clean) ? clean : `=?UTF-8?B?${Buffer.from(clean, 'utf8').toString('base64')}?=`;
}

function safeFilename(name: string): string {
  return name.replace(/[^A-Za-z0-9._-]/g, '_');
}

function wrap(base64: string): string {
  return base64.replace(/.{1,76}/g, '$&\r\n').trimEnd();
}

import type { IncomingMessage, ServerResponse } from 'node:http';

export class HttpError extends Error {
  readonly status: number;
  readonly details: Record<string, unknown> | undefined;
  readonly headers: Record<string, string>;

  constructor(status: number, message: string, details?: Record<string, unknown>, headers: Record<string, string> = {}) {
    super(message);
    this.status = status;
    this.details = details;
    this.headers = headers;
  }
}

const BASE_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

export function sendJson(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { ...BASE_HEADERS, 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload), ...headers });
  res.end(payload);
}

export function sendBytes(res: ServerResponse, status: number, contentType: string, body: Uint8Array, headers: Record<string, string> = {}): void {
  res.writeHead(status, { ...BASE_HEADERS, 'content-type': contentType, 'content-length': body.byteLength, ...headers });
  res.end(body);
}

export async function readJson(req: IncomingMessage, maxBytes: number): Promise<unknown> {
  const type = req.headers['content-type'] ?? '';
  if (!/^application\/json\b/i.test(type)) throw new HttpError(415, 'Send JSON');
  const declared = Number(req.headers['content-length'] ?? 0);
  if (declared > maxBytes) throw new HttpError(413, 'Submission too large');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > maxBytes) throw new HttpError(413, 'Submission too large');
    chunks.push(chunk as Buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    throw new HttpError(400, 'Body is not valid JSON');
  }
}

export type ClientIpSource = 'socket' | 'x-forwarded-for' | 'cf-connecting-ip' | ((req: IncomingMessage) => string);

/**
 * The client's address. Only trust a forwarding header when a proxy you control sets it; otherwise
 * anyone can claim any address. 'x-forwarded-for' takes the last hop, which is the one your proxy added.
 */
export function clientIp(req: IncomingMessage, source: ClientIpSource): string {
  if (typeof source === 'function') return source(req);
  if (source === 'cf-connecting-ip') {
    const value = req.headers['cf-connecting-ip'];
    if (typeof value === 'string' && value) return value.trim();
  }
  if (source === 'x-forwarded-for') {
    const value = req.headers['x-forwarded-for'];
    const list = (Array.isArray(value) ? value.join(',') : value ?? '').split(',').map((part) => part.trim()).filter(Boolean);
    if (list.length) return list[list.length - 1]!;
  }
  return (req.socket.remoteAddress ?? 'unknown').replace(/^::ffff:/, '');
}

export function header(req: IncomingMessage, name: string, max = 512): string {
  const value = req.headers[name];
  return (Array.isArray(value) ? value.join(', ') : value ?? '').slice(0, max);
}

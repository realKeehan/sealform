// The site layer. When sealform's Node app also serves the website (the usual cPanel setup), this adds
// what a static host cannot: pages that are hidden or private, and a parking switch that holds the whole
// site behind a "back soon" page. The dashboard edits the rules; they live in the database.

import { createReadStream } from 'node:fs';
import { chmod, readFile, realpath, rename, stat, unlink, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { extname, join, resolve, sep } from 'node:path';
import type { AdminStore } from './admin/db.ts';

export interface SiteConfig {
  /** Folder holding the built static site. */
  dir: string;
  /** Headers added to every static response, such as your Content-Security-Policy. */
  headers?: Record<string, string>;
  /** Paths that stay reachable while parked, besides the defaults. */
  parkingAllow?: string[];
  /** False when Apache serves this folder; only manage its parking switch here. */
  serve?: boolean;
  /** Optional nonsecret flag read by the static host's rewrite rule. */
  parkingFile?: string;
  /** Address shown in the dashboard when managing a separate hostname. */
  publicUrl?: string;
}

export type RuleMode = 'hidden' | 'private';
export interface SiteRule {
  prefix: string;
  mode: RuleMode;
}

export const DEFAULT_PARKING_ALLOW = ['/parked/', '/assets/', '/.well-known/', '/favicon.ico', '/robots.txt'];

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json', '.txt': 'text/plain; charset=utf-8', '.xml': 'application/xml; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp', '.avif': 'image/avif', '.ico': 'image/x-icon',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.otf': 'font/otf', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg', '.ogg': 'audio/ogg',
  '.pdf': 'application/pdf', '.zip': 'application/zip', '.wasm': 'application/wasm', '.map': 'application/json',
};

/** A normalized rule prefix, or null when it is not a safe site path. */
export function normalizePrefix(input: string): string | null {
  const value = input.trim();
  if (!value.startsWith('/') || value.length > 200 || /[\0\\?#\s]/.test(value) || value.includes('//')) return null;
  const segments = value.split('/').filter(Boolean);
  if (segments.some((s) => s === '.' || s === '..' || (s.startsWith('.') && s !== '.well-known'))) return null;
  // One canonical form: /about and /about/ are the same path, so they are the same rule.
  return '/' + segments.join('/');
}

function matches(prefix: string, path: string): boolean {
  if (prefix === '/') return true;
  const bare = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  return path === bare || path.startsWith(bare + '/');
}

export class SiteLayer {
  private readonly dir: string;
  private readonly headers: Record<string, string>;
  private readonly allow: string[];
  private readonly db: AdminStore | undefined;
  private readonly isAdmin: (req: IncomingMessage) => boolean;
  private readonly operatorName: string;

  private readonly config: SiteConfig;
  private parkingQueue: Promise<void> = Promise.resolve();

  constructor(config: SiteConfig, extras: { db: AdminStore | undefined; isAdmin: (req: IncomingMessage) => boolean; operatorName: string }) {
    this.config = config;
    this.dir = resolve(config.dir);
    this.headers = config.headers ?? {};
    this.allow = [...DEFAULT_PARKING_ALLOW, ...(config.parkingAllow ?? [])];
    this.db = extras.db;
    this.isAdmin = extras.isAdmin;
    this.operatorName = extras.operatorName;
  }

  /** Restore the static host's flag from the saved dashboard state after a restart. */
  async syncParking(): Promise<void> {
    await this.mirrorParking(this.db?.setting('parking') === 'on');
  }

  setParking(on: boolean): Promise<void> {
    const update = this.parkingQueue.then(async () => {
      const previous = this.db?.setting('parking') === 'on';
      await this.mirrorParking(on);
      try { this.db?.saveSetting('parking', on ? 'on' : 'off'); }
      catch (error) { await this.mirrorParking(previous); throw error; }
    });
    this.parkingQueue = update.catch(() => {});
    return update;
  }

  private async mirrorParking(on: boolean): Promise<void> {
    const flag = this.config.parkingFile;
    if (!flag) return;
    if (!on) {
      await unlink(flag).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'ENOENT') throw error; });
      return;
    }
    const temporary = `${flag}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, 'parked\n', { mode: 0o644, flag: 'wx' });
      await chmod(temporary, 0o644);
      await rename(temporary, flag);
    } finally {
      await unlink(temporary).catch((error: NodeJS.ErrnoException) => { if (error.code !== 'ENOENT') throw error; });
    }
  }

  /** Serves the request, or answers it with the right status. Always handles it. */
  async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    if (req.method !== 'GET' && req.method !== 'HEAD') return this.plain(req, res, 405, 'Method not allowed', { allow: 'GET, HEAD' });
    let path: string;
    try {
      path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
    } catch {
      return this.plain(req, res, 400, 'Bad request');
    }
    if (path.includes('\0') || path.includes('\\') || path.split('/').some((s) => s === '..' || (s.startsWith('.') && s !== '' && s !== '.well-known'))) return this.notFound(req, res);

    const rule = this.db
      ?.siteRules()
      .filter((r) => matches(r.prefix, path))
      .sort((a, b) => b.prefix.length - a.prefix.length)[0];
    if (rule && (rule.mode === 'hidden' || !this.isAdmin(req))) return this.notFound(req, res);

    if (this.db?.setting('parking') === 'on' && !this.allow.some((prefix) => matches(prefix, path) || (prefix.endsWith('/') ? false : path === prefix))) {
      return this.parked(req, res);
    }
    return this.serve(req, res, path);
  }

  /** Facts for the dashboard. */
  async info(): Promise<{ dir: string; exists: boolean; builtAt: string | null; hasParkedPage: boolean; hasNotFoundPage: boolean; allow: string[]; serving: boolean; publicUrl: string | null }> {
    const modified = await stat(join(this.dir, 'index.html')).then((s) => s.mtime.toISOString(), () => null);
    return {
      dir: this.dir,
      serving: this.config.serve !== false,
      publicUrl: this.config.publicUrl ?? null,
      exists: await stat(this.dir).then((s) => s.isDirectory(), () => false),
      builtAt: modified,
      hasParkedPage: await stat(join(this.dir, 'parked', 'index.html')).then(() => true, () => false),
      hasNotFoundPage: await stat(join(this.dir, '404.html')).then(() => true, () => false),
      allow: this.allow,
    };
  }

  private async serve(req: IncomingMessage, res: ServerResponse, path: string): Promise<void> {
    let target = join(this.dir, ...path.split('/').filter(Boolean));
    let info = await stat(target).catch(() => undefined);
    if (info?.isDirectory()) {
      if (!path.endsWith('/')) {
        res.writeHead(301, { location: `${path}/${new URL(req.url ?? '/', 'http://x').search}`, ...this.headers });
        res.end();
        return;
      }
      target = join(target, 'index.html');
      info = await stat(target).catch(() => undefined);
    }
    if (!info?.isFile()) return this.notFound(req, res);
    // A symlink must not lead out of the site folder.
    const real = await realpath(target).catch(() => undefined);
    const root = await realpath(this.dir).catch(() => this.dir);
    if (!real || !(real === root || real.startsWith(root + sep))) return this.notFound(req, res);

    const type = MIME[extname(real).toLowerCase()] ?? 'application/octet-stream';
    const etag = `W/"${info.size.toString(16)}-${Math.floor(info.mtimeMs).toString(16)}"`;
    const headers: Record<string, string | number> = {
      'content-type': type,
      'content-length': info.size,
      etag,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'cache-control': type.startsWith('text/html') ? 'no-cache' : path.startsWith('/assets/') ? 'public, max-age=31536000, immutable' : 'public, max-age=300',
      ...this.headers,
    };
    if (req.headers['if-none-match'] === etag) {
      res.writeHead(304, { etag, ...this.headers });
      res.end();
      return;
    }
    res.writeHead(200, headers);
    if (req.method === 'HEAD') {
      res.end();
      return;
    }
    createReadStream(real).on('error', () => res.destroy()).pipe(res);
  }

  private async notFound(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const page = await readFile(join(this.dir, '404.html')).catch(() => undefined);
    if (!page) return this.plain(req, res, 404, 'Not found');
    res.writeHead(404, { 'content-type': MIME['.html']!, 'content-length': page.length, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...this.headers });
    res.end(req.method === 'HEAD' ? undefined : page);
  }

  private async parked(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const page =
      (await readFile(join(this.dir, 'parked', 'index.html')).catch(() => undefined)) ??
      Buffer.from(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex"><title>Back soon</title></head><body><main><h1>Back soon</h1><p>${escapeHtml(this.operatorName)} is not open right now. Please check back later.</p></main></body></html>`);
    res.writeHead(503, { 'content-type': MIME['.html']!, 'content-length': page.length, 'retry-after': '3600', 'cache-control': 'no-store', 'x-robots-tag': 'noindex', 'x-content-type-options': 'nosniff', ...this.headers });
    res.end(req.method === 'HEAD' ? undefined : page);
  }

  private plain(req: IncomingMessage, res: ServerResponse, status: number, text: string, extra: Record<string, string> = {}): void {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra, ...this.headers });
    res.end(req.method === 'HEAD' ? undefined : text);
  }
}

function escapeHtml(text: string): string {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

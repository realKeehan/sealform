// View-only review links: a read-only page for a draft or published document, with a view limit, an
// expiry and revocation. No signing form and no scripts, so the CSP can forbid everything but one stylesheet.
import type { ReviewLink } from './admin/db.ts';
import { escape } from './admin/html.ts';
import { renderDocumentMarkdown } from './admin/markdown.ts';
import type { LoadedDocument } from './documents.ts';

export const REVIEW_HEADERS = {
  'content-security-policy': "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
  'referrer-policy': 'no-referrer',
  'x-robots-tag': 'noindex, nofollow',
  'cache-control': 'no-store',
};

export const REVIEW_CSS = `body{margin:0;background:#fbfaf7;color:#1c1b19;font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:46rem;margin:0 auto;padding:1.5rem 1rem 4rem}
.banner{background:#fff3cd;border:1px solid #e0c36a;border-radius:8px;padding:.75rem 1rem;margin-bottom:1.25rem}
.banner strong{display:block}
.meta{color:#5b574f;font-size:.875rem;margin:0 0 1.5rem}
.meta span{display:inline-block;margin-right:1rem}
h1{font-size:1.6rem;line-height:1.25;margin:0 0 .5rem}
article h3,article h4,article h5,article h6{margin:1.6rem 0 .4rem;line-height:1.3}
article p,article li{margin:.5rem 0}
.stop{max-width:32rem;margin:15vh auto;padding:0 1rem;text-align:center}
@media print{.banner{border-color:#000}}
`;

export function reviewPage(base: string, link: ReviewLink, doc: LoadedDocument, lang: string, status: string, viewsLeft: number, revision: string): string {
  const text = doc.texts.get(lang) ?? doc.texts.get(doc.manifest.governingLang)!;
  const others = [...doc.texts.keys()].filter((l) => l !== text.lang);
  return `<!doctype html><html lang="${escape(text.lang)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><link rel="icon" href="data:,"><title>Review copy: ${escape(doc.manifest.title)}</title><link rel="stylesheet" href="${base}/assets/review.css?v=${revision}"></head><body><main>
<div class="banner"><strong>Review copy. View only, not signed.</strong>Reading this does not sign or accept anything. This link is private to ${escape(link.recipient)}. Please do not forward it; it stops working after ${viewsLeft} more ${viewsLeft === 1 ? 'view' : 'views'} or on ${escape(link.expiresAt.slice(0, 10))}, or sooner if the sender cancels it.${status === 'draft' ? ' This is a draft and its terms may still change.' : ''}</div>
<h1>${escape(doc.manifest.title)}</h1>
<p class="meta"><span>${escape(doc.manifest.id)} version ${escape(doc.manifest.version)}</span><span>Status: ${escape(status)}</span><span>Text SHA-256: ${escape(text.sha256.slice(0, 16))}</span>${others.map((l) => `<span><a href="?lang=${escape(l)}">${escape(l)}</a></span>`).join('')}</p>
<article>${renderDocumentMarkdown(text.text).value}</article>
</main></body></html>`;
}

export function reviewStopPage(base: string, message: string, revision: string): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex, nofollow"><link rel="icon" href="data:,"><title>Review link unavailable</title><link rel="stylesheet" href="${base}/assets/review.css?v=${revision}"></head><body><main class="stop"><h1>Review link unavailable</h1><p>${escape(message)}</p></main></body></html>`;
}

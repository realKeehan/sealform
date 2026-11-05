// Dashboard preview for the Markdown subset used by signing documents.
// All document content is escaped; only renderer-owned tags become HTML.
import { escape, html, raw, type Raw } from './html.ts';

export function renderDocumentMarkdown(text: string): Raw {
  const out: string[] = [];
  let paragraph: string[] = [];
  let list: 'ul' | 'ol' | undefined;
  const flushParagraph = () => {
    if (paragraph.length) out.push(`<p>${inline(paragraph.join(' '))}</p>`);
    paragraph = [];
  };
  const flushList = () => {
    if (list) out.push(`</${list}>`);
    list = undefined;
  };
  for (const line of text.replace(/\r\n?/g, '\n').split('\n')) {
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);
    if (!line.trim()) {
      flushParagraph();
      flushList();
    } else if (heading) {
      flushParagraph();
      flushList();
      const level = Math.min(heading[1]!.length + 2, 6);
      out.push(`<h${level}>${inline(heading[2]!)}</h${level}>`);
    } else if (bullet || numbered) {
      flushParagraph();
      const tag = bullet ? 'ul' : 'ol';
      if (list !== tag) {
        flushList();
        out.push(`<${tag}>`);
        list = tag;
      }
      out.push(`<li>${inline((bullet ?? numbered)![1]!)}</li>`);
    } else {
      flushList();
      paragraph.push(line.trim());
    }
  }
  flushParagraph();
  flushList();
  return raw(out.join(''));
}

// Match the signing client's supported inline syntax and safe link protocols.
const INLINE = /(\*\*(.+?)\*\*|__(.+?)__|\*(.+?)\*|_(.+?)_|\[([^\]]+)\]\(([^)\s]+)\))/;
function inline(text: string): string {
  let rest = text;
  let out = '';
  while (rest) {
    const match = INLINE.exec(rest);
    if (!match) return out + escape(rest);
    out += escape(rest.slice(0, match.index));
    const [whole, , strong1, strong2, em1, em2, label, href] = match;
    if (strong1 ?? strong2) out += `<strong>${inline((strong1 ?? strong2)!)}</strong>`;
    else if (em1 ?? em2) out += `<em>${inline((em1 ?? em2)!)}</em>`;
    else if (label && href && /^(https?:|mailto:)/i.test(href)) {
      out += html`<a href="${href}" rel="noopener noreferrer" target="_blank">${label}</a> (${href.replace(/^mailto:/i, '')})`.value;
    } else out += escape(whole);
    rest = rest.slice(match.index + whole.length);
  }
  return out;
}

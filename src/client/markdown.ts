// A small Markdown renderer for document text: headings, paragraphs, lists, bold, italics and links.
// It builds DOM nodes with textContent only, never innerHTML, so document text cannot inject markup.

export function renderMarkdown(text: string, doc: Document = document): DocumentFragment {
  const fragment = doc.createDocumentFragment();
  let paragraph: string[] = [];
  let list: HTMLUListElement | HTMLOListElement | null = null;

  const flushParagraph = () => {
    if (paragraph.length) {
      const p = doc.createElement('p');
      appendInline(p, paragraph.join(' '), doc);
      fragment.append(p);
      paragraph = [];
    }
  };
  const flushList = () => {
    if (list) fragment.append(list);
    list = null;
  };

  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    const bullet = /^\s*[-*+]\s+(.*)$/.exec(line);
    const numbered = /^\s*\d+[.)]\s+(.*)$/.exec(line);

    if (line.trim() === '') {
      flushParagraph();
      flushList();
    } else if (heading) {
      flushParagraph();
      flushList();
      // Document headings start at h3 so they sit under the form's own h2.
      const h = doc.createElement(`h${Math.min(heading[1]!.length + 2, 6)}`);
      appendInline(h, heading[2]!, doc);
      fragment.append(h);
    } else if (bullet || numbered) {
      flushParagraph();
      const tag = bullet ? 'ul' : 'ol';
      if (!list || list.tagName.toLowerCase() !== tag) {
        flushList();
        list = doc.createElement(tag);
      }
      const li = doc.createElement('li');
      appendInline(li, (bullet ?? numbered)![1]!, doc);
      list.append(li);
    } else {
      flushList();
      paragraph.push(line.trim());
    }
  }
  flushParagraph();
  flushList();
  return fragment;
}

const INLINE = /(\*\*(.+?)\*\*|__(.+?)__|\*(.+?)\*|_(.+?)_|\[([^\]]+)\]\(([^)\s]+)\))/;

function appendInline(parent: HTMLElement, text: string, doc: Document): void {
  let rest = text;
  while (rest) {
    const match = INLINE.exec(rest);
    if (!match) {
      parent.append(rest);
      return;
    }
    if (match.index > 0) parent.append(rest.slice(0, match.index));
    const [whole, , strong1, strong2, em1, em2, linkText, href] = match;
    if (strong1 ?? strong2) {
      const el = doc.createElement('strong');
      appendInline(el, (strong1 ?? strong2)!, doc);
      parent.append(el);
    } else if (em1 ?? em2) {
      const el = doc.createElement('em');
      appendInline(el, (em1 ?? em2)!, doc);
      parent.append(el);
    } else if (linkText && href) {
      if (/^(https?:|mailto:)/i.test(href)) {
        const a = doc.createElement('a');
        a.href = href;
        a.rel = 'noopener noreferrer';
        a.target = '_blank';
        a.textContent = linkText;
        parent.append(a);
        // Printing the address keeps the signed text unambiguous about where the link points.
        parent.append(` (${href.replace(/^mailto:/i, '')})`);
      } else {
        parent.append(whole);
      }
    }
    rest = rest.slice(match.index + whole.length);
  }
}

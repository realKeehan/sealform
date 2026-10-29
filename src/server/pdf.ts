// The human-readable copy of a signed record. The sealed JSON record is the evidence; this PDF prints
// it with the full document text, the signature, and how to verify it.
//
// pdf-lib's built-in fonts only cover Western European characters. Anything else (Japanese, Greek,
// Cyrillic, emoji) prints as "?" with a note; the sealed record keeps the exact text. Embedding a
// Unicode font would fix this and needs @pdf-lib/fontkit plus a font file.

import { PDFDocument, rgb, StandardFonts, type PDFFont, type PDFPage } from 'pdf-lib';
import type { SealformRecord } from '../core/index.ts';
import type { DocumentManifest } from './documents.ts';

export interface PdfInput {
  record: SealformRecord;
  manifest: DocumentManifest;
  documentText: string;
  disclosureText?: string;
  png: Uint8Array;
  operatorName: string;
  keysUrl: string;
}

const PAGE = { width: 595.28, height: 841.89, margin: 56 };
const INK = rgb(0.1, 0.1, 0.12);
const MUTED = rgb(0.38, 0.38, 0.42);

export async function renderCertificate(input: PdfInput): Promise<Uint8Array> {
  const pdf = await PDFDocument.create();
  const regular = await pdf.embedFont(StandardFonts.Helvetica);
  const bold = await pdf.embedFont(StandardFonts.HelveticaBold);
  const mono = await pdf.embedFont(StandardFonts.Courier);
  const { record, manifest } = input;
  pdf.setTitle(`${manifest.title} - signed ${record.id}`);
  pdf.setAuthor(input.operatorName);
  pdf.setSubject(`Record ${record.id}, hash ${record.hash}`);
  pdf.setProducer('sealform');
  pdf.setCreationDate(new Date(record.server.receivedAt));

  const writer = new Writer(pdf, regular);

  writer.text(manifest.title, bold, 18);
  writer.text(`Signed copy for ${record.fields[nameField(manifest)] ?? record.signature.typedName}`, regular, 11, MUTED);
  writer.gap(10);
  writer.pairs(
    [
      ['Document', `${manifest.id}, version ${manifest.version}, language ${record.document.lang}`],
      ['Signed at', `${record.server.receivedAt} (server time, UTC)`],
      ['Record id', record.id],
    ],
    regular,
    bold,
  );

  writer.section('Signature', bold);
  const image = await pdf.embedPng(input.png);
  const scale = Math.min(220 / image.width, 90 / image.height, 1);
  writer.image(image, image.width * scale, image.height * scale);
  writer.text(`Typed name: ${record.signature.typedName}${record.signature.mode === 'typed' ? ' (signed by typing, no drawing)' : ''}`, regular, 10);

  writer.section('Answers', bold);
  writer.pairs(
    manifest.fields.map((field) => [field.label, formatValue(record.fields[field.name])]),
    regular,
    bold,
  );

  writer.section('Agreed to', bold);
  for (const consent of manifest.consents) {
    writer.paragraph(`${record.consent[consent.name] ? '[x]' : '[ ]'} ${consent.label}`, regular, 10);
  }

  writer.section('Evidence', bold);
  writer.pairs(
    [
      ['IP address', record.server.ip],
      ['Browser', record.server.userAgent],
      ['Languages', record.server.acceptLanguage || '(none sent)'],
      ['Session opened', record.server.sessionOpenedAt],
      ['Checks', record.assurance.checks.map((check) => `${check.kind}: ${check.status}`).join(', ') || 'none'],
      ['Document SHA-256', record.document.sha256, mono],
      ['Chain position', `#${record.chain.seq}`],
      ['Previous record', record.chain.prevHash, mono],
      ['Record SHA-256', record.hash, mono],
      ['Seal', `${record.seal.alg}, key ${record.seal.kid}`],
      ['Seal signature', record.seal.sig, mono],
    ],
    regular,
    bold,
  );

  writer.section('How to verify', bold);
  writer.paragraph(
    `${input.operatorName} sealed this record with the key above. To check that it has not changed since signing, ` +
      `ask for the record file (${record.id}.json) and run: npx sealform verify ${record.id}.json --keys ${input.keysUrl}`,
    regular,
    10,
  );
  writer.paragraph('This PDF is a readable copy. The sealed record is the authoritative version.', regular, 9, MUTED);

  if (input.disclosureText) {
    writer.newPage();
    writer.text(`E-signature disclosure the signer accepted (${record.disclosure.id}, version ${record.disclosure.version})`, regular, 9, MUTED);
    writer.markdown(input.disclosureText, regular, bold);
  }

  writer.newPage();
  writer.text(`Full text signed (${manifest.id}, version ${manifest.version}, language ${record.document.lang})`, regular, 9, MUTED);
  writer.markdown(input.documentText, regular, bold);

  if (writer.replaced) {
    writer.gap(12);
    writer.paragraph('Some characters cannot be shown with this PDF\'s fonts and appear as "?". The sealed record holds the exact text.', regular, 9, MUTED);
  }

  const pages = pdf.getPages();
  pages.forEach((page, i) => {
    page.drawText(writer.clean(`${record.id}   page ${i + 1} of ${pages.length}`), { x: PAGE.margin, y: 28, size: 8, font: regular, color: MUTED });
  });
  return pdf.save();
}

function nameField(manifest: DocumentManifest): string {
  return manifest.fields.find((field) => field.role === 'signerName')?.name ?? '';
}

function formatValue(value: unknown): string {
  if (value === undefined || value === '') return '(blank)';
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  return String(value);
}

class Writer {
  replaced = false;
  private page: PDFPage;
  private y = 0;
  private readonly encodable = new Map<string, boolean>();
  private readonly pdf: PDFDocument;
  private readonly probe: PDFFont;

  constructor(pdf: PDFDocument, probe: PDFFont) {
    this.pdf = pdf;
    this.probe = probe;
    this.page = this.addPage();
  }

  newPage(): void {
    this.page = this.addPage();
  }

  gap(points: number): void {
    this.y -= points;
  }

  section(title: string, font: PDFFont): void {
    this.gap(14);
    this.text(title, font, 12);
    this.gap(2);
  }

  text(text: string, font: PDFFont, size: number, color = INK): void {
    this.paragraph(text, font, size, color);
  }

  paragraph(text: string, font: PDFFont, size: number, color = INK, indent = 0): void {
    const width = PAGE.width - PAGE.margin * 2 - indent;
    for (const line of this.wrap(this.clean(text), font, size, width)) {
      this.ensure(size * 1.4);
      this.page.drawText(line, { x: PAGE.margin + indent, y: this.y, size, font, color });
      this.y -= size * 1.4;
    }
  }

  /** Label and value columns. Rows marked mono print hashes in a smaller fixed-width font so they fit. */
  pairs(rows: [string, string, PDFFont?][], font: PDFFont, labelFont: PDFFont): void {
    const labelWidth = 120;
    const valueX = PAGE.margin + labelWidth + 10;
    const valueWidth = PAGE.width - PAGE.margin - valueX;
    for (const [label, value, mono] of rows) {
      const valueFont = mono ?? font;
      const valueSize = mono ? 8 : 10;
      const labelLines = this.wrap(this.clean(label), labelFont, 9, labelWidth);
      const valueLines = this.wrap(this.clean(value), valueFont, valueSize, valueWidth);
      const rowCount = Math.max(labelLines.length, valueLines.length);
      this.ensure(rowCount * 13);
      for (let i = 0; i < rowCount; i++) {
        if (labelLines[i]) this.page.drawText(labelLines[i]!, { x: PAGE.margin, y: this.y, size: 9, font: labelFont, color: MUTED });
        if (valueLines[i]) this.page.drawText(valueLines[i]!, { x: valueX, y: this.y, size: valueSize, font: valueFont, color: INK });
        this.y -= 13;
      }
      this.y -= 2;
    }
  }

  image(image: Awaited<ReturnType<PDFDocument['embedPng']>>, width: number, height: number): void {
    this.ensure(height + 8);
    this.page.drawImage(image, { x: PAGE.margin, y: this.y - height + 10, width, height });
    this.y -= height + 6;
  }

  markdown(text: string, regular: PDFFont, bold: PDFFont): void {
    for (const raw of text.split('\n')) {
      const line = raw.trimEnd();
      if (line === '') {
        this.gap(6);
        continue;
      }
      const heading = /^(#{1,6})\s+(.*)$/.exec(line);
      if (heading) {
        this.gap(6);
        this.paragraph(heading[2]!, bold, heading[1]!.length <= 2 ? 12 : 11);
        continue;
      }
      const bullet = /^\s*[-*]\s+(.*)$/.exec(line);
      if (bullet) this.paragraph(`- ${bullet[1]}`, regular, 10, INK, 10);
      else this.paragraph(line.replace(/\*\*(.+?)\*\*/g, '$1').replace(/\[(.+?)\]\((.+?)\)/g, '$1 ($2)'), regular, 10);
    }
  }

  /** Replaces characters the standard fonts cannot encode. */
  clean(text: string): string {
    let out = '';
    for (const char of text.replace(/\t/g, '    ')) {
      let ok = this.encodable.get(char);
      if (ok === undefined) {
        try {
          this.probe.encodeText(char);
          ok = true;
        } catch {
          ok = false;
        }
        this.encodable.set(char, ok);
      }
      if (ok) out += char;
      else {
        out += '?';
        this.replaced = true;
      }
    }
    return out;
  }

  private wrap(text: string, font: PDFFont, size: number, width: number): string[] {
    const lines: string[] = [];
    let current = '';
    for (const word of text.split(/ +/)) {
      const candidate = current ? `${current} ${word}` : word;
      if (font.widthOfTextAtSize(candidate, size) <= width) {
        current = candidate;
        continue;
      }
      if (current) lines.push(current);
      current = word;
      // Break words longer than a line, such as hashes and signatures.
      while (font.widthOfTextAtSize(current, size) > width) {
        let cut = current.length - 1;
        while (cut > 1 && font.widthOfTextAtSize(current.slice(0, cut), size) > width) cut--;
        lines.push(current.slice(0, cut));
        current = current.slice(cut);
      }
    }
    lines.push(current);
    return lines;
  }

  private ensure(height: number): void {
    if (this.y - height < PAGE.margin) this.page = this.addPage();
  }

  private addPage(): PDFPage {
    const page = this.pdf.addPage([PAGE.width, PAGE.height]);
    this.y = PAGE.height - PAGE.margin;
    return page;
  }
}

// The signing form. mountSealform(element, options) fetches the published document, renders it with
// its fields, consent boxes and a signature pad, and submits to a sealform server.
//
// It brings no colors or fonts of its own beyond sealform.css, which reads --sf-* custom properties so
// the host site can theme it.

import SignaturePad from 'signature_pad';
import { sha256Hex } from '../core/index.ts';
import { renderMarkdown } from './markdown.ts';

export interface FieldSpec {
  name: string;
  label: string;
  type: 'text' | 'email' | 'country' | 'select' | 'textarea' | 'checkbox';
  required?: boolean;
  maxLength?: number;
  options?: string[];
  help?: string;
  role?: string;
}

export interface DocumentResponse {
  document: { id: string; version: string; title: string; lang: string; languages: string[]; governingLang: string; text: string; sha256: string; manifestSha256: string };
  disclosure: { id: string; version: string; lang: string; text: string; sha256: string } | null;
  fields: FieldSpec[];
  consents: { name: string; label: string; required: boolean }[];
  session: { id: string; expiresAt: string };
  botCheck: string;
}

export interface Receipt {
  id: string;
  hash: string;
  seal: { alg: string; kid: string };
  receivedAt: string;
  pdfUrl: string;
  recordUrl: string;
  keysUrl: string;
}

export interface Labels {
  version: string;
  language: string;
  documentRegion: string;
  disclosure: string;
  yourDetails: string;
  agreement: string;
  signature: string;
  typedName: string;
  typedNameHelp: string;
  drawMode: string;
  typeMode: string;
  drawHelp: string;
  typeHelp: string;
  clear: string;
  chooseCountry: string;
  chooseOption: string;
  required: string;
  optional: string;
  sign: string;
  signing: string;
  fixErrors: string;
  networkError: string;
  signedTitle: string;
  signedBody: string;
  recordId: string;
  recordHash: string;
  downloadPdf: string;
  downloadRecord: string;
  emptySignature: string;
  botCheckPending: string;
}

export const defaultLabels: Labels = {
  version: 'Version',
  language: 'Language',
  documentRegion: 'Agreement text',
  disclosure: 'Consent to sign electronically',
  yourDetails: 'Your details',
  agreement: 'Agreement',
  signature: 'Signature',
  typedName: 'Type your full legal name',
  typedNameHelp: 'It must match the legal name above.',
  drawMode: 'Draw',
  typeMode: 'Type instead',
  drawHelp: 'Draw your signature with a finger, stylus or mouse.',
  typeHelp: 'Your typed name will be used as your signature.',
  clear: 'Clear',
  chooseCountry: 'Choose a country',
  chooseOption: 'Choose one',
  required: 'required',
  optional: 'optional',
  sign: 'Sign',
  signing: 'Signing...',
  fixErrors: 'Please fix these before signing:',
  networkError: 'Could not reach the server. Nothing was signed; please try again.',
  signedTitle: 'Signed.',
  signedBody: 'Your signature is sealed. A copy is on its way to your email. You can also download it now.',
  recordId: 'Record',
  recordHash: 'SHA-256',
  downloadPdf: 'Download PDF copy',
  downloadRecord: 'Download sealed record',
  emptySignature: 'draw your signature, or choose "Type instead"',
  botCheckPending: 'Please complete the check above.',
};

export interface MountOptions {
  /** Where the server's handler is mounted, such as "/sealform" or "https://sign.example.com/sealform". */
  endpoint: string;
  documentId: string;
  lang?: string;
  /** Cloudflare Turnstile site key, when the server uses TurnstileCheck. */
  turnstileSiteKey?: string;
  labels?: Partial<Labels>;
  onSigned?: (receipt: Receipt) => void;
}

export interface MountedForm {
  destroy(): void;
}

type TurnstileApi = {
  render(el: HTMLElement, options: { sitekey: string; callback: (token: string) => void; 'expired-callback'?: () => void; 'error-callback'?: () => void }): string;
  reset(id?: string): void;
  remove(id?: string): void;
};

let uid = 0;

export async function mountSealform(root: HTMLElement, options: MountOptions): Promise<MountedForm> {
  const labels = { ...defaultLabels, ...options.labels };
  const endpoint = options.endpoint.replace(/\/+$/, '');
  const started = performance.now();
  const cleanup: (() => void)[] = [];
  const prefix = `sf${++uid}`;

  root.classList.add('sf');
  root.setAttribute('aria-busy', 'true');
  const query = options.lang ? `?lang=${encodeURIComponent(options.lang)}` : '';
  const response = await fetch(`${endpoint}/api/documents/${encodeURIComponent(options.documentId)}${query}`, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    root.removeAttribute('aria-busy');
    root.replaceChildren(el('p', { class: 'sf-error', role: 'alert' }, await errorMessage(response, labels)));
    return { destroy: () => root.replaceChildren() };
  }
  const data = (await response.json()) as DocumentResponse;
  const displayedSha = await sha256Hex(data.document.text);
  if (displayedSha !== data.document.sha256) throw new Error('The document text changed in transit');

  // Header and document ---------------------------------------------------------------------------
  const form = el('form', { class: 'sf-form', novalidate: '' });
  const titleId = `${prefix}-title`;
  form.setAttribute('aria-labelledby', titleId);
  const header = el('header', { class: 'sf-header' }, el('h2', { id: titleId, class: 'sf-title' }, data.document.title));
  const meta = el('p', { class: 'sf-meta' }, `${labels.version} ${data.document.version}`);
  header.append(meta);
  if (data.document.languages.length > 1) {
    const select = el('select', { id: `${prefix}-lang` }) as HTMLSelectElement;
    const names = new Intl.DisplayNames([data.document.lang], { type: 'language' });
    for (const lang of data.document.languages) select.append(new Option(names.of(lang) ?? lang, lang, false, lang === data.document.lang));
    select.addEventListener('change', () => {
      destroy();
      void mountSealform(root, { ...options, lang: select.value });
    });
    header.append(el('p', { class: 'sf-lang' }, el('label', { for: select.id }, labels.language), select));
  }
  form.append(header);

  const docRegion = el('section', { class: 'sf-document', tabindex: '0', 'aria-label': labels.documentRegion, lang: data.document.lang });
  docRegion.append(renderMarkdown(data.document.text));
  // The form header already shows the title; drop a leading heading that repeats it.
  const firstHeading = docRegion.firstElementChild;
  if (firstHeading && /^H[3-6]$/.test(firstHeading.tagName) && firstHeading.textContent?.trim() === data.document.title.trim()) firstHeading.remove();
  form.append(docRegion);

  if (data.disclosure) {
    const details = el('details', { class: 'sf-disclosure', lang: data.disclosure.lang }, el('summary', {}, labels.disclosure));
    details.append(renderMarkdown(data.disclosure.text));
    form.append(details);
  }

  // Fields -----------------------------------------------------------------------------------------
  const inputs = new Map<string, HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>();
  const errorSlots = new Map<string, HTMLElement>();
  const detailFields = data.fields.filter((field) => field.type !== 'checkbox');
  const checkFields = data.fields.filter((field) => field.type === 'checkbox');

  if (detailFields.length) {
    const fieldset = el('fieldset', { class: 'sf-fieldset' }, el('legend', {}, labels.yourDetails));
    for (const field of detailFields) fieldset.append(renderField(field));
    form.append(fieldset);
  }

  const agreeSet = el('fieldset', { class: 'sf-fieldset' }, el('legend', {}, labels.agreement));
  for (const field of checkFields) agreeSet.append(renderCheckbox(`fields.${field.name}`, field.label, field.required ?? false));
  for (const consent of data.consents) agreeSet.append(renderCheckbox(`consents.${consent.name}`, consent.label, consent.required));
  if (agreeSet.children.length > 1) form.append(agreeSet);

  // Signature --------------------------------------------------------------------------------------
  const sigSet = el('fieldset', { class: 'sf-fieldset sf-signature' }, el('legend', {}, labels.signature));
  const typedId = `${prefix}-typed`;
  const typed = el('input', { id: typedId, type: 'text', autocomplete: 'name', required: '', maxlength: '200', 'aria-describedby': `${typedId}-help ${typedId}-error` }) as HTMLInputElement;
  sigSet.append(
    el('div', { class: 'sf-field' },
      el('label', { for: typedId }, labels.typedName),
      typed,
      el('p', { class: 'sf-help', id: `${typedId}-help` }, labels.typedNameHelp),
      slot('signature.typedName', `${typedId}-error`),
    ),
  );
  inputs.set('signature.typedName', typed);

  const modeName = `${prefix}-mode`;
  const drawRadio = el('input', { type: 'radio', name: modeName, value: 'drawn', id: `${modeName}-draw`, checked: '' }) as HTMLInputElement;
  const typeRadio = el('input', { type: 'radio', name: modeName, value: 'typed', id: `${modeName}-type` }) as HTMLInputElement;
  sigSet.append(
    el('div', { class: 'sf-modes', role: 'radiogroup', 'aria-label': labels.signature },
      el('label', { class: 'sf-mode' }, drawRadio, labels.drawMode),
      el('label', { class: 'sf-mode' }, typeRadio, labels.typeMode),
    ),
  );

  const canvas = el('canvas', { class: 'sf-canvas', 'aria-label': labels.drawHelp, role: 'img' }) as HTMLCanvasElement;
  const clear = el('button', { type: 'button', class: 'sf-clear' }, labels.clear) as HTMLButtonElement;
  const padWrap = el('div', { class: 'sf-pad' }, canvas, clear);
  const padHelp = el('p', { class: 'sf-help', id: `${prefix}-pad-help` }, labels.drawHelp);
  const typedPreview = el('p', { class: 'sf-typed-preview', hidden: '', 'aria-hidden': 'true' });
  sigSet.append(padWrap, padHelp, typedPreview, slot('signature.vector', `${prefix}-pad-error`));
  form.append(sigSet);

  const pad = new SignaturePad(canvas, { penColor: getComputedStyle(root).getPropertyValue('--sf-ink').trim() || '#14141c' });
  const resize = () => {
    const ratio = Math.max(window.devicePixelRatio || 1, 1);
    const data = pad.toData();
    canvas.width = canvas.offsetWidth * ratio;
    canvas.height = canvas.offsetHeight * ratio;
    canvas.getContext('2d')!.scale(ratio, ratio);
    pad.clear();
    if (data.length) pad.fromData(data);
  };
  const observer = new ResizeObserver(resize);
  observer.observe(canvas);
  cleanup.push(() => observer.disconnect(), () => pad.off());
  clear.addEventListener('click', () => pad.clear());

  const setMode = () => {
    const typedMode = typeRadio.checked;
    padWrap.hidden = typedMode;
    padHelp.textContent = typedMode ? labels.typeHelp : labels.drawHelp;
    typedPreview.hidden = !typedMode;
    typedPreview.textContent = typed.value;
  };
  drawRadio.addEventListener('change', setMode);
  typeRadio.addEventListener('change', setMode);
  typed.addEventListener('input', () => {
    typedPreview.textContent = typed.value;
  });

  // Bot check, errors and submit ------------------------------------------------------------------
  let botToken: string | undefined;
  let turnstile: TurnstileApi | undefined;
  let widgetId: string | undefined;
  if (options.turnstileSiteKey && data.botCheck === 'turnstile') {
    const box = el('div', { class: 'sf-botcheck' });
    form.append(box);
    turnstile = await loadTurnstile();
    widgetId = turnstile.render(box, {
      sitekey: options.turnstileSiteKey,
      callback: (token) => {
        botToken = token;
      },
      'expired-callback': () => {
        botToken = undefined;
      },
      'error-callback': () => {
        botToken = undefined;
      },
    });
    cleanup.push(() => turnstile?.remove(widgetId));
  }

  const summary = el('div', { class: 'sf-summary', role: 'alert', tabindex: '-1', hidden: '' });
  const submit = el('button', { type: 'submit', class: 'sf-submit' }, labels.sign) as HTMLButtonElement;
  form.append(summary, el('div', { class: 'sf-actions' }, submit));

  // A field's error clears as soon as the signer changes it.
  const clearOne = (event: Event) => {
    for (const [key, input] of inputs) {
      if (input !== event.target) continue;
      input.removeAttribute('aria-invalid');
      const errorSlot = errorSlots.get(key);
      if (errorSlot) errorSlot.textContent = '';
    }
  };
  form.addEventListener('input', clearOne);
  form.addEventListener('change', clearOne);
  pad.addEventListener('endStroke', () => {
    const errorSlot = errorSlots.get('signature.vector');
    if (errorSlot) errorSlot.textContent = '';
  });

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    void send();
  });

  root.replaceChildren(form);
  root.removeAttribute('aria-busy');

  async function send(): Promise<void> {
    clearErrors();
    const mode = typeRadio.checked ? 'typed' : 'drawn';
    const local: Record<string, string> = {};
    if (mode === 'drawn' && pad.isEmpty()) local['signature.vector'] = labels.emptySignature;
    if (turnstile && !botToken) local.botToken = labels.botCheckPending;
    if (Object.keys(local).length) {
      showErrors(local);
      return;
    }

    submit.disabled = true;
    submit.textContent = labels.signing;
    try {
      const fields: Record<string, string | boolean> = {};
      for (const field of data.fields) {
        const input = inputs.get(`fields.${field.name}`)!;
        fields[field.name] = field.type === 'checkbox' ? (input as HTMLInputElement).checked : input.value;
      }
      const consents: Record<string, boolean> = {};
      for (const consent of data.consents) consents[consent.name] = (inputs.get(`consents.${consent.name}`) as HTMLInputElement).checked;

      const body = {
        sessionId: data.session.id,
        documentId: data.document.id,
        version: data.document.version,
        lang: data.document.lang,
        textSha256: displayedSha,
        manifestSha256: data.document.manifestSha256,
        fields,
        consents,
        signature: {
          mode,
          typedName: typed.value,
          vector: mode === 'drawn' ? pad.toData().map((group) => ({ points: group.points })) : [],
          png: mode === 'drawn' ? pad.toDataURL('image/png') : typedSignaturePng(typed.value, root),
        },
        client: {
          reportedAt: new Date().toISOString(),
          timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone,
          screen: `${screen.width}x${screen.height}`,
          viewport: `${innerWidth}x${innerHeight}`,
          locale: navigator.language,
          timeOnPageMs: Math.round(performance.now() - started),
          pointer: matchMedia('(pointer: coarse)').matches ? 'coarse' : 'fine',
        },
        ...(botToken ? { botToken } : {}),
      };

      let result: Response;
      try {
        result = await fetch(`${endpoint}/api/sign`, { method: 'POST', headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify(body) });
      } catch {
        showErrors({ form: labels.networkError });
        return;
      }
      if (result.status === 201) {
        const receipt = (await result.json()) as Receipt;
        showReceipt(receipt);
        options.onSigned?.(receipt);
        return;
      }
      const problem = (await result.json().catch(() => ({}))) as { error?: string; fields?: Record<string, string> };
      showErrors(problem.fields ?? { form: problem.error ?? labels.networkError });
      if (turnstile) {
        turnstile.reset(widgetId);
        botToken = undefined;
      }
    } finally {
      submit.disabled = false;
      submit.textContent = labels.sign;
    }
  }

  function showReceipt(receipt: Receipt): void {
    destroyWidgets();
    const done = el('section', { class: 'sf-receipt', tabindex: '-1', 'aria-labelledby': `${prefix}-done` },
      el('h2', { id: `${prefix}-done`, class: 'sf-title' }, labels.signedTitle),
      el('p', {}, labels.signedBody),
      el('dl', { class: 'sf-receipt-facts' },
        el('dt', {}, labels.recordId), el('dd', {}, receipt.id),
        el('dt', {}, labels.recordHash), el('dd', { class: 'sf-mono' }, receipt.hash),
      ),
      el('p', { class: 'sf-actions' },
        el('a', { class: 'sf-submit', href: receipt.pdfUrl, download: '' }, labels.downloadPdf),
        el('a', { class: 'sf-link', href: receipt.recordUrl, download: '' }, labels.downloadRecord),
      ),
    );
    root.replaceChildren(done);
    done.focus();
  }

  function showErrors(errors: Record<string, string>): void {
    const list = el('ul');
    let first: HTMLElement | undefined;
    for (const [key, message] of Object.entries(errors)) {
      const input = inputs.get(key);
      const label = describe(key);
      const errorSlot = errorSlots.get(key);
      if (errorSlot) errorSlot.textContent = message;
      if (input) {
        input.setAttribute('aria-invalid', 'true');
        first ??= input;
        const link = el('a', { href: `#${input.id}` }, label ? `${label.replace(/[.:]+$/, '')}: ${message}` : message);
        link.addEventListener('click', (event) => {
          event.preventDefault();
          input.focus();
        });
        list.append(el('li', {}, link));
      } else {
        list.append(el('li', {}, label ? `${label.replace(/[.:]+$/, '')}: ${message}` : message));
      }
    }
    summary.replaceChildren(el('p', {}, labels.fixErrors), list);
    summary.hidden = false;
    summary.focus();
  }

  function clearErrors(): void {
    summary.hidden = true;
    for (const input of inputs.values()) input.removeAttribute('aria-invalid');
    for (const errorSlot of errorSlots.values()) errorSlot.textContent = '';
  }

  function describe(key: string): string {
    const [kind, name] = key.split('.') as [string, string | undefined];
    if (kind === 'fields') return data.fields.find((f) => f.name === name)?.label ?? name ?? '';
    if (kind === 'consents') return data.consents.find((c) => c.name === name)?.label ?? name ?? '';
    if (kind === 'signature') return labels.signature;
    return '';
  }

  function renderField(field: FieldSpec): HTMLElement {
    const id = `${prefix}-${field.name}`;
    const required = field.required ?? false;
    const describedBy = [field.help ? `${id}-help` : '', `${id}-error`].filter(Boolean).join(' ');
    let input: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement;
    if (field.type === 'country') {
      input = el('select', { id, autocomplete: 'country' }) as HTMLSelectElement;
      input.append(new Option(labels.chooseCountry, ''));
      for (const [code, name] of countries(data.document.lang)) input.append(new Option(name, code));
    } else if (field.type === 'select') {
      input = el('select', { id }) as HTMLSelectElement;
      input.append(new Option(labels.chooseOption, ''));
      for (const option of field.options ?? []) input.append(new Option(option, option));
    } else if (field.type === 'textarea') {
      input = el('textarea', { id, rows: '4' }) as HTMLTextAreaElement;
    } else {
      input = el('input', { id, type: field.type === 'email' ? 'email' : 'text' }) as HTMLInputElement;
      if (field.type === 'email') input.setAttribute('autocomplete', 'email');
      if (field.role === 'signerName') input.setAttribute('autocomplete', 'name');
    }
    if (field.maxLength && !(input instanceof HTMLSelectElement)) input.setAttribute('maxlength', String(field.maxLength));
    if (required) input.setAttribute('required', '');
    input.setAttribute('aria-describedby', describedBy);
    inputs.set(`fields.${field.name}`, input);
    return el('div', { class: 'sf-field' },
      el('label', { for: id }, field.label, ' ', el('span', { class: 'sf-req' }, `(${required ? labels.required : labels.optional})`)),
      input,
      ...(field.help ? [el('p', { class: 'sf-help', id: `${id}-help` }, field.help)] : []),
      slot(`fields.${field.name}`, `${id}-error`),
    );
  }

  function renderCheckbox(key: string, label: string, required: boolean): HTMLElement {
    const id = `${prefix}-${key.replace('.', '-')}`;
    const box = el('input', { id, type: 'checkbox', 'aria-describedby': `${id}-error` }) as HTMLInputElement;
    if (required) box.setAttribute('required', '');
    inputs.set(key, box);
    return el('div', { class: 'sf-check' }, box, el('label', { for: id }, label), slot(key, `${id}-error`));
  }

  function slot(key: string, id: string): HTMLElement {
    const node = el('p', { class: 'sf-field-error', id });
    errorSlots.set(key, node);
    return node;
  }

  function destroyWidgets(): void {
    while (cleanup.length) cleanup.pop()!();
  }

  function destroy(): void {
    destroyWidgets();
    root.replaceChildren();
  }

  return { destroy };
}

/** Renders a typed name as the signature image for signers who cannot draw. */
function typedSignaturePng(name: string, root: HTMLElement): string {
  const canvas = document.createElement('canvas');
  canvas.width = 900;
  canvas.height = 240;
  const ctx = canvas.getContext('2d')!;
  ctx.fillStyle = getComputedStyle(root).getPropertyValue('--sf-ink').trim() || '#14141c';
  ctx.textBaseline = 'middle';
  let size = 96;
  do {
    ctx.font = `italic ${size}px "Segoe Script", "Brush Script MT", "Snell Roundhand", cursive`;
    size -= 4;
  } while (ctx.measureText(name).width > 840 && size > 24);
  ctx.fillText(name, 30, 120);
  return canvas.toDataURL('image/png');
}

const NOT_COUNTRIES = new Set(['EU', 'EZ', 'UN', 'QO', 'XA', 'XB', 'ZZ', 'AA']);
const countryCache = new Map<string, [string, string][]>();

/** Every ISO 3166-1 alpha-2 region the browser knows, named in the document language. */
function countries(lang: string): [string, string][] {
  const cached = countryCache.get(lang);
  if (cached) return cached;
  const names = new Intl.DisplayNames([lang, 'en'], { type: 'region', fallback: 'none' });
  const list: [string, string][] = [];
  for (let a = 65; a <= 90; a++) {
    for (let b = 65; b <= 90; b++) {
      const code = String.fromCharCode(a, b);
      if (NOT_COUNTRIES.has(code)) continue;
      const name = names.of(code);
      if (name) list.push([code, name]);
    }
  }
  list.sort((x, y) => x[1].localeCompare(y[1], lang));
  countryCache.set(lang, list);
  return list;
}

let turnstileLoading: Promise<TurnstileApi> | undefined;

function loadTurnstile(): Promise<TurnstileApi> {
  const win = window as unknown as { turnstile?: TurnstileApi };
  if (win.turnstile) return Promise.resolve(win.turnstile);
  turnstileLoading ??= new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true;
    script.onload = () => (win.turnstile ? resolve(win.turnstile) : reject(new Error('Turnstile did not load')));
    script.onerror = () => reject(new Error('Turnstile did not load'));
    document.head.append(script);
  });
  return turnstileLoading;
}

async function errorMessage(response: Response, labels: Labels): Promise<string> {
  try {
    const body = (await response.json()) as { error?: string };
    return body.error ?? labels.networkError;
  } catch {
    return labels.networkError;
  }
}

function el(tag: string, attrs: Record<string, string> = {}, ...children: (Node | string)[]): HTMLElement {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  node.append(...children);
  return node;
}

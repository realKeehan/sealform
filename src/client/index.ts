// The signing form. mountSealform(element, options) fetches the published document, renders it with
// its fields, consent boxes and a signature pad, and submits to a sealform server.
//
// It brings no colors or fonts of its own beyond sealform.css, which reads --sf-* custom properties so
// the host site can theme it.

import SignaturePad from 'signature_pad';
import { COUNTRY_CODES, sha256Hex } from '../core/index.ts';
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
  /** Present for a private link: fields the sender fixed, shown read-only. */
  prefill?: Record<string, string>;
  envelope?: { label: string; expiresAt: string };
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
  drawHelp: string;
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
  fixedByLink: string;
  readFocused: string;
  closeReader: string;
  downloadUnsigned: string;
  unsignedNotice: string;
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
  drawHelp: 'Draw your signature with a finger, stylus or mouse.',
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
  emptySignature: 'draw your signature in the box',
  botCheckPending: 'Please complete the check above.',
  fixedByLink: 'Fixed by the link you were sent.',
  readFocused: 'Read in focused view',
  closeReader: 'Close reading view',
  downloadUnsigned: 'Download unsigned copy (.txt)',
  unsignedNotice: 'Unsigned review copy. Opening or downloading it does not sign the agreement.',
};

export interface MountOptions {
  /** Where the server's handler is mounted, such as "/sealform" or "https://sign.example.com/sealform". */
  endpoint: string;
  /** The public document to sign. Not needed with an envelopeToken. */
  documentId?: string;
  /** Opens a private contract link instead of a public document. */
  envelopeToken?: string;
  lang?: string;
  /** Cloudflare Turnstile site key, when the server uses TurnstileCheck. */
  turnstileSiteKey?: string;
  /** Must match the server's expected Turnstile action when configured. */
  turnstileAction?: string;
  labels?: Partial<Labels>;
  onSigned?: (receipt: Receipt) => void;
}

export interface MountedForm {
  destroy(): void;
}

type TurnstileApi = {
  render(el: HTMLElement, options: { sitekey: string; action?: string; callback: (token: string) => void; 'expired-callback'?: () => void; 'error-callback'?: () => void }): string;
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
  if (!options.envelopeToken && !options.documentId) throw new Error('mountSealform needs a documentId or an envelopeToken');
  const source = options.envelopeToken ? `${endpoint}/api/envelopes/${encodeURIComponent(options.envelopeToken)}` : `${endpoint}/api/documents/${encodeURIComponent(options.documentId!)}`;
  const response = await fetch(`${source}${query}`, { headers: { accept: 'application/json' } });
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
  const readingActions = el('div', { class: 'sf-reading-actions' });
  const focusButton = el('button', { type: 'button', class: 'sf-read-focus' }, labels.readFocused) as HTMLButtonElement;
  const copyText = [labels.unsignedNotice, `${data.document.title} (${data.document.version}, ${data.document.lang})`, `Document SHA-256: ${data.document.sha256}`, '', data.document.text,
    ...(data.disclosure ? ['', `Electronic signature disclosure (${data.disclosure.version})`, `Disclosure SHA-256: ${data.disclosure.sha256}`, '', data.disclosure.text] : []),
  ].join('\n');
  const downloadUrl = URL.createObjectURL(new Blob([copyText], { type: 'text/plain;charset=utf-8' }));
  cleanup.push(() => URL.revokeObjectURL(downloadUrl));
  const download = el('a', { href: downloadUrl, download: `${data.document.id}-${data.document.version}-${data.document.lang}-unsigned.txt` }, labels.downloadUnsigned);
  readingActions.append(focusButton, download);
  form.append(readingActions, docRegion);

  const readerTitle = `${prefix}-reader-title`;
  const readerHelp = `${prefix}-reader-help`;
  const reader = el('dialog', { class: 'sf sf-reader', 'aria-labelledby': readerTitle, 'aria-describedby': readerHelp }) as HTMLDialogElement;
  const closeReader = el('button', { type: 'button', class: 'sf-reader-close' }, labels.closeReader) as HTMLButtonElement;
  const readerText = el('article', { class: 'sf-reader-document' });
  readerText.append(renderMarkdown(data.document.text));
  if (data.disclosure) readerText.append(el('h3', {}, labels.disclosure), renderMarkdown(data.disclosure.text));
  reader.append(el('div', { class: 'sf-reader-controls' }, el('h2', { id: readerTitle }, data.document.title), closeReader), el('p', { id: readerHelp }, labels.unsignedNotice), readerText);
  form.append(reader);
  focusButton.addEventListener('click', () => { reader.showModal(); closeReader.focus(); });
  closeReader.addEventListener('click', () => reader.close());
  reader.addEventListener('close', () => focusButton.focus());
  cleanup.push(() => { if (reader.open) reader.close(); });

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

  // Shown once a country is chosen: that country's notices, and any fields its rules add.
  const noticeBox = el('section', { class: 'sf-notices', hidden: '', 'aria-live': 'polite' });
  const extraBox = el('div', { class: 'sf-extra' });
  if (detailFields.length) {
    const fieldset = el('fieldset', { class: 'sf-fieldset' }, el('legend', {}, labels.yourDetails));
    for (const field of detailFields) fieldset.append(renderField(field));
    fieldset.append(extraBox);
    form.append(fieldset, noticeBox);
  }

  const countrySpec = data.fields.find((field) => field.type === 'country');
  const countryInput = countrySpec ? inputs.get(`fields.${countrySpec.name}`) : undefined;
  let profile: { sha256: string; extra: FieldSpec[]; country: string } | undefined;
  let extraKeys: string[] = [];

  async function loadProfile(code: string): Promise<void> {
    for (const key of extraKeys) {
      inputs.delete(key);
      errorSlots.delete(key);
    }
    extraKeys = [];
    extraBox.replaceChildren();
    profile = undefined;
    noticeBox.hidden = true;
    if (!code) return;
    const result = await fetch(`${endpoint}/api/profile/${encodeURIComponent(code)}`, { headers: { accept: 'application/json' } }).catch(() => undefined);
    if (!result?.ok) return;
    const body = (await result.json()) as { profile: { name: string; notices: string[]; requiredFields: FieldSpec[] }; sha256: string };
    const extra = body.profile.requiredFields.filter((field) => !data.fields.some((own) => own.name === field.name));
    for (const field of extra) {
      extraBox.append(renderField({ ...field, required: field.required ?? false }));
      extraKeys.push(`fields.${field.name}`);
    }
    noticeBox.replaceChildren(el('h3', {}, body.profile.name), ...body.profile.notices.map((notice) => el('p', {}, notice)));
    noticeBox.hidden = false;
    profile = { sha256: body.sha256, extra, country: code };
  }
  countryInput?.addEventListener('change', () => void loadProfile((countryInput as HTMLSelectElement).value));

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

  const canvas = el('canvas', { class: 'sf-canvas', 'aria-label': labels.drawHelp, role: 'img' }) as HTMLCanvasElement;
  const clear = el('button', { type: 'button', class: 'sf-clear' }, labels.clear) as HTMLButtonElement;
  const padWrap = el('div', { class: 'sf-pad' }, canvas, clear);
  const padHelp = el('p', { class: 'sf-help', id: `${prefix}-pad-help` }, labels.drawHelp);
  sigSet.append(padWrap, padHelp, slot('signature.vector', `${prefix}-pad-error`));
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
      ...(options.turnstileAction ? { action: options.turnstileAction } : {}),
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
    const local: Record<string, string> = {};
    if (pad.isEmpty()) local['signature.vector'] = labels.emptySignature;
    if (turnstile && !botToken) local.botToken = labels.botCheckPending;
    if (Object.keys(local).length) {
      showErrors(local);
      return;
    }

    submit.disabled = true;
    submit.textContent = labels.signing;
    try {
      // The notices must be the ones for the country that is chosen right now.
      if (countryInput && countryInput.value && profile?.country !== countryInput.value) await loadProfile(countryInput.value);
      const fields: Record<string, string | boolean> = {};
      for (const field of [...data.fields, ...(profile?.extra ?? [])]) {
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
          typedName: typed.value,
          vector: pad.toData().map((group) => ({ points: group.points })),
          png: pad.toDataURL('image/png'),
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
        ...(profile ? { profileSha256: profile.sha256 } : {}),
        ...(options.envelopeToken ? { envelopeToken: options.envelopeToken } : {}),
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
    const fixed = data.prefill?.[field.name];
    if (fixed !== undefined) {
      input.value = fixed;
      input.setAttribute('readonly', '');
      input.setAttribute('aria-readonly', 'true');
    }
    inputs.set(`fields.${field.name}`, input);
    return el('div', { class: 'sf-field' },
      el('label', { for: id }, field.label, ' ', el('span', { class: 'sf-req' }, `(${required ? labels.required : labels.optional})`)),
      input,
      ...(field.help ? [el('p', { class: 'sf-help', id: `${id}-help` }, field.help)] : []),
      ...(fixed !== undefined ? [el('p', { class: 'sf-help' }, labels.fixedByLink)] : []),
      slot(`fields.${field.name}`, `${id}-error`),
    );
  }

  function renderCheckbox(key: string, label: string, required: boolean): HTMLElement {
    const id = `${prefix}-${key.replace('.', '-')}`;
    const box = el('input', { id, type: 'checkbox', 'aria-describedby': `${id}-error` }) as HTMLInputElement;
    if (required) box.setAttribute('required', '');
    inputs.set(key, box);
    const caption = el('label', { for: id }, label);
    if (required) caption.append(' ', el('span', { class: 'sf-required-marker', 'aria-hidden': 'true' }, '*'));
    return el('div', { class: 'sf-check' }, box, caption, slot(key, `${id}-error`));
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

const countryCache = new Map<string, [string, string][]>();

/** The official country codes, named in the document language. */
function countries(lang: string): [string, string][] {
  const cached = countryCache.get(lang);
  if (cached) return cached;
  const names = new Intl.DisplayNames([lang, 'en'], { type: 'region', fallback: 'code' });
  const list = COUNTRY_CODES.map((code): [string, string] => [code, names.of(code) ?? code]);
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

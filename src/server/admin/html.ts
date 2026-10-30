// Server-rendered admin pages. Every interpolated value is escaped unless wrapped in raw(), so record
// contents (names, answers) can never become markup in the dashboard.

export class Raw {
  readonly value: string;
  constructor(value: string) {
    this.value = value;
  }
  toString(): string {
    return this.value;
  }
}

export function raw(value: string): Raw {
  return new Raw(value);
}

export function escape(value: unknown): string {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

type Part = Raw | string | number | boolean | null | undefined | Part[];

function render(part: Part): string {
  if (part === null || part === undefined || part === false) return '';
  if (part instanceof Raw) return part.value;
  if (Array.isArray(part)) return part.map(render).join('');
  return escape(part);
}

export function html(strings: TemplateStringsArray, ...values: Part[]): Raw {
  let out = '';
  strings.forEach((chunk, i) => {
    out += chunk;
    if (i < values.length) out += render(values[i]!);
  });
  return new Raw(out);
}

export interface LayoutInput {
  base: string;
  title: string;
  body: Raw;
  user?: { email: string; role: string };
  csrf?: string;
  nav?: string;
  flash?: { kind: 'ok' | 'error'; text: string } | undefined;
  operatorName: string;
}

export function layout(input: LayoutInput): string {
  const link = (href: string, label: string, key: string) =>
    html`<a href="${input.base}${href}" ${input.nav === key ? raw('aria-current="page"') : ''}>${label}</a>`;
  const role = input.user?.role;
  return `<!doctype html>${html`<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" href="data:,">
<title>${input.title} · ${input.operatorName} signing admin</title>
<link rel="stylesheet" href="${input.base}/admin.css">
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="top">
  <p class="brand">${input.operatorName} <span>signing admin</span></p>
  ${input.user
    ? html`<nav aria-label="Admin">
    ${link('/', 'Overview', 'home')}
    ${link('/submissions', 'Submissions', 'submissions')}
    ${role !== 'reviewer' ? link('/documents', 'Documents', 'documents') : ''}
    ${role !== 'reviewer' ? link('/contracts', 'Contracts', 'contracts') : ''}
    ${role === 'owner' ? link('/accounts', 'Accounts', 'accounts') : ''}
    ${link('/sign-ins', 'Sign-ins', 'sign-ins')}
    ${role === 'owner' ? link('/audit', 'Audit log', 'audit') : ''}
    ${link('/account', 'My account', 'account')}
  </nav>
  <form method="post" action="${input.base}/logout" class="logout">
    <input type="hidden" name="csrf" value="${input.csrf}">
    <span>${input.user.email}</span> <button type="submit">Sign out</button>
  </form>`
    : ''}
</header>
<main id="main">
${input.flash ? html`<p class="flash flash--${input.flash.kind}" role="status">${input.flash.text}</p>` : ''}
${input.body}
</main>
</body>
</html>`}`;
}

export function csrfField(token: string): Raw {
  return html`<input type="hidden" name="csrf" value="${token}">`;
}

export function shortDate(iso: string | null | undefined): string {
  return iso ? iso.replace('T', ' ').replace(/\.\d+Z$/, ' UTC').replace(/Z$/, ' UTC') : '';
}

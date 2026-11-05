import assert from 'node:assert/strict';
import { test } from 'node:test';
import { renderDocumentMarkdown } from '../src/server/admin/markdown.ts';

test('document preview renders agreement structure and preserves numbered clauses', () => {
  const rendered = renderDocumentMarkdown('# Agreement\n\n1.1 **Scope.** Read *carefully*.\n\n## Duties\n\n- First\n- Second\n\n1. Sign\n2. Save').value;
  assert.match(rendered, /<h3>Agreement<\/h3>/);
  assert.match(rendered, /<p>1\.1 <strong>Scope\.<\/strong> Read <em>carefully<\/em>\.<\/p>/);
  assert.match(rendered, /<h4>Duties<\/h4>/);
  assert.match(rendered, /<ul><li>First<\/li><li>Second<\/li><\/ul>/);
  assert.match(rendered, /<ol><li>Sign<\/li><li>Save<\/li><\/ol>/);
});

test('document preview escapes raw HTML and rejects unsafe link protocols', () => {
  const rendered = renderDocumentMarkdown('<script>alert(1)</script>\n\n[bad](javascript:alert) [data](data:text/html,test)\n\n**<img src=x onerror=alert>**').value;
  assert.doesNotMatch(rendered, /<script|<img|href=/);
  assert.match(rendered, /&lt;script&gt;/);
  assert.match(rendered, /<strong>&lt;img/);
  assert.match(rendered, /\[bad\]\(javascript:alert\)/);
});

test('document preview safely renders links and keeps their destinations visible', () => {
  const rendered = renderDocumentMarkdown('[Site](https://example.com/?a=1&b=2) [Email](mailto:help@example.com)').value;
  assert.match(rendered, /href="https:\/\/example\.com\/\?a=1&amp;b=2"/);
  assert.match(rendered, /rel="noopener noreferrer" target="_blank"/);
  assert.match(rendered, /href="mailto:help@example\.com"/);
  assert.match(rendered, /\(help@example\.com\)/);
});

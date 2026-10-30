import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalize, sha256Hex } from '../src/core/index.ts';

test('sorts keys and strips whitespace', () => {
  assert.equal(canonicalize({ b: 1, a: [true, null, 'x'], c: { z: 0, y: -1.5 } }), '{"a":[true,null,"x"],"b":1,"c":{"y":-1.5,"z":0}}');
});

test('key order does not change the output', () => {
  assert.equal(canonicalize({ one: 1, two: { b: 2, a: 1 } }), canonicalize({ two: { a: 1, b: 2 }, one: 1 }));
});

test('sorts keys by UTF-16 code units, as RFC 8785 requires', () => {
  // U+1F600 is a surrogate pair starting 0xD83D, which sorts before U+FB01 (0xFB01) in UTF-16
  // although its code point is higher.
  assert.equal(canonicalize({ 'ﬁ': 1, '\u{1F600}': 2, a: 3 }), '{"a":3,"\u{1F600}":2,"ﬁ":1}');
});

test('serializes numbers the ECMAScript way', () => {
  assert.equal(canonicalize([1e21, 1e-7, 0.1, -0, 100]), '[1e+21,1e-7,0.1,0,100]');
});

test('escapes strings minimally', () => {
  assert.equal(canonicalize('line\nquote" tab\t \u0001 é'), '"line\\nquote\\" tab\\t \\u0001 é"');
});

test('omits undefined object members but rejects other non-JSON values', () => {
  assert.equal(canonicalize({ a: 1, b: undefined }), '{"a":1}');
  assert.throws(() => canonicalize([undefined]), /Undefined array item/);
  assert.throws(() => canonicalize({ n: Number.NaN }), /Non-finite/);
  assert.throws(() => canonicalize({ n: Infinity }), /Non-finite/);
  assert.throws(() => canonicalize({ d: new Date(0) }), /plain objects/);
  assert.throws(() => canonicalize({ s: '\uD800' }), /Lone surrogate/);
  assert.throws(() => canonicalize(10n), /bigint/);
});

test('sha256 matches the published test vector', async () => {
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

test('the country list is the official ISO 3166-1 set, with no retired or reserved codes', async () => {
  const { COUNTRY_CODES, isCountryCode } = await import('../src/core/index.ts');
  assert.equal(COUNTRY_CODES.length, 250, '249 official codes plus XK');
  assert.equal(new Set(COUNTRY_CODES).size, COUNTRY_CODES.length, 'no duplicates');
  for (const ok of ['US', 'DE', 'LV', 'AR', 'JP', 'ZA', 'NL', 'BE', 'GB', 'XK']) assert.equal(isCountryCode(ok), true, ok);
  for (const bad of ['UK', 'DD', 'YU', 'SU', 'EU', 'UN', 'AC', 'IC', 'ZZ', 'us', 'USA', '', 'U']) assert.equal(isCountryCode(bad), false, bad);
  const names = new Intl.DisplayNames(['en'], { type: 'region', fallback: 'none' });
  assert.equal(new Set(COUNTRY_CODES.map((code) => names.of(code))).size, COUNTRY_CODES.length, 'every code has a distinct name');
});

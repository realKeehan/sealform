import assert from 'node:assert/strict';
import { test } from 'node:test';
import { TurnstileCheck } from '../src/server/guards.ts';

function check(result: unknown, hostnames: string | readonly string[] = ['example.com', 'sign.example.com'], action = 'sign') {
  const fakeFetch = (async () => new Response(JSON.stringify(result))) as typeof fetch;
  return new TurnstileCheck('test-secret', fakeFetch, hostnames, action);
}

test('Turnstile accepts the configured hostname and action only', async () => {
  assert.equal(await check({ success: true, hostname: 'example.com', action: 'sign' }).verify('token', '192.0.2.1'), true);
  assert.equal(await check({ success: true, hostname: 'sign.example.com', action: 'sign' }).verify('token', '192.0.2.1'), true);
  for (const result of [
    { success: true, hostname: 'localhost', action: 'sign' },
    { success: true, hostname: 'example.com.attacker.invalid', action: 'sign' },
    { success: true, hostname: 'example.com', action: 'login' },
    { success: true, hostname: 'example.com' },
    { success: true, action: 'sign' },
    { success: false, hostname: 'example.com', action: 'sign' },
  ]) assert.equal(await check(result).verify('token', '192.0.2.1'), false);
});

test('an empty hostname allowlist fails closed', async () => {
  assert.equal(await check({ success: true, hostname: 'example.com', action: 'sign' }, []).verify('token', '192.0.2.1'), false);
});

test('single-host and unconfigured-action callers remain compatible', async () => {
  const fakeFetch = (async () => new Response(JSON.stringify({ success: true, hostname: 'example.com' }))) as typeof fetch;
  assert.equal(await new TurnstileCheck('test-secret', fakeFetch, 'example.com').verify('token', '192.0.2.1'), true);
  assert.equal(await new TurnstileCheck('test-secret', fakeFetch).verify('token', '192.0.2.1'), true);
});

test('invalid tokens and verification failures fail closed', async () => {
  let calls = 0;
  const fakeFetch = (async () => { calls++; throw new Error('offline'); }) as typeof fetch;
  const botCheck = new TurnstileCheck('test-secret', fakeFetch, 'example.com', 'sign');
  assert.equal(await botCheck.verify(undefined, '192.0.2.1'), false);
  assert.equal(await botCheck.verify('x'.repeat(2049), '192.0.2.1'), false);
  assert.equal(calls, 0);
  assert.equal(await botCheck.verify('token', '192.0.2.1'), false);
  assert.equal(calls, 1);
});

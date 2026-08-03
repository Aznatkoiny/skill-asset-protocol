import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { Hono } from 'hono';

import { createOperatorConsoleApp } from '../src/operator/console.mjs';

const INDEX = fs.readFileSync(new URL('../operator-console/index.html', import.meta.url), 'utf8');
const SCRIPT = fs.readFileSync(new URL('../operator-console/app.mjs', import.meta.url), 'utf8');
const STYLES = fs.readFileSync(new URL('../operator-console/styles.css', import.meta.url), 'utf8');

const SECURITY_HEADERS = Object.freeze({
  'content-security-policy': "default-src 'self'; connect-src 'self'; frame-ancestors 'none'",
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
});

test('operator console is exactly four local authority views', () => {
  const views = [...INDEX.matchAll(/data-view="([a-z]+)"/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(views)], ['overview', 'policies', 'approvals', 'receipts']);
  for (const view of views) assert.match(INDEX, new RegExp(`id="view-${view}"`));
  assert.match(INDEX, /Wallet Kernel/);
  assert.match(INDEX, /reserved/i);
  assert.match(INDEX, /unresolved/i);
  assert.match(INDEX, /policy/i);
  assert.match(INDEX, /approval/i);
  assert.match(INDEX, /receipt/i);
  assert.match(INDEX, /case hash/i);

  assert.doesNotMatch(INDEX, /<style\b|<script(?!\s+type="module"\s+src="\.\/app\.mjs")/i);
  assert.doesNotMatch(INDEX, /https?:\/\/|<iframe\b|<textarea\b|type="password"/i);
  assert.doesNotMatch(INDEX, /owner.?token|private.?key|raw prompt|raw output/i);
  assert.equal((INDEX.match(/<nav\b/g) ?? []).length, 1);
  assert.equal((INDEX.match(/<main\b/g) ?? []).length, 1);
});

test('browser code burns the launch fragment before exchange and retains only CSRF authority', () => {
  const fragmentRead = SCRIPT.indexOf('window.location.hash');
  const fragmentRemoval = SCRIPT.indexOf('history.replaceState');
  const sessionExchange = SCRIPT.indexOf("'/operator/v1/session'");
  assert.ok(fragmentRead >= 0);
  assert.ok(fragmentRemoval > fragmentRead);
  assert.ok(sessionExchange > fragmentRemoval);
  assert.match(SCRIPT, /launchToken\s*=\s*null/);
  assert.match(SCRIPT, /x-csrf-token/i);
  assert.match(SCRIPT, /textContent/);
  assert.doesNotMatch(SCRIPT, /innerHTML|insertAdjacentHTML|eval\s*\(|localStorage|sessionStorage/);
  assert.doesNotMatch(SCRIPT, /owner.?token|private.?key|payment-signature/i);
  assert.doesNotMatch(SCRIPT, /https?:\/\//);
  assert.match(SCRIPT, /body:\s*body === undefined \? undefined : canonicalJson\(body\)/);
});

test('console exposes only the guarded operator mutations required for recovery', () => {
  for (const routeFragment of [
    '/agents/',
    '/revoke',
    '/sessions/',
    '/transition-policy',
    '/close',
    '/reconciliations/',
    '/abandon-candidate',
  ]) assert.match(SCRIPT, new RegExp(routeFragment.replaceAll('/', '\\/')));
  assert.match(SCRIPT, /hold remains/i);
  assert.match(SCRIPT, /fresh case hash/i);
  assert.match(SCRIPT, /expectedEnrollmentHash/);
  assert.match(SCRIPT, /expectedSessionHash/);
  assert.match(SCRIPT, /expectedIntentHash/);
  assert.match(SCRIPT, /expectedCaseHash/);
  assert.match(SCRIPT, /paymentTransactionId/);
  assert.match(SCRIPT, /refundTransactionId/);
  assert.match(SCRIPT, /resourcePath/);
  assert.match(SCRIPT, /requestHash/);
  assert.match(SCRIPT, /policyVersionId/);
  assert.match(SCRIPT, /authorizationNonce/);
  assert.match(SCRIPT, /canonicalIdForPath/);
  assert.doesNotMatch(SCRIPT, /encodeURIComponent/);
  assert.match(SCRIPT, /api\('\/operator\/v1\/approvals'\)/);
  assert.doesNotMatch(SCRIPT, /approvals\?state=pending/);
  assert.doesNotMatch(SCRIPT, /paymentPayload|paymentHeader|signature|privateKey|rawEvidence/);
});

test('console styling is local, responsive, keyboard-visible, and motion-safe', () => {
  assert.match(STYLES, /--ledger-blue:/);
  assert.match(STYLES, /receipt-tape/);
  assert.match(STYLES, /:focus-visible/);
  assert.match(STYLES, /prefers-reduced-motion/);
  assert.match(STYLES, /@media\s*\([^)]*max-width/);
  assert.doesNotMatch(STYLES, /@import|url\s*\(|https?:\/\//);
});

test('console app serves only local assets and mounts protected operator JSON', async () => {
  const operatorApp = new Hono();
  operatorApp.get('/operator/v1/overview', (context) => context.json({ status: 'ready' }));
  const app = createOperatorConsoleApp({ operatorApp });

  for (const [pathname, contentType, marker] of [
    ['/operator/', 'text/html; charset=UTF-8', '<title>Wallet Kernel</title>'],
    ['/operator/app.mjs', 'text/javascript; charset=UTF-8', 'history.replaceState'],
    ['/operator/styles.css', 'text/css; charset=UTF-8', '--ledger-blue:'],
  ]) {
    const response = await app.request(pathname);
    assert.equal(response.status, 200, pathname);
    assert.equal(response.headers.get('content-type'), contentType, pathname);
    assert.match(await response.text(), new RegExp(marker.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
      assert.equal(response.headers.get(name), value, `${pathname} ${name}`);
    }
  }

  const api = await app.request('/operator/v1/overview');
  assert.equal(api.status, 200);
  assert.deepEqual(await api.json(), { status: 'ready' });
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    assert.equal(api.headers.get(name), value, name);
  }

  for (const pathname of [
    '/operator',
    '/operator/unknown.js',
    '/operator/%2e%2e/package.json',
    '/agent/v1/overview',
  ]) {
    const response = await app.request(pathname);
    assert.equal(response.status, 404, pathname);
  }
});

test('console factory rejects capability-bearing or extension-shaped dependencies', () => {
  const operatorApp = new Hono();
  for (const value of [
    null,
    {},
    { operatorApp, token: 'forbidden' },
    { operatorApp, walletAdapter: {} },
  ]) {
    assert.throws(() => createOperatorConsoleApp(value));
  }
});

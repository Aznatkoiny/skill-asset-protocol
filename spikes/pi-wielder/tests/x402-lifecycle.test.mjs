import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { Hono } from 'hono';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { payingFetch as policyPayingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { paymentPolicyFor } from './payment-policy-fixture.mjs';
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  x402Paywall,
} from '../src/x402-seller.mjs';

const payTo = `0x${'d'.repeat(40)}`;

const payingFetch = (account, url, init, options = {}) => policyPayingFetch(account, url, init, {
  paymentPolicy: paymentPolicyFor(url, payTo),
  ...options,
});

async function withheldAttempt(account, url, init, options = {}) {
  const paymentPolicy = paymentPolicyFor(url, payTo);
  await assert.rejects(() => policyPayingFetch(account, url, init, {
    ...options,
    paymentPolicy,
  }), (error) => error.code === 'SETTLEMENT_EVIDENCE');
  const persisted = paymentPolicy.recoverSignedAuthorization({
    authorizationId: options.idempotencyKey,
    requestUrl: url,
    method: init.method ?? 'GET',
    bodyBytes: init.body ?? null,
  });
  return {
    ...persisted,
    idempotencyKey: persisted.authorizationId,
    settlementReference: persisted.authorization.nonce,
    paymentPolicy,
  };
}

function resourceApp({ facilitatorTransport, lifecycle = {}, price = '0.25', handler } = {}) {
  const app = new Hono();
  app.post('/resource', x402Paywall({
    price,
    payTo,
    facilitatorTransport,
    lifecycle,
  }), handler ?? ((c) => c.json({ ok: true })));
  return app;
}

test('challenge and retry emit one ordered lifecycle under one idempotency key', async () => {
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  const calls = [];
  const lifecycle = Object.fromEntries([
    'onOffered', 'onSigned', 'onSettled', 'onUnresolved', 'onRejected',
  ].map((name) => [name, async (payload) => calls.push([name, payload])]));
  const app = resourceApp({ facilitatorTransport: transport, lifecycle });
  const result = await payingFetch(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    fetchImpl: (url, init) => app.request(url, init),
    idempotencyKey: 'idem-lifecycle',
  });
  assert.equal(result.res.status, 200);
  assert.deepEqual(calls.map(([name]) => name), ['onOffered', 'onSigned', 'onSettled']);
  assert.ok(calls.every(([, payload]) => payload.idempotencyKey === 'idem-lifecycle'));
  assert.deepEqual(calls[0][1].requirements, calls[1][1].requirements);
  assert.match(calls[0][1].requirements.extra.requestHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(calls[2][1].settlementReference, result.settlementReference);
  assert.equal(calls[2][1].txHash, result.txHash);
  assert.equal(result.amountAtomic, '250000');
  assert.equal(result.amountDisplay, '0.250000');
});

test('a restarted paywall accepts only the complete persisted frozen offer', async () => {
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  let persistedRequirements = null;
  let fetchCount = 0;
  const beforeRestart = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async onOffered({ requirements }) { persistedRequirements = structuredClone(requirements); },
    },
    handler: (c) => c.json({ shouldNotExecute: true }),
  });
  const afterRestart = resourceApp({
    facilitatorTransport: transport,
    price: '9.99',
    lifecycle: {
      async loadFrozenOffer() { return structuredClone(persistedRequirements); },
    },
  });
  const result = await payingFetch(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{"input":"same bytes"}',
  }, {
    idempotencyKey: 'idem-restart',
    fetchImpl: (url, init) => (++fetchCount === 1 ? beforeRestart : afterRestart).request(url, init),
  });
  assert.equal(result.res.status, 200);
  assert.equal(fetchCount, 2);
  assert.equal(persistedRequirements.maxAmountRequired, '250000');
  assert.equal(persistedRequirements.payTo, payTo);
});

test('restart rejects different request bytes under the frozen idempotency key before facilitator or execution', async () => {
  let persistedRequirements = null;
  let paidHeaders = null;
  let facilitatorCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async () => {
    facilitatorCalls += 1;
    throw new Error('must not run');
  });
  const beforeRestart = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async onOffered({ requirements }) { persistedRequirements = structuredClone(requirements); },
    },
  });
  let fetchCount = 0;
  const first = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{"input":"original bytes"}',
  }, {
    idempotencyKey: 'idem-restart-conflict',
    fetchImpl: async (url, init) => {
      fetchCount += 1;
      if (fetchCount === 1) return beforeRestart.request(url, init);
      paidHeaders = init.headers;
      return new Response(JSON.stringify({ injected: 'process stopped before retry' }), {
        status: 503, headers: { 'content-type': 'application/json' },
      });
    },
  });
  assert.equal(first.state, 'unresolved');
  const afterRestart = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async loadFrozenOffer() { return structuredClone(persistedRequirements); },
    },
    handler: (c) => { executions += 1; return c.json({ ok: true }); },
  });
  const conflict = await afterRestart.request('http://seller.test/resource', {
    method: 'POST',
    headers: paidHeaders,
    body: '{"input":"different bytes"}',
  });
  assert.equal(conflict.status, 409);
  assert.match((await conflict.json()).error, /different request/);
  assert.equal(facilitatorCalls, 0);
  assert.equal(executions, 0);
});

test('missing idempotency and paid retry without a frozen offer fail before facilitator calls', async () => {
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async () => {
    facilitatorCalls += 1;
    throw new Error('must not run');
  });
  const app = resourceApp({ facilitatorTransport: transport });
  const missing = await app.request('http://seller.test/resource', { method: 'POST', body: '{}' });
  assert.equal(missing.status, 400);
  assert.match((await missing.json()).error, /Idempotency-Key/);
  const orphan = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'idem-orphan', 'X-PAYMENT': Buffer.from('{}').toString('base64') },
    body: '{}',
  });
  assert.equal(orphan.status, 409);
  assert.equal(facilitatorCalls, 0);
});

test('authorization amount must equal the frozen quote exactly before facilitator submission', async () => {
  let facilitatorCalls = 0;
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({ facilitatorTransport: transport });
  let requestCount = 0;
  await assert.rejects(() => payingFetch(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-overpay',
    fetchImpl: (url, init) => {
      requestCount += 1;
      if (requestCount === 2) {
        const payment = JSON.parse(Buffer.from(init.headers['X-PAYMENT'], 'base64').toString('utf8'));
        payment.payload.authorization.value = '250001';
        return app.request(url, {
          ...init,
          headers: { ...init.headers, 'X-PAYMENT': Buffer.from(JSON.stringify(payment)).toString('base64') },
        });
      }
      return app.request(url, init);
    },
  }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED');
  assert.equal(facilitatorCalls, 0);
});

test('seller rejects numeric and unknown authorization fields before facilitator submission', async () => {
  for (const mutate of [
    (authorization) => { authorization.value = 250000; },
    (authorization) => { authorization.injected = true; },
  ]) {
    let facilitatorCalls = 0;
    const facilitator = createMockFacilitator();
    const app = resourceApp({
      facilitatorTransport: createMockFacilitatorTransport(async (url, init) => {
        facilitatorCalls += 1;
        return facilitator.request(url, init);
      }),
    });
    let requestCount = 0;
    await assert.rejects(() => payingFetch(throwawayAccount(), 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      idempotencyKey: `idem-strict-auth-${crypto.randomUUID()}`,
      fetchImpl: (url, init) => {
        requestCount += 1;
        if (requestCount === 2) {
          const payment = JSON.parse(Buffer.from(init.headers['X-PAYMENT'], 'base64').toString('utf8'));
          mutate(payment.payload.authorization);
          return app.request(url, {
            ...init,
            headers: {
              ...init.headers,
              'X-PAYMENT': Buffer.from(JSON.stringify(payment)).toString('base64'),
            },
          });
        }
        return app.request(url, init);
      },
    }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED');
    assert.equal(facilitatorCalls, 0);
  }
});

test('unresolved payment retries return 503 without re-verification or settlement', async () => {
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport(async () => {
    facilitatorCalls += 1;
    throw new Error('must not run');
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async onSigned() { return { kind: 'payment_unresolved', settlementReference: `0x${'1'.repeat(64)}` }; },
    },
  });
  const result = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-unresolved',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(result.state, 'unresolved');
  assert.equal(facilitatorCalls, 0);
});

test('terminal replay requires settled or refunded payment with a transaction and preserves HTTP status', async () => {
  let calls = 0;
  const transport = createMockFacilitatorTransport(async () => {
    calls += 1;
    throw new Error('must not run');
  });
  const account = throwawayAccount();
  for (const [decision, expectedStatus] of [[{
    kind: 'terminal', paymentState: 'rejected', txHash: null, payer: account.address,
    httpStatus: 500, receipt: { receipt: { execution: { message: 'failed' } } },
  }, 503], [{
    kind: 'terminal', paymentState: 'settled', txHash: `0x${'4'.repeat(64)}`,
    payer: account.address.toLowerCase(), httpStatus: 500,
    receipt: { receipt: { execution: { message: 'provider failed' } } },
  }, 500]]) {
    const app = resourceApp({
      facilitatorTransport: transport,
      lifecycle: { async onSigned() { return decision; } },
    });
    if (expectedStatus === 503) {
      const withheld = await withheldAttempt(account, 'http://seller.test/resource', {
        method: 'POST', body: '{}',
      }, {
        idempotencyKey: `idem-terminal-${expectedStatus}`,
        fetchImpl: (url, init) => app.request(url, init),
      });
      assert.equal(withheld.state, 'unresolved');
    } else {
      const result = await payingFetch(account, 'http://seller.test/resource', {
        method: 'POST', body: '{}',
      }, {
        idempotencyKey: `idem-terminal-${expectedStatus}`,
        fetchImpl: (url, init) => app.request(url, init),
      });
      assert.equal(result.res.status, expectedStatus);
      const body = await result.res.json();
      assert.equal(body.replayed, true);
      assert.equal(body.error, 'terminal execution failed');
      assert.equal(result.txHash, decision.txHash);
    }
  }
  assert.equal(calls, 0);
});

test('live facilitator configuration pins one exact HTTPS base before authorization exists', () => {
  let networkCalls = 0;
  for (const malicious of [
    'http://x402.org/facilitator',
    'https://user:pass@x402.org/facilitator',
    'https://x402.org:8443/facilitator',
    'https://x402.org/facilitator/',
    'https://x402.org/facilitator/verify',
    'https://x402.org/facilitator?next=https://evil.test',
    'https://x402.org/facilitator#evil',
  ]) {
    assert.throws(() => createLiveFacilitatorTransport(malicious, async () => { networkCalls += 1; }),
      (error) => error.code === 'FACILITATOR_NOT_APPROVED');
  }
  assert.equal(networkCalls, 0);
  assert.doesNotThrow(() => createLiveFacilitatorTransport(
    APPROVED_LIVE_FACILITATOR_BASE,
    async () => { networkCalls += 1; },
  ));
});

test('verify and settle disable redirects and never follow a signed authorization', async () => {
  for (const redirectOperation of ['verify', 'settle']) {
    const destinations = [];
    const transport = createMockFacilitatorTransport(async (url, init) => {
      const operation = new URL(url).pathname.slice(1);
      destinations.push([url, init.redirect]);
      if (operation === redirectOperation) {
        return new Response(null, { status: 302, headers: { location: 'https://evil.test/collect' } });
      }
      return new Response(JSON.stringify({ isValid: true }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    });
    const app = resourceApp({ facilitatorTransport: transport });
    const result = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      fetchImpl: (url, init) => app.request(url, init),
      idempotencyKey: `idem-redirect-${redirectOperation}`,
    });
    assert.equal(result.state, 'unresolved');
    assert.equal(destinations.at(-1)[0], `http://facilitator.invalid/${redirectOperation}`);
    assert.ok(destinations.every(([, redirect]) => redirect === 'error'));
    assert.ok(destinations.every(([url]) => !url.startsWith('https://evil.test')));
  }
});

test('post-settle journal failure becomes durable unresolved and exact retry never settles twice', async () => {
  const facilitator = createMockFacilitator();
  let verifyCalls = 0;
  let settleCalls = 0;
  let unresolved = false;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const operation = new URL(url).pathname.slice(1);
    if (operation === 'verify') verifyCalls += 1;
    if (operation === 'settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async onSigned() { return unresolved ? { kind: 'payment_unresolved' } : null; },
      async onSettled() { throw new Error('injected journal append failure after settlement'); },
      async onUnresolved() { unresolved = true; },
    },
    handler: (c) => { executions += 1; return c.json({ ok: true }); },
  });
  const first = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-post-settle-gap',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(first.state, 'unresolved');
  assert.equal(unresolved, true);
  const retry = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': first.idempotencyKey, 'X-PAYMENT': first.xPayment },
    body: '{}',
  });
  assert.equal(retry.status, 503);
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
  assert.equal(executions, 0);
});

test('malformed facilitator success evidence is unresolved and never authorizes execution', async () => {
  let unresolvedCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url) => {
    const operation = new URL(url).pathname.slice(1);
    if (operation === 'verify') {
      return new Response(JSON.stringify({ isValid: true }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({
      success: true,
      transaction: 'not-a-transaction',
      payer: `0x${'9'.repeat(40)}`,
      network: 'base-mainnet',
    }), { status: 200, headers: { 'content-type': 'application/json' } });
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    lifecycle: { async onUnresolved() { unresolvedCalls += 1; } },
    handler: (c) => { executions += 1; return c.json({ ok: true }); },
  });
  const result = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-malformed-settlement',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(result.state, 'unresolved');
  assert.equal(unresolvedCalls, 1);
  assert.equal(executions, 0);
});

test('missing or malformed settle result is ambiguous unresolved, while explicit failure is rejected', async () => {
  let caseIndex = 0;
  for (const [settleBody, expectedStatus] of [[{}, 503], [{ success: 'false' }, 503], [{ success: false, errorReason: 'declined' }, 402]]) {
    let unresolvedCalls = 0;
    let rejectedCalls = 0;
    const transport = createMockFacilitatorTransport(async (url) => {
      const operation = new URL(url).pathname.slice(1);
      const body = operation === 'verify' ? { isValid: true } : settleBody;
      return new Response(JSON.stringify(body), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    });
    const app = resourceApp({
      facilitatorTransport: transport,
      lifecycle: {
        async onUnresolved() { unresolvedCalls += 1; },
        async onRejected() { rejectedCalls += 1; },
      },
    });
    const idempotencyKey = `idem-settle-shape-${expectedStatus}-${caseIndex++}`;
    if (expectedStatus === 503) {
      const result = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
        method: 'POST', body: '{}',
      }, {
        idempotencyKey,
        fetchImpl: (url, init) => app.request(url, init),
      });
      assert.equal(result.state, 'unresolved');
    } else {
      await assert.rejects(() => payingFetch(throwawayAccount(), 'http://seller.test/resource', {
        method: 'POST', body: '{}',
      }, {
        idempotencyKey,
        fetchImpl: (url, init) => app.request(url, init),
      }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED');
    }
    assert.equal(unresolvedCalls, expectedStatus === 503 ? 1 : 0);
    assert.equal(rejectedCalls, expectedStatus === 402 ? 1 : 0);
  }
});

test('onUnresolved may observe an already-settled append without turning the response into 500', async () => {
  const facilitator = createMockFacilitator();
  let settled = false;
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    if (new URL(url).pathname === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    lifecycle: {
      async onSigned({ payer }) {
        return settled ? {
          kind: 'settled', txHash: `0x${'8'.repeat(64)}`, payer,
        } : null;
      },
      async onSettled() {
        settled = true;
        throw new Error('lease release failed after append');
      },
      async onUnresolved() { throw new Error('journal already settled'); },
    },
    handler: (c) => { executions += 1; return c.json({ ok: true }); },
  });
  const first = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-settled-append-then-error',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(first.state, 'unresolved');
  const retry = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': first.idempotencyKey, 'X-PAYMENT': first.xPayment },
    body: '{}',
  });
  assert.equal(retry.status, 200);
  assert.equal(settleCalls, 1);
  assert.equal(executions, 1);
});

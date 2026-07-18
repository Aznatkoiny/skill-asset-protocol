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
  DEFAULT_FACILITATOR_RESPONSE_BYTES,
  DEFAULT_FACILITATOR_TIMEOUT_MS,
  DEFAULT_PENDING_OFFER_LIMIT,
  DEFAULT_PENDING_OFFER_TTL_MS,
  DEFAULT_X402_REQUEST_BODY_BYTES,
  DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS,
  MAX_X402_REQUEST_BODY_BYTES,
  x402Paywall,
} from '../src/x402-seller.mjs';

const payTo = `0x${'d'.repeat(40)}`;
const executionQuote = Object.freeze({
  schemaVersion: 2,
  quoteId: `sha256:${'7'.repeat(64)}`,
  grossAtomic: '250000',
  model: 'claude-sonnet-4-6',
  maxInputTokens: 16384,
  maxOutputTokens: 2048,
});

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

function resourceApp({
  facilitatorTransport,
  lifecycle = {},
  price = '0.25',
  quote = null,
  handler,
  maxRequestBodyBytes,
  requestBodyTimeoutMs,
  facilitatorTimeoutMs,
  facilitatorResponseMaxBytes,
  maxPendingOffers,
  pendingOfferTtlMs,
  now,
} = {}) {
  const app = new Hono();
  app.post('/resource', x402Paywall({
    price,
    quote,
    payTo,
    facilitatorTransport,
    lifecycle,
    ...(maxRequestBodyBytes === undefined ? {} : { maxRequestBodyBytes }),
    ...(requestBodyTimeoutMs === undefined ? {} : { requestBodyTimeoutMs }),
    ...(facilitatorTimeoutMs === undefined ? {} : { facilitatorTimeoutMs }),
    ...(facilitatorResponseMaxBytes === undefined ? {} : { facilitatorResponseMaxBytes }),
    ...(maxPendingOffers === undefined ? {} : { maxPendingOffers }),
    ...(pendingOfferTtlMs === undefined ? {} : { pendingOfferTtlMs }),
    ...(now === undefined ? {} : { now }),
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
  let quoteCalls = 0;
  let handlerQuote = null;
  const app = resourceApp({
    facilitatorTransport: transport,
    lifecycle,
    quote: async () => { quoteCalls += 1; return structuredClone(executionQuote); },
    handler: (c) => {
      handlerQuote = structuredClone(c.get('x402').executionQuote);
      return c.json({ ok: true });
    },
  });
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
  assert.equal(calls[0][1].requirements.extra.quoteId, executionQuote.quoteId);
  assert.deepEqual(calls[0][1].executionQuote, executionQuote);
  assert.deepEqual(calls[1][1].executionQuote, executionQuote);
  assert.deepEqual(calls[2][1].executionQuote, executionQuote);
  assert.deepEqual(handlerQuote, executionQuote);
  assert.equal(quoteCalls, 1);
  assert.equal(result.quoteId, executionQuote.quoteId);
  assert.match(calls[0][1].requirements.extra.requestHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(calls[2][1].settlementReference, result.settlementReference);
  assert.equal(calls[2][1].txHash, result.txHash);
  assert.equal(result.amountAtomic, '250000');
  assert.equal(result.amountDisplay, '0.250000');
});

test('a non-authoritative paywall consumes one exact paid authorization only once per offer', async () => {
  const facilitator = createMockFacilitator();
  let verifyCalls = 0;
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const operation = new URL(url).pathname;
    if (operation === '/verify') verifyCalls += 1;
    if (operation === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    handler: (c) => {
      executions += 1;
      return c.json({ ok: true });
    },
  });
  const idempotencyKey = 'idem-local-authorization-consumed-once';
  const first = await payingFetch(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(first.res.status, 200);

  const replay = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': idempotencyKey, 'X-PAYMENT': first.xPayment },
    body: '{}',
  });
  assert.equal(replay.status, 409);
  assert.deepEqual(await replay.json(), {
    error: 'payment authorization was already consumed; response replay is unavailable',
    code: 'PAYMENT_AUTHORIZATION_CONSUMED',
  });
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
  assert.equal(executions, 1);
});

test('one payment authorization cannot execute again under a different idempotency key', async () => {
  const fixedNow = Date.now();
  const facilitator = createMockFacilitator();
  let verifyCalls = 0;
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const operation = new URL(url).pathname;
    if (operation === '/verify') verifyCalls += 1;
    if (operation === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    now: () => fixedNow,
    handler: (c) => {
      executions += 1;
      return c.json({ ok: true });
    },
  });
  const first = await payingFetch(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'authorization-owner',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(first.res.status, 200);

  const secondOffer = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'authorization-replay' },
    body: '{}',
  });
  assert.equal(secondOffer.status, 402);
  const replay = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: {
      'Idempotency-Key': 'authorization-replay',
      'X-PAYMENT': first.xPayment,
    },
    body: '{}',
  });

  assert.equal(replay.status, 409);
  assert.deepEqual(await replay.json(), {
    error: 'payment authorization is already claimed by a different Idempotency-Key',
    code: 'PAYMENT_AUTHORIZATION_CLAIMED',
  });

  const originalEnvelope = JSON.parse(Buffer.from(first.xPayment, 'base64').toString('utf8'));
  const originalAuthorization = originalEnvelope.payload.authorization;
  const reorderedPayment = Buffer.from(JSON.stringify({
    network: originalEnvelope.network,
    payload: {
      authorization: {
        nonce: originalAuthorization.nonce,
        validBefore: originalAuthorization.validBefore,
        validAfter: originalAuthorization.validAfter,
        value: originalAuthorization.value,
        to: originalAuthorization.to,
        from: originalAuthorization.from,
      },
      signature: originalEnvelope.payload.signature,
    },
    scheme: originalEnvelope.scheme,
    x402Version: originalEnvelope.x402Version,
  })).toString('base64');
  assert.notEqual(reorderedPayment, first.xPayment);
  const reorderedOffer = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'authorization-reordered-replay' },
    body: '{}',
  });
  assert.equal(reorderedOffer.status, 402);
  const reorderedReplay = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: {
      'Idempotency-Key': 'authorization-reordered-replay',
      'X-PAYMENT': reorderedPayment,
    },
    body: '{}',
  });
  assert.equal(reorderedReplay.status, 409);
  assert.deepEqual(await reorderedReplay.json(), {
    error: 'payment authorization is already claimed by a different Idempotency-Key',
    code: 'PAYMENT_AUTHORIZATION_CLAIMED',
  });
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
  assert.equal(executions, 1);
});

test('concurrent cross-key replay loses the authorization claim before facilitator verification', {
  timeout: 5_000,
}, async () => {
  let clockMs = Date.now();
  const facilitator = createMockFacilitator();
  let releaseFirstVerification;
  let firstVerificationStarted;
  const firstStarted = new Promise((resolve) => { firstVerificationStarted = resolve; });
  const firstRelease = new Promise((resolve) => { releaseFirstVerification = resolve; });
  let releaseHandler;
  let handlerStarted;
  const handlerStart = new Promise((resolve) => { handlerStarted = resolve; });
  const handlerRelease = new Promise((resolve) => { releaseHandler = resolve; });
  let verifyCalls = 0;
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const operation = new URL(url).pathname;
    if (operation === '/verify') {
      verifyCalls += 1;
      if (verifyCalls === 1) {
        firstVerificationStarted();
        await firstRelease;
      }
    }
    if (operation === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    now: () => clockMs,
    handler: async (c) => {
      executions += 1;
      handlerStarted();
      await handlerRelease;
      return c.json({ ok: true });
    },
  });
  let interceptedRequests = 0;
  const signed = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'concurrent-authorization-owner',
    fetchImpl: (url, init) => {
      interceptedRequests += 1;
      return interceptedRequests === 1
        ? app.request(url, init)
        : Response.json({ error: 'withheld paid retry' }, { status: 503 });
    },
  });
  const secondOffer = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'concurrent-authorization-replay' },
    body: '{}',
  });
  assert.equal(secondOffer.status, 402);

  const ownerPromise = app.request('http://seller.test/resource', {
    method: 'POST',
    headers: {
      'Idempotency-Key': signed.idempotencyKey,
      'X-PAYMENT': signed.xPayment,
    },
    body: '{}',
  });
  await firstStarted;
  let replay;
  let replayAfterTtl;
  try {
    replay = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: {
        'Idempotency-Key': 'concurrent-authorization-replay',
        'X-PAYMENT': signed.xPayment,
      },
        body: '{}',
      });
    releaseFirstVerification();
    await handlerStart;
    clockMs += DEFAULT_PENDING_OFFER_TTL_MS + 1;
    const afterTtlOffer = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: { 'Idempotency-Key': 'concurrent-replay-after-ttl' },
      body: '{}',
    });
    assert.equal(afterTtlOffer.status, 402);
    replayAfterTtl = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: {
        'Idempotency-Key': 'concurrent-replay-after-ttl',
        'X-PAYMENT': signed.xPayment,
      },
      body: '{}',
    });
  } finally {
    releaseFirstVerification();
    releaseHandler();
  }
  const owner = await ownerPromise;

  assert.equal(owner.status, 200);
  assert.equal(replay.status, 409);
  assert.deepEqual(await replay.json(), {
    error: 'payment authorization is already claimed by a different Idempotency-Key',
    code: 'PAYMENT_AUTHORIZATION_CLAIMED',
  });
  assert.equal(replayAfterTtl.status, 409);
  assert.deepEqual(await replayAfterTtl.json(), {
    error: 'payment authorization is already claimed by a different Idempotency-Key',
    code: 'PAYMENT_AUTHORIZATION_CLAIMED',
  });
  assert.equal(verifyCalls, 1);
  assert.equal(settleCalls, 1);
  assert.equal(executions, 1);
});

test('facilitator verification accepts only the exact boolean true', async () => {
  let caseIndex = 0;
  for (const isValid of [1, 'true', {}, []]) {
    const facilitator = createMockFacilitator();
    let verifyCalls = 0;
    let settleCalls = 0;
    let executions = 0;
    const transport = createMockFacilitatorTransport(async (url, init) => {
      const operation = new URL(url).pathname;
      if (operation === '/verify') {
        verifyCalls += 1;
        return Response.json({ isValid });
      }
      settleCalls += 1;
      return facilitator.request(url, init);
    });
    const app = resourceApp({
      facilitatorTransport: transport,
      handler: (c) => {
        executions += 1;
        return c.json({ ok: true });
      },
    });
    await assert.rejects(() => payingFetch(throwawayAccount(), 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      idempotencyKey: `idem-exact-verify-boolean-${caseIndex++}`,
      fetchImpl: (url, init) => app.request(url, init),
    }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED');
    assert.equal(verifyCalls, 1);
    assert.equal(settleCalls, 0);
    assert.equal(executions, 0);
  }
});

test('a restarted paywall accepts only the complete persisted frozen offer', async () => {
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  let persistedOffer = null;
  let quoteCalls = 0;
  let fetchCount = 0;
  const beforeRestart = resourceApp({
    facilitatorTransport: transport,
    quote: async () => { quoteCalls += 1; return structuredClone(executionQuote); },
    lifecycle: {
      async onOffered({ requirements, executionQuote: offeredQuote }) {
        persistedOffer = structuredClone({
          requirements, executionQuote: offeredQuote, verificationRequired: true,
          verifiedPaymentHash: null,
        });
        offeredQuote.model = 'mutated-by-untrusted-hook';
      },
    },
    handler: (c) => c.json({ shouldNotExecute: true }),
  });
  const afterRestart = resourceApp({
    facilitatorTransport: transport,
    price: '9.99',
    quote: async () => { quoteCalls += 1; throw new Error('must not recompute after restart'); },
    lifecycle: {
      async loadFrozenOffer() { return structuredClone(persistedOffer); },
    },
    handler: (c) => {
      assert.deepEqual(c.get('x402').executionQuote, executionQuote);
      return c.json({ ok: true });
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
  assert.equal(persistedOffer.requirements.maxAmountRequired, '250000');
  assert.equal(persistedOffer.requirements.payTo, payTo);
  assert.deepEqual(persistedOffer.executionQuote, executionQuote);
  assert.equal(quoteCalls, 1);
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
      async loadFrozenOffer() {
        return {
          requirements: structuredClone(persistedRequirements),
          executionQuote: null,
          verificationRequired: true,
          verifiedPaymentHash: null,
        };
      },
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

test('idempotency keys are canonical bounded ASCII before quote, lifecycle, or facilitator work', async () => {
  let quoteCalls = 0;
  let lifecycleCalls = 0;
  let facilitatorCalls = 0;
  const app = resourceApp({
    facilitatorTransport: createMockFacilitatorTransport(async () => {
      facilitatorCalls += 1;
      throw new Error('facilitator must not run');
    }),
    quote: async () => {
      quoteCalls += 1;
      return structuredClone(executionQuote);
    },
    lifecycle: { async onOffered() { lifecycleCalls += 1; } },
  });

  for (const idempotencyKey of [
    'key-with-unicode-é',
    'x'.repeat(129),
    'key/with/slashes',
  ]) {
    const response = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: { 'Idempotency-Key': idempotencyKey },
      body: '{}',
    });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), {
      error: 'Idempotency-Key must be 1-128 canonical ASCII characters',
      code: 'IDEMPOTENCY_KEY_INVALID',
    });
  }

  const accepted = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': `a${'x'.repeat(127)}` },
    body: '{}',
  });
  assert.equal(accepted.status, 402);
  assert.equal(quoteCalls, 1);
  assert.equal(lifecycleCalls, 1);
  assert.equal(facilitatorCalls, 0);
});

test('pending unpaid offers have a strict admission cap and expire without evicting active keys', async () => {
  let clockMs = 1_000_000;
  let quoteCalls = 0;
  const app = resourceApp({
    facilitatorTransport: createMockFacilitatorTransport(async () => {
      throw new Error('facilitator must not run for unpaid offers');
    }),
    quote: async () => {
      quoteCalls += 1;
      return structuredClone(executionQuote);
    },
    maxPendingOffers: 2,
    pendingOfferTtlMs: 1_000,
    now: () => clockMs,
  });
  const request = (key) => app.request('http://seller.test/resource', {
    method: 'POST', headers: { 'Idempotency-Key': key }, body: '{}',
  });

  assert.equal((await request('pending-a')).status, 402);
  assert.equal((await request('pending-b')).status, 402);
  const full = await request('pending-c');
  assert.equal(full.status, 503);
  assert.deepEqual(await full.json(), {
    error: 'pending x402 offer capacity is exhausted',
    code: 'PENDING_OFFER_CAPACITY',
  });
  assert.equal(full.headers.get('Retry-After'), '1');
  assert.equal((await request('pending-a')).status, 402);
  assert.equal(quoteCalls, 2);

  clockMs += 1_001;
  assert.equal((await request('pending-c')).status, 402);
  assert.equal(quoteCalls, 3);
});

test('pending admission is reserved before concurrent quote work begins', async () => {
  let quoteCalls = 0;
  let releaseFirstQuote;
  let firstQuoteStarted;
  const quoteStarted = new Promise((resolve) => { firstQuoteStarted = resolve; });
  const quoteRelease = new Promise((resolve) => { releaseFirstQuote = resolve; });
  const app = resourceApp({
    facilitatorTransport: createMockFacilitatorTransport(async () => {
      throw new Error('facilitator must not run for unpaid offers');
    }),
    quote: async () => {
      quoteCalls += 1;
      firstQuoteStarted();
      await quoteRelease;
      return structuredClone(executionQuote);
    },
    maxPendingOffers: 1,
  });
  const request = (key) => app.request('http://seller.test/resource', {
    method: 'POST', headers: { 'Idempotency-Key': key }, body: '{}',
  });

  const firstPromise = request('concurrent-pending-a');
  await quoteStarted;
  const secondPromise = request('concurrent-pending-b');
  await new Promise((resolve) => setImmediate(resolve));
  releaseFirstQuote();

  const [first, second] = await Promise.all([firstPromise, secondPromise]);
  assert.equal(first.status, 402);
  assert.equal(second.status, 503);
  assert.deepEqual(await second.json(), {
    error: 'pending x402 offer capacity is exhausted',
    code: 'PENDING_OFFER_CAPACITY',
  });
  assert.equal(quoteCalls, 1);
});

test('a paid request retains admission if its pending offer expires during verification', async () => {
  let clockMs = Date.now();
  let releaseVerification;
  let verificationStarted;
  const started = new Promise((resolve) => { verificationStarted = resolve; });
  const release = new Promise((resolve) => { releaseVerification = resolve; });
  const facilitator = createMockFacilitator();
  const app = resourceApp({
    facilitatorTransport: createMockFacilitatorTransport(async (url, init) => {
      if (new URL(url).pathname === '/verify') {
        verificationStarted();
        await release;
      }
      return facilitator.request(url, init);
    }),
    maxPendingOffers: 1,
    pendingOfferTtlMs: 1_000,
    now: () => clockMs,
  });
  let sellerRequests = 0;
  const signed = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'expiring-paid-admission',
    fetchImpl: (url, init) => {
      sellerRequests += 1;
      return sellerRequests === 1
        ? app.request(url, init)
        : Response.json({ error: 'withheld paid retry' }, { status: 503 });
    },
  });

  const paidPromise = app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': signed.idempotencyKey, 'X-PAYMENT': signed.xPayment },
    body: '{}',
  });
  await started;
  clockMs += 1_001;
  const concurrent = await app.request('http://seller.test/resource', {
    method: 'POST', headers: { 'Idempotency-Key': 'blocked-by-paid-request' }, body: '{}',
  });
  releaseVerification();
  const paid = await paidPromise;
  assert.equal(concurrent.status, 503);
  assert.equal(paid.status, 200);
});

test('unresolved keys retain bounded admission across TTL and release only for trusted authority', async () => {
  for (const resolutionKind of ['settled', 'terminal']) {
    let clockMs = Date.now();
    let persistedOffer = null;
    let authorityDecision = null;
    let executions = 0;
    const facilitator = createMockFacilitator();
    const transport = createMockFacilitatorTransport(async (url, init) => {
      if (new URL(url).pathname === '/verify') return facilitator.request(url, init);
      return Response.json({});
    });
    const account = throwawayAccount();
    const originalKey = `unresolved-${resolutionKind}`;
    const app = resourceApp({
      facilitatorTransport: transport,
      maxPendingOffers: 1,
      pendingOfferTtlMs: 1_000,
      now: () => clockMs,
      lifecycle: {
        async onOffered({ idempotencyKey, requirements, executionQuote: offeredQuote }) {
          if (idempotencyKey === originalKey) {
            persistedOffer = structuredClone({
              requirements,
              executionQuote: offeredQuote,
              verificationRequired: true,
              verifiedPaymentHash: null,
            });
          }
        },
        async loadFrozenOffer({ idempotencyKey }) {
          return idempotencyKey === originalKey ? structuredClone(persistedOffer) : null;
        },
        async onSigned() { return authorityDecision; },
        async onUnresolved() {},
      },
      handler: (c) => { executions += 1; return c.json({ ok: true }); },
    });
    const first = await withheldAttempt(account, 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      idempotencyKey: originalKey,
      fetchImpl: (url, init) => app.request(url, init),
    });
    assert.equal(first.state, 'unresolved');

    clockMs += 1_001;
    const differentWhileUnresolved = await app.request('http://seller.test/resource', {
      method: 'POST', headers: { 'Idempotency-Key': `blocked-${resolutionKind}` }, body: '{}',
    });
    assert.equal(differentWhileUnresolved.status, 503, resolutionKind);

    const recreate = await app.request('http://seller.test/resource', {
      method: 'POST', headers: { 'Idempotency-Key': originalKey }, body: '{}',
    });
    assert.equal(recreate.status, 503, resolutionKind);
    assert.deepEqual(await recreate.json(), {
      error: 'payment settlement unresolved; trusted reconciliation is required',
      settlementReference: null,
    });

    authorityDecision = resolutionKind === 'settled'
      ? { kind: 'settled', txHash: `0x${'8'.repeat(64)}`, payer: `0x${'0'.repeat(40)}` }
      : {
        kind: 'terminal', paymentState: 'rejected', txHash: null, payer: account.address,
        httpStatus: 500, receipt: { receipt: { execution: { message: 'failed' } } },
      };
    const untrusted = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: { 'Idempotency-Key': originalKey, 'X-PAYMENT': first.xPayment },
      body: '{}',
    });
    assert.equal(untrusted.status, 503, resolutionKind);
    const stillBlocked = await app.request('http://seller.test/resource', {
      method: 'POST', headers: { 'Idempotency-Key': `still-blocked-${resolutionKind}` }, body: '{}',
    });
    assert.equal(stillBlocked.status, 503, resolutionKind);

    authorityDecision = resolutionKind === 'settled'
      ? { kind: 'settled', txHash: `0x${'8'.repeat(64)}`, payer: account.address.toLowerCase() }
      : {
        kind: 'terminal', paymentState: 'settled', txHash: `0x${'8'.repeat(64)}`,
        payer: account.address.toLowerCase(), httpStatus: 500,
        receipt: { receipt: { execution: { message: 'provider failed' } } },
      };
    const trusted = await app.request('http://seller.test/resource', {
      method: 'POST',
      headers: { 'Idempotency-Key': originalKey, 'X-PAYMENT': first.xPayment },
      body: '{}',
    });
    assert.equal(trusted.status, resolutionKind === 'settled' ? 200 : 500, resolutionKind);

    const retainedAfterResolution = await app.request('http://seller.test/resource', {
      method: 'POST', headers: { 'Idempotency-Key': `released-${resolutionKind}` }, body: '{}',
    });
    assert.equal(retainedAfterResolution.status, 503, resolutionKind);

    clockMs += 1_001;
    const afterResolution = await app.request('http://seller.test/resource', {
      method: 'POST', headers: { 'Idempotency-Key': `released-${resolutionKind}` }, body: '{}',
    });
    assert.equal(afterResolution.status, 402, resolutionKind);
    assert.equal(executions, resolutionKind === 'settled' ? 1 : 0, resolutionKind);
  }
});

test('x402 constructor options cannot raise secure memory, byte, or deadline ceilings', () => {
  const facilitatorTransport = createMockFacilitatorTransport(async () => {
    throw new Error('facilitator must not run');
  });
  for (const [option, value, ceiling] of [
    ['maxRequestBodyBytes', MAX_X402_REQUEST_BODY_BYTES + 1, MAX_X402_REQUEST_BODY_BYTES],
    ['requestBodyTimeoutMs', DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS + 1, DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS],
    ['facilitatorTimeoutMs', DEFAULT_FACILITATOR_TIMEOUT_MS + 1, DEFAULT_FACILITATOR_TIMEOUT_MS],
    ['facilitatorResponseMaxBytes', DEFAULT_FACILITATOR_RESPONSE_BYTES + 1, DEFAULT_FACILITATOR_RESPONSE_BYTES],
    ['maxPendingOffers', DEFAULT_PENDING_OFFER_LIMIT + 1, DEFAULT_PENDING_OFFER_LIMIT],
    ['pendingOfferTtlMs', DEFAULT_PENDING_OFFER_TTL_MS + 1, DEFAULT_PENDING_OFFER_TTL_MS],
  ]) {
    assert.throws(
      () => resourceApp({ facilitatorTransport, [option]: value }),
      new RegExp(`${option} cannot exceed ${ceiling}`),
    );
  }
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

test('an unresolved authority decision after verification returns 503 without settlement', async () => {
  const facilitator = createMockFacilitator();
  let facilitatorCalls = 0;
  let settleCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    facilitatorCalls += 1;
    if (new URL(url).pathname === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
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
  assert.equal(facilitatorCalls, 1);
  assert.equal(settleCalls, 0);
});

test('terminal replay requires settled or refunded payment with a transaction and preserves HTTP status', async () => {
  const facilitator = createMockFacilitator();
  let calls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    calls += 1;
    assert.equal(new URL(url).pathname, '/verify');
    return facilitator.request(url, init);
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
  assert.equal(calls, 2);
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

test('chunked x402 request body is rejected at 4097 bytes before quote or lifecycle state', {
  timeout: 1_000,
}, async () => {
  let quoteCalls = 0;
  let lifecycleCalls = 0;
  let pulls = 0;
  let cancelled = false;
  const transport = createMockFacilitatorTransport(async () => {
    throw new Error('facilitator must not run for an oversized unpaid request');
  });
  const app = resourceApp({
    facilitatorTransport: transport,
    maxRequestBodyBytes: 4096,
    quote: async () => { quoteCalls += 1; return structuredClone(executionQuote); },
    lifecycle: { async onOffered() { lifecycleCalls += 1; } },
  });
  const body = new ReadableStream({
    pull(controller) {
      pulls += 1;
      if (pulls === 1) controller.enqueue(new Uint8Array(4096));
      else controller.enqueue(new Uint8Array([1]));
    },
    cancel() { cancelled = true; },
  });
  const response = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'idem-chunked-oversize' },
    body,
    duplex: 'half',
  });
  assert.equal(response.status, 413);
  assert.deepEqual(await response.json(), {
    error: 'request body exceeds the 4096-byte x402 limit',
    code: 'REQUEST_BODY_TOO_LARGE',
  });
  assert.equal(cancelled, true);
  assert.equal(quoteCalls, 0);
  assert.equal(lifecycleCalls, 0);
});

test('x402 request body accepts exactly 4096 bytes', async () => {
  const transport = createMockFacilitatorTransport(async () => {
    throw new Error('facilitator must not run for an unpaid request');
  });
  const app = resourceApp({ facilitatorTransport: transport, maxRequestBodyBytes: 4096 });
  const response = await app.request('http://seller.test/resource', {
    method: 'POST',
    headers: { 'Idempotency-Key': 'idem-exact-body-limit' },
    body: 'x'.repeat(4096),
  });
  assert.equal(response.status, 402);
  assert.equal((await response.json()).x402Version, 1);
});

test('facilitator verify and settle deadlines abort ignoring transports and remain unresolved', {
  timeout: 1_000,
}, async () => {
  for (const timedOutOperation of ['verify', 'settle']) {
    let facilitatorSignal = null;
    let unresolvedReason = null;
    let executions = 0;
    const transport = createMockFacilitatorTransport(async (url, init) => {
      const operation = new URL(url).pathname.slice(1);
      if (operation === timedOutOperation) {
        facilitatorSignal = init.signal;
        return new Promise(() => {});
      }
      return new Response(JSON.stringify({ isValid: true }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    });
    const app = resourceApp({
      facilitatorTransport: transport,
      facilitatorTimeoutMs: 20,
      lifecycle: {
        async onUnresolved({ reason }) { unresolvedReason = reason; },
      },
      handler: (c) => { executions += 1; return c.json({ ok: true }); },
    });
    const held = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      idempotencyKey: `idem-facilitator-${timedOutOperation}-timeout`,
      fetchImpl: (url, init) => app.request(url, init),
    });
    assert.equal(facilitatorSignal.aborted, true, timedOutOperation);
    assert.equal(
      unresolvedReason,
      timedOutOperation === 'verify' ? null : 'facilitator response unresolved',
      timedOutOperation,
    );
    assert.equal(held.state, 'unresolved', timedOutOperation);
    assert.equal(held.paymentPolicy.snapshot().reservedAtomic, '250000', timedOutOperation);
    assert.equal(executions, 0, timedOutOperation);
  }
});

test('facilitator non-success response bodies are cancelled before payment stays unresolved', async () => {
  for (const failedOperation of ['verify', 'settle']) {
    let cancelled = false;
    let executions = 0;
    const transport = createMockFacilitatorTransport(async (url) => {
      const operation = new URL(url).pathname.slice(1);
      if (operation === failedOperation) {
        return new Response(new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{"secret":"withheld"}'));
          },
          cancel() { cancelled = true; },
        }), {
          status: 503,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify({ isValid: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    });
    const app = resourceApp({
      facilitatorTransport: transport,
      handler: (c) => { executions += 1; return c.json({ ok: true }); },
    });
    const held = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
      method: 'POST', body: '{}',
    }, {
      idempotencyKey: `idem-facilitator-${failedOperation}-http`,
      fetchImpl: (url, init) => app.request(url, init),
    });
    assert.equal(cancelled, true, failedOperation);
    assert.equal(held.state, 'unresolved', failedOperation);
    assert.equal(executions, 0, failedOperation);
  }
});

test('oversized verification JSON is cancelled before authoritative payment state', async () => {
  let cancelled = false;
  let unresolvedReason = null;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async () => new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(40_000));
      controller.enqueue(new Uint8Array(30_000));
    },
    cancel() { cancelled = true; },
  }), { status: 200, headers: { 'content-type': 'application/json' } }));
  const app = resourceApp({
    facilitatorTransport: transport,
    facilitatorResponseMaxBytes: 64 * 1024,
    lifecycle: {
      async onUnresolved({ reason }) { unresolvedReason = reason; },
    },
    handler: (c) => { executions += 1; return c.json({ ok: true }); },
  });
  const held = await withheldAttempt(throwawayAccount(), 'http://seller.test/resource', {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-facilitator-oversize',
    fetchImpl: (url, init) => app.request(url, init),
  });
  assert.equal(cancelled, true);
  assert.equal(unresolvedReason, null);
  assert.equal(held.state, 'unresolved');
  assert.equal(executions, 0);
});

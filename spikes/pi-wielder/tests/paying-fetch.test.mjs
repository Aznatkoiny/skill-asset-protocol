import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  canonicalRequestHash,
  createPaymentPolicy,
  PaymentPolicyError,
} from '../src/payment-policy.mjs';
import {
  DEFAULT_PAID_RETRY_TIMEOUT_MS,
  DEFAULT_UNPAID_FETCH_TIMEOUT_MS,
  payingFetch,
} from '../src/proxy.mjs';

const PAYEE = '0x000000000000000000000000000000000000dead';
const PAYER = '0x1000000000000000000000000000000000000000';
const URL = 'https://trusted.example/invoke/skill-a';
const BODY = '{}';
const NOW = Date.UTC(2026, 6, 17, 12, 0, 10);
const TX_HASH = `0x${'2'.repeat(64)}`;
const SIGNATURE = `0x${'1'.repeat(130)}`;

function baseOffer(overrides = {}) {
  const base = {
    scheme: 'exact',
    network: BASE_SEPOLIA_NETWORK,
    maxAmountRequired: '250000',
    resource: URL,
    description: 'test Skill',
    mimeType: 'application/json',
    payTo: PAYEE,
    maxTimeoutSeconds: 60,
    asset: BASE_SEPOLIA_USDC,
    extra: {
      name: 'USDC',
      version: '2',
      requestHash: canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: BODY }),
      quoteId: `sha256:${'b'.repeat(64)}`,
      issuedAt: new Date(NOW - 1_000).toISOString(),
      expiresAt: new Date(NOW + 59_000).toISOString(),
    },
  };
  return { ...base, ...overrides };
}

function challenge(candidate = baseOffer()) {
  return new Response(JSON.stringify(challengePayload(candidate)), {
    status: 402, headers: { 'content-type': 'application/json' },
  });
}

function challengeWithReadHook(candidate, onRead) {
  const bytes = new TextEncoder().encode(JSON.stringify(challengePayload(candidate)));
  let emitted = false;
  return new Response(new ReadableStream({
    pull(controller) {
      if (emitted) return;
      emitted = true;
      onRead();
      controller.enqueue(bytes);
      controller.close();
    },
  }, { highWaterMark: 0 }), {
    status: 402,
    headers: { 'content-type': 'application/json' },
  });
}

function challengePayload(candidate = baseOffer()) {
  return {
    x402Version: 1,
    error: 'X-PAYMENT header is required',
    accepts: [candidate],
  };
}

function listenLoopback(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
}

function closeServer(server) {
  if (!server.listening) return Promise.resolve();
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function readNodeRequest(req) {
  let body = '';
  req.setEncoding('utf8');
  for await (const chunk of req) body += chunk;
  return body;
}

function decodePayment(init) {
  const headers = new Headers(init.headers);
  return JSON.parse(Buffer.from(headers.get('X-PAYMENT'), 'base64').toString('utf8'));
}

function settlementFor(init, overrides = {}) {
  const payment = decodePayment(init);
  const authorization = payment.payload.authorization;
  return {
    success: true,
    authorizationId: new Headers(init.headers).get('Idempotency-Key'),
    idempotencyKey: new Headers(init.headers).get('Idempotency-Key'),
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    payTo: PAYEE,
    payer: authorization.from,
    value: authorization.value,
    nonce: authorization.nonce,
    settlementReference: authorization.nonce,
    requestHash: baseOffer().extra.requestHash,
    quoteId: baseOffer().extra.quoteId,
    transaction: TX_HASH,
    ...overrides,
  };
}

function paidResponse(init, { status = 200, body = '{"ok":true}', settlement = {} } = {}) {
  const encoded = Buffer.from(JSON.stringify(settlementFor(init, settlement))).toString('base64');
  return new Response(body, {
    status,
    headers: {
      'content-type': 'application/json',
      'X-PAYMENT-RESPONSE': encoded,
      'X-402-FACILITATOR-MS': '1.5',
    },
  });
}

function setup(overrides = {}) {
  let clock = NOW;
  let signatures = 0;
  const account = {
    address: PAYER,
    async signTypedData() {
      signatures += 1;
      return SIGNATURE;
    },
  };
  const paymentPolicy = createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => clock,
    sellers: [{
      origin: 'https://trusted.example', pathPrefix: '/invoke/', payTo: PAYEE,
      maxPerCallAtomic: '300000',
    }],
    ...overrides.policy,
  });
  return {
    account,
    paymentPolicy,
    signatureCount: () => signatures,
    setClock: (value) => { clock = value; },
  };
}

test('a forbidden first offer is never signed or retried', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => { fetches += 1; return challenge(baseOffer({ network: 'base' })); },
    idempotencyKey: 'idem-forbidden',
    paymentPolicy,
  }), (error) => error.code === 'NETWORK_MISMATCH');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('payingFetch timeout options cannot raise the secure deadline ceilings', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  for (const [option, value, ceiling] of [
    ['unpaidTimeoutMs', DEFAULT_UNPAID_FETCH_TIMEOUT_MS + 1, DEFAULT_UNPAID_FETCH_TIMEOUT_MS],
    ['paidTimeoutMs', DEFAULT_PAID_RETRY_TIMEOUT_MS + 1, DEFAULT_PAID_RETRY_TIMEOUT_MS],
  ]) {
    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
      fetchImpl: async () => {
        fetches += 1;
        return challenge();
      },
      idempotencyKey: `idem-${option}`,
      paymentPolicy,
      [option]: value,
    }), new RegExp(`${option} cannot exceed ${ceiling}`));
  }
  assert.equal(fetches, 0);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('payingFetch accepts exactly the seller canonical Idempotency-Key boundary', async () => {
  const { account, paymentPolicy } = setup();
  const accepted = `a${'Z9._:-'.repeat(22)}`.slice(0, 128);
  let forwardedKey = null;
  const result = await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      forwardedKey = new Headers(init.headers).get('Idempotency-Key');
      return new Response(null, { status: 204 });
    },
    idempotencyKey: accepted,
    paymentPolicy,
  });
  assert.equal(accepted.length, 128);
  assert.equal(forwardedKey, accepted);
  assert.equal(result.paid, false);
});

test('payingFetch rejects Idempotency-Keys outside the seller canonical grammar', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  for (const idempotencyKey of [
    '.leading-punctuation',
    `a${'x'.repeat(128)}`,
  ]) {
    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
      fetchImpl: async () => {
        fetches += 1;
        return new Response(null, { status: 204 });
      },
      idempotencyKey,
      paymentPolicy,
    }), (error) => error.code === 'AUTHORIZATION_ID');
  }
  assert.equal(fetches, 0);
  assert.equal(signatureCount(), 0);
});

test('freshness is captured from the injected clock immediately after the first 402', async () => {
  const { account, paymentPolicy, setClock, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      fetches += 1;
      setClock(NOW + 5_001);
      return challenge();
    },
    idempotencyKey: 'idem-stale-on-arrival',
    paymentPolicy,
  }), (error) => error.code === 'QUOTE_EXPIRY');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 0);
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(),
    idempotencyKey: 'idem-caller-clock',
    paymentPolicy,
    receivedAtMs: NOW - 1_000,
  }), (error) => error.code === 'PAYING_FETCH_OPTIONS');
});

test('a quote expiring while the first 402 JSON is parsed is rejected before signing', async () => {
  const { account, paymentPolicy, setClock, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      fetches += 1;
      if (fetches > 1) throw new Error('paid retry must not start for an expired quote');
      return challengeWithReadHook(baseOffer(), () => setClock(NOW + 59_000));
    },
    idempotencyKey: 'idem-expired-during-parse',
    paymentPolicy,
  }), (error) => error.code === 'QUOTE_EXPIRY');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 0);
  assert.deepEqual(paymentPolicy.snapshot().authorizations, []);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('a JSON-only injected challenge is rejected without calling an unbounded parser', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let jsonCalls = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => ({
      status: 402,
      async json() {
        jsonCalls += 1;
        return challengePayload();
      },
    }),
    idempotencyKey: 'idem-json-only-challenge',
    paymentPolicy,
  }), (error) => (
    error.code === 'CHALLENGE_RESPONSE_SHAPE'
      && error.message === 'x402 challenge response must expose a bounded byte stream'
  ));
  assert.equal(jsonCalls, 0);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('trusted quote age is rechecked after JSON parse against receipt and issue times', async () => {
  const cases = [
    {
      name: 'receipt age',
      candidate: baseOffer({
        extra: { ...baseOffer().extra, issuedAt: new Date(NOW).toISOString() },
      }),
      afterParse: NOW + 5_001,
    },
    {
      name: 'issue age',
      candidate: baseOffer({
        extra: { ...baseOffer().extra, issuedAt: new Date(NOW - 4_000).toISOString() },
      }),
      afterParse: NOW + 2_000,
    },
    {
      name: 'backward clock',
      candidate: baseOffer(),
      afterParse: NOW - 1,
    },
  ];

  for (const { name, candidate, afterParse } of cases) {
    const { account, paymentPolicy, setClock, signatureCount } = setup();
    let fetches = 0;
    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
      idempotencyKey: `idem-parse-${name.replaceAll(' ', '-')}`,
      paymentPolicy,
      fetchImpl: async () => {
        fetches += 1;
        return challengeWithReadHook(candidate, () => setClock(afterParse));
      },
    }), (error) => error.code === 'QUOTE_FRESHNESS');
    assert.equal(fetches, 1, name);
    assert.equal(signatureCount(), 0, name);
    assert.equal(paymentPolicy.snapshot().reservedAtomic, '0', name);
  }
});

test('caller RequestInit accessors and mutable body bytes are captured once for both requests', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const originalBody = Buffer.from('{"input":"captured"}', 'utf8');
  const expectedBody = Buffer.from(originalBody);
  const expectedRequestHash = canonicalRequestHash({
    method: 'POST', requestUrl: URL, bodyBytes: expectedBody,
  });
  const capturedOffer = baseOffer({
    extra: { ...baseOffer().extra, requestHash: expectedRequestHash },
  });
  const reads = { method: 0, body: 0, headers: 0 };
  const requestInitPrototype = {};
  Object.defineProperties(requestInitPrototype, {
    method: {
      enumerable: true,
      get() {
        reads.method += 1;
        return reads.method === 1 ? 'POST' : 'PUT';
      },
    },
    body: {
      enumerable: true,
      get() {
        reads.body += 1;
        return reads.body === 1 ? originalBody : Buffer.from('{"input":"changed"}', 'utf8');
      },
    },
    headers: {
      enumerable: true,
      get() {
        reads.headers += 1;
        return reads.headers === 1
          ? { 'content-type': 'application/json', 'x-captured': 'yes' }
          : { 'content-type': 'text/plain', 'x-captured': 'no' };
      },
    },
  });
  const callerInit = Object.create(requestInitPrototype);

  let fetches = 0;
  const result = await payingFetch(account, URL, callerInit, {
    idempotencyKey: 'idem-captured-init',
    paymentPolicy,
    fetchImpl: async (_url, requestInit) => {
      fetches += 1;
      assert.equal(requestInit.method, 'POST');
      assert.deepEqual(Buffer.from(requestInit.body), expectedBody);
      assert.equal(new Headers(requestInit.headers).get('x-captured'), 'yes');
      if (fetches === 1) {
        originalBody.fill(0x78);
        callerInit.injected = 'late mutation';
        return challenge(capturedOffer);
      }
      return paidResponse(requestInit, { settlement: { requestHash: expectedRequestHash } });
    },
  });

  assert.equal(result.res.status, 200);
  assert.equal(fetches, 2);
  assert.equal(signatureCount(), 1);
  assert.deepEqual(reads, { method: 1, body: 1, headers: 1 });
  assert.equal(result.requestHash, expectedRequestHash);
});

test('caller-supplied payment and idempotency headers are rejected case-insensitively before fetch', async () => {
  for (const headers of [
    { 'idempotency-key': 'caller-owned' },
    { 'X-Payment': 'caller-owned' },
    [['content-type', 'application/json'], ['IDEMPOTENCY-KEY', 'one'], ['Idempotency-Key', 'two']],
    new Headers([['x-payment', 'one'], ['X-PAYMENT', 'two']]),
  ]) {
    const { account, paymentPolicy, signatureCount } = setup();
    let fetches = 0;
    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY, headers }, {
      fetchImpl: async () => { fetches += 1; return challenge(); },
      idempotencyKey: 'idem-owned',
      paymentPolicy,
    }), (error) => error.code === 'CALLER_PAYMENT_HEADER');
    assert.equal(fetches, 0);
    assert.equal(signatureCount(), 0);
  }
});

test('native unpaid fetch refuses redirects even when caller asks to follow', async (t) => {
  const redirectedRequests = [];
  const redirectTarget = http.createServer(async (req, res) => {
    redirectedRequests.push({
      body: await readNodeRequest(req),
      payment: req.headers['x-payment'] ?? null,
    });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"redirected":true}');
  });
  await listenLoopback(redirectTarget);
  const redirectTargetUrl = `http://127.0.0.1:${redirectTarget.address().port}/capture`;
  const seller = http.createServer(async (req, res) => {
    await readNodeRequest(req);
    res.writeHead(307, { location: redirectTargetUrl });
    res.end();
  });
  await listenLoopback(seller);
  t.after(async () => {
    await closeServer(seller);
    await closeServer(redirectTarget);
  });

  const requestUrl = `http://127.0.0.1:${seller.address().port}/invoke/skill-a`;
  const now = Date.now();
  let signatures = 0;
  const account = {
    address: PAYER,
    async signTypedData() { signatures += 1; return SIGNATURE; },
  };
  const paymentPolicy = createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => now,
    sellers: [{
      origin: new globalThis.URL(requestUrl).origin,
      pathPrefix: '/invoke/',
      payTo: PAYEE,
      maxPerCallAtomic: '300000',
    }],
  });

  await assert.rejects(() => payingFetch(account, requestUrl, {
    method: 'POST', body: BODY, redirect: 'follow',
  }, {
    idempotencyKey: 'idem-unpaid-redirect', paymentPolicy,
  }));
  assert.equal(redirectedRequests.length, 0);
  assert.equal(signatures, 0);
  assert.equal(paymentPolicy.snapshot().authorizations.length, 0);
});

test('native paid retry refuses redirects without forwarding payment header or body', async (t) => {
  const redirectedRequests = [];
  const redirectTarget = http.createServer(async (req, res) => {
    redirectedRequests.push({
      body: await readNodeRequest(req),
      payment: req.headers['x-payment'] ?? null,
    });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{"redirected":true}');
  });
  await listenLoopback(redirectTarget);
  const redirectTargetUrl = `http://127.0.0.1:${redirectTarget.address().port}/capture`;
  let requestUrl;
  let firstChallenge;
  let sellerRequests = 0;
  const seller = http.createServer(async (req, res) => {
    await readNodeRequest(req);
    sellerRequests += 1;
    if (sellerRequests === 1) {
      res.writeHead(402, { 'content-type': 'application/json' });
      res.end(JSON.stringify(firstChallenge));
      return;
    }
    res.writeHead(307, { location: redirectTargetUrl });
    res.end();
  });
  await listenLoopback(seller);
  t.after(async () => {
    await closeServer(seller);
    await closeServer(redirectTarget);
  });

  requestUrl = `http://127.0.0.1:${seller.address().port}/invoke/skill-a`;
  const now = Date.now();
  const localOffer = {
    ...baseOffer(),
    resource: requestUrl,
    extra: {
      ...baseOffer().extra,
      requestHash: canonicalRequestHash({ method: 'POST', requestUrl, bodyBytes: BODY }),
      issuedAt: new Date(now - 1_000).toISOString(),
      expiresAt: new Date(now + 59_000).toISOString(),
    },
  };
  firstChallenge = challengePayload(localOffer);
  let signatures = 0;
  const account = {
    address: PAYER,
    async signTypedData() { signatures += 1; return SIGNATURE; },
  };
  const paymentPolicy = createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => now,
    sellers: [{
      origin: new globalThis.URL(requestUrl).origin,
      pathPrefix: '/invoke/',
      payTo: PAYEE,
      maxPerCallAtomic: '300000',
    }],
  });

  await assert.rejects(() => payingFetch(account, requestUrl, {
    method: 'POST', body: BODY, redirect: 'follow',
  }, {
    idempotencyKey: 'idem-paid-redirect', paymentPolicy,
  }));
  assert.equal(sellerRequests, 2);
  assert.equal(redirectedRequests.length, 0);
  assert.equal(signatures, 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('a changed second offer gets no second signature or third request and holds budget', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const responses = [challenge(), challenge(baseOffer({ maxAmountRequired: '260000' }))];
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => responses[fetches++],
    idempotencyKey: 'idem-changed',
    paymentPolicy,
  }), (error) => error.code === 'QUOTE_CHANGED');
  assert.equal(fetches, 2);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
});

test('an unchanged second 402 still gets no second signature or third request', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => { fetches += 1; return challenge(); },
    idempotencyKey: 'idem-second-402',
    paymentPolicy,
  }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED');
  assert.equal(fetches, 2);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
});

test('missing, malformed, unknown-key, and mismatched settlement evidence withholds upstream output', async () => {
  const cases = [
    () => new Response('{"secretOutput":"must stay withheld"}', { status: 200 }),
    () => new Response('{"secretOutput":"must stay withheld"}', {
      status: 200, headers: { 'X-PAYMENT-RESPONSE': 'not-base64' },
    }),
    (init) => paidResponse(init, {
      body: '{"secretOutput":"must stay withheld"}', settlement: { injected: true },
    }),
    (init) => paidResponse(init, {
      body: '{"secretOutput":"must stay withheld"}', settlement: { value: '250001' },
    }),
  ];
  for (let index = 0; index < cases.length; index += 1) {
    const { account, paymentPolicy } = setup();
    let fetches = 0;
    let caught;
    try {
      await payingFetch(account, URL, { method: 'POST', body: BODY }, {
        fetchImpl: async (_url, init) => {
          fetches += 1;
          return fetches === 1 ? challenge() : cases[index](init);
        },
        idempotencyKey: `idem-bad-settlement-${index}`,
        paymentPolicy,
      });
    } catch (error) {
      caught = error;
    }
    assert.ok(caught instanceof PaymentPolicyError);
    assert.equal(caught.code, 'SETTLEMENT_EVIDENCE');
    assert.equal('res' in caught, false);
    assert.doesNotMatch(caught.message, /secretOutput/);
    assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
    assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
  }
});

test('a settled HTTP 500 consumes spend and returns exactly the documented paid result', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  const result = await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      fetches += 1;
      return fetches === 1 ? challenge() : paidResponse(init, { status: 500, body: '{"error":"execution failed"}' });
    },
    idempotencyKey: 'idem-settled-500',
    paymentPolicy,
  });
  assert.deepEqual(Object.keys(result).sort(), [
    'amountAtomic', 'amountDisplay', 'idempotencyKey', 'paid', 'payer', 'quoteId', 'requestHash',
    'res', 'settlementReference', 'timings', 'txHash', 'xPayment',
  ].sort());
  assert.deepEqual(Object.keys(result.timings).sort(), [
    'ms402', 'msFacilitator', 'msOverhead', 'msPaidRoundtrip', 'msSign',
  ].sort());
  assert.equal(result.res.status, 500);
  assert.equal(result.paid, true);
  assert.equal(result.txHash, TX_HASH);
  assert.equal(result.amountAtomic, '250000');
  assert.equal(result.amountDisplay, '0.250000');
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().spentAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('a non-402 response preserves no-pay semantics without settlement fields', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const result = await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => new Response('{"public":true}', { status: 200 }),
    idempotencyKey: 'idem-no-pay',
    paymentPolicy,
  });
  assert.deepEqual(Object.keys(result).sort(), ['idempotencyKey', 'paid', 'res']);
  assert.equal(result.paid, false);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().authorizations.length, 0);
});

test('concurrent copies of one idempotency key produce one signature and one paid retry', async () => {
  const { account, paymentPolicy } = setup();
  let signatures = 0;
  let releaseSignature;
  let announceSignature;
  const started = new Promise((resolve) => { announceSignature = resolve; });
  const gate = new Promise((resolve) => { releaseSignature = resolve; });
  account.signTypedData = async () => {
    signatures += 1;
    announceSignature();
    await gate;
    return SIGNATURE;
  };
  let paidRetries = 0;
  const fetchImpl = async (_url, init) => {
    if (!new Headers(init.headers).has('X-PAYMENT')) return challenge();
    paidRetries += 1;
    return paidResponse(init);
  };
  const options = { fetchImpl, idempotencyKey: 'idem-concurrent', paymentPolicy };
  const first = payingFetch(account, URL, { method: 'POST', body: BODY }, options);
  await started;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, options),
    (error) => error.code === 'AUTHORIZATION_ALREADY_USED');
  releaseSignature();
  assert.equal((await first).res.status, 200);
  assert.equal(signatures, 1);
  assert.equal(paidRetries, 1);
});

test('a settled same-id replay after quote expiry reports already used without another signature', async () => {
  const { account, paymentPolicy, signatureCount, setClock } = setup();
  let initialFetches = 0;
  await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      initialFetches += 1;
      return initialFetches === 1 ? challenge() : paidResponse(init);
    },
    idempotencyKey: 'idem-expired-terminal-replay',
    paymentPolicy,
  });
  const before = paymentPolicy.snapshot();
  setClock(NOW + 60_000);
  let replayFetches = 0;

  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      replayFetches += 1;
      return challenge();
    },
    idempotencyKey: 'idem-expired-terminal-replay',
    paymentPolicy,
  }), (error) => error.code === 'AUTHORIZATION_ALREADY_USED');
  assert.equal(replayFetches, 1);
  assert.equal(signatureCount(), 1);
  assert.deepEqual(paymentPolicy.snapshot(), before);
});

test('ordinary signer rejection before any signature return releases reservation exactly once', async () => {
  const { account, paymentPolicy } = setup();
  account.signTypedData = async () => { throw new Error('wallet declined before signing'); };
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(), idempotencyKey: 'idem-declined', paymentPolicy,
  }), /wallet declined/);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'released');
});

test('wallet address and signer access failures release before signer invocation', async () => {
  for (const capability of ['address', 'signTypedData']) {
    const { account, paymentPolicy, signatureCount } = setup();
    Object.defineProperty(account, capability, {
      configurable: true,
      enumerable: true,
      get() {
        throw new Error(`synthetic ${capability} access failure`);
      },
    });

    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
      fetchImpl: async () => challenge(),
      idempotencyKey: `idem-${capability}-access-failure`,
      paymentPolicy,
    }), new RegExp(`synthetic ${capability} access failure`));
    assert.equal(signatureCount(), 0, capability);
    assert.equal(paymentPolicy.snapshot().reservedAtomic, '0', capability);
    assert.equal(paymentPolicy.snapshot().remainingAtomic, '500000', capability);
    assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'released', capability);
  }
});

test('wallet address and signer capabilities are captured exactly once before signing', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const signer = account.signTypedData;
  let addressReads = 0;
  let signerReads = 0;
  Object.defineProperty(account, 'address', {
    configurable: true,
    enumerable: true,
    get() {
      addressReads += 1;
      if (addressReads > 1) throw new Error('wallet address was reread');
      return PAYER;
    },
  });
  Object.defineProperty(account, 'signTypedData', {
    configurable: true,
    enumerable: true,
    get() {
      signerReads += 1;
      if (signerReads > 1) throw new Error('wallet signer was reread');
      return signer;
    },
  });
  let fetches = 0;

  const result = await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      fetches += 1;
      return fetches === 1 ? challenge() : paidResponse(init);
    },
    idempotencyKey: 'idem-wallet-snapshot',
    paymentPolicy,
  });
  assert.equal(result.paid, true);
  assert.equal(addressReads, 1);
  assert.equal(signerReads, 1);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
  assert.equal(paymentPolicy.snapshot().spentAtomic, '250000');
});

test('local nonce construction failure before signer invocation releases the reservation', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(),
    idempotencyKey: 'idem-local-nonce-failure',
    paymentPolicy,
    nonceFactory: () => { throw new Error('local entropy unavailable'); },
  }), /local entropy unavailable/);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'released');
});

test('an invalid signer return is potentially signed and never releases budget', async () => {
  const { account, paymentPolicy } = setup();
  account.signTypedData = async () => 'not-a-signature';
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(), idempotencyKey: 'idem-invalid-signature', paymentPolicy,
  }), (error) => error.code === 'SIGNATURE_FORMAT');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('persistence failure after a signature return remains unresolved with budget held', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const failingPersistencePolicy = Object.freeze({
    ...paymentPolicy,
    persistSignedAuthorization() {
      throw new Error('synthetic persistence failure after signer return');
    },
  });
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(),
    idempotencyKey: 'idem-persistence-failure',
    paymentPolicy: failingPersistencePolicy,
  }), /synthetic persistence failure/);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('a quote expiring after signature persistence never starts the paid retry', async () => {
  const { account, paymentPolicy, setClock, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      fetches += 1;
      if (fetches === 1) return challenge();
      throw new Error('paid retry must not start after authorization expiry');
    },
    idempotencyKey: 'idem-expired-after-signing',
    paymentPolicy,
    onSignedAuthorizationPersisted: ({ authorization: persisted }) => {
      assert.equal(persisted.state, 'signed');
      setClock(NOW + 59_000);
    },
  }), (error) => error.code === 'QUOTE_EXPIRY');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('trusted quote age and monotonic time are rechecked after signing before retry', async () => {
  const cases = [
    {
      name: 'issue age',
      candidate: baseOffer({
        extra: { ...baseOffer().extra, issuedAt: new Date(NOW - 4_000).toISOString() },
      }),
      beforeRetry: NOW + 2_000,
    },
    {
      name: 'backward clock',
      candidate: baseOffer(),
      beforeRetry: NOW - 1,
    },
  ];

  for (const { name, candidate, beforeRetry } of cases) {
    const { account, paymentPolicy, setClock, signatureCount } = setup();
    let fetches = 0;
    await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
      idempotencyKey: `idem-retry-${name.replaceAll(' ', '-')}`,
      paymentPolicy,
      fetchImpl: async () => {
        fetches += 1;
        if (fetches > 1) throw new Error('stale authorization must not start a paid retry');
        return challenge(candidate);
      },
      onSignedAuthorizationPersisted: () => { setClock(beforeRetry); },
    }), (error) => error.code === 'QUOTE_FRESHNESS');
    assert.equal(fetches, 1, name);
    assert.equal(signatureCount(), 1, name);
    assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000', name);
    assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved', name);
  }
});

test('a fault after synchronous signature persistence recovers exact X-PAYMENT without signing again', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let firstFetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => { firstFetches += 1; return challenge(); },
    idempotencyKey: 'idem-persisted-fault',
    paymentPolicy,
    onSignedAuthorizationPersisted: () => { throw new Error('synthetic process interruption'); },
  }), /synthetic process interruption/);
  assert.equal(firstFetches, 1);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'signed');

  let retryPayment = null;
  let recoveryFetches = 0;
  const result = await payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      recoveryFetches += 1;
      if (recoveryFetches === 1) return challenge();
      retryPayment = new Headers(init.headers).get('X-PAYMENT');
      return paidResponse(init);
    },
    idempotencyKey: 'idem-persisted-fault',
    paymentPolicy,
  });
  assert.equal(result.res.status, 200);
  assert.equal(signatureCount(), 1);
  assert.equal(recoveryFetches, 2);
  assert.equal(retryPayment, result.xPayment);
});

test('signed recovery rechecks expiry and holds the reservation without a retry', async () => {
  const { account, paymentPolicy, setClock, signatureCount } = setup();
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(),
    idempotencyKey: 'idem-expired-recovery',
    paymentPolicy,
    onSignedAuthorizationPersisted: () => { throw new Error('synthetic process interruption'); },
  }), /synthetic process interruption/);
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'signed');
  setClock(NOW + 59_000);

  let recoveryFetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      recoveryFetches += 1;
      if (recoveryFetches > 1) throw new Error('expired recovery must not start a paid retry');
      return challenge();
    },
    idempotencyKey: 'idem-expired-recovery',
    paymentPolicy,
  }), (error) => error.code === 'QUOTE_EXPIRY');
  assert.equal(recoveryFetches, 1);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('retry transport loss leaves the signed amount unresolved and never retries internally', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => {
      fetches += 1;
      if (fetches === 1) return challenge();
      throw new Error('transport response lost');
    },
    idempotencyKey: 'idem-transport-loss',
    paymentPolicy,
  }), /transport response lost/);
  assert.equal(fetches, 2);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('unpaid fetch deadline stops an ignoring transport before any reservation or signature', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const caller = new AbortController();
  let transportSignal = null;
  await assert.rejects(() => payingFetch(account, URL, {
    method: 'POST', body: BODY, signal: caller.signal,
  }, {
    fetchImpl: async (_url, init) => {
      transportSignal = init.signal;
      return new Promise(() => {});
    },
    idempotencyKey: 'idem-unpaid-timeout',
    paymentPolicy,
    unpaidTimeoutMs: 20,
    paidTimeoutMs: 20,
  }), (error) => error.code === 'UNPAID_FETCH_TIMEOUT');
  assert.equal(transportSignal.aborted, true);
  assert.notEqual(transportSignal, caller.signal);
  assert.equal(caller.signal.aborted, false);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
  assert.deepEqual(paymentPolicy.snapshot().authorizations, []);
});

test('paid retry deadline leaves the signed authorization unresolved with budget held', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  let retrySignal = null;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async (_url, init) => {
      fetches += 1;
      if (fetches === 1) return challenge();
      retrySignal = init.signal;
      return new Promise(() => {});
    },
    idempotencyKey: 'idem-paid-timeout',
    paymentPolicy,
    unpaidTimeoutMs: 200,
    paidTimeoutMs: 20,
  }), (error) => error.code === 'PAID_RETRY_TIMEOUT');
  assert.equal(fetches, 2);
  assert.equal(retrySignal.aborted, true);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
});

test('chunked oversized 402 challenge is cancelled before signing or reservation', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array(40_000));
      controller.enqueue(new Uint8Array(30_000));
    },
    cancel() { cancelled = true; },
  });
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => new Response(stream, {
      status: 402,
      headers: { 'content-type': 'application/json' },
    }),
    idempotencyKey: 'idem-oversized-challenge',
    paymentPolicy,
    unpaidTimeoutMs: 200,
    paidTimeoutMs: 200,
  }), (error) => error.code === 'X402_CHALLENGE_TOO_LARGE');
  assert.equal(cancelled, true);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('stalled 402 challenge body is cancelled at the unpaid deadline before signing', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let cancelled = false;
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode('{"x402Version":1'));
    },
    cancel() { cancelled = true; },
  });
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => new Response(stream, {
      status: 402,
      headers: { 'content-type': 'application/json' },
    }),
    idempotencyKey: 'idem-stalled-challenge',
    paymentPolicy,
    unpaidTimeoutMs: 20,
    paidTimeoutMs: 200,
  }), (error) => error.code === 'UNPAID_FETCH_TIMEOUT');
  assert.equal(cancelled, true);
  assert.equal(signatureCount(), 0);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

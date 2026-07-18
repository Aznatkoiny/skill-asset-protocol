import assert from 'node:assert/strict';
import test from 'node:test';

import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  canonicalRequestHash,
  createPaymentPolicy,
  PaymentPolicyError,
} from '../src/payment-policy.mjs';
import { payingFetch } from '../src/proxy.mjs';

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
  return new Response(JSON.stringify({
    x402Version: 1,
    error: 'X-PAYMENT header is required',
    accepts: [candidate],
  }), { status: 402, headers: { 'content-type': 'application/json' } });
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

test('signer rejection before any signature releases reservation exactly once', async () => {
  const { account, paymentPolicy } = setup();
  account.signTypedData = async () => {
    const error = new Error('wallet declined before signing');
    error.signatureProduced = false;
    throw error;
  };
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: BODY }, {
    fetchImpl: async () => challenge(), idempotencyKey: 'idem-declined', paymentPolicy,
  }), /wallet declined/);
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'released');
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

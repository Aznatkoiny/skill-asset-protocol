# Wielder Payment Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent the thin Wielder from signing an x402 offer unless its network, asset, seller, payee, resource, amount, freshness, timeout, and session budget satisfy an explicit local policy.

**Architecture:** Add a pure stateful payment-policy object that validates an offer, atomically reserves session budget, permits exactly one retry with the accepted amount, and tracks settled, rejected, or unresolved authorizations. `payingFetch` becomes an exported orchestration function that asks the policy before signing and never recursively pays a changed second offer.

**Tech Stack:** Node.js 20+, ECMAScript modules, built-in `node:test`, `node:assert/strict`, viem local signing, Hono; mock/testnet verification only, with zero funded-wallet or network requirements.

---

## Prerequisites and file map

Complete the atomic-money and Collar-journal plans first.

- Create `spikes/pi-wielder/src/payment-policy.mjs`: seller rules, offer validation, authorization reservation, retry/settlement state, and budget snapshots.
- Create `spikes/pi-wielder/tests/payment-policy.test.mjs`: one rejection test per required check plus concurrency and lifecycle cases.
- Create `spikes/pi-wielder/tests/paying-fetch.test.mjs`: orchestration tests proving no forbidden offer is signed and no second retry occurs.
- Modify `spikes/pi-wielder/src/proxy.mjs`: inject/use the policy and export `payingFetch` for focused tests.
- Modify `spikes/pi-wielder/e2e.mjs`: configure trusted mock sellers and verify session spend.
- Modify `spikes/pi-wielder/.env.example`: document testnet-only policy variables without adding any key.
- Modify `spikes/pi-wielder/package.json`: add focused policy test scripts.

## Policy interface

```js
const policy = createPaymentPolicy({
  network: 'base-sepolia',
  asset: '0x036C...CF7e',
  sessionBudgetAtomic: '1000000',
  maxQuoteAgeMs: 5_000,
  maxAuthorizationSeconds: 60,
  sellers: [{
    origin: 'http://127.0.0.1:8404',
    pathPrefix: '/invoke/',
    payTo: '0x0000...dEaD',
    maxPerCallAtomic: '500000',
  }],
});

policy.reserveAuthorization({ authorizationId, requestUrl, method, bodyBytes, offer, receivedAtMs });
policy.beginRetry(authorizationId, { amountAtomic, offerFingerprint });
policy.assertRetryOffer(authorizationId, secondOffer);
policy.markSettled(authorizationId, { txHash });
policy.markRejected(authorizationId, { reason });
policy.markUnresolved(authorizationId, { reason });
policy.snapshot();
```

The policy reserves budget before signing so concurrent calls cannot overspend. An
unresolved authorization retains its reservation until trusted reconciliation marks it
settled or rejected.

### Task 1: Implement pure offer validation and session-budget state

**Files:**
- Create: `spikes/pi-wielder/src/payment-policy.mjs`
- Create: `spikes/pi-wielder/tests/payment-policy.test.mjs`

- [ ] **Step 1: Write failing policy rejection and lifecycle tests**

Create `spikes/pi-wielder/tests/payment-policy.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  canonicalRequestHash,
  createPaymentPolicy,
  PaymentPolicyError,
} from '../src/payment-policy.mjs';

const ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const PAYEE = '0x000000000000000000000000000000000000dEaD';
const URL = 'https://trusted.example/invoke/skill-a';
const REQUEST_HASH = canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: '{}' });

const offer = (overrides = {}) => ({
  scheme: 'exact',
  network: 'base-sepolia',
  maxAmountRequired: '250000',
  resource: URL,
  payTo: PAYEE,
  maxTimeoutSeconds: 60,
  asset: ASSET,
  extra: {
    name: 'USDC',
    version: '2',
    requestHash: REQUEST_HASH,
    quoteId: `sha256:${'b'.repeat(64)}`,
    issuedAt: new Date(9_000).toISOString(),
    expiresAt: new Date(69_000).toISOString(),
  },
  ...overrides,
});

function policy(overrides = {}) {
  return createPaymentPolicy({
    network: 'base-sepolia',
    asset: ASSET,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => 10_000,
    sellers: [{
      origin: 'https://trusted.example',
      pathPrefix: '/invoke/',
      payTo: PAYEE,
      maxPerCallAtomic: '300000',
    }],
    ...overrides,
  });
}

const rejectionCases = [
  ['wrong scheme', offer({ scheme: 'upto' }), URL, 9_000, 'SCHEME'],
  ['wrong network', offer({ network: 'base' }), URL, 9_000, 'NETWORK'],
  ['wrong asset', offer({ asset: '0x1111111111111111111111111111111111111111' }), URL, 9_000, 'ASSET'],
  ['wrong payee', offer({ payTo: '0x2222222222222222222222222222222222222222' }), URL, 9_000, 'PAYEE'],
  ['wrong resource', offer({ resource: 'https://trusted.example/invoke/other' }), URL, 9_000, 'RESOURCE'],
  ['untrusted seller', offer({ resource: 'https://evil.example/invoke/skill-a' }), 'https://evil.example/invoke/skill-a', 9_000, 'SELLER'],
  ['zero amount', offer({ maxAmountRequired: '0' }), URL, 9_000, 'AMOUNT'],
  ['over per-call cap', offer({ maxAmountRequired: '300001' }), URL, 9_000, 'PER_CALL'],
  ['expired local quote', offer(), URL, 4_999, 'FRESHNESS'],
  ['excess timeout', offer({ maxTimeoutSeconds: 61 }), URL, 9_000, 'TIMEOUT'],
  ['mismatched request bytes', offer({ extra: { ...offer().extra, requestHash: `sha256:${'f'.repeat(64)}` } }), URL, 9_000, 'REQUEST_HASH'],
  ['wrong EIP-712 name', offer({ extra: { ...offer().extra, name: 'FakeUSDC' } }), URL, 9_000, 'EIP712'],
  ['wrong EIP-712 version', offer({ extra: { ...offer().extra, version: '1' } }), URL, 9_000, 'EIP712'],
  ['expired server quote', offer({ extra: { ...offer().extra, expiresAt: new Date(9_999).toISOString() } }), URL, 9_000, 'QUOTE_EXPIRY'],
];

for (const [name, candidate, requestUrl, receivedAtMs, code] of rejectionCases) {
  test(`rejects ${name} before reservation`, () => {
    const subject = policy();
    assert.throws(
      () => subject.reserveAuthorization({
        authorizationId: `auth-${code}`,
        requestUrl,
        offer: candidate,
        receivedAtMs,
        method: 'POST',
        bodyBytes: '{}',
      }),
      (error) => error instanceof PaymentPolicyError && error.code.includes(code),
    );
    assert.equal(subject.snapshot().reservedAtomic, '0');
  });
}

test('concurrent reservations cannot exceed the remaining session budget', () => {
  const subject = policy({ sessionBudgetAtomic: '400000' });
  subject.reserveAuthorization({ authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000 });
  assert.throws(() => subject.reserveAuthorization({
    authorizationId: 'auth-2', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  }), (error) => error.code === 'SESSION_BUDGET');
  assert.deepEqual(subject.snapshot(), {
    sessionBudgetAtomic: '400000',
    reservedAtomic: '250000',
    spentAtomic: '0',
    remainingAtomic: '150000',
    authorizations: [{
      authorizationId: 'auth-1',
      amountAtomic: '250000',
      state: 'reserved',
      retryCount: 0,
      txHash: null,
      reason: null,
    }],
  });
});

test('accepted amount is immutable and one authorization permits one retry', () => {
  const subject = policy();
  const auth = subject.reserveAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  assert.equal(subject.claimSignature('auth-1', { offerFingerprint: auth.offerFingerprint }).claimed, true);
  assert.throws(() => subject.beginRetry('auth-1', {
    amountAtomic: '250001', offerFingerprint: auth.offerFingerprint,
  }), (error) => error.code === 'AMOUNT_DRIFT');
  subject.beginRetry('auth-1', {
    amountAtomic: '250000', offerFingerprint: auth.offerFingerprint,
  });
  assert.throws(() => subject.beginRetry('auth-1', {
    amountAtomic: '250000', offerFingerprint: auth.offerFingerprint,
  }), (error) => error.code === 'RETRY_LIMIT');
});

test('a changed second offer is rejected and cannot receive another signature', () => {
  const subject = policy();
  const auth = subject.reserveAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  subject.claimSignature('auth-1', { offerFingerprint: auth.offerFingerprint });
  subject.beginRetry('auth-1', {
    amountAtomic: auth.amountAtomic, offerFingerprint: auth.offerFingerprint,
  });
  assert.throws(
    () => subject.assertRetryOffer('auth-1', offer({ maxAmountRequired: '260000' })),
    (error) => error.code === 'QUOTE_CHANGED',
  );
});

test('settled spend consumes budget while a pre-sign rejection releases it', () => {
  const subject = policy();
  const first = subject.reserveAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  subject.claimSignature('auth-1', { offerFingerprint: first.offerFingerprint });
  subject.beginRetry('auth-1', { amountAtomic: first.amountAtomic, offerFingerprint: first.offerFingerprint });
  subject.markSettled('auth-1', { txHash: `0x${'1'.repeat(64)}` });

  const second = subject.reserveAuthorization({
    authorizationId: 'auth-2', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer({ maxAmountRequired: '100000' }), receivedAtMs: 9_000,
  });
  subject.markRejected('auth-2', { reason: 'local signing failed before authorization' });
  assert.equal(subject.snapshot().spentAtomic, '250000');
  assert.equal(subject.snapshot().reservedAtomic, '0');
  assert.equal(subject.snapshot().remainingAtomic, '250000');
});

test('post-sign rejection requires an injected trusted rejection proof', () => {
  const subject = policy();
  const auth = subject.reserveAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  subject.claimSignature('auth-1', { offerFingerprint: auth.offerFingerprint });
  subject.beginRetry('auth-1', { amountAtomic: auth.amountAtomic, offerFingerprint: auth.offerFingerprint });
  assert.throws(
    () => subject.markRejected('auth-1', { reason: 'untrusted seller said no' }),
    (error) => error.code === 'REJECTION_PROOF',
  );
  assert.equal(subject.snapshot().reservedAtomic, '250000');
});

test('unresolved spend remains reserved until trusted settlement reconciliation', () => {
  const subject = policy();
  const auth = subject.reserveAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  subject.claimSignature('auth-1', { offerFingerprint: auth.offerFingerprint });
  subject.beginRetry('auth-1', { amountAtomic: auth.amountAtomic, offerFingerprint: auth.offerFingerprint });
  subject.markUnresolved('auth-1', { reason: 'seller response lost' });
  assert.equal(subject.snapshot().reservedAtomic, '250000');
  subject.markSettled('auth-1', { txHash: `0x${'2'.repeat(64)}` });
  assert.equal(subject.snapshot().reservedAtomic, '0');
  assert.equal(subject.snapshot().spentAtomic, '250000');
});

test('signature claim is atomic and an unsigned failure releases its reservation exactly once', () => {
  const subject = policy();
  const auth = subject.reserveAuthorization({
    authorizationId: 'auth-claim', requestUrl: URL, method: 'POST', bodyBytes: '{}', offer: offer(), receivedAtMs: 9_000,
  });
  assert.deepEqual(subject.claimSignature('auth-claim', { offerFingerprint: auth.offerFingerprint }).claimed, true);
  assert.equal(subject.claimSignature('auth-claim', { offerFingerprint: auth.offerFingerprint }).claimed, false);
  subject.releaseUnsigned('auth-claim', { reason: 'wallet declined before producing a signature' });
  assert.equal(subject.snapshot().reservedAtomic, '0');
  assert.equal(subject.snapshot().authorizations[0].state, 'released');
  assert.throws(() => subject.releaseUnsigned('auth-claim', { reason: 'double release' }),
    (error) => error.code === 'UNSIGNED_RELEASE_STATE');
});
```

- [ ] **Step 2: Run the test and verify the policy module is missing**

Run: `node --test spikes/pi-wielder/tests/payment-policy.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/payment-policy.mjs`.

- [ ] **Step 3: Implement validation, reservation, and lifecycle state**

Create `spikes/pi-wielder/src/payment-policy.mjs`:

```js
import crypto from 'node:crypto';

export class PaymentPolicyError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'PaymentPolicyError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new PaymentPolicyError(code, message); };
const copy = (value) => structuredClone(value);

function atomic(value, label) {
  const text = String(value ?? '');
  if (!/^(0|[1-9]\d*)$/.test(text)) fail('AMOUNT_FORMAT', `${label} must be a canonical atomic string`);
  return { text, value: BigInt(text) };
}

function address(value, label) {
  const text = String(value ?? '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) fail(`${label.toUpperCase()}_FORMAT`, `${label} must be a 20-byte hex address`);
  return text.toLowerCase();
}

function request(value) {
  try {
    const url = new URL(value);
    url.hash = '';
    return url;
  } catch {
    fail('RESOURCE_URL', `invalid request URL '${value}'`);
  }
}

export function canonicalRequestHash({ method, requestUrl, bodyBytes }) {
  const verb = String(method ?? '').toUpperCase();
  if (!verb) fail('REQUEST_METHOD', 'request method must be non-empty');
  const target = request(requestUrl).href;
  let body;
  if (typeof bodyBytes === 'string') body = Buffer.from(bodyBytes, 'utf8');
  else if (bodyBytes instanceof Uint8Array) body = Buffer.from(bodyBytes);
  else if (bodyBytes == null) body = Buffer.alloc(0);
  else fail('REQUEST_BODY', 'request body must be a string, Uint8Array, or null');
  const prefix = Buffer.from(`${verb}\n${target}\n`, 'utf8');
  return `sha256:${crypto.createHash('sha256').update(Buffer.concat([prefix, body])).digest('hex')}`;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

function fingerprint(offer) {
  return `sha256:${crypto.createHash('sha256').update(JSON.stringify(canonicalize(offer))).digest('hex')}`;
}

export function createPaymentPolicy({
  network,
  asset,
  sellers,
  sessionBudgetAtomic,
  maxQuoteAgeMs,
  maxAuthorizationSeconds,
  now = () => Date.now(),
  verifyRejectionProof = () => false,
}) {
  const expectedNetwork = String(network);
  const expectedAsset = address(asset, 'asset');
  const budget = atomic(sessionBudgetAtomic, 'sessionBudgetAtomic').value;
  if (!Number.isSafeInteger(maxQuoteAgeMs) || maxQuoteAgeMs < 0) fail('FRESHNESS_CONFIG', 'maxQuoteAgeMs must be a non-negative safe integer');
  if (!Number.isSafeInteger(maxAuthorizationSeconds) || maxAuthorizationSeconds <= 0) {
    fail('TIMEOUT_CONFIG', 'maxAuthorizationSeconds must be a positive safe integer');
  }
  const rules = (sellers ?? []).map((seller) => {
    const origin = request(seller.origin).origin;
    const pathPrefix = String(seller.pathPrefix ?? '');
    if (!pathPrefix.startsWith('/')) fail('SELLER_PATH', 'seller pathPrefix must start with /');
    return {
      origin,
      pathPrefix,
      payTo: address(seller.payTo, 'payee'),
      maxPerCallAtomic: atomic(seller.maxPerCallAtomic, 'maxPerCallAtomic').value,
    };
  }).sort((left, right) => right.pathPrefix.length - left.pathPrefix.length);
  if (!rules.length) fail('SELLER_CONFIG', 'at least one trusted seller rule is required');

  const authorizations = new Map();
  let reservedAtomic = 0n;
  let spentAtomic = 0n;

  function validateOffer({ requestUrl, method, bodyBytes, offer, receivedAtMs }) {
    const target = request(requestUrl);
    const seller = rules.find((rule) => rule.origin === target.origin && target.pathname.startsWith(rule.pathPrefix));
    if (!seller) fail('SELLER_UNTRUSTED', `no trusted seller rule covers ${target.origin}${target.pathname}`);
    if (offer?.scheme !== 'exact') fail('SCHEME_UNSUPPORTED', "x402 scheme must be 'exact'");
    if (offer?.network !== expectedNetwork) fail('NETWORK_MISMATCH', `x402 network must be '${expectedNetwork}'`);
    if (address(offer?.asset, 'asset') !== expectedAsset) fail('ASSET_MISMATCH', 'x402 asset does not match policy');
    if (address(offer?.payTo, 'payee') !== seller.payTo) fail('PAYEE_MISMATCH', 'x402 payee does not match trusted seller');
    if (request(offer?.resource).href !== target.href) fail('RESOURCE_MISMATCH', 'x402 resource does not match the requested URL');
    const localRequestHash = canonicalRequestHash({ method, requestUrl: target.href, bodyBytes });
    if (offer?.extra?.requestHash !== localRequestHash) {
      fail('REQUEST_HASH_MISMATCH', 'x402 requestHash does not bind the outgoing method, URL, and body bytes');
    }
    if (offer?.extra?.name !== 'USDC' || offer?.extra?.version !== '2') {
      fail('EIP712_DOMAIN', 'x402 offer must use the canonical USDC EIP-712 name and version');
    }
    if (!/^sha256:[0-9a-f]{64}$/.test(offer?.extra?.quoteId ?? '')) {
      fail('QUOTE_ID', 'x402 offer must contain a valid immutable quoteId');
    }
    const issuedAtMs = Date.parse(offer?.extra?.issuedAt ?? '');
    const expiresAtMs = Date.parse(offer?.extra?.expiresAt ?? '');
    if (!Number.isFinite(issuedAtMs) || !Number.isFinite(expiresAtMs)
      || issuedAtMs > now() || now() - issuedAtMs > maxQuoteAgeMs
      || expiresAtMs <= now() || issuedAtMs >= expiresAtMs) {
      fail('QUOTE_EXPIRY', 'x402 server quote is not currently valid');
    }

    const amount = atomic(offer?.maxAmountRequired, 'maxAmountRequired');
    if (amount.value <= 0n) fail('AMOUNT_ZERO', 'x402 amount must be positive');
    if (amount.value > seller.maxPerCallAtomic) fail('PER_CALL_LIMIT', 'x402 amount exceeds the seller per-call cap');
    if (!Number.isSafeInteger(offer?.maxTimeoutSeconds) || offer.maxTimeoutSeconds <= 0
      || offer.maxTimeoutSeconds > maxAuthorizationSeconds) {
      fail('TIMEOUT_LIMIT', 'x402 timeout exceeds policy');
    }
    if (!Number.isFinite(receivedAtMs) || receivedAtMs > now() || now() - receivedAtMs > maxQuoteAgeMs) {
      fail('FRESHNESS_EXPIRED', 'x402 quote is stale or has an invalid local receipt time');
    }
    return {
      amountAtomic: amount.text,
      requestUrl: target.href,
      requestHash: localRequestHash,
      offerFingerprint: fingerprint(offer),
    };
  }

  function reserveAuthorization({ authorizationId, requestUrl, method, bodyBytes, offer, receivedAtMs }) {
    const id = String(authorizationId ?? '').trim();
    if (!id) fail('AUTHORIZATION_ID', 'authorizationId must be non-empty');
    const validated = validateOffer({ requestUrl, method, bodyBytes, offer, receivedAtMs });
    const existing = authorizations.get(id);
    if (existing) {
      if (existing.offerFingerprint !== validated.offerFingerprint || existing.requestUrl !== validated.requestUrl) {
        fail('AUTHORIZATION_CONFLICT', 'authorizationId already binds a different offer');
      }
      return copy(existing);
    }
    const amountValue = BigInt(validated.amountAtomic);
    if (spentAtomic + reservedAtomic + amountValue > budget) fail('SESSION_BUDGET', 'x402 offer exceeds remaining session budget');
    const record = {
      authorizationId: id,
      ...validated,
      state: 'reserved',
      retryCount: 0,
      txHash: null,
      reason: null,
    };
    authorizations.set(id, record);
    reservedAtomic += amountValue;
    return copy(record);
  }

  function get(id) {
    const record = authorizations.get(id);
    if (!record) fail('AUTHORIZATION_UNKNOWN', `unknown authorization '${id}'`);
    return record;
  }

  function claimSignature(id, { offerFingerprint }) {
    const record = get(id);
    if (offerFingerprint !== record.offerFingerprint) fail('AUTHORIZATION_CONFLICT', 'signature claim does not match the reserved offer');
    if (record.state === 'reserved') {
      record.state = 'signing';
      return { claimed: true, authorization: copy(record) };
    }
    return { claimed: false, authorization: copy(record) };
  }

  function releaseUnsigned(id, { reason }) {
    const record = get(id);
    if (!['reserved', 'signing'].includes(record.state)) {
      fail('UNSIGNED_RELEASE_STATE', `cannot release unsigned authorization from '${record.state}'`);
    }
    reservedAtomic -= BigInt(record.amountAtomic);
    record.state = 'released';
    record.reason = String(reason);
    return copy(record);
  }

  function beginRetry(id, { amountAtomic, offerFingerprint }) {
    const record = get(id);
    if (record.retryCount !== 0 || record.state !== 'signing') fail('RETRY_LIMIT', 'authorization permits exactly one claimed signature and retry');
    if (String(amountAtomic) !== record.amountAtomic) fail('AMOUNT_DRIFT', 'retry amount differs from accepted quote');
    if (offerFingerprint !== record.offerFingerprint) fail('QUOTE_CHANGED', 'retry fingerprint differs from accepted quote');
    record.retryCount = 1;
    record.state = 'retrying';
    return copy(record);
  }

  function assertRetryOffer(id, secondOffer) {
    const record = get(id);
    if (fingerprint(secondOffer) !== record.offerFingerprint) fail('QUOTE_CHANGED', 'seller changed the offer after authorization');
    return copy(record);
  }

  function markSettled(id, { txHash }) {
    const record = get(id);
    if (record.state === 'settled') {
      if (record.txHash !== txHash) fail('SETTLEMENT_CONFLICT', 'authorization already binds a different transaction');
      return copy(record);
    }
    if (!['retrying', 'unresolved'].includes(record.state)) fail('SETTLEMENT_STATE', `cannot settle authorization from '${record.state}'`);
    if (!/^0x[0-9a-fA-F]{64}$/.test(txHash)) fail('SETTLEMENT_HASH', 'txHash must be a 32-byte hex string');
    const value = BigInt(record.amountAtomic);
    reservedAtomic -= value;
    spentAtomic += value;
    record.state = 'settled';
    record.txHash = txHash;
    record.reason = null;
    return copy(record);
  }

  function markRejected(id, { reason, proof = null }) {
    const record = get(id);
    if (record.state === 'rejected') return copy(record);
    if (!['reserved', 'retrying', 'unresolved'].includes(record.state)) fail('REJECTION_STATE', `cannot reject authorization from '${record.state}'`);
    if (record.state !== 'reserved' && !verifyRejectionProof({ authorization: copy(record), proof })) {
      fail('REJECTION_PROOF', 'post-sign rejection requires trusted facilitator or chain proof');
    }
    reservedAtomic -= BigInt(record.amountAtomic);
    record.state = 'rejected';
    record.reason = String(reason);
    return copy(record);
  }

  function markUnresolved(id, { reason }) {
    const record = get(id);
    if (record.state === 'unresolved') return copy(record);
    if (record.state !== 'retrying') fail('UNRESOLVED_STATE', `cannot mark unresolved from '${record.state}'`);
    record.state = 'unresolved';
    record.reason = String(reason);
    return copy(record);
  }

  function snapshot() {
    return {
      sessionBudgetAtomic: budget.toString(),
      reservedAtomic: reservedAtomic.toString(),
      spentAtomic: spentAtomic.toString(),
      remainingAtomic: (budget - reservedAtomic - spentAtomic).toString(),
      authorizations: [...authorizations.values()]
        .sort((left, right) => left.authorizationId.localeCompare(right.authorizationId))
        .map(({ authorizationId, amountAtomic, state, retryCount, txHash, reason }) => ({
          authorizationId, amountAtomic, state, retryCount, txHash, reason,
        })),
    };
  }

  return Object.freeze({
    validateOffer,
    reserveAuthorization,
    claimSignature,
    releaseUnsigned,
    beginRetry,
    assertRetryOffer,
    markSettled,
    markRejected,
    markUnresolved,
    snapshot,
  });
}
```

- [ ] **Step 4: Run the policy tests**

Run: `node --test spikes/pi-wielder/tests/payment-policy.test.mjs`

Expected: PASS, 21 tests and 0 failures.

- [ ] **Step 5: Commit the pure policy**

```bash
git add spikes/pi-wielder/src/payment-policy.mjs spikes/pi-wielder/tests/payment-policy.test.mjs
git commit -m "feat: enforce Wielder payment policy"
```

### Task 2: Put policy authorization before every signature

**Files:**
- Modify: `spikes/pi-wielder/src/proxy.mjs:37-82`
- Create: `spikes/pi-wielder/tests/paying-fetch.test.mjs`

- [ ] **Step 1: Write failing orchestration tests with a signature spy**

Create `spikes/pi-wielder/tests/paying-fetch.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import { canonicalRequestHash, createPaymentPolicy } from '../src/payment-policy.mjs';
import { payingFetch } from '../src/proxy.mjs';

const ASSET = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const PAYEE = '0x000000000000000000000000000000000000dEaD';
const URL = 'https://trusted.example/invoke/skill-a';
const NOW = Date.UTC(2026, 6, 17, 12, 0, 10);
const REQUEST_HASH = canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: '{}' });
const baseOffer = (overrides = {}) => ({
  scheme: 'exact', network: 'base-sepolia', maxAmountRequired: '250000', resource: URL,
  payTo: PAYEE, maxTimeoutSeconds: 60, asset: ASSET,
  extra: {
    name: 'USDC',
    version: '2',
    requestHash: REQUEST_HASH,
    quoteId: `sha256:${'b'.repeat(64)}`,
    issuedAt: new Date(NOW - 1_000).toISOString(),
    expiresAt: new Date(NOW + 59_000).toISOString(),
  },
  ...overrides,
});
const challenge = (offer) => new Response(JSON.stringify({ x402Version: 1, accepts: [offer] }), {
  status: 402, headers: { 'content-type': 'application/json' },
});
const paymentHeader = ({ txHash, payer, settlementReference, network = 'base-sepolia', success = true }) => Buffer.from(JSON.stringify({
  success, transaction: txHash, network, payer, settlementReference,
})).toString('base64');

function setup() {
  let signatures = 0;
  const account = {
    address: '0x1000000000000000000000000000000000000000',
    async signTypedData() { signatures += 1; return `0x${'1'.repeat(130)}`; },
  };
  const paymentPolicy = createPaymentPolicy({
    network: 'base-sepolia', asset: ASSET, sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000, maxAuthorizationSeconds: 60,
    now: () => NOW,
    sellers: [{ origin: 'https://trusted.example', pathPrefix: '/invoke/', payTo: PAYEE, maxPerCallAtomic: '300000' }],
  });
  return { account, paymentPolicy, signatureCount: () => signatures };
}

test('a forbidden first offer is never signed or retried', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  let fetches = 0;
  const fetchImpl = async () => { fetches += 1; return challenge(baseOffer({ network: 'base' })); };
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: '{}' }, {
    fetchImpl, idempotencyKey: 'idem-1', paymentPolicy, receivedAtMs: NOW - 500,
  }), (error) => error.code === 'NETWORK_MISMATCH');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 0);
});

test('an offer for different request bytes is rejected with zero signatures', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const mismatched = baseOffer();
  mismatched.extra = { ...mismatched.extra, requestHash: `sha256:${'f'.repeat(64)}` };
  let fetches = 0;
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: '{}' }, {
    fetchImpl: async () => { fetches += 1; return challenge(mismatched); },
    idempotencyKey: 'idem-request-hash', paymentPolicy, receivedAtMs: NOW - 500,
  }), (error) => error.code === 'REQUEST_HASH_MISMATCH');
  assert.equal(fetches, 1);
  assert.equal(signatureCount(), 0);
});

test('a changed second offer gets no second signature or third request', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const responses = [challenge(baseOffer()), challenge(baseOffer({ maxAmountRequired: '260000' }))];
  let fetches = 0;
  const fetchImpl = async () => responses[fetches++];
  await assert.rejects(() => payingFetch(account, URL, { method: 'POST', body: '{}' }, {
    fetchImpl, idempotencyKey: 'idem-2', paymentPolicy, receivedAtMs: NOW - 500,
  }), (error) => error.code === 'QUOTE_CHANGED');
  assert.equal(fetches, 2);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
});

test('a settled HTTP 500 still consumes exactly the signed amount', async () => {
  const { account, paymentPolicy, signatureCount } = setup();
  const txHash = `0x${'2'.repeat(64)}`;
  let fetches = 0;
  const fetchImpl = async (_url, init) => {
    fetches += 1;
    if (fetches === 1) return challenge(baseOffer());
    const payment = JSON.parse(Buffer.from(init.headers['X-PAYMENT'], 'base64').toString('utf8'));
    const authorization = payment.payload.authorization;
    return new Response(JSON.stringify({ error: 'execution failed' }), {
      status: 500,
      headers: {
        'X-PAYMENT-RESPONSE': paymentHeader({
          txHash,
          payer: authorization.from,
          settlementReference: authorization.nonce,
        }),
        'X-402-FACILITATOR-MS': '1.0',
      },
    });
  };
  const result = await payingFetch(account, URL, { method: 'POST', body: '{}' }, {
    fetchImpl, idempotencyKey: 'idem-3', paymentPolicy, receivedAtMs: NOW - 500,
  });
  assert.equal(result.res.status, 500);
  assert.equal(result.txHash, txHash);
  assert.equal(signatureCount(), 1);
  assert.equal(paymentPolicy.snapshot().spentAtomic, '250000');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '0');
});

test('a malformed or mismatched settlement header remains unresolved', async () => {
  const { account, paymentPolicy } = setup();
  let fetches = 0;
  const fetchImpl = async () => {
    fetches += 1;
    if (fetches === 1) return challenge(baseOffer());
    return new Response('{}', {
      status: 200,
      headers: { 'X-PAYMENT-RESPONSE': Buffer.from('{"success":true}').toString('base64') },
    });
  };
  const result = await payingFetch(account, URL, { method: 'POST', body: '{}' }, {
    fetchImpl, idempotencyKey: 'idem-4', paymentPolicy, receivedAtMs: NOW - 500,
  });
  assert.equal(result.txHash, null);
  assert.equal(paymentPolicy.snapshot().authorizations[0].state, 'unresolved');
  assert.equal(paymentPolicy.snapshot().reservedAtomic, '250000');
});

test('concurrent and already-used copies of one idempotency key produce exactly one signature', async () => {
  const { account, paymentPolicy } = setup();
  let releaseSignature;
  let announceSignature;
  const signatureStarted = new Promise((resolve) => { announceSignature = resolve; });
  const signatureGate = new Promise((resolve) => { releaseSignature = resolve; });
  account.signTypedData = async () => {
    account.__signatures = (account.__signatures ?? 0) + 1;
    announceSignature();
    await signatureGate;
    return `0x${'1'.repeat(130)}`;
  };
  let paidRetries = 0;
  const fetchImpl = async (_url, init) => {
    if (!init.headers?.['X-PAYMENT']) return challenge(baseOffer());
    paidRetries += 1;
    const payment = JSON.parse(Buffer.from(init.headers['X-PAYMENT'], 'base64').toString('utf8'));
    const authorization = payment.payload.authorization;
    return new Response('{}', { status: 200, headers: {
      'X-PAYMENT-RESPONSE': paymentHeader({
        txHash: `0x${'3'.repeat(64)}`,
        payer: authorization.from,
        settlementReference: authorization.nonce,
      }),
    } });
  };
  const options = { fetchImpl, idempotencyKey: 'idem-atomic-claim', paymentPolicy, receivedAtMs: NOW - 500 };
  const first = payingFetch(account, URL, { method: 'POST', body: '{}' }, options);
  await signatureStarted;
  await assert.rejects(
    () => payingFetch(account, URL, { method: 'POST', body: '{}' }, options),
    (error) => error.code === 'AUTHORIZATION_ALREADY_USED',
  );
  releaseSignature();
  assert.equal((await first).res.status, 200);
  await assert.rejects(
    () => payingFetch(account, URL, { method: 'POST', body: '{}' }, options),
    (error) => error.code === 'AUTHORIZATION_ALREADY_USED',
  );
  assert.equal(account.__signatures, 1);
  assert.equal(paidRetries, 1);
});
```

- [ ] **Step 2: Run the tests and verify policy is not consulted**

Run: `node --test spikes/pi-wielder/tests/paying-fetch.test.mjs`

Expected: FAIL because `payingFetch` does not accept or enforce `paymentPolicy`.

- [ ] **Step 3: Validate and reserve before `signTypedData`**

Add `paymentPolicy` to the options accepted by `payingFetch`:

```js
export async function payingFetch(account, url, init, {
  fetchImpl = fetch,
  idempotencyKey = crypto.randomUUID(),
  paymentPolicy,
  receivedAtMs = Date.now(),
} = {}) {
```

Immediately after selecting `req`, replace the old scheme-only check with:

```js
  if (!req || firstBody.x402Version !== 1) throw new Error('402 without a usable x402 v1 payment offer');
  if (!paymentPolicy) throw new Error('paymentPolicy is required before signing an x402 offer');
  const authorizationRecord = paymentPolicy.reserveAuthorization({
    authorizationId: idempotencyKey,
    requestUrl: url,
    method: init.method ?? 'GET',
    bodyBytes: init.body ?? null,
    offer: req,
    receivedAtMs,
  });
  const signatureClaim = paymentPolicy.claimSignature(idempotencyKey, {
    offerFingerprint: authorizationRecord.offerFingerprint,
  });
  if (!signatureClaim.claimed) {
    throw new PaymentPolicyError(
      'AUTHORIZATION_ALREADY_USED',
      'idempotency key already has a signature claim or terminal authorization',
    );
  }
```

There is no `await` between reservation and `claimSignature`; the claim is the atomic
same-process boundary that makes concurrent copies of one idempotency key single-signer.

To support that block, parse the challenge once as:

```js
  const firstBody = await first.json();
  const req = firstBody.accepts?.[0];
```

- [ ] **Step 4: Reject signing failures and bind the one retry**

When constructing the EIP-3009 authorization, replace `validBefore` with the frozen
server expiry bound:

```js
    validBefore: String(Math.min(
      now + req.maxTimeoutSeconds,
      Math.floor(Date.parse(req.extra.expiresAt) / 1_000),
    )),
```

The policy has already validated that this expiry is current and that the EIP-712
domain is exactly USDC v2.

Wrap authorization construction and `account.signTypedData(...)` in one `try/catch`.
If anything fails before a signature is returned, call:

```js
    paymentPolicy.releaseUnsigned(idempotencyKey, { reason: `pre-sign failure: ${error.message}` });
    throw error;
```

Do not release after `signTypedData` resolves: from that point settlement may exist and
only `unresolved`, trusted rejection proof, or settlement can release/move the reserve.

After the signature succeeds and before the retry fetch, add:

```js
  paymentPolicy.beginRetry(idempotencyKey, {
    amountAtomic: authorization.value,
    offerFingerprint: authorizationRecord.offerFingerprint,
  });
```

Wrap the retry fetch in `try/catch`. On a transport exception, call
`paymentPolicy.markUnresolved(idempotencyKey, { reason: error.message })`, then rethrow.

- [ ] **Step 5: Forbid a second challenge and settle only from a receipt**

Add this validator above `payingFetch`:

```js
function validatePaymentResponse(header, { network, payer, settlementReference }) {
  let receipt;
  try {
    receipt = unb64(header);
  } catch {
    throw new PaymentPolicyError('SETTLEMENT_RECEIPT', 'X-PAYMENT-RESPONSE is not valid base64 JSON');
  }
  if (receipt?.success !== true
    || receipt.network !== network
    || receipt.payer?.toLowerCase() !== payer.toLowerCase()
    || receipt.settlementReference !== settlementReference
    || !/^0x[0-9a-fA-F]{64}$/.test(receipt.transaction ?? '')) {
    throw new PaymentPolicyError('SETTLEMENT_RECEIPT', 'X-PAYMENT-RESPONSE does not match the signed authorization');
  }
  return receipt;
}
```

Immediately after the retry response, add:

```js
  if (res.status === 402) {
    const secondBody = await res.clone().json().catch(() => ({}));
    try {
      paymentPolicy.assertRetryOffer(idempotencyKey, secondBody.accepts?.[0] ?? {});
      throw new PaymentPolicyError('SECOND_PAYMENT_REQUIRED', 'seller requested a second payment after the one permitted retry');
    } catch (error) {
      paymentPolicy.markUnresolved(idempotencyKey, { reason: error.message });
      throw error;
    }
  }
  const paymentResponse = res.headers.get('X-PAYMENT-RESPONSE');
  let settlement = null;
  try {
    if (!paymentResponse) throw new PaymentPolicyError('SETTLEMENT_RECEIPT', 'retry returned without X-PAYMENT-RESPONSE');
    settlement = validatePaymentResponse(paymentResponse, {
      network: req.network,
      payer: account.address,
      settlementReference: authorization.nonce,
    });
    paymentPolicy.markSettled(idempotencyKey, { txHash: settlement.transaction });
  } catch (error) {
    paymentPolicy.markUnresolved(idempotencyKey, { reason: error.message });
  }
```

Add this import at the top of `proxy.mjs`:

```js
import { PaymentPolicyError } from './payment-policy.mjs';
```

Use the already parsed `settlement` in the return block; do not decode the header a
second time.

- [ ] **Step 6: Run orchestration and pure-policy tests**

Run: `node --test spikes/pi-wielder/tests/payment-policy.test.mjs spikes/pi-wielder/tests/paying-fetch.test.mjs`

Expected: PASS, 27 tests and 0 failures.

- [ ] **Step 7: Commit policy-gated signing**

```bash
git add spikes/pi-wielder/src/proxy.mjs spikes/pi-wielder/tests/paying-fetch.test.mjs
git commit -m "feat: gate x402 signatures with local policy"
```

### Task 3: Configure trusted testnet sellers and assert total session spend

**Files:**
- Modify: `spikes/pi-wielder/src/proxy.mjs:84-151`
- Modify: `spikes/pi-wielder/e2e.mjs:38-154`
- Modify: `spikes/pi-wielder/.env.example`

- [ ] **Step 1: Add a default testnet policy factory**

Add these imports in `spikes/pi-wielder/src/proxy.mjs`:

```js
import { parseUsdc } from '../../../prototype/atomic-money.mjs';
import { createPaymentPolicy } from './payment-policy.mjs';
import { NETWORK, USDC_ADDRESS } from './x402-seller.mjs';
```

Add this exported factory above `createProxy`:

```js
export function createDefaultPaymentPolicy({ gatewayUrl, collarUrl, env = process.env }) {
  const payTo = env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dEaD';
  return createPaymentPolicy({
    network: NETWORK,
    asset: USDC_ADDRESS,
    sessionBudgetAtomic: parseUsdc(env.WIELDER_SESSION_BUDGET_USDC || '1.00').toString(),
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    sellers: [
      {
        origin: new URL(gatewayUrl).origin,
        pathPrefix: '/v1/',
        payTo,
        maxPerCallAtomic: parseUsdc(env.WIELDER_MODEL_MAX_USDC || '0.10').toString(),
      },
      {
        origin: new URL(collarUrl).origin,
        pathPrefix: '/invoke/',
        payTo,
        maxPerCallAtomic: parseUsdc(env.WIELDER_SKILL_MAX_USDC || '0.50').toString(),
      },
    ],
  });
}
```

- [ ] **Step 2: Refactor `createProxy` to inject one policy**

Replace the `createProxy` signature and initial declarations with:

```js
export function createProxy(options = {}) {
  const account = options.account ?? loadAccount();
  const gatewayUrl = options.gatewayUrl ?? process.env.GATEWAY_URL ?? 'http://127.0.0.1:8403';
  const collarUrl = options.collarUrl ?? process.env.COLLAR_URL ?? 'http://127.0.0.1:8404';
  const ledgerFile = options.ledgerFile ?? process.env.LEDGER_FILE ?? null;
  const trustedCollarPublicKeyPem = options.trustedCollarPublicKeyPem ?? null;
  const trustedCollarKeyId = options.trustedCollarKeyId ?? null;
  const paymentPolicy = options.paymentPolicy ?? createDefaultPaymentPolicy({ gatewayUrl, collarUrl });
```

Pass `paymentPolicy` into every `payingFetch` call:

```js
    }, { paymentPolicy });
```

Return it with the existing app dependencies:

```js
  return { app, ledger, account, paymentPolicy };
```

Update `startProxy` to destructure and return `paymentPolicy` alongside `ledger` and
`account`.

- [ ] **Step 3: Assert the e2e session budget and authorization count**

After fetching the three Wielder receipt entries in `spikes/pi-wielder/e2e.mjs`, add:

```js
  const policySnapshot = proxy.paymentPolicy.snapshot();
  eq(policySnapshot.spentAtomic, usdcToAtomic('0.378'), 'policy records exact session spend');
  eq(policySnapshot.reservedAtomic, '0', 'no successful authorization remains reserved');
  eq(policySnapshot.authorizations.length, 3, 'one authorization exists per paid call');
  ok(policySnapshot.authorizations.every((authorization) => authorization.retryCount === 1), 'every authorization retried exactly once');
  ok(policySnapshot.authorizations.every((authorization) => authorization.state === 'settled'), 'every e2e authorization settled');
```

- [ ] **Step 4: Document explicit testnet policy variables**

Insert only these `WIELDER_*` controls after the existing `PAY_TO_ADDRESS=` line in
`spikes/pi-wielder/.env.example`; do not add a second payee variable or a tracked address:

```dotenv
# Wielder-side payment policy. Base Sepolia only; never point this spike at mainnet.
WIELDER_SESSION_BUDGET_USDC=1.00
WIELDER_MODEL_MAX_USDC=0.10
WIELDER_SKILL_MAX_USDC=0.50
```

Do not add `PRIVATE_KEY` values or copy the ignored local `.env`.

- [ ] **Step 5: Run the complete offline proof**

Run: `npm test --prefix spikes/pi-wielder && npm run e2e --prefix spikes/pi-wielder`

Expected: all focused tests PASS; e2e reports exact spend `378000` atomic USDC,
three settled authorizations, one retry each, and no live network or funded wallet.

- [ ] **Step 6: Commit default testnet policy wiring**

```bash
git add spikes/pi-wielder/src/proxy.mjs spikes/pi-wielder/e2e.mjs spikes/pi-wielder/.env.example
git commit -m "feat: configure testnet Wielder spending limits"
```

### Task 4: Verify every required rejection independently

**Files:**
- Modify: `spikes/pi-wielder/README.md`

- [ ] **Step 1: Document the payment-policy boundary**

Add this section to `spikes/pi-wielder/README.md`:

```markdown
## Wielder payment policy

The Wielder does not accept the first x402 offer blindly. Before signing, it requires
the configured Base Sepolia network and USDC contract, an exact trusted seller route
and payee, an exact resource match, a fresh bounded-time quote, a per-call cap, and
remaining session budget. Budget is reserved before signing. One authorization permits
one retry; a changed second offer aborts without another signature and leaves the
already-signed authorization `unresolved` with budget reserved for reconciliation.

An unresolved payment keeps its budget reservation until trusted reconciliation. This
is intentionally conservative: an unknown settlement is never treated as free and
never silently retried.

This spike's Wielder policy is an in-memory, one-process session control. Restarting
the proxy loses its policy snapshot, so it is not production spend enforcement. A
durable deployment must persist/replay authorizations and reconcile unresolved state
before it can advertise cross-restart budget guarantees.
```

- [ ] **Step 2: Run the named policy suite**

Run: `node --test --test-reporter=spec spikes/pi-wielder/tests/payment-policy.test.mjs`

Expected: named PASS cases for scheme, network, asset, payee, resource, seller,
zero amount, per-call limit, freshness, timeout, concurrent session budget, immutable
amount, one retry, changed offer, settled/rejected accounting, and unresolved accounting.

- [ ] **Step 3: Prove forbidden offers cause zero signatures**

Run: `node --test --test-name-pattern="forbidden first offer|different request bytes|changed second offer" spikes/pi-wielder/tests/paying-fetch.test.mjs`

Expected: PASS; assertions report zero signatures for the forbidden first offer and
one total signature/two total HTTP requests for the changed second offer.

- [ ] **Step 4: Confirm testnet-only constants and no key leakage**

Run: `rg -n "base-sepolia|84532|WIELDER_.*_USDC" spikes/pi-wielder/src spikes/pi-wielder/.env.example`

Expected: policy and x402 code refer to Base Sepolia/test limits; no mainnet network is configured.

Run: `git diff --check && ! git ls-files | rg '(^|/)\.env$'`

Expected: `git diff --check` exits 0 and no tracked `.env` path is printed.

- [ ] **Step 5: Commit policy documentation**

```bash
git add spikes/pi-wielder/README.md
git commit -m "docs: explain Wielder payment policy"
```

## Definition of done

- No x402 signature occurs before all network, asset, seller, payee, resource, amount, freshness, timeout, and budget checks pass.
- Session budget includes both settled and unresolved/reserved authorizations, preventing concurrent overspend.
- The EIP-3009 amount equals the accepted offer exactly.
- One authorization produces at most one paid retry; a second 402 never produces a second signature.
- Changed retry offers abort, the accepted quote fingerprint remains immutable, and a
  post-sign mismatch stays `unresolved` with its budget reservation intact.
- Settled HTTP failures count as spend; missing settlement evidence remains unresolved rather than zero-cost.
- The evidence proves one-process session enforcement only. No cross-restart or production spending-control claim is made until policy state is durably replayed and reconciled.
- All tests are mock/offline and all defaults are Base Sepolia. No mainnet transaction or real funding is permitted.

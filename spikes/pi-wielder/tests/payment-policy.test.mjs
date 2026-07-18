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

const PAYEE = '0x000000000000000000000000000000000000dead';
const PAYER = '0x1000000000000000000000000000000000000000';
const URL = 'https://trusted.example/invoke/skill-a';
const BODY = '{"input":"exact bytes"}';
const NOW = Date.UTC(2026, 6, 17, 12, 0, 10);
const TX_HASH = `0x${'2'.repeat(64)}`;
const NONCE = `0x${'3'.repeat(64)}`;
const SIGNATURE = `0x${'4'.repeat(130)}`;

function offer(overrides = {}) {
  const requestHash = canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: BODY });
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
      requestHash,
      quoteId: `sha256:${'b'.repeat(64)}`,
      issuedAt: new Date(NOW - 1_000).toISOString(),
      expiresAt: new Date(NOW + 59_000).toISOString(),
    },
  };
  return { ...base, ...overrides };
}

function challenge(candidate = offer()) {
  return {
    x402Version: 1,
    error: 'X-PAYMENT header is required',
    accepts: [candidate],
  };
}

function policy(overrides = {}) {
  return createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => NOW,
    sellers: [{
      origin: 'https://trusted.example',
      pathPrefix: '/invoke/',
      payTo: PAYEE,
      maxPerCallAtomic: '300000',
    }],
    ...overrides,
  });
}

function reserve(subject, overrides = {}) {
  return subject.reserveAuthorization({
    authorizationId: 'auth-1',
    requestUrl: URL,
    method: 'POST',
    bodyBytes: BODY,
    challenge: challenge(),
    receivedAt: subject.captureReceivedAt(),
    ...overrides,
  });
}

function authorization(record, overrides = {}) {
  return {
    from: PAYER,
    to: PAYEE,
    value: record.amountAtomic,
    validAfter: record.validAfter,
    validBefore: record.validBefore,
    nonce: NONCE,
    ...overrides,
  };
}

function encodePayment(record, auth, overrides = {}) {
  return Buffer.from(JSON.stringify({
    x402Version: 1,
    scheme: 'exact',
    network: BASE_SEPOLIA_NETWORK,
    payload: { signature: SIGNATURE, authorization: auth },
    ...overrides,
  })).toString('base64');
}

function sign(subject, record = reserve(subject)) {
  assert.equal(subject.claimSignature(record.authorizationId, {
    offerFingerprint: record.offerFingerprint,
  }).claimed, true);
  const auth = authorization(record);
  const xPayment = encodePayment(record, auth);
  subject.persistSignedAuthorization(record.authorizationId, {
    authorization: auth,
    signature: SIGNATURE,
    xPayment,
  });
  return { record, auth, xPayment };
}

function settlementEvidence(subject, id = 'auth-1', overrides = {}) {
  const recovered = subject.recoverSignedAuthorization({
    authorizationId: id,
    requestUrl: URL,
    method: 'POST',
    bodyBytes: BODY,
  });
  return {
    success: true,
    authorizationId: id,
    idempotencyKey: id,
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    payTo: PAYEE,
    payer: PAYER,
    value: recovered.authorization.value,
    nonce: NONCE,
    settlementReference: NONCE,
    requestHash: recovered.requestHash,
    quoteId: recovered.quoteId,
    transaction: TX_HASH,
    ...overrides,
  };
}

test('policy module fixes Base Sepolia and canonical Base Sepolia USDC', () => {
  assert.equal(BASE_SEPOLIA_NETWORK, 'base-sepolia');
  assert.equal(BASE_SEPOLIA_CHAIN_ID, 84532);
  assert.equal(BASE_SEPOLIA_USDC, '0x036cbd53842c5426634e7929541ec2318f3dcf7e');
  assert.throws(() => policy({ network: 'base' }), (error) => error.code === 'NETWORK_CONFIG');
  assert.throws(() => policy({ chainId: 1 }), (error) => error.code === 'CHAIN_CONFIG');
  assert.throws(() => policy({ asset: `0x${'1'.repeat(40)}` }), (error) => error.code === 'ASSET_CONFIG');
});

test('canonical request hash binds uppercase method, exact URL, and exact body bytes', () => {
  const hash = canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: BODY });
  assert.match(hash, /^sha256:[0-9a-f]{64}$/);
  assert.notEqual(hash, canonicalRequestHash({ method: 'POST', requestUrl: URL, bodyBytes: `${BODY}\n` }));
  assert.notEqual(hash, canonicalRequestHash({ method: 'PUT', requestUrl: URL, bodyBytes: BODY }));
  assert.throws(() => canonicalRequestHash({ method: 'post', requestUrl: URL, bodyBytes: BODY }),
    (error) => error.code === 'REQUEST_METHOD');
});

test('only a capability returned by the trusted policy clock can mark local 402 receipt time', () => {
  const subject = policy();
  assert.throws(() => reserve(subject, { receivedAt: NOW }), (error) => error.code === 'RECEIVED_AT');
  assert.throws(() => reserve(subject, { receivedAt: { receivedAtMs: NOW } }),
    (error) => error.code === 'RECEIVED_AT');
  assert.equal(reserve(subject).receivedAtMs, NOW);
});

test('each trusted local receipt-time capability is single-use even for the same offer', () => {
  const subject = policy();
  const receivedAt = subject.captureReceivedAt();
  reserve(subject, { authorizationId: 'auth-token-1', receivedAt });
  assert.throws(() => reserve(subject, { authorizationId: 'auth-token-2', receivedAt }),
    (error) => error.code === 'RECEIVED_AT');
});

const rejectionCases = [
  ['wrong scheme', offer({ scheme: 'upto' }), 'SCHEME'],
  ['wrong network', offer({ network: 'Base-Sepolia' }), 'NETWORK'],
  ['numeric amount', offer({ maxAmountRequired: 250000 }), 'AMOUNT_FORMAT'],
  ['noncanonical amount', offer({ maxAmountRequired: '0250000' }), 'AMOUNT_FORMAT'],
  ['zero amount', offer({ maxAmountRequired: '0' }), 'AMOUNT_ZERO'],
  ['over per-call amount', offer({ maxAmountRequired: '300001' }), 'PER_CALL'],
  ['wrong asset', offer({ asset: `0x${'1'.repeat(40)}` }), 'ASSET'],
  ['case-ambiguous asset', offer({ asset: BASE_SEPOLIA_USDC.toUpperCase().replace('0X', '0x') }), 'ASSET'],
  ['wrong payee', offer({ payTo: `0x${'2'.repeat(40)}` }), 'PAYEE'],
  ['wrong resource', offer({ resource: 'https://trusted.example/invoke/skill-b' }), 'RESOURCE'],
  ['excess timeout', offer({ maxTimeoutSeconds: 61 }), 'TIMEOUT'],
  ['numeric timeout string', offer({ maxTimeoutSeconds: '60' }), 'TIMEOUT'],
  ['wrong EIP-712 name', offer({ extra: { ...offer().extra, name: 'FakeUSDC' } }), 'EIP712'],
  ['wrong EIP-712 version', offer({ extra: { ...offer().extra, version: '1' } }), 'EIP712'],
  ['wrong request hash', offer({ extra: { ...offer().extra, requestHash: `sha256:${'f'.repeat(64)}` } }), 'REQUEST_HASH'],
  ['malformed quote ID', offer({ extra: { ...offer().extra, quoteId: 'q-1' } }), 'QUOTE_ID'],
  ['expired quote', offer({ extra: { ...offer().extra, expiresAt: new Date(NOW).toISOString() } }), 'QUOTE_EXPIRY'],
  ['future-issued quote', offer({ extra: { ...offer().extra, issuedAt: new Date(NOW + 1).toISOString() } }), 'QUOTE_EXPIRY'],
];

for (const [name, candidate, code] of rejectionCases) {
  test(`rejects ${name} before reservation`, () => {
    const subject = policy();
    assert.throws(() => reserve(subject, { challenge: challenge(candidate) }),
      (error) => error instanceof PaymentPolicyError && error.code.includes(code));
    assert.equal(subject.snapshot().reservedAtomic, '0');
  });
}

test('challenge, offer, nested extra, and seller rules are strict exact plain objects', () => {
  assert.throws(() => reserve(policy(), { challenge: { ...challenge(), injected: true } }),
    (error) => error.code === 'CHALLENGE_SCHEMA');
  assert.throws(() => reserve(policy(), { challenge: challenge(offer({ injected: true })) }),
    (error) => error.code === 'OFFER_SCHEMA');
  assert.throws(() => reserve(policy(), { challenge: challenge(offer({
    extra: { ...offer().extra, injected: true },
  })) }), (error) => error.code === 'OFFER_EXTRA_SCHEMA');
  assert.throws(() => createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '500000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    now: () => NOW,
    sellers: [{
      origin: 'https://trusted.example', pathPrefix: '/invoke/', payTo: PAYEE,
      maxPerCallAtomic: '300000', injected: true,
    }],
  }), (error) => error.code === 'SELLER_SCHEMA');
});

test('seller URL and route matching reject credentials, query, fragment, normalization, and prefix confusion', () => {
  for (const origin of [
    'ftp://trusted.example',
    'https://user:pass@trusted.example',
    'https://trusted.example/',
    'https://trusted.example?x=1',
    'https://trusted.example#x',
  ]) {
    assert.throws(() => policy({ sellers: [{
      origin, pathPrefix: '/invoke/', payTo: PAYEE, maxPerCallAtomic: '300000',
    }] }), (error) => ['SELLER_ORIGIN', 'SELLER_SCHEMA'].includes(error.code));
  }
  for (const requestUrl of [
    'https://trusted.example/invoke-evil/skill-a',
    'https://trusted.example/invokeevil/skill-a',
    'https://trusted.example/invoke/skill-a?redirect=x',
    'https://trusted.example/invoke/skill-a#fragment',
    'https://trusted.example/invoke/%2e%2e/admin',
    'https://TRUSTED.example/invoke/skill-a',
  ]) {
    const subject = policy();
    assert.throws(() => reserve(subject, {
      requestUrl,
      challenge: challenge(offer({ resource: requestUrl })),
    }), (error) => ['SELLER_UNTRUSTED', 'RESOURCE_URL'].includes(error.code));
  }
});

test('concurrent reservations count reserved and settled spend against one session budget', () => {
  const subject = policy({ sessionBudgetAtomic: '400000' });
  reserve(subject, { authorizationId: 'auth-1' });
  assert.throws(() => reserve(subject, { authorizationId: 'auth-2' }),
    (error) => error.code === 'SESSION_BUDGET');
  assert.deepEqual(subject.snapshot(), {
    sessionBudgetAtomic: '400000',
    reservedAtomic: '250000',
    spentAtomic: '0',
    remainingAtomic: '150000',
    authorizations: [{
      authorizationId: 'auth-1', amountAtomic: '250000', state: 'reserved',
      retryCount: 0, txHash: null, reasonCode: null,
    }],
  });
});

test('authorization, signature, and encoded payment are exact, immutable, and copied before persistence', () => {
  const subject = policy();
  const record = reserve(subject);
  subject.claimSignature('auth-1', { offerFingerprint: record.offerFingerprint });
  const auth = authorization(record);
  const xPayment = encodePayment(record, auth);
  const persisted = subject.persistSignedAuthorization('auth-1', {
    authorization: auth, signature: SIGNATURE, xPayment,
  });
  auth.value = '1';
  assert.equal(persisted.authorization.value, '250000');
  assert.equal(Object.isFrozen(persisted), true);
  assert.equal(Object.isFrozen(persisted.authorization), true);
  assert.throws(() => subject.persistSignedAuthorization('auth-1', {
    authorization: { ...authorization(record), injected: true }, signature: SIGNATURE, xPayment,
  }), (error) => ['SIGNED_STATE', 'AUTHORIZATION_SCHEMA'].includes(error.code));
});

test('unsigned signer rejection releases exactly once but a potentially produced signature holds budget', () => {
  const unsigned = policy();
  const first = reserve(unsigned);
  unsigned.claimSignature('auth-1', { offerFingerprint: first.offerFingerprint });
  unsigned.releaseUnsigned('auth-1', { reasonCode: 'SIGNER_REJECTED' });
  assert.equal(unsigned.snapshot().reservedAtomic, '0');
  assert.throws(() => unsigned.releaseUnsigned('auth-1', { reasonCode: 'SIGNER_REJECTED' }),
    (error) => error.code === 'UNSIGNED_RELEASE_STATE');

  const uncertain = policy();
  const second = reserve(uncertain);
  uncertain.claimSignature('auth-1', { offerFingerprint: second.offerFingerprint });
  uncertain.markPotentiallySigned('auth-1', { reasonCode: 'SIGNATURE_PERSISTENCE_UNCERTAIN' });
  assert.equal(uncertain.snapshot().reservedAtomic, '250000');
  assert.equal(uncertain.snapshot().authorizations[0].state, 'unresolved');
  assert.throws(() => uncertain.releaseUnsigned('auth-1', { reasonCode: 'LATE_RELEASE' }),
    (error) => error.code === 'UNSIGNED_RELEASE_STATE');
});

test('exact persisted signed authorization is recoverable without a replacement signature', () => {
  const subject = policy();
  const { xPayment } = sign(subject);
  const recovered = subject.recoverSignedAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: BODY,
  });
  assert.equal(recovered.xPayment, xPayment);
  assert.equal(recovered.signature, SIGNATURE);
  assert.throws(() => subject.recoverSignedAuthorization({
    authorizationId: 'auth-1', requestUrl: URL, method: 'POST', bodyBytes: `${BODY} `,
  }), (error) => error.code === 'RECOVERY_REQUEST_MISMATCH');
});

test('one signed authorization permits exactly one paid retry and immutable amount', () => {
  const subject = policy();
  sign(subject);
  subject.beginRetry('auth-1');
  assert.throws(() => subject.beginRetry('auth-1'), (error) => error.code === 'RETRY_LIMIT');
  assert.throws(() => subject.assertRetryChallenge('auth-1', challenge(offer({ maxAmountRequired: '250001' }))),
    (error) => error.code === 'QUOTE_CHANGED');
});

test('malformed or mismatched settlement evidence remains reserved', () => {
  for (const mutation of [
    { value: '250001' },
    { payer: `0x${'9'.repeat(40)}` },
    { requestHash: `sha256:${'9'.repeat(64)}` },
    { quoteId: `sha256:${'8'.repeat(64)}` },
    { network: 'base' },
    { chainId: 1 },
    { asset: `0x${'7'.repeat(40)}` },
    { payTo: `0x${'6'.repeat(40)}` },
    { settlementReference: `0x${'5'.repeat(64)}` },
    { transaction: 'not-a-hash' },
    { injected: true },
  ]) {
    const subject = policy();
    sign(subject);
    subject.beginRetry('auth-1');
    assert.throws(() => subject.acceptSettlement('auth-1', settlementEvidence(subject, 'auth-1', mutation)),
      (error) => ['SETTLEMENT_MISMATCH', 'SETTLEMENT_SCHEMA'].includes(error.code));
    assert.equal(subject.snapshot().reservedAtomic, '250000');
  }
});

test('settled spend moves reservation exactly once and settled HTTP status is not a policy concern', () => {
  const subject = policy();
  sign(subject);
  subject.beginRetry('auth-1');
  subject.acceptSettlement('auth-1', settlementEvidence(subject));
  assert.equal(subject.snapshot().reservedAtomic, '0');
  assert.equal(subject.snapshot().spentAtomic, '250000');
  assert.equal(subject.snapshot().remainingAtomic, '250000');
});

test('unresolved authorizations retain budget until trusted field-bound settlement reconciliation', () => {
  const trusted = [];
  const subject = policy({
    verifySettlementProof: ({ authorization, proof }) => {
      trusted.push({ authorization, proof });
      return proof.trustToken === 'trusted-settlement';
    },
  });
  sign(subject);
  subject.beginRetry('auth-1');
  subject.markUnresolved('auth-1', { reasonCode: 'RETRY_RESPONSE_LOST' });
  const evidence = settlementEvidence(subject);
  assert.throws(() => subject.acceptSettlement('auth-1', evidence),
    (error) => error.code === 'SETTLEMENT_STATE');
  const proof = { ...evidence, outcome: 'settled', trustToken: 'trusted-settlement' };
  subject.reconcileSettlement('auth-1', proof);
  assert.equal(trusted.length, 1);
  assert.equal(subject.snapshot().spentAtomic, '250000');
  assert.equal(subject.snapshot().reservedAtomic, '0');
});

test('trusted proof capability cannot authorize mismatched request data', () => {
  let verifierCalls = 0;
  const subject = policy({
    verifyRejectionProof: () => { verifierCalls += 1; return true; },
  });
  sign(subject);
  subject.beginRetry('auth-1');
  subject.markUnresolved('auth-1', { reasonCode: 'SETTLEMENT_EVIDENCE_INVALID' });
  const evidence = settlementEvidence(subject);
  const baseProof = {
    ...evidence,
    success: false,
    transaction: null,
    outcome: 'rejected',
    reasonCode: 'CHAIN_REJECTED',
    trustToken: 'trusted-rejection',
  };
  assert.throws(() => subject.reconcileRejection('auth-1', {
    ...baseProof, success: true,
  }), (error) => error.code === 'RECONCILIATION_SCHEMA');
  assert.throws(() => subject.reconcileRejection('auth-1', { ...baseProof, value: '1' }),
    (error) => error.code === 'RECONCILIATION_MISMATCH');
  assert.equal(verifierCalls, 0);
  assert.equal(subject.snapshot().reservedAtomic, '250000');
  subject.reconcileRejection('auth-1', baseProof);
  assert.equal(verifierCalls, 1);
  assert.equal(subject.snapshot().reservedAtomic, '0');
  assert.equal(subject.snapshot().spentAtomic, '0');
});

test('one EIP-3009 nonce cannot be persisted under two authorizations', () => {
  const subject = policy();
  sign(subject, reserve(subject, { authorizationId: 'auth-nonce-1' }));
  const second = reserve(subject, { authorizationId: 'auth-nonce-2' });
  subject.claimSignature('auth-nonce-2', { offerFingerprint: second.offerFingerprint });
  const duplicate = authorization(second);
  assert.throws(() => subject.persistSignedAuthorization('auth-nonce-2', {
    authorization: duplicate,
    signature: SIGNATURE,
    xPayment: encodePayment(second, duplicate),
  }), (error) => error.code === 'NONCE_REUSE');
  assert.equal(subject.snapshot().reservedAtomic, '500000');
  assert.deepEqual(subject.snapshot().authorizations.map(({ state }) => state), ['signed', 'signing']);
});

test('one settlement transaction cannot settle two different authorizations', () => {
  const subject = policy();
  sign(subject, reserve(subject, { authorizationId: 'auth-tx-1' }));
  subject.beginRetry('auth-tx-1');
  subject.acceptSettlement('auth-tx-1', settlementEvidence(subject, 'auth-tx-1'));

  const second = reserve(subject, { authorizationId: 'auth-tx-2' });
  subject.claimSignature('auth-tx-2', { offerFingerprint: second.offerFingerprint });
  const secondAuthorization = authorization(second, { nonce: `0x${'6'.repeat(64)}` });
  subject.persistSignedAuthorization('auth-tx-2', {
    authorization: secondAuthorization,
    signature: SIGNATURE,
    xPayment: encodePayment(second, secondAuthorization),
  });
  subject.beginRetry('auth-tx-2');
  assert.throws(() => subject.acceptSettlement('auth-tx-2', {
    ...settlementEvidence(subject, 'auth-tx-2'),
    nonce: secondAuthorization.nonce,
    settlementReference: secondAuthorization.nonce,
    transaction: TX_HASH,
  }), (error) => error.code === 'TRANSACTION_REUSE');
  assert.equal(subject.snapshot().spentAtomic, '250000');
  assert.equal(subject.snapshot().reservedAtomic, '250000');
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { createSellerEvidenceResolver } from '../src/adapters/seller-evidence-resolver.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { validatePolicyDocument } from '../src/kernel/policy-engine.mjs';

const NOW = '2026-07-31T12:10:00.000Z';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const SELLER_ORIGIN = 'https://seller.example';
const RESOURCE_PATH = '/paid/infer';
const EVIDENCE_PATH = '/.well-known/wallet-kernel/evidence';
const TRANSACTION_ID = `0x${'ab'.repeat(32)}`;
const REFUND_TRANSACTION_ID = `0x${'34'.repeat(32)}`;
const INTENT_HASH = `sha256:${'11'.repeat(32)}`;
const CASE_HASH = `sha256:${'22'.repeat(32)}`;
const RESPONSE_HASH = `sha256:${'44'.repeat(32)}`;
const PAYER = '0x1000000000000000000000000000000000000000';
const PAYEE = '0x2000000000000000000000000000000000000000';
const REFUND_SOURCE = '0x3000000000000000000000000000000000000000';

const executionAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-seller-execution-test-only')),
);
const refundAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-seller-refund-test-only')),
);

const POLICY = validatePolicyDocument({
  schemaVersion: 1,
  network: NETWORK,
  asset: ASSET,
  wallet: PAYER,
  methods: ['POST'],
  sellers: [{
    origin: SELLER_ORIGIN,
    pathPrefixes: ['/paid/'],
    payTo: PAYEE,
    evidencePath: EVIDENCE_PATH,
    executionSigner: executionAccount.address.toLowerCase(),
    refundSigner: refundAccount.address.toLowerCase(),
    refundSource: REFUND_SOURCE,
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  }],
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60000,
  approvalTtlMs: 300000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
});
const POLICY_VERSION = Object.freeze({
  id: 'policy-1',
  hash: sha256(canonicalJson(POLICY)),
  policy: POLICY,
});
const SELLER = POLICY.sellers[0];

function executionBinding(overrides = {}) {
  return {
    schemaVersion: 1,
    domain: 'wallet-kernel.execution-observation.v1',
    intentId: 'intent-1',
    intentHash: INTENT_HASH,
    policyVersion: POLICY_VERSION,
    seller: SELLER,
    resourcePath: RESOURCE_PATH,
    network: NETWORK,
    sellerOrigin: SELLER_ORIGIN,
    transactionId: TRANSACTION_ID,
    executionSigner: executionAccount.address.toLowerCase(),
    persistedHttpStatus: null,
    persistedResponseHash: null,
    resolutionReasonCode: 'PAID_RESPONSE_BODY_LOST',
    caseHash: CASE_HASH,
    ...overrides,
  };
}

function refundBinding(overrides = {}) {
  const binding = {
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation.v1',
    intentId: 'intent-1',
    intentHash: INTENT_HASH,
    policyVersion: POLICY_VERSION,
    seller: SELLER,
    resourcePath: RESOURCE_PATH,
    network: NETWORK,
    sellerOrigin: SELLER_ORIGIN,
    originalTransactionId: TRANSACTION_ID,
    refundTransactionId: REFUND_TRANSACTION_ID,
    asset: ASSET,
    originalPayer: PAYER,
    originalPayee: PAYEE,
    refundSource: REFUND_SOURCE,
    refundSigner: refundAccount.address.toLowerCase(),
    amountAtomic: '50000',
    localRefundBindingHash: null,
    refundId: 'refund-1',
    caseHash: CASE_HASH,
    ...overrides,
  };
  if (!Object.hasOwn(overrides, 'localRefundBindingHash')) {
    binding.localRefundBindingHash = sha256(canonicalJson({
      schemaVersion: 1,
      domain: 'wallet-kernel.refund-binding.v1',
      intentHash: binding.intentHash,
      originalTransactionId: binding.originalTransactionId,
      refundTransactionId: binding.refundTransactionId,
      network: binding.network,
      sellerOrigin: binding.sellerOrigin,
      asset: binding.asset,
      originalPayer: binding.originalPayer,
      originalPayee: binding.originalPayee,
      refundSource: binding.refundSource,
      refundSigner: binding.refundSigner,
      amountAtomic: binding.amountAtomic,
    }));
  }
  return binding;
}

function unsignedExecution(overrides = {}) {
  return {
    schemaVersion: 1,
    domain: 'wallet-kernel.execution.v1',
    network: NETWORK,
    sellerOrigin: SELLER_ORIGIN,
    intentHash: INTENT_HASH,
    transactionId: TRANSACTION_ID,
    outcome: 'succeeded',
    httpStatus: 200,
    responseHash: RESPONSE_HASH,
    issuedAt: '2026-07-31T12:09:00.000Z',
    expiresAt: '2026-07-31T12:15:00.000Z',
    signer: executionAccount.address.toLowerCase(),
    ...overrides,
  };
}

function unsignedRefund(overrides = {}) {
  return {
    schemaVersion: 1,
    domain: 'wallet-kernel.refund.v1',
    network: NETWORK,
    sellerOrigin: SELLER_ORIGIN,
    intentHash: INTENT_HASH,
    originalTransactionId: TRANSACTION_ID,
    refundTransactionId: REFUND_TRANSACTION_ID,
    asset: ASSET,
    originalPayer: PAYER,
    originalPayee: PAYEE,
    refundSource: REFUND_SOURCE,
    amountAtomic: '50000',
    issuedAt: '2026-07-31T12:09:00.000Z',
    expiresAt: '2026-07-31T12:15:00.000Z',
    signer: refundAccount.address.toLowerCase(),
    ...overrides,
  };
}

async function signedResponse(unsigned, account) {
  const signature = await account.signMessage({
    message: { raw: Buffer.from(canonicalJson(unsigned), 'utf8') },
  });
  return new Response(JSON.stringify({ ...unsigned, signature }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
}

function createResolver(fetchImpl, options = {}) {
  return createSellerEvidenceResolver({
    fetchImpl,
    mode: 'cdp-testnet',
    now: () => NOW,
    limits: {
      requestTimeoutMs: 5_000,
      maximumResponseBytes: 16_384,
    },
    ...options,
  });
}

function policyForOrigin(origin) {
  const document = structuredClone(POLICY);
  document.sellers[0].origin = origin;
  return validatePolicyDocument(document);
}

function versionFor(policy) {
  return Object.freeze({
    id: 'policy-1',
    hash: sha256(canonicalJson(policy)),
    policy,
  });
}

function bindingForPolicy(kind, policy, overrides = {}) {
  const common = {
    policyVersion: versionFor(policy),
    seller: policy.sellers[0],
    sellerOrigin: policy.sellers[0].origin,
  };
  return kind === 'execution'
    ? executionBinding({ ...common, ...overrides })
    : refundBinding({ ...common, ...overrides });
}

function assertUnknown(result, reasonCode) {
  assert.deepEqual(result, { kind: 'unknown', reasonCode });
  assert.ok(Object.isFrozen(result));
  assert.equal(Object.getPrototypeOf(result), Object.prototype);
}

async function responseWithSignature(unsigned, account, {
  signedBytes = canonicalJson(unsigned),
  mutateSignature = (value) => value,
  status = 200,
  contentType = 'application/json',
  extra = {},
} = {}) {
  const signature = mutateSignature(await account.signMessage({
    message: { raw: Buffer.from(signedBytes, 'utf8') },
  }));
  return new Response(JSON.stringify({ ...unsigned, signature, ...extra }), {
    status,
    headers: contentType === null ? {} : { 'content-type': contentType },
  });
}

async function observeStatic(kind, {
  binding = kind === 'execution' ? executionBinding() : refundBinding(),
  unsigned = kind === 'execution' ? unsignedExecution() : unsignedRefund(),
  account = kind === 'execution' ? executionAccount : refundAccount,
  responseOptions,
  resolverOptions,
} = {}) {
  let calls = 0;
  const response = await responseWithSignature(unsigned, account, responseOptions);
  const resolver = createResolver(async () => {
    calls += 1;
    return response;
  }, resolverOptions);
  const result = kind === 'execution'
    ? await resolver.observeExecution(binding)
    : await resolver.observeRefund(binding);
  return { result, calls };
}

test('execution evidence is requested from the persisted policy endpoint and verified', async () => {
  const calls = [];
  const resolver = createResolver(async (url, init) => {
    calls.push({ url, init });
    return await signedResponse(unsignedExecution(), executionAccount);
  });

  const result = await resolver.observeExecution(executionBinding());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${SELLER_ORIGIN}${EVIDENCE_PATH}`);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    schemaVersion: 1,
    kind: 'execution',
    sellerOrigin: SELLER_ORIGIN,
    intentHash: INTENT_HASH,
    transactionId: TRANSACTION_ID,
  });
  assert.equal(calls[0].init.method, 'POST');
  assert.equal(calls[0].init.redirect, 'manual');
  assert.deepEqual(calls[0].init.headers, {
    accept: 'application/json',
    'content-type': 'application/json',
  });
  assert.deepEqual(result, {
    kind: 'execution_attested',
    attestation: unsignedExecution(),
    attestationHash: sha256(canonicalJson(unsignedExecution())),
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.attestation));
  assert.equal(JSON.stringify(result).includes('signature'), false);
});

test('refund evidence is requested with only persisted transaction bindings and verified', async () => {
  const calls = [];
  const resolver = createResolver(async (url, init) => {
    calls.push({ url, init });
    return await signedResponse(unsignedRefund(), refundAccount);
  });

  const result = await resolver.observeRefund(refundBinding());

  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${SELLER_ORIGIN}${EVIDENCE_PATH}`);
  assert.deepEqual(JSON.parse(calls[0].init.body), {
    schemaVersion: 1,
    kind: 'refund',
    sellerOrigin: SELLER_ORIGIN,
    intentHash: INTENT_HASH,
    originalTransactionId: TRANSACTION_ID,
    refundTransactionId: REFUND_TRANSACTION_ID,
  });
  assert.deepEqual(result, {
    kind: 'refund_attested',
    attestation: unsignedRefund(),
    attestationHash: sha256(canonicalJson(unsignedRefund())),
  });
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.attestation));
  assert.equal(JSON.stringify(result).includes('signature'), false);
});

test('the resolver factory is closed, bounded, injected, and frozen', () => {
  const base = {
    fetchImpl: async () => { throw new Error('not called'); },
    mode: 'cdp-testnet',
    now: () => NOW,
    limits: { requestTimeoutMs: 5_000, maximumResponseBytes: 16_384 },
  };
  const resolver = createSellerEvidenceResolver(base);
  assert.ok(Object.isFrozen(resolver));
  assert.deepEqual(Object.keys(resolver), ['observeExecution', 'observeRefund']);

  for (const value of [
    { ...base, extra: true },
    { ...base, mode: 'production' },
    { ...base, limits: { ...base.limits, extra: true } },
    { ...base, limits: { ...base.limits, requestTimeoutMs: 0 } },
    { ...base, limits: { ...base.limits, requestTimeoutMs: 5_001 } },
    { ...base, limits: { ...base.limits, maximumResponseBytes: 0 } },
    { ...base, limits: { ...base.limits, maximumResponseBytes: 16_385 } },
    { ...base, fetchImpl: new Proxy(base.fetchImpl, {}) },
    { ...base, now: new Proxy(base.now, {}) },
    { ...base, limits: new Proxy(base.limits, {}) },
  ]) {
    assert.throws(
      () => createSellerEvidenceResolver(value),
      (error) => error?.code === 'SELLER_EVIDENCE_CONFIG'
        && !JSON.stringify(error).includes('not called'),
    );
  }
});

test('the request uses a no-credential fetch surface and no caller URL', async () => {
  const calls = [];
  const secretSentinels = [
    'BEARER_SECRET_SENTINEL',
    'COOKIE_SECRET_SENTINEL',
    'PAYMENT_SIGNATURE_SENTINEL',
    '/private/secret/path',
  ];
  const resolver = createResolver(async (url, init) => {
    calls.push({ url, init });
    return await signedResponse(unsignedExecution(), executionAccount);
  });
  const result = await resolver.observeExecution(executionBinding());

  assert.equal(result.kind, 'execution_attested');
  assert.equal(calls.length, 1);
  assert.deepEqual(Object.keys(calls[0].init).sort(), [
    'body', 'cache', 'credentials', 'headers', 'method', 'redirect',
    'referrerPolicy', 'signal',
  ]);
  assert.equal(calls[0].init.credentials, 'omit');
  assert.equal(calls[0].init.cache, 'no-store');
  assert.equal(calls[0].init.referrerPolicy, 'no-referrer');
  assert.ok(calls[0].init.signal instanceof AbortSignal);
  const serialized = JSON.stringify(calls[0]);
  for (const sentinel of secretSentinels) assert.equal(serialized.includes(sentinel), false);
  assert.deepEqual(Object.keys(JSON.parse(calls[0].init.body)).sort(), [
    'intentHash', 'kind', 'schemaVersion', 'sellerOrigin', 'transactionId',
  ]);

  let rejectedCalls = 0;
  const rejectedResolver = createResolver(async () => {
    rejectedCalls += 1;
    return await signedResponse(unsignedExecution(), executionAccount);
  });
  const resultWithCallerUrl = await rejectedResolver.observeExecution({
    ...executionBinding(),
    evidenceUrl: `https://attacker.example/${secretSentinels[0]}`,
  });
  assertUnknown(resultWithCallerUrl, 'SELLER_EVIDENCE_BINDING_INVALID');
  assert.equal(rejectedCalls, 0);
});

for (const origin of ['http://127.0.0.1:9080', 'http://[::1]:9080']) {
  test(`deterministic mode accepts only the canonical literal loopback origin ${origin}`, async () => {
    const policy = policyForOrigin(origin);
    const binding = bindingForPolicy('execution', policy);
    const unsigned = unsignedExecution({ sellerOrigin: origin });
    let endpoint;
    const resolver = createResolver(async (url) => {
      endpoint = url;
      return await responseWithSignature(unsigned, executionAccount);
    }, { mode: 'deterministic' });

    const result = await resolver.observeExecution(binding);

    assert.equal(result.kind, 'execution_attested');
    assert.equal(endpoint, `${origin}${EVIDENCE_PATH}`);
  });
}

test('live mode rejects loopback HTTP before fetch', async () => {
  const policy = policyForOrigin('http://127.0.0.1:9080');
  let calls = 0;
  const resolver = createResolver(async () => {
    calls += 1;
    return await signedResponse(unsignedExecution(), executionAccount);
  });

  const result = await resolver.observeExecution(bindingForPolicy('execution', policy));

  assertUnknown(result, 'SELLER_EVIDENCE_ENDPOINT_INVALID');
  assert.equal(calls, 0);
});

test('invalid or hostile persisted authority is rejected before fetch without invoking accessors', async () => {
  const cases = [];
  const noncanonicalPolicy = {
    ...POLICY,
    sellers: [{
      ...SELLER,
      executionSigner: executionAccount.address,
    }],
  };
  assert.notEqual(canonicalJson(noncanonicalPolicy), canonicalJson(POLICY));
  cases.push({
    ...executionBinding(),
    policyVersion: {
      ...POLICY_VERSION,
      policy: noncanonicalPolicy,
    },
  });
  cases.push({ ...executionBinding(), policyVersion: {
    ...POLICY_VERSION,
    hash: `sha256:${'99'.repeat(32)}`,
  } });
  cases.push({ ...executionBinding(), seller: { ...SELLER, evidencePath: '/attacker' } });
  cases.push(executionBinding({ resourcePath: '/untrusted/infer' }));
  cases.push(executionBinding({ sellerOrigin: 'https://attacker.example' }));
  cases.push(executionBinding({ executionSigner: refundAccount.address.toLowerCase() }));
  cases.push(executionBinding({ network: 'eip155:1' }));
  cases.push(executionBinding({ transactionId: `0x${'AB'.repeat(32)}` }));
  cases.push(executionBinding({ persistedHttpStatus: 99 }));
  cases.push(executionBinding({ persistedResponseHash: 'not-a-hash' }));
  cases.push(executionBinding({ resolutionReasonCode: 'secret reason' }));
  cases.push({ ...executionBinding(), unexpected: true });
  cases.push(new Proxy(executionBinding(), {}));

  let getterCalls = 0;
  const hostile = executionBinding();
  Object.defineProperty(hostile, 'intentHash', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return INTENT_HASH;
    },
  });
  cases.push(hostile);

  let fetchCalls = 0;
  const resolver = createResolver(async () => {
    fetchCalls += 1;
    return await signedResponse(unsignedExecution(), executionAccount);
  });
  for (const binding of cases) {
    assertUnknown(
      await resolver.observeExecution(binding),
      'SELLER_EVIDENCE_BINDING_INVALID',
    );
  }
  assert.equal(fetchCalls, 0);
  assert.equal(getterCalls, 0);
});

test('refund authority revalidates every redundant policy and local binding field', async () => {
  const mutations = [
    { policyVersion: { ...POLICY_VERSION, id: '' } },
    { seller: { ...SELLER, refundSource: PAYEE } },
    { resourcePath: '/untrusted/infer' },
    { network: 'eip155:1' },
    { sellerOrigin: 'https://attacker.example' },
    { asset: PAYEE },
    { originalPayer: PAYEE },
    { originalPayee: REFUND_SOURCE },
    { refundSource: PAYEE },
    { refundSigner: executionAccount.address.toLowerCase() },
    { amountAtomic: '0' },
    { localRefundBindingHash: `sha256:${'77'.repeat(32)}` },
    { refundTransactionId: `0x${'AB'.repeat(32)}` },
    { caseHash: 'bad' },
  ];
  let fetchCalls = 0;
  const resolver = createResolver(async () => {
    fetchCalls += 1;
    return await signedResponse(unsignedRefund(), refundAccount);
  });
  for (const mutation of mutations) {
    assertUnknown(
      await resolver.observeRefund(refundBinding(mutation)),
      'SELLER_EVIDENCE_BINDING_INVALID',
    );
  }
  assert.equal(fetchCalls, 0);
});

const executionAttestationMutations = [
  ['schemaVersion', { schemaVersion: 2 }, 'SELLER_EVIDENCE_ATTESTATION_INVALID'],
  ['domain', { domain: 'wallet-kernel.refund.v1' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['network', { network: 'eip155:1' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['sellerOrigin', { sellerOrigin: 'https://attacker.example' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['intentHash', { intentHash: `sha256:${'55'.repeat(32)}` }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['transactionId', { transactionId: `0x${'56'.repeat(32)}` }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['outcome', { outcome: 'unknown' }, 'SELLER_EVIDENCE_ATTESTATION_INVALID'],
  ['httpStatus', { httpStatus: 99 }, 'SELLER_EVIDENCE_ATTESTATION_INVALID'],
  ['responseHash', { responseHash: 'not-a-hash' }, 'SELLER_EVIDENCE_ATTESTATION_INVALID'],
  ['issuedAt', { issuedAt: '2026-07-31T12:11:00.000Z' }, 'SELLER_EVIDENCE_TIME_INVALID'],
  ['expiresAt', { expiresAt: '2026-07-31T12:09:59.999Z' }, 'SELLER_EVIDENCE_TIME_INVALID'],
  ['signer', { signer: refundAccount.address.toLowerCase() }, 'SELLER_EVIDENCE_SIGNATURE_INVALID'],
];

for (const [field, mutation, reasonCode] of executionAttestationMutations) {
  test(`execution attestation rejects a signed mutation of ${field}`, async () => {
    const { result, calls } = await observeStatic('execution', {
      unsigned: unsignedExecution(mutation),
    });
    assert.equal(calls, 1);
    assertUnknown(result, reasonCode);
  });
}

const refundAttestationMutations = [
  ['schemaVersion', { schemaVersion: 2 }, 'SELLER_EVIDENCE_ATTESTATION_INVALID'],
  ['domain', { domain: 'wallet-kernel.execution.v1' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['network', { network: 'eip155:1' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['sellerOrigin', { sellerOrigin: 'https://attacker.example' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['intentHash', { intentHash: `sha256:${'61'.repeat(32)}` }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['originalTransactionId', { originalTransactionId: `0x${'62'.repeat(32)}` }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['refundTransactionId', { refundTransactionId: `0x${'63'.repeat(32)}` }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['asset', { asset: PAYEE }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['originalPayer', { originalPayer: PAYEE }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['originalPayee', { originalPayee: REFUND_SOURCE }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['refundSource', { refundSource: PAYEE }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['amountAtomic', { amountAtomic: '49999' }, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH'],
  ['issuedAt', { issuedAt: '2026-07-31T12:11:00.000Z' }, 'SELLER_EVIDENCE_TIME_INVALID'],
  ['expiresAt', { expiresAt: '2026-07-31T12:09:59.999Z' }, 'SELLER_EVIDENCE_TIME_INVALID'],
  ['signer', { signer: executionAccount.address.toLowerCase() }, 'SELLER_EVIDENCE_SIGNATURE_INVALID'],
];

for (const [field, mutation, reasonCode] of refundAttestationMutations) {
  test(`refund attestation rejects a signed mutation of ${field}`, async () => {
    const { result, calls } = await observeStatic('refund', {
      unsigned: unsignedRefund(mutation),
    });
    assert.equal(calls, 1);
    assertUnknown(result, reasonCode);
  });
}

test('signature verification uses canonical raw bytes, not JSON transport bytes', async () => {
  const unsigned = unsignedExecution();
  const { result } = await observeStatic('execution', {
    unsigned,
    responseOptions: { signedBytes: JSON.stringify(unsigned) },
  });
  assertUnknown(result, 'SELLER_EVIDENCE_SIGNATURE_INVALID');
});

test('declared and recovered signers must independently equal the policy signer', async () => {
  const declaredWrong = await observeStatic('execution', {
    unsigned: unsignedExecution({ signer: refundAccount.address.toLowerCase() }),
    account: refundAccount,
  });
  assertUnknown(declaredWrong.result, 'SELLER_EVIDENCE_SIGNATURE_INVALID');

  const recoveredWrong = await observeStatic('execution', {
    unsigned: unsignedExecution(),
    account: refundAccount,
  });
  assertUnknown(recoveredWrong.result, 'SELLER_EVIDENCE_SIGNATURE_INVALID');
});

test('mutated signatures and cross-kind replay remain unknown', async () => {
  const mutatedSignature = await observeStatic('refund', {
    responseOptions: {
      mutateSignature: (signature) => `${signature.slice(0, -1)}${
        signature.endsWith('0') ? '1' : '0'
      }`,
    },
  });
  assertUnknown(mutatedSignature.result, 'SELLER_EVIDENCE_SIGNATURE_INVALID');

  const refundAsExecution = await observeStatic('execution', {
    unsigned: unsignedRefund(),
    account: refundAccount,
  });
  assertUnknown(refundAsExecution.result, 'SELLER_EVIDENCE_ATTESTATION_INVALID');

  const executionAsRefund = await observeStatic('refund', {
    unsigned: unsignedExecution(),
    account: executionAccount,
  });
  assertUnknown(executionAsRefund.result, 'SELLER_EVIDENCE_ATTESTATION_INVALID');
});

test('attestation schemas reject missing, unknown, array, and prototype-bearing shapes', async () => {
  const missing = unsignedExecution();
  delete missing.responseHash;
  assertUnknown(
    (await observeStatic('execution', { unsigned: missing })).result,
    'SELLER_EVIDENCE_ATTESTATION_INVALID',
  );

  assertUnknown(
    (await observeStatic('execution', {
      responseOptions: { extra: { providerSecret: 'RAW_PROVIDER_BODY_SENTINEL' } },
    })).result,
    'SELLER_EVIDENCE_ATTESTATION_INVALID',
  );

  let calls = 0;
  const resolver = createResolver(async () => {
    calls += 1;
    return new Response('[]', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  });
  assertUnknown(
    await resolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_ATTESTATION_INVALID',
  );
  assert.equal(calls, 1);

  const pollution = createResolver(async () => new Response(
    '{"__proto__":{"polluted":true}}',
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
  assertUnknown(
    await pollution.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_ATTESTATION_INVALID',
  );
  assert.equal(Object.prototype.polluted, undefined);
});

test('execution evidence honors persisted status and response-hash authority', async () => {
  const binding = executionBinding({
    persistedHttpStatus: 200,
    persistedResponseHash: RESPONSE_HASH,
  });
  const valid = await observeStatic('execution', { binding });
  assert.equal(valid.result.kind, 'execution_attested');

  const wrongStatus = await observeStatic('execution', {
    binding,
    unsigned: unsignedExecution({ httpStatus: 201 }),
  });
  assertUnknown(wrongStatus.result, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH');

  const wrongHash = await observeStatic('execution', {
    binding,
    unsigned: unsignedExecution({ responseHash: `sha256:${'45'.repeat(32)}` }),
  });
  assertUnknown(wrongHash.result, 'SELLER_EVIDENCE_ATTESTATION_MISMATCH');
});

test('execution outcome and HTTP status semantics are closed', async () => {
  const validFailure = await observeStatic('execution', {
    unsigned: unsignedExecution({ outcome: 'failed', httpStatus: 500, responseHash: null }),
  });
  assert.equal(validFailure.result.kind, 'execution_attested');

  const failedSuccessStatus = await observeStatic('execution', {
    unsigned: unsignedExecution({ outcome: 'failed', httpStatus: 200 }),
  });
  assertUnknown(failedSuccessStatus.result, 'SELLER_EVIDENCE_ATTESTATION_INVALID');

  const succeededFailureStatus = await observeStatic('execution', {
    unsigned: unsignedExecution({ outcome: 'succeeded', httpStatus: 500 }),
  });
  assertUnknown(succeededFailureStatus.result, 'SELLER_EVIDENCE_ATTESTATION_INVALID');
});

test('attestation lifetime is current, canonical, and at most fifteen minutes', async () => {
  const tooLong = await observeStatic('execution', {
    unsigned: unsignedExecution({
      issuedAt: '2026-07-31T12:00:00.000Z',
      expiresAt: '2026-07-31T12:15:00.001Z',
    }),
  });
  assertUnknown(tooLong.result, 'SELLER_EVIDENCE_TIME_INVALID');

  const noncanonical = await observeStatic('refund', {
    unsigned: unsignedRefund({ issuedAt: '2026-07-31T12:09:00Z' }),
  });
  assertUnknown(noncanonical.result, 'SELLER_EVIDENCE_TIME_INVALID');

  for (const kind of ['execution', 'refund']) {
    const atExactExpiry = await observeStatic(kind, {
      resolverOptions: { now: () => '2026-07-31T12:15:00.000Z' },
    });
    assertUnknown(
      atExactExpiry.result,
      'SELLER_EVIDENCE_TIME_INVALID',
    );
  }
});

test('provider exceptions are redacted, attempted once, and never returned as causes', async () => {
  const secret = 'RAW_PROVIDER_EXCEPTION_SENTINEL';
  let calls = 0;
  const resolver = createResolver(async () => {
    calls += 1;
    throw Object.freeze({ secret, response: { authorization: secret } });
  });

  const result = await resolver.observeExecution(executionBinding());

  assertUnknown(result, 'SELLER_EVIDENCE_FETCH_FAILED');
  assert.equal(calls, 1);
  assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal(Object.hasOwn(result, 'cause'), false);
});

test('the total deadline aborts the one provider attempt without retry', async () => {
  let calls = 0;
  let observedSignal;
  const resolver = createResolver((_url, init) => {
    calls += 1;
    observedSignal = init.signal;
    return new Promise((_resolve, reject) => {
      setTimeout(() => reject(new Error('late provider rejection')), 80);
    });
  }, {
    limits: { requestTimeoutMs: 10, maximumResponseBytes: 16_384 },
  });

  const result = await resolver.observeExecution(executionBinding());

  assertUnknown(result, 'SELLER_EVIDENCE_TIMEOUT');
  assert.equal(calls, 1);
  assert.ok(observedSignal instanceof AbortSignal);
  assert.equal(observedSignal.aborted, true);
});

test('redirects and non-success response statuses are stable unknowns', async () => {
  let redirectCalls = 0;
  const redirectResolver = createResolver(async () => {
    redirectCalls += 1;
    return new Response(null, {
      status: 302,
      headers: { location: 'https://attacker.example/evidence' },
    });
  });
  assertUnknown(
    await redirectResolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_REDIRECT',
  );
  assert.equal(redirectCalls, 1);

  const statusResolver = createResolver(async () => new Response('{}', {
    status: 503,
    headers: { 'content-type': 'application/json' },
  }));
  assertUnknown(
    await statusResolver.observeRefund(refundBinding()),
    'SELLER_EVIDENCE_HTTP_STATUS',
  );
});

test('only a JSON content type is accepted and canonical UTF-8 charset is supported', async () => {
  const wrongType = await observeStatic('execution', {
    responseOptions: { contentType: 'text/html' },
  });
  assertUnknown(wrongType.result, 'SELLER_EVIDENCE_CONTENT_TYPE');

  const missingType = await observeStatic('execution', {
    responseOptions: { contentType: null },
  });
  assertUnknown(missingType.result, 'SELLER_EVIDENCE_CONTENT_TYPE');

  const charset = await observeStatic('execution', {
    responseOptions: { contentType: 'application/json; charset=utf-8' },
  });
  assert.equal(charset.result.kind, 'execution_attested');
});

test('declared and streamed response bytes are both capped before JSON parsing', async () => {
  const declared = createResolver(async () => new Response('{}', {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'content-length': '16385',
    },
  }));
  assertUnknown(
    await declared.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_TOO_LARGE',
  );

  const streamed = createResolver(async () => new Response(
    JSON.stringify({ oversized: 'x'.repeat(1_000) }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ), {
    limits: { requestTimeoutMs: 5_000, maximumResponseBytes: 128 },
  });
  assertUnknown(
    await streamed.observeRefund(refundBinding()),
    'SELLER_EVIDENCE_TOO_LARGE',
  );
});

test('invalid JSON, invalid UTF-8, and body failures are redacted', async () => {
  const malformed = createResolver(async () => new Response('{', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
  assertUnknown(
    await malformed.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_JSON_INVALID',
  );

  const invalidUtf8 = createResolver(async () => new Response(
    new Uint8Array([0xc3, 0x28]),
    { status: 200, headers: { 'content-type': 'application/json' } },
  ));
  assertUnknown(
    await invalidUtf8.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_JSON_INVALID',
  );

  const secret = 'RAW_BODY_STREAM_ERROR_SENTINEL';
  const broken = createResolver(async () => new Response(new ReadableStream({
    pull(controller) {
      controller.error(new Error(secret));
    },
  }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));
  const result = await broken.observeRefund(refundBinding());
  assertUnknown(result, 'SELLER_EVIDENCE_RESPONSE_INVALID');
  assert.equal(JSON.stringify(result).includes(secret), false);
});

test('hostile response surfaces are rejected without invoking traps or accessors', async () => {
  let getterCalls = 0;
  const accessorResponse = {};
  Object.defineProperty(accessorResponse, 'status', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 200;
    },
  });
  const accessorResolver = createResolver(async () => accessorResponse);
  assertUnknown(
    await accessorResolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_RESPONSE_INVALID',
  );
  assert.equal(getterCalls, 0);

  const shadowedResponse = new Response('{}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  Object.defineProperty(shadowedResponse, 'status', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 200;
    },
  });
  const shadowedResolver = createResolver(async () => shadowedResponse);
  assertUnknown(
    await shadowedResolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_RESPONSE_INVALID',
  );
  assert.equal(getterCalls, 0);

  const proxyTraps = [];
  const proxiedResponse = new Proxy(new Response('{}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }), {
    get(target, property, receiver) {
      proxyTraps.push(property);
      return Reflect.get(target, property, receiver);
    },
  });
  const proxyResolver = createResolver(async () => proxiedResponse);
  assertUnknown(
    await proxyResolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_RESPONSE_INVALID',
  );
  // Promise/await assimilation performs the language-mandated `then` lookup;
  // the resolver itself must reject the proxy before touching response authority.
  assert.deepEqual(proxyTraps, ['then']);

  class HostileResponse extends Response {
    get status() {
      getterCalls += 1;
      return 200;
    }
  }
  const hostileResponse = new HostileResponse('{}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
  // Undici's constructor itself consults `status`; count only resolver access.
  getterCalls = 0;
  const subclassResolver = createResolver(async () => hostileResponse);
  assertUnknown(
    await subclassResolver.observeExecution(executionBinding()),
    'SELLER_EVIDENCE_RESPONSE_INVALID',
  );
  assert.equal(getterCalls, 0);
});

test('seller body, signature, provider error, and filesystem sentinels never cross the result boundary', async () => {
  const sentinels = [
    'RAW_SELLER_BODY_SENTINEL',
    'RAW_SIGNATURE_SENTINEL',
    'BEARER_CREDENTIAL_SENTINEL',
    '/private/wallet-kernel/evidence',
  ];
  const resolver = createResolver(async () => new Response(JSON.stringify({
    ...unsignedExecution(),
    signature: sentinels[1],
    body: sentinels[0],
    credential: sentinels[2],
    path: sentinels[3],
  }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  }));

  const result = await resolver.observeExecution(executionBinding());

  assertUnknown(result, 'SELLER_EVIDENCE_ATTESTATION_INVALID');
  const serialized = JSON.stringify(result);
  for (const sentinel of sentinels) assert.equal(serialized.includes(sentinel), false);
});

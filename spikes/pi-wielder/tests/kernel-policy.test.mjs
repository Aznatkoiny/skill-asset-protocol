import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  canonicalJson,
  KernelError,
  sha256,
} from '../src/kernel/canonical.mjs';
import {
  evaluateSpendPolicy,
  projectPaymentRequired,
  selectExactCandidate,
  validatePolicyDocument,
} from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const BASE_POLICY = {
  schemaVersion: 1,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  wallet: '0x1000000000000000000000000000000000000000',
  methods: ['GET', 'POST'],
  sellers: [{
    origin: 'https://seller.example',
    pathPrefixes: ['/paid/'],
    payTo: '0x2000000000000000000000000000000000000000',
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: '0x2000000000000000000000000000000000000000',
    refundSigner: '0x2000000000000000000000000000000000000000',
    refundSource: '0x3000000000000000000000000000000000000000',
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
};

const EXACT_OFFER = {
  scheme: 'exact',
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  amount: '50000',
  payTo: '0x2000000000000000000000000000000000000000',
  maxTimeoutSeconds: 60,
  extra: { name: 'USDC', version: '2' },
};

function clone(value) {
  return structuredClone(value);
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function policyDocument(overrides = {}) {
  return {
    ...clone(BASE_POLICY),
    ...overrides,
  };
}

function offer(overrides = {}) {
  const base = clone(EXACT_OFFER);
  return {
    ...base,
    ...overrides,
    ...(Object.hasOwn(overrides, 'extra') ? { extra: overrides.extra } : {}),
  };
}

function paymentRequired({ accepts = [offer()], ...overrides } = {}) {
  return {
    x402Version: 2,
    error: 'Payment required',
    resource: {
      url: 'https://seller.example/paid/infer',
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts,
    ...overrides,
  };
}

function evaluationInput({
  policyDocument: rawPolicy = policyDocument(),
  policyVersion: policyVersionOverrides = {},
  intent: intentOverrides = {},
  wallet: walletOverrides = {},
  paymentRequired: challenge = paymentRequired(),
  challengeReceivedAtMs = 1785502800000,
  nowMs = 1785502801000,
  budgetSnapshot: budgetOverrides = {},
} = {}) {
  const validatedPolicy = validatePolicyDocument(rawPolicy);
  const policyHash = sha256(canonicalJson(validatedPolicy));
  return deepFreeze({
    policy: validatedPolicy,
    policyVersion: {
      id: 'policy-1',
      hash: policyHash,
      ...policyVersionOverrides,
    },
    intent: {
      id: 'intent-1',
      method: 'POST',
      requestUrl: 'https://seller.example/paid/infer',
      sellerOrigin: 'https://seller.example',
      resourcePath: '/paid/infer',
      walletAddress: '0x1000000000000000000000000000000000000000',
      ...intentOverrides,
    },
    wallet: {
      provider: 'deterministic',
      walletId: 'buyer-a',
      address: '0x1000000000000000000000000000000000000000',
      network: 'eip155:84532',
      ...walletOverrides,
    },
    paymentRequired: challenge,
    challengeReceivedAtMs,
    nowMs,
    budgetSnapshot: {
      sellerSessionExposureAtomic: '0',
      sessionExposureAtomic: '0',
      rolling24hExposureAtomic: '0',
      pendingApprovalCount: 0,
      ...budgetOverrides,
    },
  });
}

function assertKernelError(operation, expectedCode) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof KernelError);
    if (expectedCode) assert.equal(error.code, expectedCode);
    return true;
  });
}

function assertDecision(input, expectedDecision, expectedReason, expectedIndex = undefined) {
  const result = evaluateSpendPolicy(input);
  assert.equal(result.decision, expectedDecision);
  assert.equal(result.reasonCode, expectedReason);
  if (expectedIndex !== undefined) assert.equal(result.acceptedIndex, expectedIndex);
  return result;
}

test('canonical example is the exact deeply frozen base policy', () => {
  const example = JSON.parse(fs.readFileSync(
    new URL('../policies/base-sepolia.example.json', import.meta.url),
    'utf8',
  ));
  assert.deepEqual(example, BASE_POLICY);

  const validated = validatePolicyDocument(BASE_POLICY);
  assert.deepEqual(validated, BASE_POLICY);
  assert.ok(Object.isFrozen(validated));
  assert.ok(Object.isFrozen(validated.methods));
  assert.ok(Object.isFrozen(validated.sellers));
  assert.ok(Object.isFrozen(validated.sellers[0]));
  assert.ok(Object.isFrozen(validated.sellers[0].pathPrefixes));
});

test('policy validation is closed at every level', () => {
  assertKernelError(() => validatePolicyDocument({ ...policyDocument(), injected: true }),
    'POLICY_SCHEMA');
  const missingTopLevel = policyDocument();
  delete missingTopLevel.defaultAction;
  assertKernelError(() => validatePolicyDocument(missingTopLevel), 'POLICY_SCHEMA');
  assertKernelError(() => validatePolicyDocument(policyDocument({
    sellers: [{ ...clone(BASE_POLICY.sellers[0]), injected: true }],
  })), 'POLICY_SCHEMA');
  const missingSellerField = clone(BASE_POLICY.sellers[0]);
  delete missingSellerField.refundSource;
  assertKernelError(() => validatePolicyDocument(policyDocument({
    sellers: [missingSellerField],
  })), 'POLICY_SCHEMA');
});

test('policy scalar, collection, and limit fields reject ambiguous configuration', () => {
  const invalidDocuments = [
    policyDocument({ schemaVersion: 2 }),
    policyDocument({ network: 'eip155:1' }),
    policyDocument({ asset: '0x4000000000000000000000000000000000000000' }),
    policyDocument({ asset: '0x1234' }),
    policyDocument({ wallet: '0x1234' }),
    policyDocument({ methods: [] }),
    policyDocument({ methods: ['POST', 'POST'] }),
    policyDocument({ methods: ['post'] }),
    policyDocument({ sellers: [] }),
    policyDocument({ sessionMaxAtomic: '01' }),
    policyDocument({ rolling24hMaxAtomic: -1 }),
    policyDocument({ challengeMaxAgeMs: 0 }),
    policyDocument({ approvalTtlMs: 1.5 }),
    policyDocument({ maxPendingApprovals: 0 }),
    policyDocument({ defaultAction: 'allow' }),
    policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), perRequestMaxAtomic: '1.0' }],
    }),
    policyDocument({
      sellers: [{
        ...clone(BASE_POLICY.sellers[0]),
        autoApproveAtomic: '500001',
      }],
    }),
    policyDocument({
      sellers: [{
        ...clone(BASE_POLICY.sellers[0]),
        humanApproveAtomic: '500001',
      }],
    }),
  ];
  for (const document of invalidDocuments) {
    assertKernelError(() => validatePolicyDocument(document));
  }
});

test('evidence paths and public evidence/refund authorities are canonical and mandatory', () => {
  for (const evidencePath of [
    'https://seller.example/evidence',
    '//other.example/evidence',
    '/a/../evidence',
    '/%2e%2e/evidence',
    '/evidence/%2fescape',
    '/evidence/%5cescape',
    '/evidence?revision=1',
    '/evidence#fragment',
  ]) {
    assertKernelError(() => validatePolicyDocument(policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), evidencePath }],
    })), 'POLICY_EVIDENCE_PATH');
  }

  for (const field of ['executionSigner', 'refundSigner', 'refundSource']) {
    assertKernelError(() => validatePolicyDocument(policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), [field]: '0x1234' }],
    })), 'POLICY_ADDRESS');
  }
});

test('seller origins are canonicalized, unique, and HTTPS except literal loopback HTTP', () => {
  const duplicate = clone(BASE_POLICY.sellers[0]);
  duplicate.origin = 'https://SELLER.example:443';
  assertKernelError(() => validatePolicyDocument(policyDocument({
    sellers: [clone(BASE_POLICY.sellers[0]), duplicate],
  })), 'POLICY_SELLER_DUPLICATE');

  for (const origin of [
    'http://seller.example',
    'http://localhost:8787',
    'http://2130706433:8787',
    'http://127.1:8787',
    'http://127.0.0.1:080',
    'ftp://seller.example',
  ]) {
    assertKernelError(() => validatePolicyDocument(policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), origin }],
    })), 'POLICY_SELLER_ORIGIN');
  }

  for (const origin of ['http://127.0.0.1:8787', 'http://[::1]:8787']) {
    const validated = validatePolicyDocument(policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), origin }],
    }));
    assert.equal(validated.sellers[0].origin, origin);
  }
});

test('seller path prefixes are canonical and unique while overlapping prefixes are harmless', () => {
  assertKernelError(() => validatePolicyDocument(policyDocument({
    sellers: [{ ...clone(BASE_POLICY.sellers[0]), pathPrefixes: ['/paid/', '/paid/'] }],
  })), 'POLICY_PATH_DUPLICATE');
  for (const prefix of ['paid/', '//paid/', '/paid/../admin', '/paid/%2fadmin', '/paid/?x=1']) {
    assertKernelError(() => validatePolicyDocument(policyDocument({
      sellers: [{ ...clone(BASE_POLICY.sellers[0]), pathPrefixes: [prefix] }],
    })), 'POLICY_RESOURCE_PATH');
  }

  const overlapping = validatePolicyDocument(policyDocument({
    sellers: [{ ...clone(BASE_POLICY.sellers[0]), pathPrefixes: ['/paid/', '/paid/infer'] }],
  }));
  assert.equal(
    evaluateSpendPolicy(evaluationInput({ policyDocument: overlapping })).decision,
    'allow',
  );
});

test('exact spend thresholds yield allow, approval, and deny decisions', () => {
  const allowed = assertDecision(
    evaluationInput({ paymentRequired: paymentRequired({ accepts: [offer({ amount: '50000' })] }) }),
    'allow',
    'WITHIN_AUTO_LIMIT',
    0,
  );
  assert.equal(allowed.amountCeilingAtomic, '50000');
  assert.match(allowed.policyHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(allowed.challengeHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(allowed.quoteId, /^sha256:[0-9a-f]{64}$/);
  assert.equal(allowed.quoteId, sha256(canonicalJson({
    challengeHash: allowed.challengeHash,
    acceptedIndex: 0,
  })));
  assert.deepEqual(Object.keys(allowed), [
    'decision',
    'reasonCode',
    'policyHash',
    'challengeHash',
    'quoteId',
    'amountCeilingAtomic',
    'acceptedIndex',
  ]);

  assertDecision(
    evaluationInput({ paymentRequired: paymentRequired({ accepts: [offer({ amount: '250000' })] }) }),
    'approval_required',
    'HUMAN_APPROVAL_REQUIRED',
    0,
  );
  assertDecision(
    evaluationInput({ paymentRequired: paymentRequired({ accepts: [offer({ amount: '500001' })] }) }),
    'deny',
    'PER_REQUEST_LIMIT',
    0,
  );
});

test('unsupported protocol, request, seller, resource, and payee inputs deny in stable order', () => {
  const cases = [
    ['X402_VERSION', { paymentRequired: paymentRequired({ x402Version: 1 }) }],
    ['SCHEME_UNSUPPORTED', {
      paymentRequired: paymentRequired({ accepts: [offer({ scheme: 'upto' })] }),
    }],
    ['NETWORK_MISMATCH', {
      paymentRequired: paymentRequired({ accepts: [offer({ network: 'eip155:1' })] }),
    }],
    ['ASSET_MISMATCH', {
      paymentRequired: paymentRequired({ accepts: [offer({
        asset: '0x4000000000000000000000000000000000000000',
      })] }),
    }],
    ['METHOD_UNSUPPORTED', { intent: { method: 'PUT' } }],
    ['SELLER_UNTRUSTED', {
      intent: {
        sellerOrigin: 'https://other.example',
        requestUrl: 'https://other.example/paid/infer',
        resourcePath: '/paid/infer',
      },
      paymentRequired: paymentRequired({
        resource: {
          url: 'https://other.example/paid/infer',
          description: 'offline fixture',
          mimeType: 'application/json',
        },
      }),
    }],
    ['RESOURCE_PATH', {
      intent: {
        requestUrl: 'https://seller.example/free/infer',
        resourcePath: '/free/infer',
      },
      paymentRequired: paymentRequired({
        resource: {
          url: 'https://seller.example/free/infer',
          description: 'offline fixture',
          mimeType: 'application/json',
        },
      }),
    }],
    ['PAYEE_MISMATCH', {
      paymentRequired: paymentRequired({ accepts: [offer({
        payTo: '0x4000000000000000000000000000000000000000',
      })] }),
    }],
  ];

  for (const [reasonCode, options] of cases) {
    const decision = assertDecision(evaluationInput(options), 'deny', reasonCode);
    assert.notEqual(decision.decision, 'approval_required');
  }
});

test('wallet identity and policy hash are bound before amount rules', () => {
  assertDecision(evaluationInput({
    intent: { walletAddress: '0x4000000000000000000000000000000000000000' },
    paymentRequired: paymentRequired({ accepts: [offer({ amount: '1' })] }),
  }), 'deny', 'WALLET_MISMATCH');
  assertDecision(evaluationInput({
    wallet: { address: '0x4000000000000000000000000000000000000000' },
    paymentRequired: paymentRequired({ accepts: [offer({ amount: '1' })] }),
  }), 'deny', 'WALLET_MISMATCH');
  assertDecision(evaluationInput({
    wallet: { network: 'eip155:1' },
    paymentRequired: paymentRequired({ accepts: [offer({ amount: '1' })] }),
  }), 'deny', 'NETWORK_MISMATCH');
  assertKernelError(() => evaluateSpendPolicy(evaluationInput({
    policyVersion: { hash: `sha256:${'0'.repeat(64)}` },
  })), 'POLICY_HASH_MISMATCH');
});

test('candidate selection owns 0/1/2 cardinality and preserves the original array index', () => {
  const input = evaluationInput();
  const none = selectExactCandidate({
    policy: input.policy,
    intent: input.intent,
    paymentRequired: paymentRequired({ accepts: [] }),
  });
  assert.equal(none.acceptedIndex, null);
  assert.equal(none.accepted, null);

  const onlyAtOne = paymentRequired({ accepts: [
    offer({ scheme: 'upto' }),
    offer({ amount: '250000' }),
  ] });
  const selected = selectExactCandidate({
    policy: input.policy,
    intent: input.intent,
    paymentRequired: onlyAtOne,
  });
  assert.equal(selected.acceptedIndex, 1);
  assert.equal(selected.accepted.amount, '250000');
  assertDecision(evaluationInput({ paymentRequired: onlyAtOne }),
    'approval_required', 'HUMAN_APPROVAL_REQUIRED', 1);

  for (const accepts of [
    [offer(), offer()],
    [offer({ amount: '50000' }), offer({ amount: '250000' })],
  ]) {
    const decision = assertDecision(
      evaluationInput({ paymentRequired: paymentRequired({ accepts }) }),
      'deny',
      'PAYMENT_OPTIONS_AMBIGUOUS',
    );
    assert.equal(decision.acceptedIndex, null);
    assert.equal(decision.quoteId, null);
    assert.equal(decision.amountCeilingAtomic, '0');
  }
});

test('zero compatible options produce a stable ordered mismatch denial', () => {
  const challenge = paymentRequired({ accepts: [
    offer({ scheme: 'upto', network: 'eip155:1' }),
    offer({ scheme: 'exact', network: 'eip155:1' }),
  ] });
  const first = evaluateSpendPolicy(evaluationInput({ paymentRequired: challenge }));
  const second = evaluateSpendPolicy(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [...challenge.accepts].reverse() }),
  }));
  assert.equal(first.decision, 'deny');
  assert.equal(first.reasonCode, 'NETWORK_MISMATCH');
  assert.equal(second.reasonCode, 'NETWORK_MISMATCH');
  assert.equal(first.acceptedIndex, null);
  assert.equal(first.quoteId, null);
  assert.equal(first.amountCeilingAtomic, '0');
  assertDecision(
    evaluationInput({ paymentRequired: paymentRequired({ accepts: [] }) }),
    'deny',
    'SCHEME_UNSUPPORTED',
  );
});

test('deny checks keep the declared precedence when several mismatches coexist', () => {
  assertDecision(evaluationInput({
    intent: {
      method: 'PUT',
      walletAddress: '0x4000000000000000000000000000000000000000',
    },
    paymentRequired: paymentRequired({
      x402Version: 1,
      accepts: [offer({
        scheme: 'upto',
        network: 'eip155:1',
        asset: '0x4000000000000000000000000000000000000000',
        payTo: '0x5000000000000000000000000000000000000000',
        amount: '999999999',
      })],
    }),
    budgetSnapshot: {
      sellerSessionExposureAtomic: '999999999',
      sessionExposureAtomic: '999999999',
      rolling24hExposureAtomic: '999999999',
      pendingApprovalCount: 20,
    },
  }), 'deny', 'X402_VERSION');

  assertDecision(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [offer({
      network: 'eip155:1',
      asset: '0x4000000000000000000000000000000000000000',
    })] }),
  }), 'deny', 'NETWORK_MISMATCH');
});

test('USDC v2 and EIP-3009 are part of exact candidate compatibility', () => {
  for (const extra of [
    { name: 'USD Coin', version: '2' },
    { name: 'USDC', version: '1' },
  ]) {
    assertDecision(evaluationInput({
      paymentRequired: paymentRequired({ accepts: [offer({ extra })] }),
    }), 'deny', 'ASSET_MISMATCH');
  }
  assertDecision(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [offer({
      extra: { name: 'USDC', version: '2', assetTransferMethod: 'permit2' },
    })] }),
  }), 'deny', 'SCHEME_UNSUPPORTED');
  assertDecision(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [offer({
      extra: { name: 'USDC', version: '2', assetTransferMethod: 'eip3009' },
    })] }),
  }), 'allow', 'WITHIN_AUTO_LIMIT', 0);
});

test('challenge candidate amounts and timeouts are structurally validated before selection', () => {
  for (const amount of ['0', '01', '-1', '1.0', 1]) {
    assertKernelError(() => evaluateSpendPolicy(evaluationInput({
      paymentRequired: paymentRequired({ accepts: [
        offer({ scheme: 'upto' }),
        offer({ amount }),
      ] }),
    })), 'CHALLENGE_AMOUNT');
  }
  for (const maxTimeoutSeconds of [0, 3601, '60', 1.5]) {
    assertKernelError(() => evaluateSpendPolicy(evaluationInput({
      paymentRequired: paymentRequired({ accepts: [offer({ maxTimeoutSeconds })] }),
    })), 'CHALLENGE_TIMEOUT');
  }
  for (const [field, value] of [
    ['asset', '0x036CBD53842C5426634E7929541EC2318F3DCF7E'],
    ['asset', 'asset-token'],
    ['payTo', '0x200000000000000000000000000000000000000A'],
    ['payTo', 'seller-account'],
  ]) {
    assertKernelError(() => evaluateSpendPolicy(evaluationInput({
      paymentRequired: paymentRequired({ accepts: [offer({ [field]: value })] }),
    })), 'CHALLENGE_SCHEMA');
  }
});

test('challenge age is local and cannot be extended by the protocol timeout', () => {
  assertDecision(evaluationInput({
    challengeReceivedAtMs: 1785502800000,
    nowMs: 1785502860001,
    paymentRequired: paymentRequired({ accepts: [offer({ maxTimeoutSeconds: 3600 })] }),
  }), 'deny', 'CHALLENGE_EXPIRED', 0);
  assertKernelError(() => evaluateSpendPolicy(evaluationInput({
    challengeReceivedAtMs: 1785502801000,
    nowMs: 1785502800000,
  })), 'CHALLENGE_TIME');
});

test('seller, session, rolling-day, and approval capacity limits include the selected amount', () => {
  const cases = [
    ['SELLER_SESSION_LIMIT', {
      sellerSessionExposureAtomic: '950001',
    }],
    ['SESSION_LIMIT', {
      sessionExposureAtomic: '1950001',
    }],
    ['ROLLING_24H_LIMIT', {
      rolling24hExposureAtomic: '4950001',
    }],
  ];
  for (const [reasonCode, budgetSnapshot] of cases) {
    assertDecision(evaluationInput({ budgetSnapshot }), 'deny', reasonCode, 0);
  }
  assertDecision(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [offer({ amount: '250000' })] }),
    budgetSnapshot: { pendingApprovalCount: 20 },
  }), 'deny', 'APPROVAL_CAPACITY', 0);
});

test('payment challenge and evaluation input schemas are closed at every level', () => {
  const base = evaluationInput();
  const badInputs = [
    { ...base, injected: true },
    { ...base, policyVersion: { ...base.policyVersion, injected: true } },
    { ...base, intent: { ...base.intent, injected: true } },
    { ...base, wallet: { ...base.wallet, injected: true } },
    { ...base, budgetSnapshot: { ...base.budgetSnapshot, injected: true } },
    { ...base, paymentRequired: { ...base.paymentRequired, injected: true } },
    {
      ...base,
      paymentRequired: {
        ...base.paymentRequired,
        resource: { ...base.paymentRequired.resource, injected: true },
      },
    },
    {
      ...base,
      paymentRequired: {
        ...base.paymentRequired,
        accepts: [{ ...base.paymentRequired.accepts[0], injected: true }],
      },
    },
    {
      ...base,
      paymentRequired: {
        ...base.paymentRequired,
        accepts: [{
          ...base.paymentRequired.accepts[0],
          extra: { ...base.paymentRequired.accepts[0].extra, injected: true },
        }],
      },
    },
  ];
  for (const badInput of badInputs) assertKernelError(() => evaluateSpendPolicy(badInput));

  const missingChallenge = clone(base.paymentRequired);
  delete missingChallenge.accepts;
  assertKernelError(() => evaluateSpendPolicy({ ...base, paymentRequired: missingChallenge }),
    'CHALLENGE_SCHEMA');

  for (const field of Object.keys(base)) {
    const missing = { ...base };
    delete missing[field];
    assertKernelError(() => evaluateSpendPolicy(missing));
  }
  for (const [field, value] of [
    ['policyVersion', base.policyVersion],
    ['intent', base.intent],
    ['wallet', base.wallet],
    ['budgetSnapshot', base.budgetSnapshot],
  ]) {
    for (const key of Object.keys(value)) {
      const missingNested = { ...value };
      delete missingNested[key];
      assertKernelError(() => evaluateSpendPolicy({ ...base, [field]: missingNested }));
    }
  }
  for (const key of ['x402Version', 'resource', 'accepts']) {
    const missing = clone(base.paymentRequired);
    delete missing[key];
    assertKernelError(() => evaluateSpendPolicy({ ...base, paymentRequired: missing }));
  }
  for (const key of ['url', 'description', 'mimeType']) {
    const missing = clone(base.paymentRequired);
    delete missing.resource[key];
    assertKernelError(() => evaluateSpendPolicy({ ...base, paymentRequired: missing }));
  }
  for (const key of ['scheme', 'network', 'asset', 'amount', 'payTo', 'maxTimeoutSeconds', 'extra']) {
    const missing = clone(base.paymentRequired);
    delete missing.accepts[0][key];
    assertKernelError(() => evaluateSpendPolicy({ ...base, paymentRequired: missing }));
  }
  for (const key of ['name', 'version']) {
    const missing = clone(base.paymentRequired);
    delete missing.accepts[0].extra[key];
    assertKernelError(() => evaluateSpendPolicy({ ...base, paymentRequired: missing }));
  }
});

test('resource URL is exact and seller error text is excluded from the challenge binding', () => {
  const input = evaluationInput();
  const a = evaluateSpendPolicy(input);
  const b = evaluateSpendPolicy(evaluationInput({
    paymentRequired: paymentRequired({ error: 'Different seller prose' }),
  }));
  assert.equal(a.challengeHash, b.challengeHash);
  assert.equal(a.quoteId, b.quoteId);

  const mismatch = paymentRequired({
    resource: {
      url: 'https://seller.example/paid/other',
      description: 'offline fixture',
      mimeType: 'application/json',
    },
  });
  assertDecision(evaluationInput({ paymentRequired: mismatch }), 'deny', 'RESOURCE_PATH');
});

test('ordered financial requirements bind challenge hash and quote index', () => {
  const unsupported = offer({ scheme: 'upto', amount: '1' });
  const exact = offer({ amount: '50000' });
  const first = evaluateSpendPolicy(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [unsupported, exact] }),
  }));
  const second = evaluateSpendPolicy(evaluationInput({
    paymentRequired: paymentRequired({ accepts: [exact, unsupported] }),
  }));
  assert.equal(first.acceptedIndex, 1);
  assert.equal(second.acceptedIndex, 0);
  assert.notEqual(first.challengeHash, second.challengeHash);
  assert.notEqual(first.quoteId, second.quoteId);
});

test('seller lookup is origin keyed rather than dependent on seller array order', () => {
  const secondSeller = {
    ...clone(BASE_POLICY.sellers[0]),
    origin: 'https://other.example',
    pathPrefixes: ['/other/'],
    payTo: '0x4000000000000000000000000000000000000000',
    executionSigner: '0x4000000000000000000000000000000000000000',
    refundSigner: '0x4000000000000000000000000000000000000000',
    refundSource: '0x5000000000000000000000000000000000000000',
    autoApproveAtomic: '1',
  };
  const sellersA = [clone(BASE_POLICY.sellers[0]), secondSeller];
  const sellersB = [...sellersA].reverse();
  const a = evaluateSpendPolicy(evaluationInput({
    policyDocument: policyDocument({ sellers: sellersA }),
  }));
  const b = evaluateSpendPolicy(evaluationInput({
    policyDocument: policyDocument({ sellers: sellersB }),
  }));
  assert.equal(a.decision, 'allow');
  assert.equal(b.decision, 'allow');
  assert.equal(a.reasonCode, b.reasonCode);
  assert.equal(a.amountCeilingAtomic, b.amountCeilingAtomic);
});

test('a frozen input snapshot is deterministic and never mutated', () => {
  const input = evaluationInput();
  const before = canonicalJson(input);
  const first = evaluateSpendPolicy(input);
  const second = evaluateSpendPolicy(input);
  assert.equal(canonicalJson(first), canonicalJson(second));
  assert.equal(canonicalJson(input), before);
  assert.ok(Object.isFrozen(first));
  assert.ok(Object.isFrozen(input));
  assert.ok(Object.isFrozen(input.paymentRequired.accepts[0]));
});

test('policy versions are immutable, predecessor linked, wallet safe, and idempotent', () => {
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => '2026-08-01T12:00:00.000Z',
  });
  try {
    const repository = createPolicyRepository(store);
    const first = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
    assert.equal(first.idempotent, false);
    assert.deepEqual(first.blockedSessionIds, []);
    assert.deepEqual(repository.active(), first.policyVersion);
    const originalRow = store.readOne('SELECT * FROM policy_versions WHERE id = ?', [
      first.policyVersion.id,
    ]);

    store.transaction((token) => store.within(token, ({ db }) => {
      const insert = db.prepare(`INSERT INTO spend_sessions
        (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`);
      insert.run('session-open', 'adapter-a', BASE_POLICY.wallet,
        first.policyVersion.id, 'open', '2026-08-01T12:00:01.000Z', null);
      insert.run('session-already-blocked', 'adapter-b', BASE_POLICY.wallet,
        first.policyVersion.id, 'policy_blocked', '2026-08-01T12:00:02.000Z', null);
      insert.run('session-closed', 'adapter-c', BASE_POLICY.wallet,
        first.policyVersion.id, 'closed', '2026-08-01T12:00:03.000Z',
        '2026-08-01T12:00:04.000Z');
    }));

    const differentWallet = policyDocument({
      wallet: '0x4000000000000000000000000000000000000000',
    });
    assertKernelError(
      () => repository.apply(differentWallet, '2026-08-01T12:01:00.000Z'),
      'POLICY_WALLET_MISMATCH',
    );
    assert.equal(repository.history().length, 1);

    const tighter = policyDocument({
      sessionMaxAtomic: '1500000',
      rolling24hMaxAtomic: '4000000',
    });
    const second = repository.apply(tighter, '2026-08-01T12:02:00.000Z');
    assert.equal(second.idempotent, false);
    assert.deepEqual(second.blockedSessionIds, ['session-open']);
    assert.equal(second.policyVersion.predecessorHash, first.policyVersion.hash);
    assert.deepEqual(store.readOne('SELECT * FROM policy_versions WHERE id = ?', [
      first.policyVersion.id,
    ]), originalRow);
    assert.deepEqual(repository.active(), second.policyVersion);
    assert.equal(store.readOne('SELECT state FROM spend_sessions WHERE id = ?', [
      'session-open',
    ]).state, 'policy_blocked');
    assert.equal(store.readOne('SELECT state FROM spend_sessions WHERE id = ?', [
      'session-already-blocked',
    ]).state, 'policy_blocked');
    assert.equal(store.readOne('SELECT state FROM spend_sessions WHERE id = ?', [
      'session-closed',
    ]).state, 'closed');
    assert.equal(store.events().filter((event) => event.event_type === 'policy.applied').length, 2);
    assert.equal(store.events().filter(
      (event) => event.event_type === 'session.policy_blocked',
    ).length, 1);

    const eventsBeforeHistoricalReuse = store.events();
    assertKernelError(
      () => repository.apply(policyDocument(), '2026-08-01T12:30:00.000Z'),
      'POLICY_VERSION_REUSE',
    );
    assert.deepEqual(store.events(), eventsBeforeHistoricalReuse);
    assert.equal(repository.history().length, 2);

    const eventsBeforeReplay = store.events();
    const replay = repository.apply(tighter, '2026-08-01T13:00:00.000Z');
    assert.equal(replay.idempotent, true);
    assert.deepEqual(replay.policyVersion, second.policyVersion);
    assert.deepEqual(replay.blockedSessionIds, []);
    assert.equal(repository.history().length, 2);
    assert.deepEqual(store.events(), eventsBeforeReplay);
    assert.equal(store.verifyEventChain(), true);
  } finally {
    store.close();
  }
});

test('idempotent policy replay still audits every live Spend Session wallet', () => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  try {
    const repository = createPolicyRepository(store);
    const applied = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
    store.transaction((token) => store.within(token, ({ db }) => db.prepare(`INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .run('session-corrupt', 'adapter-corrupt',
        '0x4000000000000000000000000000000000000000', applied.policyVersion.id,
        'open', '2026-08-01T12:00:01.000Z')));
    const eventsBefore = store.events();
    assertKernelError(
      () => repository.apply(policyDocument(), '2026-08-01T12:01:00.000Z'),
      'POLICY_WALLET_MISMATCH',
    );
    assert.deepEqual(store.events(), eventsBefore);
    assert.equal(repository.history().length, 1);
  } finally {
    store.close();
  }
});

function seedDecisionIntent(store, {
  policyVersion,
  challengeHash,
  challengeProjection,
  intentId = 'intent-1',
} = {}) {
  store.transaction((token) => store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO agent_enrollments
      (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
       state, enrolled_by_operator_hash, enrolled_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run('agent-1', 'credential-1', 'enrollment-1', '501', '20', 'active',
        'operator-1', '2026-08-01T12:00:00.000Z');
    db.prepare(`INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES (?, ?, ?, ?, ?, ?)`)
      .run('session-1', 'adapter-1', BASE_POLICY.wallet, policyVersion.id, 'open',
        '2026-08-01T12:00:00.000Z');
    db.prepare(`INSERT INTO spend_intents
      (id, request_id, session_id, enrollment_hash, route_id, method,
       request_url_hash, seller_origin, resource_path, body_hash,
       header_allowlist_hash, ordinary_fingerprint, purpose_label,
       correlation_id, idempotency_key, wallet_address, intent_hash,
       challenge_projection_json, challenge_hash, challenge_received_at,
       state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(intentId, `request-${intentId}`, 'session-1', 'enrollment-1', 'route-1', 'POST',
        sha256('https://seller.example/paid/infer'), 'https://seller.example',
        '/paid/infer', 'body-hash',
        'headers-hash', `fingerprint-${intentId}`, 'skill.invoke', `correlation-${intentId}`,
        `idempotency-${intentId}`, BASE_POLICY.wallet, `intent-hash-${intentId}`,
        canonicalJson(challengeProjection), challengeHash, '2026-08-01T12:00:01.000Z',
        'challenged', '2026-08-01T12:00:00.000Z', '2026-08-01T12:00:01.000Z');
  }));
}

test('PolicyDecision persistence is scoped, atomic, and exact-replay idempotent', () => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  try {
    const repository = createPolicyRepository(store);
    const applied = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
    const challenge = paymentRequired();
    const input = evaluationInput({
      policyVersion: {
        id: applied.policyVersion.id,
        hash: applied.policyVersion.hash,
      },
      paymentRequired: challenge,
    });
    const evaluation = evaluateSpendPolicy(input);
    seedDecisionIntent(store, {
      policyVersion: applied.policyVersion,
      challengeHash: evaluation.challengeHash,
      challengeProjection: projectPaymentRequired(challenge),
    });

    assert.throws(() => repository.recordDecisionInTransaction(
      Object.freeze(Object.create(null)),
      {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation,
        decidedAt: '2026-08-01T12:00:02.000Z',
      },
    ), /invalid authority transaction/);

    let staleToken;
    const first = store.transaction((token) => {
      staleToken = token;
      return repository.recordDecisionInTransaction(token, {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation,
        decidedAt: '2026-08-01T12:00:02.000Z',
      });
    });
    assert.equal(first.intentId, 'intent-1');
    const persistedFirst = store.readOne(
      'SELECT * FROM policy_decisions WHERE intent_id = ?', ['intent-1'],
    );
    assert.equal(persistedFirst.decision, evaluation.decision);
    assert.equal(persistedFirst.reason_code, evaluation.reasonCode);
    const eventsAfterFirst = store.events();
    const replay = store.transaction((token) => repository.recordDecisionInTransaction(token, {
      intentId: 'intent-1',
      policyVersionId: applied.policyVersion.id,
      evaluation,
      decidedAt: '2026-08-01T12:00:03.000Z',
    }));
    assert.deepEqual(replay, first);
    assert.deepEqual(store.events(), eventsAfterFirst);
    assert.throws(() => repository.recordDecisionInTransaction(staleToken, {
      intentId: 'intent-1',
      policyVersionId: applied.policyVersion.id,
      evaluation,
      decidedAt: '2026-08-01T12:00:02.000Z',
    }), /invalid authority transaction/);

    assertKernelError(() => store.transaction((token) => repository.recordDecisionInTransaction(
      token,
      {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation: Object.freeze({ ...evaluation, reasonCode: 'DIFFERENT_RESULT' }),
        decidedAt: '2026-08-01T12:00:02.000Z',
      },
    )), 'POLICY_DECISION_CORRUPTION');
    assertKernelError(() => store.transaction((token) => repository.recordDecisionInTransaction(
      token,
      {
        intentId: 'intent-1',
        policyVersionId: 'policy-999',
        evaluation,
        decidedAt: '2026-08-01T12:00:02.000Z',
      },
    )), 'POLICY_DECISION_CORRUPTION');
    assert.deepEqual(store.readOne('SELECT * FROM policy_decisions WHERE intent_id = ?', [
      'intent-1',
    ]), persistedFirst);
  } finally {
    store.close();
  }
});

test('PolicyDecision write rolls back with its caller-owned aggregate transaction', () => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  try {
    const repository = createPolicyRepository(store);
    const applied = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
    const challenge = paymentRequired();
    const evaluation = evaluateSpendPolicy(evaluationInput({
      policyVersion: {
        id: applied.policyVersion.id,
        hash: applied.policyVersion.hash,
      },
      paymentRequired: challenge,
    }));
    seedDecisionIntent(store, {
      policyVersion: applied.policyVersion,
      challengeHash: evaluation.challengeHash,
      challengeProjection: projectPaymentRequired(challenge),
    });
    const eventsBefore = store.events();

    assertKernelError(() => store.transaction((token) => repository.recordDecisionInTransaction(
      token,
      {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation: Object.freeze({
          ...evaluation,
          decision: 'deny',
          reasonCode: 'WITHIN_AUTO_LIMIT',
        }),
        decidedAt: '2026-08-01T12:00:02.000Z',
      },
    )), 'POLICY_DECISION_SCHEMA');
    const differentChallengeHash = sha256(canonicalJson({ different: true }));
    assertKernelError(() => store.transaction((token) => repository.recordDecisionInTransaction(
      token,
      {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation: Object.freeze({
          ...evaluation,
          challengeHash: differentChallengeHash,
          quoteId: sha256(canonicalJson({
            challengeHash: differentChallengeHash,
            acceptedIndex: evaluation.acceptedIndex,
          })),
        }),
        decidedAt: '2026-08-01T12:00:02.000Z',
      },
    )), 'POLICY_CHALLENGE_MISMATCH');

    assert.throws(() => store.transaction((token) => {
      repository.recordDecisionInTransaction(token, {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation,
        decidedAt: '2026-08-01T12:00:02.000Z',
      });
      throw new Error('aggregate fault');
    }), /aggregate fault/);
    assert.equal(store.readOne(
      'SELECT * FROM policy_decisions WHERE intent_id = ?', ['intent-1'],
    ), undefined);
    assert.deepEqual(store.events(), eventsBefore);
  } finally {
    store.close();
  }
});

test('PolicyDecision writer accepts pure denials from live wallet identity mismatches', () => {
  for (const wallet of [
    { network: 'eip155:1' },
    { address: '0x4000000000000000000000000000000000000000' },
  ]) {
    const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
    try {
      const repository = createPolicyRepository(store);
      const applied = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
      const challenge = paymentRequired();
      const evaluation = evaluateSpendPolicy(evaluationInput({
        policyVersion: {
          id: applied.policyVersion.id,
          hash: applied.policyVersion.hash,
        },
        paymentRequired: challenge,
        wallet,
      }));
      seedDecisionIntent(store, {
        policyVersion: applied.policyVersion,
        challengeHash: evaluation.challengeHash,
        challengeProjection: projectPaymentRequired(challenge),
      });

      const persisted = store.transaction((token) => repository.recordDecisionInTransaction(
        token,
        {
          intentId: 'intent-1',
          policyVersionId: applied.policyVersion.id,
          evaluation,
          decidedAt: '2026-08-01T12:00:02.000Z',
        },
      ));
      assert.equal(persisted.decision, 'deny');
      assert.equal(persisted.reasonCode, evaluation.reasonCode);
    } finally {
      store.close();
    }
  }
});

test('PolicyDecision writer binds persisted projection, selected candidate, and thresholds', () => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  try {
    const repository = createPolicyRepository(store);
    const applied = repository.apply(policyDocument(), '2026-08-01T12:00:00.000Z');
    const challenge = paymentRequired({
      accepts: [offer({ scheme: 'subscription', amount: '1' }), offer()],
    });
    const evaluation = evaluateSpendPolicy(evaluationInput({
      policyVersion: {
        id: applied.policyVersion.id,
        hash: applied.policyVersion.hash,
      },
      paymentRequired: challenge,
    }));
    seedDecisionIntent(store, {
      policyVersion: applied.policyVersion,
      challengeHash: evaluation.challengeHash,
      challengeProjection: projectPaymentRequired(challenge),
    });

    const assertRejected = (forged) => assertKernelError(
      () => store.transaction((token) => repository.recordDecisionInTransaction(token, {
        intentId: 'intent-1',
        policyVersionId: applied.policyVersion.id,
        evaluation: forged,
        decidedAt: '2026-08-01T12:00:02.000Z',
      })),
      'POLICY_DECISION_CORRUPTION',
    );

    assertRejected(Object.freeze({
      ...evaluation,
      acceptedIndex: 9,
      amountCeilingAtomic: '1',
      quoteId: sha256(canonicalJson({
        challengeHash: evaluation.challengeHash,
        acceptedIndex: 9,
      })),
    }));
    assertRejected(Object.freeze({
      ...evaluation,
      acceptedIndex: 0,
      amountCeilingAtomic: '1',
      quoteId: sha256(canonicalJson({
        challengeHash: evaluation.challengeHash,
        acceptedIndex: 0,
      })),
    }));
    assertRejected(Object.freeze({
      ...evaluation,
      decision: 'approval_required',
      reasonCode: 'HUMAN_APPROVAL_REQUIRED',
    }));
    assert.equal(store.readOne(
      'SELECT * FROM policy_decisions WHERE intent_id = ?', ['intent-1'],
    ), undefined);

    store.transaction((token) => store.within(token, ({ db }) => db.prepare(
      'UPDATE spend_intents SET challenge_projection_json = ? WHERE id = ?',
    ).run(canonicalJson({ tampered: true }), 'intent-1')));
    assertRejected(evaluation);
  } finally {
    store.close();
  }
});

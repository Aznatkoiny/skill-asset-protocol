import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import test from 'node:test';

import { signBudget } from '../src/budget.mjs';
import {
  signCredential,
  signManagerApproval,
  signPrincipalAttestation,
  verifyCredential,
  verifyManagerApproval,
  verifyPrincipalAttestation,
} from '../src/credentials.mjs';
import {
  authorizeInternalInvocation,
  canonicalAwardReversalBytes,
  cancelInternalAuthorization,
  createEngineState,
  executeAuthorizedInvocation,
  recordAwardReversal,
  signAwardReversal,
} from '../src/engine.mjs';
import { policyHash, skillRegistrationKey } from '../src/schema.mjs';
import { receiptHash, verifyReceipt } from '../src/statements.mjs';
import { InMemoryEngineStore } from '../src/store.mjs';

const NOW = '2026-07-17T00:01:00.000Z';
const AFTER_EXPIRY = '2026-07-17T00:06:00.000Z';
const SKILL_HASH = `sha256:${'1'.repeat(64)}`;
const KIM_SKILL_HASH = `sha256:${'2'.repeat(64)}`;
const UNKNOWN_SKILL_HASH = `sha256:${'3'.repeat(64)}`;
const OUTPUT_HASH = `sha256:${'a'.repeat(64)}`;

function publicPem(keyPair) {
  return keyPair.publicKey.export({ type: 'spki', format: 'pem' });
}

function nonce(label) {
  return createHash('sha256').update(String(label)).digest('hex');
}

function policy(overrides = {}) {
  return {
    schemaVersion: 1,
    policyId: 'policy-megacorp-ledger-recon',
    version: 1,
    status: 'active',
    currency: 'USD',
    atomicScale: 6,
    employerId: 'megacorp',
    effectiveAt: '2026-07-17T00:00:00.000Z',
    expiresAt: '2026-08-01T00:00:00.000Z',
    permittedSkillIds: ['ledger-recon'],
    permittedCreatorIds: ['sam', 'kim'],
    permittedWielderIds: ['megacorp-internal-agent'],
    permittedInitiatingPrincipalIds: ['sam', 'kim', 'jordan'],
    permittedCostCenters: ['platform-engineering'],
    maxQuoteAtomic: '4000000',
    awardRule: {
      type: 'residual_after_execution_fee_and_reserve',
      awardRateBps: 10000,
      rateBase: 'post_cost_residual',
      rounding: 'floor_atomic',
    },
    maxAwardPerInvocationAtomic: '2000000',
    maxAwardPerPeriodAtomic: '100000000',
    selfInvocation: 'manager_approval_required',
    permittedManagerSignerIds: ['manager-alex'],
    permittedCredentialAuthorizerIds: ['megacorp-collar-authorizer'],
    permittedIdentitySignerIds: ['megacorp-identity'],
    permittedFinanceSignerIds: ['megacorp-finance'],
    vestingRule: 'none',
    paymentSchedule: 'monthly_in_arrears',
    terminationTreatment: 'earned_remains_payable_unearned_cancelled',
    paymentRail: 'employer_payroll_or_ap',
    ...overrides,
  };
}

function registration({
  creatorId = 'sam',
  skillVersionHash = SKILL_HASH,
  status = 'active',
  effectiveAt = '2026-07-17T00:00:00.000Z',
  expiresAt = '2026-08-01T00:00:00.000Z',
} = {}) {
  return {
    schemaVersion: 1,
    registrationId: `registration-ledger-recon-${creatorId}-${skillVersionHash.slice(-4)}`,
    skillId: 'ledger-recon',
    skillVersionHash,
    creatorId,
    employerId: 'megacorp',
    status,
    effectiveAt,
    expiresAt,
  };
}

function makeQuote(activePolicy, suffix = '001', overrides = {}) {
  return {
    schemaVersion: 1,
    quoteId: `quote-inv-${suffix}`,
    invocationId: `inv-${suffix}`,
    idempotencyKey: `run-ledger-recon-${suffix}`,
    skillId: 'ledger-recon',
    skillVersionHash: SKILL_HASH,
    creatorId: 'sam',
    wielderId: 'megacorp-internal-agent',
    initiatingPrincipalId: 'jordan',
    principalAttestationId: `principal-attestation-${suffix}`,
    beneficiaryId: 'megacorp',
    costCenter: 'platform-engineering',
    policyId: activePolicy.policyId,
    policyVersion: activePolicy.version,
    policyHash: policyHash(activePolicy),
    maxExecutionCostAtomic: '1000000',
    protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000',
    maxInvocationAwardAtomic: '2000000',
    maxGrossAtomic: '3050000',
    expiresAt: '2026-07-17T00:05:00.000Z',
    ...overrides,
  };
}

function principalAttestation(fx, quote, overrides = {}, signer = fx.identity.privateKey) {
  return signPrincipalAttestation({
    schemaVersion: 1,
    attestationId: quote.principalAttestationId,
    identitySignerId: 'megacorp-identity',
    principalId: quote.initiatingPrincipalId,
    invocationId: quote.invocationId,
    idempotencyKey: quote.idempotencyKey,
    skillId: quote.skillId,
    skillVersionHash: quote.skillVersionHash,
    creatorId: quote.creatorId,
    wielderId: quote.wielderId,
    beneficiaryId: quote.beneficiaryId,
    policyId: quote.policyId,
    policyVersion: quote.policyVersion,
    policyHash: quote.policyHash,
    nonce: nonce(`principal:${quote.invocationId}`),
    issuedAt: NOW,
    expiresAt: quote.expiresAt,
    ...overrides,
  }, signer);
}

function managerApproval(fx, quote) {
  return signManagerApproval({
    schemaVersion: 1,
    approvalId: `approval-${quote.invocationId}`,
    managerSignerId: 'manager-alex',
    invocationId: quote.invocationId,
    creatorId: quote.creatorId,
    policyId: quote.policyId,
    policyVersion: quote.policyVersion,
    issuedAt: NOW,
    expiresAt: quote.expiresAt,
  }, fx.manager.privateKey);
}

function fixture({
  policyOverrides = {},
  budgetOverrides = {},
  registrations,
  receiptSign = null,
  additionalCredentialAuthorizers = {},
} = {}) {
  const finance = generateKeyPairSync('ed25519');
  const authorizer = generateKeyPairSync('ed25519');
  const manager = generateKeyPairSync('ed25519');
  const identity = generateKeyPairSync('ed25519');
  const receipt = generateKeyPairSync('ed25519');
  const activePolicy = policy(policyOverrides);
  const clock = { now: NOW };
  const signedBudget = signBudget({
    schemaVersion: 1,
    budgetId: 'budget-megacorp-2026-07',
    policyId: activePolicy.policyId,
    policyVersion: activePolicy.version,
    policyHash: policyHash(activePolicy),
    period: '2026-07',
    currency: activePolicy.currency,
    atomicScale: activePolicy.atomicScale,
    allocatedAtomic: '1000000000',
    effectiveAt: '2026-07-17T00:00:00.000Z',
    expiresAt: '2026-08-01T00:00:00.000Z',
    signerId: 'megacorp-finance',
    ...budgetOverrides,
  }, finance.privateKey);
  const registrationRows = registrations ?? [
    registration(),
    registration({ creatorId: 'kim', skillVersionHash: KIM_SKILL_HASH }),
  ];
  const skillRegistrations = Object.fromEntries(registrationRows.map((row) => [
    skillRegistrationKey(row.skillId, row.skillVersionHash),
    row,
  ]));
  const configuration = {
    signedBudget,
    policies: { [`${activePolicy.policyId}@${activePolicy.version}`]: activePolicy },
    skillRegistrations,
    financeSigners: { 'megacorp-finance': publicPem(finance) },
    managerSigners: { 'manager-alex': publicPem(manager) },
    credentialAuthorizers: {
      'megacorp-collar-authorizer': publicPem(authorizer),
      ...additionalCredentialAuthorizers,
    },
    identitySigners: { 'megacorp-identity': publicPem(identity) },
    receiptSigners: { 'megacorp-receipts': publicPem(receipt) },
    clock: () => clock.now,
    receiptSigner: {
      signerId: 'megacorp-receipts',
      sign: receiptSign
        ? (bytes) => receiptSign(bytes, receipt.privateKey)
        : (bytes) => cryptoSign(null, bytes, receipt.privateKey).toString('base64'),
    },
  };
  const state = createEngineState(configuration);
  return {
    store: new InMemoryEngineStore(state),
    activePolicy,
    finance,
    authorizer,
    manager,
    identity,
    receipt,
    clock,
    configuration,
  };
}

async function authorize(fx, quote, overrides = {}) {
  const snapshot = fx.store.snapshot();
  const self = quote.initiatingPrincipalId === quote.creatorId;
  const defaultApproval = self ? managerApproval(fx, quote) : null;
  return authorizeInternalInvocation({
    store: fx.store,
    quote,
    expectedRevision: snapshot.revision,
    expectedBudgetRevision: snapshot.budget.revision,
    reservationId: `res-${quote.invocationId}`,
    credentialNonce: nonce(`credential:${quote.invocationId}`),
    credentialIssuedAt: NOW,
    credentialExpiresAt: '2026-07-17T00:10:00.000Z',
    credentialAuthorizerId: 'megacorp-collar-authorizer',
    principalAttestation: principalAttestation(fx, quote),
    managerApproval: defaultApproval,
    ...overrides,
  });
}

async function executeSuccess(fx, quote, authorized, executor = null) {
  return executeAuthorizedInvocation({
    store: fx.store,
    quote,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: executor ?? (async () => ({
      kind: 'succeeded',
      executionCostAtomic: '700000',
      outputHash: OUTPUT_HASH,
    })),
  });
}

test('credential signatures bind principal, policy, Skill registration inputs, nonce, and expiry', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload = {
    schemaVersion: 1,
    credentialAuthorizerId: 'megacorp-collar-authorizer',
    invocationId: 'inv-001',
    reservationId: 'res-inv-001',
    idempotencyKey: 'run-ledger-recon-001',
    skillId: 'ledger-recon',
    skillVersionHash: SKILL_HASH,
    creatorId: 'sam',
    wielderId: 'megacorp-internal-agent',
    initiatingPrincipalId: 'jordan',
    principalAttestationId: 'principal-attestation-001',
    principalAttestationHash: `sha256:${'b'.repeat(64)}`,
    policyId: 'policy-megacorp-ledger-recon',
    policyVersion: 1,
    policyHash: `sha256:${'c'.repeat(64)}`,
    nonce: nonce('credential'),
    issuedAt: NOW,
    expiresAt: '2026-07-17T00:05:00.000Z',
  };
  const signed = signCredential(payload, privateKey);
  assert.equal(verifyCredential(signed, publicKey, NOW).initiatingPrincipalId, 'jordan');
  assert.throws(
    () => verifyCredential({ ...signed, policyHash: `sha256:${'d'.repeat(64)}` }, publicKey, NOW),
    /signature/,
  );
  assert.throws(() => verifyCredential(signed, publicKey, AFTER_EXPIRY), /expired/);
  assert.throws(
    () => signCredential({ ...payload, nonce: `0x${nonce('credential')}` }, privateKey),
    /lowercase 64-character hex/,
  );

  const rsa = generateKeyPairSync('rsa', { modulusLength: 512 });
  const rsaSigned = signCredential(payload, rsa.privateKey);
  assert.throws(() => verifyCredential(rsaSigned, rsa.publicKey, NOW), /Ed25519/);
  assert.throws(
    () => verifyCredential(
      signed,
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      NOW,
    ),
    /public SPKI PEM/,
  );
});

test('authorization requires an active engine-provisioned Skill version and canonical Creator', async (t) => {
  await t.test('missing and wrong hashes fail before reservation', async () => {
    const fx = fixture({
      registrations: [registration({ creatorId: 'kim', skillVersionHash: KIM_SKILL_HASH })],
    });
    const q = makeQuote(fx.activePolicy);
    await assert.rejects(() => authorize(fx, q), /Skill version is not provisioned/);
    assert.equal(fx.store.snapshot().revision, 0);
    await assert.rejects(
      () => authorize(fx, makeQuote(fx.activePolicy, 'wrong-hash', {
        skillVersionHash: UNKNOWN_SKILL_HASH,
      })),
      /Skill version is not provisioned/,
    );
    assert.equal(fx.store.snapshot().budget.reservedAtomic, '0');
  });

  await t.test('revoked and wrong-Creator registrations fail before reservation', async () => {
    const revoked = fixture({ registrations: [registration({ status: 'revoked' })] });
    await assert.rejects(
      () => authorize(revoked, makeQuote(revoked.activePolicy)),
      /registration is revoked/i,
    );
    assert.equal(revoked.store.snapshot().budget.reservedAtomic, '0');

    const wrongCreator = fixture({
      registrations: [registration({ creatorId: 'kim', skillVersionHash: SKILL_HASH })],
    });
    await assert.rejects(
      () => authorize(wrongCreator, makeQuote(wrongCreator.activePolicy)),
      /Creator does not match quote Creator/,
    );
    assert.equal(wrongCreator.store.snapshot().budget.reservedAtomic, '0');
  });

  await t.test('caller cannot inject or replace a registration at authorization', async () => {
    const fx = fixture();
    const q = makeQuote(fx.activePolicy);
    await assert.rejects(() => authorize(fx, q, {
      skillRegistration: registration({ creatorId: 'kim' }),
    }), /unknown key skillRegistration/);
    assert.equal(fx.store.snapshot().revision, 0);
  });
});

test('shared Wielder self policy is based on initiating principal, not agent identity', async () => {
  const fx = fixture();
  const sam = makeQuote(fx.activePolicy, 'sam-principal', {
    initiatingPrincipalId: 'sam',
  });
  await assert.rejects(
    () => authorize(fx, sam, { managerApproval: null }),
    /manager approval is required/,
  );
  assert.equal(fx.store.snapshot().revision, 0);
  const approved = await authorize(fx, sam);
  assert.equal(approved.invocation.initiatingPrincipalId, 'sam');

  const otherFx = fixture();
  const jordan = makeQuote(otherFx.activePolicy, 'jordan-principal');
  const nonSelf = await authorize(otherFx, jordan);
  assert.equal(nonSelf.invocation.wielderId, 'megacorp-internal-agent');
  assert.equal(nonSelf.invocation.initiatingPrincipalId, 'jordan');
});

test('principal attestation trust, binding, and nonce replay fail closed', async () => {
  const fx = fixture();
  const q1 = makeQuote(fx.activePolicy, 'principal-1');
  const tampered = {
    ...principalAttestation(fx, q1),
    principalId: 'sam',
  };
  await assert.rejects(
    () => authorize(fx, q1, { principalAttestation: tampered }),
    /binding does not match quote|signature/,
  );
  assert.equal(fx.store.snapshot().revision, 0);

  const attacker = generateKeyPairSync('ed25519');
  const untrusted = principalAttestation(
    fx,
    q1,
    { identitySignerId: 'attacker-identity' },
    attacker.privateKey,
  );
  await assert.rejects(
    () => authorize(fx, q1, { principalAttestation: untrusted }),
    /identity signer is not permitted/,
  );

  const sharedNonce = nonce('shared-principal-nonce');
  await authorize(fx, q1, {
    principalAttestation: principalAttestation(fx, q1, { nonce: sharedNonce }),
  });
  const q2 = makeQuote(fx.activePolicy, 'principal-2');
  await assert.rejects(
    () => authorize(fx, q2, {
      principalAttestation: principalAttestation(fx, q2, { nonce: sharedNonce }),
    }),
    /attestation nonce already consumed/,
  );
  assert.equal(Object.keys(fx.store.snapshot().reservations).length, 1);
});

test('direct signer-map verifiers reject inherited identity and manager entries', () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'inherited-verifier-keys');
  assert.throws(() => verifyPrincipalAttestation(principalAttestation(fx, q), {
    policy: fx.activePolicy,
    quote: q,
    identitySigners: Object.create({ 'megacorp-identity': publicPem(fx.identity) }),
    now: NOW,
  }), /identity signer trust map must be a plain object/);

  const selfQuote = makeQuote(fx.activePolicy, 'inherited-manager-key', {
    initiatingPrincipalId: 'sam',
  });
  assert.throws(() => verifyManagerApproval(managerApproval(fx, selfQuote), {
    policy: fx.activePolicy,
    quote: selfQuote,
    managerSigners: Object.create({ 'manager-alex': publicPem(fx.manager) }),
    now: NOW,
  }), /manager signer trust map must be a plain object/);
});

test('successful execution atomically commits policy-bound signed receipt and exact gross', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy);
  const authorized = await authorize(fx, q);
  assert.equal(authorized.reservation.state, 'reserved');
  assert.equal(authorized.credentialPayload.expiresAt, q.expiresAt);
  assert.equal(authorized.invocation.skillRegistrationId, 'registration-ledger-recon-sam-1111');
  const result = await executeSuccess(fx, q, authorized);
  assert.equal(result.invocation.state, 'succeeded');
  assert.equal(result.award.amountAtomic, '2000000');
  assert.equal(result.award.recipientId, 'sam');
  assert.equal(result.budget.consumedAtomic, '2750000');
  assert.equal(result.budget.releasedAtomic, '300000');
  assert.equal(result.allocation.journalEntries.length, 4);
  assert.equal(result.receipt.policyHash, policyHash(fx.activePolicy));
  assert.equal(result.receipt.initiatingPrincipalId, 'jordan');
  assert.equal(result.receipt.sequence, 1);
  assert.equal(receiptHash(result.receipt), result.receiptHash);
  const { signature: _signature, ...unsignedReceipt } = result.receipt;
  assert.deepEqual(
    verifyReceipt(result.receipt, { trustedReceiptSigners: fx.store.snapshot().receiptSigners }),
    unsignedReceipt,
  );
  assert.doesNotThrow(() => JSON.stringify(result));
});

test('execution captures an accessor-backed signed credential once before authorizer lookup', async () => {
  const alternateAuthorizer = generateKeyPairSync('ed25519');
  const alternateAuthorizerId = 'megacorp-alternate-authorizer';
  const fx = fixture({
    policyOverrides: {
      permittedCredentialAuthorizerIds: [
        'megacorp-collar-authorizer',
        alternateAuthorizerId,
      ],
    },
    additionalCredentialAuthorizers: {
      [alternateAuthorizerId]: publicPem(alternateAuthorizer),
    },
  });
  const q = makeQuote(fx.activePolicy, 'credential-snapshot');
  const authorized = await authorize(fx, q);
  const signedByAlternate = signCredential(
    authorized.credentialPayload,
    alternateAuthorizer.privateKey,
  );
  let authorizerReads = 0;
  const switchingCredential = { ...signedByAlternate };
  Object.defineProperty(switchingCredential, 'credentialAuthorizerId', {
    enumerable: true,
    configurable: true,
    get() {
      authorizerReads += 1;
      return authorizerReads === 1
        ? alternateAuthorizerId
        : 'megacorp-collar-authorizer';
    },
  });
  let executorCalls = 0;

  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: switchingCredential,
    executor: async () => {
      executorCalls += 1;
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
  }), /credential signature|credential payload/i);

  assert.equal(authorizerReads, 1);
  assert.equal(executorCalls, 0);
  assert.equal(fx.store.snapshot().invocations[q.invocationId].state, 'authorized');
});

test('consumed terminal credentials reject and never invoke executor again', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'retry');
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  const first = await executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => {
      calls += 1;
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
  });
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => {
      calls += 1;
      throw new Error('must not execute');
    },
  }), /credential already consumed|terminal|reservation.*consumed/i);
  assert.equal(calls, 1);
  assert.equal(first.invocation.state, 'succeeded');
  assert.equal(Object.keys(fx.store.snapshot().receipts).length, 1);
});

test('terminal replay captures an accessor-backed signed credential once before verification', async () => {
  const alternateAuthorizer = generateKeyPairSync('ed25519');
  const alternateAuthorizerId = 'megacorp-alternate-authorizer';
  const fx = fixture({
    policyOverrides: {
      permittedCredentialAuthorizerIds: [
        'megacorp-collar-authorizer',
        alternateAuthorizerId,
      ],
    },
    additionalCredentialAuthorizers: {
      [alternateAuthorizerId]: publicPem(alternateAuthorizer),
    },
  });
  const q = makeQuote(fx.activePolicy, 'terminal-credential-snapshot');
  const authorized = await authorize(fx, q);
  await executeSuccess(fx, q, authorized);
  const signedByAlternate = signCredential(
    authorized.credentialPayload,
    alternateAuthorizer.privateKey,
  );
  let authorizerReads = 0;
  const switchingCredential = { ...signedByAlternate };
  Object.defineProperty(switchingCredential, 'credentialAuthorizerId', {
    enumerable: true,
    configurable: true,
    get() {
      authorizerReads += 1;
      return authorizerReads === 1
        ? alternateAuthorizerId
        : 'megacorp-collar-authorizer';
    },
  });
  let executorCalls = 0;

  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: switchingCredential,
    executor: async () => {
      executorCalls += 1;
      throw new Error('terminal replay must not invoke executor');
    },
  }), /credential signature|credential payload/i);

  assert.equal(authorizerReads, 1);
  assert.equal(executorCalls, 0);
});

test('validated known failure records exactly one shared-kernel execution COGS row', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'failure');
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  const result = await executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => {
      calls += 1;
      return {
        kind: 'failed_after_start',
        executionCostAtomic: '700000',
        failureClass: 'provider_error',
      };
    },
  });
  assert.equal(result.invocation.state, 'failed');
  assert.equal(result.budget.consumedAtomic, '700000');
  assert.equal(result.budget.releasedAtomic, '2350000');
  assert.equal(result.award, null);
  assert.deepEqual(result.invocation.journalEntries, [{
    category: 'execution-cogs',
    debitAccountId: 'employer:invocation-gross',
    creditAccountId: 'provider:execution',
    amountAtomic: '700000',
  }]);
  assert.deepEqual(result.receipt.journalEntries, result.invocation.journalEntries);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store, quote: q, credential,
    executor: async () => { calls += 1; return {}; },
  }), /credential already consumed|terminal/i);
  assert.equal(calls, 1);
});

test('malformed and unknown-cost outcomes hold the full reservation without journals or award', async (t) => {
  const outcomes = [
    ['throw', async () => { throw new Error('provider vanished'); }],
    ['explicit executor_threw', async () => ({ kind: 'unresolved_after_start', reason: 'executor_threw' })],
    ['explicit malformed_outcome', async () => ({ kind: 'unresolved_after_start', reason: 'malformed_outcome' })],
    ['explicit cost_unknown', async () => ({ kind: 'unresolved_after_start', reason: 'cost_unknown' })],
    ['unknown kind', async () => ({ kind: 'mystery' })],
    ['missing success cost', async () => ({ kind: 'succeeded', outputHash: OUTPUT_HASH })],
    ['negative cost', async () => ({ kind: 'failed_after_start', executionCostAtomic: '-1', failureClass: 'provider_error' })],
    ['decimal cost', async () => ({ kind: 'failed_after_start', executionCostAtomic: '1.5', failureClass: 'provider_error' })],
    ['non-string cost', async () => ({ kind: 'failed_after_start', executionCostAtomic: 1, failureClass: 'provider_error' })],
    ['over-cap cost', async () => ({ kind: 'failed_after_start', executionCostAtomic: '1000001', failureClass: 'provider_error' })],
    ['extra outcome key', async () => ({ kind: 'succeeded', executionCostAtomic: '1', outputHash: OUTPUT_HASH, surprise: true })],
    ['malformed success hash', async () => ({ kind: 'succeeded', executionCostAtomic: '1', outputHash: 'bad' })],
    ['missing failure cost', async () => ({ kind: 'failed_after_start', failureClass: 'provider_error' })],
    ['invalid failure class', async () => ({ kind: 'failed_after_start', executionCostAtomic: '1', failureClass: 'timeout' })],
  ];
  for (const [index, [label, executor]] of outcomes.entries()) {
    await t.test(label, async () => {
      const fx = fixture();
      const q = makeQuote(fx.activePolicy, `unresolved-${index}`);
      const authorized = await authorize(fx, q);
      let calls = 0;
      const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
      const result = await executeAuthorizedInvocation({
        store: fx.store,
        quote: q,
        credential,
        executor: async (...args) => { calls += 1; return executor(...args); },
      });
      assert.equal(result.invocation.state, 'unresolved');
      assert.equal(result.reservation.state, 'held_unresolved');
      assert.equal(result.budget.reservedAtomic, '3050000');
      assert.equal(result.budget.consumedAtomic, '0');
      assert.equal(result.budget.releasedAtomic, '0');
      assert.equal(result.award, null);
      assert.equal(result.invocation.executionCostAtomic, null);
      assert.deepEqual(result.receipt.journalEntries, []);
      assert.ok(Object.hasOwn(result.state.consumedNonces, authorized.credentialPayload.nonce));
      assert.equal(result.events.filter((event) => event.type === 'execution_cost_unresolved').length, 1);
      assert.equal(result.events.some((event) => event.type === 'budget_consumed'), false);
      assert.equal(result.events.some((event) => event.type === 'budget_released'), false);
      await assert.rejects(() => executeAuthorizedInvocation({
        store: fx.store,
        quote: q,
        credential,
        executor: async () => { calls += 1; return {}; },
      }), /credential already consumed|terminal|held_unresolved/i);
      assert.equal(calls, 1);
    });
  }
});

test('cancellation atomically signs one journal-free terminal receipt', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'cancel');
  const authorized = await authorize(fx, q);
  const cancelled = await cancelInternalAuthorization({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    reservationId: authorized.reservation.reservationId,
    reason: 'operator_cancelled',
  });
  assert.equal(cancelled.invocation.state, 'cancelled');
  assert.equal(cancelled.receipt.sequence, 1);
  assert.deepEqual(cancelled.receipt.journalEntries, []);
  assert.equal(cancelled.state.nextReceiptSequences[cancelled.receipt.receiptSequenceScope], 2);
  assert.equal(Object.keys(cancelled.state.receipts).length, 1);
  let executorCalls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: async () => { executorCalls += 1; return {}; },
  }), /cancelled|released|terminal/i);
  assert.equal(executorCalls, 0);
});

test('receipt sequence is independent per employer, Creator, currency, and scale', async () => {
  const fx = fixture();
  const cases = [
    makeQuote(fx.activePolicy, 'sam-1'),
    makeQuote(fx.activePolicy, 'kim-1', {
      creatorId: 'kim',
      skillVersionHash: KIM_SKILL_HASH,
    }),
    makeQuote(fx.activePolicy, 'sam-2'),
  ];
  const sequences = [];
  for (const q of cases) {
    const authorized = await authorize(fx, q);
    const result = await executeSuccess(fx, q, authorized);
    sequences.push(result.receipt.sequence);
  }
  assert.deepEqual(sequences, [1, 1, 2]);
  assert.equal(Object.keys(fx.store.snapshot().nextReceiptSequences).length, 2);
});

test('signing failure commits neither terminal state nor receipt and does not re-execute', async () => {
  let signerCalls = 0;
  const fx = fixture({
    receiptSign: (bytes, privateKey) => {
      signerCalls += 1;
      if (signerCalls > 1) throw new Error('HSM unavailable');
      return cryptoSign(null, bytes, privateKey).toString('base64');
    },
  });
  const q = makeQuote(fx.activePolicy, 'sign-failure');
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => {
      calls += 1;
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
  }), /HSM unavailable/);
  const snapshot = fx.store.snapshot();
  assert.equal(calls, 1);
  assert.equal(signerCalls, 2);
  assert.equal(snapshot.invocations[q.invocationId].state, 'executing');
  assert.equal(Object.keys(snapshot.receipts).length, 0);
  assert.equal(Object.keys(snapshot.awards).length, 0);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => { calls += 1; return {}; },
  }), /already in progress|reconciliation/);
  assert.equal(calls, 1);
});

test('serialized CAS permits only one execution, award, and signed receipt', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'race');
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  const run = () => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => {
      calls += 1;
      await Promise.resolve();
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
  });
  const results = await Promise.allSettled([run(), run()]);
  assert.equal(results.filter((result) => result.status === 'fulfilled').length, 1);
  assert.equal(calls, 1);
  assert.equal(Object.keys(fx.store.snapshot().awards).length, 1);
  assert.equal(Object.keys(fx.store.snapshot().receipts).length, 1);
});

test('active Skill registration and signed budget trust are re-established before executor start', async () => {
  const fx = fixture({
    registrations: [registration({ expiresAt: '2026-07-17T00:02:00.000Z' })],
  });
  const q = makeQuote(fx.activePolicy, 'registration-expiry');
  const authorized = await authorize(fx, q);
  fx.clock.now = '2026-07-17T00:03:00.000Z';
  let calls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: async () => { calls += 1; return {}; },
  }), /Skill registration expired/);
  assert.equal(calls, 0);

  const fabricated = Object.freeze({ ...fx.store.snapshot() });
  const fabricatedStore = new InMemoryEngineStore(fabricated);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fabricatedStore,
    quote: q,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: async () => { calls += 1; return {}; },
  }), /trusted engine boundary/);
  assert.equal(calls, 0);
});

test('July authorization is capped at month end and cannot execute in August', async () => {
  const augustStart = '2026-08-01T00:00:00.000Z';
  const septemberStart = '2026-09-01T00:00:00.000Z';
  const fx = fixture({
    policyOverrides: { expiresAt: septemberStart },
    registrations: [registration({ expiresAt: septemberStart })],
  });
  const q = makeQuote(fx.activePolicy, 'cross-period', {
    expiresAt: '2026-08-02T00:00:00.000Z',
  });
  const authorized = await authorize(fx, q, {
    credentialExpiresAt: q.expiresAt,
    principalAttestation: principalAttestation(fx, q, { expiresAt: q.expiresAt }),
  });
  assert.equal(authorized.credentialPayload.expiresAt, augustStart);

  fx.clock.now = '2026-08-01T00:01:00.000Z';
  let executorCalls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: async () => {
      executorCalls += 1;
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
  }), /outside the active employer budget period/);
  assert.equal(executorCalls, 0);
  const snapshot = fx.store.snapshot();
  assert.equal(snapshot.invocations[q.invocationId].state, 'authorized');
  assert.equal(snapshot.reservations[authorized.reservation.reservationId].state, 'reserved');
  assert.equal(Object.keys(snapshot.receipts).length, 0);
  assert.equal(Object.keys(snapshot.awards).length, 0);
});

test('canonical policy bytes are bound through budget, quote, credential, Invocation, award, and receipt', async () => {
  const fx = fixture();
  const mutated = {
    ...fx.activePolicy,
    maxAwardPerPeriodAtomic: '99999999',
  };
  assert.throws(() => createEngineState({
    ...fx.configuration,
    policies: { [`${mutated.policyId}@${mutated.version}`]: mutated },
  }), /policyHash/);

  const q = makeQuote(fx.activePolicy, 'policy-hash');
  await assert.rejects(() => authorize(fx, { ...q, policyHash: policyHash(mutated) }), /policyHash/);
  const authorized = await authorize(fx, q);
  const result = await executeSuccess(fx, q, authorized);
  for (const value of [
    authorized.credentialPayload.policyHash,
    authorized.invocation.policyHash,
    result.award.policyHash,
    result.receipt.policyHash,
  ]) assert.equal(value, policyHash(fx.activePolicy));
});

test('employer cannot become a positive employee award recipient at any engine boundary', () => {
  assert.throws(
    () => fixture({ policyOverrides: { permittedCreatorIds: ['sam', 'megacorp'] } }),
    /employer cannot be a permitted employee-Creator/,
  );
  assert.throws(
    () => fixture({ registrations: [registration({ creatorId: 'megacorp' })] }),
    /employer cannot be the employee-Creator/,
  );
});

test('lifecycle callers cannot inject clocks, signer capabilities, or registration maps', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'injection');
  await assert.rejects(() => authorize(fx, q, { now: NOW }), /unknown key now/);
  await assert.rejects(() => authorize(fx, q, { receiptSigner: {} }), /unknown key receiptSigner/);
  assert.equal(fx.store.snapshot().revision, 0);
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => ({}),
    now: NOW,
  }), /unknown key now/);
  await assert.rejects(() => cancelInternalAuthorization({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    reservationId: authorized.reservation.reservationId,
    reason: 'cancel',
    receiptSigner: {},
  }), /unknown key receiptSigner/);
});

test('period cap counts every open maximum exposure', async () => {
  const fx = fixture({ policyOverrides: { maxAwardPerPeriodAtomic: '3000000' } });
  await authorize(fx, makeQuote(fx.activePolicy, 'cap-1'));
  await assert.rejects(
    () => authorize(fx, makeQuote(fx.activePolicy, 'cap-2')),
    /period award cap/,
  );
  assert.equal(Object.keys(fx.store.snapshot().reservations).length, 1);
});

test('period cap retains committed future-policy awards after successful Invocations', async () => {
  const fx = fixture({
    policyOverrides: {
      maxAwardPerPeriodAtomic: '3000000',
      vestingRule: 'future_policy_controlled',
    },
  });
  const firstQuote = makeQuote(fx.activePolicy, 'vesting-cap-1');
  const firstAuthorization = await authorize(fx, firstQuote);
  const first = await executeSuccess(fx, firstQuote, firstAuthorization);

  assert.equal(first.invocation.state, 'succeeded');
  assert.equal(first.award.state, 'vesting_pending');
  assert.equal(first.award.amountAtomic, '2000000');

  const secondQuote = makeQuote(fx.activePolicy, 'vesting-cap-2');
  await assert.rejects(() => authorize(fx, secondQuote), /period award cap/);
  const snapshot = fx.store.snapshot();
  assert.equal(Object.keys(snapshot.awards).length, 1);
  assert.equal(Object.hasOwn(snapshot.invocations, secondQuote.invocationId), false);
});

test('authorization Promise race, idempotency, and reservation bindings fail closed', async () => {
  const fx = fixture();
  const q1 = makeQuote(fx.activePolicy, 'authorize-race-1');
  const q2 = makeQuote(fx.activePolicy, 'authorize-race-2');
  const raced = await Promise.allSettled([authorize(fx, q1), authorize(fx, q2)]);
  assert.equal(raced.filter((row) => row.status === 'fulfilled').length, 1);
  assert.equal(raced.filter((row) => row.status === 'rejected').length, 1);
  assert.match(raced.find((row) => row.status === 'rejected').reason.message, /stale engine revision/);
  assert.equal(Object.keys(fx.store.snapshot().reservations).length, 1);
  assert.equal(Object.keys(fx.store.snapshot().idempotency).length, 1);

  const winner = raced.find((row) => row.status === 'fulfilled').value;
  const winnerQuote = winner.invocation.invocationId === q1.invocationId ? q1 : q2;
  await assert.rejects(() => authorize(fx, makeQuote(fx.activePolicy, 'idempotency-replay', {
    idempotencyKey: winnerQuote.idempotencyKey,
  })), /idempotency key already bound/);

  const other = winnerQuote === q1 ? q2 : q1;
  let calls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: other,
    credential: signCredential(winner.credentialPayload, fx.authorizer.privateKey),
    executor: async () => { calls += 1; return {}; },
  }), /no persisted authorization|credential.*match|quote.*match/i);
  assert.equal(calls, 0);
});

test('credential and manager signer, authorizer, and reservation bindings reject before execution', async () => {
  const fx = fixture();
  const q = makeQuote(fx.activePolicy, 'binding');
  const authorized = await authorize(fx, q);
  let calls = 0;
  const executor = async () => { calls += 1; return {}; };
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store, quote: q, credential: null, executor,
  }), /credential authorizer|credential/i);
  const attacker = generateKeyPairSync('ed25519');
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: signCredential(authorized.credentialPayload, attacker.privateKey),
    executor,
  }), /signature/);
  const wrongReservationCredential = signCredential({
    ...authorized.credentialPayload,
    reservationId: 'res-attacker',
  }, fx.authorizer.privateKey);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store, quote: q, credential: wrongReservationCredential, executor,
  }), /credential does not match persisted authorization/);
  assert.equal(calls, 0);

  const selfFx = fixture();
  const selfQuote = makeQuote(selfFx.activePolicy, 'manager-binding', {
    initiatingPrincipalId: 'sam',
  });
  const otherQuote = makeQuote(selfFx.activePolicy, 'manager-other', {
    initiatingPrincipalId: 'sam',
  });
  await assert.rejects(() => authorize(selfFx, selfQuote, {
    managerApproval: managerApproval(selfFx, otherQuote),
  }), /manager approval.*binding|invocation/i);
  await assert.rejects(() => authorize(selfFx, selfQuote, {
    managerApproval: signManagerApproval({
      ...(() => {
        const { signature: _signature, ...payload } = managerApproval(selfFx, selfQuote);
        return payload;
      })(),
      managerSignerId: 'unknown-manager',
    }, attacker.privateKey),
  }), /manager signer is not permitted|not provisioned/);
  assert.equal(selfFx.store.snapshot().revision, 0);
});

test('required policy, budget, signer, and lifecycle rejections happen before executor start', async (t) => {
  await t.test('unauthorized Wielder, quote cap, underfunding, and expired budget', async () => {
    const unauthorized = fixture();
    await assert.rejects(() => authorize(
      unauthorized,
      makeQuote(unauthorized.activePolicy, 'bad-wielder', { wielderId: 'outsider-agent' }),
    ), /Wielder is not permitted/);
    assert.equal(unauthorized.store.snapshot().revision, 0);

    const overCap = fixture();
    await assert.rejects(() => authorize(overCap, makeQuote(overCap.activePolicy, 'over-cap', {
      maxExecutionCostAtomic: '2000000',
      maxGrossAtomic: '4050000',
    })), /maxGrossAtomic exceeds policy/);
    assert.equal(overCap.store.snapshot().revision, 0);

    const underfunded = fixture({ budgetOverrides: { allocatedAtomic: '1000000' } });
    await assert.rejects(
      () => authorize(underfunded, makeQuote(underfunded.activePolicy, 'underfunded')),
      /insufficient remaining budget/,
    );
    assert.equal(underfunded.store.snapshot().revision, 0);

    const expired = fixture({ budgetOverrides: { expiresAt: '2026-07-17T00:02:00.000Z' } });
    expired.clock.now = '2026-07-17T00:03:00.000Z';
    await assert.rejects(
      () => authorize(expired, makeQuote(expired.activePolicy, 'expired-budget')),
      /budget authorization expired/,
    );
    assert.equal(expired.store.snapshot().revision, 0);
  });

  await t.test('manager approval is independent, bound, current, trusted, and key-injection-free', async () => {
    const fx = fixture();
    const q = makeQuote(fx.activePolicy, 'manager-matrix', { initiatingPrincipalId: 'sam' });
    const attacker = generateKeyPairSync('ed25519');
    const common = {
      schemaVersion: 1,
      approvalId: 'approval-manager-matrix',
      invocationId: q.invocationId,
      creatorId: q.creatorId,
      policyId: q.policyId,
      policyVersion: q.policyVersion,
      issuedAt: '2026-07-17T00:00:00.000Z',
      expiresAt: q.expiresAt,
    };
    await assert.rejects(() => authorize(fx, q, { managerApproval: signManagerApproval({
      ...common, managerSignerId: 'sam',
    }, attacker.privateKey) }), /cannot self-approve/);
    await assert.rejects(() => authorize(fx, q, { managerApproval: signManagerApproval({
      ...common, managerSignerId: 'unknown-manager',
    }, attacker.privateKey) }), /manager signer is not permitted/);
    await assert.rejects(() => authorize(fx, q, { managerApproval: signManagerApproval({
      ...common,
      managerSignerId: 'manager-alex',
      issuedAt: '2026-07-17T00:00:00.000Z',
      expiresAt: '2026-07-17T00:00:30.000Z',
    }, fx.manager.privateKey) }), /manager approval expired/);
    await assert.rejects(() => authorize(fx, q, {
      managerApproval: { ...managerApproval(fx, q), publicKeyPem: publicPem(fx.manager) },
    }), /unknown key publicKeyPem/);
    assert.equal(fx.store.snapshot().revision, 0);
  });

  await t.test('credential requires persisted exact reservation and trusted policy authorizer', async () => {
    const source = fixture();
    const q1 = makeQuote(source.activePolicy, 'credential-a');
    const q2 = makeQuote(source.activePolicy, 'credential-b');
    const a = await authorize(source, q1);
    const b = await authorize(source, q2);
    const credentialA = signCredential(a.credentialPayload, source.authorizer.privateKey);
    let calls = 0;
    const executor = async () => { calls += 1; return {}; };
    await assert.rejects(() => executeAuthorizedInvocation({
      store: source.store, quote: q2, credential: credentialA, executor,
    }), /credential does not match persisted authorization/);
    await assert.rejects(() => executeAuthorizedInvocation({
      store: source.store, quote: q1,
      credential: { ...credentialA, publicKeyPem: publicPem(source.authorizer) },
      executor,
    }), /unknown key publicKeyPem/);
    await assert.rejects(() => executeAuthorizedInvocation({
      store: source.store, quote: q1, credential: credentialA, executor,
      publicKey: source.authorizer.publicKey,
    }), /unknown key publicKey/);

    const empty = fixture();
    await assert.rejects(() => executeAuthorizedInvocation({
      store: empty.store, quote: q1, credential: credentialA, executor,
    }), /no persisted authorization/);
    const disallowed = fixture();
    await assert.rejects(() => authorize(disallowed, makeQuote(disallowed.activePolicy, 'authorizer'), {
      credentialAuthorizerId: 'attacker-authorizer',
    }), /credential authorizer is not permitted/);
    assert.equal(calls, 0);
    assert.equal(Object.hasOwn(b.credentialPayload, 'signature'), false);
  });
});

test('finance-authenticated append-only earned reversals reduce period exposure exactly once after verification', async () => {
  const fx = fixture({ policyOverrides: { maxAwardPerPeriodAtomic: '3000000' } });
  const q1 = makeQuote(fx.activePolicy, 'reversal-cap-1');
  const firstAuthorization = await authorize(fx, q1);
  const first = await executeSuccess(fx, q1, firstAuthorization);
  const q2 = makeQuote(fx.activePolicy, 'reversal-cap-2');
  await assert.rejects(() => authorize(fx, q2), /period award cap/);

  const unsignedReversal = {
    schemaVersion: 1,
    reversalId: 'award-reversal-001',
    awardId: first.award.awardId,
    invocationId: first.invocation.invocationId,
    receiptHash: first.receiptHash,
    policyId: first.award.policyId,
    policyVersion: first.award.policyVersion,
    policyHash: first.award.policyHash,
    amountAtomic: '1000000',
    reason: 'finance_authenticated_correction',
    issuedAt: fx.clock.now,
    signerId: 'megacorp-finance',
  };
  assert.ok(canonicalAwardReversalBytes(unsignedReversal) instanceof Uint8Array);
  const attacker = generateKeyPairSync('ed25519');
  const accessorBacked = {
    ...signAwardReversal(unsignedReversal, fx.finance.privateKey),
  };
  const signatureValue = accessorBacked.signature;
  Object.defineProperty(accessorBacked, 'signature', {
    enumerable: true,
    get: () => signatureValue,
  });
  await assert.rejects(() => recordAwardReversal({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    signedReversal: accessorBacked,
  }), /signature must be an enumerable data property/);
  assert.equal(Object.keys(fx.store.snapshot().awardReversals).length, 0);
  await assert.rejects(() => recordAwardReversal({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    signedReversal: signAwardReversal(unsignedReversal, attacker.privateKey),
  }), /signature/);
  assert.equal(Object.keys(fx.store.snapshot().awardReversals).length, 0);

  const recorded = await recordAwardReversal({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    signedReversal: signAwardReversal(unsignedReversal, fx.finance.privateKey),
  });
  assert.equal(recorded.reversal.amountAtomic, '1000000');
  assert.equal(recorded.event.type, 'invocation_award_reversed');
  await assert.rejects(() => recordAwardReversal({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    signedReversal: signAwardReversal(unsignedReversal, fx.finance.privateKey),
  }), /reversal identifier already exists/);
  await assert.rejects(() => recordAwardReversal({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    signedReversal: signAwardReversal({
      ...unsignedReversal,
      reversalId: 'award-reversal-over-earned',
      amountAtomic: '1000001',
    }, fx.finance.privateKey),
  }), /cumulative award reversal exceeds earned award/);
  assert.equal(Object.keys(fx.store.snapshot().awardReversals).length, 1);
  const second = await authorize(fx, q2);
  assert.equal(second.reservation.state, 'reserved');
  const secondResult = await executeSuccess(fx, q2, second);
  assert.equal(secondResult.award.state, 'earned');

  const q3 = makeQuote(fx.activePolicy, 'reversal-cap-3', {
    maxInvocationAwardAtomic: '1000000',
    maxGrossAtomic: '2050000',
  });
  await assert.rejects(() => authorize(fx, q3), /period award cap/);
  assert.equal(Object.keys(fx.store.snapshot().awardReversals).length, 1);
});

test('executions crossing period close terminally hold with honest recognition time and no late award', async (t) => {
  const julyStart = '2026-07-31T23:59:00.000Z';
  const august = '2026-08-01T00:01:00.000Z';
  const september = '2026-09-01T00:00:00.000Z';
  const cases = [
    ['success', async (fx) => {
      fx.clock.now = august;
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    }, 'known', '700000'],
    ['known failure', async (fx) => {
      fx.clock.now = august;
      return { kind: 'failed_after_start', executionCostAtomic: '600000', failureClass: 'provider_error' };
    }, 'known', '600000'],
    ['unknown cost', async (fx) => {
      fx.clock.now = august;
      return { kind: 'unresolved_after_start', reason: 'cost_unknown' };
    }, 'unresolved', null],
  ];
  for (const [label, outcome, costStatus, cost] of cases) {
    await t.test(label, async () => {
      const fx = fixture({
        policyOverrides: { expiresAt: september },
        registrations: [registration({ expiresAt: september })],
      });
      fx.clock.now = julyStart;
      const q = makeQuote(fx.activePolicy, `clock-crossing-${label.replace(' ', '-')}`, {
        expiresAt: '2026-08-02T00:00:00.000Z',
      });
      const authorized = await authorize(fx, q, {
        credentialIssuedAt: julyStart,
        credentialExpiresAt: q.expiresAt,
        principalAttestation: principalAttestation(fx, q, {
          issuedAt: julyStart,
          expiresAt: q.expiresAt,
        }),
      });
      const result = await executeAuthorizedInvocation({
        store: fx.store,
        quote: q,
        credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
        executor: () => outcome(fx),
      });
      assert.equal(result.invocation.state, 'unresolved');
      assert.equal(result.reservation.state, 'held_unresolved');
      assert.equal(result.invocation.executionCostStatus, costStatus);
      assert.equal(result.invocation.executionCostAtomic, cost);
      assert.equal(result.invocation.invocationAwardAtomic, '0');
      assert.equal(result.award, null);
      assert.equal(result.budget.reservedAtomic, '3050000');
      assert.equal(result.receipt.period, '2026-08');
      assert.equal(result.receipt.budgetPeriod, '2026-07');
      assert.equal(result.receipt.occurredAt, august);
      assert.deepEqual(result.receipt.journalEntries, []);
      assert.equal(result.events.some((event) => event.type === 'budget_consumed'), false);
      assert.equal(result.events.some((event) => event.type === 'budget_released'), false);
      assert.equal(result.events.some((event) => event.type === (
        costStatus === 'known' ? 'execution_period_closed' : 'execution_cost_unresolved'
      )), true);
    });
  }
});

test('historically authenticated reserved authorization can be cancelled after expiry', async () => {
  const september = '2026-09-01T00:00:00.000Z';
  const fx = fixture({
    policyOverrides: { expiresAt: september },
    registrations: [registration({ expiresAt: september })],
  });
  const q = makeQuote(fx.activePolicy, 'late-cancel', { expiresAt: '2026-08-02T00:00:00.000Z' });
  const authorized = await authorize(fx, q, {
    credentialExpiresAt: q.expiresAt,
    principalAttestation: principalAttestation(fx, q, { expiresAt: q.expiresAt }),
  });
  fx.clock.now = '2026-08-02T00:01:00.000Z';
  const cancelled = await cancelInternalAuthorization({
    store: fx.store,
    expectedRevision: fx.store.snapshot().revision,
    reservationId: authorized.reservation.reservationId,
    reason: 'expired_authorization_released_by_operator',
  });
  assert.equal(cancelled.invocation.state, 'cancelled');
  assert.equal(cancelled.reservation.state, 'released');
  assert.equal(cancelled.receipt.period, '2026-08');
  assert.equal(cancelled.receipt.budgetPeriod, '2026-07');
  assert.equal(cancelled.receipt.occurredAt, fx.clock.now);
  assert.equal(cancelled.budget.reservedAtomic, '0');
  assert.equal(cancelled.budget.releasedAtomic, '3050000');
});

test('engine configuration requires exact immutable trust roots and keeps capabilities private', () => {
  const fx = fixture();
  const snapshot = fx.store.snapshot();
  assert.ok(Object.isFrozen(snapshot.skillRegistrations));
  assert.ok(Object.isFrozen(snapshot.identitySigners));
  assert.equal(Object.hasOwn(snapshot, 'clock'), false);
  assert.equal(Object.hasOwn(snapshot, 'receiptSigner'), false);
  assert.throws(() => createEngineState({
    ...fx.configuration,
    identitySigners: {},
  }), /missing trusted identity signer/);
  assert.throws(() => createEngineState({
    ...fx.configuration,
    receiptSigners: { ...fx.configuration.receiptSigners, attacker: publicPem(fx.receipt) },
  }), /unexpected receipt signer attacker/);
});

test('engine provisioning rejects non-Ed25519, private PEM, and mismatched receipt capabilities', () => {
  const fx = fixture();
  const rsa = generateKeyPairSync('rsa', { modulusLength: 512 });
  const rsaPem = publicPem(rsa);
  for (const [field, signerId] of [
    ['financeSigners', 'megacorp-finance'],
    ['managerSigners', 'manager-alex'],
    ['credentialAuthorizers', 'megacorp-collar-authorizer'],
    ['identitySigners', 'megacorp-identity'],
    ['receiptSigners', 'megacorp-receipts'],
  ]) {
    assert.throws(() => createEngineState({
      ...fx.configuration,
      [field]: { [signerId]: rsaPem },
    }), /Ed25519/);
  }

  const privatePem = fx.finance.privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => createEngineState({
    ...fx.configuration,
    financeSigners: { 'megacorp-finance': privatePem },
  }), /public SPKI PEM/);
  assert.equal(JSON.stringify(fx.store.snapshot()).includes('PRIVATE KEY'), false);

  const attacker = generateKeyPairSync('ed25519');
  assert.throws(() => createEngineState({
    ...fx.configuration,
    receiptSigner: {
      signerId: 'megacorp-receipts',
      sign: (bytes) => cryptoSign(null, bytes, attacker.privateKey).toString('base64'),
    },
  }), /receipt signer provisioning challenge failed/);
});

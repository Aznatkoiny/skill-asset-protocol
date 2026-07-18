import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import { signBudget } from '../src/budget.mjs';
import {
  signCredential,
  signManagerApproval,
  verifyCredential,
} from '../src/credentials.mjs';
import {
  authorizeInternalInvocation,
  cancelInternalAuthorization,
  createEngineState,
  executeAuthorizedInvocation,
} from '../src/engine.mjs';
import { InMemoryEngineStore } from '../src/store.mjs';

const NOW = '2026-07-17T00:01:00.000Z';
const AFTER_EXPIRY = '2026-07-17T00:06:00.000Z';
const SKILL_HASH = `sha256:${'1'.repeat(64)}`;
const OUTPUT_HASH = `sha256:${'a'.repeat(64)}`;

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
    permittedCreatorIds: ['sam'],
    permittedWielderIds: ['megacorp-internal-agent'],
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
    permittedFinanceSignerIds: ['megacorp-finance'],
    vestingRule: 'none',
    paymentSchedule: 'monthly_in_arrears',
    terminationTreatment: 'earned_remains_payable_unearned_cancelled',
    paymentRail: 'employer_payroll_or_ap',
    ...overrides,
  };
}

function quote(suffix = '001', overrides = {}) {
  return {
    schemaVersion: 1,
    quoteId: `quote-inv-${suffix}`,
    invocationId: `inv-${suffix}`,
    idempotencyKey: `run-ledger-recon-${suffix}`,
    skillId: 'ledger-recon',
    skillVersionHash: SKILL_HASH,
    creatorId: 'sam',
    wielderId: 'megacorp-internal-agent',
    beneficiaryId: 'megacorp',
    costCenter: 'platform-engineering',
    policyId: 'policy-megacorp-ledger-recon',
    policyVersion: 1,
    maxExecutionCostAtomic: '1000000',
    protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000',
    maxInvocationAwardAtomic: '2000000',
    maxGrossAtomic: '3050000',
    expiresAt: '2026-07-17T00:05:00.000Z',
    ...overrides,
  };
}

function nonce(number = 1) {
  return number.toString(16).padStart(64, '0');
}

function fixture({ policyOverrides = {}, budgetOverrides = {} } = {}) {
  const finance = generateKeyPairSync('ed25519');
  const authorizer = generateKeyPairSync('ed25519');
  const manager = generateKeyPairSync('ed25519');
  const activePolicy = policy(policyOverrides);
  const managerSignerId = activePolicy.permittedManagerSignerIds[0];
  const signedBudget = signBudget({
    schemaVersion: 1,
    budgetId: 'budget-megacorp-2026-07',
    policyId: activePolicy.policyId,
    policyVersion: activePolicy.version,
    period: '2026-07',
    currency: activePolicy.currency,
    atomicScale: activePolicy.atomicScale,
    allocatedAtomic: '1000000000',
    effectiveAt: '2026-07-17T00:00:00.000Z',
    expiresAt: '2026-08-01T00:00:00.000Z',
    signerId: 'megacorp-finance',
    ...budgetOverrides,
  }, finance.privateKey);
  const state = createEngineState({
    signedBudget,
    policies: { [`${activePolicy.policyId}@${activePolicy.version}`]: activePolicy },
    financeSigners: {
      'megacorp-finance': finance.publicKey.export({ type: 'spki', format: 'pem' }),
    },
    managerSigners: {
      [managerSignerId]: manager.publicKey.export({ type: 'spki', format: 'pem' }),
    },
    credentialAuthorizers: {
      'megacorp-collar-authorizer': authorizer.publicKey.export({ type: 'spki', format: 'pem' }),
    },
    now: NOW,
  });
  return {
    store: new InMemoryEngineStore(state),
    activePolicy,
    finance,
    authorizer,
    manager,
    managerSignerId,
  };
}

async function authorize(fx, q = quote(), overrides = {}) {
  return authorizeInternalInvocation({
    store: fx.store,
    quote: q,
    expectedRevision: 0,
    expectedBudgetRevision: 0,
    reservationId: `res-${q.invocationId}`,
    credentialNonce: nonce(1),
    credentialIssuedAt: NOW,
    credentialExpiresAt: '2026-07-17T00:10:00.000Z',
    credentialAuthorizerId: 'megacorp-collar-authorizer',
    managerApproval: null,
    now: NOW,
    ...overrides,
  });
}

test('credential signatures bind exact fields, lowercase nonce, and expiry', () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const payload = {
    schemaVersion: 1,
    credentialAuthorizerId: 'megacorp-collar-authorizer',
    invocationId: 'inv-001',
    reservationId: 'res-inv-001',
    idempotencyKey: 'run-ledger-recon-001',
    skillId: 'ledger-recon',
    skillVersionHash: SKILL_HASH,
    policyId: 'policy-megacorp-ledger-recon',
    policyVersion: 1,
    nonce: nonce(1),
    issuedAt: NOW,
    expiresAt: '2026-07-17T00:05:00.000Z',
  };
  const signed = signCredential(payload, privateKey);
  assert.equal(verifyCredential(signed, publicKey, NOW).invocationId, 'inv-001');
  assert.throws(
    () => verifyCredential({ ...signed, skillVersionHash: `sha256:${'2'.repeat(64)}` }, publicKey, NOW),
    /signature/,
  );
  assert.throws(() => verifyCredential(signed, publicKey, AFTER_EXPIRY), /expired/);
  assert.throws(() => signCredential({ ...payload, nonce: `0x${nonce(1)}` }, privateKey), /lowercase 64-character hex/);
});

test('authorization reserves before signing and successful execution conserves exact gross', async () => {
  const fx = fixture();
  const q = quote();
  const authorized = await authorize(fx, q);
  assert.equal(authorized.reservation.state, 'reserved');
  assert.equal(authorized.credentialPayload.expiresAt, q.expiresAt);
  assert.equal(authorized.invocation.state, 'authorized');
  assert.equal(authorized.invocation.externalRoyaltyCreditsAtomic, '0');
  assert.equal(authorized.invocation.employerSelfCreditAtomic, '0');

  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  const result = await executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => ({
      kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH,
    }),
    now: NOW,
  });
  assert.equal(result.invocation.state, 'succeeded');
  assert.equal(result.award.amountAtomic, '2000000');
  assert.equal(result.award.state, 'earned');
  assert.equal(result.budget.consumedAtomic, '2750000');
  assert.equal(result.budget.releasedAtomic, '300000');
  assert.equal(result.allocation.journalEntries.length, 4);
  assert.doesNotThrow(() => JSON.stringify(result));
  assert.doesNotThrow(() => JSON.stringify(result.state));
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => { throw new Error('must not run'); },
    now: NOW,
  }), /credential already consumed|Invocation is not authorized|idempotency/);
});

test('execution re-establishes signed budget trust and expiry at start', async () => {
  const fx = fixture({ budgetOverrides: { expiresAt: '2026-07-17T00:03:00.000Z' } });
  const q = quote();
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential,
    executor: async () => { calls += 1; return {}; },
    now: '2026-07-17T00:04:00.000Z',
  }), /budget authorization expired/);
  assert.equal(calls, 0);

  const fabricated = Object.freeze({ ...fx.store.snapshot() });
  const fabricatedStore = new InMemoryEngineStore(fabricated);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fabricatedStore,
    quote: q,
    credential,
    executor: async () => { calls += 1; return {}; },
    now: NOW,
  }), /trusted engine boundary/);
  assert.equal(calls, 0);
});

test('validated failure consumes exact COGS and creates no award', async () => {
  const fx = fixture();
  const q = quote();
  const authorized = await authorize(fx, q);
  const result = await executeAuthorizedInvocation({
    store: fx.store,
    quote: q,
    credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
    executor: async () => ({
      kind: 'failed_after_start', executionCostAtomic: '700000', failureClass: 'provider_error',
    }),
    now: NOW,
  });
  assert.equal(result.invocation.state, 'failed');
  assert.equal(result.budget.consumedAtomic, '700000');
  assert.equal(result.budget.releasedAtomic, '2350000');
  assert.equal(result.award, null);
});

test('every malformed or unknown-cost post-start outcome keeps the full hold and no award', async (t) => {
  const outcomes = [
    async () => { throw new Error('provider vanished'); },
    async () => ({ kind: 'unresolved_after_start', reason: 'cost_unknown' }),
    async () => ({ kind: 'unknown' }),
    async () => ({ kind: 'failed_after_start', failureClass: 'provider_error' }),
    async () => ({ kind: 'failed_after_start', executionCostAtomic: '-1', failureClass: 'provider_error' }),
    async () => ({ kind: 'failed_after_start', executionCostAtomic: '1.5', failureClass: 'provider_error' }),
    async () => ({ kind: 'failed_after_start', executionCostAtomic: 1, failureClass: 'provider_error' }),
    async () => ({ kind: 'failed_after_start', executionCostAtomic: '1000001', failureClass: 'provider_error' }),
    async () => ({ kind: 'failed_after_start', executionCostAtomic: '1', failureClass: 'provider_error', extra: true }),
    async () => ({ kind: 'succeeded', executionCostAtomic: '1', outputHash: 'bad' }),
  ];
  for (const [index, executor] of outcomes.entries()) {
    await t.test(`unresolved case ${index + 1}`, async () => {
      const fx = fixture();
      const q = quote(String(index + 1).padStart(3, '0'));
      const authorized = await authorize(fx, q, { credentialNonce: nonce(index + 1) });
      const result = await executeAuthorizedInvocation({
        store: fx.store,
        quote: q,
        credential: signCredential(authorized.credentialPayload, fx.authorizer.privateKey),
        executor,
        now: NOW,
      });
      assert.equal(result.invocation.state, 'unresolved');
      assert.equal(result.reservation.state, 'held_unresolved');
      assert.equal(result.budget.reservedAtomic, '3050000');
      assert.equal(result.budget.consumedAtomic, '0');
      assert.equal(result.budget.releasedAtomic, '0');
      assert.equal(result.award, null);
      assert.equal(result.invocation.executionCostAtomic, null);
      assert.ok(result.events.some((event) => event.type === 'execution_cost_unresolved'));
      assert.ok(Object.hasOwn(fx.store.snapshot().consumedNonces, authorized.credentialPayload.nonce));
    });
  }
});

test('pre-execution trust, identity, idempotency, and manager failures never call executor', async () => {
  const fx = fixture();
  await assert.rejects(() => authorize(fx, quote('001', { wielderId: 'outsider' })), /Wielder is not permitted/);
  assert.equal(fx.store.snapshot().revision, 0);

  const authorized = await authorize(fx);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  const attacker = generateKeyPairSync('ed25519');
  let calls = 0;
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: quote(),
    credential: signCredential(authorized.credentialPayload, attacker.privateKey),
    executor: async () => { calls += 1; return { kind: 'succeeded', executionCostAtomic: '0', outputHash: OUTPUT_HASH }; },
    now: NOW,
  }), /signature/);
  assert.equal(calls, 0);
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store,
    quote: quote(),
    credential: { ...credential, publicKeyPem: 'self-declared' },
    executor: async () => { calls += 1; return {}; },
    now: NOW,
  }), /unknown key publicKeyPem/);
  assert.equal(calls, 0);
});

test('self Invocation requires a separately signed, trusted, non-self manager approval', async () => {
  const fx = fixture({ policyOverrides: { permittedWielderIds: ['megacorp-internal-agent', 'sam'] } });
  const selfQuote = quote('self', { creatorId: 'sam', wielderId: 'sam' });
  await assert.rejects(() => authorize(fx, selfQuote), /manager approval is required/);
  const approval = signManagerApproval({
    schemaVersion: 1,
    approvalId: 'approval-self-1',
    managerSignerId: 'manager-alex',
    invocationId: selfQuote.invocationId,
    creatorId: 'sam',
    policyId: selfQuote.policyId,
    policyVersion: 1,
    issuedAt: NOW,
    expiresAt: selfQuote.expiresAt,
  }, fx.manager.privateKey);
  const authorized = await authorize(fx, selfQuote, { managerApproval: approval });
  assert.equal(authorized.reservation.state, 'reserved');

  const fxSelf = fixture({
    policyOverrides: {
      permittedWielderIds: ['megacorp-internal-agent', 'sam'],
      permittedManagerSignerIds: ['sam'],
    },
  });
  const selfManager = generateKeyPairSync('ed25519');
  const badState = fxSelf.store.snapshot();
  // A manager signer cannot be injected through an approval; the trust map remains authoritative.
  const selfApproval = signManagerApproval({
    schemaVersion: 1, approvalId: 'self-approved', managerSignerId: 'sam',
    invocationId: selfQuote.invocationId, creatorId: 'sam', policyId: selfQuote.policyId,
    policyVersion: 1, issuedAt: NOW, expiresAt: selfQuote.expiresAt,
  }, selfManager.privateKey);
  assert.equal(badState.revision, 0);
  await assert.rejects(() => authorize(fxSelf, selfQuote, { managerApproval: selfApproval }), /self-approve|manager signer/);
});

test('cancelled reservation makes its signed credential unusable', async () => {
  const fx = fixture();
  const q = quote();
  const authorized = await authorize(fx, q);
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  const cancelled = await cancelInternalAuthorization({
    store: fx.store,
    expectedRevision: 1,
    reservationId: authorized.reservation.reservationId,
    reason: 'operator_cancelled',
    now: NOW,
  });
  assert.equal(cancelled.invocation.state, 'cancelled');
  await assert.rejects(() => executeAuthorizedInvocation({
    store: fx.store, quote: q, credential,
    executor: async () => { throw new Error('must not execute'); }, now: NOW,
  }), /Invocation is not authorized|reservation must be reserved/);
});

test('serialized CAS permits one stale authorization and one execution attempt', async () => {
  const fx = fixture();
  const q1 = quote('001');
  const q2 = quote('002');
  const pending = [
    authorize(fx, q1, { reservationId: 'res-race-1', credentialNonce: nonce(1) }),
    authorize(fx, q2, { reservationId: 'res-race-2', credentialNonce: nonce(2) }),
  ];
  const settled = await Promise.allSettled(pending);
  assert.equal(settled.filter((item) => item.status === 'fulfilled').length, 1);
  assert.match(settled.find((item) => item.status === 'rejected').reason.message, /stale engine revision/);
  assert.equal(Object.keys(fx.store.snapshot().reservations).length, 1);
  assert.equal(Object.keys(fx.store.snapshot().idempotency).length, 1);

  const authorized = settled.find((item) => item.status === 'fulfilled').value;
  const q = authorized.invocation.invocationId === q1.invocationId ? q1 : q2;
  const credential = signCredential(authorized.credentialPayload, fx.authorizer.privateKey);
  let calls = 0;
  const input = () => executeAuthorizedInvocation({
    store: fx.store, quote: q, credential,
    executor: async () => {
      calls += 1;
      await Promise.resolve();
      return { kind: 'succeeded', executionCostAtomic: '700000', outputHash: OUTPUT_HASH };
    },
    now: NOW,
  });
  const executions = await Promise.allSettled([input(), input()]);
  assert.equal(executions.filter((item) => item.status === 'fulfilled').length, 1);
  assert.equal(calls, 1);
  assert.equal(Object.keys(fx.store.snapshot().awards).length, 1);
});

test('period cap counts conservative earned awards and every open maximum exposure', async () => {
  const fx = fixture({ policyOverrides: { maxAwardPerPeriodAtomic: '3000000' } });
  await authorize(fx, quote('001'));
  await assert.rejects(() => authorize(fx, quote('002'), {
    expectedRevision: 1,
    expectedBudgetRevision: 1,
    reservationId: 'res-inv-002',
    credentialNonce: nonce(2),
  }), /period award cap/);
  assert.equal(Object.keys(fx.store.snapshot().reservations).length, 1);
});

test('engine configuration rejects missing and extra trust roots', () => {
  const fx = fixture();
  const snapshot = fx.store.snapshot();
  assert.ok(Object.isFrozen(snapshot.policies));
  assert.ok(Object.isFrozen(snapshot.credentialAuthorizers));
  assert.throws(() => createEngineState({
    signedBudget: snapshot.budget.authorization,
    policies: snapshot.policies,
    financeSigners: snapshot.financeSigners,
    managerSigners: snapshot.managerSigners,
    credentialAuthorizers: {},
    now: NOW,
  }), /missing trusted credential authorizer/);
  assert.throws(() => createEngineState({
    signedBudget: snapshot.budget.authorization,
    policies: snapshot.policies,
    financeSigners: snapshot.financeSigners,
    managerSigners: snapshot.managerSigners,
    credentialAuthorizers: { ...snapshot.credentialAuthorizers, attacker: 'key' },
    now: NOW,
  }), /unexpected credential authorizer/);
});

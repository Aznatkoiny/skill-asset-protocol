import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import { allocateInternalGross } from '../../../prototype/atomic-money.mjs';
import {
  createBudget,
  finalizeReservation,
  holdUnresolvedReservation,
  releaseReservation,
  remainingAtomic,
  reserveBudget,
  signBudget,
  startReservationExecution,
} from '../src/budget.mjs';
import {
  canonicalPolicyBytes,
  parseExecutorOutcome,
  policyHash,
  sumAtomic,
  toAtomic,
  validatePolicy,
  validateQuote,
} from '../src/schema.mjs';

const NOW = '2026-07-17T00:01:00.000Z';
const ACTIVE_POLICY = {
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
  permittedInitiatingPrincipalIds: ['sam', 'jordan'],
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
};

const QUOTE = {
  schemaVersion: 1,
  quoteId: 'quote-inv-001',
  invocationId: 'inv-001',
  idempotencyKey: 'run-ledger-recon-001',
  skillId: 'ledger-recon',
  skillVersionHash: `sha256:${'1'.repeat(64)}`,
  creatorId: 'sam',
  wielderId: 'megacorp-internal-agent',
  initiatingPrincipalId: 'jordan',
  principalAttestationId: 'principal-attestation-inv-001',
  beneficiaryId: 'megacorp',
  costCenter: 'platform-engineering',
  policyId: ACTIVE_POLICY.policyId,
  policyVersion: 1,
  policyHash: policyHash(ACTIVE_POLICY),
  maxExecutionCostAtomic: '1000000',
  protocolFeeAtomic: '25000',
  refundReserveAtomic: '25000',
  maxInvocationAwardAtomic: '2000000',
  maxGrossAtomic: '3050000',
  expiresAt: '2026-07-17T00:05:00.000Z',
};

test('atomic boundary accepts canonical decimal strings only', () => {
  assert.equal(toAtomic('3050000'), 3_050_000n);
  assert.equal(sumAtomic(['1000000', '25000', '25000', '2000000']), 3_050_000n);
  for (const value of [-1, 1n, '-1', '01', '1.5', '', ' 1']) {
    assert.throws(() => toAtomic(value), /non-negative decimal string/);
  }
});

test('policy validation is effective-dated, exact, recursively frozen, and denomination neutral', () => {
  const policy = validatePolicy(ACTIVE_POLICY, NOW);
  assert.ok(Object.isFrozen(policy));
  assert.ok(Object.isFrozen(policy.awardRule));
  assert.ok(Object.isFrozen(policy.permittedSkillIds));
  assert.throws(() => validatePolicy({ ...ACTIVE_POLICY, status: 'draft' }, NOW), /must be active/);
  assert.throws(
    () => validatePolicy({ ...ACTIVE_POLICY, effectiveAt: '2026-07-18T00:00:00.000Z' }, NOW),
    /not yet effective/,
  );
  assert.throws(
    () => validatePolicy({ ...ACTIVE_POLICY, expiresAt: NOW }, NOW),
    /expired/,
  );
  assert.throws(
    () => validatePolicy({
      ...ACTIVE_POLICY,
      awardRule: { ...ACTIVE_POLICY.awardRule, awardRateBps: 9000 },
    }, NOW),
    /unsupported award rule.*awardRateBps must equal 10000/,
  );
  assert.throws(() => validatePolicy({ ...ACTIVE_POLICY, surprise: true }, NOW), /unknown key surprise/);
  assert.equal(validatePolicy({ ...ACTIVE_POLICY, currency: 'EUR', atomicScale: 2 }, NOW).currency, 'EUR');
});

test('canonical policy bytes hash every field under the same ID and version', () => {
  const hash = policyHash(ACTIVE_POLICY);
  assert.match(hash, /^sha256:[0-9a-f]{64}$/);
  assert.ok(canonicalPolicyBytes(ACTIVE_POLICY) instanceof Uint8Array);
  assert.notEqual(hash, policyHash({ ...ACTIVE_POLICY, paymentRail: 'another_employer_rail' }));
  assert.equal(hash, policyHash(structuredClone(ACTIVE_POLICY)));
});

test('quote validation binds exact maximums and keeps manager approval separate', () => {
  const quote = validateQuote(QUOTE, ACTIVE_POLICY, NOW);
  assert.ok(Object.isFrozen(quote));
  assert.throws(
    () => validateQuote({ ...QUOTE, maxGrossAtomic: '3049999' }, ACTIVE_POLICY, NOW),
    /maxGrossAtomic.*3050000/,
  );
  assert.throws(
    () => validateQuote({ ...QUOTE, wielderId: 'unknown-agent' }, ACTIVE_POLICY, NOW),
    /Wielder is not permitted/,
  );
  assert.throws(
    () => validateQuote({ ...QUOTE, selfInvocationApproval: {} }, ACTIVE_POLICY, NOW),
    /unknown key selfInvocationApproval/,
  );
  assert.throws(
    () => validateQuote({ ...QUOTE, expiresAt: NOW }, ACTIVE_POLICY, NOW),
    /quote expired/,
  );
});

test('executor outcomes fail closed without inventing zero COGS', () => {
  assert.deepEqual(parseExecutorOutcome({
    kind: 'succeeded',
    executionCostAtomic: '700000',
    outputHash: `sha256:${'a'.repeat(64)}`,
  }, QUOTE), {
    kind: 'succeeded',
    executionCostAtomic: '700000',
    outputHash: `sha256:${'a'.repeat(64)}`,
  });
  assert.deepEqual(parseExecutorOutcome({ kind: 'succeeded' }, QUOTE), {
    kind: 'unresolved_after_start',
    reason: 'malformed_outcome',
  });
  assert.deepEqual(parseExecutorOutcome({
    kind: 'failed_after_start', executionCostAtomic: '1000001', failureClass: 'provider_error',
  }, QUOTE), {
    kind: 'unresolved_after_start', reason: 'malformed_outcome',
  });
});

const UNSIGNED_BUDGET_AUTHORIZATION = {
  schemaVersion: 1,
  budgetId: 'budget-megacorp-2026-07',
  policyId: ACTIVE_POLICY.policyId,
  policyVersion: 1,
  policyHash: policyHash(ACTIVE_POLICY),
  period: '2026-07',
  currency: 'USD',
  atomicScale: 6,
  allocatedAtomic: '1000000000',
  effectiveAt: '2026-07-17T00:00:00.000Z',
  expiresAt: '2026-08-01T00:00:00.000Z',
  signerId: 'megacorp-finance',
};

function financeFixture(overrides = {}) {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const unsigned = { ...UNSIGNED_BUDGET_AUTHORIZATION, ...overrides };
  const signedBudget = signBudget(unsigned, privateKey);
  const trustedFinanceSigners = {
    [unsigned.signerId]: publicKey.export({ type: 'spki', format: 'pem' }),
  };
  return { privateKey, publicKey, signedBudget, trustedFinanceSigners };
}

function verifiedBudget(fixture = financeFixture()) {
  return createBudget(fixture.signedBudget, {
    trustedFinanceSigners: fixture.trustedFinanceSigners,
    policy: ACTIVE_POLICY,
    now: NOW,
  });
}

test('signed budget authorization is immutable and separate from mutable counters', () => {
  const fixture = financeFixture();
  const budget = verifiedBudget(fixture);
  assert.equal(budget.authorization.allocatedAtomic, '1000000000');
  assert.equal(budget.reservedAtomic, '0');
  assert.equal(budget.consumedAtomic, '0');
  assert.equal(budget.releasedAtomic, '0');
  assert.equal(remainingAtomic(budget), 1_000_000_000n);
  assert.ok(Object.isFrozen(budget.authorization));

  assert.throws(
    () => createBudget({ ...fixture.signedBudget, allocatedAtomic: '999999999' }, {
      trustedFinanceSigners: fixture.trustedFinanceSigners, policy: ACTIVE_POLICY, now: NOW,
    }),
    /signature/,
  );
  assert.throws(
    () => createBudget({ ...fixture.signedBudget, signerPublicKeyPem: 'attacker' }, {
      trustedFinanceSigners: fixture.trustedFinanceSigners, policy: ACTIVE_POLICY, now: NOW,
    }),
    /unknown key signerPublicKeyPem/,
  );
  assert.throws(
    () => createBudget(fixture.signedBudget, {
      trustedFinanceSigners: {}, policy: ACTIVE_POLICY, now: NOW,
    }),
    /trusted finance signer/,
  );
  const attacker = financeFixture();
  assert.throws(
    () => createBudget(fixture.signedBudget, {
      trustedFinanceSigners: attacker.trustedFinanceSigners, policy: ACTIVE_POLICY, now: NOW,
    }),
    /signature/,
  );
});

test('budget authorization validates its own effective window and policy signer allow-list', () => {
  const future = financeFixture({ effectiveAt: '2026-07-18T00:00:00.000Z' });
  assert.throws(() => verifiedBudget(future), /budget authorization is not yet effective/);
  const expired = financeFixture({ expiresAt: NOW });
  assert.throws(() => verifiedBudget(expired), /budget authorization expired/);
  const signer = financeFixture({ signerId: 'rogue-finance' });
  assert.throws(() => verifiedBudget(signer), /finance signer is not permitted/);
});

test('reservation uses exact budget and reservation revisions then kernel finalizes', () => {
  const budget = verifiedBudget();
  const reserved = reserveBudget(budget, QUOTE, {
    expectedRevision: 0,
    reservationId: 'res-001',
    now: NOW,
  });
  assert.equal(reserved.budget.reservedAtomic, '3050000');
  assert.equal(reserved.budget.revision, 1);
  assert.equal(reserved.reservation.state, 'reserved');
  assert.equal(reserved.reservation.revision, 0);
  assert.throws(
    () => reserveBudget(reserved.budget, { ...QUOTE, quoteId: 'quote-2', invocationId: 'inv-2', idempotencyKey: 'run-2' }, {
      expectedRevision: 0, reservationId: 'res-2', now: NOW,
    }),
    /stale budget revision/,
  );

  const started = startReservationExecution(reserved.budget, reserved.reservation, {
    expectedBudgetRevision: 1,
    expectedReservationRevision: 0,
    executionAttemptId: 'attempt-inv-001-1',
    now: NOW,
  });
  assert.equal(started.reservation.state, 'executing');
  assert.equal(started.reservation.revision, 1);
  assert.equal(started.budget.revision, 2);

  const finalized = finalizeReservation(started.budget, started.reservation, {
    expectedBudgetRevision: 2,
    expectedReservationRevision: 1,
    executionAttemptId: 'attempt-inv-001-1',
    grossAtomic: '2750000',
    executionCostAtomic: '700000',
    protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000',
    recipientId: 'sam',
    now: NOW,
  });
  assert.equal(finalized.budget.consumedAtomic, '2750000');
  assert.equal(finalized.budget.releasedAtomic, '300000');
  assert.equal(finalized.budget.reservedAtomic, '0');
  assert.equal(finalized.allocation.invocationAwardAtomic, 2_000_000n);
  assert.deepEqual(finalized.allocation.awardCredit, { recipientId: 'sam', amountAtomic: 2_000_000n });
  assert.equal(finalized.event.journalEntries.length, 4);
  assert.equal(finalized.event.journalEntries.reduce(
    (sum, entry) => sum + BigInt(entry.amountAtomic), 0n,
  ), 2_750_000n);
  assert.ok(finalized.event.journalEntries.every(
    (entry) => entry.debitAccountId === 'employer:invocation-gross',
  ));
  assert.deepEqual(finalized.allocation, allocateInternalGross({
    grossAtomic: 2_750_000n,
    executionCostAtomic: 700_000n,
    protocolFeeAtomic: 25_000n,
    refundReserveAtomic: 25_000n,
    recipientId: 'sam',
  }));
  assert.equal(remainingAtomic(finalized.budget), 997_250_000n);
  assert.throws(() => finalizeReservation(finalized.budget, finalized.reservation, {
    expectedBudgetRevision: 3,
    expectedReservationRevision: 2,
    executionAttemptId: 'attempt-inv-001-1',
    grossAtomic: '2750000', executionCostAtomic: '700000', protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000', recipientId: 'sam', now: NOW,
  }), /reservation must be executing/);
});

test('insufficient budget, exact failed COGS, cancellation, and unresolved holds conserve funds', () => {
  const smallFixture = financeFixture({ allocatedAtomic: '1000000' });
  assert.throws(() => reserveBudget(verifiedBudget(smallFixture), QUOTE, {
    expectedRevision: 0, reservationId: 'res-small', now: NOW,
  }), /insufficient remaining budget/);

  const first = reserveBudget(verifiedBudget(), QUOTE, {
    expectedRevision: 0, reservationId: 'res-failed', now: NOW,
  });
  const executing = startReservationExecution(first.budget, first.reservation, {
    expectedBudgetRevision: 1, expectedReservationRevision: 0,
    executionAttemptId: 'attempt-failed-1', now: NOW,
  });
  const failed = releaseReservation(executing.budget, executing.reservation, {
    expectedBudgetRevision: 2, expectedReservationRevision: 1,
    executionAttemptId: 'attempt-failed-1', executionCostAtomic: '700000',
    reason: 'failed_after_start', now: NOW,
  });
  assert.equal(failed.budget.consumedAtomic, '700000');
  assert.equal(failed.budget.releasedAtomic, '2350000');
  assert.equal(failed.budget.reservedAtomic, '0');
  assert.deepEqual(failed.allocation.journalEntries, [{
    category: 'execution-cogs',
    debitAccountId: 'employer:invocation-gross',
    creditAccountId: 'provider:execution',
    amountAtomic: 700_000n,
  }]);
  assert.deepEqual(failed.event.journalEntries, [{
    category: 'execution-cogs',
    debitAccountId: 'employer:invocation-gross',
    creditAccountId: 'provider:execution',
    amountAtomic: '700000',
  }]);

  const cancelReserved = reserveBudget(verifiedBudget(), QUOTE, {
    expectedRevision: 0, reservationId: 'res-cancel', now: NOW,
  });
  const cancelled = releaseReservation(cancelReserved.budget, cancelReserved.reservation, {
    expectedBudgetRevision: 1, expectedReservationRevision: 0,
    executionAttemptId: null, executionCostAtomic: '0', reason: 'cancelled_before_start', now: NOW,
  });
  assert.equal(cancelled.budget.releasedAtomic, '3050000');
  assert.equal(cancelled.budget.consumedAtomic, '0');
  assert.equal(cancelled.allocation, null);
  assert.deepEqual(cancelled.event.journalEntries, []);

  const heldReserved = reserveBudget(verifiedBudget(), QUOTE, {
    expectedRevision: 0, reservationId: 'res-held', now: NOW,
  });
  const heldExecuting = startReservationExecution(heldReserved.budget, heldReserved.reservation, {
    expectedBudgetRevision: 1, expectedReservationRevision: 0,
    executionAttemptId: 'attempt-held-1', now: NOW,
  });
  const held = holdUnresolvedReservation(heldExecuting.budget, heldExecuting.reservation, {
    expectedBudgetRevision: 2, expectedReservationRevision: 1,
    executionAttemptId: 'attempt-held-1', reason: 'cost_unknown', now: NOW,
  });
  assert.equal(held.reservation.state, 'held_unresolved');
  assert.equal(held.budget.reservedAtomic, '3050000');
  assert.equal(held.budget.consumedAtomic, '0');
  assert.equal(held.budget.releasedAtomic, '0');
  assert.equal(held.event.type, 'execution_cost_unresolved');
  assert.throws(() => releaseReservation(held.budget, held.reservation, {
    expectedBudgetRevision: 3, expectedReservationRevision: 2,
    executionAttemptId: 'attempt-held-1', executionCostAtomic: '0',
    reason: 'failed_after_start', now: NOW,
  }), /reservation must be executing/);
});

export { ACTIVE_POLICY, NOW, QUOTE, UNSIGNED_BUDGET_AUTHORIZATION, financeFixture };

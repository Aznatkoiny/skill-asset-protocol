import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseExecutorOutcome,
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
  beneficiaryId: 'megacorp',
  costCenter: 'platform-engineering',
  policyId: ACTIVE_POLICY.policyId,
  policyVersion: 1,
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

export { ACTIVE_POLICY, NOW, QUOTE };

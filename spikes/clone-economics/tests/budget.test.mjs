import assert from 'node:assert/strict';
import test from 'node:test';

import {
  calculateProviderCostMicroUsd,
  conservativeSweepRequestCount,
  createAttemptBudget,
  estimateLiveSweepMicroUsd,
  validateApprovedBudgetSnapshot,
} from '../src/budget.mjs';
import { liveAuthorizationHash } from '../src/authorization.mjs';
import { startLiveSweep } from '../src/sweep.mjs';
import { approved, config } from './fixtures/live-contract.mjs';

const counts = { trainCount: 100, heldoutCount: 30, v2Count: 2 };

test('live snapshot must be complete, approved, and match the experiment', () => {
  assert.doesNotThrow(() => validateApprovedBudgetSnapshot(approved, config));
  assert.throws(
    () => validateApprovedBudgetSnapshot({ ...approved, approvalStatus: 'not_approved' }, config),
    /not approved/i,
  );
  assert.throws(
    () => validateApprovedBudgetSnapshot({
      ...approved,
      pricing: { ...approved.pricing, inputUsdPerMillionTokens: null },
    }, config),
    /input pricing/i,
  );
});

test('preflight counts the target gate and every call in all 12 cells', () => {
  assert.equal(conservativeSweepRequestCount(config, counts), 1713);
  assert.equal(calculateProviderCostMicroUsd({
    inputTokens: 4096,
    outputTokens: 1024,
    snapshot: approved,
  }), 27_648n);
  assert.equal(estimateLiveSweepMicroUsd({ config, counts, snapshot: approved }), 47_361_024n);
});

test('an under-cap live request constructs neither adapter nor fetch', async () => {
  let adapterConstructions = 0;
  let fetchConstructions = 0;
  await assert.rejects(startLiveSweep({
    env: {
      APPROVE_LIVE_SWEEP_SHA256: liveAuthorizationHash({ config, snapshot: approved }),
      MAX_SWEEP_COST_USD: '47.00',
    },
    config,
    counts,
    snapshot: approved,
    fetchFactory() {
      fetchConstructions += 1;
      throw new Error('fetch must not be constructed');
    },
    adapterFactory() {
      adapterConstructions += 1;
      throw new Error('adapter must not be constructed');
    },
  }), /47\.361024.*47\.000000/);
  assert.equal(adapterConstructions, 0);
  assert.equal(fetchConstructions, 0);
});

test('every attempted call is reserved and the next over-cap call is refused', () => {
  const budget = createAttemptBudget({ capMicroUsd: 300n, worstCaseCallMicroUsd: 100n });
  const first = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'one' });
  budget.settleAttempt(first, { knownCostMicroUsd: 80n, success: true });
  const second = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'two' });
  budget.settleAttempt(second, { knownCostMicroUsd: 90n, success: false });
  const third = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'three' });
  budget.settleAttempt(third, { knownCostMicroUsd: 100n, success: true });
  assert.deepEqual(budget.state(), {
    attemptedCalls: 3,
    knownAccruedMicroUsd: 270n,
    outstandingReservedMicroUsd: 0n,
    lock: null,
  });
  assert.throws(
    () => budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'four' }),
    /would exceed.*cap/i,
  );
  assert.equal(budget.state().attemptedCalls, 3);
});

test('unknown cost locks its reservation and fails closed', () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'distill', caseId: null });
  assert.throws(
    () => budget.settleAttempt(attempt, { knownCostMicroUsd: null, success: false }),
    /unknown live cost.*budget locked/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: attempt },
  });
  assert.throws(
    () => budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'blocked' }),
    /budget locked/i,
  );
});

test('above-token-cap usage records exact cost and permanently locks as budget_overrun', () => {
  const budget = createAttemptBudget({ capMicroUsd: 1_000n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'distill', caseId: null });
  assert.throws(
    () => budget.settleAttempt(attempt, {
      knownCostMicroUsd: 140n,
      success: false,
      budgetViolation: 'token_cap_exceeded',
    }),
    /budget_overrun.*token cap/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 140n,
    outstandingReservedMicroUsd: 0n,
    lock: { kind: 'budget_overrun', attemptId: attempt, reason: 'token_cap_exceeded' },
  });
  assert.throws(() => budget.reserveNextAttempt({ kind: 'blocked', caseId: null }), /budget_overrun/);
});

test('known provider cost above the human cap is accrued before permanent lock', () => {
  const budget = createAttemptBudget({ capMicroUsd: 100n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'one' });
  assert.throws(
    () => budget.settleAttempt(attempt, { knownCostMicroUsd: 125n, success: true }),
    /budget_overrun.*human cap/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 125n,
    outstandingReservedMicroUsd: 0n,
    lock: { kind: 'budget_overrun', attemptId: attempt, reason: 'human_cap_exceeded' },
  });
  assert.throws(() => budget.reserveNextAttempt({ kind: 'blocked', caseId: null }), /budget_overrun/);
});

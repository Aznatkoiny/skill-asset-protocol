import assert from 'node:assert/strict';
import test from 'node:test';

import { LiveAnthropicAdapter, MockLlmAdapter } from '../src/adapters.mjs';
import { createAttemptBudget } from '../src/budget.mjs';

const snapshot = (overrides = {}) => ({
  schemaVersion: 1,
  experimentFamily: 'clone-economics-high-n-v1',
  approvalStatus: 'approved',
  provider: 'anthropic',
  model: 'synthetic-adapter-test-model',
  pricing: {
    currency: 'USD',
    unit: 'per_million_tokens',
    inputUsdPerMillionTokens: '1.00',
    outputUsdPerMillionTokens: '1.00',
    asOf: '2026-07-17T00:00:00Z',
    source: 'https://example.invalid/pricing',
  },
  tokenCaps: { maxInputTokens: 4096, maxOutputTokens: 1024 },
  ...overrides,
});

function response(json, { ok = true, status = 200 } = {}) {
  return { ok, status, async json() { return structuredClone(json); } };
}

function live({ budget, fetchImpl, contract = snapshot() }) {
  return new LiveAnthropicAdapter({
    mode: 'live',
    apiKey: 'synthetic-never-sent-to-network',
    snapshot: contract,
    budget,
    fetchImpl,
    testOnlyNoNetwork: true,
  });
}

test('mock seed evidence is synthetic and output callback receives no payload bytes', async () => {
  let callbackRequest;
  const adapter = new MockLlmAdapter({
    transcript: {
      pricing: { inputUsdPerMillion: 1, outputUsdPerMillion: 1 },
      usageProfiles: { distill: { inputTokens: 1, outputTokens: 1, costUsd: 0.000002, latencyMs: 1 } },
    },
    cloneSkillMd: 'unused',
    outputFor(request) {
      callbackRequest = request;
      return 'synthetic clone';
    },
  });
  const result = await adapter.invoke({
    kind: 'distill',
    caseId: null,
    requestedDistillationSeed: 2701,
    payload: { targetSkill: 'private target bytes' },
  });
  assert.deepEqual(callbackRequest, {
    kind: 'distill',
    caseId: null,
    requestedDistillationSeed: 2701,
  });
  assert.deepEqual(result.seed, {
    requestedSeed: 2701,
    appliedSeed: 2701,
    status: 'synthetic_honored',
    mechanism: 'deterministic_mock_fixture_selection',
  });
  assert.equal(adapter.attempts[0].budgetAttemptId, null);
});

test('missing usage retains a reservation, locks unknown_cost, and permits no later fetch', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  let fetches = 0;
  const adapter = live({
    budget,
    fetchImpl: async () => {
      fetches += 1;
      return response({ id: 'synthetic-1', content: [{ type: 'text', text: 'answer' }] });
    },
  });
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'one', payload: { input: 'small' } }),
    /unknown live cost.*budget locked/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
  assert.equal(adapter.attempts[0].providerCostMicroUsd, null);
  assert.equal(adapter.attempts[0].budgetAttemptId, 'attempt-000001');
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'two', payload: { input: 'small' } }),
    /budget locked/i,
  );
  assert.equal(fetches, 1);
  assert.equal(adapter.attempts.length, 1);
});

test('above-token usage accrues exact cost, locks budget_overrun, and permits no later fetch', async () => {
  const contract = snapshot({ tokenCaps: { maxInputTokens: 500, maxOutputTokens: 10 } });
  const budget = createAttemptBudget({ capMicroUsd: 10_000n, worstCaseCallMicroUsd: 510n });
  let fetches = 0;
  const adapter = live({
    contract,
    budget,
    fetchImpl: async () => {
      fetches += 1;
      return response({
        id: 'synthetic-2',
        usage: { input_tokens: 501, output_tokens: 10 },
        content: [{ type: 'text', text: 'answer' }],
      });
    },
  });
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'one', payload: { input: 'x' } }),
    /budget_overrun.*token cap/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 511n,
    outstandingReservedMicroUsd: 0n,
    lock: { kind: 'budget_overrun', attemptId: 'attempt-000001', reason: 'token_cap_exceeded' },
  });
  assert.equal(adapter.attempts[0].inputTokens, 501);
  assert.equal(adapter.attempts[0].providerCostMicroUsd, '511');
  assert.equal(adapter.attempts[0].budgetAttemptId, 'attempt-000001');
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'two', payload: { input: 'x' } }),
    /budget_overrun/,
  );
  assert.equal(fetches, 1);
  assert.equal(adapter.attempts.length, 1);
});

test('known cost above the human cap is fully accrued and blocks all later calls', async () => {
  const contract = snapshot({ tokenCaps: { maxInputTokens: 4096, maxOutputTokens: 1 } });
  const budget = createAttemptBudget({ capMicroUsd: 100n, worstCaseCallMicroUsd: 100n });
  let fetches = 0;
  const adapter = live({
    contract,
    budget,
    fetchImpl: async () => {
      fetches += 1;
      return response({
        id: 'synthetic-3',
        usage: { input_tokens: 125, output_tokens: 0 },
        content: [{ type: 'text', text: 'answer' }],
      });
    },
  });
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'one', payload: { input: 'x' } }),
    /budget_overrun.*human cap/i,
  );
  assert.equal(budget.state().knownAccruedMicroUsd, 125n);
  assert.equal(budget.state().outstandingReservedMicroUsd, 0n);
  assert.equal(adapter.attempts[0].budgetAttemptId, 'attempt-000001');
  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'two', payload: { input: 'x' } }),
    /budget_overrun/,
  );
  assert.equal(fetches, 1);
  assert.equal(adapter.attempts.length, 1);
});

test('live distillation records unsupported seed evidence and sends no seed field', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 1_000n, worstCaseCallMicroUsd: 200n });
  let body;
  const adapter = live({
    budget,
    fetchImpl: async (_url, init) => {
      body = JSON.parse(init.body);
      return response({
        id: 'synthetic-4',
        usage: { input_tokens: 10, output_tokens: 10 },
        content: [{ type: 'text', text: 'answer' }],
      });
    },
  });
  const result = await adapter.invoke({
    kind: 'distill',
    requestedDistillationSeed: 2701,
    payload: { instructions: 'small', pairs: [] },
  });
  assert.equal(Object.hasOwn(body, 'seed'), false);
  assert.deepEqual(result.seed, {
    requestedSeed: 2701,
    appliedSeed: null,
    status: 'unsupported',
    mechanism: 'provider_seed_not_supported_by_adapter',
  });
  assert.equal(adapter.attempts[0].budgetAttemptId, 'attempt-000001');
});

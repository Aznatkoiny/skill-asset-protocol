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
  const bytes = new TextEncoder().encode(JSON.stringify(json));
  let delivered = false;
  return {
    ok,
    status,
    headers: { get: () => null },
    body: {
      getReader() {
        return {
          async read() {
            if (delivered) return { done: true, value: undefined };
            delivered = true;
            return { done: false, value: bytes };
          },
          async cancel() {},
        };
      },
    },
    async json() { throw new Error('unbounded json reader must not be called'); },
    async text() { throw new Error('unbounded text reader must not be called'); },
  };
}

function live({ budget, fetchImpl, contract = snapshot(), runtime = {} }) {
  return new LiveAnthropicAdapter({
    mode: 'live',
    apiKey: 'synthetic-never-sent-to-network',
    snapshot: contract,
    budget,
    fetchImpl,
    testOnlyNoNetwork: true,
    ...runtime,
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

test('live provider I/O has a hard wall-clock deadline and redirect refusal', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  let fetchOptions;
  const adapter = live({
    budget,
    runtime: { requestTimeoutMs: 20 },
    fetchImpl: async (_url, options) => {
      fetchOptions = options;
      return new Promise(() => {});
    },
  });

  const guard = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('test guard expired before adapter deadline')), 200);
  });
  await assert.rejects(
    Promise.race([
      adapter.invoke({ kind: 'target-heldout', caseId: 'deadline', payload: { input: 'small' } }),
      guard,
    ]),
    /Anthropic request timed out/,
  );
  assert.equal(fetchOptions.redirect, 'error');
  assert.ok(fetchOptions.signal instanceof AbortSignal);
  assert.equal(fetchOptions.signal.aborted, true);
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
});

test('live provider response cancels on the first byte beyond the cap without unbounded readers', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  let reads = 0;
  let cancellations = 0;
  const chunks = [
    new TextEncoder().encode('12345678'),
    new TextEncoder().encode('9'),
    new TextEncoder().encode('never-read'),
  ];
  const adapter = live({
    budget,
    runtime: { maxResponseBytes: 8 },
    fetchImpl: async () => ({
      ok: true,
      status: 200,
      headers: { get: () => null },
      body: {
        getReader() {
          return {
            async read() {
              const value = chunks[reads];
              reads += 1;
              return value === undefined
                ? { done: true, value: undefined }
                : { done: false, value };
            },
            async cancel() {
              cancellations += 1;
            },
          };
        },
      },
      async json() {
        throw new Error('unbounded json reader must not be called');
      },
      async text() {
        throw new Error('unbounded text reader must not be called');
      },
    }),
  });

  await assert.rejects(
    adapter.invoke({ kind: 'target-heldout', caseId: 'overflow', payload: { input: 'small' } }),
    /Anthropic response exceeded byte limit/,
  );
  assert.equal(reads, 2);
  assert.equal(cancellations, 1);
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
});

test('live provider transport errors are sanitized without releasing unknown spend', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  const adapter = live({
    budget,
    fetchImpl: async () => {
      throw new Error('private-provider-detail apiKey=should-never-cross-boundary');
    },
  });

  const error = await adapter
    .invoke({ kind: 'target-heldout', caseId: 'transport-error', payload: { input: 'small' } })
    .then(
      () => null,
      (caught) => caught,
    );
  assert.ok(error instanceof Error);
  assert.match(error.message, /Anthropic request failed/);
  assert.doesNotMatch(error.message, /private-provider-detail|apiKey|should-never-cross-boundary/);
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
  assert.equal(adapter.attempts[0].providerCostMicroUsd, null);
});

test('live provider body deadline cancels a stalled stream reader', async () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  let fetchSignal;
  let cancellations = 0;
  const adapter = live({
    budget,
    runtime: { requestTimeoutMs: 20 },
    fetchImpl: async (_url, options) => {
      fetchSignal = options.signal;
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        body: {
          getReader() {
            return {
              async read() { return new Promise(() => {}); },
              async cancel() { cancellations += 1; },
            };
          },
        },
      };
    },
  });

  const guard = new Promise((_, reject) => {
    setTimeout(() => reject(new Error('test guard expired before body deadline')), 200);
  });
  await assert.rejects(
    Promise.race([
      adapter.invoke({ kind: 'target-heldout', caseId: 'body-deadline', payload: { input: 'small' } }),
      guard,
    ]),
    /Anthropic request timed out/,
  );
  assert.equal(fetchSignal.aborted, true);
  assert.equal(cancellations, 1);
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
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

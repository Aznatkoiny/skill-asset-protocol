import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  classifyHighNSeedValidity,
  compliantHeldoutOutput,
  reconcileCellSeedEvidence,
  runSweep,
  seededOrder,
  validateSweepConfig,
  writeSweepEvidenceBundle,
} from '../src/sweep.mjs';
import { scoreEvaluation } from '../src/scoring.mjs';

const config = {
  schemaVersion: 1,
  experimentFamily: 'clone-economics-high-n-v1',
  fixtureSet: 'v2',
  nValues: [6, 25, 50, 100],
  heldoutMinimum: 30,
  replicates: [
    { replicateId: 'r1', pairOrderSeed: 1701, distillationSeed: 2701 },
    { replicateId: 'r2', pairOrderSeed: 1702, distillationSeed: 2702 },
    { replicateId: 'r3', pairOrderSeed: 1703, distillationSeed: 2703 },
  ],
  highNDefinition: 100,
  targetThreshold: 0.8,
  requireAllTargetCriticalGates: true,
  acquisitionTreatment: 'modeled_unless_x402_receipts_attached',
  attemptCostTreatment: 'include_every_attempted_provider_call',
  publicationRequiresValidTarget: true,
  publicationRequiresIndependentDistillationSeeds: true,
};

test('sweep contract requires the exact preregistered dimensions', () => {
  assert.doesNotThrow(() => validateSweepConfig(config, { trainCount: 100, heldoutCount: 30 }));
  assert.throws(() => validateSweepConfig({ ...config, nValues: [6, 100] }, { trainCount: 100, heldoutCount: 30 }), /N=6,25,50,100/);
});

test('three pair-order seeds are deterministic and distinct', () => {
  const rows = Array.from({ length: 100 }, (_, i) => `row-${i}`);
  const orders = config.replicates.map((replicate) => seededOrder(rows, replicate.pairOrderSeed));
  assert.deepEqual(orders[0], seededOrder(rows, 1701));
  assert.notDeepEqual(orders[0], orders[1]);
  assert.notDeepEqual(orders[1], orders[2]);
});

test('pair-order and distillation seeds are separate distinct contracts', () => {
  assert.deepEqual(config.replicates.map((x) => x.pairOrderSeed), [1701, 1702, 1703]);
  assert.deepEqual(config.replicates.map((x) => x.distillationSeed), [2701, 2702, 2703]);
  assert.equal(config.replicates.some((x) => x.pairOrderSeed === x.distillationSeed), false);
});

test('publishable high-N requires three adapter-confirmed distillation seeds', () => {
  const validBenchmark = { valid: true, verdict: 'VALID_BENCHMARK' };
  const invalidBenchmark = { valid: false, verdict: 'INVALID_BENCHMARK_TARGET_FAILED' };
  const honored = config.replicates.map((replicate) => ({
    n: 100,
    replicateId: replicate.replicateId,
    requestedDistillationSeed: replicate.distillationSeed,
    appliedDistillationSeed: replicate.distillationSeed,
    distillationSeedStatus: 'honored',
    seedEvidenceReconciled: true,
    status: 'complete',
    benchmark: validBenchmark,
  }));
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored,
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: true,
    reason: null,
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: [
      ...honored.slice(0, 2),
      { ...honored[2], appliedDistillationSeed: null, distillationSeedStatus: 'unsupported' },
    ],
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: false,
    reason: 'DISTILLATION_SEEDS_UNCONTROLLED',
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored.map((cell, index) =>
      index === 1 ? { ...cell, benchmark: invalidBenchmark } : cell),
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: false,
    reason: 'HIGH_N_TARGET_INVALID',
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored,
    adapterMode: 'live',
    standaloneBenchmark: invalidBenchmark,
  }), {
    valid: false,
    reason: 'STANDALONE_TARGET_INVALID',
  });
});

test('synthetic heldout output satisfies the committed expected-mode gate', () => {
  const fixture = {
    id: 'fixture',
    mode: 'Optimize',
    rubric: {
      expectedMode: 'Optimize',
      maxQuestions: 0,
      exactPaths: [{ value: '@src/example.ts', weight: 2, critical: true }],
      exactCommands: [{ value: 'npm test -- example', weight: 2, critical: true }],
      requiredAll: [{ value: 'preserve behavior', dimension: 'constraints', weight: 2, critical: true }],
      requiredAny: [{ values: ['Show the diff'], dimension: 'output', weight: 1, critical: false }],
      forbidden: [{ value: '[', dimension: 'grounding', weight: 1, critical: true }],
    },
  };
  const score = scoreEvaluation({ fixture: compliantHeldoutOutput(fixture) }, [fixture]);
  assert.equal(score.absoluteScore, 1);
  assert.equal(score.criticalGatePass, true);
});

test('offline sweep completes all 12 cells without a publishable live conclusion', async (t) => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-mock-sweep-'));
  t.after(() => fs.rmSync(outputDir, { recursive: true, force: true }));
  let networkAttempts = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => {
    networkAttempts += 1;
    throw new Error('network forbidden in mock sweep');
  };
  t.after(() => { globalThis.fetch = originalFetch; });

  const result = await runSweep({ mode: 'mock', outputDir });
  assert.equal(result.benchmark.valid, true);
  assert.equal(result.cells.length, 12);
  assert.equal(result.cells.every((cell) => cell.status === 'complete'), true);
  assert.equal(result.highNComplete, true);
  assert.equal(result.publishableHighN, false);
  assert.equal(result.suppressionReason, 'HIGH_N_NOT_LIVE');
  assert.equal(result.samples.length, 1713);
  assert.equal(result.cells.every((cell) => cell.distillationSeedStatus === 'synthetic_honored'), true);
  assert.equal(networkAttempts, 0);
});

test('direct exported live sweep rejects without the module-private authorization capability', async () => {
  let invocations = 0;
  const adapter = {
    records: [],
    attempts: [],
    async invoke() { invocations += 1; throw new Error('must not invoke'); },
  };
  await assert.rejects(runSweep({ mode: 'live', adapter }), /startLiveSweep authorization capability/i);
  assert.equal(invocations, 0);
});

test('cell seed status is derived from recorded distillation attempt evidence', () => {
  const result = reconcileCellSeedEvidence({
    requestedSeed: 2701,
    reported: {
      appliedDistillationSeed: 2701,
      distillationSeedStatus: 'honored',
      distillationSeedMechanism: 'forged-report-claim',
    },
    attempts: [{
      kind: 'distill',
      requestedSeed: 2701,
      appliedSeed: null,
      status: 'unsupported',
      mechanism: 'provider_seed_not_supported_by_adapter',
    }],
  });
  assert.deepEqual(result, {
    requestedDistillationSeed: 2701,
    appliedDistillationSeed: null,
    distillationSeedStatus: 'unsupported',
    distillationSeedMechanism: 'provider_seed_not_supported_by_adapter',
    reportMatchesAttempt: false,
  });
});

test('standalone target execution failure preserves its attempt and final budget lock', async (t) => {
  const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-failed-target-'));
  t.after(() => fs.rmSync(outputDir, { recursive: true, force: true }));
  const budget = (await import('../src/budget.mjs')).createAttemptBudget({
    capMicroUsd: 100n,
    worstCaseCallMicroUsd: 100n,
  });
  const adapter = {
    records: [],
    attempts: [],
    async invoke(request) {
      const reservation = budget.reserveNextAttempt({ kind: request.kind, caseId: request.caseId });
      this.attempts.push({
        attemptId: `${request.kind}:${request.caseId}:1`,
        kind: request.kind,
        caseId: request.caseId,
        success: false,
        providerRequestId: null,
        latencyMs: 1,
        inputTokens: null,
        outputTokens: null,
        providerCostMicroUsd: null,
        providerCostUsd: null,
        failureClass: 'ProviderError',
        requestedSeed: null,
        appliedSeed: null,
        status: 'not_requested',
        mechanism: 'no_seed_requested',
      });
      budget.settleAttempt(reservation, { knownCostMicroUsd: null, success: false });
    },
  };
  const result = await runSweep({ mode: 'mock', adapter, budget, outputDir });
  assert.equal(result.publishableHighN, false);
  assert.equal(result.suppressionReason, 'STANDALONE_TARGET_EXECUTION_FAILED');
  assert.equal(result.samples.length, 1);
  assert.deepEqual(result.budgetState, {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: 'attempt-000001' },
  });
  const evidence = await writeSweepEvidenceBundle({
    result,
    config: {
      ...config,
      acquisitionTreatment: 'modeled_unless_x402_receipts_attached',
    },
    outputDir: path.join(outputDir, 'evidence'),
    experimentId: 'failed-target-fixture',
    evidenceLabel: 'SYNTHETIC FAILED TARGET',
    command: 'synthetic failed-target test',
  });
  assert.equal(evidence.verified.valid, true);
  assert.equal(evidence.verified.samples.length, 1);
});

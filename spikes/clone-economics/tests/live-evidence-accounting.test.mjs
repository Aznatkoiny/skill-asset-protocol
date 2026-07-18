import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { liveAuthorizationHash } from '../src/authorization.mjs';
import { calculateProviderCostMicroUsd } from '../src/budget.mjs';
import { verifyLiveEvidenceContract } from '../src/evidence.mjs';
import { approved, config, economics } from './fixtures/live-contract.mjs';

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

function writeJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function normalizedLiveSample(overrides = {}) {
  return {
    sampleId: 'live:target-heldout:a',
    phase: 'evaluation',
    profile: 'target',
    caseId: 'a',
    n: null,
    replicateId: null,
    pairOrderSeed: null,
    requestedDistillationSeed: null,
    appliedDistillationSeed: null,
    distillationSeedStatus: 'not_requested',
    distillationSeedMechanism: 'no_seed_requested',
    success: true,
    latencyMs: 1,
    inputTokens: 3,
    outputTokens: 2,
    providerCostMicroUsd: '39',
    providerCostUsd: 0.000039,
    acquisitionCostUsd: 0,
    acquisitionEvidence: null,
    score: 1,
    criticalGatePass: true,
    failureClass: null,
    providerRequestId: 'synthetic-request-1',
    budgetAttemptId: 'attempt-000001',
    ...overrides,
  };
}

function fixtureContract(t, {
  sweepConfig = config,
  snapshot = approved,
  economicsContract = economics,
  samples = [normalizedLiveSample()],
} = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-live-contract-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const fixtures = path.join(root, 'fixtures');
  fs.mkdirSync(fixtures, { recursive: true });
  for (const name of ['train-v2.json', 'heldout-v2.json', 'v2-heldout.json']) {
    fs.copyFileSync(path.join(packageRoot, 'fixtures', name), path.join(fixtures, name));
  }
  writeJson(path.join(fixtures, 'sweep-v1.json'), sweepConfig);
  writeJson(path.join(fixtures, 'live-budget-v1.json'), snapshot);
  writeJson(path.join(fixtures, 'live-economics-v1.json'), economicsContract);
  const configBytes = fs.readFileSync(path.join(fixtures, 'sweep-v1.json'));
  const snapshotBytes = fs.readFileSync(path.join(fixtures, 'live-budget-v1.json'));
  const economicsBytes = fs.readFileSync(path.join(fixtures, 'live-economics-v1.json'));
  let authorizationHash = `sha256:${'0'.repeat(64)}`;
  try {
    authorizationHash = liveAuthorizationHash({
      config: sweepConfig,
      snapshot,
      economics: economicsContract,
    });
  } catch {
    // Invalid approval fixtures are expected to fail before this placeholder matters.
  }
  const knownAccrued = samples.reduce(
    (sum, sample) => sum + BigInt(sample.providerCostMicroUsd ?? 0),
    0n,
  );
  return {
    root,
    samples,
    manifest: {
      executionMode: 'live',
      gitCommit: 'a'.repeat(40),
      gitDirty: false,
      evidenceLabel: 'LIVE CANDIDATE — CONCLUSIONS SUPPRESSED',
      sourceEvidence: null,
      modelProvider: 'Anthropic',
      model: snapshot.model,
      configuration: {
        sweepConfig,
        liveEconomics: economicsContract,
      },
      liveBudget: {
        configPath: 'fixtures/sweep-v1.json',
        configSha256: digest(configBytes),
        snapshotPath: 'fixtures/live-budget-v1.json',
        snapshotSha256: digest(snapshotBytes),
        economicsSnapshotPath: 'fixtures/live-economics-v1.json',
        economicsSnapshotSha256: digest(economicsBytes),
        authorizationHash,
        humanCapMicroUsd: '50000000',
        conservativeEstimateMicroUsd: '47361024',
        worstCasePerCallMicroUsd: '27648',
        attemptedCalls: samples.length,
        knownAccruedMicroUsd: knownAccrued.toString(),
        outstandingReservedMicroUsd: '0',
        lock: null,
      },
    },
  };
}

test('live contract derives exact committed counts, request budget, and per-row accounting', (t) => {
  const fixture = fixtureContract(t);
  assert.doesNotThrow(() => verifyLiveEvidenceContract(
    fixture.samples,
    fixture.manifest,
    fixture.root,
  ));
});

test('live contract rejects non-approved budget or economics fixtures', (t) => {
  const unapprovedBudget = fixtureContract(t, {
    snapshot: {
      ...approved,
      approvalStatus: 'not_approved',
      model: null,
      pricing: {
        currency: 'USD',
        unit: 'per_million_tokens',
        inputUsdPerMillionTokens: null,
        outputUsdPerMillionTokens: null,
        asOf: null,
        source: null,
      },
      tokenCaps: { maxInputTokens: null, maxOutputTokens: null },
    },
  });
  assert.throws(
    () => verifyLiveEvidenceContract(unapprovedBudget.samples, unapprovedBudget.manifest, unapprovedBudget.root),
    /budget snapshot must be approved/i,
  );

  const unapprovedEconomics = fixtureContract(t, {
    economicsContract: {
      ...economics,
      approvalStatus: 'not_approved',
      invocationPriceUsd: null,
      cloneServingCostUsd: null,
      deployCostUsd: null,
      laborCostUsd: null,
    },
  });
  assert.throws(
    () => verifyLiveEvidenceContract(unapprovedEconomics.samples, unapprovedEconomics.manifest, unapprovedEconomics.root),
    /live economics must be approved/i,
  );
});

test('live contract rejects path, hash, config, and aggregate accounting contradictions', (t) => {
  const cases = [
    ['config path', (fixture) => { fixture.manifest.liveBudget.configPath = 'fixtures/other.json'; }, /configPath must equal/],
    ['config hash', (fixture) => { fixture.manifest.liveBudget.configSha256 = '0'.repeat(64); }, /config hash mismatch/i],
    ['config body', (fixture) => { fixture.manifest.configuration.sweepConfig.targetThreshold = 0.9; }, /configuration differs/i],
    ['request estimate', (fixture) => { fixture.manifest.liveBudget.conservativeEstimateMicroUsd = '1'; }, /conservative estimate mismatch/i],
    ['human cap', (fixture) => { fixture.manifest.liveBudget.humanCapMicroUsd = '47361023'; }, /human cap.*below.*conservative/i],
    ['attempt count', (fixture) => { fixture.manifest.liveBudget.attemptedCalls = 2; }, /attempted-call count/i],
    ['budget attempt identity', (fixture) => { fixture.samples[0].budgetAttemptId = null; }, /budgetAttemptId sequence/i],
    ['known accrued', (fixture) => { fixture.manifest.liveBudget.knownAccruedMicroUsd = '40'; }, /known accrued/i],
    ['provider USD', (fixture) => { fixture.samples[0].providerCostUsd = 0.000040; }, /provider USD cost mismatch/i],
    ['acquisition price', (fixture) => {
      Object.assign(fixture.samples[0], {
        phase: 'acquisition',
        acquisitionCostUsd: 0.24,
        acquisitionEvidence: 'MODELED',
      });
    }, /acquisition row price.*mismatch/i],
    ['acquisition', (fixture) => { fixture.samples[0].acquisitionCostUsd = 0.25; }, /non-acquisition row/i],
  ];
  for (const [name, mutate, pattern] of cases) {
    const fixture = fixtureContract(t);
    mutate(fixture);
    assert.throws(
      () => verifyLiveEvidenceContract(fixture.samples, fixture.manifest, fixture.root),
      pattern,
      name,
    );
  }
});

test('live locks are linked to the final budget attempt and exact derived reason', (t) => {
  const unknown = fixtureContract(t, {
    samples: [normalizedLiveSample({
      success: false,
      inputTokens: null,
      outputTokens: null,
      providerCostMicroUsd: null,
      providerCostUsd: null,
      failureClass: 'ProviderError',
    })],
  });
  unknown.manifest.liveBudget.outstandingReservedMicroUsd = '27648';
  unknown.manifest.liveBudget.lock = { kind: 'unknown_cost', attemptId: 'attempt-000001' };
  assert.doesNotThrow(() => verifyLiveEvidenceContract(unknown.samples, unknown.manifest, unknown.root));
  unknown.manifest.liveBudget.lock.attemptId = 'attempt-000002';
  assert.throws(
    () => verifyLiveEvidenceContract(unknown.samples, unknown.manifest, unknown.root),
    /lock attemptId.*budgetAttemptId/i,
  );

  const inputTokens = approved.tokenCaps.maxInputTokens + 1;
  const exact = calculateProviderCostMicroUsd({ inputTokens, outputTokens: 2, snapshot: approved });
  const overrun = fixtureContract(t, {
    samples: [normalizedLiveSample({
      success: false,
      inputTokens,
      outputTokens: 2,
      providerCostMicroUsd: exact.toString(),
      providerCostUsd: Number(exact) / 1_000_000,
      failureClass: 'AggregateError',
    })],
  });
  overrun.manifest.liveBudget.lock = {
    kind: 'budget_overrun',
    attemptId: 'attempt-000001',
    reason: 'human_cap_exceeded',
  };
  assert.throws(
    () => verifyLiveEvidenceContract(overrun.samples, overrun.manifest, overrun.root),
    /lock reason.*token_cap_exceeded/i,
  );
});

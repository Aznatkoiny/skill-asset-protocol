import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  calculateProviderCostMicroUsd,
  conservativeSweepRequestCount,
  createAttemptBudget,
  estimateLiveSweepMicroUsd,
  formatMicroUsd,
  validateApprovedBudgetSnapshot,
} from './budget.mjs';
import { liveAuthorizationHash, validateLiveApproval } from './authorization.mjs';
import { loadFixtureSet } from './fixture-set.mjs';
import { validateApprovedLiveEconomics } from './live-economics.mjs';

const sweepRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const LIVE_SWEEP_AUTHORIZATION = Symbol('live-sweep-authorization');

function canonicalize(value) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  throw new Error(`Unsupported sweep contract value: ${typeof value}`);
}

const canonicalJson = (value) => JSON.stringify(canonicalize(value));

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const child of Object.values(value)) deepFreeze(child);
  }
  return value;
}

function committedSweepInputs() {
  const config = JSON.parse(fs.readFileSync(path.join(sweepRoot, 'fixtures/sweep-v1.json'), 'utf8'));
  const fixtures = loadFixtureSet(sweepRoot, config.fixtureSet);
  const v2Fixtures = JSON.parse(fs.readFileSync(path.join(sweepRoot, 'fixtures/v2-heldout.json'), 'utf8'));
  return {
    config,
    fixtures,
    v2Fixtures,
    counts: {
      trainCount: fixtures.train.length,
      heldoutCount: fixtures.heldout.length,
      v2Count: v2Fixtures.length,
    },
  };
}

function requireCommittedConfig(config, committed) {
  if (canonicalJson(config) !== canonicalJson(committed)) {
    throw new Error('Live sweep config must exactly match committed fixtures/sweep-v1.json');
  }
}

function requireExactCommittedCounts(counts, expected) {
  const keys = ['trainCount', 'heldoutCount', 'v2Count'];
  if (!counts || canonicalJson(Object.keys(counts).sort()) !== canonicalJson([...keys].sort())
      || keys.some((key) => !Number.isSafeInteger(counts[key]) || counts[key] < 0)
      || keys.some((key) => counts[key] !== expected[key])) {
    throw new Error('Caller counts must exactly match committed fixtures');
  }
}

function mulberry32(seed) {
  return () => {
    seed |= 0;
    seed = seed + 0x6D2B79F5 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

// This seed controls acquisition-pair ordering only. It does not control
// provider sampling or substitute for a provider-confirmed distillation seed.
export function seededOrder(values, seed) {
  const result = [...values];
  const random = mulberry32(seed);
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}

export function validateSweepConfig(config, counts) {
  if (!config || config.schemaVersion !== 1
      || config.experimentFamily !== 'clone-economics-high-n-v1'
      || config.fixtureSet !== 'v2') {
    throw new Error('Sweep must use the v1 high-N preregistration and v2 fixtures');
  }
  if (JSON.stringify(config.nValues) !== JSON.stringify([6, 25, 50, 100])) {
    throw new Error('Sweep must use N=6,25,50,100');
  }
  if (!Array.isArray(config.replicates) || config.replicates.length !== 3) {
    throw new Error('Sweep must use exactly three preregistered replicates');
  }
  const ids = config.replicates.map((x) => x.replicateId);
  const pairOrderSeeds = config.replicates.map((x) => x.pairOrderSeed);
  const distillationSeeds = config.replicates.map((x) => x.distillationSeed);
  for (const [label, values] of [
    ['replicate IDs', ids],
    ['pair-order seeds', pairOrderSeeds],
    ['distillation seeds', distillationSeeds],
  ]) {
    if (new Set(values).size !== 3) throw new Error(`Sweep requires three distinct ${label}`);
  }
  if (![...pairOrderSeeds, ...distillationSeeds].every(Number.isSafeInteger)) {
    throw new Error('Sweep seeds must be safe integers');
  }
  if (pairOrderSeeds.some((value) => distillationSeeds.includes(value))) {
    throw new Error('Pair-order and distillation seeds must be separate');
  }
  if (config.highNDefinition !== 100 || config.heldoutMinimum !== 30) {
    throw new Error('Sweep high-N and heldout minimum do not match preregistration');
  }
  if (counts.trainCount < 100 || counts.heldoutCount < 30) {
    throw new Error('Sweep requires at least 100 train and 30 heldout fixtures');
  }
}

export function classifyHighNSeedValidity({ cells, adapterMode, standaloneBenchmark }) {
  const highN = cells.filter((cell) => cell.n === 100 && cell.status === 'complete');
  if (standaloneBenchmark?.valid !== true) {
    return { valid: false, reason: 'STANDALONE_TARGET_INVALID' };
  }
  if (highN.length !== 3) {
    return { valid: false, reason: 'HIGH_N_INCOMPLETE' };
  }
  if (highN.some((cell) => cell.benchmark?.valid !== true)) {
    return { valid: false, reason: 'HIGH_N_TARGET_INVALID' };
  }
  if (adapterMode !== 'live') {
    return { valid: false, reason: 'HIGH_N_NOT_LIVE' };
  }
  const requested = highN.map((cell) => cell.requestedDistillationSeed);
  const independentlyHonored = new Set(requested).size === 3
    && highN.every((cell) =>
      cell.seedEvidenceReconciled === true
      && cell.distillationSeedStatus === 'honored'
      && cell.appliedDistillationSeed === cell.requestedDistillationSeed);
  return independentlyHonored
    ? { valid: true, reason: null }
    : { valid: false, reason: 'DISTILLATION_SEEDS_UNCONTROLLED' };
}

export function reconcileCellSeedEvidence({ requestedSeed, reported, attempts }) {
  const distillationAttempts = attempts.filter((attempt) => attempt.kind === 'distill');
  if (distillationAttempts.length !== 1) {
    return {
      requestedDistillationSeed: requestedSeed,
      appliedDistillationSeed: null,
      distillationSeedStatus: 'unsupported',
      distillationSeedMechanism: 'distillation_attempt_evidence_missing_or_ambiguous',
      reportMatchesAttempt: false,
    };
  }
  const attempt = distillationAttempts[0];
  if (attempt.requestedSeed !== requestedSeed) {
    return {
      requestedDistillationSeed: requestedSeed,
      appliedDistillationSeed: null,
      distillationSeedStatus: 'unsupported',
      distillationSeedMechanism: 'distillation_attempt_requested_seed_mismatch',
      reportMatchesAttempt: false,
    };
  }
  const reportMatchesAttempt = reported.appliedDistillationSeed === attempt.appliedSeed
    && reported.distillationSeedStatus === attempt.status
    && reported.distillationSeedMechanism === attempt.mechanism;
  return {
    requestedDistillationSeed: requestedSeed,
    appliedDistillationSeed: attempt.appliedSeed ?? null,
    distillationSeedStatus: attempt.status,
    distillationSeedMechanism: attempt.mechanism,
    reportMatchesAttempt,
  };
}

export const compliantHeldoutOutput = (fixture) => [
  `Mode: ${fixture.mode}`,
  fixture.rubric.exactPaths[0].value,
  fixture.rubric.exactCommands[0].value,
  fixture.rubric.requiredAll[0].value,
  'Show the diff',
].join('\n');

function attemptPhase(kind) {
  if (kind === 'target-train') return 'acquisition';
  if (kind === 'distill') return 'distillation';
  return 'evaluation';
}

function attemptProfile(kind) {
  if (kind.startsWith('target-')) return 'target';
  if (kind.startsWith('bad-clone-')) return 'bad-clone';
  return 'clone';
}

export function normalizeSweepSamples({ experimentId, attempts }) {
  return attempts.map((attempt) => {
    const normalized = {
      sampleId: `${experimentId}:${attempt.attemptId}`,
      phase: attemptPhase(attempt.kind),
      profile: attemptProfile(attempt.kind),
      caseId: attempt.caseId ?? null,
      n: attempt.n ?? null,
      replicateId: attempt.replicateId ?? null,
      pairOrderSeed: attempt.pairOrderSeed ?? null,
      requestedDistillationSeed: attempt.requestedDistillationSeed ?? attempt.requestedSeed ?? null,
      appliedDistillationSeed: attempt.appliedDistillationSeed ?? attempt.appliedSeed ?? null,
      distillationSeedStatus: attempt.distillationSeedStatus ?? attempt.status ?? 'not_requested',
      distillationSeedMechanism: attempt.distillationSeedMechanism ?? attempt.mechanism ?? 'no_seed_requested',
      success: attempt.success,
      latencyMs: attempt.latencyMs,
      inputTokens: attempt.inputTokens ?? null,
      outputTokens: attempt.outputTokens ?? null,
      providerCostMicroUsd: attempt.providerCostMicroUsd ?? null,
      providerCostUsd: attempt.providerCostUsd ?? null,
      acquisitionCostUsd: attempt.acquisitionCostUsd ?? 0,
      acquisitionEvidence: attempt.acquisitionEvidence ?? null,
      score: attempt.score ?? null,
      criticalGatePass: attempt.criticalGatePass ?? null,
      failureClass: attempt.failureClass ?? null,
      providerRequestId: attempt.providerRequestId ?? null,
    };
    return normalized;
  });
}

export async function writeSweepEvidenceBundle({
  result,
  config,
  outputDir,
  experimentId,
  evidenceLabel,
  command,
  recordedAtUtc,
  gitCommit,
  modelProvider = null,
  model = null,
  liveBudget = null,
  liveEconomics = null,
  readmeInputs,
}) {
  const { verifyEvidenceBundle, writeEvidenceBundle } = await import('./evidence.mjs');
  const samples = normalizeSweepSamples({ experimentId, attempts: result.samples });
  const incompleteCosts = samples.some((sample) => sample.providerCostUsd === null);
  const verdict = result.publishableHighN
    ? 'HIGH_N_PUBLICATION_GATE_PASSED'
    : result.suppressionReason ?? result.benchmark?.verdict ?? 'HIGH_N_INCOMPLETE';
  const limitations = [
    ...(samples.some((sample) => sample.acquisitionEvidence === 'MODELED') ? ['ACQUISITION_MODELED'] : []),
    ...(incompleteCosts ? ['INCOMPLETE_PROVIDER_COST'] : []),
    ...(evidenceLabel.startsWith('SYNTHETIC') ? ['SYNTHETIC_ONLY'] : []),
  ].sort();
  const manifest = writeEvidenceBundle({
    outputDir,
    manifest: {
      experimentId,
      ...(recordedAtUtc === undefined ? {} : { recordedAtUtc }),
      ...(gitCommit === undefined ? {} : { gitCommit }),
      command,
      modelProvider,
      model,
      evidenceLabel,
      liveBudget,
      readmeInputs,
      configuration: {
        sweepConfig: config,
        fixtureSet: config.fixtureSet,
        acquisitionTreatment: config.acquisitionTreatment,
        publicationGate: {
          publishableHighN: result.publishableHighN ?? false,
          suppressionReason: result.suppressionReason ?? result.benchmark?.verdict ?? null,
        },
        ...(liveEconomics === null ? {} : { liveEconomics }),
      },
    },
    samples,
    reportInputs: {
      evidenceLabel,
      verdict,
      suppressionReason: result.publishableHighN ? null : verdict,
      limitations,
    },
  });
  return { manifest, verified: verifyEvidenceBundle(outputDir) };
}

function scoreMap(score) {
  return new Map((score?.cases ?? []).map((item) => [item.id, item]));
}

function annotateAttempt(attempt, metadata, scores = {}) {
  const score = attempt.kind === 'target-heldout'
    ? scores.target?.get(attempt.caseId)
    : attempt.kind === 'clone-heldout'
      ? scores.clone?.get(attempt.caseId)
      : attempt.kind === 'bad-clone-heldout'
        ? scores.bad?.get(attempt.caseId)
        : null;
  return {
    ...structuredClone(attempt),
    ...metadata,
    requestedDistillationSeed: metadata.requestedDistillationSeed ?? attempt.requestedSeed ?? null,
    appliedDistillationSeed: attempt.appliedSeed ?? null,
    distillationSeedStatus: attempt.status ?? 'not_requested',
    distillationSeedMechanism: attempt.mechanism ?? 'no_seed_requested',
    acquisitionCostUsd: attempt.kind === 'target-train' ? metadata.invocationPriceUsd : 0,
    acquisitionEvidence: attempt.kind === 'target-train' ? 'MODELED' : null,
    score: score?.score ?? null,
    criticalGatePass: score?.criticalGatePass ?? null,
  };
}

export async function startLiveSweep({
  env,
  config,
  counts,
  snapshot,
  economics,
  fetchFactory,
  adapterFactory,
  sweepOptions = {},
}) {
  const committed = committedSweepInputs();
  requireCommittedConfig(config, committed.config);
  requireExactCommittedCounts(counts, committed.counts);
  const authorizedConfig = deepFreeze(structuredClone(committed.config));
  const authorizedSnapshot = deepFreeze(structuredClone(snapshot));
  const authorizedEconomics = deepFreeze(structuredClone(economics));
  validateSweepConfig(authorizedConfig, committed.counts);
  validateApprovedBudgetSnapshot(authorizedSnapshot, authorizedConfig);
  validateApprovedLiveEconomics(authorizedEconomics, authorizedConfig);
  const authorizationHash = liveAuthorizationHash({
    config: authorizedConfig,
    snapshot: authorizedSnapshot,
    economics: authorizedEconomics,
  });
  const capMicroUsd = validateLiveApproval(env, {
    config: authorizedConfig,
    snapshot: authorizedSnapshot,
    economics: authorizedEconomics,
  });
  const requestCount = conservativeSweepRequestCount(authorizedConfig, committed.counts);
  const perCallMicroUsd = calculateProviderCostMicroUsd({
    inputTokens: authorizedSnapshot.tokenCaps.maxInputTokens,
    outputTokens: authorizedSnapshot.tokenCaps.maxOutputTokens,
    snapshot: authorizedSnapshot,
  });
  const estimateMicroUsd = estimateLiveSweepMicroUsd({
    config: authorizedConfig,
    counts: committed.counts,
    snapshot: authorizedSnapshot,
  });
  if (estimateMicroUsd > capMicroUsd) {
    throw new Error(`Conservative live estimate $${formatMicroUsd(estimateMicroUsd)} exceeds human cap $${formatMicroUsd(capMicroUsd)}`);
  }
  if (env.ALLOW_LIVE_LLM !== '1') throw new Error('ALLOW_LIVE_LLM=1 is required for a live sweep');
  const liveAuthorizationCapability = LIVE_SWEEP_AUTHORIZATION;
  const budget = createAttemptBudget({ capMicroUsd, worstCaseCallMicroUsd: perCallMicroUsd });
  const fetchImpl = fetchFactory();
  const adapter = adapterFactory({
    fetchImpl,
    budget,
    snapshot: authorizedSnapshot,
    economics: authorizedEconomics,
  });
  const result = await runSweep({
    ...sweepOptions,
    mode: 'live',
    config: authorizedConfig,
    adapter,
    budget,
    counts: committed.counts,
    economics: authorizedEconomics,
    liveAuthorizationCapability,
  });
  return {
    authorizationHash,
    capMicroUsd,
    estimateMicroUsd,
    requestCount,
    perCallMicroUsd,
    budgetState: budget.state(),
    result,
  };
}

export async function runSweep(options) {
  const requestedMode = options?.mode ?? 'mock';
  if (requestedMode === 'live' && options.liveAuthorizationCapability !== LIVE_SWEEP_AUTHORIZATION) {
    throw new Error('Live runSweep requires the module-private startLiveSweep authorization capability');
  }
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const { MockLlmAdapter } = await import('./adapters.mjs');
  const { runExperiment, runTargetBenchmark } = await import('./experiment.mjs');
  const { loadFixtureSet } = await import('./fixture-set.mjs');

  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const config = options.config
    ?? JSON.parse(fs.readFileSync(path.join(root, 'fixtures/sweep-v1.json'), 'utf8'));
  const fixtures = options.fixtures ?? loadFixtureSet(root, config.fixtureSet);
  const v2Fixtures = JSON.parse(fs.readFileSync(path.join(root, 'fixtures/v2-heldout.json'), 'utf8'));
  const counts = options.counts ?? {
    trainCount: fixtures.train.length,
    heldoutCount: fixtures.heldout.length,
    v2Count: v2Fixtures.length,
  };
  validateSweepConfig(config, counts);
  const mode = options.mode ?? 'mock';
  if (!['mock', 'live'].includes(mode)) throw new Error('Sweep mode must be mock or live');
  const economicInputs = mode === 'live'
    ? validateApprovedLiveEconomics(options.economics, config)
    : {
        invocationPriceUsd: options.invocationPriceUsd ?? 0.25,
        cloneServingCostUsd: options.cloneServingCostUsd ?? 0.05,
        deployCostUsd: options.deployCostUsd ?? 0.05,
        laborCostUsd: options.laborCostUsd ?? 0,
      };

  const trainById = new Map(fixtures.train.map((fixture) => [fixture.id, fixture]));
  const heldoutById = new Map(fixtures.heldout.map((fixture) => [fixture.id, fixture]));
  const outputFor = ({ kind, caseId }) => {
    if (kind === 'target-train') return trainById.get(caseId)?.expectedOutput;
    if (kind === 'target-heldout' || kind === 'clone-heldout') {
      const fixture = heldoutById.get(caseId);
      return fixture ? compliantHeldoutOutput(fixture) : undefined;
    }
    if (kind === 'bad-clone-heldout' && heldoutById.has(caseId)) return 'Unscoped answer';
    return undefined;
  };
  const adapter = options.adapter ?? new MockLlmAdapter({
    transcript: JSON.parse(fs.readFileSync(path.join(root, 'fixtures/mock-transcript.json'), 'utf8')),
    cloneSkillMd: fs.readFileSync(path.join(root, 'fixtures/good-clone/SKILL.md'), 'utf8'),
    outputFor,
  });
  const adapterMode = mode;
  const reconcileSamples = (samples) => {
    if (samples.length !== adapter.attempts.length) {
      throw new Error('Sweep sample count does not reconcile with adapter attempts');
    }
    const budgetAttempts = options.budget?.state().attemptedCalls;
    if (budgetAttempts !== undefined && budgetAttempts !== samples.length) {
      throw new Error('Sweep sample count does not reconcile with budget attemptedCalls');
    }
  };
  let benchmark;
  let targetScore;
  try {
    ({ benchmark, targetScore } = await runTargetBenchmark({
      adapter,
      heldoutFixtures: fixtures.heldout,
      threshold: config.targetThreshold ?? 0.8,
    }));
  } catch (error) {
    const samples = adapter.attempts.map((attempt) => annotateAttempt(attempt, {
      n: null,
      replicateId: null,
      pairOrderSeed: null,
      requestedDistillationSeed: null,
      invocationPriceUsd: 0,
    }));
    reconcileSamples(samples);
    return {
      experimentFamily: config.experimentFamily,
      benchmark: {
        valid: false,
        verdict: 'STANDALONE_TARGET_EXECUTION_FAILED',
        cloneConclusionAllowed: false,
        economicsConclusionAllowed: false,
        reason: `Standalone target execution failed (${error instanceof Error ? error.name : 'UnknownError'}).`,
      },
      targetScore: null,
      cells: [],
      samples,
      highNComplete: false,
      publishableHighN: false,
      suppressionReason: 'STANDALONE_TARGET_EXECUTION_FAILED',
      budgetState: options.budget?.state() ?? null,
    };
  }
  const standaloneScores = { target: scoreMap(targetScore) };
  const samples = adapter.attempts.map((attempt) => annotateAttempt(attempt, {
    n: null,
    replicateId: null,
    pairOrderSeed: null,
    requestedDistillationSeed: null,
    invocationPriceUsd: 0,
  }, standaloneScores));
  if (!benchmark.valid) {
    reconcileSamples(samples);
    return {
      experimentFamily: config.experimentFamily,
      benchmark,
      targetScore,
      cells: [],
      samples,
      highNComplete: false,
      publishableHighN: false,
      suppressionReason: benchmark.verdict,
      budgetState: options.budget?.state() ?? null,
    };
  }

  const cells = [];
  let stop = false;
  for (const n of config.nValues) {
    for (const replicate of config.replicates) {
      const attemptStart = adapter.attempts.length;
      const cellOutputDir = path.join(
        options.outputDir ?? path.join(root, 'runs', `${mode}-sweep`),
        `n${n}-${replicate.replicateId}`,
      );
      let result = null;
      try {
        result = await runExperiment({
          mode,
          adapter,
          outputDir: cellOutputDir,
          N: n,
          trainFixtures: fixtures.train,
          heldoutFixtures: fixtures.heldout,
          v2Fixtures,
          fixtureSet: config.fixtureSet,
          pairOrderSeed: replicate.pairOrderSeed,
          requestedDistillationSeed: replicate.distillationSeed,
          replicateId: replicate.replicateId,
          invocationPriceUsd: economicInputs.invocationPriceUsd,
          cloneServingCostUsd: economicInputs.cloneServingCostUsd,
          deployCostUsd: economicInputs.deployCostUsd,
          laborCostUsd: economicInputs.laborCostUsd,
        });
        const seed = reconcileCellSeedEvidence({
          requestedSeed: replicate.distillationSeed,
          reported: result.report.seedContract,
          attempts: adapter.attempts.slice(attemptStart),
        });
        cells.push({
          n,
          replicateId: replicate.replicateId,
          pairOrderSeed: replicate.pairOrderSeed,
          requestedDistillationSeed: seed.requestedDistillationSeed,
          appliedDistillationSeed: seed.appliedDistillationSeed,
          distillationSeedStatus: seed.distillationSeedStatus,
          distillationSeedMechanism: seed.distillationSeedMechanism,
          seedEvidenceReconciled: seed.reportMatchesAttempt,
          status: 'complete',
          benchmark: result.report.benchmark,
          targetAbsoluteScore: result.report.fidelity.target.absoluteScore,
          cloneAbsoluteScore: result.report.fidelity.clone.absoluteScore,
          cloneCriticalGatePass: result.report.fidelity.clone.criticalGatePass,
          providerCostUsd: result.report.usage.normalized.providerCostUsd,
        });
      } catch (error) {
        cells.push({
          n,
          replicateId: replicate.replicateId,
          pairOrderSeed: replicate.pairOrderSeed,
          requestedDistillationSeed: replicate.distillationSeed,
          appliedDistillationSeed: null,
          distillationSeedStatus: 'unsupported',
          distillationSeedMechanism: 'cell_failed_before_seed_evidence',
          status: 'failed',
          benchmark: null,
          failureClass: error instanceof Error ? error.name : 'UnknownError',
        });
        stop = true;
      } finally {
        const scores = result ? {
          target: scoreMap(result.report.fidelity.target),
          clone: scoreMap(result.report.fidelity.clone),
          bad: scoreMap(result.report.fidelity.badClone),
        } : {};
        for (const attempt of adapter.attempts.slice(attemptStart)) {
          samples.push(annotateAttempt(attempt, {
            n,
            replicateId: replicate.replicateId,
            pairOrderSeed: replicate.pairOrderSeed,
            requestedDistillationSeed: replicate.distillationSeed,
            invocationPriceUsd: economicInputs.invocationPriceUsd,
          }, scores));
        }
      }
      if (stop) break;
    }
    if (stop) break;
  }
  reconcileSamples(samples);
  const highNComplete = cells.filter((cell) => cell.n === 100 && cell.status === 'complete').length === 3;
  const highNGate = classifyHighNSeedValidity({ cells, adapterMode, standaloneBenchmark: benchmark });
  return {
    experimentFamily: config.experimentFamily,
    benchmark,
    targetScore,
    cells,
    samples,
    highNComplete,
    publishableHighN: highNGate.valid,
    suppressionReason: highNGate.reason,
    budgetState: options.budget?.state() ?? null,
  };
}

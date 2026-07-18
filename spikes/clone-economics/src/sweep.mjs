import {
  calculateProviderCostMicroUsd,
  conservativeSweepRequestCount,
  createAttemptBudget,
  estimateLiveSweepMicroUsd,
  formatMicroUsd,
  validateApprovedBudgetSnapshot,
} from './budget.mjs';
import { liveAuthorizationHash, validateLiveApproval } from './authorization.mjs';

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
      cell.distillationSeedStatus === 'honored'
      && cell.appliedDistillationSeed === cell.requestedDistillationSeed);
  return independentlyHonored
    ? { valid: true, reason: null }
    : { valid: false, reason: 'DISTILLATION_SEEDS_UNCONTROLLED' };
}

export const compliantHeldoutOutput = (fixture) => [
  `Mode: ${fixture.mode}`,
  fixture.rubric.exactPaths[0].value,
  fixture.rubric.exactCommands[0].value,
  fixture.rubric.requiredAll[0].value,
  'Show the diff',
].join('\n');

export async function startLiveSweep({
  env,
  config,
  counts,
  snapshot,
  fetchFactory,
  adapterFactory,
  runSweep: runSweepImplementation = runSweep,
  sweepOptions = {},
}) {
  validateSweepConfig(config, counts);
  validateApprovedBudgetSnapshot(snapshot, config);
  const authorizationHash = liveAuthorizationHash({ config, snapshot });
  const capMicroUsd = validateLiveApproval(env, { config, snapshot });
  const requestCount = conservativeSweepRequestCount(config, counts);
  const perCallMicroUsd = calculateProviderCostMicroUsd({
    inputTokens: snapshot.tokenCaps.maxInputTokens,
    outputTokens: snapshot.tokenCaps.maxOutputTokens,
    snapshot,
  });
  const estimateMicroUsd = estimateLiveSweepMicroUsd({ config, counts, snapshot });
  if (estimateMicroUsd > capMicroUsd) {
    throw new Error(`Conservative live estimate $${formatMicroUsd(estimateMicroUsd)} exceeds human cap $${formatMicroUsd(capMicroUsd)}`);
  }
  if (env.ALLOW_LIVE_LLM !== '1') throw new Error('ALLOW_LIVE_LLM=1 is required for a live sweep');
  const budget = createAttemptBudget({ capMicroUsd, worstCaseCallMicroUsd: perCallMicroUsd });
  const fetchImpl = fetchFactory();
  const adapter = adapterFactory({ fetchImpl, budget, snapshot });
  const result = await runSweepImplementation({
    ...sweepOptions,
    mode: 'live',
    config,
    adapter,
    budget,
    counts,
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
  const { benchmark, targetScore } = await runTargetBenchmark({
    adapter,
    heldoutFixtures: fixtures.heldout,
    threshold: config.targetThreshold ?? 0.8,
  });
  const samples = adapter.attempts.map((attempt) => structuredClone(attempt));
  const reconcile = () => {
    if (samples.length !== adapter.attempts.length) {
      throw new Error('Sweep sample count does not reconcile with adapter attempts');
    }
    const budgetAttempts = options.budget?.state().attemptedCalls;
    if (budgetAttempts !== undefined && budgetAttempts !== samples.length) {
      throw new Error('Sweep sample count does not reconcile with budget attemptedCalls');
    }
  };
  if (!benchmark.valid) {
    reconcile();
    return {
      experimentFamily: config.experimentFamily,
      benchmark,
      targetScore,
      cells: [],
      samples,
      highNComplete: false,
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
      try {
        const result = await runExperiment({
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
          invocationPriceUsd: options.invocationPriceUsd ?? 0.25,
          cloneServingCostUsd: options.cloneServingCostUsd ?? 0.05,
          deployCostUsd: options.deployCostUsd ?? 0.05,
          laborCostUsd: options.laborCostUsd ?? 0,
        });
        const seed = result.report.seedContract;
        cells.push({
          n,
          replicateId: replicate.replicateId,
          pairOrderSeed: replicate.pairOrderSeed,
          requestedDistillationSeed: replicate.distillationSeed,
          appliedDistillationSeed: seed.appliedDistillationSeed,
          distillationSeedStatus: seed.distillationSeedStatus,
          distillationSeedMechanism: seed.distillationSeedMechanism,
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
        for (const attempt of adapter.attempts.slice(attemptStart)) samples.push(structuredClone(attempt));
      }
      if (stop) break;
    }
    if (stop) break;
  }
  reconcile();
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
  };
}

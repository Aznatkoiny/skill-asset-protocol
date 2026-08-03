import fs from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { LiveAnthropicAdapter } from './src/adapters.mjs';
import {
  conservativeSweepRequestCount,
  estimateLiveSweepMicroUsd,
  formatMicroUsd,
  validateBudgetSnapshotShape,
} from './src/budget.mjs';
import { liveAuthorizationHash } from './src/authorization.mjs';
import { loadFixtureSet } from './src/fixture-set.mjs';
import { assertLiveCheckoutClean, readGitState } from './src/git-state.mjs';
import { validateLiveEconomicsShape } from './src/live-economics.mjs';
import {
  runSweep,
  startLiveSweep,
  validateSweepConfig,
  writeSweepEvidenceBundle,
} from './src/sweep.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(root, 'fixtures', name), 'utf8'));
const config = readJson('sweep-v1.json');
const snapshot = readJson('live-budget-v1.json');
const economics = readJson('live-economics-v1.json');
const fixtures = loadFixtureSet(root, config.fixtureSet);
const v2Count = readJson('v2-heldout.json').length;
const counts = {
  trainCount: fixtures.train.length,
  heldoutCount: fixtures.heldout.length,
  v2Count,
};

function printDimensions() {
  console.log(`train fixtures: ${counts.trainCount}`);
  console.log(`heldout fixtures: ${counts.heldoutCount}`);
  console.log(`sweep cells: ${config.nValues.length * config.replicates.length}`);
  console.log(`conservative live requests: ${conservativeSweepRequestCount(config, counts)}`);
}

async function main() {
  const flags = process.argv.slice(2);
  if (flags.length !== 1 || !['--preflight', '--mock', '--live'].includes(flags[0])) {
    throw new Error('Usage: node sweep.mjs --preflight|--mock|--live');
  }
  const mode = flags[0];
  validateSweepConfig(config, counts);

  if (mode === '--preflight') {
    validateBudgetSnapshotShape(snapshot, config);
    validateLiveEconomicsShape(economics, config);
    printDimensions();
    console.log(`live budget: ${snapshot.approvalStatus === 'approved' ? 'approved' : 'not approved'}`);
    console.log(`live economics: ${economics.approvalStatus === 'approved' ? 'approved' : 'not approved'}`);
    if (snapshot.approvalStatus !== 'approved' || economics.approvalStatus !== 'approved') {
      return;
    }
    const authorizationHash = liveAuthorizationHash({ config, snapshot, economics });
    const estimate = estimateLiveSweepMicroUsd({ config, counts, snapshot });
    console.log(`live authorization: ${authorizationHash}`);
    console.log(`conservative live estimate USD: ${formatMicroUsd(estimate)}`);
    return;
  }

  if (mode === '--mock') {
    const gitState = Object.freeze(readGitState(root));
    let networkAttempts = 0;
    const priorFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      networkAttempts += 1;
      throw new Error('NETWORK FORBIDDEN IN MOCK SWEEP');
    };
    try {
      const result = await runSweep({ mode: 'mock' });
      const experimentId = `mock-high-n-${new Date().toISOString().replaceAll(/[-:.]/g, '')}-${process.pid}`;
      const evidenceRelative = path.join('runs', 'mock-sweep', 'evidence', experimentId);
      await writeSweepEvidenceBundle({
        result,
        executionMode: 'mock',
        gitState,
        config,
        outputDir: path.join(root, evidenceRelative),
        experimentId,
        evidenceLabel: 'SYNTHETIC',
        command: 'npm run sweep:mock',
        readmeInputs: { bundlePath: evidenceRelative },
      });
      console.log(`cells complete: ${result.cells.filter((cell) => cell.status === 'complete').length}/${result.cells.length}`);
      console.log(`publishable high-N: ${result.publishableHighN}`);
      console.log(`suppression: ${result.suppressionReason}`);
      console.log(`networkAttempts=${networkAttempts}`);
      console.log(`verified evidence: ${evidenceRelative}`);
    } finally {
      globalThis.fetch = priorFetch;
    }
    return;
  }

  const gitState = Object.freeze(readGitState(root));
  assertLiveCheckoutClean(gitState);
  const live = await startLiveSweep({
    env: process.env,
    config,
    counts,
    snapshot,
    economics,
    fetchFactory: () => globalThis.fetch,
    adapterFactory: ({ fetchImpl, budget, snapshot: committedSnapshot }) => new LiveAnthropicAdapter({
      mode: 'live',
      apiKey: process.env.ANTHROPIC_API_KEY,
      snapshot: committedSnapshot,
      budget,
      fetchImpl,
    }),
    sweepOptions: { outputDir: path.join(root, 'runs', 'live-sweep') },
  });
  const recordedAtUtc = new Date().toISOString();
  const experimentId = `live-high-n-${recordedAtUtc.replaceAll(/[-:.]/g, '')}`;
  const evidenceRelative = path.join('evidence', experimentId);
  const configBytes = fs.readFileSync(path.join(root, 'fixtures/sweep-v1.json'));
  const snapshotBytes = fs.readFileSync(path.join(root, 'fixtures/live-budget-v1.json'));
  const economicsBytes = fs.readFileSync(path.join(root, 'fixtures/live-economics-v1.json'));
  await writeSweepEvidenceBundle({
    result: live.result,
    executionMode: 'live',
    gitState,
    config,
    outputDir: path.join(root, evidenceRelative),
    experimentId,
    evidenceLabel: live.result.publishableHighN
      ? 'LIVE CANDIDATE — PUBLICATION GATE PASSED'
      : 'LIVE CANDIDATE — CONCLUSIONS SUPPRESSED',
    command: 'npm run sweep:live',
    recordedAtUtc,
    modelProvider: 'Anthropic',
    model: snapshot.model,
    liveEconomics: economics,
    liveBudget: {
      configPath: 'fixtures/sweep-v1.json',
      configSha256: createHash('sha256').update(configBytes).digest('hex'),
      snapshotPath: 'fixtures/live-budget-v1.json',
      snapshotSha256: createHash('sha256').update(snapshotBytes).digest('hex'),
      economicsSnapshotPath: 'fixtures/live-economics-v1.json',
      economicsSnapshotSha256: createHash('sha256').update(economicsBytes).digest('hex'),
      authorizationHash: live.authorizationHash,
      humanCapMicroUsd: live.capMicroUsd.toString(),
      conservativeEstimateMicroUsd: live.estimateMicroUsd.toString(),
      worstCasePerCallMicroUsd: live.perCallMicroUsd.toString(),
      attemptedCalls: live.budgetState.attemptedCalls,
      knownAccruedMicroUsd: live.budgetState.knownAccruedMicroUsd.toString(),
      outstandingReservedMicroUsd: live.budgetState.outstandingReservedMicroUsd.toString(),
      lock: live.budgetState.lock,
    },
    readmeInputs: { bundlePath: evidenceRelative },
  });
  console.log(`live authorization: ${live.authorizationHash}`);
  console.log(`attempted calls: ${live.budgetState.attemptedCalls}`);
  console.log(`publishable high-N: ${live.result.publishableHighN}`);
  console.log(`suppression: ${live.result.suppressionReason}`);
  console.log(`verified evidence: ${evidenceRelative}`);
  if (live.result.suppressionReason === 'STANDALONE_TARGET_EXECUTION_FAILED') {
    throw new Error(`Standalone target execution failed; sanitized evidence retained at ${evidenceRelative}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

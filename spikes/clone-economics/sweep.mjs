import fs from 'node:fs';
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
import { runSweep, startLiveSweep, validateSweepConfig } from './src/sweep.mjs';

const root = path.dirname(fileURLToPath(import.meta.url));
const readJson = (name) => JSON.parse(fs.readFileSync(path.join(root, 'fixtures', name), 'utf8'));
const config = readJson('sweep-v1.json');
const snapshot = readJson('live-budget-v1.json');
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
    printDimensions();
    if (snapshot.approvalStatus === 'not_approved') {
      console.log('live budget: not approved');
      return;
    }
    const authorizationHash = liveAuthorizationHash({ config, snapshot });
    const estimate = estimateLiveSweepMicroUsd({ config, counts, snapshot });
    console.log(`live authorization: ${authorizationHash}`);
    console.log(`conservative live estimate USD: ${formatMicroUsd(estimate)}`);
    return;
  }

  if (mode === '--mock') {
    let networkAttempts = 0;
    const priorFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      networkAttempts += 1;
      throw new Error('NETWORK FORBIDDEN IN MOCK SWEEP');
    };
    try {
      const result = await runSweep({ mode: 'mock' });
      console.log(`cells complete: ${result.cells.filter((cell) => cell.status === 'complete').length}/${result.cells.length}`);
      console.log(`publishable high-N: ${result.publishableHighN}`);
      console.log(`suppression: ${result.suppressionReason}`);
      console.log(`networkAttempts=${networkAttempts}`);
    } finally {
      globalThis.fetch = priorFetch;
    }
    return;
  }

  const live = await startLiveSweep({
    env: process.env,
    config,
    counts,
    snapshot,
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
  console.log(`live authorization: ${live.authorizationHash}`);
  console.log(`attempted calls: ${live.budgetState.attemptedCalls}`);
  console.log(`publishable high-N: ${live.result.publishableHighN}`);
  console.log(`suppression: ${live.result.suppressionReason}`);
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
});

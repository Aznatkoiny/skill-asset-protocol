import assert from 'node:assert/strict';
import { cp, readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';
import test from 'node:test';

import {
  loadPackagedFixtures,
  loadScenario,
  renderScenarioModel,
  validateLive402,
} from './demo-logic.mjs';

const STATIC_ROOT = new URL('./', import.meta.url);
const DATA_URLS = Object.freeze([
  './data/fixture-integrity.json',
  './data/public-demo-allocation.json',
  './data/evidence.json',
]);
const VALID_402 = Object.freeze({
  x402Version: 1,
  accepts: Object.freeze([Object.freeze({
    scheme: 'exact',
    network: 'base-sepolia',
    maxAmountRequired: '250000',
    resource: 'https://neverhandedover.com/api/invoke/optimizing-claude-code-prompts',
    payTo: '0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189',
    asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  })]),
});

function response(bytes, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => String(bytes.length) },
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

async function packagedBytes(root = STATIC_ROOT) {
  return new Map(await Promise.all(DATA_URLS.map(async (url) => [
    url,
    await readFile(new URL(url.slice(2), root)),
  ])));
}

test('strict live validation accepts only the fixed valid 402 offer', () => {
  assert.equal(validateLive402(402, VALID_402).live, true);
  for (const [status, body] of [
    [200, VALID_402],
    [500, VALID_402],
    [402, { ...VALID_402, x402Version: 2 }],
    [402, { ...VALID_402, accepts: [] }],
  ]) {
    assert.equal(validateLive402(status, body).live, false);
  }
  for (const [field, value] of [
    ['scheme', 'upto'],
    ['network', 'base'],
    ['maxAmountRequired', '0.25'],
    ['maxAmountRequired', '01'],
    ['resource', 'https://attacker.example/invoke'],
    ['payTo', ''],
    ['asset', ''],
  ]) {
    const offer = { ...VALID_402.accepts[0], [field]: value };
    assert.equal(validateLive402(402, { x402Version: 1, accepts: [offer] }).live, false);
  }
});

test('browser model renders exact kernel journal rows and conserves gross', async () => {
  const allocation = JSON.parse(await readFile(new URL('data/public-demo-allocation.json', STATIC_ROOT)));
  assert.equal(allocation.defaultScenarioId, 'intra-org');
  assert.equal(loadScenario(allocation).id, 'intra-org');
  assert.equal(loadScenario(allocation, 'education').status, 'deferred');
  assert.equal(loadScenario(allocation, 'marketplace').status, 'phase_3_optionality');

  for (const scenario of allocation.scenarios) {
    const model = renderScenarioModel(allocation, scenario.id);
    const entries = scenario.allocation.journalEntries;
    assert.equal(model.rows.length, entries.length);
    for (let index = 0; index < entries.length; index += 1) {
      assert.equal(model.rows[index].category, entries[index].category);
      assert.equal(model.rows[index].debitAccountId, entries[index].debitAccountId);
      assert.equal(model.rows[index].creditAccountId, entries[index].creditAccountId);
      assert.equal(model.rows[index].amountAtomic, entries[index].amountAtomic);
    }
    assert.equal(
      entries.reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n),
      BigInt(scenario.grossAtomic),
    );
  }
  const rendered = JSON.stringify(allocation).toLowerCase();
  for (const percentile of [`p${50}`, `p${95}`]) assert.equal(rendered.includes(percentile), false);
});

test('fixture loader fetches only local packaged files and verifies raw hashes', async () => {
  const bytes = await packagedBytes();
  const seen = [];
  const fetchImpl = async (url) => {
    seen.push(url);
    if (!bytes.has(url)) throw new Error(`unstubbed URL: ${url}`);
    return response(bytes.get(url));
  };
  const fixtures = await loadPackagedFixtures({ fetchImpl, cryptoImpl: webcrypto });
  assert.deepEqual(seen, DATA_URLS);
  assert.equal(fixtures.allocation.defaultScenarioId, 'intra-org');
  assert.equal(fixtures.evidence.historicalOverhead.publicationAllowed, false);

  const drifted = new Map(bytes);
  drifted.set('./data/evidence.json', Buffer.concat([bytes.get('./data/evidence.json'), Buffer.from(' ')]));
  await assert.rejects(
    () => loadPackagedFixtures({
      fetchImpl: async (url) => response(drifted.get(url)),
      cryptoImpl: webcrypto,
    }),
    /packaged fixture integrity mismatch: evidence.json/,
  );
});

test('static root remains standalone when copied away from the repository', async (t) => {
  const temporary = await mkdtemp(join(tmpdir(), 'static-root-test-'));
  t.after(() => rm(temporary, { recursive: true, force: true }));
  const copiedRoot = join(temporary, 'copied-static');
  await cp(fileURLToPath(STATIC_ROOT), copiedRoot, {
    recursive: true,
    filter: (sourcePath) => !sourcePath.includes(`${join('static', 'node_modules')}`),
  });
  const source = await readFile(join(copiedRoot, 'demo-logic.mjs'), 'utf8');
  assert.doesNotMatch(source, /\.\.\/|hf-space\/(gradio|static)/);
  const bytes = new Map(await Promise.all(DATA_URLS.map(async (url) => [
    url,
    await readFile(join(copiedRoot, url.slice(2))),
  ])));
  const moduleUrl = `${pathToFileURL(join(copiedRoot, 'demo-logic.mjs')).href}?standalone=${Date.now()}`;
  const originalCwd = process.cwd();
  try {
    process.chdir(tmpdir());
    const module = await import(moduleUrl);
    const fixtures = await module.loadPackagedFixtures({
      fetchImpl: async (url) => {
        if (!bytes.has(url)) throw new Error(`unstubbed URL: ${url}`);
        return response(bytes.get(url));
      },
      cryptoImpl: webcrypto,
    });
    assert.equal(fixtures.allocation.defaultScenarioId, 'intra-org');
  } finally {
    process.chdir(originalCwd);
  }
});

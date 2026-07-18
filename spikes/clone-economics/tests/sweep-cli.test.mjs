import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function run(args, env = {}) {
  return spawnSync(process.execPath, ['sweep.mjs', ...args], {
    cwd: root,
    env: {
      ...process.env,
      ...env,
      ALLOW_LIVE_LLM: '0',
      MOCK_LLM: args.includes('--mock') ? '1' : '0',
      ANTHROPIC_API_KEY: '',
      APPROVE_LIVE_SWEEP_SHA256: '',
      MAX_SWEEP_COST_USD: '',
    },
    encoding: 'utf8',
  });
}

test('preflight reports dimensions and explicit unapproved live budget', () => {
  const result = run(['--preflight']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /train fixtures: 100/);
  assert.match(result.stdout, /heldout fixtures: 30/);
  assert.match(result.stdout, /sweep cells: 12/);
  assert.match(result.stdout, /conservative live requests: 1713/);
  assert.match(result.stdout, /live budget: not approved/);
  assert.doesNotMatch(result.stdout, /live authorization:/);
});

test('mock CLI completes without network and stays unpublishable', () => {
  const result = run(['--mock']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /cells complete: 12\/12/);
  assert.match(result.stdout, /publishable high-N: false/);
  assert.match(result.stdout, /suppression: HIGH_N_NOT_LIVE/);
  assert.match(result.stdout, /networkAttempts=0/);
});

test('missing mode and default live contract both fail before construction', () => {
  const missing = run([]);
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /Usage:/);
  const live = run(['--live']);
  assert.notEqual(live.status, 0);
  assert.match(live.stderr, /Live budget snapshot must be approved/);
});

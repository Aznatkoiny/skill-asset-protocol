import assert from 'node:assert/strict';
import test from 'node:test';

import {
  liveAuthorizationHash,
  validateLiveApproval,
} from '../src/authorization.mjs';
import { approved, config, economics } from './fixtures/live-contract.mjs';

test('live approval binds the exact canonical sweep and budget snapshot', () => {
  const authorizationHash = liveAuthorizationHash({ config, snapshot: approved, economics });
  assert.match(authorizationHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateLiveApproval({
    APPROVE_LIVE_SWEEP_SHA256: authorizationHash,
    MAX_SWEEP_COST_USD: '50.000001',
  }, { config, snapshot: approved, economics }), 50_000_001n);
});

test('a stale approval fails after any material snapshot or config change', () => {
  const stale = liveAuthorizationHash({ config, snapshot: approved, economics });
  const mutations = [
    { config: { ...config, nValues: [6, 25, 50] }, snapshot: approved, economics },
    { config: {
      ...config,
      replicates: config.replicates.map((x, index) =>
        index === 0 ? { ...x, distillationSeed: 9999 } : x),
    }, snapshot: approved, economics },
    { config, snapshot: { ...approved, model: 'changed-model' }, economics },
    { config, snapshot: {
      ...approved,
      pricing: { ...approved.pricing, inputUsdPerMillionTokens: '3.01' },
    }, economics },
    { config, snapshot: {
      ...approved,
      tokenCaps: { ...approved.tokenCaps, maxOutputTokens: 2048 },
    }, economics },
    { config, snapshot: approved, economics: { ...economics, invocationPriceUsd: 0.30 } },
  ];
  for (const changed of mutations) {
    assert.throws(() => validateLiveApproval({
      APPROVE_LIVE_SWEEP_SHA256: stale,
      MAX_SWEEP_COST_USD: '50',
    }, changed), /stale or does not match/i);
  }
});

test('the old experiment-family token is never accepted as authorization', () => {
  assert.throws(() => validateLiveApproval({
    APPROVE_LIVE_SWEEP_SHA256: config.experimentFamily,
    MAX_SWEEP_COST_USD: '50',
  }, { config, snapshot: approved, economics }), /sha256/);
});

test('authorization rejects a missing or malformed reviewed live-economics contract', () => {
  assert.throws(() => liveAuthorizationHash({ config, snapshot: approved }), /live economics/i);
  assert.throws(
    () => liveAuthorizationHash({
      config,
      snapshot: approved,
      economics: { ...economics, deployCostUsd: Number.NaN },
    }),
    /deployCostUsd.*finite non-negative/i,
  );
});

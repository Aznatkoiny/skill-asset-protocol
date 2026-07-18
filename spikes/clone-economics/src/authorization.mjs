import { createHash } from 'node:crypto';

import { parseUsdToMicroUsd } from './budget.mjs';

function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  throw new Error(`Unsupported authorization value type: ${typeof value}`);
}

export function liveAuthorizationHash({ config, snapshot }) {
  const canonical = JSON.stringify(canonicalize({
    authorizationSchemaVersion: 1,
    sweepConfig: config,
    liveBudgetSnapshot: snapshot,
  }));
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export function validateLiveApproval(env, contract) {
  const supplied = env.APPROVE_LIVE_SWEEP_SHA256;
  if (typeof supplied !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(supplied)) {
    throw new Error('APPROVE_LIVE_SWEEP_SHA256 must be a lowercase sha256 digest');
  }
  const expected = liveAuthorizationHash(contract);
  if (supplied !== expected) {
    throw new Error(`Live approval is stale or does not match ${expected}`);
  }
  return parseUsdToMicroUsd(env.MAX_SWEEP_COST_USD, 'MAX_SWEEP_COST_USD');
}

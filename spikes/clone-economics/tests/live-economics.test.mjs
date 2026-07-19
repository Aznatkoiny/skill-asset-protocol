import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  validateApprovedLiveEconomics,
  validateLiveEconomicsShape,
} from '../src/live-economics.mjs';
import { config, economics } from './fixtures/live-contract.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('committed live economics is the exact fail-closed unapproved/null contract', () => {
  const committed = JSON.parse(fs.readFileSync(path.join(root, 'fixtures/live-economics-v1.json'), 'utf8'));
  assert.doesNotThrow(() => validateLiveEconomicsShape(committed, config));
  assert.equal(committed.approvalStatus, 'not_approved');
  assert.deepEqual([
    committed.invocationPriceUsd,
    committed.cloneServingCostUsd,
    committed.deployCostUsd,
    committed.laborCostUsd,
  ], [null, null, null, null]);
  assert.throws(() => validateApprovedLiveEconomics(committed, config), /must be approved/i);
});

test('approved live economics requires exact fields and finite non-negative values', () => {
  assert.doesNotThrow(() => validateApprovedLiveEconomics(economics, config));
  assert.throws(
    () => validateApprovedLiveEconomics({ ...economics, extra: 1 }, config),
    /unexpected or missing fields/,
  );
  for (const value of [-1, Number.NaN, Number.POSITIVE_INFINITY, '0.25']) {
    assert.throws(
      () => validateApprovedLiveEconomics({ ...economics, invocationPriceUsd: value }, config),
      /finite non-negative/,
    );
  }
});

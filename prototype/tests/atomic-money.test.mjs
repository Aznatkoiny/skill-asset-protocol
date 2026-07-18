import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ATOMIC_PER_USDC,
  BPS_DENOMINATOR,
  assertAtomic,
  floorBps,
  formatUsdc,
  parseUsdc,
} from '../atomic-money.mjs';

test('parseUsdc converts exact display values to six-decimal atomic units', () => {
  assert.equal(ATOMIC_PER_USDC, 1_000_000n);
  assert.equal(BPS_DENOMINATOR, 10_000n);
  assert.equal(parseUsdc('0'), 0n);
  assert.equal(parseUsdc('0.000001'), 1n);
  assert.equal(parseUsdc('0.25'), 250_000n);
  assert.equal(parseUsdc('9007199254740991.123456'), 9_007_199_254_740_991_123_456n);
});

test('parseUsdc rejects every non-string, negative, exponent, and over-precision input', () => {
  for (const value of [
    '-1', '0.0000001', '1e-6', '', 0.25, 0, Number.NaN, Number.POSITIVE_INFINITY,
    -0.01, 9_007_199_254.740992, 1n, null,
  ]) {
    assert.throws(() => parseUsdc(value), (error) => error?.name === 'MoneyInputError');
  }
});

test('assertAtomic accepts only non-negative bigint values', () => {
  assert.equal(assertAtomic(0n), 0n);
  assert.equal(assertAtomic(7n), 7n);
  assert.throws(() => assertAtomic(-1n), /must be non-negative/);
  for (const value of [1, '1', null, undefined]) {
    assert.throws(() => assertAtomic(value), /must be a bigint/);
  }
});

test('formatUsdc is a canonical six-decimal serialization boundary', () => {
  assert.equal(formatUsdc(0n), '0.000000');
  assert.equal(formatUsdc(1n), '0.000001');
  assert.equal(formatUsdc(250_000n), '0.250000');
  assert.equal(formatUsdc(1_000_001n), '1.000001');
});

test('floorBps floors deterministically without using floating point', () => {
  assert.equal(floorBps(250_000n, 250), 6_250n);
  assert.equal(floorBps(1n, 5_000), 0n);
  assert.equal(floorBps(3n, 5_000), 1n);
  assert.throws(() => floorBps(1n, -1), /between 0 and 10000/);
  assert.throws(() => floorBps(1n, 10_001), /between 0 and 10000/);
  assert.throws(() => floorBps(1n, 1.5), /safe integer/);
});

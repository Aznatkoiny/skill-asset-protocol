import assert from 'node:assert/strict';
import test from 'node:test';

import {
  INVALID_TARGET_VERDICT,
  assessBenchmark,
} from '../src/validity.mjs';

const score = (absoluteScore, criticalGatePass) => ({
  absoluteScore,
  criticalGatePass,
  passedThreshold: absoluteScore >= 0.8,
});

test('a failed target suppresses every clone and economics conclusion', () => {
  const result = assessBenchmark({
    threshold: 0.8,
    target: score(0.4, false),
  });
  assert.deepEqual(result, {
    valid: false,
    verdict: INVALID_TARGET_VERDICT,
    cloneConclusionAllowed: false,
    economicsConclusionAllowed: false,
    reason: 'Target score 0.400 is below 0.800 and target critical gates failed.',
  });
});

test('a passing target admits a clone result without deciding its meaning', () => {
  const result = assessBenchmark({
    threshold: 0.8,
    target: score(0.9, true),
  });
  assert.equal(result.valid, true);
  assert.equal(result.verdict, 'VALID_BENCHMARK');
  assert.equal(result.cloneConclusionAllowed, true);
  assert.equal(result.economicsConclusionAllowed, true);
});

test('a score-only target failure invalidates the benchmark', () => {
  const result = assessBenchmark({ threshold: 0.8, target: score(0.4, true) });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'Target score 0.400 is below 0.800.');
});

test('a critical-gate-only target failure invalidates the benchmark', () => {
  const result = assessBenchmark({ threshold: 0.8, target: score(0.9, false) });
  assert.equal(result.valid, false);
  assert.equal(result.reason, 'target critical gates failed.');
});

test('malformed scores and thresholds throw instead of failing open', () => {
  for (const malformed of [Number.NaN, Number.POSITIVE_INFINITY, '0.9', null]) {
    assert.throws(
      () => assessBenchmark({ threshold: 0.8, target: score(malformed, true) }),
      /target absoluteScore must be a finite number from 0 to 1/,
    );
  }
  for (const malformed of [Number.NaN, Number.POSITIVE_INFINITY, '0.8', 0, 1.1]) {
    assert.throws(
      () => assessBenchmark({ threshold: malformed, target: score(0.9, true) }),
      /threshold must be a finite number greater than 0 and at most 1/,
    );
  }
  assert.throws(
    () => assessBenchmark({ threshold: 0.8, target: { ...score(0.9, true), criticalGatePass: 'yes' } }),
    /criticalGatePass must be boolean/,
  );
});

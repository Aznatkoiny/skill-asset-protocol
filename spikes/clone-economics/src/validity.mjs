export const INVALID_TARGET_VERDICT = 'INVALID_BENCHMARK_TARGET_FAILED';

export function assessBenchmark({ threshold, target }) {
  if (!Number.isFinite(threshold) || threshold <= 0 || threshold > 1) {
    throw new TypeError('Benchmark threshold must be a finite number greater than 0 and at most 1');
  }
  if (!target || !Number.isFinite(target.absoluteScore)
      || target.absoluteScore < 0 || target.absoluteScore > 1) {
    throw new TypeError('Benchmark target absoluteScore must be a finite number from 0 to 1');
  }
  if (typeof target.criticalGatePass !== 'boolean') {
    throw new TypeError('Benchmark target criticalGatePass must be boolean');
  }
  const scoreFailed = target.absoluteScore < threshold;
  const gatesFailed = !target.criticalGatePass;
  if (scoreFailed || gatesFailed) {
    const failures = [
      scoreFailed ? `Target score ${target.absoluteScore.toFixed(3)} is below ${threshold.toFixed(3)}` : null,
      gatesFailed ? 'target critical gates failed' : null,
    ].filter(Boolean);
    return {
      valid: false,
      verdict: INVALID_TARGET_VERDICT,
      cloneConclusionAllowed: false,
      economicsConclusionAllowed: false,
      reason: `${failures.join(' and ')}.`,
    };
  }
  return {
    valid: true,
    verdict: 'VALID_BENCHMARK',
    cloneConclusionAllowed: true,
    economicsConclusionAllowed: true,
    reason: `Target met ${threshold.toFixed(3)} and every critical gate.`,
  };
}

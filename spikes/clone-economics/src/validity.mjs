export const INVALID_TARGET_VERDICT = 'INVALID_BENCHMARK_TARGET_FAILED';

export function assessBenchmark({ threshold, target }) {
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

export const RUBRIC_VERSION = 'contract-v1';
export const FIDELITY_THRESHOLD = 0.80;

const rounded = (value) => Number(value.toFixed(12));

function scoreCase(output, fixture) {
  const checks = [];
  const add = (id, dimension, weight, critical, passed) => {
    checks.push({ id, dimension, weight, critical, passed });
  };
  const rubric = fixture.rubric;
  add('expected-mode', 'mode', 1, true, output.includes(`Mode: ${rubric.expectedMode}`));
  add('max-questions', 'questions', 1, true, (output.match(/\?/g) ?? []).length <= rubric.maxQuestions);
  for (const [index, item] of rubric.exactPaths.entries()) {
    add(`exact-path-${index}`, 'grounding', item.weight, item.critical, output.includes(item.value));
  }
  for (const [index, item] of rubric.exactCommands.entries()) {
    add(`exact-command-${index}`, 'verification', item.weight, item.critical, output.includes(item.value));
  }
  for (const [index, item] of rubric.requiredAll.entries()) {
    add(`required-all-${index}`, item.dimension, item.weight, item.critical, output.includes(item.value));
  }
  for (const [index, item] of rubric.requiredAny.entries()) {
    add(`required-any-${index}`, item.dimension, item.weight, item.critical, item.values.some((value) => output.includes(value)));
  }
  for (const [index, item] of rubric.forbidden.entries()) {
    add(`forbidden-${index}`, item.dimension, item.weight, item.critical, !output.includes(item.value));
  }

  const totalWeight = checks.reduce((sum, item) => sum + item.weight, 0);
  const passedWeight = checks.filter((item) => item.passed).reduce((sum, item) => sum + item.weight, 0);
  const dimensionEntries = new Map();
  for (const check of checks) {
    const current = dimensionEntries.get(check.dimension) ?? { passedWeight: 0, totalWeight: 0 };
    current.totalWeight += check.weight;
    if (check.passed) current.passedWeight += check.weight;
    dimensionEntries.set(check.dimension, current);
  }
  const dimensions = Object.fromEntries([...dimensionEntries].map(([name, value]) => [name, rounded(value.passedWeight / value.totalWeight)]));
  return {
    id: fixture.id,
    score: rounded(passedWeight / totalWeight),
    criticalGatePass: checks.filter((item) => item.critical).every((item) => item.passed),
    dimensions,
    checks,
  };
}

export function scoreEvaluation(outputsById, fixtures, threshold = FIDELITY_THRESHOLD) {
  const cases = fixtures.map((fixture) => {
    const output = outputsById[fixture.id];
    if (typeof output !== 'string') throw new Error(`Missing evaluation output for ${fixture.id}`);
    return scoreCase(output, fixture);
  });
  const absoluteScore = rounded(cases.reduce((sum, item) => sum + item.score, 0) / cases.length);
  const criticalGatePass = cases.every((item) => item.criticalGatePass);
  return {
    absoluteScore,
    criticalGatePass,
    passedThreshold: absoluteScore >= threshold && criticalGatePass,
    cases,
  };
}

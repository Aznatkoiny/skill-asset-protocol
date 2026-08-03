export function renderJson(report) {
  return `${JSON.stringify(report, null, 2)}\n`;
}

const number = (value, digits = 3) => Number.isFinite(value) ? value.toFixed(digits) : 'unknown';

function scoreRows(target, clone) {
  return target.cases.map((item, index) => `| ${item.id} | ${item.score.toFixed(3)} | ${clone.cases[index].score.toFixed(3)} | ${clone.cases[index].criticalGatePass ? 'pass' : 'FAIL'} |`).join('\n');
}

export function renderMarkdown(report) {
  const conclusion = report.benchmark.valid
    ? 'The target passed its own gate; clone and economics interpretation may proceed.'
    : `**${report.benchmark.verdict}.** ${report.benchmark.reason} Clone quality, fidelity defense, moat, and break-even conclusions are suppressed.`;
  return `# Clone-economics spike report

**Evidence:** ${report.evidenceLabel}<br>
**Mode:** ${report.mode}<br>
**Verdict:** ${report.claimStatus}

${conclusion}

## Question

${report.question}

Target Skill: \`${report.target.skill.path}\` (\`${report.target.skill.sha256}\`)<br>
Reference: \`${report.target.reference.path}\` (\`${report.target.reference.sha256}\`)<br>
Dataset: N=${report.dataset.N} acquisition pairs, H=${report.dataset.H} heldout cases; IDs and normalized hashes disjoint=${report.dataset.disjoint}.

## Fidelity (${report.fidelity.rubricVersion})

Threshold: ${report.fidelity.threshold.toFixed(2)} plus every critical gate.

| Metric | Target | Clone |
|---|---:|---:|
| Absolute score | ${report.fidelity.target.absoluteScore.toFixed(3)} | ${report.fidelity.clone.absoluteScore.toFixed(3)} |
| Critical gates | ${report.fidelity.target.criticalGatePass ? 'pass' : 'FAIL'} | ${report.fidelity.clone.criticalGatePass ? 'pass' : 'FAIL'} |
| Retention (secondary) | — | ${number(report.fidelity.retention)} |

| Case | Target | Clone | Clone critical gate |
|---|---:|---:|---|
${scoreRows(report.fidelity.target, report.fidelity.clone)}

Deliberately bad clone: ${report.fidelity.badClone.absoluteScore.toFixed(3)}, critical gates ${report.fidelity.badClone.criticalGatePass ? 'pass' : 'FAIL'}.

## Synthetic v2 staleness overlay

**${report.evolution.evidenceLabel}** — updated target ${number(report.evolution.updatedTarget.absoluteScore)}; frozen v1 clone ${number(report.evolution.frozenClone.absoluteScore)}; stale-fidelity delta ${number(report.evolution.staleFidelityDelta)}.

${report.evolution.statement}

## Economics

| Quantity | USD / ratio |
|---|---:|
| A — modeled pair acquisition | ${number(report.economics.acquisitionModeledUsd)} |
| D — distillation provider cost | ${number(report.economics.distillationProviderUsd)} |
| E_tune — attacker tuning/evaluation | ${number(report.economics.tuningEvaluationUsd)} |
| C_deploy | ${number(report.economics.deployCostUsd)} |
| C_labor | ${number(report.economics.laborCostUsd)} (${report.economics.laborCostTreatment}) |
| B — attacker build | ${number(report.economics.attackerBuildUsd)} |
| E_measure — benchmark overhead, excluded from B | ${number(report.economics.measurementEvaluationUsd)} |
| D/A | ${report.economics.distillationToAcquisition ?? 'undefined'} |
| B/A | ${report.economics.buildToAcquisition ?? 'undefined'} |
| Break-even Invocations | ${report.benchmark.valid ? report.economics.breakEvenInvocations ?? 'undefined' : 'suppressed'} |

Acquisition is MODELED as N × listed Invocation price; no x402 payment settled. Provider/harness costs are listed separately and not double-counted into A.

## Usage, pricing, and timing

Pricing snapshot: input $${report.pricing.inputUsdPerMillion}/M, output $${report.pricing.outputUsdPerMillion}/M; as of ${report.pricing.asOf}; source: ${report.pricing.source}.<br>
Normalized usage: ${number(report.usage.normalized.inputTokens, 0)} input tokens, ${number(report.usage.normalized.outputTokens, 0)} output tokens.<br>
Sequential build time: ${report.timing.sequentialBuildMs} ms. Parallel-acquisition lower bound: ${report.timing.parallelAcquisitionLowerBoundMs} ms.<br>
Required update cadence: **${report.timing.requiredUpdateCadence.label}** — ${report.timing.requiredUpdateCadence.statement}

## Limitations

${report.limitations.map((item) => `- ${item}`).join('\n')}
`;
}

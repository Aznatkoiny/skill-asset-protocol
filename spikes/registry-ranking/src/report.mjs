import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import {
  computeSkillMetrics,
  createVerifiedBillingClassifier,
  parseSettlementMetricEvent,
  rankEligibleSkills,
} from './metrics.mjs';

function sortedMetrics(metricValues) {
  if (!Array.isArray(metricValues)) throw new TypeError('metrics must be an array');
  return metricValues.slice().sort((left, right) => left.skillId.localeCompare(right.skillId));
}

export function renderRegistryReport(metricValues) {
  const metrics = sortedMetrics(metricValues);
  const lines = [
    '# Settlement-verifiable registry report',
    '',
    'This settlement-verifiable report means the ledger supports that value moved. These metrics do not establish independent demand, usefulness, authorship, originality, or safety.',
  ];
  for (const metric of metrics) {
    lines.push(
      '',
      `## Skill: ${metric.skillId}`,
      '',
      `- Total settlements: ${metric.totalSettlements}`,
      `- Successful Invocations: ${metric.successfulInvocations}`,
      `- Settled failures: ${metric.settledFailures}`,
      `- Unresolved settlements: ${metric.unresolvedSettlements}`,
      `- Refunded settlements: ${metric.refundedSettlements}`,
      `- Unique payer wallets: ${metric.uniquePayerWallets}`,
      `- Unique independent Beneficiaries: ${metric.uniqueIndependentBeneficiaries}`,
      `- Refund-adjusted net (after refunded and recycled value), atomic units: ${metric.refundAdjustedNetAtomic}`,
      `- Independent net, atomic units: ${metric.independentNetAtomic}`,
      `- Independence confidence: ${metric.independenceConfidence}`,
      `- Registry eligibility: ${metric.registryStatus}`,
      '- Exclusions:',
    );
    for (const [reason, count] of Object.entries(metric.exclusionCounts)) {
      lines.push(`  - ${reason}: ${count}`);
    }
    if (metric.auditWarnings.length > 0) {
      lines.push('- Audit warnings:');
      for (const warning of metric.auditWarnings) lines.push(`  - ${warning}`);
    }
  }
  return `${lines.join('\n')}\n`;
}

export function buildRegistryReport(eventsValue, registryValue) {
  if (!Array.isArray(eventsValue)) throw new TypeError('settlement fixture must be an array');
  const classifier = createVerifiedBillingClassifier(registryValue);
  const parsedEvents = eventsValue.map(parseSettlementMetricEvent);
  const settlementIds = new Set();
  const successfulInvocationIds = new Set();
  for (const event of parsedEvents) {
    if (settlementIds.has(event.settlementId)) {
      throw new TypeError(`duplicate settlement ID '${event.settlementId}'`);
    }
    settlementIds.add(event.settlementId);
    if (event.outcome === 'succeeded') {
      if (successfulInvocationIds.has(event.invocationId)) {
        throw new TypeError(`duplicate successful Invocation '${event.invocationId}'`);
      }
      successfulInvocationIds.add(event.invocationId);
    }
  }
  const grouped = new Map();
  for (const event of parsedEvents) {
    if (!grouped.has(event.skillId)) grouped.set(event.skillId, []);
    grouped.get(event.skillId).push(event);
  }
  const skills = [...grouped.keys()]
    .sort()
    .map((skillId) => computeSkillMetrics(grouped.get(skillId), { classifier }));
  return Object.freeze({
    schemaVersion: 1,
    evidenceStatus: 'synthetic_registry_accounting_fixture',
    eligibilityRule: 'at least two classifier-verified successful independent Beneficiaries in distinct billing clusters and positive independent net',
    eligibleSkills: rankEligibleSkills(skills),
    skills: Object.freeze(skills),
  });
}

export async function main(argv = process.argv.slice(2)) {
  const json = argv.includes('--json');
  const paths = argv.filter((argument) => argument !== '--json');
  if (paths.length !== 2) {
    throw new TypeError('usage: report.mjs SETTLEMENTS_JSON VERIFIED_BILLING_REGISTRY_JSON [--json]');
  }
  const [eventsText, registryText] = await Promise.all(paths.map((path) => readFile(path, 'utf8')));
  const report = buildRegistryReport(JSON.parse(eventsText), JSON.parse(registryText));
  process.stdout.write(json
    ? `${JSON.stringify(report, null, 2)}\n`
    : renderRegistryReport(report.skills));
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { writeEvidenceBundle } from '../src/evidence.mjs';

export const LEGACY_SOURCE_SHA256 =
  '0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212';
export const LEGACY_SOURCE_BYTES = 76_631;

function assertLegacyFacts(source) {
  assert.equal(source.schemaVersion, 1, 'historical source fact mismatch: schemaVersion');
  assert.equal(source.mode, 'live', 'historical source fact mismatch: mode');
  assert.equal(source.dataset?.N, 6, 'historical source fact mismatch: N');
  assert.equal(source.fidelity?.target?.absoluteScore, 0.4, 'historical source fact mismatch: target score');
  assert.equal(source.fidelity?.target?.criticalGatePass, false, 'historical source fact mismatch: target gates');
  assert.equal(source.economics?.acquisitionModeledUsd, 1.5, 'historical source fact mismatch: modeled acquisition');
}

function scoreFor(source, record) {
  const cases = record.kind === 'target-heldout'
    ? source.fidelity.target.cases
    : record.kind === 'clone-heldout'
      ? source.fidelity.clone.cases
      : record.kind === 'bad-clone-heldout'
        ? source.fidelity.badClone.cases
        : record.kind === 'target-v2-heldout'
          ? source.evolution.updatedTarget.cases
          : record.kind === 'clone-v2-heldout'
            ? source.evolution.frozenClone.cases
            : null;
  if (!cases) return null;
  const score = cases.find((item) => item.id === record.caseId);
  if (!score) throw new Error(`Historical fidelity row missing for ${record.kind}:${record.caseId}`);
  return score;
}

function phaseFor(kind) {
  if (kind === 'target-train') return 'acquisition';
  if (kind === 'distill') return 'distillation';
  if (kind.endsWith('-heldout')) return 'evaluation';
  throw new Error(`Unsupported historical request kind: ${kind}`);
}

function profileFor(kind) {
  if (kind.startsWith('target-')) return 'target';
  if (kind.startsWith('bad-clone-')) return 'bad-clone';
  return 'clone';
}

export function normalizeLegacyReport(source) {
  assertLegacyFacts(source);
  if (!Array.isArray(source.usage?.raw) || source.usage.raw.length !== 29) {
    throw new Error('Historical source must contain exactly 29 retained usage rows');
  }
  const acquisitionPerPair = source.economics.acquisitionModeledUsd / source.dataset.N;
  return source.usage.raw.map((record, index) => {
    const score = scoreFor(source, record);
    const inputTokens = record.normalizedUsage?.inputTokens ?? record.rawUsage?.input_tokens ?? null;
    const outputTokens = record.normalizedUsage?.outputTokens ?? record.rawUsage?.output_tokens ?? null;
    const providerCostUsd = Number.isFinite(record.costUsd) && record.costUsd >= 0
      ? record.costUsd
      : null;
    return {
      sampleId: `legacy:${record.requestId ?? `${record.kind}:${record.caseId ?? 'none'}:${index + 1}`}`,
      phase: phaseFor(record.kind),
      profile: profileFor(record.kind),
      caseId: record.caseId ?? null,
      n: 6,
      replicateId: null,
      pairOrderSeed: null,
      requestedDistillationSeed: null,
      appliedDistillationSeed: null,
      distillationSeedStatus: 'not_recorded',
      distillationSeedMechanism: 'historical_source_not_recorded',
      success: true,
      latencyMs: record.latencyMs,
      inputTokens,
      outputTokens,
      providerCostMicroUsd: providerCostUsd === null
        ? null
        : String(Math.round(providerCostUsd * 1_000_000)),
      providerCostUsd,
      acquisitionCostUsd: record.kind === 'target-train' ? acquisitionPerPair : 0,
      acquisitionEvidence: record.kind === 'target-train' ? 'MODELED' : null,
      score: score?.score ?? null,
      criticalGatePass: score?.criticalGatePass ?? null,
      failureClass: null,
      providerRequestId: record.requestId ?? null,
    };
  });
}

function parseNamedArgs(argv) {
  const allowed = new Set(['--input', '--expected-sha256', '--output']);
  if (argv.length !== 6) throw new Error('Usage: import-legacy-run.mjs --input <path> --expected-sha256 <digest> --output <path>');
  const values = {};
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(name) || typeof value !== 'string' || value === '' || values[name] !== undefined) {
      throw new Error('Importer accepts each of --input, --expected-sha256, and --output exactly once');
    }
    values[name] = value;
  }
  if (Object.keys(values).length !== 3) throw new Error('Importer requires all named arguments');
  return {
    input: path.resolve(values['--input']),
    expectedSha256: values['--expected-sha256'],
    output: path.resolve(values['--output']),
  };
}

export function importLegacyRun(argv) {
  const args = parseNamedArgs(argv);
  if (args.expectedSha256 !== LEGACY_SOURCE_SHA256) {
    throw new Error('Declared digest must equal the immutable legacy digest');
  }
  const sourceBytes = fs.readFileSync(args.input);
  if (sourceBytes.length !== LEGACY_SOURCE_BYTES) {
    throw new Error(`Legacy source byte count mismatch: ${sourceBytes.length} != ${LEGACY_SOURCE_BYTES}`);
  }
  const actualDigest = createHash('sha256').update(sourceBytes).digest('hex');
  if (actualDigest !== LEGACY_SOURCE_SHA256) throw new Error('Legacy source digest mismatch');
  if (fs.existsSync(args.output)) throw new Error('Evidence output directory already exists');
  const source = JSON.parse(sourceBytes.toString('utf8'));
  const samples = normalizeLegacyReport(source);
  writeEvidenceBundle({
    outputDir: args.output,
    manifest: {
      experimentId: '2026-07-12-n6-invalid',
      recordedAtUtc: null,
      gitCommit: 'historical-source-not-recorded',
      command: 'historical live command not retained exactly',
      modelProvider: 'Anthropic',
      model: source.usage.raw[0]?.model ?? null,
      evidenceLabel: 'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED',
      sourceEvidence: {
        kind: 'legacy-report-json',
        sha256: LEGACY_SOURCE_SHA256,
        bytes: LEGACY_SOURCE_BYTES,
      },
      configuration: {
        historicalRunDate: '2026-07-12',
        sourceTimestamp: 'not-recorded',
        nValues: [6],
        pairOrderSeeds: ['not-recorded'],
        requestedDistillationSeeds: ['not-recorded'],
        appliedDistillationSeeds: ['not-recorded'],
        acquisitionTreatment: 'modeled',
        attemptCoverage: 'successful fifth run only; four setup attempts have no normalized records',
        benchmarkVerdict: 'INVALID_BENCHMARK_TARGET_FAILED',
      },
    },
    samples,
    reportInputs: {
      evidenceLabel: 'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED',
      verdict: 'INVALID_BENCHMARK_TARGET_FAILED',
      suppressionReason: 'INVALID_BENCHMARK_TARGET_FAILED',
      limitations: ['ACQUISITION_MODELED', 'HISTORICAL_ATTEMPTS_INCOMPLETE'],
    },
    reproduction: 'node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid',
  });
  return { output: args.output, samples: samples.length };
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  try {
    const result = importLegacyRun(process.argv.slice(2));
    console.log(`Imported ${result.samples} normalized historical samples.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

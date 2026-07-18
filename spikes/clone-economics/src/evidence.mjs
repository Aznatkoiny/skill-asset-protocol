import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { liveAuthorizationHash } from './authorization.mjs';
import { calculateProviderCostMicroUsd } from './budget.mjs';

const SAMPLE_KEYS = new Set([
  'sampleId', 'phase', 'profile', 'caseId', 'n', 'replicateId',
  'pairOrderSeed', 'requestedDistillationSeed', 'appliedDistillationSeed',
  'distillationSeedStatus', 'distillationSeedMechanism',
  'success', 'latencyMs', 'inputTokens', 'outputTokens',
  'providerCostMicroUsd', 'providerCostUsd',
  'acquisitionCostUsd', 'acquisitionEvidence', 'score', 'criticalGatePass',
  'failureClass', 'providerRequestId',
]);
const FORBIDDEN_KEYS = new Set([
  'prompt', 'payload', 'output', 'rawResponse', 'apiKey', 'authorization',
  'headers', 'skillText', 'referenceText',
]);
const CONFIGURATION_KEYS = new Set([
  'sweepConfig', 'nValues', 'replicateIds', 'pairOrderSeeds',
  'requestedDistillationSeeds', 'appliedDistillationSeeds', 'distillationSeedEvidence',
  'tokenCaps', 'pricingSnapshot', 'evidenceLabels', 'acquisitionTreatment',
  'historicalRunDate', 'sourceTimestamp', 'attemptCoverage', 'benchmarkVerdict',
  'publicationGate', 'suppressionReason', 'fixtureSet',
]);
const REQUIRED_BUNDLE_FILES = ['samples.jsonl', 'summary.json', 'report.md', 'README.md'];
const rounded = (value) => Number(value.toFixed(12));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function canonicalize(value) {
  if (typeof value === 'bigint') return value.toString();
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  throw new Error(`Unsupported evidence value type: ${typeof value}`);
}

const stableJson = (value) => `${JSON.stringify(canonicalize(value), null, 2)}\n`;
const stableLine = (value) => JSON.stringify(canonicalize(value));

function finiteNonNegative(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return;
  if (!Number.isFinite(value) || value < 0) throw new Error(`${label} must be a finite non-negative number or null`);
}

function validateSample(sample) {
  if (!sample || typeof sample !== 'object' || Array.isArray(sample)) throw new Error('Sample must be an object');
  for (const key of Object.keys(sample)) {
    if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden sample field: ${key}`);
    if (!SAMPLE_KEYS.has(key)) throw new Error(`unknown sample field: ${key}`);
  }
  if (typeof sample.sampleId !== 'string' || sample.sampleId.trim() === '') throw new Error('sampleId is required');
  if (typeof sample.phase !== 'string' || sample.phase.trim() === '') throw new Error('sample phase is required');
  if (typeof sample.profile !== 'string' || sample.profile.trim() === '') throw new Error('sample profile is required');
  if (!(sample.caseId === null || typeof sample.caseId === 'string')) throw new Error('sample caseId must be string or null');
  if (typeof sample.success !== 'boolean') throw new Error('sample success must be boolean');
  finiteNonNegative(sample.latencyMs, 'sample latencyMs');
  for (const key of ['inputTokens', 'outputTokens']) {
    const value = sample[key];
    if (!(value === null || (Number.isSafeInteger(value) && value >= 0))) {
      throw new Error(`${key} must be a non-negative safe integer or null`);
    }
  }
  finiteNonNegative(sample.providerCostUsd, 'sample providerCostUsd', { nullable: true });
  if (sample.providerCostMicroUsd !== undefined && sample.providerCostMicroUsd !== null
      && !/^(?:0|[1-9]\d*)$/.test(sample.providerCostMicroUsd)) {
    throw new Error('providerCostMicroUsd must be a base-10 non-negative integer string or null');
  }
  if (sample.acquisitionCostUsd !== undefined) {
    finiteNonNegative(sample.acquisitionCostUsd, 'sample acquisitionCostUsd');
  }
  if (sample.score !== undefined && sample.score !== null
      && (!Number.isFinite(sample.score) || sample.score < 0 || sample.score > 1)) {
    throw new Error('sample score must be a finite number from 0 to 1 or null');
  }
  if (sample.criticalGatePass !== undefined && sample.criticalGatePass !== null
      && typeof sample.criticalGatePass !== 'boolean') {
    throw new Error('sample criticalGatePass must be boolean or null');
  }
  for (const key of ['n', 'pairOrderSeed', 'requestedDistillationSeed', 'appliedDistillationSeed']) {
    if (sample[key] !== undefined && sample[key] !== null && !Number.isSafeInteger(sample[key])) {
      throw new Error(`${key} must be a safe integer or null`);
    }
  }
  if ((sample.inputTokens === null || sample.outputTokens === null) && sample.providerCostMicroUsd != null) {
    throw new Error('Unknown usage requires providerCostMicroUsd to be null');
  }
  if (sample.providerCostMicroUsd === null && sample.providerCostUsd !== null) {
    throw new Error('Unknown exact provider cost requires providerCostUsd to be null');
  }
  return sample;
}

const percentile = (values, p) => {
  if (values.length === 0) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(p * ordered.length) - 1)];
};

function sum(values) {
  return values.reduce((total, value) => total + value, 0);
}

function summarizeScoresByProfile(samples) {
  const profiles = [...new Set(samples.map((sample) => sample.profile))].sort();
  return Object.fromEntries(profiles.map((profile) => {
    const scored = samples.filter((sample) => sample.profile === profile && Number.isFinite(sample.score));
    return [profile, {
      scoredSamples: scored.length,
      meanScore: scored.length === 0 ? null : rounded(sum(scored.map((sample) => sample.score)) / scored.length),
      criticalGatePass: scored.length === 0
        ? null
        : scored.every((sample) => sample.criticalGatePass === true),
    }];
  }));
}

export function recomputeSummary(samples) {
  if (!Array.isArray(samples)) throw new Error('samples must be an array');
  for (const sample of samples) validateSample(sample);
  const ids = new Set();
  for (const sample of samples) {
    if (ids.has(sample.sampleId)) throw new Error(`duplicate sampleId: ${sample.sampleId}`);
    ids.add(sample.sampleId);
  }
  const latencies = samples
    .filter((sample) => sample.success && Number.isFinite(sample.latencyMs))
    .map((sample) => sample.latencyMs);
  return {
    attemptedSamples: samples.length,
    successfulSamples: samples.filter((sample) => sample.success).length,
    failedSamples: samples.filter((sample) => !sample.success).length,
    providerCostUsd: samples.every((sample) => sample.providerCostUsd !== null)
      ? rounded(sum(samples.map((sample) => sample.providerCostUsd)))
      : null,
    acquisition: {
      modeledUsd: rounded(sum(samples.map((sample) => sample.acquisitionCostUsd ?? 0))),
      evidence: [...new Set(samples.map((sample) => sample.acquisitionEvidence).filter(Boolean))].sort(),
    },
    latencyMs: { p50: percentile(latencies, 0.5), p95: percentile(latencies, 0.95) },
    fidelity: summarizeScoresByProfile(samples),
  };
}

function sanitizeConfiguration(configuration = {}) {
  if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) {
    throw new Error('Evidence configuration must be an object');
  }
  for (const key of Object.keys(configuration)) {
    if (!CONFIGURATION_KEYS.has(key)) throw new Error(`Unsupported evidence configuration field: ${key}`);
  }
  return canonicalize(configuration);
}

function validateSourceEvidence(sourceEvidence) {
  if (sourceEvidence === null || sourceEvidence === undefined) return null;
  if (!sourceEvidence || typeof sourceEvidence !== 'object'
      || JSON.stringify(Object.keys(sourceEvidence).sort()) !== JSON.stringify(['bytes', 'kind', 'sha256'])) {
    throw new Error('sourceEvidence must contain only kind, sha256, and bytes');
  }
  if (typeof sourceEvidence.kind !== 'string' || sourceEvidence.kind === '') throw new Error('sourceEvidence kind is required');
  if (!/^[0-9a-f]{64}$/.test(sourceEvidence.sha256)) throw new Error('sourceEvidence sha256 must be a lowercase digest');
  if (!Number.isSafeInteger(sourceEvidence.bytes) || sourceEvidence.bytes <= 0) throw new Error('sourceEvidence bytes must be positive');
  return { ...sourceEvidence };
}

function renderReport(summary, interpretation) {
  const value = (input) => input === null ? 'unknown' : String(input);
  return `# Clone-economics evidence report

${interpretation}

- Attempted samples: ${summary.attemptedSamples}
- Successful samples: ${summary.successfulSamples}
- Failed samples: ${summary.failedSamples}
- Provider cost USD: ${value(summary.providerCostUsd)}
- Latency p50 ms: ${value(summary.latencyMs.p50)}
- Latency p95 ms: ${value(summary.latencyMs.p95)}
`;
}

function renderReadme(reproduction) {
  return `# Evidence bundle

Verify and reproduce:

\`\`\`bash
${reproduction}
\`\`\`

Samples are normalized and allow-listed. Prompt payloads, output text, API keys,
headers, target Skill bytes, and reference bytes are excluded.

Unknown usage or cost remains null and makes aggregate provider cost unknown.
This bundle does not by itself authorize publication or a live benchmark claim.
`;
}

export function writeEvidenceBundle({
  outputDir,
  manifest,
  samples,
  interpretation,
  reproduction,
}) {
  if (!manifest || typeof manifest.experimentId !== 'string' || manifest.experimentId === '') {
    throw new Error('Evidence manifest experimentId is required');
  }
  if (typeof manifest.evidenceLabel !== 'string' || manifest.evidenceLabel === '') {
    throw new Error('Evidence manifest evidenceLabel is required');
  }
  if (typeof manifest.command !== 'string' || manifest.command === '') throw new Error('Evidence manifest command is required');
  if (typeof interpretation !== 'string' || interpretation === '') throw new Error('Evidence interpretation is required');
  if (typeof reproduction !== 'string' || reproduction === '') throw new Error('Evidence reproduction command is required');
  const summary = recomputeSummary(samples);
  fs.mkdirSync(outputDir, { recursive: true });
  if (fs.readdirSync(outputDir).length !== 0) throw new Error('Evidence output directory must be empty');

  const contents = {
    'samples.jsonl': `${samples.map(stableLine).join('\n')}\n`,
    'summary.json': stableJson(summary),
    'report.md': renderReport(summary, interpretation),
    'README.md': renderReadme(reproduction),
  };
  for (const name of REQUIRED_BUNDLE_FILES) fs.writeFileSync(path.join(outputDir, name), contents[name]);

  const recordedAtUtc = manifest.recordedAtUtc === undefined ? new Date().toISOString() : manifest.recordedAtUtc;
  if (!(recordedAtUtc === null || (typeof recordedAtUtc === 'string'
      && Number.isFinite(Date.parse(recordedAtUtc))
      && /^\d{4}-\d{2}-\d{2}T/.test(recordedAtUtc)))) {
    throw new Error('recordedAtUtc must be an ISO-8601 instant or null');
  }
  const sourceEvidence = validateSourceEvidence(manifest.sourceEvidence);
  const configuration = sanitizeConfiguration(manifest.configuration);
  if (recordedAtUtc === null
      && !(configuration.historicalRunDate && configuration.sourceTimestamp === 'not-recorded')) {
    throw new Error('A null recordedAtUtc requires a historical date and sourceTimestamp not-recorded');
  }
  const finalManifest = {
    schemaVersion: 1,
    experimentId: manifest.experimentId,
    recordedAtUtc,
    gitCommit: manifest.gitCommit ?? 'not-recorded',
    command: manifest.command,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    modelProvider: manifest.modelProvider ?? null,
    model: manifest.model ?? null,
    evidenceLabel: manifest.evidenceLabel,
    sourceEvidence,
    liveBudget: canonicalize(manifest.liveBudget ?? null),
    configuration,
    files: Object.fromEntries(REQUIRED_BUNDLE_FILES.map((name) => [name, {
      sha256: sha256(contents[name]),
      bytes: Buffer.byteLength(contents[name]),
    }])),
  };
  fs.writeFileSync(path.join(outputDir, 'manifest.json'), stableJson(finalManifest));
  return finalManifest;
}

function assertReportMatchesSummary(report, summary) {
  const fields = {
    'Attempted samples': summary.attemptedSamples,
    'Successful samples': summary.successfulSamples,
    'Failed samples': summary.failedSamples,
    'Provider cost USD': summary.providerCostUsd,
    'Latency p50 ms': summary.latencyMs.p50,
    'Latency p95 ms': summary.latencyMs.p95,
  };
  for (const [label, expected] of Object.entries(fields)) {
    const match = report.match(new RegExp(`^- ${label}: (.+)$`, 'm'));
    if (!match) throw new Error(`report.md is missing ${label}`);
    const actual = match[1] === 'unknown' ? null : Number(match[1]);
    if (!Object.is(actual, expected)) throw new Error(`report.md ${label} differs from summary.json`);
  }
}

function verifyLiveRows(samples, manifest, dir) {
  if (manifest.liveBudget === null) return;
  const allowed = [
    'snapshotPath', 'snapshotSha256', 'authorizationHash', 'humanCapMicroUsd',
    'conservativeEstimateMicroUsd', 'worstCasePerCallMicroUsd', 'attemptedCalls',
    'knownAccruedMicroUsd', 'outstandingReservedMicroUsd', 'lock',
  ];
  if (JSON.stringify(Object.keys(manifest.liveBudget).sort()) !== JSON.stringify(allowed.sort())) {
    throw new Error('liveBudget contains unexpected or missing fields');
  }
  if (path.isAbsolute(manifest.liveBudget.snapshotPath) || manifest.liveBudget.snapshotPath.includes('..')) {
    throw new Error('liveBudget snapshotPath must be repository-relative');
  }
  const snapshotPath = path.resolve(dir, '..', '..', manifest.liveBudget.snapshotPath);
  const snapshotBytes = fs.readFileSync(snapshotPath);
  if (sha256(snapshotBytes) !== manifest.liveBudget.snapshotSha256) throw new Error('Live budget snapshot hash mismatch');
  const snapshot = JSON.parse(snapshotBytes);
  const expectedAuthorization = liveAuthorizationHash({
    config: manifest.configuration.sweepConfig,
    snapshot,
  });
  if (expectedAuthorization !== manifest.liveBudget.authorizationHash) throw new Error('Live authorization hash mismatch');
  if (manifest.liveBudget.attemptedCalls !== samples.length) throw new Error('Live attempted-call count differs from samples');
  for (const sample of samples) {
    if (sample.inputTokens === null || sample.outputTokens === null) {
      if (sample.providerCostMicroUsd !== null || sample.providerCostUsd !== null) {
        throw new Error('Unknown live usage requires both provider costs to be null');
      }
      continue;
    }
    const expected = calculateProviderCostMicroUsd({
      inputTokens: sample.inputTokens,
      outputTokens: sample.outputTokens,
      snapshot,
    });
    if (sample.providerCostMicroUsd !== expected.toString()) throw new Error(`Live exact provider cost mismatch for ${sample.sampleId}`);
  }
}

export function verifyEvidenceBundle(dir) {
  const manifestPath = path.join(dir, 'manifest.json');
  if (!fs.existsSync(manifestPath)) throw new Error('Missing required evidence file: manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.schemaVersion !== 1) throw new Error('Unsupported evidence manifest schemaVersion');
  for (const name of REQUIRED_BUNDLE_FILES) {
    const filePath = path.join(dir, name);
    if (!fs.existsSync(filePath)) throw new Error(`Missing required evidence file: ${name}`);
    const bytes = fs.readFileSync(filePath);
    const expected = manifest.files?.[name];
    if (!expected || expected.bytes !== bytes.length || expected.sha256 !== sha256(bytes)) {
      throw new Error(`Evidence hash or byte count mismatch: ${name}`);
    }
  }
  const sampleText = fs.readFileSync(path.join(dir, 'samples.jsonl'), 'utf8');
  if (!sampleText.endsWith('\n')) throw new Error('samples.jsonl must end with a newline');
  const lines = sampleText.slice(0, -1).split('\n');
  const samples = lines.length === 1 && lines[0] === '' ? [] : lines.map((line) => JSON.parse(line));
  const summary = recomputeSummary(samples);
  if (fs.readFileSync(path.join(dir, 'summary.json'), 'utf8') !== stableJson(summary)) {
    throw new Error('summary.json differs from recomputation');
  }
  assertReportMatchesSummary(fs.readFileSync(path.join(dir, 'report.md'), 'utf8'), summary);
  verifyLiveRows(samples, manifest, dir);
  return { valid: true, manifest, summary, samples };
}

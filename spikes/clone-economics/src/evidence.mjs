import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { liveAuthorizationHash } from './authorization.mjs';
import {
  calculateProviderCostMicroUsd,
  conservativeSweepRequestCount,
  estimateLiveSweepMicroUsd,
  validateApprovedBudgetSnapshot,
  validateBudgetSnapshotShape,
} from './budget.mjs';
import { loadFixtureSet } from './fixture-set.mjs';
import { readGitState } from './git-state.mjs';
import { validateApprovedLiveEconomics, validateLiveEconomicsShape } from './live-economics.mjs';
import { validateSweepConfig } from './sweep.mjs';

const evidenceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const SAMPLE_KEYS = new Set([
  'sampleId', 'phase', 'profile', 'caseId', 'n', 'replicateId',
  'pairOrderSeed', 'requestedDistillationSeed', 'appliedDistillationSeed',
  'distillationSeedStatus', 'distillationSeedMechanism',
  'success', 'latencyMs', 'inputTokens', 'outputTokens',
  'providerCostMicroUsd', 'providerCostUsd',
  'acquisitionCostUsd', 'acquisitionEvidence', 'score', 'criticalGatePass',
  'failureClass', 'providerRequestId',
  'budgetAttemptId',
]);
const SAMPLE_PHASES = new Set(['acquisition', 'distillation', 'evaluation']);
const SAMPLE_PROFILES = new Set(['target', 'clone', 'bad-clone']);
const DISTILLATION_SEED_STATUSES = new Set([
  'not_requested', 'synthetic_honored', 'honored', 'unsupported', 'not_recorded',
]);
const DISTILLATION_SEED_MECHANISMS = new Set([
  'no_seed_requested',
  'deterministic_mock_fixture_selection',
  'provider_seed_not_supported_by_adapter',
  'historical_source_not_recorded',
]);
const FORBIDDEN_KEYS = new Set([
  'prompt', 'payload', 'output', 'rawResponse', 'apiKey', 'authorization',
  'headers', 'skillText', 'targetSkill', 'targetSkillText', 'referenceText',
]);
const CONFIGURATION_KEYS = new Set([
  'sweepConfig', 'nValues', 'replicateIds', 'pairOrderSeeds',
  'requestedDistillationSeeds', 'appliedDistillationSeeds', 'distillationSeedEvidence',
  'tokenCaps', 'pricingSnapshot', 'evidenceLabels', 'acquisitionTreatment',
  'historicalRunDate', 'sourceTimestamp', 'attemptCoverage', 'benchmarkVerdict',
  'publicationGate', 'suppressionReason', 'fixtureSet',
  'liveEconomics',
]);
const REQUIRED_BUNDLE_FILES = ['samples.jsonl', 'summary.json', 'report.md', 'README.md'];
const ALL_BUNDLE_FILES = [...REQUIRED_BUNDLE_FILES, 'manifest.json'];
const MANIFEST_INPUT_KEYS = [
  'experimentId', 'executionMode', 'recordedAtUtc', 'gitCommit', 'gitDirty', 'command', 'modelProvider', 'model',
  'evidenceLabel', 'sourceEvidence', 'liveBudget', 'configuration', 'readmeInputs',
];
const MANIFEST_KEYS = [
  'schemaVersion', 'experimentId', 'executionMode', 'recordedAtUtc', 'gitCommit', 'gitDirty', 'command', 'runtime',
  'modelProvider', 'model', 'evidenceLabel', 'sourceEvidence', 'liveBudget',
  'configuration', 'reportInputs', 'readmeInputs', 'files',
];
const EXECUTION_MODES = new Set(['mock', 'live', 'historical']);
const HISTORICAL_GIT_COMMIT = 'historical-source-not-recorded';
const HISTORICAL_SOURCE_EVIDENCE = {
  kind: 'legacy-report-json',
  sha256: '0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212',
  bytes: 76_631,
};
const REPORT_INPUT_KEYS = ['evidenceLabel', 'verdict', 'suppressionReason', 'limitations'];
const EVIDENCE_LABELS = new Set([
  'SYNTHETIC',
  'SYNTHETIC FAILED TARGET',
  'LIVE CANDIDATE — PUBLICATION GATE PASSED',
  'LIVE CANDIDATE — CONCLUSIONS SUPPRESSED',
  'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED',
]);
const VERDICTS = new Set([
  'HIGH_N_PUBLICATION_GATE_PASSED',
  'HIGH_N_NOT_LIVE',
  'STANDALONE_TARGET_INVALID',
  'STANDALONE_TARGET_EXECUTION_FAILED',
  'HIGH_N_INCOMPLETE',
  'HIGH_N_TARGET_INVALID',
  'DISTILLATION_SEEDS_UNCONTROLLED',
  'INVALID_BENCHMARK_TARGET_FAILED',
]);
const LIMITATIONS = new Set([
  'SYNTHETIC_ONLY',
  'INCOMPLETE_PROVIDER_COST',
  'ACQUISITION_MODELED',
  'HISTORICAL_ATTEMPTS_INCOMPLETE',
  'DIRTY_CHECKOUT',
]);
const rounded = (value) => Number(value.toFixed(12));
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const SENSITIVE_VALUE_TOKENS = new Set([
  'apikey', 'authorization', 'authorisation', 'bearer', 'header', 'headers',
  'raw', 'rawresponse', 'rawpayload', 'rawoutput', 'tmp', 'temp', 'temporary',
  'path', 'paths',
]);

function containsSensitiveValue(value) {
  const tokens = value
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((token) => token.toLowerCase());
  if (tokens.some((token) => SENSITIVE_VALUE_TOKENS.has(token))) return true;
  return tokens.some((token, index) => token === 'api' && tokens[index + 1] === 'key');
}

function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

function assertPortableJson(value, label = 'evidence input', active = new WeakSet(), checkSensitive = true) {
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (value.length > 4096) throw new Error(`${label} exceeds the evidence string length limit`);
    if (checkSensitive && containsSensitiveValue(value)) {
      throw new Error(`${label} contains a sensitive evidence value`);
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error(`${label} must contain only finite JSON numbers`);
    return;
  }
  if (typeof value !== 'object') {
    throw new Error(`${label} contains unsupported ${typeof value} value`);
  }
  if (active.has(value)) throw new Error(`${label} must not contain cycles`);
  active.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) {
        throw new Error(`${label} contains a non-plain array`);
      }
      if (Object.getOwnPropertySymbols(value).length !== 0) {
        throw new Error(`${label} must not contain symbol keys`);
      }
      const keys = Object.getOwnPropertyNames(value);
      const expectedKeys = [...Array.from({ length: value.length }, (_, index) => String(index)), 'length'];
      if (JSON.stringify(keys) !== JSON.stringify(expectedKeys)) {
        throw new Error(`${label} must not contain sparse arrays or extra array properties`);
      }
      for (let index = 0; index < value.length; index += 1) {
        assertPortableJson(value[index], `${label}[${index}]`, active, checkSensitive);
      }
      return;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new Error(`${label} contains a non-plain object`);
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      throw new Error(`${label} must not contain symbol keys`);
    }
    for (const key of Object.getOwnPropertyNames(value)) {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor?.enumerable) throw new Error(`${label}.${key} must not be non-enumerable`);
      if (!Object.hasOwn(descriptor, 'value')) {
        throw new Error(`${label}.${key} must be a data property`);
      }
      if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden evidence field: ${label}.${key}`);
      assertPortableJson(descriptor.value, `${label}.${key}`, active, checkSensitive);
    }
  } finally {
    active.delete(value);
  }
}

function canonicalize(value) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
  );
}

const stableJson = (value) => `${JSON.stringify(canonicalize(value), null, 2)}\n`;
const stableLine = (value) => JSON.stringify(canonicalize(value));

function finiteNonNegative(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return;
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${label} must be a finite non-negative number${nullable ? ' or null' : ''}`);
  }
}

function safeIdentifier(value, label, maxLength) {
  if (typeof value !== 'string'
      || value.length === 0
      || value.length > maxLength
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value)) {
    throw new Error(`${label} must be a bounded safe identifier`);
  }
}

function validateSample(sample) {
  if (!sample || typeof sample !== 'object' || Array.isArray(sample)) throw new Error('Sample must be an object');
  for (const key of Object.keys(sample)) {
    if (FORBIDDEN_KEYS.has(key)) throw new Error(`forbidden sample field: ${key}`);
    if (!SAMPLE_KEYS.has(key)) throw new Error(`unknown sample field: ${key}`);
  }
  assertPortableJson(sample, 'sample');
  assertExactKeys(sample, SAMPLE_KEYS, 'Sample');
  safeIdentifier(sample.sampleId, 'sampleId', 256);
  if (!SAMPLE_PHASES.has(sample.phase)) throw new Error('sample phase is unsupported');
  if (!SAMPLE_PROFILES.has(sample.profile)) throw new Error('sample profile is unsupported');
  if (sample.caseId !== null) safeIdentifier(sample.caseId, 'caseId', 128);
  if (sample.replicateId !== null) safeIdentifier(sample.replicateId, 'replicateId', 64);
  if (sample.providerRequestId !== null) safeIdentifier(sample.providerRequestId, 'providerRequestId', 128);
  if (sample.budgetAttemptId !== null
      && !(typeof sample.budgetAttemptId === 'string' && /^attempt-\d{6}$/.test(sample.budgetAttemptId))) {
    throw new Error('budgetAttemptId must be an exact reservation identifier or null');
  }
  if (sample.failureClass !== null
      && !(typeof sample.failureClass === 'string' && /^[A-Z][A-Za-z0-9]{0,63}$/.test(sample.failureClass))) {
    throw new Error('failureClass must be an error-class token or null');
  }
  if (!(sample.acquisitionEvidence === null || sample.acquisitionEvidence === 'MODELED')) {
    throw new Error('acquisitionEvidence is unsupported');
  }
  if (!DISTILLATION_SEED_STATUSES.has(sample.distillationSeedStatus)) {
    throw new Error('distillationSeedStatus is unsupported');
  }
  if (!DISTILLATION_SEED_MECHANISMS.has(sample.distillationSeedMechanism)) {
    throw new Error('distillationSeedMechanism is unsupported');
  }
  if (typeof sample.success !== 'boolean') throw new Error('sample success must be boolean');
  finiteNonNegative(sample.latencyMs, 'sample latencyMs');
  for (const key of ['inputTokens', 'outputTokens']) {
    const value = sample[key];
    if (!(value === null || (Number.isSafeInteger(value) && value >= 0))) {
      throw new Error(`${key} must be a non-negative safe integer or null`);
    }
  }
  finiteNonNegative(sample.providerCostUsd, 'sample providerCostUsd', { nullable: true });
  if (sample.providerCostMicroUsd !== null
      && !/^(?:0|[1-9]\d*)$/.test(sample.providerCostMicroUsd)) {
    throw new Error('providerCostMicroUsd must be a base-10 non-negative integer string or null');
  }
  finiteNonNegative(sample.acquisitionCostUsd, 'sample acquisitionCostUsd');
  if (sample.score !== null
      && (!Number.isFinite(sample.score) || sample.score < 0 || sample.score > 1)) {
    throw new Error('sample score must be a finite number from 0 to 1 or null');
  }
  if (sample.criticalGatePass !== null
      && typeof sample.criticalGatePass !== 'boolean') {
    throw new Error('sample criticalGatePass must be boolean or null');
  }
  if (sample.n !== null && (!Number.isSafeInteger(sample.n) || sample.n <= 0)) {
    throw new Error('n must be a positive safe integer or null');
  }
  for (const key of ['pairOrderSeed', 'requestedDistillationSeed', 'appliedDistillationSeed']) {
    if (sample[key] !== null && !Number.isSafeInteger(sample[key])) {
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

function nonEmptyString(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return;
  if (typeof value !== 'string' || value === '') {
    throw new Error(`${label} must be a non-empty string${nullable ? ' or null' : ''}`);
  }
}

function integerArray(value, label, { positive = false, historical = false } = {}) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (let index = 0; index < value.length; index += 1) {
    const item = value[index];
    if (historical && item === 'not-recorded') continue;
    if (!Number.isSafeInteger(item) || (positive && item <= 0)) {
      throw new Error(`${label}[${index}] must be a ${positive ? 'positive ' : ''}safe integer${historical ? ' or not-recorded' : ''}`);
    }
  }
}

function stringArray(value, label, allowed = null) {
  if (!Array.isArray(value)) throw new Error(`${label} must be an array`);
  for (let index = 0; index < value.length; index += 1) {
    nonEmptyString(value[index], `${label}[${index}]`);
    if (allowed && !allowed.has(value[index])) throw new Error(`${label}[${index}] is unsupported`);
  }
}

function validateSweepConfiguration(value) {
  const keys = [
    'schemaVersion', 'experimentFamily', 'fixtureSet', 'nValues', 'heldoutMinimum',
    'replicates', 'highNDefinition', 'targetThreshold', 'requireAllTargetCriticalGates',
    'acquisitionTreatment', 'attemptCostTreatment', 'publicationRequiresValidTarget',
    'publicationRequiresIndependentDistillationSeeds',
  ];
  assertExactKeys(value, keys, 'configuration.sweepConfig');
  if (value.schemaVersion !== 1) throw new Error('configuration.sweepConfig.schemaVersion must be 1');
  nonEmptyString(value.experimentFamily, 'configuration.sweepConfig.experimentFamily');
  nonEmptyString(value.fixtureSet, 'configuration.sweepConfig.fixtureSet');
  integerArray(value.nValues, 'configuration.sweepConfig.nValues', { positive: true });
  for (const key of ['heldoutMinimum', 'highNDefinition']) {
    if (!Number.isSafeInteger(value[key]) || value[key] <= 0) {
      throw new Error(`configuration.sweepConfig.${key} must be a positive safe integer`);
    }
  }
  if (!Number.isFinite(value.targetThreshold) || value.targetThreshold < 0 || value.targetThreshold > 1) {
    throw new Error('configuration.sweepConfig.targetThreshold must be a finite number from 0 to 1');
  }
  for (const key of [
    'requireAllTargetCriticalGates', 'publicationRequiresValidTarget',
    'publicationRequiresIndependentDistillationSeeds',
  ]) {
    if (typeof value[key] !== 'boolean') throw new Error(`configuration.sweepConfig.${key} must be boolean`);
  }
  for (const key of ['acquisitionTreatment', 'attemptCostTreatment']) {
    nonEmptyString(value[key], `configuration.sweepConfig.${key}`);
  }
  if (!Array.isArray(value.replicates)) throw new Error('configuration.sweepConfig.replicates must be an array');
  for (let index = 0; index < value.replicates.length; index += 1) {
    const replicate = value.replicates[index];
    assertExactKeys(replicate, ['replicateId', 'pairOrderSeed', 'distillationSeed'], `configuration.sweepConfig.replicates[${index}]`);
    nonEmptyString(replicate.replicateId, `configuration.sweepConfig.replicates[${index}].replicateId`);
    for (const key of ['pairOrderSeed', 'distillationSeed']) {
      if (!Number.isSafeInteger(replicate[key])) {
        throw new Error(`configuration.sweepConfig.replicates[${index}].${key} must be a safe integer`);
      }
    }
  }
}

function validateConfiguration(configuration = {}) {
  assertPortableJson(configuration, 'configuration');
  if (!configuration || typeof configuration !== 'object' || Array.isArray(configuration)) {
    throw new Error('Evidence configuration must be an object');
  }
  for (const key of Object.keys(configuration)) {
    if (!CONFIGURATION_KEYS.has(key)) throw new Error(`Unsupported evidence configuration field: ${key}`);
  }
  if (Object.hasOwn(configuration, 'sweepConfig')) validateSweepConfiguration(configuration.sweepConfig);
  if (Object.hasOwn(configuration, 'nValues')) integerArray(configuration.nValues, 'configuration.nValues', { positive: true });
  if (Object.hasOwn(configuration, 'replicateIds')) stringArray(configuration.replicateIds, 'configuration.replicateIds');
  for (const key of ['pairOrderSeeds', 'requestedDistillationSeeds', 'appliedDistillationSeeds']) {
    if (Object.hasOwn(configuration, key)) integerArray(configuration[key], `configuration.${key}`, { historical: true });
  }
  if (Object.hasOwn(configuration, 'distillationSeedEvidence')) {
    if (!Array.isArray(configuration.distillationSeedEvidence)) {
      throw new Error('configuration.distillationSeedEvidence must be an array');
    }
    configuration.distillationSeedEvidence.forEach((item, index) => {
      assertExactKeys(item, ['requested', 'applied', 'status', 'mechanism'], `configuration.distillationSeedEvidence[${index}]`);
      for (const key of ['requested', 'applied']) {
        if (item[key] !== null && !Number.isSafeInteger(item[key])) {
          throw new Error(`configuration.distillationSeedEvidence[${index}].${key} must be a safe integer or null`);
        }
      }
      nonEmptyString(item.status, `configuration.distillationSeedEvidence[${index}].status`);
      nonEmptyString(item.mechanism, `configuration.distillationSeedEvidence[${index}].mechanism`);
    });
  }
  if (Object.hasOwn(configuration, 'tokenCaps')) {
    assertExactKeys(configuration.tokenCaps, ['maxInputTokens', 'maxOutputTokens'], 'configuration.tokenCaps');
    for (const key of ['maxInputTokens', 'maxOutputTokens']) {
      const value = configuration.tokenCaps[key];
      if (!(value === null || (Number.isSafeInteger(value) && value > 0))) {
        throw new Error(`configuration.tokenCaps.${key} must be a positive safe integer or null`);
      }
    }
  }
  if (Object.hasOwn(configuration, 'pricingSnapshot')) {
    validateBudgetSnapshotShape(configuration.pricingSnapshot, configuration.sweepConfig ?? null);
  }
  if (Object.hasOwn(configuration, 'evidenceLabels')) {
    stringArray(configuration.evidenceLabels, 'configuration.evidenceLabels', EVIDENCE_LABELS);
  }
  for (const key of ['acquisitionTreatment', 'attemptCoverage', 'fixtureSet']) {
    if (Object.hasOwn(configuration, key)) nonEmptyString(configuration[key], `configuration.${key}`);
  }
  if (Object.hasOwn(configuration, 'historicalRunDate')) {
    const value = configuration.historicalRunDate;
    const instant = typeof value === 'string' ? `${value}T00:00:00Z` : '';
    if (!(typeof value === 'string'
        && /^\d{4}-\d{2}-\d{2}$/.test(value)
        && Number.isFinite(Date.parse(instant))
        && new Date(instant).toISOString().slice(0, 10) === value)) {
      throw new Error('configuration.historicalRunDate must be a valid date-only string');
    }
  }
  if (Object.hasOwn(configuration, 'sourceTimestamp') && configuration.sourceTimestamp !== 'not-recorded') {
    throw new Error('configuration.sourceTimestamp must be not-recorded');
  }
  for (const key of ['benchmarkVerdict', 'suppressionReason']) {
    if (Object.hasOwn(configuration, key)) {
      const value = configuration[key];
      if (!(value === null || VERDICTS.has(value))) throw new Error(`configuration.${key} is unsupported`);
    }
  }
  if (Object.hasOwn(configuration, 'publicationGate')) {
    const gate = configuration.publicationGate;
    assertExactKeys(gate, ['publishableHighN', 'suppressionReason'], 'configuration.publicationGate');
    if (typeof gate.publishableHighN !== 'boolean') {
      throw new Error('publicationGate.publishableHighN must be boolean');
    }
    if (!(gate.suppressionReason === null || VERDICTS.has(gate.suppressionReason))) {
      throw new Error('publicationGate.suppressionReason must be string or null');
    }
    if (gate.publishableHighN !== (gate.suppressionReason === null)) {
      throw new Error('configuration.publicationGate has inconsistent publication state');
    }
  }
  if (Object.hasOwn(configuration, 'liveEconomics')) {
    if (!configuration.sweepConfig) throw new Error('configuration.liveEconomics requires sweepConfig');
    validateLiveEconomicsShape(configuration.liveEconomics, configuration.sweepConfig);
  }
  return canonicalize(configuration);
}

function validateSourceEvidence(sourceEvidence) {
  if (sourceEvidence === null || sourceEvidence === undefined) return null;
  assertPortableJson(sourceEvidence, 'manifest.sourceEvidence');
  assertExactKeys(sourceEvidence, ['bytes', 'kind', 'sha256'], 'sourceEvidence');
  if (typeof sourceEvidence.kind !== 'string' || sourceEvidence.kind === '') throw new Error('sourceEvidence kind is required');
  if (!/^[0-9a-f]{64}$/.test(sourceEvidence.sha256)) throw new Error('sourceEvidence sha256 must be a lowercase digest');
  if (!Number.isSafeInteger(sourceEvidence.bytes) || sourceEvidence.bytes <= 0) throw new Error('sourceEvidence bytes must be positive');
  return { ...sourceEvidence };
}

function validateReportInputs(reportInputs, manifestEvidenceLabel, configuration) {
  assertPortableJson(reportInputs, 'reportInputs');
  assertExactKeys(reportInputs, REPORT_INPUT_KEYS, 'reportInputs');
  if (!EVIDENCE_LABELS.has(reportInputs.evidenceLabel)) throw new Error('reportInputs.evidenceLabel is unsupported');
  if (reportInputs.evidenceLabel !== manifestEvidenceLabel) {
    throw new Error('reportInputs.evidenceLabel must equal manifest evidenceLabel');
  }
  if (!VERDICTS.has(reportInputs.verdict)) throw new Error('reportInputs.verdict is unsupported');
  if (!(reportInputs.suppressionReason === null || VERDICTS.has(reportInputs.suppressionReason))) {
    throw new Error('reportInputs.suppressionReason is unsupported');
  }
  stringArray(reportInputs.limitations, 'reportInputs.limitations', LIMITATIONS);
  if (new Set(reportInputs.limitations).size !== reportInputs.limitations.length) {
    throw new Error('reportInputs.limitations must not contain duplicates');
  }
  const passed = reportInputs.verdict === 'HIGH_N_PUBLICATION_GATE_PASSED';
  const passedLabel = 'LIVE CANDIDATE — PUBLICATION GATE PASSED';
  if (passed && reportInputs.evidenceLabel !== passedLabel) {
    throw new Error('Publication gate passed evidence label must identify a live candidate');
  }
  if (!passed && reportInputs.evidenceLabel === passedLabel) {
    throw new Error('Publication gate passed evidence label requires the passed verdict');
  }
  if (passed !== (reportInputs.suppressionReason === null)) {
    throw new Error('reportInputs has inconsistent verdict and suppressionReason');
  }
  if (!passed && reportInputs.suppressionReason !== reportInputs.verdict) {
    throw new Error('suppressed reportInputs verdict must equal suppressionReason');
  }
  if (configuration.publicationGate) {
    if (configuration.publicationGate.publishableHighN !== passed
        || configuration.publicationGate.suppressionReason !== reportInputs.suppressionReason) {
      throw new Error('reportInputs differs from configuration publicationGate');
    }
  } else if (configuration.benchmarkVerdict) {
    if (configuration.benchmarkVerdict !== reportInputs.verdict) {
      throw new Error('reportInputs verdict differs from configuration benchmarkVerdict');
    }
  } else if (passed) {
    throw new Error('passed reportInputs requires a validated publicationGate');
  }
  const sorted = [...reportInputs.limitations].sort();
  if (JSON.stringify(sorted) !== JSON.stringify(reportInputs.limitations)) {
    throw new Error('reportInputs.limitations must be sorted');
  }
  return canonicalize(reportInputs);
}

function validateLock(lock) {
  if (lock === null) return null;
  if (!lock || typeof lock !== 'object' || Array.isArray(lock)) throw new Error('liveBudget.lock must be object or null');
  if (lock.kind === 'unknown_cost') {
    assertExactKeys(lock, ['kind', 'attemptId'], 'liveBudget.lock');
  } else if (lock.kind === 'budget_overrun') {
    assertExactKeys(lock, ['kind', 'attemptId', 'reason'], 'liveBudget.lock');
    if (!['token_cap_exceeded', 'human_cap_exceeded', 'reservation_exceeded'].includes(lock.reason)) {
      throw new Error('liveBudget.lock.reason is unsupported');
    }
  } else {
    throw new Error('liveBudget.lock.kind is unsupported');
  }
  nonEmptyString(lock.attemptId, 'liveBudget.lock.attemptId');
  return canonicalize(lock);
}

function validateLiveBudget(liveBudget) {
  if (liveBudget === null || liveBudget === undefined) return null;
  assertPortableJson(liveBudget, 'manifest.liveBudget');
  const keys = [
    'configPath', 'configSha256', 'snapshotPath', 'snapshotSha256',
    'authorizationHash', 'humanCapMicroUsd',
    'conservativeEstimateMicroUsd', 'worstCasePerCallMicroUsd', 'attemptedCalls',
    'knownAccruedMicroUsd', 'outstandingReservedMicroUsd', 'lock',
    'economicsSnapshotPath', 'economicsSnapshotSha256',
  ];
  assertExactKeys(liveBudget, keys, 'liveBudget');
  for (const key of ['configPath', 'snapshotPath', 'economicsSnapshotPath']) {
    nonEmptyString(liveBudget[key], `liveBudget.${key}`);
    if (path.isAbsolute(liveBudget[key]) || liveBudget[key].split(/[\\/]/).includes('..')) {
      throw new Error(`liveBudget.${key} must be repository-relative`);
    }
  }
  for (const key of ['configSha256', 'snapshotSha256', 'economicsSnapshotSha256']) {
    if (!/^[0-9a-f]{64}$/.test(liveBudget[key])) throw new Error(`liveBudget.${key} must be a lowercase digest`);
  }
  if (!/^sha256:[0-9a-f]{64}$/.test(liveBudget.authorizationHash)) {
    throw new Error('liveBudget.authorizationHash must be a lowercase sha256 digest');
  }
  for (const key of [
    'humanCapMicroUsd', 'conservativeEstimateMicroUsd', 'worstCasePerCallMicroUsd',
    'knownAccruedMicroUsd', 'outstandingReservedMicroUsd',
  ]) {
    if (!/^(?:0|[1-9]\d*)$/.test(liveBudget[key])) {
      throw new Error(`liveBudget.${key} must be a base-10 non-negative integer string`);
    }
  }
  if (!Number.isSafeInteger(liveBudget.attemptedCalls) || liveBudget.attemptedCalls < 0) {
    throw new Error('liveBudget.attemptedCalls must be a non-negative safe integer');
  }
  validateLock(liveBudget.lock);
  return canonicalize(liveBudget);
}

function validateRecordedAtUtc(value) {
  if (value === null) return;
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
    throw new Error('recordedAtUtc must be an ISO-8601 instant or null');
  }
  const canonical = new Date(value).toISOString();
  const expected = value.includes('.') ? value : value.replace(/Z$/, '.000Z');
  if (canonical !== expected) throw new Error('recordedAtUtc must be an ISO-8601 instant or null');
}

function validateRecordedAtMode(recordedAtUtc, executionMode) {
  if (executionMode === 'historical' && recordedAtUtc !== null) {
    throw new Error('historical recordedAtUtc must be null');
  }
  if (executionMode !== 'historical' && recordedAtUtc === null) {
    throw new Error(`${executionMode} recordedAtUtc must be an exact execution instant`);
  }
}

function validateExecutionModeContract({ executionMode, evidenceLabel, liveBudget }) {
  if (!EXECUTION_MODES.has(executionMode)) {
    throw new Error('manifest.executionMode is required and must be mock, live, or historical');
  }
  if (executionMode === 'live') {
    if (liveBudget === null) throw new Error('live executionMode requires liveBudget');
    if (!evidenceLabel.startsWith('LIVE CANDIDATE')) {
      throw new Error('live executionMode requires a LIVE CANDIDATE evidence label');
    }
    return;
  }
  if (liveBudget !== null) throw new Error(`${executionMode} executionMode forbids liveBudget`);
  if (executionMode === 'mock' && !evidenceLabel.startsWith('SYNTHETIC')) {
    throw new Error('mock executionMode requires a SYNTHETIC evidence label');
  }
  if (executionMode === 'historical'
      && evidenceLabel !== 'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED') {
    throw new Error('historical executionMode requires the historical evidence label');
  }
}

function validateGitIdentity({ executionMode, gitCommit, gitDirty, sourceEvidence }, { current = false } = {}) {
  if (executionMode === 'historical') {
    if (gitCommit !== HISTORICAL_GIT_COMMIT || gitDirty !== null) {
      throw new Error('historical evidence requires the exact unrecorded git identity sentinel');
    }
    if (JSON.stringify(canonicalize(sourceEvidence))
        !== JSON.stringify(canonicalize(HISTORICAL_SOURCE_EVIDENCE))) {
      throw new Error('historical evidence requires the exact hash-locked sourceEvidence');
    }
    return;
  }
  if (!/^[0-9a-f]{40}$/.test(gitCommit ?? '')) {
    throw new Error('manifest.gitCommit must be an exact lowercase 40-hex commit');
  }
  if (typeof gitDirty !== 'boolean') throw new Error('manifest.gitDirty is required and must be boolean');
  if (executionMode === 'live' && gitDirty) throw new Error('Live evidence requires a clean checkout');
  if (sourceEvidence !== null) throw new Error(`${executionMode} evidence forbids sourceEvidence`);
  if (current) {
    const actual = readGitState(evidenceRoot);
    if (actual.gitCommit !== gitCommit || actual.gitDirty !== gitDirty) {
      throw new Error('Evidence git identity does not match current repository state');
    }
  }
}

function renderReport(summary, reportInputs) {
  const value = (input) => input === null ? 'unknown' : String(input);
  const limitations = reportInputs.limitations.length === 0
    ? 'none'
    : reportInputs.limitations.join(', ');
  return `# Clone-economics evidence report

- Evidence label: ${reportInputs.evidenceLabel}
- Verdict: ${reportInputs.verdict}
- Suppression reason: ${reportInputs.suppressionReason ?? 'none'}
- Limitations: ${limitations}

## Recomputed metrics

- Attempted samples: ${summary.attemptedSamples}
- Successful samples: ${summary.successfulSamples}
- Failed samples: ${summary.failedSamples}
- Provider cost USD: ${value(summary.providerCostUsd)}
- Latency p50 ms: ${value(summary.latencyMs.p50)}
- Latency p95 ms: ${value(summary.latencyMs.p95)}
`;
}

function validateReadmeInputs(readmeInputs) {
  assertPortableJson(readmeInputs, 'readmeInputs');
  assertExactKeys(readmeInputs, ['bundlePath'], 'readmeInputs');
  const { bundlePath } = readmeInputs;
  if (typeof bundlePath !== 'string'
      || bundlePath.length > 240
      || !/^(?:evidence|runs\/mock-sweep\/evidence)\/[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(bundlePath)
      || bundlePath.includes('//')
      || bundlePath.split('/').includes('..')) {
    throw new Error('readmeInputs.bundlePath must be a safe repository-relative evidence path');
  }
  return { bundlePath };
}

function renderReadme(readmeInputs) {
  return `# Evidence bundle

Verify and reproduce:

\`\`\`bash
node scripts/verify-bundle.mjs ${readmeInputs.bundlePath}
\`\`\`

Samples are normalized and allow-listed. Prompt payloads, output text, API keys,
headers, target Skill bytes, and reference bytes are excluded.

Unknown usage or cost remains null and makes aggregate provider cost unknown.
This bundle does not by itself authorize publication or a live benchmark claim.
`;
}

function validateManifest(manifest) {
  assertPortableJson(manifest, 'manifest');
  assertExactKeys(manifest, MANIFEST_KEYS, 'Evidence manifest');
  if (manifest.schemaVersion !== 1) throw new Error('Unsupported evidence manifest schemaVersion');
  if (!manifest || typeof manifest.experimentId !== 'string' || manifest.experimentId === '') {
    throw new Error('Evidence manifest experimentId is required');
  }
  validateRecordedAtUtc(manifest.recordedAtUtc);
  validateRecordedAtMode(manifest.recordedAtUtc, manifest.executionMode);
  for (const key of ['gitCommit', 'command']) nonEmptyString(manifest[key], `manifest.${key}`);
  for (const key of ['modelProvider', 'model']) nonEmptyString(manifest[key], `manifest.${key}`, { nullable: true });
  if (!EVIDENCE_LABELS.has(manifest.evidenceLabel)) throw new Error('Evidence manifest evidenceLabel is unsupported');
  assertExactKeys(manifest.runtime, ['node', 'platform', 'arch'], 'manifest.runtime');
  for (const key of ['node', 'platform', 'arch']) nonEmptyString(manifest.runtime[key], `manifest.runtime.${key}`);
  validateSourceEvidence(manifest.sourceEvidence);
  const liveBudget = validateLiveBudget(manifest.liveBudget);
  validateExecutionModeContract({
    executionMode: manifest.executionMode,
    evidenceLabel: manifest.evidenceLabel,
    liveBudget,
  });
  validateGitIdentity({
    executionMode: manifest.executionMode,
    gitCommit: manifest.gitCommit,
    gitDirty: manifest.gitDirty,
    sourceEvidence: manifest.sourceEvidence,
  });
  const configuration = validateConfiguration(manifest.configuration);
  validateReportInputs(manifest.reportInputs, manifest.evidenceLabel, configuration);
  validateReadmeInputs(manifest.readmeInputs);
  assertExactKeys(manifest.files, REQUIRED_BUNDLE_FILES, 'manifest.files');
  for (const name of REQUIRED_BUNDLE_FILES) {
    const file = manifest.files[name];
    assertExactKeys(file, ['sha256', 'bytes'], `manifest.files.${name}`);
    if (!/^[0-9a-f]{64}$/.test(file.sha256)) throw new Error(`manifest.files.${name}.sha256 must be a lowercase digest`);
    if (!Number.isSafeInteger(file.bytes) || file.bytes <= 0) {
      throw new Error(`manifest.files.${name}.bytes must be a positive safe integer`);
    }
  }
  if (manifest.recordedAtUtc === null
      && !(configuration.historicalRunDate && configuration.sourceTimestamp === 'not-recorded')) {
    throw new Error('A null recordedAtUtc requires a historical date and sourceTimestamp not-recorded');
  }
  return manifest;
}

function validateOutputDirectory(outputDir) {
  nonEmptyString(outputDir, 'outputDir');
  if (!fs.existsSync(outputDir)) return;
  const stat = fs.lstatSync(outputDir);
  if (stat.isSymbolicLink()) throw new Error('Evidence output directory must not be a symlink');
  if (!stat.isDirectory()) throw new Error('Evidence output path must be a directory');
  if (fs.readdirSync(outputDir).length !== 0) throw new Error('Evidence output directory must be empty');
}

export function writeEvidenceBundle(input) {
  assertPortableJson(input, 'writer input', new WeakSet(), false);
  assertExactKeys(input, ['outputDir', 'manifest', 'samples', 'reportInputs'], 'Evidence writer input');
  const {
    outputDir,
    manifest,
    samples,
    reportInputs,
  } = input;
  if (!manifest || typeof manifest !== 'object' || Array.isArray(manifest)) {
    throw new Error('Evidence manifest input must be an object');
  }
  for (const key of Object.keys(manifest)) {
    if (!MANIFEST_INPUT_KEYS.includes(key)) throw new Error(`Unsupported evidence manifest field: ${key}`);
  }
  assertPortableJson(manifest, 'manifest input');
  nonEmptyString(manifest.experimentId, 'manifest.experimentId');
  nonEmptyString(manifest.command, 'manifest.command');
  if (!EVIDENCE_LABELS.has(manifest.evidenceLabel)) throw new Error('Evidence manifest evidenceLabel is unsupported');
  for (const key of ['gitCommit', 'modelProvider', 'model']) {
    if (Object.hasOwn(manifest, key)) nonEmptyString(manifest[key], `manifest.${key}`, { nullable: key !== 'gitCommit' });
  }
  const recordedAtUtc = manifest.recordedAtUtc === undefined ? new Date().toISOString() : manifest.recordedAtUtc;
  validateRecordedAtUtc(recordedAtUtc);
  validateRecordedAtMode(recordedAtUtc, manifest.executionMode);
  const sourceEvidence = validateSourceEvidence(manifest.sourceEvidence);
  const liveBudget = validateLiveBudget(manifest.liveBudget);
  validateExecutionModeContract({
    executionMode: manifest.executionMode,
    evidenceLabel: manifest.evidenceLabel,
    liveBudget,
  });
  validateGitIdentity({
    executionMode: manifest.executionMode,
    gitCommit: manifest.gitCommit,
    gitDirty: manifest.gitDirty,
    sourceEvidence,
  }, { current: true });
  const configuration = validateConfiguration(manifest.configuration);
  const validatedReadmeInputs = validateReadmeInputs(manifest.readmeInputs);
  if (recordedAtUtc === null
      && !(configuration.historicalRunDate && configuration.sourceTimestamp === 'not-recorded')) {
    throw new Error('A null recordedAtUtc requires a historical date and sourceTimestamp not-recorded');
  }
  const validatedReportInputs = validateReportInputs(reportInputs, manifest.evidenceLabel, configuration);
  const summary = recomputeSummary(samples);

  const contents = {
    'samples.jsonl': `${samples.map(stableLine).join('\n')}\n`,
    'summary.json': stableJson(summary),
    'report.md': renderReport(summary, validatedReportInputs),
    'README.md': renderReadme(validatedReadmeInputs),
  };
  const finalManifest = {
    schemaVersion: 1,
    experimentId: manifest.experimentId,
    executionMode: manifest.executionMode,
    recordedAtUtc,
    gitCommit: manifest.gitCommit ?? 'not-recorded',
    gitDirty: manifest.gitDirty,
    command: manifest.command,
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    modelProvider: manifest.modelProvider ?? null,
    model: manifest.model ?? null,
    evidenceLabel: manifest.evidenceLabel,
    sourceEvidence,
    liveBudget,
    configuration,
    reportInputs: validatedReportInputs,
    readmeInputs: validatedReadmeInputs,
    files: Object.fromEntries(REQUIRED_BUNDLE_FILES.map((name) => [name, {
      sha256: sha256(contents[name]),
      bytes: Buffer.byteLength(contents[name]),
    }])),
  };
  validateManifest(finalManifest);
  verifyModeRows(samples, finalManifest, evidenceRoot);
  validateOutputDirectory(outputDir);
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
  for (const name of REQUIRED_BUNDLE_FILES) fs.writeFileSync(path.join(outputDir, name), contents[name]);
  fs.writeFileSync(path.join(outputDir, 'manifest.json'), stableJson(finalManifest));
  return finalManifest;
}

function readRegularFixture(packageRoot, relativePath, label) {
  const filePath = path.join(packageRoot, relativePath);
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch {
    throw new Error(`${label} must exist as a regular file`);
  }
  if (stat.isSymbolicLink() || !stat.isFile()) {
    throw new Error(`${label} must exist as a regular file`);
  }
  const bytes = fs.readFileSync(filePath);
  let parsed;
  try {
    parsed = JSON.parse(bytes);
  } catch {
    throw new Error(`${label} must contain valid JSON`);
  }
  return { bytes, parsed };
}

function requireExactLivePath(actual, expected, label) {
  if (actual !== expected) throw new Error(`Live ${label} must equal ${expected}`);
}

function canonicalEqual(left, right) {
  return JSON.stringify(canonicalize(left)) === JSON.stringify(canonicalize(right));
}

function deriveBudgetViolation({ sample, exactCost, knownAccrued, snapshot, worstCasePerCall, humanCap }) {
  if (sample.inputTokens > snapshot.tokenCaps.maxInputTokens
      || sample.outputTokens > snapshot.tokenCaps.maxOutputTokens) {
    return 'token_cap_exceeded';
  }
  if (knownAccrued > humanCap) return 'human_cap_exceeded';
  if (exactCost > worstCasePerCall) return 'reservation_exceeded';
  return null;
}

export function verifyLiveEvidenceContract(samples, manifest, packageRoot) {
  if (!Array.isArray(samples)) throw new Error('Live samples must be an array');
  if (typeof packageRoot !== 'string' || packageRoot === '') throw new Error('Live package root is required');
  const liveBudget = validateLiveBudget(manifest.liveBudget);
  validateExecutionModeContract({
    executionMode: manifest.executionMode,
    evidenceLabel: manifest.evidenceLabel,
    liveBudget,
  });
  if (manifest.gitDirty !== false) throw new Error('Live evidence requires a clean checkout');
  if (manifest.sourceEvidence !== null) throw new Error('Live evidence forbids sourceEvidence');
  const configuration = validateConfiguration(manifest.configuration);

  requireExactLivePath(liveBudget.configPath, 'fixtures/sweep-v1.json', 'configPath');
  requireExactLivePath(liveBudget.snapshotPath, 'fixtures/live-budget-v1.json', 'snapshotPath');
  requireExactLivePath(
    liveBudget.economicsSnapshotPath,
    'fixtures/live-economics-v1.json',
    'economicsSnapshotPath',
  );
  const configFile = readRegularFixture(packageRoot, liveBudget.configPath, 'Live sweep config');
  const snapshotFile = readRegularFixture(packageRoot, liveBudget.snapshotPath, 'Live budget snapshot');
  const economicsFile = readRegularFixture(
    packageRoot,
    liveBudget.economicsSnapshotPath,
    'Live economics snapshot',
  );
  if (sha256(configFile.bytes) !== liveBudget.configSha256) throw new Error('Live config hash mismatch');
  if (sha256(snapshotFile.bytes) !== liveBudget.snapshotSha256) throw new Error('Live budget snapshot hash mismatch');
  if (sha256(economicsFile.bytes) !== liveBudget.economicsSnapshotSha256) {
    throw new Error('Live economics snapshot hash mismatch');
  }
  if (!canonicalEqual(configFile.parsed, configuration.sweepConfig)) {
    throw new Error('Live sweep configuration differs from hash-verified config');
  }
  if (!canonicalEqual(economicsFile.parsed, configuration.liveEconomics)) {
    throw new Error('Live economics configuration differs from hash-verified snapshot');
  }
  const config = configFile.parsed;
  validateBudgetSnapshotShape(snapshotFile.parsed, config);
  const snapshot = validateApprovedBudgetSnapshot(snapshotFile.parsed, config);
  const liveEconomics = validateApprovedLiveEconomics(economicsFile.parsed, config);
  if (manifest.model !== snapshot.model) throw new Error('Live manifest model differs from approved snapshot');
  if (typeof manifest.modelProvider !== 'string'
      || manifest.modelProvider.toLowerCase() !== snapshot.provider.toLowerCase()) {
    throw new Error('Live manifest provider differs from approved snapshot');
  }

  // Validate the fixed preregistration before using fixtureSet in any path.
  validateSweepConfig(config, { trainCount: 100, heldoutCount: 30, v2Count: 0 });
  for (const name of [`train-${config.fixtureSet}.json`, `heldout-${config.fixtureSet}.json`, 'v2-heldout.json']) {
    readRegularFixture(packageRoot, path.join('fixtures', name), `Live fixture ${name}`);
  }
  const fixtures = loadFixtureSet(packageRoot, config.fixtureSet);
  const v2Fixtures = readRegularFixture(packageRoot, 'fixtures/v2-heldout.json', 'Live v2 fixtures').parsed;
  if (!Array.isArray(v2Fixtures)) throw new Error('Live v2 fixtures must be an array');
  const counts = {
    trainCount: fixtures.train.length,
    heldoutCount: fixtures.heldout.length,
    v2Count: v2Fixtures.length,
  };
  validateSweepConfig(config, counts);
  const requestCount = conservativeSweepRequestCount(config, counts);
  if (requestCount !== 1713) throw new Error('Live committed fixture request count must equal 1713');
  const worstCasePerCall = calculateProviderCostMicroUsd({
    inputTokens: snapshot.tokenCaps.maxInputTokens,
    outputTokens: snapshot.tokenCaps.maxOutputTokens,
    snapshot,
  });
  const conservativeEstimate = estimateLiveSweepMicroUsd({ config, counts, snapshot });
  if (liveBudget.worstCasePerCallMicroUsd !== worstCasePerCall.toString()) {
    throw new Error('Live worst-case per-call amount mismatch');
  }
  if (liveBudget.conservativeEstimateMicroUsd !== conservativeEstimate.toString()) {
    throw new Error('Live conservative estimate mismatch');
  }
  const humanCap = BigInt(liveBudget.humanCapMicroUsd);
  if (humanCap < conservativeEstimate) {
    throw new Error('Live human cap is below the conservative estimate');
  }
  const expectedAuthorization = liveAuthorizationHash({ config, snapshot, economics: liveEconomics });
  if (expectedAuthorization !== liveBudget.authorizationHash) throw new Error('Live authorization hash mismatch');
  if (liveBudget.attemptedCalls !== samples.length || samples.length > requestCount) {
    throw new Error('Live attempted-call count differs from samples or approved request count');
  }

  let knownAccrued = 0n;
  const unknownIndexes = [];
  const violations = [];
  for (let index = 0; index < samples.length; index += 1) {
    const sample = validateSample(samples[index]);
    const expectedAttemptId = `attempt-${String(index + 1).padStart(6, '0')}`;
    if (sample.budgetAttemptId !== expectedAttemptId) {
      throw new Error(`Live budgetAttemptId sequence mismatch for ${sample.sampleId}`);
    }
    if (knownAccrued + worstCasePerCall > humanCap) {
      throw new Error(`Live sample ${sample.sampleId} could not have reserved within the human cap`);
    }
    if (sample.phase === 'acquisition') {
      if (sample.acquisitionCostUsd !== liveEconomics.invocationPriceUsd
          || sample.acquisitionEvidence !== 'MODELED') {
        throw new Error(`Live acquisition row price or evidence mismatch for ${sample.sampleId}`);
      }
    } else if (sample.acquisitionCostUsd !== 0 || sample.acquisitionEvidence !== null) {
      throw new Error(`Live non-acquisition row carries acquisition cost for ${sample.sampleId}`);
    }

    const unknownUsage = sample.inputTokens === null || sample.outputTokens === null;
    if (unknownUsage) {
      if (!(sample.inputTokens === null && sample.outputTokens === null
          && sample.providerCostMicroUsd === null && sample.providerCostUsd === null)) {
        throw new Error('Unknown live usage requires both usage and provider costs to be null');
      }
      unknownIndexes.push(index);
      violations.push(null);
      continue;
    }
    const exactCost = calculateProviderCostMicroUsd({
      inputTokens: sample.inputTokens,
      outputTokens: sample.outputTokens,
      snapshot,
    });
    if (sample.providerCostMicroUsd !== exactCost.toString()) {
      throw new Error(`Live exact provider cost mismatch for ${sample.sampleId}`);
    }
    if (sample.providerCostUsd !== Number(exactCost) / 1_000_000) {
      throw new Error(`Live provider USD cost mismatch for ${sample.sampleId}`);
    }
    knownAccrued += exactCost;
    violations.push(deriveBudgetViolation({
      sample,
      exactCost,
      knownAccrued,
      snapshot,
      worstCasePerCall,
      humanCap,
    }));
  }
  if (liveBudget.knownAccruedMicroUsd !== knownAccrued.toString()) {
    throw new Error('Live known accrued amount differs from exact sample costs');
  }

  const outstanding = BigInt(liveBudget.outstandingReservedMicroUsd);
  const finalIndex = samples.length - 1;
  const finalSample = samples[finalIndex];
  const earlierViolation = violations.findIndex((reason, index) => reason !== null && index !== finalIndex);
  if (earlierViolation !== -1) throw new Error('Live samples continue after a budget violation');
  if (liveBudget.lock === null) {
    if (unknownIndexes.length !== 0) throw new Error('Unknown live cost requires an unknown_cost lock');
    if (outstanding !== 0n) throw new Error('Unlocked live budget must have zero outstanding reservation');
    if (violations[finalIndex] !== null && samples.length !== 0) {
      throw new Error('Live budget violation requires a budget_overrun lock');
    }
    return;
  }
  if (!finalSample || finalSample.success !== false) throw new Error('Live budget lock requires a final failed sample');
  if (liveBudget.lock.attemptId !== finalSample.budgetAttemptId) {
    throw new Error('Live lock attemptId must equal final sample budgetAttemptId');
  }
  if (liveBudget.lock.kind === 'unknown_cost') {
    if (unknownIndexes.length !== 1 || unknownIndexes[0] !== finalIndex) {
      throw new Error('unknown_cost lock requires exactly one final unknown-cost sample');
    }
    if (outstanding !== worstCasePerCall) {
      throw new Error('unknown_cost lock must retain exactly one worst-case reservation');
    }
    return;
  }
  if (unknownIndexes.length !== 0) throw new Error('budget_overrun lock requires a known final cost');
  if (outstanding !== 0n) throw new Error('budget_overrun lock must have zero outstanding reservation');
  const expectedReason = violations[finalIndex];
  if (expectedReason === null) throw new Error('budget_overrun lock has no derived budget violation');
  if (liveBudget.lock.reason !== expectedReason) {
    throw new Error(`Live lock reason must equal ${expectedReason}`);
  }
}

function verifyModeRows(samples, manifest, packageRoot) {
  if (manifest.executionMode === 'live') {
    verifyLiveEvidenceContract(samples, manifest, packageRoot);
    return;
  }
  if (samples.some((sample) => sample.budgetAttemptId !== null)) {
    throw new Error(`${manifest.executionMode} evidence requires null budgetAttemptId values`);
  }
}

export function verifyEvidenceBundle(dir) {
  nonEmptyString(dir, 'Evidence bundle path');
  let directoryStat;
  try {
    directoryStat = fs.lstatSync(dir);
  } catch {
    throw new Error('Evidence bundle path must be a real directory');
  }
  if (directoryStat.isSymbolicLink() || !directoryStat.isDirectory()) {
    throw new Error('Evidence bundle path must be a real directory');
  }
  const listing = fs.readdirSync(dir).sort();
  if (JSON.stringify(listing) !== JSON.stringify([...ALL_BUNDLE_FILES].sort())) {
    throw new Error('Evidence bundle must contain exactly the five required regular files');
  }
  for (const name of ALL_BUNDLE_FILES) {
    const stat = fs.lstatSync(path.join(dir, name));
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`Evidence bundle entry must be a regular file: ${name}`);
  }
  const manifestPath = path.join(dir, 'manifest.json');
  const manifestText = fs.readFileSync(manifestPath, 'utf8');
  const manifest = JSON.parse(manifestText);
  if (manifestText !== stableJson(manifest)) throw new Error('manifest.json must use canonical JSON');
  validateManifest(manifest);
  for (const name of REQUIRED_BUNDLE_FILES) {
    const filePath = path.join(dir, name);
    const bytes = fs.readFileSync(filePath);
    const expected = manifest.files[name];
    if (expected.bytes !== bytes.length || expected.sha256 !== sha256(bytes)) {
      throw new Error(`Evidence hash or byte count mismatch: ${name}`);
    }
  }
  const sampleText = fs.readFileSync(path.join(dir, 'samples.jsonl'), 'utf8');
  if (!sampleText.endsWith('\n')) throw new Error('samples.jsonl must end with a newline');
  const lines = sampleText.slice(0, -1).split('\n');
  const samples = lines.length === 1 && lines[0] === '' ? [] : lines.map((line) => JSON.parse(line));
  for (let index = 0; index < samples.length; index += 1) {
    if (lines[index] !== stableLine(samples[index])) {
      throw new Error(`samples.jsonl row ${index + 1} is not canonical JSON`);
    }
  }
  const summary = recomputeSummary(samples);
  if (fs.readFileSync(path.join(dir, 'summary.json'), 'utf8') !== stableJson(summary)) {
    throw new Error('summary.json differs from recomputation');
  }
  if (fs.readFileSync(path.join(dir, 'report.md'), 'utf8') !== renderReport(summary, manifest.reportInputs)) {
    throw new Error('report.md differs from deterministic rendering');
  }
  if (fs.readFileSync(path.join(dir, 'README.md'), 'utf8') !== renderReadme(manifest.readmeInputs)) {
    throw new Error('README.md differs from deterministic rendering');
  }
  verifyModeRows(samples, manifest, evidenceRoot);
  return { valid: true, manifest, summary, samples };
}

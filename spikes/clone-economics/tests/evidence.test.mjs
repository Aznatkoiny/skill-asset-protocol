import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { recomputeSummary, verifyEvidenceBundle, writeEvidenceBundle } from '../src/evidence.mjs';
import { readGitState } from '../src/git-state.mjs';
import { normalizeSweepSamples, writeSweepEvidenceBundle } from '../src/sweep.mjs';
import { config } from './fixtures/live-contract.mjs';

const normalizedSample = (overrides = {}) => ({
  sampleId: 'run:target-heldout:a',
  phase: 'evaluation',
  profile: 'target',
  caseId: 'a',
  n: null,
  replicateId: null,
  pairOrderSeed: null,
  requestedDistillationSeed: null,
  appliedDistillationSeed: null,
  distillationSeedStatus: 'not_requested',
  distillationSeedMechanism: 'no_seed_requested',
  success: true,
  latencyMs: 10,
  inputTokens: 3,
  outputTokens: 2,
  providerCostMicroUsd: '10000',
  providerCostUsd: 0.01,
  acquisitionCostUsd: 0,
  acquisitionEvidence: null,
  score: 0.9,
  criticalGatePass: true,
  failureClass: null,
  providerRequestId: null,
  budgetAttemptId: null,
  ...overrides,
});

const syntheticReportInputs = (overrides = {}) => ({
  evidenceLabel: 'SYNTHETIC',
  verdict: 'HIGH_N_NOT_LIVE',
  suppressionReason: 'HIGH_N_NOT_LIVE',
  limitations: ['SYNTHETIC_ONLY'],
  ...overrides,
});

const readmeInputs = (bundlePath = 'evidence/adversarial-fixture') => ({ bundlePath });
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const currentGitState = readGitState(packageRoot);
const currentGitIdentity = {
  gitCommit: currentGitState.gitCommit,
  gitDirty: currentGitState.gitDirty,
};

function evidenceInput(outputDir, overrides = {}) {
  return {
    outputDir,
    manifest: {
      experimentId: 'adversarial-fixture',
      executionMode: 'mock',
      gitCommit: currentGitState.gitCommit,
      gitDirty: currentGitState.gitDirty,
      evidenceLabel: 'SYNTHETIC',
      command: 'test',
      configuration: {},
      readmeInputs: readmeInputs(),
      ...(overrides.manifest ?? {}),
    },
    samples,
    reportInputs: syntheticReportInputs(overrides.reportInputs),
  };
}

const samples = [
  normalizedSample(),
  normalizedSample({
    sampleId: 'run:clone-heldout:a',
    profile: 'clone',
    latencyMs: 30,
    providerCostMicroUsd: '20000',
    providerCostUsd: 0.02,
    score: 0.7,
    criticalGatePass: false,
  }),
  normalizedSample({
    sampleId: 'run:distill:1',
    phase: 'distillation',
    profile: 'clone',
    caseId: null,
    success: false,
    latencyMs: 5,
    inputTokens: null,
    outputTokens: null,
    providerCostMicroUsd: null,
    providerCostUsd: null,
    score: null,
    criticalGatePass: null,
    failureClass: 'ProviderError',
  }),
];

test('bundle hashes and summary recompute from normalized samples', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeEvidenceBundle({
    outputDir: dir,
    manifest: {
      experimentId: 'fixture-run',
      executionMode: 'mock',
      ...currentGitIdentity,
      evidenceLabel: 'SYNTHETIC',
      command: 'npm run sweep:mock',
      readmeInputs: readmeInputs('evidence/fixture-run'),
    },
    samples,
    reportInputs: syntheticReportInputs(),
  });
  const verified = verifyEvidenceBundle(dir);
  assert.equal(verified.valid, true);
  assert.equal(verified.summary.attemptedSamples, 3);
  assert.equal(verified.summary.failedSamples, 1);
  assert.equal(verified.summary.providerCostUsd, null);
  assert.equal(verified.summary.latencyMs.p50, 10);
  assert.equal(verified.summary.latencyMs.p95, 30);
});

test('executionMode is required and live mode requires a live budget', (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-mode-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));

  const missingMode = evidenceInput(path.join(parent, 'missing-mode'));
  delete missingMode.manifest.executionMode;
  assert.throws(
    () => writeEvidenceBundle(missingMode),
    /manifest\.executionMode is required/,
  );
  assert.equal(fs.existsSync(path.join(parent, 'missing-mode')), false);

  const live = evidenceInput(path.join(parent, 'live-without-budget'), {
    manifest: {
      executionMode: 'live',
      evidenceLabel: 'LIVE CANDIDATE — CONCLUSIONS SUPPRESSED',
    },
    reportInputs: {
      evidenceLabel: 'LIVE CANDIDATE — CONCLUSIONS SUPPRESSED',
    },
  });
  assert.throws(
    () => writeEvidenceBundle(live),
    /live executionMode requires liveBudget/,
  );
  assert.equal(fs.existsSync(path.join(parent, 'live-without-budget')), false);
});

test('new-run evidence rejects missing or arbitrary git identity', (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-git-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));

  const missing = evidenceInput(path.join(parent, 'missing'));
  delete missing.manifest.gitDirty;
  assert.throws(() => writeEvidenceBundle(missing), /manifest\.gitDirty is required/);
  assert.equal(fs.existsSync(path.join(parent, 'missing')), false);

  const arbitrary = evidenceInput(path.join(parent, 'arbitrary'), {
    manifest: { gitCommit: '0'.repeat(40) },
  });
  assert.throws(() => writeEvidenceBundle(arbitrary), /git identity does not match current repository state/i);
  assert.equal(fs.existsSync(path.join(parent, 'arbitrary')), false);
});

test('mode rows and historical provenance use exact non-forgeable sentinels', (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-modes-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));

  assert.throws(
    () => writeEvidenceBundle({
      ...evidenceInput(path.join(parent, 'mock-budget-id')),
      samples: [normalizedSample({ budgetAttemptId: 'attempt-000001' })],
    }),
    /mock evidence requires null budgetAttemptId values/,
  );

  const historicalLabel = 'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED';
  const historical = (outputDir) => ({
    outputDir,
    manifest: {
      experimentId: 'historical-fixture',
      executionMode: 'historical',
      recordedAtUtc: null,
      gitCommit: 'historical-source-not-recorded',
      gitDirty: null,
      command: 'historical command not retained exactly',
      evidenceLabel: historicalLabel,
      sourceEvidence: {
        kind: 'legacy-report-json',
        sha256: '0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212',
        bytes: 76_631,
      },
      configuration: {
        historicalRunDate: '2026-07-12',
        sourceTimestamp: 'not-recorded',
        benchmarkVerdict: 'INVALID_BENCHMARK_TARGET_FAILED',
      },
      readmeInputs: readmeInputs('evidence/historical-fixture'),
    },
    samples: [normalizedSample({
      sampleId: 'legacy:fixture',
      distillationSeedStatus: 'not_recorded',
      distillationSeedMechanism: 'historical_source_not_recorded',
    })],
    reportInputs: {
      evidenceLabel: historicalLabel,
      verdict: 'INVALID_BENCHMARK_TARGET_FAILED',
      suppressionReason: 'INVALID_BENCHMARK_TARGET_FAILED',
      limitations: ['HISTORICAL_ATTEMPTS_INCOMPLETE'],
    },
  });

  const valid = historical(path.join(parent, 'valid-historical'));
  writeEvidenceBundle(valid);
  assert.equal(verifyEvidenceBundle(valid.outputDir).valid, true);

  const mutations = [
    ['git sentinel', (input) => { input.manifest.gitCommit = 'a'.repeat(40); }, /unrecorded git identity sentinel/],
    ['dirty sentinel', (input) => { input.manifest.gitDirty = false; }, /unrecorded git identity sentinel/],
    ['source identity', (input) => { input.manifest.sourceEvidence.bytes -= 1; }, /exact hash-locked sourceEvidence/],
    ['invented timestamp', (input) => { input.manifest.recordedAtUtc = '2026-07-12T00:00:00Z'; }, /historical recordedAtUtc must be null/],
  ];
  mutations.forEach(([name, mutate, pattern], index) => {
    const input = historical(path.join(parent, `invalid-${index}`));
    mutate(input);
    assert.throws(() => writeEvidenceBundle(input), pattern, name);
    assert.equal(fs.existsSync(input.outputDir), false);
  });
});

test('redaction rejects private payload fields', () => {
  assert.throws(() => recomputeSummary([{ ...samples[0], prompt: 'private' }]), /forbidden sample field: prompt/);
});

test('sample and configuration schemas reject nested values and secrets', () => {
  assert.throws(
    () => recomputeSummary([{ ...samples[0], failureClass: { rawResponse: 'private' } }]),
    /forbidden evidence field|failureClass must be string or null/,
  );
  assert.throws(
    () => recomputeSummary([{ ...samples[0], acquisitionEvidence: { authorization: 'private' } }]),
    /forbidden evidence field|acquisitionEvidence must be string or null/,
  );
  assert.throws(
    () => recomputeSummary([{ ...samples[0], failureClass: { code: 'ProviderError' } }]),
    /failureClass must be an error-class token or null/,
  );

  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-preflight-'));
  const outputDir = path.join(parent, 'bundle');
  try {
    assert.throws(() => writeEvidenceBundle({
      outputDir,
      manifest: {
        experimentId: 'nested-config',
        executionMode: 'mock',
        ...currentGitIdentity,
        evidenceLabel: 'SYNTHETIC',
        command: 'test',
        readmeInputs: readmeInputs('evidence/nested-config'),
        configuration: {
          publicationGate: {
            publishableHighN: false,
            suppressionReason: { rawResponse: 'private' },
          },
        },
      },
      samples,
      reportInputs: syntheticReportInputs(),
    }), /forbidden evidence field|publicationGate\.suppressionReason must be string or null/);
    assert.equal(fs.existsSync(outputDir), false, 'invalid input must not create an output directory');
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

function canonicalizeForTest(value) {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return value;
  if (Array.isArray(value)) return value.map(canonicalizeForTest);
  return Object.fromEntries(
    Object.keys(value).sort().map((key) => [key, canonicalizeForTest(value[key])]),
  );
}

function writeCanonicalJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(canonicalizeForTest(value), null, 2)}\n`);
}

function rewriteManifestHash(dir, name) {
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const bytes = fs.readFileSync(path.join(dir, name));
  manifest.files[name] = {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.length,
  };
  writeCanonicalJson(manifestPath, manifest);
}

function bundle(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-strict-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeEvidenceBundle({
    outputDir: dir,
    manifest: {
      experimentId: 'strict-run',
      executionMode: 'mock',
      ...currentGitIdentity,
      evidenceLabel: 'SYNTHETIC',
      command: 'test',
      readmeInputs: readmeInputs('evidence/strict-run'),
    },
    samples,
    reportInputs: syntheticReportInputs(),
  });
  return dir;
}

test('verifier rejects a changed file even when JSON remains parseable', (t) => {
  const dir = bundle(t);
  fs.appendFileSync(path.join(dir, 'README.md'), '\ntampered\n');
  assert.throws(() => verifyEvidenceBundle(dir), /hash or byte count mismatch: README\.md/);
});

test('verifier requires exactly five regular files and a real directory', (t) => {
  const extraDir = bundle(t);
  fs.writeFileSync(path.join(extraDir, 'raw-provider.json'), '{}\n');
  assert.throws(() => verifyEvidenceBundle(extraDir), /exactly the five required regular files/);

  const nestedDir = bundle(t);
  fs.mkdirSync(path.join(nestedDir, 'raw'));
  assert.throws(() => verifyEvidenceBundle(nestedDir), /exactly the five required regular files/);

  const linkedFileDir = bundle(t);
  const reportPath = path.join(linkedFileDir, 'report.md');
  const externalReport = path.join(path.dirname(linkedFileDir), `${path.basename(linkedFileDir)}-report.md`);
  fs.renameSync(reportPath, externalReport);
  fs.symlinkSync(externalReport, reportPath);
  t.after(() => fs.rmSync(externalReport, { force: true }));
  assert.throws(() => verifyEvidenceBundle(linkedFileDir), /must be a regular file: report\.md/);

  const targetDir = bundle(t);
  const linkedDir = `${targetDir}-link`;
  fs.symlinkSync(targetDir, linkedDir, 'dir');
  t.after(() => fs.rmSync(linkedDir, { force: true }));
  assert.throws(() => verifyEvidenceBundle(linkedDir), /Evidence bundle path must be a real directory/);
});

test('verifier validates the exact manifest shape and nested scalar values', (t) => {
  const extraFieldDir = bundle(t);
  const extraManifestPath = path.join(extraFieldDir, 'manifest.json');
  const extraManifest = JSON.parse(fs.readFileSync(extraManifestPath, 'utf8'));
  extraManifest.rawResponse = { private: true };
  writeCanonicalJson(extraManifestPath, extraManifest);
  assert.throws(() => verifyEvidenceBundle(extraFieldDir), /forbidden evidence field|Evidence manifest has unexpected or missing fields/);

  const nonFiniteDir = bundle(t);
  const nonFiniteManifestPath = path.join(nonFiniteDir, 'manifest.json');
  const nonFiniteText = fs.readFileSync(nonFiniteManifestPath, 'utf8')
    .replace('"configuration": {}', '"configuration": {"nValues": [1e400]}');
  fs.writeFileSync(nonFiniteManifestPath, nonFiniteText);
  assert.throws(() => verifyEvidenceBundle(nonFiniteDir), /canonical JSON|finite JSON numbers|configuration\.nValues\[0\] must be a positive safe integer/);
});

test('verifier rejects duplicate manifest keys and noncanonical manifest bytes', (t) => {
  const dir = bundle(t);
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = fs.readFileSync(manifestPath, 'utf8')
    .replace('{\n', '{\n  "command": "authorization: Bearer private",\n');
  fs.writeFileSync(manifestPath, manifest);
  assert.throws(() => verifyEvidenceBundle(dir), /manifest\.json must use canonical JSON/);
});

test('verifier rejects duplicate IDs and forbidden fields after a manifest rehash', (t) => {
  const duplicateDir = bundle(t);
  const firstLine = fs.readFileSync(path.join(duplicateDir, 'samples.jsonl'), 'utf8').split('\n')[0];
  fs.appendFileSync(path.join(duplicateDir, 'samples.jsonl'), `${firstLine}\n`);
  rewriteManifestHash(duplicateDir, 'samples.jsonl');
  assert.throws(() => verifyEvidenceBundle(duplicateDir), /duplicate sampleId/);

  const forbiddenDir = bundle(t);
  const changed = { ...samples[0], prompt: 'private' };
  const lines = fs.readFileSync(path.join(forbiddenDir, 'samples.jsonl'), 'utf8').trimEnd().split('\n');
  lines[0] = JSON.stringify(Object.fromEntries(Object.entries(changed).sort(([left], [right]) => left.localeCompare(right))));
  fs.writeFileSync(path.join(forbiddenDir, 'samples.jsonl'), `${lines.join('\n')}\n`);
  rewriteManifestHash(forbiddenDir, 'samples.jsonl');
  assert.throws(() => verifyEvidenceBundle(forbiddenDir), /forbidden sample field: prompt/);
});

test('verifier rejects summary and report numbers changed behind updated hashes', (t) => {
  const summaryDir = bundle(t);
  const summaryPath = path.join(summaryDir, 'summary.json');
  const summary = JSON.parse(fs.readFileSync(summaryPath, 'utf8'));
  summary.failedSamples = 0;
  fs.writeFileSync(summaryPath, `${JSON.stringify(summary, null, 2)}\n`);
  rewriteManifestHash(summaryDir, 'summary.json');
  assert.throws(() => verifyEvidenceBundle(summaryDir), /summary\.json differs from recomputation/);

  const reportDir = bundle(t);
  const reportPath = path.join(reportDir, 'report.md');
  fs.writeFileSync(reportPath, fs.readFileSync(reportPath, 'utf8').replace('Latency p95 ms: 30', 'Latency p95 ms: 29'));
  rewriteManifestHash(reportDir, 'report.md');
  assert.throws(() => verifyEvidenceBundle(reportDir), /report\.md differs from deterministic rendering/);

  const duplicateDir = bundle(t);
  const duplicateReportPath = path.join(duplicateDir, 'report.md');
  fs.appendFileSync(duplicateReportPath, '- Provider cost USD: 0\n');
  rewriteManifestHash(duplicateDir, 'report.md');
  assert.throws(() => verifyEvidenceBundle(duplicateDir), /report\.md differs from deterministic rendering/);

  const interpretationDir = bundle(t);
  const interpretationPath = path.join(interpretationDir, 'report.md');
  fs.writeFileSync(
    interpretationPath,
    fs.readFileSync(interpretationPath, 'utf8')
      .replace('Verdict: HIGH_N_NOT_LIVE', 'Verdict: HIGH_N_PUBLICATION_GATE_PASSED'),
  );
  rewriteManifestHash(interpretationDir, 'report.md');
  assert.throws(() => verifyEvidenceBundle(interpretationDir), /report\.md differs from deterministic rendering/);
});

test('verifier rejects a rehashed README publication claim', (t) => {
  const dir = bundle(t);
  const readmePath = path.join(dir, 'README.md');
  fs.appendFileSync(readmePath, '\nThis bundle is approved for publication.\n');
  rewriteManifestHash(dir, 'README.md');
  assert.throws(() => verifyEvidenceBundle(dir), /README\.md differs from deterministic rendering/);
});

test('readmeInputs accepts only the closed repository-relative verifier command', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-readme-inputs-'));
  try {
    const cases = [
      { bundlePath: 'docs/not-evidence' },
      { bundlePath: '/tmp/raw-evidence' },
      { bundlePath: '../evidence/run' },
      { bundlePath: 'evidence/run', note: 'publishable' },
    ];
    cases.forEach((value, index) => {
      const outputDir = path.join(parent, `bundle-${index}`);
      assert.throws(
        () => writeEvidenceBundle(evidenceInput(outputDir, { manifest: { readmeInputs: value } })),
        /readmeInputs|verifier command|repository-relative|unexpected or missing fields/,
      );
      assert.equal(fs.existsSync(outputDir), false);
    });
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('sample scalar channels reject unsupported enums, unsafe IDs, and sensitive values', () => {
  const mutations = [
    { phase: 'raw' },
    { profile: 'administrator' },
    { distillationSeedStatus: 'forged' },
    { distillationSeedMechanism: 'custom_header_authorization' },
    { acquisitionEvidence: 'RAW' },
    { sampleId: '../tmp/raw-response' },
    { caseId: '/private/tmp/case' },
    { replicateId: 'replicate with spaces' },
    { failureClass: 'Error: authorization Bearer private' },
    { providerRequestId: 'x-api-key=private' },
  ];
  for (const mutation of mutations) {
    assert.throws(
      () => recomputeSummary([normalizedSample(mutation)]),
      /unsupported|safe identifier|error-class token|sensitive evidence value/,
    );
  }
});

test('manifest and configuration string values reject secret and raw path markers', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-sensitive-values-'));
  try {
    const cases = [
      { model: 'authorization=Bearer private' },
      { modelProvider: 'x-api-key private' },
      { model: 'rawResponse=private' },
      { configuration: { attemptCoverage: 'raw response retained at /tmp/private' } },
    ];
    cases.forEach((manifest, index) => {
      const outputDir = path.join(parent, `bundle-${index}`);
      assert.throws(
        () => writeEvidenceBundle(evidenceInput(outputDir, { manifest })),
        /sensitive evidence value/,
      );
      assert.equal(fs.existsSync(outputDir), false);
    });
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('writer validates all inputs before creating output', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-no-partial-'));
  const outputDir = path.join(parent, 'bundle');
  try {
    assert.throws(() => writeEvidenceBundle({
      outputDir,
      manifest: {
        experimentId: 'invalid-manifest',
        executionMode: 'mock',
        ...currentGitIdentity,
        recordedAtUtc: 'not-a-timestamp',
        evidenceLabel: 'SYNTHETIC',
        command: 'test',
        readmeInputs: readmeInputs('evidence/invalid-manifest'),
      },
      samples,
      reportInputs: syntheticReportInputs(),
    }), /recordedAtUtc must be an ISO-8601 instant or null/);
    assert.equal(fs.existsSync(outputDir), false);

    const invalidCalendarOutput = path.join(parent, 'invalid-calendar');
    assert.throws(() => writeEvidenceBundle(evidenceInput(invalidCalendarOutput, {
      manifest: { recordedAtUtc: '2026-02-30T00:00:00Z' },
    })), /recordedAtUtc must be an ISO-8601 instant or null/);
    assert.equal(fs.existsSync(invalidCalendarOutput), false);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('writer rejects every non-portable JSON value before creating output', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-portable-'));
  try {
    const cycle = {};
    cycle.self = cycle;
    const sparse = [];
    sparse[1] = 'value';
    const customPrototype = Object.create({ inherited: true });
    customPrototype.value = 'value';
    const symbolKey = { value: 'value' };
    symbolKey[Symbol('secret')] = 'private';
    const extraArrayProperty = ['value'];
    extraArrayProperty.private = 'hidden';
    const invalidValues = [
      NaN,
      Infinity,
      -Infinity,
      1n,
      undefined,
      () => {},
      Symbol('value'),
      sparse,
      cycle,
      new Date('2026-07-17T00:00:00Z'),
      new Map([['value', 1]]),
      customPrototype,
      symbolKey,
      extraArrayProperty,
    ];
    invalidValues.forEach((value, index) => {
      const outputDir = path.join(parent, `bundle-${index}`);
      const input = evidenceInput(outputDir, {
        manifest: { configuration: { evidenceLabels: [value] } },
      });
      assert.throws(() => writeEvidenceBundle(input), /unsupported|finite JSON|cycles|non-plain|sparse arrays|symbol keys|extra array/);
      assert.equal(fs.existsSync(outputDir), false);
    });

    const hiddenConfiguration = {};
    Object.defineProperty(hiddenConfiguration, 'authorization', { value: 'private', enumerable: false });
    const hiddenOutput = path.join(parent, 'hidden-property');
    assert.throws(
      () => writeEvidenceBundle(evidenceInput(hiddenOutput, { manifest: { configuration: hiddenConfiguration } })),
      /non-enumerable|forbidden evidence field/,
    );
    assert.equal(fs.existsSync(hiddenOutput), false);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test('writer rejects a symlink output directory without touching its target', (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-output-link-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const target = path.join(parent, 'target');
  const outputDir = path.join(parent, 'bundle');
  fs.mkdirSync(target);
  fs.symlinkSync(target, outputDir, 'dir');
  assert.throws(() => writeEvidenceBundle(evidenceInput(outputDir)), /must not be a symlink/);
  assert.deepEqual(fs.readdirSync(target), []);
});

test('verifier requires exact runtime and file-entry schemas', (t) => {
  const runtimeDir = bundle(t);
  const runtimeManifestPath = path.join(runtimeDir, 'manifest.json');
  const runtimeManifest = JSON.parse(fs.readFileSync(runtimeManifestPath, 'utf8'));
  runtimeManifest.runtime.node = null;
  writeCanonicalJson(runtimeManifestPath, runtimeManifest);
  assert.throws(() => verifyEvidenceBundle(runtimeDir), /manifest\.runtime\.node must be a non-empty string/);

  const filesDir = bundle(t);
  const filesManifestPath = path.join(filesDir, 'manifest.json');
  const filesManifest = JSON.parse(fs.readFileSync(filesManifestPath, 'utf8'));
  filesManifest.files['report.md'].contentType = 'text/markdown';
  writeCanonicalJson(filesManifestPath, filesManifest);
  assert.throws(() => verifyEvidenceBundle(filesDir), /manifest\.files\.report\.md has unexpected or missing fields/);
});

test('verifier rejects a coordinated false publication claim even when report hash is updated', (t) => {
  const dir = bundle(t);
  const manifestPath = path.join(dir, 'manifest.json');
  const reportPath = path.join(dir, 'report.md');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  manifest.configuration.publicationGate = { publishableHighN: true, suppressionReason: null };
  manifest.reportInputs.verdict = 'HIGH_N_PUBLICATION_GATE_PASSED';
  manifest.reportInputs.suppressionReason = null;
  const report = fs.readFileSync(reportPath, 'utf8')
    .replace('Verdict: HIGH_N_NOT_LIVE', 'Verdict: HIGH_N_PUBLICATION_GATE_PASSED')
    .replace('Suppression reason: HIGH_N_NOT_LIVE', 'Suppression reason: none');
  fs.writeFileSync(reportPath, report);
  const bytes = fs.readFileSync(reportPath);
  manifest.files['report.md'] = {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.length,
  };
  writeCanonicalJson(manifestPath, manifest);
  assert.throws(() => verifyEvidenceBundle(dir), /publication gate passed evidence label|SYNTHETIC.*publication/i);
});

test('sweep attempts normalize without request payload or output bytes', () => {
  const normalized = normalizeSweepSamples({
    experimentId: 'sweep-fixture',
    attempts: [{
      attemptId: 'distill:distill:1',
      kind: 'distill',
      caseId: null,
      n: 100,
      replicateId: 'r1',
      pairOrderSeed: 1701,
      requestedDistillationSeed: 2701,
      appliedDistillationSeed: null,
      distillationSeedStatus: 'unsupported',
      distillationSeedMechanism: 'provider_seed_not_supported_by_adapter',
      success: false,
      latencyMs: 5,
      inputTokens: null,
      outputTokens: null,
      providerCostMicroUsd: null,
      providerCostUsd: null,
      failureClass: 'ProviderError',
      providerRequestId: null,
      budgetAttemptId: 'attempt-000001',
      payload: { private: true },
      output: 'private',
    }],
  });
  assert.equal(normalized.length, 1);
  assert.equal(Object.hasOwn(normalized[0], 'payload'), false);
  assert.equal(Object.hasOwn(normalized[0], 'output'), false);
  assert.equal(normalized[0].budgetAttemptId, 'attempt-000001');
  assert.doesNotThrow(() => recomputeSummary(normalized));
});

test('completed sweep output writes and verifies through the public bundle seam', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-sweep-evidence-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const result = {
    samples: [{
      attemptId: 'target-heldout:a:1',
      kind: 'target-heldout',
      caseId: 'a',
      n: null,
      replicateId: null,
      pairOrderSeed: null,
      requestedDistillationSeed: null,
      appliedDistillationSeed: null,
      distillationSeedStatus: 'not_requested',
      distillationSeedMechanism: 'no_seed_requested',
      success: true,
      latencyMs: 10,
      inputTokens: 3,
      outputTokens: 2,
      providerCostMicroUsd: '5',
      providerCostUsd: 0.000005,
      score: 1,
      criticalGatePass: true,
      failureClass: null,
      providerRequestId: 'synthetic',
    }],
    publishableHighN: false,
    suppressionReason: 'HIGH_N_NOT_LIVE',
  };
  const written = await writeSweepEvidenceBundle({
    result,
    executionMode: 'mock',
    gitState: currentGitState,
    config,
    outputDir: dir,
    experimentId: 'sweep-bundle-fixture',
    evidenceLabel: 'SYNTHETIC',
    command: 'npm run sweep:mock',
    readmeInputs: readmeInputs('evidence/sweep-bundle-fixture'),
  });
  assert.equal(written.verified.valid, true);
  assert.equal(written.verified.samples.length, 1);
});

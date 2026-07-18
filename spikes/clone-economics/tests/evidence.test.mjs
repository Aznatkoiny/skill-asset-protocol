import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';

import { recomputeSummary, verifyEvidenceBundle, writeEvidenceBundle } from '../src/evidence.mjs';
import { normalizeSweepSamples, writeSweepEvidenceBundle } from '../src/sweep.mjs';
import { liveAuthorizationHash } from '../src/authorization.mjs';
import { approved, config, economics } from './fixtures/live-contract.mjs';

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
  ...overrides,
});

const syntheticReportInputs = (overrides = {}) => ({
  evidenceLabel: 'SYNTHETIC',
  verdict: 'HIGH_N_NOT_LIVE',
  suppressionReason: 'HIGH_N_NOT_LIVE',
  limitations: ['SYNTHETIC_ONLY'],
  ...overrides,
});

function evidenceInput(outputDir, overrides = {}) {
  return {
    outputDir,
    manifest: {
      experimentId: 'adversarial-fixture',
      evidenceLabel: 'SYNTHETIC',
      command: 'test',
      configuration: {},
      ...(overrides.manifest ?? {}),
    },
    samples,
    reportInputs: syntheticReportInputs(overrides.reportInputs),
    reproduction: 'verify adversarial fixture',
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
    manifest: { experimentId: 'fixture-run', evidenceLabel: 'SYNTHETIC', command: 'npm run sweep:mock' },
    samples,
    reportInputs: syntheticReportInputs(),
    reproduction: 'node scripts/verify-bundle.mjs evidence/fixture-run',
  });
  const verified = verifyEvidenceBundle(dir);
  assert.equal(verified.valid, true);
  assert.equal(verified.summary.attemptedSamples, 3);
  assert.equal(verified.summary.failedSamples, 1);
  assert.equal(verified.summary.providerCostUsd, null);
  assert.equal(verified.summary.latencyMs.p50, 10);
  assert.equal(verified.summary.latencyMs.p95, 30);
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
    /failureClass must be string or null/,
  );

  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-preflight-'));
  const outputDir = path.join(parent, 'bundle');
  try {
    assert.throws(() => writeEvidenceBundle({
      outputDir,
      manifest: {
        experimentId: 'nested-config',
        evidenceLabel: 'SYNTHETIC',
        command: 'test',
        configuration: {
          publicationGate: {
            publishableHighN: false,
            suppressionReason: { rawResponse: 'private' },
          },
        },
      },
      samples,
      reportInputs: syntheticReportInputs(),
      reproduction: 'verify rejected fixture',
    }), /forbidden evidence field|publicationGate\.suppressionReason must be string or null/);
    assert.equal(fs.existsSync(outputDir), false, 'invalid input must not create an output directory');
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

function rewriteManifestHash(dir, name) {
  const manifestPath = path.join(dir, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const bytes = fs.readFileSync(path.join(dir, name));
  manifest.files[name] = {
    sha256: createHash('sha256').update(bytes).digest('hex'),
    bytes: bytes.length,
  };
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
}

function bundle(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-strict-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeEvidenceBundle({
    outputDir: dir,
    manifest: { experimentId: 'strict-run', evidenceLabel: 'SYNTHETIC', command: 'test' },
    samples,
    reportInputs: syntheticReportInputs(),
    reproduction: 'verify strict fixture',
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
  fs.writeFileSync(extraManifestPath, `${JSON.stringify(extraManifest, null, 2)}\n`);
  assert.throws(() => verifyEvidenceBundle(extraFieldDir), /forbidden evidence field|Evidence manifest has unexpected or missing fields/);

  const nonFiniteDir = bundle(t);
  const nonFiniteManifestPath = path.join(nonFiniteDir, 'manifest.json');
  const nonFiniteText = fs.readFileSync(nonFiniteManifestPath, 'utf8')
    .replace('"configuration": {}', '"configuration": {"nValues": [1e400]}');
  fs.writeFileSync(nonFiniteManifestPath, nonFiniteText);
  assert.throws(() => verifyEvidenceBundle(nonFiniteDir), /finite JSON numbers|configuration\.nValues\[0\] must be a positive safe integer/);
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

test('writer validates all inputs before creating output', () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-no-partial-'));
  const outputDir = path.join(parent, 'bundle');
  try {
    assert.throws(() => writeEvidenceBundle({
      outputDir,
      manifest: {
        experimentId: 'invalid-manifest',
        recordedAtUtc: 'not-a-timestamp',
        evidenceLabel: 'SYNTHETIC',
        command: 'test',
      },
      samples,
      reportInputs: syntheticReportInputs(),
      reproduction: 'verify absent fixture',
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
  fs.writeFileSync(runtimeManifestPath, `${JSON.stringify(runtimeManifest, null, 2)}\n`);
  assert.throws(() => verifyEvidenceBundle(runtimeDir), /manifest\.runtime\.node must be a non-empty string/);

  const filesDir = bundle(t);
  const filesManifestPath = path.join(filesDir, 'manifest.json');
  const filesManifest = JSON.parse(fs.readFileSync(filesManifestPath, 'utf8'));
  filesManifest.files['report.md'].contentType = 'text/markdown';
  fs.writeFileSync(filesManifestPath, `${JSON.stringify(filesManifest, null, 2)}\n`);
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
  fs.writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
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
      payload: { private: true },
      output: 'private',
    }],
  });
  assert.equal(normalized.length, 1);
  assert.equal(Object.hasOwn(normalized[0], 'payload'), false);
  assert.equal(Object.hasOwn(normalized[0], 'output'), false);
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
    config,
    outputDir: dir,
    experimentId: 'sweep-bundle-fixture',
    evidenceLabel: 'SYNTHETIC',
    command: 'npm run sweep:mock',
  });
  assert.equal(written.verified.valid, true);
  assert.equal(written.verified.samples.length, 1);
});

test('live bundle authorization recomputes from hash-verified budget and economics snapshots', (t) => {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-live-evidence-'));
  t.after(() => fs.rmSync(tempRoot, { recursive: true, force: true }));
  const fixturesDir = path.join(tempRoot, 'fixtures');
  const outputDir = path.join(tempRoot, 'evidence', 'live-fixture');
  fs.mkdirSync(fixturesDir, { recursive: true });
  const snapshotBytes = Buffer.from(`${JSON.stringify(approved, null, 2)}\n`);
  const economicsBytes = Buffer.from(`${JSON.stringify(economics, null, 2)}\n`);
  fs.writeFileSync(path.join(fixturesDir, 'live-budget-v1.json'), snapshotBytes);
  fs.writeFileSync(path.join(fixturesDir, 'live-economics-v1.json'), economicsBytes);
  const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
  const authorizationHash = liveAuthorizationHash({ config, snapshot: approved, economics });
  writeEvidenceBundle({
    outputDir,
    manifest: {
      experimentId: 'live-fixture',
      evidenceLabel: 'SYNTHETIC',
      command: 'synthetic live verifier fixture',
      liveBudget: {
        snapshotPath: 'fixtures/live-budget-v1.json',
        snapshotSha256: digest(snapshotBytes),
        economicsSnapshotPath: 'fixtures/live-economics-v1.json',
        economicsSnapshotSha256: digest(economicsBytes),
        authorizationHash,
        humanCapMicroUsd: '1000000',
        conservativeEstimateMicroUsd: '1000000',
        worstCasePerCallMicroUsd: '1000000',
        attemptedCalls: 1,
        knownAccruedMicroUsd: '39',
        outstandingReservedMicroUsd: '0',
        lock: null,
      },
      configuration: { sweepConfig: config, liveEconomics: economics },
    },
    samples: [normalizedSample({
      sampleId: 'live:target-heldout:a',
      latencyMs: 1,
      inputTokens: 3,
      outputTokens: 2,
      providerCostMicroUsd: '39',
      providerCostUsd: 0.000039,
      score: 1,
      criticalGatePass: true,
    })],
    reportInputs: syntheticReportInputs(),
    reproduction: 'verify live fixture',
  });
  assert.equal(verifyEvidenceBundle(outputDir).valid, true);
});

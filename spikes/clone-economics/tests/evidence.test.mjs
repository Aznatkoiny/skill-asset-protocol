import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createHash } from 'node:crypto';

import { recomputeSummary, verifyEvidenceBundle, writeEvidenceBundle } from '../src/evidence.mjs';
import { normalizeSweepSamples, writeSweepEvidenceBundle } from '../src/sweep.mjs';

const samples = [
  { sampleId: 'run:target-heldout:a', phase: 'evaluation', profile: 'target', caseId: 'a', success: true, latencyMs: 10, inputTokens: 3, outputTokens: 2, providerCostUsd: 0.01, score: 0.9, criticalGatePass: true },
  { sampleId: 'run:clone-heldout:a', phase: 'evaluation', profile: 'clone', caseId: 'a', success: true, latencyMs: 30, inputTokens: 3, outputTokens: 2, providerCostUsd: 0.02, score: 0.7, criticalGatePass: false },
  { sampleId: 'run:distill:1', phase: 'distillation', profile: 'clone', caseId: null, success: false, latencyMs: 5, inputTokens: null, outputTokens: null, providerCostUsd: null, score: null, criticalGatePass: null, failureClass: 'ProviderError' },
];

test('bundle hashes and summary recompute from normalized samples', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeEvidenceBundle({
    outputDir: dir,
    manifest: { experimentId: 'fixture-run', evidenceLabel: 'SYNTHETIC', command: 'npm run sweep:mock' },
    samples,
    interpretation: 'Synthetic fixture bundle.',
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
    interpretation: 'Strict fixture bundle.',
    reproduction: 'verify strict fixture',
  });
  return dir;
}

test('verifier rejects a changed file even when JSON remains parseable', (t) => {
  const dir = bundle(t);
  fs.appendFileSync(path.join(dir, 'README.md'), '\ntampered\n');
  assert.throws(() => verifyEvidenceBundle(dir), /hash or byte count mismatch: README\.md/);
});

test('verifier rejects duplicate IDs and forbidden fields after a manifest rehash', (t) => {
  const duplicateDir = bundle(t);
  fs.appendFileSync(path.join(duplicateDir, 'samples.jsonl'), `${JSON.stringify(samples[0])}\n`);
  rewriteManifestHash(duplicateDir, 'samples.jsonl');
  assert.throws(() => verifyEvidenceBundle(duplicateDir), /duplicate sampleId/);

  const forbiddenDir = bundle(t);
  const changed = { ...samples[0], prompt: 'private' };
  const lines = fs.readFileSync(path.join(forbiddenDir, 'samples.jsonl'), 'utf8').trimEnd().split('\n');
  lines[0] = JSON.stringify(changed);
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
  assert.throws(() => verifyEvidenceBundle(reportDir), /Latency p95 ms differs/);
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
  const config = {
    schemaVersion: 1,
    experimentFamily: 'clone-economics-high-n-v1',
    fixtureSet: 'v2',
    nValues: [6, 25, 50, 100],
    replicates: [],
    acquisitionTreatment: 'modeled_unless_x402_receipts_attached',
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

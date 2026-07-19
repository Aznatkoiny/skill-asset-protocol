import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  LEGACY_SOURCE_SHA256,
  normalizeLegacyReport,
} from '../scripts/import-legacy-run.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const importer = path.join(root, 'scripts/import-legacy-run.mjs');

function scoreCases(prefix, count, score, criticalGatePass) {
  return Array.from({ length: count }, (_, index) => ({
    id: `${prefix}-${index + 1}`,
    score,
    criticalGatePass,
  }));
}

function syntheticLegacyReport() {
  const heldoutIds = Array.from({ length: 6 }, (_, index) => `heldout-${index + 1}`);
  const v2Ids = ['v2-1', 'v2-2'];
  const records = [];
  const add = (kind, caseId, index) => records.push({
    requestId: `legacy-${String(index).padStart(3, '0')}`,
    kind,
    caseId,
    model: 'synthetic-legacy-model',
    normalizedUsage: { inputTokens: 10 + index, outputTokens: 5 + index },
    costUsd: 0.001 * index,
    latencyMs: index,
  });
  let index = 1;
  for (let i = 1; i <= 6; i += 1) add('target-train', `train-${i}`, index++);
  add('distill', null, index++);
  for (const id of heldoutIds) add('target-heldout', id, index++);
  for (const id of heldoutIds) add('clone-heldout', id, index++);
  for (const id of heldoutIds) add('bad-clone-heldout', id, index++);
  for (const id of v2Ids) add('target-v2-heldout', id, index++);
  for (const id of v2Ids) add('clone-v2-heldout', id, index++);
  return {
    schemaVersion: 1,
    mode: 'live',
    dataset: { N: 6 },
    fidelity: {
      target: { absoluteScore: 0.4, criticalGatePass: false, cases: scoreCases('heldout', 6, 0.4, false) },
      clone: { absoluteScore: 0.3, criticalGatePass: false, cases: scoreCases('heldout', 6, 0.3, false) },
      badClone: { absoluteScore: 0.1, criticalGatePass: false, cases: scoreCases('heldout', 6, 0.1, false) },
    },
    evolution: {
      updatedTarget: { cases: scoreCases('v2', 2, 0.5, false) },
      frozenClone: { cases: scoreCases('v2', 2, 0.25, false) },
    },
    economics: { acquisitionModeledUsd: 1.5 },
    usage: { raw: records },
  };
}

test('legacy normalization retains 29 allow-listed rows and joins fidelity', () => {
  const samples = normalizeLegacyReport(syntheticLegacyReport());
  assert.equal(samples.length, 29);
  assert.equal(samples.filter((sample) => sample.phase === 'acquisition').length, 6);
  assert.equal(samples.filter((sample) => sample.phase === 'distillation').length, 1);
  assert.equal(samples.find((sample) => sample.caseId === 'heldout-1' && sample.profile === 'target').score, 0.4);
  assert.equal(samples.reduce((sum, sample) => sum + sample.acquisitionCostUsd, 0), 1.5);
  for (const sample of samples) {
    assert.equal(sample.budgetAttemptId, null);
    for (const forbidden of ['prompt', 'payload', 'output', 'rawResponse', 'targetSkill', 'referenceText']) {
      assert.equal(Object.hasOwn(sample, forbidden), false);
    }
  }
});

test('all six immutable historical facts are asserted', () => {
  const source = syntheticLegacyReport();
  const mutations = [
    { ...source, schemaVersion: 2 },
    { ...source, mode: 'mock' },
    { ...source, dataset: { ...source.dataset, N: 7 } },
    { ...source, fidelity: { ...source.fidelity, target: { ...source.fidelity.target, absoluteScore: 0.5 } } },
    { ...source, fidelity: { ...source.fidelity, target: { ...source.fidelity.target, criticalGatePass: true } } },
    { ...source, economics: { ...source.economics, acquisitionModeledUsd: 1.6 } },
  ];
  for (const changed of mutations) assert.throws(() => normalizeLegacyReport(changed), /historical source fact mismatch/);
});

test('wrong declared digest and changed source bytes create no output', (t) => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-legacy-import-test-'));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const input = path.join(temp, 'source.json');
  fs.writeFileSync(input, JSON.stringify(syntheticLegacyReport()));

  const wrongOutput = path.join(temp, 'wrong-output');
  const wrong = spawnSync(process.execPath, [
    importer,
    '--input', input,
    '--expected-sha256', '0'.repeat(64),
    '--output', wrongOutput,
  ], { cwd: root, encoding: 'utf8' });
  assert.notEqual(wrong.status, 0);
  assert.match(wrong.stderr, /declared digest must equal the immutable legacy digest/i);
  assert.equal(fs.existsSync(wrongOutput), false);

  const changedOutput = path.join(temp, 'changed-output');
  const changed = spawnSync(process.execPath, [
    importer,
    '--input', input,
    '--expected-sha256', LEGACY_SOURCE_SHA256,
    '--output', changedOutput,
  ], { cwd: root, encoding: 'utf8' });
  assert.notEqual(changed.status, 0);
  assert.match(changed.stderr, /byte count|digest mismatch/i);
  assert.equal(fs.existsSync(changedOutput), false);
});

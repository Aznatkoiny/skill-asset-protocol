import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadFixtureSet } from '../src/fixture-set.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('v2 fixtures contain 100 train and 30 disjoint heldout cases', () => {
  const fixtures = loadFixtureSet(root, 'v2');
  assert.equal(fixtures.train.length, 100);
  assert.equal(fixtures.heldout.length, 30);
  assert.equal(fixtures.disjoint, true);
  assert.equal(new Set(fixtures.train.map((x) => x.id)).size, 100);
  assert.equal(new Set(fixtures.heldout.map((x) => x.id)).size, 30);
  assert.equal(fixtures.heldout.every((x) => x.rubric && x.rubric.exactPaths.length === 1), true);
});

test('fixture generation is byte deterministic', () => {
  const train = fs.readFileSync(path.join(root, 'fixtures/train-v2.json'), 'utf8');
  const heldout = fs.readFileSync(path.join(root, 'fixtures/heldout-v2.json'), 'utf8');
  execFileSync(process.execPath, ['scripts/generate-fixtures.mjs', '--check'], { cwd: root });
  assert.equal(fs.readFileSync(path.join(root, 'fixtures/train-v2.json'), 'utf8'), train);
  assert.equal(fs.readFileSync(path.join(root, 'fixtures/heldout-v2.json'), 'utf8'), heldout);
});

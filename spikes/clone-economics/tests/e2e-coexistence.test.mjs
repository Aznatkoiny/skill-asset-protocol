import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { treeSnapshot } from '../src/tree-snapshot.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('offline e2e preserves an existing ignored runs directory', (t) => {
  const retainedRoot = path.join(root, 'runs', 'e2e-retained-regression');
  const marker = path.join(retainedRoot, 'live', 'nested', 'e2e-retained-marker.bin');
  const expected = Buffer.from([0, 1, 2, 10, 13, 255]);
  fs.mkdirSync(path.dirname(marker), { recursive: true });
  fs.writeFileSync(marker, expected);
  t.after(() => fs.rmSync(retainedRoot, { recursive: true, force: true }));
  const output = execFileSync(process.execPath, ['e2e.mjs'], {
    cwd: root,
    env: { ...process.env, MOCK_LLM: '1', ALLOW_LIVE_LLM: '0' },
    encoding: 'utf8',
  });
  assert.match(output, /PASS/);
  assert.deepEqual(fs.readFileSync(marker), expected);
});

test('tree snapshots detect changed bytes at an unchanged nested path', (t) => {
  const directory = fs.mkdtempSync(path.join(process.env.TMPDIR ?? '/tmp', 'clone-tree-snapshot-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const marker = path.join(directory, 'nested', 'marker.bin');
  fs.mkdirSync(path.dirname(marker), { recursive: true });
  fs.writeFileSync(marker, Buffer.from('before'));
  const before = treeSnapshot(directory);
  fs.writeFileSync(marker, Buffer.from('after!'));
  assert.notDeepEqual(treeSnapshot(directory), before);
});

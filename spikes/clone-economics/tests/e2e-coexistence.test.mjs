import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('offline e2e preserves an existing ignored runs directory', (t) => {
  const marker = path.join(root, 'runs', 'e2e-retained-marker.txt');
  fs.mkdirSync(path.dirname(marker), { recursive: true });
  fs.writeFileSync(marker, 'retain me\n');
  t.after(() => fs.rmSync(marker, { force: true }));
  const output = execFileSync(process.execPath, ['e2e.mjs'], {
    cwd: root,
    env: { ...process.env, MOCK_LLM: '1', ALLOW_LIVE_LLM: '0' },
    encoding: 'utf8',
  });
  assert.match(output, /PASS/);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'retain me\n');
});

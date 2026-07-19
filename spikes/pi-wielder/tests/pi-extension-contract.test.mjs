import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const extensionUrl = new URL('../pi-extension/x402.ts', import.meta.url);

test('Pi invoke_skill exposes only input and uses one fixed encoded Collar route', () => {
  const source = fs.readFileSync(extensionUrl, 'utf8');
  assert.equal(/\bskillId\b/.test(source), false);
  assert.match(
    source,
    /const HOSTED_SKILL_ID = "optimizing-claude-code-prompts";/,
  );
  assert.match(
    source,
    /const HOSTED_SKILL_PATH = `\/invoke\/\$\{encodeURIComponent\(HOSTED_SKILL_ID\)\}`;/,
  );
  assert.match(source, /async execute\(args: \{ input: string \}\)/);
  assert.match(source, /fetch\(`\$\{PROXY\}\$\{HOSTED_SKILL_PATH\}`/);
  assert.doesNotMatch(source, /properties:\s*\{[^}]*skill/i);
});

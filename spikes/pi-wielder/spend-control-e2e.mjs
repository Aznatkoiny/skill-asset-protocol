import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { canonicalJson } from './src/kernel/canonical.mjs';
import { runSpendControlProcessAcceptance } from './scripts/lib/spend-control-process-runner.mjs';

const authorityDirectory = fs.realpathSync(
  fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-spend-control-')),
);
fs.chmodSync(authorityDirectory, 0o700);

let cleanup = async () => {};
try {
  const result = await runSpendControlProcessAcceptance({
    authorityDirectory,
    piExecutable: path.resolve(import.meta.dirname, 'node_modules', '.bin', 'pi'),
  });
  cleanup = result.cleanup;
  process.stdout.write(`${canonicalJson(result.summary)}\n`);
  if (result.summary.tests !== 18 || result.summary.passed !== 18) process.exitCode = 1;
} catch (error) {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code)
    ? error.code
    : 'SPEND_CONTROL_PROCESS_FAILED';
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
} finally {
  try { await cleanup(); } catch {}
  fs.rmSync(authorityDirectory, { recursive: true, force: true });
}

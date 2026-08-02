import fs from 'node:fs';

import { createBudgetLedger } from '../../src/kernel/budget-ledger.mjs';
import { canonicalTimestamp } from '../../src/kernel/canonical.mjs';
import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';

const arguments_ = process.argv.slice(2);
if (arguments_.length !== 7) {
  throw new Error(
    'usage: budget-writer.mjs databasePath trustedAncestor intentId amountAtomic fixedNow readyFile releaseFile',
  );
}
const [
  databasePath,
  trustedAncestor,
  intentId,
  amountAtomic,
  fixedNow,
  readyFile,
  releaseFile,
] = arguments_;
const timestamp = canonicalTimestamp(fixedNow, 'budget writer fixed time');
const now = () => timestamp;
const pathTrust = Object.freeze({
  mode: 'deterministic',
  trustedAncestor,
  kernelUid: process.getuid(),
  agentUid: process.getuid(),
});

const store = openKernelStore({ filePath: databasePath, pathTrust, now });
let result;
try {
  fs.writeFileSync(readyFile, 'ready', { flag: 'wx', mode: 0o600 });
  const signal = new Int32Array(new SharedArrayBuffer(4));
  while (!fs.existsSync(releaseFile)) Atomics.wait(signal, 0, 0, 5);

  const ledger = createBudgetLedger({ store, now });
  try {
    ledger.reserve({ intentId, amountAtomic });
    result = 'reserved';
  } catch (error) {
    if (error?.code !== 'LIMIT_EXCEEDED') throw error;
    result = 'LIMIT_EXCEEDED';
  }
} finally {
  store.close();
}
process.stdout.write(`${result}\n`);

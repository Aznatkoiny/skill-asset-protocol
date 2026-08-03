import fs from 'node:fs';

import { createInvocationJournal } from '../src/invocation-journal.mjs';

const [filePath, signingKeyPath, barrierPath, idempotencyKey, readyPath] = process.argv.slice(2);
const journal = createInvocationJournal({ filePath, signingKeyPath });
fs.writeFileSync(readyPath, 'ready', { flag: 'wx' });
while (!fs.existsSync(barrierPath)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
const digit = idempotencyKey.endsWith('-a') ? '1' : '2';
journal.requestInvocation({
  idempotencyKey,
  mode: 'external',
  skillId: 'skill-a',
  skillVersionHash: `sha256:${'a'.repeat(64)}`,
  requestHash: `sha256:${digit.repeat(64)}`,
  creatorId: 'creator-a',
  beneficiaryId: null,
});

import { DatabaseSync } from 'node:sqlite';

import { acquireAuthorityLock } from '../../src/kernel/authority-lock.mjs';

function report(message) {
  if (typeof process.send === 'function') process.send(message);
  else process.stdout.write(`${JSON.stringify(message)}\n`);
}

function mutateMainDatabase(databasePath, marker) {
  const database = new DatabaseSync(databasePath, { timeout: 0 });
  try {
    database.exec(`
      CREATE TABLE IF NOT EXISTS authority_lock_probe (
        marker TEXT PRIMARY KEY NOT NULL
      ) STRICT
    `);
    database.prepare('INSERT INTO authority_lock_probe(marker) VALUES (?)').run(marker);
  } finally {
    database.close();
  }
}

const payload = JSON.parse(process.argv[2]);
const pathTrust = Object.freeze({
  mode: 'deterministic',
  trustedAncestor: payload.trustedAncestor,
  kernelUid: process.getuid(),
  agentUid: process.getuid(),
});

let lock;
try {
  lock = acquireAuthorityLock({
    databasePath: payload.databasePath,
    role: payload.role,
    pathTrust,
  });
  if (payload.mutateMainDatabase === true) {
    mutateMainDatabase(payload.databasePath, payload.marker);
  }
  report({ role: payload.role, type: 'ready' });
} catch (error) {
  report({
    code: error?.code ?? null,
    message: error?.message ?? String(error),
    name: error?.name ?? null,
    type: 'error',
  });
  process.exitCode = 1;
}

if (lock) {
  process.on('message', (message) => {
    if (message?.type === 'abort') process.abort();
    if (message?.type !== 'release') return;
    try {
      lock.close();
      lock.close();
      report({ type: 'closed' });
    } finally {
      process.exit(0);
    }
  });
}

import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';

const [databasePath, trustedAncestor, claimId] = process.argv.slice(2);
const pathTrust = Object.freeze({
  mode: 'deterministic',
  trustedAncestor,
  kernelUid: process.getuid(),
  agentUid: process.getuid(),
});
const store = openKernelStore({ filePath: databasePath, pathTrust });
try {
  const outcome = store.transaction((token) => store.within(token,
    ({ db, appendEvent }) => {
      const current = db.prepare('SELECT value FROM metadata WHERE key = ?').get('claim');
      if (current) return 'already_claimed';
      db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('claim', claimId);
      appendEvent({
        entityType: 'test',
        entityId: claimId,
        eventType: 'test.claimed',
        data: { claimId },
      });
      return 'claimed';
    }));
  process.stdout.write(`${outcome}\n`);
} finally {
  store.close();
}

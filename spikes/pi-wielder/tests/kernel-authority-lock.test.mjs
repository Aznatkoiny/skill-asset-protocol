import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { KernelError } from '../src/kernel/canonical.mjs';

const CURRENT_UID = process.getuid();
const REPOSITORY_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
const WORKER_PATH = fileURLToPath(new URL('./fixtures/kernel-lock-worker.mjs', import.meta.url));
const ROLES = Object.freeze(['kernel', 'bootstrap', 'prelaunch']);

function authority(t, prefix = 'wallet-kernel-authority-lock-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: CURRENT_UID,
    agentUid: CURRENT_UID,
  });
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    databasePath: path.join(directory, 'kernel.sqlite'),
    directory,
    pathTrust,
  };
}

function authorityLockPath(databasePath) {
  return `${databasePath}.authority-lock.sqlite`;
}

function startWorker(t, fixture, overrides = {}) {
  const payload = {
    databasePath: fixture.databasePath,
    role: 'kernel',
    trustedAncestor: fixture.directory,
    ...overrides,
  };
  const child = fork(WORKER_PATH, [JSON.stringify(payload)], {
    silent: true,
  });
  const messages = [];
  const waiters = [];
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('message', (message) => {
    const index = waiters.findIndex((waiter) => waiter.predicate(message));
    if (index === -1) {
      messages.push(message);
      return;
    }
    const [waiter] = waiters.splice(index, 1);
    clearTimeout(waiter.timer);
    waiter.resolve(message);
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });

  return {
    child,
    get stderr() { return stderr; },
    next(predicate = () => true, timeoutMilliseconds = 5_000) {
      const index = messages.findIndex(predicate);
      if (index !== -1) return Promise.resolve(messages.splice(index, 1)[0]);
      return new Promise((resolve, reject) => {
        const waiter = { predicate, resolve };
        waiter.timer = setTimeout(() => {
          const waiterIndex = waiters.indexOf(waiter);
          if (waiterIndex !== -1) waiters.splice(waiterIndex, 1);
          reject(new Error(`timed out waiting for lock worker message; stderr=${stderr}`));
        }, timeoutMilliseconds);
        waiters.push(waiter);
      });
    },
  };
}

function waitForExit(worker, timeoutMilliseconds = 5_000) {
  if (worker.child.exitCode !== null || worker.child.signalCode !== null) {
    return Promise.resolve({
      code: worker.child.exitCode,
      signal: worker.child.signalCode,
    });
  }
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      reject(new Error(`timed out waiting for lock worker exit; stderr=${worker.stderr}`));
    }, timeoutMilliseconds);
    worker.child.once('exit', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal });
    });
  });
}

async function releaseWorker(worker) {
  worker.child.send({ type: 'release' });
  assert.deepEqual(await worker.next((message) => message.type === 'closed'), {
    type: 'closed',
  });
  assert.deepEqual(await waitForExit(worker), { code: 0, signal: null });
}

test('one process owns the shared authority until its idempotent close', (t) => {
  const fixture = authority(t);
  const owner = acquireAuthorityLock({
    databasePath: fixture.databasePath,
    role: 'kernel',
    pathTrust: fixture.pathTrust,
  });
  assert.equal(typeof owner.close, 'function');
  assert.throws(
    () => acquireAuthorityLock({
      databasePath: fixture.databasePath,
      role: 'bootstrap',
      pathTrust: fixture.pathTrust,
    }),
    (error) => error instanceof KernelError
      && error.code === 'AUTHORITY_BUSY'
      && /authority/i.test(error.message),
  );
  owner.close();
  owner.close();
  acquireAuthorityLock({
    databasePath: fixture.databasePath,
    role: 'bootstrap',
    pathTrust: fixture.pathTrust,
  }).close();

  const lockPath = authorityLockPath(fixture.databasePath);
  assert.equal(fs.statSync(lockPath).mode & 0o777, 0o600);
  const database = new DatabaseSync(lockPath, { readOnly: true });
  try {
    assert.equal(database.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
    assert.deepEqual(database.prepare(`
      SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name
    `).all(), []);
  } finally {
    database.close();
  }
});

test('a failed connection close is retryable without rolling back twice', (t) => {
  const fixture = authority(t, 'wallet-kernel-close-retry-');
  const owner = acquireAuthorityLock({
    databasePath: fixture.databasePath,
    role: 'kernel',
    pathTrust: fixture.pathTrust,
  });
  const originalClose = DatabaseSync.prototype.close;
  const originalExec = DatabaseSync.prototype.exec;
  let closeCalls = 0;
  let rollbackCalls = 0;
  DatabaseSync.prototype.exec = function countAuthorityRollback(statement) {
    if (statement === 'ROLLBACK') rollbackCalls += 1;
    return originalExec.call(this, statement);
  };
  DatabaseSync.prototype.close = function failFirstAuthorityClose() {
    closeCalls += 1;
    if (closeCalls === 1) throw new Error('injected authority connection close failure');
    return originalClose.call(this);
  };
  try {
    assert.throws(() => owner.close(), /injected authority connection close failure/);
    assert.equal(rollbackCalls, 1);
    assert.doesNotThrow(() => owner.close());
    assert.equal(closeCalls, 2);
    assert.equal(rollbackCalls, 1);
    assert.doesNotThrow(() => owner.close());
    assert.equal(closeCalls, 2);
  } finally {
    DatabaseSync.prototype.close = originalClose;
    DatabaseSync.prototype.exec = originalExec;
  }
});

test('only kernel, bootstrap, and prelaunch roles are accepted', (t) => {
  for (const role of ROLES) {
    const fixture = authority(t, `wallet-kernel-role-${role}-`);
    acquireAuthorityLock({
      databasePath: fixture.databasePath,
      role,
      pathTrust: fixture.pathTrust,
    }).close();
  }
  const fixture = authority(t, 'wallet-kernel-role-invalid-');
  for (const role of ['', 'operator', 'Kernel', null, 1]) {
    assert.throws(
      () => acquireAuthorityLock({
        databasePath: fixture.databasePath,
        role,
        pathTrust: fixture.pathTrust,
      }),
      (error) => error.code !== 'AUTHORITY_BUSY' && /role/.test(error.message),
    );
  }
});

test('simultaneous fresh processes yield exactly one ready owner', async (t) => {
  const fixture = authority(t, 'wallet-kernel-simultaneous-lock-');
  const first = startWorker(t, fixture, { role: 'kernel' });
  const second = startWorker(t, fixture, { role: 'bootstrap' });
  const outcomes = await Promise.all([first.next(), second.next()]);
  assert.equal(
    outcomes.filter((outcome) => outcome.type === 'ready').length,
    1,
    JSON.stringify(outcomes),
  );
  assert.equal(outcomes.filter(
    (outcome) => outcome.type === 'error' && outcome.code === 'AUTHORITY_BUSY',
  ).length, 1);

  const winner = outcomes[0].type === 'ready' ? first : second;
  const loser = winner === first ? second : first;
  assert.deepEqual(await waitForExit(loser), { code: 1, signal: null });
  await releaseWorker(winner);
});

test('simultaneous fresh processes migrate WAL to one rollback-journal owner', async (t) => {
  const fixture = authority(t, 'wallet-kernel-simultaneous-wal-lock-');
  const lockPath = authorityLockPath(fixture.databasePath);
  fs.writeFileSync(lockPath, '', { mode: 0o600 });
  const setup = new DatabaseSync(lockPath, { timeout: 0 });
  try {
    assert.equal(
      setup.prepare('PRAGMA journal_mode = WAL').get().journal_mode,
      'wal',
    );
  } finally {
    setup.close();
  }

  const first = startWorker(t, fixture, { role: 'kernel' });
  const second = startWorker(t, fixture, { role: 'prelaunch' });
  const outcomes = await Promise.all([first.next(), second.next()]);
  assert.equal(
    outcomes.filter((outcome) => outcome.type === 'ready').length,
    1,
    JSON.stringify(outcomes),
  );
  assert.equal(
    outcomes.filter(
      (outcome) => outcome.type === 'error' && outcome.code === 'AUTHORITY_BUSY',
    ).length,
    1,
    JSON.stringify(outcomes),
  );

  const winner = outcomes[0].type === 'ready' ? first : second;
  const loser = winner === first ? second : first;
  assert.deepEqual(await waitForExit(loser), { code: 1, signal: null });
  await releaseWorker(winner);

  const check = new DatabaseSync(lockPath, { readOnly: true });
  try {
    assert.equal(check.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
  } finally {
    check.close();
  }
});

test('a transient non-delete WAL result exhausts as AUTHORITY_BUSY', (t) => {
  const fixture = authority(t, 'wallet-kernel-wal-transition-busy-');
  const lockPath = authorityLockPath(fixture.databasePath);
  fs.writeFileSync(lockPath, '', { mode: 0o600 });
  const setup = new DatabaseSync(lockPath, { timeout: 0 });
  try {
    assert.equal(
      setup.prepare('PRAGMA journal_mode = WAL').get().journal_mode,
      'wal',
    );
  } finally {
    setup.close();
  }

  const originalPrepare = DatabaseSync.prototype.prepare;
  DatabaseSync.prototype.prepare = function retainWalMode(statement) {
    if (statement === 'PRAGMA journal_mode = DELETE') {
      return Object.freeze({
        get: () => Object.freeze({ journal_mode: 'wal' }),
      });
    }
    return originalPrepare.call(this, statement);
  };
  try {
    assert.throws(
      () => acquireAuthorityLock({
        databasePath: fixture.databasePath,
        role: 'kernel',
        pathTrust: fixture.pathTrust,
      }),
      (error) => error instanceof KernelError && error.code === 'AUTHORITY_BUSY',
    );
  } finally {
    DatabaseSync.prototype.prepare = originalPrepare;
  }

  acquireAuthorityLock({
    databasePath: fixture.databasePath,
    role: 'kernel',
    pathTrust: fixture.pathTrust,
  }).close();
  const check = new DatabaseSync(lockPath, { readOnly: true });
  try {
    assert.equal(check.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
  } finally {
    check.close();
  }
});

test('every ordered role pair contends and clean close permits a successor', async (t) => {
  for (const ownerRole of ROLES) {
    for (const contenderRole of ROLES) {
      const fixture = authority(t, `wallet-kernel-pair-${ownerRole}-${contenderRole}-`);
      const owner = startWorker(t, fixture, { role: ownerRole });
      assert.deepEqual(await owner.next(), { role: ownerRole, type: 'ready' });

      const contender = startWorker(t, fixture, { role: contenderRole });
      const rejected = await contender.next();
      assert.equal(rejected.type, 'error');
      assert.equal(rejected.code, 'AUTHORITY_BUSY');
      assert.deepEqual(await waitForExit(contender), { code: 1, signal: null });

      await releaseWorker(owner);
      const successor = startWorker(t, fixture, { role: contenderRole });
      assert.deepEqual(await successor.next(), { role: contenderRole, type: 'ready' });
      await releaseWorker(successor);
    }
  }
});

test('process.abort releases the OS lease and the leftover database is reusable', async (t) => {
  const fixture = authority(t, 'wallet-kernel-crash-release-');
  const owner = startWorker(t, fixture, { role: 'kernel' });
  assert.deepEqual(await owner.next(), { role: 'kernel', type: 'ready' });
  const lockPath = authorityLockPath(fixture.databasePath);
  assert.equal(fs.existsSync(lockPath), true);
  const originalIdentity = fs.statSync(lockPath);

  owner.child.send({ type: 'abort' });
  const crashed = await waitForExit(owner);
  assert.equal(crashed.code, null);
  assert.equal(crashed.signal, 'SIGABRT');
  assert.equal(fs.existsSync(lockPath), true);

  const successor = startWorker(t, fixture, { role: 'prelaunch' });
  assert.deepEqual(await successor.next(), { role: 'prelaunch', type: 'ready' });
  await releaseWorker(successor);
  const reusedIdentity = fs.statSync(lockPath);
  assert.equal(reusedIdentity.dev, originalIdentity.dev);
  assert.equal(reusedIdentity.ino, originalIdentity.ino);
});

test('PID-like files are neither trusted, created, nor deleted', (t) => {
  const fixture = authority(t, 'wallet-kernel-no-pid-file-');
  const lockPath = authorityLockPath(fixture.databasePath);
  const fakePidPath = `${lockPath}.pid`;
  fs.writeFileSync(fakePidPath, '999999\n', { mode: 0o600 });

  acquireAuthorityLock({
    databasePath: fixture.databasePath,
    role: 'bootstrap',
    pathTrust: fixture.pathTrust,
  }).close();

  assert.equal(fs.readFileSync(fakePidPath, 'utf8'), '999999\n');
  assert.deepEqual(
    fs.readdirSync(fixture.directory).filter((name) => name.endsWith('.pid')),
    [path.basename(fakePidPath)],
  );
});

test('a contender cannot mutate the main database before acquiring authority', async (t) => {
  const fixture = authority(t, 'wallet-kernel-mutation-order-');
  const database = new DatabaseSync(fixture.databasePath);
  try {
    database.exec(`
      CREATE TABLE authority_lock_probe (
        marker TEXT PRIMARY KEY NOT NULL
      ) STRICT
    `);
  } finally {
    database.close();
  }
  fs.chmodSync(fixture.databasePath, 0o600);

  const owner = startWorker(t, fixture, { role: 'kernel' });
  assert.deepEqual(await owner.next(), { role: 'kernel', type: 'ready' });
  const contender = startWorker(t, fixture, {
    marker: 'must-not-appear',
    mutateMainDatabase: true,
    role: 'bootstrap',
  });
  const rejected = await contender.next();
  assert.equal(rejected.type, 'error');
  assert.equal(rejected.code, 'AUTHORITY_BUSY');
  assert.deepEqual(await waitForExit(contender), { code: 1, signal: null });

  let check = new DatabaseSync(fixture.databasePath, { readOnly: true });
  try {
    assert.equal(check.prepare('SELECT count(*) AS count FROM authority_lock_probe').get().count, 0);
  } finally {
    check.close();
  }
  await releaseWorker(owner);

  const successor = startWorker(t, fixture, {
    marker: 'after-authority',
    mutateMainDatabase: true,
    role: 'bootstrap',
  });
  assert.deepEqual(await successor.next(), { role: 'bootstrap', type: 'ready' });
  await releaseWorker(successor);
  check = new DatabaseSync(fixture.databasePath, { readOnly: true });
  try {
    assert.deepEqual(
      check.prepare('SELECT marker FROM authority_lock_probe').all().map((row) => row.marker),
      ['after-authority'],
    );
  } finally {
    check.close();
  }
});

test('derived lock database rejects checkout, symlink, permissive, and wrong-owner-like paths', (t) => {
  {
    const fixture = authority(t, 'wallet-kernel-checkout-lock-');
    assert.throws(
      () => acquireAuthorityLock({
        databasePath: path.join(REPOSITORY_ROOT, 'spikes/pi-wielder/forbidden.sqlite'),
        role: 'kernel',
        pathTrust: fixture.pathTrust,
      }),
      (error) => error.code !== 'AUTHORITY_BUSY' && /outside the checkout/.test(error.message),
    );
  }
  {
    const fixture = authority(t, 'wallet-kernel-symlink-lock-');
    const target = path.join(fixture.directory, 'symlink-target');
    fs.writeFileSync(target, '', { mode: 0o600 });
    fs.symlinkSync(target, authorityLockPath(fixture.databasePath));
    assert.throws(
      () => acquireAuthorityLock({
        databasePath: fixture.databasePath,
        role: 'kernel',
        pathTrust: fixture.pathTrust,
      }),
      (error) => error.code !== 'AUTHORITY_BUSY' && /symlink/.test(error.message),
    );
  }
  {
    const fixture = authority(t, 'wallet-kernel-permissive-lock-');
    const lockPath = authorityLockPath(fixture.databasePath);
    fs.writeFileSync(lockPath, '', { mode: 0o644 });
    assert.throws(
      () => acquireAuthorityLock({
        databasePath: fixture.databasePath,
        role: 'prelaunch',
        pathTrust: fixture.pathTrust,
      }),
      (error) => error.code !== 'AUTHORITY_BUSY' && /owner-only/.test(error.message),
    );
    assert.equal(fs.statSync(lockPath).mode & 0o777, 0o644);
  }
  {
    const fixture = authority(t, 'wallet-kernel-owner-lock-');
    fs.writeFileSync(authorityLockPath(fixture.databasePath), '', { mode: 0o600 });
    const originalFstat = fs.fstatSync;
    fs.fstatSync = function reportDifferentFileOwner(descriptor, options) {
      const stat = originalFstat.call(fs, descriptor, options);
      if (stat.isFile()) stat.uid = CURRENT_UID + 1;
      return stat;
    };
    try {
      assert.throws(
        () => acquireAuthorityLock({
          databasePath: fixture.databasePath,
          role: 'prelaunch',
          pathTrust: fixture.pathTrust,
        }),
        (error) => error.code !== 'AUTHORITY_BUSY' && /current user/.test(error.message),
      );
    } finally {
      fs.fstatSync = originalFstat;
    }
  }
});

test('malformed paths and non-busy SQLite failures are never mapped to AUTHORITY_BUSY', (t) => {
  const fixture = authority(t, 'wallet-kernel-distinct-errors-');
  assert.throws(
    () => acquireAuthorityLock({
      databasePath: 'relative.sqlite',
      role: 'kernel',
      pathTrust: fixture.pathTrust,
    }),
    (error) => error.code !== 'AUTHORITY_BUSY' && /absolute/.test(error.message),
  );

  fs.writeFileSync(
    authorityLockPath(fixture.databasePath),
    'this is not a sqlite database',
    { mode: 0o600 },
  );
  assert.throws(
    () => acquireAuthorityLock({
      databasePath: fixture.databasePath,
      role: 'kernel',
      pathTrust: fixture.pathTrust,
    }),
    (error) => error.code === 'ERR_SQLITE_ERROR'
      && error.errcode !== 5
      && error.errcode !== 6,
  );
});

import { DatabaseSync } from 'node:sqlite';

import { KernelError } from './canonical.mjs';
import { preparePrivateFile } from './secure-storage.mjs';

const AUTHORITY_LOCK_SUFFIX = '.authority-lock.sqlite';
const ROLES = new Set(['kernel', 'bootstrap', 'prelaunch']);
const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;
const ACQUISITION_ATTEMPTS = 4;
const RETRY_SIGNAL = new Int32Array(new SharedArrayBuffer(4));

function isSqliteContention(error) {
  if (error?.code !== 'ERR_SQLITE_ERROR' || !Number.isInteger(error.errcode)) return false;
  const primaryResultCode = error.errcode & 0xff;
  return primaryResultCode === SQLITE_BUSY || primaryResultCode === SQLITE_LOCKED;
}

function closeFailedAcquisition(database) {
  if (!database) return;
  try {
    database.close();
  } catch {
    // Preserve the acquisition failure. This connection never owned the authority transaction.
  }
}

function waitForZeroTimeoutTieBreak(attempt) {
  // Two new zero-time connections can both lose a simultaneous lock upgrade.
  // Bounded PID-staggered fresh-connection retries resolve that startup tie
  // without changing SQLite's zero timeout or indefinitely waiting on an owner.
  Atomics.wait(RETRY_SIGNAL, 0, 0, 1 + ((process.pid * (attempt + 1)) % 97));
}

function openExclusiveAuthorityDatabase(lockPath) {
  let database;
  try {
    database = new DatabaseSync(lockPath, { timeout: 0 });
    database.exec('BEGIN EXCLUSIVE');
    let journalMode = database.prepare('PRAGMA journal_mode').get()?.journal_mode;
    if (journalMode !== 'delete') {
      database.exec('ROLLBACK');
      journalMode = database.prepare('PRAGMA journal_mode = DELETE').get()?.journal_mode;
      database.exec('BEGIN EXCLUSIVE');
    }
    if (journalMode !== 'delete') {
      throw new KernelError(
        'AUTHORITY_JOURNAL_MODE',
        'Wallet Kernel authority lock requires SQLite rollback journal mode',
      );
    }
    return database;
  } catch (error) {
    closeFailedAcquisition(database);
    throw error;
  }
}

export function acquireAuthorityLock({ databasePath, role, pathTrust }) {
  if (!ROLES.has(role)) {
    throw new KernelError(
      'AUTHORITY_ROLE_INVALID',
      'Wallet Kernel authority role must be kernel, bootstrap, or prelaunch',
    );
  }
  if (typeof databasePath !== 'string') {
    throw new KernelError(
      'AUTHORITY_PATH_INVALID',
      'Wallet Kernel database path must be an absolute string',
    );
  }

  const lockPath = `${databasePath}${AUTHORITY_LOCK_SUFFIX}`;
  preparePrivateFile(lockPath, 'Wallet Kernel authority lock', { pathTrust });

  let database;
  let contention;
  for (let attempt = 0; attempt < ACQUISITION_ATTEMPTS; attempt += 1) {
    try {
      database = openExclusiveAuthorityDatabase(lockPath);
      break;
    } catch (error) {
      if (!isSqliteContention(error)) throw error;
      contention = error;
      if (attempt + 1 < ACQUISITION_ATTEMPTS) waitForZeroTimeoutTieBreak(attempt);
    }
  }
  if (!database) {
    throw new KernelError(
      'AUTHORITY_BUSY',
      'Wallet Kernel authority is already held by another process',
      { cause: contention },
    );
  }

  let closed = false;
  return Object.freeze({
    close() {
      if (closed) return;
      closed = true;
      let failure;
      try {
        database.exec('ROLLBACK');
      } catch (error) {
        failure = error;
      }
      try {
        database.close();
      } catch (error) {
        failure ??= error;
      }
      if (failure) throw failure;
    },
  });
}

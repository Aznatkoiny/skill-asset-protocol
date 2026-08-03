import { DatabaseSync } from 'node:sqlite';

import { KernelError } from './canonical.mjs';
import { preparePrivateFile } from './secure-storage.mjs';

const AUTHORITY_LOCK_SUFFIX = '.authority-lock.sqlite';
const ROLES = new Set(['kernel', 'bootstrap', 'prelaunch']);
const SQLITE_BUSY = 5;
const SQLITE_LOCKED = 6;
const ACQUISITION_ATTEMPTS = 4;
const RETRY_SIGNAL = new Int32Array(new SharedArrayBuffer(4));

class RetryableJournalTransition extends Error {
  constructor() {
    super('SQLite rollback journal transition did not complete');
    this.name = 'RetryableJournalTransition';
  }
}

function isSqliteContention(error) {
  if (error?.code !== 'ERR_SQLITE_ERROR' || !Number.isInteger(error.errcode)) return false;
  const primaryResultCode = error.errcode & 0xff;
  return primaryResultCode === SQLITE_BUSY || primaryResultCode === SQLITE_LOCKED;
}

function closeFailedAcquisition(database, transactionHeld) {
  if (!database) return;
  if (transactionHeld) {
    try {
      database.exec('ROLLBACK');
    } catch {
      // Preserve the acquisition failure while still attempting connection close.
    }
  }
  try {
    database.close();
  } catch {
    // Preserve the acquisition failure; a failed open never returns an authority handle.
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
  let transactionHeld = false;
  try {
    database = new DatabaseSync(lockPath, { timeout: 0 });
    database.exec('BEGIN EXCLUSIVE');
    transactionHeld = true;
    let journalMode = database.prepare('PRAGMA journal_mode').get()?.journal_mode;
    if (journalMode !== 'delete') {
      database.exec('ROLLBACK');
      transactionHeld = false;
      journalMode = database.prepare('PRAGMA journal_mode = DELETE').get()?.journal_mode;
      if (journalMode !== 'delete') throw new RetryableJournalTransition();
      database.exec('BEGIN EXCLUSIVE');
      transactionHeld = true;
    }
    return database;
  } catch (error) {
    closeFailedAcquisition(database, transactionHeld);
    throw error;
  }
}

function isRetryableAcquisition(error) {
  return isSqliteContention(error) || error instanceof RetryableJournalTransition;
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
  let retryableFailure;
  for (let attempt = 0; attempt < ACQUISITION_ATTEMPTS; attempt += 1) {
    try {
      database = openExclusiveAuthorityDatabase(lockPath);
      break;
    } catch (error) {
      if (!isRetryableAcquisition(error)) throw error;
      retryableFailure = error;
      if (attempt + 1 < ACQUISITION_ATTEMPTS) waitForZeroTimeoutTieBreak(attempt);
    }
  }
  if (!database) {
    if (retryableFailure instanceof RetryableJournalTransition) {
      throw new KernelError(
        'AUTHORITY_JOURNAL_MODE',
        'Wallet Kernel authority lock could not enter SQLite rollback journal mode',
        { cause: retryableFailure },
      );
    }
    throw new KernelError(
      'AUTHORITY_BUSY',
      'Wallet Kernel authority is already held by another process',
      { cause: retryableFailure },
    );
  }

  let state = 'transaction-held';
  return Object.freeze({
    close() {
      if (state === 'closed' || state === 'rolling-back' || state === 'closing') return;
      if (state === 'transaction-held') {
        state = 'rolling-back';
        try {
          database.exec('ROLLBACK');
          state = 'rollback-complete';
        } catch (error) {
          state = 'transaction-held';
          throw error;
        }
      }

      state = 'closing';
      try {
        database.close();
      } catch (error) {
        state = 'rollback-complete';
        throw error;
      }
      state = 'closed';
    },
  });
}

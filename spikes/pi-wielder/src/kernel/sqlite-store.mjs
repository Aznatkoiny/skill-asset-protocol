import { DatabaseSync } from 'node:sqlite';

import { canonicalJson, exactRecord, sha256 } from './canonical.mjs';
import {
  preflightSqliteFiles,
  preparePrivateFile,
  secureNewSqliteSideFiles,
} from './secure-storage.mjs';
import { KERNEL_SCHEMA_VERSION, SCHEMA_V1_SQL } from './sqlite-schema.mjs';

const EXPOSED_PRAGMAS = Object.freeze([
  'journal_mode',
  'synchronous',
  'foreign_keys',
  'user_version',
]);
function assertSynchronousOperation(operation) {
  if (Object.getPrototypeOf(operation) !== Function.prototype) {
    throw new Error(
      'authority transactions must be synchronous; only ordinary synchronous functions are accepted',
    );
  }
}

function hasThenBoundary(value) {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') {
    return false;
  }
  let cursor = value;
  while (cursor !== null) {
    const descriptor = Object.getOwnPropertyDescriptor(cursor, 'then');
    if (descriptor) {
      return !Object.hasOwn(descriptor, 'value') || typeof descriptor.value === 'function';
    }
    cursor = Object.getPrototypeOf(cursor);
  }
  return false;
}

function assertSafeTransactionReturn(value, token, seen = new Set()) {
  if (value === token) {
    throw new Error('authority transaction token must not cross a return boundary');
  }
  if (hasThenBoundary(value)) throw new Error('authority transactions must be synchronous');
  if (value === null || (typeof value !== 'object' && typeof value !== 'function')) return;
  if (typeof value === 'function') {
    throw new Error('authority transaction return values must be inert data');
  }
  if (seen.has(value)) return;
  seen.add(value);

  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
      throw new Error('authority transaction return values must be inert data');
    }
    assertSafeTransactionReturn(descriptor.value, token, seen);
  }
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null && prototype !== Array.prototype) {
    throw new Error('authority transaction return values must be inert data');
  }
}

function rollbackWithoutMasking(db) {
  try {
    if (db?.isTransaction) db.exec('ROLLBACK');
  } catch {
    // Preserve the initialization or transaction error that caused cleanup.
  }
}

function closeWithoutMasking(db) {
  try {
    db?.close();
  } catch {
    // Preserve the initialization error that caused cleanup.
  }
}

export function openKernelStore({
  filePath,
  allowMemory = false,
  pathTrust,
  now = () => new Date().toISOString(),
}) {
  const inMemory = filePath === ':memory:';
  if (inMemory && !allowMemory) {
    throw new Error('in-memory authority requires explicit test injection');
  }

  const existing = inMemory ? null : preflightSqliteFiles(filePath, { pathTrust });
  if (!inMemory) {
    preparePrivateFile(filePath, 'Wallet Kernel database', { pathTrust });
  }

  let db;
  try {
    db = new DatabaseSync(filePath, { timeout: 5_000, readBigInts: true });
    db.exec('PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF; PRAGMA synchronous = FULL;');
    if (!inMemory) db.exec('PRAGMA journal_mode = WAL;');

    const version = Number(db.prepare('PRAGMA user_version').get().user_version);
    if (version > KERNEL_SCHEMA_VERSION) {
      throw new Error('Wallet Kernel database uses a newer schema');
    }
    if (version === 0) {
      db.exec('BEGIN IMMEDIATE');
      try {
        db.exec(SCHEMA_V1_SQL);
        db.exec(`PRAGMA user_version = ${KERNEL_SCHEMA_VERSION}`);
        db.exec('COMMIT');
      } catch (error) {
        rollbackWithoutMasking(db);
        throw error;
      }
    }

    if (!inMemory) secureNewSqliteSideFiles(filePath, existing, { pathTrust });
  } catch (error) {
    rollbackWithoutMasking(db);
    closeWithoutMasking(db);
    throw error;
  }

  const liveTransactions = new WeakSet();
  let transactionOpen = false;
  let closed = false;

  const assertOpen = () => {
    if (closed) throw new Error('Wallet Kernel store is closed');
  };

  const appendEvent = (event, txDb = db) => {
    const { entityType, entityId, eventType, data } = exactRecord(
      event,
      ['entityType', 'entityId', 'eventType', 'data'],
      [],
      'EVENT_SCHEMA',
      'event',
    );
    const previous = txDb.prepare(
      'SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1',
    ).get();
    const createdAt = now();
    const dataJson = canonicalJson(data);
    const previousHash = previous?.event_hash ?? null;
    const eventHash = sha256(canonicalJson({
      entityType,
      entityId,
      eventType,
      data,
      previousHash,
      createdAt,
    }));
    txDb.prepare(`INSERT INTO events
      (entity_type, entity_id, event_type, data_json, previous_hash, event_hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(entityType, entityId, eventType, dataJson, previousHash, eventHash, createdAt);
    return eventHash;
  };

  const within = (token, operation) => {
    assertOpen();
    if (!liveTransactions.has(token)) throw new Error('invalid authority transaction');
    if (typeof operation !== 'function') throw new TypeError('transaction operation must be a function');
    assertSynchronousOperation(operation);
    const value = operation({ db, appendEvent: (event) => appendEvent(event, db) });
    assertSafeTransactionReturn(value, token);
    return value;
  };

  const transaction = (operation) => {
    assertOpen();
    if (typeof operation !== 'function') throw new TypeError('transaction operation must be a function');
    assertSynchronousOperation(operation);
    if (transactionOpen) throw new Error('nested authority transaction is forbidden');
    transactionOpen = true;
    const token = Object.freeze(Object.create(null));
    try {
      db.exec('BEGIN IMMEDIATE');
      liveTransactions.add(token);
      const value = operation(token);
      assertSafeTransactionReturn(value, token);
      if (!inMemory) preflightSqliteFiles(filePath, { pathTrust });
      db.exec('COMMIT');
      return value;
    } catch (error) {
      rollbackWithoutMasking(db);
      throw error;
    } finally {
      liveTransactions.delete(token);
      transactionOpen = false;
    }
  };

  const mutate = (event, operation) => transaction((token) => within(token,
    ({ db: txDb, appendEvent: appendInTransaction }) => {
      if (typeof operation !== 'function') {
        throw new TypeError('mutation operation must be a function');
      }
      assertSynchronousOperation(operation);
      const value = operation({ db: txDb });
      appendInTransaction(event);
      return value;
    }));

  const events = () => {
    assertOpen();
    return db.prepare('SELECT * FROM events ORDER BY sequence').all();
  };

  const readStatement = (sql) => {
    assertOpen();
    if (typeof sql !== 'string' || !/^\s*SELECT\b/i.test(sql) || sql.includes(';')) {
      throw new Error('only one parameterized SELECT is exposed outside a transaction');
    }
    return db.prepare(sql);
  };
  const readOne = (sql, parameters = []) => readStatement(sql).get(...parameters);
  const readAll = (sql, parameters = []) => readStatement(sql).all(...parameters);

  const pragma = (name) => {
    assertOpen();
    if (!EXPOSED_PRAGMAS.includes(name)) throw new Error('PRAGMA is not exposed');
    const value = Object.values(db.prepare(`PRAGMA ${name}`).get())[0];
    return typeof value === 'bigint' ? Number(value) : value;
  };

  const verifyEventChain = () => {
    let previousHash = null;
    for (const row of events()) {
      const expected = sha256(canonicalJson({
        entityType: row.entity_type,
        entityId: row.entity_id,
        eventType: row.event_type,
        data: JSON.parse(row.data_json),
        previousHash,
        createdAt: row.created_at,
      }));
      if (row.previous_hash !== previousHash || row.event_hash !== expected) return false;
      previousHash = row.event_hash;
    }
    return true;
  };

  const close = () => {
    if (closed) return;
    if (transactionOpen) throw new Error('cannot close Wallet Kernel store during a transaction');
    db.close();
    closed = true;
  };

  return Object.freeze({
    transaction,
    within,
    mutate,
    readOne,
    readAll,
    events,
    verifyEventChain,
    pragma,
    integrityCheck: () => {
      assertOpen();
      return db.prepare('PRAGMA integrity_check').get().integrity_check;
    },
    getMetadata: (key) => {
      assertOpen();
      return db.prepare('SELECT value FROM metadata WHERE key = ?').get(key)?.value ?? null;
    },
    close,
    ...(inMemory && allowMemory ? { execForTest: (sql) => {
      assertOpen();
      return db.exec(sql);
    } } : {}),
  });
}

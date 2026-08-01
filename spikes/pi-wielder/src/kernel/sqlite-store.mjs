import { DatabaseSync } from 'node:sqlite';
import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  KernelError,
  sha256,
} from './canonical.mjs';
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
  if (utilTypes.isProxy(operation)
      || Object.getPrototypeOf(operation) !== Function.prototype) {
    throw new Error(
      'authority transactions must be synchronous; only ordinary synchronous functions are accepted',
    );
  }
}

function assertScopedSql(sql) {
  if (typeof sql !== 'string'
      || sql.includes(';')
      || !/^\s*(?:SELECT|INSERT|UPDATE|DELETE)\b/i.test(sql)) {
    throw new Error(
      'only one SELECT, INSERT, UPDATE, or DELETE statement is exposed inside a transaction',
    );
  }
}

function hasThenBoundary(value) {
  if ((typeof value !== 'object' || value === null) && typeof value !== 'function') {
    return false;
  }
  let cursor = value;
  while (cursor !== null) {
    if (utilTypes.isProxy(cursor)) {
      throw new Error('authority transaction return values must not contain a proxy');
    }
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
  if (value !== null
      && (typeof value === 'object' || typeof value === 'function')
      && utilTypes.isProxy(value)) {
    throw new Error('authority transaction return values must not contain a proxy');
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
    return true;
  } catch {
    // Preserve the initialization error that caused cleanup.
    return false;
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
  let sqliteFiles;
  let failedSqliteProof;
  let initializationDatabaseClosed = false;
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

    if (!inMemory) {
      sqliteFiles = secureNewSqliteSideFiles(filePath, existing, {
        pathTrust,
        onAcquisitionFailure: (proof) => {
          failedSqliteProof = proof;
          rollbackWithoutMasking(db);
          initializationDatabaseClosed = closeWithoutMasking(db);
          if (initializationDatabaseClosed) {
            try {
              proof.close();
              failedSqliteProof = undefined;
            } catch {}
          }
        },
      });
    }
  } catch (error) {
    if (!initializationDatabaseClosed) {
      rollbackWithoutMasking(db);
      initializationDatabaseClosed = closeWithoutMasking(db);
    }
    if (initializationDatabaseClosed) {
      try { failedSqliteProof?.close(); } catch {}
      try { sqliteFiles?.close(); } catch {}
    }
    throw error;
  }

  const liveTransactions = new WeakSet();
  let transactionOpen = false;
  let databaseClosed = false;
  let closed = false;

  const assertOpen = () => {
    if (databaseClosed || closed) throw new Error('Wallet Kernel store is closed');
  };

  const assertLiveTransaction = (token) => {
    if (!liveTransactions.has(token)) throw new Error('invalid authority transaction');
    assertOpen();
  };

  const frozenCapability = (fields) => {
    const capability = Object.create(null);
    for (const [name, value] of fields) {
      Object.defineProperty(capability, name, {
        configurable: false,
        enumerable: true,
        value: Object.freeze(value),
        writable: false,
      });
    }
    return Object.freeze(capability);
  };

  const statementCapability = (token, statement) => frozenCapability([
    ['run', (...parameters) => {
      assertLiveTransaction(token);
      return statement.run(...parameters);
    }],
    ['get', (...parameters) => {
      assertLiveTransaction(token);
      return statement.get(...parameters);
    }],
    ['all', (...parameters) => {
      assertLiveTransaction(token);
      return statement.all(...parameters);
    }],
  ]);

  const databaseCapability = (token) => frozenCapability([
    ['prepare', (sql) => {
      assertLiveTransaction(token);
      assertScopedSql(sql);
      return statementCapability(token, db.prepare(sql));
    }],
  ]);

  const appendEvent = (event, txDb = db) => {
    const normalized = exactRecord(
      event,
      ['entityType', 'entityId', 'eventType', 'data'],
      [],
      'EVENT_SCHEMA',
      'event',
    );
    const entityType = canonicalToken(normalized.entityType, 'event entity type');
    const entityId = canonicalToken(normalized.entityId, 'event entity ID');
    const eventType = canonicalToken(normalized.eventType, 'event type');
    const { data } = normalized;
    if (!data || typeof data !== 'object' || Array.isArray(data)
        || Object.getPrototypeOf(data) !== Object.prototype) {
      throw new KernelError('EVENT_SCHEMA', 'event data must be one plain object');
    }
    const createdAt = canonicalTimestamp(now(), 'event createdAt');
    const dataJson = canonicalJson(data);
    const previous = txDb.prepare(
      'SELECT event_hash FROM events ORDER BY sequence DESC LIMIT 1',
    ).get();
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
    assertLiveTransaction(token);
    if (typeof operation !== 'function') throw new TypeError('transaction operation must be a function');
    assertSynchronousOperation(operation);
    const scopedDatabase = databaseCapability(token);
    const scope = frozenCapability([
      ['db', scopedDatabase],
      ['appendEvent', (event) => {
        assertLiveTransaction(token);
        return appendEvent(event, db);
      }],
    ]);
    const value = operation(scope);
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
      if (!inMemory) sqliteFiles.revalidate();
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
    if (!databaseClosed) {
      db.close();
      databaseClosed = true;
    }
    // POSIX may drop SQLite's process-associated locks when any proof fd for
    // the same inode closes, so the database always closes first.
    sqliteFiles?.close();
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

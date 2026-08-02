import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createApprovalQueue } from '../src/kernel/approval-queue.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { createBudgetLedger } from '../src/kernel/budget-ledger.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { loadOrCreateReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../src/kernel/recovery.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { KERNEL_FAULT_POINTS } from '../src/kernel/wallet-kernel.mjs';

const NOW = '2026-08-01T12:00:00.000Z';
const SELLER = 'https://seller.example';
const CURRENT_UID = process.getuid();
const WORKER_PATH = fileURLToPath(new URL('./fixtures/kernel-crash-worker.mjs', import.meta.url));
const ABORT_TIMEOUT_MS = 15_000;
const SIGNED_BYTE_POINTS = new Set([
  'after_signed_payment_commit',
  'after_retry_claim_commit',
  'after_paid_response',
  'after_settlement_commit',
  'before_terminal_receipt_commit',
]);
const AMBIGUOUS_POINTS = new Set([
  'after_signing_claim_commit',
  'after_signer_return',
  'after_signed_payment_commit',
  'after_retry_claim_commit',
  'after_paid_response',
]);
const SETTLED_POINTS = new Set([
  'after_settlement_commit',
  'before_terminal_receipt_commit',
]);

const EXPECTED = Object.freeze({
  after_intent_commit: Object.freeze({
    before: ['captured', null, null, null, 0],
    after: ['terminal', null, null, 'upstream_failed', false],
    signer: [0, 0],
    transport: [0, 0, 0],
    repairedIntentCount: 1,
  }),
  after_challenge_commit: Object.freeze({
    before: ['challenged', null, null, null, 0],
    after: ['terminal', null, null, 'payment_failed', false],
    signer: [1, 0],
    transport: [1, 0, 0],
    repairedIntentCount: 1,
  }),
  after_reservation_commit: Object.freeze({
    before: ['reserved', 'reserved', 'reserved', null, 1],
    after: ['terminal', 'released', 'rejected', 'payment_failed', false],
    signer: [1, 0],
    transport: [1, 0, 0],
    repairedIntentCount: 1,
  }),
  after_signing_claim_commit: Object.freeze({
    before: ['signing', 'reserved', 'signing', null, 1],
    after: ['unresolved', 'unresolved', 'unresolved', 'payment_unresolved', true],
    signer: [1, 0],
    transport: [1, 0, 0],
    repairedIntentCount: 1,
  }),
  after_signer_return: Object.freeze({
    before: ['signing', 'reserved', 'signing', null, 1],
    after: ['unresolved', 'unresolved', 'unresolved', 'payment_unresolved', true],
    signer: [1, 1],
    transport: [1, 0, 0],
    repairedIntentCount: 1,
  }),
  after_signed_payment_commit: Object.freeze({
    before: ['signed', 'reserved', 'signed', null, 1],
    after: ['unresolved', 'unresolved', 'unresolved', 'payment_unresolved', true],
    signer: [1, 1],
    transport: [1, 1, 0],
    repairedIntentCount: 1,
  }),
  after_retry_claim_commit: Object.freeze({
    before: ['retrying', 'reserved', 'retrying', null, 1],
    after: ['unresolved', 'unresolved', 'unresolved', 'payment_unresolved', true],
    signer: [1, 1],
    transport: [1, 1, 0],
    repairedIntentCount: 1,
  }),
  after_paid_response: Object.freeze({
    before: ['retrying', 'reserved', 'retrying', null, 1],
    after: ['unresolved', 'unresolved', 'unresolved', 'payment_unresolved', true],
    signer: [1, 1],
    transport: [1, 1, 1],
    repairedIntentCount: 1,
  }),
  after_settlement_commit: Object.freeze({
    before: ['terminal', 'committed', 'settled', 'completed', 1],
    after: ['terminal', 'committed', 'settled', 'completed', false],
    signer: [1, 1],
    transport: [1, 1, 1],
    repairedIntentCount: 0,
  }),
  before_terminal_receipt_commit: Object.freeze({
    before: ['terminal', 'committed', 'settled', 'completed', 1],
    after: ['terminal', 'committed', 'settled', 'completed', false],
    signer: [1, 1],
    transport: [1, 1, 1],
    repairedIntentCount: 0,
  }),
});

function writeOwnerOnlyJson(filePath, value) {
  fs.writeFileSync(filePath, `${JSON.stringify(value)}\n`, {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  });
}

function readOwnerOnlyJson(filePath) {
  const stat = fs.statSync(filePath);
  assert.equal(stat.isFile(), true, `${filePath} must be a regular file`);
  assert.equal(stat.uid, CURRENT_UID, `${filePath} must retain its owner`);
  assert.equal(stat.mode & 0o777, 0o600, `${filePath} must remain owner-only`);
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function createFixture(t, faultPoint) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), `wallet-kernel-restart-${faultPoint}-`));
  fs.chmodSync(directory, 0o700);
  const fixture = Object.freeze({
    databasePath: path.join(directory, 'kernel.sqlite'),
    directory,
    receiptKeyPath: path.join(directory, 'receipt-key.pem'),
    signerCountPath: path.join(directory, 'signer-count.json'),
    transportCountPath: path.join(directory, 'transport-count.json'),
  });
  writeOwnerOnlyJson(fixture.signerCountPath, {
    walletIdentity: 0,
    signX402Exact: 0,
  });
  writeOwnerOnlyJson(fixture.transportCountPath, {
    probe: 0,
    encodePayment: 0,
    retryPaid: 0,
  });
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return fixture;
}

function pathTrust(directory) {
  return Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: CURRENT_UID,
    agentUid: CURRENT_UID,
  });
}

function startWorker(t, fixture, faultPoint) {
  const child = fork(WORKER_PATH, [JSON.stringify({
    ...fixture,
    faultPoint,
  })], {
    serialization: 'json',
    silent: true,
  });
  const messages = [];
  const messageWaiters = [];
  let exitResult = null;
  let processError = null;
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    stderr = `${stderr}${chunk}`.slice(-16_384);
  });
  child.on('message', (message) => {
    if (message?.type === 'error') {
      const error = new Error(`crash worker setup failed: ${JSON.stringify(message)}`);
      processError = error;
      for (const waiter of messageWaiters.splice(0)) {
        clearTimeout(waiter.timer);
        waiter.reject(error);
      }
      return;
    }
    const index = messageWaiters.findIndex((waiter) => waiter.predicate(message));
    if (index === -1) messages.push(message);
    else {
      const [waiter] = messageWaiters.splice(index, 1);
      clearTimeout(waiter.timer);
      waiter.resolve(message);
    }
  });
  child.on('error', (error) => {
    processError = error;
    for (const waiter of messageWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(error);
    }
  });
  child.on('exit', (code, signal) => {
    exitResult = { code, signal };
    for (const waiter of messageWaiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(new Error(
        `crash worker exited before the expected message: ${JSON.stringify(exitResult)}; stderr=${stderr}`,
      ));
    }
  });
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });

  return Object.freeze({
    child,
    get stderr() { return stderr; },
    next(predicate, timeoutMilliseconds = ABORT_TIMEOUT_MS) {
      const index = messages.findIndex(predicate);
      if (index !== -1) return Promise.resolve(messages.splice(index, 1)[0]);
      if (processError) return Promise.reject(processError);
      if (exitResult) {
        return Promise.reject(new Error(
          `crash worker already exited: ${JSON.stringify(exitResult)}; stderr=${stderr}`,
        ));
      }
      return new Promise((resolve, reject) => {
        const waiter = { predicate, resolve, reject };
        waiter.timer = setTimeout(() => {
          const waiterIndex = messageWaiters.indexOf(waiter);
          if (waiterIndex !== -1) messageWaiters.splice(waiterIndex, 1);
          reject(new Error(`timed out waiting for crash-worker readiness; stderr=${stderr}`));
        }, timeoutMilliseconds);
        messageWaiters.push(waiter);
      });
    },
    waitForExit(timeoutMilliseconds = ABORT_TIMEOUT_MS) {
      if (exitResult) return Promise.resolve(exitResult);
      if (processError) return Promise.reject(processError);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          reject(new Error(`timed out waiting for crash-worker abort; stderr=${stderr}`));
        }, timeoutMilliseconds);
        child.once('error', (error) => {
          clearTimeout(timer);
          reject(error);
        });
        child.once('exit', (code, signal) => {
          clearTimeout(timer);
          resolve({ code, signal });
        });
      });
    },
  });
}

function readState(store) {
  return Object.freeze({
    attempt: store.readOne('SELECT * FROM payment_attempts ORDER BY rowid'),
    budget: store.readOne('SELECT * FROM budget_reservations ORDER BY rowid'),
    decision: store.readOne('SELECT * FROM policy_decisions ORDER BY rowid'),
    execution: store.readOne('SELECT * FROM execution_outcomes ORDER BY rowid'),
    intent: store.readOne('SELECT * FROM spend_intents ORDER BY rowid'),
    outcome: store.readOne('SELECT * FROM buyer_outcomes ORDER BY rowid'),
    receiptCount: Number(store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count),
    reservationCount: Number(
      store.readOne('SELECT COUNT(*) AS count FROM budget_reservations').count,
    ),
    session: store.readOne('SELECT * FROM spend_sessions ORDER BY rowid'),
  });
}

function signedBytes(state) {
  return Object.freeze({
    paymentHash: state.attempt?.payment_hash ?? null,
    paymentHeader: state.attempt?.payment_header ?? null,
    paymentPayloadJson: state.attempt?.payment_payload_json ?? null,
  });
}

function transactionIds(store) {
  return store.readAll(`SELECT transaction_id AS transaction_id
    FROM payment_attempts WHERE transaction_id IS NOT NULL
    UNION ALL
    SELECT transaction_id AS transaction_id
    FROM payment_reconciliation_candidates
    UNION ALL
    SELECT refund_transaction_id AS transaction_id
    FROM refunds WHERE refund_transaction_id IS NOT NULL`)
    .map((row) => row.transaction_id);
}

function assertEveryReceiptVerifies(store, receipts) {
  for (const row of store.readAll('SELECT * FROM signed_receipts ORDER BY intent_id, revision')) {
    assert.equal(receipts.verify({
      id: row.id,
      intentId: row.intent_id,
      revision: Number(row.revision),
      receipt: JSON.parse(row.receipt_json),
      receiptHash: row.receipt_hash,
      signature: row.signature,
      algorithm: row.algorithm,
      keyId: row.key_id,
      supersedesReceiptHash: row.supersedes_receipt_hash,
      createdAt: row.created_at,
    }), true);
  }
}

function authorityFingerprint(store) {
  const rows = [
    'spend_intents',
    'budget_reservations',
    'payment_attempts',
    'execution_outcomes',
    'execution_resolutions',
    'buyer_outcomes',
    'signed_receipts',
    'events',
  ].map((table) => [table, store.readAll(`SELECT * FROM ${table} ORDER BY rowid`)]);
  return JSON.stringify(rows, (_key, value) => (
    typeof value === 'bigint' ? value.toString(10) : value
  ));
}

test('fresh-process recovery classifies every Wallet Kernel abort boundary exactly once', async (t) => {
  assert.deepEqual(Object.keys(EXPECTED), [...KERNEL_FAULT_POINTS]);

  for (const faultPoint of KERNEL_FAULT_POINTS) {
    await t.test(faultPoint, async (st) => {
      const expected = EXPECTED[faultPoint];
      const fixture = createFixture(st, faultPoint);
      const trust = pathTrust(fixture.directory);
      const worker = startWorker(st, fixture, faultPoint);
      assert.deepEqual(
        await worker.next((message) => message?.type === 'ready'),
        { type: 'ready', faultPoint },
      );

      assert.throws(
        () => acquireAuthorityLock({
          databasePath: fixture.databasePath,
          role: 'prelaunch',
          pathTrust: trust,
        }),
        (error) => error?.code === 'AUTHORITY_BUSY',
        'the worker must hold the cross-process authority lease before fault injection',
      );

      worker.child.send({ type: 'run' });
      const exit = await worker.waitForExit();
      assert.deepEqual(exit, { code: null, signal: 'SIGABRT' }, worker.stderr);

      const countsBeforeRecovery = Object.freeze({
        signer: readOwnerOnlyJson(fixture.signerCountPath),
        transport: readOwnerOnlyJson(fixture.transportCountPath),
      });
      assert.deepEqual(
        [countsBeforeRecovery.signer.walletIdentity, countsBeforeRecovery.signer.signX402Exact],
        expected.signer,
      );
      assert.deepEqual([
        countsBeforeRecovery.transport.probe,
        countsBeforeRecovery.transport.encodePayment,
        countsBeforeRecovery.transport.retryPaid,
      ], expected.transport);

      const successor = acquireAuthorityLock({
        databasePath: fixture.databasePath,
        role: 'prelaunch',
        pathTrust: trust,
      });
      let store;
      try {
        const signer = loadOrCreateReceiptSigner(fixture.receiptKeyPath, { pathTrust: trust });
        store = openKernelStore({
          filePath: fixture.databasePath,
          pathTrust: trust,
          now: () => NOW,
        });
        const ids = (() => {
          let sequence = 0;
          return (kind) => `restart-${kind}-${++sequence}`;
        })();
        const intents = createIntentRepository({
          store,
          idFactory: ids,
          now: () => NOW,
          routeMetadata: Object.freeze({
            'paid-infer': Object.freeze({
              description: 'offline fixture',
              mimeType: 'application/json',
            }),
          }),
        });
        const budgets = createBudgetLedger({ store, now: () => NOW });
        const approvals = createApprovalQueue({ store, idFactory: ids, now: () => NOW });
        const receipts = createSignedReceiptRepository({
          store,
          signer,
          idFactory: ids,
          now: () => NOW,
        });

        const before = readState(store);
        assert.deepEqual([
          before.intent.state,
          before.budget?.state ?? null,
          before.attempt?.state ?? null,
          before.outcome?.status ?? null,
          before.reservationCount,
        ], expected.before, 'abort must expose the exact Task 10 durable state');
        assert.equal(before.decision?.decision ?? null,
          faultPoint === 'after_intent_commit' ? null : 'allow');
        assert.equal(before.intent.challenge_hash === null,
          faultPoint === 'after_intent_commit');
        assert.equal(before.receiptCount, 0, 'no abort boundary may expose a partial receipt');
        assert.equal(store.verifyEventChain(), true);
        const signedMaterialBeforeRecovery = signedBytes(before);
        assert.equal(
          signedMaterialBeforeRecovery.paymentPayloadJson !== null,
          SIGNED_BYTE_POINTS.has(faultPoint),
          'only post-signature-persistence boundaries may expose signed bytes',
        );
        const transactionIdsBefore = transactionIds(store);
        assert.equal(transactionIdsBefore.length, new Set(transactionIdsBefore).size);
        assert.equal(
          transactionIdsBefore.length,
          faultPoint === 'after_settlement_commit'
            || faultPoint === 'before_terminal_receipt_commit' ? 1 : 0,
        );

        const report = recoverKernelAuthority({
          store,
          intents,
          budgets,
          approvals,
          receipts,
          now: () => NOW,
        });
        const after = readState(store);
        const budgetSnapshot = budgets.snapshot({
          sessionId: after.session.id,
          sellerOrigin: SELLER,
          at: NOW,
        });
        assert.deepEqual([
          after.intent.state,
          after.budget?.state ?? null,
          after.attempt?.state ?? null,
          after.outcome?.status ?? null,
          budgetSnapshot.walletBlocked,
        ], expected.after, 'recovery must produce the one planned classification');
        assert.equal(after.outcome.reason_code,
          SETTLED_POINTS.has(faultPoint)
            ? 'PAYMENT_SETTLED'
            : AMBIGUOUS_POINTS.has(faultPoint)
              ? 'RECOVERY_PAYMENT_AMBIGUOUS'
              : 'RECOVERY_ABANDONED_UNSIGNED');
        assert.equal(after.execution?.state ?? null,
          SETTLED_POINTS.has(faultPoint) ? 'succeeded' : null);
        assert.equal(after.reservationCount, expected.before[4]);
        if (after.budget) {
          const conserved = BigInt(after.budget.reserved_atomic)
            + BigInt(after.budget.committed_atomic)
            + BigInt(after.budget.released_atomic)
            + BigInt(after.budget.unresolved_atomic);
          assert.equal(conserved, 50_000n);
        }
        assert.equal(after.receiptCount, 1);
        assert.equal(report.ready, true);
        assert.equal(report.repairedIntentCount, expected.repairedIntentCount);
        assert.equal(report.repairedReceiptCount, 1);
        assert.equal(report.unresolvedIntentCount, expected.after[4] ? 1 : 0);
        assert.deepEqual(signedBytes(after), signedMaterialBeforeRecovery,
          'recovery must never alter persisted payment bytes');

        const transactionIdsAfter = transactionIds(store);
        assert.deepEqual(transactionIdsAfter, transactionIdsBefore);
        assert.equal(transactionIdsAfter.length, new Set(transactionIdsAfter).size,
          'one transaction ID may commit at most once');
        assert.equal(store.verifyEventChain(), true);
        assert.equal(receipts.assertParity(), true);
        assertEveryReceiptVerifies(store, receipts);

        const countsAfterRecovery = Object.freeze({
          signer: readOwnerOnlyJson(fixture.signerCountPath),
          transport: readOwnerOnlyJson(fixture.transportCountPath),
        });
        assert.deepEqual(countsAfterRecovery, countsBeforeRecovery,
          'startup recovery must not sign or blindly retry paid transport');

        const stableFingerprint = authorityFingerprint(store);
        const second = recoverKernelAuthority({
          store,
          intents,
          budgets,
          approvals,
          receipts,
          now: () => NOW,
        });
        assert.equal(second.ready, true);
        assert.equal(second.repairedIntentCount, 0);
        assert.equal(second.repairedReceiptCount, 0);
        assert.equal(authorityFingerprint(store), stableFingerprint,
          'a second startup audit must be mutation-free');
        assert.deepEqual({
          signer: readOwnerOnlyJson(fixture.signerCountPath),
          transport: readOwnerOnlyJson(fixture.transportCountPath),
        }, countsBeforeRecovery);
      } finally {
        store?.close();
        successor.close();
      }
    });
  }
});

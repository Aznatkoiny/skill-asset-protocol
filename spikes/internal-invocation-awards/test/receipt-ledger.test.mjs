import assert from 'node:assert/strict';
import test from 'node:test';

import {
  appendSignedReceipt,
  createReceiptLedgerState,
  receiptSequenceScope,
} from '../src/receipt-ledger.mjs';

function receipt(receiptId, sequence, creatorId = 'sam') {
  return Object.freeze({
    receiptId,
    sequence,
    receiptSequenceScope: receiptSequenceScope({
      employerId: 'megacorp', creatorId, currency: 'USD', atomicScale: 6,
    }),
    signature: 'signed-by-test-capability',
  });
}

test('receipt sequence is scoped by employer, Creator, currency, and scale', () => {
  assert.notEqual(
    receiptSequenceScope({ employerId: 'megacorp', creatorId: 'sam', currency: 'USD', atomicScale: 6 }),
    receiptSequenceScope({ employerId: 'megacorp', creatorId: 'kim', currency: 'USD', atomicScale: 6 }),
  );
  assert.equal(
    receiptSequenceScope({ employerId: 'megacorp', creatorId: 'sam', currency: 'USD', atomicScale: 6 }),
    '["megacorp","sam","USD",6]',
  );
});

test('atomic receipt append rejects duplicate IDs, sequence conflicts, and gaps', () => {
  const empty = createReceiptLedgerState();
  const first = appendSignedReceipt(empty, {
    signedReceipt: receipt('receipt-1', 1),
    hash: `sha256:${'1'.repeat(64)}`,
  });
  assert.equal(first.receipts['receipt-1'].sequence, 1);
  assert.equal(first.nextReceiptSequences['["megacorp","sam","USD",6]'], 2);
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: receipt('receipt-1', 2), hash: `sha256:${'2'.repeat(64)}`,
  }), /receipt ID already committed/);
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: receipt('receipt-2', 1), hash: `sha256:${'2'.repeat(64)}`,
  }), /receipt sequence already committed/);
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: receipt('receipt-2', 3), hash: `sha256:${'2'.repeat(64)}`,
  }), /expected receipt sequence 2/);
});

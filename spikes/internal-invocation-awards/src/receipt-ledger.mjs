import { cloneFrozen, deepFreeze } from './schema.mjs';

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be non-empty`);
}

export function receiptSequenceScope({ employerId, creatorId, currency, atomicScale }) {
  for (const [value, label] of [
    [employerId, 'receipt employerId'],
    [creatorId, 'receipt creatorId'],
    [currency, 'receipt currency'],
  ]) requireString(value, label);
  if (!Number.isSafeInteger(atomicScale) || atomicScale < 0 || atomicScale > 18) {
    throw new Error('receipt atomicScale must be an integer from 0 through 18');
  }
  return JSON.stringify([employerId, creatorId, currency, atomicScale]);
}

export function createReceiptLedgerState() {
  return deepFreeze({
    receipts: {},
    receiptHashes: {},
    receiptSequenceIndex: {},
    nextReceiptSequences: {},
  });
}

export function appendSignedReceipt(state, { signedReceipt, hash }) {
  if (!state || typeof state !== 'object') throw new Error('receipt ledger state is required');
  for (const key of [
    'receipts', 'receiptHashes', 'receiptSequenceIndex', 'nextReceiptSequences',
  ]) {
    if (!state[key] || typeof state[key] !== 'object' || Array.isArray(state[key])) {
      throw new Error(`receipt ledger ${key} must be an object`);
    }
  }
  if (!signedReceipt || typeof signedReceipt !== 'object' || Array.isArray(signedReceipt)) {
    throw new Error('signed receipt must be an object');
  }
  requireString(signedReceipt.receiptId, 'receiptId');
  requireString(signedReceipt.receiptSequenceScope, 'receiptSequenceScope');
  if (!Number.isSafeInteger(signedReceipt.sequence) || signedReceipt.sequence < 1) {
    throw new Error('receipt sequence must be a positive integer');
  }
  if (typeof hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(hash)) {
    throw new Error('receipt hash must be a lowercase SHA-256 hash');
  }
  if (Object.hasOwn(state.receipts, signedReceipt.receiptId)) {
    throw new Error('receipt ID already committed');
  }
  if (Object.hasOwn(state.receiptHashes, hash)) {
    throw new Error('receipt hash already committed');
  }
  const indexKey = JSON.stringify([signedReceipt.receiptSequenceScope, signedReceipt.sequence]);
  if (Object.hasOwn(state.receiptSequenceIndex, indexKey)) {
    throw new Error('receipt sequence already committed for scope');
  }
  const expected = state.nextReceiptSequences[signedReceipt.receiptSequenceScope] ?? 1;
  if (signedReceipt.sequence !== expected) {
    throw new Error(`expected receipt sequence ${expected}, received ${signedReceipt.sequence}`);
  }
  return deepFreeze({
    receipts: { ...state.receipts, [signedReceipt.receiptId]: cloneFrozen(signedReceipt) },
    receiptHashes: { ...state.receiptHashes, [signedReceipt.receiptId]: hash },
    receiptSequenceIndex: {
      ...state.receiptSequenceIndex,
      [indexKey]: signedReceipt.receiptId,
    },
    nextReceiptSequences: {
      ...state.nextReceiptSequences,
      [signedReceipt.receiptSequenceScope]: expected + 1,
    },
  });
}

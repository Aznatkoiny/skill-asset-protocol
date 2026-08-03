import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import test from 'node:test';

import {
  appendSignedReceipt,
  createReceiptLedgerState,
  receiptSequenceScope,
} from '../src/receipt-ledger.mjs';
import {
  buildInvocationReceipt,
  receiptHash,
  signReceipt,
} from '../src/statements.mjs';

const NOW = '2026-07-17T00:01:00.000Z';

function cancelledReceipt(privateKey, sequence, suffix, creatorId = 'sam') {
  const invocationId = `inv-${suffix}`;
  const reservationId = `res-${suffix}`;
  const scope = receiptSequenceScope({
    employerId: 'megacorp', creatorId, currency: 'USD', atomicScale: 6,
  });
  const reservation = {
    reservationId,
    quote: { invocationId },
    state: 'released',
    reservedAtomic: '1',
  };
  const invocation = {
    invocationId,
    reservationId,
    beneficiaryId: 'megacorp',
    creatorId,
    skillId: 'ledger-recon',
    skillVersionHash: `sha256:${'1'.repeat(64)}`,
    skillRegistrationId: `registration-${suffix}`,
    initiatingPrincipalId: 'jordan',
    principalAttestationId: `attestation-${suffix}`,
    principalAttestationHash: `sha256:${'2'.repeat(64)}`,
    policyId: 'policy-megacorp-ledger-recon',
    policyVersion: 1,
    policyHash: `sha256:${'3'.repeat(64)}`,
    period: '2026-07',
    currency: 'USD',
    atomicScale: 6,
    state: 'cancelled',
    executionAttemptId: null,
    releasedAtomic: '1',
    heldReservationAtomic: '0',
    executionCostStatus: null,
    executionCostAtomic: null,
    outputHash: null,
    failureClass: null,
    unresolvedReason: null,
    protocolFeeAtomic: '0',
    refundReserveAtomic: '0',
    invocationAwardAtomic: '0',
    externalRoyaltyCreditsAtomic: '0',
    employerSelfCreditAtomic: '0',
    journalEntries: [],
    finalizedAt: NOW,
    receiptSequence: sequence,
    receiptSequenceScope: scope,
  };
  return signReceipt(buildInvocationReceipt({
    invocation,
    reservation,
    award: null,
    employerId: 'megacorp',
    receiptSignerId: 'receipt-signer',
  }), privateKey);
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
  const { privateKey } = generateKeyPairSync('ed25519');
  const empty = createReceiptLedgerState();
  const receipt1 = cancelledReceipt(privateKey, 1, '1');
  const hash1 = receiptHash(receipt1);
  const first = appendSignedReceipt(empty, {
    signedReceipt: receipt1,
    hash: hash1,
  });
  assert.equal(first.receipts['receipt-inv-1'].sequence, 1);
  assert.equal(first.nextReceiptSequences['["megacorp","sam","USD",6]'], 2);
  const duplicateId = cancelledReceipt(privateKey, 2, '1');
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: duplicateId, hash: receiptHash(duplicateId),
  }), /receipt ID already committed/);
  const sequenceConflict = cancelledReceipt(privateKey, 1, '2');
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: sequenceConflict, hash: receiptHash(sequenceConflict),
  }), /receipt sequence already committed/);
  const gap = cancelledReceipt(privateKey, 3, '2');
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: gap, hash: receiptHash(gap),
  }), /expected receipt sequence 2/);

  const receipt2 = cancelledReceipt(privateKey, 2, '2');
  const hash2 = receiptHash(receipt2);
  assert.throws(() => appendSignedReceipt(first, {
    signedReceipt: receipt2, hash: hash1,
  }), /supplied receipt hash does not match signed receipt/);

  const seededDuplicateHash = Object.freeze({
    ...first,
    receiptHashes: Object.freeze({ 'receipt-inv-1': hash2 }),
  });
  assert.throws(() => appendSignedReceipt(seededDuplicateHash, {
    signedReceipt: receipt2, hash: hash2,
  }), /receipt hash already committed/);
});

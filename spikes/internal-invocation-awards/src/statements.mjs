import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

import {
  cloneFrozen,
  deepFreeze,
  fromAtomic,
  parseUtc,
  requireExactKeys,
  toAtomic,
} from './schema.mjs';

const JOURNAL_ENTRY_KEYS = [
  'category', 'debitAccountId', 'creditAccountId', 'amountAtomic',
];
const RECEIPT_KEYS = [
  'schemaVersion', 'receiptId', 'sequence', 'receiptType', 'invocationId',
  'reservationId', 'employerId', 'creatorId', 'skillId', 'skillVersionHash',
  'policyId', 'policyVersion', 'period', 'currency', 'atomicScale',
  'invocationState', 'reservationState', 'executionAttemptId', 'reservedAtomic',
  'consumedAtomic', 'releasedAtomic', 'heldReservationAtomic',
  'executionCostStatus', 'executionCostAtomic', 'outputHash', 'failureClass',
  'unresolvedReason', 'protocolFeeAtomic', 'refundReserveAtomic',
  'invocationAwardAtomic', 'awardState', 'externalSettlementHash',
  'externalRoyaltyCreditsAtomic', 'employerSelfCreditAtomic', 'journalEntries',
  'occurredAt', 'receiptSignerId',
];
const SIGNED_RECEIPT_KEYS = [...RECEIPT_KEYS, 'signature'];
const PAYMENT_KEYS = ['paymentId', 'amountAtomic', 'paidAt', 'railReference'];
const ADVANCE_KEYS = ['advanceId', 'receiptHash', 'amountAtomic', 'advancedAt'];
const REVERSAL_KEYS = [
  'reversalId', 'receiptHash', 'amountAtomic', 'balanceEffect', 'reason', 'occurredAt',
];
const STATEMENT_KEYS = [
  'schemaVersion', 'statementId', 'employerId', 'creatorId', 'period', 'currency',
  'atomicScale', 'openingPayableAtomic', 'firstReceiptSequence',
  'lastReceiptSequence', 'receiptHashes', 'receiptMerkleRoot',
  'reservationTotalAtomic', 'releaseTotalAtomic', 'chargeTotalAtomic',
  'earnedAwardTotalAtomic', 'payableAdvances', 'payableAdvanceTotalAtomic',
  'reversals', 'reversalTotalAtomic', 'payableReversalTotalAtomic', 'payments',
  'paymentTotalAtomic', 'closingPayableAtomic', 'statementSignerId',
];
const SIGNED_STATEMENT_KEYS = [...STATEMENT_KEYS, 'signature'];
const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

function ordered(source, keys) {
  return Object.fromEntries(keys.map((key) => [key, source[key]]));
}

function canonicalBytes(source, keys) {
  return new TextEncoder().encode(JSON.stringify(ordered(source, keys)));
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be non-empty`);
}

function decodeSignature(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error(`${label} signature must be canonical base64`);
  }
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) {
    throw new Error(`${label} signature must be a 64-byte Ed25519 signature`);
  }
  return decoded;
}

function trustedKey(map, keyId, label) {
  if (map === null || typeof map !== 'object' || Array.isArray(map)) {
    throw new Error(`${label} trust map must be an object`);
  }
  const key = map[keyId];
  if (typeof key !== 'string' || key.length === 0) {
    throw new Error(`${label} key ID ${keyId} is not trusted`);
  }
  return key;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

function taggedHash(bytes) {
  return `sha256:${sha256(bytes).toString('hex')}`;
}

function validateJournalEntries(entries) {
  if (!Array.isArray(entries)) throw new Error('receipt journalEntries must be an array');
  return entries.map((entry, index) => {
    requireExactKeys(entry, JOURNAL_ENTRY_KEYS, `journal entry ${index}`);
    for (const key of ['category', 'debitAccountId', 'creditAccountId']) {
      requireString(entry[key], `journal entry ${key}`);
    }
    toAtomic(entry.amountAtomic);
    if (entry.debitAccountId !== 'employer:invocation-gross') {
      throw new Error('internal journal entry must debit employer:invocation-gross');
    }
    return cloneFrozen(entry);
  });
}

function validateReceiptPayload(input) {
  requireExactKeys(input, RECEIPT_KEYS, 'receipt');
  if (input.schemaVersion !== 1) throw new Error('receipt schemaVersion must equal 1');
  for (const key of [
    'receiptId', 'receiptType', 'invocationId', 'reservationId', 'employerId',
    'creatorId', 'skillId', 'policyId', 'period', 'currency', 'invocationState',
    'reservationState', 'receiptSignerId',
  ]) requireString(input[key], key);
  if (!Number.isSafeInteger(input.sequence) || input.sequence < 1) {
    throw new Error('receipt sequence must be a positive integer');
  }
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('receipt policyVersion must be a positive integer');
  }
  if (!Number.isSafeInteger(input.atomicScale) || input.atomicScale < 0 || input.atomicScale > 18) {
    throw new Error('receipt atomicScale must be an integer from 0 through 18');
  }
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(input.period)) throw new Error('receipt period must be YYYY-MM');
  if (!SHA256_PATTERN.test(input.skillVersionHash)) throw new Error('receipt Skill hash is invalid');
  parseUtc(input.occurredAt, 'receipt occurredAt');
  for (const key of [
    'reservedAtomic', 'consumedAtomic', 'releasedAtomic', 'heldReservationAtomic',
    'protocolFeeAtomic', 'refundReserveAtomic', 'invocationAwardAtomic',
    'externalRoyaltyCreditsAtomic', 'employerSelfCreditAtomic',
  ]) toAtomic(input[key]);
  if (input.executionCostAtomic !== null) toAtomic(input.executionCostAtomic);
  if (input.externalSettlementHash !== null) {
    throw new Error('internal Invocation receipt cannot contain an external settlement hash');
  }
  if (input.externalRoyaltyCreditsAtomic !== '0' || input.employerSelfCreditAtomic !== '0') {
    throw new Error('internal Invocation receipt cannot create external or employer-self credits');
  }
  const journalEntries = validateJournalEntries(input.journalEntries);
  const reserved = toAtomic(input.reservedAtomic);
  const consumed = toAtomic(input.consumedAtomic);
  const released = toAtomic(input.releasedAtomic);
  const held = toAtomic(input.heldReservationAtomic);
  if (reserved !== consumed + released + held) {
    throw new Error('receipt reserved amount must equal consumed, released, and held amounts');
  }

  if (input.invocationState === 'succeeded') {
    if (input.receiptType !== 'internal_invocation_finalized'
        || input.reservationState !== 'consumed'
        || input.executionCostStatus !== 'known'
        || input.executionCostAtomic === null
        || !SHA256_PATTERN.test(input.outputHash)
        || input.failureClass !== null
        || input.unresolvedReason !== null
        || !['earned', 'vesting_pending', 'payable', 'paid'].includes(input.awardState)) {
      throw new Error('invalid successful Invocation receipt state');
    }
    const componentTotal = toAtomic(input.executionCostAtomic)
      + toAtomic(input.protocolFeeAtomic)
      + toAtomic(input.refundReserveAtomic)
      + toAtomic(input.invocationAwardAtomic);
    if (componentTotal !== consumed) throw new Error('receipt consumedAtomic does not equal components');
    const journalTotal = journalEntries.reduce((sum, entry) => sum + toAtomic(entry.amountAtomic), 0n);
    if (journalTotal !== consumed || journalEntries.length !== 4) {
      throw new Error('receipt journal entries do not conserve consumed gross');
    }
    const expectedJournal = [
      ['execution-cogs', 'provider:execution', input.executionCostAtomic],
      ['protocol-fee', 'protocol:treasury', input.protocolFeeAtomic],
      ['refund-reserve', 'reserve:refund', input.refundReserveAtomic],
      ['invocation-award', `employee:${input.creatorId}`, input.invocationAwardAtomic],
    ];
    for (const [index, [category, creditAccountId, amountAtomic]] of expectedJournal.entries()) {
      const entry = journalEntries[index];
      if (entry.category !== category
          || entry.creditAccountId !== creditAccountId
          || entry.amountAtomic !== amountAtomic) {
        throw new Error('receipt journal entries do not match the shared atomic allocation');
      }
    }
  } else if (input.invocationState === 'failed') {
    if (input.receiptType !== 'internal_invocation_finalized'
        || input.reservationState !== 'released'
        || input.executionCostStatus !== 'known'
        || input.executionCostAtomic === null
        || input.outputHash !== null
        || !['provider_error', 'skill_error', 'invalid_output'].includes(input.failureClass)
        || input.unresolvedReason !== null
        || input.protocolFeeAtomic !== '0'
        || input.refundReserveAtomic !== '0'
        || input.invocationAwardAtomic !== '0'
        || input.awardState !== null
        || journalEntries.length !== 0
        || consumed !== toAtomic(input.executionCostAtomic)) {
      throw new Error('invalid failed Invocation receipt state');
    }
  } else if (input.invocationState === 'unresolved') {
    if (input.receiptType !== 'internal_invocation_finalized'
        || input.reservationState !== 'held_unresolved'
        || input.executionCostStatus !== 'unresolved'
        || input.executionCostAtomic !== null
        || input.outputHash !== null
        || input.failureClass !== null
        || !['executor_threw', 'malformed_outcome', 'cost_unknown'].includes(input.unresolvedReason)
        || input.protocolFeeAtomic !== '0'
        || input.refundReserveAtomic !== '0'
        || input.invocationAwardAtomic !== '0'
        || input.awardState !== null
        || consumed !== 0n || released !== 0n || held !== reserved
        || journalEntries.length !== 0) {
      throw new Error('invalid unresolved Invocation receipt state');
    }
  } else if (input.invocationState === 'cancelled') {
    if (input.receiptType !== 'internal_invocation_cancelled'
        || input.reservationState !== 'released'
        || input.executionAttemptId !== null
        || input.executionCostStatus !== null
        || input.executionCostAtomic !== null
        || input.outputHash !== null
        || input.failureClass !== null
        || input.unresolvedReason !== null
        || input.protocolFeeAtomic !== '0'
        || input.refundReserveAtomic !== '0'
        || input.invocationAwardAtomic !== '0'
        || input.awardState !== null
        || consumed !== 0n || released !== reserved || held !== 0n
        || journalEntries.length !== 0) {
      throw new Error('invalid cancelled Invocation receipt state');
    }
  } else {
    throw new Error('unsupported terminal Invocation receipt state');
  }
  if (input.invocationState !== 'cancelled'
      && (typeof input.executionAttemptId !== 'string' || input.executionAttemptId.length === 0)) {
    throw new Error('finalized receipt requires executionAttemptId');
  }
  return cloneFrozen({ ...input, journalEntries });
}

export function buildInvocationReceipt({
  invocation,
  reservation,
  award,
  employerId,
  receiptSignerId,
}) {
  if (!invocation || !reservation || invocation.reservationId !== reservation.reservationId
      || invocation.invocationId !== reservation.quote.invocationId) {
    throw new Error('Invocation and reservation bindings do not match');
  }
  if (invocation.beneficiaryId !== employerId) throw new Error('receipt employer does not match Beneficiary');
  const success = invocation.state === 'succeeded';
  const failed = invocation.state === 'failed';
  const unresolved = invocation.state === 'unresolved';
  const cancelled = invocation.state === 'cancelled';
  if (!success && !failed && !unresolved && !cancelled) {
    throw new Error('receipt requires a terminal Invocation');
  }
  if (success && (!award || award.awardId !== invocation.awardId
      || award.amountAtomic !== invocation.invocationAwardAtomic)) {
    throw new Error('successful Invocation receipt requires its exact award');
  }
  if (!success && award !== null) throw new Error('non-success receipt cannot include an award');
  let consumedAtomic = '0';
  if (success) {
    consumedAtomic = fromAtomic(
      toAtomic(invocation.executionCostAtomic)
      + toAtomic(invocation.protocolFeeAtomic)
      + toAtomic(invocation.refundReserveAtomic)
      + toAtomic(invocation.invocationAwardAtomic),
    );
  } else if (failed) {
    consumedAtomic = invocation.executionCostAtomic;
  }
  return validateReceiptPayload({
    schemaVersion: 1,
    receiptId: `receipt-${invocation.invocationId}`,
    sequence: invocation.receiptSequence,
    receiptType: cancelled ? 'internal_invocation_cancelled' : 'internal_invocation_finalized',
    invocationId: invocation.invocationId,
    reservationId: reservation.reservationId,
    employerId,
    creatorId: invocation.creatorId,
    skillId: invocation.skillId,
    skillVersionHash: invocation.skillVersionHash,
    policyId: invocation.policyId,
    policyVersion: invocation.policyVersion,
    period: invocation.period,
    currency: invocation.currency,
    atomicScale: invocation.atomicScale,
    invocationState: invocation.state,
    reservationState: reservation.state,
    executionAttemptId: invocation.executionAttemptId,
    reservedAtomic: reservation.reservedAtomic,
    consumedAtomic,
    releasedAtomic: invocation.releasedAtomic,
    heldReservationAtomic: invocation.heldReservationAtomic,
    executionCostStatus: invocation.executionCostStatus,
    executionCostAtomic: invocation.executionCostAtomic,
    outputHash: invocation.outputHash,
    failureClass: invocation.failureClass,
    unresolvedReason: invocation.unresolvedReason,
    protocolFeeAtomic: invocation.protocolFeeAtomic,
    refundReserveAtomic: invocation.refundReserveAtomic,
    invocationAwardAtomic: invocation.invocationAwardAtomic,
    awardState: award?.state ?? null,
    externalSettlementHash: null,
    externalRoyaltyCreditsAtomic: invocation.externalRoyaltyCreditsAtomic,
    employerSelfCreditAtomic: invocation.employerSelfCreditAtomic,
    journalEntries: invocation.journalEntries,
    occurredAt: invocation.finalizedAt,
    receiptSignerId,
  });
}

export function canonicalReceiptBytes(receipt) {
  const validated = validateReceiptPayload(receipt);
  return canonicalBytes(validated, RECEIPT_KEYS);
}

export function signReceipt(receipt, privateKey) {
  const validated = validateReceiptPayload(receipt);
  return cloneFrozen({
    ...validated,
    signature: cryptoSign(null, canonicalReceiptBytes(validated), privateKey).toString('base64'),
  });
}

function validateSignedReceiptShape(signedReceipt) {
  requireExactKeys(signedReceipt, SIGNED_RECEIPT_KEYS, 'signed receipt');
  const receipt = validateReceiptPayload(ordered(signedReceipt, RECEIPT_KEYS));
  decodeSignature(signedReceipt.signature, 'receipt');
  return receipt;
}

export function verifyReceipt(signedReceipt, { trustedReceiptSigners }) {
  const receipt = validateSignedReceiptShape(signedReceipt);
  const key = trustedKey(trustedReceiptSigners, receipt.receiptSignerId, 'receipt signer');
  if (!cryptoVerify(
    null,
    canonicalReceiptBytes(receipt),
    key,
    decodeSignature(signedReceipt.signature, 'receipt'),
  )) throw new Error('receipt signature verification failed');
  return receipt;
}

function canonicalSignedReceiptBytes(signedReceipt) {
  validateSignedReceiptShape(signedReceipt);
  return canonicalBytes(signedReceipt, SIGNED_RECEIPT_KEYS);
}

export function receiptHash(signedReceipt) {
  return taggedHash(canonicalSignedReceiptBytes(signedReceipt));
}

export function receiptMerkleRoot(signedReceipts) {
  if (!Array.isArray(signedReceipts)) throw new Error('signedReceipts must be an array');
  if (signedReceipts.length === 0) {
    return taggedHash(Buffer.from('internal-invocation-awards:receipt-merkle:v1:empty'));
  }
  let level = signedReceipts.map((receipt) => {
    const digest = Buffer.from(receiptHash(receipt).slice(7), 'hex');
    return sha256(Buffer.concat([
      Buffer.from('internal-invocation-awards:receipt-merkle:v1:leaf\0'),
      digest,
    ]));
  });
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(sha256(Buffer.concat([
        Buffer.from('internal-invocation-awards:receipt-merkle:v1:node\0'),
        left,
        right,
      ])));
    }
    level = next;
  }
  return `sha256:${level[0].toString('hex')}`;
}

function uniqueSorted(items, idKey, label, validator) {
  if (!Array.isArray(items)) throw new Error(`${label} must be an array`);
  const result = items.map((item, index) => validator(item, index));
  result.sort((left, right) => left[idKey].localeCompare(right[idKey]));
  const seen = new Set();
  for (const item of result) {
    if (seen.has(item[idKey])) throw new Error(`duplicate ${label} ID ${item[idKey]}`);
    seen.add(item[idKey]);
  }
  return result;
}

function validatePayment(payment, index) {
  requireExactKeys(payment, PAYMENT_KEYS, `payment ${index}`);
  requireString(payment.paymentId, 'paymentId');
  toAtomic(payment.amountAtomic);
  parseUtc(payment.paidAt, 'payment paidAt');
  requireString(payment.railReference, 'payment railReference');
  return cloneFrozen(payment);
}

function validateAdvance(advance, index) {
  requireExactKeys(advance, ADVANCE_KEYS, `payable advance ${index}`);
  requireString(advance.advanceId, 'advanceId');
  if (!SHA256_PATTERN.test(advance.receiptHash)) throw new Error('advance receiptHash is invalid');
  toAtomic(advance.amountAtomic);
  parseUtc(advance.advancedAt, 'advance advancedAt');
  return cloneFrozen(advance);
}

function validateReversal(reversal, index) {
  requireExactKeys(reversal, REVERSAL_KEYS, `reversal ${index}`);
  requireString(reversal.reversalId, 'reversalId');
  if (!SHA256_PATTERN.test(reversal.receiptHash)) throw new Error('reversal receiptHash is invalid');
  toAtomic(reversal.amountAtomic);
  if (!['earned_only', 'payable'].includes(reversal.balanceEffect)) {
    throw new Error('reversal balanceEffect must be earned_only or payable');
  }
  requireString(reversal.reason, 'reversal reason');
  parseUtc(reversal.occurredAt, 'reversal occurredAt');
  return cloneFrozen(reversal);
}

function statementReceiptRows(receipts, identity) {
  if (!Array.isArray(receipts)) throw new Error('receipts must be an array');
  const rows = receipts.map((signed) => ({ signed, receipt: validateSignedReceiptShape(signed) }));
  rows.sort((left, right) => left.receipt.sequence - right.receipt.sequence);
  const seenIds = new Set();
  const seenHashes = new Set();
  let expected = rows.length === 0 ? null : rows[0].receipt.sequence;
  for (const row of rows) {
    if (row.receipt.sequence !== expected) {
      throw new Error(`statement sequence gap: expected ${expected}, received ${row.receipt.sequence}`);
    }
    expected += 1;
    if (seenIds.has(row.receipt.receiptId)) throw new Error(`duplicate receipt ID ${row.receipt.receiptId}`);
    seenIds.add(row.receipt.receiptId);
    const hash = receiptHash(row.signed);
    if (seenHashes.has(hash)) throw new Error(`duplicate receipt hash ${hash}`);
    seenHashes.add(hash);
    for (const [field, expectedValue] of Object.entries(identity)) {
      if (row.receipt[field] !== expectedValue) {
        throw new Error(`receipt ${field} does not match statement`);
      }
    }
  }
  return rows;
}

export function buildStatement({
  statementId,
  employerId,
  creatorId,
  period,
  currency,
  atomicScale,
  openingPayableAtomic,
  receipts,
  payableAdvances,
  reversals,
  payments,
  statementSignerId,
}) {
  for (const [value, label] of [
    [statementId, 'statementId'], [employerId, 'employerId'], [creatorId, 'creatorId'],
    [currency, 'currency'], [statementSignerId, 'statementSignerId'],
  ]) requireString(value, label);
  if (typeof period !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])$/.test(period)) {
    throw new Error('statement period must be YYYY-MM');
  }
  if (!Number.isSafeInteger(atomicScale) || atomicScale < 0 || atomicScale > 18) {
    throw new Error('statement atomicScale must be an integer from 0 through 18');
  }
  const opening = toAtomic(openingPayableAtomic);
  const rows = statementReceiptRows(receipts, {
    employerId, creatorId, period, currency, atomicScale,
  });
  const sortedReceipts = rows.map((row) => row.signed);
  const hashes = rows.map((row) => receiptHash(row.signed));
  const reservationTotal = rows.reduce(
    (sum, row) => sum + toAtomic(row.receipt.reservedAtomic), 0n,
  );
  const releaseTotal = rows.reduce(
    (sum, row) => sum + toAtomic(row.receipt.releasedAtomic), 0n,
  );
  const chargeTotal = rows.reduce(
    (sum, row) => sum + toAtomic(row.receipt.consumedAtomic), 0n,
  );
  const earnedAwardTotal = rows.reduce((sum, row) => (
    ['earned', 'payable', 'paid'].includes(row.receipt.awardState)
      ? sum + toAtomic(row.receipt.invocationAwardAtomic)
      : sum
  ), 0n);
  const awardsByHash = new Map(rows.map((row) => [
    receiptHash(row.signed),
    {
      amount: ['earned', 'payable', 'paid'].includes(row.receipt.awardState)
        ? toAtomic(row.receipt.invocationAwardAtomic)
        : 0n,
      advance: 0n,
      earnedReversal: 0n,
      payableReversal: 0n,
    },
  ]));

  const advances = uniqueSorted(payableAdvances, 'advanceId', 'payable advances', validateAdvance);
  for (const advance of advances) {
    const award = awardsByHash.get(advance.receiptHash);
    if (!award) throw new Error('payable advance references an unknown receipt');
    award.advance += toAtomic(advance.amountAtomic);
    if (award.advance > award.amount) throw new Error('payable advance exceeds earned award');
  }
  const reversalRows = uniqueSorted(reversals, 'reversalId', 'reversals', validateReversal);
  for (const reversal of reversalRows) {
    const award = awardsByHash.get(reversal.receiptHash);
    if (!award) throw new Error('reversal references an unknown receipt');
    if (reversal.balanceEffect === 'earned_only') {
      award.earnedReversal += toAtomic(reversal.amountAtomic);
      if (award.advance + award.earnedReversal > award.amount) {
        throw new Error('earned-only reversal exceeds unadvanced earned award');
      }
    } else {
      award.payableReversal += toAtomic(reversal.amountAtomic);
      if (award.payableReversal > award.advance) {
        throw new Error('payable reversal exceeds advanced amount');
      }
    }
  }
  const paymentRows = uniqueSorted(payments, 'paymentId', 'payments', validatePayment);
  const payableAdvanceTotal = advances.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const reversalTotal = reversalRows.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const payableReversalTotal = reversalRows.reduce((sum, row) => (
    row.balanceEffect === 'payable' ? sum + toAtomic(row.amountAtomic) : sum
  ), 0n);
  const paymentTotal = paymentRows.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const payableBeforePayment = opening + payableAdvanceTotal - payableReversalTotal;
  if (paymentTotal > payableBeforePayment) throw new Error('payments exceed payable balance');
  const closing = payableBeforePayment - paymentTotal;

  return validateStatementPayload({
    schemaVersion: 1,
    statementId,
    employerId,
    creatorId,
    period,
    currency,
    atomicScale,
    openingPayableAtomic,
    firstReceiptSequence: rows.length === 0 ? null : rows[0].receipt.sequence,
    lastReceiptSequence: rows.length === 0 ? null : rows.at(-1).receipt.sequence,
    receiptHashes: hashes,
    receiptMerkleRoot: receiptMerkleRoot(sortedReceipts),
    reservationTotalAtomic: fromAtomic(reservationTotal),
    releaseTotalAtomic: fromAtomic(releaseTotal),
    chargeTotalAtomic: fromAtomic(chargeTotal),
    earnedAwardTotalAtomic: fromAtomic(earnedAwardTotal),
    payableAdvances: advances,
    payableAdvanceTotalAtomic: fromAtomic(payableAdvanceTotal),
    reversals: reversalRows,
    reversalTotalAtomic: fromAtomic(reversalTotal),
    payableReversalTotalAtomic: fromAtomic(payableReversalTotal),
    payments: paymentRows,
    paymentTotalAtomic: fromAtomic(paymentTotal),
    closingPayableAtomic: fromAtomic(closing),
    statementSignerId,
  });
}

function validateStatementPayload(input) {
  requireExactKeys(input, STATEMENT_KEYS, 'statement');
  if (input.schemaVersion !== 1) throw new Error('statement schemaVersion must equal 1');
  for (const key of ['statementId', 'employerId', 'creatorId', 'period', 'currency', 'statementSignerId']) {
    requireString(input[key], key);
  }
  if (!Number.isSafeInteger(input.atomicScale) || input.atomicScale < 0 || input.atomicScale > 18) {
    throw new Error('statement atomicScale must be an integer from 0 through 18');
  }
  const bothNull = input.firstReceiptSequence === null && input.lastReceiptSequence === null;
  const bothIntegers = Number.isSafeInteger(input.firstReceiptSequence)
    && Number.isSafeInteger(input.lastReceiptSequence)
    && input.firstReceiptSequence >= 1
    && input.lastReceiptSequence >= input.firstReceiptSequence;
  if (!bothNull && !bothIntegers) throw new Error('statement receipt sequence bounds are invalid');
  if (!Array.isArray(input.receiptHashes) || input.receiptHashes.some((hash) => !SHA256_PATTERN.test(hash))) {
    throw new Error('statement receiptHashes are invalid');
  }
  if (!SHA256_PATTERN.test(input.receiptMerkleRoot)) throw new Error('statement receiptMerkleRoot is invalid');
  for (const key of [
    'openingPayableAtomic', 'reservationTotalAtomic', 'releaseTotalAtomic',
    'chargeTotalAtomic', 'earnedAwardTotalAtomic', 'payableAdvanceTotalAtomic',
    'reversalTotalAtomic', 'payableReversalTotalAtomic', 'paymentTotalAtomic',
    'closingPayableAtomic',
  ]) toAtomic(input[key]);
  uniqueSorted(input.payableAdvances, 'advanceId', 'payable advances', validateAdvance);
  uniqueSorted(input.reversals, 'reversalId', 'reversals', validateReversal);
  uniqueSorted(input.payments, 'paymentId', 'payments', validatePayment);
  return cloneFrozen(input);
}

export function canonicalStatementBytes(unsignedStatement) {
  const validated = validateStatementPayload(unsignedStatement);
  return canonicalBytes(validated, STATEMENT_KEYS);
}

export function signStatement(unsignedStatement, privateKey) {
  const validated = validateStatementPayload(unsignedStatement);
  return cloneFrozen({
    ...validated,
    signature: cryptoSign(null, canonicalStatementBytes(validated), privateKey).toString('base64'),
  });
}

export function verifyStatement(signedStatement, {
  signedReceipts,
  trustedReceiptSigners,
  trustedStatementSigners,
}) {
  requireExactKeys(signedStatement, SIGNED_STATEMENT_KEYS, 'signed statement');
  const statement = validateStatementPayload(ordered(signedStatement, STATEMENT_KEYS));
  const key = trustedKey(
    trustedStatementSigners,
    statement.statementSignerId,
    'statement signer',
  );
  if (!cryptoVerify(
    null,
    canonicalStatementBytes(statement),
    key,
    decodeSignature(signedStatement.signature, 'statement'),
  )) throw new Error('statement signature verification failed');
  for (const receipt of signedReceipts) {
    verifyReceipt(receipt, { trustedReceiptSigners });
  }
  const recomputed = buildStatement({
    statementId: statement.statementId,
    employerId: statement.employerId,
    creatorId: statement.creatorId,
    period: statement.period,
    currency: statement.currency,
    atomicScale: statement.atomicScale,
    openingPayableAtomic: statement.openingPayableAtomic,
    receipts: signedReceipts,
    payableAdvances: statement.payableAdvances,
    reversals: statement.reversals,
    payments: statement.payments,
    statementSignerId: statement.statementSignerId,
  });
  if (!Buffer.from(canonicalStatementBytes(recomputed))
    .equals(Buffer.from(canonicalStatementBytes(statement)))) {
    throw new Error('statement does not match deterministic economic recomputation');
  }
  return statement;
}

function stableJson(value) {
  if (typeof value === 'bigint') throw new Error('JSON-safe records cannot contain BigInt');
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('JSON-safe records require finite numbers');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  if (value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${stableJson(value[key])}`).join(',')}}`;
  }
  throw new Error('JSON-safe records require plain objects and arrays');
}

export function renderJsonl(events) {
  if (!Array.isArray(events)) throw new Error('events must be an array');
  if (events.length === 0) return '';
  return `${events.map(stableJson).join('\n')}\n`;
}

export const STATEMENT_SCHEMAS = cloneFrozen({
  InvocationReceiptV1: RECEIPT_KEYS,
  StatementV1: STATEMENT_KEYS,
  PayableAdvanceV1: ADVANCE_KEYS,
  AwardReversalV1: REVERSAL_KEYS,
  EmployerPaymentV1: PAYMENT_KEYS,
});

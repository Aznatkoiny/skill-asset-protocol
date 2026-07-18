import {
  createHash,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';

import { validateInternalJournalEntries } from '../../../prototype/atomic-money.mjs';

import {
  cloneFrozen,
  deepFreeze,
  fromAtomic,
  parseUtc,
  receiptSequenceScope,
  requireExactKeys,
  toAtomic,
} from './schema.mjs';
import { normalizeEd25519PublicKey } from './public-keys.mjs';

const JOURNAL_ENTRY_KEYS = [
  'category', 'debitAccountId', 'creditAccountId', 'amountAtomic',
];
const RECEIPT_KEYS = [
  'schemaVersion', 'receiptId', 'sequence', 'receiptSequenceScope', 'receiptType', 'invocationId',
  'reservationId', 'employerId', 'creatorId', 'skillId', 'skillVersionHash',
  'skillRegistrationId', 'initiatingPrincipalId', 'principalAttestationId',
  'principalAttestationHash', 'policyId', 'policyVersion', 'policyHash',
  'period', 'currency', 'atomicScale',
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
const AWARD_ACTIVITY_KEYS = [
  'receiptHash', 'earnedAtomic', 'advancedAtomic', 'earnedReversedAtomic',
  'payableReversedAtomic',
];
const STATEMENT_KEYS = [
  'schemaVersion', 'statementId', 'employerId', 'creatorId', 'period', 'currency',
  'atomicScale', 'openingPayableAtomic', 'priorStatementHash',
  'priorClosingPayableAtomic', 'firstReceiptSequence', 'lastReceiptSequence',
  'lastRecognizedReceiptSequence',
  'receiptHashes', 'receiptMerkleRoot', 'historicalReceiptHashes',
  'reservationTotalAtomic', 'releaseTotalAtomic', 'chargeTotalAtomic',
  'earnedAwardTotalAtomic', 'payableAdvances', 'payableAdvanceTotalAtomic',
  'reversals', 'reversalTotalAtomic', 'payableReversalTotalAtomic', 'payments',
  'paymentTotalAtomic', 'cumulativeAdvanceIds', 'cumulativeReversalIds',
  'cumulativePaymentIds', 'cumulativePaymentRailReferences', 'awardActivity',
  'closingPayableAtomic', 'statementSignerId',
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

function requireSortableId(value, label) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@/-]*$/.test(value)) {
    throw new Error(`${label} must be a normalized ASCII identifier`);
  }
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
  if (map === null || typeof map !== 'object' || Array.isArray(map)
      || Object.getPrototypeOf(map) !== Object.prototype) {
    throw new Error(`${label} trust map must be a plain object`);
  }
  if (!Object.hasOwn(map, keyId)) {
    throw new Error(`${label} key ID ${keyId} is not trusted`);
  }
  const key = map[keyId];
  if (typeof key !== 'string' || key.length === 0) {
    throw new Error(`${label} key ID ${keyId} is not trusted`);
  }
  return normalizeEd25519PublicKey(key, `${label} ${keyId}`);
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
    'creatorId', 'skillId', 'skillRegistrationId', 'initiatingPrincipalId',
    'principalAttestationId', 'policyId', 'period', 'currency', 'invocationState',
    'reservationState', 'receiptSignerId', 'receiptSequenceScope',
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
  if (!SHA256_PATTERN.test(input.policyHash)) throw new Error('receipt policyHash is invalid');
  if (!SHA256_PATTERN.test(input.principalAttestationHash)) {
    throw new Error('receipt principalAttestationHash is invalid');
  }
  if (input.receiptSequenceScope !== receiptSequenceScope({
    employerId: input.employerId,
    creatorId: input.creatorId,
    currency: input.currency,
    atomicScale: input.atomicScale,
  })) throw new Error('receipt sequence scope does not match receipt identity');
  parseUtc(input.occurredAt, 'receipt occurredAt');
  if (input.occurredAt.slice(0, 7) !== input.period) {
    throw new Error(`receipt occurredAt must fall within receipt period ${input.period}`);
  }
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
    validateInternalJournalEntries({
      kind: 'succeeded',
      grossAtomic: consumed,
      executionCostAtomic: toAtomic(input.executionCostAtomic),
      protocolFeeAtomic: toAtomic(input.protocolFeeAtomic),
      refundReserveAtomic: toAtomic(input.refundReserveAtomic),
      recipientId: input.creatorId,
      employerId: input.employerId,
      journalEntries: journalEntries.map((entry) => ({
        ...entry, amountAtomic: toAtomic(entry.amountAtomic),
      })),
    });
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
        || journalEntries.length !== 1
        || consumed !== toAtomic(input.executionCostAtomic)) {
      throw new Error('invalid failed Invocation receipt state');
    }
    validateInternalJournalEntries({
      kind: 'failed_after_start',
      grossAtomic: consumed,
      executionCostAtomic: toAtomic(input.executionCostAtomic),
      journalEntries: journalEntries.map((entry) => ({
        ...entry, amountAtomic: toAtomic(entry.amountAtomic),
      })),
    });
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
    receiptSequenceScope: invocation.receiptSequenceScope,
    receiptType: cancelled ? 'internal_invocation_cancelled' : 'internal_invocation_finalized',
    invocationId: invocation.invocationId,
    reservationId: reservation.reservationId,
    employerId,
    creatorId: invocation.creatorId,
    skillId: invocation.skillId,
    skillVersionHash: invocation.skillVersionHash,
    skillRegistrationId: invocation.skillRegistrationId,
    initiatingPrincipalId: invocation.initiatingPrincipalId,
    principalAttestationId: invocation.principalAttestationId,
    principalAttestationHash: invocation.principalAttestationHash,
    policyId: invocation.policyId,
    policyVersion: invocation.policyVersion,
    policyHash: invocation.policyHash,
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

export function signReceiptWithCapability(receipt, capability) {
  const validated = validateReceiptPayload(receipt);
  if (!capability || typeof capability !== 'object'
      || capability.signerId !== validated.receiptSignerId
      || typeof capability.sign !== 'function') {
    throw new Error('receipt signer capability does not match receiptSignerId');
  }
  const signature = capability.sign(canonicalReceiptBytes(validated));
  const signed = { ...validated, signature };
  validateSignedReceiptShape(signed);
  return cloneFrozen(signed);
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
  result.sort((left, right) => {
    if (left[idKey] < right[idKey]) return -1;
    if (left[idKey] > right[idKey]) return 1;
    return 0;
  });
  const seen = new Set();
  for (const item of result) {
    if (seen.has(item[idKey])) throw new Error(`duplicate ${label} ID ${item[idKey]}`);
    seen.add(item[idKey]);
  }
  return result;
}

function validatePayment(payment, index) {
  requireExactKeys(payment, PAYMENT_KEYS, `payment ${index}`);
  requireSortableId(payment.paymentId, 'paymentId');
  toAtomic(payment.amountAtomic);
  parseUtc(payment.paidAt, 'payment paidAt');
  requireString(payment.railReference, 'payment railReference');
  return cloneFrozen(payment);
}

function validateAdvance(advance, index) {
  requireExactKeys(advance, ADVANCE_KEYS, `payable advance ${index}`);
  requireSortableId(advance.advanceId, 'advanceId');
  if (!SHA256_PATTERN.test(advance.receiptHash)) throw new Error('advance receiptHash is invalid');
  toAtomic(advance.amountAtomic);
  parseUtc(advance.advancedAt, 'advance advancedAt');
  return cloneFrozen(advance);
}

function validateReversal(reversal, index) {
  requireExactKeys(reversal, REVERSAL_KEYS, `reversal ${index}`);
  requireSortableId(reversal.reversalId, 'reversalId');
  if (!SHA256_PATTERN.test(reversal.receiptHash)) throw new Error('reversal receiptHash is invalid');
  toAtomic(reversal.amountAtomic);
  if (!['earned_only', 'payable'].includes(reversal.balanceEffect)) {
    throw new Error('reversal balanceEffect must be earned_only or payable');
  }
  requireString(reversal.reason, 'reversal reason');
  parseUtc(reversal.occurredAt, 'reversal occurredAt');
  return cloneFrozen(reversal);
}

function statementReceiptRows(receipts, identity, { enforceContinuity = true } = {}) {
  if (!Array.isArray(receipts)) throw new Error('receipts must be an array');
  const rows = receipts.map((signed) => ({ signed, receipt: validateSignedReceiptShape(signed) }));
  rows.sort((left, right) => left.receipt.sequence - right.receipt.sequence);
  const seenIds = new Set();
  const seenHashes = new Set();
  let expected = rows.length === 0 ? null : rows[0].receipt.sequence;
  for (const row of rows) {
    if (enforceContinuity && row.receipt.sequence !== expected) {
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

function sortedStrings(values) {
  return [...values].sort((left, right) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  });
}

function validateAwardActivity(row, index) {
  requireExactKeys(row, AWARD_ACTIVITY_KEYS, `award activity ${index}`);
  if (!SHA256_PATTERN.test(row.receiptHash)) throw new Error('award activity receiptHash is invalid');
  for (const key of [
    'earnedAtomic', 'advancedAtomic', 'earnedReversedAtomic', 'payableReversedAtomic',
  ]) toAtomic(row[key]);
  return cloneFrozen(row);
}

function cumulativeIds(priorValues, currentValues, label) {
  const prior = Array.isArray(priorValues) ? priorValues : [];
  const seen = new Set(prior);
  for (const id of currentValues) {
    if (seen.has(id)) throw new Error(`${label} ID already appeared in a prior statement: ${id}`);
    seen.add(id);
  }
  return sortedStrings(seen);
}

function assertTimestampInPeriod(timestamp, period, label) {
  parseUtc(timestamp, label);
  if (timestamp.slice(0, 7) !== period) {
    throw new Error(`${label} must fall within statement period ${period}`);
  }
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
  historicalReceipts = [],
  priorStatement = null,
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
  let priorPayload = null;
  let priorHash = null;
  if (priorStatement !== null) {
    priorPayload = validateSignedStatementShape(priorStatement);
    priorHash = statementHash(priorStatement);
    for (const key of ['employerId', 'creatorId', 'currency', 'atomicScale']) {
      if (priorPayload[key] !== { employerId, creatorId, currency, atomicScale }[key]) {
        throw new Error(`prior statement ${key} does not match current statement`);
      }
    }
    if (priorPayload.period >= period) throw new Error('prior statement period must precede current period');
    if (openingPayableAtomic !== priorPayload.closingPayableAtomic) {
      throw new Error('opening payable must equal authenticated prior closing payable');
    }
  }

  const rows = statementReceiptRows(receipts, {
    employerId, creatorId, period, currency, atomicScale,
  });
  const priorReceiptCursor = priorPayload?.lastRecognizedReceiptSequence ?? 0;
  if (rows.length > 0 && rows[0].receipt.sequence !== priorReceiptCursor + 1) {
    throw new Error(
      `statement sequence gap across periods: expected ${priorReceiptCursor + 1}, received ${rows[0].receipt.sequence}`,
    );
  }
  const lastRecognizedReceiptSequence = rows.length === 0
    ? priorReceiptCursor
    : rows.at(-1).receipt.sequence;
  const historicalRows = statementReceiptRows(historicalReceipts, {
    employerId, creatorId, currency, atomicScale,
  }, { enforceContinuity: false });
  for (const row of historicalRows) {
    if (row.receipt.period >= period) {
      throw new Error('historical receipt period must precede current statement period');
    }
  }
  const sortedReceipts = rows.map((row) => row.signed);
  const hashes = rows.map((row) => receiptHash(row.signed));
  const historicalHashes = sortedStrings(historicalRows.map((row) => receiptHash(row.signed)));
  if (new Set([...hashes, ...historicalHashes]).size !== hashes.length + historicalHashes.length) {
    throw new Error('receipt cannot be both current and historical');
  }
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

  const awardsByHash = new Map();
  for (const activity of priorPayload?.awardActivity ?? []) {
    awardsByHash.set(activity.receiptHash, {
      amount: toAtomic(activity.earnedAtomic),
      advance: toAtomic(activity.advancedAtomic),
      earnedReversal: toAtomic(activity.earnedReversedAtomic),
      payableReversal: toAtomic(activity.payableReversedAtomic),
    });
  }
  for (const row of rows) {
    const hash = receiptHash(row.signed);
    if (awardsByHash.has(hash)) throw new Error('current receipt was already recognized by prior statement');
    awardsByHash.set(hash, {
      amount: ['earned', 'payable', 'paid'].includes(row.receipt.awardState)
        ? toAtomic(row.receipt.invocationAwardAtomic)
        : 0n,
      advance: 0n,
      earnedReversal: 0n,
      payableReversal: 0n,
    });
  }
  const historicalSet = new Set(historicalHashes);
  for (const row of historicalRows) {
    const hash = receiptHash(row.signed);
    const activity = awardsByHash.get(hash);
    if (!priorPayload || !activity) {
      throw new Error('historical receipt is not authenticated by the prior statement chain');
    }
    const receiptEarned = ['earned', 'payable', 'paid'].includes(row.receipt.awardState)
      ? toAtomic(row.receipt.invocationAwardAtomic)
      : 0n;
    if (receiptEarned !== activity.amount) {
      throw new Error('historical receipt award does not match prior statement activity');
    }
  }

  const advances = uniqueSorted(payableAdvances, 'advanceId', 'payable advances', validateAdvance);
  for (const advance of advances) {
    assertTimestampInPeriod(advance.advancedAt, period, 'advance advancedAt');
  }
  for (const advance of advances) {
    const award = awardsByHash.get(advance.receiptHash);
    if (!award || !historicalSet.has(advance.receiptHash)) {
      throw new Error('payable advance must reference an authenticated historical receipt');
    }
    award.advance += toAtomic(advance.amountAtomic);
    if (award.advance > award.amount) throw new Error('payable advance exceeds earned award');
  }
  const reversalRows = uniqueSorted(reversals, 'reversalId', 'reversals', validateReversal);
  for (const reversal of reversalRows) {
    assertTimestampInPeriod(reversal.occurredAt, period, 'reversal occurredAt');
  }
  for (const reversal of reversalRows) {
    const award = awardsByHash.get(reversal.receiptHash);
    if (!award || (!hashes.includes(reversal.receiptHash) && !historicalSet.has(reversal.receiptHash))) {
      throw new Error('reversal references an unauthenticated current or historical receipt');
    }
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
  for (const payment of paymentRows) {
    assertTimestampInPeriod(payment.paidAt, period, 'payment paidAt');
  }
  if (new Set(paymentRows.map((row) => row.railReference)).size !== paymentRows.length) {
    throw new Error('duplicate payment railReference in statement');
  }
  const cumulativeAdvanceIds = cumulativeIds(
    priorPayload?.cumulativeAdvanceIds,
    advances.map((row) => row.advanceId),
    'payable advance',
  );
  const cumulativeReversalIds = cumulativeIds(
    priorPayload?.cumulativeReversalIds,
    reversalRows.map((row) => row.reversalId),
    'reversal',
  );
  const cumulativePaymentIds = cumulativeIds(
    priorPayload?.cumulativePaymentIds,
    paymentRows.map((row) => row.paymentId),
    'payment',
  );
  const cumulativePaymentRailReferences = cumulativeIds(
    priorPayload?.cumulativePaymentRailReferences,
    paymentRows.map((row) => row.railReference),
    'payment railReference',
  );
  const payableAdvanceTotal = advances.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const reversalTotal = reversalRows.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const payableReversalTotal = reversalRows.reduce((sum, row) => (
    row.balanceEffect === 'payable' ? sum + toAtomic(row.amountAtomic) : sum
  ), 0n);
  const paymentTotal = paymentRows.reduce((sum, row) => sum + toAtomic(row.amountAtomic), 0n);
  const payableBeforePayment = opening + payableAdvanceTotal - payableReversalTotal;
  if (paymentTotal > payableBeforePayment) throw new Error('payments exceed payable balance');
  const closing = payableBeforePayment - paymentTotal;
  const awardActivity = sortedStrings(awardsByHash.keys()).map((hash) => {
    const value = awardsByHash.get(hash);
    return deepFreeze({
      receiptHash: hash,
      earnedAtomic: fromAtomic(value.amount),
      advancedAtomic: fromAtomic(value.advance),
      earnedReversedAtomic: fromAtomic(value.earnedReversal),
      payableReversedAtomic: fromAtomic(value.payableReversal),
    });
  });

  return validateStatementPayload({
    schemaVersion: 1,
    statementId,
    employerId,
    creatorId,
    period,
    currency,
    atomicScale,
    openingPayableAtomic,
    priorStatementHash: priorHash,
    priorClosingPayableAtomic: priorPayload?.closingPayableAtomic ?? null,
    firstReceiptSequence: rows.length === 0 ? null : rows[0].receipt.sequence,
    lastReceiptSequence: rows.length === 0 ? null : rows.at(-1).receipt.sequence,
    lastRecognizedReceiptSequence,
    receiptHashes: hashes,
    receiptMerkleRoot: receiptMerkleRoot(sortedReceipts),
    historicalReceiptHashes: historicalHashes,
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
    cumulativeAdvanceIds,
    cumulativeReversalIds,
    cumulativePaymentIds,
    cumulativePaymentRailReferences,
    awardActivity,
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
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(input.period)) throw new Error('statement period must be YYYY-MM');
  const noPrior = input.priorStatementHash === null && input.priorClosingPayableAtomic === null;
  const hasPrior = SHA256_PATTERN.test(input.priorStatementHash)
    && typeof input.priorClosingPayableAtomic === 'string';
  if (!noPrior && !hasPrior) throw new Error('statement prior chain fields are invalid');
  if (input.priorClosingPayableAtomic !== null) toAtomic(input.priorClosingPayableAtomic);
  const bothNull = input.firstReceiptSequence === null && input.lastReceiptSequence === null;
  const bothIntegers = Number.isSafeInteger(input.firstReceiptSequence)
    && Number.isSafeInteger(input.lastReceiptSequence)
    && input.firstReceiptSequence >= 1
    && input.lastReceiptSequence >= input.firstReceiptSequence;
  if (!bothNull && !bothIntegers) throw new Error('statement receipt sequence bounds are invalid');
  if (!Number.isSafeInteger(input.lastRecognizedReceiptSequence)
      || input.lastRecognizedReceiptSequence < 0) {
    throw new Error('statement lastRecognizedReceiptSequence must be a non-negative integer');
  }
  if (bothIntegers && input.lastRecognizedReceiptSequence !== input.lastReceiptSequence) {
    throw new Error('statement receipt cursor must equal the current last receipt sequence');
  }
  if (input.priorStatementHash === null) {
    const expectedGenesisCursor = bothNull ? 0 : input.lastReceiptSequence;
    if (input.lastRecognizedReceiptSequence !== expectedGenesisCursor
        || (bothIntegers && input.firstReceiptSequence !== 1)) {
      throw new Error('genesis statement receipt sequence must begin at 1');
    }
  }
  if (!Array.isArray(input.receiptHashes) || input.receiptHashes.some((hash) => !SHA256_PATTERN.test(hash))) {
    throw new Error('statement receiptHashes are invalid');
  }
  if (!Array.isArray(input.historicalReceiptHashes)
      || input.historicalReceiptHashes.some((hash) => !SHA256_PATTERN.test(hash))) {
    throw new Error('statement historicalReceiptHashes are invalid');
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
  for (const advance of input.payableAdvances) {
    assertTimestampInPeriod(advance.advancedAt, input.period, 'advance advancedAt');
  }
  for (const reversal of input.reversals) {
    assertTimestampInPeriod(reversal.occurredAt, input.period, 'reversal occurredAt');
  }
  for (const payment of input.payments) {
    assertTimestampInPeriod(payment.paidAt, input.period, 'payment paidAt');
  }
  if (new Set(input.payments.map((row) => row.railReference)).size !== input.payments.length) {
    throw new Error('duplicate payment railReference in statement');
  }
  for (const [values, label] of [
    [input.cumulativeAdvanceIds, 'cumulativeAdvanceIds'],
    [input.cumulativeReversalIds, 'cumulativeReversalIds'],
    [input.cumulativePaymentIds, 'cumulativePaymentIds'],
    [input.cumulativePaymentRailReferences, 'cumulativePaymentRailReferences'],
  ]) {
    if (!Array.isArray(values)) throw new Error(`${label} must be an array`);
    for (const value of values) {
      if (label === 'cumulativePaymentRailReferences') {
        requireString(value, `${label} entry`);
      } else {
        requireSortableId(value, `${label} entry`);
      }
    }
    if (new Set(values).size !== values.length
        || JSON.stringify(values) !== JSON.stringify(sortedStrings(values))) {
      throw new Error(`${label} must be unique and code-unit sorted`);
    }
  }
  if (!Array.isArray(input.awardActivity)) throw new Error('awardActivity must be an array');
  const activity = input.awardActivity.map(validateAwardActivity);
  if (new Set(activity.map((row) => row.receiptHash)).size !== activity.length
      || JSON.stringify(activity.map((row) => row.receiptHash))
        !== JSON.stringify(sortedStrings(activity.map((row) => row.receiptHash)))) {
    throw new Error('awardActivity must have unique code-unit-sorted receipt hashes');
  }
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

function validateSignedStatementShape(signedStatement) {
  requireExactKeys(signedStatement, SIGNED_STATEMENT_KEYS, 'signed statement');
  const statement = validateStatementPayload(ordered(signedStatement, STATEMENT_KEYS));
  decodeSignature(signedStatement.signature, 'statement');
  return statement;
}

function canonicalSignedStatementBytes(signedStatement) {
  validateSignedStatementShape(signedStatement);
  return canonicalBytes(signedStatement, SIGNED_STATEMENT_KEYS);
}

export function statementHash(signedStatement) {
  return taggedHash(canonicalSignedStatementBytes(signedStatement));
}

function verifyOneStatement(signedStatement, {
  signedReceipts,
  historicalSignedReceipts,
  priorStatement,
  trustedReceiptSigners,
  trustedStatementSigners,
}) {
  const statement = validateSignedStatementShape(signedStatement);
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
  for (const receipt of [...signedReceipts, ...historicalSignedReceipts]) {
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
    historicalReceipts: historicalSignedReceipts,
    priorStatement,
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

export function verifyStatement(signedStatement, {
  signedReceipts,
  historicalSignedReceipts = [],
  priorStatements = [],
  trustedReceiptSigners,
  trustedStatementSigners,
}) {
  if (!Array.isArray(priorStatements)) throw new Error('priorStatements must be an array');
  let prior = null;
  for (const [index, entry] of priorStatements.entries()) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`prior statement entry ${index} must be an object`);
    }
    verifyOneStatement(entry.signedStatement, {
      signedReceipts: entry.signedReceipts ?? [],
      historicalSignedReceipts: entry.historicalSignedReceipts ?? [],
      priorStatement: prior,
      trustedReceiptSigners,
      trustedStatementSigners,
    });
    prior = entry.signedStatement;
  }
  return verifyOneStatement(signedStatement, {
    signedReceipts,
    historicalSignedReceipts,
    priorStatement: prior,
    trustedReceiptSigners,
    trustedStatementSigners,
  });
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

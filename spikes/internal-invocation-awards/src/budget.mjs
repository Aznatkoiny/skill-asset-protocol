import { sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';

import {
  allocateInternalFailureGross,
  allocateInternalGross,
} from '../../../prototype/atomic-money.mjs';
import {
  cloneFrozen,
  deepFreeze,
  fromAtomic,
  parseUtc,
  policyHash,
  requireExactKeys,
  sumAtomic,
  toAtomic,
  validatePolicy,
  validateQuote,
} from './schema.mjs';

const BUDGET_AUTHORIZATION_KEYS = [
  'schemaVersion', 'budgetId', 'policyId', 'policyVersion', 'policyHash',
  'period', 'currency',
  'atomicScale', 'allocatedAtomic', 'effectiveAt', 'expiresAt', 'signerId',
];
const SIGNED_BUDGET_AUTHORIZATION_KEYS = [...BUDGET_AUTHORIZATION_KEYS, 'signature'];
const BUDGET_STATE_KEYS = [
  'schemaVersion', 'budgetId', 'policyId', 'policyVersion', 'policyHash',
  'period', 'currency',
  'atomicScale', 'authorization', 'policy', 'allocatedAtomic', 'reservedAtomic',
  'consumedAtomic', 'releasedAtomic', 'revision',
];
const RESERVATION_KEYS = [
  'schemaVersion', 'reservationId', 'quote', 'state', 'reservedAtomic', 'revision',
  'executionAttemptId', 'authorizedAt', 'startedAt', 'finalizedAt',
];

function ordered(source, keys) {
  return Object.fromEntries(keys.map((key) => [key, source[key]]));
}

function canonicalBytes(source, keys) {
  return new TextEncoder().encode(JSON.stringify(ordered(source, keys)));
}

function requireNonEmpty(value, label) {
  if (typeof value !== 'string' || value.length === 0) throw new Error(`${label} must be non-empty`);
}

function decodeSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('budget signature must be canonical base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length !== 64 || bytes.toString('base64') !== value) {
    throw new Error('budget signature must be a 64-byte canonical base64 Ed25519 signature');
  }
  return bytes;
}

function validateUnsignedAuthorization(input) {
  requireExactKeys(input, BUDGET_AUTHORIZATION_KEYS, 'budget authorization');
  if (input.schemaVersion !== 1) throw new Error('budget authorization schemaVersion must equal 1');
  for (const key of ['budgetId', 'policyId', 'policyHash', 'currency', 'signerId']) {
    requireNonEmpty(input[key], key);
  }
  if (!Number.isSafeInteger(input.policyVersion) || input.policyVersion < 1) {
    throw new Error('budget policyVersion must be a positive integer');
  }
  if (typeof input.period !== 'string' || !/^\d{4}-(0[1-9]|1[0-2])$/.test(input.period)) {
    throw new Error('budget period must be YYYY-MM');
  }
  if (!Number.isSafeInteger(input.atomicScale) || input.atomicScale < 0 || input.atomicScale > 18) {
    throw new Error('budget atomicScale must be an integer from 0 through 18');
  }
  toAtomic(input.allocatedAtomic);
  const effectiveAt = parseUtc(input.effectiveAt, 'budget effectiveAt');
  const expiresAt = parseUtc(input.expiresAt, 'budget expiresAt');
  if (expiresAt <= effectiveAt) throw new Error('budget expiresAt must follow effectiveAt');
  return cloneFrozen(input);
}

export function canonicalBudgetBytes(unsignedBudget) {
  const validated = validateUnsignedAuthorization(unsignedBudget);
  return canonicalBytes(validated, BUDGET_AUTHORIZATION_KEYS);
}

export function signBudget(unsignedBudget, privateKey) {
  const validated = validateUnsignedAuthorization(unsignedBudget);
  const signature = cryptoSign(null, canonicalBudgetBytes(validated), privateKey).toString('base64');
  return cloneFrozen({ ...validated, signature });
}

function validateTrustedSignerMap(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('trustedFinanceSigners must be an object');
  }
  for (const [signerId, key] of Object.entries(value)) {
    requireNonEmpty(signerId, 'finance signer ID');
    requireNonEmpty(key, `trusted key for ${signerId}`);
  }
}

export function createBudget(signedBudget, { trustedFinanceSigners, policy: policyInput, now }) {
  requireExactKeys(signedBudget, SIGNED_BUDGET_AUTHORIZATION_KEYS, 'signed budget authorization');
  const unsigned = validateUnsignedAuthorization(ordered(signedBudget, BUDGET_AUTHORIZATION_KEYS));
  const policy = validatePolicy(policyInput, now);
  validateTrustedSignerMap(trustedFinanceSigners);
  if (unsigned.policyId !== policy.policyId || unsigned.policyVersion !== policy.version) {
    throw new Error('budget authorization policy binding does not match effective policy');
  }
  if (unsigned.policyHash !== policyHash(policy)) {
    throw new Error('budget authorization policyHash does not match canonical policy');
  }
  if (unsigned.currency !== policy.currency || unsigned.atomicScale !== policy.atomicScale) {
    throw new Error('budget authorization denomination does not match policy');
  }
  if (!policy.permittedFinanceSignerIds.includes(unsigned.signerId)) {
    throw new Error('finance signer is not permitted by policy');
  }
  const trustedKey = trustedFinanceSigners[unsigned.signerId];
  if (typeof trustedKey !== 'string' || trustedKey.length === 0) {
    throw new Error('trusted finance signer is not provisioned');
  }
  const at = parseUtc(now, 'now');
  const effectiveAt = parseUtc(unsigned.effectiveAt, 'budget effectiveAt');
  const expiresAt = parseUtc(unsigned.expiresAt, 'budget expiresAt');
  if (at < effectiveAt) throw new Error('budget authorization is not yet effective');
  if (at >= expiresAt) throw new Error('budget authorization expired');
  if (effectiveAt < parseUtc(policy.effectiveAt, 'policy effectiveAt')
      || expiresAt > parseUtc(policy.expiresAt, 'policy expiresAt')) {
    throw new Error('budget authorization window exceeds policy window');
  }
  const signature = decodeSignature(signedBudget.signature);
  if (!cryptoVerify(null, canonicalBudgetBytes(unsigned), trustedKey, signature)) {
    throw new Error('budget authorization signature verification failed');
  }
  return deepFreeze({
    schemaVersion: 1,
    budgetId: unsigned.budgetId,
    policyId: unsigned.policyId,
    policyVersion: unsigned.policyVersion,
    policyHash: unsigned.policyHash,
    period: unsigned.period,
    currency: unsigned.currency,
    atomicScale: unsigned.atomicScale,
    authorization: cloneFrozen(signedBudget),
    policy,
    allocatedAtomic: unsigned.allocatedAtomic,
    reservedAtomic: '0',
    consumedAtomic: '0',
    releasedAtomic: '0',
    revision: 0,
  });
}

function validateBudgetState(budget) {
  requireExactKeys(budget, BUDGET_STATE_KEYS, 'budget state');
  if (budget.schemaVersion !== 1 || !Number.isSafeInteger(budget.revision) || budget.revision < 0) {
    throw new Error('invalid budget state revision');
  }
  for (const key of ['allocatedAtomic', 'reservedAtomic', 'consumedAtomic', 'releasedAtomic']) {
    toAtomic(budget[key]);
  }
  const allocated = toAtomic(budget.allocatedAtomic);
  const committed = toAtomic(budget.reservedAtomic) + toAtomic(budget.consumedAtomic);
  if (committed > allocated) throw new Error('budget state exceeds allocated amount');
  return budget;
}

function validateReservation(reservation) {
  requireExactKeys(reservation, RESERVATION_KEYS, 'reservation');
  if (reservation.schemaVersion !== 1
      || !Number.isSafeInteger(reservation.revision) || reservation.revision < 0) {
    throw new Error('invalid reservation revision');
  }
  toAtomic(reservation.reservedAtomic);
  return reservation;
}

function requireRevision(actual, expected, label) {
  if (!Number.isSafeInteger(expected) || actual !== expected) {
    throw new Error(`stale ${label} revision: expected ${expected}, received ${actual}`);
  }
}

function requireCurrentAuthorization(budget, now) {
  validatePolicy(budget.policy, now);
  const at = parseUtc(now, 'now');
  if (at < parseUtc(budget.authorization.effectiveAt, 'budget effectiveAt')) {
    throw new Error('budget authorization is not yet effective');
  }
  if (at >= parseUtc(budget.authorization.expiresAt, 'budget expiresAt')) {
    throw new Error('budget authorization expired');
  }
  if (String(now).slice(0, 7) !== budget.period) throw new Error('budget period is not active');
}

function replaceBudget(budget, changes) {
  const next = deepFreeze({ ...budget, ...changes });
  validateBudgetState(next);
  return next;
}

function replaceReservation(reservation, changes) {
  const next = deepFreeze({ ...reservation, ...changes });
  validateReservation(next);
  return next;
}

function event(type, reservation, budget, now, details = {}) {
  return deepFreeze({
    schemaVersion: 1,
    eventId: `${reservation.reservationId}:${type}:${budget.revision}`,
    type,
    occurredAt: now,
    budgetId: budget.budgetId,
    budgetRevision: budget.revision,
    reservationId: reservation.reservationId,
    reservationRevision: reservation.revision,
    invocationId: reservation.quote.invocationId,
    ...details,
  });
}

export function remainingAtomic(budget) {
  validateBudgetState(budget);
  return toAtomic(budget.allocatedAtomic)
    - toAtomic(budget.reservedAtomic)
    - toAtomic(budget.consumedAtomic);
}

export function reserveBudget(budgetInput, quoteInput, { expectedRevision, reservationId, now }) {
  const budget = validateBudgetState(budgetInput);
  requireRevision(budget.revision, expectedRevision, 'budget');
  requireCurrentAuthorization(budget, now);
  requireNonEmpty(reservationId, 'reservationId');
  const quote = validateQuote(quoteInput, budget.policy, now);
  if (quote.policyId !== budget.policyId || quote.policyVersion !== budget.policyVersion) {
    throw new Error('quote does not match budget policy');
  }
  const amount = toAtomic(quote.maxGrossAtomic);
  if (amount > remainingAtomic(budget)) throw new Error('insufficient remaining budget');
  const nextBudget = replaceBudget(budget, {
    reservedAtomic: fromAtomic(toAtomic(budget.reservedAtomic) + amount),
    revision: budget.revision + 1,
  });
  const reservation = deepFreeze({
    schemaVersion: 1,
    reservationId,
    quote,
    state: 'reserved',
    reservedAtomic: quote.maxGrossAtomic,
    revision: 0,
    executionAttemptId: null,
    authorizedAt: now,
    startedAt: null,
    finalizedAt: null,
  });
  return deepFreeze({
    budget: nextBudget,
    reservation,
    event: event('budget_reserved', reservation, nextBudget, now, {
      reservedAtomic: reservation.reservedAtomic,
    }),
  });
}

function requireTransitionRevisions(budget, reservation, options) {
  requireRevision(budget.revision, options.expectedBudgetRevision, 'budget');
  requireRevision(reservation.revision, options.expectedReservationRevision, 'reservation');
}

export function startReservationExecution(budgetInput, reservationInput, options) {
  const budget = validateBudgetState(budgetInput);
  const reservation = validateReservation(reservationInput);
  requireTransitionRevisions(budget, reservation, options);
  if (reservation.state !== 'reserved') throw new Error('reservation must be reserved');
  requireNonEmpty(options.executionAttemptId, 'executionAttemptId');
  parseUtc(options.now, 'now');
  const nextBudget = replaceBudget(budget, { revision: budget.revision + 1 });
  const nextReservation = replaceReservation(reservation, {
    state: 'executing',
    revision: reservation.revision + 1,
    executionAttemptId: options.executionAttemptId,
    startedAt: options.now,
  });
  return deepFreeze({
    budget: nextBudget,
    reservation: nextReservation,
    event: event('execution_started', nextReservation, nextBudget, options.now, {
      executionAttemptId: options.executionAttemptId,
    }),
  });
}

function requireExecuting(budget, reservation, options) {
  requireTransitionRevisions(budget, reservation, options);
  if (reservation.state !== 'executing') throw new Error('reservation must be executing');
  if (reservation.executionAttemptId !== options.executionAttemptId) {
    throw new Error('execution attempt does not match reservation');
  }
}

function serializeJournalEntries(entries) {
  return entries.map((entry) => deepFreeze({
    category: entry.category,
    debitAccountId: entry.debitAccountId,
    creditAccountId: entry.creditAccountId,
    amountAtomic: fromAtomic(entry.amountAtomic),
  }));
}

export function finalizeReservation(budgetInput, reservationInput, actual) {
  const budget = validateBudgetState(budgetInput);
  const reservation = validateReservation(reservationInput);
  requireExecuting(budget, reservation, actual);
  parseUtc(actual.now, 'now');
  if (actual.recipientId !== reservation.quote.creatorId) {
    throw new Error('award recipient must equal quote Creator');
  }
  const executionCost = toAtomic(actual.executionCostAtomic);
  const fee = toAtomic(actual.protocolFeeAtomic);
  const reserve = toAtomic(actual.refundReserveAtomic);
  const gross = toAtomic(actual.grossAtomic);
  const maximumAward = toAtomic(reservation.quote.maxInvocationAwardAtomic);
  if (executionCost > toAtomic(reservation.quote.maxExecutionCostAtomic)) {
    throw new Error('execution cost exceeds quote maximum');
  }
  if (actual.protocolFeeAtomic !== reservation.quote.protocolFeeAtomic) {
    throw new Error('protocol fee must equal the quote-final amount');
  }
  if (actual.refundReserveAtomic !== reservation.quote.refundReserveAtomic) {
    throw new Error('refund reserve must equal the quote-final amount');
  }
  const derivedGross = executionCost + fee + reserve + maximumAward;
  if (gross !== derivedGross) {
    throw new Error(`grossAtomic must equal cost, fee, reserve, and maximum award (${derivedGross})`);
  }
  const reservedAmount = toAtomic(reservation.reservedAtomic);
  if (gross > reservedAmount) throw new Error('actual gross exceeds reserved amount');
  const allocation = deepFreeze(allocateInternalGross({
    grossAtomic: gross,
    executionCostAtomic: executionCost,
    protocolFeeAtomic: fee,
    refundReserveAtomic: reserve,
    recipientId: actual.recipientId,
    employerId: reservation.quote.beneficiaryId,
  }));
  if (allocation.invocationAwardAtomic !== maximumAward) {
    throw new Error('kernel Invocation award does not equal the authorized maximum award');
  }
  const released = reservedAmount - gross;
  const nextBudget = replaceBudget(budget, {
    reservedAtomic: fromAtomic(toAtomic(budget.reservedAtomic) - reservedAmount),
    consumedAtomic: fromAtomic(toAtomic(budget.consumedAtomic) + gross),
    releasedAtomic: fromAtomic(toAtomic(budget.releasedAtomic) + released),
    revision: budget.revision + 1,
  });
  const nextReservation = replaceReservation(reservation, {
    state: 'consumed',
    revision: reservation.revision + 1,
    finalizedAt: actual.now,
  });
  const journalEntries = serializeJournalEntries(allocation.journalEntries);
  return deepFreeze({
    budget: nextBudget,
    reservation: nextReservation,
    allocation,
    event: event('budget_consumed', nextReservation, nextBudget, actual.now, {
      grossAtomic: actual.grossAtomic,
      releasedUnusedAtomic: fromAtomic(released),
      executionCostAtomic: actual.executionCostAtomic,
      protocolFeeAtomic: actual.protocolFeeAtomic,
      refundReserveAtomic: actual.refundReserveAtomic,
      invocationAwardAtomic: fromAtomic(allocation.invocationAwardAtomic),
      journalEntries,
    }),
  });
}

export function releaseReservation(budgetInput, reservationInput, options) {
  const budget = validateBudgetState(budgetInput);
  const reservation = validateReservation(reservationInput);
  requireTransitionRevisions(budget, reservation, options);
  parseUtc(options.now, 'now');
  const cost = toAtomic(options.executionCostAtomic);
  let allocation = null;
  if (options.reason === 'cancelled_before_start') {
    if (reservation.state !== 'reserved') throw new Error('reservation must be reserved');
    if (options.executionAttemptId !== null || cost !== 0n) {
      throw new Error('pre-execution cancellation must have no attempt and zero execution cost');
    }
  } else if (options.reason === 'failed_after_start') {
    if (reservation.state !== 'executing') throw new Error('reservation must be executing');
    if (reservation.executionAttemptId !== options.executionAttemptId) {
      throw new Error('execution attempt does not match reservation');
    }
    if (cost > toAtomic(reservation.quote.maxExecutionCostAtomic)) {
      throw new Error('execution cost exceeds quote maximum');
    }
    allocation = deepFreeze(allocateInternalFailureGross({ executionCostAtomic: cost }));
  } else {
    throw new Error('unsupported reservation release reason');
  }
  const reservedAmount = toAtomic(reservation.reservedAtomic);
  const released = reservedAmount - cost;
  const nextBudget = replaceBudget(budget, {
    reservedAtomic: fromAtomic(toAtomic(budget.reservedAtomic) - reservedAmount),
    consumedAtomic: fromAtomic(toAtomic(budget.consumedAtomic) + cost),
    releasedAtomic: fromAtomic(toAtomic(budget.releasedAtomic) + released),
    revision: budget.revision + 1,
  });
  const nextReservation = replaceReservation(reservation, {
    state: 'released',
    revision: reservation.revision + 1,
    finalizedAt: options.now,
  });
  const journalEntries = allocation ? serializeJournalEntries(allocation.journalEntries) : [];
  return deepFreeze({
    budget: nextBudget,
    reservation: nextReservation,
    allocation,
    event: event('budget_released', nextReservation, nextBudget, options.now, {
      reason: options.reason,
      executionCostAtomic: options.executionCostAtomic,
      releasedAtomic: fromAtomic(released),
      journalEntries,
    }),
  });
}

export function holdUnresolvedReservation(budgetInput, reservationInput, options) {
  const budget = validateBudgetState(budgetInput);
  const reservation = validateReservation(reservationInput);
  requireExecuting(budget, reservation, options);
  parseUtc(options.now, 'now');
  if (!['executor_threw', 'malformed_outcome', 'cost_unknown'].includes(options.reason)) {
    throw new Error('unsupported unresolved reason');
  }
  const nextBudget = replaceBudget(budget, { revision: budget.revision + 1 });
  const nextReservation = replaceReservation(reservation, {
    state: 'held_unresolved',
    revision: reservation.revision + 1,
    finalizedAt: options.now,
  });
  return deepFreeze({
    budget: nextBudget,
    reservation: nextReservation,
    event: event('execution_cost_unresolved', nextReservation, nextBudget, options.now, {
      reason: options.reason,
      heldAtomic: reservation.reservedAtomic,
      executionCostStatus: 'unresolved',
    }),
  });
}

export const BUDGET_SCHEMAS = deepFreeze({
  EmployerBudgetAuthorizationV1: BUDGET_AUTHORIZATION_KEYS,
  BudgetStateV1: BUDGET_STATE_KEYS,
  ReservationV1: RESERVATION_KEYS,
});

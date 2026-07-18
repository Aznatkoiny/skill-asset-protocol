import { createPublicKey } from 'node:crypto';

import {
  createBudget,
  finalizeReservation,
  holdUnresolvedReservation,
  releaseReservation,
  remainingAtomic,
  reserveBudget,
  startReservationExecution,
} from './budget.mjs';
import {
  canonicalCredentialBytes,
  verifyCredential,
  verifyManagerApproval,
} from './credentials.mjs';
import {
  cloneFrozen,
  deepFreeze,
  fromAtomic,
  parseExecutorOutcome,
  parseUtc,
  requireExactKeys,
  toAtomic,
  validatePolicy,
  validateQuote,
} from './schema.mjs';

const TRUSTED_ENGINE_STATES = new WeakSet();

const CREATE_STATE_KEYS = [
  'signedBudget', 'policies', 'financeSigners', 'managerSigners',
  'credentialAuthorizers', 'now',
];
const AUTHORIZE_KEYS = [
  'store', 'quote', 'expectedRevision', 'expectedBudgetRevision', 'reservationId',
  'credentialNonce', 'credentialIssuedAt', 'credentialExpiresAt',
  'credentialAuthorizerId', 'managerApproval', 'now',
];
const CANCEL_KEYS = ['store', 'expectedRevision', 'reservationId', 'reason', 'now'];
const EXECUTE_KEYS = ['store', 'quote', 'credential', 'executor', 'now'];
const ENGINE_STATE_KEYS = [
  'revision', 'budget', 'policies', 'financeSigners', 'managerSigners',
  'credentialAuthorizers', 'invocations', 'reservations', 'awards',
  'consumedNonces', 'issuedNonces', 'idempotency', 'events', 'nextReceiptSequence',
];

function requirePlainMap(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
  return value;
}

function validateTrustMap(mapInput, allowedIds, label) {
  const map = requirePlainMap(mapInput, label);
  const allowed = new Set(allowedIds);
  for (const id of allowed) {
    if (typeof map[id] !== 'string' || map[id].length === 0) {
      throw new Error(`missing trusted ${label.slice(0, -1)} ${id}`);
    }
  }
  for (const [id, key] of Object.entries(map)) {
    if (!allowed.has(id)) throw new Error(`unexpected ${label.slice(0, -1)} ${id}`);
    try {
      createPublicKey(key);
    } catch {
      throw new Error(`invalid public key for ${label.slice(0, -1)} ${id}`);
    }
  }
  return cloneFrozen(map);
}

function markTrusted(state) {
  const frozen = deepFreeze(state);
  TRUSTED_ENGINE_STATES.add(frozen);
  return frozen;
}

function assertTrustedState(state, now) {
  if (!TRUSTED_ENGINE_STATES.has(state)) {
    throw new Error('engine state was not created by the trusted engine boundary');
  }
  requireExactKeys(state, ENGINE_STATE_KEYS, 'engine state');
  const policyKey = `${state.budget.policyId}@${state.budget.policyVersion}`;
  const policy = validatePolicy(state.policies[policyKey], now);
  const verified = createBudget(state.budget.authorization, {
    trustedFinanceSigners: state.financeSigners,
    policy,
    now,
  });
  for (const key of [
    'budgetId', 'policyId', 'policyVersion', 'period', 'currency', 'atomicScale',
    'allocatedAtomic',
  ]) {
    if (state.budget[key] !== verified[key]) throw new Error(`budget state changed signed ${key}`);
  }
  remainingAtomic(state.budget);
  return policy;
}

function nextState(state, changes) {
  return markTrusted({ ...state, ...changes, revision: state.revision + 1 });
}

function mapWith(map, key, value) {
  return deepFreeze({ ...map, [key]: value });
}

function invocationEvent(type, invocationId, occurredAt, details = {}) {
  return deepFreeze({
    schemaVersion: 1,
    eventId: `${invocationId}:${type}:${occurredAt}`,
    type,
    invocationId,
    occurredAt,
    ...details,
  });
}

function effectiveCredentialExpiry(requested, quote, policy, budget) {
  const candidates = [
    requested,
    quote.expiresAt,
    policy.expiresAt,
    budget.authorization.expiresAt,
  ];
  for (const [index, candidate] of candidates.entries()) parseUtc(candidate, `credential bound ${index}`);
  return candidates.reduce((earliest, candidate) => (
    parseUtc(candidate, 'credential bound') < parseUtc(earliest, 'credential bound')
      ? candidate
      : earliest
  ));
}

function assertCredentialNonce(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error('credential nonce must be lowercase 64-character hex without 0x');
  }
}

function compareQuote(left, right) {
  if (JSON.stringify(left) !== JSON.stringify(right)) {
    throw new Error('quote does not match persisted authorization');
  }
}

function awardExposureAtomic(state, policy, period) {
  let exposure = 0n;
  // V1 has no automated reversal API, so every recorded award remains in exposure.
  for (const award of Object.values(state.awards)) {
    if (award.policyId === policy.policyId
        && award.policyVersion === policy.version
        && award.period === period) {
      exposure += toAtomic(award.amountAtomic);
    }
  }
  for (const invocation of Object.values(state.invocations)) {
    if (invocation.policyId === policy.policyId
        && invocation.policyVersion === policy.version
        && invocation.period === period
        && ['authorized', 'executing', 'unresolved'].includes(invocation.state)) {
      exposure += toAtomic(invocation.maxInvocationAwardAtomic);
    }
  }
  return exposure;
}

function jsonAllocation(allocation) {
  if (!allocation) return null;
  return deepFreeze({
    grossAtomic: fromAtomic(allocation.grossAtomic),
    executionCostAtomic: fromAtomic(allocation.executionCostAtomic),
    protocolFeeAtomic: fromAtomic(allocation.protocolFeeAtomic),
    refundReserveAtomic: fromAtomic(allocation.refundReserveAtomic),
    invocationAwardAtomic: fromAtomic(allocation.invocationAwardAtomic),
    awardCredit: {
      recipientId: allocation.awardCredit.recipientId,
      amountAtomic: fromAtomic(allocation.awardCredit.amountAtomic),
    },
    journalEntries: allocation.journalEntries.map((entry) => ({
      category: entry.category,
      debitAccountId: entry.debitAccountId,
      creditAccountId: entry.creditAccountId,
      amountAtomic: fromAtomic(entry.amountAtomic),
    })),
  });
}

export function createEngineState(input) {
  requireExactKeys(input, CREATE_STATE_KEYS, 'engine configuration');
  const rawPolicies = requirePlainMap(input.policies, 'policies');
  if (Object.keys(rawPolicies).length === 0) throw new Error('at least one policy is required');
  const policies = {};
  const financeIds = new Set();
  const managerIds = new Set();
  const authorizerIds = new Set();
  for (const [key, rawPolicy] of Object.entries(rawPolicies)) {
    const validated = validatePolicy(rawPolicy, input.now);
    if (key !== `${validated.policyId}@${validated.version}`) {
      throw new Error(`policy map key ${key} does not match policy identity`);
    }
    policies[key] = validated;
    for (const id of validated.permittedFinanceSignerIds) financeIds.add(id);
    for (const id of validated.permittedManagerSignerIds) managerIds.add(id);
    for (const id of validated.permittedCredentialAuthorizerIds) authorizerIds.add(id);
  }
  const frozenPolicies = cloneFrozen(policies);
  const financeSigners = validateTrustMap(input.financeSigners, financeIds, 'finance signers');
  const managerSigners = validateTrustMap(input.managerSigners, managerIds, 'manager signers');
  const credentialAuthorizers = validateTrustMap(
    input.credentialAuthorizers,
    authorizerIds,
    'credential authorizers',
  );
  const policy = frozenPolicies[`${input.signedBudget.policyId}@${input.signedBudget.policyVersion}`];
  if (!policy) throw new Error('signed budget policy is not provisioned');
  const budget = createBudget(input.signedBudget, {
    trustedFinanceSigners: financeSigners,
    policy,
    now: input.now,
  });
  return markTrusted({
    revision: 0,
    budget,
    policies: frozenPolicies,
    financeSigners,
    managerSigners,
    credentialAuthorizers,
    invocations: deepFreeze({}),
    reservations: deepFreeze({}),
    awards: deepFreeze({}),
    consumedNonces: deepFreeze({}),
    issuedNonces: deepFreeze({}),
    idempotency: deepFreeze({}),
    events: deepFreeze([]),
    nextReceiptSequence: 1,
  });
}

export async function authorizeInternalInvocation(input) {
  requireExactKeys(input, AUTHORIZE_KEYS, 'authorization input');
  const beforeCount = input.store.snapshot().events.length;
  const state = await input.store.transact(input.expectedRevision, (current) => {
    const policyKey = `${input.quote.policyId}@${input.quote.policyVersion}`;
    const trustedPolicy = assertTrustedState(current, input.now);
    const policy = current.policies[policyKey];
    if (!policy || policy !== trustedPolicy) {
      // Object identity is stable because createEngineState freezes the same policy instance.
      if (!policy) throw new Error('quote policy is not provisioned');
    }
    const validatedPolicy = validatePolicy(policy, input.now);
    const quote = validateQuote(input.quote, validatedPolicy, input.now);
    if (current.budget.policyId !== quote.policyId
        || current.budget.policyVersion !== quote.policyVersion
        || current.budget.period !== String(input.now).slice(0, 7)) {
      throw new Error('quote is outside the active employer budget');
    }
    if (current.budget.revision !== input.expectedBudgetRevision) {
      throw new Error(
        `stale budget revision: expected ${input.expectedBudgetRevision}, received ${current.budget.revision}`,
      );
    }
    if (Object.hasOwn(current.idempotency, quote.idempotencyKey)) {
      throw new Error('idempotency key already bound');
    }
    if (Object.hasOwn(current.invocations, quote.invocationId)) {
      throw new Error('Invocation identifier already exists');
    }
    if (Object.hasOwn(current.reservations, input.reservationId)) {
      throw new Error('reservation identifier already exists');
    }
    assertCredentialNonce(input.credentialNonce);
    if (Object.hasOwn(current.issuedNonces, input.credentialNonce)) {
      throw new Error('credential nonce already issued');
    }
    if (!validatedPolicy.permittedCredentialAuthorizerIds.includes(input.credentialAuthorizerId)) {
      throw new Error('credential authorizer is not permitted by policy');
    }
    if (!current.credentialAuthorizers[input.credentialAuthorizerId]) {
      throw new Error('credential authorizer is not provisioned');
    }

    const isSelfInvocation = quote.creatorId === quote.wielderId;
    if (isSelfInvocation) {
      if (validatedPolicy.selfInvocation === 'excluded') {
        throw new Error('self Invocation is excluded by policy');
      }
      if (input.managerApproval === null) throw new Error('manager approval is required for self Invocation');
      verifyManagerApproval(input.managerApproval, {
        policy: validatedPolicy,
        quote,
        managerSigners: current.managerSigners,
        now: input.now,
      });
    } else if (input.managerApproval !== null) {
      throw new Error('manager approval must be separate and null for non-self Invocation');
    }

    const requestedExpiry = parseUtc(input.credentialExpiresAt, 'credential expiresAt');
    const issuedAt = parseUtc(input.credentialIssuedAt, 'credential issuedAt');
    const at = parseUtc(input.now, 'now');
    if (issuedAt > at) throw new Error('credential issuedAt cannot be in the future');
    const earliestIssue = Math.max(
      parseUtc(validatedPolicy.effectiveAt, 'policy effectiveAt'),
      parseUtc(current.budget.authorization.effectiveAt, 'budget effectiveAt'),
    );
    if (issuedAt < earliestIssue) {
      throw new Error('credential issuedAt precedes the effective policy or budget');
    }
    if (requestedExpiry <= issuedAt || requestedExpiry <= at) {
      throw new Error('credential expiry must follow issuance and authorization');
    }
    const expiresAt = effectiveCredentialExpiry(
      input.credentialExpiresAt,
      quote,
      validatedPolicy,
      current.budget,
    );
    if (parseUtc(expiresAt, 'credential expiresAt') <= issuedAt) {
      throw new Error('effective credential expiry does not follow issuance');
    }

    const prospectiveExposure = awardExposureAtomic(current, validatedPolicy, current.budget.period)
      + toAtomic(quote.maxInvocationAwardAtomic);
    if (prospectiveExposure > toAtomic(validatedPolicy.maxAwardPerPeriodAtomic)) {
      throw new Error('period award cap would be exceeded');
    }
    const reserved = reserveBudget(current.budget, quote, {
      expectedRevision: input.expectedBudgetRevision,
      reservationId: input.reservationId,
      now: input.now,
    });
    const credentialPayload = deepFreeze({
      schemaVersion: 1,
      credentialAuthorizerId: input.credentialAuthorizerId,
      invocationId: quote.invocationId,
      reservationId: input.reservationId,
      idempotencyKey: quote.idempotencyKey,
      skillId: quote.skillId,
      skillVersionHash: quote.skillVersionHash,
      policyId: quote.policyId,
      policyVersion: quote.policyVersion,
      nonce: input.credentialNonce,
      issuedAt: input.credentialIssuedAt,
      expiresAt,
    });
    const invocation = deepFreeze({
      schemaVersion: 1,
      invocationId: quote.invocationId,
      idempotencyKey: quote.idempotencyKey,
      quoteId: quote.quoteId,
      reservationId: input.reservationId,
      skillId: quote.skillId,
      skillVersionHash: quote.skillVersionHash,
      creatorId: quote.creatorId,
      wielderId: quote.wielderId,
      beneficiaryId: quote.beneficiaryId,
      costCenter: quote.costCenter,
      policyId: quote.policyId,
      policyVersion: quote.policyVersion,
      period: current.budget.period,
      currency: current.budget.currency,
      atomicScale: current.budget.atomicScale,
      state: 'authorized',
      revision: 0,
      credentialPayload,
      credentialNonce: input.credentialNonce,
      credentialIssuedAt: input.credentialIssuedAt,
      credentialExpiresAt: expiresAt,
      executionAttemptId: null,
      authorizedAt: input.now,
      startedAt: null,
      finalizedAt: null,
      executionCostStatus: null,
      executionCostAtomic: null,
      protocolFeeAtomic: '0',
      refundReserveAtomic: '0',
      maxInvocationAwardAtomic: quote.maxInvocationAwardAtomic,
      invocationAwardAtomic: '0',
      releasedAtomic: '0',
      heldReservationAtomic: '0',
      awardId: null,
      outputHash: null,
      failureClass: null,
      unresolvedReason: null,
      externalRoyaltyCreditsAtomic: '0',
      employerSelfCreditAtomic: '0',
      journalEntries: deepFreeze([]),
      receiptSequence: null,
    });
    const lifecycleEvents = [
      invocationEvent('invocation_requested', quote.invocationId, input.now),
      invocationEvent('invocation_quoted', quote.invocationId, input.now, { quoteId: quote.quoteId }),
      reserved.event,
      invocationEvent('invocation_authorized', quote.invocationId, input.now, {
        reservationId: input.reservationId,
        credentialAuthorizerId: input.credentialAuthorizerId,
      }),
    ];
    return nextState(current, {
      budget: reserved.budget,
      invocations: mapWith(current.invocations, quote.invocationId, invocation),
      reservations: mapWith(current.reservations, input.reservationId, reserved.reservation),
      issuedNonces: mapWith(current.issuedNonces, input.credentialNonce, {
        invocationId: quote.invocationId,
        reservationId: input.reservationId,
      }),
      idempotency: mapWith(current.idempotency, quote.idempotencyKey, {
        invocationId: quote.invocationId,
        reservationId: input.reservationId,
        quoteId: quote.quoteId,
      }),
      events: deepFreeze([...current.events, ...lifecycleEvents]),
    });
  });
  const invocation = state.invocations[input.quote.invocationId];
  const reservation = state.reservations[input.reservationId];
  return deepFreeze({
    state,
    budget: state.budget,
    invocation,
    reservation,
    credentialPayload: invocation?.credentialPayload ?? null,
    events: deepFreeze(state.events.slice(beforeCount)),
  });
}

export async function cancelInternalAuthorization(input) {
  requireExactKeys(input, CANCEL_KEYS, 'cancellation input');
  if (typeof input.reason !== 'string' || input.reason.length === 0) {
    throw new Error('cancellation reason must be non-empty');
  }
  const beforeCount = input.store.snapshot().events.length;
  const state = await input.store.transact(input.expectedRevision, (current) => {
    assertTrustedState(current, input.now);
    const reservation = current.reservations[input.reservationId];
    if (!reservation) throw new Error('reservation does not exist');
    const invocation = current.invocations[reservation.quote.invocationId];
    if (!invocation || invocation.state !== 'authorized') throw new Error('Invocation is not authorized');
    const released = releaseReservation(current.budget, reservation, {
      expectedBudgetRevision: current.budget.revision,
      expectedReservationRevision: reservation.revision,
      executionAttemptId: null,
      executionCostAtomic: '0',
      reason: 'cancelled_before_start',
      now: input.now,
    });
    const cancelled = deepFreeze({
      ...invocation,
      state: 'cancelled',
      revision: invocation.revision + 1,
      finalizedAt: input.now,
      releasedAtomic: reservation.reservedAtomic,
      receiptSequence: current.nextReceiptSequence,
    });
    return nextState(current, {
      budget: released.budget,
      reservations: mapWith(current.reservations, input.reservationId, released.reservation),
      invocations: mapWith(current.invocations, invocation.invocationId, cancelled),
      events: deepFreeze([
        ...current.events,
        released.event,
        invocationEvent('invocation_cancelled', invocation.invocationId, input.now, {
          reason: input.reason,
        }),
      ]),
      nextReceiptSequence: current.nextReceiptSequence + 1,
    });
  });
  const reservation = state.reservations[input.reservationId];
  return deepFreeze({
    state,
    budget: state.budget,
    reservation,
    invocation: state.invocations[reservation.quote.invocationId],
    events: deepFreeze(state.events.slice(beforeCount)),
  });
}

export async function executeAuthorizedInvocation(input) {
  requireExactKeys(input, EXECUTE_KEYS, 'execution input');
  if (typeof input.executor !== 'function') throw new Error('executor must be an injected function');
  const initial = input.store.snapshot();
  const beforeCount = initial.events.length;
  const started = await input.store.transact(initial.revision, (current) => {
    const policy = assertTrustedState(current, input.now);
    const quote = validateQuote(input.quote, policy, input.now);
    const invocation = current.invocations[quote.invocationId];
    if (!invocation) throw new Error('Invocation has no persisted authorization');
    const reservation = current.reservations[invocation.reservationId];
    if (!reservation) throw new Error('Invocation has no persisted reservation');
    if (Object.hasOwn(current.consumedNonces, invocation.credentialNonce)) {
      throw new Error('credential already consumed');
    }
    if (invocation.state !== 'authorized') throw new Error('Invocation is not authorized');
    if (reservation.state !== 'reserved') throw new Error('reservation must be reserved');
    compareQuote(quote, reservation.quote);
    const authorizerId = input.credential?.credentialAuthorizerId;
    if (typeof authorizerId !== 'string'
        || !policy.permittedCredentialAuthorizerIds.includes(authorizerId)) {
      throw new Error('credential authorizer is not permitted by policy');
    }
    const trustedKey = current.credentialAuthorizers[authorizerId];
    if (!trustedKey) throw new Error('credential authorizer is not provisioned');
    const credentialPayload = verifyCredential(input.credential, trustedKey, input.now);
    const expectedPayload = invocation.credentialPayload;
    if (!Buffer.from(canonicalCredentialBytes(credentialPayload))
      .equals(Buffer.from(canonicalCredentialBytes(expectedPayload)))) {
      throw new Error('credential does not match persisted authorization');
    }
    const executionAttemptId = `attempt-${invocation.invocationId}-${invocation.credentialNonce}`;
    const execution = startReservationExecution(current.budget, reservation, {
      expectedBudgetRevision: current.budget.revision,
      expectedReservationRevision: reservation.revision,
      executionAttemptId,
      now: input.now,
    });
    const executingInvocation = deepFreeze({
      ...invocation,
      state: 'executing',
      revision: invocation.revision + 1,
      executionAttemptId,
      startedAt: input.now,
    });
    return nextState(current, {
      budget: execution.budget,
      reservations: mapWith(current.reservations, reservation.reservationId, execution.reservation),
      invocations: mapWith(current.invocations, invocation.invocationId, executingInvocation),
      consumedNonces: mapWith(current.consumedNonces, invocation.credentialNonce, {
        invocationId: invocation.invocationId,
        reservationId: reservation.reservationId,
        executionAttemptId,
        consumedAt: input.now,
      }),
      events: deepFreeze([
        ...current.events,
        execution.event,
        invocationEvent('invocation_executing', invocation.invocationId, input.now, {
          executionAttemptId,
        }),
      ]),
    });
  });

  const startedInvocation = started.invocations[input.quote.invocationId];
  const startedReservation = started.reservations[startedInvocation.reservationId];
  let rawOutcome;
  try {
    rawOutcome = await input.executor(cloneFrozen({
      invocationId: startedInvocation.invocationId,
      reservationId: startedReservation.reservationId,
      executionAttemptId: startedInvocation.executionAttemptId,
      skillId: startedInvocation.skillId,
      skillVersionHash: startedInvocation.skillVersionHash,
    }));
  } catch {
    rawOutcome = { kind: 'unresolved_after_start', reason: 'executor_threw' };
  }
  const outcome = parseExecutorOutcome(rawOutcome, startedReservation.quote);
  let resultAllocation = null;
  const finalized = await input.store.transactRecord({
    invocationId: startedInvocation.invocationId,
    expectedInvocationRevision: startedInvocation.revision,
    reservationId: startedReservation.reservationId,
    expectedReservationRevision: startedReservation.revision,
    executionAttemptId: startedInvocation.executionAttemptId,
  }, (current, { invocation, reservation }) => {
    if (!TRUSTED_ENGINE_STATES.has(current)) {
      throw new Error('engine state was not created by the trusted engine boundary');
    }
    let money;
    let terminalInvocation;
    let award = null;
    const receiptSequence = current.nextReceiptSequence;
    if (outcome.kind === 'succeeded') {
      const gross = toAtomic(outcome.executionCostAtomic)
        + toAtomic(reservation.quote.protocolFeeAtomic)
        + toAtomic(reservation.quote.refundReserveAtomic)
        + toAtomic(reservation.quote.maxInvocationAwardAtomic);
      money = finalizeReservation(current.budget, reservation, {
        expectedBudgetRevision: current.budget.revision,
        expectedReservationRevision: reservation.revision,
        executionAttemptId: invocation.executionAttemptId,
        grossAtomic: fromAtomic(gross),
        executionCostAtomic: outcome.executionCostAtomic,
        protocolFeeAtomic: reservation.quote.protocolFeeAtomic,
        refundReserveAtomic: reservation.quote.refundReserveAtomic,
        recipientId: invocation.creatorId,
        now: input.now,
      });
      resultAllocation = jsonAllocation(money.allocation);
      const awardState = current.policies[`${invocation.policyId}@${invocation.policyVersion}`].vestingRule === 'none'
        ? 'earned'
        : 'vesting_pending';
      award = deepFreeze({
        schemaVersion: 1,
        awardId: `award-${invocation.invocationId}`,
        invocationId: invocation.invocationId,
        recipientId: invocation.creatorId,
        policyId: invocation.policyId,
        policyVersion: invocation.policyVersion,
        period: invocation.period,
        currency: invocation.currency,
        atomicScale: invocation.atomicScale,
        amountAtomic: resultAllocation.invocationAwardAtomic,
        state: awardState,
        measuredAt: input.now,
        earnedAt: awardState === 'earned' ? input.now : null,
        payableAt: null,
        paidAt: null,
      });
      terminalInvocation = deepFreeze({
        ...invocation,
        state: 'succeeded',
        revision: invocation.revision + 1,
        finalizedAt: input.now,
        executionCostStatus: 'known',
        executionCostAtomic: outcome.executionCostAtomic,
        protocolFeeAtomic: reservation.quote.protocolFeeAtomic,
        refundReserveAtomic: reservation.quote.refundReserveAtomic,
        invocationAwardAtomic: resultAllocation.invocationAwardAtomic,
        releasedAtomic: money.event.releasedUnusedAtomic,
        awardId: award.awardId,
        outputHash: outcome.outputHash,
        journalEntries: resultAllocation.journalEntries,
        receiptSequence,
      });
    } else if (outcome.kind === 'failed_after_start') {
      money = releaseReservation(current.budget, reservation, {
        expectedBudgetRevision: current.budget.revision,
        expectedReservationRevision: reservation.revision,
        executionAttemptId: invocation.executionAttemptId,
        executionCostAtomic: outcome.executionCostAtomic,
        reason: 'failed_after_start',
        now: input.now,
      });
      terminalInvocation = deepFreeze({
        ...invocation,
        state: 'failed',
        revision: invocation.revision + 1,
        finalizedAt: input.now,
        executionCostStatus: 'known',
        executionCostAtomic: outcome.executionCostAtomic,
        releasedAtomic: money.event.releasedAtomic,
        failureClass: outcome.failureClass,
        receiptSequence,
      });
    } else {
      money = holdUnresolvedReservation(current.budget, reservation, {
        expectedBudgetRevision: current.budget.revision,
        expectedReservationRevision: reservation.revision,
        executionAttemptId: invocation.executionAttemptId,
        reason: outcome.reason,
        now: input.now,
      });
      terminalInvocation = deepFreeze({
        ...invocation,
        state: 'unresolved',
        revision: invocation.revision + 1,
        finalizedAt: input.now,
        executionCostStatus: 'unresolved',
        executionCostAtomic: null,
        heldReservationAtomic: reservation.reservedAtomic,
        unresolvedReason: outcome.reason,
        receiptSequence,
      });
    }
    const terminalEvents = [
      money.event,
      invocationEvent(`invocation_${terminalInvocation.state}`, invocation.invocationId, input.now, {
        receiptSequence,
        executionAttemptId: invocation.executionAttemptId,
      }),
    ];
    if (award) {
      terminalEvents.push(invocationEvent('invocation_award_measured', invocation.invocationId, input.now, {
        awardId: award.awardId,
        amountAtomic: award.amountAtomic,
      }));
      if (award.state === 'earned') {
        terminalEvents.push(invocationEvent('invocation_award_earned', invocation.invocationId, input.now, {
          awardId: award.awardId,
          amountAtomic: award.amountAtomic,
        }));
      }
    }
    return nextState(current, {
      budget: money.budget,
      reservations: mapWith(current.reservations, reservation.reservationId, money.reservation),
      invocations: mapWith(current.invocations, invocation.invocationId, terminalInvocation),
      awards: award ? mapWith(current.awards, award.awardId, award) : current.awards,
      events: deepFreeze([...current.events, ...terminalEvents]),
      nextReceiptSequence: receiptSequence + 1,
    });
  });
  const invocation = finalized.invocations[startedInvocation.invocationId];
  const reservation = finalized.reservations[startedReservation.reservationId];
  const award = invocation.awardId ? finalized.awards[invocation.awardId] : null;
  return deepFreeze({
    state: finalized,
    budget: finalized.budget,
    invocation,
    reservation,
    award,
    allocation: resultAllocation,
    events: deepFreeze(finalized.events.slice(beforeCount)),
  });
}

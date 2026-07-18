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
  principalAttestationHash,
  verifyCredential,
  verifyCredentialSignature,
  verifyManagerApproval,
  verifyPrincipalAttestation,
} from './credentials.mjs';
import {
  appendSignedReceipt,
  createReceiptLedgerState,
  receiptSequenceScope,
} from './receipt-ledger.mjs';
import {
  cloneFrozen,
  deepFreeze,
  fromAtomic,
  parseExecutorOutcome,
  parseUtc,
  requireExactKeys,
  skillRegistrationKey,
  toAtomic,
  validatePolicy,
  validateQuote,
  validateSkillRegistration,
} from './schema.mjs';
import {
  buildInvocationReceipt,
  receiptHash,
  signReceiptWithCapability,
  verifyReceipt,
} from './statements.mjs';

const TRUSTED_ENGINE_STATES = new WeakSet();
const ENGINE_CAPABILITIES = new WeakMap();

const CREATE_STATE_KEYS = [
  'signedBudget', 'policies', 'skillRegistrations', 'financeSigners',
  'managerSigners', 'credentialAuthorizers', 'identitySigners', 'receiptSigners',
  'clock', 'receiptSigner',
];
const AUTHORIZE_KEYS = [
  'store', 'quote', 'expectedRevision', 'expectedBudgetRevision', 'reservationId',
  'credentialNonce', 'credentialIssuedAt', 'credentialExpiresAt',
  'credentialAuthorizerId', 'principalAttestation', 'managerApproval',
];
const CANCEL_KEYS = ['store', 'expectedRevision', 'reservationId', 'reason'];
const EXECUTE_KEYS = ['store', 'quote', 'credential', 'executor'];
const ENGINE_STATE_KEYS = [
  'revision', 'budget', 'policies', 'skillRegistrations', 'financeSigners',
  'managerSigners', 'credentialAuthorizers', 'identitySigners', 'receiptSigners',
  'invocations', 'reservations', 'awards', 'consumedNonces', 'issuedNonces',
  'consumedPrincipalNonces', 'idempotency', 'events', 'receipts',
  'receiptHashes', 'receiptSequenceIndex', 'nextReceiptSequences',
];
const TERMINAL_STATES = new Set(['succeeded', 'failed', 'unresolved', 'cancelled']);

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

function provisionCapabilities(input) {
  if (typeof input.clock !== 'function') throw new Error('engine clock must be a function');
  requireExactKeys(input.receiptSigner, ['signerId', 'sign'], 'receipt signer capability');
  if (typeof input.receiptSigner.signerId !== 'string'
      || input.receiptSigner.signerId.length === 0
      || typeof input.receiptSigner.sign !== 'function') {
    throw new Error('receipt signer capability is invalid');
  }
  const capabilities = Object.freeze({
    clock: input.clock,
    receiptSigner: Object.freeze({
      signerId: input.receiptSigner.signerId,
      sign: input.receiptSigner.sign,
    }),
  });
  const now = capabilities.clock();
  parseUtc(now, 'engine clock');
  return { capabilities, now };
}

function markTrusted(state, capabilities) {
  const frozen = deepFreeze(state);
  TRUSTED_ENGINE_STATES.add(frozen);
  ENGINE_CAPABILITIES.set(frozen, capabilities);
  return frozen;
}

function capabilitiesFor(state) {
  if (!TRUSTED_ENGINE_STATES.has(state) || !ENGINE_CAPABILITIES.has(state)) {
    throw new Error('engine state was not created by the trusted engine boundary');
  }
  return ENGINE_CAPABILITIES.get(state);
}

function engineNow(state) {
  const now = capabilitiesFor(state).clock();
  parseUtc(now, 'engine clock');
  return now;
}

function assertTrustedState(state, now) {
  capabilitiesFor(state);
  requireExactKeys(state, ENGINE_STATE_KEYS, 'engine state');
  const policyKey = `${state.budget.policyId}@${state.budget.policyVersion}`;
  const policy = validatePolicy(state.policies[policyKey], now);
  const verified = createBudget(state.budget.authorization, {
    trustedFinanceSigners: state.financeSigners,
    policy,
    now,
  });
  for (const key of [
    'budgetId', 'policyId', 'policyVersion', 'policyHash', 'period', 'currency',
    'atomicScale', 'allocatedAtomic',
  ]) {
    if (state.budget[key] !== verified[key]) throw new Error(`budget state changed signed ${key}`);
  }
  remainingAtomic(state.budget);
  return policy;
}

function nextState(state, changes) {
  return markTrusted(
    { ...state, ...changes, revision: state.revision + 1 },
    capabilitiesFor(state),
  );
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
  for (const [index, candidate] of candidates.entries()) {
    parseUtc(candidate, `credential bound ${index}`);
  }
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

function compareCredentialPayload(left, right) {
  if (!Buffer.from(canonicalCredentialBytes(left))
    .equals(Buffer.from(canonicalCredentialBytes(right)))) {
    throw new Error('credential does not match persisted authorization');
  }
}

function awardExposureAtomic(state, policy, period) {
  let exposure = 0n;
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

function resolveActiveRegistration(state, quote, policy, now) {
  const key = skillRegistrationKey(quote.skillId, quote.skillVersionHash);
  const registration = state.skillRegistrations[key];
  if (!registration) throw new Error('Skill version is not provisioned');
  const active = validateSkillRegistration(registration, now);
  if (active.creatorId !== quote.creatorId) {
    throw new Error('Skill registration Creator does not match quote Creator');
  }
  if (active.employerId !== quote.beneficiaryId || active.employerId !== policy.employerId) {
    throw new Error('Skill registration employer does not match Beneficiary');
  }
  return active;
}

function serializedAllocation(allocation) {
  if (!allocation) return null;
  const result = {
    grossAtomic: fromAtomic(allocation.grossAtomic),
    executionCostAtomic: fromAtomic(allocation.executionCostAtomic),
    journalEntries: allocation.journalEntries.map((entry) => ({
      category: entry.category,
      debitAccountId: entry.debitAccountId,
      creditAccountId: entry.creditAccountId,
      amountAtomic: fromAtomic(entry.amountAtomic),
    })),
  };
  if (Object.hasOwn(allocation, 'protocolFeeAtomic')) {
    Object.assign(result, {
      protocolFeeAtomic: fromAtomic(allocation.protocolFeeAtomic),
      refundReserveAtomic: fromAtomic(allocation.refundReserveAtomic),
      invocationAwardAtomic: fromAtomic(allocation.invocationAwardAtomic),
      awardCredit: {
        recipientId: allocation.awardCredit.recipientId,
        amountAtomic: fromAtomic(allocation.awardCredit.amountAtomic),
      },
    });
  }
  return deepFreeze(result);
}

function receiptLedgerFields(state) {
  return {
    receipts: state.receipts,
    receiptHashes: state.receiptHashes,
    receiptSequenceIndex: state.receiptSequenceIndex,
    nextReceiptSequences: state.nextReceiptSequences,
  };
}

function commitReceipt(state, invocation, reservation, award) {
  const capability = capabilitiesFor(state).receiptSigner;
  const unsigned = buildInvocationReceipt({
    invocation,
    reservation,
    award,
    employerId: invocation.beneficiaryId,
    receiptSignerId: capability.signerId,
  });
  const signedReceipt = signReceiptWithCapability(unsigned, capability);
  verifyReceipt(signedReceipt, { trustedReceiptSigners: state.receiptSigners });
  const hash = receiptHash(signedReceipt);
  const ledger = appendSignedReceipt(receiptLedgerFields(state), { signedReceipt, hash });
  return { signedReceipt, hash, ledger };
}

function allocationFromInvocation(invocation) {
  if (invocation.state === 'succeeded') {
    return deepFreeze({
      grossAtomic: fromAtomic(
        toAtomic(invocation.executionCostAtomic)
        + toAtomic(invocation.protocolFeeAtomic)
        + toAtomic(invocation.refundReserveAtomic)
        + toAtomic(invocation.invocationAwardAtomic),
      ),
      executionCostAtomic: invocation.executionCostAtomic,
      protocolFeeAtomic: invocation.protocolFeeAtomic,
      refundReserveAtomic: invocation.refundReserveAtomic,
      invocationAwardAtomic: invocation.invocationAwardAtomic,
      awardCredit: {
        recipientId: invocation.creatorId,
        amountAtomic: invocation.invocationAwardAtomic,
      },
      journalEntries: invocation.journalEntries,
    });
  }
  if (invocation.state === 'failed') {
    return deepFreeze({
      grossAtomic: invocation.executionCostAtomic,
      executionCostAtomic: invocation.executionCostAtomic,
      journalEntries: invocation.journalEntries,
    });
  }
  return null;
}

function terminalResult(state, invocationId) {
  const invocation = state.invocations[invocationId];
  const reservation = state.reservations[invocation.reservationId];
  const award = invocation.awardId ? state.awards[invocation.awardId] : null;
  return deepFreeze({
    state,
    budget: state.budget,
    invocation,
    reservation,
    award,
    allocation: allocationFromInvocation(invocation),
    receipt: state.receipts[invocation.receiptId],
    receiptHash: invocation.receiptHash,
    events: state.events.filter((event) => event.invocationId === invocationId),
  });
}

function verifyTerminalReplay(state, quote, credential) {
  const invocation = state.invocations[quote.invocationId];
  if (!invocation || !TERMINAL_STATES.has(invocation.state)) return null;
  const reservation = state.reservations[invocation.reservationId];
  compareQuote(quote, reservation.quote);
  const authorizerId = credential?.credentialAuthorizerId;
  const trustedKey = state.credentialAuthorizers[authorizerId];
  if (!trustedKey) throw new Error('credential authorizer is not provisioned');
  compareCredentialPayload(
    verifyCredentialSignature(credential, trustedKey),
    invocation.credentialPayload,
  );
  if (!invocation.receiptId || !invocation.receiptHash) {
    throw new Error('terminal Invocation is missing its committed receipt');
  }
  const signedReceipt = state.receipts[invocation.receiptId];
  verifyReceipt(signedReceipt, { trustedReceiptSigners: state.receiptSigners });
  if (receiptHash(signedReceipt) !== invocation.receiptHash
      || state.receiptHashes[invocation.receiptId] !== invocation.receiptHash) {
    throw new Error('committed receipt hash does not match terminal Invocation');
  }
  return terminalResult(state, invocation.invocationId);
}

export function createEngineState(input) {
  requireExactKeys(input, CREATE_STATE_KEYS, 'engine configuration');
  const { capabilities, now } = provisionCapabilities(input);
  const rawPolicies = requirePlainMap(input.policies, 'policies');
  if (Object.keys(rawPolicies).length === 0) throw new Error('at least one policy is required');
  const policies = {};
  const financeIds = new Set();
  const managerIds = new Set();
  const authorizerIds = new Set();
  const identityIds = new Set();
  for (const [key, rawPolicy] of Object.entries(rawPolicies)) {
    const validated = validatePolicy(rawPolicy, now);
    if (key !== `${validated.policyId}@${validated.version}`) {
      throw new Error(`policy map key ${key} does not match policy identity`);
    }
    policies[key] = validated;
    for (const id of validated.permittedFinanceSignerIds) financeIds.add(id);
    for (const id of validated.permittedManagerSignerIds) managerIds.add(id);
    for (const id of validated.permittedCredentialAuthorizerIds) authorizerIds.add(id);
    for (const id of validated.permittedIdentitySignerIds) identityIds.add(id);
  }
  const frozenPolicies = cloneFrozen(policies);
  const financeSigners = validateTrustMap(input.financeSigners, financeIds, 'finance signers');
  const managerSigners = validateTrustMap(input.managerSigners, managerIds, 'manager signers');
  const credentialAuthorizers = validateTrustMap(
    input.credentialAuthorizers,
    authorizerIds,
    'credential authorizers',
  );
  const identitySigners = validateTrustMap(input.identitySigners, identityIds, 'identity signers');
  const receiptSigners = validateTrustMap(
    input.receiptSigners,
    [capabilities.receiptSigner.signerId],
    'receipt signers',
  );

  const rawRegistrations = requirePlainMap(input.skillRegistrations, 'Skill registrations');
  if (Object.keys(rawRegistrations).length === 0) {
    throw new Error('at least one Skill registration is required');
  }
  const registrations = {};
  for (const [key, rawRegistration] of Object.entries(rawRegistrations)) {
    const registration = validateSkillRegistration(rawRegistration, now, { allowInactive: true });
    if (key !== skillRegistrationKey(registration.skillId, registration.skillVersionHash)) {
      throw new Error(`Skill registration map key ${key} does not match Skill version identity`);
    }
    const compatible = Object.values(frozenPolicies).some((policy) => (
      policy.employerId === registration.employerId
      && policy.permittedSkillIds.includes(registration.skillId)
      && policy.permittedCreatorIds.includes(registration.creatorId)
    ));
    if (!compatible) throw new Error('Skill registration is not compatible with a provisioned policy');
    registrations[key] = registration;
  }
  const skillRegistrations = cloneFrozen(registrations);
  const policy = frozenPolicies[`${input.signedBudget.policyId}@${input.signedBudget.policyVersion}`];
  if (!policy) throw new Error('signed budget policy is not provisioned');
  const budget = createBudget(input.signedBudget, {
    trustedFinanceSigners: financeSigners,
    policy,
    now,
  });
  const receiptLedger = createReceiptLedgerState();
  return markTrusted({
    revision: 0,
    budget,
    policies: frozenPolicies,
    skillRegistrations,
    financeSigners,
    managerSigners,
    credentialAuthorizers,
    identitySigners,
    receiptSigners,
    invocations: deepFreeze({}),
    reservations: deepFreeze({}),
    awards: deepFreeze({}),
    consumedNonces: deepFreeze({}),
    issuedNonces: deepFreeze({}),
    consumedPrincipalNonces: deepFreeze({}),
    idempotency: deepFreeze({}),
    events: deepFreeze([]),
    ...receiptLedger,
  }, capabilities);
}

export async function authorizeInternalInvocation(input) {
  requireExactKeys(input, AUTHORIZE_KEYS, 'authorization input');
  const state = await input.store.transact(input.expectedRevision, (current) => {
    const now = engineNow(current);
    const trustedPolicy = assertTrustedState(current, now);
    const policyKey = `${input.quote.policyId}@${input.quote.policyVersion}`;
    const policy = current.policies[policyKey];
    if (!policy) throw new Error('quote policy is not provisioned');
    if (policyKey !== `${trustedPolicy.policyId}@${trustedPolicy.version}`) {
      throw new Error('quote policy is outside the active employer budget');
    }
    const validatedPolicy = validatePolicy(policy, now);
    const quote = validateQuote(input.quote, validatedPolicy, now);
    const registration = resolveActiveRegistration(current, quote, validatedPolicy, now);
    if (current.budget.policyHash !== quote.policyHash
        || current.budget.period !== now.slice(0, 7)) {
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

    const principal = verifyPrincipalAttestation(input.principalAttestation, {
      policy: validatedPolicy,
      quote,
      identitySigners: current.identitySigners,
      now,
    });
    if (Object.hasOwn(current.consumedPrincipalNonces, principal.nonce)) {
      throw new Error('initiating-principal attestation nonce already consumed');
    }
    const attestationHash = principalAttestationHash(input.principalAttestation);

    const isSelfInvocation = quote.initiatingPrincipalId === quote.creatorId;
    if (isSelfInvocation) {
      if (validatedPolicy.selfInvocation === 'excluded') {
        throw new Error('self Invocation is excluded by policy');
      }
      if (input.managerApproval === null) {
        throw new Error('manager approval is required for self Invocation');
      }
      verifyManagerApproval(input.managerApproval, {
        policy: validatedPolicy,
        quote,
        managerSigners: current.managerSigners,
        now,
      });
    } else if (input.managerApproval !== null) {
      throw new Error('manager approval must be null for non-self Invocation');
    }

    const requestedExpiry = parseUtc(input.credentialExpiresAt, 'credential expiresAt');
    const issuedAt = parseUtc(input.credentialIssuedAt, 'credential issuedAt');
    const at = parseUtc(now, 'engine clock');
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
      now,
    });
    const credentialPayload = deepFreeze({
      schemaVersion: 1,
      credentialAuthorizerId: input.credentialAuthorizerId,
      invocationId: quote.invocationId,
      reservationId: input.reservationId,
      idempotencyKey: quote.idempotencyKey,
      skillId: quote.skillId,
      skillVersionHash: quote.skillVersionHash,
      creatorId: quote.creatorId,
      wielderId: quote.wielderId,
      initiatingPrincipalId: quote.initiatingPrincipalId,
      principalAttestationId: principal.attestationId,
      principalAttestationHash: attestationHash,
      policyId: quote.policyId,
      policyVersion: quote.policyVersion,
      policyHash: quote.policyHash,
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
      skillRegistrationId: registration.registrationId,
      creatorId: quote.creatorId,
      wielderId: quote.wielderId,
      initiatingPrincipalId: quote.initiatingPrincipalId,
      principalAttestationId: principal.attestationId,
      principalAttestationHash: attestationHash,
      principalAttestation: cloneFrozen(input.principalAttestation),
      beneficiaryId: quote.beneficiaryId,
      costCenter: quote.costCenter,
      policyId: quote.policyId,
      policyVersion: quote.policyVersion,
      policyHash: quote.policyHash,
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
      authorizedAt: now,
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
      receiptSequenceScope: null,
      receiptSequence: null,
      receiptId: null,
      receiptHash: null,
    });
    const lifecycleEvents = [
      invocationEvent('invocation_requested', quote.invocationId, now),
      invocationEvent('invocation_quoted', quote.invocationId, now, { quoteId: quote.quoteId }),
      reserved.event,
      invocationEvent('invocation_authorized', quote.invocationId, now, {
        reservationId: input.reservationId,
        skillRegistrationId: registration.registrationId,
        initiatingPrincipalId: principal.principalId,
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
      consumedPrincipalNonces: mapWith(current.consumedPrincipalNonces, principal.nonce, {
        invocationId: quote.invocationId,
        attestationId: principal.attestationId,
        principalId: principal.principalId,
        consumedAt: now,
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
  return deepFreeze({
    state,
    budget: state.budget,
    invocation,
    reservation: state.reservations[input.reservationId],
    credentialPayload: invocation.credentialPayload,
    events: state.events.filter((event) => event.invocationId === invocation.invocationId),
  });
}

export async function cancelInternalAuthorization(input) {
  requireExactKeys(input, CANCEL_KEYS, 'cancellation input');
  if (typeof input.reason !== 'string' || input.reason.length === 0) {
    throw new Error('cancellation reason must be non-empty');
  }
  const state = await input.store.transact(input.expectedRevision, (current) => {
    const now = engineNow(current);
    assertTrustedState(current, now);
    const reservation = current.reservations[input.reservationId];
    if (!reservation) throw new Error('reservation does not exist');
    const invocation = current.invocations[reservation.quote.invocationId];
    if (!invocation || invocation.state !== 'authorized') {
      throw new Error('Invocation is not authorized');
    }
    const released = releaseReservation(current.budget, reservation, {
      expectedBudgetRevision: current.budget.revision,
      expectedReservationRevision: reservation.revision,
      executionAttemptId: null,
      executionCostAtomic: '0',
      reason: 'cancelled_before_start',
      now,
    });
    const scope = receiptSequenceScope({
      employerId: invocation.beneficiaryId,
      creatorId: invocation.creatorId,
      currency: invocation.currency,
      atomicScale: invocation.atomicScale,
    });
    const sequence = current.nextReceiptSequences[scope] ?? 1;
    const receiptId = `receipt-${invocation.invocationId}`;
    const preReceiptInvocation = deepFreeze({
      ...invocation,
      state: 'cancelled',
      revision: invocation.revision + 1,
      finalizedAt: now,
      releasedAtomic: reservation.reservedAtomic,
      receiptSequenceScope: scope,
      receiptSequence: sequence,
      receiptId,
    });
    const committed = commitReceipt(current, preReceiptInvocation, released.reservation, null);
    const cancelled = deepFreeze({
      ...preReceiptInvocation,
      receiptHash: committed.hash,
    });
    return nextState(current, {
      budget: released.budget,
      reservations: mapWith(current.reservations, input.reservationId, released.reservation),
      invocations: mapWith(current.invocations, invocation.invocationId, cancelled),
      events: deepFreeze([
        ...current.events,
        released.event,
        invocationEvent('invocation_cancelled', invocation.invocationId, now, {
          reason: input.reason,
          receiptId,
          receiptHash: committed.hash,
          receiptSequence: sequence,
          receiptSequenceScope: scope,
        }),
      ]),
      ...committed.ledger,
    });
  });
  const reservation = state.reservations[input.reservationId];
  return terminalResult(state, reservation.quote.invocationId);
}

export async function executeAuthorizedInvocation(input) {
  requireExactKeys(input, EXECUTE_KEYS, 'execution input');
  const initial = input.store.snapshot();
  capabilitiesFor(initial);
  const replay = verifyTerminalReplay(initial, input.quote, input.credential);
  if (replay) return replay;
  if (typeof input.executor !== 'function') throw new Error('executor must be an injected function');

  const started = await input.store.transact(initial.revision, (current) => {
    const now = engineNow(current);
    const policy = assertTrustedState(current, now);
    const quote = validateQuote(input.quote, policy, now);
    const invocation = current.invocations[quote.invocationId];
    if (!invocation) throw new Error('Invocation has no persisted authorization');
    if (TERMINAL_STATES.has(invocation.state)) {
      throw new Error('Invocation became terminal; retry execution to read its committed receipt');
    }
    if (invocation.state === 'executing') {
      throw new Error('Invocation execution is already in progress or requires reconciliation');
    }
    const reservation = current.reservations[invocation.reservationId];
    if (!reservation) throw new Error('Invocation has no persisted reservation');
    if (Object.hasOwn(current.consumedNonces, invocation.credentialNonce)) {
      throw new Error('credential already consumed');
    }
    if (invocation.state !== 'authorized') throw new Error('Invocation is not authorized');
    if (reservation.state !== 'reserved') throw new Error('reservation must be reserved');
    compareQuote(quote, reservation.quote);
    const registration = resolveActiveRegistration(current, quote, policy, now);
    if (registration.registrationId !== invocation.skillRegistrationId) {
      throw new Error('persisted Skill registration binding changed');
    }
    verifyPrincipalAttestation(invocation.principalAttestation, {
      policy,
      quote,
      identitySigners: current.identitySigners,
      now,
    });
    if (principalAttestationHash(invocation.principalAttestation)
        !== invocation.principalAttestationHash) {
      throw new Error('persisted initiating-principal attestation hash changed');
    }
    const authorizerId = input.credential?.credentialAuthorizerId;
    if (typeof authorizerId !== 'string'
        || !policy.permittedCredentialAuthorizerIds.includes(authorizerId)) {
      throw new Error('credential authorizer is not permitted by policy');
    }
    const trustedKey = current.credentialAuthorizers[authorizerId];
    if (!trustedKey) throw new Error('credential authorizer is not provisioned');
    compareCredentialPayload(
      verifyCredential(input.credential, trustedKey, now),
      invocation.credentialPayload,
    );
    const executionAttemptId = `attempt-${invocation.invocationId}-${invocation.credentialNonce}`;
    const execution = startReservationExecution(current.budget, reservation, {
      expectedBudgetRevision: current.budget.revision,
      expectedReservationRevision: reservation.revision,
      executionAttemptId,
      now,
    });
    const executingInvocation = deepFreeze({
      ...invocation,
      state: 'executing',
      revision: invocation.revision + 1,
      executionAttemptId,
      startedAt: now,
    });
    return nextState(current, {
      budget: execution.budget,
      reservations: mapWith(current.reservations, reservation.reservationId, execution.reservation),
      invocations: mapWith(current.invocations, invocation.invocationId, executingInvocation),
      consumedNonces: mapWith(current.consumedNonces, invocation.credentialNonce, {
        invocationId: invocation.invocationId,
        reservationId: reservation.reservationId,
        executionAttemptId,
        consumedAt: now,
      }),
      events: deepFreeze([
        ...current.events,
        execution.event,
        invocationEvent('invocation_executing', invocation.invocationId, now, {
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
      skillRegistrationId: startedInvocation.skillRegistrationId,
      initiatingPrincipalId: startedInvocation.initiatingPrincipalId,
      policyHash: startedInvocation.policyHash,
    }));
  } catch {
    rawOutcome = { kind: 'unresolved_after_start', reason: 'executor_threw' };
  }
  const outcome = parseExecutorOutcome(rawOutcome, startedReservation.quote);
  const finalized = await input.store.transactRecord({
    invocationId: startedInvocation.invocationId,
    expectedInvocationRevision: startedInvocation.revision,
    reservationId: startedReservation.reservationId,
    expectedReservationRevision: startedReservation.revision,
    executionAttemptId: startedInvocation.executionAttemptId,
  }, (current, { invocation, reservation }) => {
    capabilitiesFor(current);
    const now = engineNow(current);
    let money;
    let preReceiptInvocation;
    let award = null;
    const scope = receiptSequenceScope({
      employerId: invocation.beneficiaryId,
      creatorId: invocation.creatorId,
      currency: invocation.currency,
      atomicScale: invocation.atomicScale,
    });
    const receiptSequence = current.nextReceiptSequences[scope] ?? 1;
    const receiptId = `receipt-${invocation.invocationId}`;
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
        now,
      });
      const allocation = serializedAllocation(money.allocation);
      const awardState = current.policies[
        `${invocation.policyId}@${invocation.policyVersion}`
      ].vestingRule === 'none' ? 'earned' : 'vesting_pending';
      award = deepFreeze({
        schemaVersion: 1,
        awardId: `award-${invocation.invocationId}`,
        invocationId: invocation.invocationId,
        recipientId: invocation.creatorId,
        policyId: invocation.policyId,
        policyVersion: invocation.policyVersion,
        policyHash: invocation.policyHash,
        period: invocation.period,
        currency: invocation.currency,
        atomicScale: invocation.atomicScale,
        amountAtomic: allocation.invocationAwardAtomic,
        state: awardState,
        measuredAt: now,
        earnedAt: awardState === 'earned' ? now : null,
        payableAt: null,
        paidAt: null,
      });
      preReceiptInvocation = deepFreeze({
        ...invocation,
        state: 'succeeded',
        revision: invocation.revision + 1,
        finalizedAt: now,
        executionCostStatus: 'known',
        executionCostAtomic: outcome.executionCostAtomic,
        protocolFeeAtomic: reservation.quote.protocolFeeAtomic,
        refundReserveAtomic: reservation.quote.refundReserveAtomic,
        invocationAwardAtomic: allocation.invocationAwardAtomic,
        releasedAtomic: money.event.releasedUnusedAtomic,
        awardId: award.awardId,
        outputHash: outcome.outputHash,
        journalEntries: allocation.journalEntries,
        receiptSequenceScope: scope,
        receiptSequence,
        receiptId,
      });
    } else if (outcome.kind === 'failed_after_start') {
      money = releaseReservation(current.budget, reservation, {
        expectedBudgetRevision: current.budget.revision,
        expectedReservationRevision: reservation.revision,
        executionAttemptId: invocation.executionAttemptId,
        executionCostAtomic: outcome.executionCostAtomic,
        reason: 'failed_after_start',
        now,
      });
      const allocation = serializedAllocation(money.allocation);
      preReceiptInvocation = deepFreeze({
        ...invocation,
        state: 'failed',
        revision: invocation.revision + 1,
        finalizedAt: now,
        executionCostStatus: 'known',
        executionCostAtomic: outcome.executionCostAtomic,
        releasedAtomic: money.event.releasedAtomic,
        failureClass: outcome.failureClass,
        journalEntries: allocation.journalEntries,
        receiptSequenceScope: scope,
        receiptSequence,
        receiptId,
      });
    } else {
      money = holdUnresolvedReservation(current.budget, reservation, {
        expectedBudgetRevision: current.budget.revision,
        expectedReservationRevision: reservation.revision,
        executionAttemptId: invocation.executionAttemptId,
        reason: outcome.reason,
        now,
      });
      preReceiptInvocation = deepFreeze({
        ...invocation,
        state: 'unresolved',
        revision: invocation.revision + 1,
        finalizedAt: now,
        executionCostStatus: 'unresolved',
        executionCostAtomic: null,
        heldReservationAtomic: reservation.reservedAtomic,
        unresolvedReason: outcome.reason,
        journalEntries: deepFreeze([]),
        receiptSequenceScope: scope,
        receiptSequence,
        receiptId,
      });
    }

    const committed = commitReceipt(current, preReceiptInvocation, money.reservation, award);
    const terminalInvocation = deepFreeze({
      ...preReceiptInvocation,
      receiptHash: committed.hash,
    });
    const terminalEvents = [
      money.event,
      invocationEvent(`invocation_${terminalInvocation.state}`, invocation.invocationId, now, {
        receiptId,
        receiptHash: committed.hash,
        receiptSequence,
        receiptSequenceScope: scope,
        executionAttemptId: invocation.executionAttemptId,
      }),
    ];
    if (award) {
      terminalEvents.push(invocationEvent('invocation_award_measured', invocation.invocationId, now, {
        awardId: award.awardId,
        amountAtomic: award.amountAtomic,
      }));
      if (award.state === 'earned') {
        terminalEvents.push(invocationEvent('invocation_award_earned', invocation.invocationId, now, {
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
      ...committed.ledger,
    });
  });
  return terminalResult(finalized, startedInvocation.invocationId);
}

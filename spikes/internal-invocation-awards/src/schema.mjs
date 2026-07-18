import { createHash } from 'node:crypto';

export const AWARD_STATES = deepFreeze([
  'measured',
  'vesting_pending',
  'earned',
  'payable',
  'paid',
]);

export const INVOCATION_STATES = deepFreeze([
  'requested',
  'quoted',
  'authorized',
  'executing',
  'succeeded',
  'failed',
  'unresolved',
  'cancelled',
]);

const POLICY_KEYS = [
  'schemaVersion', 'policyId', 'version', 'status', 'currency', 'atomicScale',
  'employerId', 'effectiveAt', 'expiresAt', 'permittedSkillIds',
  'permittedCreatorIds', 'permittedWielderIds', 'permittedInitiatingPrincipalIds',
  'permittedCostCenters',
  'maxQuoteAtomic', 'awardRule', 'maxAwardPerInvocationAtomic',
  'maxAwardPerPeriodAtomic', 'selfInvocation', 'permittedManagerSignerIds',
  'permittedCredentialAuthorizerIds', 'permittedIdentitySignerIds',
  'permittedFinanceSignerIds', 'vestingRule',
  'paymentSchedule', 'terminationTreatment', 'paymentRail',
];

const AWARD_RULE_KEYS = ['type', 'awardRateBps', 'rateBase', 'rounding'];

const QUOTE_KEYS = [
  'schemaVersion', 'quoteId', 'invocationId', 'idempotencyKey', 'skillId',
  'skillVersionHash', 'creatorId', 'wielderId', 'initiatingPrincipalId',
  'principalAttestationId', 'beneficiaryId', 'costCenter', 'policyId',
  'policyVersion', 'policyHash', 'maxExecutionCostAtomic', 'protocolFeeAtomic',
  'refundReserveAtomic', 'maxInvocationAwardAtomic', 'maxGrossAtomic', 'expiresAt',
];

const SHA256_PATTERN = /^sha256:[0-9a-f]{64}$/;

const POLICY_SET_KEYS = new Set([
  'permittedSkillIds', 'permittedCreatorIds', 'permittedWielderIds',
  'permittedInitiatingPrincipalIds', 'permittedCostCenters',
  'permittedManagerSignerIds', 'permittedCredentialAuthorizerIds',
  'permittedIdentitySignerIds', 'permittedFinanceSignerIds',
]);

const SKILL_REGISTRATION_KEYS = [
  'schemaVersion', 'registrationId', 'skillId', 'skillVersionHash', 'creatorId',
  'employerId', 'status', 'effectiveAt', 'expiresAt',
];

export function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const child of Object.values(value)) deepFreeze(child);
  return Object.freeze(value);
}

export function cloneFrozen(value) {
  return deepFreeze(structuredClone(value));
}

export function toAtomic(value) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error('atomic amount must be a non-negative decimal string');
  }
  return BigInt(value);
}

export function fromAtomic(value) {
  if (typeof value !== 'bigint' || value < 0n) {
    throw new Error('atomic amount must be a non-negative bigint');
  }
  return value.toString();
}

export function sumAtomic(values) {
  if (!Array.isArray(values)) throw new Error('atomic values must be an array');
  return values.reduce((sum, value) => sum + toAtomic(value), 0n);
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

function codeUnitSort(values) {
  return [...values].sort((left, right) => {
    if (left < right) return -1;
    if (left > right) return 1;
    return 0;
  });
}

export function canonicalPolicyBytes(policy) {
  requireExactKeys(policy, POLICY_KEYS, 'policy');
  requireExactKeys(policy.awardRule, AWARD_RULE_KEYS, 'awardRule');
  const canonical = {};
  for (const key of POLICY_KEYS) {
    if (key === 'awardRule') {
      canonical[key] = Object.fromEntries(
        AWARD_RULE_KEYS.map((ruleKey) => [ruleKey, policy.awardRule[ruleKey]]),
      );
    } else if (POLICY_SET_KEYS.has(key)) {
      if (!Array.isArray(policy[key])) throw new Error(`${key} must be an array`);
      canonical[key] = codeUnitSort(policy[key]);
    } else {
      canonical[key] = policy[key];
    }
  }
  return new TextEncoder().encode(JSON.stringify(canonical));
}

export function policyHash(policy) {
  return `sha256:${createHash('sha256').update(canonicalPolicyBytes(policy)).digest('hex')}`;
}

function requirePlainObject(value, label) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
}

export function requireExactKeys(value, keys, label) {
  requirePlainObject(value, label);
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${label} has unknown key ${key}`);
  }
  for (const key of keys) {
    if (!Object.hasOwn(value, key)) throw new Error(`${label} is missing key ${key}`);
  }
}

export function parseUtc(value, label) {
  if (typeof value !== 'string') throw new Error(`${label} must be a UTC timestamp`);
  const millis = Date.parse(value);
  if (!Number.isFinite(millis) || new Date(millis).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  return millis;
}

function nowMillis(now) {
  if (now instanceof Date) return now.getTime();
  return parseUtc(now, 'now');
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${label} must be a non-empty string`);
  }
  return value;
}

function requireStringSet(value, label) {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${label} must be a non-empty array`);
  }
  const seen = new Set();
  for (const item of value) {
    requireString(item, `${label} entry`);
    if (seen.has(item)) throw new Error(`${label} contains duplicate ${item}`);
    seen.add(item);
  }
}

function assertPermitted(value, permitted, label) {
  if (!permitted.includes(value)) throw new Error(`${label} is not permitted`);
}

export function validatePolicy(input, now) {
  requireExactKeys(input, POLICY_KEYS, 'policy');
  if (input.schemaVersion !== 1) throw new Error('policy schemaVersion must equal 1');
  requireString(input.policyId, 'policyId');
  if (!Number.isSafeInteger(input.version) || input.version < 1) {
    throw new Error('policy version must be a positive integer');
  }
  if (input.status !== 'active') throw new Error('policy must be active');
  if (typeof input.currency !== 'string' || !/^[A-Z]{3,12}$/.test(input.currency)) {
    throw new Error('policy currency must be an uppercase denomination identifier');
  }
  if (!Number.isSafeInteger(input.atomicScale) || input.atomicScale < 0 || input.atomicScale > 18) {
    throw new Error('policy atomicScale must be an integer from 0 through 18');
  }
  requireString(input.employerId, 'employerId');
  const effectiveAt = parseUtc(input.effectiveAt, 'policy effectiveAt');
  const expiresAt = parseUtc(input.expiresAt, 'policy expiresAt');
  if (expiresAt <= effectiveAt) throw new Error('policy expiresAt must follow effectiveAt');
  const at = nowMillis(now);
  if (at < effectiveAt) throw new Error('policy is not yet effective');
  if (at >= expiresAt) throw new Error('policy expired');

  for (const key of [
    'permittedSkillIds', 'permittedCreatorIds', 'permittedWielderIds',
    'permittedInitiatingPrincipalIds', 'permittedCostCenters',
    'permittedManagerSignerIds', 'permittedCredentialAuthorizerIds',
    'permittedIdentitySignerIds', 'permittedFinanceSignerIds',
  ]) requireStringSet(input[key], key);
  if (input.permittedCreatorIds.includes(input.employerId)) {
    throw new Error('policy employer cannot be a permitted employee-Creator award recipient');
  }

  toAtomic(input.maxQuoteAtomic);
  toAtomic(input.maxAwardPerInvocationAtomic);
  toAtomic(input.maxAwardPerPeriodAtomic);
  if (toAtomic(input.maxAwardPerInvocationAtomic) > toAtomic(input.maxAwardPerPeriodAtomic)) {
    throw new Error('maxAwardPerInvocationAtomic exceeds maxAwardPerPeriodAtomic');
  }

  requireExactKeys(input.awardRule, AWARD_RULE_KEYS, 'awardRule');
  const ruleProblems = [];
  if (input.awardRule.type !== 'residual_after_execution_fee_and_reserve') {
    ruleProblems.push('type must equal residual_after_execution_fee_and_reserve');
  }
  if (input.awardRule.awardRateBps !== 10000) {
    ruleProblems.push('awardRateBps must equal 10000');
  }
  if (input.awardRule.rateBase !== 'post_cost_residual') {
    ruleProblems.push('rateBase must equal post_cost_residual');
  }
  if (input.awardRule.rounding !== 'floor_atomic') {
    ruleProblems.push('rounding must equal floor_atomic');
  }
  if (ruleProblems.length > 0) {
    throw new Error(`unsupported award rule: ${ruleProblems.join('; ')}`);
  }
  if (!['excluded', 'manager_approval_required'].includes(input.selfInvocation)) {
    throw new Error('unsupported selfInvocation policy');
  }
  if (!['none', 'future_policy_controlled'].includes(input.vestingRule)) {
    throw new Error('unsupported vestingRule');
  }
  if (input.paymentSchedule !== 'monthly_in_arrears') {
    throw new Error('paymentSchedule must equal monthly_in_arrears');
  }
  requireString(input.terminationTreatment, 'terminationTreatment');
  requireString(input.paymentRail, 'paymentRail');
  return cloneFrozen(input);
}

export function validateQuote(input, policyInput, now) {
  requireExactKeys(input, QUOTE_KEYS, 'quote');
  const policy = validatePolicy(policyInput, now);
  if (input.schemaVersion !== 1) throw new Error('quote schemaVersion must equal 1');
  for (const key of ['quoteId', 'invocationId', 'idempotencyKey', 'skillId', 'creatorId',
    'wielderId', 'initiatingPrincipalId', 'principalAttestationId', 'beneficiaryId',
    'costCenter', 'policyId']) {
    requireString(input[key], key);
  }
  if (!SHA256_PATTERN.test(input.skillVersionHash)) {
    throw new Error('skillVersionHash must be a lowercase SHA-256 hash');
  }
  if (input.policyId !== policy.policyId || input.policyVersion !== policy.version) {
    throw new Error('quote policy binding does not match effective policy');
  }
  if (input.policyHash !== policyHash(policy)) {
    throw new Error('quote policyHash does not match canonical effective policy');
  }
  assertPermitted(input.skillId, policy.permittedSkillIds, 'Skill');
  assertPermitted(input.creatorId, policy.permittedCreatorIds, 'Creator');
  assertPermitted(input.wielderId, policy.permittedWielderIds, 'Wielder');
  assertPermitted(
    input.initiatingPrincipalId,
    policy.permittedInitiatingPrincipalIds,
    'initiating principal',
  );
  assertPermitted(input.costCenter, policy.permittedCostCenters, 'cost center');
  if (input.beneficiaryId !== policy.employerId) {
    throw new Error('Beneficiary must equal the policy employer');
  }

  const componentNames = [
    'maxExecutionCostAtomic', 'protocolFeeAtomic', 'refundReserveAtomic',
    'maxInvocationAwardAtomic',
  ];
  for (const key of [...componentNames, 'maxGrossAtomic']) toAtomic(input[key]);
  const expectedGross = sumAtomic(componentNames.map((key) => input[key]));
  if (toAtomic(input.maxGrossAtomic) !== expectedGross) {
    throw new Error(`maxGrossAtomic must equal ${expectedGross}`);
  }
  if (toAtomic(input.maxGrossAtomic) > toAtomic(policy.maxQuoteAtomic)) {
    throw new Error('maxGrossAtomic exceeds policy maxQuoteAtomic');
  }
  if (toAtomic(input.maxInvocationAwardAtomic) > toAtomic(policy.maxAwardPerInvocationAtomic)) {
    throw new Error('maxInvocationAwardAtomic exceeds policy cap');
  }
  if (toAtomic(input.maxInvocationAwardAtomic) > 0n
      && (input.creatorId === policy.employerId || input.creatorId === input.beneficiaryId)) {
    throw new Error('employer or Beneficiary cannot receive a positive employee Invocation award');
  }
  const expiry = parseUtc(input.expiresAt, 'quote expiresAt');
  const at = nowMillis(now);
  if (at >= expiry) throw new Error('quote expired');
  if (expiry > parseUtc(policy.expiresAt, 'policy expiresAt')) {
    throw new Error('quote expiry exceeds policy expiry');
  }
  return cloneFrozen(input);
}

export function skillRegistrationKey(skillId, skillVersionHash) {
  requireString(skillId, 'Skill registration skillId');
  if (!SHA256_PATTERN.test(skillVersionHash)) {
    throw new Error('Skill registration version hash must be a lowercase SHA-256 hash');
  }
  return `${skillId}@${skillVersionHash}`;
}

export function validateSkillRegistration(input, now, { allowInactive = false } = {}) {
  requireExactKeys(input, SKILL_REGISTRATION_KEYS, 'Skill registration');
  if (input.schemaVersion !== 1) throw new Error('Skill registration schemaVersion must equal 1');
  for (const key of ['registrationId', 'skillId', 'creatorId', 'employerId']) {
    requireString(input[key], `Skill registration ${key}`);
  }
  skillRegistrationKey(input.skillId, input.skillVersionHash);
  if (!['active', 'revoked'].includes(input.status)) {
    throw new Error('Skill registration status must be active or revoked');
  }
  if (input.creatorId === input.employerId) {
    throw new Error('Skill registration employer cannot be the employee-Creator');
  }
  const effectiveAt = parseUtc(input.effectiveAt, 'Skill registration effectiveAt');
  const expiresAt = parseUtc(input.expiresAt, 'Skill registration expiresAt');
  if (expiresAt <= effectiveAt) throw new Error('Skill registration expiresAt must follow effectiveAt');
  const at = nowMillis(now);
  if (!allowInactive) {
    if (input.status !== 'active') throw new Error('Skill registration is revoked');
    if (at < effectiveAt) throw new Error('Skill registration is not yet effective');
    if (at >= expiresAt) throw new Error('Skill registration expired');
  }
  return cloneFrozen(input);
}

const UNRESOLVED_SENTINEL = deepFreeze({
  kind: 'unresolved_after_start',
  reason: 'malformed_outcome',
});

export function parseExecutorOutcome(value, quote) {
  try {
    requirePlainObject(value, 'executor outcome');
    if (value.kind === 'succeeded') {
      requireExactKeys(value, ['kind', 'executionCostAtomic', 'outputHash'], 'executor outcome');
      if (!SHA256_PATTERN.test(value.outputHash)) throw new Error('invalid outputHash');
      if (toAtomic(value.executionCostAtomic) > toAtomic(quote.maxExecutionCostAtomic)) {
        throw new Error('execution cost exceeds quote');
      }
      return cloneFrozen(value);
    }
    if (value.kind === 'failed_after_start') {
      requireExactKeys(value, ['kind', 'executionCostAtomic', 'failureClass'], 'executor outcome');
      if (!['provider_error', 'skill_error', 'invalid_output'].includes(value.failureClass)) {
        throw new Error('invalid failureClass');
      }
      if (toAtomic(value.executionCostAtomic) > toAtomic(quote.maxExecutionCostAtomic)) {
        throw new Error('execution cost exceeds quote');
      }
      return cloneFrozen(value);
    }
    if (value.kind === 'unresolved_after_start') {
      requireExactKeys(value, ['kind', 'reason'], 'executor outcome');
      if (!['executor_threw', 'malformed_outcome', 'cost_unknown'].includes(value.reason)) {
        throw new Error('invalid unresolved reason');
      }
      return cloneFrozen(value);
    }
    throw new Error('unknown outcome kind');
  } catch {
    return UNRESOLVED_SENTINEL;
  }
}

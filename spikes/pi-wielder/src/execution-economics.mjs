import crypto from 'node:crypto';

import { allocateExternalGross } from '../../../prototype/atomic-money.mjs';

export class ExecutionEconomicsError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ExecutionEconomicsError';
    this.code = code;
  }
}

const fail = (code, message) => { throw new ExecutionEconomicsError(code, message); };

function isPlainObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactPlainObject(value, required, optional, code, label) {
  if (!isPlainObject(value)) fail(code, `${label} must be an exact plain object`);
  const keys = Object.keys(value);
  if (required.some((key) => !keys.includes(key))
      || keys.some((key) => !required.includes(key) && !optional.includes(key))) {
    fail(code, `${label} has missing or unknown fields`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

const frozenCopy = (value) => deepFreeze(structuredClone(value));

export const EXECUTION_CATALOG = deepFreeze({
  schemaVersion: 2,
  version: 'synthetic-anthropic-2026-07-17-v1',
  evidenceLabel: 'synthetic_config',
  source: null,
  asOf: null,
  models: {
    'claude-sonnet-4-6': {
      provider: 'anthropic',
      inputAtomicPerMillionTokens: '3000000',
      outputAtomicPerMillionTokens: '15000000',
      maxInputTokens: 16384,
      maxOutputTokens: 2048,
    },
  },
});

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('TOKEN_INTEGER', `${label} must be a non-negative safe integer`);
  }
  return BigInt(value);
}

function atomic(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d*)$/.test(value)) {
    fail('ATOMIC_FORMAT', `${label} must be a canonical atomic string`);
  }
  return BigInt(value);
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string'
      || !Number.isFinite(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    fail('CATALOG_SCHEMA', `${label} must be one canonical ISO timestamp`);
  }
  return value;
}

const ceilDiv = (numerator, denominator) => (numerator + denominator - 1n) / denominator;

function validateCatalog(input) {
  const catalog = exactPlainObject(input,
    ['schemaVersion', 'version', 'evidenceLabel', 'source', 'asOf', 'models'], [],
    'CATALOG_SCHEMA', 'execution catalog');
  if (catalog.schemaVersion !== 2
      || typeof catalog.version !== 'string' || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(catalog.version)
      || !['synthetic_config', 'human_verified'].includes(catalog.evidenceLabel)
      || !isPlainObject(catalog.models) || Object.keys(catalog.models).length === 0) {
    fail('CATALOG_SCHEMA', 'execution catalog metadata is invalid');
  }
  if (catalog.evidenceLabel === 'synthetic_config') {
    if (catalog.source !== null || catalog.asOf !== null) {
      fail('CATALOG_SCHEMA', 'synthetic catalog source and as-of must remain null');
    }
  } else {
    if (typeof catalog.source !== 'string' || !catalog.source) {
      fail('CATALOG_SCHEMA', 'human-verified catalog requires a source');
    }
    canonicalTimestamp(catalog.asOf, 'catalog as-of');
  }
  for (const [model, policy] of Object.entries(catalog.models)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(model)) {
      fail('CATALOG_SCHEMA', 'catalog model identifier is invalid');
    }
    exactPlainObject(policy, [
      'provider', 'inputAtomicPerMillionTokens', 'outputAtomicPerMillionTokens',
      'maxInputTokens', 'maxOutputTokens',
    ], [], 'CATALOG_SCHEMA', `catalog model '${model}'`);
    if (typeof policy.provider !== 'string' || !policy.provider
        || integer(policy.maxInputTokens, 'catalog maxInputTokens') <= 0n
        || integer(policy.maxOutputTokens, 'catalog maxOutputTokens') <= 0n
        || atomic(policy.inputAtomicPerMillionTokens, 'catalog input rate') <= 0n
        || atomic(policy.outputAtomicPerMillionTokens, 'catalog output rate') <= 0n) {
      fail('CATALOG_SCHEMA', `catalog model '${model}' has invalid limits or rates`);
    }
  }
  return catalog;
}

function modelPolicy(model, catalog = EXECUTION_CATALOG) {
  const validated = validateCatalog(catalog);
  if (typeof model !== 'string') fail('MODEL_NOT_ALLOWED', 'model must be a catalog identifier');
  const policy = validated.models[model];
  if (!policy) fail('MODEL_NOT_ALLOWED', `model '${model}' is not in pricing catalog '${validated.version}'`);
  return policy;
}

function normalizeUsage(input) {
  const usage = exactPlainObject(input,
    ['schemaVersion', 'model', 'inputTokens', 'outputTokens'], [],
    'USAGE_SCHEMA', 'provider usage');
  if (usage.schemaVersion !== 2 || typeof usage.model !== 'string') {
    fail('USAGE_SCHEMA', 'provider usage must use strict schema version 2');
  }
  integer(usage.inputTokens, 'inputTokens');
  integer(usage.outputTokens, 'outputTokens');
  return {
    schemaVersion: 2,
    model: usage.model,
    inputTokens: usage.inputTokens,
    outputTokens: usage.outputTokens,
  };
}

export function usageCostAtomic(input, catalog = EXECUTION_CATALOG) {
  const usage = normalizeUsage(input);
  const policy = modelPolicy(usage.model, catalog);
  const inputCost = ceilDiv(
    integer(usage.inputTokens, 'inputTokens') * atomic(policy.inputAtomicPerMillionTokens, 'input rate'),
    1_000_000n,
  );
  const outputCost = ceilDiv(
    integer(usage.outputTokens, 'outputTokens') * atomic(policy.outputAtomicPerMillionTokens, 'output rate'),
    1_000_000n,
  );
  return inputCost + outputCost;
}

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

const hash = (value) => `sha256:${crypto.createHash('sha256')
  .update(JSON.stringify(canonicalize(value)))
  .digest('hex')}`;

export function artifactDigest(content) {
  if (typeof content !== 'string') fail('ARTIFACT_SCHEMA', 'Skill artifact must be exact string bytes');
  return `sha256:${crypto.createHash('sha256').update(content).digest('hex')}`;
}

export const royaltyGraphDigest = (skills) => hash(skills);

export function catalogDigest(catalog) {
  return hash(validateCatalog(catalog));
}

export function assertLiveCatalogApproval(input) {
  const captured = exactPlainObject(input, ['catalog', 'approval', 'grossAtomic'], [],
    'LIVE_APPROVAL_SHAPE', 'live approval check');
  const catalog = validateCatalog(captured.catalog);
  if (catalog.evidenceLabel !== 'human_verified') {
    fail('LIVE_CATALOG_EVIDENCE', 'live catalog requires human_verified evidence, source, and as-of');
  }
  const approval = exactPlainObject(captured.approval,
    ['catalogDigest', 'spendCapAtomic'], [], 'LIVE_APPROVAL_SHAPE', 'live approval');
  if (typeof approval.catalogDigest !== 'string') {
    fail('LIVE_APPROVAL_SHAPE', 'live catalog digest must be a string');
  }
  const recomputed = catalogDigest(catalog);
  if (approval.catalogDigest !== recomputed) {
    fail('LIVE_CATALOG_DIGEST', 'human-approved digest does not match canonical catalog content');
  }
  const cap = atomic(approval.spendCapAtomic, 'live spend cap');
  const gross = atomic(captured.grossAtomic, 'grossAtomic');
  if (gross > cap) fail('LIVE_SPEND_CAP', 'Invocation gross exceeds the separately approved spend cap');
  return deepFreeze({ catalogDigest: recomputed, spendCapAtomic: cap.toString() });
}

const QUOTE_FIELDS = Object.freeze([
  'schemaVersion', 'quoteId', 'catalogVersion', 'evidenceLabel', 'skillId', 'skillVersion',
  'artifactHash', 'royaltyGraphDigest', 'catalogDigest', 'model', 'maxInputTokens',
  'maxOutputTokens', 'promptBytes', 'estimatedInputTokens', 'grossAtomic',
  'worstCaseExecutionCostAtomic', 'settlementCostAtomic', 'refundReserveAtomic',
  'protocolFeeBps', 'protocolFeeAtomic', 'worstCaseRoyaltyPoolAtomic',
  'worstCaseContributionMarginAtomic',
]);

export function assertExecutionQuote(input) {
  const quote = exactPlainObject(input, QUOTE_FIELDS, [], 'QUOTE_SCHEMA', 'execution quote');
  if (quote.schemaVersion !== 2
      || typeof quote.quoteId !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(quote.quoteId)
      || typeof quote.catalogVersion !== 'string'
      || !['synthetic_config', 'human_verified'].includes(quote.evidenceLabel)
      || typeof quote.skillId !== 'string' || !quote.skillId
      || typeof quote.skillVersion !== 'string' || !quote.skillVersion
      || !/^sha256:[0-9a-f]{64}$/.test(quote.artifactHash)
      || !/^sha256:[0-9a-f]{64}$/.test(quote.royaltyGraphDigest)
      || !/^sha256:[0-9a-f]{64}$/.test(quote.catalogDigest)
      || typeof quote.model !== 'string'
      || !Number.isSafeInteger(quote.maxInputTokens) || quote.maxInputTokens < 0
      || !Number.isSafeInteger(quote.maxOutputTokens) || quote.maxOutputTokens < 1
      || !Number.isSafeInteger(quote.promptBytes) || quote.promptBytes < 0
      || !Number.isSafeInteger(quote.estimatedInputTokens) || quote.estimatedInputTokens < quote.promptBytes
      || !Number.isSafeInteger(quote.protocolFeeBps) || quote.protocolFeeBps < 0 || quote.protocolFeeBps > 10_000) {
    fail('QUOTE_SCHEMA', 'execution quote contains invalid versioned fields');
  }
  for (const field of [
    'grossAtomic', 'worstCaseExecutionCostAtomic', 'settlementCostAtomic',
    'refundReserveAtomic', 'protocolFeeAtomic', 'worstCaseRoyaltyPoolAtomic',
    'worstCaseContributionMarginAtomic',
  ]) atomic(quote[field], field);
  const { quoteId: ignored, ...body } = quote;
  if (hash(body) !== quote.quoteId) fail('QUOTE_ID_MISMATCH', 'quote ID does not bind the complete execution quote');
  return quote;
}

export function assertFrozenExecutionIdentity(input) {
  const captured = exactPlainObject(input,
    ['quote', 'skillId', 'skillVersion', 'artifactContent', 'skills', 'catalog'], [],
    'IDENTITY_SCHEMA', 'frozen execution identity check');
  const quote = assertExecutionQuote(captured.quote);
  if (quote.skillId !== captured.skillId || quote.skillVersion !== captured.skillVersion) {
    fail('SKILL_IDENTITY_DRIFT', 'current Skill identity differs from the accepted quote');
  }
  if (quote.artifactHash !== artifactDigest(captured.artifactContent)) {
    fail('ARTIFACT_DRIFT', 'current hosted Skill bytes differ from the accepted quote');
  }
  if (quote.royaltyGraphDigest !== royaltyGraphDigest(captured.skills)) {
    fail('ROYALTY_GRAPH_DRIFT', 'current Royalty graph differs from the accepted quote');
  }
  if (quote.catalogDigest !== catalogDigest(captured.catalog)) {
    fail('CATALOG_DIGEST_DRIFT', 'current pricing catalog differs from the accepted quote');
  }
  if (quote.catalogVersion !== captured.catalog.version) {
    fail('CATALOG_VERSION_DRIFT', 'current pricing catalog version differs from the accepted quote');
  }
  return true;
}

const PROVIDER_FRAMING_TOKEN_ALLOWANCE = 256;

export function conservativeProviderPromptBound(input) {
  const captured = exactPlainObject(input, [
    'systemPrompt', 'userInput', 'requestBodyBytes', 'maxRequestBodyBytes', 'maxInputTokens',
  ], [], 'PROMPT_BOUND_SCHEMA', 'provider prompt bound');
  if (typeof captured.systemPrompt !== 'string' || typeof captured.userInput !== 'string') {
    fail('PROMPT_BOUND_SCHEMA', 'provider prompt inputs must be strings');
  }
  for (const [label, value] of Object.entries({
    requestBodyBytes: captured.requestBodyBytes,
    maxRequestBodyBytes: captured.maxRequestBodyBytes,
    maxInputTokens: captured.maxInputTokens,
  })) {
    if (!Number.isSafeInteger(value) || value < 0) {
      fail('PROMPT_BOUND_INTEGER', `${label} must be a non-negative safe integer`);
    }
  }
  if (captured.requestBodyBytes > captured.maxRequestBodyBytes) {
    fail('REQUEST_BODY_TOO_LARGE', 'request body exceeds the pre-payment byte cap');
  }
  const promptBytes = Buffer.byteLength(captured.systemPrompt, 'utf8')
    + Buffer.byteLength(captured.userInput, 'utf8');
  const estimatedInputTokens = promptBytes + PROVIDER_FRAMING_TOKEN_ALLOWANCE;
  if (estimatedInputTokens > captured.maxInputTokens) {
    fail('PROMPT_TOKEN_BOUND', 'complete provider prompt exceeds the frozen conservative input-token cap');
  }
  return deepFreeze({ promptBytes, estimatedInputTokens, requestBodyBytes: captured.requestBodyBytes });
}

function serializeAllocation(allocation) {
  return {
    allocationPolicy: allocation.allocationPolicy,
    grossAtomic: allocation.grossAtomic.toString(),
    executionCostAtomic: allocation.executionCostAtomic.toString(),
    settlementCostAtomic: allocation.settlementCostAtomic.toString(),
    protocolFeeAtomic: allocation.protocolFeeAtomic.toString(),
    royaltyPoolAtomic: allocation.royaltyPoolAtomic.toString(),
    refundReserveAtomic: allocation.refundReserveAtomic.toString(),
    holderCredits: allocation.holderCredits.map((credit) => ({
      ...credit, amountAtomic: credit.amountAtomic.toString(),
    })),
    ancestorCredits: allocation.ancestorCredits.map((credit) => ({
      ...credit, amountAtomic: credit.amountAtomic.toString(),
    })),
    journalEntries: allocation.journalEntries.map((entry) => ({
      ...entry, amountAtomic: entry.amountAtomic.toString(),
    })),
  };
}

export function createExecutionQuote(input) {
  const captured = exactPlainObject(input, [
    'schemaVersion', 'grossAtomic', 'model', 'maxInputTokens', 'maxOutputTokens',
    'promptBytes', 'estimatedInputTokens', 'settlementCostAtomic', 'refundReserveAtomic',
    'protocolFeeBps', 'leafSkillId', 'skillId', 'skillVersion', 'artifactHash', 'skills',
  ], ['catalog'], 'QUOTE_SCHEMA', 'execution quote request');
  if (captured.schemaVersion !== 2) fail('QUOTE_SCHEMA', 'execution quote request must use schema version 2');
  const catalog = captured.catalog ?? EXECUTION_CATALOG;
  const policy = modelPolicy(captured.model, catalog);
  if (captured.skillId !== captured.leafSkillId
      || typeof captured.skillId !== 'string' || !captured.skillId
      || typeof captured.skillVersion !== 'string' || !captured.skillVersion
      || typeof captured.artifactHash !== 'string'
      || !/^sha256:[0-9a-f]{64}$/.test(captured.artifactHash)) {
    fail('EXECUTION_IDENTITY', 'quote requires exact Skill id/version and lowercase artifact hash');
  }
  if (!Number.isSafeInteger(captured.maxInputTokens) || captured.maxInputTokens < 0
      || !Number.isSafeInteger(captured.maxOutputTokens) || captured.maxOutputTokens < 1
      || captured.maxInputTokens > policy.maxInputTokens
      || captured.maxOutputTokens > policy.maxOutputTokens) {
    fail('TOKEN_LIMIT', `requested token limits exceed catalog policy for '${captured.model}'`);
  }
  if (!Number.isSafeInteger(captured.promptBytes) || captured.promptBytes < 0
      || !Number.isSafeInteger(captured.estimatedInputTokens)
      || captured.estimatedInputTokens < captured.promptBytes
      || captured.estimatedInputTokens > captured.maxInputTokens) {
    fail('PROMPT_TOKEN_BOUND', 'quote prompt bounds must fit the accepted maxInputTokens');
  }
  const worstCaseExecutionCost = usageCostAtomic({
    schemaVersion: 2,
    model: captured.model,
    inputTokens: captured.maxInputTokens,
    outputTokens: captured.maxOutputTokens,
  }, catalog);
  let allocation;
  try {
    allocation = allocateExternalGross({
      grossAtomic: atomic(captured.grossAtomic, 'grossAtomic'),
      executionCostAtomic: worstCaseExecutionCost,
      settlementCostAtomic: atomic(captured.settlementCostAtomic, 'settlementCostAtomic'),
      protocolFeeBps: captured.protocolFeeBps,
      refundReserveAtomic: atomic(captured.refundReserveAtomic, 'refundReserveAtomic'),
      leafSkillId: captured.leafSkillId,
      skills: structuredClone(captured.skills),
    });
  } catch (error) {
    fail('NEGATIVE_WORST_CASE_MARGIN', `quote cannot cover worst-case costs: ${error.message}`);
  }
  const body = {
    schemaVersion: 2,
    catalogVersion: catalog.version,
    evidenceLabel: catalog.evidenceLabel,
    skillId: captured.skillId,
    skillVersion: captured.skillVersion,
    artifactHash: captured.artifactHash,
    royaltyGraphDigest: royaltyGraphDigest(captured.skills),
    catalogDigest: catalogDigest(catalog),
    model: captured.model,
    maxInputTokens: captured.maxInputTokens,
    maxOutputTokens: captured.maxOutputTokens,
    promptBytes: captured.promptBytes,
    estimatedInputTokens: captured.estimatedInputTokens,
    grossAtomic: allocation.grossAtomic.toString(),
    worstCaseExecutionCostAtomic: worstCaseExecutionCost.toString(),
    settlementCostAtomic: allocation.settlementCostAtomic.toString(),
    refundReserveAtomic: allocation.refundReserveAtomic.toString(),
    protocolFeeBps: captured.protocolFeeBps,
    protocolFeeAtomic: allocation.protocolFeeAtomic.toString(),
    worstCaseRoyaltyPoolAtomic: allocation.royaltyPoolAtomic.toString(),
    worstCaseContributionMarginAtomic: allocation.protocolFeeAtomic.toString(),
  };
  return frozenCopy({ quoteId: hash(body), ...body });
}

function pendingUsage(input, catalog) {
  if (input == null) return { actual: null, usage: null };
  const usage = normalizeUsage(input);
  try {
    return { actual: usageCostAtomic(usage, catalog), usage };
  } catch {
    return { actual: null, usage: null };
  }
}

export function createPendingExecutionAccounting(input) {
  const captured = exactPlainObject(input,
    ['quote', 'failureClass', 'reason'], ['usage', 'catalog'],
    'ACCOUNTING_SCHEMA', 'pending execution accounting');
  const quote = assertExecutionQuote(captured.quote);
  const catalog = captured.catalog ?? EXECUTION_CATALOG;
  const { actual, usage } = pendingUsage(captured.usage ?? null, catalog);
  const quotedWorstCase = BigInt(quote.worstCaseExecutionCostAtomic);
  const overrun = actual != null && actual > quotedWorstCase ? actual - quotedWorstCase : 0n;
  const result = {
    schemaVersion: 2,
    quoteId: quote.quoteId,
    grossAtomic: quote.grossAtomic,
    executionCostAtomic: '0',
    settlementCostAtomic: '0',
    protocolFeeAtomic: '0',
    royaltyPoolAtomic: '0',
    refundReserveAtomic: '0',
    contributionMarginAtomic: '0',
    allocationState: 'pending_cogs_reconciliation',
    allocationPolicy: null,
    holderCredits: [],
    ancestorCredits: [],
    journalEntries: [{
      category: 'unresolved-execution-accounting',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'hold:execution-accounting-reconciliation',
      amountAtomic: quote.grossAtomic,
    }],
    executionCogs: {
      schemaVersion: 2,
      status: actual == null ? 'unknown' : 'known',
      actualAtomic: actual?.toString() ?? null,
      chargedAtomic: null,
      quotedWorstCaseAtomic: quote.worstCaseExecutionCostAtomic,
      accruedOverrunAtomic: overrun.toString(),
      catalogVersion: quote.catalogVersion,
      catalogDigest: quote.catalogDigest,
      usage,
      failureClass: String(captured.failureClass),
      reason: String(captured.reason),
    },
  };
  return frozenCopy(result);
}

export function finalizeExecutionAccounting(input) {
  const captured = exactPlainObject(input,
    ['quote', 'usage', 'leafSkillId', 'skills'], ['unknownReason', 'catalog'],
    'ACCOUNTING_SCHEMA', 'final execution accounting');
  const quote = assertExecutionQuote(captured.quote);
  const catalog = captured.catalog ?? EXECUTION_CATALOG;
  validateCatalog(catalog);
  if (quote.catalogVersion !== catalog.version || quote.catalogDigest !== catalogDigest(catalog)) {
    fail('CATALOG_VERSION', 'quote pricing catalog identity is not loaded');
  }
  if (quote.skillId !== captured.leafSkillId
      || quote.royaltyGraphDigest !== royaltyGraphDigest(captured.skills)) {
    fail('ROYALTY_GRAPH_DRIFT', 'final allocation graph differs from the accepted quote');
  }
  if (captured.usage == null) {
    return createPendingExecutionAccounting({
      quote,
      usage: null,
      failureClass: 'COGS_UNKNOWN',
      reason: captured.unknownReason ?? 'provider usage unavailable',
      catalog,
    });
  }
  const usage = normalizeUsage(captured.usage);
  if (usage.model !== quote.model
      || usage.inputTokens > quote.maxInputTokens
      || usage.outputTokens > quote.maxOutputTokens) {
    fail('USAGE_EXCEEDS_QUOTE', 'provider usage exceeds the accepted model or token limits');
  }
  const actual = usageCostAtomic(usage, catalog);
  if (actual > BigInt(quote.worstCaseExecutionCostAtomic)) {
    fail('COGS_EXCEEDS_QUOTE', 'actual provider COGS exceeds the accepted reserve');
  }
  let allocation;
  try {
    allocation = allocateExternalGross({
      grossAtomic: BigInt(quote.grossAtomic),
      executionCostAtomic: actual,
      settlementCostAtomic: BigInt(quote.settlementCostAtomic),
      protocolFeeBps: quote.protocolFeeBps,
      refundReserveAtomic: BigInt(quote.refundReserveAtomic),
      leafSkillId: captured.leafSkillId,
      skills: structuredClone(captured.skills),
    });
  } catch (error) {
    fail('NEGATIVE_CONTRIBUTION_MARGIN', `actual execution economics do not conserve: ${error.message}`);
  }
  const serialized = serializeAllocation(allocation);
  return frozenCopy({
    schemaVersion: 2,
    ...serialized,
    quoteId: quote.quoteId,
    allocationState: 'finalized',
    contributionMarginAtomic: serialized.protocolFeeAtomic,
    executionCogs: {
      schemaVersion: 2,
      status: 'known',
      actualAtomic: actual.toString(),
      chargedAtomic: actual.toString(),
      quotedWorstCaseAtomic: quote.worstCaseExecutionCostAtomic,
      accruedOverrunAtomic: '0',
      catalogVersion: catalog.version,
      catalogDigest: quote.catalogDigest,
      usage,
      failureClass: null,
      reason: null,
    },
  });
}

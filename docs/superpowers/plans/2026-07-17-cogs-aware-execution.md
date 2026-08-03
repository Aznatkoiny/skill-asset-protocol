# COGS-Aware Execution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Quote hosted-Skill Invocations from versioned provider pricing and model limits, record known or explicitly unresolved execution COGS, and finalize Royalty-claim credits only when actual COGS is known.

**Architecture:** Add a versioned execution catalog and pure quote/accounting functions backed by `prototype/atomic-money.mjs`; the Collar validates model/token limits before offering x402, binds the quote to the Invocation, records provider usage after execution, and finalizes the authoritative journal receipt. A quote is accepted only when worst-case contribution margin is non-negative. Unknown usage makes execution terminal `failed/COGS_UNKNOWN`, preserves the settled payment, emits no output or Royalty credits, and puts full gross in one balanced reconciliation hold.

**Tech Stack:** Node.js 20+, ECMAScript modules, built-in `node:test`, `node:assert/strict`, Hono, Anthropic Messages mock/live adapter, atomic USDC strings; automated verification is offline/mock and never performs a live provider call or a funded transaction.

---

## Prerequisites and file map

Complete the atomic-money, Collar-journal, and Wielder-policy plans first.

- Create `spikes/pi-wielder/src/execution-economics.mjs`: immutable provider catalog, request limits, worst-case quote, actual-cost calculation, and final allocation.
- Create `spikes/pi-wielder/tests/execution-economics.test.mjs`: quote, margin, usage, unknown-cost, and exact allocation tests.
- Create `spikes/pi-wielder/tests/collar-cogs.test.mjs`: offline Collar quote-binding and receipt tests.
- Modify `spikes/pi-wielder/src/collar.mjs`: validate before payment, execute through an injected adapter, and finalize actual/unknown COGS in the journal.
- Modify `spikes/pi-wielder/src/invocation-journal.mjs`: accept the COGS/accounting terminal payload defined here without weakening earlier transitions.
- Modify `spikes/pi-wielder/src/x402-seller.mjs`: quote atomic amounts directly and preserve the quote identifier in payment requirements.
- Modify `spikes/pi-wielder/src/proxy.mjs`: bind policy authorization to the quote identifier.
- Modify `spikes/pi-wielder/e2e.mjs`: assert quote, COGS, margin, and post-cost Royalty credits.
- Modify `spikes/pi-wielder/README.md` and `spikes/pi-wielder/RUNBOOK.md`: replace gross-split language with implemented cost ordering and label historical n=48 overhead evidence unreproducible.
- Verify `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`: Plan 1 owns this tracked `historical_unreproducible` tombstone; this plan reads it and must not overwrite it or treat its p50/p95 as reproducible.
- Modify `spikes/pi-wielder/package.json`: add focused execution-economics tests.

## Execution economics contract

The first catalog is deliberately `synthetic_config`, not a claim about current live
provider prices. Before any live run, a human must verify and version the actual price
sheet. The mock rates are useful only to prove the accounting path:

```js
EXECUTION_CATALOG = {
  version: 'synthetic-anthropic-2026-07-17-v1',
  evidenceLabel: 'synthetic_config',
  models: {
    'claude-sonnet-4-6': {
      provider: 'anthropic',
      inputAtomicPerMillionTokens: '3000000',
      outputAtomicPerMillionTokens: '15000000',
      maxInputTokens: 16384,
      maxOutputTokens: 2048,
    },
  },
};
```

`contributionMarginAtomic` in this spike means the retained protocol-fee component
after execution COGS, settlement cost, refund reserve, and Royalty pool have each been
separately allocated. It does not include unmodeled company payroll or overhead.

### Task 1: Build versioned quote and final-accounting functions

**Files:**
- Create: `spikes/pi-wielder/src/execution-economics.mjs`
- Create: `spikes/pi-wielder/tests/execution-economics.test.mjs`

- [ ] **Step 1: Write failing quote, COGS, and allocation tests**

Create `spikes/pi-wielder/tests/execution-economics.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  artifactDigest,
  assertFrozenExecutionIdentity,
  assertLiveCatalogApproval,
  catalogDigest,
  conservativeProviderPromptBound,
  createPendingExecutionAccounting,
  createExecutionQuote,
  EXECUTION_CATALOG,
  ExecutionEconomicsError,
  finalizeExecutionAccounting,
  usageCostAtomic,
} from '../src/execution-economics.mjs';

const SKILL_ID = 'skill-a';
const SKILL_VERSION = 'skill-a/2026-07-17-v1';
const SKILL_ARTIFACT = 'system prompt artifact v1';
const skills = {
  [SKILL_ID]: {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: 'creator', bps: 10_000 }],
  },
};

const quote = (overrides = {}) => createExecutionQuote({
  grossAtomic: '250000',
  model: 'claude-sonnet-4-6',
  maxInputTokens: 16384,
  maxOutputTokens: 2048,
  promptBytes: 10_000,
  estimatedInputTokens: 10_256,
  settlementCostAtomic: '1000',
  refundReserveAtomic: '5000',
  protocolFeeBps: 250,
  leafSkillId: SKILL_ID,
  skillId: SKILL_ID,
  skillVersion: SKILL_VERSION,
  artifactHash: artifactDigest(SKILL_ARTIFACT),
  skills,
  ...overrides,
});

test('usageCostAtomic rounds each versioned provider charge upward', () => {
  assert.equal(usageCostAtomic({
    model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42,
  }), 756n);
  assert.equal(usageCostAtomic({
    model: 'claude-sonnet-4-6', inputTokens: 1, outputTokens: 1,
  }), 18n);
});

test('complete provider prompt bound is byte-conservative and rejects body/token overflow', () => {
  assert.deepEqual(conservativeProviderPromptBound({
    systemPrompt: 'abc', userInput: 'é', requestBodyBytes: 100,
    maxRequestBodyBytes: 4096, maxInputTokens: 300,
  }), { promptBytes: 5, estimatedInputTokens: 261, requestBodyBytes: 100 });
  assert.throws(() => conservativeProviderPromptBound({
    systemPrompt: 'x', userInput: 'y', requestBodyBytes: 4097,
    maxRequestBodyBytes: 4096, maxInputTokens: 300,
  }), (error) => error.code === 'REQUEST_BODY_TOO_LARGE');
  assert.throws(() => conservativeProviderPromptBound({
    systemPrompt: 'x'.repeat(100), userInput: 'y', requestBodyBytes: 120,
    maxRequestBodyBytes: 4096, maxInputTokens: 300,
  }), (error) => error.code === 'PROMPT_TOKEN_BOUND');
});

test('quote reserves worst-case COGS before fee and Royalty pool', () => {
  const result = quote();
  assert.equal(result.catalogVersion, EXECUTION_CATALOG.version);
  assert.equal(result.evidenceLabel, 'synthetic_config');
  assert.equal(result.worstCaseExecutionCostAtomic, '79872');
  assert.equal(result.protocolFeeAtomic, '6250');
  assert.equal(result.worstCaseRoyaltyPoolAtomic, '157878');
  assert.equal(result.worstCaseContributionMarginAtomic, '6250');
  assert.match(result.quoteId, /^sha256:[0-9a-f]{64}$/);
});

test('known usage charges actual COGS before increasing the Royalty pool', () => {
  const result = finalizeExecutionAccounting({
    quote: quote(),
    usage: { model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    leafSkillId: SKILL_ID,
    skills,
  });
  assert.deepEqual(result.executionCogs, {
    status: 'known',
    actualAtomic: '756',
    chargedAtomic: '756',
    quotedWorstCaseAtomic: '79872',
    catalogVersion: EXECUTION_CATALOG.version,
    usage: { model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    reason: null,
  });
  assert.equal(result.royaltyPoolAtomic, '236994');
  assert.equal(result.protocolFeeAtomic, '6250');
  assert.equal(result.contributionMarginAtomic, '6250');
  assert.equal(result.journalEntries.reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n), 250_000n);
  assert.ok(result.journalEntries.every((entry) => entry.debitAccountId === 'wielder:external-gross'));
});

test('unknown usage fails closed into one full-gross hold and finalizes no Royalty claims', () => {
  const result = finalizeExecutionAccounting({
    quote: quote(),
    usage: null,
    unknownReason: 'provider response omitted usage',
    leafSkillId: SKILL_ID,
    skills,
  });
  assert.equal(result.executionCogs.status, 'unknown');
  assert.equal(result.executionCogs.actualAtomic, null);
  assert.equal(result.executionCogs.chargedAtomic, null);
  assert.equal(result.executionCogs.quotedWorstCaseAtomic, '79872');
  assert.equal(result.executionCogs.reason, 'provider response omitted usage');
  assert.equal(result.allocationState, 'pending_cogs_reconciliation');
  assert.equal(result.royaltyPoolAtomic, '0');
  assert.deepEqual(result.holderCredits, []);
  assert.deepEqual(result.ancestorCredits, []);
  assert.deepEqual(result.journalEntries, [{
    category: 'unresolved-execution-accounting',
    debitAccountId: 'wielder:external-gross',
    creditAccountId: 'hold:execution-accounting-reconciliation',
    amountAtomic: '250000',
  }]);
});

test('quotes fail before payment when caps or worst-case economics are invalid', () => {
  assert.throws(() => quote({ model: 'unlisted-model' }), (error) => (
    error instanceof ExecutionEconomicsError && error.code === 'MODEL_NOT_ALLOWED'
  ));
  assert.throws(() => quote({ maxOutputTokens: 2049 }), (error) => error.code === 'TOKEN_LIMIT');
  assert.throws(() => quote({ grossAtomic: '50000' }), (error) => error.code === 'NEGATIVE_WORST_CASE_MARGIN');
});

test('provider usage above the accepted quote fails product acceptance', () => {
  assert.throws(() => finalizeExecutionAccounting({
    quote: quote(),
    usage: { model: 'claude-sonnet-4-6', inputTokens: 4096, outputTokens: 2049 },
    leafSkillId: SKILL_ID,
    skills,
  }), (error) => error.code === 'USAGE_EXCEEDS_QUOTE');
});

test('post-provider overrun accounting records known accrued COGS but finalizes no claims', () => {
  const result = createPendingExecutionAccounting({
    quote: quote(),
    usage: { model: 'claude-sonnet-4-6', inputTokens: 16384, outputTokens: 2049 },
    failureClass: 'USAGE_EXCEEDS_QUOTE',
    reason: 'provider exceeded frozen output cap',
  });
  assert.equal(result.allocationState, 'pending_cogs_reconciliation');
  assert.equal(result.executionCogs.status, 'known');
  assert.equal(result.executionCogs.actualAtomic, '79887');
  assert.equal(result.executionCogs.accruedOverrunAtomic, '15');
  assert.equal(result.royaltyPoolAtomic, '0');
  assert.deepEqual(result.holderCredits, []);
  assert.deepEqual(result.ancestorCredits, []);
  assert.equal(result.journalEntries[0].amountAtomic, result.grossAtomic);
});

test('live approval binds a separately supplied exact catalog digest and spend cap', () => {
  const verifiedCatalog = structuredClone(EXECUTION_CATALOG);
  verifiedCatalog.evidenceLabel = 'human_verified';
  verifiedCatalog.source = 'https://provider.example/pricing/2026-07-17';
  verifiedCatalog.asOf = '2026-07-17T00:00:00.000Z';
  const approval = { catalogDigest: catalogDigest(verifiedCatalog), spendCapAtomic: '250000' };
  assert.doesNotThrow(() => assertLiveCatalogApproval({ catalog: verifiedCatalog, approval, grossAtomic: '250000' }));
  const mutated = structuredClone(verifiedCatalog);
  mutated.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  assert.throws(() => assertLiveCatalogApproval({ catalog: mutated, approval, grossAtomic: '250000' }),
    (error) => error.code === 'LIVE_CATALOG_DIGEST');
  assert.throws(() => assertLiveCatalogApproval({
    catalog: verifiedCatalog,
    approval: { ...approval, spendCapAtomic: '249999' },
    grossAtomic: '250000',
  }), (error) => error.code === 'LIVE_SPEND_CAP');
});

test('quote ID freezes Skill, artifact, Royalty graph, and catalog identity', () => {
  const frozen = quote();
  assert.deepEqual({
    skillId: frozen.skillId,
    skillVersion: frozen.skillVersion,
    artifactHash: frozen.artifactHash,
  }, { skillId: SKILL_ID, skillVersion: SKILL_VERSION, artifactHash: artifactDigest(SKILL_ARTIFACT) });
  assert.doesNotThrow(() => assertFrozenExecutionIdentity({
    quote: frozen, skillId: SKILL_ID, skillVersion: SKILL_VERSION,
    artifactContent: SKILL_ARTIFACT, skills, catalog: EXECUTION_CATALOG,
  }));
  for (const [expectedCode, overrides] of [
    ['SKILL_IDENTITY_DRIFT', { skillVersion: `${SKILL_VERSION}-changed` }],
    ['ARTIFACT_DRIFT', { artifactContent: `${SKILL_ARTIFACT}\nchanged` }],
    ['ROYALTY_GRAPH_DRIFT', { skills: { ...skills, extra: { parentIds: [], inheritBps: 0, holders: [] } } }],
    ['CATALOG_DIGEST_DRIFT', { catalog: { ...EXECUTION_CATALOG, version: 'changed' } }],
  ]) {
    assert.throws(() => assertFrozenExecutionIdentity({
      quote: frozen, skillId: SKILL_ID, skillVersion: SKILL_VERSION,
      artifactContent: SKILL_ARTIFACT, skills, catalog: EXECUTION_CATALOG, ...overrides,
    }), (error) => error.code === expectedCode);
  }
  const driftedCatalog = structuredClone(EXECUTION_CATALOG);
  driftedCatalog.version = 'drifted-current-config';
  const pending = createPendingExecutionAccounting({
    quote: frozen, usage: null, failureClass: 'CATALOG_DIGEST_DRIFT',
    reason: 'current catalog changed', catalog: driftedCatalog,
  });
  assert.equal(pending.executionCogs.catalogVersion, frozen.catalogVersion);
  assert.equal(pending.executionCogs.catalogDigest, frozen.catalogDigest);
});
```

- [ ] **Step 2: Run the test and verify the module is missing**

Run: `node --test spikes/pi-wielder/tests/execution-economics.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/execution-economics.mjs`.

- [ ] **Step 3: Implement the pure execution-economics module**

Create `spikes/pi-wielder/src/execution-economics.mjs`:

```js
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

export const EXECUTION_CATALOG = Object.freeze({
  version: 'synthetic-anthropic-2026-07-17-v1',
  evidenceLabel: 'synthetic_config',
  source: null,
  asOf: null,
  models: Object.freeze({
    'claude-sonnet-4-6': Object.freeze({
      provider: 'anthropic',
      inputAtomicPerMillionTokens: '3000000',
      outputAtomicPerMillionTokens: '15000000',
      maxInputTokens: 16384,
      maxOutputTokens: 2048,
    }),
  }),
});

function integer(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) fail('TOKEN_INTEGER', `${label} must be a non-negative safe integer`);
  return BigInt(value);
}

function atomic(value, label) {
  const text = String(value ?? '');
  if (!/^(0|[1-9]\d*)$/.test(text)) fail('ATOMIC_FORMAT', `${label} must be a canonical atomic string`);
  return BigInt(text);
}

const ceilDiv = (numerator, denominator) => (numerator + denominator - 1n) / denominator;

function modelPolicy(model, catalog = EXECUTION_CATALOG) {
  const policy = catalog.models[model];
  if (!policy) fail('MODEL_NOT_ALLOWED', `model '${model}' is not in pricing catalog '${catalog.version}'`);
  return policy;
}

export function usageCostAtomic({ model, inputTokens, outputTokens }, catalog = EXECUTION_CATALOG) {
  const policy = modelPolicy(model, catalog);
  const input = ceilDiv(
    integer(inputTokens, 'inputTokens') * atomic(policy.inputAtomicPerMillionTokens, 'input rate'),
    1_000_000n,
  );
  const output = ceilDiv(
    integer(outputTokens, 'outputTokens') * atomic(policy.outputAtomicPerMillionTokens, 'output rate'),
    1_000_000n,
  );
  return input + output;
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

export const artifactDigest = (content) => `sha256:${crypto.createHash('sha256')
  .update(String(content))
  .digest('hex')}`;
export const royaltyGraphDigest = (skills) => hash(skills);

export function catalogDigest(catalog) {
  const { approval: ignoredApproval, ...catalogBody } = catalog;
  return hash(catalogBody);
}

export function assertLiveCatalogApproval({ catalog, approval, grossAtomic }) {
  if (catalog?.evidenceLabel !== 'human_verified'
    || typeof catalog.source !== 'string' || !catalog.source
    || !Number.isFinite(Date.parse(catalog.asOf))) {
    fail('LIVE_CATALOG_EVIDENCE', 'live catalog requires human_verified evidence, source, and as-of');
  }
  if (!approval || typeof approval !== 'object' || Array.isArray(approval)
    || Object.keys(approval).sort().join(',') !== 'catalogDigest,spendCapAtomic') {
    fail('LIVE_APPROVAL_SHAPE', 'live approval must contain exactly catalogDigest and spendCapAtomic');
  }
  const recomputed = catalogDigest(catalog);
  if (approval.catalogDigest !== recomputed) fail('LIVE_CATALOG_DIGEST', 'human-approved digest does not match canonical catalog content');
  const cap = atomic(approval.spendCapAtomic, 'live spend cap');
  const gross = atomic(grossAtomic, 'grossAtomic');
  if (gross > cap) fail('LIVE_SPEND_CAP', 'Invocation gross exceeds the separately approved spend cap');
  return { catalogDigest: recomputed, spendCapAtomic: cap.toString() };
}

export function assertFrozenExecutionIdentity({
  quote, skillId, skillVersion, artifactContent, skills, catalog,
}) {
  if (quote.skillId !== skillId || quote.skillVersion !== skillVersion) {
    fail('SKILL_IDENTITY_DRIFT', 'current Skill identity differs from the accepted quote');
  }
  if (quote.artifactHash !== artifactDigest(artifactContent)) {
    fail('ARTIFACT_DRIFT', 'current hosted Skill bytes differ from the accepted quote');
  }
  if (quote.royaltyGraphDigest !== royaltyGraphDigest(skills)) {
    fail('ROYALTY_GRAPH_DRIFT', 'current Royalty graph differs from the accepted quote');
  }
  if (quote.catalogDigest !== catalogDigest(catalog)) {
    fail('CATALOG_DIGEST_DRIFT', 'current pricing catalog differs from the accepted quote');
  }
  return true;
}

const PROVIDER_FRAMING_TOKEN_ALLOWANCE = 256;

export function conservativeProviderPromptBound({
  systemPrompt,
  userInput,
  requestBodyBytes,
  maxRequestBodyBytes,
  maxInputTokens,
}) {
  for (const [label, value] of Object.entries({ requestBodyBytes, maxRequestBodyBytes, maxInputTokens })) {
    if (!Number.isSafeInteger(value) || value < 0) fail('PROMPT_BOUND_INTEGER', `${label} must be a non-negative safe integer`);
  }
  if (requestBodyBytes > maxRequestBodyBytes) fail('REQUEST_BODY_TOO_LARGE', 'request body exceeds the pre-payment byte cap');
  const promptBytes = Buffer.byteLength(String(systemPrompt), 'utf8')
    + Buffer.byteLength(String(userInput), 'utf8');
  const estimatedInputTokens = promptBytes + PROVIDER_FRAMING_TOKEN_ALLOWANCE;
  if (estimatedInputTokens > maxInputTokens) {
    fail('PROMPT_TOKEN_BOUND', 'complete provider prompt exceeds the frozen conservative input-token cap');
  }
  return { promptBytes, estimatedInputTokens, requestBodyBytes };
}

function serializeAllocation(allocation) {
  return {
    grossAtomic: allocation.grossAtomic.toString(),
    executionCostAtomic: allocation.executionCostAtomic.toString(),
    settlementCostAtomic: allocation.settlementCostAtomic.toString(),
    protocolFeeAtomic: allocation.protocolFeeAtomic.toString(),
    royaltyPoolAtomic: allocation.royaltyPoolAtomic.toString(),
    refundReserveAtomic: allocation.refundReserveAtomic.toString(),
    holderCredits: allocation.holderCredits.map((credit) => ({ ...credit, amountAtomic: credit.amountAtomic.toString() })),
    ancestorCredits: allocation.ancestorCredits.map((credit) => ({ ...credit, amountAtomic: credit.amountAtomic.toString() })),
    journalEntries: allocation.journalEntries.map((entry) => ({ ...entry, amountAtomic: entry.amountAtomic.toString() })),
  };
}

export function createExecutionQuote({
  grossAtomic,
  model,
  maxInputTokens,
  maxOutputTokens,
  promptBytes,
  estimatedInputTokens,
  settlementCostAtomic,
  refundReserveAtomic,
  protocolFeeBps,
  leafSkillId,
  skillId,
  skillVersion,
  artifactHash,
  skills,
  catalog = EXECUTION_CATALOG,
}) {
  const policy = modelPolicy(model, catalog);
  if (skillId !== leafSkillId || typeof skillVersion !== 'string' || !skillVersion
    || !/^sha256:[0-9a-f]{64}$/.test(artifactHash)) {
    fail('EXECUTION_IDENTITY', 'quote requires exact Skill id/version and lowercase artifact hash');
  }
  if (!Number.isSafeInteger(maxInputTokens) || maxInputTokens < 0
    || !Number.isSafeInteger(maxOutputTokens) || maxOutputTokens < 1
    || maxInputTokens > policy.maxInputTokens || maxOutputTokens > policy.maxOutputTokens) {
    fail('TOKEN_LIMIT', `requested token limits exceed catalog policy for '${model}'`);
  }
  if (!Number.isSafeInteger(promptBytes) || promptBytes < 0
    || !Number.isSafeInteger(estimatedInputTokens) || estimatedInputTokens < promptBytes
    || estimatedInputTokens > maxInputTokens) {
    fail('PROMPT_TOKEN_BOUND', 'quote prompt bounds must fit the accepted maxInputTokens');
  }
  const worstCaseExecutionCost = usageCostAtomic({ model, inputTokens: maxInputTokens, outputTokens: maxOutputTokens }, catalog);
  let allocation;
  try {
    allocation = allocateExternalGross({
      grossAtomic: atomic(grossAtomic, 'grossAtomic'),
      executionCostAtomic: worstCaseExecutionCost,
      settlementCostAtomic: atomic(settlementCostAtomic, 'settlementCostAtomic'),
      protocolFeeBps,
      refundReserveAtomic: atomic(refundReserveAtomic, 'refundReserveAtomic'),
      leafSkillId,
      skills,
    });
  } catch (error) {
    fail('NEGATIVE_WORST_CASE_MARGIN', `quote cannot cover worst-case costs: ${error.message}`);
  }
  const body = {
    catalogVersion: catalog.version,
    evidenceLabel: catalog.evidenceLabel,
    skillId,
    skillVersion,
    artifactHash,
    royaltyGraphDigest: royaltyGraphDigest(skills),
    catalogDigest: catalogDigest(catalog),
    model,
    maxInputTokens,
    maxOutputTokens,
    promptBytes,
    estimatedInputTokens,
    grossAtomic: allocation.grossAtomic.toString(),
    worstCaseExecutionCostAtomic: worstCaseExecutionCost.toString(),
    settlementCostAtomic: allocation.settlementCostAtomic.toString(),
    refundReserveAtomic: allocation.refundReserveAtomic.toString(),
    protocolFeeBps,
    protocolFeeAtomic: allocation.protocolFeeAtomic.toString(),
    worstCaseRoyaltyPoolAtomic: allocation.royaltyPoolAtomic.toString(),
    worstCaseContributionMarginAtomic: allocation.protocolFeeAtomic.toString(),
  };
  return { quoteId: hash(body), ...body };
}

export function createPendingExecutionAccounting({
  quote,
  usage = null,
  failureClass,
  reason,
  catalog = EXECUTION_CATALOG,
}) {
  let actual = null;
  let normalizedUsage = null;
  try {
    if (usage && typeof usage === 'object'
      && typeof usage.model === 'string'
      && Number.isSafeInteger(usage.inputTokens) && usage.inputTokens >= 0
      && Number.isSafeInteger(usage.outputTokens) && usage.outputTokens >= 0) {
      actual = usageCostAtomic(usage, catalog);
      normalizedUsage = { model: usage.model, inputTokens: usage.inputTokens, outputTokens: usage.outputTokens };
    }
  } catch {
    actual = null;
    normalizedUsage = null;
  }
  const quotedWorstCase = BigInt(quote.worstCaseExecutionCostAtomic);
  const overrun = actual != null && actual > quotedWorstCase ? actual - quotedWorstCase : 0n;
  return {
    quoteId: quote.quoteId,
    grossAtomic: quote.grossAtomic,
    executionCostAtomic: '0',
    settlementCostAtomic: '0',
    protocolFeeAtomic: '0',
    royaltyPoolAtomic: '0',
    refundReserveAtomic: '0',
    contributionMarginAtomic: '0',
    allocationState: 'pending_cogs_reconciliation',
    holderCredits: [],
    ancestorCredits: [],
    journalEntries: [{
      category: 'unresolved-execution-accounting',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'hold:execution-accounting-reconciliation',
      amountAtomic: quote.grossAtomic,
    }],
    executionCogs: {
      status: actual == null ? 'unknown' : 'known',
      actualAtomic: actual?.toString() ?? null,
      chargedAtomic: null,
      quotedWorstCaseAtomic: quote.worstCaseExecutionCostAtomic,
      accruedOverrunAtomic: overrun.toString(),
      // The hold describes the accepted frozen quote. A drifted current catalog may be
      // supplied only to classify valid usage; it must never relabel the receipt.
      catalogVersion: quote.catalogVersion,
      catalogDigest: quote.catalogDigest,
      usage: normalizedUsage,
      failureClass: String(failureClass),
      reason: String(reason),
    },
  };
}

export function finalizeExecutionAccounting({
  quote,
  usage,
  unknownReason = 'provider usage unavailable',
  leafSkillId,
  skills,
  catalog = EXECUTION_CATALOG,
}) {
  if (quote.catalogVersion !== catalog.version) fail('CATALOG_VERSION', 'quote pricing version is not loaded');
  if (usage == null) {
    return createPendingExecutionAccounting({
      quote,
      usage: null,
      failureClass: 'COGS_UNKNOWN',
      reason: unknownReason,
      catalog,
    });
  }
  let actual = null;
  if (usage.model !== quote.model
    || usage.inputTokens > quote.maxInputTokens
    || usage.outputTokens > quote.maxOutputTokens) {
    fail('USAGE_EXCEEDS_QUOTE', 'provider usage exceeds the accepted model or token limits');
  }
  actual = usageCostAtomic(usage, catalog);
  if (actual > BigInt(quote.worstCaseExecutionCostAtomic)) {
    fail('COGS_EXCEEDS_QUOTE', 'actual provider COGS exceeds the accepted reserve');
  }
  const charged = actual;
  let allocation;
  try {
    allocation = allocateExternalGross({
      grossAtomic: BigInt(quote.grossAtomic),
      executionCostAtomic: charged,
      settlementCostAtomic: BigInt(quote.settlementCostAtomic),
      protocolFeeBps: quote.protocolFeeBps,
      refundReserveAtomic: BigInt(quote.refundReserveAtomic),
      leafSkillId,
      skills,
    });
  } catch (error) {
    fail('NEGATIVE_CONTRIBUTION_MARGIN', `actual execution economics do not conserve: ${error.message}`);
  }
  const serialized = serializeAllocation(allocation);
  return {
    ...serialized,
    quoteId: quote.quoteId,
    allocationState: 'finalized',
    contributionMarginAtomic: serialized.protocolFeeAtomic,
    executionCogs: {
      status: 'known',
      actualAtomic: actual.toString(),
      chargedAtomic: charged.toString(),
      quotedWorstCaseAtomic: quote.worstCaseExecutionCostAtomic,
      catalogVersion: catalog.version,
      usage: usage ?? null,
      reason: null,
    },
  };
}
```

- [ ] **Step 4: Run the focused economics tests**

Run: `node --test spikes/pi-wielder/tests/execution-economics.test.mjs`

Expected: PASS, 10 tests and 0 failures.

- [ ] **Step 5: Commit quote and final-accounting functions**

```bash
git add spikes/pi-wielder/src/execution-economics.mjs spikes/pi-wielder/tests/execution-economics.test.mjs
git commit -m "feat: quote hosted Skill execution costs"
```

### Task 2: Enforce the artifact serialization boundary without promising extraction-proof output

**Files:**
- Create: `spikes/pi-wielder/src/artifact-boundary.mjs`
- Create: `spikes/pi-wielder/tests/artifact-boundary.test.mjs`

- [ ] **Step 1: Write failing direct-serialization tests**

Create `spikes/pi-wielder/tests/artifact-boundary.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import { assertArtifactNotSerialized } from '../src/artifact-boundary.mjs';

const artifact = 'A'.repeat(220) + '\nSECRET-RULE\n' + 'B'.repeat(220);

test('rejects the full artifact and long exact boundary fragments', () => {
  assert.throws(() => assertArtifactNotSerialized({ output: artifact, artifact }), /direct artifact serialization/);
  assert.throws(() => assertArtifactNotSerialized({ output: artifact.slice(0, 220), artifact }), /direct artifact serialization/);
  assert.throws(() => assertArtifactNotSerialized({ output: artifact.slice(-220), artifact }), /direct artifact serialization/);
});

test('permits ordinary derived output and states the limit of the check', () => {
  assert.equal(assertArtifactNotSerialized({
    output: 'A concise optimized prompt derived from the Skill behavior.', artifact,
  }), true);
});
```

- [ ] **Step 2: Run the test and verify the boundary module is missing**

Run: `node --test spikes/pi-wielder/tests/artifact-boundary.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the narrow serialization guard**

Create `spikes/pi-wielder/src/artifact-boundary.mjs`:

```js
export function assertArtifactNotSerialized({ output, artifact }) {
  const result = String(output ?? '');
  const source = String(artifact ?? '');
  const fragments = source.length >= 400
    ? [source, source.slice(0, 200), source.slice(-200)]
    : [source];
  if (fragments.some((fragment) => fragment.length > 0 && result.includes(fragment))) {
    throw new Error('direct artifact serialization detected in model output');
  }
  return true;
}
```

- [ ] **Step 4: Run the boundary tests**

Run: `node --test spikes/pi-wielder/tests/artifact-boundary.test.mjs`

Expected: PASS, 2 tests and 0 failures.

- [ ] **Step 5: Commit the direct-serialization guard**

```bash
git add spikes/pi-wielder/src/artifact-boundary.mjs spikes/pi-wielder/tests/artifact-boundary.test.mjs
git commit -m "feat: detect direct Skill serialization"
```

### Task 3: Carry one execution quote through x402 and the journal

**Files:**
- Modify: `spikes/pi-wielder/src/x402-seller.mjs`
- Modify: `spikes/pi-wielder/src/invocation-journal.mjs`
- Modify: `spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

- [ ] **Step 1: Add a failing quote-binding assertion to the x402 lifecycle test**

In `spikes/pi-wielder/tests/x402-lifecycle.test.mjs`, define:

```js
  const executionQuote = {
    quoteId: `sha256:${'7'.repeat(64)}`,
    grossAtomic: '250000',
    model: 'claude-sonnet-4-6',
    maxInputTokens: 16384,
    maxOutputTokens: 2048,
  };
```

Pass this option to `x402Paywall`:

```js
    quote: async () => executionQuote,
```

Append these assertions after the existing frozen-requirements check:

```js
    assert.equal(calls[0][1].requirements.extra.quoteId, executionQuote.quoteId);
    assert.deepEqual(calls[0][1].executionQuote, executionQuote);
    assert.deepEqual(calls[1][1].executionQuote, executionQuote);
```

- [ ] **Step 2: Run the lifecycle test and verify execution quote data is absent**

Run: `node --test spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

Expected: FAIL because the paywall ignores `quote` and lifecycle hooks do not carry it.

- [ ] **Step 3: Extend the journal quote schema without changing lifecycle states**

In `offerExternalPayment` inside `invocation-journal.mjs`, add this final quote field:

```js
      executionQuote: input.executionQuote == null ? null : copy(input.executionQuote),
```

Also add `'executionQuote'` to Plan 5's strict `validateQuote` exact-key list and require
`quote.executionQuote.quoteId === quote.quoteId` whenever it is non-null. This keeps
live append and signed replay on the same strict schema.

The existing canonical quote comparison makes a changed execution quote under the same
idempotency key fail closed. Because `quote` is part of the signed receipt, no separate
receipt-schema change is necessary.

- [ ] **Step 4: Add an optional execution-quote provider to `x402Paywall`**

Add `quote = null` to the paywall options. In the Plan-5 frozen-offer block, change the
cache value from `requirements` to:

```js
{ requirements, executionQuote }
```

Use this exact initial-quote branch:

```js
      let executionQuote = null;
      try {
        executionQuote = quote ? await quote(c) : null;
      } catch (error) {
        const status = error.code === 'REQUEST_BODY_TOO_LARGE' ? 413 : 400;
        return c.json({ error: error.message, code: error.code ?? 'QUOTE_REJECTED' }, status);
      }
      const priceUsdc = executionQuote == null
        ? (typeof price === 'function' ? await price(c) : price)
        : null;
      const amountAtomic = executionQuote == null
        ? usdcToAtomic(priceUsdc)
        : String(executionQuote.grossAtomic);
```

Set `base.maxAmountRequired` to `amountAtomic`. Choose the quote ID as:

```js
      const quoteId = executionQuote?.quoteId ?? `sha256:${crypto.createHash('sha256')
        .update(JSON.stringify({ ...base, requestHash, issuedAt, expiresAt }))
        .digest('hex')}`;
```

Store and read the cache as:

```js
      frozenOffers.set(idempotencyKey, { requirements, executionQuote });
```

```js
    const frozen = frozenOffers.get(idempotencyKey);
    let requirements = frozen?.requirements;
    let executionQuote = frozen?.executionQuote ?? null;
```

Update the restart recovery branch to expect the journal-backed lifecycle hook to return
the same pair and cache it without recomputation:

```js
      const recovered = await lifecycle.loadFrozenOffer?.({ idempotencyKey });
      if (recovered) frozenOffers.set(idempotencyKey, structuredClone(recovered));
```

Pass `executionQuote` through `onOffered`, `onSigned`, and `onSettled`, and include it
in `c.set('x402', ...)`. Do not recompute it on a paid retry.

- [ ] **Step 5: Bind the execution quote in the Collar offer hook**

Change the Collar lifecycle signature and journal call to:

```js
    async onOffered({ idempotencyKey, requirements, expiresAt, executionQuote }) {
```

```js
      journal.offerExternalPayment(idempotencyKey, {
        quoteId: requirements.extra.quoteId,
        amountAtomic: requirements.maxAmountRequired,
        currency: 'USDC',
        network: requirements.network,
        asset: requirements.asset,
        payTo: requirements.payTo,
        resource: requirements.resource,
        requestHash: requirements.extra.requestHash,
        requirementsHash: hash(canonicalJson(requirements)),
        expiresAt,
        executionQuote,
      });
```

The x402 `quoteId`, journal quote ID, and execution quote ID are now identical.

Change the Collar `loadFrozenOffer` hook to return the complete pair:

```js
const persistedQuote = journal.getByIdempotencyKey(idempotencyKey)?.quote;
return persistedQuote
  ? { requirements: persistedQuote.requirements, executionQuote: persistedQuote.executionQuote }
  : null;
```

- [ ] **Step 6: Run journal and lifecycle tests**

Run: `node --test spikes/pi-wielder/tests/invocation-journal.test.mjs spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

Expected: PASS; the same quote object and byte-identical PaymentRequirements appear on
challenge and retry.

- [ ] **Step 7: Commit quote propagation**

```bash
git add spikes/pi-wielder/src/x402-seller.mjs spikes/pi-wielder/src/invocation-journal.mjs spikes/pi-wielder/tests/x402-lifecycle.test.mjs
git commit -m "feat: bind execution quote to x402 payment"
```

### Task 4: Finalize actual-or-unknown COGS in Collar receipts

**Files:**
- Modify: `spikes/pi-wielder/src/collar.mjs`
- Create: `spikes/pi-wielder/tests/collar-cogs.test.mjs`

- [ ] **Step 1: Write failing Collar economics integration tests**

Create `spikes/pi-wielder/tests/collar-cogs.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import { createAnthropicExecutor, createCollar, startCollar, SKILL_ID } from '../src/collar.mjs';
import { catalogDigest, EXECUTION_CATALOG } from '../src/execution-economics.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { createInvocationJournal, createReceiptSigner } from '../src/invocation-journal.mjs';
import { payingFetch, startProxy } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';

async function stack(collarOptions = {}) {
  const facilitatorApp = createMockFacilitator();
  const facilitator = {
    transport: createMockFacilitatorTransport((url, init) => facilitatorApp.request(url, init)),
    close() {},
  };
  const collar = await startCollar({ facilitatorTransport: facilitator.transport, ...collarOptions });
  const proxy = await startProxy({
    account: throwawayAccount(),
    collarUrl: collar.url,
    trustedCollarPublicKeyPem: collar.signingPublicKeyPem,
    trustedCollarKeyId: collar.signingKeyId,
  });
  return { facilitator, collar, proxy };
}

async function invoke(proxy, execution = {}) {
  const res = await fetch(`${proxy.url}/invoke/${SKILL_ID}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'optimize this prompt', execution }),
  });
  return { res, body: await res.json() };
}

test('known provider usage is charged before the Royalty pool', async () => {
  const services = await stack();
  try {
    const { res, body } = await invoke(services.proxy);
    assert.equal(res.status, 200);
    const accounting = body.receipt.receipt.accounting;
    assert.equal(accounting.executionCogs.status, 'known');
    assert.equal(accounting.executionCogs.actualAtomic, '756');
    assert.equal(accounting.executionCostAtomic, '756');
    assert.equal(accounting.royaltyPoolAtomic, '236994');
    assert.equal(accounting.protocolFeeAtomic, '6250');
    assert.equal(accounting.contributionMarginAtomic, '6250');
    assert.equal(body.receipt.receipt.quote.executionQuote.quoteId, accounting.quoteId);
  } finally {
    services.proxy.close(); services.collar.close(); services.facilitator.close();
  }
});

test('missing usage fails settled execution, emits no output, and holds the full gross', async () => {
  const services = await stack({
    executeSkill: async () => ({ output: 'safe output', usage: null }),
  });
  try {
    const { res, body } = await invoke(services.proxy);
    assert.equal(res.status, 500);
    assert.equal(body.output, undefined);
    assert.equal(body.receipt.receipt.execution.failureClass, 'COGS_UNKNOWN');
    const accounting = body.receipt.receipt.accounting;
    const cogs = accounting.executionCogs;
    assert.equal(cogs.status, 'unknown');
    assert.equal(cogs.actualAtomic, null);
    assert.equal(cogs.chargedAtomic, null);
    assert.equal(cogs.quotedWorstCaseAtomic, '79872');
    assert.equal(accounting.royaltyPoolAtomic, '0');
    assert.deepEqual(accounting.holderCredits, []);
    assert.deepEqual(accounting.ancestorCredits, []);
    assert.equal(accounting.journalEntries[0].amountAtomic, accounting.grossAtomic);
  } finally {
    services.proxy.close(); services.collar.close(); services.facilitator.close();
  }
});

test('synthetic pricing blocks live adapter construction even when live mode is requested', () => {
  let constructions = 0;
  assert.throws(() => createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async () => { throw new Error('must not fetch'); }),
    mockLlm: false,
    allowLiveProvider: true,
    liveExecutorFactory: () => { constructions += 1; return async () => ({ output: '', usage: null }); },
  }), (error) => error.code === 'LIVE_PRICING_UNAPPROVED');
  assert.equal(constructions, 0);
});

test('live approval is rechecked against the canonical catalog before adapter construction', () => {
  const catalog = structuredClone(EXECUTION_CATALOG);
  Object.assign(catalog, {
    evidenceLabel: 'human_verified',
    source: 'https://provider.example/pricing/2026-07-17',
    asOf: '2026-07-17T00:00:00.000Z',
  });
  const liveApproval = { catalogDigest: catalogDigest(catalog), spendCapAtomic: '250000' };
  catalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  let constructions = 0;
  assert.throws(() => createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async () => { throw new Error('must not fetch'); }),
    mockLlm: false, allowLiveProvider: true,
    executionCatalog: catalog, liveApproval,
    liveExecutorFactory: () => { constructions += 1; return async () => {}; },
  }), (error) => error.code === 'LIVE_CATALOG_DIGEST');
  assert.equal(constructions, 0);
});

test('a restarted Collar rejects persisted quote identity drift before facilitator or provider calls', async () => {
  const facilitatorApp = createMockFacilitator();
  let facilitatorCalls = 0;
  const transport = createMockFacilitatorTransport((url, init) => {
    facilitatorCalls += 1;
    return facilitatorApp.request(url, init);
  });
  const journal = createInvocationJournal({ signer: createReceiptSigner() });
  const beforeRestart = createCollar({ facilitatorTransport: transport, journal });
  const changedCatalog = structuredClone(EXECUTION_CATALOG);
  changedCatalog.models['claude-sonnet-4-6'].outputAtomicPerMillionTokens = '15000001';
  const afterRestart = createCollar({
    facilitatorTransport: transport, journal, executionCatalog: changedCatalog,
  });
  let sellerRequests = 0;
  const result = await payingFetch(throwawayAccount(), `http://seller.test/invoke/${SKILL_ID}`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ input: 'same frozen request' }),
  }, {
    idempotencyKey: 'restart-catalog-drift',
    fetchImpl: (url, init) => (++sellerRequests === 1 ? beforeRestart.app : afterRestart.app).request(url, init),
  });
  assert.equal(result.res.status, 409);
  assert.equal((await result.res.json()).error.includes('catalog differs'), true);
  assert.equal(facilitatorCalls, 0);
  assert.equal(journal.events.some((event) => event.type === 'payment.signed'), false);
});

test('Anthropic adapter sends the frozen model and exact output cap and rejects prompt overflow before fetch', async () => {
  const requests = [];
  const executor = createAnthropicExecutor({
    apiKey: 'test-only',
    fetchImpl: async (_url, init) => {
      requests.push(JSON.parse(init.body));
      return { ok: true, json: async () => ({ content: [{ text: 'ok' }], usage: { input_tokens: 11, output_tokens: 2 } }) };
    },
  });
  const frozen = { model: 'claude-sonnet-4-6', maxInputTokens: 300, maxOutputTokens: 17 };
  assert.deepEqual(await executor({
    skillContent: 'system', input: 'hello', ...frozen, promptBytes: 11, estimatedInputTokens: 267,
  }), { output: 'ok', usage: { model: frozen.model, inputTokens: 11, outputTokens: 2 } });
  assert.equal(requests[0].model, frozen.model);
  assert.equal(requests[0].max_tokens, frozen.maxOutputTokens);
  await assert.rejects(executor({
    skillContent: 'x'.repeat(45), input: '', ...frozen, promptBytes: 45, estimatedInputTokens: 301,
  }), (error) => error.code === 'PROMPT_TOKEN_BOUND');
  assert.equal(requests.length, 1);
});

test('body and complete-prompt caps reject before a 402 offer', async () => {
  const facilitator = createMockFacilitator();
  const collar = await startCollar({
    facilitatorTransport: createMockFacilitatorTransport((url, init) => facilitator.request(url, init)),
  });
  try {
    const cases = [
      [{ input: 'x'.repeat(4097) }, 413, 'REQUEST_BODY_TOO_LARGE'],
      [{ input: 'x', execution: { maxInputTokens: 300 } }, 400, 'PROMPT_TOKEN_BOUND'],
    ];
    for (const [body, status, code] of cases) {
      const res = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
        body: JSON.stringify(body),
      });
      assert.equal(res.status, status);
      assert.equal((await res.json()).code, code);
    }
    assert.equal(collar.journal.events.length, 0);
  } finally {
    collar.close();
  }
});

test('unlisted models and excessive token limits fail before a 402 offer', async () => {
  const facilitator = createMockFacilitator();
  const collar = await startCollar({
    facilitatorTransport: createMockFacilitatorTransport((url, init) => facilitator.request(url, init)),
  });
  try {
    for (const execution of [
      { model: 'unlisted-model' },
      { model: 'claude-sonnet-4-6', maxOutputTokens: 2049 },
    ]) {
      const res = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'Idempotency-Key': crypto.randomUUID() },
        body: JSON.stringify({ input: 'x', execution }),
      });
      assert.equal(res.status, 400);
      assert.equal((await res.json()).code === 'MODEL_NOT_ALLOWED' || execution.maxOutputTokens === 2049, true);
    }
    assert.equal(collar.journal.events.length, 0);
  } finally {
    collar.close();
  }
});

test('usage above the accepted limit fails after settlement and returns no output', async () => {
  const services = await stack({
    executeSkill: async () => ({
      output: 'must not escape',
      usage: { model: 'claude-sonnet-4-6', inputTokens: 4096, outputTokens: 2049 },
    }),
  });
  try {
    const { res, body } = await invoke(services.proxy);
    assert.equal(res.status, 500);
    assert.equal(body.output, undefined);
    assert.equal(body.receipt.receipt.payment.state, 'settled');
    assert.equal(body.receipt.receipt.execution.state, 'failed');
    assert.equal(body.receipt.receipt.execution.failureClass, 'USAGE_EXCEEDS_QUOTE');
    const accounting = body.receipt.receipt.accounting;
    assert.equal(accounting.allocationState, 'pending_cogs_reconciliation');
    assert.equal(accounting.executionCogs.status, 'known');
    assert.equal(accounting.executionCogs.actualAtomic, '79887');
    assert.equal(accounting.executionCogs.accruedOverrunAtomic, '15');
    assert.equal(accounting.executionCogs.failureClass, 'USAGE_EXCEEDS_QUOTE');
    assert.equal(accounting.royaltyPoolAtomic, '0');
    assert.deepEqual(accounting.holderCredits, []);
    assert.equal(accounting.journalEntries[0].amountAtomic, accounting.grossAtomic);
  } finally {
    services.proxy.close(); services.collar.close(); services.facilitator.close();
  }
});

for (const [name, executeSkill, failureClass, expectedCogs] of [
  ['provider throw', async () => { throw Object.assign(new Error('upstream failed'), { code: 'UPSTREAM_PROVIDER_ERROR' }); }, 'UPSTREAM_PROVIDER_ERROR', 'unknown'],
  ['malformed result', async () => ({ output: 42, usage: { model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 } }), 'INVALID_EXECUTOR_RESULT', 'known'],
]) test(`${name} records a balanced pending reconciliation and emits no output`, async () => {
  const services = await stack({ executeSkill });
  try {
    const { res, body } = await invoke(services.proxy);
    assert.equal(res.status, 500);
    assert.equal(body.output, undefined);
    assert.equal(body.receipt.receipt.execution.failureClass, failureClass);
    const accounting = body.receipt.receipt.accounting;
    assert.equal(accounting.allocationState, 'pending_cogs_reconciliation');
    assert.equal(accounting.executionCogs.status, expectedCogs);
    assert.equal(accounting.executionCogs.failureClass, failureClass);
    assert.equal(accounting.royaltyPoolAtomic, '0');
    assert.deepEqual(accounting.holderCredits, []);
    assert.equal(accounting.journalEntries[0].amountAtomic, accounting.grossAtomic);
  } finally {
    services.proxy.close(); services.collar.close(); services.facilitator.close();
  }
});
```

Add `import crypto from 'node:crypto';` at the top of this test.

- [ ] **Step 2: Run the test and verify gross-only accounting fails**

Run: `node --test spikes/pi-wielder/tests/collar-cogs.test.mjs`

Expected: FAIL because the Collar does not quote limits or record provider usage.

- [ ] **Step 3: Add execution-economics dependencies and constants to the Collar**

Add these imports:

```js
import { assertArtifactNotSerialized } from './artifact-boundary.mjs';
import {
  artifactDigest,
  assertFrozenExecutionIdentity,
  assertLiveCatalogApproval,
  conservativeProviderPromptBound,
  createPendingExecutionAccounting,
  createExecutionQuote,
  EXECUTION_CATALOG,
  ExecutionEconomicsError,
  finalizeExecutionAccounting,
} from './execution-economics.mjs';
```

Add these constants near `DEFAULT_PRICE_USDC`:

```js
const DEFAULT_EXECUTION = Object.freeze({
  model: 'claude-sonnet-4-6',
  maxInputTokens: 16384,
  maxOutputTokens: 2048,
});
const SETTLEMENT_COST_ATOMIC = '1000';
const REFUND_RESERVE_ATOMIC = '5000';
const MAX_REQUEST_BODY_BYTES = 4096;
const SKILL_VERSION = 'optimizing-claude-code-prompts/2026-07-17-v1';
```

Change the Collar defaults so offline mock execution is the safe default, and add the
catalog/live-factory options:

```js
  mockLlm = process.env.MOCK_LLM !== '0',
  allowLiveProvider = process.env.ALLOW_LIVE_PROVIDER === '1',
  executionCatalog = EXECUTION_CATALOG,
  liveApproval = null,
  liveExecutorFactory = () => createAnthropicExecutor(),
```

Before constructing the executor, add this fail-closed gate:

```js
  let executor = executeSkill;
  if (!executor && mockLlm) {
    executor = async ({ input }) => ({
      output: mockSkillOutput(input),
      usage: { model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    });
  }
  if (!executor) {
    if (!allowLiveProvider) {
      throw new ExecutionEconomicsError(
        'LIVE_PRICING_UNAPPROVED',
        'live provider execution requires an explicit gate',
      );
    }
    assertLiveCatalogApproval({ catalog: executionCatalog, approval: liveApproval, grossAtomic: priceAtomic });
    executor = liveExecutorFactory();
  }
```

For standalone live mode, construct `liveApproval` only when both
`LIVE_CATALOG_DIGEST` and `LIVE_SPEND_CAP_ATOMIC` are explicitly present; otherwise
leave it `null` and fail before factory/fetch construction. The digest is recomputed
from canonical catalog content with any catalog-owned `approval` field excluded and
must equal the separately supplied human value exactly.

Pass `executionCatalog` into both `createExecutionQuote` and
`finalizeExecutionAccounting`; do not silently fall back to the synthetic catalog.

- [ ] **Step 4: Quote from the frozen request before offering payment**

Inside `createCollar`, add:

```js
  const readInvocationBody = async (c) => {
    const cached = c.get('invocationBody');
    if (cached) return cached;
    const raw = await c.req.text();
    const requestBodyBytes = Buffer.byteLength(raw, 'utf8');
    if (requestBodyBytes > MAX_REQUEST_BODY_BYTES) {
      throw new ExecutionEconomicsError('REQUEST_BODY_TOO_LARGE', 'request body exceeds the pre-payment byte cap');
    }
    let body;
    try { body = JSON.parse(raw); } catch { throw new ExecutionEconomicsError('INVALID_REQUEST', 'body must be JSON'); }
    if (typeof body?.input !== 'string' || !body.input) {
      throw new ExecutionEconomicsError('INVALID_REQUEST', 'body must contain a non-empty string input');
    }
    const parsed = { body, requestBodyBytes };
    c.set('invocationBody', parsed);
    return parsed;
  };

  const buildQuote = async (c) => {
    const { body, requestBodyBytes } = await readInvocationBody(c);
    const requested = { ...DEFAULT_EXECUTION, ...(body.execution ?? {}) };
    const promptBound = conservativeProviderPromptBound({
      systemPrompt: skillContent,
      userInput: body.input,
      requestBodyBytes,
      maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
      maxInputTokens: requested.maxInputTokens,
    });
    return createExecutionQuote({
      grossAtomic: priceAtomic,
      model: requested.model,
      maxInputTokens: requested.maxInputTokens,
      maxOutputTokens: requested.maxOutputTokens,
      promptBytes: promptBound.promptBytes,
      estimatedInputTokens: promptBound.estimatedInputTokens,
      settlementCostAtomic: SETTLEMENT_COST_ATOMIC,
      refundReserveAtomic: REFUND_RESERVE_ATOMIC,
      protocolFeeBps: 250,
      leafSkillId: SKILL_ID,
      skillId: SKILL_ID,
      skillVersion: SKILL_VERSION,
      artifactHash: artifactDigest(skillContent),
      skills: royaltyGraph,
      catalog: executionCatalog,
    });
  };
```

Pass `quote: buildQuote` to `x402Paywall`. Its frozen cache guarantees that the paid
retry receives the same object through `c.get('x402').executionQuote`.
The paid handler calls `readInvocationBody(c)` too (the retry is a new request) and uses
that cached body; it never calls `c.req.json()` independently.

Extend the lifecycle `onSigned` parameters with `executionQuote` and run this check as
its first statement, before `markExternalPaymentSigned` and therefore before facilitator
verify/settle. Repeat the same check immediately before calling `executor` to close the
configuration-mutation window after settlement:

```js
assertFrozenExecutionIdentity({
  quote: executionQuote,
  skillId: SKILL_ID,
  skillVersion: SKILL_VERSION,
  artifactContent: skillContent,
  skills: royaltyGraph,
  catalog: executionCatalog,
});
```

On the post-settlement check, convert any drift error to `createPendingExecutionAccounting`
with that exact failure class, full-gross hold, and no provider call, output, or Royalty
claim. A paid retry recovered after restart never substitutes current identity into the
persisted quote.

- [ ] **Step 5: Return usage from mock and Anthropic adapters**

Make the default mock executor return:

```js
{
  output: mockSkillOutput(input),
  usage: { model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
}
```

Replace the live helper with this injectable adapter. It recomputes the complete prompt
bound before fetch and sends the frozen quote's exact model and output limit:

```js
export function createAnthropicExecutor({
  apiKey = process.env.ANTHROPIC_API_KEY,
  fetchImpl = fetch,
} = {}) {
  return async ({
    skillContent, input, model, maxInputTokens, maxOutputTokens,
    promptBytes, estimatedInputTokens,
  }) => {
    const rebound = conservativeProviderPromptBound({
      systemPrompt: skillContent, userInput: input, requestBodyBytes: 0,
      maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES, maxInputTokens,
    });
    if (rebound.promptBytes !== promptBytes || rebound.estimatedInputTokens !== estimatedInputTokens) {
      throw new ExecutionEconomicsError('FROZEN_PROMPT_MISMATCH', 'provider prompt differs from the accepted quote');
    }
    const response = await fetchImpl('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'content-type': 'application/json', 'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model,
        max_tokens: maxOutputTokens,
        system: skillContent,
        messages: [{ role: 'user', content: input }],
      }),
    });
    if (!response.ok) {
      throw Object.assign(new Error(`Anthropic returned ${response.status}`), { code: 'UPSTREAM_PROVIDER_ERROR' });
    }
    const data = await response.json();
    return {
      output: data.content?.map((block) => block.text ?? '').join('') ?? '',
      usage: data.usage ? {
        model,
        inputTokens: data.usage.input_tokens,
        outputTokens: data.usage.output_tokens,
      } : null,
    };
  };
}
```

The live adapter still does not run in automated tests. Its catalog version remains
`synthetic_config` until a human verifies a current price sheet.

- [ ] **Step 6: Replace zero-cost success allocation with final COGS accounting**

First replace Plan 5's helper signature/body fields with:

```js
const finishFailure = (failureClass, message, status, accounting = null) => {
  journal.finishExecution(key, {
    executionAttemptId,
    outcome: 'failed', failureClass, message, outcomeHash: null, accounting,
  });
  return c.json({ error: message, receipt: journal.issueReceipt(key) }, status);
};
```

Invoke the executor only with frozen quote fields, then finalize accounting before any
output can escape. Every post-provider failure receives one balanced pending accounting
record; retain valid usage even when the result or accepted caps are violated:

```js
      const { body } = await readInvocationBody(c);
      const frozenQuote = payment.executionQuote;
      try {
        assertFrozenExecutionIdentity({
          quote: frozenQuote, skillId: SKILL_ID, skillVersion: SKILL_VERSION,
          artifactContent: skillContent, skills: royaltyGraph, catalog: executionCatalog,
        });
      } catch (error) {
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote, usage: null, failureClass: error.code,
          reason: error.message, catalog: executionCatalog,
        });
        return finishFailure(error.code, error.message, 500, accounting);
      }
      let execution;
      try {
        execution = await executor({
          skillContent,
          input: body.input,
          model: frozenQuote.model,
          maxInputTokens: frozenQuote.maxInputTokens,
          maxOutputTokens: frozenQuote.maxOutputTokens,
          promptBytes: frozenQuote.promptBytes,
          estimatedInputTokens: frozenQuote.estimatedInputTokens,
        });
      } catch (error) {
        const failureClass = error.code ?? 'UPSTREAM_PROVIDER_ERROR';
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: error.usage ?? null,
          failureClass,
          reason: error.message,
          catalog: executionCatalog,
        });
        return finishFailure(failureClass, error.message, 500, accounting);
      }

      if (!execution || typeof execution.output !== 'string'
        || !Object.hasOwn(execution, 'usage')
        || !(execution.usage == null || typeof execution.usage === 'object')) {
        const failureClass = 'INVALID_EXECUTOR_RESULT';
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: execution?.usage ?? null,
          failureClass,
          reason: 'executor must return exactly output:string and usage:object|null',
          catalog: executionCatalog,
        });
        return finishFailure(failureClass, 'invalid executor result', 500, accounting);
      }

      try {
        const accounting = finalizeExecutionAccounting({
          quote: frozenQuote,
          usage: execution.usage ?? null,
          unknownReason: execution.usage == null ? 'provider response omitted usage' : undefined,
          leafSkillId: SKILL_ID,
          skills: royaltyGraph,
          catalog: executionCatalog,
        });
        if (accounting.executionCogs.status === 'unknown') {
          return finishFailure(
            'COGS_UNKNOWN',
            'provider usage is unavailable; full gross held pending trusted COGS reconciliation or refund',
            500,
            accounting,
          );
        }
        assertArtifactNotSerialized({ output: execution.output, artifact: skillContent });
        journal.finishExecution(key, {
          executionAttemptId,
          outcome: 'succeeded',
          failureClass: null,
          message: null,
          outcomeHash: hash(execution.output),
          accounting,
        });
      } catch (error) {
        if (error instanceof ExecutionEconomicsError || error.message.includes('artifact serialization')) {
          const failureClass = error.code ?? 'ARTIFACT_SERIALIZATION';
          const accounting = createPendingExecutionAccounting({
            quote: frozenQuote,
            usage: execution.usage,
            failureClass,
            reason: error.message,
            catalog: executionCatalog,
          });
          return finishFailure(failureClass, error.message, 500, accounting);
        }
        throw error;
      }
      return c.json({ output: execution.output, receipt: journal.issueReceipt(key) });
```

Delete the Plan-5 zero-cost `allocateExternalGross(...)` block and its success response.
Update the earlier executor-result check to accept exactly
`{ output: string, usage: object | null }`.

- [ ] **Step 7: Run Collar economics and boundary tests**

Run: `node --test spikes/pi-wielder/tests/execution-economics.test.mjs spikes/pi-wielder/tests/artifact-boundary.test.mjs spikes/pi-wielder/tests/collar-cogs.test.mjs`

Expected: PASS, 21 tests and 0 failures.

- [ ] **Step 8: Commit COGS-aware Collar execution**

```bash
git add spikes/pi-wielder/src/collar.mjs spikes/pi-wielder/tests/collar-cogs.test.mjs
git commit -m "feat: settle hosted Skill COGS before royalties"
```

### Task 5: Update the end-to-end proof and evidence labels

**Files:**
- Modify: `spikes/pi-wielder/e2e.mjs`
- Modify: `spikes/pi-wielder/README.md`
- Modify: `spikes/pi-wielder/RUNBOOK.md`
- Verify: `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`

- [ ] **Step 1: Assert actual COGS and exact post-cost allocation in e2e**

After the existing signed-receipt assertions in `e2e.mjs`, add:

```js
  const skillAccounting = entries[2].receipt.receipt.accounting;
  eq(skillAccounting.executionCogs.status, 'known', 'mock provider usage is explicitly known');
  eq(skillAccounting.executionCogs.actualAtomic, '756', 'mock provider COGS uses the versioned catalog');
  eq(skillAccounting.settlementCostAtomic, '1000', 'settlement cost is allocated before royalties');
  eq(skillAccounting.protocolFeeAtomic, '6250', 'protocol fee remains exact');
  eq(skillAccounting.refundReserveAtomic, '5000', 'refund reserve remains explicit');
  eq(skillAccounting.royaltyPoolAtomic, '236994', 'Royalty pool is the exact post-cost residual');
  eq(
    BigInt(skillAccounting.executionCostAtomic)
      + BigInt(skillAccounting.settlementCostAtomic)
      + BigInt(skillAccounting.protocolFeeAtomic)
      + BigInt(skillAccounting.royaltyPoolAtomic)
      + BigInt(skillAccounting.refundReserveAtomic),
    BigInt(skillAccounting.grossAtomic),
    'receipt accounting conserves gross exactly',
  );
```

- [ ] **Step 2: Replace gross-split prose with the implemented ordering**

In `spikes/pi-wielder/README.md`, replace any example that splits the full `$0.25`
only between Creator and treasury with:

```markdown
For the deterministic mock fixture, a 250,000-atomic-USDC gross Invocation allocates
756 to synthetic-config execution COGS, 1,000 to settlement cost, 6,250 to protocol
fee, 5,000 to refund reserve, and 236,994 to the Royalty pool. These are mock accounting
values, not observed live provider economics. If provider usage is missing, the settled
Invocation fails `COGS_UNKNOWN`, emits no output or Royalty credits, and holds full gross
in `pending_cogs_reconciliation` until trusted reconciliation or refund.
```

Replace “the Skill never leaves” with:

```markdown
The Collar does not directly return or serialize the hosted Skill artifact. A narrow
runtime guard rejects full or long exact artifact fragments. Model-output extraction
can never be ruled out categorically; prompt-injection resistance remains adversarial
test evidence, not a secrecy guarantee.
```

- [ ] **Step 3: Add the human live-pricing gate to the runbook**

Add to `spikes/pi-wielder/RUNBOOK.md`:

```markdown
Before a live provider run, verify the current provider price sheet, add a new immutable
catalog version with `evidenceLabel: human_verified`, source, and as-of timestamp. Compute
its exact canonical `catalogDigest`, set that separately as `LIVE_CATALOG_DIGEST`, set an
atomic `LIVE_SPEND_CAP_ATOMIC`, then set `ALLOW_LIVE_PROVIDER=1`. Do not embed approval
or spend authorization in the catalog itself. Never relabel
`synthetic-anthropic-2026-07-17-v1` as measured. Automated verification stays on the
mock facilitator and mock model and uses no real funds.
```

- [ ] **Step 4: Verify—not recreate—the historical overhead tombstone**

Plan 1 owns `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. Run:

```bash
node -e "const m=require('./spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json'); if(m.evidenceStatus!=='historical_unreproducible') process.exit(1)"
```

Expected: exit 0. Do not quote, recompute, or validate its historical p50/p95 because
the raw n=48 samples are absent. Do not edit or overwrite this manifest in this plan.

- [ ] **Step 5: Run focused and end-to-end verification**

Run: `npm test --prefix prototype && npm test --prefix spikes/pi-wielder && npm run e2e --prefix spikes/pi-wielder`

Expected: every offline test passes; e2e conserves 250,000 atomic USDC with 756 known
mock COGS and returns one pinned-key Collar receipt. No provider or chain network is used.

- [ ] **Step 6: Confirm unknown COGS is never zeroed**

Run: `rg -n "status: 'unknown'|actualAtomic: null|chargedAtomic" spikes/pi-wielder/src/execution-economics.mjs spikes/pi-wielder/tests`

Expected: the unknown path has `actualAtomic: null`, `chargedAtomic: null`, a non-zero
`quotedWorstCaseAtomic`, no finalized Royalty credits, and one full-gross balanced hold;
no test or implementation assigns zero to unknown actual cost.

- [ ] **Step 7: Commit runtime truthfulness documentation**

```bash
git add spikes/pi-wielder/e2e.mjs spikes/pi-wielder/README.md spikes/pi-wielder/RUNBOOK.md
git commit -m "docs: label hosted Skill execution economics"
```

## Definition of done

- A versioned allowlist controls model, token limits, and atomic input/output rates.
- Mock execution is the default; a live adapter is not even constructed without an
  explicit gate, a human-verified immutable catalog carrying source/as-of, and separately
  supplied exact digest and spend authorization.
- The x402 offer, Wielder authorization, journal quote, and signed receipt share one immutable quote ID and request hash.
- That quote ID also commits to Skill ID/version, hosted artifact hash, canonical Royalty
  graph digest, and canonical catalog digest; restart/config drift is rejected before
  facilitator settlement and rechecked immediately before provider execution.
- Worst-case COGS, settlement cost, fee, and refund reserve fit inside gross before any offer is signable.
- Known usage charges exact versioned COGS. Missing usage ends `failed/COGS_UNKNOWN`,
  releases no output or Royalty claims, and holds full gross for reconciliation/refund.
- Thrown providers and malformed results hold full gross with unknown or retained-known
  usage; above-cap valid usage records accrued COGS/overrun. All return failed signed
  receipts without output or Royalty claims.
- Royalty holder and ancestor credits are calculated only from the post-cost Royalty pool through `prototype/atomic-money.mjs`.
- The runtime blocks direct artifact serialization but makes no absolute model-extraction guarantee.
- Historical n=48 overhead numbers remain `historical_unreproducible`; this plan does not present them as a validated distribution.
- All verification is offline/mock, Base Sepolia-shaped, and uses no real funds, live provider call, or mainnet transaction.

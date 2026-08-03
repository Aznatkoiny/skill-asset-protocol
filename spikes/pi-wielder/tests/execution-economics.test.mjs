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
  schemaVersion: 2,
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
    schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42,
  }), 756n);
  assert.equal(usageCostAtomic({
    schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 1, outputTokens: 1,
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
  assert.equal(result.schemaVersion, 2);
  assert.equal(result.catalogVersion, EXECUTION_CATALOG.version);
  assert.equal(result.evidenceLabel, 'synthetic_config');
  assert.equal(result.worstCaseExecutionCostAtomic, '79872');
  assert.equal(result.protocolFeeAtomic, '6250');
  assert.equal(result.worstCaseRoyaltyPoolAtomic, '157878');
  assert.equal(result.worstCaseContributionMarginAtomic, '6250');
  assert.match(result.quoteId, /^sha256:[0-9a-f]{64}$/);
  assert.ok(Object.isFrozen(result));
});

test('known usage charges actual COGS before increasing the Royalty pool', () => {
  const result = finalizeExecutionAccounting({
    quote: quote(),
    usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    leafSkillId: SKILL_ID,
    skills,
  });
  assert.equal(result.schemaVersion, 2);
  assert.deepEqual(result.executionCogs, {
    schemaVersion: 2,
    status: 'known',
    actualAtomic: '756',
    chargedAtomic: '756',
    quotedWorstCaseAtomic: '79872',
    accruedOverrunAtomic: '0',
    catalogVersion: EXECUTION_CATALOG.version,
    catalogDigest: quote().catalogDigest,
    usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 42, outputTokens: 42 },
    failureClass: null,
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
  assert.equal(result.schemaVersion, 2);
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
    usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 4096, outputTokens: 2049 },
    leafSkillId: SKILL_ID,
    skills,
  }), (error) => error.code === 'USAGE_EXCEEDS_QUOTE');
});

test('post-provider overrun accounting records known accrued COGS but finalizes no claims', () => {
  const result = createPendingExecutionAccounting({
    quote: quote(),
    usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 16384, outputTokens: 2049 },
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
  const driftedKnownUsage = createPendingExecutionAccounting({
    quote: frozen,
    usage: { schemaVersion: 2, model: frozen.model, inputTokens: 42, outputTokens: 42 },
    failureClass: 'CATALOG_DIGEST_DRIFT',
    reason: 'current catalog changed',
    catalog: driftedCatalog,
  });
  assert.equal(driftedKnownUsage.executionCogs.status, 'unknown');
  assert.equal(driftedKnownUsage.executionCogs.actualAtomic, null);
});

test('strict v2 quote and usage schemas reject inherited, unknown, and unsafe values', () => {
  assert.throws(() => createExecutionQuote(Object.assign(Object.create({ grossAtomic: '250000' }), {
    model: 'claude-sonnet-4-6', maxInputTokens: 1, maxOutputTokens: 1,
  })), (error) => error.code === 'QUOTE_SCHEMA');
  assert.throws(() => finalizeExecutionAccounting({
    quote: quote(),
    usage: { schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: 1, outputTokens: 1, extra: true },
    leafSkillId: SKILL_ID,
    skills,
  }), (error) => error.code === 'USAGE_SCHEMA');
  assert.throws(() => usageCostAtomic({
    schemaVersion: 2, model: 'claude-sonnet-4-6', inputTokens: Number.MAX_SAFE_INTEGER + 1, outputTokens: 0,
  }), (error) => error.code === 'TOKEN_INTEGER');
});

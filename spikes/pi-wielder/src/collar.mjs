// Authoritative seller-side Collar for the Pi-Wielder spike.
//
// The append-only Invocation journal owns payment, execution, accounting, and
// signed receipts. A settled payment is never erased by an execution failure;
// ambiguous settlement or execution stays unresolved until a trusted resolver
// advances it. The hosted Skill artifact is read server-side and is not
// directly serialized in responses.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { serve } from '@hono/node-server';
import { Hono } from 'hono';

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
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  usdcToAtomic,
  x402Paywall,
  x402RequestBodyBytes,
  x402RequestBodyText,
} from './x402-seller.mjs';
import {
  canonicalJson,
  createInvocationJournal,
} from './invocation-journal.mjs';
import {
  readJsonBody,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from './runtime-boundaries.mjs';

export const SKILL_ID = 'optimizing-claude-code-prompts';
const SKILL_PATH = fileURLToPath(
  new URL(`../../../.claude/skills/${SKILL_ID}/SKILL.md`, import.meta.url),
);
const DEFAULT_PRICE_USDC = '0.25';
const DEFAULT_EXECUTION = Object.freeze({
  model: 'claude-sonnet-4-6',
  maxInputTokens: 16384,
  maxOutputTokens: 2048,
});
const SETTLEMENT_COST_ATOMIC = '1000';
const REFUND_RESERVE_ATOMIC = '5000';
const MAX_REQUEST_BODY_BYTES = 4096;
export const DEFAULT_PROVIDER_TIMEOUT_MS = 30_000;
export const DEFAULT_PROVIDER_RESPONSE_BYTES = 1024 * 1024;
const SKILL_VERSION = 'optimizing-claude-code-prompts/2026-07-17-v1';
const TERMINAL = new Set(['succeeded', 'failed', 'cancelled']);

const hash = (value) => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;

const royaltyGraph = Object.freeze({
  [SKILL_ID]: Object.freeze({
    parentIds: Object.freeze([]),
    inheritBps: 0,
    holders: Object.freeze([{ recipientId: 'creator', bps: 10_000 }]),
  }),
});

function legacyPendingFailureAccounting(amountAtomic) {
  return {
    grossAtomic: String(amountAtomic),
    allocationState: 'pending_cogs_reconciliation',
    holderCredits: [],
    ancestorCredits: [],
    journalEntries: [{
      category: 'unresolved-execution-accounting',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'hold:execution-accounting-reconciliation',
      amountAtomic: String(amountAtomic),
    }],
  };
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function isExactPlainObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function validTxHash(value) {
  return /^0x[0-9a-fA-F]{64}$/.test(String(value ?? ''));
}

function sameAddress(left, right) {
  return /^0x[0-9a-fA-F]{40}$/.test(String(left ?? ''))
    && String(left).toLowerCase() === String(right ?? '').toLowerCase();
}

export async function chooseFacilitator({
  env = process.env,
  createMock = async () => (await import('./facilitator-mock.mjs')).createMockFacilitator(),
} = {}) {
  if (env.ALLOW_LIVE_X402 !== '1') {
    const app = await createMock();
    return {
      transport: createMockFacilitatorTransport((url, init) => app.request(url, init)),
      mode: 'mock',
    };
  }
  if (!env.FACILITATOR_URL) {
    throw new Error('ALLOW_LIVE_X402=1 requires an explicit Base Sepolia FACILITATOR_URL');
  }
  return {
    transport: createLiveFacilitatorTransport(env.FACILITATOR_URL),
    mode: 'approved-base-sepolia',
  };
}

export function createCollar({
  facilitatorTransport,
  payTo = process.env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dead',
  priceUsdc = process.env.SKILL_PRICE_USDC || DEFAULT_PRICE_USDC,
  mockLlm = process.env.MOCK_LLM !== '0',
  allowLiveProvider = process.env.ALLOW_LIVE_PROVIDER === '1',
  executionCatalog = EXECUTION_CATALOG,
  liveApproval = process.env.LIVE_CATALOG_DIGEST && process.env.LIVE_SPEND_CAP_ATOMIC
    ? {
      catalogDigest: process.env.LIVE_CATALOG_DIGEST,
      spendCapAtomic: process.env.LIVE_SPEND_CAP_ATOMIC,
    }
    : null,
  liveExecutorFactory = () => createAnthropicExecutor(),
  journal = null,
  journalFile = process.env.COLLAR_JOURNAL_FILE || null,
  signingKeyFile = process.env.COLLAR_SIGNING_KEY_FILE || null,
  receiptSigner = null,
  executeSkill = null,
  providerTimeoutMs = DEFAULT_PROVIDER_TIMEOUT_MS,
  lifecycleFaults = {},
  resolveSettlement = null,
  executeRefund = null,
  resolveRefund = null,
} = {}) {
  if (!Number.isSafeInteger(providerTimeoutMs) || providerTimeoutMs <= 0) {
    throw new TypeError('providerTimeoutMs must be a positive safe integer');
  }
  if (providerTimeoutMs > DEFAULT_PROVIDER_TIMEOUT_MS) {
    throw new TypeError(`providerTimeoutMs cannot exceed ${DEFAULT_PROVIDER_TIMEOUT_MS}`);
  }
  if (journal && (journalFile || signingKeyFile || receiptSigner)) {
    throw new Error('injected journal cannot be combined with journal/key paths or signer');
  }
  if (!journal && Boolean(journalFile) !== Boolean(signingKeyFile)) {
    throw new Error('COLLAR_JOURNAL_FILE and COLLAR_SIGNING_KEY_FILE must be set together');
  }
  journal ??= createInvocationJournal({
    filePath: journalFile,
    signingKeyPath: signingKeyFile,
    signer: receiptSigner,
  });
  if (facilitatorTransport?.mode === 'live') {
    if (!journal.isPersistent) throw new Error('live settlement requires a persistent journal and signing key');
    if (typeof resolveSettlement !== 'function') throw new Error('live settlement requires a trusted settlement resolver');
    if (typeof executeRefund !== 'function') throw new Error('live settlement requires a trusted refund executor');
    if (typeof resolveRefund !== 'function') throw new Error('live settlement requires a trusted refund resolver');
  }
  const settlementResolver = resolveSettlement ?? (async () => ({ settled: false }));
  const refundExecutor = executeRefund ?? null;
  const refundResolver = resolveRefund ?? null;
  const skillContent = fs.readFileSync(SKILL_PATH, 'utf8');
  const skillVersionHash = hash(skillContent);
  const priceAtomic = usdcToAtomic(priceUsdc);
  const frozenExecutionCatalog = deepFreeze(structuredClone(executionCatalog));
  let executor = executeSkill;
  if (!executor && mockLlm) {
    executor = async ({ input }) => ({
      output: mockSkillOutput(input),
      usage: {
        schemaVersion: 2,
        model: 'claude-sonnet-4-6',
        inputTokens: 42,
        outputTokens: 42,
      },
    });
  }
  if (!executor) {
    if (!allowLiveProvider) {
      throw new ExecutionEconomicsError(
        'LIVE_PRICING_UNAPPROVED',
        'live provider execution requires an explicit gate',
      );
    }
    assertLiveCatalogApproval({
      catalog: frozenExecutionCatalog,
      approval: liveApproval,
      grossAtomic: priceAtomic,
    });
    executor = liveExecutorFactory();
  }
  if (typeof executor !== 'function') {
    throw new TypeError('Skill executor must be a function');
  }

  const readInvocationBody = async (c) => {
    const cached = c.get('invocationBody');
    if (cached) return cached;
    const raw = x402RequestBodyText(c);
    const requestBodyBytes = x402RequestBodyBytes(c).byteLength;
    if (requestBodyBytes > MAX_REQUEST_BODY_BYTES) {
      throw new ExecutionEconomicsError(
        'REQUEST_BODY_TOO_LARGE',
        'request body exceeds the pre-payment byte cap',
      );
    }
    let body;
    try {
      body = JSON.parse(raw);
    } catch {
      throw new ExecutionEconomicsError('INVALID_REQUEST', 'body must be JSON');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.getPrototypeOf(body) !== Object.prototype
        || typeof body.input !== 'string' || !body.input) {
      throw new ExecutionEconomicsError(
        'INVALID_REQUEST',
        'body must contain a non-empty string input',
      );
    }
    const execution = body.execution ?? {};
    if (!isExactPlainObject(execution, Object.keys(execution))
        || Object.keys(execution).some((key) => !Object.hasOwn(DEFAULT_EXECUTION, key))) {
      throw new ExecutionEconomicsError(
        'EXECUTION_REQUEST_SCHEMA',
        'execution options contain unknown fields',
      );
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
      schemaVersion: 2,
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
      catalog: frozenExecutionCatalog,
    });
  };

  const persistVerifiedOffer = ({ idempotencyKey, requirements, executionQuote }) => {
    const existing = journal.getByIdempotencyKey(idempotencyKey);
    if (!existing) {
      journal.requestInvocation({
        idempotencyKey,
        mode: 'external',
        skillId: SKILL_ID,
        skillVersionHash,
        requestHash: requirements.extra.requestHash,
        creatorId: 'creator',
        beneficiaryId: null,
      });
    }
    if (!journal.getByIdempotencyKey(idempotencyKey)?.quote) {
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
        expiresAt: requirements.extra.expiresAt,
        requirements,
        executionQuote,
      });
    }
  };

  const lifecycle = {
    // Unpaid challenges are bounded, expiring process-local state in the
    // paywall. Authority begins only after facilitator verification succeeds.
    async onOffered() {},

    async loadFrozenOffer({ idempotencyKey, paymentHeaderPresent = false }) {
      const record = journal.getByIdempotencyKey(idempotencyKey);
      const persistedQuote = record?.quote;
      if (!persistedQuote) return null;
      if (record.schemaVersion === 1 && !paymentHeaderPresent) {
        throw new Error('legacy v1 frozen offers cannot authorize a new payment');
      }
      const verifiedPaymentHash = journal.getVerifiedPaymentHash(idempotencyKey);
      return {
        requirements: persistedQuote.requirements,
        executionQuote: persistedQuote.executionQuote ?? null,
        verificationRequired: verifiedPaymentHash === null,
        verifiedPaymentHash,
      };
    },

    async onSigned({
      idempotencyKey, settlementReference, payer, requirements, executionQuote,
      verifiedPaymentHash,
    }) {
      persistVerifiedOffer({ idempotencyKey, requirements, executionQuote });
      const existing = journal.getByIdempotencyKey(idempotencyKey);
      if (!existing?.quote) throw new Error('verified paid retry could not persist its frozen offer');
      if (existing.quote.requirementsHash !== hash(canonicalJson(requirements))
          || existing.quote.requestHash !== requirements.extra.requestHash) {
        throw new Error('paid retry does not match the frozen x402 requirements');
      }
      if (existing.schemaVersion === 2
          && canonicalJson(existing.quote.executionQuote) !== canonicalJson(executionQuote)) {
        throw new Error('paid retry does not match the frozen execution quote');
      }
      const recordedPaymentHash = journal.getVerifiedPaymentHash(idempotencyKey);
      if (recordedPaymentHash !== null && recordedPaymentHash !== verifiedPaymentHash) {
        throw new Error('paid retry does not match the facilitator-verified payment authorization');
      }
      if (recordedPaymentHash === null && existing.payment.state === 'offered') {
        journal.recordExternalPaymentVerification(idempotencyKey, { verifiedPaymentHash });
      }
      if (existing.payment.settlementReference !== null
          && (existing.payment.settlementReference !== settlementReference
            || existing.payment.payer !== payer)) {
        throw new Error('paid retry does not match the persisted signed payment');
      }
      // A terminal record is immutable historical authority. Replay it before
      // consulting current catalog or artifact configuration.
      if (TERMINAL.has(existing.execution.state)) {
        if (!['settled', 'refunded'].includes(existing.payment.state) || !existing.payment.txHash) {
          throw new Error('terminal Invocation does not carry a replayable settled payment');
        }
        return {
          kind: 'terminal',
          paymentState: existing.payment.state,
          receipt: existing.receipt ?? journal.issueReceipt(idempotencyKey),
          txHash: existing.payment.txHash,
          payer: existing.payment.payer,
          httpStatus: existing.execution.httpStatus,
        };
      }
      if (existing.execution.state === 'executing') {
        return {
          kind: 'execution_unresolved',
          executionAttemptId: existing.execution.executionAttemptId,
        };
      }
      if (existing.schemaVersion === 1) {
        if (existing.payment.state === 'settled' && existing.execution.state === 'authorized') {
          return {
            kind: 'settled',
            txHash: existing.payment.txHash,
            payer: existing.payment.payer,
            legacySchemaVersion: 1,
          };
        }
        throw new Error('legacy v1 nonterminal payment cannot continue');
      }
      // Once settlement is authoritative, recovery must reach the
      // post-settlement identity check so any current-config drift is journaled
      // as one terminal full-gross hold instead of stranding settled value.
      if (existing.payment.state === 'settled' && existing.execution.state === 'authorized') {
        return {
          kind: 'settled',
          txHash: existing.payment.txHash,
          payer: existing.payment.payer,
        };
      }
      // Before the seller records payment.signed or calls the facilitator, the
      // current execution identity must still match the persisted full quote.
      assertFrozenExecutionIdentity({
        quote: executionQuote,
        skillId: SKILL_ID,
        skillVersion: SKILL_VERSION,
        artifactContent: skillContent,
        skills: royaltyGraph,
        catalog: frozenExecutionCatalog,
      });
      const claim = journal.claimExternalPaymentSigned(idempotencyKey, { settlementReference, payer });
      const record = claim.record;
      if (record.payment.state === 'unresolved' || (!claim.claimed && record.payment.state === 'signed')) {
        return {
          kind: 'payment_unresolved',
          settlementReference: record.payment.settlementReference,
        };
      }
      if (record.payment.state === 'settled' && record.execution.state === 'authorized') {
        return {
          kind: 'settled',
          txHash: record.payment.txHash,
          payer: record.payment.payer,
        };
      }
      return { kind: 'signed' };
    },

    async onSettled({
      idempotencyKey, settlementReference, txHash, payer, executionQuote,
    }) {
      const persisted = journal.getByIdempotencyKey(idempotencyKey);
      if (persisted?.schemaVersion === 2
          && canonicalJson(persisted.quote.executionQuote) !== canonicalJson(executionQuote)) {
        throw new Error('settlement does not match the frozen execution quote');
      }
      await lifecycleFaults.beforeSettlementRecorded?.({ idempotencyKey, settlementReference, txHash, payer });
      const record = journal.markExternalPaymentSettled(idempotencyKey, {
        settlementReference,
        txHash,
        payer,
      });
      await lifecycleFaults.afterSettlementRecorded?.({ idempotencyKey, record });
    },

    async onUnresolved({ idempotencyKey, reason }) {
      const record = journal.getByIdempotencyKey(idempotencyKey);
      if (!record) throw new Error('unresolved payment has no Invocation');
      if (['settled', 'refunded'].includes(record.payment.state)) return record;
      if (record.payment.state === 'unresolved') return record;
      return journal.markExternalPaymentUnresolved(idempotencyKey, { reason });
    },

    async onRejected({ idempotencyKey, reason }) {
      const record = journal.getByIdempotencyKey(idempotencyKey);
      if (!record) throw new Error('rejected payment has no Invocation');
      if (['settled', 'refunded'].includes(record.payment.state)) return record;
      if (record.payment.state === 'rejected') return record;
      return journal.rejectExternalPayment(idempotencyKey, { reason });
    },
  };

  const app = new Hono();
  app.onError(() => new Response(JSON.stringify({ error: 'internal Collar error' }), {
    status: 500,
    headers: { 'content-type': 'application/json; charset=UTF-8' },
  }));
  app.get('/healthz', (c) => c.json({
    ok: true,
    skill: SKILL_ID,
    skillVersionHash,
    priceAtomic,
    currency: 'USDC',
    receiptAlgorithm: 'Ed25519',
    signingPublicKeyPem: journal.signingPublicKeyPem,
    signingKeyId: journal.signingKeyId,
    authority: 'collar-invocation-journal',
  }));

  app.get('/receipts/by-settlement/:reference', (c) => {
    let record;
    try { record = journal.getBySettlementReference(c.req.param('reference')); } catch {
      return c.json({ error: 'invalid settlement reference' }, 400);
    }
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (!record.receipt) {
      return c.json({
        invocationId: record.invocationId,
        paymentState: record.payment.state,
        executionState: record.execution.state,
      }, 202);
    }
    return c.json({ receipt: record.receipt });
  });

  app.post('/reconcile/by-settlement/:reference', async (c) => {
    const settlementReference = c.req.param('reference').toLowerCase();
    let record;
    try { record = journal.getBySettlementReference(settlementReference); } catch {
      return c.json({ error: 'invalid settlement reference' }, 400);
    }
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (['settled', 'refunded'].includes(record.payment.state)) {
      return c.json({ paymentState: record.payment.state, txHash: record.payment.txHash });
    }
    if (record.payment.state !== 'unresolved') {
      return c.json({ error: `payment state '${record.payment.state}' is not reconcilable` }, 409);
    }
    let resolution;
    try {
      resolution = await settlementResolver({
        settlementReference,
        payer: record.payment.payer,
        amountAtomic: record.quote.amountAtomic,
        network: record.quote.network,
        asset: record.quote.asset,
        payTo: record.quote.payTo,
      });
    } catch {
      return c.json({ error: 'trusted settlement resolution failed' }, 502);
    }
    if (!resolution?.settled) {
      return c.json({ paymentState: 'unresolved', settlementReference }, 202);
    }
    if (String(resolution.settlementReference ?? '').toLowerCase() !== settlementReference
        || !sameAddress(resolution.payer, record.payment.payer)
        || typeof resolution.amountAtomic !== 'string'
        || resolution.amountAtomic !== record.quote.amountAtomic
        || !validTxHash(resolution.txHash)) {
      return c.json({ error: 'trusted settlement resolver returned a mismatched proof' }, 502);
    }
    const reconciled = journal.reconcileExternalSettlement({
      settlementReference,
      txHash: resolution.txHash,
      payer: resolution.payer,
    });
    return c.json({ paymentState: reconciled.payment.state, txHash: reconciled.payment.txHash });
  });

  const refundRequestFor = (record) => ({
    invocationId: record.invocationId,
    settlementReference: record.payment.settlementReference,
    originalTxHash: record.payment.txHash,
    payer: record.payment.payer,
    amountAtomic: record.quote.amountAtomic,
    network: record.quote.network,
    asset: record.quote.asset,
    payTo: record.quote.payTo,
    refundAttemptId: record.payment.refundExecution.refundAttemptId,
  });

  const refundEvidenceMatches = (resolution, request) => resolution?.refunded === true
    && String(resolution.settlementReference ?? '').toLowerCase() === request.settlementReference
    && String(resolution.originalTxHash ?? '').toLowerCase() === request.originalTxHash
    && sameAddress(resolution.payer, request.payer)
    && typeof resolution.amountAtomic === 'string'
    && resolution.amountAtomic === request.amountAtomic
    && typeof resolution.refundReference === 'string'
    && Boolean(resolution.refundReference.trim());

  const markRefundOutcomeUnresolved = (record) => {
    const current = journal.getByIdempotencyKey(record.idempotencyKey);
    if (current.payment.state === 'refunded'
        || current.payment.refundExecution?.state === 'unresolved') return current;
    return journal.markRefundUnresolved(record.idempotencyKey, {
      refundAttemptId: record.payment.refundExecution.refundAttemptId,
      reason: 'trusted refund outcome unresolved',
    });
  };

  const refundTerminalResponse = (c, record) => c.json({
    receipt: record.receipt ?? journal.issueReceipt(record.idempotencyKey),
  });

  const finalizeRefund = (record, resolution) => {
    journal.refundExternalPayment(record.idempotencyKey, {
      refundAttemptId: record.payment.refundExecution.refundAttemptId,
      reason: 'trusted full-gross refund confirmed',
      refundReference: resolution.refundReference,
      refundAmountAtomic: resolution.amountAtomic,
    });
    return journal.issueReceipt(record.idempotencyKey);
  };

  app.post('/refund/by-settlement/:reference', async (c) => {
    const settlementReference = c.req.param('reference').toLowerCase();
    let record;
    try { record = journal.getBySettlementReference(settlementReference); } catch {
      return c.json({ error: 'invalid settlement reference' }, 400);
    }
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (record.payment.state === 'refunded') {
      return c.json({ receipt: record.receipt ?? journal.issueReceipt(record.idempotencyKey) });
    }
    if (record.payment.state !== 'settled'
        || record.execution.state !== 'failed'
        || record.accounting?.allocationState !== 'pending_cogs_reconciliation') {
      return c.json({ error: 'refund requires a settled failed full-gross reconciliation hold' }, 409);
    }
    if (!refundExecutor) return c.json({ error: 'trusted refund executor is not configured' }, 501);
    const claim = journal.startRefund(record.idempotencyKey);
    if (!claim.started) {
      if (claim.record.payment.state === 'refunded') {
        return refundTerminalResponse(c, claim.record);
      }
      return c.json({
        error: 'refund outcome unresolved; trusted reconciliation is required',
        refundAttemptId: claim.record.payment.refundExecution?.refundAttemptId ?? null,
      }, 503);
    }
    record = claim.record;
    const request = refundRequestFor(record);
    let resolution;
    try {
      resolution = await refundExecutor(request);
      await lifecycleFaults.afterRefundExecutorReturned?.({
        idempotencyKey: record.idempotencyKey,
        refundAttemptId: request.refundAttemptId,
      });
    } catch {
      const current = markRefundOutcomeUnresolved(record);
      if (current.payment.state === 'refunded') return refundTerminalResponse(c, current);
      return c.json({ error: 'refund outcome unresolved; trusted reconciliation is required' }, 503);
    }
    if (!refundEvidenceMatches(resolution, request)) {
      const current = markRefundOutcomeUnresolved(record);
      if (current.payment.state === 'refunded') return refundTerminalResponse(c, current);
      return c.json({ error: 'refund outcome unresolved; trusted reconciliation is required' }, 503);
    }
    return c.json({ receipt: finalizeRefund(record, resolution) });
  });

  app.post('/reconcile/refund/by-settlement/:reference', async (c) => {
    const settlementReference = c.req.param('reference').toLowerCase();
    let record;
    try { record = journal.getBySettlementReference(settlementReference); } catch {
      return c.json({ error: 'invalid settlement reference' }, 400);
    }
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (record.payment.state === 'refunded') {
      return c.json({ receipt: record.receipt ?? journal.issueReceipt(record.idempotencyKey) });
    }
    if (!['executing', 'unresolved'].includes(record.payment.refundExecution?.state)) {
      return c.json({ error: 'refund has no durable execution claim to reconcile' }, 409);
    }
    if (!refundResolver) return c.json({ error: 'trusted refund resolver is not configured' }, 501);
    const request = refundRequestFor(record);
    let resolution;
    try {
      resolution = await refundResolver(request);
    } catch {
      const current = markRefundOutcomeUnresolved(record);
      if (current.payment.state === 'refunded') return refundTerminalResponse(c, current);
      return c.json({ error: 'trusted refund resolution failed' }, 502);
    }
    if (!resolution?.refunded) {
      const current = markRefundOutcomeUnresolved(record);
      if (current.payment.state === 'refunded') return refundTerminalResponse(c, current);
      return c.json({ refundState: 'unresolved', refundAttemptId: request.refundAttemptId }, 202);
    }
    if (!refundEvidenceMatches(resolution, request)) {
      const current = markRefundOutcomeUnresolved(record);
      if (current.payment.state === 'refunded') return refundTerminalResponse(c, current);
      return c.json({ error: 'trusted refund resolver returned mismatched evidence' }, 502);
    }
    return c.json({ receipt: finalizeRefund(record, resolution) });
  });

  app.post(
    '/invoke/:skillId',
    async (c, next) => {
      const skillId = c.req.param('skillId');
      if (skillId !== SKILL_ID) return c.json({ error: `unknown Skill '${skillId}'` }, 404);
      await next();
    },
    x402Paywall({
      price: priceUsdc,
      quote: buildQuote,
      payTo,
      facilitatorTransport,
      description: `hosted-skill Invocation: ${SKILL_ID}`,
      lifecycle,
    }),
    async (c) => {
      const payment = c.get('x402');
      const key = payment.idempotencyKey;
      const claim = journal.startExecution(key);
      if (!claim.started) {
        return c.json({
          error: 'execution outcome unresolved; trusted executor reconciliation is required',
          executionAttemptId: claim.record.execution.executionAttemptId,
        }, 503);
      }
      const executionAttemptId = claim.record.execution.executionAttemptId;
      const finishFailure = (failureClass, message, status, accounting) => {
        journal.finishExecution(key, {
          executionAttemptId,
          outcome: 'failed',
          failureClass,
          message,
          outcomeHash: null,
          httpStatus: status,
          accounting,
        });
        return c.json({ error: message, receipt: journal.issueReceipt(key) }, status);
      };

      if (payment.legacySchemaVersion === 1) {
        return finishFailure(
          'LEGACY_ACCOUNTING_UNSUPPORTED',
          'legacy settled Invocation cannot execute without a frozen COGS quote',
          500,
          legacyPendingFailureAccounting(payment.amountAtomic),
        );
      }

      const { body } = await readInvocationBody(c);
      const frozenQuote = payment.executionQuote;
      try {
        assertFrozenExecutionIdentity({
          quote: frozenQuote,
          skillId: SKILL_ID,
          skillVersion: SKILL_VERSION,
          artifactContent: skillContent,
          skills: royaltyGraph,
          catalog: frozenExecutionCatalog,
        });
      } catch (error) {
        const failureClass = error instanceof ExecutionEconomicsError
          ? error.code
          : 'EXECUTION_IDENTITY_DRIFT';
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: null,
          failureClass,
          reason: 'frozen execution identity changed after settlement',
          catalog: frozenExecutionCatalog,
        });
        return finishFailure(
          failureClass,
          'frozen execution identity changed after settlement',
          500,
          accounting,
        );
      }

      let execution;
      try {
        execution = await withWallClockDeadline({
          signal: c.req.raw.signal,
          timeoutMs: providerTimeoutMs,
          timeoutCode: 'UPSTREAM_PROVIDER_TIMEOUT',
          timeoutMessage: 'provider execution timed out after settlement',
          abortedCode: 'UPSTREAM_PROVIDER_ABORTED',
          abortedMessage: 'provider execution was aborted after settlement',
        }, (signal) => executor({
          skillId: SKILL_ID,
          skillVersionHash,
          skillContent,
          input: body.input,
          executionAttemptId,
          model: frozenQuote.model,
          maxInputTokens: frozenQuote.maxInputTokens,
          maxOutputTokens: frozenQuote.maxOutputTokens,
          promptBytes: frozenQuote.promptBytes,
          estimatedInputTokens: frozenQuote.estimatedInputTokens,
          signal,
        }));
      } catch (error) {
        let retainedUsage = null;
        try { retainedUsage = error?.usage ?? null; } catch { retainedUsage = null; }
        const safeProviderFailureClasses = new Set([
          'UPSTREAM_PROVIDER_TIMEOUT',
          'UPSTREAM_PROVIDER_ABORTED',
          'UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE',
        ]);
        const failureClass = safeProviderFailureClasses.has(error?.code)
          ? error.code
          : 'UPSTREAM_PROVIDER_ERROR';
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: retainedUsage,
          failureClass,
          reason: 'provider execution failed after settlement',
          catalog: frozenExecutionCatalog,
        });
        return finishFailure(
          failureClass,
          'Skill execution failed after settlement',
          500,
          accounting,
        );
      }
      await lifecycleFaults.afterExecutorReturned?.({ idempotencyKey: key, executionAttemptId });

      let capturedExecution = null;
      try { capturedExecution = structuredClone(execution); } catch { /* invalid result below */ }
      if (!isExactPlainObject(capturedExecution, ['output', 'usage'])
          || typeof capturedExecution.output !== 'string'
          || !(capturedExecution.usage === null
            || (capturedExecution.usage && typeof capturedExecution.usage === 'object'))) {
        const accounting = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: capturedExecution?.usage ?? null,
          failureClass: 'INVALID_EXECUTOR_RESULT',
          reason: 'executor returned an invalid result',
          catalog: frozenExecutionCatalog,
        });
        return finishFailure(
          'INVALID_EXECUTOR_RESULT',
          'executor must return exactly output:string and usage:object|null',
          500,
          accounting,
        );
      }

      let accounting;
      try {
        accounting = finalizeExecutionAccounting({
          quote: frozenQuote,
          usage: capturedExecution.usage,
          unknownReason: 'provider response omitted usage',
          leafSkillId: SKILL_ID,
          skills: royaltyGraph,
          catalog: frozenExecutionCatalog,
        });
      } catch (error) {
        if (!(error instanceof ExecutionEconomicsError)) throw error;
        const pending = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: capturedExecution.usage,
          failureClass: error.code,
          reason: 'provider usage violated the frozen execution quote',
          catalog: frozenExecutionCatalog,
        });
        return finishFailure(
          error.code,
          'provider usage violated the frozen execution quote',
          500,
          pending,
        );
      }
      if (accounting.executionCogs.status === 'unknown') {
        return finishFailure(
          'COGS_UNKNOWN',
          'provider usage is unavailable; full gross held pending trusted COGS reconciliation or refund',
          500,
          accounting,
        );
      }
      try {
        assertArtifactNotSerialized({ output: capturedExecution.output, artifact: skillContent });
      } catch {
        const pending = createPendingExecutionAccounting({
          quote: frozenQuote,
          usage: capturedExecution.usage,
          failureClass: 'ARTIFACT_SERIALIZATION',
          reason: 'direct artifact serialization detected',
          catalog: frozenExecutionCatalog,
        });
        return finishFailure(
          'ARTIFACT_SERIALIZATION',
          'Skill output violated the direct artifact serialization boundary',
          500,
          pending,
        );
      }
      journal.finishExecution(key, {
        executionAttemptId,
        outcome: 'succeeded',
        failureClass: null,
        message: null,
        outcomeHash: hash(capturedExecution.output),
        httpStatus: 200,
        accounting,
      });
      await lifecycleFaults.afterExecutionFinished?.({ idempotencyKey: key, executionAttemptId });
      return c.json({ output: capturedExecution.output, receipt: journal.issueReceipt(key) });
    },
  );

  return { app, journal, skillVersionHash };
}

function mockSkillOutput(input) {
  return [
    `[mock ${SKILL_ID}] Optimized prompt for: "${String(input).slice(0, 120)}"`,
    '',
    'Goal: <grounded restatement of the request>',
    'Context: <where this lives in the repo>',
    'Constraints: <what must not change>',
    'Done when: <a real, runnable check>',
  ].join('\n');
}

export function createAnthropicExecutor({
  apiKey = process.env.ANTHROPIC_API_KEY,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_PROVIDER_TIMEOUT_MS,
  maxResponseBytes = DEFAULT_PROVIDER_RESPONSE_BYTES,
} = {}) {
  if (typeof apiKey !== 'string' || !apiKey) {
    throw new Error('Anthropic API key is required for the live executor');
  }
  if (typeof fetchImpl !== 'function') throw new TypeError('Anthropic executor requires fetch');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError('Anthropic timeoutMs must be a positive safe integer');
  }
  if (timeoutMs > DEFAULT_PROVIDER_TIMEOUT_MS) {
    throw new TypeError(`Anthropic timeoutMs cannot exceed ${DEFAULT_PROVIDER_TIMEOUT_MS}`);
  }
  if (!Number.isSafeInteger(maxResponseBytes) || maxResponseBytes <= 0) {
    throw new TypeError('Anthropic maxResponseBytes must be a positive safe integer');
  }
  if (maxResponseBytes > DEFAULT_PROVIDER_RESPONSE_BYTES) {
    throw new TypeError(
      `Anthropic maxResponseBytes cannot exceed ${DEFAULT_PROVIDER_RESPONSE_BYTES}`,
    );
  }
  return async ({
    skillContent,
    input,
    model,
    maxInputTokens,
    maxOutputTokens,
    promptBytes,
    estimatedInputTokens,
    signal = null,
  }) => {
    const rebound = conservativeProviderPromptBound({
      systemPrompt: skillContent,
      userInput: input,
      requestBodyBytes: 0,
      maxRequestBodyBytes: MAX_REQUEST_BODY_BYTES,
      maxInputTokens,
    });
    if (rebound.promptBytes !== promptBytes
        || rebound.estimatedInputTokens !== estimatedInputTokens) {
      throw new ExecutionEconomicsError(
        'FROZEN_PROMPT_MISMATCH',
        'provider prompt differs from the accepted quote',
      );
    }
    let data;
    try {
      data = await withWallClockDeadline({
        signal,
        timeoutMs,
        timeoutCode: 'UPSTREAM_PROVIDER_TIMEOUT',
        timeoutMessage: 'provider request timed out',
        abortedCode: 'UPSTREAM_PROVIDER_ABORTED',
        abortedMessage: 'provider request was aborted',
      }, async (composedSignal) => {
        const response = await fetchImpl('https://api.anthropic.com/v1/messages', {
          method: 'POST',
          redirect: 'error',
          signal: composedSignal,
          headers: {
            'content-type': 'application/json',
            'x-api-key': apiKey,
            'anthropic-version': '2023-06-01',
          },
          body: JSON.stringify({
            model,
            max_tokens: maxOutputTokens,
            system: skillContent,
            messages: [{ role: 'user', content: input }],
          }),
        });
        if (!response?.ok) {
          throw new RuntimeBoundaryError('UPSTREAM_PROVIDER_ERROR', 'provider request failed');
        }
        if (!(response instanceof Response)) {
          throw new RuntimeBoundaryError(
            'UPSTREAM_PROVIDER_RESPONSE_SHAPE',
            'provider response must expose a bounded byte stream',
          );
        }
        return readJsonBody(response, {
          maxBytes: maxResponseBytes,
          tooLargeCode: 'UPSTREAM_PROVIDER_RESPONSE_TOO_LARGE',
          tooLargeMessage: 'provider response exceeds the JSON byte limit',
          readErrorCode: 'UPSTREAM_PROVIDER_RESPONSE_READ_FAILED',
          readErrorMessage: 'provider response could not be read',
          jsonErrorCode: 'UPSTREAM_PROVIDER_RESPONSE_JSON',
          jsonErrorMessage: 'provider response was not JSON',
          signal: composedSignal,
        });
      });
    } catch (error) {
      if (error instanceof RuntimeBoundaryError) {
        throw new ExecutionEconomicsError(error.code, error.message);
      }
      if (error instanceof ExecutionEconomicsError) throw error;
      throw new ExecutionEconomicsError('UPSTREAM_PROVIDER_ERROR', 'provider request failed');
    }
    return {
      output: Array.isArray(data?.content)
        ? data.content.map((block) => (typeof block?.text === 'string' ? block.text : '')).join('')
        : '',
      usage: data?.usage ? {
        schemaVersion: 2,
        model,
        inputTokens: data.usage.input_tokens,
        outputTokens: data.usage.output_tokens,
      } : null,
    };
  };
}

export function startCollar({ port = 0, ...options } = {}) {
  const { app, journal, skillVersionHash } = createCollar(options);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, (info) => {
      resolve({
        url: `http://127.0.0.1:${info.port}`,
        port: info.port,
        journal,
        skillVersionHash,
        signingPublicKeyPem: journal.signingPublicKeyPem,
        signingKeyId: journal.signingKeyId,
        close: () => server.close(),
      });
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const selected = await chooseFacilitator();
  const { url } = await startCollar({
    port: Number(process.env.COLLAR_PORT || 8404),
    facilitatorTransport: selected.transport,
  });
  console.log(`[collar] hosted Skill '${SKILL_ID}' at ${url}/invoke/${SKILL_ID} (${selected.mode})`);
}

export { APPROVED_LIVE_FACILITATOR_BASE };

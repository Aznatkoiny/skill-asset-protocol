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

import { allocateExternalGross } from '../../../prototype/atomic-money.mjs';
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  usdcToAtomic,
  x402Paywall,
} from './x402-seller.mjs';
import {
  canonicalJson,
  createInvocationJournal,
} from './invocation-journal.mjs';

export const SKILL_ID = 'optimizing-claude-code-prompts';
const SKILL_PATH = fileURLToPath(
  new URL(`../../../.claude/skills/${SKILL_ID}/SKILL.md`, import.meta.url),
);
const DEFAULT_PRICE_USDC = '0.25';
const TERMINAL = new Set(['succeeded', 'failed', 'cancelled']);

const hash = (value) => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;

const royaltyGraph = Object.freeze({
  [SKILL_ID]: Object.freeze({
    parentIds: Object.freeze([]),
    inheritBps: 0,
    holders: Object.freeze([{ recipientId: 'creator', bps: 10_000 }]),
  }),
});

function serializeEntry(entry) {
  return { ...entry, amountAtomic: entry.amountAtomic.toString() };
}

function serializeCredit(credit) {
  return { ...credit, amountAtomic: credit.amountAtomic.toString() };
}

function serializeAccounting(result) {
  return {
    allocationState: 'finalized',
    allocationPolicy: result.allocationPolicy,
    grossAtomic: result.grossAtomic.toString(),
    executionCostAtomic: result.executionCostAtomic.toString(),
    settlementCostAtomic: result.settlementCostAtomic.toString(),
    protocolFeeAtomic: result.protocolFeeAtomic.toString(),
    royaltyPoolAtomic: result.royaltyPoolAtomic.toString(),
    refundReserveAtomic: result.refundReserveAtomic.toString(),
    holderCredits: result.holderCredits.map(serializeCredit),
    ancestorCredits: result.ancestorCredits.map(serializeCredit),
    journalEntries: result.journalEntries.map(serializeEntry),
  };
}

function pendingFailureAccounting(amountAtomic) {
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
  payTo = process.env.PAY_TO_ADDRESS || `0x${'d'.repeat(40)}`,
  priceUsdc = process.env.SKILL_PRICE_USDC || DEFAULT_PRICE_USDC,
  mockLlm = process.env.MOCK_LLM === '1',
  journal = null,
  journalFile = process.env.COLLAR_JOURNAL_FILE || null,
  signingKeyFile = process.env.COLLAR_SIGNING_KEY_FILE || null,
  receiptSigner = null,
  executeSkill = null,
  lifecycleFaults = {},
  resolveSettlement = null,
  executeRefund = null,
} = {}) {
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
  }
  const settlementResolver = resolveSettlement ?? (async () => ({ settled: false }));
  const refundExecutor = executeRefund ?? null;
  const skillContent = fs.readFileSync(SKILL_PATH, 'utf8');
  const skillVersionHash = hash(skillContent);
  const priceAtomic = usdcToAtomic(priceUsdc);
  const executor = executeSkill ?? (mockLlm
    ? async ({ input }) => ({ output: mockSkillOutput(input) })
    : async ({ input }) => ({ output: await runSkillViaAnthropic(skillContent, input) }));

  const lifecycle = {
    async onOffered({ idempotencyKey, requirements, expiresAt }) {
      journal.requestInvocation({
        idempotencyKey,
        mode: 'external',
        skillId: SKILL_ID,
        skillVersionHash,
        requestHash: requirements.extra.requestHash,
        creatorId: 'creator',
        beneficiaryId: null,
      });
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
        requirements,
      });
    },

    async loadFrozenOffer({ idempotencyKey }) {
      return journal.getByIdempotencyKey(idempotencyKey)?.quote?.requirements ?? null;
    },

    async onSigned({ idempotencyKey, settlementReference, payer, requirements }) {
      const existing = journal.getByIdempotencyKey(idempotencyKey);
      if (!existing?.quote) throw new Error('paid retry has no prior quoted Invocation');
      if (existing.quote.requirementsHash !== hash(canonicalJson(requirements))
          || existing.quote.requestHash !== requirements.extra.requestHash) {
        throw new Error('paid retry does not match the frozen x402 requirements');
      }
      const claim = journal.claimExternalPaymentSigned(idempotencyKey, { settlementReference, payer });
      const record = claim.record;
      if (TERMINAL.has(record.execution.state)) {
        if (!['settled', 'refunded'].includes(record.payment.state) || !record.payment.txHash) {
          throw new Error('terminal Invocation does not carry a replayable settled payment');
        }
        return {
          kind: 'terminal',
          paymentState: record.payment.state,
          receipt: record.receipt ?? journal.issueReceipt(idempotencyKey),
          txHash: record.payment.txHash,
          payer: record.payment.payer,
          httpStatus: record.execution.httpStatus,
        };
      }
      if (record.execution.state === 'executing') {
        return { kind: 'execution_unresolved', executionAttemptId: record.execution.executionAttemptId };
      }
      if (record.payment.state === 'unresolved' || (!claim.claimed && record.payment.state === 'signed')) {
        return { kind: 'payment_unresolved', settlementReference: record.payment.settlementReference };
      }
      if (record.payment.state === 'settled' && record.execution.state === 'authorized') {
        return {
          kind: 'settled',
          txHash: record.payment.txHash,
          payer: record.payment.payer,
        };
      }
      return null;
    },

    async onSettled({ idempotencyKey, settlementReference, txHash, payer }) {
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
    try { record = journal.getBySettlementReference(c.req.param('reference')); } catch (error) {
      return c.json({ error: error.message }, 400);
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
    try { record = journal.getBySettlementReference(settlementReference); } catch (error) {
      return c.json({ error: error.message }, 400);
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
    } catch (error) {
      return c.json({ error: `trusted settlement resolver failed: ${error.message}` }, 502);
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

  app.post('/refund/by-settlement/:reference', async (c) => {
    const settlementReference = c.req.param('reference').toLowerCase();
    let record;
    try { record = journal.getBySettlementReference(settlementReference); } catch (error) {
      return c.json({ error: error.message }, 400);
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
    let resolution;
    try {
      resolution = await refundExecutor({
        invocationId: record.invocationId,
        settlementReference,
        originalTxHash: record.payment.txHash,
        payer: record.payment.payer,
        amountAtomic: record.quote.amountAtomic,
        network: record.quote.network,
        asset: record.quote.asset,
        payTo: record.quote.payTo,
      });
    } catch (error) {
      return c.json({ error: `trusted refund executor failed: ${error.message}` }, 502);
    }
    if (resolution?.refunded !== true
        || String(resolution.settlementReference ?? '').toLowerCase() !== settlementReference
        || String(resolution.originalTxHash ?? '').toLowerCase() !== record.payment.txHash
        || !sameAddress(resolution.payer, record.payment.payer)
        || typeof resolution.amountAtomic !== 'string'
        || resolution.amountAtomic !== record.quote.amountAtomic
        || typeof resolution.refundReference !== 'string'
        || !resolution.refundReference.trim()) {
      return c.json({ error: 'trusted refund executor returned a mismatched proof' }, 502);
    }
    journal.refundExternalPayment(record.idempotencyKey, {
      reason: 'trusted full-gross refund confirmed',
      refundReference: resolution.refundReference,
      refundAmountAtomic: resolution.amountAtomic,
    });
    return c.json({ receipt: journal.issueReceipt(record.idempotencyKey) });
  });

  app.post(
    '/invoke/:skillId',
    x402Paywall({
      price: priceUsdc,
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
      const finishFailure = (failureClass, message, status) => {
        journal.finishExecution(key, {
          executionAttemptId,
          outcome: 'failed',
          failureClass,
          message,
          outcomeHash: null,
          httpStatus: status,
          accounting: pendingFailureAccounting(payment.amountAtomic),
        });
        return c.json({ error: message, receipt: journal.issueReceipt(key) }, status);
      };

      if (c.req.param('skillId') !== SKILL_ID) {
        return finishFailure('UNKNOWN_SKILL', `unknown skill '${c.req.param('skillId')}'`, 404);
      }
      const body = await c.req.json().catch(() => null);
      if (typeof body?.input !== 'string' || !body.input) {
        return finishFailure('INVALID_REQUEST', 'body must be JSON: { "input": "..." }', 400);
      }

      let execution;
      try {
        execution = await executor({
          skillId: SKILL_ID,
          skillVersionHash,
          skillContent,
          input: body.input,
          executionAttemptId,
        });
      } catch (error) {
        return finishFailure('UPSTREAM_500', error.message, 500);
      }
      if (!execution || typeof execution.output !== 'string') {
        return finishFailure('INVALID_EXECUTOR_RESULT', 'executor must return { output: string }', 500);
      }
      await lifecycleFaults.afterExecutorReturned?.({ idempotencyKey: key, executionAttemptId });

      const allocation = allocateExternalGross({
        grossAtomic: BigInt(payment.amountAtomic),
        executionCostAtomic: 0n,
        settlementCostAtomic: 0n,
        protocolFeeBps: 250,
        refundReserveAtomic: 0n,
        leafSkillId: SKILL_ID,
        skills: royaltyGraph,
      });
      journal.finishExecution(key, {
        executionAttemptId,
        outcome: 'succeeded',
        failureClass: null,
        message: null,
        outcomeHash: hash(execution.output),
        httpStatus: 200,
        accounting: serializeAccounting(allocation),
      });
      await lifecycleFaults.afterExecutionFinished?.({ idempotencyKey: key, executionAttemptId });
      return c.json({ output: execution.output, receipt: journal.issueReceipt(key) });
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

async function runSkillViaAnthropic(skillContent, input) {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('ANTHROPIC_API_KEY required unless MOCK_LLM=1');
  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
      'content-type': 'application/json',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-6',
      max_tokens: 2048,
      system: skillContent,
      messages: [{ role: 'user', content: String(input) }],
    }),
  });
  if (!response.ok) throw new Error(`Anthropic API ${response.status}: ${await response.text()}`);
  const data = await response.json();
  return data.content?.map((block) => block.text ?? '').join('') ?? '';
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

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { chooseFacilitator, createCollar, SKILL_ID } from '../src/collar.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { verifySignedReceipt } from '../src/invocation-journal.mjs';
import { payingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
} from '../src/x402-seller.mjs';

const invokeUrl = `http://collar.test/invoke/${SKILL_ID}`;
const requestBody = JSON.stringify({ input: 'same bytes' });

function mockTransport(fetchImpl = null) {
  const facilitator = createMockFacilitator();
  return createMockFacilitatorTransport(fetchImpl ?? ((url, init) => facilitator.request(url, init)));
}

const trustFor = (collar) => ({
  publicKeyPem: collar.journal.signingPublicKeyPem,
  keyId: collar.journal.signingKeyId,
});

async function prepareReconciledRetry({ executeSkill, lifecycleFaults = {} }) {
  const facilitator = createMockFacilitator();
  let lostSettlement;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const response = await facilitator.request(url, init);
    if (new URL(url).pathname === '/settle') {
      lostSettlement = await response.clone().json();
      throw new Error('injected response loss before execution');
    }
    return response;
  });
  const collar = createCollar({
    facilitatorTransport: transport,
    executeSkill,
    lifecycleFaults,
    resolveSettlement: async ({ settlementReference, amountAtomic, payer }) => ({
      settled: true,
      settlementReference,
      amountAtomic,
      txHash: lostSettlement.transaction,
      payer,
    }),
  });
  const idempotencyKey = `idem-crash-${crypto.randomUUID()}`;
  const first = await payingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.res.status, 503);
  const reconcile = await collar.app.request(
    `http://collar.test/reconcile/by-settlement/${first.settlementReference}`,
    { method: 'POST' },
  );
  assert.equal(reconcile.status, 200);
  const retry = () => collar.app.request(invokeUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': first.xPayment,
    },
    body: requestBody,
  });
  return { collar, idempotencyKey, retry };
}

async function invokeSettledFailure({ executeRefund = null } = {}) {
  const collar = createCollar({
    facilitatorTransport: mockTransport(),
    executeSkill: async () => { throw new Error('refund-target provider fault'); },
    executeRefund,
  });
  const result = await payingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey: `idem-refund-${crypto.randomUUID()}`,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(result.res.status, 500);
  const body = await result.res.json();
  return { collar, result, body };
}

test('standalone selection defaults to injected offline mock and live mode is explicit', async () => {
  let mockStarts = 0;
  const selected = await chooseFacilitator({
    env: {},
    createMock: async () => { mockStarts += 1; return createMockFacilitator(); },
  });
  assert.equal(selected.mode, 'mock');
  assert.equal(selected.transport.mode, 'mock');
  assert.equal(mockStarts, 1);
  await assert.rejects(() => chooseFacilitator({ env: { ALLOW_LIVE_X402: '1' } }), /requires/);
  const live = await chooseFacilitator({
    env: { ALLOW_LIVE_X402: '1', FACILITATOR_URL: APPROVED_LIVE_FACILITATOR_BASE },
  });
  assert.equal(live.transport.mode, 'live');
});

test('live settlement refuses ephemeral authority and accepts only paired persistent paths', () => {
  const live = createLiveFacilitatorTransport(APPROVED_LIVE_FACILITATOR_BASE, async () => {
    throw new Error('network must not run');
  });
  assert.throws(() => createCollar({ facilitatorTransport: live, mockLlm: true }), /persistent journal/);
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-live-authority-')));
  assert.throws(() => createCollar({
    facilitatorTransport: live,
    mockLlm: true,
    journalFile: path.join(directory, 'events.jsonl'),
  }), /set together/);
  assert.throws(() => createCollar({
    facilitatorTransport: live,
    mockLlm: true,
    journalFile: path.join(directory, 'events.jsonl'),
    signingKeyFile: path.join(directory, 'receipt-key.pem'),
  }), /trusted settlement resolver|refund executor/);
  const collar = createCollar({
    facilitatorTransport: live,
    mockLlm: true,
    journalFile: path.join(directory, 'events.jsonl'),
    signingKeyFile: path.join(directory, 'receipt-key.pem'),
    resolveSettlement: async () => ({ settled: false }),
    executeRefund: async () => ({ refunded: false }),
  });
  assert.equal(collar.journal.isPersistent, true);
});

test('settled-then-500 stays authoritative, full-gross held, and exact replay preserves 500', async () => {
  const facilitator = createMockFacilitator();
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    if (new URL(url).pathname === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const collar = createCollar({
    facilitatorTransport: transport,
    executeSkill: async () => { executions += 1; throw new Error('injected provider fault'); },
  });
  const account = throwawayAccount();
  const idempotencyKey = 'idem-settled-failure';
  const result = await payingFetch(account, invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(result.res.status, 500);
  const body = await result.res.json();
  assert.equal(verifySignedReceipt(body.receipt, trustFor(collar)), true);
  assert.equal(body.receipt.receipt.payment.state, 'settled');
  assert.match(body.receipt.receipt.payment.txHash, /^0x[0-9a-f]{64}$/);
  assert.equal(body.receipt.receipt.execution.state, 'failed');
  assert.equal(body.receipt.receipt.execution.httpStatus, 500);
  assert.deepEqual(body.receipt.receipt.accounting.journalEntries, [{
    category: 'unresolved-execution-accounting',
    debitAccountId: 'wielder:external-gross',
    creditAccountId: 'hold:execution-accounting-reconciliation',
    amountAtomic: '250000',
  }]);

  const eventCount = collar.journal.events.length;
  const lookup = await collar.app.request(
    `http://collar.test/receipts/by-settlement/${result.settlementReference}`,
  );
  assert.equal(lookup.status, 200);
  assert.deepEqual((await lookup.json()).receipt, body.receipt);
  assert.equal(collar.journal.events.length, eventCount);

  const replay = await collar.app.request(invokeUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': result.xPayment,
    },
    body: requestBody,
  });
  assert.equal(replay.status, 500);
  const replayBody = await replay.json();
  assert.equal(replayBody.replayed, true);
  assert.deepEqual(replayBody.receipt, body.receipt);
  assert.equal(executions, 1);
  assert.equal(settleCalls, 1);
});

test('response-loss reconciliation advances once and exact retry never duplicates debit or execution', async () => {
  const facilitator = createMockFacilitator();
  let lostSettlement = null;
  let settleCalls = 0;
  let executions = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const response = await facilitator.request(url, init);
    if (new URL(url).pathname === '/settle') {
      settleCalls += 1;
      lostSettlement = await response.clone().json();
      throw new Error('injected lost facilitator response');
    }
    return response;
  });
  const collar = createCollar({
    facilitatorTransport: transport,
    resolveSettlement: async ({ settlementReference, amountAtomic, payer }) => ({
      settled: true,
      settlementReference,
      amountAtomic,
      txHash: lostSettlement.transaction,
      payer,
    }),
    executeSkill: async ({ input }) => { executions += 1; return { output: `executed ${input}` }; },
  });
  const idempotencyKey = 'idem-response-loss';
  const first = await payingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.res.status, 503);
  assert.equal(collar.journal.getBySettlementReference(first.settlementReference).payment.state, 'unresolved');

  const retryRequest = (body = requestBody) => collar.app.request(invokeUrl, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': first.xPayment,
    },
    body,
  });
  assert.equal((await retryRequest()).status, 503);
  assert.equal(settleCalls, 1);
  const reconcile = await collar.app.request(
    `http://collar.test/reconcile/by-settlement/${first.settlementReference}`,
    { method: 'POST' },
  );
  assert.equal(reconcile.status, 200);
  assert.equal((await reconcile.json()).txHash, lostSettlement.transaction);
  const completed = await retryRequest();
  assert.equal(completed.status, 200);
  const completedBody = await completed.json();
  assert.equal(verifySignedReceipt(completedBody.receipt, trustFor(collar)), true);
  const exact = await retryRequest();
  assert.equal(exact.status, 200);
  assert.equal((await exact.json()).replayed, true);
  assert.equal((await retryRequest(JSON.stringify({ input: 'different bytes' }))).status, 409);
  assert.equal(executions, 1);
  assert.equal(settleCalls, 1);
  assert.equal(collar.journal.events.filter((event) => event.type === 'payment.settled').length, 1);
  assert.equal(collar.journal.events.filter((event) => event.type === 'execution.started').length, 1);
});

test('settlement success followed by journal fault is persisted unresolved before retry', async () => {
  const facilitator = createMockFacilitator();
  let settleCalls = 0;
  const transport = createMockFacilitatorTransport(async (url, init) => {
    if (new URL(url).pathname === '/settle') settleCalls += 1;
    return facilitator.request(url, init);
  });
  const collar = createCollar({
    facilitatorTransport: transport,
    lifecycleFaults: {
      beforeSettlementRecorded: async () => { throw new Error('injected append boundary fault'); },
    },
    executeSkill: async () => { throw new Error('must not execute'); },
  });
  const first = await payingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey: 'idem-post-settle-collar',
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.res.status, 503);
  assert.equal(collar.journal.getBySettlementReference(first.settlementReference).payment.state, 'unresolved');
  const retry = await collar.app.request(invokeUrl, {
    method: 'POST',
    headers: { 'Idempotency-Key': first.idempotencyKey, 'X-PAYMENT': first.xPayment },
    body: requestBody,
  });
  assert.equal(retry.status, 503);
  assert.equal(settleCalls, 1);
});

test('crash after the provider returns leaves one unresolved attempt and never calls the provider again', async () => {
  let executions = 0;
  const prepared = await prepareReconciledRetry({
    executeSkill: async () => {
      executions += 1;
      return { output: 'completed but not journaled' };
    },
    lifecycleFaults: {
      afterExecutorReturned: async () => { throw new Error('crash after provider return'); },
    },
  });
  assert.equal((await prepared.retry()).status, 500);
  assert.equal(executions, 1);
  assert.equal((await prepared.retry()).status, 503);
  assert.equal(executions, 1);
  const record = prepared.collar.journal.getByIdempotencyKey(prepared.idempotencyKey);
  assert.equal(record.execution.state, 'executing');
  assert.match(record.execution.executionAttemptId, /^attempt:/);
});

test('crash after finish but before receipt issuance replays without another provider call', async () => {
  let executions = 0;
  let crash = true;
  const prepared = await prepareReconciledRetry({
    executeSkill: async () => {
      executions += 1;
      return { output: 'journaled output' };
    },
    lifecycleFaults: {
      afterExecutionFinished: async () => {
        if (crash) {
          crash = false;
          throw new Error('crash before receipt append');
        }
      },
    },
  });
  assert.equal((await prepared.retry()).status, 500);
  assert.equal(executions, 1);
  assert.equal(
    prepared.collar.journal.getByIdempotencyKey(prepared.idempotencyKey).receipt,
    null,
  );
  const replay = await prepared.retry();
  assert.equal(replay.status, 200);
  const body = await replay.json();
  assert.equal(body.replayed, true);
  assert.equal(executions, 1);
  assert.equal(verifySignedReceipt(body.receipt, trustFor(prepared.collar)), true);
});

test('overlapping paid retries atomically claim one execution attempt', async () => {
  let executions = 0;
  let releaseExecution;
  let announceStarted;
  const started = new Promise((resolve) => { announceStarted = resolve; });
  const gate = new Promise((resolve) => { releaseExecution = resolve; });
  const prepared = await prepareReconciledRetry({
    executeSkill: async ({ executionAttemptId }) => {
      executions += 1;
      assert.match(executionAttemptId, /^attempt:/);
      announceStarted();
      await gate;
      return { output: 'one output' };
    },
  });
  const winner = prepared.retry();
  await started;
  const overlap = await prepared.retry();
  assert.equal(overlap.status, 503);
  assert.equal(executions, 1);
  releaseExecution();
  assert.equal((await winner).status, 200);
  assert.equal(executions, 1);
  assert.equal(
    prepared.collar.journal.events.filter((event) => event.type === 'execution.started').length,
    1,
  );
});

test('refund endpoint ignores client proof and fails closed without a trusted executor', async () => {
  const { collar, result, body } = await invokeSettledFailure();
  const before = collar.journal.events.length;
  const response = await collar.app.request(
    `http://collar.test/refund/by-settlement/${result.settlementReference}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        refunded: true,
        payer: body.receipt.receipt.payment.payer,
        amountAtomic: '250000',
        refundReference: 'client-forged-proof',
      }),
    },
  );
  assert.equal(response.status, 501);
  assert.equal(collar.journal.events.length, before);
  assert.deepEqual(
    collar.journal.getBySettlementReference(result.settlementReference).receipt,
    body.receipt,
  );
});

test('trusted refund requires exact journal-bound proof and issues one signed revision', async () => {
  let executorResult = null;
  const calls = [];
  const { collar, result, body } = await invokeSettledFailure({
    executeRefund: async (request) => {
      calls.push(structuredClone(request));
      return executorResult;
    },
  });
  const original = structuredClone(body.receipt);
  const payment = original.receipt.payment;
  const endpoint = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const stateBefore = () => collar.journal.getBySettlementReference(result.settlementReference);
  const eventCount = collar.journal.events.length;

  const mismatches = [
    null,
    {
      refunded: true,
      settlementReference: `0x${'f'.repeat(64)}`,
      originalTxHash: payment.txHash,
      payer: payment.payer,
      amountAtomic: '250000',
      refundReference: 'refund-wrong-reference',
    },
    {
      refunded: true,
      settlementReference: payment.settlementReference,
      originalTxHash: payment.txHash,
      payer: `0x${'a'.repeat(40)}`,
      amountAtomic: '250000',
      refundReference: 'refund-wrong-payer',
    },
    {
      refunded: true,
      settlementReference: payment.settlementReference,
      originalTxHash: payment.txHash,
      payer: payment.payer,
      amountAtomic: '249999',
      refundReference: 'refund-partial',
    },
    {
      refunded: true,
      settlementReference: payment.settlementReference,
      originalTxHash: `0x${'e'.repeat(64)}`,
      payer: payment.payer,
      amountAtomic: '250000',
      refundReference: 'refund-wrong-original-tx',
    },
  ];
  for (const mismatch of mismatches) {
    executorResult = mismatch;
    const rejected = await collar.app.request(endpoint, { method: 'POST' });
    assert.equal(rejected.status, 502);
    assert.equal(collar.journal.events.length, eventCount);
    assert.equal(stateBefore().payment.state, 'settled');
    assert.deepEqual(stateBefore().receipt, original);
  }

  assert.deepEqual(calls[0], {
    invocationId: original.receipt.invocationId,
    settlementReference: payment.settlementReference,
    originalTxHash: payment.txHash,
    payer: payment.payer,
    amountAtomic: '250000',
    network: original.receipt.quote.network,
    asset: original.receipt.quote.asset,
    payTo: original.receipt.quote.payTo,
  });
  executorResult = {
    refunded: true,
    settlementReference: payment.settlementReference,
    originalTxHash: payment.txHash,
    payer: payment.payer,
    amountAtomic: '250000',
    refundReference: 'trusted-refund-0001',
  };
  const refunded = await collar.app.request(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refundReference: 'client-must-not-win' }),
  });
  assert.equal(refunded.status, 200);
  const revised = (await refunded.json()).receipt;
  assert.equal(verifySignedReceipt(revised, trustFor(collar)), true);
  assert.equal(revised.receipt.revision, 2);
  assert.equal(revised.receipt.supersedesReceiptHash, original.receiptHash);
  assert.equal(revised.receipt.payment.state, 'refunded');
  assert.equal(revised.receipt.payment.refundReference, 'trusted-refund-0001');
  assert.equal(revised.receipt.payment.refundAmountAtomic, '250000');
  assert.deepEqual(revised.receipt.payment.refundAccounting.reversalEntries, [
    {
      category: 'refund-reverse-reconciliation-hold',
      debitAccountId: 'hold:execution-accounting-reconciliation',
      creditAccountId: 'wielder:external-gross',
      amountAtomic: '250000',
    },
    {
      category: 'refund-disbursement',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: `refund:${payment.payer}`,
      amountAtomic: '250000',
    },
  ]);
  assert.deepEqual(original, body.receipt);

  const callCount = calls.length;
  const replay = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(replay.status, 200);
  assert.deepEqual((await replay.json()).receipt, revised);
  assert.equal(calls.length, callCount);
});

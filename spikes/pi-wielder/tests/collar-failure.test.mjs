import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { chooseFacilitator, createCollar, SKILL_ID } from '../src/collar.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { verifySignedReceipt } from '../src/invocation-journal.mjs';
import { payingFetch as policyPayingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
} from '../src/x402-seller.mjs';
import { paymentPolicyFor } from './payment-policy-fixture.mjs';

const invokeUrl = `http://collar.test/invoke/${SKILL_ID}`;
const requestBody = JSON.stringify({ input: 'same bytes' });
const payingFetch = (account, url, init, options = {}) => policyPayingFetch(account, url, init, {
  paymentPolicy: paymentPolicyFor(url),
  ...options,
});

async function withheldPayingFetch(account, url, init, options = {}) {
  const paymentPolicy = paymentPolicyFor(url);
  await assert.rejects(() => policyPayingFetch(account, url, init, {
    ...options,
    paymentPolicy,
  }), (error) => error.code === 'SETTLEMENT_EVIDENCE');
  const persisted = paymentPolicy.recoverSignedAuthorization({
    authorizationId: options.idempotencyKey,
    requestUrl: url,
    method: init.method ?? 'GET',
    bodyBytes: init.body ?? null,
  });
  return {
    ...persisted,
    idempotencyKey: persisted.authorizationId,
    settlementReference: persisted.authorization.nonce,
    paymentPolicy,
  };
}

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
  const first = await withheldPayingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.state, 'unresolved');
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

async function invokeSettledFailure({
  executeRefund = null,
  resolveRefund = null,
  lifecycleFaults = {},
  executeSkill = async () => { throw new Error('refund-target provider fault'); },
  onCollarCreated = null,
} = {}) {
  const collar = createCollar({
    facilitatorTransport: mockTransport(),
    executeSkill,
    executeRefund,
    resolveRefund,
    lifecycleFaults,
  });
  onCollarCreated?.(collar);
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
    resolveRefund: async () => ({ refunded: false }),
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
  const first = await withheldPayingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey,
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.state, 'unresolved');
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
  const first = await withheldPayingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey: 'idem-post-settle-collar',
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  assert.equal(first.state, 'unresolved');
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
  const crashed = await prepared.retry();
  assert.equal(crashed.status, 500);
  assert.doesNotMatch(await crashed.text(), /crash after provider return/);
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
  const calls = [];
  let expected;
  const { collar, result, body } = await invokeSettledFailure({
    executeRefund: async (request) => {
      calls.push(structuredClone(request));
      return {
        refunded: true,
        settlementReference: request.settlementReference,
        originalTxHash: request.originalTxHash,
        payer: request.payer,
        amountAtomic: request.amountAtomic,
        refundReference: 'trusted-refund-0001',
      };
    },
  });
  const original = structuredClone(body.receipt);
  const payment = original.receipt.payment;
  const endpoint = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const refunded = await collar.app.request(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ refundReference: 'client-must-not-win' }),
  });
  assert.equal(refunded.status, 200);
  expected = {
    invocationId: original.receipt.invocationId,
    settlementReference: payment.settlementReference,
    originalTxHash: payment.txHash,
    payer: payment.payer,
    amountAtomic: '250000',
    network: original.receipt.quote.network,
    asset: original.receipt.quote.asset,
    payTo: original.receipt.quote.payTo,
  };
  assert.match(calls[0].refundAttemptId, /^refund-attempt:/);
  assert.deepEqual({ ...calls[0], refundAttemptId: undefined }, {
    ...expected,
    refundAttemptId: undefined,
  });
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

test('crash after refund provider return stays unresolved until a trusted resolver advances it', async () => {
  let executorCalls = 0;
  let resolverResult = null;
  const { collar, result, body } = await invokeSettledFailure({
    executeRefund: async (request) => {
      executorCalls += 1;
      return {
        refunded: true,
        settlementReference: request.settlementReference,
        originalTxHash: request.originalTxHash,
        payer: request.payer,
        amountAtomic: request.amountAtomic,
        refundReference: 'response-lost-after-provider-return',
      };
    },
    resolveRefund: async () => resolverResult,
    lifecycleFaults: {
      afterRefundExecutorReturned: async () => { throw new Error('crash after refund return'); },
    },
  });
  const payment = body.receipt.receipt.payment;
  const refundUrl = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const reconcileUrl = `http://collar.test/reconcile/refund/by-settlement/${result.settlementReference}`;
  const first = await collar.app.request(refundUrl, { method: 'POST' });
  assert.equal(first.status, 503);
  assert.doesNotMatch(JSON.stringify(await first.json()), /null|undefined/i);
  assert.equal(executorCalls, 1);
  assert.equal((await collar.app.request(refundUrl, { method: 'POST' })).status, 503);
  assert.equal(executorCalls, 1);
  const unresolved = collar.journal.getBySettlementReference(result.settlementReference);
  assert.equal(unresolved.payment.refundExecution.state, 'unresolved');
  assert.deepEqual(unresolved.receipt, body.receipt);
  assert.equal(verifySignedReceipt(unresolved.receipt, trustFor(collar)), true);

  const mismatches = [
    null,
    {
      refunded: true,
      settlementReference: `0x${'f'.repeat(64)}`,
      originalTxHash: payment.txHash,
      payer: payment.payer,
      amountAtomic: '250000',
      refundReference: 'wrong-reference',
    },
    {
      refunded: true,
      settlementReference: payment.settlementReference,
      originalTxHash: payment.txHash,
      payer: `0x${'a'.repeat(40)}`,
      amountAtomic: '250000',
      refundReference: 'wrong-payer',
    },
    {
      refunded: true,
      settlementReference: payment.settlementReference,
      originalTxHash: payment.txHash,
      payer: payment.payer,
      amountAtomic: '249999',
      refundReference: 'partial-refund',
    },
  ];
  const eventCount = collar.journal.events.length;
  for (const mismatch of mismatches) {
    resolverResult = mismatch;
    const response = await collar.app.request(reconcileUrl, { method: 'POST' });
    assert.equal(response.status, mismatch ? 502 : 202);
    assert.equal(collar.journal.events.length, eventCount);
    assert.equal(
      collar.journal.getBySettlementReference(result.settlementReference).payment.state,
      'settled',
    );
  }
  resolverResult = {
    refunded: true,
    settlementReference: payment.settlementReference,
    originalTxHash: payment.txHash,
    payer: payment.payer,
    amountAtomic: '250000',
    refundReference: 'reconciled-refund',
  };
  const reconciled = await collar.app.request(reconcileUrl, { method: 'POST' });
  assert.equal(reconciled.status, 200);
  const revised = (await reconciled.json()).receipt;
  assert.equal(revised.receipt.payment.state, 'refunded');
  assert.equal(revised.receipt.payment.refundReference, 'reconciled-refund');
  assert.equal(verifySignedReceipt(revised, trustFor(collar)), true);
});

test('overlapping refund requests durably claim one external execution', async () => {
  let calls = 0;
  let announceStarted;
  let release;
  const started = new Promise((resolve) => { announceStarted = resolve; });
  const gate = new Promise((resolve) => { release = resolve; });
  const { collar, result } = await invokeSettledFailure({
    executeRefund: async (request) => {
      calls += 1;
      announceStarted();
      await gate;
      return {
        refunded: true,
        settlementReference: request.settlementReference,
        originalTxHash: request.originalTxHash,
        payer: request.payer,
        amountAtomic: request.amountAtomic,
        refundReference: 'one-refund',
      };
    },
  });
  const endpoint = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const winner = collar.app.request(endpoint, { method: 'POST' });
  await started;
  const overlap = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(overlap.status, 503);
  assert.equal(calls, 1);
  release();
  const completed = await winner;
  assert.equal(completed.status, 200);
  const receipt = (await completed.json()).receipt;
  const replay = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(replay.status, 200);
  assert.deepEqual((await replay.json()).receipt, receipt);
  assert.equal(calls, 1);
  assert.equal(collar.journal.events.filter((event) => event.type === 'refund.started').length, 1);
});

test('a concurrently confirmed refund wins over an unresolved executor return path', async () => {
  let collarAuthority;
  let trustedResolution;
  const { collar, result } = await invokeSettledFailure({
    onCollarCreated: (created) => { collarAuthority = created; },
    executeRefund: async (request) => {
      trustedResolution = {
        refunded: true,
        settlementReference: request.settlementReference,
        originalTxHash: request.originalTxHash,
        payer: request.payer,
        amountAtomic: request.amountAtomic,
        refundReference: 'concurrent-winner-refund',
      };
      return trustedResolution;
    },
    lifecycleFaults: {
      afterRefundExecutorReturned: async ({ idempotencyKey, refundAttemptId }) => {
        collarAuthority.journal.refundExternalPayment(idempotencyKey, {
          refundAttemptId,
          reason: 'trusted full-gross refund confirmed',
          refundReference: trustedResolution.refundReference,
          refundAmountAtomic: trustedResolution.amountAtomic,
        });
        collarAuthority.journal.issueReceipt(idempotencyKey);
        throw new Error('stale worker lost the completion race');
      },
    },
  });
  const endpoint = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const response = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(response.status, 200);
  const receipt = (await response.json()).receipt;
  assert.equal(receipt.receipt.payment.state, 'refunded');
  assert.equal(receipt.receipt.payment.refundReference, 'concurrent-winner-refund');
  assert.equal(verifySignedReceipt(receipt, trustFor(collar)), true);
  const replay = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(replay.status, 200);
  assert.deepEqual((await replay.json()).receipt, receipt);
});

test('refund crash boundary stays unresolved and provider secrets never reach clients', async () => {
  const secret = 'sk-refund-super-secret';
  let calls = 0;
  const { collar, result } = await invokeSettledFailure({
    executeRefund: async () => {
      calls += 1;
      throw new Error(secret);
    },
  });
  const endpoint = `http://collar.test/refund/by-settlement/${result.settlementReference}`;
  const response = await collar.app.request(endpoint, { method: 'POST' });
  assert.equal(response.status, 503);
  const text = await response.text();
  assert.doesNotMatch(text, new RegExp(secret));
  assert.equal(calls, 1);
  assert.equal((await collar.app.request(endpoint, { method: 'POST' })).status, 503);
  assert.equal(calls, 1);
  assert.equal(
    collar.journal.getBySettlementReference(result.settlementReference).payment.refundExecution.state,
    'unresolved',
  );
});

test('Skill provider and settlement resolver secrets are replaced with stable public errors', async () => {
  const providerSecret = 'sk-provider-secret-response-body';
  const failed = await invokeSettledFailure({
    executeSkill: async () => { throw new Error(providerSecret); },
  });
  const failureText = JSON.stringify(failed.body);
  assert.doesNotMatch(failureText, new RegExp(providerSecret));
  assert.equal(failed.body.error, 'Skill execution failed after settlement');
  assert.equal(failed.body.receipt.receipt.execution.message, 'Skill execution failed after settlement');

  const resolverSecret = 'resolver-secret-token';
  const facilitator = createMockFacilitator();
  const transport = createMockFacilitatorTransport(async (url, init) => {
    const response = await facilitator.request(url, init);
    if (new URL(url).pathname === '/settle') throw new Error('lost response');
    return response;
  });
  const collar = createCollar({
    facilitatorTransport: transport,
    resolveSettlement: async () => { throw new Error(resolverSecret); },
    executeSkill: async () => ({ output: 'must not run' }),
  });
  const first = await withheldPayingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey: 'idem-secret-resolver',
    fetchImpl: (url, init) => collar.app.request(url, init),
  });
  const resolution = await collar.app.request(
    `http://collar.test/reconcile/by-settlement/${first.settlementReference}`,
    { method: 'POST' },
  );
  assert.equal(resolution.status, 502);
  assert.doesNotMatch(await resolution.text(), new RegExp(resolverSecret));
});

test('facilitator verification detail is absent from the response and durable journal', async () => {
  const secret = 'verify-invalidReason-secret-sentinel';
  let settleCalls = 0;
  let executionCalls = 0;
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-verify-secret-')));
  const journalFile = path.join(directory, 'events.jsonl');
  const signingKeyFile = path.join(directory, 'receipt-key.pem');
  const collar = createCollar({
    facilitatorTransport: createMockFacilitatorTransport(async (url) => {
      if (new URL(url).pathname === '/verify') {
        return new Response(JSON.stringify({ isValid: false, invalidReason: secret }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      settleCalls += 1;
      throw new Error('settlement must not run after rejected verification');
    }),
    journalFile,
    signingKeyFile,
    executeSkill: async () => {
      executionCalls += 1;
      return { output: 'must not run' };
    },
  });
  await assert.rejects(() => payingFetch(throwawayAccount(), invokeUrl, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, {
    idempotencyKey: 'idem-verifier-secret',
    fetchImpl: (url, init) => collar.app.request(url, init),
  }), (error) => error.code === 'SECOND_PAYMENT_REQUIRED'
    && !error.message.includes(secret));
  const record = collar.journal.getByIdempotencyKey('idem-verifier-secret');
  assert.equal(record.payment.state, 'rejected');
  assert.equal(record.payment.reason, 'payment verification failed');
  const durableBytes = fs.readFileSync(journalFile, 'utf8');
  assert.doesNotMatch(durableBytes, new RegExp(secret));
  assert.match(durableBytes, /payment verification failed/);
  assert.equal(settleCalls, 0);
  assert.equal(executionCalls, 0);
});

test('Anthropic error response bodies are never copied into the failed receipt', async () => {
  const responseSecret = 'sk-ant-secret-inside-upstream-body';
  const previousFetch = globalThis.fetch;
  const previousKey = process.env.ANTHROPIC_API_KEY;
  process.env.ANTHROPIC_API_KEY = 'test-only-key';
  globalThis.fetch = async (url) => {
    assert.equal(url, 'https://api.anthropic.com/v1/messages');
    return new Response(JSON.stringify({ error: responseSecret }), {
      status: 500,
      headers: { 'content-type': 'application/json' },
    });
  };
  try {
    const collar = createCollar({ facilitatorTransport: mockTransport(), mockLlm: false });
    const result = await payingFetch(throwawayAccount(), invokeUrl, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
    }, {
      idempotencyKey: 'idem-anthropic-secret-body',
      fetchImpl: (url, init) => collar.app.request(url, init),
    });
    assert.equal(result.res.status, 500);
    const text = await result.res.text();
    assert.doesNotMatch(text, new RegExp(responseSecret));
    assert.match(text, /Skill execution failed after settlement/);
  } finally {
    globalThis.fetch = previousFetch;
    if (previousKey === undefined) delete process.env.ANTHROPIC_API_KEY;
    else process.env.ANTHROPIC_API_KEY = previousKey;
  }
});

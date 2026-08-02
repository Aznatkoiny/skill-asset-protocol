import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { createBudgetLedger } from '../src/kernel/budget-ledger.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { evaluateSpendPolicy, projectPaymentRequired } from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { createReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import { createReconciler } from '../src/kernel/recovery.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:10:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const REFUND_SOURCE = '0x3000000000000000000000000000000000000000';
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function paymentRequired(amount = '50000') {
  return {
    x402Version: 2,
    error: 'not persisted',
    resource: {
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount,
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
  };
}

function currentPaymentCaseHash(store, intentId) {
  const intent = store.readOne('SELECT * FROM spend_intents WHERE id = ?', [intentId]);
  const attempt = store.readOne('SELECT * FROM payment_attempts WHERE intent_id = ?', [intentId]);
  const budget = store.readOne('SELECT * FROM budget_reservations WHERE intent_id = ?', [intentId]);
  const outcome = store.readOne('SELECT * FROM buyer_outcomes WHERE intent_id = ?', [intentId]);
  const history = store.readAll(`SELECT * FROM payment_reconciliation_candidates
    WHERE intent_id = ? ORDER BY rowid`, [intentId]);
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-reconciliation-case.v1',
    intentId,
    intentHash: intent.intent_hash,
    attemptState: attempt.state,
    budgetState: budget.state,
    buyerOutcomeRevision: Number(outcome.revision),
    history: history.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      state: row.state,
      evidenceHash: row.evidence_json === null ? null : sha256(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function bindExpectedIntentHash(reconciler, expectedIntentHash) {
  return Object.freeze({
    reconcilePayment: (input) => reconciler.reconcilePayment({
      expectedIntentHash,
      ...input,
    }),
    reconcileExecution: (input) => reconciler.reconcileExecution({
      expectedIntentHash,
      ...input,
    }),
    observeRefund: (input) => reconciler.observeRefund({
      expectedIntentHash,
      ...input,
    }),
    abandonCandidate: (input) => reconciler.abandonCandidate(input),
  });
}

function setupUnresolved(t, observePayment, {
  observeExecution = () => ({
    kind: 'unknown',
    reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
  }),
  observeRefund = () => ({
    kind: 'unknown',
    reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
  }),
  minimumConfirmations,
} = {}) {
  const clock = { value: NOW };
  const now = () => clock.value;
  const idFactory = sequenceIds();
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true, now });
  t.after(() => store.close());
  const policyDocument = structuredClone(BASE_POLICY);
  policyDocument.sellers[0].autoApproveAtomic = '1000000';
  policyDocument.sellers[0].perRequestMaxAtomic = '1000000';
  policyDocument.sellers[0].humanApproveAtomic = '1000000';
  policyDocument.sellers[0].sellerSessionMaxAtomic = '1000000';
  policyDocument.sessionMaxAtomic = '2000000';
  policyDocument.rolling24hMaxAtomic = '5000000';
  const policies = createPolicyRepository(store);
  const policyVersion = policies.apply(policyDocument, NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store, now });
  enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: sha256(canonicalJson(DESCRIPTOR)),
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const intents = createIntentRepository({
    store,
    idFactory,
    now,
    routeMetadata: Object.freeze({
      'paid-infer': Object.freeze({
        description: 'offline fixture',
        mimeType: 'application/json',
      }),
    }),
  });
  const session = intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: policyVersion.id,
  });
  const request = {
    routeId: 'paid-infer',
    method: 'POST',
    requestUrl: `${SELLER}/paid/infer`,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from('{}'),
    purposeLabel: 'skill.invoke',
    correlationId: 'reconcile-fixture',
  };
  const intent = intents.captureIntent({ sessionId: session.id, ...request });
  const challenge = paymentRequired();
  intents.attachChallenge({ intentId: intent.id, paymentRequired: challenge, challengeReceivedAt: NOW });
  const evaluation = evaluateSpendPolicy({
    policy: policyVersion.policy,
    policyVersion: { id: policyVersion.id, hash: policyVersion.hash },
    intent: {
      id: intent.id,
      method: request.method,
      requestUrl: request.requestUrl,
      sellerOrigin: SELLER,
      resourcePath: '/paid/infer',
      walletAddress: WALLET,
    },
    wallet: { provider: 'deterministic', walletId: 'buyer', address: WALLET, network: NETWORK },
    paymentRequired: challenge,
    challengeReceivedAtMs: Date.parse(NOW),
    nowMs: Date.parse(NOW),
    budgetSnapshot: {
      sellerSessionExposureAtomic: '0',
      sessionExposureAtomic: '0',
      rolling24hExposureAtomic: '0',
      pendingApprovalCount: 0,
    },
  });
  store.transaction((token) => policies.recordDecisionInTransaction(token, {
    intentId: intent.id,
    policyVersionId: policyVersion.id,
    evaluation,
    decidedAt: NOW,
  }));
  intents.transition({
    intentId: intent.id,
    expectedState: 'challenged',
    nextState: 'authorized',
    reasonCode: 'POLICY_ALLOWED',
  });
  const budgets = createBudgetLedger({ store, now });
  budgets.reserve({ intentId: intent.id, amountAtomic: evaluation.amountCeilingAtomic });
  const projection = projectPaymentRequired(challenge);
  const nonce = `0x${'11'.repeat(32)}`;
  const paymentHeader = 'integration-payment-header';
  const paymentPayload = {
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: {
      signature: `0x${'22'.repeat(65)}`,
      authorization: {
        from: WALLET,
        to: PAY_TO,
        value: evaluation.amountCeilingAtomic,
        validAfter: '0',
        validBefore: '1785502860',
        nonce,
      },
    },
  };
  store.transaction((token) => store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, signing_claimed_at, signed_at, retry_started_at,
       created_at, updated_at)
      VALUES ('payment-1', ?, 'retrying', ?, 0, ?, ?, ?, ?, ?, '0', '1785502860',
        ?, ?, ?, ?, ?)`).run(
      intent.id,
      canonicalJson(projection),
      canonicalJson(paymentPayload),
      paymentHeader,
      sha256(Buffer.from(paymentHeader, 'ascii')),
      evaluation.quoteId,
      nonce,
      NOW,
      NOW,
      NOW,
      NOW,
      NOW,
    );
  }));
  for (const [expectedState, nextState] of [
    ['authorized', 'reserved'], ['reserved', 'signing'], ['signing', 'signed'], ['signed', 'retrying'],
  ]) {
    intents.transition({
      intentId: intent.id,
      expectedState,
      nextState,
      reasonCode: `TEST_${nextState.toUpperCase()}`,
    });
  }
  store.transaction((token) => {
    budgets.holdUnresolvedInTransaction(token, {
      intentId: intent.id,
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
    });
    store.within(token, ({ db, appendEvent }) => {
      db.prepare(`UPDATE payment_attempts
        SET state = 'unresolved', reason_code = 'PAID_RESPONSE_AMBIGUOUS'
        WHERE intent_id = ? AND state = 'retrying'`).run(intent.id);
      db.prepare(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES (?, 'payment_unresolved', 'PAID_RESPONSE_AMBIGUOUS', 1, ?)`).run(intent.id, NOW);
      appendEvent({
        entityType: 'buyer_outcome',
        entityId: intent.id,
        eventType: 'buyer_outcome.recorded',
        data: {
          status: 'payment_unresolved',
          reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
          revision: 1,
          recordedAt: NOW,
        },
      });
    });
    intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'retrying',
      nextState: 'unresolved',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
    });
  });
  const receipts = createSignedReceiptRepository({
    store,
    signer: createReceiptSigner(),
    idFactory,
    now,
  });
  receipts.issueForTerminal({ intentId: intent.id });
  let leaseDepth = 0;
  const authorityMutationCoordinator = Object.freeze({
    runExclusive(operation) {
      leaseDepth += 1;
      try { return Promise.resolve(operation()); } finally { leaseDepth -= 1; }
    },
  });
  const resolver = Object.freeze({
    observePayment: (binding) => {
      assert.equal(leaseDepth, 0);
      return observePayment(binding);
    },
    observeExecution: (binding) => {
      assert.equal(leaseDepth, 0);
      assertPersistedSellerAuthority(binding);
      return observeExecution(binding);
    },
    observeRefund: (binding) => {
      assert.equal(leaseDepth, 0);
      assertPersistedSellerAuthority(binding);
      return observeRefund(binding);
    },
  });
  const rawReconciler = createReconciler({
    store,
    budgets,
    receipts,
    resolver,
    now,
    idFactory,
    authorityMutationCoordinator,
    markAuthorityUnhealthy: () => undefined,
    ...(minimumConfirmations === undefined ? {} : { minimumConfirmations }),
  });
  const reconciler = bindExpectedIntentHash(rawReconciler, intent.intentHash);
  return { budgets, clock, intent, receipts, reconciler, session, store };
}

function assertPersistedSellerAuthority(binding) {
  assert.equal(binding.resourcePath, '/paid/infer');
  assert.equal(binding.policyVersion.id.startsWith('policy-'), true);
  assert.equal(
    binding.policyVersion.hash,
    sha256(canonicalJson(binding.policyVersion.policy)),
  );
  assert.deepEqual(binding.seller, binding.policyVersion.policy.sellers[0]);
  assert.equal(binding.seller.origin, binding.sellerOrigin);
  assert.equal(
    binding.seller.pathPrefixes.some((prefix) => binding.resourcePath.startsWith(prefix)),
    true,
  );
  assert.equal(Object.isFrozen(binding.policyVersion), true);
  assert.equal(Object.isFrozen(binding.policyVersion.policy), true);
  assert.equal(Object.isFrozen(binding.seller), true);
}

function settledPaymentObservation(binding) {
  return Object.freeze({
    kind: 'settled_transfer',
    rpcTransferProof: Object.freeze({
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: binding.candidate.transactionId,
      blockHash: `0x${'71'.repeat(32)}`,
      blockNumber: '1234571',
      transactionStatus: 'success',
      confirmations: 3,
      transferLogIndex: 4,
      authorizationLogIndex: 5,
      tokenContract: ASSET,
      from: WALLET,
      to: PAY_TO,
      valueAtomic: '50000',
      authorizationNonce: `0x${'11'.repeat(32)}`,
      observedAt: NOW,
    }),
  });
}

function failedExecutionObservation(binding) {
  const attestation = Object.freeze({
    schemaVersion: 1,
    domain: 'wallet-kernel.execution.v1',
    network: NETWORK,
    sellerOrigin: SELLER,
    intentHash: binding.intentHash,
    transactionId: binding.transactionId,
    outcome: 'failed',
    httpStatus: 503,
    responseHash: null,
    issuedAt: '2026-07-31T12:09:00.000Z',
    expiresAt: '2026-07-31T12:15:00.000Z',
    signer: PAY_TO,
  });
  return Object.freeze({
    kind: 'execution_attested',
    attestation,
    attestationHash: sha256(canonicalJson(attestation)),
  });
}

async function setupRefundPending(t, observeRefund) {
  const context = setupUnresolved(t, settledPaymentObservation, {
    observeExecution: failedExecutionObservation,
    observeRefund,
  });
  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'72'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });
  const execution = await context.reconciler.reconcileExecution({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedExecutionCaseHash: payment.executionCaseHash,
  });
  return { context, refundCaseHash: execution.refundCaseHash };
}

test('trusted reconciler exposes only the four operator workflows', () => {
  const noop = () => undefined;
  const reconciler = createReconciler({
    store: Object.freeze({ transaction: noop, within: noop }),
    budgets: Object.freeze({
      resolvePaymentInTransaction: noop,
      recordConfirmedRefundInTransaction: noop,
    }),
    receipts: Object.freeze({
      assertParityInTransaction: noop,
      issueRevisionForTerminal: noop,
      latest: noop,
    }),
    resolver: Object.freeze({
      observePayment: noop,
      observeExecution: noop,
      observeRefund: noop,
    }),
    now: () => '2026-07-31T12:10:00.000Z',
    idFactory: (kind) => `${kind}-1`,
    authorityMutationCoordinator: Object.freeze({ runExclusive: noop }),
    markAuthorityUnhealthy: noop,
  });

  assert.deepEqual(Object.keys(reconciler), [
    'reconcilePayment',
    'reconcileExecution',
    'observeRefund',
    'abandonCandidate',
  ]);
  assert.ok(Object.isFrozen(reconciler));
  for (const method of Object.values(reconciler)) assert.equal(typeof method, 'function');
});

test('trusted reconciler rejects dependency and request extension fields', async () => {
  const noop = () => undefined;
  assert.throws(() => createReconciler({}), TypeError);
  const reconciler = createReconciler({
    store: Object.freeze({ transaction: noop, within: noop }),
    budgets: Object.freeze({
      resolvePaymentInTransaction: noop,
      recordConfirmedRefundInTransaction: noop,
    }),
    receipts: Object.freeze({
      assertParityInTransaction: noop,
      issueRevisionForTerminal: noop,
      latest: noop,
    }),
    resolver: Object.freeze({
      observePayment: noop,
      observeExecution: noop,
      observeRefund: noop,
    }),
    now: () => '2026-07-31T12:10:00.000Z',
    idFactory: (kind) => `${kind}-1`,
    authorityMutationCoordinator: Object.freeze({ runExclusive: noop }),
    markAuthorityUnhealthy: noop,
  });

  await assert.rejects(
    reconciler.reconcilePayment({
      intentId: 'intent-1',
      operatorIdHash: `sha256:${'ab'.repeat(32)}`,
      expectedIntentHash: `sha256:${'ef'.repeat(32)}`,
      paymentTransactionId: null,
      expectedPaymentCaseHash: `sha256:${'cd'.repeat(32)}`,
      evidence: {},
    }),
    (error) => error?.code === 'RECONCILIATION_INPUT',
  );
  await assert.rejects(
    reconciler.reconcilePayment({
      intentId: 'intent-1',
      operatorIdHash: `sha256:${'ab'.repeat(32)}`,
      expectedPaymentCaseHash: `sha256:${'cd'.repeat(32)}`,
    }),
    (error) => error?.code === 'RECONCILIATION_INPUT',
  );
  assert.throws(
    () => createReconciler({
      store: Object.freeze({ transaction: noop, within: noop }),
      budgets: Object.freeze({
        resolvePaymentInTransaction: noop,
        recordConfirmedRefundInTransaction: noop,
      }),
      receipts: Object.freeze({
        assertParityInTransaction: noop,
        issueRevisionForTerminal: noop,
        latest: noop,
      }),
      resolver: Object.freeze({
        observePayment: noop,
        observeExecution: noop,
        observeRefund: noop,
      }),
      now: () => '2026-07-31T12:10:00.000Z',
      idFactory: (kind) => `${kind}-1`,
      authorityMutationCoordinator: Object.freeze({ runExclusive: noop }),
      markAuthorityUnhealthy: noop,
      minimumConfirmations: 0,
    }),
    TypeError,
  );
});

test('stale intent hashes reject payment, execution, and refund before evidence or mutation', async (t) => {
  const calls = { payment: 0, execution: 0, refund: 0 };
  const context = setupUnresolved(t, (binding) => {
    calls.payment += 1;
    return settledPaymentObservation(binding);
  }, {
    observeExecution: (binding) => {
      calls.execution += 1;
      return failedExecutionObservation(binding);
    },
    observeRefund: () => {
      calls.refund += 1;
      return Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      });
    },
  });
  const staleIntentHash = `sha256:${'ee'.repeat(32)}`;
  assert.notEqual(staleIntentHash, context.intent.intentHash);

  let eventCount = context.store.events().length;
  await assert.rejects(
    context.reconciler.reconcilePayment({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedIntentHash: staleIntentHash,
      paymentTransactionId: `0x${'29'.repeat(32)}`,
      expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
    }),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(calls.payment, 0);
  assert.equal(context.store.events().length, eventCount);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM payment_reconciliation_candidates WHERE intent_id = ?',
    [context.intent.id],
  ).count, 0n);

  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'2c'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });
  eventCount = context.store.events().length;
  await assert.rejects(
    context.reconciler.reconcileExecution({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedIntentHash: staleIntentHash,
      expectedExecutionCaseHash: payment.executionCaseHash,
    }),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(calls.execution, 0);
  assert.equal(context.store.events().length, eventCount);

  const execution = await context.reconciler.reconcileExecution({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedExecutionCaseHash: payment.executionCaseHash,
  });
  eventCount = context.store.events().length;
  const refundCount = context.store.readOne(
    'SELECT COUNT(*) AS count FROM refunds WHERE intent_id = ?',
    [context.intent.id],
  ).count;
  await assert.rejects(
    context.reconciler.observeRefund({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedIntentHash: staleIntentHash,
      refundTransactionId: `0x${'2d'.repeat(32)}`,
      expectedRefundCaseHash: execution.refundCaseHash,
    }),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(calls.refund, 0);
  assert.equal(context.store.events().length, eventCount);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM refunds WHERE intent_id = ?',
    [context.intent.id],
  ).count, refundCount);
});

test('confirmation depth defaults to two and honors a stricter configured threshold', async (t) => {
  const defaultContext = setupUnresolved(t, (binding) => {
    const observation = settledPaymentObservation(binding);
    return Object.freeze({
      ...observation,
      rpcTransferProof: Object.freeze({ ...observation.rpcTransferProof, confirmations: 2 }),
    });
  });
  const defaultResult = await defaultContext.reconciler.reconcilePayment({
    intentId: defaultContext.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'2a'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(defaultContext.store, defaultContext.intent.id),
  });
  assert.equal(defaultResult.status, 'execution_unknown');

  let confirmations = 3;
  const strictContext = setupUnresolved(t, (binding) => {
    const observation = settledPaymentObservation(binding);
    return Object.freeze({
      ...observation,
      rpcTransferProof: Object.freeze({ ...observation.rpcTransferProof, confirmations }),
    });
  }, { minimumConfirmations: 4 });
  const strictRequest = {
    intentId: strictContext.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'2b'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(strictContext.store, strictContext.intent.id),
  };
  await assert.rejects(
    strictContext.reconciler.reconcilePayment(strictRequest),
    (error) => error?.code === 'RECONCILIATION_MISMATCH',
  );
  assert.equal(strictContext.store.readOne(
    'SELECT COUNT(*) AS count FROM reconciliations WHERE intent_id = ?',
    [strictContext.intent.id],
  ).count, 0n);

  confirmations = 4;
  strictRequest.expectedPaymentCaseHash = currentPaymentCaseHash(
    strictContext.store,
    strictContext.intent.id,
  );
  const strictResult = await strictContext.reconciler.reconcilePayment(strictRequest);
  assert.equal(strictResult.status, 'execution_unknown');
});

test('payment candidate observation runs outside leases and abandonment only rotates history', async (t) => {
  let observations = 0;
  const context = setupUnresolved(t, () => {
    observations += 1;
    return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_RECEIPT_MISSING' });
  });
  const initialCaseHash = currentPaymentCaseHash(context.store, context.intent.id);
  const firstTransactionId = `0x${'31'.repeat(32)}`;
  const first = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: firstTransactionId,
    expectedPaymentCaseHash: initialCaseHash,
  });

  assert.equal(first.status, 'payment_unresolved');
  assert.notEqual(first.paymentCaseHash, initialCaseHash);
  assert.equal(observations, 1);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?',
    [context.intent.id],
  ).state, 'unresolved');
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?',
    [context.intent.id],
  ).revision, 1n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?',
    [context.intent.id],
  ).count, 1n);

  const abandoned = await context.reconciler.abandonCandidate({
    intentId: context.intent.id,
    kind: 'payment',
    operatorIdHash: OPERATOR_HASH,
    expectedCaseHash: first.paymentCaseHash,
  });
  assert.notEqual(abandoned.caseHash, first.paymentCaseHash);
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
    [firstTransactionId],
  ).state, 'abandoned');
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?',
    [context.intent.id],
  ).revision, 1n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?',
    [context.intent.id],
  ).count, 1n);

  const secondTransactionId = `0x${'32'.repeat(32)}`;
  const second = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: secondTransactionId,
    expectedPaymentCaseHash: abandoned.caseHash,
  });
  assert.equal(second.status, 'payment_unresolved');
  assert.equal(observations, 2);
  assert.deepEqual(context.store.readAll(`SELECT transaction_id, state
    FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid`, [context.intent.id])
    .map((row) => ({ transactionId: row.transaction_id, state: row.state })), [
    { transactionId: firstTransactionId, state: 'abandoned' },
    { transactionId: secondTransactionId, state: 'pending' },
  ]);
  assert.equal(context.store.verifyEventChain(), true);
});

test('a concurrent abandonment makes the resolver result stale with zero resolution writes', async (t) => {
  let context;
  context = setupUnresolved(t, async (binding) => {
    await context.reconciler.abandonCandidate({
      intentId: binding.intentId,
      kind: 'payment',
      operatorIdHash: OPERATOR_HASH,
      expectedCaseHash: binding.caseHash,
    });
    return settledPaymentObservation(binding);
  });
  const transactionId = `0x${'33'.repeat(32)}`;

  await assert.rejects(
    context.reconciler.reconcilePayment({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      paymentTransactionId: transactionId,
      expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
    }),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );

  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
    [transactionId],
  ).state, 'abandoned');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM reconciliations WHERE intent_id = ?',
    [context.intent.id],
  ).count, 0n);
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?',
    [context.intent.id],
  ).revision, 1n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?',
    [context.intent.id],
  ).count, 1n);
  assert.equal(context.store.verifyEventChain(), true);
});

test('candidate abandonment rejects a clock behind persisted payment and refund authority', async (t) => {
  await t.test('payment candidate', async (st) => {
    const context = setupUnresolved(st, () => Object.freeze({
      kind: 'unknown',
      reasonCode: 'RPC_RECEIPT_MISSING',
    }));
    const transactionId = `0x${'34'.repeat(32)}`;
    const pending = await context.reconciler.reconcilePayment({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      paymentTransactionId: transactionId,
      expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
    });
    context.clock.value = '2026-07-31T12:09:59.999Z';
    const beforeEvents = context.store.events().length;

    await assert.rejects(
      context.reconciler.abandonCandidate({
        intentId: context.intent.id,
        kind: 'payment',
        operatorIdHash: OPERATOR_HASH,
        expectedCaseHash: pending.paymentCaseHash,
      }),
      (error) => error?.code === 'RECONCILIATION_TIME',
    );
    assert.equal(context.store.readOne(
      'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
      [transactionId],
    ).state, 'pending');
    assert.equal(context.store.events().length, beforeEvents);
  });

  await t.test('refund candidate', async (st) => {
    const context = setupUnresolved(st, settledPaymentObservation, {
      observeExecution: failedExecutionObservation,
    });
    const payment = await context.reconciler.reconcilePayment({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      paymentTransactionId: `0x${'35'.repeat(32)}`,
      expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
    });
    const execution = await context.reconciler.reconcileExecution({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedExecutionCaseHash: payment.executionCaseHash,
    });
    const refundTransactionId = `0x${'36'.repeat(32)}`;
    const pending = await context.reconciler.observeRefund({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      refundTransactionId,
      expectedRefundCaseHash: execution.refundCaseHash,
    });
    context.clock.value = '2026-07-31T12:09:59.999Z';
    const beforeEvents = context.store.events().length;

    await assert.rejects(
      context.reconciler.abandonCandidate({
        intentId: context.intent.id,
        kind: 'refund-observation',
        operatorIdHash: OPERATOR_HASH,
        expectedCaseHash: pending.refundCaseHash,
      }),
      (error) => error?.code === 'RECONCILIATION_TIME',
    );
    assert.equal(context.store.readOne(
      'SELECT state FROM refunds WHERE refund_transaction_id = ?',
      [refundTransactionId],
    ).state, 'pending');
    assert.equal(context.store.events().length, beforeEvents);
  });
});

test('settled payment observation commits through the trusted budget API and signs revision two', async (t) => {
  let conflictingReplay = false;
  const context = setupUnresolved(t, (binding) => Object.freeze({
    kind: 'settled_transfer',
    rpcTransferProof: Object.freeze({
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: binding.candidate.transactionId,
      blockHash: `0x${(conflictingReplay ? 'ce' : 'cd').repeat(32)}`,
      blockNumber: '1234567',
      transactionStatus: 'success',
      confirmations: 3,
      transferLogIndex: 4,
      authorizationLogIndex: 5,
      tokenContract: ASSET,
      from: WALLET,
      to: PAY_TO,
      valueAtomic: '50000',
      authorizationNonce: `0x${'11'.repeat(32)}`,
      observedAt: NOW,
    }),
  }));
  const transactionId = `0x${'41'.repeat(32)}`;
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: transactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  };
  const result = await context.reconciler.reconcilePayment(request);

  assert.equal(result.status, 'execution_unknown');
  assert.equal(result.reasonCode, 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN');
  assert.equal(result.receipt.revision, 2);
  assert.deepEqual({
    intent: context.store.readOne('SELECT state FROM spend_intents WHERE id = ?', [context.intent.id]).state,
    payment: context.store.readOne(
      'SELECT state FROM payment_attempts WHERE intent_id = ?', [context.intent.id],
    ).state,
    budget: context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [context.intent.id],
    ).state,
    execution: context.store.readOne(
      'SELECT state FROM execution_outcomes WHERE intent_id = ?', [context.intent.id],
    ).state,
    resolution: context.store.readOne(
      'SELECT state FROM execution_resolutions WHERE intent_id = ?', [context.intent.id],
    ).state,
  }, {
    intent: 'terminal',
    payment: 'settled',
    budget: 'committed',
    execution: 'unknown',
    resolution: 'reconciliation_required',
  });
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.verifyEventChain(), true);
  assert.deepEqual(
    context.store.events()
      .filter((event) => event.entity_id === context.intent.id)
      .map((event) => event.event_type)
      .filter((eventType) => eventType === 'execution.recorded'
        || eventType === 'execution_resolution.opened'),
    ['execution.recorded', 'execution_resolution.opened'],
  );

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.reconcilePayment(request);
  assert.equal(replay.status, result.status);
  assert.equal(replay.reasonCode, result.reasonCode);
  assert.equal(replay.executionCaseHash, result.executionCaseHash);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);

  conflictingReplay = true;
  await assert.rejects(
    context.reconciler.reconcilePayment(request),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(context.store.events().length, eventCount);
});

test('conclusive candidate rejection rotates the case but preserves the signed hold', async (t) => {
  let observations = 0;
  const context = setupUnresolved(t, (binding) => {
    observations += 1;
    if (observations > 2) {
      return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_RECEIPT_MISSING' });
    }
    return Object.freeze({
      kind: 'payment_candidate_rejected',
      rejectionProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.candidate.transactionId,
        blockHash: `0x${'51'.repeat(32)}`,
        blockNumber: '1234568',
        transactionStatus: 'reverted',
        confirmations: 3,
        reasonCode: 'TRANSACTION_REVERTED',
        observedAt: NOW,
      }),
    });
  });
  const transactionId = `0x${'52'.repeat(32)}`;
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: transactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  };
  const result = await context.reconciler.reconcilePayment(request);

  assert.equal(result.status, 'payment_unresolved');
  assert.equal(result.reasonCode, 'PAYMENT_CANDIDATE_REJECTED');
  assert.equal(result.receipt.revision, 2);
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
    [transactionId],
  ).state, 'rejected');
  assert.deepEqual({
    payment: context.store.readOne(
      'SELECT state FROM payment_attempts WHERE intent_id = ?', [context.intent.id],
    ).state,
    budget: context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [context.intent.id],
    ).state,
    outcome: context.store.readOne(
      'SELECT reason_code FROM buyer_outcomes WHERE intent_id = ?', [context.intent.id],
    ).reason_code,
  }, {
    payment: 'unresolved',
    budget: 'unresolved',
    outcome: 'PAYMENT_CANDIDATE_REJECTED',
  });
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assert.equal(context.receipts.assertParity(), true);

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.reconcilePayment(request);
  assert.equal(replay.status, result.status);
  assert.equal(replay.reasonCode, result.reasonCode);
  assert.equal(replay.paymentCaseHash, result.paymentCaseHash);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);

  const replacementTransactionId = `0x${'53'.repeat(32)}`;
  const replacement = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: replacementTransactionId,
    expectedPaymentCaseHash: result.paymentCaseHash,
  });
  assert.equal(replacement.status, 'payment_unresolved');
  assert.equal(replacement.receipt, null);
  assert.deepEqual(context.store.readAll(`SELECT state, transaction_id
    FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid`,
  [context.intent.id]).map((row) => ({
    state: row.state,
    transactionId: row.transaction_id,
  })), [
    { state: 'rejected', transactionId },
    { state: 'pending', transactionId: replacementTransactionId },
  ]);
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?', [context.intent.id],
  ).revision, 2n);
  assert.equal(context.receipts.assertParity(), true);
});

test('only exact post-expiry unused authorization releases a signed payment hold', async (t) => {
  let conflictingReplay = false;
  const context = setupUnresolved(t, () => Object.freeze({
    kind: 'authorization_unused_after_expiry',
    network: NETWORK,
    asset: ASSET,
    payer: WALLET,
    nonce: `0x${'11'.repeat(32)}`,
    validBefore: '1785502860',
    authorizationState: false,
    observedBlockNumber: '1234570',
    observedBlockHash: `0x${(conflictingReplay ? '55' : '54').repeat(32)}`,
    observedBlockTimestamp: '1785502920',
    confirmations: 3,
  }));
  context.clock.value = '2026-07-31T13:02:00.000Z';
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  };
  const result = await context.reconciler.reconcilePayment(request);
  assert.equal(result.status, 'payment_rejected');
  assert.equal(result.reasonCode, 'AUTHORIZATION_UNUSED_AFTER_EXPIRY');
  assert.equal(result.receipt.revision, 2);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [context.intent.id],
  ).state, 'released');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?', [context.intent.id],
  ).state, 'rejected');

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.reconcilePayment(request);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);
  conflictingReplay = true;
  await assert.rejects(
    context.reconciler.reconcilePayment(request),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(context.store.events().length, eventCount);
});

test('post-expiry unused authorization terminally rejects a retained pending candidate', async (t) => {
  let observationCount = 0;
  const context = setupUnresolved(t, () => {
    observationCount += 1;
    if (observationCount === 1) {
      return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_RECEIPT_MISSING' });
    }
    return Object.freeze({
      kind: 'authorization_unused_after_expiry',
      network: NETWORK,
      asset: ASSET,
      payer: WALLET,
      nonce: `0x${'11'.repeat(32)}`,
      validBefore: '1785502860',
      authorizationState: false,
      observedBlockNumber: '1234571',
      observedBlockHash: `0x${'56'.repeat(32)}`,
      observedBlockTimestamp: '1785502920',
      confirmations: 3,
    });
  });
  const transactionId = `0x${'57'.repeat(32)}`;
  const pending = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: transactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });
  context.clock.value = '2026-07-31T13:02:00.000Z';

  const result = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedPaymentCaseHash: pending.paymentCaseHash,
  });
  assert.equal(result.status, 'payment_rejected');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
    [transactionId],
  ).state, 'rejected');
  assert.equal(context.store.events().filter((event) => (
    event.entity_type === 'payment_reconciliation_candidate'
      && event.event_type === 'payment.candidate_rejected'
  )).length, 1);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [context.intent.id],
  ).state, 'released');
  assert.equal(context.receipts.assertParity(), true);
});

test('verified execution failure opens one blocking full-refund case and revision', async (t) => {
  let conflictingReplay = false;
  const context = setupUnresolved(
    t,
    (binding) => Object.freeze({
      kind: 'settled_transfer',
      rpcTransferProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.candidate.transactionId,
        blockHash: `0x${'61'.repeat(32)}`,
        blockNumber: '1234570',
        transactionStatus: 'success',
        confirmations: 3,
        transferLogIndex: 4,
        authorizationLogIndex: 5,
        tokenContract: ASSET,
        from: WALLET,
        to: PAY_TO,
        valueAtomic: '50000',
        authorizationNonce: `0x${'11'.repeat(32)}`,
        observedAt: NOW,
      }),
    }),
    {
      observeExecution: (binding) => {
        const attestation = Object.freeze({
          schemaVersion: 1,
          domain: 'wallet-kernel.execution.v1',
          network: NETWORK,
          sellerOrigin: SELLER,
          intentHash: binding.intentHash,
          transactionId: binding.transactionId,
          outcome: 'failed',
          httpStatus: 503,
          responseHash: null,
          issuedAt: conflictingReplay
            ? '2026-07-31T12:08:00.000Z'
            : '2026-07-31T12:09:00.000Z',
          expiresAt: '2026-07-31T12:15:00.000Z',
          signer: PAY_TO,
        });
        return Object.freeze({
          kind: 'execution_attested',
          attestation,
          attestationHash: sha256(canonicalJson(attestation)),
        });
      },
    },
  );
  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'62'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedExecutionCaseHash: payment.executionCaseHash,
  };
  const result = await context.reconciler.reconcileExecution(request);

  assert.equal(result.status, 'execution_failed');
  assert.equal(result.reasonCode, 'REFUND_UNRESOLVED');
  assert.equal(result.receipt.revision, 3);
  assert.equal(context.store.readOne(
    'SELECT state FROM execution_outcomes WHERE intent_id = ?', [context.intent.id],
  ).state, 'failed');
  assert.equal(context.store.readOne(
    'SELECT state FROM execution_resolutions WHERE intent_id = ?', [context.intent.id],
  ).state, 'refund_pending');
  assert.deepEqual(context.store.readOne(
    `SELECT amount_atomic, state, refund_transaction_id FROM refunds
      WHERE intent_id = ?`, [context.intent.id],
  ), Object.assign(Object.create(null), {
    amount_atomic: '50000',
    state: 'pending',
    refund_transaction_id: null,
  }));
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.events().some((event) => (
    event.entity_id === context.intent.id
      && event.event_type === 'execution_resolution.opened'
      && JSON.parse(event.data_json).state === 'refund_pending'
  )), true);
  assert.equal(context.store.events().some((event) => (
    event.event_type === 'refund.opened'
      && JSON.parse(event.data_json).intentId === context.intent.id
  )), true);

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.reconcileExecution(request);
  assert.equal(replay.status, result.status);
  assert.equal(replay.reasonCode, result.reasonCode);
  assert.equal(replay.refundCaseHash, result.refundCaseHash);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);
  conflictingReplay = true;
  await assert.rejects(
    context.reconciler.reconcileExecution(request),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(context.store.events().length, eventCount);
});

test('rejected refund candidate signs one revision and permits a named replacement', async (t) => {
  let observations = 0;
  const { context, refundCaseHash } = await setupRefundPending(t, (binding) => {
    observations += 1;
    if (observations > 2) {
      return Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      });
    }
    return Object.freeze({
      kind: 'refund_candidate_rejected',
      rejectionProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.refundTransactionId,
        blockHash: `0x${'73'.repeat(32)}`,
        blockNumber: '1234572',
        transactionStatus: 'reverted',
        confirmations: 3,
        reasonCode: 'TRANSACTION_REVERTED',
        observedAt: NOW,
      }),
    });
  });
  const rejectedTransactionId = `0x${'74'.repeat(32)}`;
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    refundTransactionId: rejectedTransactionId,
    expectedRefundCaseHash: refundCaseHash,
  };
  const rejected = await context.reconciler.observeRefund(request);

  assert.equal(rejected.status, 'execution_failed');
  assert.equal(rejected.reasonCode, 'REFUND_UNRESOLVED');
  assert.equal(rejected.receipt.revision, 4);
  assert.equal(rejected.receipt.receipt.refund.state, 'rejected');
  assert.equal(context.store.readOne(
    'SELECT state FROM refunds WHERE refund_transaction_id = ?', [rejectedTransactionId],
  ).state, 'rejected');
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.observeRefund(request);
  assert.equal(replay.status, rejected.status);
  assert.equal(replay.reasonCode, rejected.reasonCode);
  assert.equal(replay.refundCaseHash, rejected.refundCaseHash);
  assert.equal(replay.receipt.receiptHash, rejected.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);

  const replacementTransactionId = `0x${'75'.repeat(32)}`;
  const replacement = await context.reconciler.observeRefund({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    refundTransactionId: replacementTransactionId,
    expectedRefundCaseHash: rejected.refundCaseHash,
  });
  assert.equal(replacement.status, 'execution_failed');
  assert.equal(replacement.receipt, null);
  assert.deepEqual(context.store.readAll(`SELECT state, refund_transaction_id
    FROM refunds WHERE intent_id = ? ORDER BY rowid`, [context.intent.id])
    .map((row) => ({ state: row.state, transactionId: row.refund_transaction_id })), [
    { state: 'rejected', transactionId: rejectedTransactionId },
    { state: 'pending', transactionId: replacementTransactionId },
  ]);
  assert.equal(context.receipts.assertParity(), true);
});

test('unknown refund candidates remain blocking through abandonment and replacement', async (t) => {
  const { context, refundCaseHash } = await setupRefundPending(
    t,
    () => Object.freeze({
      kind: 'unknown',
      reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
    }),
  );
  const abandonedTransactionId = `0x${'76'.repeat(32)}`;
  const pending = await context.reconciler.observeRefund({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    refundTransactionId: abandonedTransactionId,
    expectedRefundCaseHash: refundCaseHash,
  });
  assert.equal(pending.status, 'execution_failed');
  assert.equal(pending.receipt, null);

  const abandoned = await context.reconciler.abandonCandidate({
    intentId: context.intent.id,
    kind: 'refund-observation',
    operatorIdHash: OPERATOR_HASH,
    expectedCaseHash: pending.refundCaseHash,
  });
  assert.notEqual(abandoned.caseHash, pending.refundCaseHash);
  assert.equal(context.store.readOne(
    'SELECT state FROM refunds WHERE refund_transaction_id = ?', [abandonedTransactionId],
  ).state, 'abandoned');
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);

  const replacementTransactionId = `0x${'77'.repeat(32)}`;
  const replacement = await context.reconciler.observeRefund({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    refundTransactionId: replacementTransactionId,
    expectedRefundCaseHash: abandoned.caseHash,
  });
  assert.equal(replacement.receipt, null);
  assert.deepEqual(context.store.readAll(`SELECT state, refund_transaction_id
    FROM refunds WHERE intent_id = ? ORDER BY rowid`, [context.intent.id])
    .map((row) => ({ state: row.state, transactionId: row.refund_transaction_id })), [
    { state: 'abandoned', transactionId: abandonedTransactionId },
    { state: 'pending', transactionId: replacementTransactionId },
  ]);
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?', [context.intent.id],
  ).revision, 3n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', [context.intent.id],
  ).count, 3n);
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.verifyEventChain(), true);
});

test('confirmed full refund releases the block and signs the exact revision', async (t) => {
  let conflictingReplay = false;
  const { context, refundCaseHash } = await setupRefundPending(t, (binding) => {
    const attestation = Object.freeze({
      schemaVersion: 1,
      domain: 'wallet-kernel.refund.v1',
      network: NETWORK,
      sellerOrigin: SELLER,
      intentHash: binding.intentHash,
      originalTransactionId: binding.originalTransactionId,
      refundTransactionId: binding.refundTransactionId,
      asset: ASSET,
      originalPayer: WALLET,
      originalPayee: PAY_TO,
      refundSource: REFUND_SOURCE,
      amountAtomic: '50000',
      issuedAt: '2026-07-31T12:09:00.000Z',
      expiresAt: '2026-07-31T12:15:00.000Z',
      signer: PAY_TO,
    });
    return Object.freeze({
      kind: 'refund_attested_and_confirmed',
      attestation,
      attestationHash: sha256(canonicalJson(attestation)),
      rpcTransferProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.refundTransactionId,
        blockHash: `0x${(conflictingReplay ? '7b' : '78').repeat(32)}`,
        blockNumber: '1234573',
        transactionStatus: 'success',
        confirmations: 3,
        transferLogIndex: 6,
        tokenContract: ASSET,
        from: REFUND_SOURCE,
        to: WALLET,
        valueAtomic: '50000',
        observedAt: NOW,
      }),
    });
  });
  const refundTransactionId = `0x${'79'.repeat(32)}`;
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    refundTransactionId,
    expectedRefundCaseHash: refundCaseHash,
  };
  const result = await context.reconciler.observeRefund(request);

  assert.equal(result.status, 'refunded');
  assert.equal(result.reasonCode, 'REFUND_CONFIRMED');
  assert.equal(result.receipt.revision, 4);
  assert.deepEqual({
    refund: context.store.readOne(
      'SELECT state FROM refunds WHERE refund_transaction_id = ?', [refundTransactionId],
    ).state,
    budget: context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [context.intent.id],
    ).state,
    resolution: context.store.readOne(
      'SELECT state FROM execution_resolutions WHERE intent_id = ?', [context.intent.id],
    ).state,
    outcome: context.store.readOne(
      'SELECT status FROM buyer_outcomes WHERE intent_id = ?', [context.intent.id],
    ).status,
  }, {
    refund: 'confirmed',
    budget: 'released',
    resolution: 'resolved',
    outcome: 'refunded',
  });
  assert.equal(result.receipt.receipt.refund.transactionId, refundTransactionId);
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, false);
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.events().some((event) => (
    event.entity_id === context.intent.id
      && event.event_type === 'execution_resolution.resolved'
  )), true);
  assert.equal(context.store.events().some((event) => (
    event.event_type === 'refund.confirmed'
      && JSON.parse(event.data_json).intentId === context.intent.id
  )), true);
  assert.equal(context.store.verifyEventChain(), true);

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.observeRefund(request);
  assert.equal(replay.status, result.status);
  assert.equal(replay.reasonCode, result.reasonCode);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);
  conflictingReplay = true;
  await assert.rejects(
    context.reconciler.observeRefund(request),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(context.store.events().length, eventCount);
});

test('refund evidence expires exactly at the post-resolver boundary', async (t) => {
  let context;
  const pending = await setupRefundPending(t, (binding) => {
    context.clock.value = '2026-07-31T12:15:00.000Z';
    const attestation = Object.freeze({
      schemaVersion: 1,
      domain: 'wallet-kernel.refund.v1',
      network: NETWORK,
      sellerOrigin: SELLER,
      intentHash: binding.intentHash,
      originalTransactionId: binding.originalTransactionId,
      refundTransactionId: binding.refundTransactionId,
      asset: ASSET,
      originalPayer: WALLET,
      originalPayee: PAY_TO,
      refundSource: REFUND_SOURCE,
      amountAtomic: '50000',
      issuedAt: '2026-07-31T12:09:00.000Z',
      expiresAt: '2026-07-31T12:15:00.000Z',
      signer: PAY_TO,
    });
    return Object.freeze({
      kind: 'refund_attested_and_confirmed',
      attestation,
      attestationHash: sha256(canonicalJson(attestation)),
      rpcTransferProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.refundTransactionId,
        blockHash: `0x${'7e'.repeat(32)}`,
        blockNumber: '1234574',
        transactionStatus: 'success',
        confirmations: 3,
        transferLogIndex: 7,
        tokenContract: ASSET,
        from: REFUND_SOURCE,
        to: WALLET,
        valueAtomic: '50000',
        observedAt: NOW,
      }),
    });
  });
  context = pending.context;
  const refundTransactionId = `0x${'7f'.repeat(32)}`;

  await assert.rejects(
    context.reconciler.observeRefund({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      refundTransactionId,
      expectedRefundCaseHash: pending.refundCaseHash,
    }),
    (error) => error?.code === 'RECONCILIATION_MISMATCH',
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM refunds WHERE refund_transaction_id = ?', [refundTransactionId],
  ).state, 'pending');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM reconciliations WHERE intent_id = ?', [context.intent.id],
  ).count, 2n);
});

test('verified successful execution resolves its case without inventing output', async (t) => {
  const responseHash = sha256(Buffer.from('{"ok":true}', 'utf8'));
  let conflictingReplay = false;
  const context = setupUnresolved(t, settledPaymentObservation, {
    observeExecution: (binding) => {
      const attestation = Object.freeze({
        schemaVersion: 1,
        domain: 'wallet-kernel.execution.v1',
        network: NETWORK,
        sellerOrigin: SELLER,
        intentHash: binding.intentHash,
        transactionId: binding.transactionId,
        outcome: 'succeeded',
        httpStatus: 200,
        responseHash,
        issuedAt: conflictingReplay
          ? '2026-07-31T12:08:00.000Z'
          : '2026-07-31T12:09:00.000Z',
        expiresAt: '2026-07-31T12:15:00.000Z',
        signer: PAY_TO,
      });
      return Object.freeze({
        kind: 'execution_attested',
        attestation,
        attestationHash: sha256(canonicalJson(attestation)),
      });
    },
  });
  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'7a'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });
  const request = {
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedExecutionCaseHash: payment.executionCaseHash,
  };
  const result = await context.reconciler.reconcileExecution(request);

  assert.equal(result.status, 'completed');
  assert.equal(result.reasonCode, 'EXECUTION_RECONCILED_SUCCEEDED');
  assert.equal(result.receipt.revision, 3);
  assert.equal(result.receipt.receipt.execution.responseHash, responseHash);
  assert.equal(context.store.readOne(
    'SELECT state FROM execution_resolutions WHERE intent_id = ?', [context.intent.id],
  ).state, 'resolved');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM refunds WHERE intent_id = ?', [context.intent.id],
  ).count, 0n);
  assert.equal(context.budgets.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, false);
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.events().some((event) => (
    event.entity_id === context.intent.id
      && event.event_type === 'execution_resolution.resolved'
  )), true);

  const eventCount = context.store.events().length;
  const replay = await context.reconciler.reconcileExecution(request);
  assert.equal(replay.status, result.status);
  assert.equal(replay.reasonCode, result.reasonCode);
  assert.equal(replay.receipt.receiptHash, result.receipt.receiptHash);
  assert.equal(context.store.events().length, eventCount);
  conflictingReplay = true;
  await assert.rejects(
    context.reconciler.reconcileExecution(request),
    (error) => error?.code === 'RECONCILIATION_CONFLICT',
  );
  assert.equal(context.store.events().length, eventCount);
});

test('execution evidence expires exactly at its boundary after a long-running resolver call', async (t) => {
  let context;
  context = setupUnresolved(t, settledPaymentObservation, {
    observeExecution: (binding) => {
      context.clock.value = '2026-07-31T12:15:00.000Z';
      return failedExecutionObservation(binding);
    },
  });
  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'7c'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });

  await assert.rejects(
    context.reconciler.reconcileExecution({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedExecutionCaseHash: payment.executionCaseHash,
    }),
    (error) => error?.code === 'RECONCILIATION_MISMATCH',
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM execution_outcomes WHERE intent_id = ?', [context.intent.id],
  ).state, 'unknown');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM reconciliations WHERE intent_id = ?', [context.intent.id],
  ).count, 1n);
});

test('resolver clock regression fails closed before reconciliation mutation', async (t) => {
  let context;
  context = setupUnresolved(t, settledPaymentObservation, {
    observeExecution: (binding) => {
      context.clock.value = '2026-07-31T12:09:59.999Z';
      return failedExecutionObservation(binding);
    },
  });
  const payment = await context.reconciler.reconcilePayment({
    intentId: context.intent.id,
    operatorIdHash: OPERATOR_HASH,
    paymentTransactionId: `0x${'7d'.repeat(32)}`,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, context.intent.id),
  });

  await assert.rejects(
    context.reconciler.reconcileExecution({
      intentId: context.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedExecutionCaseHash: payment.executionCaseHash,
    }),
    (error) => error?.code === 'RECONCILIATION_TIME',
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM execution_outcomes WHERE intent_id = ?', [context.intent.id],
  ).state, 'unknown');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM reconciliations WHERE intent_id = ?', [context.intent.id],
  ).count, 1n);
});

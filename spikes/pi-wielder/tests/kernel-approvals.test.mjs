import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { createApprovalQueue } from '../src/kernel/approval-queue.mjs';
import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { evaluateSpendPolicy } from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:00.000Z';
const APPROVED_AT = '2026-07-31T12:01:00.000Z';
const EXPIRES_AT = '2026-07-31T12:05:00.000Z';
const AFTER_EXPIRY = '2026-07-31T12:05:00.001Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const OPERATOR_HASH = `sha256:${'aa'.repeat(32)}`;
const ENROLLMENT_OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const ROUTE_METADATA = Object.freeze({
  'paid-infer': Object.freeze({
    description: 'offline fixture',
    mimeType: 'application/json',
  }),
});
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function policyDocument(overrides = {}) {
  const document = structuredClone(BASE_POLICY);
  document.challengeMaxAgeMs = 600_000;
  document.approvalTtlMs = 300_000;
  document.maxPendingApprovals = 20;
  Object.assign(document, overrides);
  return document;
}

function paymentRequired(amountAtomic = '250000') {
  return {
    x402Version: 2,
    error: 'seller prose is excluded from the durable projection',
    resource: {
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount: amountAtomic,
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
  };
}

function sequenceIds() {
  const counts = new Map();
  const calls = [];
  const factory = (kind) => {
    calls.push(kind);
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
  factory.calls = calls;
  return factory;
}

function fileAuthority(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-approvals-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return Object.freeze({
    databasePath: path.join(directory, 'kernel.sqlite'),
    pathTrust: Object.freeze({
      mode: 'deterministic',
      trustedAncestor: directory,
      kernelUid: process.getuid(),
      agentUid: process.getuid(),
    }),
  });
}

function setup(t, {
  authority = null,
  clock = { value: NOW },
  ids = sequenceIds(),
  policy = policyDocument(),
} = {}) {
  const store = openKernelStore(authority ? {
    filePath: authority.databasePath,
    pathTrust: authority.pathTrust,
    now: () => clock.value,
  } : {
    filePath: ':memory:',
    allowMemory: true,
    now: () => clock.value,
  });
  t.after(() => {
    try { store.close(); } catch {}
  });
  const policies = createPolicyRepository(store);
  const activePolicy = policies.apply(policy, NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store, now: () => clock.value });
  enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: ENROLLMENT_OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const intents = createIntentRepository({
    store,
    idFactory: ids,
    now: () => clock.value,
    routeMetadata: ROUTE_METADATA,
  });
  const session = intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  const approvals = createApprovalQueue({ store, idFactory: ids, now: () => clock.value });
  return {
    activePolicy,
    approvals,
    clock,
    ids,
    intents,
    policies,
    session,
    store,
  };
}

function createApprovalRequiredIntent(context, label, {
  amountAtomic = '250000',
  challengeReceivedAt = NOW,
  decidedAt = NOW,
  pendingApprovalCount,
  requestApproval = true,
} = {}) {
  context.clock.value = challengeReceivedAt;
  const requestUrl = `${SELLER}/paid/infer`;
  const request = {
    routeId: 'paid-infer',
    method: 'POST',
    requestUrl,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from(canonicalJson({ label }), 'utf8'),
    purposeLabel: 'skill.invoke',
    correlationId: `pi-call-${label}`,
  };
  const captured = context.intents.captureIntent({
    sessionId: context.session.id,
    ...request,
  });
  const challenge = paymentRequired(amountAtomic);
  context.intents.attachChallenge({
    intentId: captured.id,
    paymentRequired: challenge,
    challengeReceivedAt,
  });
  const evaluation = evaluateSpendPolicy({
    policy: context.activePolicy.policy,
    policyVersion: { id: context.activePolicy.id, hash: context.activePolicy.hash },
    intent: {
      id: captured.id,
      method: request.method,
      requestUrl,
      sellerOrigin: SELLER,
      resourcePath: '/paid/infer',
      walletAddress: WALLET,
    },
    wallet: {
      provider: 'deterministic',
      walletId: 'buyer-a',
      address: WALLET,
      network: NETWORK,
    },
    paymentRequired: challenge,
    challengeReceivedAtMs: Date.parse(challengeReceivedAt),
    nowMs: Date.parse(decidedAt),
    budgetSnapshot: {
      sellerSessionExposureAtomic: '0',
      sessionExposureAtomic: '0',
      rolling24hExposureAtomic: '0',
      pendingApprovalCount: pendingApprovalCount ?? Number(context.store.readOne(
        "SELECT COUNT(*) AS count FROM approvals WHERE decision = 'pending'",
      ).count),
    },
  });
  assert.equal(evaluation.decision, 'approval_required');
  context.clock.value = decidedAt;
  context.store.transaction((token) => context.policies.recordDecisionInTransaction(token, {
    intentId: captured.id,
    policyVersionId: context.activePolicy.id,
    evaluation,
    decidedAt,
  }));
  const requestBinding = Object.freeze({
    intentId: captured.id,
    intentHash: captured.intentHash,
    challengeHash: evaluation.challengeHash,
    quoteId: evaluation.quoteId,
    amountCeilingAtomic: amountAtomic,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
    acceptedIndex: evaluation.acceptedIndex,
  });
  let approval = null;
  if (requestApproval) {
    approval = context.approvals.request(requestBinding);
    context.intents.transition({
      intentId: captured.id,
      expectedState: 'challenged',
      nextState: 'approval_pending',
      reasonCode: 'HUMAN_APPROVAL_REQUIRED',
    });
  }
  return Object.freeze({ approval, captured, evaluation, requestBinding });
}

function approvalBinding(record) {
  return Object.freeze({
    intentId: record.intentId,
    intentHash: record.intentHash,
    challengeHash: record.challengeHash,
    quoteId: record.quoteId,
    amountCeilingAtomic: record.amountCeilingAtomic,
    walletAddress: record.walletAddress,
    policyVersionId: record.policyVersionId,
    acceptedIndex: record.acceptedIndex,
    expiresAt: record.expiresAt,
  });
}

function approve(context, approval) {
  context.clock.value = APPROVED_AT;
  return context.approvals.approve({
    approvalId: approval.approvalId,
    expectedIntentHash: approval.intentHash,
    operatorIdHash: OPERATOR_HASH,
  });
}

function insertReservation(context, token, intentId) {
  return context.store.within(token, ({ db }) => db.prepare(`INSERT INTO budget_reservations
    (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
     released_atomic, unresolved_atomic, state, updated_at)
    VALUES (?, ?, ?, '250000', '0', '0', '0', 'reserved', ?)`)
    .run(intentId, context.session.id, SELLER, context.clock.value));
}

function assertKernelError(operation, expectedCode) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

function authoritySnapshot(context) {
  return {
    approvals: context.store.readAll('SELECT * FROM approvals ORDER BY id'),
    events: context.store.events(),
    reservations: context.store.readAll('SELECT * FROM budget_reservations ORDER BY intent_id'),
  };
}

test('approval binds every authority field, stores only an operator hash, and survives reopen', (t) => {
  const authority = fileAuthority(t);
  const clock = { value: NOW };
  const first = setup(t, { authority, clock });
  const { approval } = createApprovalRequiredIntent(first, 'durable');

  assert.deepEqual(approvalBinding(approval), {
    intentId: approval.intentId,
    intentHash: approval.intentHash,
    challengeHash: approval.challengeHash,
    quoteId: approval.quoteId,
    amountCeilingAtomic: '250000',
    walletAddress: WALLET,
    policyVersionId: first.activePolicy.id,
    acceptedIndex: 0,
    expiresAt: EXPIRES_AT,
  });
  assert.equal(Object.isFrozen(approval), true);
  assert.equal(approval.decision, 'pending');

  const approved = approve(first, approval);
  assert.equal(approved.operatorIdHash, OPERATOR_HASH);
  assert.equal(approved.decidedAt, APPROVED_AT);
  assert.equal(approved.reasonCode, null);
  const raw = first.store.readOne('SELECT * FROM approvals WHERE id = ?', [approval.approvalId]);
  assert.equal(raw.operator_id_hash, OPERATOR_HASH);
  assert.equal(Object.values(raw).filter((value) => typeof value === 'string')
    .some((value) => value.includes('RAW_OPERATOR_SENTINEL')), false);
  first.store.close();

  const reopenedStore = openKernelStore({
    filePath: authority.databasePath,
    pathTrust: authority.pathTrust,
    now: () => clock.value,
  });
  t.after(() => reopenedStore.close());
  const reopened = createApprovalQueue({
    store: reopenedStore,
    idFactory: sequenceIds(),
    now: () => clock.value,
  });
  assert.deepEqual(reopened.get(approval.approvalId), approved);
  assert.equal(reopenedStore.verifyEventChain(), true);
});

test('approval rows require one exact authority-bound append-only lifecycle', (t) => {
  const missingTransitionContext = setup(t);
  const missingTransition = createApprovalRequiredIntent(
    missingTransitionContext,
    'missing-approved-event',
  ).approval;
  missingTransitionContext.store.transaction((token) => missingTransitionContext.store.within(
    token,
    ({ db }) => db.prepare(`UPDATE approvals
      SET decision = 'approved', operator_id_hash = ?, decided_at = ?
      WHERE id = ?`).run(
      OPERATOR_HASH,
      APPROVED_AT,
      missingTransition.approvalId,
    ),
  ));
  assertKernelError(
    () => missingTransitionContext.approvals.get(missingTransition.approvalId),
    'APPROVAL_CORRUPTION',
  );

  const duplicateContext = setup(t);
  const duplicate = createApprovalRequiredIntent(duplicateContext, 'duplicate-approved-event')
    .approval;
  approve(duplicateContext, duplicate);
  const approvedEvent = duplicateContext.store.events().find(
    (event) => event.entity_id === duplicate.approvalId
      && event.event_type === 'approval.approved',
  );
  duplicateContext.store.transaction((token) => duplicateContext.store.within(
    token,
    ({ appendEvent }) => appendEvent({
      entityType: 'approval',
      entityId: duplicate.approvalId,
      eventType: 'approval.approved',
      data: JSON.parse(approvedEvent.data_json),
    }),
  ));
  assertKernelError(
    () => duplicateContext.approvals.get(duplicate.approvalId),
    'APPROVAL_CORRUPTION',
  );

  const missingRequestContext = setup(t);
  const missingRequest = createApprovalRequiredIntent(missingRequestContext, 'missing-request-event')
    .approval;
  missingRequestContext.store.transaction((token) => missingRequestContext.store.within(
    token,
    ({ db }) => db.prepare(`DELETE FROM events
      WHERE entity_type = 'approval' AND entity_id = ?
        AND event_type = 'approval.requested'`).run(missingRequest.approvalId),
  ));
  assertKernelError(
    () => missingRequestContext.approvals.get(missingRequest.approvalId),
    'APPROVAL_CORRUPTION',
  );

  const outOfOrderContext = setup(t);
  const outOfOrder = createApprovalRequiredIntent(outOfOrderContext, 'out-of-order-events').approval;
  approve(outOfOrderContext, outOfOrder);
  outOfOrderContext.store.transaction((token) => outOfOrderContext.store.within(
    token,
    ({ db }) => db.prepare(`UPDATE events SET sequence = -1
      WHERE entity_type = 'approval' AND entity_id = ?
        AND event_type = 'approval.approved'`).run(outOfOrder.approvalId),
  ));
  assertKernelError(
    () => outOfOrderContext.approvals.get(outOfOrder.approvalId),
    'APPROVAL_CORRUPTION',
  );

  const mismatchedContext = setup(t);
  const mismatched = createApprovalRequiredIntent(mismatchedContext, 'mismatched-event').approval;
  mismatchedContext.clock.value = APPROVED_AT;
  mismatchedContext.store.transaction((token) => mismatchedContext.store.within(
    token,
    ({ db, appendEvent }) => {
      db.prepare(`UPDATE approvals
        SET decision = 'approved', operator_id_hash = ?, decided_at = ?
        WHERE id = ?`).run(OPERATOR_HASH, APPROVED_AT, mismatched.approvalId);
      appendEvent({
        entityType: 'approval',
        entityId: mismatched.approvalId,
        eventType: 'approval.approved',
        data: { message: 'approved', intentId: mismatched.intentId },
      });
    },
  ));
  assertKernelError(
    () => mismatchedContext.approvals.get(mismatched.approvalId),
    'APPROVAL_CORRUPTION',
  );
});

test('approval clocks never regress from the requested event or an approved predecessor', (t) => {
  const requestAt = (context, label, requestedAt) => {
    const candidate = createApprovalRequiredIntent(context, label, { requestApproval: false });
    context.clock.value = requestedAt;
    return context.approvals.request(candidate.requestBinding);
  };
  const requestedAt = '2026-07-31T12:00:30.000Z';
  const regressedAt = '2026-07-31T12:00:15.000Z';

  const approveContext = setup(t);
  const approvable = requestAt(approveContext, 'approve-request-clock', requestedAt);
  approveContext.clock.value = regressedAt;
  const beforeApprove = authoritySnapshot(approveContext);
  assertKernelError(() => approveContext.approvals.approve({
    approvalId: approvable.approvalId,
    expectedIntentHash: approvable.intentHash,
    operatorIdHash: OPERATOR_HASH,
  }), 'APPROVAL_TIME');
  assert.deepEqual(authoritySnapshot(approveContext), beforeApprove);

  const denyContext = setup(t);
  const deniable = requestAt(denyContext, 'deny-request-clock', requestedAt);
  denyContext.clock.value = regressedAt;
  const beforeDeny = authoritySnapshot(denyContext);
  assertKernelError(() => denyContext.store.transaction(
    (token) => denyContext.approvals.denyForIntentInTransaction(token, {
      approvalId: deniable.approvalId,
      intentId: deniable.intentId,
      expectedIntentHash: deniable.intentHash,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    }),
  ), 'APPROVAL_TIME');
  assert.deepEqual(authoritySnapshot(denyContext), beforeDeny);

  const pendingCancelContext = setup(t);
  const pendingCancellable = requestAt(
    pendingCancelContext,
    'cancel-request-clock',
    requestedAt,
  );
  pendingCancelContext.clock.value = regressedAt;
  const beforePendingCancel = authoritySnapshot(pendingCancelContext);
  assertKernelError(() => pendingCancelContext.store.transaction(
    (token) => pendingCancelContext.approvals.cancelForIntentInTransaction(token, {
      intentId: pendingCancellable.intentId,
      reasonCode: 'SESSION_CLOSED',
    }),
  ), 'APPROVAL_TIME');
  assert.deepEqual(authoritySnapshot(pendingCancelContext), beforePendingCancel);

  const approvedCancelContext = setup(t);
  const approvedCancellable = createApprovalRequiredIntent(
    approvedCancelContext,
    'cancel-approved-clock',
  ).approval;
  approve(approvedCancelContext, approvedCancellable);
  approvedCancelContext.clock.value = '2026-07-31T12:00:30.000Z';
  const beforeApprovedCancel = authoritySnapshot(approvedCancelContext);
  assertKernelError(() => approvedCancelContext.store.transaction(
    (token) => approvedCancelContext.approvals.cancelForIntentInTransaction(token, {
      intentId: approvedCancellable.intentId,
      reasonCode: 'POLICY_SUPERSEDED',
    }),
  ), 'APPROVAL_TIME');
  assert.deepEqual(authoritySnapshot(approvedCancelContext), beforeApprovedCancel);
  assert.equal(
    approvedCancelContext.approvals.get(approvedCancellable.approvalId).decidedAt,
    APPROVED_AT,
  );

  const consumeContext = setup(t);
  const consumable = createApprovalRequiredIntent(consumeContext, 'consume-approved-clock')
    .approval;
  const approved = approve(consumeContext, consumable);
  consumeContext.clock.value = '2026-07-31T12:00:30.000Z';
  const beforeConsume = authoritySnapshot(consumeContext);
  assertKernelError(() => consumeContext.store.transaction(
    (token) => consumeContext.approvals.consumeForInTransaction(
      token,
      approvalBinding(approved),
    ),
  ), 'APPROVAL_TIME');
  assert.deepEqual(authoritySnapshot(consumeContext), beforeConsume);
});

test('consumption and its caller-owned reservation commit or roll back together exactly once', (t) => {
  const context = setup(t);
  const { approval } = createApprovalRequiredIntent(context, 'consume');
  const approved = approve(context, approval);
  const binding = approvalBinding(approved);
  const before = authoritySnapshot(context);

  assert.throws(() => context.store.transaction((token) => {
    assert.equal(context.approvals.consumeForInTransaction(token, binding).decision, 'consumed');
    insertReservation(context, token, approval.intentId);
    throw new Error('aggregate fault');
  }), /aggregate fault/);
  assert.deepEqual(authoritySnapshot(context), before);

  const consumed = context.store.transaction((token) => {
    const result = context.approvals.consumeForInTransaction(token, binding);
    insertReservation(context, token, approval.intentId);
    return result;
  });
  assert.equal(consumed.decision, 'consumed');
  assert.equal(consumed.consumedAt, APPROVED_AT);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [approval.intentId],
  ).state, 'reserved');

  const after = authoritySnapshot(context);
  assert.equal(context.store.transaction(
    (token) => context.approvals.consumeForInTransaction(token, binding),
  ), null);
  assert.deepEqual(authoritySnapshot(context), after);
  assert.equal(context.store.events().filter(
    (event) => event.event_type === 'approval.consumed',
  ).length, 1);
});

test('every approval binding substitution fails atomically', (t) => {
  const context = setup(t);
  const { approval } = createApprovalRequiredIntent(context, 'substitution');
  const approved = approve(context, approval);
  const binding = approvalBinding(approved);
  const substitutions = {
    intentId: 'intent-substituted',
    intentHash: `sha256:${'01'.repeat(32)}`,
    challengeHash: `sha256:${'02'.repeat(32)}`,
    quoteId: `sha256:${'03'.repeat(32)}`,
    amountCeilingAtomic: '250001',
    walletAddress: '0x3000000000000000000000000000000000000000',
    policyVersionId: 'policy-substituted',
    acceptedIndex: 1,
    expiresAt: '2026-07-31T12:05:00.001Z',
  };

  for (const [field, value] of Object.entries(substitutions)) {
    const before = authoritySnapshot(context);
    assertKernelError(() => context.store.transaction(
      (token) => context.approvals.consumeForInTransaction(token, {
        ...binding,
        [field]: value,
      }),
    ), 'APPROVAL_BINDING_MISMATCH');
    assert.deepEqual(authoritySnapshot(context), before, field);
  }
});

test('pending, denied, expired, consumed, and unknown approvals never authorize', (t) => {
  const pendingContext = setup(t);
  const { approval: pending } = createApprovalRequiredIntent(pendingContext, 'pending');
  const pendingBefore = authoritySnapshot(pendingContext);
  assert.equal(pendingContext.store.transaction(
    (token) => pendingContext.approvals.consumeForInTransaction(
      token,
      approvalBinding(pending),
    ),
  ), null);
  assert.deepEqual(authoritySnapshot(pendingContext), pendingBefore);

  const deniedContext = setup(t);
  const { approval: denied } = createApprovalRequiredIntent(deniedContext, 'denied');
  deniedContext.clock.value = APPROVED_AT;
  deniedContext.store.transaction((token) => deniedContext.approvals.denyForIntentInTransaction(
    token,
    {
      approvalId: denied.approvalId,
      intentId: denied.intentId,
      expectedIntentHash: denied.intentHash,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    },
  ));
  assert.equal(deniedContext.store.transaction(
    (token) => deniedContext.approvals.consumeForInTransaction(
      token,
      approvalBinding(denied),
    ),
  ), null);

  const consumedContext = setup(t);
  const { approval: consumedApproval } = createApprovalRequiredIntent(consumedContext, 'consumed');
  const consumedBinding = approvalBinding(approve(consumedContext, consumedApproval));
  consumedContext.store.transaction(
    (token) => consumedContext.approvals.consumeForInTransaction(token, consumedBinding),
  );
  assert.equal(consumedContext.store.transaction(
    (token) => consumedContext.approvals.consumeForInTransaction(token, consumedBinding),
  ), null);

  const expiredContext = setup(t);
  const { approval: expiring } = createApprovalRequiredIntent(expiredContext, 'expired');
  approve(expiredContext, expiring);
  expiredContext.clock.value = AFTER_EXPIRY;
  assert.equal(expiredContext.store.transaction(
    (token) => expiredContext.approvals.consumeForInTransaction(
      token,
      approvalBinding(expiring),
    ),
  ), null);
  assert.equal(expiredContext.approvals.get(expiring.approvalId).decision, 'expired');

  const unknown = { ...approvalBinding(pending), intentId: 'intent-unknown' };
  assertKernelError(() => pendingContext.store.transaction(
    (token) => pendingContext.approvals.consumeForInTransaction(token, unknown),
  ), 'APPROVAL_BINDING_MISMATCH');
  assert.equal(pendingContext.approvals.get('approval-unknown'), null);
});

test('expiry during consumption stays inside the caller terminal-outcome aggregate', (t) => {
  const context = setup(t);
  const { approval } = createApprovalRequiredIntent(context, 'expiry-aggregate');
  approve(context, approval);
  const binding = approvalBinding(approval);
  context.clock.value = EXPIRES_AT;
  const before = authoritySnapshot(context);

  assert.throws(() => context.store.transaction((token) => {
    assert.equal(context.approvals.consumeForInTransaction(token, binding), null);
    context.intents.transitionInTransaction(token, {
      intentId: approval.intentId,
      expectedState: 'approval_pending',
      nextState: 'terminal',
      reasonCode: 'APPROVAL_EXPIRED',
    });
    context.store.within(token, ({ db }) => db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'payment_denied', 'APPROVAL_EXPIRED', 1, ?)`)
      .run(approval.intentId, context.clock.value));
    throw new Error('aggregate fault');
  }), /aggregate fault/);
  assert.deepEqual(authoritySnapshot(context), before);
  assert.equal(context.approvals.get(approval.approvalId).decision, 'approved');

  context.store.transaction((token) => {
    assert.equal(context.approvals.consumeForInTransaction(token, binding), null);
    context.intents.transitionInTransaction(token, {
      intentId: approval.intentId,
      expectedState: 'approval_pending',
      nextState: 'terminal',
      reasonCode: 'APPROVAL_EXPIRED',
    });
    context.store.within(token, ({ db }) => db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'payment_denied', 'APPROVAL_EXPIRED', 1, ?)`)
      .run(approval.intentId, context.clock.value));
  });
  assert.equal(context.approvals.get(approval.approvalId).decision, 'expired');
  assert.equal(context.store.readOne(
    'SELECT state FROM spend_intents WHERE id = ?', [approval.intentId],
  ).state, 'terminal');
  assert.equal(context.store.readOne(
    'SELECT status FROM buyer_outcomes WHERE intent_id = ?', [approval.intentId],
  ).status, 'payment_denied');
});

test('capacity is atomic and denial or expiry releases exactly one pending slot', (t) => {
  const context = setup(t, { policy: policyDocument({ maxPendingApprovals: 2 }) });
  const first = createApprovalRequiredIntent(context, 'capacity-1').approval;
  const second = createApprovalRequiredIntent(context, 'capacity-2').approval;
  const third = createApprovalRequiredIntent(context, 'capacity-3', {
    pendingApprovalCount: 0,
    requestApproval: false,
  });
  const before = authoritySnapshot(context);
  assertKernelError(() => context.approvals.request(third.requestBinding), 'APPROVAL_CAPACITY');
  assert.deepEqual(authoritySnapshot(context), before);

  context.clock.value = APPROVED_AT;
  context.store.transaction((token) => context.approvals.denyForIntentInTransaction(token, {
    approvalId: first.approvalId,
    intentId: first.intentId,
    expectedIntentHash: first.intentHash,
    operatorIdHash: OPERATOR_HASH,
    reasonCode: 'OPERATOR_DENIED',
  }));
  assert.equal(context.approvals.request(third.requestBinding).decision, 'pending');
  assert.equal(context.store.readOne(
    "SELECT COUNT(*) AS count FROM approvals WHERE decision = 'pending'",
  ).count, 2n);

  const expiryContext = setup(t, { policy: policyDocument({ maxPendingApprovals: 1 }) });
  const due = createApprovalRequiredIntent(expiryContext, 'capacity-expire').approval;
  const blocked = createApprovalRequiredIntent(expiryContext, 'capacity-blocked', {
    pendingApprovalCount: 0,
    requestApproval: false,
  });
  assertKernelError(() => expiryContext.approvals.request(blocked.requestBinding),
    'APPROVAL_CAPACITY');
  expiryContext.clock.value = EXPIRES_AT;
  expiryContext.store.transaction((token) => expiryContext.approvals.expireForIntentInTransaction(
    token,
    {
      approvalId: due.approvalId,
      intentId: due.intentId,
      expectedIntentHash: due.intentHash,
      at: EXPIRES_AT,
    },
  ));
  const replacement = createApprovalRequiredIntent(expiryContext, 'capacity-replacement', {
    challengeReceivedAt: AFTER_EXPIRY,
    decidedAt: AFTER_EXPIRY,
    pendingApprovalCount: 0,
    requestApproval: false,
  });
  assert.equal(expiryContext.approvals.request(replacement.requestBinding).decision, 'pending');
});

test('retry and due discovery are bounded, stable, read-only, and agent-ID independent', (t) => {
  const context = setup(t);
  const first = createApprovalRequiredIntent(context, 'discover-1').approval;
  context.clock.value = '2026-07-31T12:00:01.000Z';
  const second = createApprovalRequiredIntent(context, 'discover-2', {
    challengeReceivedAt: context.clock.value,
    decidedAt: context.clock.value,
  }).approval;

  assert.deepEqual(
    context.approvals.findRetryable({
      sessionId: context.session.id,
      intentHash: first.intentHash,
    }),
    first,
  );
  assert.equal(context.approvals.findRetryable({
    sessionId: 'session-other',
    intentHash: first.intentHash,
  }), null);
  assert.equal(context.approvals.findRetryable({
    sessionId: context.session.id,
    intentHash: `sha256:${'99'.repeat(32)}`,
  }), null);

  approve(context, first);
  assert.equal(context.approvals.findRetryable({
    sessionId: context.session.id,
    intentHash: first.intentHash,
  }).decision, 'approved');
  const before = authoritySnapshot(context);
  assert.deepEqual(context.approvals.listDue({ at: EXPIRES_AT, limit: 10 }), [{
    approvalId: first.approvalId,
    intentId: first.intentId,
    intentHash: first.intentHash,
  }]);
  assert.deepEqual(authoritySnapshot(context), before);
  assert.deepEqual(context.approvals.listDue({
    at: '2026-07-31T12:05:01.000Z',
    limit: 1,
  }), [{
    approvalId: first.approvalId,
    intentId: first.intentId,
    intentHash: first.intentHash,
  }]);
  assert.equal(second.expiresAt, '2026-07-31T12:05:01.000Z');
});

test('terminal non-matchable approved history is never retryable or due authority', (t) => {
  const context = setup(t);
  const { approval, captured } = createApprovalRequiredIntent(context, 'approved-history');
  const approved = approve(context, approval);
  context.intents.transition({
    intentId: captured.id,
    expectedState: 'approval_pending',
    nextState: 'terminal',
    reasonCode: 'UPSTREAM_TRANSPORT_FAILURE',
  });
  const before = authoritySnapshot(context);

  assert.deepEqual(context.approvals.get(approved.approvalId), approved);
  assert.deepEqual(context.approvals.list({ state: 'approved', limit: 10 }), [approved]);
  assert.equal(context.approvals.findRetryable({
    sessionId: context.session.id,
    intentHash: approved.intentHash,
  }), null);
  assert.deepEqual(context.approvals.listDue({ at: AFTER_EXPIRY, limit: 10 }), []);
  assert.deepEqual(authoritySnapshot(context), before);
});

test('request derives immutable expiry, exact replay is idempotent, and conflicts do not mutate', (t) => {
  const ids = sequenceIds();
  const context = setup(t, { ids });
  const candidate = createApprovalRequiredIntent(context, 'idempotent', {
    requestApproval: false,
  });
  const first = context.approvals.request(candidate.requestBinding);
  const events = context.store.events();
  const calls = [...ids.calls];
  context.clock.value = APPROVED_AT;
  assert.deepEqual(context.approvals.request(candidate.requestBinding), first);
  assert.deepEqual(context.store.events(), events);
  assert.deepEqual(ids.calls, calls);
  assert.equal(first.expiresAt, EXPIRES_AT);

  assertKernelError(() => context.approvals.request({
    ...candidate.requestBinding,
    expiresAt: '2099-01-01T00:00:00.000Z',
  }), 'APPROVAL_SCHEMA');
  for (const [field, value] of [
    ['intentHash', `sha256:${'44'.repeat(32)}`],
    ['challengeHash', `sha256:${'55'.repeat(32)}`],
    ['quoteId', `sha256:${'66'.repeat(32)}`],
    ['amountCeilingAtomic', '250001'],
    ['walletAddress', '0x3000000000000000000000000000000000000000'],
    ['policyVersionId', 'policy-other'],
    ['acceptedIndex', 1],
  ]) {
    const before = authoritySnapshot(context);
    assertKernelError(() => context.approvals.request({
      ...candidate.requestBinding,
      [field]: value,
    }), 'APPROVAL_BINDING_MISMATCH');
    assert.deepEqual(authoritySnapshot(context), before, field);
  }
});

test('challenge lifetime can be the tighter immutable approval deadline', (t) => {
  const context = setup(t, {
    policy: policyDocument({ challengeMaxAgeMs: 60_000, approvalTtlMs: 300_000 }),
  });
  const candidate = createApprovalRequiredIntent(context, 'challenge-deadline', {
    requestApproval: false,
  });
  context.clock.value = '2026-07-31T12:00:30.000Z';

  const approval = context.approvals.request(candidate.requestBinding);

  assert.equal(approval.expiresAt, '2026-07-31T12:01:00.000Z');
});

test('requestInTransaction shares its caller aggregate and rolls creation back on fault', (t) => {
  const context = setup(t);
  const candidate = createApprovalRequiredIntent(context, 'scoped-request', {
    requestApproval: false,
  });
  const before = authoritySnapshot(context);

  assert.throws(() => context.store.transaction((token) => {
    context.approvals.requestInTransaction(token, candidate.requestBinding);
    throw new Error('request aggregate fault');
  }), /request aggregate fault/);
  assert.deepEqual(authoritySnapshot(context), before);

  const created = context.store.transaction(
    (token) => context.approvals.requestInTransaction(token, candidate.requestBinding),
  );
  assert.equal(created.decision, 'pending');
  assert.equal(context.store.events().filter(
    (event) => event.event_type === 'approval.requested',
  ).length, 1);
});

test('request rejects a persisted approval decision retargeted to an incompatible offer', (t) => {
  const context = setup(t);
  const candidate = createApprovalRequiredIntent(context, 'retargeted-offer', {
    requestApproval: false,
  });
  const row = context.store.readOne(
    'SELECT challenge_projection_json FROM spend_intents WHERE id = ?',
    [candidate.captured.id],
  );
  const projection = JSON.parse(row.challenge_projection_json);
  projection.accepts.unshift({
    ...projection.accepts[0],
    scheme: 'subscription',
  });
  const projectionJson = canonicalJson(projection);
  const challengeHash = sha256(projectionJson);
  const quoteId = sha256(canonicalJson({ challengeHash, acceptedIndex: 0 }));
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`UPDATE spend_intents
      SET challenge_projection_json = ?, challenge_hash = ? WHERE id = ?`).run(
      projectionJson,
      challengeHash,
      candidate.captured.id,
    );
    db.prepare(`UPDATE policy_decisions
      SET challenge_hash = ?, accepted_index = 0, quote_id = ? WHERE intent_id = ?`).run(
      challengeHash,
      quoteId,
      candidate.captured.id,
    );
  }));

  const before = authoritySnapshot(context);
  assertKernelError(() => context.approvals.request({
    ...candidate.requestBinding,
    challengeHash,
    quoteId,
    acceptedIndex: 0,
  }), 'APPROVAL_CORRUPTION');
  assert.deepEqual(authoritySnapshot(context), before);
});

test('operator transitions match the displayed hash inside their transaction', (t) => {
  const approveContext = setup(t);
  const { approval } = createApprovalRequiredIntent(approveContext, 'approve-confirmation');
  approveContext.clock.value = APPROVED_AT;
  const before = authoritySnapshot(approveContext);
  assertKernelError(() => approveContext.approvals.approve({
    approvalId: approval.approvalId,
    expectedIntentHash: `sha256:${'77'.repeat(32)}`,
    operatorIdHash: OPERATOR_HASH,
  }), 'APPROVAL_BINDING_MISMATCH');
  assert.deepEqual(authoritySnapshot(approveContext), before);
  assertKernelError(() => approveContext.approvals.approve({
    approvalId: approval.approvalId,
    expectedIntentHash: approval.intentHash,
    operatorIdHash: OPERATOR_HASH,
    operatorIdentity: 'RAW_OPERATOR_SENTINEL',
  }), 'APPROVAL_DECISION_SCHEMA');
  assert.equal(approveContext.store.events().some(
    (event) => event.data_json.includes('RAW_OPERATOR_SENTINEL'),
  ), false);
  assert.equal(approveContext.approvals.approve({
    approvalId: approval.approvalId,
    expectedIntentHash: approval.intentHash,
    operatorIdHash: OPERATOR_HASH,
  }).decision, 'approved');
  const after = authoritySnapshot(approveContext);
  assertKernelError(() => approveContext.approvals.approve({
    approvalId: approval.approvalId,
    expectedIntentHash: approval.intentHash,
    operatorIdHash: OPERATOR_HASH,
  }), 'APPROVAL_STATE_CONFLICT');
  assert.deepEqual(authoritySnapshot(approveContext), after);

  const denyContext = setup(t);
  const { approval: denied } = createApprovalRequiredIntent(denyContext, 'deny-confirmation');
  denyContext.clock.value = APPROVED_AT;
  assertKernelError(() => denyContext.store.transaction(
    (token) => denyContext.approvals.denyForIntentInTransaction(token, {
      approvalId: denied.approvalId,
      intentId: denied.intentId,
      expectedIntentHash: `sha256:${'88'.repeat(32)}`,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    }),
  ), 'APPROVAL_BINDING_MISMATCH');
  assert.equal(denyContext.store.transaction(
    (token) => denyContext.approvals.denyForIntentInTransaction(token, {
      approvalId: denied.approvalId,
      intentId: denied.intentId,
      expectedIntentHash: denied.intentHash,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    }),
  ).decision, 'denied');
});

test('denial, expiry, and cancellation are aggregate-scoped and never alter consumed authority', (t) => {
  const context = setup(t);
  const denied = createApprovalRequiredIntent(context, 'scope-deny').approval;
  assert.equal(Object.hasOwn(context.approvals, 'deny'), false);
  assert.equal(Object.hasOwn(context.approvals, 'expire'), false);
  assert.equal(Object.hasOwn(context.approvals, 'cancel'), false);
  context.clock.value = APPROVED_AT;
  const before = authoritySnapshot(context);
  assert.throws(() => context.store.transaction((token) => {
    context.approvals.denyForIntentInTransaction(token, {
      approvalId: denied.approvalId,
      intentId: denied.intentId,
      expectedIntentHash: denied.intentHash,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    });
    throw new Error('denial fault');
  }), /denial fault/);
  assert.deepEqual(authoritySnapshot(context), before);

  const consumedApproval = createApprovalRequiredIntent(context, 'scope-consumed').approval;
  const consumedBinding = approvalBinding(approve(context, consumedApproval));
  context.store.transaction(
    (token) => context.approvals.consumeForInTransaction(token, consumedBinding),
  );
  const consumedBefore = authoritySnapshot(context);
  assert.equal(context.store.transaction(
    (token) => context.approvals.cancelForIntentInTransaction(token, {
      intentId: consumedApproval.intentId,
      reasonCode: 'SESSION_CLOSED',
    }),
  ), null);
  assert.deepEqual(authoritySnapshot(context), consumedBefore);

  const cancellable = createApprovalRequiredIntent(context, 'scope-cancel').approval;
  const cancelled = context.store.transaction(
    (token) => context.approvals.cancelForIntentInTransaction(token, {
      intentId: cancellable.intentId,
      reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
    }),
  );
  assert.equal(cancelled.decision, 'cancelled');
  assert.equal(cancelled.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assertKernelError(() => context.store.transaction(
    (token) => context.approvals.cancelForIntentInTransaction(token, {
      intentId: denied.intentId,
      reasonCode: 'NOT_ALLOWED',
    }),
  ), 'APPROVAL_CANCEL_REASON');
});

test('scoped methods authenticate the opaque token before parsing hostile input', (t) => {
  const context = setup(t);
  let getterCalls = 0;
  const hostile = {};
  Object.defineProperty(hostile, 'intentId', {
    enumerable: true,
    get() {
      getterCalls += 1;
      throw new Error('caller getter ran');
    },
  });
  const fake = Object.freeze(Object.create(null));

  for (const invoke of [
    () => context.approvals.requestInTransaction(fake, hostile),
    () => context.approvals.consumeForInTransaction(fake, hostile),
    () => context.approvals.denyForIntentInTransaction(fake, hostile),
    () => context.approvals.expireForIntentInTransaction(fake, hostile),
    () => context.approvals.cancelForIntentInTransaction(fake, hostile),
  ]) {
    assert.throws(invoke, /invalid authority transaction/);
  }
  assert.equal(getterCalls, 0);

  let stale;
  context.store.transaction((token) => { stale = token; });
  assert.throws(() => context.approvals.requestInTransaction(stale, hostile),
    /invalid authority transaction/);
  assert.equal(getterCalls, 0);
});

test('get/list inputs and outputs are closed, bounded, immutable, and stable', (t) => {
  const context = setup(t);
  const first = createApprovalRequiredIntent(context, 'list-1').approval;
  const second = createApprovalRequiredIntent(context, 'list-2').approval;
  approve(context, second);

  assert.deepEqual(context.approvals.list({ state: 'pending', limit: 10 }), [first]);
  assert.deepEqual(context.approvals.list({ limit: 1 }), [first]);
  assert.equal(Object.isFrozen(context.approvals.list({ limit: 10 })), true);
  assert.equal(Object.isFrozen(context.approvals.list({ limit: 10 })[0]), true);
  assertKernelError(() => context.approvals.list({ state: 'unknown', limit: 10 }),
    'APPROVAL_LIST_SCHEMA');
  assertKernelError(() => context.approvals.list({ limit: 0 }), 'APPROVAL_LIST_SCHEMA');
  assertKernelError(() => context.approvals.list({ limit: 10, injected: true }),
    'APPROVAL_LIST_SCHEMA');
  assertKernelError(() => context.approvals.get('not valid'), 'TOKEN_FORMAT');
});

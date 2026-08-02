import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  createWalletKernel,
  KERNEL_FAULT_POINTS,
} from '../src/kernel/wallet-kernel.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { WalletSigningError } from '../src/adapters/wallet-adapter-contract.mjs';
import { createApprovalQueue } from '../src/kernel/approval-queue.mjs';
import { createAuthorityMutationCoordinator } from '../src/kernel/authority-mutation-coordinator.mjs';
import { createPermitAuthority } from '../src/kernel/authorized-permit.mjs';
import { createBudgetLedger } from '../src/kernel/budget-ledger.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { createReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../src/kernel/recovery.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const METHOD_NAMES = Object.freeze([
  'openOrResumeSession',
  'applyPolicy',
  'revokeAgent',
  'transitionSessionPolicy',
  'closeSession',
  'approvePending',
  'denyPending',
  'expireDueApprovals',
  'execute',
  'status',
  'statusByRequestId',
  'receiptById',
]);

const NOW = '2026-08-01T12:00:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const ROTATED_WALLET = '0x3000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
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

function dependencies(overrides = {}) {
  const noCall = () => {
    throw new Error('unexpected dependency call');
  };
  return {
    store: Object.freeze({ transaction: noCall, within: noCall }),
    policies: Object.freeze({ apply: noCall }),
    enrollments: Object.freeze({ revoke: noCall }),
    intents: Object.freeze({ openOrResumeSession: noCall }),
    budgets: Object.freeze({ snapshot: noCall }),
    approvals: Object.freeze({ approve: noCall }),
    receipts: Object.freeze({ assertParity: noCall }),
    permitAuthority: Object.freeze({ issue: noCall }),
    walletAdapter: Object.freeze({ walletIdentity: noCall, signX402Exact: noCall }),
    transport: Object.freeze({ probe: noCall, encodePayment: noCall, retryPaid: noCall }),
    authorityMutationCoordinator: Object.freeze({ runExclusive: noCall }),
    markAuthorityUnhealthy: noCall,
    now: () => '2026-08-01T12:00:00.000Z',
    idFactory: (kind) => `${kind}-1`,
    randomBytes: (size) => Buffer.alloc(size, 0x11),
    faultInjector: () => {},
    ...overrides,
  };
}

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return Object.freeze({ promise, resolve, reject });
}

function ordinaryRequest(label = 'ordinary') {
  return {
    requestUrl: `${SELLER}/paid/infer`,
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from(canonicalJson({ label })),
  };
}

function paymentRequired(amountAtomic) {
  return Object.freeze({
    x402Version: 2,
    resource: Object.freeze({
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
      mimeType: 'application/json',
    }),
    accepts: Object.freeze([Object.freeze({
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount: amountAtomic,
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: Object.freeze({ name: 'USDC', version: '2' }),
    })]),
  });
}

function signedPaymentPayload(challenge, amountAtomic = challenge.accepts[0].amount) {
  return Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: amountAtomic,
        validAfter: '0',
        validBefore: String(Math.floor(Date.parse(NOW) / 1_000) + 60),
        nonce: `0x${'11'.repeat(32)}`,
      }),
    }),
  });
}

function setupKernel(t, {
  transport,
  walletAdapter,
  autoApproveAtomic = '1000000',
  faultInjector = () => {},
  clock = () => NOW,
  wrapReceipts = (repository) => repository,
  idFactory = sequenceIds(),
} = {}) {
  const now = clock;
  const ids = idFactory;
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true, now });
  t.after(() => store.close());
  const policies = createPolicyRepository(store);
  const policy = structuredClone(BASE_POLICY);
  policy.sellers[0] = {
    ...policy.sellers[0],
    perRequestMaxAtomic: '1000000',
    autoApproveAtomic,
    humanApproveAtomic: '1000000',
    sellerSessionMaxAtomic: '2000000',
  };
  policy.sessionMaxAtomic = '2000000';
  policy.rolling24hMaxAtomic = '5000000';
  const activePolicy = policies.apply(policy, NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store, now });
  const enrollment = enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const intents = createIntentRepository({
    store,
    idFactory: ids,
    now,
    routeMetadata: ROUTE_METADATA,
  });
  const budgets = createBudgetLedger({ store, now });
  const approvals = createApprovalQueue({ store, idFactory: ids, now });
  const receiptRepository = createSignedReceiptRepository({
    store,
    signer: createReceiptSigner(),
    idFactory: ids,
    now,
  });
  const receipts = wrapReceipts(receiptRepository);
  let healthy = true;
  const markAuthorityUnhealthy = () => { healthy = false; };
  const authorityMutationCoordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      if (!healthy) {
        const error = new Error('receipt parity is required');
        error.code = 'RECEIPT_PARITY_REQUIRED';
        throw error;
      }
    },
    markAuthorityUnhealthy,
  });
  const configuredWalletAdapter = walletAdapter ?? Object.freeze({
    async walletIdentity() {
      return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
    },
    async signX402Exact() { throw new Error('unexpected signing'); },
  });
  const configuredTransport = transport ?? Object.freeze({
    async probe() { return { kind: 'response', status: 200, body: Buffer.from('ok') }; },
    encodePayment() { throw new Error('unexpected encoding'); },
    async retryPaid() { throw new Error('unexpected retry'); },
  });
  const createKernel = ({
    nextWalletAdapter = configuredWalletAdapter,
    nextTransport = configuredTransport,
  } = {}) => createWalletKernel({
    store,
    policies,
    enrollments,
    intents,
    budgets,
    approvals,
    receipts,
    permitAuthority: createPermitAuthority(),
    walletAdapter: nextWalletAdapter,
    transport: nextTransport,
    authorityMutationCoordinator,
    markAuthorityUnhealthy,
    now,
    idFactory: ids,
    randomBytes: (size) => Buffer.alloc(size, 0x11),
    faultInjector,
  });
  const kernel = createKernel();
  return {
    activePolicy,
    approvals,
    budgets,
    createKernel,
    enrollment,
    enrollments,
    intents,
    kernel,
    policy,
    receipts: receiptRepository,
    store,
  };
}

test('Slice A RED: exports the exact frozen twelve-method API and ten fault points', () => {
  const kernel = createWalletKernel(dependencies());
  assert.ok(Object.isFrozen(kernel));
  assert.deepEqual(Object.keys(kernel), METHOD_NAMES);
  for (const name of METHOD_NAMES) assert.equal(typeof kernel[name], 'function');
  assert.deepEqual(KERNEL_FAULT_POINTS, Object.freeze([
    'after_intent_commit',
    'after_challenge_commit',
    'after_reservation_commit',
    'after_signing_claim_commit',
    'after_signer_return',
    'after_signed_payment_commit',
    'after_retry_claim_commit',
    'after_paid_response',
    'after_settlement_commit',
    'before_terminal_receipt_commit',
  ]));
  assert.ok(Object.isFrozen(KERNEL_FAULT_POINTS));
});

test('Slice A RED: constructor dependencies form one closed injected authority graph', () => {
  const valid = dependencies();
  assert.throws(() => createWalletKernel(), TypeError);
  assert.throws(() => createWalletKernel({ ...valid, environment: process.env }), TypeError);
  assert.throws(() => createWalletKernel({ ...valid, randomBytes: null }), TypeError);
  assert.throws(() => createWalletKernel({ ...valid, idFactory: new Proxy(() => '', {}) }), TypeError);
});

test('Slice A RED: session and operator mutations are FIFO coordinator-held repository wrappers', async () => {
  const trace = [];
  const document = { schemaVersion: 1, wallet: 'fixture' };
  const expectedPolicyHash = sha256(canonicalJson(document));
  const operatorIdHash = `sha256:${'22'.repeat(32)}`;
  const expectedEnrollmentHash = `sha256:${'33'.repeat(32)}`;
  const expectedIntentHash = `sha256:${'44'.repeat(32)}`;
  const deps = dependencies({
    authorityMutationCoordinator: Object.freeze({
      async runExclusive(operation) {
        trace.push('lease');
        try {
          return await operation();
        } finally {
          trace.push('release');
        }
      },
    }),
    walletAdapter: Object.freeze({
      async walletIdentity() {
        trace.push('wallet');
        return { address: 'fixture' };
      },
      async signX402Exact() { throw new Error('must not sign'); },
    }),
    intents: Object.freeze({
      openOrResumeSession(input) {
        trace.push(['session', input]);
        return Object.freeze({ id: 'session-1' });
      },
    }),
    policies: Object.freeze({
      active() { return null; },
      apply(received, at) {
        trace.push(['policy', received, at]);
        return Object.freeze({ policyVersion: { id: 'policy-1' } });
      },
    }),
    enrollments: Object.freeze({
      revoke(input) {
        trace.push(['revoke', input]);
        return Object.freeze({ boundSessionIds: ['session-1'] });
      },
    }),
    approvals: Object.freeze({
      approve(input) {
        trace.push(['approve', input]);
        return Object.freeze({ approvalId: input.approvalId, decision: 'approved' });
      },
      listDue() { return Object.freeze([]); },
    }),
  });
  const kernel = createWalletKernel(deps);

  assert.deepEqual(await kernel.openOrResumeSession({
    agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
    walletAddress: '0x1000000000000000000000000000000000000000',
    policyVersionId: 'policy-1',
  }), { id: 'session-1' });
  assert.deepEqual(await kernel.applyPolicy({ document, expectedPolicyHash }), {
    policyVersion: { id: 'policy-1' },
  });
  assert.deepEqual(await kernel.revokeAgent({
    agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
    expectedEnrollmentHash,
    operatorIdHash,
  }), { boundSessionIds: ['session-1'] });
  assert.deepEqual(await kernel.approvePending({
    approvalId: 'approval-1',
    expectedIntentHash,
    operatorIdHash,
  }), { approvalId: 'approval-1', decision: 'approved' });

  assert.deepEqual(trace, [
    'lease',
    ['session', {
      agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
      walletAddress: '0x1000000000000000000000000000000000000000',
      policyVersionId: 'policy-1',
    }],
    'release',
    'wallet',
    'lease',
    ['policy', document, '2026-08-01T12:00:00.000Z'],
    'release',
    'lease',
    ['revoke', { agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA', expectedEnrollmentHash, operatorIdHash }],
    'release',
    'lease',
    ['approve', { approvalId: 'approval-1', expectedIntentHash, operatorIdHash }],
    'release',
  ]);
});

test('Slice A RED: policy hash confirmation and all wrapper schemas fail closed before a lease', async () => {
  let leases = 0;
  const kernel = createWalletKernel(dependencies({
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) {
        leases += 1;
        return Promise.resolve(operation());
      },
    }),
  }));
  await assert.rejects(
    kernel.applyPolicy({
      document: { schemaVersion: 1 },
      expectedPolicyHash: `sha256:${'00'.repeat(32)}`,
    }),
    (error) => error?.code === 'POLICY_CONFIRMATION_STALE',
  );
  await assert.rejects(
    kernel.openOrResumeSession({ sessionId: 'attacker-chosen' }),
    (error) => error?.code === 'SESSION_SCHEMA',
  );
  await assert.rejects(
    kernel.approvePending({ approvalId: 'approval-1' }),
    (error) => error?.code === 'APPROVAL_DECISION_SCHEMA',
  );
  assert.equal(leases, 0);
});

test('Slice B RED: ordinary 2xx captures once and returns only after terminal outcome and receipt', async (t) => {
  const context = setupKernel(t);
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest(),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-ordinary',
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.reasonCode, 'ORDINARY_SUCCESS');
  assert.match(result.requestId, /^request-/);
  assert.equal(result.upstreamStatus, 200);
  assert.deepEqual(result.body, Buffer.from('ok'));
  assert.equal(result.receipt.receipt.outcome.status, 'completed');
  assert.equal(result.receipt.receipt.intent.requestId, result.requestId);
  assert.equal(context.receipts.assertParity(), true);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  const outcome = context.store.readOne(
    'SELECT status, reason_code, revision FROM buyer_outcomes',
  );
  assert.equal(outcome.status, 'completed');
  assert.equal(outcome.reason_code, 'ORDINARY_SUCCESS');
  assert.equal(outcome.revision, 1n);
});

test('Slice B RED: ordinary non-402 HTTP failure is terminal and never creates spend authority', async (t) => {
  const context = setupKernel(t, {
    transport: Object.freeze({
      async probe() { return { kind: 'response', status: 503, body: Buffer.from('unavailable') }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('ordinary-http-failure'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-ordinary-http-failure',
  });

  assert.equal(result.status, 'upstream_failed');
  assert.equal(result.reasonCode, 'ORDINARY_HTTP_FAILURE');
  assert.equal(result.upstreamStatus, 503);
  assert.deepEqual(result.body, Buffer.from('unavailable'));
  assert.equal(result.receipt.receipt.execution.state, 'failed');
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
  assert.equal(context.store.readOne('SELECT status FROM buyer_outcomes').status,
    'upstream_failed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: unpaid transport failure terminalizes without budget or signing', async (t) => {
  const context = setupKernel(t, {
    transport: Object.freeze({
      async probe() {
        const error = new Error('private transport detail');
        error.code = 'UNPAID_FETCH_FAILED';
        throw error;
      },
      encodePayment() { throw new Error('unexpected encoding'); },
      async retryPaid() { throw new Error('unexpected retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('transport-failure'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-transport-failure',
  });

  assert.equal(result.status, 'upstream_failed');
  assert.equal(result.reasonCode, 'UPSTREAM_TRANSPORT_FAILURE');
  assert.equal(result.upstreamStatus, null);
  assert.equal(result.body, null);
  assert.equal(result.receipt.receipt.execution.state, 'unknown');
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: an impossible transport result fails closed without inventing authority', async (t) => {
  const context = setupKernel(t, {
    transport: Object.freeze({
      async probe() { return { kind: 'unexpected_internal_variant' }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('invalid-transport-result'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-invalid-transport-result',
    }),
    (error) => error?.code === 'TRANSPORT_RESULT_SCHEMA',
  );
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'captured');
  assert.equal(context.store.readAll('SELECT * FROM policy_decisions').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 0);
});

test('Slice B RED: policy denial persists challenge and decision before a no-spend receipt', async (t) => {
  let signerCalls = 0;
  const challenge = paymentRequired('1000001');
  const context = setupKernel(t, {
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('unexpected encoding'); },
      async retryPaid() { throw new Error('unexpected retry'); },
    }),
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('policy-deny'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-policy-deny',
  });

  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'PER_REQUEST_LIMIT');
  assert.equal(result.receipt.receipt.policy.decision, 'deny');
  assert.equal(result.receipt.receipt.payment.state, 'none');
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readAll('SELECT * FROM policy_decisions').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: pending approval is idempotent by ordinary request and hides approval authority', async (t) => {
  let probes = 0;
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { throw new Error('unexpected encoding'); },
      async retryPaid() { throw new Error('unexpected retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approval'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approval',
  };
  const first = await context.kernel.execute(call);
  const [second, third] = await Promise.all([
    context.kernel.execute(call),
    context.kernel.execute(call),
  ]);

  assert.equal(first.status, 'payment_approval_required');
  assert.equal(first.reasonCode, 'HUMAN_APPROVAL_REQUIRED');
  assert.equal(first.receipt, null);
  assert.equal(second.requestId, first.requestId);
  assert.equal(second.status, first.status);
  assert.equal(probes, 1);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM approvals').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  const approvalId = context.store.readOne('SELECT id FROM approvals').id;
  assert.equal(JSON.stringify(first).includes(approvalId), false);
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'approval_pending');
});

test('challenge persistence never backdates its policy decision when the clock advances', async (t) => {
  const base = Date.parse(NOW);
  let tick = 0;
  const clock = () => new Date(base + tick++).toISOString();
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock,
    transport: Object.freeze({
      async probe() {
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { throw new Error('unexpected encoding'); },
      async retryPaid() { throw new Error('unexpected retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('advancing-clock-approval'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-advancing-clock-approval',
  });

  assert.equal(result.status, 'payment_approval_required');
  const intent = context.store.readOne('SELECT id FROM spend_intents');
  const challengeEvent = context.store.readOne(
    "SELECT data_json FROM events WHERE entity_id = ? AND event_type = 'intent.challenge_attached'",
    [intent.id],
  );
  const decision = context.store.readOne(
    'SELECT decided_at FROM policy_decisions WHERE intent_id = ?',
    [intent.id],
  );
  assert.ok(
    Date.parse(decision.decided_at) >= Date.parse(JSON.parse(challengeEvent.data_json).updatedAt),
  );
  assert.equal(recoverKernelAuthority({
    store: context.store,
    intents: context.intents,
    budgets: context.budgets,
    approvals: context.approvals,
    receipts: context.receipts,
    now: clock,
  }).ready, true);
});

test('Slices C-D RED: auto-approved settlement signs once, commits once, and receipts exact terminal facts', async (t) => {
  const trace = [];
  const base = Date.parse(NOW);
  let tick = 0;
  const clock = () => new Date(base + tick++).toISOString();
  const challenge = paymentRequired('50000');
  const validBefore = String(Math.floor(Date.parse(NOW) / 1_000) + 60);
  const nonce = `0x${'11'.repeat(32)}`;
  const paymentPayload = Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore,
        nonce,
      }),
    }),
  });
  let retryBinding;
  const context = setupKernel(t, {
    clock,
    faultInjector(point) { trace.push(point); },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        trace.push('wallet_identity');
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact(permit) {
        trace.push('sign');
        assert.equal(permit.kind, 'AuthorizedPermit');
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() {
        trace.push('probe');
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment(received) {
        trace.push('encode');
        assert.equal(received, paymentPayload);
        return 'fixture-payment-header';
      },
      async retryPaid({ binding }) {
        trace.push('retry');
        retryBinding = binding;
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('fixture-payment-response', 'ascii')),
            success: true,
            transaction: `0x${'aa'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 200,
          body: Buffer.from('{"ok":true}'),
          executionState: 'succeeded',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('settled'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-settled',
  });

  assert.equal(result.status, 'completed');
  assert.equal(result.reasonCode, 'PAYMENT_SETTLED');
  assert.equal(result.receipt.receipt.payment.transactionId, `0x${'aa'.repeat(32)}`);
  assert.equal(result.receipt.receipt.budget.disposition, 'committed');
  assert.equal(retryBinding.paymentHash, sha256(Buffer.from('fixture-payment-header', 'ascii')));
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'settled');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'committed');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  const chronology = context.store.readOne(`SELECT
    payment_attempts.settled_at,
    execution_outcomes.recorded_at
    FROM payment_attempts
    JOIN execution_outcomes ON execution_outcomes.intent_id = payment_attempts.intent_id`);
  assert.ok(Date.parse(chronology.recorded_at) >= Date.parse(chronology.settled_at));
  assert.equal(context.receipts.assertParity(), true);
  assert.deepEqual(trace, [
    'after_intent_commit',
    'probe',
    'wallet_identity',
    'after_challenge_commit',
    'after_reservation_commit',
    'after_signing_claim_commit',
    'sign',
    'after_signer_return',
    'encode',
    'after_signed_payment_commit',
    'after_retry_claim_commit',
    'retry',
    'after_paid_response',
    'after_settlement_commit',
    'before_terminal_receipt_commit',
  ]);
});

test('Slices B-D RED: every declared fault point leaves one classified durable state', async (t) => {
  const expected = Object.freeze({
    after_intent_commit: Object.freeze({
      intent: 'captured', budget: null, payment: null, signer: 0, retry: 0, outcome: false,
    }),
    after_challenge_commit: Object.freeze({
      intent: 'challenged', budget: null, payment: null, signer: 0, retry: 0, outcome: false,
    }),
    after_reservation_commit: Object.freeze({
      intent: 'reserved', budget: 'reserved', payment: 'reserved', signer: 0, retry: 0,
      outcome: false,
    }),
    after_signing_claim_commit: Object.freeze({
      intent: 'signing', budget: 'reserved', payment: 'signing', signer: 0, retry: 0,
      outcome: false,
    }),
    after_signer_return: Object.freeze({
      intent: 'signing', budget: 'reserved', payment: 'signing', signer: 1, retry: 0,
      outcome: false,
    }),
    after_signed_payment_commit: Object.freeze({
      intent: 'signed', budget: 'reserved', payment: 'signed', signer: 1, retry: 0,
      outcome: false,
    }),
    after_retry_claim_commit: Object.freeze({
      intent: 'retrying', budget: 'reserved', payment: 'retrying', signer: 1, retry: 0,
      outcome: false,
    }),
    after_paid_response: Object.freeze({
      intent: 'retrying', budget: 'reserved', payment: 'retrying', signer: 1, retry: 1,
      outcome: false,
    }),
    after_settlement_commit: Object.freeze({
      intent: 'terminal', budget: 'committed', payment: 'settled', signer: 1, retry: 1,
      outcome: true,
    }),
    before_terminal_receipt_commit: Object.freeze({
      intent: 'terminal', budget: 'committed', payment: 'settled', signer: 1, retry: 1,
      outcome: true,
    }),
  });

  for (const point of KERNEL_FAULT_POINTS) {
    await t.test(point, async (st) => {
      const challenge = paymentRequired('50000');
      const paymentPayload = signedPaymentPayload(challenge);
      const crash = new Error(`fault:${point}`);
      let signerCalls = 0;
      let retryCalls = 0;
      const context = setupKernel(st, {
        faultInjector(observed) {
          if (observed === point) throw crash;
        },
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
          },
          async signX402Exact() {
            signerCalls += 1;
            return { paymentPayload };
          },
        }),
        transport: Object.freeze({
          async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
          encodePayment() { return 'fault-matrix-payment-header'; },
          async retryPaid({ binding }) {
            retryCalls += 1;
            return Object.freeze({
              kind: 'settled_response',
              settlement: Object.freeze({
                source: 'x402-payment-response',
                headerHash: sha256(Buffer.from('fault-matrix-settlement', 'ascii')),
                success: true,
                transaction: `0x${'ef'.repeat(32)}`,
                network: NETWORK,
                payer: WALLET,
                amountAtomic: '50000',
                paymentHash: binding.paymentHash,
              }),
              status: 200,
              body: Buffer.from('fault-matrix-ok'),
              executionState: 'succeeded',
            });
          },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      await assert.rejects(context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`fault-${point}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-fault-${point}`,
      }), (error) => error === crash);

      const classification = expected[point];
      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state,
        classification.intent);
      assert.equal(context.store.readOne('SELECT state FROM budget_reservations')?.state ?? null,
        classification.budget);
      const attempt = context.store.readOne('SELECT * FROM payment_attempts');
      assert.equal(attempt?.state ?? null, classification.payment);
      assert.equal(signerCalls, classification.signer);
      assert.equal(retryCalls, classification.retry);
      assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length <= 1, true);
      assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length <= 1, true);
      assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length,
        classification.outcome ? 1 : 0);
      assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 0);
      if (new Set(['signed', 'retrying', 'settled']).has(classification.payment)) {
        assert.equal(attempt.payment_payload_json, canonicalJson(paymentPayload));
        assert.equal(attempt.payment_header, 'fault-matrix-payment-header');
        assert.equal(attempt.payment_hash,
          sha256(Buffer.from('fault-matrix-payment-header', 'ascii')));
      } else if (attempt) {
        assert.equal(attempt.payment_payload_json, null);
        assert.equal(attempt.payment_header, null);
        assert.equal(attempt.payment_hash, null);
      }
      assert.equal(attempt?.transaction_id ?? null,
        classification.outcome ? `0x${'ef'.repeat(32)}` : null);
      assert.equal(context.store.verifyEventChain(), true);
      if (classification.outcome) {
        assert.throws(() => context.receipts.assertParity(),
          (error) => error?.code === 'RECEIPT_PARITY_REQUIRED');
      } else {
        assert.equal(context.receipts.assertParity(), true);
      }
    });
  }
});

test('post-signer storage faults close admission before a second authorization can be signed', async (t) => {
  const stages = Object.freeze([
    Object.freeze({ name: 'signed payment persistence', failOnParityCall: 1, state: 'signing', retries: 0 }),
    Object.freeze({ name: 'paid retry claim', failOnParityCall: 2, state: 'signed', retries: 0 }),
    Object.freeze({ name: 'terminal settlement', failOnParityCall: 3, state: 'retrying', retries: 1 }),
  ]);

  for (const stage of stages) {
    await t.test(stage.name, async (st) => {
      const challenge = paymentRequired('50000');
      const paymentPayload = signedPaymentPayload(challenge);
      const storageFailure = new Error(`storage fault:${stage.name}`);
      let signerReturned = false;
      let postSignerParityCalls = 0;
      let signerCalls = 0;
      let retryCalls = 0;
      const context = setupKernel(st, {
        wrapReceipts(repository) {
          return Object.freeze({
            ...repository,
            assertParityInTransaction(token) {
              if (signerReturned) {
                postSignerParityCalls += 1;
                if (postSignerParityCalls === stage.failOnParityCall) throw storageFailure;
              }
              return repository.assertParityInTransaction(token);
            },
          });
        },
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
          },
          async signX402Exact() {
            signerCalls += 1;
            signerReturned = true;
            return { paymentPayload };
          },
        }),
        transport: Object.freeze({
          async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
          encodePayment() { return 'post-signer-storage-fault-header'; },
          async retryPaid({ binding }) {
            retryCalls += 1;
            return Object.freeze({
              kind: 'settled_response',
              settlement: Object.freeze({
                source: 'x402-payment-response',
                headerHash: sha256(Buffer.from('post-signer-storage-fault-settlement', 'ascii')),
                success: true,
                transaction: `0x${'aa'.repeat(32)}`,
                network: NETWORK,
                payer: WALLET,
                amountAtomic: '50000',
                paymentHash: binding.paymentHash,
              }),
              status: 200,
              body: Buffer.from('settled-before-storage-fault'),
              executionState: 'succeeded',
            });
          },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });

      await assert.rejects(context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`post-signer-fault-${stage.failOnParityCall}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-post-signer-fault-${stage.failOnParityCall}`,
      }), (error) => error === storageFailure);
      assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, stage.state);

      await assert.rejects(context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`post-signer-second-${stage.failOnParityCall}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-post-signer-second-${stage.failOnParityCall}`,
      }), (error) => error?.code === 'RECEIPT_PARITY_REQUIRED');
      assert.equal(signerCalls, 1);
      assert.equal(retryCalls, stage.retries);
      assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 1);
    });
  }
});

test('Slice D RED: ambiguous paid response holds once and exact retries reuse its signed outcome', async (t) => {
  const challenge = paymentRequired('50000');
  const validBefore = String(Math.floor(Date.parse(NOW) / 1_000) + 60);
  const paymentPayload = Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore,
        nonce: `0x${'11'.repeat(32)}`,
      }),
    }),
  });
  let signerCalls = 0;
  let retries = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid() {
        retries += 1;
        return Object.freeze({
          kind: 'paid_response_ambiguous',
          reasonCode: 'SECOND_PAYMENT_REQUIRED',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('ambiguous'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-ambiguous',
  };
  const first = await context.kernel.execute(call);
  const [second, third] = await Promise.all([
    context.kernel.execute(call),
    context.kernel.execute(call),
  ]);

  assert.equal(first.status, 'payment_unresolved');
  assert.equal(first.reasonCode, 'SECOND_PAYMENT_REQUIRED');
  assert.equal(first.receipt.receipt.payment.state, 'unresolved');
  assert.equal(first.receipt.receipt.budget.disposition, 'unresolved');
  assert.equal(second.requestId, first.requestId);
  assert.equal(second.receipt.receiptHash, first.receipt.receiptHash);
  assert.equal(third.requestId, first.requestId);
  assert.equal(third.receipt.receiptHash, first.receipt.receiptHash);
  assert.equal(signerCalls, 1);
  assert.equal(retries, 1);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'unresolved');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice D RED: a thrown paid retry is one receipt-backed unresolved hold', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = signedPaymentPayload(challenge);
  let signerCalls = 0;
  let retries = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'thrown-paid-retry-header'; },
      async retryPaid() {
        retries += 1;
        const error = new Error('seller delivery is unknowable');
        error.code = 'PAID_FETCH_FAILED';
        throw error;
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('thrown-paid-retry'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-thrown-paid-retry',
  };

  const first = await context.kernel.execute(call);
  const second = await context.kernel.execute(call);

  assert.equal(first.status, 'payment_unresolved');
  assert.equal(first.reasonCode, 'PAID_RESPONSE_AMBIGUOUS');
  assert.equal(second.requestId, first.requestId);
  assert.equal(second.receipt.receiptHash, first.receipt.receiptHash);
  assert.equal(signerCalls, 1);
  assert.equal(retries, 1);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes').reason_code,
    'PAID_RESPONSE_AMBIGUOUS');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice D RED: settled HTTP failure atomically commits spend and opens a full refund blocker', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore: String(Math.floor(Date.parse(NOW) / 1_000) + 60),
        nonce: `0x${'11'.repeat(32)}`,
      }),
    }),
  });
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { return { paymentPayload }; },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid({ binding }) {
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('fixture-payment-response', 'ascii')),
            success: true,
            transaction: `0x${'bb'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            paymentHash: binding.paymentHash,
          }),
          status: 500,
          body: null,
          executionState: 'failed',
          deliveryReason: 'HTTP_STATUS_FAILURE',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('settled-failure'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-settled-failure',
  });

  assert.equal(result.status, 'execution_failed');
  assert.equal(result.reasonCode, 'UPSTREAM_HTTP_FAILURE');
  assert.equal(result.receipt.receipt.budget.disposition, 'committed');
  assert.equal(result.receipt.receipt.refund.state, 'pending');
  const refund = context.store.readOne('SELECT * FROM refunds');
  assert.equal(refund.amount_atomic, '50000');
  assert.equal(refund.original_transaction_id, `0x${'bb'.repeat(32)}`);
  assert.equal(context.store.readOne('SELECT state FROM execution_resolutions').state, 'refund_pending');
  const resolutionEvent = context.store.events().find(
    (event) => event.entity_type === 'execution_resolution'
      && event.event_type === 'execution_resolution.opened',
  );
  assert.deepEqual({
    entityId: resolutionEvent?.entity_id,
    data: resolutionEvent === undefined ? null : JSON.parse(resolutionEvent.data_json),
  }, {
    entityId: context.store.readOne('SELECT id FROM spend_intents').id,
    data: {
      intentId: context.store.readOne('SELECT id FROM spend_intents').id,
      state: 'refund_pending',
      reasonCode: 'UPSTREAM_HTTP_FAILURE',
      blocksWallet: true,
      openedAt: NOW,
    },
  });
  const refundEvent = context.store.events().find(
    (event) => event.entity_type === 'refund' && event.event_type === 'refund.opened',
  );
  assert.deepEqual({
    entityId: refundEvent?.entity_id,
    data: refundEvent === undefined ? null : JSON.parse(refundEvent.data_json),
  }, {
    entityId: refund.id,
    data: {
      refundId: refund.id,
      intentId: refund.intent_id,
      originalTransactionId: refund.original_transaction_id,
      amountAtomic: refund.amount_atomic,
      state: 'pending',
      createdAt: NOW,
    },
  });
  assert.equal(context.budgets.snapshot({
    sessionId: session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice D RED: a write failure inside settlement rolls back payment, execution, and refund together', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = signedPaymentPayload(challenge);
  const ids = sequenceIds();
  const settlementWriteFailure = new Error('refund ID persistence unavailable');
  const context = setupKernel(t, {
    idFactory(kind) {
      if (kind === 'refund') throw settlementWriteFailure;
      return ids(kind);
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { return { paymentPayload }; },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'atomic-settlement-payment-header'; },
      async retryPaid({ binding }) {
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('atomic-settlement-response', 'ascii')),
            success: true,
            transaction: `0x${'83'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 500,
          body: null,
          executionState: 'failed',
          deliveryReason: 'HTTP_STATUS_FAILURE',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('atomic-settlement-rollback'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-atomic-settlement-rollback',
    }),
    (error) => error === settlementWriteFailure,
  );

  const attempt = context.store.readOne('SELECT * FROM payment_attempts');
  assert.equal(attempt.state, 'retrying');
  assert.equal(attempt.transaction_id, null);
  assert.equal(attempt.settlement_json, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'reserved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'retrying');
  assert.equal(context.store.readAll('SELECT * FROM execution_outcomes').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM execution_resolutions').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM refunds').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 0);
  assert.equal(context.store.events().filter(
    (event) => event.event_type === 'execution_resolution.opened'
      || event.event_type === 'refund.opened',
  ).length, 0);
  assert.equal(context.store.verifyEventChain(), true);
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: approved exact retry freshly probes then consumes approval with its reservation', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore: String(Math.floor(Date.parse(NOW) / 1_000) + 60),
        nonce: `0x${'11'.repeat(32)}`,
      }),
    }),
  });
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid({ binding }) {
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('fixture-payment-response', 'ascii')),
            success: true,
            transaction: `0x${'cc'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 200,
          body: Buffer.from('approved'),
          executionState: 'succeeded',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approved-retry'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approved-retry',
  };
  const pending = await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });
  const completed = await context.kernel.execute(call);

  assert.equal(completed.requestId, pending.requestId);
  assert.equal(completed.status, 'completed');
  assert.equal(probes, 2);
  assert.equal(signerCalls, 1);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'consumed');
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 1);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'committed');
  assert.equal(completed.receipt.receipt.approval.state, 'consumed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C RED: exact branded pre-signer rejection releases the claimed reservation', async (t) => {
  const challenge = paymentRequired('50000');
  let retryCalls = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        throw new WalletSigningError(
          'WALLET_PRE_SIGN_REJECTED',
          'fixture rejected before signer',
          { signatureMayExist: false },
        );
      },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { retryCalls += 1; throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('pre-sign-rejected'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-pre-sign-rejected',
  });

  assert.equal(result.status, 'payment_failed');
  assert.equal(result.reasonCode, 'WALLET_PRE_SIGN_REJECTED');
  assert.equal(retryCalls, 0);
  const attempt = context.store.readOne('SELECT * FROM payment_attempts');
  assert.equal(attempt.state, 'rejected');
  assert.equal(attempt.nonce, `0x${'11'.repeat(32)}`);
  assert.equal(attempt.payment_payload_json, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(result.receipt.receipt.payment.state, 'not_signed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C RED: untyped signer throw holds full unresolved exposure without retry', async (t) => {
  const challenge = paymentRequired('50000');
  let retryCalls = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { throw new Error('untyped signer failure'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { retryCalls += 1; throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('signer-ambiguous'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-signer-ambiguous',
  });

  assert.equal(result.status, 'payment_unresolved');
  assert.equal(result.reasonCode, 'WALLET_SIGNATURE_AMBIGUOUS');
  assert.equal(retryCalls, 0);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT payment_payload_json FROM payment_attempts')
    .payment_payload_json, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'unresolved');
  assert.equal(result.receipt.receipt.payment.state, 'unresolved');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A RED: operator denial atomically terminalizes approval and issues its receipt', async (t) => {
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const pending = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('operator-denied'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-operator-denied',
  });
  const approval = context.store.readOne('SELECT id, intent_id, intent_hash FROM approvals');
  const denied = await context.kernel.denyPending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
    reasonCode: 'OPERATOR_DENIED',
  });

  assert.equal(denied.status, 'payment_denied');
  assert.equal(denied.reasonCode, 'OPERATOR_DENIED');
  assert.equal(denied.requestId, pending.requestId);
  assert.equal(denied.receipt.receipt.approval.state, 'denied');
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'denied');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT status FROM buyer_outcomes').status, 'payment_denied');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A RED: due pending and approved approvals expire in stable receipt-backed aggregates', async (t) => {
  let currentTime = NOW;
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock: () => currentTime,
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  for (const label of ['expiry-pending', 'expiry-approved']) {
    await context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest(label),
      purposeLabel: 'skill.invoke',
      correlationId: `pi-call-${label}`,
    });
  }
  const approvals = context.store.readAll(
    'SELECT id, intent_id, intent_hash, expires_at FROM approvals ORDER BY id',
  );
  await context.kernel.approvePending({
    approvalId: approvals[1].id,
    expectedIntentHash: approvals[1].intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });
  currentTime = approvals[0].expires_at;

  const expired = await context.kernel.expireDueApprovals({ limit: 10 });

  assert.deepEqual(expired.map((entry) => entry.intentId), approvals.map((entry) => entry.intent_id));
  assert.deepEqual(expired.map((entry) => entry.status), ['payment_denied', 'payment_denied']);
  assert.deepEqual(expired.map((entry) => entry.reasonCode), ['APPROVAL_EXPIRED', 'APPROVAL_EXPIRED']);
  assert.deepEqual(
    context.store.readAll('SELECT decision FROM approvals ORDER BY id').map((row) => row.decision),
    ['expired', 'expired'],
  );
  assert.deepEqual(
    context.store.readAll('SELECT state FROM spend_intents ORDER BY id').map((row) => row.state),
    ['terminal', 'terminal'],
  );
  assert.deepEqual(
    context.store.readAll('SELECT status, reason_code FROM buyer_outcomes ORDER BY intent_id')
      .map((row) => [row.status, row.reason_code]),
    [
      ['payment_denied', 'APPROVAL_EXPIRED'],
      ['payment_denied', 'APPROVAL_EXPIRED'],
    ],
  );
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 2);
  assert.equal(context.receipts.assertParity(), true);
  assert.deepEqual(await context.kernel.expireDueApprovals({ limit: 10 }), []);
});

test('Slice C RED: malformed signer output becomes one unresolved hold without a paid retry', async (t) => {
  const challenge = paymentRequired('50000');
  let signerCalls = 0;
  let retryCalls = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        return { paymentPayload: Object.freeze({ x402Version: 2 }) };
      },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode malformed payload'); },
      async retryPaid() { retryCalls += 1; throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('malformed-signer-output'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-malformed-signer-output',
  });

  assert.equal(result.status, 'payment_unresolved');
  assert.equal(result.reasonCode, 'WALLET_SIGNATURE_AMBIGUOUS');
  assert.equal(signerCalls, 1);
  assert.equal(retryCalls, 0);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT payment_payload_json FROM payment_attempts')
    .payment_payload_json, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'unresolved');
  assert.equal(result.receipt.receipt.payment.state, 'unresolved');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C RED: a durable nonce collision releases unsigned work without a second draw or signer call', async (t) => {
  const challenge = paymentRequired('50000');
  let signerCalls = 0;
  let retryCalls = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { retryCalls += 1; throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const seededIntent = context.intents.captureIntent({
    sessionId: session.id,
    routeId: 'paid-infer',
    method: 'POST',
    requestUrl: `${SELLER}/paid/infer`,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from(canonicalJson({ label: 'nonce-seed' })),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-nonce-seed',
  });
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       quote_id, nonce, created_at, updated_at)
      VALUES (?, ?, 'rejected', '{}', 0, ?, ?, ?, ?)`).run(
      'payment-nonce-seed',
      seededIntent.id,
      `sha256:${'ef'.repeat(32)}`,
      `0x${'11'.repeat(32)}`,
      NOW,
      NOW,
    );
  }));

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('nonce-collision'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-nonce-collision',
  });

  assert.equal(result.status, 'payment_failed');
  assert.equal(result.reasonCode, 'NONCE_COLLISION');
  assert.equal(signerCalls, 0);
  assert.equal(retryCalls, 0);
  const targetAttempt = context.store.readOne(
    "SELECT * FROM payment_attempts WHERE id != 'payment-nonce-seed'",
  );
  assert.equal(targetAttempt.state, 'rejected');
  assert.equal(targetAttempt.nonce, null);
  assert.equal(targetAttempt.signing_claimed_at, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.store.readOne("SELECT state FROM spend_intents WHERE id != ?", [seededIntent.id])
    .state, 'terminal');
  assert.equal(result.receipt.receipt.payment.state, 'not_signed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C RED: revocation before the signing claim releases and denies the unsigned reservation', async (t) => {
  const challenge = paymentRequired('50000');
  let signerCalls = 0;
  let context;
  context = setupKernel(t, {
    faultInjector(point) {
      if (point !== 'after_reservation_commit') return;
      context.enrollments.revoke({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        expectedEnrollmentHash: context.enrollment.enrollmentHash,
        operatorIdHash: OPERATOR_HASH,
      });
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('revoked-before-claim'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-revoked-before-claim',
  });

  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'AGENT_REVOKED');
  assert.equal(signerCalls, 0);
  const attempt = context.store.readOne('SELECT * FROM payment_attempts');
  assert.equal(attempt.state, 'rejected');
  assert.equal(attempt.nonce, null);
  assert.equal(attempt.signing_claimed_at, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(result.receipt.receipt.payment.state, 'not_signed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C RED: authorization-window expiry after reservation releases before signing', async (t) => {
  const challenge = paymentRequired('50000');
  let currentTime = NOW;
  let signerCalls = 0;
  const context = setupKernel(t, {
    clock: () => currentTime,
    faultInjector(point) {
      if (point === 'after_reservation_commit') {
        currentTime = new Date(Date.parse(NOW) + 60_000).toISOString();
      }
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('authorization-window-expired'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-authorization-window-expired',
  });

  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'CHALLENGE_EXPIRED');
  assert.equal(signerCalls, 0);
  const attempt = context.store.readOne('SELECT * FROM payment_attempts');
  assert.equal(attempt.state, 'rejected');
  assert.equal(attempt.nonce, null);
  assert.equal(attempt.signing_claimed_at, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes').reason_code,
    'CHALLENGE_EXPIRED');
  assert.equal(result.receipt.receipt.payment.state, 'not_signed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slices A-C RED: FIFO revocation queued after reservation wins the signing claim', async (t) => {
  const challenge = paymentRequired('50000');
  let signerCalls = 0;
  let revocationPromise;
  let context;
  context = setupKernel(t, {
    faultInjector(point) {
      if (point !== 'after_reservation_commit' || revocationPromise !== undefined) return;
      revocationPromise = context.kernel.revokeAgent({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        expectedEnrollmentHash: context.enrollment.enrollmentHash,
        operatorIdHash: OPERATOR_HASH,
      });
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('fifo-revoke-before-claim'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-fifo-revoke-before-claim',
  });
  const revocation = await revocationPromise;

  assert.equal(revocation.enrollment.state, 'revoked');
  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'AGENT_REVOKED');
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'rejected');
  assert.equal(context.store.readOne('SELECT nonce FROM payment_attempts').nonce, null);
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slices A-C RED: FIFO policy rotation queued after reservation blocks the signing claim', async (t) => {
  const challenge = paymentRequired('50000');
  let signerCalls = 0;
  let policyPromise;
  let targetPolicyId;
  let context;
  context = setupKernel(t, {
    faultInjector(point) {
      if (point !== 'after_reservation_commit' || policyPromise !== undefined) return;
      const nextPolicy = structuredClone(context.policy);
      nextPolicy.sellers[0].autoApproveAtomic = '20000';
      policyPromise = context.kernel.applyPolicy({
        document: nextPolicy,
        expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
      }).then((applied) => {
        targetPolicyId = applied.policyVersion.id;
        return applied;
      });
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('fifo-policy-before-claim'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-fifo-policy-before-claim',
    }),
    (error) => error?.code === 'SESSION_POLICY_BLOCKED',
  );
  await policyPromise;

  assert.equal(signerCalls, 0);
  assert.equal(context.intents.getSession(session.id).state, 'policy_blocked');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'reserved');
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'reserved');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'reserved');
  assert.equal(context.store.readOne('SELECT nonce FROM payment_attempts').nonce, null);

  const blocked = context.intents.getSession(session.id);
  const transitioned = await context.kernel.transitionSessionPolicy({
    sessionId: session.id,
    targetPolicyVersionId: targetPolicyId,
    expectedSessionHash: blocked.sessionHash,
  });
  assert.equal(transitioned.previousSession.state, 'closed');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'rejected');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes').reason_code,
    'POLICY_SUPERSEDED');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slices A-C RED: revocation at the unpaid-probe barrier blocks all later authority', async (t) => {
  const challenge = paymentRequired('50000');
  const probeEntered = deferred();
  const releaseProbe = deferred();
  let signerCalls = 0;
  let probes = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        probeEntered.resolve();
        await releaseProbe.promise;
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const execution = context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('revoke-at-probe'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-revoke-at-probe',
  });
  await probeEntered.promise;
  await context.kernel.revokeAgent({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrollment.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  releaseProbe.resolve();

  await assert.rejects(execution, (error) => error?.code === 'AGENT_REVOKED');
  assert.equal(probes, 1);
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'captured');
  assert.equal(context.store.readAll('SELECT * FROM policy_decisions').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
});

test('Slices A-D RED: a signing claim that wins revocation may finish only its persisted spend', async (t) => {
  const challenge = paymentRequired('50000');
  const signerEntered = deferred();
  const releaseSigner = deferred();
  const paymentPayload = signedPaymentPayload(challenge);
  let signerCalls = 0;
  let retries = 0;
  let probes = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        signerEntered.resolve();
        await releaseSigner.promise;
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { return 'claim-won-payment-header'; },
      async retryPaid({ binding }) {
        retries += 1;
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('claim-won-settlement', 'ascii')),
            success: true,
            transaction: `0x${'81'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 200,
          body: Buffer.from('claim won'),
          executionState: 'succeeded',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const execution = context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('claim-wins-revocation'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-claim-wins-revocation',
  });
  await signerEntered.promise;
  await context.kernel.revokeAgent({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrollment.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  releaseSigner.resolve();
  const completed = await execution;

  assert.equal(completed.status, 'completed');
  assert.equal(signerCalls, 1);
  assert.equal(retries, 1);
  assert.equal(context.store.readOne('SELECT state FROM agent_enrollments').state, 'revoked');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'committed');
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'settled');
  assert.equal(context.receipts.assertParity(), true);

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('post-revocation-new-work'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-post-revocation-new-work',
    }),
    (error) => error?.code === 'AGENT_REVOKED',
  );
  assert.equal(probes, 1);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
});

test('Slice C RED: a wallet blocker committed after reservation wins the final signing admission check', async (t) => {
  const challenge = paymentRequired('50000');
  const stopAfterReservation = new Error('stop after seed reservation');
  let phase = 'seed';
  let seedIntentId;
  let signerCalls = 0;
  let context;
  context = setupKernel(t, {
    faultInjector(point, details) {
      if (point !== 'after_reservation_commit') return;
      if (phase === 'seed') {
        seedIntentId = details.intentId;
        throw stopAfterReservation;
      }
      context.store.transaction((token) => {
        context.store.within(token, ({ db, appendEvent }) => {
          db.prepare(`UPDATE payment_attempts
            SET state = 'signing', nonce = ?, valid_after = '0', valid_before = ?,
                signing_claimed_at = ?, updated_at = ?
            WHERE intent_id = ? AND state = 'reserved'`).run(
            `0x${'22'.repeat(32)}`,
            String(Math.floor(Date.parse(NOW) / 1_000) + 60),
            NOW,
            NOW,
            seedIntentId,
          );
          appendEvent({
            entityType: 'payment_attempt',
            entityId: seedIntentId,
            eventType: 'payment.signing_claimed',
            data: {
              nonce: `0x${'22'.repeat(32)}`,
              validAfter: '0',
              validBefore: String(Math.floor(Date.parse(NOW) / 1_000) + 60),
              signingClaimedAt: NOW,
            },
          });
        });
        context.intents.transitionInTransaction(token, {
          intentId: seedIntentId,
          expectedState: 'reserved',
          nextState: 'signing',
          reasonCode: 'SIGNING_CLAIMED',
        });
        context.budgets.holdUnresolvedInTransaction(token, {
          intentId: seedIntentId,
          reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
        });
        const heldAt = context.store.within(token, ({ db }) => db.prepare(
          'SELECT updated_at FROM budget_reservations WHERE intent_id = ?',
        ).get(seedIntentId).updated_at);
        context.store.within(token, ({ db, appendEvent }) => {
          db.prepare(`UPDATE payment_attempts
            SET state = 'unresolved', reason_code = 'WALLET_SIGNATURE_AMBIGUOUS',
                updated_at = ?
            WHERE intent_id = ? AND state = 'signing'`).run(heldAt, seedIntentId);
          appendEvent({
            entityType: 'payment_attempt',
            entityId: seedIntentId,
            eventType: 'payment.unresolved',
            data: { reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS', recordedAt: heldAt },
          });
        });
        context.intents.transitionInTransaction(token, {
          intentId: seedIntentId,
          expectedState: 'signing',
          nextState: 'unresolved',
          reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
        });
        context.store.within(token, ({ db, appendEvent }) => {
          db.prepare(`INSERT INTO buyer_outcomes
            (intent_id, status, reason_code, revision, recorded_at)
            VALUES (?, 'payment_unresolved', 'WALLET_SIGNATURE_AMBIGUOUS', 1, ?)`).run(
            seedIntentId,
            heldAt,
          );
          appendEvent({
            entityType: 'buyer_outcome',
            entityId: seedIntentId,
            eventType: 'buyer_outcome.recorded',
            data: {
              status: 'payment_unresolved',
              reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
              revision: 1,
              recordedAt: heldAt,
            },
          });
        });
      });
      context.receipts.issueForTerminal({ intentId: seedIntentId });
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('wallet-blocker-seed'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-wallet-blocker-seed',
    }),
    (error) => error === stopAfterReservation,
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?',
    [seedIntentId],
  ).state, 'reserved');
  phase = 'target';

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('wallet-blocker-target'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-wallet-blocker-target',
  });

  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'WALLET_RECOVERY_REQUIRED');
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?',
    [seedIntentId],
  ).state, 'unresolved');
  const targetIntentId = context.store.readOne(
    "SELECT intent_id FROM buyer_outcomes WHERE reason_code = 'WALLET_RECOVERY_REQUIRED'",
  ).intent_id;
  const targetAttempt = context.store.readOne(
    'SELECT * FROM payment_attempts WHERE intent_id = ?',
    [targetIntentId],
  );
  assert.equal(targetAttempt.state, 'rejected');
  assert.equal(targetAttempt.nonce, null);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?',
    [targetIntentId],
  ).state, 'released');
  assert.equal(result.receipt.receipt.payment.state, 'not_signed');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: a changed approved challenge cancels the old authority and atomically replaces approval', async (t) => {
  const originalChallenge = paymentRequired('50000');
  const changedChallenge = paymentRequired('60000');
  const base = Date.parse(NOW);
  let tick = 0;
  const clock = () => new Date(base + tick++).toISOString();
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock,
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return {
          kind: 'payment_required',
          paymentRequired: probes === 1 ? originalChallenge : changedChallenge,
        };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('changed-approved-challenge'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-changed-approved-challenge',
  };
  const pending = await context.kernel.execute(call);
  const oldApproval = context.store.readOne('SELECT id, intent_id, intent_hash FROM approvals');
  await context.kernel.approvePending({
    approvalId: oldApproval.id,
    expectedIntentHash: oldApproval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });

  const changed = await context.kernel.execute(call);

  assert.equal(changed.requestId, pending.requestId);
  assert.equal(changed.status, 'payment_denied');
  assert.equal(changed.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(changed.receipt.receipt.approval.state, 'cancelled');
  assert.equal(signerCalls, 0);
  assert.equal(probes, 2);
  const approvals = context.store.readAll('SELECT * FROM approvals ORDER BY id');
  assert.equal(approvals.length, 2);
  assert.equal(approvals[0].decision, 'cancelled');
  assert.equal(approvals[0].reason_code, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(approvals[1].decision, 'pending');
  assert.notEqual(approvals[1].intent_id, oldApproval.intent_id);
  const intents = context.store.readAll('SELECT * FROM spend_intents ORDER BY id');
  assert.equal(intents.length, 2);
  assert.equal(intents[0].state, 'terminal');
  assert.equal(intents[0].retry_matchable, 0n);
  assert.equal(intents[1].state, 'approval_pending');
  assert.equal(intents[1].retry_matchable, 1n);
  assert.notEqual(intents[1].request_id, pending.requestId);
  assert.notEqual(intents[1].correlation_id, call.correlationId);
  assert.equal(context.store.readAll('SELECT * FROM policy_decisions').length, 2);
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 1);
  assert.equal(context.receipts.assertParity(), true);

  const replacement = await context.kernel.execute({
    ...call,
    correlationId: 'pi-call-changed-approved-challenge-replacement',
  });
  assert.equal(replacement.requestId, intents[1].request_id);
  assert.equal(replacement.status, 'payment_approval_required');
  assert.equal(probes, 2);
  assert.equal(recoverKernelAuthority({
    store: context.store,
    intents: context.intents,
    budgets: context.budgets,
    approvals: context.approvals,
    receipts: context.receipts,
    now: clock,
  }).ready, true);
});

test('Slice B RED: a missing challenge on approved retry cancels old authority without executing', async (t) => {
  const challenge = paymentRequired('50000');
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        if (probes === 1) return { kind: 'payment_required', paymentRequired: challenge };
        return { kind: 'response', status: 200, body: Buffer.from('challenge disappeared') };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approved-missing-challenge'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approved-missing-challenge',
  };
  const pending = await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });

  const cancelled = await context.kernel.execute(call);

  assert.equal(cancelled.requestId, pending.requestId);
  assert.equal(cancelled.status, 'payment_denied');
  assert.equal(cancelled.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'cancelled');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM approvals').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(cancelled.receipt.receipt.outcome.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: an approved-retry probe failure terminalizes with its signed receipt', async (t) => {
  const challenge = paymentRequired('50000');
  let clockValue = NOW;
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock: () => clockValue,
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        if (probes === 1) return { kind: 'payment_required', paymentRequired: challenge };
        const error = new Error('transient unpaid timeout');
        error.code = 'UNPAID_FETCH_FAILED';
        throw error;
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approved-probe-timeout'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approved-probe-timeout',
  };
  const pending = await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash, expires_at FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });
  const eventsBefore = context.store.events().length;

  const failedProbe = await context.kernel.execute(call);

  assert.equal(failedProbe.requestId, pending.requestId);
  assert.equal(failedProbe.status, 'upstream_failed');
  assert.equal(failedProbe.reasonCode, 'UPSTREAM_TRANSPORT_FAILURE');
  assert.equal(failedProbe.receipt.receipt.outcome.status, 'upstream_failed');
  assert.equal(failedProbe.receipt.receipt.outcome.reasonCode, 'UPSTREAM_TRANSPORT_FAILURE');
  assert.equal(failedProbe.receipt.receipt.approval.state, 'approved');
  assert.equal(failedProbe.receipt.receipt.payment.state, 'none');
  assert.equal(failedProbe.receipt.receipt.budget, null);
  assert.deepEqual(failedProbe.receipt.receipt.execution, {
    state: 'unknown',
    httpStatus: null,
    responseHash: null,
  });
  assert.equal(signerCalls, 0);
  assert.ok(context.store.events().length > eventsBefore);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'approved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.deepEqual({ ...context.store.readOne(
    'SELECT status, reason_code FROM buyer_outcomes',
  ) }, {
    status: 'upstream_failed',
    reason_code: 'UPSTREAM_TRANSPORT_FAILURE',
  });
  assert.equal(context.receipts.assertParity(), true);

  const terminalEvents = context.store.events().length;
  const replay = await context.kernel.execute(call);
  assert.equal(replay.requestId, failedProbe.requestId);
  assert.equal(replay.receipt.receiptHash, failedProbe.receipt.receiptHash);
  assert.equal(probes, 2);
  assert.equal(context.store.events().length, terminalEvents);

  clockValue = new Date(Date.parse(approval.expires_at) + 1).toISOString();
  assert.deepEqual(await context.kernel.expireDueApprovals({ limit: 100 }), []);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'approved');
  assert.equal(context.store.events().length, terminalEvents);

  const closed = await context.kernel.closeSession({
    sessionId: session.id,
    expectedSessionHash: context.intents.getSession(session.id).sessionHash,
  });
  assert.equal(closed.closedSession.state, 'closed');
  assert.deepEqual(closed.terminalReceipts, []);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'approved');
});

test('Slice B RED: approval expiry wins every paused approved-probe continuation', async (t) => {
  const challenge = paymentRequired('50000');
  const scenarios = [
    Object.freeze({
      name: 'transport failure',
      release(gate) {
        const error = new Error('late unpaid transport failure');
        error.code = 'UNPAID_FETCH_FAILED';
        gate.reject(error);
      },
    }),
    Object.freeze({
      name: 'changed ordinary response',
      release(gate) {
        gate.resolve({ kind: 'response', status: 200, body: Buffer.from('late ordinary response') });
      },
    }),
    Object.freeze({
      name: 'still-valid payment requirement',
      release(gate) {
        gate.resolve({ kind: 'payment_required', paymentRequired: challenge });
      },
    }),
  ];

  for (const [index, scenario] of scenarios.entries()) {
    await t.test(scenario.name, async (scenarioTest) => {
      let clockValue = NOW;
      let probes = 0;
      let signerCalls = 0;
      let paidRetries = 0;
      const probeEntered = deferred();
      const probeRelease = deferred();
      const context = setupKernel(scenarioTest, {
        autoApproveAtomic: '10000',
        clock: () => clockValue,
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return {
              provider: 'deterministic',
              walletId: 'wallet-1',
              address: WALLET,
              network: NETWORK,
            };
          },
          async signX402Exact() {
            signerCalls += 1;
            throw new Error('must not sign after expiry wins');
          },
        }),
        transport: Object.freeze({
          async probe() {
            probes += 1;
            if (probes === 1) {
              return { kind: 'payment_required', paymentRequired: challenge };
            }
            probeEntered.resolve();
            return await probeRelease.promise;
          },
          encodePayment() { throw new Error('must not encode after expiry wins'); },
          async retryPaid() {
            paidRetries += 1;
            throw new Error('must not retry after expiry wins');
          },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      const call = {
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`expiry-probe-race-${index}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-expiry-probe-race-${index}`,
      };
      const pending = await context.kernel.execute(call);
      const approval = context.store.readOne(
        'SELECT id, intent_id, intent_hash, expires_at FROM approvals',
      );
      await context.kernel.approvePending({
        approvalId: approval.id,
        expectedIntentHash: approval.intent_hash,
        operatorIdHash: OPERATOR_HASH,
      });

      const racingExecution = context.kernel.execute(call);
      await probeEntered.promise;
      clockValue = approval.expires_at;
      const expired = await context.kernel.expireDueApprovals({ limit: 100 });
      assert.equal(expired.length, 1);
      const expiryWinner = expired[0];
      assert.equal(expiryWinner.intentId, approval.intent_id);
      assert.equal(expiryWinner.requestId, pending.requestId);
      assert.equal(expiryWinner.status, 'payment_denied');
      assert.equal(expiryWinner.reasonCode, 'APPROVAL_EXPIRED');
      assert.equal(expiryWinner.receipt.receipt.approval.state, 'expired');
      const eventsAfterExpiry = context.store.events().length;

      scenario.release(probeRelease);
      const raced = await racingExecution;

      assert.deepEqual(Object.keys(raced), ['requestId', 'status', 'reasonCode', 'receipt']);
      assert.equal(raced.requestId, expiryWinner.requestId);
      assert.equal(raced.status, expiryWinner.status);
      assert.equal(raced.reasonCode, expiryWinner.reasonCode);
      assert.equal(raced.receipt.receiptHash, expiryWinner.receipt.receiptHash);
      assert.equal(context.store.events().length, eventsAfterExpiry);

      const replay = await context.kernel.execute(call);
      assert.equal(replay.requestId, expiryWinner.requestId);
      assert.equal(replay.status, expiryWinner.status);
      assert.equal(replay.reasonCode, expiryWinner.reasonCode);
      assert.equal(replay.receipt.receiptHash, expiryWinner.receipt.receiptHash);
      assert.equal(context.store.events().length, eventsAfterExpiry);
      assert.equal(probes, 2);
      assert.equal(signerCalls, 0);
      assert.equal(paidRetries, 0);
      assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'expired');
      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
      assert.deepEqual({ ...context.store.readOne(
        'SELECT status, reason_code FROM buyer_outcomes',
      ) }, {
        status: 'payment_denied',
        reason_code: 'APPROVAL_EXPIRED',
      });
      assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM approvals').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
      assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('Slices A-B RED: policy transition ignores terminal approved history', async (t) => {
  const challenge = paymentRequired('50000');
  let probes = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() {
        probes += 1;
        if (probes === 1) return { kind: 'payment_required', paymentRequired: challenge };
        const error = new Error('unpaid connection reset');
        error.code = 'UNPAID_FETCH_FAILED';
        throw error;
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approved-history-transition'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approved-history-transition',
  };
  await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });
  const terminal = await context.kernel.execute(call);
  assert.equal(terminal.status, 'upstream_failed');
  assert.equal(terminal.reasonCode, 'UPSTREAM_TRANSPORT_FAILURE');

  const nextPolicy = structuredClone(context.policy);
  nextPolicy.sellers[0].autoApproveAtomic = '20000';
  const applied = await context.kernel.applyPolicy({
    document: nextPolicy,
    expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
  });
  const blocked = context.intents.getSession(session.id);
  assert.equal(blocked.state, 'policy_blocked');

  const transitioned = await context.kernel.transitionSessionPolicy({
    sessionId: session.id,
    targetPolicyVersionId: applied.policyVersion.id,
    expectedSessionHash: blocked.sessionHash,
  });

  assert.equal(transitioned.previousSession.state, 'closed');
  assert.equal(transitioned.replacementSession.state, 'open');
  assert.deepEqual(transitioned.terminalReceipts, []);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'approved');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: freshly allowed or denied changed challenges create no replacement authority', async (t) => {
  for (const scenario of [
    { name: 'allow', freshAmount: '5000' },
    { name: 'deny', freshAmount: '1000001' },
  ]) {
    await t.test(scenario.name, async (st) => {
      const initialChallenge = paymentRequired('50000');
      const freshChallenge = paymentRequired(scenario.freshAmount);
      let probes = 0;
      let signerCalls = 0;
      const context = setupKernel(st, {
        autoApproveAtomic: '10000',
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
          },
          async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
        }),
        transport: Object.freeze({
          async probe() {
            probes += 1;
            return {
              kind: 'payment_required',
              paymentRequired: probes === 1 ? initialChallenge : freshChallenge,
            };
          },
          encodePayment() { throw new Error('must not encode'); },
          async retryPaid() { throw new Error('must not retry'); },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      const call = {
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`changed-${scenario.name}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-changed-${scenario.name}`,
      };
      await context.kernel.execute(call);
      const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
      await context.kernel.approvePending({
        approvalId: approval.id,
        expectedIntentHash: approval.intent_hash,
        operatorIdHash: OPERATOR_HASH,
      });

      const cancelled = await context.kernel.execute(call);

      assert.equal(cancelled.status, 'payment_denied');
      assert.equal(cancelled.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
      assert.equal(Object.hasOwn(cancelled, 'replacementRequestId'), false);
      assert.equal(signerCalls, 0);
      assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM approvals').length, 1);
      assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
      assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'cancelled');
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('Slice B RED: an invalid fresh challenge cancels approved authority without replacement', async (t) => {
  const challenge = paymentRequired('50000');
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        if (probes === 1) return { kind: 'payment_required', paymentRequired: challenge };
        const error = new Error('malformed fresh challenge');
        error.code = 'PAYMENT_REQUIRED_DECODE';
        throw error;
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('invalid-fresh-challenge'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-invalid-fresh-challenge',
  };
  await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });

  const result = await context.kernel.execute(call);

  assert.equal(result.status, 'payment_denied');
  assert.equal(result.reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(Object.hasOwn(result, 'replacementRequestId'), false);
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM approvals').length, 1);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'cancelled');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A: receipt failure closes FIFO admission before queued agent and operator writes', async (t) => {
  const challenge = paymentRequired('50000');
  const receiptFailure = new Error('fixture receipt signer unavailable');
  const queued = [];
  let queueAfterDomainCommit = () => {};
  let context;
  let probes = 0;
  context = setupKernel(t, {
    autoApproveAtomic: '10000',
    wrapReceipts(repository) {
      return Object.freeze({
        ...repository,
        issueForTerminal(input) {
          queueAfterDomainCommit();
          throw receiptFailure;
        },
      });
    },
    transport: Object.freeze({
      async probe(request) {
        probes += 1;
        return request.bodyBytes.toString().includes('fail-stop-pending')
          ? { kind: 'payment_required', paymentRequired: challenge }
          : { kind: 'response', status: 200, body: Buffer.from('ok') };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('fail-stop-pending'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-fail-stop-pending',
  });
  const approval = context.store.readOne('SELECT id, intent_hash FROM approvals');
  queueAfterDomainCommit = () => {
    queueAfterDomainCommit = () => {};
    queued.push(context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('fail-stop-queued-agent'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-fail-stop-queued-agent',
    }));
    queued.push(context.kernel.applyPolicy({
      document: context.policy,
      expectedPolicyHash: sha256(canonicalJson(context.policy)),
    }));
    queued.push(context.kernel.revokeAgent({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      expectedEnrollmentHash: context.enrollment.enrollmentHash,
      operatorIdHash: OPERATOR_HASH,
    }));
    queued.push(context.kernel.approvePending({
      approvalId: approval.id,
      expectedIntentHash: approval.intent_hash,
      operatorIdHash: OPERATOR_HASH,
    }));
    queued.push(context.kernel.denyPending({
      approvalId: approval.id,
      expectedIntentHash: approval.intent_hash,
      operatorIdHash: OPERATOR_HASH,
      reasonCode: 'OPERATOR_DENIED',
    }));
    queued.push(context.kernel.closeSession({
      sessionId: session.id,
      expectedSessionHash: context.intents.getSession(session.id).sessionHash,
    }));
    queued.push(context.kernel.transitionSessionPolicy({
      sessionId: session.id,
      targetPolicyVersionId: 'policy-queued',
      expectedSessionHash: context.intents.getSession(session.id).sessionHash,
    }));
  };

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('fail-stop-terminal'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-fail-stop-terminal',
    }),
    (error) => error === receiptFailure,
  );
  assert.equal(queued.length, 7);
  for (const operation of queued) {
    await assert.rejects(operation, (error) => error?.code === 'RECEIPT_PARITY_REQUIRED');
  }
  assert.equal(probes, 2);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 2);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'pending');
  assert.equal(context.store.readOne('SELECT state FROM agent_enrollments').state, 'active');
  assert.equal(context.store.readAll('SELECT * FROM policy_versions').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 0);
});

test('Slice D: valid settlement with unknown body delivery commits spend and opens reconciliation', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = signedPaymentPayload(challenge);
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { return { paymentPayload }; },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid({ binding }) {
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('fixture-payment-response', 'ascii')),
            success: true,
            transaction: `0x${'dd'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 200,
          body: null,
          executionState: 'unknown',
          deliveryReason: 'RESPONSE_BODY_TIMEOUT',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });

  const result = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('execution-unknown'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-execution-unknown',
  });

  assert.equal(result.status, 'execution_unknown');
  assert.equal(result.reasonCode, 'PAID_RESPONSE_AMBIGUOUS');
  assert.equal(result.body, null);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'settled');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'committed');
  assert.equal(context.store.readOne('SELECT state FROM execution_outcomes').state, 'unknown');
  assert.equal(context.store.readOne('SELECT state FROM execution_resolutions')
    .state, 'reconciliation_required');
  assert.equal(context.store.readAll('SELECT * FROM refunds').length, 0);
  const resolutionEvent = context.store.events().find(
    (event) => event.entity_type === 'execution_resolution'
      && event.event_type === 'execution_resolution.opened',
  );
  const intentId = context.store.readOne('SELECT id FROM spend_intents').id;
  assert.deepEqual({
    entityId: resolutionEvent?.entity_id,
    data: resolutionEvent === undefined ? null : JSON.parse(resolutionEvent.data_json),
  }, {
    entityId: intentId,
    data: {
      intentId,
      state: 'reconciliation_required',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      blocksWallet: true,
      openedAt: NOW,
    },
  });
  assert.equal(context.store.events().filter(
    (event) => event.event_type === 'refund.opened',
  ).length, 0);
  assert.equal(context.budgets.snapshot({
    sessionId: session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assert.equal(result.receipt.receipt.outcome.status, 'execution_unknown');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice D: settlement-reported failure preserves unresolved exposure and never retries twice', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = signedPaymentPayload(challenge);
  let signerCalls = 0;
  let retryCalls = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; return { paymentPayload }; },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid() {
        retryCalls += 1;
        return Object.freeze({
          kind: 'paid_response_ambiguous',
          reasonCode: 'SETTLEMENT_REPORTED_FAILURE',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('settlement-false'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-settlement-false',
  };

  const first = await context.kernel.execute(call);
  const second = await context.kernel.execute(call);

  assert.equal(first.status, 'payment_unresolved');
  assert.equal(first.reasonCode, 'SETTLEMENT_EVIDENCE_INVALID');
  assert.equal(second.receipt.receiptHash, first.receipt.receiptHash);
  assert.equal(signerCalls, 1);
  assert.equal(retryCalls, 1);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'unresolved');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'unresolved');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice C-D: concurrent exact followers at signing, signed, and retrying never duplicate money work', async (t) => {
  const challenge = paymentRequired('50000');
  const paymentPayload = signedPaymentPayload(challenge);
  const signerStarted = deferred();
  const signerRelease = deferred();
  const retryStarted = deferred();
  const retryRelease = deferred();
  const signedFollowers = [];
  let signerCalls = 0;
  let retryCalls = 0;
  let context;
  let call;
  context = setupKernel(t, {
    faultInjector(point) {
      if (point !== 'after_signed_payment_commit') return;
      signedFollowers.push(context.kernel.execute(call), context.kernel.execute(call));
    },
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() {
        signerCalls += 1;
        signerStarted.resolve();
        await signerRelease.promise;
        return { paymentPayload };
      },
    }),
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { return 'fixture-payment-header'; },
      async retryPaid({ binding }) {
        retryCalls += 1;
        retryStarted.resolve();
        await retryRelease.promise;
        return Object.freeze({
          kind: 'settled_response',
          settlement: Object.freeze({
            source: 'x402-payment-response',
            headerHash: sha256(Buffer.from('fixture-payment-response', 'ascii')),
            success: true,
            transaction: `0x${'ee'.repeat(32)}`,
            network: NETWORK,
            payer: WALLET,
            amountAtomic: '50000',
            paymentHash: binding.paymentHash,
          }),
          status: 200,
          body: Buffer.from('concurrency-ok'),
          executionState: 'succeeded',
        });
      },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('barriered-followers'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-barriered-followers',
  };

  const leader = context.kernel.execute(call);
  await signerStarted.promise;
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'signing');
  const signingFollowers = await Promise.all([
    context.kernel.execute(call),
    context.kernel.execute(call),
  ]);
  assert.deepEqual(signingFollowers.map((result) => result.status), [
    'request_in_flight',
    'request_in_flight',
  ]);
  signerRelease.resolve();
  await retryStarted.promise;
  assert.equal(signedFollowers.length, 2);
  const signedResults = await Promise.all(signedFollowers);
  assert.deepEqual(signedResults.map((result) => result.status), [
    'request_in_flight',
    'request_in_flight',
  ]);
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'retrying');
  const retryingFollowers = await Promise.all([
    context.kernel.execute(call),
    context.kernel.execute(call),
  ]);
  assert.deepEqual(retryingFollowers.map((result) => result.status), [
    'request_in_flight',
    'request_in_flight',
  ]);
  retryRelease.resolve();
  const completed = await leader;

  assert.equal(completed.status, 'completed');
  assert.equal(signerCalls, 1);
  assert.equal(retryCalls, 1);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM approvals').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 1);
  assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 1);
  for (const follower of [...signingFollowers, ...signedResults, ...retryingFollowers]) {
    assert.equal(follower.requestId, completed.requestId);
  }
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice B RED: malformed and oversized payment challenges deny without spend authority', async (t) => {
  const scenarios = [
    {
      name: 'oversized header',
      reasonCode: 'PAYMENT_CHALLENGE_OVERSIZED',
      async probe() {
        const error = new Error('PAYMENT-REQUIRED exceeds its byte ceiling');
        error.code = 'PAYMENT_REQUIRED_TOO_LARGE';
        throw error;
      },
    },
    {
      name: 'malformed header',
      reasonCode: 'PAYMENT_CHALLENGE_MALFORMED',
      async probe() {
        const error = new Error('PAYMENT-REQUIRED is malformed');
        error.code = 'PAYMENT_REQUIRED_MALFORMED';
        throw error;
      },
    },
    {
      name: 'malformed decoded value',
      reasonCode: 'PAYMENT_CHALLENGE_MALFORMED',
      async probe() { return { kind: 'payment_required', paymentRequired: {} }; },
    },
  ];
  for (const scenario of scenarios) {
    await t.test(scenario.name, async (subtest) => {
      let signerCalls = 0;
      const context = setupKernel(subtest, {
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return {
              provider: 'deterministic',
              walletId: 'wallet-1',
              address: WALLET,
              network: NETWORK,
            };
          },
          async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
        }),
        transport: Object.freeze({
          probe: scenario.probe,
          encodePayment() { throw new Error('must not encode'); },
          async retryPaid() { throw new Error('must not retry'); },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });

      const result = await context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`invalid-challenge-${scenario.name}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-invalid-challenge-${scenario.name.replaceAll(' ', '-')}`,
      });

      assert.equal(result.status, 'payment_denied');
      assert.equal(result.reasonCode, scenario.reasonCode);
      assert.equal(signerCalls, 0);
      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
      assert.equal(context.store.readAll('SELECT * FROM policy_decisions').length, 0);
      assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
      assert.equal(context.store.readAll('SELECT * FROM payment_attempts').length, 0);
      assert.equal(result.receipt.receipt.payment.state, 'none');
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('Slice B RED: an exact retry at approval expiry terminalizes before a fresh probe', async (t) => {
  const challenge = paymentRequired('50000');
  let currentTime = NOW;
  let probes = 0;
  let signerCalls = 0;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock: () => currentTime,
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return { kind: 'payment_required', paymentRequired: challenge };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('approval-expired-retry'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-approval-expired-retry',
  };
  const pending = await context.kernel.execute(call);
  const approval = context.store.readOne('SELECT id, intent_hash, expires_at FROM approvals');
  await context.kernel.approvePending({
    approvalId: approval.id,
    expectedIntentHash: approval.intent_hash,
    operatorIdHash: OPERATOR_HASH,
  });
  currentTime = approval.expires_at;

  const expired = await context.kernel.execute(call);

  assert.equal(expired.requestId, pending.requestId);
  assert.equal(expired.status, 'payment_denied');
  assert.equal(expired.reasonCode, 'APPROVAL_EXPIRED');
  assert.equal(probes, 1);
  assert.equal(signerCalls, 0);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'expired');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readAll('SELECT * FROM budget_reservations').length, 0);
  assert.equal(expired.receipt.receipt.approval.state, 'expired');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A RED: policy transition cancels pending authority and opens one receipt-backed replacement session', async (t) => {
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('policy-transition-pending'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-policy-transition-pending',
  });
  const nextPolicy = structuredClone(context.policy);
  nextPolicy.sellers[0].autoApproveAtomic = '20000';
  const applied = await context.kernel.applyPolicy({
    document: nextPolicy,
    expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
  });
  const blocked = context.intents.getSession(session.id);
  assert.equal(blocked.state, 'policy_blocked');

  const transitioned = await context.kernel.transitionSessionPolicy({
    sessionId: session.id,
    targetPolicyVersionId: applied.policyVersion.id,
    expectedSessionHash: blocked.sessionHash,
  });

  assert.equal(transitioned.previousSession.state, 'closed');
  assert.equal(transitioned.replacementSession.state, 'open');
  assert.equal(transitioned.replacementSession.policyVersionId, applied.policyVersion.id);
  assert.notEqual(transitioned.replacementSession.id, session.id);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'cancelled');
  assert.equal(context.store.readOne('SELECT reason_code FROM approvals')
    .reason_code, 'POLICY_SUPERSEDED');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes')
    .reason_code, 'POLICY_SUPERSEDED');
  assert.equal(transitioned.terminalReceipts.length, 1);
  assert.equal(transitioned.terminalReceipts[0].receipt.receipt.outcome.reasonCode,
    'POLICY_SUPERSEDED');
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A RED: guarded close latches the old Kernel and a fresh instance may restart', async (t) => {
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('session-close-pending'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-session-close-pending',
  });

  const closed = await context.kernel.closeSession({
    sessionId: session.id,
    expectedSessionHash: context.intents.getSession(session.id).sessionHash,
  });

  assert.equal(closed.closedSession.state, 'closed');
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'cancelled');
  assert.equal(context.store.readOne('SELECT reason_code FROM approvals').reason_code, 'SESSION_CLOSED');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes')
    .reason_code, 'SESSION_CLOSED');
  assert.equal(closed.terminalReceipts.length, 1);
  assert.equal(context.store.readOne('SELECT state FROM agent_enrollments').state, 'active');
  assert.equal(context.receipts.assertParity(), true);

  await assert.rejects(
    context.kernel.openOrResumeSession({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      walletAddress: WALLET,
      policyVersionId: context.activePolicy.id,
    }),
    (error) => error?.code === 'AGENT_SESSION_UNAVAILABLE',
  );
  await assert.rejects(
    context.kernel.applyPolicy({
      document: context.policy,
      expectedPolicyHash: sha256(canonicalJson(context.policy)),
    }),
    (error) => error?.code === 'AGENT_SESSION_UNAVAILABLE',
  );

  const restarted = await context.createKernel().openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  assert.notEqual(restarted.id, session.id);
  assert.equal(restarted.state, 'open');
});

test('Slice A RED: wallet rotation requires a fresh Kernel configured for the new wallet', async (t) => {
  let configuredAddress = WALLET;
  const oldAdapter = Object.freeze({
    async walletIdentity() {
      return {
        provider: 'deterministic',
        walletId: 'wallet-old',
        address: configuredAddress,
        network: NETWORK,
      };
    },
    async signX402Exact() { throw new Error('must not sign'); },
  });
  const context = setupKernel(t, { walletAdapter: oldAdapter });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.closeSession({
    sessionId: session.id,
    expectedSessionHash: context.intents.getSession(session.id).sessionHash,
  });
  const rotatedPolicy = structuredClone(context.policy);
  rotatedPolicy.wallet = ROTATED_WALLET;
  const request = {
    document: rotatedPolicy,
    expectedPolicyHash: sha256(canonicalJson(rotatedPolicy)),
  };

  await assert.rejects(
    context.kernel.applyPolicy(request),
    (error) => error?.code === 'AGENT_SESSION_UNAVAILABLE',
  );
  const freshOldWalletKernel = context.createKernel({ nextWalletAdapter: oldAdapter });
  await assert.rejects(
    freshOldWalletKernel.applyPolicy(request),
    (error) => error?.code === 'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART',
  );
  assert.equal(configuredAddress, WALLET);

  const rotatedAdapter = Object.freeze({
    async walletIdentity() {
      return {
        provider: 'deterministic',
        walletId: 'wallet-rotated',
        address: ROTATED_WALLET,
        network: NETWORK,
      };
    },
    async signX402Exact() { throw new Error('must not sign'); },
  });
  const freshRotatedKernel = context.createKernel({ nextWalletAdapter: rotatedAdapter });
  const applied = await freshRotatedKernel.applyPolicy(request);
  const restarted = await freshRotatedKernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: ROTATED_WALLET,
    policyVersionId: applied.policyVersion.id,
  });
  assert.equal(restarted.walletAddress, ROTATED_WALLET);
  assert.equal(configuredAddress, WALLET);
});

test('Slice A RED: stale session confirmations roll back every pending-authority write', async (t) => {
  const challenge = paymentRequired('50000');
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('stale-session-confirmation'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-stale-session-confirmation',
  });
  const nextPolicy = structuredClone(context.policy);
  nextPolicy.sellers[0].autoApproveAtomic = '20000';
  const applied = await context.kernel.applyPolicy({
    document: nextPolicy,
    expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
  });
  const eventsBefore = context.store.events().length;
  const staleHash = `sha256:${'00'.repeat(32)}`;

  await assert.rejects(
    context.kernel.transitionSessionPolicy({
      sessionId: session.id,
      targetPolicyVersionId: applied.policyVersion.id,
      expectedSessionHash: staleHash,
    }),
    (error) => error?.code === 'SESSION_CONFIRMATION_STALE',
  );
  await assert.rejects(
    context.kernel.closeSession({
      sessionId: session.id,
      expectedSessionHash: staleHash,
    }),
    (error) => error?.code === 'SESSION_CONFIRMATION_STALE',
  );

  assert.equal(context.store.events().length, eventsBefore);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'pending');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'approval_pending');
  assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 0);
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 0);
  assert.equal(context.intents.getSession(session.id).state, 'policy_blocked');
});

test('Slice A RED: session transition and close release only definitely unsigned reservations', async (t) => {
  for (const command of ['close', 'transition']) {
    await t.test(command, async (st) => {
      const challenge = paymentRequired('50000');
      const crash = new Error(`stop after reservation for ${command}`);
      const context = setupKernel(st, {
        faultInjector(point) {
          if (point === 'after_reservation_commit') throw crash;
        },
        transport: Object.freeze({
          async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
          encodePayment() { throw new Error('must not encode'); },
          async retryPaid() { throw new Error('must not retry'); },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      await assert.rejects(context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`unsigned-${command}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-unsigned-${command}`,
      }), (error) => error === crash);
      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'reserved');
      assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'reserved');
      assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'reserved');

      let result;
      let reasonCode;
      if (command === 'close') {
        reasonCode = 'SESSION_CLOSED';
        result = await context.kernel.closeSession({
          sessionId: session.id,
          expectedSessionHash: context.intents.getSession(session.id).sessionHash,
        });
        assert.equal(result.closedSession.state, 'closed');
      } else {
        reasonCode = 'POLICY_SUPERSEDED';
        const nextPolicy = structuredClone(context.policy);
        nextPolicy.sellers[0].autoApproveAtomic = '20000';
        const applied = await context.kernel.applyPolicy({
          document: nextPolicy,
          expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
        });
        const blocked = context.intents.getSession(session.id);
        result = await context.kernel.transitionSessionPolicy({
          sessionId: session.id,
          targetPolicyVersionId: applied.policyVersion.id,
          expectedSessionHash: blocked.sessionHash,
        });
        assert.equal(result.previousSession.state, 'closed');
        assert.equal(result.replacementSession.state, 'open');
      }

      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
      assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'released');
      assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'rejected');
      assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes').reason_code,
        reasonCode);
      assert.equal(result.terminalReceipts.length, 1);
      assert.equal(result.terminalReceipts[0].receipt.receipt.outcome.reasonCode, reasonCode);
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('Slices A-B RED: session aggregates preserve a faulted authoritative deny decision', async (t) => {
  for (const command of ['close', 'transition']) {
    await t.test(command, async (st) => {
      const challenge = paymentRequired('1000001');
      const crash = new Error(`stop after deny decision for ${command}`);
      const context = setupKernel(st, {
        faultInjector(point) {
          if (point === 'after_challenge_commit') throw crash;
        },
        transport: Object.freeze({
          async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
          encodePayment() { throw new Error('must not encode'); },
          async retryPaid() { throw new Error('must not retry'); },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      await assert.rejects(context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`faulted-deny-${command}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-faulted-deny-${command}`,
      }), (error) => error === crash);
      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'challenged');
      const decision = context.store.readOne('SELECT decision, reason_code FROM policy_decisions');
      assert.equal(decision.decision, 'deny');
      assert.equal(decision.reason_code, 'PER_REQUEST_LIMIT');

      let result;
      if (command === 'close') {
        result = await context.kernel.closeSession({
          sessionId: session.id,
          expectedSessionHash: context.intents.getSession(session.id).sessionHash,
        });
        assert.equal(result.closedSession.state, 'closed');
      } else {
        const nextPolicy = structuredClone(context.policy);
        nextPolicy.sellers[0].autoApproveAtomic = '20000';
        const applied = await context.kernel.applyPolicy({
          document: nextPolicy,
          expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
        });
        const blocked = context.intents.getSession(session.id);
        result = await context.kernel.transitionSessionPolicy({
          sessionId: session.id,
          targetPolicyVersionId: applied.policyVersion.id,
          expectedSessionHash: blocked.sessionHash,
        });
        assert.equal(result.previousSession.state, 'closed');
      }

      assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
      const outcome = context.store.readOne('SELECT status, reason_code FROM buyer_outcomes');
      assert.equal(outcome.status, 'payment_denied');
      assert.equal(outcome.reason_code, 'PER_REQUEST_LIMIT');
      assert.equal(result.terminalReceipts.length, 1);
      assert.equal(result.terminalReceipts[0].receipt.receipt.policy.decision, 'deny');
      assert.equal(result.terminalReceipts[0].receipt.receipt.outcome.reasonCode,
        'PER_REQUEST_LIMIT');
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('Slice A RED: signing authority blocks both close and policy transition without mutation', async (t) => {
  const challenge = paymentRequired('50000');
  const crash = new Error('stop after signing claim');
  const context = setupKernel(t, {
    faultInjector(point) {
      if (point === 'after_signing_claim_commit') throw crash;
    },
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await assert.rejects(context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('session-signing-blocker'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-session-signing-blocker',
  }), (error) => error === crash);
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'signing');
  assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state, 'signing');
  let eventsBefore = context.store.events().length;

  await assert.rejects(
    context.kernel.closeSession({
      sessionId: session.id,
      expectedSessionHash: context.intents.getSession(session.id).sessionHash,
    }),
    (error) => error?.code === 'SESSION_CLOSE_BLOCKED',
  );
  assert.equal(context.store.events().length, eventsBefore);

  const nextPolicy = structuredClone(context.policy);
  nextPolicy.sellers[0].autoApproveAtomic = '20000';
  const applied = await context.kernel.applyPolicy({
    document: nextPolicy,
    expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
  });
  const blocked = context.intents.getSession(session.id);
  eventsBefore = context.store.events().length;
  await assert.rejects(
    context.kernel.transitionSessionPolicy({
      sessionId: session.id,
      targetPolicyVersionId: applied.policyVersion.id,
      expectedSessionHash: blocked.sessionHash,
    }),
    (error) => error?.code === 'SESSION_TRANSITION_BLOCKED',
  );
  assert.equal(context.store.events().length, eventsBefore);
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'signing');
  assert.equal(context.store.readOne('SELECT state FROM budget_reservations').state, 'reserved');
  assert.equal(context.store.readAll('SELECT * FROM buyer_outcomes').length, 0);
});

test('Slice A RED: all signed, ambiguous, and resolution states block session mutation', async (t) => {
  for (const scenario of [
    { name: 'signed', faultPoint: 'after_signed_payment_commit', paymentState: 'signed' },
    { name: 'retrying', faultPoint: 'after_retry_claim_commit', paymentState: 'retrying' },
    { name: 'unresolved', signerFailure: true, paymentState: 'unresolved' },
    { name: 'refund-pending', executionState: 'failed', paymentState: 'settled' },
    { name: 'execution-unknown', executionState: 'unknown', paymentState: 'settled' },
  ]) {
    await t.test(scenario.name, async (st) => {
      const challenge = paymentRequired('50000');
      const paymentPayload = signedPaymentPayload(challenge);
      const crash = new Error(`stop at ${scenario.name}`);
      const context = setupKernel(st, {
        faultInjector(point) {
          if (point === scenario.faultPoint) throw crash;
        },
        walletAdapter: Object.freeze({
          async walletIdentity() {
            return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
          },
          async signX402Exact() {
            if (scenario.signerFailure) throw new Error('ambiguous signer failure');
            return { paymentPayload };
          },
        }),
        transport: Object.freeze({
          async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
          encodePayment() { return `session-blocker-${scenario.name}`; },
          async retryPaid({ binding }) {
            const executionState = scenario.executionState ?? 'succeeded';
            return Object.freeze({
              kind: 'settled_response',
              settlement: Object.freeze({
                source: 'x402-payment-response',
                headerHash: sha256(Buffer.from(`session-blocker-${scenario.name}`, 'ascii')),
                success: true,
                transaction: `0x${'82'.repeat(32)}`,
                network: NETWORK,
                payer: WALLET,
                amountAtomic: '50000',
                paymentHash: binding.paymentHash,
              }),
              status: executionState === 'failed' ? 500 : 200,
              body: executionState === 'unknown' ? null : Buffer.from(scenario.name),
              executionState,
              ...(executionState === 'failed' ? { deliveryReason: 'HTTP_STATUS_FAILURE' } : {}),
              ...(executionState === 'unknown' ? { deliveryReason: 'BODY_DELIVERY_UNKNOWN' } : {}),
            });
          },
        }),
      });
      const session = await context.kernel.openOrResumeSession({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        walletAddress: WALLET,
        policyVersionId: context.activePolicy.id,
      });
      const execution = context.kernel.execute({
        sessionId: session.id,
        routeId: 'paid-infer',
        request: ordinaryRequest(`session-blocker-${scenario.name}`),
        purposeLabel: 'skill.invoke',
        correlationId: `pi-call-session-blocker-${scenario.name}`,
      });
      if (scenario.faultPoint) {
        await assert.rejects(execution, (error) => error === crash);
      } else {
        await execution;
      }
      assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state,
        scenario.paymentState);
      let eventsBefore = context.store.events().length;

      await assert.rejects(
        context.kernel.closeSession({
          sessionId: session.id,
          expectedSessionHash: context.intents.getSession(session.id).sessionHash,
        }),
        (error) => error?.code === (scenario.faultPoint
          ? 'RECEIPT_PARITY_REQUIRED'
          : 'SESSION_CLOSE_BLOCKED'),
      );
      assert.equal(context.store.events().length, eventsBefore);

      const nextPolicy = structuredClone(context.policy);
      nextPolicy.sellers[0].autoApproveAtomic = '20000';
      if (scenario.faultPoint) {
        await assert.rejects(
          context.kernel.applyPolicy({
            document: nextPolicy,
            expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
          }),
          (error) => error?.code === 'RECEIPT_PARITY_REQUIRED',
        );
        assert.equal(context.store.events().length, eventsBefore);
        assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state,
          scenario.paymentState);
        return;
      }
      const applied = await context.kernel.applyPolicy({
        document: nextPolicy,
        expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
      });
      const blocked = context.intents.getSession(session.id);
      eventsBefore = context.store.events().length;
      await assert.rejects(
        context.kernel.transitionSessionPolicy({
          sessionId: session.id,
          targetPolicyVersionId: applied.policyVersion.id,
          expectedSessionHash: blocked.sessionHash,
        }),
        (error) => error?.code === 'SESSION_TRANSITION_BLOCKED',
      );
      assert.equal(context.store.events().length, eventsBefore);
      assert.equal(context.store.readOne('SELECT state FROM payment_attempts').state,
        scenario.paymentState);
    });
  }
});

test('Slice A RED: a policy-blocked session rejects new admission before any probe', async (t) => {
  let probes = 0;
  const context = setupKernel(t, {
    transport: Object.freeze({
      async probe() { probes += 1; return { kind: 'response', status: 200, body: Buffer.from('no') }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const nextPolicy = structuredClone(context.policy);
  nextPolicy.sellers[0].autoApproveAtomic = '20000';
  await context.kernel.applyPolicy({
    document: nextPolicy,
    expectedPolicyHash: sha256(canonicalJson(nextPolicy)),
  });

  await assert.rejects(
    context.kernel.execute({
      sessionId: session.id,
      routeId: 'paid-infer',
      request: ordinaryRequest('blocked-before-probe'),
      purposeLabel: 'skill.invoke',
      correlationId: 'pi-call-blocked-before-probe',
    }),
    (error) => error?.code === 'SESSION_POLICY_BLOCKED',
  );
  assert.equal(probes, 0);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 0);
});

test('Slice A RED: operator approval sweeps an expired target before attempting its decision', async (t) => {
  const challenge = paymentRequired('50000');
  let currentTime = NOW;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock: () => currentTime,
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('operator-expiry-sweep'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-operator-expiry-sweep',
  });
  const approval = context.store.readOne('SELECT id, intent_hash, expires_at FROM approvals');
  currentTime = approval.expires_at;

  await assert.rejects(
    context.kernel.approvePending({
      approvalId: approval.id,
      expectedIntentHash: approval.intent_hash,
      operatorIdHash: OPERATOR_HASH,
    }),
    (error) => error?.code === 'APPROVAL_STATE_CONFLICT',
  );

  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'expired');
  assert.equal(context.store.readOne('SELECT state FROM spend_intents').state, 'terminal');
  assert.equal(context.store.readOne('SELECT reason_code FROM buyer_outcomes')
    .reason_code, 'APPROVAL_EXPIRED');
  assert.equal(context.store.readAll('SELECT * FROM signed_receipts').length, 1);
  assert.equal(context.receipts.assertParity(), true);
});

test('Slice A RED: status is sanitized, receipt-aware, and never sweeps an expired approval', async (t) => {
  const challenge = paymentRequired('50000');
  let currentTime = NOW;
  const context = setupKernel(t, {
    autoApproveAtomic: '10000',
    clock: () => currentTime,
    transport: Object.freeze({
      async probe() { return { kind: 'payment_required', paymentRequired: challenge }; },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('status-read-only'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-status-read-only',
  });
  const approval = context.store.readOne('SELECT intent_id, expires_at FROM approvals');
  currentTime = approval.expires_at;
  const eventsBefore = context.store.events().length;

  const status = context.kernel.status({
    sessionId: session.id,
    intentId: approval.intent_id,
  });

  assert.ok(Object.isFrozen(status));
  assert.deepEqual(Object.keys(status), [
    'sessionId',
    'intentId',
    'sessionState',
    'intentState',
    'approvalState',
    'budgetState',
    'paymentState',
    'outcome',
    'receipt',
  ]);
  assert.equal(status.sessionState, 'open');
  assert.equal(status.intentState, 'approval_pending');
  assert.equal(status.approvalState, 'pending');
  assert.equal(status.budgetState, null);
  assert.equal(status.paymentState, null);
  assert.equal(status.outcome, null);
  assert.equal(status.receipt, null);
  assert.equal(context.store.readOne('SELECT decision FROM approvals').decision, 'pending');
  assert.equal(context.store.events().length, eventsBefore);
});

test('Slice A RED: terminal status returns the exact receipt and rejects cross-session lookup', async (t) => {
  const context = setupKernel(t);
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const completed = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('terminal-status'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-terminal-status',
  });
  const intentId = context.store.readOne('SELECT id FROM spend_intents').id;
  const eventsBefore = context.store.events().length;

  const status = context.kernel.status({ sessionId: session.id, intentId });

  assert.equal(status.intentState, 'terminal');
  assert.equal(status.approvalState, null);
  assert.equal(status.budgetState, null);
  assert.equal(status.paymentState, null);
  assert.ok(Object.isFrozen(status.outcome));
  assert.deepEqual(status.outcome, {
    status: 'completed',
    reasonCode: 'ORDINARY_SUCCESS',
    revision: 1,
  });
  assert.equal(status.receipt.receiptHash, completed.receipt.receiptHash);
  assert.equal(context.store.events().length, eventsBefore);

  await context.kernel.closeSession({
    sessionId: session.id,
    expectedSessionHash: context.intents.getSession(session.id).sessionHash,
  });
  const restarted = await context.createKernel().openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  assert.throws(
    () => context.kernel.status({ sessionId: restarted.id, intentId }),
    (error) => error?.code === 'INTENT_SESSION_MISMATCH',
  );
  assert.throws(
    () => context.kernel.status({ sessionId: session.id, intentId: 'intent-missing' }),
    (error) => error?.code === 'INTENT_UNKNOWN',
  );
});

test('agent-scoped public status resolves request and receipt IDs without internal authority IDs', async (t) => {
  const context = setupKernel(t);
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const completed = await context.kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('public-status'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-public-status',
  });

  const byRequest = context.kernel.statusByRequestId({
    sessionId: session.id,
    requestId: completed.requestId,
  });
  assert.deepEqual(Object.keys(byRequest), [
    'requestId', 'sellerOrigin', 'purposeLabel', 'intentState',
    'approval', 'outcome', 'receipt', 'remainingSessionAtomic',
  ]);
  assert.equal(byRequest.requestId, completed.requestId);
  assert.equal(byRequest.sellerOrigin, SELLER);
  assert.equal(byRequest.purposeLabel, 'skill.invoke');
  assert.equal(byRequest.intentState, 'terminal');
  assert.equal(byRequest.approval, null);
  assert.equal(byRequest.outcome.status, 'completed');
  assert.equal(byRequest.receipt.receiptHash, completed.receipt.receiptHash);
  assert.equal(byRequest.remainingSessionAtomic, context.activePolicy.policy.sessionMaxAtomic);
  assert.equal(Object.hasOwn(byRequest, 'sessionId'), false);
  assert.equal(Object.hasOwn(byRequest, 'intentId'), false);

  const byReceipt = context.kernel.receiptById({
    sessionId: session.id,
    receiptId: completed.receipt.receipt.receiptId,
  });
  assert.deepEqual(byReceipt, byRequest);
  assert.equal(context.kernel.statusByRequestId({
    sessionId: session.id,
    requestId: 'request-missing',
  }), null);
  assert.equal(context.kernel.receiptById({
    sessionId: session.id,
    receiptId: 'receipt-missing',
  }), null);
});

test('Slice B RED: exact terminal correlation replays only persisted sanitized facts', async (t) => {
  let probes = 0;
  let signerCalls = 0;
  let paidRetries = 0;
  const context = setupKernel(t, {
    walletAdapter: Object.freeze({
      async walletIdentity() {
        return { provider: 'deterministic', walletId: 'wallet-1', address: WALLET, network: NETWORK };
      },
      async signX402Exact() { signerCalls += 1; throw new Error('must not sign'); },
    }),
    transport: Object.freeze({
      async probe() {
        probes += 1;
        return { kind: 'response', status: 200, body: Buffer.from(`ok-${probes}`) };
      },
      encodePayment() { throw new Error('must not encode'); },
      async retryPaid() { paidRetries += 1; throw new Error('must not retry'); },
    }),
  });
  const session = await context.kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  const call = {
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest('terminal-correlation'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-terminal-correlation',
  };
  const first = await context.kernel.execute(call);
  const eventsBeforeReplay = context.store.events().length;

  const replay = await context.kernel.execute(call);

  assert.deepEqual(Object.keys(replay), ['requestId', 'status', 'reasonCode', 'receipt']);
  assert.equal(replay.requestId, first.requestId);
  assert.equal(replay.status, first.status);
  assert.equal(replay.reasonCode, first.reasonCode);
  assert.equal(replay.receipt.receiptHash, first.receipt.receiptHash);
  assert.equal(probes, 1);
  assert.equal(signerCalls, 0);
  assert.equal(paidRetries, 0);
  assert.equal(context.store.events().length, eventsBeforeReplay);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 1);

  await assert.rejects(
    context.kernel.execute({
      ...call,
      request: ordinaryRequest('terminal-correlation-mismatch'),
    }),
    (error) => error?.code === 'CORRELATION_CONFLICT',
  );
  assert.equal(probes, 1);
  assert.equal(context.store.events().length, eventsBeforeReplay);

  const fresh = await context.kernel.execute({
    ...call,
    correlationId: 'pi-call-terminal-correlation-fresh',
  });
  assert.notEqual(fresh.requestId, first.requestId);
  assert.equal(fresh.status, 'completed');
  assert.equal(probes, 2);
  assert.equal(signerCalls, 0);
  assert.equal(paidRetries, 0);
  assert.equal(context.store.readAll('SELECT * FROM spend_intents').length, 2);
  assert.equal(context.receipts.assertParity(), true);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  createOperatorApp,
  projectOperatorPublicResult,
} from '../src/operator/api.mjs';
import { createOperatorAuth } from '../src/operator/auth.mjs';
import {
  canonicalJson,
  KernelError,
  sha256,
} from '../src/kernel/canonical.mjs';
import { validatePolicyDocument } from '../src/kernel/policy-engine.mjs';

const ORIGIN = 'http://127.0.0.1:8405';
const WALLET = '0x1000000000000000000000000000000000000000';
const OPERATOR_HASH = `sha256:${'11'.repeat(32)}`;
const INTENT_HASH = `sha256:${'22'.repeat(32)}`;
const CASE_HASH = `sha256:${'33'.repeat(32)}`;
const POLICY_HASH = `sha256:${'44'.repeat(32)}`;
const SESSION_HASH = `sha256:${'55'.repeat(32)}`;
const ENROLLMENT_HASH = `sha256:${'66'.repeat(32)}`;
const PAYMENT_TRANSACTION = `0x${'ab'.repeat(32)}`;
const REFUND_TRANSACTION = `0x${'cd'.repeat(32)}`;

const POLICY = Object.freeze({
  schemaVersion: 1,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  wallet: WALLET,
  methods: Object.freeze(['GET', 'POST']),
  sellers: Object.freeze([Object.freeze({
    origin: 'https://seller.example',
    pathPrefixes: Object.freeze(['/paid/']),
    payTo: '0x2000000000000000000000000000000000000000',
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: '0x2000000000000000000000000000000000000000',
    refundSigner: '0x2000000000000000000000000000000000000000',
    refundSource: '0x3000000000000000000000000000000000000000',
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  })]),
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60_000,
  approvalTtlMs: 300_000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
});

const SERVICE_NAMES = Object.freeze([
  'overview',
  'listPolicies',
  'walletIdentity',
  'applyPolicy',
  'revokeAgent',
  'transitionSessionPolicy',
  'closeSession',
  'listApprovals',
  'approvePending',
  'denyPending',
  'listReceipts',
  'getReceipt',
  'reconcilePayment',
  'reconcileExecution',
  'reconcileRefundObservation',
  'abandonCandidate',
  'exportSession',
  'receiptPublicKey',
]);

function requestHeaders(channel, { mutation = false } = {}) {
  if (channel === 'admin') return { authorization: 'Bearer owner-secret' };
  return {
    cookie: 'wallet_kernel_session=browser-session',
    ...(mutation ? { origin: ORIGIN, 'x-csrf-token': 'csrf-value' } : {}),
  };
}

function jsonInit(value, channel = 'admin') {
  return {
    method: 'POST',
    headers: {
      ...requestHeaders(channel, { mutation: true }),
      'content-type': 'application/json',
    },
    body: canonicalJson(value),
  };
}

function createAuthFake(calls, overrides = {}) {
  const principal = Object.freeze({ operatorIdHash: OPERATOR_HASH });
  const unauthorized = () => {
    throw new KernelError('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
  };
  return Object.freeze(Object.assign({
    authenticateBearer(request, options) {
      calls.push(Object.freeze({ name: 'authenticateBearer', options }));
      if (request.headers.get('authorization') !== 'Bearer owner-secret'
          || request.headers.has('cookie')) unauthorized();
      return principal;
    },
    authenticateBrowser(request, options) {
      calls.push(Object.freeze({ name: 'authenticateBrowser', options }));
      if (request.headers.get('cookie') !== 'wallet_kernel_session=browser-session'
          || request.headers.has('authorization')) unauthorized();
      if (options.mutation
          && (request.headers.get('origin') !== ORIGIN
            || request.headers.get('x-csrf-token') !== 'csrf-value')) unauthorized();
      return principal;
    },
    issueBrowserLaunch(options) {
      calls.push(Object.freeze({ name: 'issueBrowserLaunch', options }));
      return Object.freeze({
        url: `${ORIGIN}/operator/#launch=${'A'.repeat(43)}`,
        expiresAt: '2026-08-01T12:01:00.000Z',
      });
    },
    exchangeBrowserSession(request) {
      calls.push(Object.freeze({ name: 'exchangeBrowserSession', request }));
      return new Response(null, {
        status: 204,
        headers: {
          'cache-control': 'no-store',
          'set-cookie': 'wallet_kernel_session=session; HttpOnly; SameSite=Strict; Path=/operator',
          'x-csrf-token': 'csrf-value',
        },
      });
    },
    revokeBrowserSession(request) {
      calls.push(Object.freeze({ name: 'revokeBrowserSession', request }));
      return new Response(null, { status: 204, headers: { 'cache-control': 'no-store' } });
    },
  }, overrides));
}

function createServicesFake(calls, overrides = {}) {
  const services = {};
  for (const name of SERVICE_NAMES) {
    services[name] = async (input = {}) => {
      calls.push(Object.freeze({ name, input }));
      return Object.freeze({ operation: name, accepted: true });
    };
  }
  services.walletIdentity = async (input = {}) => {
    calls.push(Object.freeze({ name: 'walletIdentity', input }));
    return Object.freeze({ address: WALLET });
  };
  return Object.freeze(Object.assign(services, overrides));
}

function harness({
  mode = 'deterministic',
  transport = 'loopback-demo',
  serviceOverrides = {},
  authOverrides = {},
  bodyLimits = { jsonBytes: 65_536 },
} = {}) {
  const authCalls = [];
  const serviceCalls = [];
  const auth = createAuthFake(authCalls, authOverrides);
  const services = createServicesFake(serviceCalls, serviceOverrides);
  const app = createOperatorApp({
    auth,
    services,
    bodyLimits,
    mode,
    transport,
    origin: ORIGIN,
  });
  return Object.freeze({ app, auth, services, authCalls, serviceCalls });
}

async function operatorRequest(app, pathname, init = {}, channel = 'admin') {
  const headers = new Headers(init.headers ?? requestHeaders(channel, {
    mutation: init.method !== undefined && init.method !== 'GET',
  }));
  const response = await app.request(`${ORIGIN}${pathname}`, { ...init, headers });
  return response;
}

async function successData(response, status = 200) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(response.headers.get('content-type'), 'application/json');
  const payload = await response.json();
  assert.deepEqual(Object.keys(payload), ['ok', 'data']);
  assert.equal(payload.ok, true);
  return payload.data;
}

async function errorCode(response, status) {
  assert.equal(response.status, status);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const payload = await response.json();
  assert.deepEqual(Object.keys(payload), ['ok', 'error']);
  assert.equal(payload.ok, false);
  assert.deepEqual(Object.keys(payload.error), ['code', 'message']);
  return payload.error.code;
}

test('constructor accepts only the narrow inert dependency and channel surfaces', () => {
  const value = harness();
  assert.equal(typeof value.app.request, 'function');
  assert.equal(typeof createOperatorApp({
    auth: value.auth,
    services: value.services,
    bodyLimits: { jsonBytes: 65_536 },
    mode: 'deterministic',
    transport: 'loopback-demo',
    origin: 'http://127.0.0.1:49152',
  }).request, 'function');
  assert.throws(() => createOperatorApp({
    auth: value.auth,
    services: value.services,
    bodyLimits: { jsonBytes: 65_536 },
    mode: 'cdp-testnet',
    transport: 'socket-activated-loopback',
    origin: 'http://127.0.0.1:49152',
  }), TypeError);

  assert.throws(() => createOperatorApp({
    auth: value.auth,
    services: { ...value.services, store: {} },
    bodyLimits: { jsonBytes: 65_536 },
    mode: 'deterministic',
    transport: 'loopback-demo',
    origin: ORIGIN,
  }), TypeError);
  assert.throws(() => createOperatorApp({
    auth: value.auth,
    services: value.services,
    bodyLimits: { jsonBytes: 65_536, evidenceBytes: 1 },
    mode: 'deterministic',
    transport: 'loopback-demo',
    origin: ORIGIN,
  }), TypeError);
  for (const [mode, transport] of [
    ['cdp-testnet', 'loopback-demo'],
    ['deterministic', 'unix'],
    ['deterministic', 'socket-activated-loopback'],
    ['cdp-testnet', 'tcp'],
    ['other', 'socket-activated-loopback'],
  ]) {
    assert.throws(() => createOperatorApp({
      auth: value.auth,
      services: value.services,
      bodyLimits: { jsonBytes: 65_536 },
      mode,
      transport,
      origin: ORIGIN,
    }), TypeError);
  }
});

test('route table contains only the exact documented methods and paths', () => {
  const { app } = harness();
  assert.deepEqual(
    app.routes.map(({ method, path }) => `${method} ${path}`).sort(),
    [
      'DELETE /operator/v1/session',
      'GET /operator/v1/approvals',
      'GET /operator/v1/exports/:sessionId',
      'GET /operator/v1/overview',
      'GET /operator/v1/policies',
      'GET /operator/v1/receipt-public-key',
      'GET /operator/v1/receipts',
      'GET /operator/v1/receipts/:receiptId',
      'POST /operator/v1/agents/:agentInstanceId/revoke',
      'POST /operator/v1/approvals/:approvalId/approve',
      'POST /operator/v1/approvals/:approvalId/deny',
      'POST /operator/v1/browser-launch',
      'POST /operator/v1/policies/apply',
      'POST /operator/v1/policies/validate',
      'POST /operator/v1/reconciliations/:intentId/:kind',
      'POST /operator/v1/reconciliations/:intentId/:kind/abandon-candidate',
      'POST /operator/v1/session',
      'POST /operator/v1/sessions/:sessionId/close',
      'POST /operator/v1/sessions/:sessionId/transition-policy',
      'ALL /*',
    ].sort(),
  );
});

test('a malformed principal returned by auth remains an authentication failure', async () => {
  const value = harness({
    authOverrides: {
      authenticateBearer() {
        return Object.freeze({ operatorIdHash: 'not-a-hash' });
      },
    },
  });
  assert.equal(await errorCode(await operatorRequest(
    value.app,
    '/operator/v1/overview',
  ), 401), 'OPERATOR_UNAUTHORIZED');
  assert.deepEqual(value.serviceCalls, []);
});

test('admin-only browser launch authenticates bearer first and accepts no body or query', async () => {
  const value = harness();
  const response = await operatorRequest(value.app, '/operator/v1/browser-launch', {
    method: 'POST',
  });
  assert.deepEqual(await successData(response), {
    url: `${ORIGIN}/operator/#launch=${'A'.repeat(43)}`,
    expiresAt: '2026-08-01T12:01:00.000Z',
  });
  assert.deepEqual(value.authCalls.map(({ name }) => name), [
    'authenticateBearer',
    'issueBrowserLaunch',
  ]);
  assert.deepEqual(value.authCalls[0].options, { transport: 'loopback-demo' });
  assert.deepEqual(value.authCalls[1].options, { transport: 'loopback-demo' });

  const cookieOnly = await operatorRequest(value.app, '/operator/v1/browser-launch', {
    method: 'POST',
    headers: requestHeaders('console', { mutation: true }),
  });
  assert.equal(await errorCode(cookieOnly, 401), 'OPERATOR_UNAUTHORIZED');
  assert.equal(await errorCode(await operatorRequest(
    value.app,
    '/operator/v1/browser-launch?next=x',
    { method: 'POST' },
  ), 400), 'OPERATOR_QUERY_SCHEMA');
  assert.equal(await errorCode(await operatorRequest(
    value.app,
    '/operator/v1/browser-launch',
    jsonInit({}, 'admin'),
  ), 400), 'OPERATOR_BODY_FORBIDDEN');
});

test('loopback demo carries both channels while live session routes remain console-only', async () => {
  const value = harness();
  const exchange = await operatorRequest(value.app, '/operator/v1/session', {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: canonicalJson({ launchToken: 'A'.repeat(43) }),
  }, 'console');
  assert.equal(exchange.status, 204);
  assert.match(exchange.headers.get('set-cookie'), /^wallet_kernel_session=/);

  const deletion = await operatorRequest(value.app, '/operator/v1/session', {
    method: 'DELETE',
    headers: requestHeaders('console', { mutation: true }),
  }, 'console');
  assert.equal(deletion.status, 204);
  assert.deepEqual(value.authCalls.map(({ name }) => name), [
    'exchangeBrowserSession',
    'revokeBrowserSession',
  ]);

  const admin = harness({ mode: 'cdp-testnet', transport: 'unix' });
  assert.equal(await errorCode(await operatorRequest(
    admin.app,
    '/operator/v1/session',
    jsonInit({ launchToken: 'A'.repeat(43) }),
  ), 401), 'OPERATOR_UNAUTHORIZED');
  const liveConsole = harness({
    mode: 'cdp-testnet',
    transport: 'socket-activated-loopback',
  });
  assert.equal(await errorCode(await operatorRequest(
    liveConsole.app,
    '/operator/v1/browser-launch',
    { method: 'POST', headers: requestHeaders('console', { mutation: true }) },
    'console',
  ), 401), 'OPERATOR_UNAUTHORIZED');
});

test('read routes expose only the injected projections with exact query handling', async () => {
  const value = harness();
  const cases = [
    ['/operator/v1/overview', 'overview', {}],
    ['/operator/v1/policies', 'listPolicies', {}],
    ['/operator/v1/approvals', 'listApprovals', { state: null }],
    ['/operator/v1/approvals?state=pending', 'listApprovals', { state: 'pending' }],
    ['/operator/v1/approvals?state=approved', 'listApprovals', { state: 'approved' }],
    ['/operator/v1/approvals?state=denied', 'listApprovals', { state: 'denied' }],
    ['/operator/v1/approvals?state=expired', 'listApprovals', { state: 'expired' }],
    ['/operator/v1/approvals?state=cancelled', 'listApprovals', { state: 'cancelled' }],
    ['/operator/v1/receipts', 'listReceipts', {}],
    ['/operator/v1/receipts/receipt-1', 'getReceipt', { receiptId: 'receipt-1' }],
    ['/operator/v1/exports/session-1', 'exportSession', { sessionId: 'session-1' }],
    ['/operator/v1/receipt-public-key', 'receiptPublicKey', {}],
  ];
  for (const [pathname, name, input] of cases) {
    value.serviceCalls.length = 0;
    const data = await successData(await operatorRequest(value.app, pathname));
    assert.deepEqual(data, { operation: name, accepted: true });
    assert.deepEqual(value.serviceCalls, [{ name, input }]);
  }

  for (const pathname of [
    '/operator/v1/overview?state=pending',
    '/operator/v1/approvals?state=unknown',
    '/operator/v1/approvals?state=pending&state=pending',
    '/operator/v1/approvals?limit=10',
    '/operator/v1/receipts?page=1',
    '/operator/v1/receipts/not%2Fcanonical',
  ]) {
    value.serviceCalls.length = 0;
    assert.equal(
      await errorCode(await operatorRequest(value.app, pathname), 400),
      pathname.includes('not%2Fcanonical') ? 'OPERATOR_IDENTIFIER' : 'OPERATOR_QUERY_SCHEMA',
      pathname,
    );
    assert.deepEqual(value.serviceCalls, [], pathname);
  }
});

test('policy validation normalizes public policy and apply revalidates the confirmed bytes', async () => {
  const value = harness();
  const noncanonical = structuredClone(POLICY);
  noncanonical.wallet = WALLET.toUpperCase().replace('0X', '0x');
  noncanonical.sellers[0].origin = 'https://seller.example:443';
  const normalized = validatePolicyDocument(noncanonical);
  const displayedHash = sha256(canonicalJson(normalized));

  const validation = await successData(await operatorRequest(
    value.app,
    '/operator/v1/policies/validate',
    jsonInit({ document: noncanonical }),
  ));
  assert.deepEqual(validation, { policy: normalized, policyHash: displayedHash });
  assert.deepEqual(value.serviceCalls, []);

  const applied = await successData(await operatorRequest(
    value.app,
    '/operator/v1/policies/apply',
    jsonInit({ document: noncanonical, expectedPolicyHash: displayedHash }),
  ));
  assert.deepEqual(applied, { operation: 'applyPolicy', accepted: true });
  assert.deepEqual(value.serviceCalls, [
    { name: 'walletIdentity', input: {} },
    {
      name: 'applyPolicy',
      input: { document: normalized, expectedPolicyHash: displayedHash },
    },
  ]);

  value.serviceCalls.length = 0;
  assert.equal(await errorCode(await operatorRequest(
    value.app,
    '/operator/v1/policies/apply',
    jsonInit({ document: noncanonical, expectedPolicyHash: POLICY_HASH }),
  ), 409), 'POLICY_CONFIRMATION_STALE');
  assert.deepEqual(value.serviceCalls, []);

  const rotated = harness({
    serviceOverrides: {
      async walletIdentity() { return { address: '0x9000000000000000000000000000000000000000' }; },
    },
  });
  assert.equal(await errorCode(await operatorRequest(
    rotated.app,
    '/operator/v1/policies/apply',
    jsonInit({ document: POLICY, expectedPolicyHash: sha256(canonicalJson(POLICY)) }),
  ), 409), 'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART');
  assert.equal(rotated.serviceCalls.some(({ name }) => name === 'applyPolicy'), false);
});

test('agent, session, and approval mutations call only their narrow aggregate services', async () => {
  const value = harness();
  const cases = [
    {
      path: '/operator/v1/agents/agent-1/revoke',
      body: { expectedEnrollmentHash: ENROLLMENT_HASH },
      service: 'revokeAgent',
      input: {
        agentInstanceId: 'agent-1',
        expectedEnrollmentHash: ENROLLMENT_HASH,
        operatorIdHash: OPERATOR_HASH,
      },
    },
    {
      path: '/operator/v1/sessions/session-1/transition-policy',
      body: { targetPolicyHash: POLICY_HASH, expectedSessionHash: SESSION_HASH },
      service: 'transitionSessionPolicy',
      input: {
        sessionId: 'session-1',
        targetPolicyHash: POLICY_HASH,
        expectedSessionHash: SESSION_HASH,
      },
    },
    {
      path: '/operator/v1/sessions/session-1/close',
      body: { expectedSessionHash: SESSION_HASH },
      service: 'closeSession',
      input: { sessionId: 'session-1', expectedSessionHash: SESSION_HASH },
    },
    {
      path: '/operator/v1/approvals/approval-1/approve',
      body: { expectedIntentHash: INTENT_HASH },
      service: 'approvePending',
      input: {
        approvalId: 'approval-1',
        expectedIntentHash: INTENT_HASH,
        operatorIdHash: OPERATOR_HASH,
      },
    },
    {
      path: '/operator/v1/approvals/approval-1/deny',
      body: { expectedIntentHash: INTENT_HASH, reasonCode: 'OPERATOR_DENIED' },
      service: 'denyPending',
      input: {
        approvalId: 'approval-1',
        expectedIntentHash: INTENT_HASH,
        operatorIdHash: OPERATOR_HASH,
        reasonCode: 'OPERATOR_DENIED',
      },
    },
  ];

  for (const item of cases) {
    value.serviceCalls.length = 0;
    const data = await successData(await operatorRequest(value.app, item.path, jsonInit(item.body)));
    assert.deepEqual(data, { operation: item.service, accepted: true });
    assert.deepEqual(value.serviceCalls, [{ name: item.service, input: item.input }]);
  }

  for (const [path, body] of [
    ['/operator/v1/agents/agent-1/revoke', {
      expectedEnrollmentHash: ENROLLMENT_HASH, sessionId: 'session-1',
    }],
    ['/operator/v1/sessions/session-1/transition-policy', {
      targetPolicyHash: POLICY_HASH, expectedSessionHash: SESSION_HASH, wallet: WALLET,
    }],
    ['/operator/v1/sessions/session-1/close', {
      expectedSessionHash: SESSION_HASH, replace: true,
    }],
    ['/operator/v1/approvals/approval-1/approve', {
      expectedIntentHash: INTENT_HASH, amountAtomic: '1',
    }],
    ['/operator/v1/approvals/approval-1/deny', {
      expectedIntentHash: INTENT_HASH, reasonCode: 'CUSTOM_REASON',
    }],
  ]) {
    value.serviceCalls.length = 0;
    assert.equal(
      await errorCode(await operatorRequest(value.app, path, jsonInit(body)), 400),
      path.endsWith('/deny') ? 'APPROVAL_DENIAL_REASON' : 'OPERATOR_BODY_SCHEMA',
      path,
    );
    assert.deepEqual(value.serviceCalls, [], path);
  }
});

test('reconciliation accepts only displayed hashes and the one allowed public candidate', async () => {
  const value = harness();
  const cases = [
    {
      kind: 'payment',
      body: { expectedIntentHash: INTENT_HASH, expectedCaseHash: CASE_HASH },
      service: 'reconcilePayment',
      input: {
        intentId: 'intent-1',
        operatorIdHash: OPERATOR_HASH,
        expectedIntentHash: INTENT_HASH,
        expectedPaymentCaseHash: CASE_HASH,
        paymentTransactionId: null,
      },
    },
    {
      kind: 'payment',
      body: {
        expectedIntentHash: INTENT_HASH,
        expectedCaseHash: CASE_HASH,
        paymentTransactionId: PAYMENT_TRANSACTION,
      },
      service: 'reconcilePayment',
      input: {
        intentId: 'intent-1',
        operatorIdHash: OPERATOR_HASH,
        expectedIntentHash: INTENT_HASH,
        expectedPaymentCaseHash: CASE_HASH,
        paymentTransactionId: PAYMENT_TRANSACTION,
      },
    },
    {
      kind: 'execution',
      body: { expectedIntentHash: INTENT_HASH, expectedCaseHash: CASE_HASH },
      service: 'reconcileExecution',
      input: {
        intentId: 'intent-1',
        operatorIdHash: OPERATOR_HASH,
        expectedIntentHash: INTENT_HASH,
        expectedExecutionCaseHash: CASE_HASH,
      },
    },
    {
      kind: 'refund-observation',
      body: {
        expectedIntentHash: INTENT_HASH,
        expectedCaseHash: CASE_HASH,
        refundTransactionId: REFUND_TRANSACTION,
      },
      service: 'reconcileRefundObservation',
      input: {
        intentId: 'intent-1',
        operatorIdHash: OPERATOR_HASH,
        expectedIntentHash: INTENT_HASH,
        expectedRefundCaseHash: CASE_HASH,
        refundTransactionId: REFUND_TRANSACTION,
      },
    },
  ];
  for (const item of cases) {
    value.serviceCalls.length = 0;
    const data = await successData(await operatorRequest(
      value.app,
      `/operator/v1/reconciliations/intent-1/${item.kind}`,
      jsonInit(item.body),
    ));
    assert.deepEqual(data, { operation: item.service, accepted: true });
    assert.deepEqual(value.serviceCalls, [{ name: item.service, input: item.input }]);
  }

  for (const [kind, body] of [
    ['unknown', { expectedIntentHash: INTENT_HASH, expectedCaseHash: CASE_HASH }],
    ['execution', {
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
      transactionId: PAYMENT_TRANSACTION,
    }],
    ['payment', {
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
      evidence: { status: 'success' },
    }],
    ['refund-observation', {
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
    }],
    ['payment', {
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
      paymentTransactionId: PAYMENT_TRANSACTION.toUpperCase().replace('0X', '0x'),
    }],
  ]) {
    value.serviceCalls.length = 0;
    const response = await operatorRequest(
      value.app,
      `/operator/v1/reconciliations/intent-1/${kind}`,
      jsonInit(body),
    );
    assert.equal(await errorCode(response, 400),
      kind === 'unknown' ? 'RECONCILIATION_KIND' : 'OPERATOR_BODY_SCHEMA');
    assert.deepEqual(value.serviceCalls, []);
  }
});

test('candidate abandonment is closed to payment and refund observation and keeps evidence out', async () => {
  const value = harness();
  for (const kind of ['payment', 'refund-observation']) {
    value.serviceCalls.length = 0;
    const input = {
      intentId: 'intent-1',
      kind,
      operatorIdHash: OPERATOR_HASH,
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
    };
    const data = await successData(await operatorRequest(
      value.app,
      `/operator/v1/reconciliations/intent-1/${kind}/abandon-candidate`,
      jsonInit({ expectedIntentHash: INTENT_HASH, expectedCaseHash: CASE_HASH }),
    ));
    assert.deepEqual(data, { operation: 'abandonCandidate', accepted: true });
    assert.deepEqual(value.serviceCalls, [{ name: 'abandonCandidate', input }]);
  }
  for (const [kind, body] of [
    ['execution', { expectedIntentHash: INTENT_HASH, expectedCaseHash: CASE_HASH }],
    ['payment', {
      expectedIntentHash: INTENT_HASH,
      expectedCaseHash: CASE_HASH,
      paymentTransactionId: PAYMENT_TRANSACTION,
    }],
  ]) {
    value.serviceCalls.length = 0;
    assert.equal(await errorCode(await operatorRequest(
      value.app,
      `/operator/v1/reconciliations/intent-1/${kind}/abandon-candidate`,
      jsonInit(body),
    ), 400), kind === 'execution' ? 'RECONCILIATION_KIND' : 'OPERATOR_BODY_SCHEMA');
    assert.deepEqual(value.serviceCalls, []);
  }
});

test('live channels are exclusive and deterministic loopback selects bearer or browser auth', async () => {
  const admin = harness({ mode: 'cdp-testnet', transport: 'unix' });
  const adminCookie = await operatorRequest(admin.app, '/operator/v1/overview', {
    headers: requestHeaders('console'),
  });
  assert.equal(await errorCode(adminCookie, 401), 'OPERATOR_UNAUTHORIZED');
  assert.equal(admin.serviceCalls.length, 0);

  const consoleValue = harness({
    mode: 'cdp-testnet',
    transport: 'socket-activated-loopback',
  });
  const read = await operatorRequest(consoleValue.app, '/operator/v1/overview', {
    headers: requestHeaders('console'),
  }, 'console');
  await successData(read);
  assert.deepEqual(consoleValue.authCalls.at(-1), {
    name: 'authenticateBrowser',
    options: { mutation: false },
  });

  consoleValue.serviceCalls.length = 0;
  const mutation = await operatorRequest(
    consoleValue.app,
    '/operator/v1/approvals/approval-1/approve',
    jsonInit({ expectedIntentHash: INTENT_HASH }, 'console'),
    'console',
  );
  await successData(mutation);
  assert.deepEqual(consoleValue.authCalls.at(-1), {
    name: 'authenticateBrowser',
    options: { mutation: true },
  });

  const bearer = await operatorRequest(consoleValue.app, '/operator/v1/overview', {
    headers: requestHeaders('admin'),
  }, 'console');
  assert.equal(await errorCode(bearer, 401), 'OPERATOR_UNAUTHORIZED');

  const demo = harness();
  await successData(await operatorRequest(demo.app, '/operator/v1/overview'));
  assert.deepEqual(demo.authCalls.at(-1), {
    name: 'authenticateBearer',
    options: { transport: 'loopback-demo' },
  });
  await successData(await operatorRequest(demo.app, '/operator/v1/overview', {
    headers: requestHeaders('console'),
  }, 'console'));
  assert.deepEqual(demo.authCalls.at(-1), {
    name: 'authenticateBrowser',
    options: { mutation: false },
  });
});

test('mutation JSON is read with a byte bound and must be exact canonical closed data', async () => {
  const value = harness({ bodyLimits: { jsonBytes: 256 } });
  for (const [label, init, code] of [
    ['wrong content type', {
      method: 'POST',
      headers: { ...requestHeaders('admin'), 'content-type': 'text/plain' },
      body: canonicalJson({ expectedIntentHash: INTENT_HASH }),
    }, 'OPERATOR_CONTENT_TYPE'],
    ['noncanonical whitespace', {
      method: 'POST',
      headers: { ...requestHeaders('admin'), 'content-type': 'application/json' },
      body: ` ${canonicalJson({ expectedIntentHash: INTENT_HASH })}`,
    }, 'OPERATOR_BODY_SCHEMA'],
    ['duplicate key', {
      method: 'POST',
      headers: { ...requestHeaders('admin'), 'content-type': 'application/json' },
      body: `{"expectedIntentHash":"${INTENT_HASH}","expectedIntentHash":"${INTENT_HASH}"}`,
    }, 'OPERATOR_BODY_SCHEMA'],
    ['oversized declared body', {
      method: 'POST',
      headers: {
        ...requestHeaders('admin'),
        'content-type': 'application/json',
        'content-length': '999',
      },
      body: canonicalJson({ expectedIntentHash: INTENT_HASH }),
    }, 'OPERATOR_BODY_TOO_LARGE'],
    ['oversized streamed body', {
      method: 'POST',
      headers: { ...requestHeaders('admin'), 'content-type': 'application/json' },
      body: canonicalJson({
        expectedIntentHash: INTENT_HASH,
        padding: 'x'.repeat(300),
      }),
    }, 'OPERATOR_BODY_TOO_LARGE'],
  ]) {
    value.serviceCalls.length = 0;
    const response = await operatorRequest(
      value.app,
      '/operator/v1/approvals/approval-1/approve',
      init,
    );
    assert.equal(await errorCode(response, code === 'OPERATOR_BODY_TOO_LARGE' ? 413 : 400), code, label);
    assert.deepEqual(value.serviceCalls, [], label);
  }
});

test('unknown paths, methods, identifiers, and agent/operator credential crossover fail closed', async () => {
  const value = harness();
  const changedOrigin = await value.app.request(
    'http://127.0.0.1:8406/operator/v1/overview',
    { headers: requestHeaders('admin') },
  );
  assert.equal(await errorCode(changedOrigin, 401), 'OPERATOR_UNAUTHORIZED');
  assert.deepEqual(value.serviceCalls, []);
  const implicitHead = await operatorRequest(value.app, '/operator/v1/overview', {
    method: 'HEAD',
  });
  assert.equal(implicitHead.status, 404);
  assert.deepEqual(value.serviceCalls, []);
  for (const [pathname, init, expected] of [
    ['/operator/v1/not-a-route', {}, 404],
    ['/operator/v1/overview/', {}, 404],
    ['/operator/v1/overview', { method: 'POST' }, 404],
    ['/operator/v1/receipts/bad%20id', {}, 400],
    ['/operator/v1/agents/-bad/revoke', jsonInit({ expectedEnrollmentHash: ENROLLMENT_HASH }), 400],
    ['/agent/v1/status', { headers: requestHeaders('admin') }, 404],
  ]) {
    value.serviceCalls.length = 0;
    const response = await operatorRequest(value.app, pathname, init);
    assert.equal(response.status, expected, pathname);
    const payload = await response.json();
    assert.equal(payload.ok, false, pathname);
    assert.deepEqual(value.serviceCalls, [], pathname);
  }

  const agentCredential = await operatorRequest(value.app, '/operator/v1/overview', {
    headers: { authorization: 'Bearer agent-capability' },
  });
  assert.equal(await errorCode(agentCredential, 401), 'OPERATOR_UNAUTHORIZED');
  assert.equal(value.serviceCalls.length, 0);

  const nodeStyleEmpty = await operatorRequest(value.app, '/operator/v1/browser-launch', {
    method: 'POST',
    headers: { ...requestHeaders('admin'), 'content-length': '0' },
  });
  assert.equal(nodeStyleEmpty.status, 200);
});

test('service KernelErrors preserve stable public codes while unexpected errors are redacted', async () => {
  const kernelSecret = 'kernel-provider-secret-that-must-not-escape';
  const conflict = harness({
    serviceOverrides: {
      async closeSession() {
        throw new KernelError('SESSION_STATE_CONFLICT', kernelSecret);
      },
    },
  });
  const response = await operatorRequest(
    conflict.app,
    '/operator/v1/sessions/session-1/close',
    jsonInit({ expectedSessionHash: SESSION_HASH }),
  );
  const conflictInspection = response.clone();
  assert.equal(await errorCode(response, 409), 'SESSION_STATE_CONFLICT');
  assert.equal((await conflictInspection.text()).includes(kernelSecret), false);

  const unhealthy = harness({
    serviceOverrides: {
      async overview() {
        throw new KernelError('AUTHORITY_UNHEALTHY', kernelSecret);
      },
    },
  });
  const unavailable = await operatorRequest(unhealthy.app, '/operator/v1/overview');
  const unavailableInspection = unavailable.clone();
  assert.equal(await errorCode(unavailable, 503), 'AUTHORITY_UNHEALTHY');
  assert.equal((await unavailableInspection.text()).includes(kernelSecret), false);

  for (const [code, expectedStatus] of [
    ['SESSION_TRANSITION_BLOCKED', 409],
    ['SESSION_CLOSE_BLOCKED', 409],
    ['RECOVERY_ONLY_OPERATION_FORBIDDEN', 409],
    ['RECONCILIATION_STATE', 409],
    ['POLICY_SCHEMA', 400],
    ['POLICY_NETWORK', 400],
    ['OPERATOR_CAPACITY', 429],
  ]) {
    const stable = harness({
      serviceOverrides: { async overview() { throw new KernelError(code, kernelSecret); } },
    });
    const rejected = await operatorRequest(stable.app, '/operator/v1/overview');
    const inspection = rejected.clone();
    assert.equal(await errorCode(rejected, expectedStatus), code);
    assert.equal((await inspection.text()).includes(kernelSecret), false);
  }

  for (const thrown of [
    new KernelError('PROVIDER_SECRET_SENTINEL', kernelSecret),
    Object.assign(new KernelError('AUTHORITY_UNHEALTHY', kernelSecret), { code: { secret: true } }),
  ]) {
    const invalidCode = harness({
      serviceOverrides: { async overview() { throw thrown; } },
    });
    const invalid = await operatorRequest(invalidCode.app, '/operator/v1/overview');
    const invalidInspection = invalid.clone();
    assert.equal(await errorCode(invalid, 500), 'OPERATOR_INTERNAL');
    const bytes = await invalidInspection.text();
    assert.equal(bytes.includes(kernelSecret), false);
    assert.equal(bytes.includes('PROVIDER_SECRET_SENTINEL'), false);
  }

  const secret = 'provider-secret-that-must-not-escape';
  const failed = harness({
    serviceOverrides: {
      async overview() { throw new Error(secret); },
    },
  });
  const failure = await operatorRequest(failed.app, '/operator/v1/overview');
  const inspection = failure.clone();
  assert.equal(await errorCode(failure, 500), 'OPERATOR_INTERNAL');
  assert.equal((await inspection.text()).includes(secret), false);
});

test('service results cross a closed public projection boundary before serialization', async () => {
  const sentinel = 'RAW_PRIVATE_PROVIDER_RESPONSE';
  for (const result of [
    { items: [{ content: sentinel }] },
    { items: [{ rawEvidence: sentinel }] },
    { operatorIdHash: OPERATOR_HASH },
    new Proxy({ operation: 'overview', accepted: true }, {}),
  ]) {
    const value = harness({
      serviceOverrides: { async listReceipts() { return result; } },
    });
    const response = await operatorRequest(value.app, '/operator/v1/receipts');
    const inspection = response.clone();
    assert.equal(await errorCode(response, 500), 'OPERATOR_INTERNAL');
    const bytes = await inspection.text();
    assert.equal(bytes.includes(sentinel), false);
    assert.equal(bytes.includes(OPERATOR_HASH), false);
  }
});

test('the public boundary admits the production signed session projection shape', () => {
  const hash = (byte) => `sha256:${byte.repeat(64)}`;
  const receiptHash = 'aa'.repeat(32);
  const signature = Buffer.alloc(64, 0x41).toString('base64');
  const signedReceipt = {
    id: 'receipt-1',
    intentId: 'intent-1',
    revision: 1,
    receipt: {
      schemaVersion: 1,
      receiptId: 'receipt-1',
      revision: 1,
      issuedAt: '2026-08-01T12:00:00.000Z',
      intent: {
        id: 'intent-1',
        requestId: 'request-1',
        intentHash: hash('1'),
        sessionId: 'session-1',
        sellerOrigin: 'https://seller.example',
        resourcePath: '/paid/infer',
        purposeLabel: 'commercial-test',
      },
      outcome: { status: 'succeeded', reasonCode: 'PAYMENT_SETTLED' },
      policy: { versionId: 'policy-1', decision: 'allow', reasonCode: 'WITHIN_AUTO_LIMIT' },
      approval: { state: 'not_required', operatorIdHash: null },
      payment: {
        state: 'settled',
        amountAtomic: '1000',
        network: 'eip155:84532',
        asset: POLICY.asset,
        payTo: POLICY.sellers[0].payTo,
        transactionId: PAYMENT_TRANSACTION,
      },
      execution: { state: 'succeeded', httpStatus: 200, responseHash: hash('2') },
      budget: { disposition: 'committed', amountAtomic: '1000' },
      reconciliation: null,
      refund: null,
      supersedesReceiptHash: null,
    },
    receiptHash,
    signature,
    algorithm: 'Ed25519',
    keyId: hash('3'),
    supersedesReceiptHash: null,
    createdAt: '2026-08-01T12:00:00.000Z',
  };
  const projection = {
    schemaVersion: 1,
    domain: 'wallet-kernel.sanitized-projection.v1',
    authoritySchemaVersion: 1,
    sessionHash: hash('4'),
    sessionState: 'active',
    wallet: { address: WALLET, adapterHash: hash('5') },
    agentEnrollment: {
      enrollmentHash: ENROLLMENT_HASH,
      identityHash: hash('6'),
      state: 'active',
    },
    isolation: { status: 'simulated', preflightDigest: null },
    policies: {
      activePolicyHash: POLICY_HASH,
      sessionPolicyHash: POLICY_HASH,
      historyHashes: [POLICY_HASH],
    },
    budgets: {
      session: {
        reservedAtomic: '0',
        committedAtomic: '1000',
        releasedAtomic: '0',
        unresolvedAtomic: '0',
        exposureAtomic: '1000',
      },
      wallet: {
        reservedAtomic: '0',
        committedAtomic: '1000',
        releasedAtomic: '0',
        unresolvedAtomic: '0',
        exposureAtomic: '1000',
      },
    },
    approvals: {
      approved: 0,
      cancelled: 0,
      consumed: 0,
      denied: 0,
      expired: 0,
      pending: 0,
    },
    blockers: {
      blockedIntentCount: 0,
      execution: { openCount: 0, reasonCodes: [] },
      payment: { openCount: 0, reasonCodes: [] },
      refund: { openCount: 0, reasonCodes: [] },
      walletBlocked: false,
    },
    intents: [{
      intentHash: hash('1'),
      requestIdHash: hash('7'),
      routeHash: hash('8'),
      method: 'POST',
      sellerOrigin: 'https://seller.example',
      requestUrlHash: hash('9'),
      resourceHash: hash('a'),
      purposeHash: hash('b'),
      correlationHash: hash('c'),
      state: 'terminal',
      outcome: { status: 'succeeded', reasonCode: 'PAYMENT_SETTLED', revision: 1 },
      createdAt: '2026-08-01T12:00:00.000Z',
      updatedAt: '2026-08-01T12:00:00.000Z',
    }],
    signedReceipts: [signedReceipt],
    eventHeadHash: hash('d'),
    issuedAt: '2026-08-01T12:00:00.000Z',
  };
  const bundle = {
    schemaVersion: 1,
    domain: 'wallet-kernel.projection-export.v1',
    projection,
    algorithm: 'Ed25519',
    keyId: hash('e'),
    publicKeyPem: '-----BEGIN PUBLIC KEY-----\nfixture\n-----END PUBLIC KEY-----\n',
    projectionHash: hash('f'),
    signature,
  };

  assert.deepEqual(projectOperatorPublicResult(bundle), bundle);
  assert.throws(() => projectOperatorPublicResult({
    ...bundle,
    projection: { ...projection, rawEvidence: 'provider-secret' },
  }), /non-public field/);
});

test('real auth completes bearer launch, fragment exchange, browser mutation, and logout', async () => {
  const token = Buffer.alloc(32, 0x71).toString('base64url');
  let randomValue = 0x31;
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes(size) {
      const bytes = Buffer.alloc(size, randomValue);
      randomValue += 1;
      return bytes;
    },
  });
  const serviceCalls = [];
  const app = createOperatorApp({
    auth,
    services: createServicesFake(serviceCalls),
    bodyLimits: { jsonBytes: 65_536 },
    mode: 'deterministic',
    transport: 'loopback-demo',
    origin: ORIGIN,
  });

  const launch = await successData(await app.request(`${ORIGIN}/operator/v1/browser-launch`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}` },
  }));
  assert.equal(JSON.stringify(launch).includes(token), false);
  const launchToken = new URL(launch.url).hash.slice('#launch='.length);
  const session = await app.request(`${ORIGIN}/operator/v1/session`, {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json' },
    body: canonicalJson({ launchToken }),
  });
  assert.equal(session.status, 204);
  const cookie = session.headers.get('set-cookie').split(';', 1)[0];
  const csrf = session.headers.get('x-csrf-token');

  await successData(await app.request(`${ORIGIN}/operator/v1/overview`, {
    headers: { cookie },
  }));
  await successData(await app.request(
    `${ORIGIN}/operator/v1/approvals/approval-1/approve`,
    {
      method: 'POST',
      headers: { cookie, origin: ORIGIN, 'x-csrf-token': csrf, 'content-type': 'application/json' },
      body: canonicalJson({ expectedIntentHash: INTENT_HASH }),
    },
  ));
  assert.match(serviceCalls.at(-1).input.operatorIdHash, /^sha256:[0-9a-f]{64}$/);

  const logout = await app.request(`${ORIGIN}/operator/v1/session`, {
    method: 'DELETE',
    headers: { cookie, origin: ORIGIN, 'x-csrf-token': csrf },
  });
  assert.equal(logout.status, 204);
  assert.equal(await errorCode(await app.request(`${ORIGIN}/operator/v1/overview`, {
    headers: { cookie },
  }), 401), 'OPERATOR_UNAUTHORIZED');
});

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  createControlPlane,
  startControlPlane,
} from '../src/control-plane.mjs';
import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { createAuthorityMutationCoordinator } from '../src/kernel/authority-mutation-coordinator.mjs';
import { validatePolicyDocument } from '../src/kernel/policy-engine.mjs';
import { LIVE_LAUNCH_GATE } from '../scripts/preflight-live-deployment.mjs';

const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const LOOPBACK_SELLER = 'http://127.0.0.1:9901';
const HASH = (byte) => `sha256:${byte.repeat(64)}`;
const OPERATOR_HASH = HASH('9');

const POLICY = validatePolicyDocument({
  schemaVersion: 1,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  wallet: WALLET,
  methods: ['POST'],
  sellers: [{
    origin: SELLER,
    pathPrefixes: ['/paid/'],
    payTo: '0x2000000000000000000000000000000000000000',
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: '0x3000000000000000000000000000000000000000',
    refundSigner: '0x4000000000000000000000000000000000000000',
    refundSource: '0x5000000000000000000000000000000000000000',
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  }],
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60_000,
  approvalTtlMs: 300_000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
});

const POLICY_VERSION = Object.freeze({
  id: 'policy-1',
  hash: sha256(canonicalJson(POLICY)),
  policy: POLICY,
});

const ENROLLMENT = Object.freeze({
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: HASH('a'),
  enrollmentHash: HASH('b'),
  agentUid: String(process.getuid()),
  agentGid: String(process.getgid()),
  isolation: 'simulated',
});

const ROUTE_DOCUMENT = Object.freeze({
  schemaVersion: 1,
  routes: Object.freeze([Object.freeze({
    id: 'example-model',
    kind: 'openai-chat',
    method: 'POST',
    upstreamUrl: `${SELLER}/paid/chat/completions`,
    resourceDescription: 'Control plane fixture',
    resourceMimeType: 'application/json',
    purposeLabel: 'model.infer',
    requestContentTypes: Object.freeze(['application/json']),
    maximumRequestBytes: 4096,
    maximumResponseBytes: 8192,
  })]),
});

function session(overrides = {}) {
  return Object.freeze({
    id: 'session-1',
    adapterId: `pi:${ENROLLMENT.agentInstanceId}`,
    agentInstanceId: ENROLLMENT.agentInstanceId,
    enrollmentHash: ENROLLMENT.enrollmentHash,
    walletAddress: WALLET,
    policyVersionId: POLICY_VERSION.id,
    state: 'open',
    createdAt: '2026-08-01T12:00:00.000Z',
    closedAt: null,
    sessionHash: HASH('c'),
    ...overrides,
  });
}

function binding(overrides = {}) {
  return Object.freeze({
    bindingId: 'binding-1',
    agentInstanceId: ENROLLMENT.agentInstanceId,
    credentialDigest: ENROLLMENT.credentialDigest,
    enrollmentHash: ENROLLMENT.enrollmentHash,
    state: 'open',
    session: session(),
    ...overrides,
  });
}

function revokedEnrollment(operatorIdHash = OPERATOR_HASH) {
  return Object.freeze({
    ...ENROLLMENT,
    state: 'revoked',
    enrolledByOperatorHash: HASH('8'),
    enrolledAt: '2026-08-01T12:00:00.000Z',
    revokedByOperatorHash: operatorIdHash,
    revokedAt: '2026-08-01T12:01:00.000Z',
  });
}

function closedSession() {
  return session({
    state: 'closed',
    closedAt: '2026-08-01T12:01:00.000Z',
    sessionHash: HASH('e'),
  });
}

const OPERATOR_READ_NAMES = Object.freeze([
  'overview',
  'listPolicies',
  'walletIdentity',
  'listApprovals',
  'listReceipts',
  'getReceipt',
  'exportSession',
  'receiptPublicKey',
]);

function app(label) {
  return Object.freeze({
    label,
    routes: Object.freeze([]),
    fetch() {
      return new Response(JSON.stringify({ label }), {
        headers: { 'content-type': 'application/json' },
      });
    },
  });
}

function fakeListener(label, calls) {
  let closed = false;
  return Object.freeze({
    label,
    async close() {
      if (closed) return;
      closed = true;
      calls.push(`close:${label}`);
    },
  });
}

function fixture({
  mode = 'deterministic',
  enrollment = ENROLLMENT,
  bindings = [],
  blockedSessionIds = Object.freeze(['session-1']),
  policyVersion = POLICY_VERSION,
  routeDocument = ROUTE_DOCUMENT,
  authorityOverrides = {},
  dependencyOverrides = {},
} = {}) {
  const calls = [];
  const captured = {};
  const state = {
    enrollment,
    bindings,
    policyVersion,
    session: session({ policyVersionId: policyVersion.id }),
  };
  const operatorReads = {};
  for (const name of OPERATOR_READ_NAMES) {
    operatorReads[name] = async (input) => {
      calls.push(`read:${name}`);
      return Object.freeze({ operation: name, ...(input ?? {}) });
    };
  }
  operatorReads.walletIdentity = async () => ({ address: WALLET });

  const kernel = Object.freeze({
    async openOrResumeSession(input) {
      calls.push('kernel:openOrResumeSession');
      captured.openInput = input;
      if (state.bindings.length === 0) {
        state.session = session({ policyVersionId: input.policyVersionId });
        state.bindings = [binding({ session: state.session })];
      }
      return state.session;
    },
    async applyPolicy(input) {
      calls.push('kernel:applyPolicy');
      captured.applyInput = input;
      return Object.freeze({
        policyVersion: Object.freeze({
          id: state.policyVersion.id,
          schemaVersion: state.policyVersion.policy.schemaVersion,
          policy: state.policyVersion.policy,
          canonicalJson: canonicalJson(state.policyVersion.policy),
          hash: state.policyVersion.hash,
          predecessorHash: null,
          appliedAt: '2026-08-01T12:01:00.000Z',
        }),
        blockedSessionIds,
        idempotent: false,
      });
    },
    async revokeAgent(input) {
      calls.push('kernel:revokeAgent');
      return Object.freeze({
        enrollment: revokedEnrollment(input.operatorIdHash),
        boundSessionIds: Object.freeze(['session-1']),
      });
    },
    async transitionSessionPolicy(input) {
      calls.push('kernel:transitionSessionPolicy');
      captured.transitionInput = input;
      return Object.freeze({ replacementSession: state.session });
    },
    async closeSession(input) {
      calls.push('kernel:closeSession');
      return Object.freeze({ closedSession: closedSession() });
    },
    async approvePending(input) {
      calls.push('kernel:approvePending');
      captured.approveInput = input;
      return Object.freeze({
        approvalId: 'approval-1',
        intentId: 'intent-1',
        decision: 'approved',
        operatorIdHash: HASH('9'),
        intentHash: HASH('d'),
        challengeHash: HASH('e'),
        quoteId: HASH('f'),
        acceptedIndex: 0,
        amountCeilingAtomic: '200000',
        walletAddress: WALLET,
        policyVersionId: POLICY_VERSION.id,
        expiresAt: '2026-08-01T12:05:00.000Z',
        reasonCode: null,
        decidedAt: '2026-08-01T12:01:00.000Z',
        consumedAt: null,
      });
    },
    async denyPending(input) {
      calls.push('kernel:denyPending');
      return Object.freeze({ input });
    },
    async expireDueApprovals() { return Object.freeze([]); },
    async execute() { throw new Error('not used by control-plane tests'); },
    status() { return null; },
    statusByRequestId() { return null; },
    receiptById() { return null; },
  });

  const reconciler = Object.freeze({
    async reconcilePayment(input) {
      calls.push('reconciler:payment');
      return Object.freeze({ input });
    },
    async reconcileExecution(input) {
      calls.push('reconciler:execution');
      return Object.freeze({ input });
    },
    async observeRefund(input) {
      calls.push('reconciler:refund');
      return Object.freeze({ input });
    },
    async abandonCandidate(input) {
      calls.push('reconciler:abandon');
      return Object.freeze({ input });
    },
  });

  const authority = {
    activePolicy() { return state.policyVersion; },
    activeEnrollment() { return state.enrollment; },
    bindingsForEnrollment(input) {
      calls.push('authority:bindings');
      captured.bindingInput = input;
      return state.bindings;
    },
    walletIdentity() {
      calls.push('authority:walletIdentity');
      return Object.freeze({ network: 'eip155:84532', address: WALLET });
    },
    operatorAuth: Object.freeze({ opaque: 'auth-fake' }),
    operatorReads: Object.freeze(operatorReads),
    agentAuthDependencies: Object.freeze({ opaqueAgentAuthDependency: true }),
    createKernelDependencies() {
      calls.push('authority:kernel-dependencies');
      return Object.freeze({ opaqueKernelDependency: true });
    },
    reconcilerDependencies: Object.freeze({ opaqueReconcilerDependency: true }),
    recoveryDependencies: Object.freeze({ opaqueRecoveryDependency: true }),
    async recoverySessionCloser(input) {
      calls.push('recovery:closeSession');
      return Object.freeze({ closedSession: closedSession() });
    },
    async close() { calls.push('close:authority'); },
    ...authorityOverrides,
  };

  const publicConfig = Object.freeze({
    mode,
    agentHost: '127.0.0.1',
    agentPort: 8505,
    operatorAdminTransport: mode === 'cdp-testnet' ? 'unix' : 'loopback-demo',
    operatorSocketPath: mode === 'cdp-testnet' ? '/run/wallet-kernel/admin.sock' : null,
    operatorConsoleTransport: mode === 'cdp-testnet'
      ? 'socket-activated-loopback'
      : 'loopback-demo',
    operatorConsoleActivationName: mode === 'cdp-testnet' ? 'wallet-kernel-console' : null,
    operatorHost: '127.0.0.1',
    operatorPort: 8405,
    databasePath: '/authority/kernel.sqlite',
    policyPath: '/authority/policy.json',
    routePath: '/authority/routes.json',
    receiptKeyPath: '/authority/receipt.key',
    operatorTokenPath: '/authority/operator.token',
    enrollmentInboxPath: null,
    agentRunOutboxPath: null,
    trustedAncestor: mode === 'cdp-testnet' ? '/authority' : null,
    releaseRoot: mode === 'cdp-testnet' ? '/release' : null,
    releaseManifestPath: mode === 'cdp-testnet' ? '/release/manifest.json' : null,
    serviceDefinitionPath: mode === 'cdp-testnet' ? '/etc/systemd/system/wallet.service' : null,
    socketDefinitionPath: mode === 'cdp-testnet' ? '/etc/systemd/system/wallet.socket' : null,
    environmentFilePath: mode === 'cdp-testnet' ? '/etc/wallet.env' : null,
    evidenceRoot: mode === 'cdp-testnet' ? '/evidence' : null,
    isolationReportPath: mode === 'cdp-testnet' ? '/authority/isolation.json' : null,
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
    cdpWalletName: mode === 'cdp-testnet' ? 'wallet-fixture' : null,
    network: 'eip155:84532',
    observer: mode === 'cdp-testnet' ? 'base-sepolia-read-only' : 'deterministic',
  });

  let credentialsAsserted = false;
  const dependencies = {
    checkoutRoot: '/checkout',
    loadConfig() {
      calls.push('config');
      return Object.freeze({
        publicConfig,
        assertCredentialPresence() {
          credentialsAsserted = true;
          calls.push('credentials');
        },
      });
    },
    readRouteDocument() {
      calls.push('routes');
      return routeDocument;
    },
    async verifyRelease() {
      calls.push('release');
      return Object.freeze({ releaseManifestHash: HASH('d'), deployment: 'verified' });
    },
    async acquireAuthorityLock(input) {
      calls.push('lock');
      captured.lockInput = input;
      return Object.freeze({ async close() { calls.push('close:lock'); } });
    },
    async openAuthority(input) {
      calls.push('open');
      captured.openAuthorityInput = input;
      return authority;
    },
    async recoverAuthority(input) {
      calls.push('recover');
      captured.recoveryInput = input;
      return Object.freeze({ ready: true, repairedIntentCount: 0, repairedReceiptCount: 0 });
    },
    createAuthorityMutationCoordinator(input) {
      calls.push('coordinator');
      captured.coordinatorInput = input;
      captured.coordinatorCount = (captured.coordinatorCount ?? 0) + 1;
      return createAuthorityMutationCoordinator(input);
    },
    createWalletKernel(input) {
      calls.push('kernel:create');
      captured.kernelDependencies = input;
      return kernel;
    },
    createReconciler(input) {
      calls.push('reconciler:create');
      captured.reconcilerDependencies = input;
      return reconciler;
    },
    createAgentAuth(input) {
      calls.push('agent-auth:create');
      captured.agentAuthInput = input;
      return Object.freeze({
        authenticate() { return state.enrollment; },
        resolveBoundSession() {
          const current = state.bindings[0]?.session;
          if (!current || current.state !== 'open') {
            throw new KernelError('AGENT_SESSION_UNAVAILABLE', 'unavailable');
          }
          return current;
        },
      });
    },
    createSpendControlProxy(input) {
      calls.push('agent-app:create');
      captured.agentAppInput = input;
      return app('agent');
    },
    createOperatorApp(input) {
      calls.push(`operator-app:create:${input.transport}`);
      captured.operatorApps ??= [];
      captured.operatorApps.push(input);
      return app(`operator:${input.transport}`);
    },
    createOperatorConsoleApp(input) {
      calls.push('console-app:create');
      captured.consoleAppInput = input;
      return app('console');
    },
    async assertLiveAdmission(input) {
      calls.push('live-admission');
      captured.liveAdmissionInput = input;
      return Object.freeze({ isolation: 'verified', observer: 'verified' });
    },
    async listenOperatorAdmin(input) {
      calls.push('listen:admin');
      captured.adminListen = input;
      return fakeListener('admin', calls);
    },
    async listenOperatorConsole(input) {
      calls.push('listen:console');
      captured.consoleListen = input;
      return fakeListener('console', calls);
    },
    async listenAgent(input) {
      calls.push('listen:agent');
      captured.agentListen = input;
      return fakeListener('agent', calls);
    },
    async publishReady(input) {
      calls.push('ready');
      captured.ready = input;
    },
    async prepareStartupReport(input) {
      calls.push('startup-report');
      captured.startupReport = input;
    },
    scheduleShutdown(operation) {
      calls.push('schedule:shutdown');
      queueMicrotask(operation);
    },
    ...dependencyOverrides,
  };

  return {
    authority,
    calls,
    captured,
    dependencies,
    get credentialsAsserted() { return credentialsAsserted; },
    kernel,
    reconciler,
    state,
  };
}

function assertCode(error, code) {
  assert.ok(error instanceof KernelError, String(error));
  assert.equal(error.code, code);
  return true;
}

test('composition recovers under one lock and injects one coordinator identity into both facades', async () => {
  const value = fixture();
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });

  assert.equal(value.captured.coordinatorCount, 1);
  assert.equal(
    value.captured.kernelDependencies.authorityMutationCoordinator,
    value.captured.reconcilerDependencies.authorityMutationCoordinator,
  );
  assert.equal(
    value.captured.kernelDependencies.markAuthorityUnhealthy,
    value.captured.reconcilerDependencies.markAuthorityUnhealthy,
  );
  assert.equal(
    value.captured.coordinatorInput.markAuthorityUnhealthy,
    value.captured.kernelDependencies.markAuthorityUnhealthy,
  );
  assert.ok(value.calls.indexOf('lock') < value.calls.indexOf('open'));
  assert.ok(value.calls.indexOf('open') < value.calls.indexOf('recover'));
  assert.ok(value.calls.indexOf('recover') < value.calls.indexOf('coordinator'));
  assert.deepEqual(value.captured.openInput, {
    agentInstanceId: ENROLLMENT.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: POLICY_VERSION.id,
  });

  assert.deepEqual(Object.keys(value.captured.agentAppInput).sort(), [
    'agentAuth', 'kernel', 'maximumRequestBytes', 'routes',
  ]);
  for (const application of value.captured.operatorApps) {
    assert.deepEqual(Object.keys(application).sort(), [
      'auth', 'bodyLimits', 'mode', 'origin', 'services', 'transport',
    ]);
    for (const forbidden of ['store', 'walletAdapter', 'permitAuthority', 'environment']) {
      assert.equal(Object.hasOwn(application, forbidden), false);
    }
  }
  assert.equal(plane.health().admission, 'open');
  assert.equal(plane.health().mode, 'normal');
  await plane.close();
  assert.deepEqual(value.calls.slice(-2), ['close:authority', 'close:lock']);
});

test('the shared coordinator serializes Kernel, reconciliation phases, and operator mutations', async () => {
  const value = fixture();
  await createControlPlane({ env: {}, dependencies: value.dependencies });
  const coordinator = value.captured.kernelDependencies.authorityMutationCoordinator;
  const order = [];
  let releaseResolver;
  const resolver = new Promise((resolve) => { releaseResolver = resolve; });

  const terminal = coordinator.runExclusive(() => order.push('kernel-terminal'));
  const reconciliation = (async () => {
    await coordinator.runExclusive(() => order.push('reconcile-prepare'));
    order.push('resolver-start');
    await resolver;
    order.push('resolver-end');
    await coordinator.runExclusive(() => order.push('reconcile-resolve'));
  })();
  const operator = coordinator.runExclusive(() => order.push('operator-mutation'));
  await Promise.all([terminal, operator]);
  releaseResolver();
  await reconciliation;

  assert.deepEqual(order, [
    'kernel-terminal',
    'reconcile-prepare',
    'operator-mutation',
    'resolver-start',
    'resolver-end',
    'reconcile-resolve',
  ]);
});

test('startup honors no-binding, exact-open, and policy-blocked binding rules', async (t) => {
  await t.test('no binding creates exactly one session through Kernel', async () => {
    const value = fixture({ bindings: [] });
    const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
    assert.equal(value.calls.filter((entry) => entry === 'kernel:openOrResumeSession').length, 1);
    await plane.close();
  });

  await t.test('exact open binding is idempotently resumed through Kernel', async () => {
    const value = fixture({ bindings: [binding()] });
    const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
    assert.equal(value.calls.filter((entry) => entry === 'kernel:openOrResumeSession').length, 1);
    assert.equal(plane.health().sessionState, 'open');
    await plane.close();
  });

  await t.test('policy-blocked binding is retained and never opened implicitly', async () => {
    const blockedSession = session({
      state: 'policy_blocked',
      policyVersionId: 'policy-previous',
    });
    const value = fixture({ bindings: [binding({ session: blockedSession })] });
    const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
    assert.equal(value.calls.includes('kernel:openOrResumeSession'), false);
    assert.equal(plane.health().sessionState, 'policy_blocked');
    await plane.close();
  });

  const corruptions = [
    binding({ credentialDigest: HASH('e') }),
    binding({ session: session({ walletAddress: '0x9000000000000000000000000000000000000000' }) }),
    binding({ session: session({ policyVersionId: 'policy-previous' }) }),
    binding({ state: 'closed' }),
  ];
  for (const candidate of corruptions) {
    await t.test(`fails closed for ${JSON.stringify(candidate).slice(0, 48)}`, async () => {
      const value = fixture({ bindings: [candidate] });
      await assert.rejects(
        createControlPlane({ env: {}, dependencies: value.dependencies }),
        (error) => assertCode(error, 'SESSION_AUTHORITY_AMBIGUOUS'),
      );
      assert.deepEqual(value.calls.slice(-2), ['close:authority', 'close:lock']);
      assert.equal(value.calls.some((entry) => entry.startsWith('listen:')), false);
    });
  }

  await t.test('multiple candidates fail before app construction', async () => {
    const value = fixture({ bindings: [binding(), binding({ bindingId: 'binding-2' })] });
    await assert.rejects(
      createControlPlane({ env: {}, dependencies: value.dependencies }),
      (error) => assertCode(error, 'SESSION_AUTHORITY_AMBIGUOUS'),
    );
    assert.equal(value.calls.includes('agent-app:create'), false);
  });
});

test('recovery-only composition has no signer/session facade and exposes only recovery mutations', async () => {
  const value = fixture({ enrollment: null, bindings: [] });
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });

  assert.equal(value.calls.includes('kernel:create'), false);
  assert.equal(value.calls.includes('authority:kernel-dependencies'), false);
  assert.equal(value.calls.includes('kernel:openOrResumeSession'), false);
  assert.equal(value.calls.includes('agent-auth:create'), false);
  assert.equal(value.calls.includes('agent-app:create'), false);
  assert.equal(value.calls.includes('reconciler:create'), true);
  assert.equal(plane.health().mode, 'recovery_only');
  const services = value.captured.operatorApps[0].services;

  for (const name of [
    'applyPolicy',
    'revokeAgent',
    'transitionSessionPolicy',
    'approvePending',
    'denyPending',
  ]) {
    await assert.rejects(
      services[name]({}),
      (error) => assertCode(error, 'RECOVERY_ONLY_OPERATION_FORBIDDEN'),
    );
  }
  assert.equal(value.calls.some((entry) => entry.startsWith('kernel:')), false);

  await services.reconcilePayment({ intentId: 'intent-1' });
  await services.reconcileExecution({ intentId: 'intent-1' });
  await services.reconcileRefundObservation({ intentId: 'intent-1' });
  await services.abandonCandidate({ intentId: 'intent-1' });
  const closed = await services.closeSession({ sessionId: 'session-1' });
  assert.deepEqual(closed, { session: closedSession() });
  assert.deepEqual(value.calls.filter((entry) => (
    (entry.startsWith('reconciler:') && entry !== 'reconciler:create')
      || entry.startsWith('recovery:')
  )), [
    'reconciler:payment',
    'reconciler:execution',
    'reconciler:refund',
    'reconciler:abandon',
    'recovery:closeSession',
  ]);

  const response = await plane.apps.agent.fetch(new Request(
    'http://127.0.0.1:8505/agent/v1/invoke/unknown',
    { method: 'POST', body: 'RAW_PROMPT_SENTINEL' },
  ));
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    error: {
      code: 'AGENT_ENROLLMENT_REQUIRED',
      message: 'Agent enrollment is required',
    },
  });
  await plane.close();
});

test('revocation and guarded close expose validated public mutation projections', async () => {
  const value = fixture();
  await createControlPlane({ env: {}, dependencies: value.dependencies });
  const services = value.captured.operatorApps[0].services;

  const revoked = await services.revokeAgent({
    agentInstanceId: ENROLLMENT.agentInstanceId,
    expectedEnrollmentHash: ENROLLMENT.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  assert.deepEqual(revoked, {
    agentEnrollment: {
      agentInstanceId: ENROLLMENT.agentInstanceId,
      enrollmentHash: ENROLLMENT.enrollmentHash,
      agentUid: ENROLLMENT.agentUid,
      agentGid: ENROLLMENT.agentGid,
      state: 'revoked',
      isolation: ENROLLMENT.isolation,
      enrolledAt: '2026-08-01T12:00:00.000Z',
      revokedAt: '2026-08-01T12:01:00.000Z',
    },
    sessions: ['session-1'],
  });
  assert.equal(JSON.stringify(revoked).includes(OPERATOR_HASH), false);
  assert.equal(JSON.stringify(revoked).includes(ENROLLMENT.credentialDigest), false);

  const closed = await services.closeSession({
    sessionId: 'session-1',
    expectedSessionHash: HASH('c'),
  });
  assert.deepEqual(closed, { session: closedSession() });
  assert.equal(Object.hasOwn(closed, 'closedSession'), false);
});

test('operator transition resolves the active policy hash to the internal version ID at call time', async () => {
  const value = fixture();
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
  const services = value.captured.operatorApps[0].services;

  await services.transitionSessionPolicy({
    sessionId: 'session-1',
    targetPolicyHash: POLICY_VERSION.hash,
    expectedSessionHash: HASH('c'),
  });
  assert.deepEqual(value.captured.transitionInput, {
    sessionId: 'session-1',
    targetPolicyVersionId: 'policy-1',
    expectedSessionHash: HASH('c'),
  });
  assert.equal(Object.hasOwn(value.captured.transitionInput, 'targetPolicyHash'), false);

  await assert.rejects(
    services.transitionSessionPolicy({
      sessionId: 'session-1',
      targetPolicyHash: HASH('f'),
      expectedSessionHash: HASH('c'),
    }),
    (error) => assertCode(error, 'POLICY_NOT_ACTIVE'),
  );

  const nextPolicy = validatePolicyDocument({
    ...structuredClone(POLICY),
    sessionMaxAtomic: '3000000',
  });
  value.state.policyVersion = Object.freeze({
    id: 'policy-2',
    hash: sha256(canonicalJson(nextPolicy)),
    policy: nextPolicy,
  });
  await services.transitionSessionPolicy({
    sessionId: 'session-1',
    targetPolicyHash: value.state.policyVersion.hash,
    expectedSessionHash: HASH('c'),
  });
  assert.equal(value.captured.transitionInput.targetPolicyVersionId, 'policy-2');
  await plane.close();
});

test('operator approval mutation strips the stable operator identity before the public boundary', async () => {
  const value = fixture();
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
  const services = value.captured.operatorApps[0].services;
  const input = Object.freeze({
    approvalId: 'approval-1',
    expectedIntentHash: HASH('d'),
    operatorIdHash: HASH('9'),
  });

  const result = await services.approvePending(input);

  assert.deepEqual(result, {
    approvalId: 'approval-1',
    intentId: 'intent-1',
    decision: 'approved',
    intentHash: HASH('d'),
    challengeHash: HASH('e'),
    quoteId: HASH('f'),
    acceptedIndex: 0,
    amountAtomic: '200000',
    walletAddress: WALLET,
    policyVersionId: POLICY_VERSION.id,
    expiresAt: '2026-08-01T12:05:00.000Z',
    reasonCode: null,
    recordedAt: '2026-08-01T12:01:00.000Z',
    consumedAt: null,
  });
  assert.equal(JSON.stringify(result).includes(HASH('9')), false);
  assert.equal(Object.hasOwn(result, 'operatorIdHash'), false);
  assert.equal(value.captured.approveInput, input);
  await assert.rejects(
    services.approvePending({ ...input, operatorIdHash: HASH('8') }),
    (error) => assertCode(error, 'APPROVAL_CORRUPTION'),
  );
  await plane.close();
});

test('operator policy mutation publishes only the validated public PolicyVersion shape', async () => {
  const value = fixture();
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
  const services = value.captured.operatorApps[0].services;
  const input = Object.freeze({
    document: POLICY,
    expectedPolicyHash: POLICY_VERSION.hash,
  });

  const result = await services.applyPolicy(input);

  assert.deepEqual(result, {
    policyVersion: {
      versionId: POLICY_VERSION.id,
      policy: POLICY,
      policyHash: POLICY_VERSION.hash,
      predecessorHash: null,
      createdAt: '2026-08-01T12:01:00.000Z',
      active: true,
    },
    blockedSessionIds: ['session-1'],
    idempotent: false,
  });
  assert.equal(JSON.stringify(result).includes('canonicalJson'), false);
  assert.equal(value.captured.applyInput, input);
  await assert.rejects(
    services.applyPolicy({ ...input, expectedPolicyHash: HASH('9') }),
    (error) => assertCode(error, 'POLICY_CORRUPTION'),
  );
  await plane.close();
});

test('operator policy projection rejects accessor-bearing session arrays without invoking them', async () => {
  let accessorReads = 0;
  const blockedSessionIds = [];
  Object.defineProperty(blockedSessionIds, '0', {
    enumerable: true,
    configurable: true,
    get() {
      accessorReads += 1;
      return 'session-1';
    },
  });
  blockedSessionIds.length = 1;
  const value = fixture({ blockedSessionIds });
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
  const services = value.captured.operatorApps[0].services;

  await assert.rejects(
    services.applyPolicy({
      document: POLICY,
      expectedPolicyHash: POLICY_VERSION.hash,
    }),
    (error) => assertCode(error, 'POLICY_CORRUPTION'),
  );
  assert.equal(accessorReads, 0);
  await plane.close();
});

test('routes are cross-checked against active policy method, origin, path, and live HTTPS', async (t) => {
  const cases = [
    {
      name: 'origin mismatch',
      mutate: (route) => ({ ...route, upstreamUrl: 'https://other.example/paid/chat' }),
    },
    {
      name: 'path mismatch',
      mutate: (route) => ({ ...route, upstreamUrl: `${SELLER}/private/chat` }),
    },
    {
      name: 'method outside policy',
      mutate: (route) => ({ ...route, method: 'GET' }),
    },
  ];
  for (const { name, mutate } of cases) {
    await t.test(name, async () => {
      const document = structuredClone(ROUTE_DOCUMENT);
      document.routes[0] = mutate(document.routes[0]);
      const value = fixture({ routeDocument: document });
      await assert.rejects(
        createControlPlane({ env: {}, dependencies: value.dependencies }),
        (error) => error instanceof KernelError
          && ['ROUTE_POLICY_MISMATCH', 'ROUTE_METHOD'].includes(error.code),
      );
      assert.equal(value.calls.includes('agent-app:create'), false);
    });
  }

  await t.test('deterministic literal-loopback policy and route are allowed', async () => {
    const policy = validatePolicyDocument({
      ...structuredClone(POLICY),
      sellers: [{ ...structuredClone(POLICY.sellers[0]), origin: LOOPBACK_SELLER }],
    });
    const policyVersion = Object.freeze({
      id: 'policy-loopback',
      hash: sha256(canonicalJson(policy)),
      policy,
    });
    const document = structuredClone(ROUTE_DOCUMENT);
    document.routes[0].upstreamUrl = `${LOOPBACK_SELLER}/paid/chat`;
    const value = fixture({ policyVersion, routeDocument: document });
    const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
    await plane.close();
  });

  await t.test('live rejects loopback HTTP policy before authority admission', async () => {
    const policy = validatePolicyDocument({
      ...structuredClone(POLICY),
      sellers: [{ ...structuredClone(POLICY.sellers[0]), origin: LOOPBACK_SELLER }],
    });
    const policyVersion = Object.freeze({
      id: 'policy-loopback',
      hash: sha256(canonicalJson(policy)),
      policy,
    });
    const document = structuredClone(ROUTE_DOCUMENT);
    document.routes[0].upstreamUrl = `${LOOPBACK_SELLER}/paid/chat`;
    const value = fixture({ mode: 'cdp-testnet', policyVersion, routeDocument: document });
    await assert.rejects(
      createControlPlane({ env: {}, dependencies: value.dependencies }),
      (error) => assertCode(error, 'ROUTE_URL'),
    );
    assert.equal(value.calls.includes('live-admission'), false);
  });
});

test('live verifies release before credentials/SQLite and binds admission to recovered authority', async () => {
  const value = fixture({ mode: 'cdp-testnet' });
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });

  assert.ok(value.calls.indexOf('release') < value.calls.indexOf('credentials'));
  assert.ok(value.calls.indexOf('release') < value.calls.indexOf('lock'));
  assert.ok(value.calls.indexOf('lock') < value.calls.indexOf('open'));
  assert.ok(value.calls.indexOf('recover') < value.calls.indexOf('live-admission'));
  assert.ok(value.calls.indexOf('live-admission') < value.calls.indexOf('agent-app:create'));
  assert.equal(value.credentialsAsserted, true);
  assert.deepEqual(value.captured.liveAdmissionInput.enrollment, {
    agentInstanceId: ENROLLMENT.agentInstanceId,
    credentialDigest: ENROLLMENT.credentialDigest,
    enrollmentHash: ENROLLMENT.enrollmentHash,
    agentUid: ENROLLMENT.agentUid,
    agentGid: ENROLLMENT.agentGid,
  });
  assert.equal(
    value.captured.liveAdmissionInput.release.releaseManifestHash,
    HASH('d'),
  );
  assert.equal(plane.health().deployment, 'verified');
  assert.equal(plane.health().isolation, 'verified');
  await plane.close();
});

test('recovery-only live startup skips agent isolation admission but retains release verification', async () => {
  const value = fixture({ mode: 'cdp-testnet', enrollment: null });
  const plane = await createControlPlane({ env: {}, dependencies: value.dependencies });
  assert.equal(value.calls.includes('release'), true);
  assert.equal(value.calls.includes('live-admission'), false);
  assert.equal(value.calls.includes('kernel:create'), false);
  assert.equal(plane.health().mode, 'recovery_only');
  await plane.close();
});

test('fail-stop closes admission before queued callbacks and schedules listener shutdown once', async () => {
  const value = fixture();
  const plane = await startControlPlane({ env: {}, dependencies: value.dependencies });
  const coordinator = value.captured.kernelDependencies.authorityMutationCoordinator;
  const mark = value.captured.kernelDependencies.markAuthorityUnhealthy;
  let callbackRan = false;

  mark('RECEIPT_PARITY_REQUIRED');
  mark('IGNORED_SECOND_REASON');
  await assert.rejects(
    coordinator.runExclusive(() => { callbackRan = true; }),
    (error) => assertCode(error, 'RECEIPT_PARITY_REQUIRED'),
  );
  assert.equal(callbackRan, false);
  assert.equal(plane.health().admission, 'closed');
  assert.equal(plane.health().reasonCode, 'RECEIPT_PARITY_REQUIRED');
  assert.equal(value.calls.filter((entry) => entry === 'schedule:shutdown').length, 1);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(value.calls.filter((entry) => entry.startsWith('close:')), [
    'close:agent',
    'close:console',
    'close:authority',
    'close:lock',
  ]);
  await plane.close();
});

test('listener lifecycle is ordered, separate, idempotent, and fail-closed', async (t) => {
  await t.test('deterministic publishes operator readiness before agent admission', async () => {
    const value = fixture();
    const plane = await startControlPlane({ env: {}, dependencies: value.dependencies });
    const sequence = value.calls.filter((entry) => (
      entry.startsWith('listen:') || entry === 'ready'
    ));
    assert.deepEqual(sequence, ['listen:console', 'listen:agent', 'ready']);
    assert.ok(value.calls.indexOf('listen:console') < value.calls.indexOf('startup-report'));
    assert.ok(value.calls.indexOf('startup-report') < value.calls.indexOf('listen:agent'));
    assert.notEqual(value.captured.consoleListen.app, value.captured.agentListen.app);
    assert.equal(value.captured.ready.agentOrigin, 'http://127.0.0.1:8505');
    assert.equal(value.captured.ready.operatorOrigin, 'http://127.0.0.1:8405');
    await plane.close();
    await plane.close();
    assert.equal(value.calls.filter((entry) => entry === 'close:lock').length, 1);
  });

  await t.test('live admin UDS and inherited console precede the agent listener', async () => {
    const value = fixture({ mode: 'cdp-testnet' });
    const plane = await startControlPlane({ env: {}, dependencies: value.dependencies });
    const sequence = value.calls.filter((entry) => (
      entry.startsWith('listen:') || entry === 'ready'
    ));
    assert.deepEqual(sequence, ['listen:admin', 'listen:console', 'listen:agent', 'ready']);
    assert.ok(value.calls.indexOf('listen:console') < value.calls.indexOf('startup-report'));
    assert.ok(value.calls.indexOf('startup-report') < value.calls.indexOf('listen:agent'));
    assert.equal(value.captured.adminListen.socketPath, '/run/wallet-kernel/admin.sock');
    assert.equal(value.captured.consoleListen.activationName, 'wallet-kernel-console');
    await plane.close();
    assert.deepEqual(value.calls.filter((entry) => entry.startsWith('close:')), [
      'close:agent',
      'close:console',
      'close:admin',
      'close:authority',
      'close:lock',
    ]);
  });

  await t.test('partial listener failure unwinds already-owned authority', async () => {
    const value = fixture({
      dependencyOverrides: {
        async listenAgent() {
          value.calls.push('listen:agent');
          const error = new Error('port collision');
          error.code = 'EADDRINUSE';
          throw error;
        },
      },
    });
    await assert.rejects(
      startControlPlane({ env: {}, dependencies: value.dependencies }),
      (error) => error?.code === 'EADDRINUSE',
    );
    assert.deepEqual(value.calls.filter((entry) => entry.startsWith('close:')), [
      'close:console',
      'close:authority',
      'close:lock',
    ]);
  });
});

test('composition rejects injected coordinator aliases and broad operator service objects', async (t) => {
  await t.test('Kernel dependency cannot pre-install another coordinator', async () => {
    const value = fixture({
      authorityOverrides: {
        createKernelDependencies() {
          return Object.freeze({
            opaqueKernelDependency: true,
            authorityMutationCoordinator: Object.freeze({}),
          });
        },
      },
    });
    await assert.rejects(
      createControlPlane({ env: {}, dependencies: value.dependencies }),
      (error) => assertCode(error, 'CONTROL_PLANE_AUTHORITY_INJECTION'),
    );
  });

  await t.test('operator read facade rejects a raw store property', async () => {
    const reads = Object.fromEntries(OPERATOR_READ_NAMES.map((name) => [name, async () => ({})]));
    reads.store = Object.freeze({ mutate() {} });
    const value = fixture({
      authorityOverrides: { operatorReads: Object.freeze(reads) },
    });
    await assert.rejects(
      createControlPlane({ env: {}, dependencies: value.dependencies }),
      (error) => assertCode(error, 'CONTROL_PLANE_DEPENDENCY'),
    );
    assert.equal(value.calls.some((entry) => entry.startsWith('operator-app:create')), false);
  });
});

test('installed direct execution reports the remaining Linux lifecycle gate', () => {
  const entrypoint = fileURLToPath(new URL('../src/control-plane.mjs', import.meta.url));
  const child = spawnSync(process.execPath, [entrypoint], {
    encoding: 'utf8',
    env: Object.freeze({}),
  });
  assert.equal(child.status, LIVE_LAUNCH_GATE.exitStatus);
  assert.equal(child.stdout, '');
  assert.equal(child.stderr, `${canonicalJson(LIVE_LAUNCH_GATE)}\n`);
});

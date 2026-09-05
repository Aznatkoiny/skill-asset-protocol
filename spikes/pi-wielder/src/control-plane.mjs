import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { types as utilTypes } from 'node:util';

import { Hono } from 'hono';

import { createAgentAuth } from './agent/auth.mjs';
import { codeBoundaryRoot } from './code-root.mjs';
import {
  loadControlPlaneConfig,
  readBoundedRouteDocument,
  validateRouteMap,
} from './config.mjs';
import {
  canonicalJson,
  KernelError,
  sha256,
} from './kernel/canonical.mjs';
import { createAuthorityMutationCoordinator } from './kernel/authority-mutation-coordinator.mjs';
import { validatePolicyDocument } from './kernel/policy-engine.mjs';
import { createReconciler } from './kernel/recovery.mjs';
import { createWalletKernel } from './kernel/wallet-kernel.mjs';
import {
  createOperatorApp,
  projectOperatorPublicResult,
} from './operator/api.mjs';
import { createOperatorConsoleApp } from './operator/console.mjs';
import { createSpendControlProxy } from './spend-control-proxy.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const INSTANCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const MODES = new Set(['deterministic', 'cdp-testnet']);
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
const DEPENDENCY_FIELDS = new Set([
  'checkoutRoot',
  'deterministicEndpoints',
  'loadConfig',
  'readRouteDocument',
  'verifyRelease',
  'acquireAuthorityLock',
  'openAuthority',
  'recoverAuthority',
  'createAuthorityMutationCoordinator',
  'createWalletKernel',
  'createReconciler',
  'createAgentAuth',
  'createSpendControlProxy',
  'createOperatorApp',
  'createOperatorConsoleApp',
  'assertLiveAdmission',
  'listenOperatorAdmin',
  'listenOperatorConsole',
  'listenAgent',
  'prepareStartupReport',
  'publishReady',
  'scheduleShutdown',
]);
const AUTHORITY_FIELDS = Object.freeze([
  'activePolicy',
  'activeEnrollment',
  'bindingsForEnrollment',
  'walletIdentity',
  'operatorAuth',
  'operatorReads',
  'agentAuthDependencies',
  'createKernelDependencies',
  'reconcilerDependencies',
  'recoveryDependencies',
  'recoverySessionCloser',
  'close',
]);
const OPTIONAL_AUTHORITY_FIELDS = Object.freeze(['waitForUnsignedWork']);
const RESERVED_FACTORY_DEPENDENCIES = new Set([
  'authorityMutationCoordinator',
  'markAuthorityUnhealthy',
]);
const INTERNALS = new WeakMap();

function fail(code, message, cause) {
  throw new KernelError(code, message, cause === undefined ? undefined : { cause });
}

function isPlainRecord(value) {
  return Boolean(value)
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function captureRecord(value, label, { allowed, required = [] } = {}) {
  if (!isPlainRecord(value)) throw new TypeError(`${label} must be one plain object`);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string')
      || (allowed && keys.some((key) => !allowed.has(key)))
      || required.some((key) => !Object.hasOwn(descriptors, key))) {
    throw new TypeError(`${label} has an invalid shape`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = descriptors[key];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} must contain only enumerable data fields`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function ordinaryFunction(value, label, { optional = false } = {}) {
  if (optional && value === undefined) return null;
  if (typeof value !== 'function' || utilTypes.isProxy(value)) {
    throw new TypeError(`${label} must be one non-proxy function`);
  }
  return value;
}

function ownData(value, field, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    fail(code, `${label} is invalid`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
    fail(code, `${label} is invalid`);
  }
  return descriptor.value;
}

function canonicalHash(value, code, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalToken(value, code, label, pattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail(code, `${label} is invalid`);
  }
  return value;
}

function captureCanonicalTokenArray(value, code, label, maximumLength) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) {
    fail(code, `${label} must be one ordinary array`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const lengthDescriptor = descriptors.length;
  if (!lengthDescriptor || !Object.hasOwn(lengthDescriptor, 'value')
      || !Number.isSafeInteger(lengthDescriptor.value)
      || lengthDescriptor.value < 0 || lengthDescriptor.value > maximumLength) {
    fail(code, `${label} length is invalid`);
  }
  const length = lengthDescriptor.value;
  const keys = Reflect.ownKeys(descriptors);
  if (keys.some((key) => typeof key !== 'string') || keys.length !== length + 1) {
    fail(code, `${label} must be one dense data-only array`);
  }
  const captured = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, `${label} must be one dense data-only array`);
    }
    captured.push(canonicalToken(
      descriptor.value,
      code,
      `${label} entry`,
    ));
  }
  if (new Set(captured).size !== captured.length) {
    fail(code, `${label} entries must be unique`);
  }
  return Object.freeze(captured);
}

function captureOptions(value) {
  const input = value === undefined ? {} : captureRecord(value, 'control plane options', {
    allowed: new Set(['env', 'dependencies']),
  });
  const env = Object.hasOwn(input, 'env') ? input.env : process.env;
  if (!env || typeof env !== 'object' || utilTypes.isProxy(env)) {
    throw new TypeError('control plane environment must be one non-proxy object');
  }
  const supplied = Object.hasOwn(input, 'dependencies') ? input.dependencies : {};
  const captured = captureRecord(supplied, 'control plane dependencies', {
    allowed: DEPENDENCY_FIELDS,
  });
  return Object.freeze({ env, dependencies: captured });
}

function defaultCheckoutRoot() {
  return codeBoundaryRoot();
}

function defaultsFor(input) {
  const dependency = (name, fallback) => Object.hasOwn(input, name) ? input[name] : fallback;
  const missing = (name) => async () => {
    throw new TypeError(`control plane dependency ${name} is required`);
  };
  const checkoutRoot = dependency('checkoutRoot', defaultCheckoutRoot());
  if (typeof checkoutRoot !== 'string' || !path.isAbsolute(checkoutRoot)) {
    throw new TypeError('control plane checkoutRoot must be absolute');
  }
  const functions = {
    loadConfig: dependency('loadConfig', loadControlPlaneConfig),
    readRouteDocument: dependency('readRouteDocument', readBoundedRouteDocument),
    verifyRelease: dependency('verifyRelease', missing('verifyRelease')),
    acquireAuthorityLock: dependency(
      'acquireAuthorityLock',
      missing('acquireAuthorityLock'),
    ),
    openAuthority: dependency('openAuthority', missing('openAuthority')),
    recoverAuthority: dependency('recoverAuthority', missing('recoverAuthority')),
    createAuthorityMutationCoordinator: dependency(
      'createAuthorityMutationCoordinator',
      createAuthorityMutationCoordinator,
    ),
    createWalletKernel: dependency('createWalletKernel', createWalletKernel),
    createReconciler: dependency('createReconciler', createReconciler),
    createAgentAuth: dependency('createAgentAuth', createAgentAuth),
    createSpendControlProxy: dependency('createSpendControlProxy', createSpendControlProxy),
    createOperatorApp: dependency('createOperatorApp', createOperatorApp),
    createOperatorConsoleApp: dependency(
      'createOperatorConsoleApp',
      createOperatorConsoleApp,
    ),
    assertLiveAdmission: dependency('assertLiveAdmission', missing('assertLiveAdmission')),
    listenOperatorAdmin: dependency('listenOperatorAdmin', missing('listenOperatorAdmin')),
    listenOperatorConsole: dependency(
      'listenOperatorConsole',
      missing('listenOperatorConsole'),
    ),
    listenAgent: dependency('listenAgent', missing('listenAgent')),
    prepareStartupReport: dependency('prepareStartupReport', async () => undefined),
    publishReady: dependency('publishReady', async () => undefined),
    scheduleShutdown: dependency('scheduleShutdown', (operation) => queueMicrotask(operation)),
  };
  for (const [name, value] of Object.entries(functions)) ordinaryFunction(value, name);
  return Object.freeze({
    checkoutRoot,
    deterministicEndpoints: Object.hasOwn(input, 'deterministicEndpoints')
      ? input.deterministicEndpoints
      : null,
    ...functions,
  });
}

function configuredModeHint(env) {
  const descriptor = Object.getOwnPropertyDescriptor(env, 'WALLET_KERNEL_MODE');
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) return null;
  return typeof descriptor.value === 'string' ? descriptor.value : null;
}

function normalizeLiveRelease(value) {
  const fields = [
    'releaseManifestHash',
    'releaseTreeHash',
    'nodeExecutableHash',
    'serviceArtifactsHash',
    'systemdEffectiveConfigHash',
    'environmentMetadataHash',
  ];
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    fail('RELEASE_VERIFY_INPUT', 'live release verification result is invalid');
  }
  const projection = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (field === 'releaseManifestHash' && !descriptor) {
      fail('RELEASE_VERIFY_INPUT', 'live release verification returned no manifest hash');
    }
    if (!descriptor) continue;
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('RELEASE_VERIFY_INPUT', 'live release verification result is not inert data');
    }
    projection[field] = canonicalHash(
      descriptor.value,
      'RELEASE_VERIFY_INPUT',
      field,
    );
  }
  return Object.freeze({ deployment: 'verified', ...projection });
}

function validateLoadedConfig(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new TypeError('control plane configuration result is invalid');
  }
  const publicConfig = ownData(
    value,
    'publicConfig',
    'CONTROL_PLANE_CONFIG',
    'control plane public configuration',
  );
  const assertCredentialPresence = ownData(
    value,
    'assertCredentialPresence',
    'CONTROL_PLANE_CONFIG',
    'control plane credential gate',
  );
  ordinaryFunction(assertCredentialPresence, 'control plane credential gate');
  if (!publicConfig || typeof publicConfig !== 'object' || utilTypes.isProxy(publicConfig)
      || !MODES.has(publicConfig.mode)
      || publicConfig.agentHost !== '127.0.0.1'
      || publicConfig.operatorHost !== '127.0.0.1'
      || !Number.isSafeInteger(publicConfig.agentPort)
      || publicConfig.agentPort < 1 || publicConfig.agentPort > 65_535
      || !Number.isSafeInteger(publicConfig.operatorPort)
      || publicConfig.operatorPort < 1 || publicConfig.operatorPort > 65_535
      || publicConfig.agentPort === publicConfig.operatorPort) {
    fail('CONTROL_PLANE_CONFIG', 'control plane public configuration is invalid');
  }
  return Object.freeze({ publicConfig, assertCredentialPresence });
}

function positivePort(value, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_535) {
    fail('CONTROL_PLANE_CONFIG', `${label} must be a nonzero TCP port`);
  }
  return value;
}

function endpointsFor(config, injected) {
  if (injected === null) {
    return Object.freeze({
      agentHost: config.agentHost,
      agentPort: config.agentPort,
      operatorHost: config.operatorHost,
      operatorPort: config.operatorPort,
    });
  }
  if (config.mode !== 'deterministic') {
    fail('CONTROL_PLANE_CONFIG', 'listener endpoint injection is deterministic-only');
  }
  const captured = captureRecord(injected, 'deterministic listener endpoints', {
    allowed: new Set(['agentHost', 'agentPort', 'operatorHost', 'operatorPort']),
    required: ['agentHost', 'agentPort', 'operatorHost', 'operatorPort'],
  });
  if (captured.agentHost !== '127.0.0.1' || captured.operatorHost !== '127.0.0.1') {
    fail('CONTROL_PLANE_CONFIG', 'deterministic listeners must use literal loopback');
  }
  const agentPort = positivePort(captured.agentPort, 'agent port');
  const operatorPort = positivePort(captured.operatorPort, 'operator port');
  if (agentPort === operatorPort) {
    fail('CONTROL_PLANE_CONFIG', 'agent and operator listeners must be distinct');
  }
  return Object.freeze({
    agentHost: captured.agentHost,
    agentPort,
    operatorHost: captured.operatorHost,
    operatorPort,
  });
}

function captureDependencyBag(value, label) {
  const captured = captureRecord(value, label);
  if (Reflect.ownKeys(captured).some((key) => RESERVED_FACTORY_DEPENDENCIES.has(key))) {
    fail(
      'CONTROL_PLANE_AUTHORITY_INJECTION',
      `${label} may not supply an authority coordinator or fail-stop hook`,
    );
  }
  return captured;
}

function captureFunctionSurface(value, names, label) {
  const captured = captureRecord(value, label, {
    allowed: new Set(names),
    required: names,
  });
  const surface = {};
  for (const name of names) {
    const fn = ordinaryFunction(captured[name], `${label}.${name}`);
    surface[name] = (...args) => Reflect.apply(fn, value, args);
  }
  return Object.freeze(surface);
}

function captureAuthority(value) {
  const allowed = new Set([...AUTHORITY_FIELDS, ...OPTIONAL_AUTHORITY_FIELDS]);
  const captured = captureRecord(value, 'control plane authority', {
    allowed,
    required: AUTHORITY_FIELDS,
  });
  for (const name of [
    'activePolicy',
    'activeEnrollment',
    'bindingsForEnrollment',
    'walletIdentity',
    'createKernelDependencies',
    'recoverySessionCloser',
    'close',
  ]) ordinaryFunction(captured[name], `control plane authority.${name}`);
  if (Object.hasOwn(captured, 'waitForUnsignedWork')) {
    ordinaryFunction(captured.waitForUnsignedWork, 'control plane authority.waitForUnsignedWork');
  }
  if (!captured.operatorAuth || typeof captured.operatorAuth !== 'object'
      || utilTypes.isProxy(captured.operatorAuth)) {
    fail('CONTROL_PLANE_DEPENDENCY', 'operator authentication facade is invalid');
  }
  let operatorReads;
  try {
    operatorReads = captureFunctionSurface(
      captured.operatorReads,
      OPERATOR_READ_NAMES,
      'operator read services',
    );
  } catch (cause) {
    fail(
      'CONTROL_PLANE_DEPENDENCY',
      'operator read services must be one exact narrow function facade',
      cause,
    );
  }
  return Object.freeze({
    ...captured,
    operatorReads,
    agentAuthDependencies: captureDependencyBag(
      captured.agentAuthDependencies,
      'agent authentication dependencies',
    ),
    reconcilerDependencies: captureDependencyBag(
      captured.reconcilerDependencies,
      'reconciler dependencies',
    ),
    recoveryDependencies: captureDependencyBag(
      captured.recoveryDependencies,
      'recovery dependencies',
    ),
  });
}

function validateWalletIdentity(value, config) {
  const network = ownData(value, 'network', 'CONTROL_PLANE_WALLET', 'wallet identity');
  const address = ownData(value, 'address', 'CONTROL_PLANE_WALLET', 'wallet identity');
  if (network !== config.network || typeof address !== 'string'
      || !ADDRESS_PATTERN.test(address)) {
    fail('CONTROL_PLANE_WALLET', 'wallet identity differs from the closed configuration');
  }
  return Object.freeze({ network, address });
}

function validatePolicyVersion(value, walletIdentity) {
  const id = ownData(value, 'id', 'POLICY_CORRUPTION', 'active PolicyVersion');
  const hash = ownData(value, 'hash', 'POLICY_CORRUPTION', 'active PolicyVersion');
  const document = ownData(value, 'policy', 'POLICY_CORRUPTION', 'active PolicyVersion');
  canonicalToken(id, 'POLICY_CORRUPTION', 'active PolicyVersion ID');
  canonicalHash(hash, 'POLICY_CORRUPTION', 'active PolicyVersion hash');
  let policy;
  try {
    policy = validatePolicyDocument(document);
  } catch (cause) {
    fail('POLICY_CORRUPTION', 'active PolicyVersion document is invalid', cause);
  }
  if (canonicalJson(policy) !== canonicalJson(document)
      || sha256(canonicalJson(policy)) !== hash
      || policy.wallet !== walletIdentity.address
      || policy.network !== walletIdentity.network) {
    fail('POLICY_CORRUPTION', 'active PolicyVersion differs from wallet authority');
  }
  return Object.freeze({ id, hash, policy });
}

function validateEnrollment(value, config) {
  if (value === null) return null;
  const agentInstanceId = ownData(
    value,
    'agentInstanceId',
    'AGENT_ENROLLMENT_CORRUPTION',
    'active enrollment',
  );
  const credentialDigest = ownData(
    value,
    'credentialDigest',
    'AGENT_ENROLLMENT_CORRUPTION',
    'active enrollment',
  );
  const enrollmentHash = ownData(
    value,
    'enrollmentHash',
    'AGENT_ENROLLMENT_CORRUPTION',
    'active enrollment',
  );
  const agentUid = ownData(
    value,
    'agentUid',
    'AGENT_ENROLLMENT_CORRUPTION',
    'active enrollment',
  );
  const agentGid = ownData(
    value,
    'agentGid',
    'AGENT_ENROLLMENT_CORRUPTION',
    'active enrollment',
  );
  canonicalToken(
    agentInstanceId,
    'AGENT_ENROLLMENT_CORRUPTION',
    'active agent instance ID',
    INSTANCE_PATTERN,
  );
  canonicalHash(credentialDigest, 'AGENT_ENROLLMENT_CORRUPTION', 'credential digest');
  canonicalHash(enrollmentHash, 'AGENT_ENROLLMENT_CORRUPTION', 'enrollment hash');
  if (agentUid !== String(config.expectedAgentUid)
      || agentGid !== String(config.expectedAgentGid)
      || (Object.hasOwn(value, 'state') && value.state !== 'active')) {
    fail('AGENT_IDENTITY_MISMATCH', 'active enrollment differs from configured identity');
  }
  return Object.freeze({
    agentInstanceId,
    credentialDigest,
    enrollmentHash,
    agentUid,
    agentGid,
  });
}

function assertRoutePolicyBindings(routes, activePolicy, mode) {
  for (const route of routes.routes) {
    const parsed = new URL(route.upstreamUrl);
    const sellers = activePolicy.policy.sellers.filter((seller) => seller.origin === parsed.origin);
    if (sellers.length !== 1
        || !activePolicy.policy.methods.includes(route.method)
        || !sellers[0].pathPrefixes.some((prefix) => parsed.pathname.startsWith(prefix))) {
      fail(
        'ROUTE_POLICY_MISMATCH',
        'configured route is not authorized by one exact active PolicyVersion seller binding',
      );
    }
  }
  if (mode === 'cdp-testnet'
      && activePolicy.policy.sellers.some((seller) => (
        new URL(seller.origin).protocol !== 'https:'
        || new URL(seller.evidencePath, `${seller.origin}/`).protocol !== 'https:'
      ))) {
    fail('ROUTE_POLICY_MISMATCH', 'live policy sellers and evidence must use HTTPS');
  }
}

function captureBinding(value, enrollment, walletIdentity, activePolicy) {
  const fields = captureRecord(value, 'agent session binding', {
    allowed: new Set([
      'bindingId', 'agentInstanceId', 'credentialDigest', 'enrollmentHash', 'state', 'session',
    ]),
    required: [
      'bindingId', 'agentInstanceId', 'credentialDigest', 'enrollmentHash', 'state', 'session',
    ],
  });
  const sessionValue = fields.session;
  if (!sessionValue || typeof sessionValue !== 'object' || utilTypes.isProxy(sessionValue)) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'agent binding references no Spend Session');
  }
  const sessionFields = Object.fromEntries([
    'id', 'agentInstanceId', 'enrollmentHash', 'walletAddress', 'policyVersionId', 'state',
  ].map((name) => [name, ownData(
    sessionValue,
    name,
    'SESSION_AUTHORITY_AMBIGUOUS',
    'bound Spend Session',
  )]));
  if (typeof fields.bindingId !== 'string' || fields.bindingId.length === 0
      || fields.state !== 'open'
      || fields.agentInstanceId !== enrollment.agentInstanceId
      || fields.credentialDigest !== enrollment.credentialDigest
      || fields.enrollmentHash !== enrollment.enrollmentHash
      || sessionFields.agentInstanceId !== enrollment.agentInstanceId
      || sessionFields.enrollmentHash !== enrollment.enrollmentHash
      || sessionFields.walletAddress !== walletIdentity.address
      || !['open', 'policy_blocked'].includes(sessionFields.state)) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'agent Spend Session binding is inconsistent');
  }
  if (sessionFields.state === 'open' && sessionFields.policyVersionId !== activePolicy.id) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'open binding is pinned to a non-active policy');
  }
  if (sessionFields.state === 'policy_blocked'
      && sessionFields.policyVersionId === activePolicy.id) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'blocked binding is already pinned to active policy');
  }
  return Object.freeze({ ...fields, session: sessionValue });
}

function validateBindings(value, enrollment, walletIdentity, activePolicy) {
  if (!Array.isArray(value) || value.length > 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'agent has multiple candidate Spend Sessions');
  }
  if (value.length === 0) return null;
  return captureBinding(value[0], enrollment, walletIdentity, activePolicy);
}

function recoveryOnlyAgentApp() {
  const app = new Hono({ strict: true });
  app.all('/agent/v1/*', (context) => {
    context.header('Cache-Control', 'no-store');
    context.header('X-Content-Type-Options', 'nosniff');
    return context.json({
      error: {
        code: 'AGENT_ENROLLMENT_REQUIRED',
        message: 'Agent enrollment is required',
      },
    }, 503);
  });
  app.notFound((context) => context.json({
    error: {
      code: 'AGENT_ROUTE_NOT_FOUND',
      message: 'Agent route does not exist',
    },
  }, 404, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }));
  return app;
}

function ensureFacade(value, methods, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  for (const method of methods) {
    ordinaryFunction(ownData(value, method, 'CONTROL_PLANE_DEPENDENCY', label), `${label}.${method}`);
  }
  return value;
}

function forbiddenRecoveryOperation() {
  throw new KernelError(
    'RECOVERY_ONLY_OPERATION_FORBIDDEN',
    'operation is forbidden while the Wallet Kernel is recovery-only',
  );
}

function transitionRequest(value) {
  const request = captureRecord(value, 'session policy transition service request', {
    allowed: new Set(['sessionId', 'targetPolicyHash', 'expectedSessionHash']),
    required: ['sessionId', 'targetPolicyHash', 'expectedSessionHash'],
  });
  canonicalToken(request.sessionId, 'SESSION_TRANSITION_SCHEMA', 'session ID');
  canonicalHash(request.targetPolicyHash, 'SESSION_TRANSITION_SCHEMA', 'target policy hash');
  canonicalHash(request.expectedSessionHash, 'SESSION_TRANSITION_SCHEMA', 'session hash');
  return request;
}

function publicPolicyApplyResult(value, expectedPolicyHash) {
  const resultFields = ['policyVersion', 'blockedSessionIds', 'idempotent'];
  const result = captureRecord(value, 'policy mutation result', {
    allowed: new Set(resultFields),
    required: resultFields,
  });
  const versionFields = [
    'id', 'schemaVersion', 'policy', 'canonicalJson', 'hash', 'predecessorHash', 'appliedAt',
  ];
  const version = captureRecord(result.policyVersion, 'applied PolicyVersion', {
    allowed: new Set(versionFields),
    required: versionFields,
  });
  const policy = validatePolicyDocument(version.policy);
  const canonical = canonicalJson(policy);
  const blockedSessionIds = captureCanonicalTokenArray(
    result.blockedSessionIds,
    'POLICY_CORRUPTION',
    'blocked Spend Session IDs',
    10_000,
  );
  const appliedMilliseconds = typeof version.appliedAt === 'string'
    ? Date.parse(version.appliedAt)
    : Number.NaN;
  canonicalToken(version.id, 'POLICY_CORRUPTION', 'PolicyVersion ID');
  if (version.schemaVersion !== policy.schemaVersion
      || version.canonicalJson !== canonical
      || version.hash !== expectedPolicyHash
      || version.hash !== sha256(canonical)
      || (version.predecessorHash !== null
        && (typeof version.predecessorHash !== 'string'
          || !HASH_PATTERN.test(version.predecessorHash)))
      || !Number.isFinite(appliedMilliseconds)
      || new Date(appliedMilliseconds).toISOString() !== version.appliedAt
      || typeof result.idempotent !== 'boolean') {
    fail('POLICY_CORRUPTION', 'policy mutation returned a corrupt public projection');
  }
  return Object.freeze({
    policyVersion: Object.freeze({
      versionId: version.id,
      policy,
      policyHash: version.hash,
      predecessorHash: version.predecessorHash,
      createdAt: version.appliedAt,
      active: true,
    }),
    blockedSessionIds,
    idempotent: result.idempotent,
  });
}

function publicApprovalResult(value, expectedOperatorIdHash) {
  const fields = [
    'approvalId',
    'intentId',
    'decision',
    'operatorIdHash',
    'intentHash',
    'challengeHash',
    'quoteId',
    'acceptedIndex',
    'amountCeilingAtomic',
    'walletAddress',
    'policyVersionId',
    'expiresAt',
    'reasonCode',
    'decidedAt',
    'consumedAt',
  ];
  const approval = captureRecord(value, 'approval mutation result', {
    allowed: new Set(fields),
    required: fields,
  });
  if (approval.operatorIdHash !== expectedOperatorIdHash) {
    fail('APPROVAL_CORRUPTION', 'approval mutation changed its operator authority');
  }
  return Object.freeze({
    approvalId: approval.approvalId,
    intentId: approval.intentId,
    decision: approval.decision,
    intentHash: approval.intentHash,
    challengeHash: approval.challengeHash,
    quoteId: approval.quoteId,
    acceptedIndex: approval.acceptedIndex,
    amountAtomic: approval.amountCeilingAtomic,
    walletAddress: approval.walletAddress,
    policyVersionId: approval.policyVersionId,
    expiresAt: approval.expiresAt,
    reasonCode: approval.reasonCode,
    recordedAt: approval.decidedAt,
    consumedAt: approval.consumedAt,
  });
}

function publicRevocationResult(value, expected) {
  const result = captureRecord(value, 'agent revocation result', {
    allowed: new Set(['enrollment', 'boundSessionIds']),
    required: ['enrollment', 'boundSessionIds'],
  });
  const fields = [
    'agentInstanceId',
    'credentialDigest',
    'enrollmentHash',
    'agentUid',
    'agentGid',
    'state',
    'enrolledByOperatorHash',
    'enrolledAt',
    'revokedByOperatorHash',
    'revokedAt',
    'isolation',
  ];
  const enrollment = captureRecord(result.enrollment, 'revoked agent enrollment', {
    allowed: new Set(fields),
    required: fields,
  });
  const sessions = captureCanonicalTokenArray(
    result.boundSessionIds,
    'AGENT_ENROLLMENT_CORRUPTION',
    'revoked enrollment bound Spend Session IDs',
    10_000,
  );
  const enrolledAt = typeof enrollment.enrolledAt === 'string'
    ? Date.parse(enrollment.enrolledAt)
    : Number.NaN;
  const revokedAt = typeof enrollment.revokedAt === 'string'
    ? Date.parse(enrollment.revokedAt)
    : Number.NaN;
  canonicalToken(
    enrollment.agentInstanceId,
    'AGENT_ENROLLMENT_CORRUPTION',
    'revoked Agent instance ID',
    INSTANCE_PATTERN,
  );
  for (const [hash, label] of [
    [enrollment.credentialDigest, 'revoked credential digest'],
    [enrollment.enrollmentHash, 'revoked enrollment hash'],
    [enrollment.enrolledByOperatorHash, 'enrollment operator hash'],
    [enrollment.revokedByOperatorHash, 'revocation operator hash'],
  ]) canonicalHash(hash, 'AGENT_ENROLLMENT_CORRUPTION', label);
  if (enrollment.agentInstanceId !== expected.agentInstanceId
      || enrollment.enrollmentHash !== expected.expectedEnrollmentHash
      || enrollment.revokedByOperatorHash !== expected.operatorIdHash
      || !/^[1-9][0-9]*$/.test(enrollment.agentUid)
      || !/^[1-9][0-9]*$/.test(enrollment.agentGid)
      || !Number.isSafeInteger(Number(enrollment.agentUid))
      || !Number.isSafeInteger(Number(enrollment.agentGid))
      || enrollment.state !== 'revoked'
      || !new Set(['simulated', 'pending_verification']).has(enrollment.isolation)
      || !Number.isFinite(enrolledAt)
      || new Date(enrolledAt).toISOString() !== enrollment.enrolledAt
      || !Number.isFinite(revokedAt)
      || new Date(revokedAt).toISOString() !== enrollment.revokedAt
      || revokedAt < enrolledAt) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'agent revocation returned a corrupt public projection');
  }
  return Object.freeze({
    agentEnrollment: Object.freeze({
      agentInstanceId: enrollment.agentInstanceId,
      enrollmentHash: enrollment.enrollmentHash,
      agentUid: enrollment.agentUid,
      agentGid: enrollment.agentGid,
      state: enrollment.state,
      isolation: enrollment.isolation,
      enrolledAt: enrollment.enrolledAt,
      revokedAt: enrollment.revokedAt,
    }),
    sessions,
  });
}

function publicClosedSessionResult(value, expectedSessionId) {
  const result = captureRecord(value, 'guarded session close result', {
    allowed: new Set(['closedSession']),
    required: ['closedSession'],
  });
  const fields = [
    'id', 'adapterId', 'agentInstanceId', 'enrollmentHash', 'walletAddress',
    'policyVersionId', 'state', 'createdAt', 'closedAt', 'sessionHash',
  ];
  const session = captureRecord(result.closedSession, 'closed Spend Session', {
    allowed: new Set(fields),
    required: fields,
  });
  canonicalToken(session.id, 'SESSION_AUTHORITY_AMBIGUOUS', 'closed Spend Session ID');
  canonicalToken(session.adapterId, 'SESSION_AUTHORITY_AMBIGUOUS', 'closed adapter ID');
  canonicalToken(
    session.agentInstanceId,
    'SESSION_AUTHORITY_AMBIGUOUS',
    'closed Agent instance ID',
    INSTANCE_PATTERN,
  );
  canonicalHash(session.enrollmentHash, 'SESSION_AUTHORITY_AMBIGUOUS', 'enrollment hash');
  canonicalToken(
    session.policyVersionId,
    'SESSION_AUTHORITY_AMBIGUOUS',
    'closed PolicyVersion ID',
  );
  canonicalHash(session.sessionHash, 'SESSION_AUTHORITY_AMBIGUOUS', 'closed session hash');
  const createdAt = typeof session.createdAt === 'string' ? Date.parse(session.createdAt) : NaN;
  const closedAt = typeof session.closedAt === 'string' ? Date.parse(session.closedAt) : NaN;
  if (session.id !== expectedSessionId
      || typeof session.walletAddress !== 'string'
      || !ADDRESS_PATTERN.test(session.walletAddress)
      || session.state !== 'closed'
      || !Number.isFinite(createdAt)
      || new Date(createdAt).toISOString() !== session.createdAt
      || !Number.isFinite(closedAt)
      || new Date(closedAt).toISOString() !== session.closedAt
      || closedAt < createdAt) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'guarded close returned a corrupt public projection');
  }
  return Object.freeze({ session: Object.freeze(session) });
}

function createOperatorServices({ mode, authority, kernel, reconciler, walletIdentity }) {
  const read = authority.operatorReads;
  const forbidden = async () => forbiddenRecoveryOperation();
  const normal = mode === 'normal';
  return Object.freeze({
    overview: read.overview,
    listPolicies: normal ? read.listPolicies : forbidden,
    walletIdentity: read.walletIdentity,
    applyPolicy: normal ? async (input) => publicPolicyApplyResult(
      await kernel.applyPolicy(input),
      input.expectedPolicyHash,
    ) : forbidden,
    revokeAgent: normal ? async (input) => publicRevocationResult(
      await kernel.revokeAgent(input),
      input,
    ) : forbidden,
    transitionSessionPolicy: normal ? async (input) => {
      const request = transitionRequest(input);
      const target = validatePolicyVersion(authority.activePolicy(), walletIdentity);
      if (target.hash !== request.targetPolicyHash) {
        fail('POLICY_NOT_ACTIVE', 'target policy hash is not the active PolicyVersion');
      }
      return await kernel.transitionSessionPolicy(Object.freeze({
        sessionId: request.sessionId,
        targetPolicyVersionId: target.id,
        expectedSessionHash: request.expectedSessionHash,
      }));
    } : forbidden,
    closeSession: normal
      ? async (input) => publicClosedSessionResult(
        await kernel.closeSession(input),
        input.sessionId,
      )
      : async (input) => publicClosedSessionResult(
        await authority.recoverySessionCloser(input),
        input.sessionId,
      ),
    listApprovals: normal ? read.listApprovals : forbidden,
    approvePending: normal ? async (input) => publicApprovalResult(
      await kernel.approvePending(input),
      input.operatorIdHash,
    ) : forbidden,
    denyPending: normal ? (input) => kernel.denyPending(input) : forbidden,
    listReceipts: read.listReceipts,
    getReceipt: read.getReceipt,
    reconcilePayment: (input) => reconciler.reconcilePayment(input),
    reconcileExecution: (input) => reconciler.reconcileExecution(input),
    reconcileRefundObservation: (input) => reconciler.observeRefund(input),
    abandonCandidate: (input) => reconciler.abandonCandidate(input),
    exportSession: read.exportSession,
    receiptPublicKey: read.receiptPublicKey,
  });
}

function operatorOrigin(endpoints) {
  return `http://${endpoints.operatorHost}:${endpoints.operatorPort}`;
}

function createOperatorApplications({ dependencies, config, endpoints, authority, services }) {
  const origin = operatorOrigin(endpoints);
  const common = {
    auth: authority.operatorAuth,
    services,
    bodyLimits: Object.freeze({ jsonBytes: 1_048_576 }),
    mode: config.mode,
    origin,
  };
  if (config.mode === 'deterministic') {
    const api = dependencies.createOperatorApp({ ...common, transport: 'loopback-demo' });
    return Object.freeze({
      admin: null,
      console: dependencies.createOperatorConsoleApp({ operatorApp: api }),
    });
  }
  const admin = dependencies.createOperatorApp({ ...common, transport: 'unix' });
  const consoleApi = dependencies.createOperatorApp({
    ...common,
    transport: 'socket-activated-loopback',
  });
  return Object.freeze({
    admin,
    console: dependencies.createOperatorConsoleApp({ operatorApp: consoleApi }),
  });
}

function healthProjection(state) {
  return Object.freeze({
    mode: state.compositionMode,
    admission: state.gate,
    reasonCode: state.reasonCode,
    deployment: state.deployment,
    isolation: state.isolation,
    sessionState: state.sessionState,
  });
}

async function closeResource(resource) {
  if (!resource) return;
  const close = resource.close;
  if (typeof close !== 'function' || utilTypes.isProxy(close)) {
    throw new TypeError('control plane lifecycle resource must expose close()');
  }
  await Reflect.apply(close, resource, []);
}

async function closeCreatedAuthority(authority, lock) {
  let firstError = null;
  for (const resource of [authority, lock]) {
    try {
      await closeResource(resource);
    } catch (error) {
      firstError ??= error;
    }
  }
  if (firstError) throw firstError;
}

export async function createControlPlane(options = undefined) {
  const captured = captureOptions(options);
  const dependencies = defaultsFor(captured.dependencies);
  const modeHint = configuredModeHint(captured.env);
  let release = null;
  if (modeHint === 'cdp-testnet') {
    release = await dependencies.verifyRelease(Object.freeze({
      env: captured.env,
      checkoutRoot: dependencies.checkoutRoot,
    }));
  }
  const loaded = validateLoadedConfig(dependencies.loadConfig({
    env: captured.env,
    checkoutRoot: dependencies.checkoutRoot,
  }));
  const config = loaded.publicConfig;
  if (modeHint !== null && modeHint !== config.mode) {
    fail('CONTROL_PLANE_CONFIG', 'early mode and validated configuration disagree');
  }
  if (config.mode === 'cdp-testnet' && release === null) {
    release = await dependencies.verifyRelease(Object.freeze({
      env: captured.env,
      checkoutRoot: dependencies.checkoutRoot,
    }));
  }
  if (config.mode === 'deterministic') {
    release = Object.freeze({ deployment: 'simulated', releaseManifestHash: null });
  } else {
    release = normalizeLiveRelease(release);
  }
  const endpoints = endpointsFor(config, dependencies.deterministicEndpoints);
  const routeDocument = await dependencies.readRouteDocument(config.routePath);
  const routes = validateRouteMap({ document: routeDocument, mode: config.mode });

  let lock = null;
  let authority = null;
  let publicPlane = null;
  const state = {
    gate: 'booting',
    reasonCode: null,
    compositionMode: null,
    deployment: config.mode === 'deterministic'
      ? 'simulated'
      : 'verified',
    isolation: config.mode === 'deterministic' ? 'simulated' : null,
    sessionState: null,
    closePromise: null,
    scheduled: false,
    constructed: false,
  };

  const scheduleClose = () => {
    if (!state.constructed || state.scheduled || !publicPlane) return;
    state.scheduled = true;
    dependencies.scheduleShutdown(() => {
      void publicPlane.close().catch(() => undefined);
    });
  };
  const markAuthorityUnhealthy = (reason) => {
    if (state.gate === 'closed') return;
    state.reasonCode = typeof reason === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/.test(reason)
      ? reason
      : 'AUTHORITY_UNHEALTHY';
    state.gate = 'closed';
    scheduleClose();
  };
  const assertAdmissionOpen = () => {
    if (state.gate !== 'open') {
      throw new KernelError(
        state.reasonCode ?? 'AUTHORITY_UNHEALTHY',
        'Wallet authority admission is closed',
      );
    }
  };

  try {
    lock = await dependencies.acquireAuthorityLock(Object.freeze({
      config,
      role: 'kernel',
    }));
    ensureFacade(lock, ['close'], 'authority lock');
    if (config.mode === 'cdp-testnet') loaded.assertCredentialPresence();
    authority = captureAuthority(await dependencies.openAuthority(Object.freeze({
      config,
      env: captured.env,
      routes,
    })));
    await dependencies.recoverAuthority(authority.recoveryDependencies);

    const walletIdentity = validateWalletIdentity(authority.walletIdentity(), config);
    const activePolicy = validatePolicyVersion(authority.activePolicy(), walletIdentity);
    assertRoutePolicyBindings(routes, activePolicy, config.mode);
    const enrollment = validateEnrollment(authority.activeEnrollment(), config);

    if (config.mode === 'cdp-testnet' && enrollment !== null) {
      const admission = await dependencies.assertLiveAdmission(Object.freeze({
        config,
        release,
        enrollment,
        walletIdentity,
        activePolicy,
      }));
      if (!admission || admission.isolation !== 'verified'
          || admission.observer !== 'verified') {
        fail('AGENT_IDENTITY_NOT_ISOLATED', 'live agent admission is not verified');
      }
      state.isolation = 'verified';
    }

    state.gate = 'open';
    const authorityMutationCoordinator = dependencies.createAuthorityMutationCoordinator({
      assertAdmissionOpen,
      markAuthorityUnhealthy,
    });
    ensureFacade(
      authorityMutationCoordinator,
      ['runExclusive'],
      'authority mutation coordinator',
    );
    const reconciler = ensureFacade(dependencies.createReconciler({
      ...authority.reconcilerDependencies,
      authorityMutationCoordinator,
      markAuthorityUnhealthy,
    }), [
      'reconcilePayment', 'reconcileExecution', 'observeRefund', 'abandonCandidate',
    ], 'reconciler');

    let kernel = null;
    let kernelDependencies = null;
    let agentApp;
    if (enrollment === null) {
      state.compositionMode = 'recovery_only';
      state.sessionState = null;
      agentApp = recoveryOnlyAgentApp();
    } else {
      state.compositionMode = 'normal';
      kernelDependencies = captureDependencyBag(
        await authority.createKernelDependencies(Object.freeze({
          config,
          release,
          enrollment,
          walletIdentity,
          activePolicy,
          routes,
        })),
        'Wallet Kernel dependencies',
      );
      kernel = ensureFacade(dependencies.createWalletKernel({
        ...kernelDependencies,
        authorityMutationCoordinator,
        markAuthorityUnhealthy,
      }), [
        'openOrResumeSession', 'applyPolicy', 'revokeAgent', 'transitionSessionPolicy',
        'closeSession', 'approvePending', 'denyPending', 'expireDueApprovals', 'execute',
        'status', 'statusByRequestId', 'receiptById',
      ], 'Wallet Kernel');
      const candidates = authority.bindingsForEnrollment(Object.freeze({
        agentInstanceId: enrollment.agentInstanceId,
        enrollmentHash: enrollment.enrollmentHash,
      }));
      const current = validateBindings(candidates, enrollment, walletIdentity, activePolicy);
      let admittedSession;
      if (current === null || current.session.state === 'open') {
        admittedSession = await kernel.openOrResumeSession(Object.freeze({
          agentInstanceId: enrollment.agentInstanceId,
          walletAddress: walletIdentity.address,
          policyVersionId: activePolicy.id,
        }));
        if (!admittedSession || typeof admittedSession !== 'object'
            || utilTypes.isProxy(admittedSession)
            || (current !== null && admittedSession.id !== current.session.id)
            || admittedSession.agentInstanceId !== enrollment.agentInstanceId
            || admittedSession.enrollmentHash !== enrollment.enrollmentHash
            || admittedSession.walletAddress !== walletIdentity.address
            || admittedSession.policyVersionId !== activePolicy.id
            || admittedSession.state !== 'open') {
          fail('SESSION_AUTHORITY_AMBIGUOUS', 'session open/resume returned different authority');
        }
      } else {
        admittedSession = current.session;
      }
      state.sessionState = admittedSession.state;
      assertAdmissionOpen();
      const agentAuth = dependencies.createAgentAuth({
        store: authority.agentAuthDependencies.store,
        intents: authority.agentAuthDependencies.intents,
        walletIdentity,
        activePolicy,
        kernelUid: typeof process.getuid === 'function' ? process.getuid() : 1,
        kernelGid: typeof process.getgid === 'function' ? process.getgid() : 1,
        expectedAgentUid: config.expectedAgentUid,
        expectedAgentGid: config.expectedAgentGid,
        mode: config.mode,
      });
      ensureFacade(agentAuth, ['authenticate', 'resolveBoundSession'], 'agent auth');
      agentApp = dependencies.createSpendControlProxy({
        agentAuth,
        kernel,
        routes,
        maximumRequestBytes: Math.max(...routes.routes.map(
          (route) => route.maximumRequestBytes,
        )),
      });
    }
    if (!agentApp || typeof agentApp.fetch !== 'function') {
      throw new TypeError('agent application must expose fetch()');
    }

    const services = createOperatorServices({
      mode: state.compositionMode,
      authority,
      kernel,
      reconciler,
      walletIdentity,
    });
    const operatorApps = createOperatorApplications({
      dependencies,
      config,
      endpoints,
      authority,
      services,
    });

    const apps = Object.freeze({
      agent: agentApp,
      operatorAdmin: operatorApps.admin,
      operatorConsole: operatorApps.console,
    });
    publicPlane = Object.freeze({
      apps,
      health: Object.freeze(() => healthProjection(state)),
      close: Object.freeze(async () => {
        if (state.closePromise) return await state.closePromise;
        state.closePromise = (async () => {
          if (state.gate !== 'closed') {
            state.gate = 'closed';
            state.reasonCode ??= 'CONTROL_PLANE_SHUTDOWN';
          }
          const internals = INTERNALS.get(publicPlane);
          let firstError = null;
          try {
            if (authority.waitForUnsignedWork) await authority.waitForUnsignedWork();
          } catch (error) {
            firstError ??= error;
          }
          for (const resource of [
            internals?.listeners.agent,
            internals?.listeners.console,
            internals?.listeners.admin,
            authority,
            lock,
          ]) {
            try {
              await closeResource(resource);
            } catch (error) {
              firstError ??= error;
            }
          }
          if (firstError) throw firstError;
        })();
        return await state.closePromise;
      }),
    });
    INTERNALS.set(publicPlane, {
      config,
      dependencies,
      endpoints,
      state,
      walletIdentity,
      operatorReads: authority.operatorReads,
      onListenerFatal: Object.freeze(() => markAuthorityUnhealthy('RUNTIME_LISTENER')),
      listeners: { admin: null, console: null, agent: null },
      startState: 'created',
    });
    state.constructed = true;
    if (state.gate === 'closed') scheduleClose();
    return publicPlane;
  } catch (error) {
    if (state.gate !== 'closed') {
      state.gate = 'closed';
      state.reasonCode = error instanceof KernelError ? error.code : 'CONTROL_PLANE_STARTUP';
    }
    try {
      await closeCreatedAuthority(authority, lock);
    } catch {
      // Preserve the startup cause; neither cleanup error nor provider text is public.
    }
    throw error;
  }
}

export async function startControlPlane(options = undefined) {
  const plane = await createControlPlane(options);
  const internals = INTERNALS.get(plane);
  if (!internals || internals.startState !== 'created') {
    await plane.close();
    fail('CONTROL_PLANE_STATE', 'control plane cannot be started twice');
  }
  internals.startState = 'starting';
  const {
    config,
    dependencies,
    endpoints,
    state,
    walletIdentity,
    operatorReads,
    onListenerFatal,
    listeners,
  } = internals;
  const ownListener = async (name, factory, input) => {
    const assertOpen = () => {
      if (state.gate !== 'open') {
        fail(state.reasonCode ?? 'AUTHORITY_UNHEALTHY', 'Listener admission closed during startup');
      }
    };
    assertOpen();
    const listener = await Reflect.apply(factory, dependencies, [Object.freeze({ ...input, onFatal: onListenerFatal })]);
    ensureFacade(listener, ['close'], `${name} listener`);
    listeners[name] = listener;
    // A synchronous fatal callback can complete plane.close() before the
    // factory resolves. Explicitly release this late listener in that case.
    if (state.gate !== 'open') {
      try { await closeResource(listener); } catch {}
      assertOpen();
    }
  };
  try {
    if (config.mode === 'cdp-testnet') {
      await ownListener('admin', dependencies.listenOperatorAdmin, {
        app: plane.apps.operatorAdmin,
        socketPath: config.operatorSocketPath,
      });
      await ownListener('console', dependencies.listenOperatorConsole, {
        app: plane.apps.operatorConsole,
        activationName: config.operatorConsoleActivationName,
        host: endpoints.operatorHost,
        port: endpoints.operatorPort,
      });
    } else {
      await ownListener('console', dependencies.listenOperatorConsole, {
        app: plane.apps.operatorConsole,
        host: endpoints.operatorHost,
        port: endpoints.operatorPort,
      });
    }
    const receiptPublicKey = projectOperatorPublicResult(
      await operatorReads.receiptPublicKey({}),
    );
    const readiness = Object.freeze({
      agentOrigin: `http://${endpoints.agentHost}:${endpoints.agentPort}`,
      operatorOrigin: operatorOrigin(endpoints),
      walletAddress: walletIdentity.address,
      receiptPublicKey,
    });
    await dependencies.prepareStartupReport(Object.freeze({
      ...readiness,
      deployment: state.deployment,
      isolation: state.isolation,
      mode: state.compositionMode,
    }));
    if (state.gate !== 'open') {
      throw new KernelError(
        state.reasonCode ?? 'AUTHORITY_UNHEALTHY',
        'Wallet authority admission closed during listener startup',
      );
    }
    await ownListener('agent', dependencies.listenAgent, {
      app: plane.apps.agent,
      host: endpoints.agentHost,
      port: endpoints.agentPort,
    });
    await dependencies.publishReady(Object.freeze({ type: 'ready', ...readiness }));
    if (state.gate !== 'open') {
      fail(state.reasonCode ?? 'AUTHORITY_UNHEALTHY', 'Listener admission closed during startup');
    }
    internals.startState = 'started';
    return plane;
  } catch (error) {
    internals.startState = 'failed';
    if (state.gate !== 'closed') {
      state.gate = 'closed';
      state.reasonCode = error instanceof KernelError ? error.code : 'CONTROL_PLANE_LISTENER';
    }
    try { await plane.close(); } catch {}
    throw error;
  }
}

// Defer the installed entrypoint until this module finishes evaluating: the
// runtime composition imports the public control-plane functions above.
const directlyExecuted = typeof process.argv[1] === 'string'
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (directlyExecuted) {
  import('./runtime/installed-service.mjs')
    .then(({ runInstalledService }) => runInstalledService())
    .catch(() => {
      process.stderr.write('RUNTIME_STARTUP_FAILED\n');
      process.exitCode = 1;
    });
}

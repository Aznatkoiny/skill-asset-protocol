import { types as utilTypes } from 'node:util';

import { Hono } from 'hono';

import {
  canonicalJson,
  exactRecord,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { validatePolicyDocument } from '../kernel/policy-engine.mjs';

const AUTH_METHODS = Object.freeze([
  'authenticateBearer',
  'authenticateBrowser',
  'exchangeBrowserSession',
  'issueBrowserLaunch',
  'revokeBrowserSession',
]);

const SERVICE_METHODS = Object.freeze([
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

const APPROVAL_STATES = new Set([
  'pending',
  'approved',
  'denied',
  'expired',
  'cancelled',
]);
const RECONCILIATION_KINDS = new Set(['payment', 'execution', 'refund-observation']);
const ABANDON_KINDS = new Set(['payment', 'refund-observation']);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const PUBLIC_RESULT_FIELDS = new Set([
  'accepted', 'acceptedIndex', 'active', 'adapterId', 'address', 'admission',
  'agent', 'agentEnrollment', 'agentGid', 'agentInstanceId', 'agentUid', 'algorithm',
  'amountAtomic',
  'approval', 'approvalId', 'approvalTtlMs', 'approvals', 'asset', 'authorizationNonce',
  'approved', 'authoritySchemaVersion', 'autoApproveAtomic', 'availableAtomic', 'binding',
  'blockedIntentCount', 'blockedSessionIds', 'blockedSessions', 'blockers', 'budget',
  'budgetReservations', 'budgets', 'buyerOutcomes', 'cancelled', 'candidate', 'caseHash',
  'commandState', 'committedAtomic', 'consumed',
  'challengeHash', 'challengeMaxAgeMs', 'chargedAtomic', 'closedAt', 'closedSessionHash',
  'consumedAt', 'correlationHash', 'createdAt', 'credentialHash', 'decision', 'defaultAction',
  'denied', 'deployment',
  'disposition', 'domain', 'enrolledAt', 'enrollment', 'enrollmentHash', 'eventHash',
  'eventHead', 'eventHeadHash', 'events', 'evidencePath', 'execution', 'executionCaseHash',
  'executionOutcomes', 'executionResolutions', 'executionSigner', 'expiresAt',
  'expired', 'exposureAtomic', 'hash', 'health', 'historyHashes', 'httpStatus',
  'humanApproveAtomic', 'id', 'idempotent', 'identityHash', 'intent', 'intentHash',
  'intentId', 'intents', 'isolation', 'issuedAt', 'items', 'keyId', 'kind', 'lastSeenAt',
  'localBinding', 'maxPendingApprovals', 'metadataHash', 'method', 'methods', 'network',
  'openCount', 'operation', 'operatorIdHash', 'origin', 'originalTransactionId', 'outcome',
  'pathPrefixes', 'payTo', 'pending',
  'payment', 'paymentAttempts', 'paymentCaseHash', 'paymentTransactionId',
  'perRequestMaxAtomic', 'policy', 'policyHash', 'policyVersion', 'policyVersionId',
  'policies', 'policyVersions', 'predecessorHash', 'preflightDigest', 'previousEventHash',
  'previousSession', 'projection',
  'projectionHash', 'publicKeyPem', 'purposeHash', 'purposeLabel', 'quoteId',
  'reasonCode', 'receipt', 'receiptHash', 'receiptId', 'receipts', 'reconciliation',
  'reconciliations', 'recordedAt', 'refund', 'refundCaseHash', 'refundSigner',
  'refundSource', 'refundTransactionId', 'refunds', 'remainingSessionAtomic',
  'releasedAtomic', 'replacementSession', 'replacementSessionHash', 'requestHash', 'requestId',
  'requestIdHash',
  'requestUrlHash', 'reservedAtomic', 'resourceHash', 'resourcePath', 'revision',
  'revokedAt', 'rolling24hMaxAtomic', 'routeHash', 'schemaVersion', 'sellerOrigin', 'session',
  'sellerSessionMaxAtomic', 'sellers', 'sessionHash', 'sessionId', 'sessionMaxAtomic',
  'sessionPolicyHash', 'sessionState', 'sessions', 'signature', 'signedReceipts', 'state',
  'status', 'supersedesReceiptHash', 'terminalReceipts',
  'terminalState', 'tokenContract', 'transactionId', 'transactionPrefix', 'unresolvedAtomic', 'updatedAt',
  'url', 'versionId', 'wallet', 'walletAddress', 'walletBlocked', 'authorizationState',
  'activePolicyHash', 'adapterHash', 'reasonCodes', 'responseHash',
]);
const PUBLIC_OPERATIONS = new Set(SERVICE_METHODS);
const RAW_HASH_PATTERN = /^[0-9a-f]{64}$/;
const SIGNATURE_PATTERN = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/][AQgw]==$/;
const PUBLIC_KERNEL_CODES = new Set([
  'AGENT_DESCRIPTOR_HASH', 'AGENT_ENROLLMENT_AMBIGUOUS', 'AGENT_ENROLLMENT_CONFLICT',
  'AGENT_ENROLLMENT_CORRUPTION', 'AGENT_ENROLLMENT_REQUIRED', 'AGENT_ENROLLMENT_STALE',
  'AGENT_IDENTITY_MISMATCH', 'AGENT_REVOKED', 'AGENT_SESSION_UNAVAILABLE',
  'APPROVAL_AUTHORITY_INACTIVE', 'APPROVAL_BINDING_MISMATCH', 'APPROVAL_CAPACITY',
  'APPROVAL_CORRUPTION', 'APPROVAL_DENIAL_REASON', 'APPROVAL_EXPIRED',
  'APPROVAL_STATE_CONFLICT', 'APPROVAL_UNKNOWN', 'AUTHORITY_BUSY',
  'AUTHORITY_RECOVERY_REQUIRED', 'AUTHORITY_SEMANTIC_CORRUPTION', 'AUTHORITY_UNHEALTHY',
  'BUDGET_CORRUPTION', 'INTENT_UNKNOWN', 'OPERATOR_BODY_FORBIDDEN',
  'OPERATOR_BODY_SCHEMA', 'OPERATOR_BODY_TOO_LARGE', 'OPERATOR_CONTENT_TYPE',
  'OPERATOR_CAPACITY', 'OPERATOR_IDENTIFIER', 'OPERATOR_QUERY_SCHEMA', 'OPERATOR_SERVICE_RESULT',
  'OPERATOR_UNAUTHORIZED', 'POLICY_CONFIRMATION_STALE', 'POLICY_CORRUPTION',
  'POLICY_ADDRESS', 'POLICY_APPROVAL_CAPACITY', 'POLICY_ASSET', 'POLICY_ATOMIC',
  'POLICY_DEFAULT', 'POLICY_EVIDENCE_PATH', 'POLICY_HASH_MISMATCH', 'POLICY_LIMIT_ORDER',
  'POLICY_METHODS', 'POLICY_NETWORK', 'POLICY_NOT_ACTIVE', 'POLICY_PATH_DUPLICATE',
  'POLICY_RESOURCE_PATH', 'POLICY_SCHEMA', 'POLICY_SCHEMA_VERSION', 'POLICY_SELLERS',
  'POLICY_SELLER_DUPLICATE', 'POLICY_SELLER_ORIGIN', 'POLICY_TIME',
  'POLICY_TRANSITION_REQUIRED', 'POLICY_VERSION_MISSING', 'POLICY_WALLET_MISMATCH',
  'PROJECTION_CORRUPTION',
  'PROJECTION_EVENT_CHAIN', 'PROJECTION_SANITIZATION', 'PROJECTION_SIGNATURE',
  'RECEIPT_CONFLICT', 'RECEIPT_CORRUPTION', 'RECEIPT_PARITY_REQUIRED',
  'RECEIPT_REVISION', 'RECEIPT_SIGNATURE', 'RECONCILIATION_CONFLICT',
  'RECONCILIATION_CORRUPTION', 'RECONCILIATION_EVIDENCE', 'RECONCILIATION_INPUT',
  'RECONCILIATION_KIND', 'RECONCILIATION_MISMATCH', 'RECONCILIATION_STATE',
  'RECONCILIATION_TIME', 'RECOVERY_ONLY_OPERATION_FORBIDDEN',
  'SESSION_AUTHORITY_AMBIGUOUS', 'SESSION_CONFIRMATION_STALE',
  'SESSION_CLOSE_BLOCKED', 'SESSION_MONETARY_AMBIGUITY', 'SESSION_STATE',
  'SESSION_STATE_CONFLICT', 'SESSION_TRANSITION_BLOCKED',
  'SESSION_UNKNOWN', 'TRANSACTION_REUSED', 'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART',
]);

function fail(code, message) {
  throw new KernelError(code, message);
}

export function projectOperatorPublicResult(
  value,
  ancestors = new Set(),
  path = [],
  state = { nodes: 0 },
) {
  state.nodes += 1;
  if (state.nodes > 20_000 || path.length > 64) {
    throw new TypeError('operator service result exceeds the public projection boundary');
  }
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new TypeError('operator service result number is not canonical');
    }
    return value;
  }
  if (typeof value === 'string') {
    const field = path.at(-1);
    if (Buffer.byteLength(value, 'utf8') > 65_536 || value.includes('\0')) {
      throw new TypeError('operator service result string is outside the public boundary');
    }
    if (field === 'operation' && !PUBLIC_OPERATIONS.has(value)) {
      throw new TypeError('operator service operation is not public');
    }
    if (field === 'reasonCode' && !/^[A-Z][A-Z0-9_]{0,127}$/.test(value)) {
      throw new TypeError('operator service reason code is not public');
    }
    if (field?.endsWith('Hash') && field !== 'receiptHash'
        && field !== 'supersedesReceiptHash'
        && !HASH_PATTERN.test(value)) {
      throw new TypeError('operator service hash is not canonical');
    }
    if ((field === 'receiptHash' || field === 'supersedesReceiptHash')
        && value !== null && !HASH_PATTERN.test(value) && !RAW_HASH_PATTERN.test(value)) {
      throw new TypeError('operator signed receipt hash is not canonical');
    }
    return value;
  }
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || ancestors.has(value)) {
    throw new TypeError('operator service result must be inert acyclic data');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype || value.length > 10_000) {
        throw new TypeError('operator service result array is outside the public boundary');
      }
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(value).length !== value.length + 1) {
        throw new TypeError('operator service result array must be dense data');
      }
      const copy = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
          throw new TypeError('operator service result array must contain data fields');
        }
        copy.push(projectOperatorPublicResult(descriptor.value, ancestors, path, state));
      }
      return Object.freeze(copy);
    }
    if (Object.getPrototypeOf(value) !== Object.prototype) {
      throw new TypeError('operator service result object must be plain data');
    }
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== 'string'
        || !descriptors[key]?.enumerable
        || !Object.hasOwn(descriptors[key], 'value')
        || !PUBLIC_RESULT_FIELDS.has(key))) {
      throw new TypeError('operator service result contains a non-public field');
    }
    if (Object.hasOwn(descriptors, 'operatorIdHash')) {
      if (!path.includes('receipt')
          || (descriptors.operatorIdHash.value !== null
            && (typeof descriptors.operatorIdHash.value !== 'string'
              || !HASH_PATTERN.test(descriptors.operatorIdHash.value)))) {
        throw new TypeError('operator identity is outside this public projection');
      }
    }
    if (Object.hasOwn(descriptors, 'authorizationState')
        && typeof descriptors.authorizationState.value !== 'boolean') {
      throw new TypeError('operator authorization state is not public');
    }
    if (Object.hasOwn(descriptors, 'tokenContract')
        && (typeof descriptors.tokenContract.value !== 'string'
          || !ADDRESS_PATTERN.test(descriptors.tokenContract.value))) {
      throw new TypeError('operator token contract is not canonical public data');
    }
    if (Object.hasOwn(descriptors, 'signature')) {
      const signature = descriptors.signature.value;
      const signedReceipt = descriptors.algorithm?.value === 'Ed25519'
        && typeof descriptors.keyId?.value === 'string'
        && HASH_PATTERN.test(descriptors.keyId.value)
        && typeof descriptors.receiptHash?.value === 'string'
        && RAW_HASH_PATTERN.test(descriptors.receiptHash.value)
        && Object.hasOwn(descriptors, 'receipt');
      const signedProjection = descriptors.domain?.value === 'wallet-kernel.projection-export.v1'
        && descriptors.algorithm?.value === 'Ed25519'
        && typeof descriptors.keyId?.value === 'string'
        && HASH_PATTERN.test(descriptors.keyId.value)
        && typeof descriptors.projectionHash?.value === 'string'
        && HASH_PATTERN.test(descriptors.projectionHash.value)
        && Object.hasOwn(descriptors, 'projection');
      if (typeof signature !== 'string' || !SIGNATURE_PATTERN.test(signature)
          || (!signedReceipt && !signedProjection)) {
        throw new TypeError('operator signature is outside a closed public bundle');
      }
    }
    const copy = {};
    for (const key of keys) {
      copy[key] = projectOperatorPublicResult(
        descriptors[key].value,
        ancestors,
        [...path, key],
        state,
      );
    }
    return Object.freeze(copy);
  } finally {
    ancestors.delete(value);
  }
}

function ownDataRecord(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be one plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length
      || keys.some((key) => typeof key !== 'string' || !names.includes(key))) {
    throw new TypeError(`${label} has an invalid shape`);
  }
  const result = {};
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} ${name} must be an enumerable data property`);
    }
    result[name] = descriptor.value;
  }
  return result;
}

function exactFunctionSurface(value, names, label) {
  const result = ownDataRecord(value, names, label);
  for (const name of names) {
    if (typeof result[name] !== 'function' || utilTypes.isProxy(result[name])) {
      throw new TypeError(`${label} ${name} must be a non-proxy function`);
    }
  }
  return Object.freeze(result);
}

function validateOrigin(origin, mode) {
  if (typeof origin !== 'string') throw new TypeError('operator origin must be a string');
  let parsed;
  try {
    parsed = new URL(origin);
  } catch {
    throw new TypeError('operator origin must be the fixed loopback console origin');
  }
  const port = Number(parsed.port);
  const validPort = parsed.port !== ''
    && Number.isSafeInteger(port)
    && port >= 1
    && port <= 65_535
    && String(port) === parsed.port;
  if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.hostname !== '127.0.0.1'
      || !validPort
      || (mode === 'cdp-testnet' && parsed.port !== '8405')
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.origin !== origin) {
    throw new TypeError('operator origin must be the fixed loopback console origin');
  }
  return origin;
}

function validateDependencies(value) {
  const dependencies = ownDataRecord(value, [
    'auth',
    'services',
    'bodyLimits',
    'mode',
    'transport',
    'origin',
  ], 'operator API dependencies');
  if (dependencies.mode !== 'deterministic' && dependencies.mode !== 'cdp-testnet') {
    throw new TypeError('operator API mode is invalid');
  }
  const legalTransport = (dependencies.mode === 'deterministic'
      && dependencies.transport === 'loopback-demo')
    || (dependencies.mode === 'cdp-testnet'
      && ['unix', 'socket-activated-loopback'].includes(dependencies.transport));
  if (!legalTransport) throw new TypeError('operator API transport is invalid for its mode');
  const limits = ownDataRecord(dependencies.bodyLimits, ['jsonBytes'], 'operator body limits');
  if (!Number.isSafeInteger(limits.jsonBytes)
      || limits.jsonBytes < 64
      || limits.jsonBytes > 1_048_576) {
    throw new TypeError('operator JSON body limit is invalid');
  }
  return Object.freeze({
    auth: exactFunctionSurface(dependencies.auth, AUTH_METHODS, 'operator auth'),
    services: exactFunctionSurface(dependencies.services, SERVICE_METHODS, 'operator services'),
    jsonBytes: limits.jsonBytes,
    mode: dependencies.mode,
    transport: dependencies.transport,
    origin: validateOrigin(dependencies.origin, dependencies.mode),
  });
}

function canonicalIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    fail('OPERATOR_IDENTIFIER', `${label} must be one bounded canonical identifier`);
  }
  return value;
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail('OPERATOR_BODY_SCHEMA', `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalTransaction(value, label) {
  if (typeof value !== 'string' || !TRANSACTION_PATTERN.test(value)) {
    fail('OPERATOR_BODY_SCHEMA', `${label} must be one canonical lowercase transaction hash`);
  }
  return value;
}

function urlFor(context) {
  return new URL(context.req.url);
}

function requireCanonicalPath(context) {
  if (urlFor(context).pathname.includes('%')) {
    fail('OPERATOR_IDENTIFIER', 'operator route identifiers must not be percent-encoded');
  }
}

function requireNoQuery(context) {
  if (urlFor(context).search !== '') {
    fail('OPERATOR_QUERY_SCHEMA', 'operator route does not accept query parameters');
  }
}

function requireNoBody(context) {
  const request = context.req.raw;
  const declared = request.headers.get('content-length');
  if (request.body !== null
      || (declared !== null && declared !== '0')
      || request.headers.has('transfer-encoding')
      || request.headers.has('content-type')) {
    fail('OPERATOR_BODY_FORBIDDEN', 'operator route does not accept a request body');
  }
}

function declaredLength(request, maximum) {
  const value = request.headers.get('content-length');
  if (value === null) return null;
  if (!/^(0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) {
    fail('OPERATOR_BODY_SCHEMA', 'Content-Length must be canonical bounded decimal text');
  }
  const length = Number(value);
  if (length > maximum) {
    fail('OPERATOR_BODY_TOO_LARGE', 'operator request body exceeds its byte limit');
  }
  return length;
}

async function readBoundedJson(request, maximum) {
  if (request.headers.get('content-type') !== 'application/json') {
    fail('OPERATOR_CONTENT_TYPE', 'operator mutation requires application/json');
  }
  const expectedLength = declaredLength(request, maximum);
  if (request.body === null) fail('OPERATOR_BODY_SCHEMA', 'operator request body is required');

  const chunks = [];
  let length = 0;
  const reader = request.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) {
        fail('OPERATOR_BODY_SCHEMA', 'operator request body stream is invalid');
      }
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        fail('OPERATOR_BODY_TOO_LARGE', 'operator request body exceeds its byte limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (expectedLength !== null && expectedLength !== length) {
    fail('OPERATOR_BODY_SCHEMA', 'operator request body length changed');
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('OPERATOR_BODY_SCHEMA', 'operator request body must be valid UTF-8 JSON');
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    fail('OPERATOR_BODY_SCHEMA', 'operator request body must be valid JSON');
  }
  try {
    if (canonicalJson(parsed) !== text) {
      fail('OPERATOR_BODY_SCHEMA', 'operator request body must be exact canonical JSON');
    }
  } catch (error) {
    if (error instanceof KernelError && error.code === 'OPERATOR_BODY_SCHEMA') throw error;
    fail('OPERATOR_BODY_SCHEMA', 'operator request body must be inert canonical JSON');
  }
  return parsed;
}

function exactBody(value, required, optional = []) {
  return exactRecord(
    value,
    required,
    optional,
    'OPERATOR_BODY_SCHEMA',
    'operator request body',
  );
}

function responseStatus(error) {
  const code = error instanceof KernelError
      && typeof error.code === 'string'
      && PUBLIC_KERNEL_CODES.has(error.code)
    ? error.code
    : null;
  if (code === null) return 500;
  if (code === 'OPERATOR_UNAUTHORIZED') return 401;
  if (code === 'OPERATOR_CAPACITY') return 429;
  if (code === 'OPERATOR_BODY_TOO_LARGE') return 413;
  if (code.endsWith('_UNKNOWN') || code === 'INTENT_UNKNOWN') return 404;
  if (code.includes('CONFLICT')
      || code.includes('STALE')
      || code.includes('MISMATCH')
      || code.endsWith('_BLOCKED')
      || code === 'RECOVERY_ONLY_OPERATION_FORBIDDEN'
      || code === 'RECONCILIATION_STATE'
      || code === 'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART') return 409;
  if (code === 'RECEIPT_PARITY_REQUIRED'
      || code === 'AUTHORITY_UNHEALTHY'
      || code === 'AUTHORITY_RECOVERY_REQUIRED') return 503;
  return 400;
}

function publicError(error) {
  if (error instanceof KernelError
      && typeof error.code === 'string'
      && PUBLIC_KERNEL_CODES.has(error.code)) {
    const status = responseStatus(error);
    let message = 'operator request was rejected';
    if (status === 401) message = 'operator authentication failed';
    if (status === 404) message = 'operator resource was not found';
    if (status === 409) message = 'operator confirmation conflicts with current authority';
    if (status === 413) message = 'operator request body exceeds its byte limit';
    if (status === 503) message = 'wallet authority requires recovery before this operation';
    return Object.freeze({ code: error.code, message });
  }
  return Object.freeze({ code: 'OPERATOR_INTERNAL', message: 'operator request failed' });
}

export function createOperatorApp(value) {
  const {
    auth,
    services,
    jsonBytes,
    transport,
    origin,
  } = validateDependencies(value);
  const combinedDemoChannel = transport === 'loopback-demo';
  const adminChannel = transport === 'unix' || combinedDemoChannel;
  const consoleChannel = transport === 'socket-activated-loopback' || combinedDemoChannel;
  const app = new Hono({ strict: true });

  app.use('*', async (context, next) => {
    context.header('Cache-Control', 'no-store');
    let requestOrigin;
    try {
      requestOrigin = new URL(context.req.url).origin;
    } catch {
      fail('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
    }
    if (requestOrigin !== origin) {
      fail('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
    }
    if (context.req.method === 'HEAD') {
      return context.body(null, 404);
    }
    await next();
  });

  app.onError((error, context) => {
    const projected = publicError(error);
    return context.json({ ok: false, error: projected }, responseStatus(error));
  });
  app.notFound((context) => context.json({
    ok: false,
    error: {
      code: 'OPERATOR_ROUTE_NOT_FOUND',
      message: 'operator route does not exist',
    },
  }, 404));

  const authenticate = async (context, { mutation, requiredChannel = null }) => {
    let principal;
    const hasBearer = context.req.raw.headers.has('authorization');
    const hasCookie = context.req.raw.headers.has('cookie');
    if (requiredChannel === 'admin') {
      if (!adminChannel) fail('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
      principal = await auth.authenticateBearer(context.req.raw, { transport });
    } else if (combinedDemoChannel && hasBearer !== hasCookie) {
      principal = hasBearer
        ? await auth.authenticateBearer(context.req.raw, { transport })
        : await auth.authenticateBrowser(context.req.raw, { mutation });
    } else if (transport === 'socket-activated-loopback') {
      principal = await auth.authenticateBrowser(context.req.raw, { mutation });
    } else if (transport === 'unix') {
      principal = await auth.authenticateBearer(context.req.raw, { transport });
    } else {
      fail('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
    }
    const operatorHashDescriptor = principal && typeof principal === 'object'
      ? Object.getOwnPropertyDescriptor(principal, 'operatorIdHash')
      : null;
    if (!principal || typeof principal !== 'object' || Array.isArray(principal)
        || utilTypes.isProxy(principal)
        || Object.getPrototypeOf(principal) !== Object.prototype
        || Reflect.ownKeys(principal).length !== 1
        || !operatorHashDescriptor?.enumerable
        || !Object.hasOwn(operatorHashDescriptor, 'value')
        || typeof operatorHashDescriptor.value !== 'string'
        || !HASH_PATTERN.test(operatorHashDescriptor.value)) {
      fail('OPERATOR_UNAUTHORIZED', 'operator authentication failed');
    }
    return Object.freeze({
      operatorIdHash: operatorHashDescriptor.value,
    });
  };

  const readMutation = async (context, required, optional = []) => {
    requireCanonicalPath(context);
    requireNoQuery(context);
    return exactBody(await readBoundedJson(context.req.raw, jsonBytes), required, optional);
  };

  const success = (context, data) => context.json({
    ok: true,
    data: projectOperatorPublicResult(data),
  });

  app.post('/operator/v1/browser-launch', async (context) => {
    if (!adminChannel) fail('OPERATOR_UNAUTHORIZED', 'browser launch requires the admin channel');
    requireNoQuery(context);
    requireNoBody(context);
    await authenticate(context, { mutation: true, requiredChannel: 'admin' });
    return success(context, await auth.issueBrowserLaunch({ transport }));
  });

  app.post('/operator/v1/session', async (context) => {
    if (!consoleChannel) fail('OPERATOR_UNAUTHORIZED', 'session exchange requires console channel');
    requireNoQuery(context);
    declaredLength(context.req.raw, jsonBytes);
    return await auth.exchangeBrowserSession(context.req.raw);
  });

  app.delete('/operator/v1/session', async (context) => {
    if (!consoleChannel) fail('OPERATOR_UNAUTHORIZED', 'session deletion requires console channel');
    requireNoQuery(context);
    requireNoBody(context);
    return await auth.revokeBrowserSession(context.req.raw);
  });

  app.get('/operator/v1/overview', async (context) => {
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.overview({}));
  });

  app.get('/operator/v1/policies', async (context) => {
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.listPolicies({}));
  });

  app.post('/operator/v1/policies/validate', async (context) => {
    await authenticate(context, { mutation: true });
    const body = await readMutation(context, ['document']);
    const policy = validatePolicyDocument(body.document);
    return success(context, Object.freeze({
      policy,
      policyHash: sha256(canonicalJson(policy)),
    }));
  });

  app.post('/operator/v1/policies/apply', async (context) => {
    await authenticate(context, { mutation: true });
    const body = await readMutation(context, ['document', 'expectedPolicyHash']);
    const expectedPolicyHash = canonicalHash(body.expectedPolicyHash, 'expected policy hash');
    const document = validatePolicyDocument(body.document);
    const actualPolicyHash = sha256(canonicalJson(document));
    if (actualPolicyHash !== expectedPolicyHash) {
      fail('POLICY_CONFIRMATION_STALE', 'displayed policy hash differs from submitted policy');
    }
    const wallet = await services.walletIdentity({});
    if (!wallet || typeof wallet !== 'object' || Array.isArray(wallet)
        || utilTypes.isProxy(wallet) || Object.getPrototypeOf(wallet) !== Object.prototype
        || Reflect.ownKeys(wallet).length !== 1 || !Object.hasOwn(wallet, 'address')
        || typeof wallet.address !== 'string' || !ADDRESS_PATTERN.test(wallet.address)) {
      fail('OPERATOR_SERVICE_RESULT', 'running wallet identity is invalid');
    }
    if (wallet.address !== document.wallet) {
      fail(
        'WALLET_ROTATION_REQUIRES_OFFLINE_RESTART',
        'policy wallet differs from the running wallet identity',
      );
    }
    return success(context, await services.applyPolicy(Object.freeze({
      document,
      expectedPolicyHash,
    })));
  });

  app.post('/operator/v1/agents/:agentInstanceId/revoke', async (context) => {
    const principal = await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const agentInstanceId = canonicalIdentifier(context.req.param('agentInstanceId'), 'agent ID');
    const body = await readMutation(context, ['expectedEnrollmentHash']);
    return success(context, await services.revokeAgent(Object.freeze({
      agentInstanceId,
      expectedEnrollmentHash: canonicalHash(body.expectedEnrollmentHash, 'enrollment hash'),
      operatorIdHash: principal.operatorIdHash,
    })));
  });

  app.post('/operator/v1/sessions/:sessionId/transition-policy', async (context) => {
    await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const sessionId = canonicalIdentifier(context.req.param('sessionId'), 'session ID');
    const body = await readMutation(context, ['targetPolicyHash', 'expectedSessionHash']);
    return success(context, await services.transitionSessionPolicy(Object.freeze({
      sessionId,
      targetPolicyHash: canonicalHash(body.targetPolicyHash, 'target policy hash'),
      expectedSessionHash: canonicalHash(body.expectedSessionHash, 'session hash'),
    })));
  });

  app.post('/operator/v1/sessions/:sessionId/close', async (context) => {
    await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const sessionId = canonicalIdentifier(context.req.param('sessionId'), 'session ID');
    const body = await readMutation(context, ['expectedSessionHash']);
    return success(context, await services.closeSession(Object.freeze({
      sessionId,
      expectedSessionHash: canonicalHash(body.expectedSessionHash, 'session hash'),
    })));
  });

  app.get('/operator/v1/approvals', async (context) => {
    await authenticate(context, { mutation: false });
    const entries = [...urlFor(context).searchParams.entries()];
    if (entries.length > 1
        || (entries.length === 1
          && (entries[0][0] !== 'state' || !APPROVAL_STATES.has(entries[0][1])))) {
      fail('OPERATOR_QUERY_SCHEMA', 'approval query is invalid');
    }
    return success(context, await services.listApprovals({
      state: entries.length === 0 ? null : entries[0][1],
    }));
  });

  app.post('/operator/v1/approvals/:approvalId/approve', async (context) => {
    const principal = await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const approvalId = canonicalIdentifier(context.req.param('approvalId'), 'approval ID');
    const body = await readMutation(context, ['expectedIntentHash']);
    return success(context, await services.approvePending(Object.freeze({
      approvalId,
      expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
      operatorIdHash: principal.operatorIdHash,
    })));
  });

  app.post('/operator/v1/approvals/:approvalId/deny', async (context) => {
    const principal = await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const approvalId = canonicalIdentifier(context.req.param('approvalId'), 'approval ID');
    const body = await readMutation(context, ['expectedIntentHash', 'reasonCode']);
    if (body.reasonCode !== 'OPERATOR_DENIED') {
      fail('APPROVAL_DENIAL_REASON', 'operator denial reason must be OPERATOR_DENIED');
    }
    return success(context, await services.denyPending(Object.freeze({
      approvalId,
      expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
      operatorIdHash: principal.operatorIdHash,
      reasonCode: body.reasonCode,
    })));
  });

  app.get('/operator/v1/receipts', async (context) => {
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.listReceipts({}));
  });

  app.get('/operator/v1/receipts/:receiptId', async (context) => {
    requireCanonicalPath(context);
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.getReceipt({
      receiptId: canonicalIdentifier(context.req.param('receiptId'), 'receipt ID'),
    }));
  });

  app.post(
    '/operator/v1/reconciliations/:intentId/:kind/abandon-candidate',
    async (context) => {
      const principal = await authenticate(context, { mutation: true });
      requireCanonicalPath(context);
      const intentId = canonicalIdentifier(context.req.param('intentId'), 'intent ID');
      const kind = context.req.param('kind');
      if (!ABANDON_KINDS.has(kind)) {
        fail('RECONCILIATION_KIND', 'candidate abandonment kind is invalid');
      }
      const body = await readMutation(context, ['expectedIntentHash', 'expectedCaseHash']);
      return success(context, await services.abandonCandidate(Object.freeze({
        intentId,
        kind,
        operatorIdHash: principal.operatorIdHash,
        expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
        expectedCaseHash: canonicalHash(body.expectedCaseHash, 'case hash'),
      })));
    },
  );

  app.post('/operator/v1/reconciliations/:intentId/:kind', async (context) => {
    const principal = await authenticate(context, { mutation: true });
    requireCanonicalPath(context);
    const intentId = canonicalIdentifier(context.req.param('intentId'), 'intent ID');
    const kind = context.req.param('kind');
    if (!RECONCILIATION_KINDS.has(kind)) {
      fail('RECONCILIATION_KIND', 'reconciliation kind is invalid');
    }
    if (kind === 'payment') {
      const body = await readMutation(
        context,
        ['expectedIntentHash', 'expectedCaseHash'],
        ['paymentTransactionId'],
      );
      return success(context, await services.reconcilePayment(Object.freeze({
        intentId,
        operatorIdHash: principal.operatorIdHash,
        expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
        expectedPaymentCaseHash: canonicalHash(body.expectedCaseHash, 'payment case hash'),
        paymentTransactionId: Object.hasOwn(body, 'paymentTransactionId')
          ? canonicalTransaction(body.paymentTransactionId, 'payment transaction ID')
          : null,
      })));
    }
    if (kind === 'execution') {
      const body = await readMutation(context, ['expectedIntentHash', 'expectedCaseHash']);
      return success(context, await services.reconcileExecution(Object.freeze({
        intentId,
        operatorIdHash: principal.operatorIdHash,
        expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
        expectedExecutionCaseHash: canonicalHash(body.expectedCaseHash, 'execution case hash'),
      })));
    }
    const body = await readMutation(
      context,
      ['expectedIntentHash', 'expectedCaseHash', 'refundTransactionId'],
    );
    return success(context, await services.reconcileRefundObservation(Object.freeze({
      intentId,
      operatorIdHash: principal.operatorIdHash,
      expectedIntentHash: canonicalHash(body.expectedIntentHash, 'intent hash'),
      expectedRefundCaseHash: canonicalHash(body.expectedCaseHash, 'refund case hash'),
      refundTransactionId: canonicalTransaction(body.refundTransactionId, 'refund transaction ID'),
    })));
  });

  app.get('/operator/v1/exports/:sessionId', async (context) => {
    requireCanonicalPath(context);
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.exportSession({
      sessionId: canonicalIdentifier(context.req.param('sessionId'), 'session ID'),
    }));
  });

  app.get('/operator/v1/receipt-public-key', async (context) => {
    requireNoQuery(context);
    await authenticate(context, { mutation: false });
    return success(context, await services.receiptPublicKey({}));
  });

  return app;
}

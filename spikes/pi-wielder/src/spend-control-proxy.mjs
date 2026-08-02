import crypto from 'node:crypto';
import { types as utilTypes } from 'node:util';

import { Hono } from 'hono';

import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  KernelError,
} from './kernel/canonical.mjs';

const SHA256 = /^sha256:[0-9a-f]{64}$/;
const RECEIPT_HASH = /^[0-9a-f]{64}$/;
const EVM_TRANSACTION = /^0x[0-9a-f]{64}$/;
const ATOMIC = /^(0|[1-9][0-9]*)$/;
const APPROVAL_POLL_INTERVAL_MS = 25;
const MAXIMUM_CONNECTED_APPROVAL_WAIT_MS = 300_000;
const MAXIMUM_APPROVAL_TRANSITIONS = 8;
const PUBLIC_OUTCOMES = new Set([
  'completed',
  'upstream_failed',
  'payment_denied',
  'payment_failed',
  'payment_unresolved',
  'payment_rejected',
  'execution_failed',
  'execution_unknown',
  'refunded',
]);
const INTENT_STATES = new Set([
  'captured', 'challenged', 'approval_pending', 'authorized', 'reserved',
  'signing', 'signed', 'retrying', 'unresolved', 'terminal',
]);
const PUBLIC_ERROR_STATUS = Object.freeze({
  AGENT_UNAUTHORIZED: 401,
  AGENT_ENROLLMENT_REQUIRED: 503,
  AGENT_ENROLLMENT_AMBIGUOUS: 503,
  AGENT_IDENTITY_MISMATCH: 503,
  AGENT_AUTHORITY_CORRUPTION: 503,
  AGENT_AUTHORITY_UNAVAILABLE: 503,
  AGENT_SESSION_UNAVAILABLE: 503,
  POLICY_TRANSITION_REQUIRED: 409,
  SESSION_POLICY_BLOCKED: 409,
  SESSION_AUTHORITY_AMBIGUOUS: 503,
  SESSION_CLOSED: 503,
  AUTHORITY_UNHEALTHY: 503,
  AUTHORITY_RECOVERY_REQUIRED: 503,
  RECEIPT_PARITY_REQUIRED: 503,
  WALLET_RECOVERY_REQUIRED: 503,
  AGENT_ROUTE_NOT_FOUND: 404,
  AGENT_IDENTIFIER: 400,
  AGENT_QUERY_FORBIDDEN: 400,
  AGENT_CONTENT_TYPE: 415,
  AGENT_BODY_REQUIRED: 400,
  AGENT_BODY_SCHEMA: 400,
  AGENT_BODY_TOO_LARGE: 413,
  AGENT_CALL_ID_INVALID: 400,
  AGENT_PREFER_INVALID: 400,
  AGENT_FORBIDDEN_HEADER: 400,
  CORRELATION_CONFLICT: 409,
  AGENT_RESPONSE_INVALID: 502,
  AGENT_READ_NOT_FOUND: 404,
  AGENT_REQUEST_ABORTED: 503,
  AGENT_APPROVAL_WAIT_TIMEOUT: 503,
});

const DEPENDENCY_FIELDS = Object.freeze([
  'agentAuth',
  'kernel',
  'routes',
  'maximumRequestBytes',
]);

function captureExactRecord(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be one plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length
      || keys.some((key) => typeof key !== 'string' || !fields.includes(key))) {
    throw new TypeError(`${label} has an invalid shape`);
  }
  const result = {};
  for (const field of fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} must contain only enumerable data fields`);
    }
    result[field] = descriptor.value;
  }
  return result;
}

function captureClosedRecord(value, required, optional, code, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, `${label} must be one plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((field) => !Object.hasOwn(value, field))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    fail(code, `${label} has an invalid shape`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, `${label} must contain only enumerable data fields`);
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function captureMethod(value, name, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new TypeError(`${label} is invalid`);
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'function' || utilTypes.isProxy(descriptor.value)) {
    throw new TypeError(`${label} must expose ${name} as one data method`);
  }
  return (...args) => Reflect.apply(descriptor.value, value, args);
}

function captureDependencies(value) {
  const input = captureExactRecord(value, DEPENDENCY_FIELDS, 'Spend Control proxy dependencies');
  if (!Number.isSafeInteger(input.maximumRequestBytes)
      || input.maximumRequestBytes < 1
      || input.maximumRequestBytes > 1_048_576) {
    throw new TypeError('Spend Control maximum request bytes is invalid');
  }
  if (!input.routes || typeof input.routes !== 'object' || utilTypes.isProxy(input.routes)
      || input.routes.schemaVersion !== 1 || !Array.isArray(input.routes.routes)
      || !Object.isFrozen(input.routes) || !Object.isFrozen(input.routes.routes)) {
    throw new TypeError('Spend Control routes must be a validated immutable route map');
  }
  const routeFields = [
    'id', 'kind', 'method', 'upstreamUrl', 'resourceDescription', 'resourceMimeType',
    'purposeLabel', 'requestContentTypes', 'maximumRequestBytes', 'maximumResponseBytes',
  ];
  for (const route of input.routes.routes) {
    if (!route || typeof route !== 'object' || utilTypes.isProxy(route)
        || !Object.isFrozen(route) || Reflect.ownKeys(route).length !== routeFields.length
        || routeFields.some((field) => {
          const descriptor = Object.getOwnPropertyDescriptor(route, field);
          return !descriptor?.enumerable || !Object.hasOwn(descriptor, 'value');
        })) {
      throw new TypeError('Spend Control routes must contain immutable validated entries');
    }
  }
  const routeLookup = captureMethod(input.routes, 'get', 'validated route map');
  if (input.routes.routes.some((route) => routeLookup(route.id) !== route)) {
    throw new TypeError('Spend Control route lookup differs from its validated entries');
  }
  return Object.freeze({
    authenticate: captureMethod(input.agentAuth, 'authenticate', 'agent auth'),
    resolveBoundSession: captureMethod(
      input.agentAuth,
      'resolveBoundSession',
      'agent auth',
    ),
    execute: captureMethod(input.kernel, 'execute', 'Wallet Kernel'),
    statusByRequestId: captureMethod(input.kernel, 'statusByRequestId', 'Wallet Kernel'),
    receiptById: captureMethod(input.kernel, 'receiptById', 'Wallet Kernel'),
    route: routeLookup,
    maximumRequestBytes: input.maximumRequestBytes,
  });
}

function fail(code, message) {
  throw new KernelError(code, message);
}

function publicError(error) {
  const code = error instanceof KernelError && Object.hasOwn(PUBLIC_ERROR_STATUS, error.code)
    ? error.code
    : 'AGENT_INTERNAL';
  const message = {
    AGENT_UNAUTHORIZED: 'Agent authentication failed',
    AGENT_ENROLLMENT_REQUIRED: 'Agent enrollment is required',
    AGENT_ENROLLMENT_AMBIGUOUS: 'Agent enrollment authority is unavailable',
    AGENT_IDENTITY_MISMATCH: 'Agent identity authority is unavailable',
    AGENT_AUTHORITY_CORRUPTION: 'Agent authority is unavailable',
    AGENT_AUTHORITY_UNAVAILABLE: 'Agent authority is unavailable',
    AGENT_SESSION_UNAVAILABLE: 'Agent Spend Session is unavailable',
    POLICY_TRANSITION_REQUIRED: 'Agent Spend Session requires a policy transition',
    SESSION_POLICY_BLOCKED: 'Agent Spend Session requires a policy transition',
    SESSION_AUTHORITY_AMBIGUOUS: 'Agent Spend Session authority is unavailable',
    SESSION_CLOSED: 'Agent Spend Session is unavailable',
    AUTHORITY_UNHEALTHY: 'Wallet authority requires recovery',
    AUTHORITY_RECOVERY_REQUIRED: 'Wallet authority requires recovery',
    RECEIPT_PARITY_REQUIRED: 'Wallet authority requires recovery',
    WALLET_RECOVERY_REQUIRED: 'Wallet authority requires recovery',
    AGENT_ROUTE_NOT_FOUND: 'Agent route does not exist',
    AGENT_IDENTIFIER: 'Agent route identifier is invalid',
    AGENT_QUERY_FORBIDDEN: 'Agent routes do not accept query parameters',
    AGENT_CONTENT_TYPE: 'Agent request requires application/json',
    AGENT_BODY_REQUIRED: 'Agent request body is required',
    AGENT_BODY_SCHEMA: 'Agent request body must be one valid JSON object',
    AGENT_BODY_TOO_LARGE: 'Agent request body exceeds its byte limit',
    AGENT_CALL_ID_INVALID: 'Agent call ID must be one canonical 32-byte token',
    AGENT_PREFER_INVALID: 'Agent approval wait preference is invalid',
    AGENT_FORBIDDEN_HEADER: 'Agent request contains a forbidden authority header',
    CORRELATION_CONFLICT: 'Agent call ID is already bound to a different request',
    AGENT_RESPONSE_INVALID: 'Upstream response could not be delivered safely',
    AGENT_READ_NOT_FOUND: 'Agent resource was not found',
    AGENT_REQUEST_ABORTED: 'Agent request ended before approval completed',
    AGENT_APPROVAL_WAIT_TIMEOUT: 'Agent approval wait reached its safety bound',
    AGENT_INTERNAL: 'Agent request failed',
  }[code];
  return Object.freeze({ code, message });
}

function errorStatus(error) {
  return error instanceof KernelError && Object.hasOwn(PUBLIC_ERROR_STATUS, error.code)
    ? PUBLIC_ERROR_STATUS[error.code]
    : 500;
}

function requestUrl(context) {
  try {
    return new URL(context.req.url);
  } catch {
    fail('AGENT_IDENTIFIER', 'agent request URL is invalid');
  }
}

function requireNoQueryOrEncoding(context) {
  const url = requestUrl(context);
  if (url.search !== '') fail('AGENT_QUERY_FORBIDDEN', 'agent route query is forbidden');
  if (url.pathname.includes('%') || url.pathname.includes('\\')) {
    fail('AGENT_IDENTIFIER', 'agent route identifiers must not be encoded');
  }
}

function requireRoute(dependencies, routeId, kind) {
  let id;
  try {
    id = canonicalToken(routeId, 'agent route ID', 64);
  } catch {
    fail('AGENT_IDENTIFIER', 'agent route ID is invalid');
  }
  const route = dependencies.route(id);
  if (!route || route.kind !== kind || route.id !== id || route.method !== 'POST') {
    fail('AGENT_ROUTE_NOT_FOUND', 'agent route does not exist');
  }
  return route;
}

const FORBIDDEN_AUTHORITY_HEADERS = Object.freeze([
  'payment-required',
  'payment-signature',
  'payment-response',
  'x-payment',
  'x-payment-required',
  'x-payment-response',
  'idempotency-key',
  'x-idempotency-key',
  'x-approval-id',
  'x-spend-session',
  'x-session-id',
  'x-wallet-address',
  'x-wallet-policy',
  'x-wallet-payee',
  'x-wallet-amount',
  'x-target-url',
  'x-http-method',
  'x-correlation-id',
  'x-request-id',
]);

function normalizedHeader(request, name, maximumBytes) {
  const value = request.headers.get(name);
  if (value === null) return null;
  if (Buffer.byteLength(value, 'utf8') > maximumBytes
      || /[\x00-\x1f\x7f]/u.test(value)) {
    fail('AGENT_FORBIDDEN_HEADER', 'agent header value is invalid');
  }
  const normalized = value.replace(/^[ \t]+|[ \t]+$/gu, '');
  if (normalized.length === 0) fail('AGENT_FORBIDDEN_HEADER', 'agent header value is empty');
  return normalized;
}

function forwardHeaders(request) {
  if (FORBIDDEN_AUTHORITY_HEADERS.some((name) => request.headers.has(name))) {
    fail('AGENT_FORBIDDEN_HEADER', 'agent supplied spend authority in a header');
  }
  const contentType = normalizedHeader(request, 'content-type', 128);
  if (contentType !== 'application/json') {
    fail('AGENT_CONTENT_TYPE', 'agent content type must be exact application/json');
  }
  const accept = normalizedHeader(request, 'accept', 512);
  const userAgent = normalizedHeader(request, 'user-agent', 512);
  return Object.freeze({
    ...(accept === null ? {} : { accept }),
    'content-type': contentType,
    ...(userAgent === null ? {} : { 'user-agent': userAgent }),
  });
}

function requiredAgentCallId(request) {
  const value = request.headers.get('x-agent-call-id');
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    fail('AGENT_CALL_ID_INVALID', 'agent call ID is missing or malformed');
  }
  const decoded = Buffer.from(value, 'base64url');
  const canonical = decoded.length === 32 && decoded.toString('base64url') === value;
  decoded.fill(0);
  if (!canonical) {
    fail('AGENT_CALL_ID_INVALID', 'agent call ID is not canonical base64url');
  }
  return value;
}

function requestedApprovalWaitMs(request) {
  const value = request.headers.get('prefer');
  if (value === null) return 0;
  if (!/^wait=(?:[1-9]|[1-9][0-9]|[12][0-9]{2}|300)$/u.test(value)) {
    fail('AGENT_PREFER_INVALID', 'approval wait preference is malformed or out of bounds');
  }
  const milliseconds = Number(value.slice('wait='.length)) * 1_000;
  if (!Number.isSafeInteger(milliseconds)
      || milliseconds < 1_000
      || milliseconds > MAXIMUM_CONNECTED_APPROVAL_WAIT_MS) {
    fail('AGENT_PREFER_INVALID', 'approval wait preference is outside its safety bound');
  }
  return milliseconds;
}

function correlationIdForAgentCall(agentCallId) {
  return `agent-call:${crypto.createHash('sha256')
    .update('wallet-kernel.agent-call.v1\0', 'utf8')
    .update(agentCallId, 'ascii')
    .digest('base64url')}`;
}

function declaredLength(request, maximum) {
  const value = request.headers.get('content-length');
  if (value === null) return null;
  if (!/^(0|[1-9][0-9]*)$/u.test(value)
      || !Number.isSafeInteger(Number(value))) {
    fail('AGENT_BODY_SCHEMA', 'Content-Length is invalid');
  }
  const length = Number(value);
  if (length > maximum) fail('AGENT_BODY_TOO_LARGE', 'agent body exceeds its byte limit');
  return length;
}

function assertDuplicateFreeJson(text) {
  let index = 0;
  const maximumDepth = 64;
  const skipWhitespace = () => {
    while (index < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[index])) index += 1;
  };
  const parseString = () => {
    if (text[index] !== '"') fail('AGENT_BODY_SCHEMA', 'JSON string is invalid');
    const start = index;
    index += 1;
    while (index < text.length) {
      const character = text[index];
      if (character === '"') {
        index += 1;
        return JSON.parse(text.slice(start, index));
      }
      if (character === '\\') {
        index += 1;
        if (text[index] === 'u') index += 5;
        else index += 1;
      } else {
        index += 1;
      }
    }
    fail('AGENT_BODY_SCHEMA', 'JSON string is unterminated');
  };
  const parsePrimitive = () => {
    const remainder = text.slice(index);
    const token = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/u.exec(remainder)?.[0];
    if (!token) fail('AGENT_BODY_SCHEMA', 'JSON primitive is invalid');
    index += token.length;
  };
  const parseValue = (depth) => {
    if (depth > maximumDepth) fail('AGENT_BODY_SCHEMA', 'JSON nesting exceeds its bound');
    skipWhitespace();
    if (text[index] === '{') {
      index += 1;
      skipWhitespace();
      const keys = new Set();
      if (text[index] === '}') { index += 1; return; }
      while (index < text.length) {
        const key = parseString();
        if (keys.has(key)) fail('AGENT_BODY_SCHEMA', 'JSON object contains a duplicate key');
        keys.add(key);
        skipWhitespace();
        if (text[index] !== ':') fail('AGENT_BODY_SCHEMA', 'JSON object separator is invalid');
        index += 1;
        parseValue(depth + 1);
        skipWhitespace();
        if (text[index] === '}') { index += 1; return; }
        if (text[index] !== ',') fail('AGENT_BODY_SCHEMA', 'JSON object separator is invalid');
        index += 1;
        skipWhitespace();
      }
      fail('AGENT_BODY_SCHEMA', 'JSON object is unterminated');
    }
    if (text[index] === '[') {
      index += 1;
      skipWhitespace();
      if (text[index] === ']') { index += 1; return; }
      while (index < text.length) {
        parseValue(depth + 1);
        skipWhitespace();
        if (text[index] === ']') { index += 1; return; }
        if (text[index] !== ',') fail('AGENT_BODY_SCHEMA', 'JSON array separator is invalid');
        index += 1;
      }
      fail('AGENT_BODY_SCHEMA', 'JSON array is unterminated');
    }
    if (text[index] === '"') {
      parseString();
      return;
    }
    parsePrimitive();
  };
  parseValue(0);
  skipWhitespace();
  if (index !== text.length) fail('AGENT_BODY_SCHEMA', 'JSON has trailing non-whitespace data');
}

async function readJsonObjectBody(request, maximum) {
  const expectedLength = declaredLength(request, maximum);
  if (request.body === null) fail('AGENT_BODY_REQUIRED', 'agent request body is required');
  const chunks = [];
  let length = 0;
  const reader = request.body.getReader();
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) fail('AGENT_BODY_SCHEMA', 'agent body stream is invalid');
      length += value.byteLength;
      if (length > maximum) {
        await reader.cancel();
        fail('AGENT_BODY_TOO_LARGE', 'agent body exceeds its byte limit');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (expectedLength !== null && expectedLength !== length) {
    fail('AGENT_BODY_SCHEMA', 'agent body length changed');
  }
  const bytes = Buffer.alloc(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text;
  let parsed;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    parsed = JSON.parse(text);
    assertDuplicateFreeJson(text);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      fail('AGENT_BODY_SCHEMA', 'agent body must be one JSON object');
    }
  } catch (error) {
    if (error instanceof KernelError && error.code === 'AGENT_BODY_SCHEMA') throw error;
    fail('AGENT_BODY_SCHEMA', 'agent body must be valid duplicate-free JSON');
  }
  return Buffer.from(canonicalJson(parsed), 'utf8');
}

function capturedExecutionResult(value) {
  return captureClosedRecord(value, [
    'requestId', 'status', 'reasonCode', 'receipt',
  ], [
    'upstreamStatus', 'body', 'expiresAt', 'replacementRequestId', 'replacementExpiresAt',
  ], 'AGENT_RESPONSE_INVALID', 'Kernel execution result');
}

function capturedStatusView(value) {
  return captureClosedRecord(value, [
    'requestId',
    'sellerOrigin',
    'purposeLabel',
    'intentState',
    'approval',
    'outcome',
    'receipt',
    'remainingSessionAtomic',
  ], [], 'AGENT_RESPONSE_INVALID', 'Kernel agent status projection');
}

function validateStatusBinding(status) {
  try {
    canonicalToken(status.requestId, 'Kernel request ID');
    canonicalToken(status.purposeLabel, 'Kernel purpose label', 64);
    const origin = new URL(status.sellerOrigin);
    if (origin.origin !== status.sellerOrigin || origin.pathname !== '/'
        || origin.search !== '' || origin.hash !== '' || origin.username || origin.password) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel seller origin is invalid');
    }
    if (!INTENT_STATES.has(status.intentState) || !ATOMIC.test(status.remainingSessionAtomic)) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel status state is invalid');
    }
  } catch (error) {
    if (error instanceof KernelError && error.code === 'AGENT_RESPONSE_INVALID') throw error;
    fail('AGENT_RESPONSE_INVALID', 'Kernel status binding is invalid');
  }
  return status;
}

function canonicalPublicOutcome(value) {
  const outcome = exactRecord(
    value,
    ['status', 'reasonCode', 'revision'],
    [],
    'AGENT_RESPONSE_INVALID',
    'Kernel BuyerOutcome projection',
  );
  if (!PUBLIC_OUTCOMES.has(outcome.status)
      || typeof outcome.reasonCode !== 'string'
      || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(outcome.reasonCode)
      || !Number.isSafeInteger(outcome.revision) || outcome.revision < 1) {
    fail('AGENT_RESPONSE_INVALID', 'Kernel BuyerOutcome projection is invalid');
  }
  return outcome;
}

function projectReceipt(value, remainingSessionAtomic, { sessionId, route = null }) {
  if (!ATOMIC.test(remainingSessionAtomic)) {
    fail('AGENT_RESPONSE_INVALID', 'Kernel session remainder is invalid');
  }
  const bundle = exactRecord(value, [
    'id', 'intentId', 'revision', 'receipt', 'receiptHash', 'signature',
    'algorithm', 'keyId', 'supersedesReceiptHash', 'createdAt',
  ], [], 'AGENT_RESPONSE_INVALID', 'signed receipt bundle');
  const receipt = exactRecord(bundle.receipt, [
    'schemaVersion', 'receiptId', 'revision', 'issuedAt', 'intent', 'outcome',
    'policy', 'approval', 'payment', 'execution', 'budget', 'reconciliation',
    'refund', 'supersedesReceiptHash',
  ], [], 'AGENT_RESPONSE_INVALID', 'signed receipt');
  const intent = exactRecord(receipt.intent, [
    'id', 'requestId', 'intentHash', 'sessionId', 'sellerOrigin', 'resourcePath', 'purposeLabel',
  ], [], 'AGENT_RESPONSE_INVALID', 'signed receipt intent');
  const outcome = exactRecord(receipt.outcome, ['status', 'reasonCode'], [],
    'AGENT_RESPONSE_INVALID', 'signed receipt outcome');
  const execution = exactRecord(receipt.execution, ['state', 'httpStatus', 'responseHash'], [],
    'AGENT_RESPONSE_INVALID', 'signed receipt execution');
  const paymentFields = receipt.payment?.state === 'none'
    ? ['state']
    : ['state', 'amountAtomic', 'network', 'asset', 'payTo', 'transactionId'];
  const payment = exactRecord(receipt.payment, paymentFields, [],
    'AGENT_RESPONSE_INVALID', 'signed receipt payment');
  const paymentStates = new Set(['none', 'not_signed', 'unresolved', 'rejected', 'settled']);
  try {
    canonicalToken(bundle.id, 'signed receipt ID');
    canonicalToken(bundle.intentId, 'signed receipt intent ID');
    canonicalToken(receipt.receiptId, 'receipt ID');
    canonicalToken(intent.id, 'receipt intent ID');
    canonicalToken(intent.requestId, 'receipt request ID');
    canonicalToken(intent.sessionId, 'receipt session ID');
    canonicalToken(intent.purposeLabel, 'receipt purpose label', 64);
    canonicalTimestamp(receipt.issuedAt, 'receipt issuedAt');
    canonicalTimestamp(bundle.createdAt, 'signed receipt createdAt');
  } catch {
    fail('AGENT_RESPONSE_INVALID', 'signed receipt identifiers are invalid');
  }
  if (receipt.schemaVersion !== 1
      || bundle.id !== receipt.receiptId
      || bundle.intentId !== intent.id
      || bundle.revision !== receipt.revision
      || bundle.createdAt !== receipt.issuedAt
      || bundle.supersedesReceiptHash !== receipt.supersedesReceiptHash
      || bundle.algorithm !== 'Ed25519'
      || typeof bundle.signature !== 'string'
      || Buffer.from(bundle.signature, 'base64').length !== 64
      || Buffer.from(bundle.signature, 'base64').toString('base64') !== bundle.signature
      || !SHA256.test(bundle.keyId)
      || !RECEIPT_HASH.test(bundle.receiptHash)
      || !PUBLIC_OUTCOMES.has(outcome.status)
      || typeof outcome.reasonCode !== 'string'
      || !/^[A-Z][A-Z0-9_]{0,127}$/u.test(outcome.reasonCode)
      || !Number.isSafeInteger(receipt.revision) || receipt.revision < 1
      || ((receipt.revision === 1) !== (receipt.supersedesReceiptHash === null))
      || (receipt.supersedesReceiptHash !== null
        && !RECEIPT_HASH.test(receipt.supersedesReceiptHash))
      || intent.sessionId !== sessionId
      || !SHA256.test(intent.intentHash)
      || typeof intent.sellerOrigin !== 'string'
      || new URL(intent.sellerOrigin).origin !== intent.sellerOrigin
      || (route !== null
        && (new URL(route.upstreamUrl).origin !== intent.sellerOrigin
          || new URL(route.upstreamUrl).pathname !== intent.resourcePath
          || route.purposeLabel !== intent.purposeLabel))
      || !paymentStates.has(payment.state)
      || (payment.state !== 'none' && !ATOMIC.test(payment.amountAtomic))
      || (payment.state !== 'none'
        && payment.transactionId !== null
        && !EVM_TRANSACTION.test(payment.transactionId))
      || (execution.httpStatus !== null
        && (!Number.isSafeInteger(execution.httpStatus)
          || execution.httpStatus < 100 || execution.httpStatus > 599))) {
    fail('AGENT_RESPONSE_INVALID', 'signed receipt projection is invalid');
  }
  const chargedAtomic = payment.state === 'settled'
    ? payment.amountAtomic
    : (payment.state === 'unresolved' ? null : '0');
  return Object.freeze({
    compact: Object.freeze({
      id: receipt.receiptId,
      hash: bundle.receiptHash,
      sellerOrigin: intent.sellerOrigin,
      chargedAtomic,
      remainingSessionAtomic,
      terminalState: outcome.status,
      transactionPrefix: payment.state === 'none' || payment.transactionId === null
        ? null
        : payment.transactionId.slice(0, 10),
    }),
    requestId: intent.requestId,
    reasonCode: outcome.reasonCode,
    revision: receipt.revision,
    httpStatus: execution.httpStatus,
  });
}

function approvalProjection(value, { allowApproved = false } = {}) {
  const approval = exactRecord(value, [
    'state', 'expiresAt', 'amountAtomic',
  ], [], 'AGENT_RESPONSE_INVALID', 'Kernel approval projection');
  if ((approval.state !== 'pending' && !(allowApproved && approval.state === 'approved'))
      || !ATOMIC.test(approval.amountAtomic) || BigInt(approval.amountAtomic) < 1n) {
    fail('AGENT_RESPONSE_INVALID', 'Kernel approval projection is invalid');
  }
  try {
    canonicalTimestamp(approval.expiresAt, 'approval expiry');
  } catch {
    fail('AGENT_RESPONSE_INVALID', 'Kernel approval expiry is invalid');
  }
  return approval;
}

function terminalHttpStatus(status, upstreamStatus) {
  if (status === 'completed' || status === 'refunded') return 200;
  if (status === 'payment_denied') return 403;
  if (status === 'payment_failed' || status === 'upstream_failed'
      || status === 'execution_unknown') return 502;
  if (status === 'payment_unresolved') return 503;
  if (status === 'payment_rejected') return 402;
  if (status === 'execution_failed') {
    return Number.isSafeInteger(upstreamStatus)
        && upstreamStatus >= 400 && upstreamStatus <= 599
      ? upstreamStatus
      : 502;
  }
  fail('AGENT_RESPONSE_INVALID', 'Kernel BuyerOutcome status is invalid');
}

function boundedResponseBody(value, maximum) {
  const isBuffer = Buffer.isBuffer(value) && Object.getPrototypeOf(value) === Buffer.prototype;
  const isBytes = value instanceof Uint8Array
    && Object.getPrototypeOf(value) === Uint8Array.prototype;
  if ((!isBuffer && !isBytes) || value.buffer instanceof SharedArrayBuffer
      || value.byteLength > maximum) {
    fail('AGENT_RESPONSE_INVALID', 'upstream response body is invalid');
  }
  return Buffer.from(value);
}

function validJsonResponseBody(value, maximum) {
  const bytes = boundedResponseBody(value, maximum);
  try {
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      fail('AGENT_RESPONSE_INVALID', 'upstream response body is not one JSON object');
    }
  } catch (error) {
    if (error instanceof KernelError) throw error;
    fail('AGENT_RESPONSE_INVALID', 'upstream response body is invalid JSON');
  }
  return bytes;
}

function validOpenAiEventStreamBody(value, maximum) {
  const bytes = boundedResponseBody(value, maximum);
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('AGENT_RESPONSE_INVALID', 'upstream event stream is invalid UTF-8');
  }
  const normalized = text.replaceAll('\r\n', '\n');
  if (normalized.includes('\r') || !normalized.endsWith('\n\n')) {
    fail('AGENT_RESPONSE_INVALID', 'upstream event stream framing is invalid');
  }
  const frames = normalized.slice(0, -2).split('\n\n');
  if (frames.length < 2 || frames.some((frame) => frame.length === 0)) {
    fail('AGENT_RESPONSE_INVALID', 'upstream event stream framing is invalid');
  }
  let eventCount = 0;
  for (let index = 0; index < frames.length; index += 1) {
    const frame = frames[index];
    if (frame.includes('\n') || !frame.startsWith('data:')) {
      fail('AGENT_RESPONSE_INVALID', 'upstream event stream contains an unsupported field');
    }
    let payload = frame.slice('data:'.length);
    if (payload.startsWith(' ')) payload = payload.slice(1);
    if (payload === '[DONE]') {
      if (index !== frames.length - 1 || eventCount === 0) {
        fail('AGENT_RESPONSE_INVALID', 'upstream event stream terminator is invalid');
      }
      continue;
    }
    if (index === frames.length - 1) {
      fail('AGENT_RESPONSE_INVALID', 'upstream event stream terminator is missing');
    }
    try {
      const parsed = JSON.parse(payload);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        fail('AGENT_RESPONSE_INVALID', 'upstream event stream data is not one JSON object');
      }
    } catch (error) {
      if (error instanceof KernelError) throw error;
      fail('AGENT_RESPONSE_INVALID', 'upstream event stream data is invalid JSON');
    }
    eventCount += 1;
  }
  return bytes;
}

function approvalWaitDelay(milliseconds, signal) {
  if (signal.aborted) {
    fail('AGENT_REQUEST_ABORTED', 'agent disconnected during approval wait');
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => {
      clearTimeout(timer);
      reject(new KernelError(
        'AGENT_REQUEST_ABORTED',
        'agent disconnected during approval wait',
      ));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, milliseconds);
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export function createSpendControlProxy(value) {
  const dependencies = captureDependencies(value);
  const app = new Hono({ strict: true });

  const secureResponseHeaders = (context) => {
    context.header('Cache-Control', 'no-store');
    context.header('X-Content-Type-Options', 'nosniff');
  };

  app.onError((error, context) => {
    secureResponseHeaders(context);
    return context.json({ error: publicError(error) }, errorStatus(error));
  });
  app.notFound((context) => {
    secureResponseHeaders(context);
    return context.json({
      error: { code: 'AGENT_ROUTE_NOT_FOUND', message: 'Agent route does not exist' },
    }, 404);
  });

  const authorize = async (context) => {
    secureResponseHeaders(context);
    const principal = await dependencies.authenticate(context.req.raw);
    const session = await dependencies.resolveBoundSession(principal);
    if (!session || typeof session !== 'object' || utilTypes.isProxy(session)) {
      throw new KernelError('AGENT_SESSION_UNAVAILABLE', 'Agent Spend Session is unavailable');
    }
    const descriptor = Object.getOwnPropertyDescriptor(session, 'id');
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new KernelError('AGENT_SESSION_UNAVAILABLE', 'Agent Spend Session is unavailable');
    }
    return Object.freeze({ id: canonicalToken(descriptor.value, 'Spend Session ID') });
  };

  const executeRoute = (kind) => async (context) => {
    const session = await authorize(context);
    requireNoQueryOrEncoding(context);
    const route = requireRoute(dependencies, context.req.param('routeId'), kind);
    const approvalWaitMs = requestedApprovalWaitMs(context.req.raw);
    const headers = forwardHeaders(context.req.raw);
    const agentCallId = requiredAgentCallId(context.req.raw);
    const bodyBytes = await readJsonObjectBody(
      context.req.raw,
      Math.min(dependencies.maximumRequestBytes, route.maximumRequestBytes),
    );
    const correlationId = correlationIdForAgentCall(agentCallId);
    const executionInput = () => Object.freeze({
      sessionId: session.id,
      routeId: route.id,
      request: Object.freeze({
        requestUrl: route.upstreamUrl,
        method: route.method,
        headers,
        bodyBytes: Buffer.from(bodyBytes),
      }),
      purposeLabel: route.purposeLabel,
      correlationId,
    });
    const readStatus = async (requestId) => {
      const status = validateStatusBinding(capturedStatusView(
        await dependencies.statusByRequestId({ sessionId: session.id, requestId }),
      ));
      if (status.requestId !== requestId
          || status.sellerOrigin !== new URL(route.upstreamUrl).origin
          || status.purposeLabel !== route.purposeLabel) {
        fail('AGENT_RESPONSE_INVALID', 'Kernel execution and status projections disagree');
      }
      return status;
    };
    const executeExact = async () => {
      const result = capturedExecutionResult(
        await dependencies.execute(executionInput()),
      );
      canonicalToken(result.requestId, 'Kernel request ID');
      return Object.freeze({ result, status: await readStatus(result.requestId) });
    };
    let { result, status } = await executeExact();

    const approvalHardDeadline = approvalWaitMs === 0 ? null : Date.now() + approvalWaitMs;
    let approvalTransitions = 0;
    while (result.status === 'payment_approval_required') {
      approvalTransitions += 1;
      if (approvalTransitions > MAXIMUM_APPROVAL_TRANSITIONS) {
        fail('AGENT_APPROVAL_WAIT_TIMEOUT', 'approval transition count reached its safety bound');
      }
      if (result.receipt !== null || result.reasonCode !== 'HUMAN_APPROVAL_REQUIRED') {
        fail('AGENT_RESPONSE_INVALID', 'Kernel approval projections disagree');
      }
      try {
        canonicalTimestamp(result.expiresAt, 'Kernel approval result expiry');
      } catch {
        fail('AGENT_RESPONSE_INVALID', 'Kernel approval result expiry is invalid');
      }
      const requestId = result.requestId;
      if (status.outcome !== null) {
        if (status.approval !== null || status.receipt === null) {
          fail('AGENT_RESPONSE_INVALID', 'Kernel raced terminal approval projection is invalid');
        }
      } else {
        const approval = approvalProjection(status.approval, { allowApproved: true });
        if (status.receipt !== null || result.expiresAt !== approval.expiresAt) {
          fail('AGENT_RESPONSE_INVALID', 'Kernel approval projections disagree');
        }
        if (approvalWaitMs === 0) {
          return context.json({
            status: 'payment_approval_required',
            requestId: result.requestId,
            approval: {
              expiresAt: approval.expiresAt,
              amountAtomic: approval.amountAtomic,
              sellerOrigin: new URL(route.upstreamUrl).origin,
              purposeLabel: route.purposeLabel,
            },
          }, 409);
        }
        while (status.approval?.state === 'pending') {
          const now = Date.now();
          if (now >= Date.parse(approval.expiresAt)
              || now >= approvalHardDeadline) break;
          await approvalWaitDelay(Math.min(
            APPROVAL_POLL_INTERVAL_MS,
            Date.parse(approval.expiresAt) - now,
            approvalHardDeadline - now,
          ), context.req.raw.signal);
          status = await readStatus(requestId);
        }
        if (Date.now() >= approvalHardDeadline
            && Date.now() < Date.parse(approval.expiresAt)
            && status.outcome === null) {
          fail('AGENT_APPROVAL_WAIT_TIMEOUT', 'connected approval wait reached its bound');
        }
      }
      if (context.req.raw.signal.aborted) {
        fail('AGENT_REQUEST_ABORTED', 'agent disconnected before approval resume');
      }
      ({ result, status } = await executeExact());
    }

    if (result.status === 'request_in_flight') {
      if (status.outcome !== null || status.receipt !== null || result.receipt !== null
          || result.reasonCode !== 'REQUEST_IN_FLIGHT') {
        fail('AGENT_RESPONSE_INVALID', 'Kernel in-flight projections disagree');
      }
      return context.json({
        status: 'request_in_flight',
        requestId: result.requestId,
        reasonCode: 'REQUEST_IN_FLIGHT',
      }, 409);
    }

    const outcome = canonicalPublicOutcome(status.outcome);
    if (outcome.status !== result.status || outcome.reasonCode !== result.reasonCode
        || status.receipt === null || result.receipt === null) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel execution and status projections disagree');
    }
    const projected = projectReceipt(status.receipt, status.remainingSessionAtomic, {
      sessionId: session.id,
      route,
    });
    const resultProjected = projectReceipt(result.receipt, status.remainingSessionAtomic, {
      sessionId: session.id,
      route,
    });
    const hasUpstreamStatus = Object.hasOwn(result, 'upstreamStatus');
    const hasBody = Object.hasOwn(result, 'body');
    const completedReplay = result.status === 'completed' && !hasUpstreamStatus && !hasBody;
    if (projected.compact.hash !== resultProjected.compact.hash
        || projected.requestId !== result.requestId
        || projected.reasonCode !== result.reasonCode
        || projected.revision !== outcome.revision
        || (result.status === 'completed'
          && (hasUpstreamStatus !== hasBody
            || (!completedReplay && (!Number.isSafeInteger(result.upstreamStatus)
            || result.upstreamStatus < 200
            || result.upstreamStatus > 299
            || result.upstreamStatus !== projected.httpStatus))))) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel signed receipt projection disagrees');
    }
    const receipt = projected.compact;
    if (result.status !== 'completed') {
      return context.json({
        status: result.status,
        requestId: result.requestId,
        reasonCode: result.reasonCode,
        receipt,
      }, terminalHttpStatus(result.status, projected.httpStatus));
    }
    if (completedReplay) {
      return context.json({
        status: 'completed_replay',
        terminalStatus: 'completed',
        requestId: result.requestId,
        reasonCode: result.reasonCode,
        projections: {
          request: `/agent/v1/intents/${encodeURIComponent(result.requestId)}`,
          receipt: `/agent/v1/receipts/${encodeURIComponent(receipt.id)}`,
        },
        receipt,
      }, 409);
    }
    const streamRequested = kind === 'openai-chat'
      && JSON.parse(bodyBytes.toString('utf8')).stream === true;
    const responseBody = streamRequested
      ? validOpenAiEventStreamBody(result.body, route.maximumResponseBytes)
      : validJsonResponseBody(result.body, route.maximumResponseBytes);
    if (kind === 'openai-chat') {
      return new Response(responseBody, {
        status: 200,
        headers: {
          'cache-control': 'no-store',
          'content-type': streamRequested
            ? 'text/event-stream; charset=utf-8'
            : route.resourceMimeType,
          'x-content-type-options': 'nosniff',
          'x-wallet-receipt-id': receipt.id,
          'x-wallet-terminal-state': receipt.terminalState,
          'x-wallet-charged-atomic': receipt.chargedAtomic ?? 'unknown',
          'x-wallet-session-remaining-atomic': receipt.remainingSessionAtomic,
          'x-wallet-transaction-prefix': receipt.transactionPrefix ?? 'none',
        },
      });
    }
    return context.json({
      status: 'completed',
      requestId: result.requestId,
      resource: {
        httpStatus: projected.httpStatus,
        contentType: route.resourceMimeType,
        body: JSON.parse(responseBody.toString('utf8')),
      },
      receipt,
    }, 200);
  };
  app.post('/agent/v1/openai/:routeId/chat/completions', executeRoute('openai-chat'));
  app.post('/agent/v1/invoke/:routeId', executeRoute('tool'));

  const requireRead = (context, parameter) => {
    requireNoQueryOrEncoding(context);
    const identifier = context.req.param(parameter);
    try {
      canonicalToken(identifier, `agent ${parameter}`, 200);
    } catch {
      fail('AGENT_IDENTIFIER', 'agent read identifier is invalid');
    }
    const request = context.req.raw;
    const declared = request.headers.get('content-length');
    if (request.body !== null
        || (declared !== null && declared !== '0')
        || request.headers.has('content-type')
        || request.headers.has('transfer-encoding')) {
      fail('AGENT_BODY_SCHEMA', 'agent read route does not accept a body');
    }
    return identifier;
  };

  const readProjection = (status, session, { expectedRequestId, expectedReceiptId = null }) => {
    validateStatusBinding(status);
    if (status.requestId !== expectedRequestId) {
      fail('AGENT_READ_NOT_FOUND', 'agent resource is outside its Spend Session');
    }
    if (status.outcome === null) {
      if (status.receipt !== null && status.approval === null) {
        fail('AGENT_RESPONSE_INVALID', 'Kernel nonterminal status projection is invalid');
      }
      if (status.approval !== null) {
        const approval = approvalProjection(status.approval, { allowApproved: true });
        if (approval.state === 'approved') {
          return Object.freeze({
            status: 'request_in_flight',
            requestId: status.requestId,
            reasonCode: 'APPROVAL_GRANTED_RETRY_REQUIRED',
          });
        }
        return Object.freeze({
          status: 'payment_approval_required',
          requestId: status.requestId,
          approval: Object.freeze({
            expiresAt: approval.expiresAt,
            amountAtomic: approval.amountAtomic,
            sellerOrigin: status.sellerOrigin,
            purposeLabel: status.purposeLabel,
          }),
        });
      }
      return Object.freeze({
        status: 'request_in_flight',
        requestId: status.requestId,
        reasonCode: 'REQUEST_IN_FLIGHT',
      });
    }
    const outcome = canonicalPublicOutcome(status.outcome);
    if (status.receipt === null) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel terminal status has no receipt');
    }
    const receipt = projectReceipt(status.receipt, status.remainingSessionAtomic, {
      sessionId: session.id,
    });
    if (receipt.requestId !== status.requestId
        || receipt.reasonCode !== outcome.reasonCode
        || receipt.revision !== outcome.revision
        || receipt.compact.terminalState !== outcome.status
        || receipt.compact.sellerOrigin !== status.sellerOrigin
        || (expectedReceiptId !== null && receipt.compact.id !== expectedReceiptId)) {
      fail('AGENT_RESPONSE_INVALID', 'Kernel status and receipt projections disagree');
    }
    return Object.freeze({
      status: outcome.status,
      requestId: status.requestId,
      reasonCode: outcome.reasonCode,
      receipt: receipt.compact,
    });
  };

  const scopedRead = async (action) => {
    try {
      const value = await action();
      if (value === null) fail('AGENT_READ_NOT_FOUND', 'agent resource was not found');
      return validateStatusBinding(capturedStatusView(value));
    } catch (error) {
      if (error instanceof KernelError
          && (error.code === 'AGENT_READ_NOT_FOUND'
            || error.code?.endsWith('_UNKNOWN')
            || error.code?.endsWith('_MISMATCH')
            || error.code === 'INTENT_UNKNOWN')) {
        fail('AGENT_READ_NOT_FOUND', 'agent resource was not found');
      }
      throw error;
    }
  };

  app.get('/agent/v1/intents/:requestId', async (context) => {
    if (context.req.method !== 'GET') return context.notFound();
    const session = await authorize(context);
    const requestId = requireRead(context, 'requestId');
    const status = await scopedRead(() => dependencies.statusByRequestId({
      sessionId: session.id,
      requestId,
    }));
    return context.json(readProjection(status, session, { expectedRequestId: requestId }), 200);
  });
  app.get('/agent/v1/receipts/:receiptId', async (context) => {
    if (context.req.method !== 'GET') return context.notFound();
    const session = await authorize(context);
    const receiptId = requireRead(context, 'receiptId');
    const status = await scopedRead(() => dependencies.receiptById({
      sessionId: session.id,
      receiptId,
    }));
    return context.json(readProjection(status, session, {
      expectedRequestId: status.requestId,
      expectedReceiptId: receiptId,
    }), 200);
  });

  return app;
}

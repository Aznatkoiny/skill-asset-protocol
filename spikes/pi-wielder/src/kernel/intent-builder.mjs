import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';
import {
  projectPaymentRequired,
  validateChallengeProjection,
  validatePolicyDocument,
} from './policy-engine.mjs';

export const FORBIDDEN_AGENT_HEADERS = Object.freeze([
  'payment-required',
  'payment-signature',
  'payment-response',
  'x-payment',
  'x-payment-required',
  'x-payment-response',
  'idempotency-key',
  'x-approval-id',
  'x-spend-session',
]);

const FORBIDDEN_HEADER_SET = new Set(FORBIDDEN_AGENT_HEADERS);
const ALLOWED_HEADER_SET = new Set(['accept', 'content-type', 'user-agent']);
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const INSTANCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const HEADER_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const ENCODED_PATH_SEPARATOR = /%(?:2f|5c)/i;
const MAX_BODY_BYTES = 1_048_576;
const MAX_HEADER_BYTES = 8_192;
const MAX_ID_ATTEMPTS = 32;

const LEGAL_TRANSITIONS = Object.freeze(new Map([
  ['captured', new Set(['challenged', 'terminal'])],
  ['challenged', new Set(['approval_pending', 'authorized', 'terminal'])],
  ['approval_pending', new Set(['authorized', 'terminal'])],
  ['authorized', new Set(['reserved', 'terminal'])],
  ['reserved', new Set(['signing', 'terminal'])],
  ['signing', new Set(['signed', 'unresolved'])],
  ['signed', new Set(['retrying', 'unresolved'])],
  ['retrying', new Set(['terminal', 'unresolved'])],
  ['unresolved', new Set(['terminal'])],
  ['terminal', new Set()],
]));

function fail(code, message) {
  throw new KernelError(code, message);
}

function closedRecord(value, required, optional, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, `${label} must be one plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    fail(code, `${label} fields do not match the closed schema`);
  }
  const copy = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, `${label} fields must be enumerable data properties`);
    }
    copy[key] = descriptor.value;
  }
  return copy;
}

function canonicalHash(value, label, code = 'INTENT_CORRUPTION') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalAddress(value, label, code = 'SESSION_SCHEMA') {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical lowercase EVM address`);
  }
  return value;
}

function canonicalInstanceId(value) {
  if (typeof value !== 'string' || !INSTANCE_ID_PATTERN.test(value)) {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  if (decoded.length !== 16 || decoded.toString('base64url') !== value) {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  return value;
}

function boundedToken(value, label, code, maximum = 200) {
  try {
    return canonicalToken(value, label, maximum);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} must be one bounded canonical token`);
    throw error;
  }
}

function isCanonicalLiteralLoopbackHttp(value, parsed) {
  if (parsed.protocol !== 'http:' || !value.startsWith('http://')) return false;
  const authority = value.slice('http://'.length).split(/[/?#]/u, 1)[0];
  if (!/^(?:127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(authority)) return false;
  return parsed.origin === `http://${authority}`;
}

function canonicalRequestUrl(value, allowLoopbackHttp) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > 4_096) {
    fail('REQUEST_URL', 'request URL must be one bounded string');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('REQUEST_URL', 'request URL must be absolute and canonical');
  }
  const allowedProtocol = parsed.protocol === 'https:'
    || (allowLoopbackHttp && isCanonicalLiteralLoopbackHttp(value, parsed));
  if (!allowedProtocol
      || parsed.username !== ''
      || parsed.password !== ''
      || value.includes('?')
      || value.includes('#')
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.href !== value
      || parsed.pathname.startsWith('//')
      || parsed.pathname.includes('\\')
      || ENCODED_PATH_SEPARATOR.test(parsed.pathname)) {
    fail('REQUEST_URL', 'request URL must be one exact queryless HTTPS or allowed loopback URL');
  }
  return Object.freeze({
    href: value,
    origin: parsed.origin,
    pathname: parsed.pathname,
  });
}

function canonicalMethod(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 32) {
    fail('REQUEST_METHOD', 'request method must be one bounded HTTP token');
  }
  const method = value.toUpperCase();
  if (!/^[A-Z][A-Z0-9-]{0,31}$/.test(method)) {
    fail('REQUEST_METHOD', 'request method must be one canonical HTTP token');
  }
  return method;
}

function canonicalHeaders(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('AGENT_HEADER_SCHEMA', 'agent headers must be one plain object');
  }
  const normalized = new Map();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string' || !HEADER_NAME_PATTERN.test(key)) {
      fail('AGENT_HEADER_SCHEMA', 'agent header name is invalid');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('AGENT_HEADER_SCHEMA', 'agent headers must contain only data properties');
    }
    const lower = key.toLowerCase();
    if (normalized.has(lower)) {
      fail('AGENT_HEADER_SCHEMA', 'case-colliding agent headers are forbidden');
    }
    if (FORBIDDEN_HEADER_SET.has(lower)) {
      fail('AGENT_HEADER_FORBIDDEN', `agent may not supply ${lower}`);
    }
    if (!ALLOWED_HEADER_SET.has(lower)) {
      fail('AGENT_HEADER_UNSUPPORTED', `agent header ${lower} is not allowlisted`);
    }
    const raw = descriptor.value;
    if (typeof raw !== 'string' || /[\x00-\x08\x0a-\x1f\x7f]/.test(raw)
        || Buffer.byteLength(raw, 'utf8') > MAX_HEADER_BYTES) {
      fail('AGENT_HEADER_SCHEMA', 'agent header value is invalid');
    }
    const trimmed = raw.replace(/^[ \t]+|[ \t]+$/g, '');
    if (trimmed.length === 0) fail('AGENT_HEADER_SCHEMA', 'agent header value is empty');
    normalized.set(lower, trimmed);
  }
  return Object.freeze(Object.fromEntries([...normalized.entries()].sort(([a], [b]) => (
    a < b ? -1 : a > b ? 1 : 0
  ))));
}

function canonicalRouteMetadata(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('routeMetadata must be one plain operator-owned map');
  }
  const normalized = new Map();
  for (const routeKey of Reflect.ownKeys(value)) {
    if (typeof routeKey !== 'string') {
      throw new TypeError('routeMetadata keys must be canonical route IDs');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, routeKey);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('routeMetadata must contain only enumerable data properties');
    }
    const routeId = boundedToken(routeKey, 'route metadata ID', 'ROUTE_METADATA');
    const metadata = closedRecord(
      descriptor.value,
      ['description', 'mimeType'],
      [],
      'ROUTE_METADATA',
      'route metadata',
    );
    if (typeof metadata.description !== 'string'
        || metadata.description.length === 0
        || Buffer.byteLength(metadata.description, 'utf8') > 1_024
        || /[\x00-\x1f\x7f]/.test(metadata.description)
        || typeof metadata.mimeType !== 'string'
        || Buffer.byteLength(metadata.mimeType, 'utf8') > 200
        || !/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/.test(
          metadata.mimeType,
        )) {
      fail('ROUTE_METADATA', 'route metadata must be bounded canonical public text');
    }
    normalized.set(routeId, Object.freeze({
      description: metadata.description,
      mimeType: metadata.mimeType,
    }));
  }
  return normalized;
}

function copyBodyBytes(value) {
  if (utilTypes.isProxy(value)) fail('REQUEST_BODY', 'request body must be inert bytes');
  const isBuffer = Buffer.isBuffer(value) && Object.getPrototypeOf(value) === Buffer.prototype;
  const isUint8 = value instanceof Uint8Array
    && Object.getPrototypeOf(value) === Uint8Array.prototype;
  if ((!isBuffer && !isUint8)
      || value.buffer instanceof SharedArrayBuffer
      || value.byteLength > MAX_BODY_BYTES) {
    fail('REQUEST_BODY', 'request body must be bounded inert bytes');
  }
  return Buffer.from(value);
}

function prepareFingerprintInput(value, { allowLoopbackHttp, allowCorrelation = false }) {
  const request = closedRecord(value, [
    'routeId',
    'method',
    'requestUrl',
    'headers',
    'bodyBytes',
    'purposeLabel',
  ], allowCorrelation ? ['correlationId'] : [], 'INTENT_SCHEMA', 'intent request');
  const routeId = boundedToken(request.routeId, 'route ID', 'ROUTE_ID');
  const method = canonicalMethod(request.method);
  const url = canonicalRequestUrl(request.requestUrl, allowLoopbackHttp);
  const headers = canonicalHeaders(request.headers);
  const bodyBytes = copyBodyBytes(request.bodyBytes);
  const purposeLabel = boundedToken(request.purposeLabel, 'purpose label', 'PURPOSE_LABEL');
  const requestUrlHash = sha256(url.href);
  const bodyHash = sha256(bodyBytes);
  const headerAllowlistHash = sha256(canonicalJson(headers));
  const ordinary = Object.freeze({
    routeId,
    method,
    requestUrlHash,
    bodyHash,
    headerAllowlistHash,
    purposeLabel,
  });
  return Object.freeze({
    routeId,
    method,
    requestUrl: url.href,
    requestUrlHash,
    sellerOrigin: url.origin,
    resourcePath: url.pathname,
    bodyHash,
    headerAllowlistHash,
    purposeLabel,
    ordinaryFingerprint: sha256(canonicalJson(ordinary)),
    ...(allowCorrelation && Object.hasOwn(request, 'correlationId')
      ? { correlationId: boundedToken(
        request.correlationId,
        'correlation ID',
        'CORRELATION_ID',
      ) }
      : {}),
  });
}

export function canonicalIntentFingerprint(value) {
  return frozenCopy(prepareFingerprintInput(value, {
    allowLoopbackHttp: false,
    allowCorrelation: false,
  }));
}

function validatePolicyRow(row) {
  if (!row) fail('POLICY_VERSION_MISSING', 'PolicyVersion does not exist');
  let parsed;
  try {
    parsed = JSON.parse(row.canonical_json);
  } catch {
    fail('POLICY_CORRUPTION', 'persisted policy JSON is invalid');
  }
  let policy;
  try {
    policy = validatePolicyDocument(parsed);
  } catch (error) {
    if (error instanceof KernelError) fail('POLICY_CORRUPTION', 'persisted policy is invalid');
    throw error;
  }
  const canonical = canonicalJson(policy);
  const hash = sha256(canonical);
  const id = boundedToken(row.id, 'policy version ID', 'POLICY_CORRUPTION');
  const appliedAt = persistedTimestamp(row.applied_at, 'policy appliedAt', 'POLICY_CORRUPTION');
  const predecessorHash = row.predecessor_hash === null
    ? null
    : canonicalHash(row.predecessor_hash, 'policy predecessor hash', 'POLICY_CORRUPTION');
  if (canonical !== row.canonical_json || hash !== row.policy_hash
      || !HASH_PATTERN.test(row.policy_hash)
      || Number(row.schema_version) !== policy.schemaVersion) {
    fail('POLICY_CORRUPTION', 'persisted PolicyVersion binding changed');
  }
  return Object.freeze({ id, policy, hash, predecessorHash, appliedAt });
}

function persistedTimestamp(value, label, code) {
  try {
    return canonicalTimestamp(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} is not canonical`);
    throw error;
  }
}

function timestampIsBefore(left, right) {
  return Date.parse(left) < Date.parse(right);
}

function validateEnrollmentRow(row, { requireActive = true } = {}) {
  if (!row) fail('AGENT_ENROLLMENT_REQUIRED', 'agent enrollment does not exist');
  if (requireActive && row.state !== 'active') fail('AGENT_REVOKED', 'agent enrollment is revoked');
  if (row.state !== 'active' && row.state !== 'revoked') {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'agent enrollment state is invalid');
  }
  let agentInstanceId;
  try {
    agentInstanceId = canonicalInstanceId(row.agent_instance_id);
  } catch (error) {
    if (error instanceof KernelError) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted agent instance ID is invalid');
    }
    throw error;
  }
  const descriptor = {
    schemaVersion: 1,
    agentInstanceId,
    credentialDigest: canonicalHash(
      row.credential_digest,
      'credential digest',
      'AGENT_ENROLLMENT_CORRUPTION',
    ),
    agentUid: row.agent_uid,
    agentGid: row.agent_gid,
  };
  if (!/^[1-9][0-9]*$/.test(descriptor.agentUid)
      || !/^[1-9][0-9]*$/.test(descriptor.agentGid)
      || !Number.isSafeInteger(Number(descriptor.agentUid))
      || !Number.isSafeInteger(Number(descriptor.agentGid))
      || String(Number(descriptor.agentUid)) !== descriptor.agentUid
      || String(Number(descriptor.agentGid)) !== descriptor.agentGid) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted agent identity is invalid');
  }
  const enrollmentHash = canonicalHash(
    row.enrollment_hash,
    'enrollment hash',
    'AGENT_ENROLLMENT_CORRUPTION',
  );
  if (sha256(canonicalJson(descriptor)) !== enrollmentHash) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment hash changed');
  }
  const enrolledByOperatorHash = canonicalHash(
    row.enrolled_by_operator_hash,
    'enrollment operator hash',
    'AGENT_ENROLLMENT_CORRUPTION',
  );
  const enrolledAt = persistedTimestamp(
    row.enrolled_at,
    'enrollment enrolledAt',
    'AGENT_ENROLLMENT_CORRUPTION',
  );
  let revokedByOperatorHash = null;
  let revokedAt = null;
  if (row.state === 'active') {
    if (row.revoked_by_operator_hash !== null || row.revoked_at !== null) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'active enrollment has revocation fields');
    }
  } else {
    revokedByOperatorHash = canonicalHash(
      row.revoked_by_operator_hash,
      'revocation operator hash',
      'AGENT_ENROLLMENT_CORRUPTION',
    );
    revokedAt = persistedTimestamp(
      row.revoked_at,
      'enrollment revokedAt',
      'AGENT_ENROLLMENT_CORRUPTION',
    );
    if (timestampIsBefore(revokedAt, enrolledAt)) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'enrollment revocation predates enrollment');
    }
  }
  return Object.freeze({
    ...descriptor,
    enrollmentHash,
    state: row.state,
    enrolledByOperatorHash,
    enrolledAt,
    revokedByOperatorHash,
    revokedAt,
  });
}

function bindingIdFor(sessionId) {
  const digest = sha256(canonicalJson({
    domain: 'wallet-kernel.session-binding.v1',
    sessionId,
  }));
  return `binding-${digest.slice('sha256:'.length)}`;
}

function correlationAliasIdFor(sessionId, correlationId) {
  const digest = sha256(canonicalJson({
    domain: 'wallet-kernel.intent-correlation-alias.v1',
    sessionId,
    correlationId,
  }));
  return `correlation-${digest.slice('sha256:'.length)}`;
}

function sessionProjection(authority) {
  return {
    session: {
      id: authority.id,
      adapterId: authority.adapterId,
      walletAddress: authority.walletAddress,
      policyVersionId: authority.policyVersionId,
      state: authority.state,
      createdAt: authority.createdAt,
      closedAt: authority.closedAt,
    },
    binding: {
      id: authority.bindingId,
      agentInstanceId: authority.agentInstanceId,
      credentialDigest: authority.credentialDigest,
      enrollmentHash: authority.enrollmentHash,
      sessionId: authority.id,
      state: authority.bindingState,
      createdAt: authority.bindingCreatedAt,
      lastSeenAt: authority.lastSeenAt,
      closedAt: authority.bindingClosedAt,
    },
  };
}

function publicSession(authority) {
  return frozenCopy({
    id: authority.id,
    adapterId: authority.adapterId,
    agentInstanceId: authority.agentInstanceId,
    enrollmentHash: authority.enrollmentHash,
    walletAddress: authority.walletAddress,
    policyVersionId: authority.policyVersionId,
    state: authority.state,
    createdAt: authority.createdAt,
    closedAt: authority.closedAt,
    sessionHash: sha256(canonicalJson(sessionProjection(authority))),
  });
}

function exactEventData(row, required, code, label) {
  let parsed;
  try {
    parsed = JSON.parse(row.data_json);
  } catch {
    fail(code, `${label} event JSON is invalid`);
  }
  const data = closedRecord(parsed, required, [], code, `${label} event data`);
  if (canonicalJson(data) !== row.data_json) {
    fail(code, `${label} event JSON is not canonical`);
  }
  persistedTimestamp(row.created_at, `${label} event createdAt`, code);
  return data;
}

function validateSessionGenesisEvents(db, authority) {
  const initialAuthority = {
    ...authority,
    state: 'open',
    closedAt: null,
    bindingState: 'open',
    lastSeenAt: authority.createdAt,
    bindingClosedAt: null,
  };
  const initialSessionHash = publicSession(initialAuthority).sessionHash;
  const sessionEvents = db.prepare(`SELECT data_json, created_at FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?
    ORDER BY sequence`).all('spend_session', authority.id, 'session.started');
  const bindingEvents = db.prepare(`SELECT data_json, created_at FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?
    ORDER BY sequence`).all('session_binding', authority.bindingId, 'session.binding_opened');
  if (sessionEvents.length !== 1 || bindingEvents.length !== 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'session genesis events are missing or ambiguous');
  }
  const sessionData = exactEventData(sessionEvents[0], [
    'adapterId',
    'enrollmentHash',
    'policyVersionId',
    'sessionHash',
    'walletAddress',
    'createdAt',
  ], 'SESSION_AUTHORITY_AMBIGUOUS', 'session.started');
  const bindingData = exactEventData(bindingEvents[0], [
    'agentInstanceId',
    'enrollmentHash',
    'sessionId',
    'createdAt',
  ], 'SESSION_AUTHORITY_AMBIGUOUS', 'session.binding_opened');
  const expectedSessionData = {
    adapterId: authority.adapterId,
    enrollmentHash: authority.enrollmentHash,
    policyVersionId: authority.policyVersionId,
    sessionHash: initialSessionHash,
    walletAddress: authority.walletAddress,
    createdAt: authority.createdAt,
  };
  const expectedBindingData = {
    agentInstanceId: authority.agentInstanceId,
    enrollmentHash: authority.enrollmentHash,
    sessionId: authority.id,
    createdAt: authority.createdAt,
  };
  if (canonicalJson(sessionData) !== canonicalJson(expectedSessionData)
      || canonicalJson(bindingData) !== canonicalJson(expectedBindingData)) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'session genesis event binding changed');
  }
}

function loadSessionCommandEvent(db, sessionId, eventType) {
  const rows = db.prepare(`SELECT data_json, created_at FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?
    ORDER BY sequence`).all('spend_session', sessionId, eventType);
  if (rows.length === 0) return null;
  if (rows.length !== 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'session command replay is ambiguous');
  }
  const fields = eventType === 'session.closed'
    ? ['expectedSessionHash', 'closedSessionHash', 'closedAt']
    : eventType === 'session.policy_transitioned'
      ? [
        'expectedSessionHash',
        'targetPolicyVersionId',
        'closedSessionHash',
        'replacementSessionId',
        'replacementSessionHash',
        'transitionedAt',
      ]
      : null;
  if (!fields) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'session command event type is unsupported');
  }
  const data = exactEventData(
    rows[0],
    fields,
    'SESSION_AUTHORITY_AMBIGUOUS',
    eventType,
  );
  canonicalHash(data.expectedSessionHash, 'expected session hash', 'SESSION_AUTHORITY_AMBIGUOUS');
  canonicalHash(data.closedSessionHash, 'closed session hash', 'SESSION_AUTHORITY_AMBIGUOUS');
  if (eventType === 'session.closed') {
    persistedTimestamp(data.closedAt, 'session close event time', 'SESSION_AUTHORITY_AMBIGUOUS');
  } else {
    boundedToken(
      data.targetPolicyVersionId,
      'target policy version ID',
      'SESSION_AUTHORITY_AMBIGUOUS',
    );
    boundedToken(
      data.replacementSessionId,
      'replacement session ID',
      'SESSION_AUTHORITY_AMBIGUOUS',
    );
    canonicalHash(
      data.replacementSessionHash,
      'replacement session hash',
      'SESSION_AUTHORITY_AMBIGUOUS',
    );
    persistedTimestamp(
      data.transitionedAt,
      'session transition event time',
      'SESSION_AUTHORITY_AMBIGUOUS',
    );
  }
  return data;
}

function validateSessionLifecycleEvents(db, authority) {
  const bindingEvents = db.prepare(`SELECT data_json, created_at FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?
    ORDER BY sequence`).all(
    'session_binding',
    authority.bindingId,
    'session.binding_closed',
  );
  const closeEvent = loadSessionCommandEvent(db, authority.id, 'session.closed');
  const transitionEvent = loadSessionCommandEvent(
    db,
    authority.id,
    'session.policy_transitioned',
  );
  if (authority.state !== 'closed') {
    if (bindingEvents.length !== 0 || closeEvent || transitionEvent) {
      fail('SESSION_AUTHORITY_AMBIGUOUS', 'live session has a close event');
    }
    return;
  }
  if (bindingEvents.length !== 1 || Number(Boolean(closeEvent)) + Number(Boolean(transitionEvent)) !== 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'closed session lifecycle events are incomplete');
  }
  const bindingData = exactEventData(bindingEvents[0], [
    'sessionId',
    'closedAt',
    'reasonCode',
  ], 'SESSION_AUTHORITY_AMBIGUOUS', 'session.binding_closed');
  boundedToken(bindingData.reasonCode, 'binding close reason', 'SESSION_AUTHORITY_AMBIGUOUS');
  persistedTimestamp(
    bindingData.closedAt,
    'binding close event time',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const closedSessionHash = publicSession(authority).sessionHash;
  if (bindingData.sessionId !== authority.id || bindingData.closedAt !== authority.closedAt) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'binding close event disagrees with session');
  }
  if (closeEvent) {
    if (bindingData.reasonCode !== 'SESSION_CLOSED'
        || closeEvent.closedAt !== authority.closedAt
        || closeEvent.closedSessionHash !== closedSessionHash) {
      fail('SESSION_AUTHORITY_AMBIGUOUS', 'session close event disagrees with authority');
    }
    return;
  }
  if (bindingData.reasonCode !== 'POLICY_SUPERSEDED'
      || transitionEvent.transitionedAt !== authority.closedAt
      || transitionEvent.closedSessionHash !== closedSessionHash
      || transitionEvent.replacementSessionId === authority.id) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'policy transition event disagrees with authority');
  }
  loadHistoricalReplacementSession(db, transitionEvent, authority);
}

function loadHistoricalReplacementSession(db, transitionEvent, previousAuthority) {
  const replacement = loadSessionAuthority(db, transitionEvent.replacementSessionId, {
    requireActive: false,
    validateEvents: false,
  });
  validateSessionGenesisEvents(db, replacement);
  const initialReplacement = {
    ...replacement,
    state: 'open',
    closedAt: null,
    bindingState: 'open',
    lastSeenAt: replacement.createdAt,
    bindingClosedAt: null,
  };
  const replacementSession = publicSession(initialReplacement);
  if (replacement.createdAt !== previousAuthority.closedAt
      || replacement.adapterId !== previousAuthority.adapterId
      || replacement.agentInstanceId !== previousAuthority.agentInstanceId
      || replacement.enrollmentHash !== previousAuthority.enrollmentHash
      || replacement.walletAddress !== previousAuthority.walletAddress
      || replacement.policyVersionId !== transitionEvent.targetPolicyVersionId
      || replacementSession.sessionHash !== transitionEvent.replacementSessionHash) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'policy replacement session binding changed');
  }
  return replacementSession;
}

function loadSessionAuthority(db, sessionId, {
  requireActive = true,
  validateEvents = true,
} = {}) {
  const session = db.prepare('SELECT * FROM spend_sessions WHERE id = ?').get(sessionId);
  if (!session) fail('SESSION_UNKNOWN', 'Spend Session does not exist');
  const bindings = db.prepare(
    'SELECT * FROM agent_session_bindings WHERE session_id = ? ORDER BY rowid',
  ).all(sessionId);
  if (bindings.length !== 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session must have exactly one binding');
  }
  const binding = bindings[0];
  const enrollmentRow = db.prepare(
    'SELECT * FROM agent_enrollments WHERE enrollment_hash = ?',
  ).get(binding.enrollment_hash);
  const enrollment = validateEnrollmentRow(enrollmentRow, { requireActive });
  const policy = validatePolicyRow(db.prepare(
    'SELECT * FROM policy_versions WHERE id = ?',
  ).get(session.policy_version_id));
  const activePolicyId = db.prepare(
    'SELECT value FROM metadata WHERE key = ?'
  ).get('active_policy_id')?.value ?? null;
  const id = boundedToken(session.id, 'session ID', 'SESSION_AUTHORITY_AMBIGUOUS');
  const policyVersionId = boundedToken(
    session.policy_version_id,
    'session policy version ID',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const walletAddress = canonicalAddress(
    session.wallet_address,
    'session wallet',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const createdAt = persistedTimestamp(
    session.created_at,
    'session createdAt',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const lastSeenAt = persistedTimestamp(
    binding.last_seen_at,
    'binding lastSeenAt',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const bindingCreatedAt = persistedTimestamp(
    binding.created_at,
    'binding createdAt',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const closedAt = session.closed_at === null ? null : persistedTimestamp(
    session.closed_at,
    'session closedAt',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  const bindingClosedAt = binding.closed_at === null ? null : persistedTimestamp(
    binding.closed_at,
    'binding closedAt',
    'SESSION_AUTHORITY_AMBIGUOUS',
  );
  if (session.state !== 'open' && session.state !== 'policy_blocked' && session.state !== 'closed') {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session state is invalid');
  }
  const sessionOpen = session.state === 'open' || session.state === 'policy_blocked';
  const pairIsValid = id === sessionId
    && binding.id === bindingIdFor(id)
    && binding.agent_instance_id === enrollment.agentInstanceId
    && binding.credential_digest === enrollment.credentialDigest
    && binding.enrollment_hash === enrollment.enrollmentHash
    && binding.state === (sessionOpen ? 'open' : 'closed')
    && session.adapter_id === `pi:${enrollment.agentInstanceId}`
    && walletAddress === policy.policy.wallet
    && policy.id === policyVersionId
    && bindingCreatedAt === createdAt
    && !timestampIsBefore(lastSeenAt, createdAt)
    && ((sessionOpen && closedAt === null && bindingClosedAt === null)
      || (session.state === 'closed' && closedAt !== null
        && bindingClosedAt === closedAt && lastSeenAt === closedAt));
  if (!pairIsValid) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session authority rows disagree');
  }
  if (activePolicyId !== null) {
    boundedToken(activePolicyId, 'active policy version ID', 'SESSION_AUTHORITY_AMBIGUOUS');
  }
  if (session.state === 'open' && activePolicyId !== policyVersionId) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'open Spend Session is not bound to active policy');
  }
  if (session.state === 'policy_blocked' && activePolicyId === policyVersionId) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'policy-blocked session still names active policy');
  }
  const authority = Object.freeze({
    id,
    adapterId: session.adapter_id,
    walletAddress,
    policyVersionId,
    state: session.state,
    createdAt,
    closedAt,
    bindingId: binding.id,
    agentInstanceId: binding.agent_instance_id,
    credentialDigest: binding.credential_digest,
    enrollmentHash: binding.enrollment_hash,
    bindingState: binding.state,
    bindingCreatedAt,
    lastSeenAt,
    bindingClosedAt,
    policy,
    enrollment,
  });
  if (validateEvents) {
    validateSessionGenesisEvents(db, authority);
    validateSessionLifecycleEvents(db, authority);
  }
  return authority;
}

function rowToIntent(row, authority, allowLoopbackHttp) {
  if (!row) return null;
  try {
    const id = boundedToken(row.id, 'intent ID', 'INTENT_CORRUPTION');
    const requestId = boundedToken(row.request_id, 'request ID', 'INTENT_CORRUPTION');
    const sessionId = boundedToken(row.session_id, 'session ID', 'INTENT_CORRUPTION');
    const enrollmentHash = canonicalHash(
      row.enrollment_hash,
      'intent enrollment hash',
      'INTENT_CORRUPTION',
    );
    const routeId = boundedToken(row.route_id, 'route ID', 'INTENT_CORRUPTION');
    const method = canonicalMethod(row.method);
    if (method !== row.method) fail('INTENT_CORRUPTION', 'persisted method is not canonical');
    const requestUrlHash = canonicalHash(
      row.request_url_hash,
      'request URL hash',
      'INTENT_CORRUPTION',
    );
    const bodyHash = canonicalHash(row.body_hash, 'body hash', 'INTENT_CORRUPTION');
    const headerAllowlistHash = canonicalHash(
      row.header_allowlist_hash,
      'header allowlist hash',
      'INTENT_CORRUPTION',
    );
    const ordinaryFingerprint = canonicalHash(
      row.ordinary_fingerprint,
      'ordinary fingerprint',
      'INTENT_CORRUPTION',
    );
    const purposeLabel = boundedToken(
      row.purpose_label,
      'purpose label',
      'INTENT_CORRUPTION',
    );
    const correlationId = boundedToken(
      row.correlation_id,
      'correlation ID',
      'INTENT_CORRUPTION',
    );
    const walletAddress = canonicalAddress(
      row.wallet_address,
      'intent wallet',
      'INTENT_CORRUPTION',
    );
    const intentHash = canonicalHash(row.intent_hash, 'intent hash', 'INTENT_CORRUPTION');
    const createdAt = persistedTimestamp(
      row.created_at,
      'intent createdAt',
      'INTENT_CORRUPTION',
    );
    const updatedAt = persistedTimestamp(
      row.updated_at,
      'intent updatedAt',
      'INTENT_CORRUPTION',
    );
    if (timestampIsBefore(updatedAt, createdAt)) {
      fail('INTENT_CORRUPTION', 'Spend Intent update predates capture');
    }
    if (!LEGAL_TRANSITIONS.has(row.state)) {
      fail('INTENT_CORRUPTION', 'Spend Intent state is invalid');
    }
    const retryValue = typeof row.retry_matchable === 'bigint'
      ? row.retry_matchable
      : BigInt(row.retry_matchable);
    if ((retryValue !== 0n && retryValue !== 1n)
        || (row.state === 'terminal') !== (retryValue === 0n)) {
      fail('INTENT_CORRUPTION', 'Spend Intent retry authority disagrees with state');
    }
    let reconstructedUrl;
    try {
      reconstructedUrl = canonicalRequestUrl(
        `${row.seller_origin}${row.resource_path}`,
        allowLoopbackHttp,
      );
    } catch (error) {
      if (error instanceof KernelError) {
        fail('INTENT_CORRUPTION', 'persisted request URL projection is invalid');
      }
      throw error;
    }
    if (reconstructedUrl.origin !== row.seller_origin
        || reconstructedUrl.pathname !== row.resource_path
        || sha256(reconstructedUrl.href) !== requestUrlHash) {
      fail('INTENT_CORRUPTION', 'persisted request URL projection changed');
    }
    const expectedOrdinaryFingerprint = sha256(canonicalJson({
      routeId,
      method,
      requestUrlHash,
      bodyHash,
      headerAllowlistHash,
      purposeLabel,
    }));
    if (ordinaryFingerprint !== expectedOrdinaryFingerprint) {
      fail('INTENT_CORRUPTION', 'persisted ordinary fingerprint changed');
    }
    if (!authority || sessionId !== authority.id
        || enrollmentHash !== authority.enrollmentHash
        || walletAddress !== authority.walletAddress
        || timestampIsBefore(createdAt, authority.createdAt)) {
      fail('INTENT_CORRUPTION', 'Spend Intent authority binding changed');
    }
    const expectedIdempotencyKey = idempotencyKeyFor({
      intentId: id,
      requestId,
      sessionId,
      enrollmentHash,
      ordinaryFingerprint,
      correlationId,
    });
    if (row.idempotency_key !== expectedIdempotencyKey) {
      fail('INTENT_CORRUPTION', 'Spend Intent idempotency binding changed');
    }
    const expectedIntentHash = sha256(canonicalJson({
      requestId,
      sessionId,
      enrollmentHash,
      routeId,
      method,
      requestUrlHash,
      sellerOrigin: reconstructedUrl.origin,
      resourcePath: reconstructedUrl.pathname,
      bodyHash,
      headerAllowlistHash,
      purposeLabel,
      correlationId,
      walletAddress,
      policyVersionId: authority.policyVersionId,
    }));
    if (intentHash !== expectedIntentHash) {
      fail('INTENT_CORRUPTION', 'Spend Intent hash binding changed');
    }
    const challengeValues = [
      row.challenge_projection_json,
      row.challenge_hash,
      row.challenge_received_at,
    ];
    const nullCount = challengeValues.filter((value) => value === null).length;
    if (nullCount !== 0 && nullCount !== challengeValues.length) {
      fail('INTENT_CORRUPTION', 'Spend Intent challenge columns are partial');
    }
    let challengeProjectionJson = null;
    let challengeHash = null;
    let challengeReceivedAt = null;
    if (nullCount === 0) {
      let parsed;
      try {
        parsed = JSON.parse(row.challenge_projection_json);
        const projection = validateChallengeProjection(parsed);
        challengeProjectionJson = canonicalJson(projection);
      } catch (error) {
        if (error instanceof KernelError || error instanceof SyntaxError) {
          fail('INTENT_CORRUPTION', 'persisted challenge projection is invalid');
        }
        throw error;
      }
      challengeHash = canonicalHash(
        row.challenge_hash,
        'challenge hash',
        'INTENT_CORRUPTION',
      );
      challengeReceivedAt = persistedTimestamp(
        row.challenge_received_at,
        'challenge receivedAt',
        'INTENT_CORRUPTION',
      );
      if (challengeProjectionJson !== row.challenge_projection_json
          || sha256(challengeProjectionJson) !== challengeHash
          || parsed.resource.urlHash !== requestUrlHash
          || row.state === 'captured'
          || timestampIsBefore(challengeReceivedAt, createdAt)
          || timestampIsBefore(updatedAt, challengeReceivedAt)) {
        fail('INTENT_CORRUPTION', 'persisted challenge binding changed');
      }
    } else if (row.state !== 'captured' && row.state !== 'terminal') {
      fail('INTENT_CORRUPTION', 'Spend Intent state requires an attached challenge');
    }
    return frozenCopy({
      id,
      requestId,
      sessionId,
      enrollmentHash,
      routeId,
      method,
      requestUrlHash,
      sellerOrigin: reconstructedUrl.origin,
      resourcePath: reconstructedUrl.pathname,
      bodyHash,
      headerAllowlistHash,
      ordinaryFingerprint,
      retryMatchable: retryValue === 1n,
      purposeLabel,
      correlationId,
      idempotencyKey: row.idempotency_key,
      walletAddress,
      intentHash,
      challengeProjectionJson,
      challengeHash,
      challengeReceivedAt,
      state: row.state,
      createdAt,
      updatedAt,
    });
  } catch (error) {
    if (error instanceof KernelError && error.code !== 'INTENT_CORRUPTION') {
      fail('INTENT_CORRUPTION', 'persisted Spend Intent is invalid');
    }
    throw error;
  }
}

function validateIntentEvents(db, intent, authority) {
  const rows = db.prepare(`SELECT event_type, data_json, created_at FROM events
    WHERE entity_type = ? AND entity_id = ?
      AND event_type IN (?, ?, ?)
    ORDER BY sequence`).all(
    'spend_intent',
    intent.id,
    'intent.captured',
    'intent.challenge_attached',
    'intent.transitioned',
  );
  const captured = rows.filter((row) => row.event_type === 'intent.captured');
  if (captured.length !== 1 || rows[0]?.event_type !== 'intent.captured') {
    fail('INTENT_CORRUPTION', 'Spend Intent capture event is missing or ambiguous');
  }
  const captureData = exactEventData(captured[0], [
    'requestId',
    'sessionId',
    'enrollmentHash',
    'routeId',
    'method',
    'requestUrlHash',
    'sellerOrigin',
    'resourcePath',
    'bodyHash',
    'headerAllowlistHash',
    'ordinaryFingerprint',
    'purposeLabel',
    'correlationId',
    'idempotencyKey',
    'walletAddress',
    'policyVersionId',
    'intentHash',
    'createdAt',
  ], 'INTENT_CORRUPTION', 'intent.captured');
  const expectedCapture = {
    requestId: intent.requestId,
    sessionId: intent.sessionId,
    enrollmentHash: intent.enrollmentHash,
    routeId: intent.routeId,
    method: intent.method,
    requestUrlHash: intent.requestUrlHash,
    sellerOrigin: intent.sellerOrigin,
    resourcePath: intent.resourcePath,
    bodyHash: intent.bodyHash,
    headerAllowlistHash: intent.headerAllowlistHash,
    ordinaryFingerprint: intent.ordinaryFingerprint,
    purposeLabel: intent.purposeLabel,
    correlationId: intent.correlationId,
    idempotencyKey: intent.idempotencyKey,
    walletAddress: intent.walletAddress,
    policyVersionId: authority.policyVersionId,
    intentHash: intent.intentHash,
    createdAt: intent.createdAt,
  };
  if (canonicalJson(captureData) !== canonicalJson(expectedCapture)) {
    fail('INTENT_CORRUPTION', 'Spend Intent capture event binding changed');
  }

  let state = 'captured';
  let updatedAt = intent.createdAt;
  let challengeCount = 0;
  for (const event of rows.slice(1)) {
    if (event.event_type === 'intent.captured') {
      fail('INTENT_CORRUPTION', 'Spend Intent has duplicate capture events');
    }
    if (event.event_type === 'intent.challenge_attached') {
      challengeCount += 1;
      if (challengeCount !== 1 || state !== 'captured' || intent.challengeHash === null) {
        fail('INTENT_CORRUPTION', 'Spend Intent challenge history is invalid');
      }
      const data = exactEventData(event, [
        'challengeHash',
        'challengeReceivedAt',
        'projectionHash',
        'updatedAt',
      ], 'INTENT_CORRUPTION', 'intent.challenge_attached');
      const eventUpdatedAt = persistedTimestamp(
        data.updatedAt,
        'challenge event updatedAt',
        'INTENT_CORRUPTION',
      );
      if (data.challengeHash !== intent.challengeHash
          || data.projectionHash !== intent.challengeHash
          || data.challengeReceivedAt !== intent.challengeReceivedAt
          || timestampIsBefore(eventUpdatedAt, intent.challengeReceivedAt)
          || timestampIsBefore(eventUpdatedAt, updatedAt)) {
        fail('INTENT_CORRUPTION', 'Spend Intent challenge event binding changed');
      }
      state = 'challenged';
      updatedAt = eventUpdatedAt;
      continue;
    }
    const data = exactEventData(event, [
      'previousState',
      'nextState',
      'reasonCode',
      'retryMatchable',
      'updatedAt',
    ], 'INTENT_CORRUPTION', 'intent.transitioned');
    if (!LEGAL_TRANSITIONS.has(data.previousState)
        || !LEGAL_TRANSITIONS.has(data.nextState)
        || data.previousState !== state
        || data.nextState === 'challenged'
        || !LEGAL_TRANSITIONS.get(state).has(data.nextState)
        || typeof data.retryMatchable !== 'boolean'
        || data.retryMatchable !== (data.nextState !== 'terminal')) {
      fail('INTENT_CORRUPTION', 'Spend Intent transition event is invalid');
    }
    boundedToken(data.reasonCode, 'transition reason code', 'INTENT_CORRUPTION');
    const eventUpdatedAt = persistedTimestamp(
      data.updatedAt,
      'transition event updatedAt',
      'INTENT_CORRUPTION',
    );
    if (timestampIsBefore(eventUpdatedAt, updatedAt)) {
      fail('INTENT_CORRUPTION', 'Spend Intent transition time regressed');
    }
    state = data.nextState;
    updatedAt = eventUpdatedAt;
  }
  if ((intent.challengeHash === null ? 0 : 1) !== challengeCount
      || state !== intent.state
      || updatedAt !== intent.updatedAt) {
    fail('INTENT_CORRUPTION', 'Spend Intent row disagrees with event history');
  }
}

function decodeIntent(db, row, authority, allowLoopbackHttp) {
  const intent = rowToIntent(row, authority, allowLoopbackHttp);
  if (intent) validateIntentEvents(db, intent, authority);
  return intent;
}

function exactIntentMatch(intent, prepared) {
  return intent.routeId === prepared.routeId
    && intent.method === prepared.method
    && intent.requestUrlHash === prepared.requestUrlHash
    && intent.sellerOrigin === prepared.sellerOrigin
    && intent.resourcePath === prepared.resourcePath
    && intent.bodyHash === prepared.bodyHash
    && intent.headerAllowlistHash === prepared.headerAllowlistHash
    && intent.ordinaryFingerprint === prepared.ordinaryFingerprint
    && intent.purposeLabel === prepared.purposeLabel;
}

function generatedId(idFactory, kind) {
  return boundedToken(idFactory(kind), `${kind} ID`, 'ID_FACTORY');
}

function idempotencyKeyFor(fields) {
  const digest = sha256(canonicalJson({
    domain: 'wallet-kernel.intent-idempotency.v1',
    ...fields,
  }));
  return `wk_${digest.slice('sha256:'.length)}`;
}

export function createIntentRepository({
  store,
  idFactory,
  now,
  allowLoopbackHttp = false,
  routeMetadata = {},
}) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('intent repository requires a Wallet Kernel store');
  }
  if (typeof idFactory !== 'function' || utilTypes.isProxy(idFactory)) {
    throw new TypeError('intent repository requires an ID factory');
  }
  if (typeof now !== 'function' || utilTypes.isProxy(now)) {
    throw new TypeError('intent repository requires a clock');
  }
  if (typeof allowLoopbackHttp !== 'boolean') {
    throw new TypeError('allowLoopbackHttp must be boolean');
  }
  const routeMetadataById = canonicalRouteMetadata(routeMetadata);

  const nextSessionIdentity = (db) => {
    for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
      const id = generatedId(idFactory, 'session');
      const bindingId = bindingIdFor(id);
      const sessionExists = db.prepare('SELECT id FROM spend_sessions WHERE id = ?').get(id);
      const bindingExists = db.prepare(
        'SELECT id FROM agent_session_bindings WHERE id = ?',
      ).get(bindingId);
      if (!sessionExists && !bindingExists) return Object.freeze({ id, bindingId });
    }
    fail('ID_FACTORY_COLLISION', 'session ID factory exhausted collision retries');
  };

  const nextIntentId = (db) => {
    for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
      const id = generatedId(idFactory, 'intent');
      if (!db.prepare('SELECT id FROM spend_intents WHERE id = ?').get(id)) return id;
    }
    fail('ID_FACTORY_COLLISION', 'intent ID factory exhausted collision retries');
  };

  const nextRequestId = (db) => {
    for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
      const id = generatedId(idFactory, 'request');
      if (!db.prepare('SELECT id FROM spend_intents WHERE request_id = ?').get(id)) return id;
    }
    fail('ID_FACTORY_COLLISION', 'request ID factory exhausted collision retries');
  };

  const nextCorrelationId = (db, sessionId) => {
    for (let attempt = 0; attempt < MAX_ID_ATTEMPTS; attempt += 1) {
      const id = generatedId(idFactory, 'correlation');
      const intent = db.prepare(`SELECT id FROM spend_intents
        WHERE session_id = ? AND correlation_id = ?`).get(sessionId, id);
      const alias = db.prepare(`SELECT sequence FROM events
        WHERE entity_type = ? AND entity_id = ? AND event_type = ?
        LIMIT 1`).get(
        'intent_correlation',
        correlationAliasIdFor(sessionId, id),
        'intent.correlation_bound',
      );
      if (!intent && !alias) return id;
    }
    fail('ID_FACTORY_COLLISION', 'correlation ID factory exhausted collision retries');
  };

  const loadCorrelatedIntent = (db, sessionId, correlationId, authority) => {
    const primaryRow = db.prepare(`SELECT * FROM spend_intents
      WHERE session_id = ? AND correlation_id = ?`).get(sessionId, correlationId);
    const aliasRows = db.prepare(`SELECT data_json, created_at FROM events
      WHERE entity_type = ? AND entity_id = ? AND event_type = ?
      ORDER BY sequence`).all(
      'intent_correlation',
      correlationAliasIdFor(sessionId, correlationId),
      'intent.correlation_bound',
    );
    if (aliasRows.length > 1 || (primaryRow && aliasRows.length !== 0)) {
      fail('INTENT_CORRUPTION', 'correlation authority is ambiguous');
    }
    if (primaryRow) {
      return decodeIntent(db, primaryRow, authority, allowLoopbackHttp);
    }
    if (aliasRows.length === 0) return null;
    const data = exactEventData(aliasRows[0], [
      'sessionId',
      'intentId',
      'correlationId',
      'ordinaryFingerprint',
    ], 'INTENT_CORRUPTION', 'intent.correlation_bound');
    const intentId = boundedToken(data.intentId, 'alias intent ID', 'INTENT_CORRUPTION');
    const fingerprint = canonicalHash(
      data.ordinaryFingerprint,
      'alias ordinary fingerprint',
      'INTENT_CORRUPTION',
    );
    if (data.sessionId !== sessionId || data.correlationId !== correlationId) {
      fail('INTENT_CORRUPTION', 'correlation alias key changed');
    }
    const intent = decodeIntent(
      db,
      db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(intentId),
      authority,
      allowLoopbackHttp,
    );
    if (!intent || intent.sessionId !== sessionId
        || intent.ordinaryFingerprint !== fingerprint) {
      fail('INTENT_CORRUPTION', 'correlation alias target changed');
    }
    return intent;
  };

  const appendCorrelationAlias = (db, appendEvent, intent, correlationId) => {
    if (correlationId === intent.correlationId) return;
    const primary = db.prepare(`SELECT id FROM spend_intents
      WHERE session_id = ? AND correlation_id = ?`).get(intent.sessionId, correlationId);
    const alias = db.prepare(`SELECT sequence FROM events
      WHERE entity_type = ? AND entity_id = ? AND event_type = ?
      LIMIT 1`).get(
      'intent_correlation',
      correlationAliasIdFor(intent.sessionId, correlationId),
      'intent.correlation_bound',
    );
    if (primary || alias) {
      fail('INTENT_CORRUPTION', 'correlation alias already exists');
    }
    appendEvent({
      entityType: 'intent_correlation',
      entityId: correlationAliasIdFor(intent.sessionId, correlationId),
      eventType: 'intent.correlation_bound',
      data: {
        sessionId: intent.sessionId,
        intentId: intent.id,
        correlationId,
        ordinaryFingerprint: intent.ordinaryFingerprint,
      },
    });
  };

  const getSession = (sessionId) => {
    const id = boundedToken(sessionId, 'session ID', 'SESSION_SCHEMA');
    return store.transaction((token) => store.within(token, ({ db }) => {
      if (!db.prepare('SELECT id FROM spend_sessions WHERE id = ?').get(id)) return null;
      return publicSession(loadSessionAuthority(db, id, { requireActive: false }));
    }));
  };

  const openOrResumeSession = (input) => {
    const request = closedRecord(input, [
      'agentInstanceId',
      'walletAddress',
      'policyVersionId',
    ], [], 'SESSION_SCHEMA', 'open session request');
    const agentInstanceId = canonicalInstanceId(request.agentInstanceId);
    const walletAddress = canonicalAddress(request.walletAddress, 'session wallet');
    const policyVersionId = boundedToken(
      request.policyVersionId,
      'policy version ID',
      'SESSION_SCHEMA',
    );
    return store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
      const activeRows = db.prepare(
        "SELECT * FROM agent_enrollments WHERE state = 'active' ORDER BY rowid",
      ).all();
      if (activeRows.length > 1) {
        fail('AGENT_ENROLLMENT_AMBIGUOUS', 'multiple active agent enrollments exist');
      }
      const enrollmentRow = activeRows.find((row) => row.agent_instance_id === agentInstanceId);
      if (!enrollmentRow) {
        const historical = db.prepare(
          'SELECT state FROM agent_enrollments WHERE agent_instance_id = ?',
        ).get(agentInstanceId);
        fail(historical?.state === 'revoked' ? 'AGENT_REVOKED' : 'AGENT_ENROLLMENT_REQUIRED',
          'exact active agent enrollment is required');
      }
      const enrollment = validateEnrollmentRow(enrollmentRow);
      const policy = validatePolicyRow(db.prepare(
        'SELECT * FROM policy_versions WHERE id = ?',
      ).get(policyVersionId));
      const activePolicyId = db.prepare(
        'SELECT value FROM metadata WHERE key = ?'
      ).get('active_policy_id')?.value ?? null;
      if (activePolicyId !== policyVersionId) {
        fail('POLICY_NOT_ACTIVE', 'Spend Session requires the active PolicyVersion');
      }
      if (policy.policy.wallet !== walletAddress) {
        fail('POLICY_WALLET_MISMATCH', 'session wallet differs from PolicyVersion wallet');
      }
      const adapterId = `pi:${agentInstanceId}`;
      const authorityRows = db.prepare(`SELECT DISTINCT spend_sessions.id
        FROM spend_sessions
        LEFT JOIN agent_session_bindings
          ON agent_session_bindings.session_id = spend_sessions.id
        WHERE (spend_sessions.state IN ('open','policy_blocked')
            AND (spend_sessions.adapter_id = ?
              OR agent_session_bindings.agent_instance_id = ?
              OR agent_session_bindings.credential_digest = ?
              OR agent_session_bindings.enrollment_hash = ?))
          OR (agent_session_bindings.state = 'open'
            AND (agent_session_bindings.agent_instance_id = ?
              OR agent_session_bindings.credential_digest = ?
              OR agent_session_bindings.enrollment_hash = ?))
        ORDER BY spend_sessions.id`).all(
        adapterId,
        agentInstanceId,
        enrollment.credentialDigest,
        enrollment.enrollmentHash,
        agentInstanceId,
        enrollment.credentialDigest,
        enrollment.enrollmentHash,
      );
      if (authorityRows.length > 1) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'agent has ambiguous open session authority');
      }
      if (authorityRows.length === 1) {
        const authority = loadSessionAuthority(db, authorityRows[0].id, {
          requireActive: false,
        });
        if (authority.state !== 'open'
            || authority.enrollment.state !== 'active'
            || authority.agentInstanceId !== agentInstanceId
            || authority.enrollmentHash !== enrollment.enrollmentHash
            || authority.walletAddress !== walletAddress
            || authority.policyVersionId !== policyVersionId) {
          fail('AGENT_SESSION_UNAVAILABLE', 'existing agent session has a different authority');
        }
        return publicSession(authority);
      }

      const { id, bindingId } = nextSessionIdentity(db);
      const createdAt = canonicalTimestamp(now(), 'session createdAt');
      db.prepare(`INSERT INTO spend_sessions
        (id, adapter_id, wallet_address, policy_version_id, state, created_at)
        VALUES (?, ?, ?, ?, 'open', ?)`).run(
        id,
        adapterId,
        walletAddress,
        policyVersionId,
        createdAt,
      );
      db.prepare(`INSERT INTO agent_session_bindings
        (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
         state, created_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`).run(
        bindingId,
        agentInstanceId,
        enrollment.credentialDigest,
        enrollment.enrollmentHash,
        id,
        createdAt,
        createdAt,
      );
      const session = publicSession(loadSessionAuthority(db, id, { validateEvents: false }));
      appendEvent({
        entityType: 'spend_session',
        entityId: id,
        eventType: 'session.started',
        data: {
          adapterId,
          enrollmentHash: enrollment.enrollmentHash,
          policyVersionId,
          sessionHash: session.sessionHash,
          walletAddress,
          createdAt,
        },
      });
      appendEvent({
        entityType: 'session_binding',
        entityId: bindingId,
        eventType: 'session.binding_opened',
        data: {
          agentInstanceId,
          enrollmentHash: enrollment.enrollmentHash,
          sessionId: id,
          createdAt,
        },
      });
      const persisted = publicSession(loadSessionAuthority(db, id));
      if (persisted.sessionHash !== session.sessionHash) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'new session authority changed during creation');
      }
      return persisted;
    }));
  };

  const prepareCapture = (input) => {
    const request = closedRecord(input, [
      'sessionId',
      'routeId',
      'method',
      'requestUrl',
      'headers',
      'bodyBytes',
      'purposeLabel',
    ], ['correlationId'], 'INTENT_SCHEMA', 'intent capture');
    const sessionId = boundedToken(request.sessionId, 'session ID', 'INTENT_SCHEMA');
    const fingerprint = prepareFingerprintInput({
      routeId: request.routeId,
      method: request.method,
      requestUrl: request.requestUrl,
      headers: request.headers,
      bodyBytes: request.bodyBytes,
      purposeLabel: request.purposeLabel,
      ...(Object.hasOwn(request, 'correlationId')
        ? { correlationId: request.correlationId }
        : {}),
    }, { allowLoopbackHttp, allowCorrelation: true });
    return Object.freeze({ sessionId, ...fingerprint });
  };

  const capturePrepared = (db, appendEvent, prepared) => {
    const authority = loadSessionAuthority(db, prepared.sessionId);
    if (authority.state !== 'open') {
      fail(authority.state === 'policy_blocked' ? 'SESSION_POLICY_BLOCKED' : 'SESSION_CLOSED',
        'Spend Session cannot capture an intent');
    }
    if (prepared.correlationId) {
      const byCorrelation = loadCorrelatedIntent(
        db,
        prepared.sessionId,
        prepared.correlationId,
        authority,
      );
      if (byCorrelation) {
        if (!exactIntentMatch(byCorrelation, prepared)
            || byCorrelation.enrollmentHash !== authority.enrollmentHash
            || byCorrelation.walletAddress !== authority.walletAddress) {
          fail('CORRELATION_CONFLICT', 'correlation ID is bound to a different request');
        }
        return byCorrelation;
      }
    }
    const retryRows = db.prepare(`SELECT * FROM spend_intents
      WHERE session_id = ? AND ordinary_fingerprint = ? AND retry_matchable = 1
      ORDER BY rowid`).all(prepared.sessionId, prepared.ordinaryFingerprint);
    if (retryRows.length > 1) fail('INTENT_RETRY_AMBIGUOUS', 'retry authority is ambiguous');
    if (retryRows.length === 1) {
      const existing = decodeIntent(db, retryRows[0], authority, allowLoopbackHttp);
      if (!exactIntentMatch(existing, prepared)
          || existing.enrollmentHash !== authority.enrollmentHash
          || existing.walletAddress !== authority.walletAddress) {
        fail('INTENT_CORRUPTION', 'retry fingerprint row differs from canonical request');
      }
      if (prepared.correlationId) {
        appendCorrelationAlias(db, appendEvent, existing, prepared.correlationId);
      }
      return existing;
    }

    const correlationId = prepared.correlationId
      ?? nextCorrelationId(db, prepared.sessionId);
    const id = nextIntentId(db);
    const requestId = nextRequestId(db);
    const createdAt = canonicalTimestamp(now(), 'intent createdAt');
    const intentHash = sha256(canonicalJson({
      requestId,
      sessionId: prepared.sessionId,
      enrollmentHash: authority.enrollmentHash,
      routeId: prepared.routeId,
      method: prepared.method,
      requestUrlHash: prepared.requestUrlHash,
      sellerOrigin: prepared.sellerOrigin,
      resourcePath: prepared.resourcePath,
      bodyHash: prepared.bodyHash,
      headerAllowlistHash: prepared.headerAllowlistHash,
      purposeLabel: prepared.purposeLabel,
      correlationId,
      walletAddress: authority.walletAddress,
      policyVersionId: authority.policyVersionId,
    }));
    const idempotencyKey = idempotencyKeyFor({
      intentId: id,
      requestId,
      sessionId: prepared.sessionId,
      enrollmentHash: authority.enrollmentHash,
      ordinaryFingerprint: prepared.ordinaryFingerprint,
      correlationId,
    });
    db.prepare(`INSERT INTO spend_intents
      (id, request_id, session_id, enrollment_hash, route_id, method,
       request_url_hash, seller_origin, resource_path, body_hash,
       header_allowlist_hash, ordinary_fingerprint, purpose_label,
       correlation_id, idempotency_key, wallet_address, intent_hash,
       state, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
       'captured', ?, ?)`).run(
      id,
      requestId,
      prepared.sessionId,
      authority.enrollmentHash,
      prepared.routeId,
      prepared.method,
      prepared.requestUrlHash,
      prepared.sellerOrigin,
      prepared.resourcePath,
      prepared.bodyHash,
      prepared.headerAllowlistHash,
      prepared.ordinaryFingerprint,
      prepared.purposeLabel,
      correlationId,
      idempotencyKey,
      authority.walletAddress,
      intentHash,
      createdAt,
      createdAt,
    );
    appendEvent({
      entityType: 'spend_intent',
      entityId: id,
      eventType: 'intent.captured',
      data: {
        requestId,
        sessionId: prepared.sessionId,
        enrollmentHash: authority.enrollmentHash,
        routeId: prepared.routeId,
        method: prepared.method,
        requestUrlHash: prepared.requestUrlHash,
        sellerOrigin: prepared.sellerOrigin,
        resourcePath: prepared.resourcePath,
        bodyHash: prepared.bodyHash,
        headerAllowlistHash: prepared.headerAllowlistHash,
        ordinaryFingerprint: prepared.ordinaryFingerprint,
        purposeLabel: prepared.purposeLabel,
        correlationId,
        idempotencyKey,
        walletAddress: authority.walletAddress,
        policyVersionId: authority.policyVersionId,
        intentHash,
        createdAt,
      },
    });
    return decodeIntent(
      db,
      db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(id),
      authority,
      allowLoopbackHttp,
    );
  };

  const captureIntentInTransaction = (token, input) => {
    const prepared = prepareCapture(input);
    return store.within(token, ({ db, appendEvent }) => capturePrepared(
      db,
      appendEvent,
      prepared,
    ));
  };

  const captureIntent = (input) => {
    const prepared = prepareCapture(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => capturePrepared(db, appendEvent, prepared),
    ));
  };

  const getIntent = (intentId) => {
    const id = boundedToken(intentId, 'intent ID', 'INTENT_SCHEMA');
    return store.transaction((token) => store.within(token, ({ db }) => {
      const row = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(id);
      if (!row) return null;
      const sessionId = boundedToken(
        row.session_id,
        'persisted session ID',
        'INTENT_CORRUPTION',
      );
      const authority = loadSessionAuthority(db, sessionId, { requireActive: false });
      return decodeIntent(db, row, authority, allowLoopbackHttp);
    }));
  };

  const matchRetry = (input) => {
    const request = closedRecord(
      input,
      ['sessionId', 'request'],
      [],
      'INTENT_SCHEMA',
      'retry match',
    );
    const sessionId = boundedToken(request.sessionId, 'session ID', 'INTENT_SCHEMA');
    const prepared = prepareFingerprintInput(request.request, {
      allowLoopbackHttp,
      allowCorrelation: true,
    });
    return store.transaction((token) => store.within(token, ({ db }) => {
      if (!db.prepare('SELECT id FROM spend_sessions WHERE id = ?').get(sessionId)) return null;
      const authority = loadSessionAuthority(db, sessionId);
      if (authority.state !== 'open') {
        fail(authority.state === 'policy_blocked' ? 'SESSION_POLICY_BLOCKED' : 'SESSION_CLOSED',
          'Spend Session cannot match an agent retry');
      }
      if (prepared.correlationId) {
        const correlation = loadCorrelatedIntent(
          db,
          sessionId,
          prepared.correlationId,
          authority,
        );
        if (correlation) {
          if (!exactIntentMatch(correlation, prepared)) {
            fail('CORRELATION_CONFLICT', 'correlation ID is bound to a different request');
          }
          return correlation.id;
        }
      }
      const rows = db.prepare(`SELECT * FROM spend_intents
        WHERE session_id = ? AND ordinary_fingerprint = ? AND retry_matchable = 1
        ORDER BY rowid`).all(sessionId, prepared.ordinaryFingerprint);
      if (rows.length > 1) fail('INTENT_RETRY_AMBIGUOUS', 'retry authority is ambiguous');
      if (rows.length === 0) return null;
      const existing = decodeIntent(db, rows[0], authority, allowLoopbackHttp);
      if (!exactIntentMatch(existing, prepared)) {
        fail('INTENT_CORRUPTION', 'retry fingerprint row differs from canonical request');
      }
      return existing.id;
    }));
  };

  const prepareChallenge = (input) => {
    const request = closedRecord(input, [
      'intentId',
      'paymentRequired',
      'challengeReceivedAt',
    ], [], 'CHALLENGE_ATTACH_SCHEMA', 'challenge attachment');
    const intentId = boundedToken(request.intentId, 'intent ID', 'CHALLENGE_ATTACH_SCHEMA');
    const challengeReceivedAt = canonicalTimestamp(
      request.challengeReceivedAt,
      'challenge receivedAt',
    );
    const projection = projectPaymentRequired(request.paymentRequired);
    const projectionJson = canonicalJson(projection);
    return Object.freeze({
      intentId,
      projection,
      projectionJson,
      challengeHash: sha256(projectionJson),
      challengeReceivedAt,
    });
  };

  const attachPrepared = (db, appendEvent, prepared) => {
    const row = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(prepared.intentId);
    if (!row) fail('INTENT_UNKNOWN', 'Spend Intent does not exist');
    const sessionId = boundedToken(row.session_id, 'session ID', 'INTENT_CORRUPTION');
    const authority = loadSessionAuthority(db, sessionId);
    if (authority.state !== 'open') {
      fail(authority.state === 'policy_blocked' ? 'SESSION_POLICY_BLOCKED' : 'SESSION_CLOSED',
        'Spend Session cannot attach a challenge');
    }
    const intent = decodeIntent(db, row, authority, allowLoopbackHttp);
    const fixedMetadata = routeMetadataById.get(intent.routeId);
    if (!fixedMetadata) {
      fail('ROUTE_METADATA_REQUIRED', 'Spend Intent route has no operator-owned metadata');
    }
    if (prepared.projection.resource.description !== fixedMetadata.description
        || prepared.projection.resource.mimeType !== fixedMetadata.mimeType) {
      fail(
        'CHALLENGE_RESOURCE_METADATA_MISMATCH',
        'challenge resource metadata differs from the operator route map',
      );
    }
    if (prepared.projection.resource.urlHash !== intent.requestUrlHash) {
      fail('CHALLENGE_RESOURCE_MISMATCH', 'challenge resource differs from Spend Intent');
    }
    if (intent.challengeHash !== null) {
      if (intent.challengeProjectionJson !== prepared.projectionJson
          || intent.challengeHash !== prepared.challengeHash
          || intent.challengeReceivedAt !== prepared.challengeReceivedAt) {
        fail('CHALLENGE_CHANGED', 'Spend Intent challenge is immutable');
      }
      return intent;
    }
    if (intent.state !== 'captured') {
      fail('INTENT_CORRUPTION', 'unchallenged Spend Intent is not captured');
    }
    const updatedAt = canonicalTimestamp(now(), 'intent updatedAt');
    if (timestampIsBefore(prepared.challengeReceivedAt, intent.createdAt)
        || timestampIsBefore(updatedAt, prepared.challengeReceivedAt)
        || timestampIsBefore(updatedAt, intent.updatedAt)) {
      fail('CHALLENGE_TIME', 'challenge or Kernel clock regressed');
    }
    const updated = db.prepare(`UPDATE spend_intents
      SET challenge_projection_json = ?, challenge_hash = ?, challenge_received_at = ?,
          state = 'challenged', updated_at = ?
      WHERE id = ? AND state = 'captured'
        AND challenge_projection_json IS NULL
        AND challenge_hash IS NULL
        AND challenge_received_at IS NULL`).run(
      prepared.projectionJson,
      prepared.challengeHash,
      prepared.challengeReceivedAt,
      updatedAt,
      prepared.intentId,
    );
    if (updated.changes !== 1n) fail('CHALLENGE_CHANGED', 'challenge attachment lost its race');
    appendEvent({
      entityType: 'spend_intent',
      entityId: prepared.intentId,
      eventType: 'intent.challenge_attached',
      data: {
        challengeHash: prepared.challengeHash,
        challengeReceivedAt: prepared.challengeReceivedAt,
        projectionHash: prepared.challengeHash,
        updatedAt,
      },
    });
    return decodeIntent(
      db,
      db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(prepared.intentId),
      authority,
      allowLoopbackHttp,
    );
  };

  const attachChallengeInTransaction = (token, input) => {
    const prepared = prepareChallenge(input);
    return store.within(token, ({ db, appendEvent }) => attachPrepared(
      db,
      appendEvent,
      prepared,
    ));
  };

  const attachChallenge = (input) => {
    const prepared = prepareChallenge(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => attachPrepared(db, appendEvent, prepared),
    ));
  };

  const prepareTransition = (input) => {
    const request = closedRecord(input, [
      'intentId',
      'expectedState',
      'nextState',
      'reasonCode',
    ], [], 'INTENT_TRANSITION_SCHEMA', 'intent transition');
    const intentId = boundedToken(request.intentId, 'intent ID', 'INTENT_TRANSITION_SCHEMA');
    if (!LEGAL_TRANSITIONS.has(request.expectedState)
        || !LEGAL_TRANSITIONS.has(request.nextState)) {
      fail('INTENT_TRANSITION', 'intent transition names an unknown state');
    }
    return Object.freeze({
      intentId,
      expectedState: request.expectedState,
      nextState: request.nextState,
      reasonCode: boundedToken(request.reasonCode, 'reason code', 'INTENT_TRANSITION_SCHEMA'),
    });
  };

  const transitionPrepared = (db, appendEvent, prepared) => {
    const row = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(prepared.intentId);
    if (!row) fail('INTENT_UNKNOWN', 'Spend Intent does not exist');
    const advancesAuthority = new Set([
      'challenged',
      'approval_pending',
      'authorized',
      'reserved',
      'signing',
    ]).has(prepared.nextState);
    const sessionId = boundedToken(row.session_id, 'session ID', 'INTENT_CORRUPTION');
    const authority = loadSessionAuthority(db, sessionId, {
      requireActive: advancesAuthority,
    });
    if (advancesAuthority && authority.state !== 'open') {
      fail(authority.state === 'policy_blocked' ? 'SESSION_POLICY_BLOCKED' : 'SESSION_CLOSED',
        'Spend Session cannot advance spend authority');
    }
    const intent = decodeIntent(db, row, authority, allowLoopbackHttp);
    if (intent.state !== prepared.expectedState) {
      fail('INTENT_STATE_CONFLICT', 'Spend Intent state differs from expected state');
    }
    if (!LEGAL_TRANSITIONS.get(prepared.expectedState).has(prepared.nextState)
        || prepared.nextState === 'challenged') {
      fail('INTENT_TRANSITION', 'intent state edge is not legal');
    }
    const updatedAt = canonicalTimestamp(now(), 'intent updatedAt');
    if (timestampIsBefore(updatedAt, intent.updatedAt)) {
      fail('INTENT_TIME', 'Kernel clock regressed during intent transition');
    }
    const retryMatchable = prepared.nextState === 'terminal' ? 0 : 1;
    const changed = db.prepare(`UPDATE spend_intents
      SET state = ?, retry_matchable = ?, updated_at = ?
      WHERE id = ? AND state = ?`).run(
      prepared.nextState,
      retryMatchable,
      updatedAt,
      prepared.intentId,
      prepared.expectedState,
    );
    if (changed.changes !== 1n) {
      fail('INTENT_STATE_CONFLICT', 'Spend Intent transition lost its race');
    }
    appendEvent({
      entityType: 'spend_intent',
      entityId: prepared.intentId,
      eventType: 'intent.transitioned',
      data: {
        previousState: prepared.expectedState,
        nextState: prepared.nextState,
        reasonCode: prepared.reasonCode,
        retryMatchable: retryMatchable === 1,
        updatedAt,
      },
    });
    return decodeIntent(
      db,
      db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(prepared.intentId),
      authority,
      allowLoopbackHttp,
    );
  };

  const transitionInTransaction = (token, input) => {
    const prepared = prepareTransition(input);
    return store.within(token, ({ db, appendEvent }) => transitionPrepared(
      db,
      appendEvent,
      prepared,
    ));
  };

  const transition = (input) => {
    const prepared = prepareTransition(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => transitionPrepared(db, appendEvent, prepared),
    ));
  };

  const assertSessionMonetarySafety = (db, sessionId, authority) => {
    const intentRows = db.prepare(`SELECT * FROM spend_intents
      WHERE session_id = ? ORDER BY id`).all(sessionId);
    for (const row of intentRows) {
      const intent = decodeIntent(db, row, authority, allowLoopbackHttp);
      const outcome = db.prepare(
        'SELECT intent_id FROM buyer_outcomes WHERE intent_id = ?',
      ).get(intent.id);
      if (intent.state !== 'terminal' || intent.retryMatchable || !outcome) {
        fail('SESSION_MONETARY_AMBIGUITY', 'Spend Session has nonterminal intent authority');
      }
    }
    const openApproval = db.prepare(`SELECT approvals.id
      FROM approvals JOIN spend_intents ON spend_intents.id = approvals.intent_id
      WHERE spend_intents.session_id = ?
        AND (approvals.decision = 'pending'
          OR (approvals.decision = 'approved'
            AND NOT (spend_intents.state = 'terminal'
              AND spend_intents.retry_matchable = 0)))
      LIMIT 1`).get(sessionId);
    const heldBudget = db.prepare(`SELECT budget_reservations.intent_id
      FROM budget_reservations
      WHERE session_id = ? AND state IN ('reserved','unresolved') LIMIT 1`).get(sessionId);
    const activePayment = db.prepare(`SELECT payment_attempts.intent_id
      FROM payment_attempts JOIN spend_intents ON spend_intents.id = payment_attempts.intent_id
      WHERE spend_intents.session_id = ?
        AND payment_attempts.state IN ('reserved','signing','signed','retrying','unresolved')
      LIMIT 1`).get(sessionId);
    const paymentCandidate = db.prepare(`SELECT payment_reconciliation_candidates.id
      FROM payment_reconciliation_candidates
      JOIN spend_intents ON spend_intents.id = payment_reconciliation_candidates.intent_id
      WHERE spend_intents.session_id = ?
        AND payment_reconciliation_candidates.state = 'pending' LIMIT 1`).get(sessionId);
    const executionCase = db.prepare(`SELECT execution_resolutions.intent_id
      FROM execution_resolutions
      JOIN spend_intents ON spend_intents.id = execution_resolutions.intent_id
      WHERE spend_intents.session_id = ?
        AND execution_resolutions.state != 'resolved' LIMIT 1`).get(sessionId);
    const executionWithoutResolution = db.prepare(`SELECT execution_outcomes.intent_id
      FROM execution_outcomes
      JOIN spend_intents ON spend_intents.id = execution_outcomes.intent_id
      LEFT JOIN payment_attempts
        ON payment_attempts.intent_id = execution_outcomes.intent_id
      LEFT JOIN budget_reservations
        ON budget_reservations.intent_id = execution_outcomes.intent_id
      LEFT JOIN execution_resolutions
        ON execution_resolutions.intent_id = execution_outcomes.intent_id
      WHERE spend_intents.session_id = ?
        AND execution_outcomes.state IN ('failed','unknown')
        AND (payment_attempts.state = 'settled'
          OR budget_reservations.state = 'committed')
        AND (execution_resolutions.intent_id IS NULL
          OR execution_resolutions.state != 'resolved')
      LIMIT 1`).get(sessionId);
    const refundCase = db.prepare(`SELECT refunds.id FROM refunds
      JOIN spend_intents ON spend_intents.id = refunds.intent_id
      WHERE spend_intents.session_id = ?
        AND refunds.state IN ('pending','unresolved') LIMIT 1`).get(sessionId);
    const unresolvedReconciliation = db.prepare(`SELECT reconciliations.id
      FROM reconciliations
      JOIN spend_intents ON spend_intents.id = reconciliations.intent_id
      WHERE spend_intents.session_id = ?
        AND reconciliations.outcome = 'unresolved'
        AND NOT EXISTS (
          SELECT 1 FROM reconciliations AS later
          WHERE later.intent_id = reconciliations.intent_id
            AND later.kind = reconciliations.kind
            AND later.rowid > reconciliations.rowid
        )
      LIMIT 1`).get(sessionId);
    if (openApproval || heldBudget || activePayment || paymentCandidate || executionCase
        || executionWithoutResolution || refundCase || unresolvedReconciliation) {
      fail('SESSION_MONETARY_AMBIGUITY', 'Spend Session retains monetary ambiguity');
    }
  };

  const commandEvent = (db, sessionId, eventType) => (
    loadSessionCommandEvent(db, sessionId, eventType)
  );

  const closeBoundSessionInTransaction = (token, input) => {
    const request = closedRecord(input, [
      'sessionId',
      'expectedSessionHash',
    ], [], 'SESSION_CLOSE_SCHEMA', 'session close');
    const sessionId = boundedToken(request.sessionId, 'session ID', 'SESSION_CLOSE_SCHEMA');
    const expectedSessionHash = canonicalHash(
      request.expectedSessionHash,
      'expected session hash',
      'SESSION_CLOSE_SCHEMA',
    );
    return store.within(token, ({ db, appendEvent }) => {
      const authority = loadSessionAuthority(db, sessionId, { requireActive: false });
      if (authority.state === 'closed') {
        const replay = commandEvent(db, sessionId, 'session.closed');
        if (!replay || replay.expectedSessionHash !== expectedSessionHash) {
          fail('SESSION_CONFIRMATION_STALE', 'session close confirmation is stale');
        }
        const closedSession = publicSession(authority);
        if (replay.closedSessionHash !== closedSession.sessionHash
            || replay.closedAt !== authority.closedAt) {
          fail('SESSION_AUTHORITY_AMBIGUOUS', 'closed session replay binding changed');
        }
        return frozenCopy({ closedSession });
      }
      if (authority.state !== 'open' && authority.state !== 'policy_blocked') {
        fail('SESSION_STATE', 'Spend Session cannot be closed');
      }
      const current = publicSession(authority);
      if (current.sessionHash !== expectedSessionHash) {
        fail('SESSION_CONFIRMATION_STALE', 'session close confirmation is stale');
      }
      assertSessionMonetarySafety(db, sessionId, authority);
      const closedAt = canonicalTimestamp(now(), 'session closedAt');
      if (timestampIsBefore(closedAt, authority.lastSeenAt)) {
        fail('SESSION_TIME', 'Kernel clock regressed during session close');
      }
      const sessionUpdate = db.prepare(`UPDATE spend_sessions
        SET state = 'closed', closed_at = ?
        WHERE id = ? AND state = ? AND closed_at IS NULL`).run(
        closedAt,
        sessionId,
        authority.state,
      );
      if (sessionUpdate.changes !== 1n) {
        fail('SESSION_CONFIRMATION_STALE', 'Spend Session close lost its race');
      }
      const bindingUpdate = db.prepare(`UPDATE agent_session_bindings
        SET state = 'closed', last_seen_at = ?, closed_at = ?
        WHERE id = ? AND session_id = ? AND state = 'open' AND closed_at IS NULL`).run(
        closedAt,
        closedAt,
        authority.bindingId,
        sessionId,
      );
      if (bindingUpdate.changes !== 1n) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'session binding close lost its race');
      }
      const closedSession = publicSession(loadSessionAuthority(db, sessionId, {
        requireActive: false,
        validateEvents: false,
      }));
      appendEvent({
        entityType: 'session_binding',
        entityId: authority.bindingId,
        eventType: 'session.binding_closed',
        data: { sessionId, closedAt, reasonCode: 'SESSION_CLOSED' },
      });
      appendEvent({
        entityType: 'spend_session',
        entityId: sessionId,
        eventType: 'session.closed',
        data: {
          expectedSessionHash,
          closedSessionHash: closedSession.sessionHash,
          closedAt,
        },
      });
      const persistedClosedSession = publicSession(loadSessionAuthority(db, sessionId, {
        requireActive: false,
      }));
      if (persistedClosedSession.sessionHash !== closedSession.sessionHash) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'closed session authority changed');
      }
      return frozenCopy({ closedSession: persistedClosedSession });
    });
  };

  const transitionBlockedSessionInTransaction = (token, input) => {
    const request = closedRecord(input, [
      'sessionId',
      'targetPolicyVersionId',
      'expectedSessionHash',
    ], [], 'SESSION_TRANSITION_SCHEMA', 'session policy transition');
    const sessionId = boundedToken(request.sessionId, 'session ID', 'SESSION_TRANSITION_SCHEMA');
    const targetPolicyVersionId = boundedToken(
      request.targetPolicyVersionId,
      'target policy version ID',
      'SESSION_TRANSITION_SCHEMA',
    );
    const expectedSessionHash = canonicalHash(
      request.expectedSessionHash,
      'expected session hash',
      'SESSION_TRANSITION_SCHEMA',
    );
    return store.within(token, ({ db, appendEvent }) => {
      const authority = loadSessionAuthority(db, sessionId, { requireActive: false });
      if (authority.state === 'closed') {
        const replay = commandEvent(db, sessionId, 'session.policy_transitioned');
        if (!replay
            || replay.expectedSessionHash !== expectedSessionHash
            || replay.targetPolicyVersionId !== targetPolicyVersionId) {
          fail('SESSION_CONFIRMATION_STALE', 'session transition confirmation is stale');
        }
        const previousSession = publicSession(authority);
        const replacementSession = loadHistoricalReplacementSession(db, replay, authority);
        if (previousSession.sessionHash !== replay.closedSessionHash
            || replay.transitionedAt !== authority.closedAt
            || replacementSession.sessionHash !== replay.replacementSessionHash) {
          fail('SESSION_AUTHORITY_AMBIGUOUS', 'session transition replay binding changed');
        }
        return frozenCopy({ previousSession, replacementSession });
      }
      if (authority.enrollment.state !== 'active') {
        fail('AGENT_REVOKED', 'policy transition requires active enrollment');
      }
      if (authority.state !== 'policy_blocked') {
        fail('SESSION_STATE', 'policy transition requires a policy-blocked session');
      }
      const previous = publicSession(authority);
      if (previous.sessionHash !== expectedSessionHash) {
        fail('SESSION_CONFIRMATION_STALE', 'session transition confirmation is stale');
      }
      const activePolicyId = db.prepare(
        'SELECT value FROM metadata WHERE key = ?'
      ).get('active_policy_id')?.value ?? null;
      if (activePolicyId !== targetPolicyVersionId) {
        fail('POLICY_NOT_ACTIVE', 'target PolicyVersion is not active');
      }
      const targetPolicy = validatePolicyRow(db.prepare(
        'SELECT * FROM policy_versions WHERE id = ?',
      ).get(targetPolicyVersionId));
      if (targetPolicy.policy.wallet !== authority.walletAddress) {
        fail('POLICY_WALLET_MISMATCH', 'target PolicyVersion wallet changed');
      }
      assertSessionMonetarySafety(db, sessionId, authority);
      const transitionedAt = canonicalTimestamp(now(), 'session transitionedAt');
      if (timestampIsBefore(transitionedAt, authority.lastSeenAt)) {
        fail('SESSION_TIME', 'Kernel clock regressed during policy transition');
      }
      const closedSessionUpdate = db.prepare(`UPDATE spend_sessions
        SET state = 'closed', closed_at = ?
        WHERE id = ? AND state = 'policy_blocked' AND closed_at IS NULL`).run(
        transitionedAt,
        sessionId,
      );
      if (closedSessionUpdate.changes !== 1n) {
        fail('SESSION_CONFIRMATION_STALE', 'policy transition lost its race');
      }
      const closedBindingUpdate = db.prepare(`UPDATE agent_session_bindings
        SET state = 'closed', last_seen_at = ?, closed_at = ?
        WHERE id = ? AND session_id = ? AND state = 'open' AND closed_at IS NULL`).run(
        transitionedAt,
        transitionedAt,
        authority.bindingId,
        sessionId,
      );
      if (closedBindingUpdate.changes !== 1n) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'policy transition binding changed');
      }
      const {
        id: replacementId,
        bindingId: replacementBindingId,
      } = nextSessionIdentity(db);
      db.prepare(`INSERT INTO spend_sessions
        (id, adapter_id, wallet_address, policy_version_id, state, created_at)
        VALUES (?, ?, ?, ?, 'open', ?)`).run(
        replacementId,
        authority.adapterId,
        authority.walletAddress,
        targetPolicyVersionId,
        transitionedAt,
      );
      db.prepare(`INSERT INTO agent_session_bindings
        (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
         state, created_at, last_seen_at)
        VALUES (?, ?, ?, ?, ?, 'open', ?, ?)`).run(
        replacementBindingId,
        authority.agentInstanceId,
        authority.credentialDigest,
        authority.enrollmentHash,
        replacementId,
        transitionedAt,
        transitionedAt,
      );
      const previousSession = publicSession(loadSessionAuthority(db, sessionId, {
        requireActive: false,
        validateEvents: false,
      }));
      const replacementSession = publicSession(loadSessionAuthority(db, replacementId, {
        validateEvents: false,
      }));
      appendEvent({
        entityType: 'session_binding',
        entityId: authority.bindingId,
        eventType: 'session.binding_closed',
        data: { sessionId, closedAt: transitionedAt, reasonCode: 'POLICY_SUPERSEDED' },
      });
      appendEvent({
        entityType: 'spend_session',
        entityId: replacementId,
        eventType: 'session.started',
        data: {
          adapterId: authority.adapterId,
          enrollmentHash: authority.enrollmentHash,
          policyVersionId: targetPolicyVersionId,
          sessionHash: replacementSession.sessionHash,
          walletAddress: authority.walletAddress,
          createdAt: transitionedAt,
        },
      });
      appendEvent({
        entityType: 'session_binding',
        entityId: replacementBindingId,
        eventType: 'session.binding_opened',
        data: {
          agentInstanceId: authority.agentInstanceId,
          enrollmentHash: authority.enrollmentHash,
          sessionId: replacementId,
          createdAt: transitionedAt,
        },
      });
      appendEvent({
        entityType: 'spend_session',
        entityId: sessionId,
        eventType: 'session.policy_transitioned',
        data: {
          expectedSessionHash,
          targetPolicyVersionId,
          closedSessionHash: previousSession.sessionHash,
          replacementSessionId: replacementId,
          replacementSessionHash: replacementSession.sessionHash,
          transitionedAt,
        },
      });
      const persistedPrevious = publicSession(loadSessionAuthority(db, sessionId, {
        requireActive: false,
      }));
      const persistedReplacement = publicSession(loadSessionAuthority(db, replacementId));
      if (persistedPrevious.sessionHash !== previousSession.sessionHash
          || persistedReplacement.sessionHash !== replacementSession.sessionHash) {
        fail('SESSION_AUTHORITY_AMBIGUOUS', 'policy transition authority changed');
      }
      return frozenCopy({
        previousSession: persistedPrevious,
        replacementSession: persistedReplacement,
      });
    });
  };

  return Object.freeze({
    openOrResumeSession,
    transitionBlockedSessionInTransaction,
    closeBoundSessionInTransaction,
    getSession,
    captureIntent,
    captureIntentInTransaction,
    attachChallenge,
    attachChallengeInTransaction,
    transition,
    transitionInTransaction,
    getIntent,
    matchRetry,
  });
}

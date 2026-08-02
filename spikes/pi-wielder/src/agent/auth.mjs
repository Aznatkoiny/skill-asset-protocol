import crypto from 'node:crypto';
import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { validatePolicyDocument } from '../kernel/policy-engine.mjs';

const INSTANCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const FORWARDED_HEADERS = Object.freeze([
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
]);
const OPTION_FIELDS = Object.freeze([
  'store',
  'intents',
  'walletIdentity',
  'activePolicy',
  'kernelUid',
  'kernelGid',
  'expectedAgentUid',
  'expectedAgentGid',
  'mode',
]);

const ACTIVE_SQL = `SELECT agent_instance_id, credential_digest, enrollment_hash,
    agent_uid, agent_gid, state
  FROM agent_enrollments
  WHERE state = 'active'
  ORDER BY agent_instance_id`;
const BINDING_SQL = `SELECT agent_session_bindings.id AS binding_id,
    agent_session_bindings.agent_instance_id,
    agent_session_bindings.credential_digest,
    agent_session_bindings.enrollment_hash,
    agent_session_bindings.session_id,
    agent_session_bindings.state AS binding_state,
    spend_sessions.state AS session_state
  FROM agent_session_bindings
  JOIN spend_sessions ON spend_sessions.id = agent_session_bindings.session_id
  WHERE agent_session_bindings.enrollment_hash = ?
    AND agent_session_bindings.state = 'open'
    AND spend_sessions.state IN ('open','policy_blocked')
  ORDER BY agent_session_bindings.id`;

function fail(code, message) {
  throw new KernelError(code, message);
}

function unauthorized() {
  fail('AGENT_UNAUTHORIZED', 'Agent authentication failed');
}

function exactOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError('agent auth options must be one plain object');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== OPTION_FIELDS.length
      || OPTION_FIELDS.some((field) => !Object.hasOwn(value, field))
      || keys.some((key) => typeof key !== 'string' || !OPTION_FIELDS.includes(key))) {
    throw new TypeError('agent auth options must contain the exact fields');
  }
  const result = {};
  for (const field of OPTION_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError('agent auth options must contain only data fields');
    }
    result[field] = descriptor.value;
  }
  return result;
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

function identity(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail('AGENT_IDENTITY', `${label} must be one positive safe integer`);
  }
  return value;
}

function identityText(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)
      || !Number.isSafeInteger(Number(value)) || String(Number(value)) !== value) {
    fail('AGENT_AUTHORITY_CORRUPTION', `${label} is invalid`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail('AGENT_AUTHORITY_CORRUPTION', `${label} is invalid`);
  }
  return value;
}

function instanceId(value) {
  if (typeof value !== 'string' || !INSTANCE_PATTERN.test(value)) {
    fail('AGENT_AUTHORITY_CORRUPTION', 'agent instance ID is invalid');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 16 || bytes.toString('base64url') !== value) {
    bytes.fill(0);
    fail('AGENT_AUTHORITY_CORRUPTION', 'agent instance ID is invalid');
  }
  bytes.fill(0);
  return value;
}

function exactStoreRow(value, fields, code, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value)) {
    fail(code, `${label} must be one database row`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) {
    fail(code, `${label} must be one database row`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== fields.length
      || fields.some((field) => !Object.hasOwn(descriptors, field))
      || keys.some((key) => typeof key !== 'string' || !fields.includes(key))
      || keys.some((key) => !descriptors[key]?.enumerable
        || !Object.hasOwn(descriptors[key], 'value'))) {
    fail(code, `${label} fields do not match the closed database schema`);
  }
  return exactRecord(
    Object.fromEntries(fields.map((field) => [field, descriptors[field].value])),
    fields,
    [],
    code,
    label,
  );
}

function activeEnrollmentRow(value) {
  let row;
  try {
    row = exactStoreRow(value, [
      'agent_instance_id',
      'credential_digest',
      'enrollment_hash',
      'agent_uid',
      'agent_gid',
      'state',
    ], 'AGENT_AUTHORITY_CORRUPTION', 'active enrollment row');
  } catch (error) {
    if (error instanceof KernelError) throw error;
    fail('AGENT_AUTHORITY_CORRUPTION', 'active enrollment row is invalid');
  }
  if (row.state !== 'active') fail('AGENT_AUTHORITY_CORRUPTION', 'active enrollment state changed');
  const enrollment = {
    agentInstanceId: instanceId(row.agent_instance_id),
    credentialDigest: hash(row.credential_digest, 'credential digest'),
    enrollmentHash: hash(row.enrollment_hash, 'enrollment hash'),
    agentUid: identityText(row.agent_uid, 'agent UID'),
    agentGid: identityText(row.agent_gid, 'agent GID'),
  };
  const expectedEnrollmentHash = sha256(canonicalJson({
    schemaVersion: 1,
    agentInstanceId: enrollment.agentInstanceId,
    credentialDigest: enrollment.credentialDigest,
    agentUid: enrollment.agentUid,
    agentGid: enrollment.agentGid,
  }));
  if (expectedEnrollmentHash !== enrollment.enrollmentHash) {
    fail('AGENT_AUTHORITY_CORRUPTION', 'active enrollment binding changed');
  }
  return frozenCopy(enrollment);
}

function readActive(readAll) {
  let rows;
  try {
    rows = readAll(ACTIVE_SQL);
  } catch (error) {
    if (error instanceof KernelError) throw error;
    fail('AGENT_AUTHORITY_UNAVAILABLE', 'Agent enrollment authority is unavailable');
  }
  if (!Array.isArray(rows)) fail('AGENT_AUTHORITY_CORRUPTION', 'active enrollment query is invalid');
  if (rows.length > 1) {
    fail('AGENT_ENROLLMENT_AMBIGUOUS', 'Multiple active agent enrollments exist');
  }
  return rows.length === 0 ? null : activeEnrollmentRow(rows[0]);
}

function assertConfiguredEnrollment(enrollment, expectedAgentUid, expectedAgentGid) {
  if (enrollment !== null
      && (enrollment.agentUid !== String(expectedAgentUid)
        || enrollment.agentGid !== String(expectedAgentGid))) {
    fail('AGENT_IDENTITY_MISMATCH', 'Active enrollment differs from configured agent identity');
  }
}

function persistedDigestBytes(value) {
  return Buffer.from(value.slice('sha256:'.length), 'hex');
}

function credentialDigest(value) {
  const decoded = Buffer.from(value, 'base64url');
  try {
    if (decoded.length !== 32 || decoded.toString('base64url') !== value) return null;
    return crypto.createHash('sha256').update(decoded).digest();
  } finally {
    decoded.fill(0);
  }
}

function rejectChannelCredentials(request) {
  if (request.headers.has('cookie')
      || FORWARDED_HEADERS.some((name) => request.headers.has(name))) unauthorized();
  let parsed;
  try {
    parsed = new URL(request.url);
  } catch {
    unauthorized();
  }
  if (parsed.search !== '' || parsed.hash !== '') unauthorized();
}

function validateWalletIdentity(value) {
  const identityValue = exactRecord(
    value,
    ['network', 'address'],
    [],
    'AGENT_CONFIGURATION',
    'wallet identity',
  );
  if (typeof identityValue.network !== 'string'
      || typeof identityValue.address !== 'string'
      || !ADDRESS_PATTERN.test(identityValue.address)) {
    fail('AGENT_CONFIGURATION', 'wallet identity is invalid');
  }
  return frozenCopy(identityValue);
}

function validateActivePolicy(value, walletIdentity) {
  const version = exactRecord(
    value,
    ['id', 'hash', 'policy'],
    [],
    'AGENT_CONFIGURATION',
    'active PolicyVersion',
  );
  let policy;
  try {
    policy = validatePolicyDocument(version.policy);
  } catch {
    fail('AGENT_CONFIGURATION', 'active PolicyVersion is invalid');
  }
  if (typeof version.id !== 'string' || version.id.length === 0
      || !HASH_PATTERN.test(version.hash)
      || canonicalJson(version.policy) !== canonicalJson(policy)
      || sha256(canonicalJson(policy)) !== version.hash
      || policy.network !== walletIdentity.network
      || policy.wallet !== walletIdentity.address) {
    fail('AGENT_CONFIGURATION', 'active PolicyVersion authority does not match the wallet');
  }
  return frozenCopy({ id: version.id, hash: version.hash, policy });
}

function validatePrincipal(value) {
  return frozenCopy(exactRecord(value, [
    'agentInstanceId',
    'credentialDigest',
    'enrollmentHash',
    'agentUid',
    'agentGid',
  ], [], 'AGENT_UNAUTHORIZED', 'authenticated agent'));
}

function validateBinding(value, enrollment) {
  const row = exactStoreRow(value, [
    'binding_id',
    'agent_instance_id',
    'credential_digest',
    'enrollment_hash',
    'session_id',
    'binding_state',
    'session_state',
  ], 'SESSION_AUTHORITY_AMBIGUOUS', 'agent session binding');
  if (row.binding_state !== 'open'
      || (row.session_state !== 'open' && row.session_state !== 'policy_blocked')) {
    fail('AGENT_SESSION_UNAVAILABLE', 'Agent has no active Spend Session');
  }
  if (row.agent_instance_id !== enrollment.agentInstanceId
      || row.credential_digest !== enrollment.credentialDigest
      || row.enrollment_hash !== enrollment.enrollmentHash
      || typeof row.binding_id !== 'string' || row.binding_id.length === 0
      || typeof row.session_id !== 'string' || row.session_id.length === 0) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Agent Spend Session binding is ambiguous');
  }
  return row;
}

export function createAgentAuth(options) {
  const captured = exactOptions(options);
  const readAll = captureMethod(captured.store, 'readAll', 'agent auth store');
  const getSession = captureMethod(captured.intents, 'getSession', 'intent repository');
  const kernelUid = identity(captured.kernelUid, 'kernel UID');
  const kernelGid = identity(captured.kernelGid, 'kernel GID');
  const expectedAgentUid = identity(captured.expectedAgentUid, 'agent UID');
  const expectedAgentGid = identity(captured.expectedAgentGid, 'agent GID');
  if (captured.mode !== 'deterministic' && captured.mode !== 'cdp-testnet') {
    fail('AGENT_CONFIGURATION', 'agent authentication mode is invalid');
  }
  if (captured.mode === 'cdp-testnet' && expectedAgentUid === kernelUid) {
    fail('AGENT_IDENTITY_NOT_ISOLATED', 'live agent UID must differ from kernel UID');
  }
  if (captured.mode === 'deterministic'
      && (expectedAgentUid !== kernelUid || expectedAgentGid !== kernelGid)) {
    fail('AGENT_DETERMINISTIC_FIXTURE', 'deterministic auth requires one same-identity fixture');
  }
  const walletIdentity = validateWalletIdentity(captured.walletIdentity);
  validateActivePolicy(captured.activePolicy, walletIdentity);
  assertConfiguredEnrollment(readActive(readAll), expectedAgentUid, expectedAgentGid);

  function authenticate(request) {
    if (!(request instanceof Request)) unauthorized();
    rejectChannelCredentials(request);
    const enrollment = readActive(readAll);
    if (enrollment === null) {
      fail('AGENT_ENROLLMENT_REQUIRED', 'An active agent enrollment is required');
    }
    assertConfiguredEnrollment(enrollment, expectedAgentUid, expectedAgentGid);
    const authorization = request.headers.get('authorization');
    const match = typeof authorization === 'string'
      ? /^WalletKernelAgent ([A-Za-z0-9_-]{43})$/.exec(authorization)
      : null;
    const actual = match ? credentialDigest(match[1]) : null;
    const expected = persistedDigestBytes(enrollment.credentialDigest);
    const candidate = actual ?? Buffer.alloc(32);
    let valid = false;
    try {
      valid = crypto.timingSafeEqual(candidate, expected);
    } finally {
      candidate.fill(0);
      expected.fill(0);
    }
    if (!match || actual === null || !valid) unauthorized();
    return enrollment;
  }

  function resolveBoundSession(value) {
    const principal = validatePrincipal(value);
    const enrollment = readActive(readAll);
    if (enrollment === null) {
      fail('AGENT_ENROLLMENT_REQUIRED', 'An active agent enrollment is required');
    }
    assertConfiguredEnrollment(enrollment, expectedAgentUid, expectedAgentGid);
    if (canonicalJson(principal) !== canonicalJson(enrollment)) unauthorized();
    let rows;
    try {
      rows = readAll(BINDING_SQL, [enrollment.enrollmentHash]);
    } catch (error) {
      if (error instanceof KernelError) throw error;
      fail('AGENT_AUTHORITY_UNAVAILABLE', 'Agent session authority is unavailable');
    }
    if (!Array.isArray(rows)) fail('SESSION_AUTHORITY_AMBIGUOUS', 'Agent session query is invalid');
    if (rows.length === 0) fail('AGENT_SESSION_UNAVAILABLE', 'Agent has no active Spend Session');
    if (rows.length !== 1) {
      fail('SESSION_AUTHORITY_AMBIGUOUS', 'Agent has multiple active Spend Sessions');
    }
    const binding = validateBinding(rows[0], enrollment);
    let session;
    try {
      session = getSession(binding.session_id);
    } catch (error) {
      if (error instanceof KernelError) throw error;
      fail('AGENT_AUTHORITY_UNAVAILABLE', 'Agent Spend Session is unavailable');
    }
    if (!session || typeof session !== 'object'
        || session.id !== binding.session_id
        || session.agentInstanceId !== enrollment.agentInstanceId
        || session.enrollmentHash !== enrollment.enrollmentHash
        || session.walletAddress !== walletIdentity.address
        || session.state !== binding.session_state) {
      fail('SESSION_AUTHORITY_AMBIGUOUS', 'Agent Spend Session authority changed');
    }
    if (session.state === 'policy_blocked') {
      fail('POLICY_TRANSITION_REQUIRED', 'Agent Spend Session requires a guarded policy transition');
    }
    // The repository lookup is the dynamic authority boundary: it validates an
    // open session against the currently active PolicyVersion. Capturing the
    // constructor-time policy ID here would strand a safely transitioned
    // replacement until process restart.
    return frozenCopy(session);
  }

  return Object.freeze({ authenticate, resolveBoundSession });
}

import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';
import { validatePolicyDocument } from './policy-engine.mjs';
import { KERNEL_SCHEMA_VERSION } from './sqlite-schema.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const EVM_HASH_PATTERN = /^0x[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const INSTANCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const STABLE_REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,99}$/;
const OPEN_APPROVALS = new Set(['pending', 'approved']);
const AMBIGUOUS_PAYMENT_STATES = new Set(['signing', 'signed', 'retrying']);
const LEGAL_INTENT_TRANSITIONS = Object.freeze(new Map([
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
const APPROVAL_CANCEL_REASONS = new Set([
  'POLICY_SUPERSEDED',
  'SESSION_CLOSED',
  'APPROVAL_CHALLENGE_CHANGED',
]);
const ENFORCED_ISOLATION_PROBES = Object.freeze({
  authorityDirectory: 'EACCES',
  database: 'EACCES',
  operatorToken: 'EACCES',
  receiptKey: 'EACCES',
  kernelEnvironment: 'EACCES',
  agentCredential: 'READABLE',
  releaseTreeWrite: 'EACCES',
  dependencyTreeWrite: 'EACCES',
  serviceArtifactsWrite: 'EACCES',
  kernelEnvironmentParentWrite: 'EACCES',
});
const SELLER_EVIDENCE_UNKNOWN_REASONS = new Set([
  'SELLER_EVIDENCE_BINDING_INVALID',
  'SELLER_EVIDENCE_ENDPOINT_INVALID',
  'SELLER_EVIDENCE_FETCH_FAILED',
  'SELLER_EVIDENCE_TIMEOUT',
  'SELLER_EVIDENCE_REDIRECT',
  'SELLER_EVIDENCE_HTTP_STATUS',
  'SELLER_EVIDENCE_CONTENT_TYPE',
  'SELLER_EVIDENCE_TOO_LARGE',
  'SELLER_EVIDENCE_RESPONSE_INVALID',
  'SELLER_EVIDENCE_JSON_INVALID',
  'SELLER_EVIDENCE_ATTESTATION_INVALID',
  'SELLER_EVIDENCE_ATTESTATION_MISMATCH',
  'SELLER_EVIDENCE_TIME_INVALID',
  'SELLER_EVIDENCE_SIGNATURE_INVALID',
]);
const PAYMENT_RPC_UNKNOWN_REASONS = new Set([
  'RPC_RECEIPT_MISSING',
  'RPC_CONFIRMATIONS_INSUFFICIENT',
  'RPC_PROVIDER_UNAVAILABLE',
  'RPC_REORG_DETECTED',
  'RPC_EVIDENCE_INVALID',
  'AUTHORIZATION_ALREADY_USED',
  'AUTHORIZATION_NOT_EXPIRED',
]);
const REFUND_RPC_UNKNOWN_REASONS = new Set([
  'RPC_RECEIPT_MISSING',
  'RPC_CONFIRMATIONS_INSUFFICIENT',
  'RPC_PROVIDER_UNAVAILABLE',
  'RPC_REORG_DETECTED',
  'RPC_EVIDENCE_INVALID',
]);

function semantic(message, cause) {
  if (cause instanceof KernelError && cause.code === 'AUTHORITY_SEMANTIC_CORRUPTION') {
    return cause;
  }
  return new KernelError('AUTHORITY_SEMANTIC_CORRUPTION', message, { cause });
}

function assertPlainDependencies(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new TypeError(`${label} must be one plain object`);
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length !== names.length
      || keys.some((key) => typeof key !== 'string' || !names.includes(key))) {
    throw new TypeError(`${label} has an invalid shape`);
  }
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new TypeError(`${label} must contain enumerable data properties`);
    }
  }
  return value;
}

function requireMethods(value, names, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new TypeError(`${label} is required`);
  }
  for (const name of names) {
    if (typeof value[name] !== 'function') throw new TypeError(`${label}.${name} is required`);
  }
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    throw semantic(`${label} is not a canonical SHA-256 hash`);
  }
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    throw semantic(`${label} is not a canonical lowercase EVM address`);
  }
  return value;
}

function canonicalTransactionId(value, label) {
  if (typeof value !== 'string' || !EVM_HASH_PATTERN.test(value)) {
    throw semantic(`${label} is not a canonical lowercase transaction hash`);
  }
  return value;
}

function canonicalReason(value, label) {
  if (typeof value !== 'string' || !STABLE_REASON_PATTERN.test(value)) {
    throw semantic(`${label} is not a stable reason code`);
  }
  return value;
}

function parseCanonical(value, label) {
  let parsed;
  try {
    parsed = JSON.parse(value);
    if (canonicalJson(parsed) !== value) throw new Error('non-canonical JSON');
  } catch (cause) {
    throw semantic(`${label} is not canonical JSON`, cause);
  }
  return parsed;
}

function safeTimestamp(value, label) {
  try {
    return canonicalTimestamp(value, label);
  } catch (cause) {
    throw semantic(`${label} is invalid`, cause);
  }
}

function safeToken(value, label) {
  try {
    return canonicalToken(value, label);
  } catch (cause) {
    throw semantic(`${label} is invalid`, cause);
  }
}

function number(value, label) {
  const converted = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(converted)) throw semantic(`${label} is not a safe integer`);
  return converted;
}

function mapBy(rows, key) {
  const mapped = new Map();
  for (const row of rows) {
    const value = row[key];
    const existing = mapped.get(value) ?? [];
    existing.push(row);
    mapped.set(value, existing);
  }
  return mapped;
}

function one(mapped, key, label) {
  const rows = mapped.get(key) ?? [];
  if (rows.length > 1) throw semantic(`${label} is ambiguous`);
  return rows[0] ?? null;
}

function exactSemantic(value, required, optional, label) {
  try {
    return exactRecord(
      value,
      required,
      optional,
      'AUTHORITY_SEMANTIC_CORRUPTION',
      label,
    );
  } catch (cause) {
    throw semantic(`${label} has an invalid closed shape`, cause);
  }
}

function canonicalAtomic(value, label) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    throw semantic(`${label} is not canonical atomic text`);
  }
  return value;
}

function entityEvents(snapshot, entityType, entityId) {
  return snapshot.events.filter((event) => (
    event.entity_type === entityType && event.entity_id === entityId
  ));
}

function bindingIdFor(sessionId) {
  const digest = sha256(canonicalJson({
    domain: 'wallet-kernel.session-binding.v1',
    sessionId,
  }));
  return `binding-${digest.slice('sha256:'.length)}`;
}

function sessionAuthorityHash(session, binding, {
  sessionState = session.state,
  sessionClosedAt = session.closed_at,
  bindingState = binding.state,
  bindingLastSeenAt = binding.last_seen_at,
  bindingClosedAt = binding.closed_at,
} = {}) {
  return sha256(canonicalJson({
    session: {
      id: session.id,
      adapterId: session.adapter_id,
      walletAddress: session.wallet_address,
      policyVersionId: session.policy_version_id,
      state: sessionState,
      createdAt: session.created_at,
      closedAt: sessionClosedAt,
    },
    binding: {
      id: binding.id,
      agentInstanceId: binding.agent_instance_id,
      credentialDigest: binding.credential_digest,
      enrollmentHash: binding.enrollment_hash,
      sessionId: session.id,
      state: bindingState,
      createdAt: binding.created_at,
      lastSeenAt: bindingLastSeenAt,
      closedAt: bindingClosedAt,
    },
  }));
}

function verifyEventChain(events) {
  let previousHash = null;
  for (const row of events) {
    const data = parseCanonical(row.data_json, 'event data');
    const createdAt = safeTimestamp(row.created_at, 'event timestamp');
    safeToken(row.entity_type, 'event entity type');
    safeToken(row.entity_id, 'event entity ID');
    safeToken(row.event_type, 'event type');
    const expected = sha256(canonicalJson({
      entityType: row.entity_type,
      entityId: row.entity_id,
      eventType: row.event_type,
      data,
      previousHash,
      createdAt,
    }));
    if (row.previous_hash !== previousHash || row.event_hash !== expected) {
      throw semantic('authority event hash chain is invalid');
    }
    previousHash = row.event_hash;
  }
}

function verifyPolicies(snapshot) {
  const policies = new Map();
  let predecessor = null;
  let predecessorAppliedAt = null;
  for (const row of snapshot.policy_versions) {
    safeToken(row.id, 'PolicyVersion ID');
    const document = parseCanonical(row.canonical_json, 'PolicyVersion document');
    let policy;
    try {
      policy = validatePolicyDocument(document);
    } catch (cause) {
      throw semantic('PolicyVersion document is invalid', cause);
    }
    if (canonicalJson(policy) !== row.canonical_json
        || canonicalHash(row.policy_hash, 'PolicyVersion hash') !== sha256(row.canonical_json)
        || number(row.schema_version, 'PolicyVersion schema version') !== policy.schemaVersion) {
      throw semantic('PolicyVersion immutable binding changed');
    }
    if (row.predecessor_hash !== null) canonicalHash(row.predecessor_hash, 'policy predecessor');
    const appliedAt = safeTimestamp(row.applied_at, 'PolicyVersion appliedAt');
    if (row.predecessor_hash !== predecessor
        || (predecessorAppliedAt !== null
          && Date.parse(appliedAt) < Date.parse(predecessorAppliedAt))) {
      throw semantic('PolicyVersion predecessor chain or chronology changed');
    }
    const events = entityEvents(snapshot, 'policy', row.id);
    if (events.length !== 1 || events[0].event_type !== 'policy.applied') {
      throw semantic('PolicyVersion application event is incomplete or ambiguous');
    }
    const eventData = exactSemantic(parseCanonical(
      events[0].data_json,
      'PolicyVersion applied event data',
    ), ['policyHash', 'predecessorHash', 'blockedSessionIds'], [], 'policy.applied event');
    if (eventData.policyHash !== row.policy_hash
        || eventData.predecessorHash !== row.predecessor_hash
        || !Array.isArray(eventData.blockedSessionIds)
        || eventData.blockedSessionIds.some((id) => typeof id !== 'string')
        || Date.parse(events[0].created_at) < Date.parse(appliedAt)) {
      throw semantic('PolicyVersion application event binding changed');
    }
    policies.set(row.id, Object.freeze({ row, policy }));
    predecessor = row.policy_hash;
    predecessorAppliedAt = appliedAt;
  }
  const activeRows = snapshot.metadata.filter((row) => row.key === 'active_policy_id');
  if (activeRows.length > 1) throw semantic('active PolicyVersion metadata is ambiguous');
  const activePolicyId = activeRows[0]?.value ?? null;
  if (activePolicyId !== null && !policies.has(activePolicyId)) {
    throw semantic('active PolicyVersion metadata is dangling');
  }
  const latestPolicyId = snapshot.policy_versions.at(-1)?.id ?? null;
  if (activePolicyId !== latestPolicyId) {
    throw semantic('active PolicyVersion is not the exact chain head');
  }
  return Object.freeze({ activePolicyId, policies });
}

function verifyEnrollments(snapshot) {
  const byHash = new Map();
  let activeCount = 0;
  for (const row of snapshot.agent_enrollments) {
    if (typeof row.agent_instance_id !== 'string'
        || !INSTANCE_ID_PATTERN.test(row.agent_instance_id)
        || Buffer.from(row.agent_instance_id, 'base64url').length !== 16
        || Buffer.from(row.agent_instance_id, 'base64url').toString('base64url')
          !== row.agent_instance_id) {
      throw semantic('agent enrollment instance ID is invalid');
    }
    canonicalHash(row.credential_digest, 'agent credential digest');
    canonicalHash(row.enrollment_hash, 'agent enrollment hash');
    canonicalHash(row.enrolled_by_operator_hash, 'agent enrollment operator hash');
    if (!/^[1-9][0-9]*$/.test(row.agent_uid) || !/^[1-9][0-9]*$/.test(row.agent_gid)) {
      throw semantic('agent enrollment identity is invalid');
    }
    const descriptor = {
      schemaVersion: 1,
      agentInstanceId: row.agent_instance_id,
      credentialDigest: row.credential_digest,
      agentUid: row.agent_uid,
      agentGid: row.agent_gid,
    };
    if (sha256(canonicalJson(descriptor)) !== row.enrollment_hash) {
      throw semantic('agent enrollment hash changed');
    }
    if (byHash.has(row.enrollment_hash)) {
      throw semantic('agent enrollment hash is ambiguous');
    }
    const enrolledAt = safeTimestamp(row.enrolled_at, 'agent enrolledAt');
    const events = entityEvents(snapshot, 'agent_enrollment', row.agent_instance_id);
    const expectedTypes = row.state === 'revoked'
      ? ['agent.enrolled', 'agent.revoked']
      : ['agent.enrolled'];
    if (canonicalJson(events.map((event) => event.event_type)) !== canonicalJson(expectedTypes)) {
      throw semantic('agent enrollment event lifecycle is missing, duplicated, or reordered');
    }
    const enrolledEvent = exactSemantic(
      parseCanonical(events[0].data_json, 'agent enrollment event data'),
      [
        'enrollmentHash', 'credentialDigest', 'agentUid', 'agentGid',
        'operatorIdHash', 'isolation', 'enrolledAt',
      ],
      [],
      'agent.enrolled event',
    );
    if (enrolledEvent.enrollmentHash !== row.enrollment_hash
        || enrolledEvent.credentialDigest !== row.credential_digest
        || enrolledEvent.agentUid !== row.agent_uid
        || enrolledEvent.agentGid !== row.agent_gid
        || enrolledEvent.operatorIdHash !== row.enrolled_by_operator_hash
        || enrolledEvent.enrolledAt !== enrolledAt
        || !new Set(['simulated', 'pending_verification']).has(enrolledEvent.isolation)
        || Date.parse(safeTimestamp(events[0].created_at, 'agent enrolled event createdAt'))
          < Date.parse(enrolledAt)) {
      throw semantic('agent enrollment creation event binding changed');
    }
    if (row.state === 'active') {
      activeCount += 1;
      if (row.revoked_by_operator_hash !== null || row.revoked_at !== null) {
        throw semantic('active enrollment contains revocation fields');
      }
    } else if (row.state === 'revoked') {
      canonicalHash(row.revoked_by_operator_hash, 'agent revocation operator hash');
      const revokedAt = safeTimestamp(row.revoked_at, 'agent revokedAt');
      if (Date.parse(revokedAt) < Date.parse(enrolledAt)) {
        throw semantic('agent revocation predates enrollment');
      }
      const revokedEvent = exactSemantic(
        parseCanonical(events[1].data_json, 'agent revocation event data'),
        ['enrollmentHash', 'operatorIdHash', 'boundSessionIds', 'revokedAt'],
        [],
        'agent.revoked event',
      );
      if (!Array.isArray(revokedEvent.boundSessionIds)
          || revokedEvent.boundSessionIds.some((id) => {
            try { safeToken(id, 'revoked bound session ID'); return false; } catch { return true; }
          })) {
        throw semantic('agent revocation event session binding list is invalid');
      }
      const expectedBoundSessionIds = snapshot.agent_session_bindings
        .filter((binding) => {
          if (binding.enrollment_hash !== row.enrollment_hash) return false;
          const createdAt = safeTimestamp(binding.created_at, 'revoked binding createdAt');
          const closedAt = binding.closed_at === null
            ? null
            : safeTimestamp(binding.closed_at, 'revoked binding closedAt');
          return Date.parse(createdAt) <= Date.parse(revokedAt)
            && (closedAt === null || Date.parse(closedAt) > Date.parse(revokedAt));
        })
        .map((binding) => binding.session_id)
        .sort();
      if (revokedEvent.enrollmentHash !== row.enrollment_hash
          || revokedEvent.operatorIdHash !== row.revoked_by_operator_hash
          || revokedEvent.revokedAt !== revokedAt
          || canonicalJson(revokedEvent.boundSessionIds) !== canonicalJson(expectedBoundSessionIds)
          || Date.parse(safeTimestamp(events[1].created_at, 'agent revoked event createdAt'))
            < Date.parse(revokedAt)) {
        throw semantic('agent revocation event binding changed');
      }
    } else {
      throw semantic('agent enrollment state is invalid');
    }
    byHash.set(row.enrollment_hash, Object.freeze({
      ...row,
      isolation: enrolledEvent.isolation,
    }));
  }
  if (activeCount > 1) throw semantic('multiple active enrollments exist');
  const identities = new Set(snapshot.agent_enrollments.map((row) => row.agent_instance_id));
  if (snapshot.events.some((event) => (
    event.entity_type === 'agent_enrollment' && !identities.has(event.entity_id)
  ))) {
    throw semantic('orphan agent enrollment lifecycle event exists');
  }
  return byHash;
}

function verifySessions(snapshot, policyAuthority, enrollments) {
  const bindingsBySession = mapBy(snapshot.agent_session_bindings, 'session_id');
  const bindingsById = new Map(snapshot.agent_session_bindings.map((row) => [row.id, row]));
  const sessionRowsById = new Map(snapshot.spend_sessions.map((row) => [row.id, row]));
  const sessions = new Map();
  const seenOpenEnrollment = new Set();
  for (const session of snapshot.spend_sessions) {
    safeToken(session.id, 'Spend Session ID');
    canonicalAddress(session.wallet_address, 'Spend Session wallet');
    safeTimestamp(session.created_at, 'Spend Session createdAt');
    const policy = policyAuthority.policies.get(session.policy_version_id);
    if (!policy || policy.policy.wallet !== session.wallet_address) {
      throw semantic('Spend Session policy binding changed');
    }
    const bindings = bindingsBySession.get(session.id) ?? [];
    if (bindings.length !== 1) {
      throw semantic('Spend Session must have exactly one agent binding');
    }
    const binding = bindings[0];
    const enrollment = enrollments.get(binding.enrollment_hash);
    if (!enrollment
        || binding.id !== bindingIdFor(session.id)
        || binding.agent_instance_id !== enrollment.agent_instance_id
        || binding.credential_digest !== enrollment.credential_digest
        || session.adapter_id !== `pi:${enrollment.agent_instance_id}`
        || binding.created_at !== session.created_at) {
      throw semantic('Spend Session and enrollment binding disagree');
    }
    const initialSessionHash = sessionAuthorityHash(session, binding, {
      sessionState: 'open',
      sessionClosedAt: null,
      bindingState: 'open',
      bindingLastSeenAt: session.created_at,
      bindingClosedAt: null,
    });
    const sessionEvents = entityEvents(snapshot, 'spend_session', session.id);
    const bindingEvents = entityEvents(snapshot, 'session_binding', binding.id);
    const startedEvents = sessionEvents.filter((event) => event.event_type === 'session.started');
    const openedEvents = bindingEvents.filter(
      (event) => event.event_type === 'session.binding_opened',
    );
    if (startedEvents.length !== 1 || openedEvents.length !== 1
        || sessionEvents.some((event) => !new Set([
          'session.started', 'session.policy_blocked', 'session.closed',
          'session.policy_transitioned',
        ]).has(event.event_type))
        || bindingEvents.some((event) => !new Set([
          'session.binding_opened', 'session.binding_closed',
        ]).has(event.event_type))) {
      throw semantic('Spend Session genesis or lifecycle events are incomplete');
    }
    const started = exactSemantic(
      parseCanonical(startedEvents[0].data_json, 'session.started event data'),
      [
        'adapterId', 'enrollmentHash', 'policyVersionId', 'sessionHash',
        'walletAddress', 'createdAt',
      ],
      [],
      'session.started event',
    );
    const opened = exactSemantic(
      parseCanonical(openedEvents[0].data_json, 'session.binding_opened event data'),
      ['agentInstanceId', 'enrollmentHash', 'sessionId', 'createdAt'],
      [],
      'session.binding_opened event',
    );
    if (started.adapterId !== session.adapter_id
        || started.enrollmentHash !== binding.enrollment_hash
        || started.policyVersionId !== session.policy_version_id
        || started.sessionHash !== initialSessionHash
        || started.walletAddress !== session.wallet_address
        || started.createdAt !== session.created_at
        || opened.agentInstanceId !== binding.agent_instance_id
        || opened.enrollmentHash !== binding.enrollment_hash
        || opened.sessionId !== session.id
        || opened.createdAt !== session.created_at
        || Date.parse(safeTimestamp(
          startedEvents[0].created_at,
          'session.started event createdAt',
        )) < Date.parse(session.created_at)
        || Date.parse(safeTimestamp(
          openedEvents[0].created_at,
          'session.binding_opened event createdAt',
        )) < Date.parse(session.created_at)) {
      throw semantic('Spend Session genesis event binding changed');
    }
    const bindingLastSeenAt = safeTimestamp(
      binding.last_seen_at,
      'session binding lastSeenAt',
    );
    if (Date.parse(bindingLastSeenAt) < Date.parse(session.created_at)) {
      throw semantic('Spend Session binding chronology regressed');
    }
    const open = session.state === 'open' || session.state === 'policy_blocked';
    if (open) {
      if (binding.state !== 'open' || session.closed_at !== null || binding.closed_at !== null) {
        throw semantic('open Spend Session has a closed or partial binding');
      }
      const identity = `${binding.agent_instance_id}\u0000${binding.credential_digest}`;
      if (seenOpenEnrollment.has(identity)) {
        throw semantic('agent enrollment owns more than one open session candidate');
      }
      seenOpenEnrollment.add(identity);
      if (session.state === 'open'
          && policyAuthority.activePolicyId !== null
          && session.policy_version_id !== policyAuthority.activePolicyId) {
        throw semantic('open Spend Session does not use the active policy');
      }
      if (session.state === 'policy_blocked'
          && session.policy_version_id === policyAuthority.activePolicyId) {
        throw semantic('policy-blocked Spend Session still uses the active policy');
      }
      const blockedEvents = sessionEvents.filter(
        (event) => event.event_type === 'session.policy_blocked',
      );
      const terminalEvents = sessionEvents.filter((event) => (
        event.event_type === 'session.closed'
          || event.event_type === 'session.policy_transitioned'
      ));
      const closedBindingEvents = bindingEvents.filter(
        (event) => event.event_type === 'session.binding_closed',
      );
      if (terminalEvents.length !== 0 || closedBindingEvents.length !== 0
          || (session.state === 'open' && blockedEvents.length !== 0)
          || (session.state === 'policy_blocked' && blockedEvents.length !== 1)) {
        throw semantic('open Spend Session event lifecycle disagrees with its state');
      }
      if (blockedEvents.length === 1) {
        const blocked = exactSemantic(
          parseCanonical(blockedEvents[0].data_json, 'session.policy_blocked event data'),
          ['previousPolicyVersionId', 'targetPolicyVersionId'],
          [],
          'session.policy_blocked event',
        );
        const targetPolicy = policyAuthority.policies.get(blocked.targetPolicyVersionId);
        const targetEvent = targetPolicy === undefined
          ? null
          : entityEvents(snapshot, 'policy', targetPolicy.row.id)[0];
        const targetData = targetEvent === null
          ? null
          : parseCanonical(targetEvent.data_json, 'blocking policy event data');
        if (blocked.previousPolicyVersionId !== session.policy_version_id
            || targetPolicy === undefined
            || !Array.isArray(targetData?.blockedSessionIds)
            || !targetData.blockedSessionIds.includes(session.id)) {
          throw semantic('policy-blocked Spend Session event binding changed');
        }
      }
    } else if (session.state === 'closed') {
      const closedAt = safeTimestamp(session.closed_at, 'Spend Session closedAt');
      if (binding.state !== 'closed' || binding.closed_at !== closedAt
          || binding.last_seen_at !== closedAt
          || Date.parse(closedAt) < Date.parse(session.created_at)) {
        throw semantic('closed Spend Session and binding disagree');
      }
      const closedBindingEvents = bindingEvents.filter(
        (event) => event.event_type === 'session.binding_closed',
      );
      const terminalEvents = sessionEvents.filter((event) => (
        event.event_type === 'session.closed'
          || event.event_type === 'session.policy_transitioned'
      ));
      if (closedBindingEvents.length !== 1 || terminalEvents.length !== 1) {
        throw semantic('closed Spend Session lifecycle event is missing or ambiguous');
      }
      const terminalType = terminalEvents[0].event_type;
      const closedBinding = exactSemantic(
        parseCanonical(closedBindingEvents[0].data_json, 'session binding close event data'),
        ['sessionId', 'closedAt', 'reasonCode'],
        [],
        'session.binding_closed event',
      );
      if (closedBinding.sessionId !== session.id || closedBinding.closedAt !== closedAt
          || closedBinding.reasonCode !== (terminalType === 'session.closed'
            ? 'SESSION_CLOSED'
            : 'POLICY_SUPERSEDED')) {
        throw semantic('closed Spend Session binding event changed');
      }
      const closedSessionHash = sessionAuthorityHash(session, binding);
      if (terminalType === 'session.closed') {
        const closed = exactSemantic(
          parseCanonical(terminalEvents[0].data_json, 'session.closed event data'),
          ['expectedSessionHash', 'closedSessionHash', 'closedAt'],
          [],
          'session.closed event',
        );
        if (closed.closedAt !== closedAt
            || canonicalHash(closed.expectedSessionHash, 'expected closed session hash')
              !== closed.expectedSessionHash
            || closed.closedSessionHash !== closedSessionHash) {
          throw semantic('session.closed event binding changed');
        }
      } else {
        const transitioned = exactSemantic(
          parseCanonical(terminalEvents[0].data_json, 'session transition event data'),
          [
            'expectedSessionHash', 'targetPolicyVersionId', 'closedSessionHash',
            'replacementSessionId', 'replacementSessionHash', 'transitionedAt',
          ],
          [],
          'session.policy_transitioned event',
        );
        const replacement = sessionRowsById.get(transitioned.replacementSessionId);
        const replacementBindings = replacement === undefined
          ? []
          : bindingsBySession.get(replacement.id) ?? [];
        const replacementBinding = replacementBindings.length === 1
          ? replacementBindings[0]
          : null;
        const replacementInitialHash = replacementBinding === null
          ? null
          : sessionAuthorityHash(replacement, replacementBinding, {
            sessionState: 'open',
            sessionClosedAt: null,
            bindingState: 'open',
            bindingLastSeenAt: replacement.created_at,
            bindingClosedAt: null,
          });
        if (transitioned.transitionedAt !== closedAt
            || canonicalHash(transitioned.expectedSessionHash, 'transition expected session hash')
              !== transitioned.expectedSessionHash
            || transitioned.closedSessionHash !== closedSessionHash
            || transitioned.targetPolicyVersionId !== replacement?.policy_version_id
            || replacement?.created_at !== closedAt
            || transitioned.replacementSessionHash !== replacementInitialHash) {
          throw semantic('session.policy_transitioned event binding changed');
        }
      }
      if (Date.parse(safeTimestamp(
        closedBindingEvents[0].created_at,
        'session binding closed event createdAt',
      )) < Date.parse(closedAt)
          || Date.parse(safeTimestamp(
            terminalEvents[0].created_at,
            'session terminal event createdAt',
          )) < Date.parse(closedAt)) {
        throw semantic('closed Spend Session event chronology regressed');
      }
    } else {
      throw semantic('Spend Session state is invalid');
    }
    sessions.set(session.id, Object.freeze({ session, binding, enrollment, policy }));
  }
  if (snapshot.agent_session_bindings.length !== snapshot.spend_sessions.length) {
    throw semantic('dangling agent session binding exists');
  }
  if (snapshot.events.some((event) => (
    (event.entity_type === 'spend_session' && !sessionRowsById.has(event.entity_id))
      || (event.entity_type === 'session_binding' && !bindingsById.has(event.entity_id))
  ))) {
    throw semantic('orphan Spend Session lifecycle event exists');
  }
  const activeEnrollment = [...enrollments.values()].find((row) => row.state === 'active') ?? null;
  if (activeEnrollment) {
    const activeOpenBinding = snapshot.agent_session_bindings.some((binding) => (
      binding.enrollment_hash === activeEnrollment.enrollment_hash && binding.state === 'open'
    ));
    const revokedOpenBinding = snapshot.agent_session_bindings.some((binding) => (
      binding.state === 'open'
        && enrollments.get(binding.enrollment_hash)?.state === 'revoked'
    ));
    if (!activeOpenBinding && revokedOpenBinding) {
      throw semantic('active unbound enrollment conflicts with retained revoked open authority');
    }
  }
  return sessions;
}

function verifyIsolation(snapshot, enrollments, startupAt) {
  let current = null;
  const attestationIds = new Set(snapshot.isolation_attestations.map((row) => row.id));
  for (const row of snapshot.isolation_attestations) {
    safeToken(row.id, 'isolation attestation ID');
    const enrollment = enrollments.get(row.enrollment_hash);
    if (!enrollment) throw semantic('isolation attestation enrollment is missing');
    const report = parseCanonical(row.report_json, 'isolation attestation report');
    if (canonicalHash(row.report_hash, 'isolation report hash') !== sha256(canonicalJson(report))) {
      throw semantic('isolation attestation report hash changed');
    }
    canonicalHash(row.imported_by_operator_hash, 'isolation attestation operator hash');
    const probedAt = safeTimestamp(row.probed_at, 'isolation probedAt');
    const expiresAt = safeTimestamp(row.expires_at, 'isolation expiresAt');
    const importedAt = safeTimestamp(row.imported_at, 'isolation importedAt');
    if (Date.parse(expiresAt) <= Date.parse(probedAt)
        || Date.parse(expiresAt) - Date.parse(probedAt) > 15 * 60 * 1_000
        || Date.parse(importedAt) < Date.parse(probedAt)
        || Date.parse(importedAt) >= Date.parse(expiresAt)) {
      throw semantic('isolation attestation chronology is invalid');
    }
    if (row.state === 'current') {
      if (current !== null || enrollment.state !== 'active'
          || enrollment.isolation !== 'pending_verification'
          || row.superseded_at !== null) {
        throw semantic('current isolation attestation is ambiguous or misbound');
      }
      let normalized;
      try {
        normalized = exactRecord(report, [
          'schemaVersion', 'enrollmentHash', 'kernelUid', 'kernelGid',
          'agentUid', 'agentGid', 'authorityMetadataHash', 'credentialMetadataHash',
          'releaseManifestHash', 'releaseTreeHash', 'nodeExecutableHash',
          'serviceArtifactsHash', 'systemdEffectiveConfigHash',
          'environmentMetadataHash', 'probeResults', 'probedAt', 'expiresAt',
        ], [], 'AUTHORITY_SEMANTIC_CORRUPTION', 'current isolation report');
      } catch (cause) {
        throw semantic('current isolation report shape is invalid', cause);
      }
      if (normalized.schemaVersion !== 1
          || normalized.enrollmentHash !== enrollment.enrollment_hash
          || normalized.agentUid !== enrollment.agent_uid
          || normalized.agentGid !== enrollment.agent_gid
          || !/^[1-9][0-9]*$/.test(normalized.kernelUid)
          || !/^[1-9][0-9]*$/.test(normalized.kernelGid)
          || normalized.kernelUid === normalized.agentUid
          || normalized.probedAt !== probedAt
          || normalized.expiresAt !== expiresAt
          || Date.parse(importedAt) > Date.parse(startupAt)) {
        throw semantic('current isolation report identity or time binding changed');
      }
      // "Current" identifies the latest imported report, not perpetual admission.
      // Expiry alone does not corrupt its history or prevent an Operator from
      // renewing it. Prelaunch and live admission independently enforce freshness.
      for (const name of [
        'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
        'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
        'systemdEffectiveConfigHash', 'environmentMetadataHash',
      ]) canonicalHash(normalized[name], `isolation report ${name}`);
      let probes;
      try {
        probes = exactRecord(
          normalized.probeResults,
          Object.keys(ENFORCED_ISOLATION_PROBES),
          [],
          'AUTHORITY_SEMANTIC_CORRUPTION',
          'isolation probe results',
        );
      } catch (cause) {
        throw semantic('isolation probe result shape is invalid', cause);
      }
      if (Object.entries(ENFORCED_ISOLATION_PROBES)
        .some(([name, result]) => probes[name] !== result)) {
        throw semantic('current isolation report does not prove enforced isolation');
      }
      current = row;
    } else if (row.state === 'superseded') {
      const supersededAt = safeTimestamp(row.superseded_at, 'isolation supersededAt');
      if (Date.parse(supersededAt) < Date.parse(importedAt)) {
        throw semantic('isolation supersession predates import');
      }
      const events = entityEvents(snapshot, 'isolation_attestation', row.id)
        .filter((event) => event.event_type === 'isolation.attestation_superseded');
      if (events.length !== 1) {
        throw semantic('isolation attestation supersession event is missing or ambiguous');
      }
      const event = exactSemantic(
        parseCanonical(events[0].data_json, 'isolation supersession event data'),
        ['enrollmentHash', 'reportHash', 'supersededAt', 'reasonCode'],
        [],
        'isolation.attestation_superseded event',
      );
      const replacementRows = snapshot.isolation_attestations.filter((candidate) => (
        candidate.id !== row.id
          && candidate.enrollment_hash === row.enrollment_hash
          && candidate.imported_at === supersededAt
          && candidate.report_hash !== row.report_hash
      ));
      const reasonIsBound = event.reasonCode === 'AGENT_REVOKED'
        ? enrollment.state === 'revoked' && enrollment.revoked_at === supersededAt
        : event.reasonCode === 'ATTESTATION_REPLACED' && replacementRows.length === 1;
      if (event.enrollmentHash !== row.enrollment_hash
          || event.reportHash !== row.report_hash
          || event.supersededAt !== supersededAt
          || !reasonIsBound
          || Date.parse(safeTimestamp(
            events[0].created_at,
            'isolation supersession event createdAt',
          )) < Date.parse(supersededAt)) {
        throw semantic('isolation attestation supersession binding changed');
      }
    } else {
      throw semantic('isolation attestation state is invalid');
    }
  }
  if (snapshot.events.some((event) => (
    event.entity_type === 'isolation_attestation' && !attestationIds.has(event.entity_id)
  ))) {
    throw semantic('orphan isolation attestation lifecycle event exists');
  }
}

function verifyApprovalHistory(snapshot) {
  const approvalsById = new Map();
  for (const row of snapshot.approvals) {
    safeToken(row.id, 'Approval ID');
    if (approvalsById.has(row.id)) throw semantic('Approval identity is ambiguous');
    approvalsById.set(row.id, row);
    canonicalHash(row.intent_hash, 'Approval intent hash');
    canonicalHash(row.challenge_hash, 'Approval challenge hash');
    canonicalHash(row.quote_id, 'Approval quote ID');
    canonicalAddress(row.wallet_address, 'Approval wallet');
    safeToken(row.policy_version_id, 'Approval PolicyVersion ID');
    canonicalAtomic(row.amount_ceiling_atomic, 'Approval amount ceiling');
    const acceptedIndex = number(row.accepted_index, 'Approval accepted index');
    if (acceptedIndex < 0) throw semantic('Approval accepted index is negative');
    const expiresAt = safeTimestamp(row.expires_at, 'Approval expiresAt');
    const decidedAt = row.decided_at === null
      ? null
      : safeTimestamp(row.decided_at, 'Approval decidedAt');
    const consumedAt = row.consumed_at === null
      ? null
      : safeTimestamp(row.consumed_at, 'Approval consumedAt');
    if (row.operator_id_hash !== null) {
      canonicalHash(row.operator_id_hash, 'Approval operator hash');
    }
    if (row.reason_code !== null) canonicalReason(row.reason_code, 'Approval reason');
    const lifecycleValid = (row.decision === 'pending'
        && row.operator_id_hash === null && row.reason_code === null
        && decidedAt === null && consumedAt === null)
      || (row.decision === 'approved'
        && row.operator_id_hash !== null && row.reason_code === null
        && decidedAt !== null && consumedAt === null)
      || (row.decision === 'denied'
        && row.operator_id_hash !== null && row.reason_code !== null
        && decidedAt !== null && consumedAt === null)
      || (row.decision === 'expired'
        && row.reason_code === 'APPROVAL_EXPIRED'
        && decidedAt !== null && consumedAt === null)
      || (row.decision === 'cancelled'
        && APPROVAL_CANCEL_REASONS.has(row.reason_code)
        && decidedAt !== null && consumedAt === null)
      || (row.decision === 'consumed'
        && row.operator_id_hash !== null && row.reason_code === null
        && decidedAt !== null && consumedAt !== null
        && Date.parse(consumedAt) >= Date.parse(decidedAt));
    if (!lifecycleValid) throw semantic('Approval row lifecycle is invalid');

    const events = entityEvents(snapshot, 'approval', row.id);
    const types = events.map((event) => event.event_type);
    let expectedTypes;
    if (row.decision === 'pending') expectedTypes = ['approval.requested'];
    else if (row.decision === 'approved') {
      expectedTypes = ['approval.requested', 'approval.approved'];
    } else if (row.decision === 'denied') {
      expectedTypes = ['approval.requested', 'approval.denied'];
    } else if (row.decision === 'consumed') {
      expectedTypes = ['approval.requested', 'approval.approved', 'approval.consumed'];
    } else {
      const priorApproved = events.some((event) => event.event_type === 'approval.approved');
      expectedTypes = [
        'approval.requested',
        ...(priorApproved ? ['approval.approved'] : []),
        `approval.${row.decision}`,
      ];
    }
    if (canonicalJson(types) !== canonicalJson(expectedTypes)) {
      throw semantic('Approval event lifecycle is missing, duplicated, or reordered');
    }
    let predecessorAt = null;
    for (const [index, event] of events.entries()) {
      const data = parseCanonical(event.data_json, 'Approval event data');
      let transitionAt;
      if (event.event_type === 'approval.requested') {
        const bound = exactSemantic(data, [
          'intentId', 'intentHash', 'challengeHash', 'quoteId', 'amountCeilingAtomic',
          'walletAddress', 'policyVersionId', 'acceptedIndex', 'expiresAt', 'requestedAt',
        ], [], 'approval.requested event');
        if (bound.intentId !== row.intent_id
            || bound.intentHash !== row.intent_hash
            || bound.challengeHash !== row.challenge_hash
            || bound.quoteId !== row.quote_id
            || bound.amountCeilingAtomic !== row.amount_ceiling_atomic
            || bound.walletAddress !== row.wallet_address
            || bound.policyVersionId !== row.policy_version_id
            || number(bound.acceptedIndex, 'approval event accepted index') !== acceptedIndex
            || bound.expiresAt !== expiresAt) {
          throw semantic('approval.requested event immutable binding changed');
        }
        transitionAt = safeTimestamp(bound.requestedAt, 'approval requestedAt');
        if (Date.parse(transitionAt) >= Date.parse(expiresAt)) {
          throw semantic('Approval was requested after immutable expiry');
        }
      } else if (event.event_type === 'approval.approved') {
        const bound = exactSemantic(data, [
          'intentId', 'intentHash', 'operatorIdHash', 'approvedAt',
        ], [], 'approval.approved event');
        if (bound.intentId !== row.intent_id || bound.intentHash !== row.intent_hash
            || bound.operatorIdHash !== row.operator_id_hash) {
          throw semantic('approval.approved event binding changed');
        }
        transitionAt = safeTimestamp(bound.approvedAt, 'approval approvedAt');
        if (row.decision === 'approved' || row.decision === 'consumed') {
          if (transitionAt !== decidedAt) throw semantic('Approval approvedAt changed');
        }
      } else if (event.event_type === 'approval.denied') {
        const bound = exactSemantic(data, [
          'intentId', 'intentHash', 'operatorIdHash', 'reasonCode', 'deniedAt',
        ], [], 'approval.denied event');
        if (bound.intentId !== row.intent_id || bound.intentHash !== row.intent_hash
            || bound.operatorIdHash !== row.operator_id_hash
            || bound.reasonCode !== row.reason_code) {
          throw semantic('approval.denied event binding changed');
        }
        transitionAt = safeTimestamp(bound.deniedAt, 'approval deniedAt');
      } else if (event.event_type === 'approval.consumed') {
        const bound = exactSemantic(data, [
          'intentId', 'intentHash', 'consumedAt',
        ], [], 'approval.consumed event');
        if (bound.intentId !== row.intent_id || bound.intentHash !== row.intent_hash) {
          throw semantic('approval.consumed event binding changed');
        }
        transitionAt = safeTimestamp(bound.consumedAt, 'approval consumedAt');
        if (transitionAt !== consumedAt) throw semantic('Approval consumedAt changed');
      } else {
        const timestampField = row.decision === 'expired' ? 'expiredAt' : 'cancelledAt';
        const bound = exactSemantic(data, [
          'intentId', 'intentHash', 'previousDecision', 'reasonCode', timestampField,
        ], [], `approval.${row.decision} event`);
        if (bound.intentId !== row.intent_id || bound.intentHash !== row.intent_hash
            || !OPEN_APPROVALS.has(bound.previousDecision)
            || bound.reasonCode !== row.reason_code) {
          throw semantic(`approval.${row.decision} event binding changed`);
        }
        transitionAt = safeTimestamp(bound[timestampField], `approval ${timestampField}`);
        if (transitionAt !== decidedAt) throw semantic('Approval terminal time changed');
      }
      const createdAt = safeTimestamp(event.created_at, 'Approval event createdAt');
      if (Date.parse(createdAt) < Date.parse(transitionAt)
          || (predecessorAt !== null
            && Date.parse(transitionAt) < Date.parse(predecessorAt))) {
        throw semantic('Approval event chronology regressed');
      }
      if (index === events.length - 1 && row.decision === 'expired'
          && Date.parse(transitionAt) < Date.parse(expiresAt)) {
        throw semantic('Approval expired before immutable expiry');
      }
      predecessorAt = transitionAt;
    }
  }
  const orphanEvents = snapshot.events.filter((event) => (
    event.entity_type === 'approval' && !approvalsById.has(event.entity_id)
  ));
  if (orphanEvents.length > 0) throw semantic('orphan Approval lifecycle event exists');
}

function verifyReceiptRows(snapshot, receipts) {
  for (const row of snapshot.signed_receipts) {
    let receipt;
    try { receipt = JSON.parse(row.receipt_json); } catch (cause) {
      throw semantic('signed receipt JSON is invalid', cause);
    }
    const record = {
      id: row.id,
      intentId: row.intent_id,
      revision: number(row.revision, 'signed receipt revision'),
      receipt,
      receiptHash: row.receipt_hash,
      signature: row.signature,
      algorithm: row.algorithm,
      keyId: row.key_id,
      supersedesReceiptHash: row.supersedes_receipt_hash,
      createdAt: row.created_at,
    };
    if (!receipts.verify(record)) throw semantic('signed receipt signature or schema is invalid');
  }
}

function reconciliationAuditAuthority(snapshot, policyAuthority, sessions, intentId) {
  const intent = snapshot.spend_intents.find((row) => row.id === intentId);
  if (!intent) throw semantic('reconciliation references a missing Spend Intent');
  const sessionAuthority = sessions.get(intent.session_id);
  const decision = snapshot.policy_decisions.find((row) => row.intent_id === intentId);
  const attempt = snapshot.payment_attempts.find((row) => row.intent_id === intentId);
  if (!sessionAuthority || !decision || !attempt) {
    throw semantic('reconciliation authority is incomplete');
  }
  const policyVersion = policyAuthority.policies.get(decision.policy_version_id);
  if (!policyVersion) throw semantic('reconciliation PolicyVersion is missing');
  const challenge = parseCanonical(intent.challenge_projection_json, 'reconciliation challenge');
  const acceptedIndex = number(decision.accepted_index, 'reconciliation accepted index');
  const selected = challenge.accepts?.[acceptedIndex];
  const seller = policyVersion.policy.sellers.find((candidate) => (
    candidate.origin === intent.seller_origin
      && candidate.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
  ));
  if (!selected || !seller || selected.payTo !== seller.payTo
      || selected.amount !== decision.amount_ceiling_atomic
      || selected.network !== policyVersion.policy.network
      || selected.asset !== policyVersion.policy.asset) {
    throw semantic('reconciliation selected payment authority changed');
  }
  return Object.freeze({
    intent,
    session: sessionAuthority.session,
    decision,
    attempt,
    policyVersion,
    selected,
    seller,
  });
}

function auditedExecutionCaseHash(snapshot, authority, reconciliationEvent) {
  const intentId = authority.intent.id;
  const preceding = (event) => event.sequence < reconciliationEvent.sequence;
  const recordedEvents = entityEvents(snapshot, 'execution_outcome', intentId)
    .filter((event) => event.event_type === 'execution.recorded' && preceding(event));
  const openedEvents = entityEvents(snapshot, 'execution_resolution', intentId)
    .filter((event) => event.event_type === 'execution_resolution.opened' && preceding(event));
  const outcomeEvents = entityEvents(snapshot, 'buyer_outcome', intentId)
    .filter((event) => new Set([
      'buyer_outcome.recorded', 'buyer_outcome.revised',
    ]).has(event.event_type) && preceding(event));
  if (recordedEvents.length !== 1 || openedEvents.length !== 1 || outcomeEvents.length < 1) {
    throw semantic('execution reconciliation predecessor history is incomplete or ambiguous');
  }
  const recorded = exactSemantic(parseCanonical(
    recordedEvents[0].data_json,
    'historical execution recorded event data',
  ), [
    'state', 'httpStatus', 'responseHash', 'metadataHash', 'reasonCode', 'recordedAt',
  ], [], 'historical execution.recorded event');
  const resolution = exactSemantic(parseCanonical(
    openedEvents[0].data_json,
    'historical execution resolution event data',
  ), [
    'intentId', 'state', 'reasonCode', 'blocksWallet', 'openedAt',
  ], [], 'historical execution_resolution.opened event');
  const buyerOutcome = exactSemantic(parseCanonical(
    outcomeEvents.at(-1).data_json,
    'historical BuyerOutcome event data',
  ), [
    'status', 'reasonCode', 'revision', 'recordedAt',
  ], [], 'historical BuyerOutcome event');
  const httpStatus = recorded.httpStatus === null
    ? null
    : number(recorded.httpStatus, 'historical execution HTTP status');
  if (recorded.state !== 'unknown'
      || (httpStatus !== null && (httpStatus < 100 || httpStatus > 599))
      || (recorded.responseHash !== null
        && canonicalHash(recorded.responseHash, 'historical execution response hash')
          !== recorded.responseHash)
      || canonicalHash(recorded.metadataHash, 'historical execution metadata hash')
        !== recorded.metadataHash
      || canonicalReason(recorded.reasonCode, 'historical execution reason')
        !== recorded.reasonCode
      || resolution.intentId !== intentId
      || resolution.state !== 'reconciliation_required'
      || resolution.reasonCode !== recorded.reasonCode
      || resolution.blocksWallet !== true
      || buyerOutcome.status !== 'execution_unknown') {
    throw semantic('execution reconciliation predecessor authority changed');
  }
  const recordedAt = safeTimestamp(recorded.recordedAt, 'historical execution recordedAt');
  const openedAt = safeTimestamp(resolution.openedAt, 'historical execution resolution openedAt');
  safeTimestamp(buyerOutcome.recordedAt, 'historical BuyerOutcome recordedAt');
  if (Date.parse(reconciliationEvent.created_at) < Date.parse(recordedAt)
      || Date.parse(reconciliationEvent.created_at) < Date.parse(openedAt)) {
    throw semantic('execution reconciliation predecessor chronology regressed');
  }
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.execution-reconciliation-case.v1',
    intentId,
    intentHash: authority.intent.intent_hash,
    transactionId: canonicalTransactionId(
      authority.attempt.transaction_id,
      'historical execution payment transaction',
    ),
    execution: {
      state: recorded.state,
      httpStatus,
      responseHash: recorded.responseHash,
      metadataHash: recorded.metadataHash,
      recordedAt,
    },
    resolution: {
      state: resolution.state,
      reasonCode: resolution.reasonCode,
      openedAt,
    },
    buyerOutcomeRevision: number(
      buyerOutcome.revision,
      'historical BuyerOutcome revision',
    ),
  }));
}

function verifyReconciliationHistory(snapshot, policyAuthority, sessions) {
  const histories = mapBy(snapshot.reconciliations, 'intent_id');
  const seenIds = new Set();
  for (const [intentId, rows] of histories) {
    const authority = reconciliationAuditAuthority(
      snapshot,
      policyAuthority,
      sessions,
      intentId,
    );
    let predecessorAt = null;
    for (const row of rows) {
      safeToken(row.id, 'reconciliation ID');
      if (seenIds.has(row.id)) throw semantic('reconciliation identity is ambiguous');
      seenIds.add(row.id);
      canonicalHash(row.operator_id_hash, 'reconciliation operator hash');
      const recordedAt = safeTimestamp(row.recorded_at, 'reconciliation recordedAt');
      if (predecessorAt !== null && Date.parse(recordedAt) < Date.parse(predecessorAt)) {
        throw semantic('reconciliation history chronology regressed');
      }
      predecessorAt = recordedAt;
      const evidence = parseCanonical(row.evidence_json, 'reconciliation evidence');
      const events = entityEvents(snapshot, 'reconciliation', row.id);
      if (events.length !== 1 || events[0].event_type !== 'reconciliation.recorded') {
        throw semantic('reconciliation event history is incomplete or ambiguous');
      }
      const event = events[0];
      const eventData = exactSemantic(parseCanonical(
        event.data_json,
        'reconciliation event data',
      ), [
        'intentId', 'kind', 'outcome', 'evidenceHash', 'operatorIdHash',
        'recordedAt', 'requestCaseHash', 'observedCaseHash',
      ], [], 'reconciliation.recorded event');
      if (eventData.intentId !== intentId
          || eventData.kind !== row.kind
          || eventData.outcome !== row.outcome
          || eventData.evidenceHash !== sha256(row.evidence_json)
          || eventData.operatorIdHash !== row.operator_id_hash
          || eventData.recordedAt !== recordedAt
          || Date.parse(event.created_at) < Date.parse(recordedAt)) {
        throw semantic('reconciliation event binding changed');
      }
      canonicalHash(eventData.requestCaseHash, 'reconciliation requested case hash');
      canonicalHash(eventData.observedCaseHash, 'reconciliation observed case hash');

      if (row.kind === 'payment' && row.outcome === 'settled') {
        const proof = exactSemantic(evidence, [
          'kind', 'transactionId', 'rpcProofHash', 'localAttemptHash',
        ], [], 'settled payment reconciliation evidence');
        canonicalTransactionId(proof.transactionId, 'settled payment evidence transaction');
        canonicalHash(proof.rpcProofHash, 'settled payment RPC proof hash');
        canonicalHash(proof.localAttemptHash, 'settled payment local binding hash');
        if (proof.kind !== 'settled_transfer'
            || authority.attempt.transaction_id !== proof.transactionId
            || proof.localAttemptHash !== localAttemptBindingHash(authority)) {
          throw semantic('settled payment reconciliation authority changed');
        }
        const candidate = snapshot.payment_reconciliation_candidates.find(
          (entry) => entry.intent_id === intentId
            && entry.transaction_id === proof.transactionId,
        );
        const persistedEvent = candidate
          ? entityEvents(snapshot, 'payment_reconciliation_candidate', candidate.id)
            .find((entry) => entry.event_type === 'payment.candidate_persisted')
          : null;
        if (!persistedEvent) throw semantic('settled payment candidate history is missing');
      } else if (row.kind === 'payment' && row.outcome === 'unresolved') {
        const proof = exactSemantic(evidence, [
          'kind', 'transactionId', 'reasonCode', 'rpcProofHash',
        ], [], 'rejected payment candidate evidence');
        canonicalTransactionId(proof.transactionId, 'rejected payment candidate transaction');
        canonicalHash(proof.rpcProofHash, 'rejected payment candidate RPC proof hash');
        if (proof.kind !== 'payment_candidate_rejected'
            || !new Set(['TRANSACTION_REVERTED', 'EXACT_TRANSFER_ABSENT'])
              .has(proof.reasonCode)) {
          throw semantic('rejected payment candidate evidence changed');
        }
        const candidate = snapshot.payment_reconciliation_candidates.find(
          (entry) => entry.intent_id === intentId
            && entry.transaction_id === proof.transactionId,
        );
        const persistedEvent = candidate
          ? entityEvents(snapshot, 'payment_reconciliation_candidate', candidate.id)
            .find((entry) => entry.event_type === 'payment.candidate_persisted')
          : null;
        if (!persistedEvent) throw semantic('rejected payment candidate history is missing');
      } else if (row.kind === 'payment' && row.outcome === 'rejected') {
        const proof = exactSemantic(evidence, [
          'kind', 'network', 'asset', 'payer', 'nonce', 'validBefore',
          'authorizationState', 'observedBlockNumber', 'observedBlockHash',
          'observedBlockTimestamp', 'confirmations',
        ], [], 'unused authorization reconciliation evidence');
        canonicalTransactionId(proof.nonce, 'unused authorization nonce');
        canonicalTransactionId(proof.observedBlockHash, 'unused authorization block hash');
        canonicalAtomic(proof.validBefore, 'unused authorization validBefore');
        canonicalAtomic(proof.observedBlockNumber, 'unused authorization block number');
        canonicalAtomic(proof.observedBlockTimestamp, 'unused authorization block timestamp');
        if (proof.kind !== 'authorization_unused_after_expiry'
            || proof.network !== authority.policyVersion.policy.network
            || proof.asset !== authority.policyVersion.policy.asset
            || proof.payer !== authority.session.wallet_address
            || proof.nonce !== authority.attempt.nonce
            || proof.validBefore !== authority.attempt.valid_before
            || proof.authorizationState !== false
            || !Number.isSafeInteger(proof.confirmations)
            || proof.confirmations < 1) {
          throw semantic('unused authorization reconciliation authority changed');
        }
        if (eventData.requestCaseHash !== eventData.observedCaseHash) {
          throw semantic('unused authorization reconciliation case binding changed');
        }
      } else if (row.kind === 'execution'
          && new Set(['execution_succeeded', 'execution_failed']).has(row.outcome)) {
        const proof = exactSemantic(evidence, [
          'kind', 'attestationHash', 'attestation',
        ], [], 'execution reconciliation evidence');
        const attestation = exactSemantic(proof.attestation, [
          'schemaVersion', 'domain', 'network', 'sellerOrigin', 'intentHash',
          'transactionId', 'outcome', 'httpStatus', 'responseHash', 'issuedAt',
          'expiresAt', 'signer',
        ], [], 'execution reconciliation attestation');
        const issuedAt = safeTimestamp(attestation.issuedAt, 'execution attestation issuedAt');
        const expiresAt = safeTimestamp(attestation.expiresAt, 'execution attestation expiresAt');
        const expectedState = row.outcome === 'execution_succeeded' ? 'succeeded' : 'failed';
        const execution = snapshot.execution_outcomes.find(
          (candidate) => candidate.intent_id === intentId,
        );
        const metadata = execution
          ? parseCanonical(execution.metadata_json, 'execution reconciliation metadata')
          : null;
        if (proof.kind !== 'execution_attested'
            || canonicalHash(proof.attestationHash, 'execution attestation hash')
              !== sha256(canonicalJson(attestation))
            || attestation.schemaVersion !== 1
            || attestation.domain !== 'wallet-kernel.execution.v1'
            || attestation.network !== authority.policyVersion.policy.network
            || attestation.sellerOrigin !== authority.intent.seller_origin
            || attestation.intentHash !== authority.intent.intent_hash
            || attestation.transactionId !== authority.attempt.transaction_id
            || attestation.outcome !== expectedState
            || attestation.signer !== authority.seller.executionSigner
            || Date.parse(recordedAt) < Date.parse(issuedAt)
            || Date.parse(recordedAt) >= Date.parse(expiresAt)
            || Date.parse(expiresAt) - Date.parse(issuedAt) > 15 * 60 * 1_000
            || execution?.state !== expectedState
            || number(execution.http_status, 'execution reconciliation HTTP status')
              !== attestation.httpStatus
            || execution.response_hash !== attestation.responseHash
            || execution.recorded_at !== recordedAt
            || metadata?.attestationHash !== proof.attestationHash) {
          throw semantic('execution reconciliation attestation authority changed');
        }
        const expectedCaseHash = auditedExecutionCaseHash(snapshot, authority, event);
        if (eventData.requestCaseHash !== expectedCaseHash
            || eventData.observedCaseHash !== expectedCaseHash) {
          throw semantic('execution reconciliation case binding changed');
        }
      } else if (row.kind === 'refund' && row.outcome === 'refund_rejected') {
        const proof = exactSemantic(evidence, [
          'kind', 'refundTransactionId', 'reasonCode', 'rpcProofHash',
        ], [], 'rejected refund candidate evidence');
        canonicalTransactionId(proof.refundTransactionId, 'rejected refund transaction');
        canonicalHash(proof.rpcProofHash, 'rejected refund RPC proof hash');
        if (proof.kind !== 'refund_candidate_rejected'
            || !new Set(['TRANSACTION_REVERTED', 'EXACT_TRANSFER_ABSENT'])
              .has(proof.reasonCode)) {
          throw semantic('rejected refund candidate evidence changed');
        }
        const refund = snapshot.refunds.find((entry) => (
          entry.intent_id === intentId
            && entry.refund_transaction_id === proof.refundTransactionId
        ));
        const persistedEvent = refund
          ? entityEvents(snapshot, 'refund', refund.id)
            .find((entry) => entry.event_type === 'refund.candidate_persisted')
          : null;
        if (!persistedEvent) throw semantic('rejected refund candidate history is missing');
      } else if (row.kind === 'refund' && row.outcome === 'refund_confirmed') {
        const proof = exactSemantic(evidence, [
          'kind', 'originalTransactionId', 'refundTransactionId', 'attestationHash',
          'attestation', 'rpcProofHash', 'localRefundBindingHash',
        ], [], 'confirmed refund reconciliation evidence');
        const attestation = exactSemantic(proof.attestation, [
          'schemaVersion', 'domain', 'network', 'sellerOrigin', 'intentHash',
          'originalTransactionId', 'refundTransactionId', 'asset', 'originalPayer',
          'originalPayee', 'refundSource', 'amountAtomic', 'issuedAt', 'expiresAt', 'signer',
        ], [], 'confirmed refund attestation');
        const issuedAt = safeTimestamp(attestation.issuedAt, 'refund attestation issuedAt');
        const expiresAt = safeTimestamp(attestation.expiresAt, 'refund attestation expiresAt');
        canonicalHash(proof.rpcProofHash, 'confirmed refund RPC proof hash');
        canonicalTransactionId(proof.refundTransactionId, 'confirmed refund transaction');
        if (proof.kind !== 'refund_attested_and_confirmed'
            || canonicalHash(proof.attestationHash, 'refund attestation hash')
              !== sha256(canonicalJson(attestation))
            || attestation.schemaVersion !== 1
            || attestation.domain !== 'wallet-kernel.refund.v1'
            || attestation.network !== authority.policyVersion.policy.network
            || attestation.sellerOrigin !== authority.intent.seller_origin
            || attestation.intentHash !== authority.intent.intent_hash
            || attestation.originalTransactionId !== authority.attempt.transaction_id
            || attestation.refundTransactionId !== proof.refundTransactionId
            || attestation.asset !== authority.policyVersion.policy.asset
            || attestation.originalPayer !== authority.session.wallet_address
            || attestation.originalPayee !== authority.selected.payTo
            || attestation.refundSource !== authority.seller.refundSource
            || attestation.amountAtomic !== authority.decision.amount_ceiling_atomic
            || attestation.signer !== authority.seller.refundSigner
            || Date.parse(recordedAt) < Date.parse(issuedAt)
            || Date.parse(recordedAt) >= Date.parse(expiresAt)
            || Date.parse(expiresAt) - Date.parse(issuedAt) > 15 * 60 * 1_000
            || proof.localRefundBindingHash
              !== localRefundBindingHash(authority, proof.refundTransactionId)) {
          throw semantic('confirmed refund reconciliation authority changed');
        }
        const refund = snapshot.refunds.find((entry) => (
          entry.intent_id === intentId
            && entry.refund_transaction_id === proof.refundTransactionId
        ));
        const persistedEvent = refund
          ? entityEvents(snapshot, 'refund', refund.id)
            .find((entry) => entry.event_type === 'refund.candidate_persisted')
          : null;
        if (!persistedEvent) throw semantic('confirmed refund candidate history is missing');
      } else {
        throw semantic('reconciliation kind and outcome pair is unsupported');
      }
    }
  }
  const orphanEvents = snapshot.events.filter((event) => (
    event.entity_type === 'reconciliation' && !seenIds.has(event.entity_id)
  ));
  if (orphanEvents.length > 0) throw semantic('orphan reconciliation event exists');
  return histories;
}

function auditedPaymentCaseHash(intent, buyerOutcomeRevision, rows) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-reconciliation-case.v1',
    intentId: intent.id,
    intentHash: intent.intent_hash,
    attemptState: 'unresolved',
    budgetState: 'unresolved',
    buyerOutcomeRevision,
    history: rows.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      state: row.state,
      evidenceHash: row.evidence_json === null ? null : sha256(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function auditedRefundCaseHash(intent, attempt, buyerOutcomeRevision, rows) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation-case.v1',
    intentId: intent.id,
    intentHash: intent.intent_hash,
    originalTransactionId: attempt.transaction_id,
    executionState: 'failed',
    resolutionState: 'refund_pending',
    buyerOutcomeRevision,
    history: rows.map((row) => ({
      id: row.id,
      originalTransactionId: row.original_transaction_id,
      amountAtomic: row.amount_atomic,
      state: row.state,
      refundTransactionId: row.refund_transaction_id,
      evidenceHash: row.evidence_json === null ? null : sha256(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function verifyCandidateHistory(snapshot, reconciliationHistories) {
  const paymentByIntent = mapBy(snapshot.payment_reconciliation_candidates, 'intent_id');
  const refundByIntent = mapBy(snapshot.refunds, 'intent_id');
  const attemptsByIntent = mapBy(snapshot.payment_attempts, 'intent_id');
  const attemptOwnerByTransaction = new Map();
  const globallyUsed = new Map();
  const rememberTransaction = (transactionId, owner) => {
    const previous = globallyUsed.get(transactionId);
    if (previous && previous !== owner) throw semantic('transaction ID is reused across authority rows');
    globallyUsed.set(transactionId, owner);
  };
  for (const attempt of snapshot.payment_attempts) {
    if (attempt.transaction_id !== null) {
      const transactionId = canonicalTransactionId(
        attempt.transaction_id,
        'payment transaction ID',
      );
      rememberTransaction(
        transactionId,
        `payment:${attempt.intent_id}`,
      );
      attemptOwnerByTransaction.set(transactionId, attempt.intent_id);
    }
  }
  for (const [intentId, rows] of paymentByIntent) {
    const intent = snapshot.spend_intents.find((entry) => entry.id === intentId);
    if (!intent) throw semantic('payment candidate references a missing Spend Intent');
    let open = 0;
    let predecessorUpdatedAt = null;
    let historicalRevision = 1;
    const historicalRows = [];
    for (const row of rows) {
      safeToken(row.id, 'payment candidate ID');
      const transactionId = canonicalTransactionId(row.transaction_id, 'payment candidate transaction');
      const attempt = one(attemptsByIntent, intentId, 'PaymentAttempt');
      const exactConfirmedSettlement = row.state === 'confirmed'
        && attempt?.state === 'settled'
        && attempt.transaction_id === transactionId
        && attemptOwnerByTransaction.get(transactionId) === intentId;
      if (!exactConfirmedSettlement) {
        rememberTransaction(transactionId, `payment-candidate:${row.id}`);
      }
      if (row.state === 'pending') open += 1;
      if (!new Set(['pending', 'abandoned', 'rejected', 'confirmed']).has(row.state)) {
        throw semantic('payment candidate state is invalid');
      }
      if (row.state === 'confirmed' && !exactConfirmedSettlement) {
        throw semantic('confirmed payment candidate does not own its exact settlement');
      }
      const evidence = row.evidence_json === null
        ? null
        : parseCanonical(row.evidence_json, 'payment candidate evidence');
      if ((row.state === 'pending' || row.state === 'abandoned') && evidence !== null) {
        throw semantic('open or abandoned payment candidate contains resolution evidence');
      }
      if ((row.state === 'rejected' || row.state === 'confirmed') && evidence === null) {
        throw semantic('resolved payment candidate lacks exact evidence');
      }
      const matchingReconciliations = (reconciliationHistories.get(intentId) ?? [])
        .filter((reconciliation) => reconciliation.evidence_json === row.evidence_json);
      if (row.state === 'confirmed'
          && (matchingReconciliations.length !== 1
            || matchingReconciliations[0].kind !== 'payment'
            || matchingReconciliations[0].outcome !== 'settled')) {
        throw semantic('confirmed payment candidate lost its exact reconciliation');
      }
      if (row.state === 'rejected'
          && (matchingReconciliations.length !== 1
            || matchingReconciliations[0].kind !== 'payment'
            || !new Set(['unresolved', 'rejected']).has(matchingReconciliations[0].outcome))) {
        throw semantic('rejected payment candidate lost its exact reconciliation');
      }
      const createdAt = safeTimestamp(row.created_at, 'payment candidate createdAt');
      const updatedAt = safeTimestamp(row.updated_at, 'payment candidate updatedAt');
      if (Date.parse(updatedAt) < Date.parse(createdAt)
          || (predecessorUpdatedAt !== null
            && Date.parse(createdAt) < Date.parse(predecessorUpdatedAt))) {
        throw semantic('payment candidate chronology regressed');
      }
      predecessorUpdatedAt = updatedAt;
      const previousCaseHash = auditedPaymentCaseHash(
        intent,
        historicalRevision,
        historicalRows,
      );
      const pendingProjection = Object.freeze({
        ...row,
        state: 'pending',
        evidence_json: null,
        updated_at: createdAt,
      });
      const observedCaseHash = auditedPaymentCaseHash(
        intent,
        historicalRevision,
        [...historicalRows, pendingProjection],
      );
      const events = entityEvents(snapshot, 'payment_reconciliation_candidate', row.id);
      const expectedTypes = [
        'payment.candidate_persisted',
        ...(row.state === 'abandoned' ? ['payment.candidate_abandoned'] : []),
        ...(row.state === 'rejected' ? ['payment.candidate_rejected'] : []),
        ...(row.state === 'confirmed' ? ['payment.candidate_confirmed'] : []),
      ];
      if (canonicalJson(events.map((event) => event.event_type)) !== canonicalJson(expectedTypes)) {
        throw semantic('payment candidate event lifecycle is incomplete or ambiguous');
      }
      const persisted = exactSemantic(parseCanonical(
        events[0].data_json,
        'payment candidate persisted event data',
      ), [
        'intentId', 'transactionId', 'operatorIdHash', 'previousCaseHash', 'createdAt',
      ], [], 'payment candidate persisted event');
      if (persisted.intentId !== intentId
          || persisted.transactionId !== transactionId
          || persisted.createdAt !== createdAt) {
        throw semantic('payment candidate persisted event binding changed');
      }
      canonicalHash(persisted.operatorIdHash, 'payment candidate operator hash');
      if (canonicalHash(persisted.previousCaseHash, 'payment candidate previous case hash')
          !== previousCaseHash) {
        throw semantic('payment candidate predecessor case hash changed');
      }
      if (row.state === 'abandoned') {
        const abandoned = exactSemantic(parseCanonical(
          events[1].data_json,
          'payment candidate abandonment event data',
        ), [
          'intentId', 'transactionId', 'operatorIdHash', 'previousCaseHash', 'abandonedAt',
        ], [], 'payment candidate abandonment event');
        if (abandoned.intentId !== intentId || abandoned.transactionId !== transactionId
            || abandoned.previousCaseHash !== observedCaseHash
            || abandoned.abandonedAt !== updatedAt) {
          throw semantic('payment candidate abandonment event binding changed');
        }
      } else if (row.state === 'rejected') {
        const rejected = exactSemantic(parseCanonical(
          events[1].data_json,
          'payment candidate rejection event data',
        ), [
          'intentId', 'transactionId', 'evidenceHash', 'operatorIdHash', 'rejectedAt',
        ], [], 'payment candidate rejection event');
        if (rejected.intentId !== intentId || rejected.transactionId !== transactionId
            || rejected.evidenceHash !== sha256(row.evidence_json)
            || rejected.rejectedAt !== updatedAt) {
          throw semantic('payment candidate rejection event binding changed');
        }
      } else if (row.state === 'confirmed') {
        const confirmed = exactSemantic(parseCanonical(
          events[1].data_json,
          'payment candidate confirmation event data',
        ), [
          'intentId', 'transactionId', 'evidenceHash', 'operatorIdHash', 'confirmedAt',
        ], [], 'payment candidate confirmation event');
        if (confirmed.intentId !== intentId || confirmed.transactionId !== transactionId
            || confirmed.evidenceHash !== sha256(row.evidence_json)
            || confirmed.confirmedAt !== updatedAt) {
          throw semantic('payment candidate confirmation event binding changed');
        }
      }
      if (matchingReconciliations.length === 1) {
        const reconciliation = matchingReconciliations[0];
        const reconciliationEvent = entityEvents(
          snapshot,
          'reconciliation',
          reconciliation.id,
        )[0];
        const eventData = parseCanonical(
          reconciliationEvent.data_json,
          'payment candidate reconciliation event data',
        );
        if (eventData.observedCaseHash !== observedCaseHash
            || !new Set([previousCaseHash, observedCaseHash]).has(eventData.requestCaseHash)) {
          throw semantic('payment candidate reconciliation case hash changed');
        }
        historicalRevision += 1;
      }
      historicalRows.push(row);
    }
    if (open > 1) throw semantic(`payment candidate history for ${intentId} is ambiguous`);
  }
  for (const [intentId, rows] of refundByIntent) {
    const intent = snapshot.spend_intents.find((entry) => entry.id === intentId);
    const attempt = one(attemptsByIntent, intentId, 'PaymentAttempt');
    const outcome = snapshot.buyer_outcomes.find((entry) => entry.intent_id === intentId);
    if (!intent || !attempt || !outcome) {
      throw semantic('refund history references incomplete authority');
    }
    const resolvedRefundCount = rows.filter(
      (row) => row.state === 'confirmed' || row.state === 'rejected',
    ).length;
    let historicalRevision = number(outcome.revision, 'refund BuyerOutcome revision')
      - resolvedRefundCount;
    if (historicalRevision < 1) throw semantic('refund history revision underflowed');
    const historicalRows = [];
    let open = 0;
    let predecessorUpdatedAt = null;
    for (const row of rows) {
      safeToken(row.id, 'refund candidate ID');
      canonicalTransactionId(row.original_transaction_id, 'refund original transaction');
      if (row.refund_transaction_id !== null) {
        rememberTransaction(
          canonicalTransactionId(row.refund_transaction_id, 'refund transaction'),
          `refund:${row.id}`,
        );
      }
      if (row.state === 'pending' || row.state === 'unresolved') open += 1;
      const evidence = row.evidence_json === null
        ? null
        : parseCanonical(row.evidence_json, 'refund evidence');
      if (new Set(['pending', 'unresolved', 'abandoned']).has(row.state)
          && evidence !== null) {
        throw semantic('open or abandoned refund contains resolution evidence');
      }
      if (new Set(['confirmed', 'rejected']).has(row.state) && evidence === null) {
        throw semantic('resolved refund lacks exact evidence');
      }
      if ((row.state === 'confirmed' || row.state === 'rejected')
          && row.refund_transaction_id === null) {
        throw semantic('resolved refund lacks a named transaction');
      }
      const matchingReconciliations = (reconciliationHistories.get(intentId) ?? [])
        .filter((reconciliation) => reconciliation.evidence_json === row.evidence_json);
      const expectedOutcome = row.state === 'confirmed'
        ? 'refund_confirmed'
        : (row.state === 'rejected' ? 'refund_rejected' : null);
      if (expectedOutcome !== null
          && (matchingReconciliations.length !== 1
            || matchingReconciliations[0].kind !== 'refund'
            || matchingReconciliations[0].outcome !== expectedOutcome)) {
        throw semantic('resolved refund lost its exact reconciliation');
      }
      const createdAt = safeTimestamp(row.created_at, 'refund createdAt');
      const updatedAt = safeTimestamp(row.updated_at, 'refund updatedAt');
      if (Date.parse(updatedAt) < Date.parse(createdAt)
          || (predecessorUpdatedAt !== null
            && Date.parse(createdAt) < Date.parse(predecessorUpdatedAt))) {
        throw semantic('refund chronology regressed');
      }
      predecessorUpdatedAt = updatedAt;
      const events = entityEvents(snapshot, 'refund', row.id);
      const opened = events.filter((event) => event.event_type === 'refund.opened');
      if (opened.length !== 1) throw semantic('refund opening event is incomplete or ambiguous');
      const openedData = exactSemantic(parseCanonical(
        opened[0].data_json,
        'refund opened event data',
      ), [
        'refundId', 'intentId', 'originalTransactionId', 'amountAtomic', 'state', 'createdAt',
      ], [], 'refund.opened event');
      if (openedData.refundId !== row.id || openedData.intentId !== intentId
          || openedData.originalTransactionId !== row.original_transaction_id
          || openedData.amountAtomic !== row.amount_atomic
          || openedData.state !== 'pending' || openedData.createdAt !== createdAt) {
        throw semantic('refund opening event binding changed');
      }
      let observedCaseHash = null;
      if (row.refund_transaction_id !== null) {
        const persisted = events.filter(
          (event) => event.event_type === 'refund.candidate_persisted',
        );
        if (persisted.length !== 1) {
          throw semantic('named refund candidate lacks one persistence event');
        }
        const persistedData = exactSemantic(parseCanonical(
          persisted[0].data_json,
          'refund candidate persistence event data',
        ), [
          'intentId', 'originalTransactionId', 'refundTransactionId', 'operatorIdHash',
          'previousCaseHash', 'recordedAt',
        ], [], 'refund.candidate_persisted event');
        if (persistedData.intentId !== intentId
            || persistedData.originalTransactionId !== row.original_transaction_id
            || persistedData.refundTransactionId !== row.refund_transaction_id
            || Date.parse(safeTimestamp(
              persistedData.recordedAt,
              'refund candidate persistedAt',
            )) < Date.parse(createdAt)
            || Date.parse(persistedData.recordedAt) > Date.parse(updatedAt)
            || (row.state === 'pending' && persistedData.recordedAt !== updatedAt)) {
          throw semantic('refund candidate persistence event binding changed');
        }
        canonicalHash(persistedData.operatorIdHash, 'refund candidate operator hash');
        const caseWithoutRow = auditedRefundCaseHash(
          intent,
          attempt,
          historicalRevision,
          historicalRows,
        );
        const unnamedProjection = Object.freeze({
          ...row,
          state: 'pending',
          evidence_json: null,
          refund_transaction_id: null,
          updated_at: createdAt,
        });
        const caseWithUnnamedRow = auditedRefundCaseHash(
          intent,
          attempt,
          historicalRevision,
          [...historicalRows, unnamedProjection],
        );
        if (!new Set([caseWithoutRow, caseWithUnnamedRow]).has(canonicalHash(
          persistedData.previousCaseHash,
          'refund candidate previous case hash',
        ))) {
          throw semantic('refund candidate predecessor case hash changed');
        }
        const namedProjection = Object.freeze({
          ...row,
          state: 'pending',
          evidence_json: null,
          updated_at: persistedData.recordedAt,
        });
        observedCaseHash = auditedRefundCaseHash(
          intent,
          attempt,
          historicalRevision,
          [...historicalRows, namedProjection],
        );
      }
      const terminalType = row.state === 'abandoned'
        ? 'refund.candidate_abandoned'
        : (row.state === 'rejected'
          ? 'refund.candidate_rejected'
          : (row.state === 'confirmed' ? 'refund.confirmed' : null));
      if (terminalType !== null
          && events.filter((event) => event.event_type === terminalType).length !== 1) {
        throw semantic('refund candidate terminal event is incomplete or ambiguous');
      }
      if (terminalType === 'refund.candidate_abandoned') {
        const terminal = exactSemantic(parseCanonical(
          events.find((event) => event.event_type === terminalType).data_json,
          'refund abandonment event data',
        ), [
          'intentId', 'refundTransactionId', 'operatorIdHash', 'previousCaseHash', 'abandonedAt',
        ], [], 'refund.candidate_abandoned event');
        if (terminal.intentId !== intentId
            || terminal.refundTransactionId !== row.refund_transaction_id
            || terminal.previousCaseHash !== observedCaseHash
            || terminal.abandonedAt !== updatedAt) {
          throw semantic('refund abandonment event binding changed');
        }
      } else if (terminalType === 'refund.candidate_rejected') {
        const terminal = exactSemantic(parseCanonical(
          events.find((event) => event.event_type === terminalType).data_json,
          'refund rejection event data',
        ), [
          'intentId', 'refundTransactionId', 'evidenceHash', 'operatorIdHash', 'rejectedAt',
        ], [], 'refund.candidate_rejected event');
        if (terminal.intentId !== intentId
            || terminal.refundTransactionId !== row.refund_transaction_id
            || terminal.evidenceHash !== sha256(row.evidence_json)
            || terminal.rejectedAt !== updatedAt) {
          throw semantic('refund rejection event binding changed');
        }
      } else if (terminalType === 'refund.confirmed') {
        const terminal = exactSemantic(parseCanonical(
          events.find((event) => event.event_type === terminalType).data_json,
          'refund confirmation event data',
        ), [
          'refundId', 'intentId', 'originalTransactionId', 'refundTransactionId',
          'amountAtomic', 'evidenceId', 'confirmedAt',
        ], [], 'refund.confirmed event');
        if (terminal.refundId !== row.id || terminal.intentId !== intentId
            || terminal.originalTransactionId !== row.original_transaction_id
            || terminal.refundTransactionId !== row.refund_transaction_id
            || terminal.amountAtomic !== row.amount_atomic
            || terminal.confirmedAt !== updatedAt) {
          throw semantic('refund confirmation event binding changed');
        }
        safeToken(terminal.evidenceId, 'refund confirmation evidence ID');
      }
      if (matchingReconciliations.length === 1) {
        const reconciliation = matchingReconciliations[0];
        const reconciliationEvent = entityEvents(
          snapshot,
          'reconciliation',
          reconciliation.id,
        )[0];
        const eventData = parseCanonical(
          reconciliationEvent.data_json,
          'refund candidate reconciliation event data',
        );
        if (observedCaseHash === null
            || eventData.observedCaseHash !== observedCaseHash
            || !new Set([
              observedCaseHash,
              parseCanonical(
                events.find((event) => event.event_type === 'refund.candidate_persisted')
                  .data_json,
                'refund candidate case event data',
              ).previousCaseHash,
            ]).has(eventData.requestCaseHash)) {
          throw semantic('refund candidate reconciliation case hash changed');
        }
        historicalRevision += 1;
      }
      historicalRows.push(row);
    }
    if (open > 1) throw semantic(`refund candidate history for ${intentId} is ambiguous`);
  }
}

function verifyOutcomeAndExecutionEvents(snapshot) {
  for (const outcome of snapshot.buyer_outcomes) {
    const revision = number(outcome.revision, 'BuyerOutcome revision');
    const events = entityEvents(snapshot, 'buyer_outcome', outcome.intent_id)
      .filter((event) => new Set([
        'buyer_outcome.recorded', 'buyer_outcome.revised',
      ]).has(event.event_type));
    if (events.length !== revision) {
      throw semantic('BuyerOutcome event revision history is incomplete or ambiguous');
    }
    for (const [index, event] of events.entries()) {
      const data = exactSemantic(parseCanonical(
        event.data_json,
        'BuyerOutcome event data',
      ), ['status', 'reasonCode', 'revision', 'recordedAt'], [], 'buyer_outcome.recorded event');
      const expectedEventType = index === 0
        ? 'buyer_outcome.recorded'
        : 'buyer_outcome.revised';
      if (event.event_type !== expectedEventType
          || number(data.revision, 'BuyerOutcome event revision') !== index + 1) {
        throw semantic('BuyerOutcome event revisions are not contiguous');
      }
      safeTimestamp(data.recordedAt, 'BuyerOutcome event recordedAt');
      if (Date.parse(event.created_at) < Date.parse(data.recordedAt)) {
        throw semantic('BuyerOutcome event predates its recorded fact');
      }
      if (index === events.length - 1
          && (data.status !== outcome.status
            || data.reasonCode !== outcome.reason_code
            || data.recordedAt !== outcome.recorded_at)) {
        throw semantic('current BuyerOutcome event projection changed');
      }
    }
  }

  for (const execution of snapshot.execution_outcomes) {
    const executionEvents = entityEvents(snapshot, 'execution_outcome', execution.intent_id);
    const recordedEvents = executionEvents
      .filter((event) => event.event_type === 'execution.recorded');
    const reconciledEvents = executionEvents
      .filter((event) => event.event_type === 'execution.reconciled');
    if (recordedEvents.length !== 1 || reconciledEvents.length > 1
        || executionEvents.length !== recordedEvents.length + reconciledEvents.length) {
      throw semantic('execution event lifecycle is incomplete or ambiguous');
    }
    const recordedData = exactSemantic(parseCanonical(
      recordedEvents[0].data_json,
      'execution recorded event data',
    ), [
      'state', 'httpStatus', 'responseHash', 'metadataHash', 'reasonCode', 'recordedAt',
    ], [], 'execution.recorded event');
    canonicalHash(recordedData.metadataHash, 'execution recorded metadata hash');
    canonicalReason(recordedData.reasonCode, 'execution recorded reason');
    const historicalRecordedAt = safeTimestamp(
      recordedData.recordedAt,
      'execution recorded event recordedAt',
    );
    if (Date.parse(recordedEvents[0].created_at) < Date.parse(historicalRecordedAt)) {
      throw semantic('execution recorded event predates its recorded fact');
    }
    const currentEvent = reconciledEvents[0] ?? recordedEvents[0];
    const data = exactSemantic(parseCanonical(
      currentEvent.data_json,
      'execution event data',
    ), reconciledEvents.length === 1
      ? [
        'state', 'httpStatus', 'responseHash', 'metadataHash', 'attestationHash',
        'reasonCode', 'recordedAt',
      ]
      : [
        'state', 'httpStatus', 'responseHash', 'metadataHash', 'reasonCode', 'recordedAt',
      ], [],
    reconciledEvents.length === 1 ? 'execution.reconciled event' : 'execution.recorded event');
    const metadata = parseCanonical(execution.metadata_json, 'current execution metadata');
    const recordedAt = safeTimestamp(data.recordedAt, 'current execution event recordedAt');
    if (data.state !== execution.state
        || data.httpStatus !== (execution.http_status === null
          ? null
          : number(execution.http_status, 'execution event HTTP status'))
        || data.responseHash !== execution.response_hash
        || data.metadataHash !== sha256(execution.metadata_json)
        || data.reasonCode !== metadata.reasonCode
        || recordedAt !== execution.recorded_at
        || Date.parse(currentEvent.created_at) < Date.parse(recordedAt)
        || (reconciledEvents.length === 1
          && reconciledEvents[0].sequence <= recordedEvents[0].sequence)) {
      throw semantic('current execution event projection changed');
    }
    canonicalHash(data.metadataHash, 'current execution metadata hash');
    canonicalReason(data.reasonCode, 'current execution reason');
    if (Object.hasOwn(data, 'attestationHash')) {
      canonicalHash(data.attestationHash, 'execution event attestation hash');
    }
  }

  for (const resolution of snapshot.execution_resolutions) {
    const events = entityEvents(snapshot, 'execution_resolution', resolution.intent_id);
    const opened = events.filter((event) => event.event_type === 'execution_resolution.opened');
    const resolved = events.filter((event) => event.event_type === 'execution_resolution.resolved');
    if (opened.length < 1 || opened.length > 2 || resolved.length > 1) {
      throw semantic('execution resolution event lifecycle is incomplete or ambiguous');
    }
    const currentOpen = opened.at(-1);
    const openData = exactSemantic(parseCanonical(
      currentOpen.data_json,
      'execution resolution opened event data',
    ), [
      'intentId', 'state', 'reasonCode', 'blocksWallet', 'openedAt',
    ], [], 'execution_resolution.opened event');
    if (openData.intentId !== resolution.intent_id
        || openData.openedAt !== resolution.opened_at
        || openData.blocksWallet !== true) {
      throw semantic('execution resolution opening event binding changed');
    }
    if (resolution.state === 'resolved') {
      if (resolved.length !== 1) {
        throw semantic('resolved execution case lacks one resolution event');
      }
      const resolvedData = exactSemantic(parseCanonical(
        resolved[0].data_json,
        'execution resolution resolved event data',
      ), [
        'intentId', 'state', 'reasonCode', 'blocksWallet', 'resolvedAt',
      ], [], 'execution_resolution.resolved event');
      if (resolvedData.intentId !== resolution.intent_id
          || resolvedData.state !== 'resolved'
          || resolvedData.reasonCode !== resolution.reason_code
          || resolvedData.blocksWallet !== false
          || resolvedData.resolvedAt !== resolution.resolved_at) {
        throw semantic('execution resolution terminal event projection changed');
      }
    } else if (resolved.length !== 0
        || openData.state !== resolution.state
        || openData.reasonCode !== resolution.reason_code) {
      throw semantic('open execution resolution event projection changed');
    }
  }
}

function verifyIntentAndDecisionHistory(snapshot, sessions, policyAuthority) {
  const decisionsByIntent = mapBy(snapshot.policy_decisions, 'intent_id');
  const intentsById = new Map();
  for (const intent of snapshot.spend_intents) {
    safeToken(intent.id, 'Spend Intent ID');
    safeToken(intent.request_id, 'Spend Intent request ID');
    safeToken(intent.route_id, 'Spend Intent route ID');
    safeToken(intent.purpose_label, 'Spend Intent purpose label');
    safeToken(intent.correlation_id, 'Spend Intent correlation ID');
    canonicalHash(intent.enrollment_hash, 'Spend Intent enrollment hash');
    canonicalHash(intent.request_url_hash, 'Spend Intent request URL hash');
    canonicalHash(intent.body_hash, 'Spend Intent body hash');
    canonicalHash(intent.header_allowlist_hash, 'Spend Intent header allowlist hash');
    canonicalHash(intent.ordinary_fingerprint, 'Spend Intent ordinary fingerprint');
    canonicalHash(intent.intent_hash, 'Spend Intent hash');
    canonicalAddress(intent.wallet_address, 'Spend Intent wallet');
    if (!/^[A-Z]+$/.test(intent.method)
        || typeof intent.seller_origin !== 'string'
        || new URL(intent.seller_origin).origin !== intent.seller_origin
        || typeof intent.resource_path !== 'string'
        || !intent.resource_path.startsWith('/')
        || !/^wk_[0-9a-f]{64}$/.test(intent.idempotency_key)) {
      throw semantic('Spend Intent immutable request fields are invalid');
    }
    const authority = sessions.get(intent.session_id);
    if (!authority) throw semantic('Spend Intent session is missing');
    const createdAt = safeTimestamp(intent.created_at, 'Spend Intent createdAt');
    const updatedAt = safeTimestamp(intent.updated_at, 'Spend Intent updatedAt');
    if (Date.parse(updatedAt) < Date.parse(createdAt)) {
      throw semantic('Spend Intent chronology regressed');
    }
    const ordinaryFingerprint = sha256(canonicalJson({
      routeId: intent.route_id,
      method: intent.method,
      requestUrlHash: intent.request_url_hash,
      bodyHash: intent.body_hash,
      headerAllowlistHash: intent.header_allowlist_hash,
      purposeLabel: intent.purpose_label,
    }));
    const intentHash = sha256(canonicalJson({
      requestId: intent.request_id,
      sessionId: intent.session_id,
      enrollmentHash: intent.enrollment_hash,
      routeId: intent.route_id,
      method: intent.method,
      requestUrlHash: intent.request_url_hash,
      sellerOrigin: intent.seller_origin,
      resourcePath: intent.resource_path,
      bodyHash: intent.body_hash,
      headerAllowlistHash: intent.header_allowlist_hash,
      purposeLabel: intent.purpose_label,
      correlationId: intent.correlation_id,
      walletAddress: intent.wallet_address,
      policyVersionId: authority.session.policy_version_id,
    }));
    const idempotencyDigest = sha256(canonicalJson({
      domain: 'wallet-kernel.intent-idempotency.v1',
      intentId: intent.id,
      requestId: intent.request_id,
      sessionId: intent.session_id,
      enrollmentHash: intent.enrollment_hash,
      ordinaryFingerprint: intent.ordinary_fingerprint,
      correlationId: intent.correlation_id,
    }));
    if (ordinaryFingerprint !== intent.ordinary_fingerprint
        || intentHash !== intent.intent_hash
        || intent.idempotency_key !== `wk_${idempotencyDigest.slice('sha256:'.length)}`
        || number(intent.retry_matchable, 'Spend Intent retry flag')
          !== (intent.state === 'terminal' ? 0 : 1)) {
      throw semantic('Spend Intent immutable hash projection changed');
    }

    const events = entityEvents(snapshot, 'spend_intent', intent.id);
    if (events.length === 0 || events[0].event_type !== 'intent.captured'
        || events.some((event) => !new Set([
          'intent.captured', 'intent.challenge_attached',
          'policy.decision_recorded', 'intent.transitioned',
        ]).has(event.event_type))) {
      throw semantic('Spend Intent event lifecycle is missing or contains an unknown event');
    }
    const captured = exactSemantic(
      parseCanonical(events[0].data_json, 'intent.captured event data'),
      [
        'requestId', 'sessionId', 'enrollmentHash', 'routeId', 'method',
        'requestUrlHash', 'sellerOrigin', 'resourcePath', 'bodyHash',
        'headerAllowlistHash', 'ordinaryFingerprint', 'purposeLabel',
        'correlationId', 'idempotencyKey', 'walletAddress', 'policyVersionId',
        'intentHash', 'createdAt',
      ],
      [],
      'intent.captured event',
    );
    const expectedCaptured = {
      requestId: intent.request_id,
      sessionId: intent.session_id,
      enrollmentHash: intent.enrollment_hash,
      routeId: intent.route_id,
      method: intent.method,
      requestUrlHash: intent.request_url_hash,
      sellerOrigin: intent.seller_origin,
      resourcePath: intent.resource_path,
      bodyHash: intent.body_hash,
      headerAllowlistHash: intent.header_allowlist_hash,
      ordinaryFingerprint: intent.ordinary_fingerprint,
      purposeLabel: intent.purpose_label,
      correlationId: intent.correlation_id,
      idempotencyKey: intent.idempotency_key,
      walletAddress: intent.wallet_address,
      policyVersionId: authority.session.policy_version_id,
      intentHash: intent.intent_hash,
      createdAt,
    };
    if (canonicalJson(captured) !== canonicalJson(expectedCaptured)
        || Date.parse(safeTimestamp(
          events[0].created_at,
          'intent captured event createdAt',
        )) < Date.parse(createdAt)) {
      throw semantic('Spend Intent capture event binding changed');
    }

    const decision = one(decisionsByIntent, intent.id, 'PolicyDecision');
    let state = 'captured';
    let projectionUpdatedAt = createdAt;
    let predecessorAt = createdAt;
    let challengeEventCount = 0;
    let decisionEventCount = 0;
    for (const event of events.slice(1)) {
      let transitionAt;
      if (event.event_type === 'intent.challenge_attached') {
        challengeEventCount += 1;
        const challenge = exactSemantic(
          parseCanonical(event.data_json, 'intent challenge event data'),
          ['challengeHash', 'challengeReceivedAt', 'projectionHash', 'updatedAt'],
          [],
          'intent.challenge_attached event',
        );
        if (challengeEventCount !== 1 || state !== 'captured'
            || intent.challenge_hash === null
            || challenge.challengeHash !== intent.challenge_hash
            || challenge.projectionHash !== intent.challenge_hash
            || challenge.challengeReceivedAt !== intent.challenge_received_at) {
          throw semantic('Spend Intent challenge event binding changed');
        }
        transitionAt = safeTimestamp(challenge.updatedAt, 'intent challenge updatedAt');
        if (Date.parse(intent.challenge_received_at) < Date.parse(createdAt)
            || Date.parse(transitionAt) < Date.parse(intent.challenge_received_at)) {
          throw semantic('Spend Intent challenge chronology is invalid');
        }
        state = 'challenged';
        projectionUpdatedAt = transitionAt;
      } else if (event.event_type === 'policy.decision_recorded') {
        decisionEventCount += 1;
        const data = exactSemantic(
          parseCanonical(event.data_json, 'PolicyDecision event data'),
          [
            'policyVersionId', 'decision', 'reasonCode', 'challengeHash',
            'acceptedIndex', 'quoteId', 'amountCeilingAtomic', 'decidedAt',
          ],
          [],
          'policy.decision_recorded event',
        );
        if (decisionEventCount !== 1 || state !== 'challenged' || !decision
            || data.policyVersionId !== decision.policy_version_id
            || data.decision !== decision.decision
            || data.reasonCode !== decision.reason_code
            || data.challengeHash !== decision.challenge_hash
            || data.acceptedIndex !== (decision.accepted_index === null
              ? null
              : number(decision.accepted_index, 'PolicyDecision event accepted index'))
            || data.quoteId !== decision.quote_id
            || data.amountCeilingAtomic !== decision.amount_ceiling_atomic
            || data.decidedAt !== decision.decided_at) {
          throw semantic('PolicyDecision event projection changed');
        }
        transitionAt = safeTimestamp(data.decidedAt, 'PolicyDecision event decidedAt');
      } else if (event.event_type === 'intent.transitioned') {
        const transition = exactSemantic(
          parseCanonical(event.data_json, 'Spend Intent transition event data'),
          ['previousState', 'nextState', 'reasonCode', 'retryMatchable', 'updatedAt'],
          [],
          'intent.transitioned event',
        );
        if (transition.previousState !== state
            || !LEGAL_INTENT_TRANSITIONS.get(state)?.has(transition.nextState)
            || transition.retryMatchable !== (transition.nextState !== 'terminal')) {
          throw semantic('Spend Intent transition event is not a legal state edge');
        }
        canonicalReason(transition.reasonCode, 'Spend Intent transition reason');
        transitionAt = safeTimestamp(transition.updatedAt, 'Spend Intent transition updatedAt');
        state = transition.nextState;
        projectionUpdatedAt = transitionAt;
      } else {
        throw semantic('Spend Intent capture event is duplicated or reordered');
      }
      if (Date.parse(transitionAt) < Date.parse(predecessorAt)
          || Date.parse(safeTimestamp(event.created_at, 'Spend Intent event createdAt'))
            < Date.parse(transitionAt)) {
        throw semantic('Spend Intent event chronology regressed');
      }
      predecessorAt = transitionAt;
    }
    if (state !== intent.state || projectionUpdatedAt !== updatedAt
        || challengeEventCount !== (intent.challenge_hash === null ? 0 : 1)
        || decisionEventCount !== (decision === null ? 0 : 1)) {
      throw semantic('Spend Intent event history does not project its current row');
    }
    if (decision !== null) {
      const policy = policyAuthority.policies.get(decision.policy_version_id);
      const acceptedIndex = decision.accepted_index === null
        ? null
        : number(decision.accepted_index, 'PolicyDecision accepted index');
      const decidedAt = safeTimestamp(decision.decided_at, 'PolicyDecision decidedAt');
      canonicalReason(decision.reason_code, 'PolicyDecision reason');
      canonicalAtomic(decision.amount_ceiling_atomic, 'PolicyDecision amount ceiling');
      if (!new Set(['allow', 'approval_required', 'deny']).has(decision.decision)
          || policy === undefined
          || decision.challenge_hash !== intent.challenge_hash
          || Date.parse(decidedAt) < Date.parse(intent.challenge_received_at)
          || Date.parse(decidedAt) < Date.parse(policy.row.applied_at)
          || (acceptedIndex === null
            ? (decision.quote_id !== null
              || decision.amount_ceiling_atomic !== '0'
              || decision.decision !== 'deny')
            : (acceptedIndex < 0
              || decision.quote_id !== sha256(canonicalJson({
                challengeHash: decision.challenge_hash,
                acceptedIndex,
              }))
              || decision.amount_ceiling_atomic === '0'))) {
        throw semantic('PolicyDecision immutable projection is invalid');
      }
    }
    intentsById.set(intent.id, intent);
  }

  const aliasIds = new Set();
  for (const event of snapshot.events.filter(
    (row) => row.entity_type === 'intent_correlation',
  )) {
    if (event.event_type !== 'intent.correlation_bound' || aliasIds.has(event.entity_id)) {
      throw semantic('intent correlation alias event is duplicated or invalid');
    }
    aliasIds.add(event.entity_id);
    const data = exactSemantic(
      parseCanonical(event.data_json, 'intent correlation event data'),
      ['sessionId', 'intentId', 'correlationId', 'ordinaryFingerprint'],
      [],
      'intent.correlation_bound event',
    );
    const intent = intentsById.get(data.intentId);
    safeToken(data.correlationId, 'intent correlation alias');
    const digest = sha256(canonicalJson({
      domain: 'wallet-kernel.intent-correlation-alias.v1',
      sessionId: data.sessionId,
      correlationId: data.correlationId,
    }));
    if (!intent || data.sessionId !== intent.session_id
        || data.correlationId === intent.correlation_id
        || data.ordinaryFingerprint !== intent.ordinary_fingerprint
        || event.entity_id !== `correlation-${digest.slice('sha256:'.length)}`) {
      throw semantic('intent correlation alias binding changed');
    }
  }
  if (snapshot.events.some((event) => (
    event.entity_type === 'spend_intent' && !intentsById.has(event.entity_id)
  ))) {
    throw semantic('orphan Spend Intent lifecycle event exists');
  }
}

function dependencyMaps(snapshot) {
  return Object.freeze({
    decisions: mapBy(snapshot.policy_decisions, 'intent_id'),
    approvals: mapBy(snapshot.approvals, 'intent_id'),
    budgets: mapBy(snapshot.budget_reservations, 'intent_id'),
    attempts: mapBy(snapshot.payment_attempts, 'intent_id'),
    candidates: mapBy(snapshot.payment_reconciliation_candidates, 'intent_id'),
    executions: mapBy(snapshot.execution_outcomes, 'intent_id'),
    resolutions: mapBy(snapshot.execution_resolutions, 'intent_id'),
    refunds: mapBy(snapshot.refunds, 'intent_id'),
    reconciliations: mapBy(snapshot.reconciliations, 'intent_id'),
    outcomes: mapBy(snapshot.buyer_outcomes, 'intent_id'),
    receiptRows: mapBy(snapshot.signed_receipts, 'intent_id'),
  });
}

function assertIntentBindings(intent, deps, sessions) {
  const authority = sessions.get(intent.session_id);
  if (!authority || intent.enrollment_hash !== authority.binding.enrollment_hash
      || intent.wallet_address !== authority.session.wallet_address) {
    throw semantic('Spend Intent session or enrollment binding changed');
  }
  const challengeFields = [
    intent.challenge_projection_json,
    intent.challenge_hash,
    intent.challenge_received_at,
  ];
  const hasChallenge = challengeFields.every((value) => value !== null);
  if (!hasChallenge && challengeFields.some((value) => value !== null)) {
    throw semantic('Spend Intent challenge fields are partial');
  }
  if (hasChallenge) {
    const projection = parseCanonical(intent.challenge_projection_json, 'challenge projection');
    if (sha256(canonicalJson(projection)) !== intent.challenge_hash) {
      throw semantic('Spend Intent challenge hash changed');
    }
    safeTimestamp(intent.challenge_received_at, 'challenge receivedAt');
  }
  const decision = one(deps.decisions, intent.id, 'PolicyDecision');
  if (decision) {
    if (!hasChallenge || decision.challenge_hash !== intent.challenge_hash
        || decision.policy_version_id !== authority.session.policy_version_id) {
      throw semantic('PolicyDecision immutable binding changed');
    }
    canonicalReason(decision.reason_code, 'PolicyDecision reason');
    safeTimestamp(decision.decided_at, 'PolicyDecision decidedAt');
  }
  const approval = one(deps.approvals, intent.id, 'Approval');
  if (approval) {
    if (!decision || approval.intent_hash !== intent.intent_hash
        || approval.challenge_hash !== intent.challenge_hash
        || approval.policy_version_id !== decision.policy_version_id
        || approval.quote_id !== decision.quote_id
        || number(approval.accepted_index, 'approval accepted index')
          !== number(decision.accepted_index, 'decision accepted index')
        || approval.amount_ceiling_atomic !== decision.amount_ceiling_atomic
        || approval.wallet_address !== intent.wallet_address) {
      throw semantic('Approval immutable binding changed');
    }
    safeTimestamp(approval.expires_at, 'approval expiresAt');
  }
  const budget = one(deps.budgets, intent.id, 'BudgetReservation');
  if (budget && (budget.session_id !== intent.session_id
      || budget.seller_origin !== intent.seller_origin)) {
    throw semantic('BudgetReservation immutable binding changed');
  }
  const attempt = one(deps.attempts, intent.id, 'PaymentAttempt');
  if (attempt && (!decision
      || attempt.payment_required_projection_json !== intent.challenge_projection_json
      || attempt.quote_id !== decision.quote_id
      || number(attempt.accepted_index, 'attempt accepted index')
        !== number(decision.accepted_index, 'decision accepted index'))) {
    throw semantic('PaymentAttempt immutable binding changed');
  }
  const execution = one(deps.executions, intent.id, 'execution outcome');
  const resolution = one(deps.resolutions, intent.id, 'execution resolution');
  if (resolution && !execution) throw semantic('execution resolution has no execution outcome');
  if (execution?.state === 'unknown' && resolution?.state !== 'reconciliation_required') {
    throw semantic('unknown execution has no reconciliation blocker');
  }
  if (execution?.state === 'failed' && resolution?.state !== 'refund_pending'
      && resolution?.state !== 'resolved') {
    throw semantic('failed execution has no refund resolution');
  }
  if (resolution?.state === 'refund_pending') {
    const refunds = deps.refunds.get(intent.id) ?? [];
    const openRefunds = refunds.filter(
      (row) => row.state === 'pending' || row.state === 'unresolved',
    );
    const terminalHistoryOnly = refunds.length > 0
      && openRefunds.length === 0
      && refunds.every((row) => row.state === 'abandoned' || row.state === 'rejected');
    if (execution?.state !== 'failed'
        || (openRefunds.length !== 1 && !terminalHistoryOnly)) {
      throw semantic('refund-pending execution has no exact open refund');
    }
  }
  return Object.freeze({ approval, attempt, budget, decision, execution, resolution });
}

function classifyIntents(snapshot, sessions, startupAt, { final = false } = {}) {
  const deps = dependencyMaps(snapshot);
  const repairs = [];
  let retainedIntentCount = 0;
  let unresolvedIntentCount = 0;
  let pendingApprovalCount = 0;
  for (const intent of snapshot.spend_intents) {
    safeToken(intent.id, 'Spend Intent ID');
    canonicalHash(intent.enrollment_hash, 'Spend Intent enrollment hash');
    canonicalHash(intent.intent_hash, 'Spend Intent hash');
    safeTimestamp(intent.created_at, 'Spend Intent createdAt');
    safeTimestamp(intent.updated_at, 'Spend Intent updatedAt');
    const authority = assertIntentBindings(intent, deps, sessions);
    const outcome = one(deps.outcomes, intent.id, 'BuyerOutcome');
    if (outcome) {
      canonicalReason(outcome.reason_code, 'BuyerOutcome reason');
      const revision = number(outcome.revision, 'BuyerOutcome revision');
      if (revision < 1) throw semantic('BuyerOutcome revision is invalid');
      safeTimestamp(outcome.recorded_at, 'BuyerOutcome recordedAt');
      const receiptRows = deps.receiptRows.get(intent.id) ?? [];
      if (receiptRows.length > revision) throw semantic('receipt history exceeds BuyerOutcome revision');
    }

    const hasNoMoney = !authority.budget && !authority.attempt
      && (deps.candidates.get(intent.id) ?? []).length === 0
      && !authority.execution && !authority.resolution
      && (deps.refunds.get(intent.id) ?? []).length === 0
      && (deps.reconciliations.get(intent.id) ?? []).length === 0;

    if (intent.state === 'captured') {
      if (authority.decision || authority.approval || !hasNoMoney || outcome
          || intent.challenge_hash !== null) {
        throw semantic('captured recovery gap is not exactly unsigned');
      }
      repairs.push({ kind: 'abandon_unsigned', intentId: intent.id, expectedState: 'captured',
        status: 'upstream_failed', reasonCode: 'RECOVERY_ABANDONED_UNSIGNED' });
      continue;
    }
    if (intent.state === 'challenged') {
      if (!authority.decision || authority.approval || !hasNoMoney || outcome) {
        throw semantic('challenged recovery gap has unexpected dependent authority');
      }
      if (authority.decision.decision === 'deny') {
        repairs.push({ kind: 'abandon_unsigned', intentId: intent.id, expectedState: 'challenged',
          status: 'payment_denied', reasonCode: authority.decision.reason_code });
      } else if (authority.decision.decision === 'allow'
          || authority.decision.decision === 'approval_required') {
        repairs.push({ kind: 'abandon_unsigned', intentId: intent.id, expectedState: 'challenged',
          status: 'payment_failed', reasonCode: 'RECOVERY_ABANDONED_UNSIGNED' });
      } else {
        throw semantic('challenged recovery PolicyDecision is invalid');
      }
      continue;
    }
    if (intent.state === 'approval_pending') {
      if (!authority.approval || authority.decision?.decision !== 'approval_required'
          || authority.budget || authority.attempt || authority.execution || outcome) {
        throw semantic('approval-pending recovery authority is incomplete');
      }
      if (!OPEN_APPROVALS.has(authority.approval.decision)) {
        throw semantic('approval-pending intent has a closed approval');
      }
      if (Date.parse(authority.approval.expires_at) <= Date.parse(startupAt)) {
        repairs.push({ kind: 'expire_approval', intentId: intent.id,
          approvalId: authority.approval.id, intentHash: intent.intent_hash });
      } else {
        retainedIntentCount += 1;
        pendingApprovalCount += 1;
      }
      continue;
    }
    if (intent.state === 'reserved') {
      if (!authority.budget || authority.budget.state !== 'reserved'
          || !authority.attempt || authority.attempt.state !== 'reserved'
          || authority.execution || outcome) {
        throw semantic('reserved recovery gap is not definitely unsigned');
      }
      repairs.push({ kind: 'release_reserved', intentId: intent.id });
      continue;
    }
    if (authority.attempt?.state === 'settled' && authority.budget?.state === 'committed'
        && !authority.execution && !authority.resolution
        && (deps.refunds.get(intent.id) ?? []).length === 0) {
      if (intent.state !== 'retrying' || outcome) {
        throw semantic('settled-without-execution gap has an illegal predecessor');
      }
      repairs.push({ kind: 'repair_missing_execution', intentId: intent.id,
        expectedState: 'retrying' });
      continue;
    }
    if (AMBIGUOUS_PAYMENT_STATES.has(intent.state)) {
      if (!authority.budget || authority.budget.state !== 'reserved'
          || !authority.attempt || authority.attempt.state !== intent.state
          || authority.execution || outcome) {
        throw semantic('in-flight payment recovery gap is not exact');
      }
      repairs.push({ kind: 'hold_ambiguous', intentId: intent.id,
        expectedState: intent.state });
      continue;
    }
    if (intent.state === 'unresolved') {
      if (authority.budget?.state !== 'unresolved'
          || authority.attempt?.state !== 'unresolved'
          || outcome?.status !== 'payment_unresolved'
          || authority.execution || authority.resolution) {
        throw semantic('unresolved payment authority is incomplete');
      }
      unresolvedIntentCount += 1;
      retainedIntentCount += 1;
      continue;
    }
    if (intent.state === 'terminal') {
      if (!outcome) throw semantic('terminal Spend Intent has no BuyerOutcome');
      if (authority.budget?.state === 'reserved' || authority.budget?.state === 'unresolved'
          || authority.attempt?.state === 'reserved'
          || AMBIGUOUS_PAYMENT_STATES.has(authority.attempt?.state)) {
        throw semantic('terminal Spend Intent retains in-flight payment authority');
      }
      retainedIntentCount += 1;
      continue;
    }
    if (intent.state === 'authorized') {
      throw semantic('authorized intent without its aggregate reservation is not recoverable');
    }
    throw semantic('Spend Intent state is not covered by the recovery matrix');
  }
  if (final && repairs.length > 0) throw semantic('final recovery audit still finds a crash gap');
  return Object.freeze({
    repairs: Object.freeze(repairs.map((repair) => Object.freeze(repair))),
    retainedIntentCount,
    unresolvedIntentCount,
    pendingApprovalCount,
  });
}

const TABLES = Object.freeze([
  'metadata', 'policy_versions', 'spend_sessions', 'agent_enrollments',
  'isolation_attestations', 'agent_session_bindings', 'spend_intents',
  'policy_decisions', 'budget_reservations', 'approvals', 'payment_attempts',
  'payment_reconciliation_candidates', 'execution_outcomes', 'execution_resolutions',
  'refunds', 'reconciliations', 'buyer_outcomes', 'signed_receipts', 'events',
]);

function auditAndClassify({ store, budgets, receipts, startupAt, final = false }) {
  return store.transaction((token) => {
    if (final) receipts.assertParityInTransaction(token);
    else receipts.assertRecoverableParityInTransaction(token);
    const snapshot = store.within(token, ({ db }) => {
      const integrity = db.prepare('SELECT * FROM pragma_integrity_check').all();
      const foreignKeyViolations = db.prepare('SELECT * FROM pragma_foreign_key_check').all();
      const userVersion = db.prepare('SELECT * FROM pragma_user_version').get();
      const foreignKeys = db.prepare('SELECT * FROM pragma_foreign_keys').get();
      if (integrity.length !== 1 || integrity[0].integrity_check !== 'ok'
          || foreignKeyViolations.length !== 0
          || number(userVersion.user_version, 'schema version') !== KERNEL_SCHEMA_VERSION
          || number(foreignKeys.foreign_keys, 'foreign-key enforcement') !== 1) {
        throw semantic('SQLite physical, schema, or foreign-key audit failed');
      }
      const value = {};
      for (const table of TABLES) {
        value[table] = db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
      }
      return value;
    });
    verifyEventChain(snapshot.events);
    const policyAuthority = verifyPolicies(snapshot);
    const enrollments = verifyEnrollments(snapshot);
    const sessions = verifySessions(snapshot, policyAuthority, enrollments);
    verifyIsolation(snapshot, enrollments, startupAt);
    verifyIntentAndDecisionHistory(snapshot, sessions, policyAuthority);
    verifyApprovalHistory(snapshot);
    const reconciliationHistories = verifyReconciliationHistory(
      snapshot,
      policyAuthority,
      sessions,
    );
    verifyCandidateHistory(snapshot, reconciliationHistories);
    verifyOutcomeAndExecutionEvents(snapshot);
    verifyReceiptRows(snapshot, receipts);
    for (const reservation of snapshot.budget_reservations) {
      budgets.snapshotInTransaction(token, {
        sessionId: reservation.session_id,
        sellerOrigin: reservation.seller_origin,
        at: startupAt,
      });
    }
    return classifyIntents(snapshot, sessions, startupAt, { final });
  });
}

function writeInitialOutcome(store, token, {
  intentId,
  status,
  reasonCode,
  recordedAt,
}) {
  store.within(token, ({ db, appendEvent }) => {
    const inserted = db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, ?, ?, 1, ?)`).run(intentId, status, reasonCode, recordedAt);
    if (inserted.changes !== 1n) throw semantic('recovery BuyerOutcome insert lost its race');
    appendEvent({
      entityType: 'buyer_outcome',
      entityId: intentId,
      eventType: 'buyer_outcome.recorded',
      data: { status, reasonCode, revision: 1, recordedAt },
    });
  });
}

function applyRepair({ store, intents, budgets, approvals, now }, repair, startupAt) {
  const recordedAt = canonicalTimestamp(now(), 'recovery repair timestamp');
  if (Date.parse(recordedAt) < Date.parse(startupAt)) {
    throw semantic('recovery clock regressed after startup classification');
  }
  store.transaction((token) => {
    if (repair.kind === 'abandon_unsigned') {
      intents.transitionInTransaction(token, {
        intentId: repair.intentId,
        expectedState: repair.expectedState,
        nextState: 'terminal',
        reasonCode: repair.reasonCode,
      });
      writeInitialOutcome(store, token, { ...repair, recordedAt });
      return;
    }
    if (repair.kind === 'expire_approval') {
      const expired = approvals.expireForIntentInTransaction(token, {
        approvalId: repair.approvalId,
        intentId: repair.intentId,
        expectedIntentHash: repair.intentHash,
        at: recordedAt,
      });
      if (expired === null) throw semantic('due approval changed before recovery expiry');
      intents.transitionInTransaction(token, {
        intentId: repair.intentId,
        expectedState: 'approval_pending',
        nextState: 'terminal',
        reasonCode: 'APPROVAL_EXPIRED',
      });
      writeInitialOutcome(store, token, {
        intentId: repair.intentId,
        status: 'payment_denied',
        reasonCode: 'APPROVAL_EXPIRED',
        recordedAt,
      });
      return;
    }
    if (repair.kind === 'release_reserved') {
      budgets.releaseInTransaction(token, {
        intentId: repair.intentId,
        reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
      });
      intents.transitionInTransaction(token, {
        intentId: repair.intentId,
        expectedState: 'reserved',
        nextState: 'terminal',
        reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
      });
      writeInitialOutcome(store, token, {
        intentId: repair.intentId,
        status: 'payment_failed',
        reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
        recordedAt,
      });
      return;
    }
    if (repair.kind === 'hold_ambiguous') {
      budgets.holdUnresolvedInTransaction(token, {
        intentId: repair.intentId,
        reasonCode: 'RECOVERY_PAYMENT_AMBIGUOUS',
      });
      // The budget ledger samples its own clock. Bind the PaymentAttempt to
      // that durable hold timestamp, not the earlier repair timestamp.
      const heldAt = safeTimestamp(store.within(token, ({ db }) => db.prepare(
        'SELECT updated_at FROM budget_reservations WHERE intent_id = ?',
      ).get(repair.intentId)?.updated_at), 'recovery budget hold timestamp');
      if (Date.parse(heldAt) < Date.parse(recordedAt)) {
        throw semantic('recovery budget hold clock regressed');
      }
      store.within(token, ({ db, appendEvent }) => {
        const changed = db.prepare(`UPDATE payment_attempts
          SET state = 'unresolved', reason_code = 'RECOVERY_PAYMENT_AMBIGUOUS', updated_at = ?
          WHERE intent_id = ? AND state = ?`).run(
          heldAt,
          repair.intentId,
          repair.expectedState,
        );
        if (changed.changes !== 1n) throw semantic('recovery PaymentAttempt update lost its race');
        appendEvent({
          entityType: 'payment_attempt',
          entityId: repair.intentId,
          eventType: 'payment.unresolved',
          data: { reasonCode: 'RECOVERY_PAYMENT_AMBIGUOUS', recordedAt: heldAt },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: repair.intentId,
        expectedState: repair.expectedState,
        nextState: 'unresolved',
        reasonCode: 'RECOVERY_PAYMENT_AMBIGUOUS',
      });
      writeInitialOutcome(store, token, {
        intentId: repair.intentId,
        status: 'payment_unresolved',
        reasonCode: 'RECOVERY_PAYMENT_AMBIGUOUS',
        recordedAt,
      });
      return;
    }
    if (repair.kind === 'repair_missing_execution') {
      store.within(token, ({ db, appendEvent }) => {
        const metadataJson = canonicalJson({ reasonCode: 'RECOVERY_EXECUTION_MISSING' });
        db.prepare(`INSERT INTO execution_outcomes
          (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
          VALUES (?, 'unknown', NULL, NULL, ?, ?)`).run(
          repair.intentId,
          metadataJson,
          recordedAt,
        );
        db.prepare(`INSERT INTO execution_resolutions
          (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
          VALUES (?, 'reconciliation_required', 'RECOVERY_EXECUTION_MISSING', 1, ?, NULL)`).run(
          repair.intentId,
          recordedAt,
        );
        appendEvent({
          entityType: 'execution_outcome',
          entityId: repair.intentId,
          eventType: 'execution.recorded',
          data: {
            state: 'unknown',
            httpStatus: null,
            responseHash: null,
            metadataHash: sha256(metadataJson),
            reasonCode: 'RECOVERY_EXECUTION_MISSING',
            recordedAt,
          },
        });
        appendEvent({
          entityType: 'execution_resolution',
          entityId: repair.intentId,
          eventType: 'execution_resolution.opened',
          data: {
            intentId: repair.intentId,
            state: 'reconciliation_required',
            reasonCode: 'RECOVERY_EXECUTION_MISSING',
            blocksWallet: true,
            openedAt: recordedAt,
          },
        });
      });
      intents.transitionInTransaction(token, {
        intentId: repair.intentId,
        expectedState: repair.expectedState,
        nextState: 'terminal',
        reasonCode: 'RECOVERY_EXECUTION_MISSING',
      });
      writeInitialOutcome(store, token, {
        intentId: repair.intentId,
        status: 'execution_unknown',
        reasonCode: 'RECOVERY_EXECUTION_MISSING',
        recordedAt,
      });
      return;
    }
    throw semantic('unknown deterministic recovery repair');
  });
}

export function recoverKernelAuthority(value) {
  if (arguments.length !== 1) {
    throw new TypeError('recoverKernelAuthority requires exactly one dependency object');
  }
  const dependencies = assertPlainDependencies(
    value,
    ['store', 'intents', 'budgets', 'approvals', 'receipts', 'now'],
    'recovery dependencies',
  );
  const { store, intents, budgets, approvals, receipts, now } = dependencies;
  requireMethods(store, ['transaction', 'within'], 'recovery store');
  requireMethods(intents, ['transitionInTransaction'], 'recovery intent repository');
  requireMethods(budgets, [
    'snapshotInTransaction', 'releaseInTransaction', 'holdUnresolvedInTransaction',
  ], 'recovery budget ledger');
  requireMethods(approvals, ['expireForIntentInTransaction'], 'recovery approval queue');
  requireMethods(receipts, [
    'issueMissingTerminalReceipts', 'assertParity', 'assertParityInTransaction',
    'assertRecoverableParityInTransaction', 'verify',
  ], 'recovery receipt repository');
  if (typeof now !== 'function' || utilTypes.isProxy(now)) {
    throw new TypeError('recovery requires an ordinary clock');
  }

  let startupAt;
  try { startupAt = canonicalTimestamp(now(), 'recovery startup time'); } catch (cause) {
    throw semantic('recovery clock is invalid', cause);
  }
  let classification;
  try {
    classification = auditAndClassify({ store, budgets, receipts, startupAt });
  } catch (cause) {
    throw semantic('pre-classification authority audit failed', cause);
  }
  for (const repair of classification.repairs) {
    try {
      applyRepair({ store, intents, budgets, approvals, now }, repair, startupAt);
    } catch (cause) {
      throw semantic('deterministic recovery repair failed', cause);
    }
  }

  let repairedReceipts;
  let final;
  try {
    repairedReceipts = receipts.issueMissingTerminalReceipts();
    receipts.assertParity();
    final = auditAndClassify({ store, budgets, receipts, startupAt, final: true });
  } catch (cause) {
    throw semantic('post-recovery authority audit failed', cause);
  }
  return frozenCopy({
    ready: true,
    repairedIntentCount: classification.repairs.length,
    repairedReceiptCount: Array.isArray(repairedReceipts) ? repairedReceipts.length : 0,
    retainedIntentCount: final.retainedIntentCount,
    unresolvedIntentCount: final.unresolvedIntentCount,
    pendingApprovalCount: final.pendingApprovalCount,
  });
}

function reconciliationInput(value, required, optional, label) {
  let record;
  try {
    record = exactRecord(value, required, optional, 'RECONCILIATION_INPUT', label);
  } catch (cause) {
    if (cause instanceof KernelError && cause.code === 'RECONCILIATION_INPUT') throw cause;
    throw new KernelError('RECONCILIATION_INPUT', `${label} is invalid`, { cause });
  }
  return record;
}

function canonicalReconciliationHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    throw new KernelError('RECONCILIATION_INPUT', `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalReconciliationToken(value, label) {
  try { return canonicalToken(value, label); } catch (cause) {
    throw new KernelError('RECONCILIATION_INPUT', `${label} is invalid`, { cause });
  }
}

function canonicalReconciliationTransaction(value, label) {
  if (typeof value !== 'string' || !EVM_HASH_PATTERN.test(value)) {
    throw new KernelError(
      'RECONCILIATION_INPUT',
      `${label} must be one canonical lowercase transaction hash`,
    );
  }
  return value;
}

function reconciliationConflict(message) {
  throw new KernelError('RECONCILIATION_CONFLICT', message);
}

function reconciliationMismatch(message) {
  throw new KernelError('RECONCILIATION_MISMATCH', message);
}

function assertExpectedReconciliationIntentHash(authority, expectedIntentHash) {
  if (authority.intent.intent_hash !== expectedIntentHash) {
    reconciliationConflict('displayed intent hash is stale');
  }
}

function reconciliationClockTimestamp(now, label, notBefore = []) {
  let value;
  try {
    value = canonicalTimestamp(now(), label);
  } catch (cause) {
    throw new KernelError('RECONCILIATION_TIME', `${label} is invalid`, { cause });
  }
  const instant = Date.parse(value);
  for (const predecessor of notBefore) {
    if (predecessor === null || predecessor === undefined) continue;
    let canonicalPredecessor;
    try {
      canonicalPredecessor = canonicalTimestamp(predecessor, `${label} predecessor`);
    } catch (cause) {
      throw new KernelError(
        'RECONCILIATION_CORRUPTION',
        `${label} predecessor timestamp is invalid`,
        { cause },
      );
    }
    if (instant < Date.parse(canonicalPredecessor)) {
      throw new KernelError(
        'RECONCILIATION_TIME',
        `${label} regressed behind persisted authority`,
      );
    }
  }
  return value;
}

function assertEvidenceTimestampNotFuture(value, resolvedAt, label) {
  const observedAt = safeTimestamp(value, label);
  if (Date.parse(observedAt) > Date.parse(resolvedAt)) {
    reconciliationMismatch(`${label} is later than resolver completion`);
  }
  return observedAt;
}

function exactResolverResult(value, required, optional, label) {
  try {
    return exactRecord(value, required, optional, 'RECONCILIATION_EVIDENCE', label);
  } catch (cause) {
    if (cause instanceof KernelError && cause.code === 'RECONCILIATION_EVIDENCE') throw cause;
    throw new KernelError('RECONCILIATION_EVIDENCE', `${label} is malformed`, { cause });
  }
}

function loadReconciliationPolicy(db, policyVersionId) {
  const row = db.prepare('SELECT * FROM policy_versions WHERE id = ?').get(policyVersionId);
  if (!row) throw new KernelError('RECONCILIATION_CORRUPTION', 'PolicyVersion is missing');
  let policy;
  try {
    const parsed = JSON.parse(row.canonical_json);
    policy = validatePolicyDocument(parsed);
    if (canonicalJson(policy) !== row.canonical_json
        || sha256(row.canonical_json) !== row.policy_hash) {
      throw new Error('policy binding changed');
    }
  } catch (cause) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'persisted PolicyVersion is invalid',
      { cause },
    );
  }
  return Object.freeze({ id: row.id, hash: row.policy_hash, policy });
}

function selectedReconciliationAuthority(db, intentId) {
  const intent = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(intentId);
  if (!intent) throw new KernelError('INTENT_UNKNOWN', 'Spend Intent does not exist');
  const session = db.prepare('SELECT * FROM spend_sessions WHERE id = ?').get(intent.session_id);
  const decision = db.prepare('SELECT * FROM policy_decisions WHERE intent_id = ?').get(intentId);
  const budget = db.prepare('SELECT * FROM budget_reservations WHERE intent_id = ?').get(intentId);
  const attempt = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?').get(intentId);
  const outcome = db.prepare('SELECT * FROM buyer_outcomes WHERE intent_id = ?').get(intentId);
  if (!session || !decision || !budget || !attempt || !outcome) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation authority is incomplete',
    );
  }
  const policyVersion = loadReconciliationPolicy(db, decision.policy_version_id);
  let challenge;
  try {
    challenge = JSON.parse(intent.challenge_projection_json);
    if (canonicalJson(challenge) !== intent.challenge_projection_json
        || sha256(intent.challenge_projection_json) !== intent.challenge_hash) {
      throw new Error('challenge binding changed');
    }
  } catch (cause) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'persisted challenge projection is invalid',
      { cause },
    );
  }
  const acceptedIndex = number(decision.accepted_index, 'PolicyDecision accepted index');
  const selected = challenge.accepts?.[acceptedIndex];
  const seller = policyVersion.policy.sellers.find((candidate) => (
    candidate.origin === intent.seller_origin
      && candidate.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
  ));
  if (!selected || !seller
      || session.policy_version_id !== policyVersion.id
      || intent.wallet_address !== session.wallet_address
      || policyVersion.policy.wallet !== session.wallet_address
      || decision.challenge_hash !== intent.challenge_hash
      || decision.quote_id !== attempt.quote_id
      || acceptedIndex !== number(attempt.accepted_index, 'PaymentAttempt accepted index')
      || attempt.payment_required_projection_json !== intent.challenge_projection_json
      || selected.network !== policyVersion.policy.network
      || selected.asset !== policyVersion.policy.asset
      || selected.payTo !== seller.payTo
      || selected.amount !== decision.amount_ceiling_atomic) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'persisted payment authority bindings disagree',
    );
  }
  canonicalReconciliationHash(intent.intent_hash, 'persisted intent hash');
  canonicalReconciliationHash(intent.challenge_hash, 'persisted challenge hash');
  canonicalReconciliationHash(attempt.payment_hash, 'persisted payment header hash');
  canonicalReconciliationTransaction(attempt.nonce, 'persisted authorization nonce');
  if (attempt.payment_payload_json === null || attempt.payment_header === null
      || attempt.valid_after === null || attempt.valid_before === null) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation requires one fully persisted signed authorization',
    );
  }
  const receipt = db.prepare(`SELECT * FROM signed_receipts
    WHERE intent_id = ? ORDER BY revision DESC LIMIT 1`).get(intentId);
  if (!receipt || number(receipt.revision, 'signed receipt revision')
      !== number(outcome.revision, 'BuyerOutcome revision')) {
    throw new KernelError('RECEIPT_PARITY_REQUIRED', 'current BuyerOutcome receipt is missing');
  }
  return Object.freeze({
    intent,
    session,
    decision,
    budget,
    attempt,
    outcome,
    policyVersion,
    selected,
    seller,
    predecessorReceiptHash: receipt.receipt_hash,
  });
}

function localAttemptBindingHash(authority) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-attempt-binding.v1',
    intentHash: authority.intent.intent_hash,
    challengeHash: authority.intent.challenge_hash,
    quoteId: authority.attempt.quote_id,
    paymentPayloadHash: sha256(authority.attempt.payment_payload_json),
    paymentHeaderHash: authority.attempt.payment_hash,
    network: authority.policyVersion.policy.network,
    payer: authority.session.wallet_address,
    payee: authority.selected.payTo,
    asset: authority.policyVersion.policy.asset,
    amountAtomic: authority.decision.amount_ceiling_atomic,
    nonce: authority.attempt.nonce,
    validAfter: authority.attempt.valid_after,
    validBefore: authority.attempt.valid_before,
  }));
}

function localRefundBindingHash(authority, refundTransactionId) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-binding.v1',
    intentHash: authority.intent.intent_hash,
    originalTransactionId: authority.attempt.transaction_id,
    refundTransactionId,
    network: authority.policyVersion.policy.network,
    sellerOrigin: authority.intent.seller_origin,
    asset: authority.policyVersion.policy.asset,
    originalPayer: authority.session.wallet_address,
    originalPayee: authority.selected.payTo,
    refundSource: authority.seller.refundSource,
    refundSigner: authority.seller.refundSigner,
    amountAtomic: authority.decision.amount_ceiling_atomic,
  }));
}

function paymentHistory(db, intentId) {
  return db.prepare(`SELECT * FROM payment_reconciliation_candidates
    WHERE intent_id = ? ORDER BY rowid`).all(intentId);
}

function refundHistory(db, intentId) {
  return db.prepare('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid').all(intentId);
}

function evidenceDigest(value) {
  return value === null ? null : sha256(value);
}

function paymentCaseHash(authority, candidates) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-reconciliation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    attemptState: authority.attempt.state,
    budgetState: authority.budget.state,
    buyerOutcomeRevision: number(authority.outcome.revision, 'BuyerOutcome revision'),
    history: candidates.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      state: row.state,
      evidenceHash: evidenceDigest(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function executionCaseHash(authority, execution, resolution) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.execution-reconciliation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    transactionId: authority.attempt.transaction_id,
    execution: {
      state: execution.state,
      httpStatus: execution.http_status === null ? null : number(execution.http_status, 'HTTP status'),
      responseHash: execution.response_hash,
      metadataHash: sha256(execution.metadata_json),
      recordedAt: execution.recorded_at,
    },
    resolution: {
      state: resolution.state,
      reasonCode: resolution.reason_code,
      openedAt: resolution.opened_at,
    },
    buyerOutcomeRevision: number(authority.outcome.revision, 'BuyerOutcome revision'),
  }));
}

function refundCaseHash(authority, execution, resolution, refunds) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    originalTransactionId: authority.attempt.transaction_id,
    executionState: execution.state,
    resolutionState: resolution.state,
    buyerOutcomeRevision: number(authority.outcome.revision, 'BuyerOutcome revision'),
    history: refunds.map((row) => ({
      id: row.id,
      originalTransactionId: row.original_transaction_id,
      amountAtomic: row.amount_atomic,
      state: row.state,
      refundTransactionId: row.refund_transaction_id,
      evidenceHash: evidenceDigest(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function loadPaymentCase(db, intentId) {
  const authority = selectedReconciliationAuthority(db, intentId);
  if (authority.intent.state !== 'unresolved'
      || authority.attempt.state !== 'unresolved'
      || authority.budget.state !== 'unresolved'
      || authority.outcome.status !== 'payment_unresolved') {
    throw new KernelError(
      'RECONCILIATION_STATE',
      'payment reconciliation requires one unresolved signed payment',
    );
  }
  const candidates = paymentHistory(db, intentId);
  if (candidates.filter((row) => row.state === 'pending').length > 1) {
    throw new KernelError('RECONCILIATION_CORRUPTION', 'payment candidates are ambiguous');
  }
  for (const row of candidates) {
    canonicalReconciliationTransaction(row.transaction_id, 'persisted payment candidate');
    if (row.state === 'pending' && row.evidence_json !== null) {
      throw new KernelError('RECONCILIATION_CORRUPTION', 'pending candidate contains evidence');
    }
  }
  return Object.freeze({
    authority,
    candidates: Object.freeze(candidates),
    caseHash: paymentCaseHash(authority, candidates),
  });
}

function loadExecutionCase(db, intentId) {
  const authority = selectedReconciliationAuthority(db, intentId);
  const execution = db.prepare('SELECT * FROM execution_outcomes WHERE intent_id = ?').get(intentId);
  const resolution = db.prepare('SELECT * FROM execution_resolutions WHERE intent_id = ?').get(intentId);
  if (authority.intent.state !== 'terminal'
      || authority.attempt.state !== 'settled'
      || authority.budget.state !== 'committed'
      || authority.outcome.status !== 'execution_unknown'
      || execution?.state !== 'unknown'
      || resolution?.state !== 'reconciliation_required'
      || number(resolution.blocks_wallet, 'execution wallet blocker') !== 1) {
    throw new KernelError(
      'RECONCILIATION_STATE',
      'execution reconciliation requires one blocking unknown execution',
    );
  }
  return Object.freeze({
    authority,
    execution,
    resolution,
    caseHash: executionCaseHash(authority, execution, resolution),
  });
}

function loadRefundCase(db, intentId) {
  const authority = selectedReconciliationAuthority(db, intentId);
  const execution = db.prepare('SELECT * FROM execution_outcomes WHERE intent_id = ?').get(intentId);
  const resolution = db.prepare('SELECT * FROM execution_resolutions WHERE intent_id = ?').get(intentId);
  const refunds = refundHistory(db, intentId);
  const open = refunds.filter((row) => row.state === 'pending' || row.state === 'unresolved');
  if (authority.intent.state !== 'terminal'
      || authority.attempt.state !== 'settled'
      || authority.budget.state !== 'committed'
      || authority.outcome.status !== 'execution_failed'
      || execution?.state !== 'failed'
      || resolution?.state !== 'refund_pending'
      || number(resolution.blocks_wallet, 'refund wallet blocker') !== 1
      || open.length > 1) {
    throw new KernelError(
      'RECONCILIATION_STATE',
      'refund observation requires one blocking failed execution',
    );
  }
  for (const refund of refunds) {
    if (refund.original_transaction_id !== authority.attempt.transaction_id
        || refund.amount_atomic !== authority.decision.amount_ceiling_atomic) {
      throw new KernelError('RECONCILIATION_CORRUPTION', 'refund history binding changed');
    }
    if (refund.refund_transaction_id !== null) {
      canonicalReconciliationTransaction(refund.refund_transaction_id, 'persisted refund transaction');
    }
  }
  return Object.freeze({
    authority,
    execution,
    resolution,
    refunds: Object.freeze(refunds),
    openRefund: open[0] ?? null,
    caseHash: refundCaseHash(authority, execution, resolution, refunds),
  });
}

function assertUnusedTransaction(db, transactionId, allowances = {}) {
  const rows = [
    ...db.prepare(`SELECT 'payment' AS kind, intent_id AS owner, transaction_id AS value
      FROM payment_attempts WHERE transaction_id IS NOT NULL`).all(),
    ...db.prepare(`SELECT 'payment_candidate' AS kind, id AS owner, transaction_id AS value
      FROM payment_reconciliation_candidates`).all(),
    ...db.prepare(`SELECT 'refund' AS kind, id AS owner, refund_transaction_id AS value
      FROM refunds WHERE refund_transaction_id IS NOT NULL`).all(),
  ];
  for (const row of rows) {
    if (row.value === transactionId && allowances[`${row.kind}:${row.owner}`] !== true) {
      throw new KernelError('TRANSACTION_REUSED', 'transaction is already bound to authority');
    }
  }
}

function nextReconciliationId(db, idFactory, kind, table = 'reconciliations') {
  for (let attempt = 0; attempt < 32; attempt += 1) {
    const id = canonicalReconciliationToken(idFactory(kind), `${kind} ID`);
    if (!db.prepare(`SELECT rowid FROM ${table} WHERE id = ?`).get(id)) return id;
  }
  throw new KernelError('ID_FACTORY_COLLISION', `${kind} ID factory exhausted collisions`);
}

function persistedPaymentBinding(paymentCase, candidate) {
  const { authority } = paymentCase;
  return frozenCopy({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-observation.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    challengeHash: authority.intent.challenge_hash,
    quoteId: authority.attempt.quote_id,
    network: authority.policyVersion.policy.network,
    asset: authority.policyVersion.policy.asset,
    payer: authority.session.wallet_address,
    payee: authority.selected.payTo,
    amountAtomic: authority.decision.amount_ceiling_atomic,
    nonce: authority.attempt.nonce,
    validAfter: authority.attempt.valid_after,
    validBefore: authority.attempt.valid_before,
    paymentPayloadHash: sha256(authority.attempt.payment_payload_json),
    paymentHeaderHash: authority.attempt.payment_hash,
    localAttemptHash: localAttemptBindingHash(authority),
    caseHash: paymentCase.caseHash,
    candidate: candidate === null ? null : {
      id: candidate.id,
      transactionId: candidate.transaction_id,
      state: candidate.state,
      createdAt: candidate.created_at,
    },
  });
}

function persistedExecutionBinding(executionCase) {
  const { authority, execution, resolution } = executionCase;
  return frozenCopy({
    schemaVersion: 1,
    domain: 'wallet-kernel.execution-observation.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    policyVersion: {
      id: authority.policyVersion.id,
      hash: authority.policyVersion.hash,
      policy: authority.policyVersion.policy,
    },
    seller: authority.seller,
    resourcePath: authority.intent.resource_path,
    network: authority.policyVersion.policy.network,
    sellerOrigin: authority.intent.seller_origin,
    transactionId: authority.attempt.transaction_id,
    executionSigner: authority.seller.executionSigner,
    persistedHttpStatus: execution.http_status === null
      ? null : number(execution.http_status, 'persisted HTTP status'),
    persistedResponseHash: execution.response_hash,
    resolutionReasonCode: resolution.reason_code,
    caseHash: executionCase.caseHash,
  });
}

function persistedRefundBinding(refundCase, refund) {
  const { authority } = refundCase;
  return frozenCopy({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    policyVersion: {
      id: authority.policyVersion.id,
      hash: authority.policyVersion.hash,
      policy: authority.policyVersion.policy,
    },
    seller: authority.seller,
    resourcePath: authority.intent.resource_path,
    network: authority.policyVersion.policy.network,
    sellerOrigin: authority.intent.seller_origin,
    originalTransactionId: authority.attempt.transaction_id,
    refundTransactionId: refund.refund_transaction_id,
    asset: authority.policyVersion.policy.asset,
    originalPayer: authority.session.wallet_address,
    originalPayee: authority.selected.payTo,
    refundSource: authority.seller.refundSource,
    refundSigner: authority.seller.refundSigner,
    amountAtomic: authority.decision.amount_ceiling_atomic,
    localRefundBindingHash: localRefundBindingHash(authority, refund.refund_transaction_id),
    refundId: refund.id,
    caseHash: refundCase.caseHash,
  });
}

function canonicalDecimal(value, label, { positive = false } = {}) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]*)$/.test(value)) {
    reconciliationMismatch(`${label} must be canonical decimal text`);
  }
  const parsed = BigInt(value);
  if (positive && parsed <= 0n) reconciliationMismatch(`${label} must be positive`);
  return parsed;
}

function nonnegativeInteger(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) reconciliationMismatch(`${label} is invalid`);
  return value;
}

function confirmedInteger(value, minimumConfirmations, label) {
  if (!Number.isSafeInteger(value) || value < minimumConfirmations) {
    reconciliationMismatch(`${label} does not meet the minimum confirmation depth`);
  }
  return value;
}

const TRANSFER_PROOF_FIELDS = Object.freeze([
  'source',
  'network',
  'transactionId',
  'blockHash',
  'blockNumber',
  'transactionStatus',
  'confirmations',
  'transferLogIndex',
  'authorizationLogIndex',
  'tokenContract',
  'from',
  'to',
  'valueAtomic',
  'authorizationNonce',
  'observedAt',
]);

function validateTransferProof(value, binding, minimumConfirmations, resolvedAt) {
  const proof = exactResolverResult(
    value,
    TRANSFER_PROOF_FIELDS,
    [],
    'settled transfer RPC proof',
  );
  if (proof.source !== 'base-sepolia-rpc'
      || proof.network !== binding.network
      || proof.transactionId !== binding.candidate?.transactionId
      || proof.transactionStatus !== 'success'
      || proof.tokenContract !== binding.asset
      || proof.from !== binding.payer
      || proof.to !== binding.payee
      || proof.valueAtomic !== binding.amountAtomic
      || proof.authorizationNonce !== binding.nonce) {
    reconciliationMismatch('settled transfer proof differs from persisted payment authority');
  }
  canonicalReconciliationTransaction(proof.transactionId, 'settled transaction ID');
  canonicalReconciliationTransaction(proof.blockHash, 'settled block hash');
  canonicalReconciliationTransaction(proof.authorizationNonce, 'settled authorization nonce');
  canonicalDecimal(proof.blockNumber, 'settled block number', { positive: true });
  confirmedInteger(
    proof.confirmations,
    minimumConfirmations,
    'settled transfer confirmations',
  );
  nonnegativeInteger(proof.transferLogIndex, 'settled transfer log index');
  nonnegativeInteger(proof.authorizationLogIndex, 'settled authorization log index');
  assertEvidenceTimestampNotFuture(
    proof.observedAt,
    resolvedAt,
    'settled transfer observedAt',
  );
  return frozenCopy(proof);
}

function validateRejectedCandidateProof(
  value,
  binding,
  kind,
  minimumConfirmations,
  resolvedAt,
) {
  const proof = exactResolverResult(value, [
    'source', 'network', 'transactionId', 'blockHash', 'blockNumber',
    'transactionStatus', 'confirmations', 'reasonCode', 'observedAt',
  ], [], `${kind} rejected-candidate proof`);
  const expectedTransaction = kind === 'payment'
    ? binding.candidate?.transactionId
    : binding.refundTransactionId;
  if (proof.source !== 'base-sepolia-rpc'
      || proof.network !== binding.network
      || proof.transactionId !== expectedTransaction
      || !new Set(['reverted', 'success']).has(proof.transactionStatus)
      || !new Set(['TRANSACTION_REVERTED', 'EXACT_TRANSFER_ABSENT']).has(proof.reasonCode)
      || (proof.transactionStatus === 'reverted' && proof.reasonCode !== 'TRANSACTION_REVERTED')
      || (proof.transactionStatus === 'success' && proof.reasonCode !== 'EXACT_TRANSFER_ABSENT')) {
    reconciliationMismatch(`${kind} rejected-candidate proof is not conclusive`);
  }
  canonicalReconciliationTransaction(proof.transactionId, `${kind} rejected transaction ID`);
  canonicalReconciliationTransaction(proof.blockHash, `${kind} rejected block hash`);
  canonicalDecimal(proof.blockNumber, `${kind} rejected block number`, { positive: true });
  confirmedInteger(proof.confirmations, minimumConfirmations, `${kind} rejected confirmations`);
  assertEvidenceTimestampNotFuture(
    proof.observedAt,
    resolvedAt,
    `${kind} rejected observedAt`,
  );
  return frozenCopy(proof);
}

function validateUnusedAuthorization(value, binding, minimumConfirmations, resolvedAt) {
  const proof = exactResolverResult(value, [
    'kind',
    'network',
    'asset',
    'payer',
    'nonce',
    'validBefore',
    'authorizationState',
    'observedBlockNumber',
    'observedBlockHash',
    'observedBlockTimestamp',
    'confirmations',
  ], [], 'unused-authorization proof');
  const validBefore = canonicalDecimal(proof.validBefore, 'authorization validBefore');
  const observedAt = canonicalDecimal(
    proof.observedBlockTimestamp,
    'authorization observed block timestamp',
  );
  if (proof.kind !== 'authorization_unused_after_expiry'
      || proof.network !== binding.network
      || proof.asset !== binding.asset
      || proof.payer !== binding.payer
      || proof.nonce !== binding.nonce
      || proof.validBefore !== binding.validBefore
      || proof.authorizationState !== false
      || observedAt < validBefore
      || observedAt * 1_000n > BigInt(Date.parse(resolvedAt))) {
    reconciliationMismatch('unused-authorization proof differs from persisted authority');
  }
  canonicalReconciliationTransaction(proof.nonce, 'unused authorization nonce');
  canonicalReconciliationTransaction(proof.observedBlockHash, 'unused authorization block hash');
  canonicalDecimal(proof.observedBlockNumber, 'unused authorization block number', { positive: true });
  confirmedInteger(
    proof.confirmations,
    minimumConfirmations,
    'unused authorization confirmations',
  );
  return frozenCopy(proof);
}

function normalizePaymentObservation(value, binding, minimumConfirmations, resolvedAt) {
  const discriminator = exactResolverResult(
    value,
    ['kind'],
    ['rpcTransferProof', 'rejectionProof', 'reasonCode', 'network', 'asset', 'payer', 'nonce',
      'validBefore', 'authorizationState', 'observedBlockNumber', 'observedBlockHash',
      'observedBlockTimestamp', 'confirmations'],
    'payment observation result',
  );
  if (discriminator.kind === 'unknown') {
    const unknown = exactResolverResult(
      value,
      ['kind', 'reasonCode'],
      [],
      'unknown payment observation',
    );
    if (!PAYMENT_RPC_UNKNOWN_REASONS.has(unknown.reasonCode)) {
      throw new KernelError(
        'RECONCILIATION_EVIDENCE',
        'unknown payment observation reason is not allowlisted',
      );
    }
    return Object.freeze({ kind: 'unknown', reasonCode: unknown.reasonCode });
  }
  if (discriminator.kind === 'settled_transfer') {
    const result = exactResolverResult(
      value,
      ['kind', 'rpcTransferProof'],
      [],
      'settled payment observation',
    );
    if (binding.candidate === null) {
      reconciliationMismatch('settled payment observation has no persisted candidate');
    }
    const rpcTransferProof = validateTransferProof(
      result.rpcTransferProof,
      binding,
      minimumConfirmations,
      resolvedAt,
    );
    return frozenCopy({
      kind: 'settled_transfer',
      evidence: {
        kind: 'settled_transfer',
        transactionId: binding.candidate.transactionId,
        rpcProofHash: sha256(canonicalJson(rpcTransferProof)),
        localAttemptHash: binding.localAttemptHash,
      },
    });
  }
  if (discriminator.kind === 'payment_candidate_rejected') {
    const result = exactResolverResult(
      value,
      ['kind', 'rejectionProof'],
      [],
      'rejected payment candidate observation',
    );
    if (binding.candidate === null) {
      reconciliationMismatch('rejected payment observation has no persisted candidate');
    }
    const proof = validateRejectedCandidateProof(
      result.rejectionProof,
      binding,
      'payment',
      minimumConfirmations,
      resolvedAt,
    );
    return frozenCopy({
      kind: 'payment_candidate_rejected',
      evidence: {
        kind: 'payment_candidate_rejected',
        transactionId: binding.candidate.transactionId,
        reasonCode: proof.reasonCode,
        rpcProofHash: sha256(canonicalJson(proof)),
      },
    });
  }
  if (discriminator.kind === 'authorization_unused_after_expiry') {
    return frozenCopy({
      kind: 'authorization_unused_after_expiry',
      evidence: validateUnusedAuthorization(
        value,
        binding,
        minimumConfirmations,
        resolvedAt,
      ),
    });
  }
  throw new KernelError('RECONCILIATION_EVIDENCE', 'payment resolver returned an unknown kind');
}

function validateAttestationWindow(attestation, observedAt, label) {
  const issuedAt = safeTimestamp(attestation.issuedAt, `${label} issuedAt`);
  const expiresAt = safeTimestamp(attestation.expiresAt, `${label} expiresAt`);
  const current = safeTimestamp(observedAt, `${label} observation time`);
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(issuedAt) > 15 * 60 * 1_000
      || Date.parse(current) < Date.parse(issuedAt)
      || Date.parse(current) >= Date.parse(expiresAt)) {
    reconciliationMismatch(`${label} validity window is not current and bounded`);
  }
}

function normalizeExecutionObservation(value, binding, observedAt) {
  const discriminator = exactResolverResult(
    value,
    ['kind'],
    ['attestation', 'attestationHash', 'reasonCode'],
    'execution observation result',
  );
  if (discriminator.kind === 'unknown') {
    const unknown = exactResolverResult(
      value,
      ['kind', 'reasonCode'],
      [],
      'unknown execution observation',
    );
    if (!SELLER_EVIDENCE_UNKNOWN_REASONS.has(unknown.reasonCode)) {
      throw new KernelError(
        'RECONCILIATION_EVIDENCE',
        'unknown execution observation reason is not allowlisted',
      );
    }
    return Object.freeze({ kind: 'unknown', reasonCode: unknown.reasonCode });
  }
  const result = exactResolverResult(
    value,
    ['kind', 'attestation', 'attestationHash'],
    [],
    'verified execution observation',
  );
  if (result.kind !== 'execution_attested') {
    throw new KernelError('RECONCILIATION_EVIDENCE', 'execution resolver returned an unknown kind');
  }
  const attestation = exactResolverResult(result.attestation, [
    'schemaVersion', 'domain', 'network', 'sellerOrigin', 'intentHash',
    'transactionId', 'outcome', 'httpStatus', 'responseHash', 'issuedAt',
    'expiresAt', 'signer',
  ], [], 'verified execution attestation');
  const attestationHash = canonicalReconciliationHash(
    result.attestationHash,
    'execution attestation hash',
  );
  if (attestation.schemaVersion !== 1
      || attestation.domain !== 'wallet-kernel.execution.v1'
      || attestation.network !== binding.network
      || attestation.sellerOrigin !== binding.sellerOrigin
      || attestation.intentHash !== binding.intentHash
      || attestation.transactionId !== binding.transactionId
      || !new Set(['succeeded', 'failed']).has(attestation.outcome)
      || attestation.signer !== binding.executionSigner
      || sha256(canonicalJson(attestation)) !== attestationHash
      || (binding.persistedHttpStatus !== null
        && attestation.httpStatus !== binding.persistedHttpStatus)
      || (binding.persistedResponseHash !== null
        && attestation.responseHash !== binding.persistedResponseHash)) {
    reconciliationMismatch('execution attestation differs from persisted authority');
  }
  if (!Number.isSafeInteger(attestation.httpStatus)
      || attestation.httpStatus < 100 || attestation.httpStatus > 599
      || (attestation.outcome === 'succeeded'
        && (attestation.httpStatus < 200 || attestation.httpStatus > 299))
      || (attestation.outcome === 'failed' && attestation.httpStatus < 400)) {
    reconciliationMismatch('execution attestation status disagrees with its outcome');
  }
  if (attestation.responseHash !== null) {
    canonicalReconciliationHash(attestation.responseHash, 'execution response hash');
  }
  validateAttestationWindow(attestation, observedAt, 'execution attestation');
  return frozenCopy({ kind: 'execution_attested', attestation, attestationHash });
}

const REFUND_RPC_FIELDS = Object.freeze([
  'source', 'network', 'transactionId', 'blockHash', 'blockNumber',
  'transactionStatus', 'confirmations', 'transferLogIndex', 'tokenContract',
  'from', 'to', 'valueAtomic', 'observedAt',
]);

function validateRefundTransferProof(value, binding, minimumConfirmations, resolvedAt) {
  const proof = exactResolverResult(value, REFUND_RPC_FIELDS, [], 'refund transfer RPC proof');
  if (proof.source !== 'base-sepolia-rpc'
      || proof.network !== binding.network
      || proof.transactionId !== binding.refundTransactionId
      || proof.transactionStatus !== 'success'
      || proof.tokenContract !== binding.asset
      || proof.from !== binding.refundSource
      || proof.to !== binding.originalPayer
      || proof.valueAtomic !== binding.amountAtomic) {
    reconciliationMismatch('refund transfer proof differs from persisted authority');
  }
  canonicalReconciliationTransaction(proof.transactionId, 'refund transaction ID');
  canonicalReconciliationTransaction(proof.blockHash, 'refund block hash');
  canonicalDecimal(proof.blockNumber, 'refund block number', { positive: true });
  confirmedInteger(proof.confirmations, minimumConfirmations, 'refund confirmations');
  nonnegativeInteger(proof.transferLogIndex, 'refund transfer log index');
  assertEvidenceTimestampNotFuture(proof.observedAt, resolvedAt, 'refund observedAt');
  return frozenCopy(proof);
}

function normalizeRefundObservation(value, binding, observedAt, minimumConfirmations) {
  const discriminator = exactResolverResult(
    value,
    ['kind'],
    ['attestation', 'attestationHash', 'rpcTransferProof', 'rejectionProof', 'reasonCode'],
    'refund observation result',
  );
  if (discriminator.kind === 'unknown') {
    const unknown = exactResolverResult(
      value,
      ['kind', 'reasonCode'],
      [],
      'unknown refund observation',
    );
    if (!SELLER_EVIDENCE_UNKNOWN_REASONS.has(unknown.reasonCode)
        && !REFUND_RPC_UNKNOWN_REASONS.has(unknown.reasonCode)) {
      throw new KernelError(
        'RECONCILIATION_EVIDENCE',
        'unknown refund observation reason is not allowlisted',
      );
    }
    return Object.freeze({ kind: 'unknown', reasonCode: unknown.reasonCode });
  }
  if (discriminator.kind === 'refund_candidate_rejected') {
    const result = exactResolverResult(
      value,
      ['kind', 'rejectionProof'],
      [],
      'rejected refund candidate observation',
    );
    const proof = validateRejectedCandidateProof(
      result.rejectionProof,
      binding,
      'refund',
      minimumConfirmations,
      observedAt,
    );
    return frozenCopy({
      kind: 'refund_candidate_rejected',
      evidence: {
        kind: 'refund_candidate_rejected',
        refundTransactionId: binding.refundTransactionId,
        reasonCode: proof.reasonCode,
        rpcProofHash: sha256(canonicalJson(proof)),
      },
    });
  }
  const result = exactResolverResult(value, [
    'kind', 'attestation', 'attestationHash', 'rpcTransferProof',
  ], [], 'confirmed refund observation');
  if (result.kind !== 'refund_attested_and_confirmed') {
    throw new KernelError('RECONCILIATION_EVIDENCE', 'refund resolver returned an unknown kind');
  }
  const attestation = exactResolverResult(result.attestation, [
    'schemaVersion', 'domain', 'network', 'sellerOrigin', 'intentHash',
    'originalTransactionId', 'refundTransactionId', 'asset', 'originalPayer',
    'originalPayee', 'refundSource', 'amountAtomic', 'issuedAt', 'expiresAt', 'signer',
  ], [], 'verified refund attestation');
  const attestationHash = canonicalReconciliationHash(
    result.attestationHash,
    'refund attestation hash',
  );
  if (attestation.schemaVersion !== 1
      || attestation.domain !== 'wallet-kernel.refund.v1'
      || attestation.network !== binding.network
      || attestation.sellerOrigin !== binding.sellerOrigin
      || attestation.intentHash !== binding.intentHash
      || attestation.originalTransactionId !== binding.originalTransactionId
      || attestation.refundTransactionId !== binding.refundTransactionId
      || attestation.asset !== binding.asset
      || attestation.originalPayer !== binding.originalPayer
      || attestation.originalPayee !== binding.originalPayee
      || attestation.refundSource !== binding.refundSource
      || attestation.amountAtomic !== binding.amountAtomic
      || attestation.signer !== binding.refundSigner
      || sha256(canonicalJson(attestation)) !== attestationHash) {
    reconciliationMismatch('refund attestation differs from persisted authority');
  }
  validateAttestationWindow(attestation, observedAt, 'refund attestation');
  const rpcProof = validateRefundTransferProof(
    result.rpcTransferProof,
    binding,
    minimumConfirmations,
    observedAt,
  );
  return frozenCopy({
    kind: 'refund_attested_and_confirmed',
    evidence: {
      kind: 'refund_attested_and_confirmed',
      originalTransactionId: binding.originalTransactionId,
      refundTransactionId: binding.refundTransactionId,
      attestationHash,
      attestation,
      rpcProofHash: sha256(canonicalJson(rpcProof)),
      localRefundBindingHash: binding.localRefundBindingHash,
    },
  });
}

function insertReconciliationRow({ db, appendEvent }, idFactory, {
  intentId,
  kind,
  outcome,
  evidence,
  operatorIdHash,
  recordedAt,
  requestCaseHash,
  observedCaseHash,
}) {
  const id = nextReconciliationId(db, idFactory, 'reconciliation');
  const evidenceJson = canonicalJson(evidence);
  db.prepare(`INSERT INTO reconciliations
    (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
    id,
    intentId,
    kind,
    outcome,
    evidenceJson,
    operatorIdHash,
    recordedAt,
  );
  appendEvent({
    entityType: 'reconciliation',
    entityId: id,
    eventType: 'reconciliation.recorded',
    data: {
      intentId,
      kind,
      outcome,
      evidenceHash: sha256(evidenceJson),
      operatorIdHash,
      recordedAt,
      requestCaseHash,
      observedCaseHash,
    },
  });
  return id;
}

function reconciliationReplayEvent(db, reconciliation) {
  const events = db.prepare(`SELECT * FROM events
    WHERE entity_type = 'reconciliation' AND entity_id = ?
      AND event_type = 'reconciliation.recorded' ORDER BY sequence`).all(reconciliation.id);
  if (events.length !== 1) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation replay has no exact recorded event',
    );
  }
  let data;
  try {
    data = JSON.parse(events[0].data_json);
    if (canonicalJson(data) !== events[0].data_json) throw new Error('non-canonical');
    data = exactRecord(data, [
      'intentId', 'kind', 'outcome', 'evidenceHash', 'operatorIdHash', 'recordedAt',
      'requestCaseHash', 'observedCaseHash',
    ], [], 'RECONCILIATION_CORRUPTION', 'reconciliation replay event');
  } catch (cause) {
    if (cause instanceof KernelError) throw cause;
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation replay event is malformed',
      { cause },
    );
  }
  if (data.intentId !== reconciliation.intent_id
      || data.kind !== reconciliation.kind
      || data.outcome !== reconciliation.outcome
      || data.evidenceHash !== sha256(reconciliation.evidence_json)
      || data.operatorIdHash !== reconciliation.operator_id_hash
      || data.recordedAt !== reconciliation.recorded_at
      || !HASH_PATTERN.test(data.requestCaseHash)
      || !HASH_PATTERN.test(data.observedCaseHash)) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation replay event changed its authority binding',
    );
  }
  return Object.freeze(data);
}

function parsedReconciliationEvidence(row) {
  try {
    const evidence = JSON.parse(row.evidence_json);
    if (canonicalJson(evidence) !== row.evidence_json) throw new Error('non-canonical');
    return evidence;
  } catch (cause) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'reconciliation replay evidence is malformed',
      { cause },
    );
  }
}

function loadPaymentReplay(db, {
  intentId,
  operatorIdHash,
  expectedIntentHash,
  transactionId,
  expectedCaseHash,
}) {
  const authority = selectedReconciliationAuthority(db, intentId);
  assertExpectedReconciliationIntentHash(authority, expectedIntentHash);
  const candidates = paymentHistory(db, intentId);
  const reconciliations = db.prepare(
    `SELECT * FROM reconciliations WHERE intent_id = ? AND kind = 'payment' ORDER BY rowid DESC`,
  ).all(intentId);
  let candidate = null;
  let reconciliation = null;
  let expectedObservationKind = null;
  let domain = null;

  if (transactionId !== null) {
    candidate = candidates.find((row) => row.transaction_id === transactionId) ?? null;
    if (!candidate || !new Set(['confirmed', 'rejected']).has(candidate.state)
        || candidate.evidence_json === null) {
      return null;
    }
    const expectedOutcome = candidate.state === 'confirmed' ? 'settled' : 'unresolved';
    reconciliation = reconciliations.find((row) => (
      row.outcome === expectedOutcome && row.evidence_json === candidate.evidence_json
    )) ?? null;
    if (!reconciliation) {
      throw new KernelError(
        'RECONCILIATION_CORRUPTION',
        'resolved payment candidate lost its reconciliation evidence',
      );
    }
    if (candidate.state === 'confirmed') {
      const execution = db.prepare(
        'SELECT * FROM execution_outcomes WHERE intent_id = ?',
      ).get(intentId);
      const resolution = db.prepare(
        'SELECT * FROM execution_resolutions WHERE intent_id = ?',
      ).get(intentId);
      if (authority.attempt.state !== 'settled'
          || authority.attempt.transaction_id !== transactionId
          || authority.budget.state !== 'committed'
          || authority.outcome.status !== 'execution_unknown'
          || execution?.state !== 'unknown'
          || resolution?.state !== 'reconciliation_required') {
        return null;
      }
      expectedObservationKind = 'settled_transfer';
      domain = frozenCopy({
        status: 'execution_unknown',
        reasonCode: authority.outcome.reason_code,
        executionCaseHash: executionCaseHash(authority, execution, resolution),
      });
    } else {
      if (authority.attempt.state !== 'unresolved'
          || authority.budget.state !== 'unresolved'
          || authority.outcome.status !== 'payment_unresolved'
          || authority.outcome.reason_code !== 'PAYMENT_CANDIDATE_REJECTED') {
        return null;
      }
      expectedObservationKind = 'payment_candidate_rejected';
      domain = frozenCopy({
        status: 'payment_unresolved',
        reasonCode: authority.outcome.reason_code,
        paymentCaseHash: paymentCaseHash(authority, candidates),
      });
    }
  } else {
    reconciliation = reconciliations.find((row) => {
      if (row.outcome !== 'rejected') return false;
      return parsedReconciliationEvidence(row).kind === 'authorization_unused_after_expiry';
    }) ?? null;
    if (!reconciliation
        || authority.attempt.state !== 'rejected'
        || authority.attempt.reason_code !== 'AUTHORIZATION_UNUSED_AFTER_EXPIRY'
        || authority.budget.state !== 'released'
        || authority.outcome.status !== 'payment_rejected'
        || authority.outcome.reason_code !== 'AUTHORIZATION_UNUSED_AFTER_EXPIRY') {
      return null;
    }
    expectedObservationKind = 'authorization_unused_after_expiry';
    domain = frozenCopy({
      status: 'payment_rejected',
      reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    });
  }

  const event = reconciliationReplayEvent(db, reconciliation);
  if (event.operatorIdHash !== operatorIdHash) {
    reconciliationConflict('payment replay operator differs from committed authority');
  }
  const currentCaseHash = domain.paymentCaseHash ?? null;
  if (expectedCaseHash !== event.requestCaseHash
      && expectedCaseHash !== currentCaseHash) {
    reconciliationConflict('payment replay case hash differs from committed authority');
  }
  const binding = persistedPaymentBinding({
    authority,
    candidates: Object.freeze(candidates),
    caseHash: event.observedCaseHash,
  }, candidate);
  return Object.freeze({
    binding,
    candidateId: candidate?.id ?? null,
    domain,
    event,
    expectedObservationKind,
    reconciliationId: reconciliation.id,
    reconciliationEvidenceJson: reconciliation.evidence_json,
  });
}

function loadExecutionReplay(db, {
  intentId,
  operatorIdHash,
  expectedIntentHash,
  expectedCaseHash,
}) {
  const authority = selectedReconciliationAuthority(db, intentId);
  assertExpectedReconciliationIntentHash(authority, expectedIntentHash);
  const execution = db.prepare(
    'SELECT * FROM execution_outcomes WHERE intent_id = ?',
  ).get(intentId);
  const resolution = db.prepare(
    'SELECT * FROM execution_resolutions WHERE intent_id = ?',
  ).get(intentId);
  if (!execution || !resolution || !new Set(['succeeded', 'failed']).has(execution.state)) {
    return null;
  }
  const reconciliations = db.prepare(
    'SELECT * FROM reconciliations WHERE intent_id = ? ORDER BY rowid',
  ).all(intentId);
  const reconciliation = reconciliations.at(-1);
  const expectedOutcome = execution.state === 'succeeded'
    ? 'execution_succeeded'
    : 'execution_failed';
  if (reconciliation?.kind !== 'execution'
      || reconciliation.outcome !== expectedOutcome) {
    return null;
  }
  const evidence = parsedReconciliationEvidence(reconciliation);
  if (evidence.kind !== 'execution_attested'
      || evidence.attestation?.outcome !== execution.state
      || evidence.attestationHash !== sha256(canonicalJson(evidence.attestation))) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'resolved execution lost its exact attestation projection',
    );
  }
  const event = reconciliationReplayEvent(db, reconciliation);
  if (event.operatorIdHash !== operatorIdHash) {
    reconciliationConflict('execution replay operator differs from committed authority');
  }
  if (expectedCaseHash !== event.requestCaseHash) {
    reconciliationConflict('execution replay case hash differs from committed authority');
  }
  let domain;
  if (execution.state === 'succeeded') {
    if (authority.outcome.status !== 'completed'
        || authority.outcome.reason_code !== 'EXECUTION_RECONCILED_SUCCEEDED'
        || authority.budget.state !== 'committed'
        || resolution.state !== 'resolved'
        || number(resolution.blocks_wallet, 'execution replay blocker') !== 0) {
      return null;
    }
    domain = frozenCopy({
      status: 'completed',
      reasonCode: 'EXECUTION_RECONCILED_SUCCEEDED',
    });
  } else {
    const refunds = refundHistory(db, intentId);
    if (authority.outcome.status !== 'execution_failed'
        || authority.outcome.reason_code !== 'REFUND_UNRESOLVED'
        || authority.budget.state !== 'committed'
        || resolution.state !== 'refund_pending'
        || number(resolution.blocks_wallet, 'execution replay blocker') !== 1) {
      return null;
    }
    domain = frozenCopy({
      status: 'execution_failed',
      reasonCode: 'REFUND_UNRESOLVED',
      refundCaseHash: refundCaseHash(authority, execution, resolution, refunds),
    });
  }
  const binding = persistedExecutionBinding({
    authority,
    execution,
    resolution,
    caseHash: event.observedCaseHash,
  });
  return Object.freeze({
    binding,
    domain,
    event,
    reconciliationEvidenceJson: reconciliation.evidence_json,
    reconciliationId: reconciliation.id,
  });
}

function loadRefundReplay(db, {
  intentId,
  operatorIdHash,
  expectedIntentHash,
  refundTransactionId,
  expectedCaseHash,
}) {
  const authority = selectedReconciliationAuthority(db, intentId);
  assertExpectedReconciliationIntentHash(authority, expectedIntentHash);
  const execution = db.prepare(
    'SELECT * FROM execution_outcomes WHERE intent_id = ?',
  ).get(intentId);
  const resolution = db.prepare(
    'SELECT * FROM execution_resolutions WHERE intent_id = ?',
  ).get(intentId);
  const refunds = refundHistory(db, intentId);
  const refund = refunds.find((row) => row.refund_transaction_id === refundTransactionId) ?? null;
  if (!refund || !new Set(['confirmed', 'rejected']).has(refund.state)
      || refund.evidence_json === null) {
    return null;
  }
  const expectedOutcome = refund.state === 'confirmed'
    ? 'refund_confirmed'
    : 'refund_rejected';
  const reconciliations = db.prepare(
    'SELECT * FROM reconciliations WHERE intent_id = ? ORDER BY rowid',
  ).all(intentId);
  const reconciliation = reconciliations.findLast((row) => (
    row.kind === 'refund'
      && row.outcome === expectedOutcome
      && row.evidence_json === refund.evidence_json
  )) ?? null;
  if (!reconciliation || reconciliations.at(-1)?.id !== reconciliation.id) {
    return null;
  }
  const evidence = parsedReconciliationEvidence(reconciliation);
  const expectedObservationKind = refund.state === 'confirmed'
    ? 'refund_attested_and_confirmed'
    : 'refund_candidate_rejected';
  if (evidence.kind !== expectedObservationKind
      || evidence.refundTransactionId !== refundTransactionId) {
    throw new KernelError(
      'RECONCILIATION_CORRUPTION',
      'resolved refund lost its exact evidence projection',
    );
  }
  const event = reconciliationReplayEvent(db, reconciliation);
  if (event.operatorIdHash !== operatorIdHash) {
    reconciliationConflict('refund replay operator differs from committed authority');
  }
  let domain;
  let currentCaseHash = null;
  if (refund.state === 'confirmed') {
    if (authority.outcome.status !== 'refunded'
        || authority.outcome.reason_code !== 'REFUND_CONFIRMED'
        || authority.budget.state !== 'released'
        || execution?.state !== 'failed'
        || resolution?.state !== 'resolved'
        || number(resolution.blocks_wallet, 'refund replay blocker') !== 0) {
      return null;
    }
    domain = frozenCopy({ status: 'refunded', reasonCode: 'REFUND_CONFIRMED' });
  } else {
    if (authority.outcome.status !== 'execution_failed'
        || authority.outcome.reason_code !== 'REFUND_UNRESOLVED'
        || authority.budget.state !== 'committed'
        || execution?.state !== 'failed'
        || resolution?.state !== 'refund_pending'
        || number(resolution.blocks_wallet, 'refund replay blocker') !== 1) {
      return null;
    }
    currentCaseHash = refundCaseHash(authority, execution, resolution, refunds);
    domain = frozenCopy({
      status: 'execution_failed',
      reasonCode: 'REFUND_UNRESOLVED',
      refundCaseHash: currentCaseHash,
    });
  }
  if (expectedCaseHash !== event.requestCaseHash
      && expectedCaseHash !== currentCaseHash) {
    reconciliationConflict('refund replay case hash differs from committed authority');
  }
  const binding = persistedRefundBinding({
    authority,
    execution,
    resolution,
    refunds: Object.freeze(refunds),
    caseHash: event.observedCaseHash,
  }, refund);
  return Object.freeze({
    binding,
    domain,
    event,
    expectedObservationKind,
    reconciliationEvidenceJson: reconciliation.evidence_json,
    reconciliationId: reconciliation.id,
  });
}

function terminalizeIntent({ db, appendEvent }, intentId, expectedState, reasonCode, updatedAt) {
  const changed = db.prepare(`UPDATE spend_intents
    SET state = 'terminal', retry_matchable = 0, updated_at = ?
    WHERE id = ? AND state = ? AND retry_matchable = 1`).run(
    updatedAt,
    intentId,
    expectedState,
  );
  if (changed.changes !== 1n) reconciliationConflict('Spend Intent resolution lost its race');
  appendEvent({
    entityType: 'spend_intent',
    entityId: intentId,
    eventType: 'intent.transitioned',
    data: {
      previousState: expectedState,
      nextState: 'terminal',
      reasonCode,
      retryMatchable: false,
      updatedAt,
    },
  });
}

function updateBuyerOutcome({ db, appendEvent }, {
  intentId,
  expectedStatus,
  status,
  reasonCode,
  recordedAt,
}) {
  const current = db.prepare('SELECT * FROM buyer_outcomes WHERE intent_id = ?').get(intentId);
  if (!current || current.status !== expectedStatus) {
    throw new KernelError('RECONCILIATION_CORRUPTION', 'BuyerOutcome predecessor changed');
  }
  const revision = number(current.revision, 'BuyerOutcome revision') + 1;
  const changed = db.prepare(`UPDATE buyer_outcomes
    SET status = ?, reason_code = ?, revision = ?, recorded_at = ?
    WHERE intent_id = ? AND revision = ?`).run(
    status,
    reasonCode,
    revision,
    recordedAt,
    intentId,
    current.revision,
  );
  if (changed.changes !== 1n) reconciliationConflict('BuyerOutcome update lost its race');
  appendEvent({
    entityType: 'buyer_outcome',
    entityId: intentId,
    eventType: 'buyer_outcome.revised',
    data: { status, reasonCode, revision, recordedAt },
  });
  return revision;
}

function issueReconciliationReceipt(receipts, markAuthorityUnhealthy, intentId, predecessorHash) {
  try {
    return receipts.issueRevisionForTerminal({
      intentId,
      supersedesReceiptHash: predecessorHash,
    });
  } catch (cause) {
    try {
      markAuthorityUnhealthy('RECEIPT_PARITY_REQUIRED');
    } catch (markCause) {
      throw new KernelError(
        'RECEIPT_PARITY_REQUIRED',
        'receipt parity failed and the authority fail-stop hook also failed',
        { cause: markCause },
      );
    }
    throw cause;
  }
}

export function createReconciler(value) {
  if (arguments.length !== 1) {
    throw new TypeError('createReconciler requires exactly one dependency object');
  }
  const requiredDependencies = [
    'store',
    'budgets',
    'receipts',
    'resolver',
    'now',
    'idFactory',
    'authorityMutationCoordinator',
    'markAuthorityUnhealthy',
  ];
  const hasMinimumConfirmations = Boolean(
    value && typeof value === 'object' && Object.hasOwn(value, 'minimumConfirmations'),
  );
  const dependencies = assertPlainDependencies(
    value,
    hasMinimumConfirmations
      ? [...requiredDependencies, 'minimumConfirmations']
      : requiredDependencies,
    'reconciler dependencies',
  );
  const {
    store,
    budgets,
    receipts,
    resolver,
    now,
    idFactory,
    authorityMutationCoordinator,
    markAuthorityUnhealthy,
  } = dependencies;
  const minimumConfirmations = Object.hasOwn(dependencies, 'minimumConfirmations')
    ? dependencies.minimumConfirmations
    : 2;
  if (!Number.isSafeInteger(minimumConfirmations)
      || minimumConfirmations < 1
      || minimumConfirmations > 1_000) {
    throw new TypeError('reconciler minimumConfirmations must be an integer from 1 through 1000');
  }
  requireMethods(store, ['transaction', 'within'], 'reconciler store');
  requireMethods(budgets, [
    'resolvePaymentInTransaction', 'recordConfirmedRefundInTransaction',
  ], 'reconciler budget ledger');
  requireMethods(receipts, [
    'assertParityInTransaction', 'issueRevisionForTerminal', 'latest',
  ], 'reconciler receipt repository');
  assertPlainDependencies(
    resolver,
    ['observePayment', 'observeExecution', 'observeRefund'],
    'trusted resolver',
  );
  requireMethods(resolver, ['observePayment', 'observeExecution', 'observeRefund'], 'trusted resolver');
  requireMethods(authorityMutationCoordinator, ['runExclusive'], 'authority coordinator');
  for (const [label, dependency] of [
    ['clock', now],
    ['ID factory', idFactory],
    ['authority fail-stop hook', markAuthorityUnhealthy],
  ]) {
    if (typeof dependency !== 'function' || utilTypes.isProxy(dependency)) {
      throw new TypeError(`reconciler ${label} must be an ordinary function`);
    }
  }

  const reconcilePayment = async (input) => {
    const request = reconciliationInput(input, [
      'intentId', 'operatorIdHash', 'expectedIntentHash', 'expectedPaymentCaseHash',
    ], ['paymentTransactionId'], 'payment reconciliation request');
    canonicalReconciliationToken(request.intentId, 'payment intent ID');
    canonicalReconciliationHash(request.operatorIdHash, 'payment operator hash');
    canonicalReconciliationHash(request.expectedIntentHash, 'expected intent hash');
    canonicalReconciliationHash(request.expectedPaymentCaseHash, 'expected payment case hash');
    const transactionId = Object.hasOwn(request, 'paymentTransactionId')
      ? request.paymentTransactionId
      : null;
    if (transactionId !== null) {
      canonicalReconciliationTransaction(transactionId, 'payment transaction ID');
    }
    const intentId = request.intentId;
    const operatorIdHash = request.operatorIdHash;
    const expectedIntentHash = request.expectedIntentHash;
    const expectedCaseHash = request.expectedPaymentCaseHash;

    const prepared = await authorityMutationCoordinator.runExclusive(() => (
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        return store.within(token, ({ db, appendEvent }) => {
          const replay = loadPaymentReplay(db, {
            intentId,
            operatorIdHash,
            expectedIntentHash,
            transactionId,
            expectedCaseHash,
          });
          if (replay) return Object.freeze({ binding: replay.binding, replay });
          let paymentCase = loadPaymentCase(db, intentId);
          if (paymentCase.caseHash !== expectedCaseHash) {
            reconciliationConflict('displayed payment case hash is stale');
          }
          let candidate = null;
          if (transactionId !== null) {
            candidate = paymentCase.candidates.find((row) => row.state === 'pending') ?? null;
            if (candidate !== null && candidate.transaction_id !== transactionId) {
              reconciliationConflict('a different payment candidate is already pending');
            }
            if (candidate === null) {
              assertUnusedTransaction(db, transactionId);
              const candidateId = nextReconciliationId(
                db,
                idFactory,
                'payment_candidate',
                'payment_reconciliation_candidates',
              );
              const createdAt = reconciliationClockTimestamp(
                now,
                'payment candidate createdAt',
                [
                  paymentCase.authority.intent.updated_at,
                  paymentCase.authority.attempt.updated_at,
                  paymentCase.authority.budget.updated_at,
                  paymentCase.authority.outcome.recorded_at,
                ],
              );
              db.prepare(`INSERT INTO payment_reconciliation_candidates
                (id, intent_id, transaction_id, state, evidence_json, created_at, updated_at)
                VALUES (?, ?, ?, 'pending', NULL, ?, ?)`).run(
                candidateId,
                intentId,
                transactionId,
                createdAt,
                createdAt,
              );
              appendEvent({
                entityType: 'payment_reconciliation_candidate',
                entityId: candidateId,
                eventType: 'payment.candidate_persisted',
                data: {
                  intentId,
                  transactionId,
                  operatorIdHash,
                  previousCaseHash: paymentCase.caseHash,
                  createdAt,
                },
              });
              paymentCase = loadPaymentCase(db, intentId);
              candidate = paymentCase.candidates.find((row) => row.id === candidateId);
            }
          }
          return Object.freeze({
            binding: persistedPaymentBinding(paymentCase, candidate),
            replay: null,
          });
        });
      })
    ));
    const persistedBinding = prepared.binding;

    const resolverStartedAt = reconciliationClockTimestamp(now, 'payment resolver startedAt');
    const resolverValue = await resolver.observePayment(persistedBinding);
    const resolverResolvedAt = reconciliationClockTimestamp(
      now,
      'payment resolver resolvedAt',
      [resolverStartedAt],
    );
    const evidenceValidationAt = prepared.replay?.event.recordedAt ?? resolverResolvedAt;
    const observation = normalizePaymentObservation(
      resolverValue,
      persistedBinding,
      minimumConfirmations,
      evidenceValidationAt,
    );

    return await authorityMutationCoordinator.runExclusive(() => {
      if (prepared.replay !== null) {
        const domain = store.transaction((token) => {
          receipts.assertParityInTransaction(token);
          return store.within(token, ({ db }) => {
            const replay = loadPaymentReplay(db, {
              intentId,
              operatorIdHash,
              expectedIntentHash,
              transactionId,
              expectedCaseHash,
            });
            if (!replay
                || replay.reconciliationId !== prepared.replay.reconciliationId
                || replay.event.observedCaseHash !== prepared.replay.event.observedCaseHash) {
              reconciliationConflict('payment replay authority changed while evidence was observed');
            }
            if (observation.kind !== replay.expectedObservationKind
                || canonicalJson(observation.evidence)
                  !== replay.reconciliationEvidenceJson) {
              reconciliationConflict('payment replay evidence differs from committed authority');
            }
            return replay.domain;
          });
        });
        return frozenCopy({ ...domain, receipt: receipts.latest(intentId) });
      }
      let domain;
      let predecessorHash = null;
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        store.within(token, ({ db, appendEvent }) => {
          const current = loadPaymentCase(db, intentId);
          if (current.caseHash !== persistedBinding.caseHash
              || localAttemptBindingHash(current.authority) !== persistedBinding.localAttemptHash) {
            reconciliationConflict('payment authority changed while evidence was observed');
          }
          const candidate = persistedBinding.candidate === null
            ? null
            : current.candidates.find((row) => row.id === persistedBinding.candidate.id);
          if (persistedBinding.candidate !== null
              && (!candidate || candidate.state !== 'pending'
                || candidate.transaction_id !== persistedBinding.candidate.transactionId)) {
            reconciliationConflict('payment candidate changed while evidence was observed');
          }
          predecessorHash = current.authority.predecessorReceiptHash;
          if (observation.kind === 'unknown') {
            domain = frozenCopy({
              status: 'payment_unresolved',
              reasonCode: current.authority.outcome.reason_code,
              paymentCaseHash: current.caseHash,
              receipt: null,
            });
            return;
          }
          const recordedAt = reconciliationClockTimestamp(
            now,
            'payment reconciliation recordedAt',
            [
              resolverResolvedAt,
              current.authority.intent.updated_at,
              current.authority.attempt.updated_at,
              current.authority.budget.updated_at,
              current.authority.outcome.recorded_at,
              candidate?.updated_at,
            ],
          );
          if (observation.kind === 'payment_candidate_rejected') {
            const evidenceJson = canonicalJson(observation.evidence);
            const changed = db.prepare(`UPDATE payment_reconciliation_candidates
              SET state = 'rejected', evidence_json = ?, updated_at = ?
              WHERE id = ? AND intent_id = ? AND state = 'pending'
                AND transaction_id = ? AND evidence_json IS NULL`).run(
              evidenceJson,
              recordedAt,
              candidate.id,
              intentId,
              candidate.transaction_id,
            );
            if (changed.changes !== 1n) reconciliationConflict('payment candidate rejection lost its race');
            const attemptReason = db.prepare(`UPDATE payment_attempts
              SET reason_code = 'PAYMENT_CANDIDATE_REJECTED'
              WHERE intent_id = ? AND state = 'unresolved'`).run(intentId);
            if (attemptReason.changes !== 1n) {
              reconciliationConflict('payment candidate rejection lost its attempt binding');
            }
            insertReconciliationRow({ db, appendEvent }, idFactory, {
              intentId,
              kind: 'payment',
              outcome: 'unresolved',
              evidence: observation.evidence,
              operatorIdHash,
              recordedAt,
              requestCaseHash: expectedCaseHash,
              observedCaseHash: current.caseHash,
            });
            updateBuyerOutcome({ db, appendEvent }, {
              intentId,
              expectedStatus: 'payment_unresolved',
              status: 'payment_unresolved',
              reasonCode: 'PAYMENT_CANDIDATE_REJECTED',
              recordedAt,
            });
            appendEvent({
              entityType: 'payment_reconciliation_candidate',
              entityId: candidate.id,
              eventType: 'payment.candidate_rejected',
              data: {
                intentId,
                transactionId: candidate.transaction_id,
                evidenceHash: sha256(evidenceJson),
                operatorIdHash,
                rejectedAt: recordedAt,
              },
            });
            const updatedAuthority = Object.freeze({
              ...current.authority,
              attempt: db.prepare(
                'SELECT * FROM payment_attempts WHERE intent_id = ?',
              ).get(intentId),
              outcome: db.prepare(
                'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
              ).get(intentId),
            });
            const updatedCandidates = paymentHistory(db, intentId);
            domain = frozenCopy({
              status: 'payment_unresolved',
              reasonCode: 'PAYMENT_CANDIDATE_REJECTED',
              paymentCaseHash: paymentCaseHash(updatedAuthority, updatedCandidates),
            });
            return;
          }
          const outcome = observation.kind === 'settled_transfer' ? 'settled' : 'rejected';
          const evidenceId = insertReconciliationRow({ db, appendEvent }, idFactory, {
            intentId,
            kind: 'payment',
            outcome,
            evidence: observation.evidence,
            operatorIdHash,
            recordedAt,
            requestCaseHash: expectedCaseHash,
            observedCaseHash: current.caseHash,
          });
          budgets.resolvePaymentInTransaction(token, { intentId, outcome, evidenceId });
          if (outcome === 'settled') {
            const confirmedCandidate = db.prepare(
              'SELECT * FROM payment_reconciliation_candidates WHERE id = ?',
            ).get(candidate.id);
            appendEvent({
              entityType: 'payment_reconciliation_candidate',
              entityId: candidate.id,
              eventType: 'payment.candidate_confirmed',
              data: {
                intentId,
                transactionId: confirmedCandidate.transaction_id,
                evidenceHash: sha256(confirmedCandidate.evidence_json),
                operatorIdHash,
                confirmedAt: confirmedCandidate.updated_at,
              },
            });
          } else {
            for (const pendingCandidate of current.candidates.filter(
              (row) => row.state === 'pending',
            )) {
              const rejectedCandidate = db.prepare(
                'SELECT * FROM payment_reconciliation_candidates WHERE id = ?',
              ).get(pendingCandidate.id);
              if (rejectedCandidate?.state !== 'rejected'
                  || rejectedCandidate.evidence_json !== canonicalJson(observation.evidence)) {
                reconciliationConflict('unused authorization candidate projection changed');
              }
              appendEvent({
                entityType: 'payment_reconciliation_candidate',
                entityId: rejectedCandidate.id,
                eventType: 'payment.candidate_rejected',
                data: {
                  intentId,
                  transactionId: rejectedCandidate.transaction_id,
                  evidenceHash: sha256(rejectedCandidate.evidence_json),
                  operatorIdHash,
                  rejectedAt: rejectedCandidate.updated_at,
                },
              });
            }
          }
          const resolvedOutcome = db.prepare(
            'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
          ).get(intentId);
          appendEvent({
            entityType: 'buyer_outcome',
            entityId: intentId,
            eventType: 'buyer_outcome.revised',
            data: {
              status: resolvedOutcome.status,
              reasonCode: resolvedOutcome.reason_code,
              revision: number(resolvedOutcome.revision, 'resolved BuyerOutcome revision'),
              recordedAt: resolvedOutcome.recorded_at,
            },
          });
          const reasonCode = outcome === 'settled'
            ? 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN'
            : 'AUTHORIZATION_UNUSED_AFTER_EXPIRY';
          terminalizeIntent(
            { db, appendEvent },
            intentId,
            'unresolved',
            reasonCode,
            recordedAt,
          );
          if (outcome === 'settled') {
            const execution = db.prepare(
              'SELECT * FROM execution_outcomes WHERE intent_id = ?',
            ).get(intentId);
            const resolution = db.prepare(
              'SELECT * FROM execution_resolutions WHERE intent_id = ?',
            ).get(intentId);
            appendEvent({
              entityType: 'execution_outcome',
              entityId: intentId,
              eventType: 'execution.recorded',
              data: {
                state: execution.state,
                httpStatus: execution.http_status,
                responseHash: execution.response_hash,
                metadataHash: sha256(execution.metadata_json),
                reasonCode: resolution.reason_code,
                recordedAt: execution.recorded_at,
              },
            });
            appendEvent({
              entityType: 'execution_resolution',
              entityId: intentId,
              eventType: 'execution_resolution.opened',
              data: {
                intentId,
                state: resolution.state,
                reasonCode: resolution.reason_code,
                blocksWallet: number(
                  resolution.blocks_wallet,
                  'payment execution resolution blocker',
                ) === 1,
                openedAt: resolution.opened_at,
              },
            });
            const updatedAuthority = Object.freeze({
              ...current.authority,
              intent: db.prepare(
                'SELECT * FROM spend_intents WHERE id = ?',
              ).get(intentId),
              attempt: db.prepare(
                'SELECT * FROM payment_attempts WHERE intent_id = ?',
              ).get(intentId),
              budget: db.prepare(
                'SELECT * FROM budget_reservations WHERE intent_id = ?',
              ).get(intentId),
              outcome: resolvedOutcome,
            });
            domain = frozenCopy({
              status: 'execution_unknown',
              reasonCode,
              executionCaseHash: executionCaseHash(updatedAuthority, execution, resolution),
            });
          } else {
            domain = frozenCopy({ status: 'payment_rejected', reasonCode });
          }
        });
      });
      if (observation.kind === 'unknown') return domain;
      const receipt = issueReconciliationReceipt(
        receipts,
        markAuthorityUnhealthy,
        intentId,
        predecessorHash,
      );
      return frozenCopy({ ...domain, receipt });
    });
  };

  const reconcileExecution = async (input) => {
    const request = reconciliationInput(input, [
      'intentId', 'operatorIdHash', 'expectedIntentHash', 'expectedExecutionCaseHash',
    ], [], 'execution reconciliation request');
    canonicalReconciliationToken(request.intentId, 'execution intent ID');
    canonicalReconciliationHash(request.operatorIdHash, 'execution operator hash');
    canonicalReconciliationHash(request.expectedIntentHash, 'expected intent hash');
    canonicalReconciliationHash(request.expectedExecutionCaseHash, 'expected execution case hash');
    const intentId = request.intentId;
    const operatorIdHash = request.operatorIdHash;
    const expectedIntentHash = request.expectedIntentHash;
    const prepared = await authorityMutationCoordinator.runExclusive(() => (
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        return store.within(token, ({ db }) => {
          const replay = loadExecutionReplay(db, {
            intentId,
            operatorIdHash,
            expectedIntentHash,
            expectedCaseHash: request.expectedExecutionCaseHash,
          });
          if (replay) return Object.freeze({ binding: replay.binding, replay });
          const executionCase = loadExecutionCase(db, intentId);
          if (executionCase.caseHash !== request.expectedExecutionCaseHash) {
            reconciliationConflict('displayed execution case hash is stale');
          }
          return Object.freeze({
            binding: persistedExecutionBinding(executionCase),
            replay: null,
          });
        });
      })
    ));
    const persistedBinding = prepared.binding;
    const resolverStartedAt = reconciliationClockTimestamp(now, 'execution resolver startedAt');
    const resolverValue = await resolver.observeExecution(persistedBinding);
    const resolverResolvedAt = reconciliationClockTimestamp(
      now,
      'execution resolver resolvedAt',
      [resolverStartedAt],
    );
    const evidenceValidationAt = prepared.replay?.event.recordedAt ?? resolverResolvedAt;
    const observation = normalizeExecutionObservation(
      resolverValue,
      persistedBinding,
      evidenceValidationAt,
    );

    return await authorityMutationCoordinator.runExclusive(() => {
      if (prepared.replay !== null) {
        const domain = store.transaction((token) => {
          receipts.assertParityInTransaction(token);
          return store.within(token, ({ db }) => {
            const replay = loadExecutionReplay(db, {
              intentId,
              operatorIdHash,
              expectedIntentHash,
              expectedCaseHash: request.expectedExecutionCaseHash,
            });
            if (!replay
                || replay.reconciliationId !== prepared.replay.reconciliationId
                || replay.event.observedCaseHash !== prepared.replay.event.observedCaseHash) {
              reconciliationConflict('execution replay authority changed while evidence was observed');
            }
            const evidenceJson = canonicalJson({
              kind: 'execution_attested',
              attestationHash: observation.attestationHash,
              attestation: observation.attestation,
            });
            if (observation.kind !== 'execution_attested'
                || evidenceJson !== replay.reconciliationEvidenceJson) {
              reconciliationConflict('execution replay evidence differs from committed authority');
            }
            return replay.domain;
          });
        });
        return frozenCopy({ ...domain, receipt: receipts.latest(intentId) });
      }
      let domain;
      let predecessorHash = null;
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        store.within(token, ({ db, appendEvent }) => {
          const current = loadExecutionCase(db, intentId);
          if (current.caseHash !== persistedBinding.caseHash) {
            reconciliationConflict('execution authority changed while evidence was observed');
          }
          predecessorHash = current.authority.predecessorReceiptHash;
          if (observation.kind === 'unknown') {
            domain = frozenCopy({
              status: 'execution_unknown',
              reasonCode: current.authority.outcome.reason_code,
              executionCaseHash: current.caseHash,
              receipt: null,
            });
            return;
          }
          const recordedAt = reconciliationClockTimestamp(
            now,
            'execution reconciliation recordedAt',
            [
              resolverResolvedAt,
              current.authority.intent.updated_at,
              current.authority.attempt.updated_at,
              current.authority.budget.updated_at,
              current.authority.outcome.recorded_at,
              current.execution.recorded_at,
              current.resolution.opened_at,
            ],
          );
          const attestation = observation.attestation;
          const succeeded = attestation.outcome === 'succeeded';
          const reasonCode = succeeded
            ? 'EXECUTION_RECONCILED_SUCCEEDED'
            : 'REFUND_UNRESOLVED';
          insertReconciliationRow({ db, appendEvent }, idFactory, {
            intentId,
            kind: 'execution',
            outcome: succeeded ? 'execution_succeeded' : 'execution_failed',
            evidence: {
              kind: 'execution_attested',
              attestationHash: observation.attestationHash,
              attestation,
            },
            operatorIdHash,
            recordedAt,
            requestCaseHash: request.expectedExecutionCaseHash,
            observedCaseHash: current.caseHash,
          });
          const executionMetadataJson = canonicalJson({
            attestationHash: observation.attestationHash,
            reasonCode,
          });
          const executionUpdate = db.prepare(`UPDATE execution_outcomes
            SET state = ?, http_status = ?, response_hash = ?, metadata_json = ?, recorded_at = ?
            WHERE intent_id = ? AND state = 'unknown'`).run(
            attestation.outcome,
            attestation.httpStatus,
            attestation.responseHash,
            executionMetadataJson,
            recordedAt,
            intentId,
          );
          if (executionUpdate.changes !== 1n) reconciliationConflict('execution resolution lost its race');
          if (succeeded) {
            const resolutionUpdate = db.prepare(`UPDATE execution_resolutions
              SET state = 'resolved', reason_code = ?, blocks_wallet = 0, resolved_at = ?
              WHERE intent_id = ? AND state = 'reconciliation_required'
                AND blocks_wallet = 1 AND resolved_at IS NULL`).run(
              reasonCode,
              recordedAt,
              intentId,
            );
            if (resolutionUpdate.changes !== 1n) reconciliationConflict('execution case resolution lost its race');
            appendEvent({
              entityType: 'execution_resolution',
              entityId: intentId,
              eventType: 'execution_resolution.resolved',
              data: {
                intentId,
                state: 'resolved',
                reasonCode,
                blocksWallet: false,
                resolvedAt: recordedAt,
              },
            });
          } else {
            const resolutionUpdate = db.prepare(`UPDATE execution_resolutions
              SET state = 'refund_pending', reason_code = ?, opened_at = ?
              WHERE intent_id = ? AND state = 'reconciliation_required'
                AND blocks_wallet = 1 AND resolved_at IS NULL`).run(
              reasonCode,
              recordedAt,
              intentId,
            );
            if (resolutionUpdate.changes !== 1n) reconciliationConflict('refund case opening lost its race');
            if (db.prepare('SELECT id FROM refunds WHERE intent_id = ?').get(intentId)) {
              throw new KernelError('RECONCILIATION_CORRUPTION', 'execution case already owns refund history');
            }
            const refundId = nextReconciliationId(db, idFactory, 'refund', 'refunds');
            db.prepare(`INSERT INTO refunds
              (id, intent_id, original_transaction_id, amount_atomic, state,
               evidence_json, refund_transaction_id, created_at, updated_at)
              VALUES (?, ?, ?, ?, 'pending', NULL, NULL, ?, ?)`).run(
              refundId,
              intentId,
              current.authority.attempt.transaction_id,
              current.authority.decision.amount_ceiling_atomic,
              recordedAt,
              recordedAt,
            );
            appendEvent({
              entityType: 'execution_resolution',
              entityId: intentId,
              eventType: 'execution_resolution.opened',
              data: {
                intentId,
                state: 'refund_pending',
                reasonCode,
                blocksWallet: true,
                openedAt: recordedAt,
              },
            });
            appendEvent({
              entityType: 'refund',
              entityId: refundId,
              eventType: 'refund.opened',
              data: {
                refundId,
                intentId,
                originalTransactionId: current.authority.attempt.transaction_id,
                amountAtomic: current.authority.decision.amount_ceiling_atomic,
                state: 'pending',
                createdAt: recordedAt,
              },
            });
          }
          updateBuyerOutcome({ db, appendEvent }, {
            intentId,
            expectedStatus: 'execution_unknown',
            status: succeeded ? 'completed' : 'execution_failed',
            reasonCode,
            recordedAt,
          });
          appendEvent({
            entityType: 'execution_outcome',
            entityId: intentId,
            eventType: 'execution.reconciled',
            data: {
              state: attestation.outcome,
              httpStatus: attestation.httpStatus,
              responseHash: attestation.responseHash,
              metadataHash: sha256(executionMetadataJson),
              attestationHash: observation.attestationHash,
              reasonCode,
              recordedAt,
            },
          });
          if (succeeded) {
            domain = frozenCopy({ status: 'completed', reasonCode });
          } else {
            const updatedExecution = db.prepare(
              'SELECT * FROM execution_outcomes WHERE intent_id = ?',
            ).get(intentId);
            const updatedResolution = db.prepare(
              'SELECT * FROM execution_resolutions WHERE intent_id = ?',
            ).get(intentId);
            const updatedRefunds = refundHistory(db, intentId);
            const updatedAuthority = Object.freeze({
              ...current.authority,
              intent: db.prepare(
                'SELECT * FROM spend_intents WHERE id = ?',
              ).get(intentId),
              attempt: db.prepare(
                'SELECT * FROM payment_attempts WHERE intent_id = ?',
              ).get(intentId),
              budget: db.prepare(
                'SELECT * FROM budget_reservations WHERE intent_id = ?',
              ).get(intentId),
              outcome: db.prepare(
                'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
              ).get(intentId),
            });
            domain = frozenCopy({
              status: 'execution_failed',
              reasonCode,
              refundCaseHash: refundCaseHash(
                updatedAuthority,
                updatedExecution,
                updatedResolution,
                updatedRefunds,
              ),
            });
          }
        });
      });
      if (observation.kind === 'unknown') return domain;
      const receipt = issueReconciliationReceipt(
        receipts,
        markAuthorityUnhealthy,
        intentId,
        predecessorHash,
      );
      return frozenCopy({ ...domain, receipt });
    });
  };

  const observeRefund = async (input) => {
    const request = reconciliationInput(input, [
      'intentId', 'operatorIdHash', 'expectedIntentHash', 'refundTransactionId',
      'expectedRefundCaseHash',
    ], [], 'refund observation request');
    canonicalReconciliationToken(request.intentId, 'refund intent ID');
    canonicalReconciliationHash(request.operatorIdHash, 'refund operator hash');
    canonicalReconciliationHash(request.expectedIntentHash, 'expected intent hash');
    canonicalReconciliationTransaction(request.refundTransactionId, 'refund transaction ID');
    canonicalReconciliationHash(request.expectedRefundCaseHash, 'expected refund case hash');
    const intentId = request.intentId;
    const operatorIdHash = request.operatorIdHash;
    const expectedIntentHash = request.expectedIntentHash;
    const refundTransactionId = request.refundTransactionId;
    const prepared = await authorityMutationCoordinator.runExclusive(() => (
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        return store.within(token, ({ db, appendEvent }) => {
          const replay = loadRefundReplay(db, {
            intentId,
            operatorIdHash,
            expectedIntentHash,
            refundTransactionId,
            expectedCaseHash: request.expectedRefundCaseHash,
          });
          if (replay) return Object.freeze({ binding: replay.binding, replay });
          let refundCase = loadRefundCase(db, intentId);
          if (refundCase.caseHash !== request.expectedRefundCaseHash) {
            reconciliationConflict('displayed refund case hash is stale');
          }
          let refund = refundCase.openRefund;
          if (refund && refund.refund_transaction_id !== null
              && refund.refund_transaction_id !== refundTransactionId) {
            reconciliationConflict('a different refund candidate is already pending');
          }
          if (!refund || refund.refund_transaction_id === null) {
            assertUnusedTransaction(db, refundTransactionId);
            const recordedAt = reconciliationClockTimestamp(
              now,
              'refund candidate recordedAt',
              [
                refundCase.authority.intent.updated_at,
                refundCase.authority.attempt.updated_at,
                refundCase.authority.budget.updated_at,
                refundCase.authority.outcome.recorded_at,
                refundCase.execution.recorded_at,
                refundCase.resolution.opened_at,
                refund?.updated_at,
              ],
            );
            if (!refund) {
              const refundId = nextReconciliationId(db, idFactory, 'refund', 'refunds');
              db.prepare(`INSERT INTO refunds
                (id, intent_id, original_transaction_id, amount_atomic, state,
                 evidence_json, refund_transaction_id, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'pending', NULL, ?, ?, ?)`).run(
                refundId,
                intentId,
                refundCase.authority.attempt.transaction_id,
                refundCase.authority.decision.amount_ceiling_atomic,
                refundTransactionId,
                recordedAt,
                recordedAt,
              );
              refund = db.prepare('SELECT * FROM refunds WHERE id = ?').get(refundId);
              appendEvent({
                entityType: 'refund',
                entityId: refundId,
                eventType: 'refund.opened',
                data: {
                  refundId,
                  intentId,
                  originalTransactionId: refundCase.authority.attempt.transaction_id,
                  amountAtomic: refundCase.authority.decision.amount_ceiling_atomic,
                  state: 'pending',
                  createdAt: recordedAt,
                },
              });
            } else {
              const changed = db.prepare(`UPDATE refunds
                SET refund_transaction_id = ?, updated_at = ?
                WHERE id = ? AND intent_id = ? AND state IN ('pending','unresolved')
                  AND refund_transaction_id IS NULL AND evidence_json IS NULL`).run(
                refundTransactionId,
                recordedAt,
                refund.id,
                intentId,
              );
              if (changed.changes !== 1n) reconciliationConflict('refund candidate binding lost its race');
              refund = db.prepare('SELECT * FROM refunds WHERE id = ?').get(refund.id);
            }
            appendEvent({
              entityType: 'refund',
              entityId: refund.id,
              eventType: 'refund.candidate_persisted',
              data: {
                intentId,
                originalTransactionId: refundCase.authority.attempt.transaction_id,
                refundTransactionId,
                operatorIdHash,
                previousCaseHash: refundCase.caseHash,
                recordedAt,
              },
            });
            refundCase = loadRefundCase(db, intentId);
            refund = refundCase.refunds.find((row) => row.id === refund.id);
          }
          return Object.freeze({
            binding: persistedRefundBinding(refundCase, refund),
            replay: null,
          });
        });
      })
    ));
    const persistedBinding = prepared.binding;
    const resolverStartedAt = reconciliationClockTimestamp(now, 'refund resolver startedAt');
    const resolverValue = await resolver.observeRefund(persistedBinding);
    const resolverResolvedAt = reconciliationClockTimestamp(
      now,
      'refund resolver resolvedAt',
      [resolverStartedAt],
    );
    const evidenceValidationAt = prepared.replay?.event.recordedAt ?? resolverResolvedAt;
    const observation = normalizeRefundObservation(
      resolverValue,
      persistedBinding,
      evidenceValidationAt,
      minimumConfirmations,
    );

    return await authorityMutationCoordinator.runExclusive(() => {
      if (prepared.replay !== null) {
        const domain = store.transaction((token) => {
          receipts.assertParityInTransaction(token);
          return store.within(token, ({ db }) => {
            const replay = loadRefundReplay(db, {
              intentId,
              operatorIdHash,
              expectedIntentHash,
              refundTransactionId,
              expectedCaseHash: request.expectedRefundCaseHash,
            });
            if (!replay
                || replay.reconciliationId !== prepared.replay.reconciliationId
                || replay.event.observedCaseHash !== prepared.replay.event.observedCaseHash) {
              reconciliationConflict('refund replay authority changed while evidence was observed');
            }
            if (observation.kind !== replay.expectedObservationKind
                || canonicalJson(observation.evidence)
                  !== replay.reconciliationEvidenceJson) {
              reconciliationConflict('refund replay evidence differs from committed authority');
            }
            return replay.domain;
          });
        });
        return frozenCopy({ ...domain, receipt: receipts.latest(intentId) });
      }
      let domain;
      let predecessorHash = null;
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        store.within(token, ({ db, appendEvent }) => {
          const current = loadRefundCase(db, intentId);
          const refund = current.refunds.find((row) => row.id === persistedBinding.refundId);
          if (current.caseHash !== persistedBinding.caseHash
              || !refund
              || !new Set(['pending', 'unresolved']).has(refund.state)
              || refund.refund_transaction_id !== refundTransactionId) {
            reconciliationConflict('refund authority changed while evidence was observed');
          }
          predecessorHash = current.authority.predecessorReceiptHash;
          if (observation.kind === 'unknown') {
            domain = frozenCopy({
              status: 'execution_failed',
              reasonCode: current.authority.outcome.reason_code,
              refundCaseHash: current.caseHash,
              receipt: null,
            });
            return;
          }
          const recordedAt = reconciliationClockTimestamp(
            now,
            'refund reconciliation recordedAt',
            [
              resolverResolvedAt,
              current.authority.intent.updated_at,
              current.authority.attempt.updated_at,
              current.authority.budget.updated_at,
              current.authority.outcome.recorded_at,
              current.execution.recorded_at,
              current.resolution.opened_at,
              refund.updated_at,
            ],
          );
          if (observation.kind === 'refund_candidate_rejected') {
            const evidenceJson = canonicalJson(observation.evidence);
            const changed = db.prepare(`UPDATE refunds
              SET state = 'rejected', evidence_json = ?, updated_at = ?
              WHERE id = ? AND intent_id = ? AND state IN ('pending','unresolved')
                AND refund_transaction_id = ? AND evidence_json IS NULL`).run(
              evidenceJson,
              recordedAt,
              refund.id,
              intentId,
              refundTransactionId,
            );
            if (changed.changes !== 1n) reconciliationConflict('refund candidate rejection lost its race');
            insertReconciliationRow({ db, appendEvent }, idFactory, {
              intentId,
              kind: 'refund',
              outcome: 'refund_rejected',
              evidence: observation.evidence,
              operatorIdHash,
              recordedAt,
              requestCaseHash: request.expectedRefundCaseHash,
              observedCaseHash: current.caseHash,
            });
            updateBuyerOutcome({ db, appendEvent }, {
              intentId,
              expectedStatus: 'execution_failed',
              status: 'execution_failed',
              reasonCode: 'REFUND_UNRESOLVED',
              recordedAt,
            });
            appendEvent({
              entityType: 'refund',
              entityId: refund.id,
              eventType: 'refund.candidate_rejected',
              data: {
                intentId,
                refundTransactionId,
                evidenceHash: sha256(evidenceJson),
                operatorIdHash,
                rejectedAt: recordedAt,
              },
            });
            const updatedExecution = db.prepare(
              'SELECT * FROM execution_outcomes WHERE intent_id = ?',
            ).get(intentId);
            const updatedResolution = db.prepare(
              'SELECT * FROM execution_resolutions WHERE intent_id = ?',
            ).get(intentId);
            const updatedRefunds = refundHistory(db, intentId);
            const updatedAuthority = Object.freeze({
              ...current.authority,
              intent: db.prepare(
                'SELECT * FROM spend_intents WHERE id = ?',
              ).get(intentId),
              attempt: db.prepare(
                'SELECT * FROM payment_attempts WHERE intent_id = ?',
              ).get(intentId),
              budget: db.prepare(
                'SELECT * FROM budget_reservations WHERE intent_id = ?',
              ).get(intentId),
              outcome: db.prepare(
                'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
              ).get(intentId),
            });
            domain = frozenCopy({
              status: 'execution_failed',
              reasonCode: 'REFUND_UNRESOLVED',
              refundCaseHash: refundCaseHash(
                updatedAuthority,
                updatedExecution,
                updatedResolution,
                updatedRefunds,
              ),
            });
            return;
          }
          const evidenceId = insertReconciliationRow({ db, appendEvent }, idFactory, {
            intentId,
            kind: 'refund',
            outcome: 'refund_confirmed',
            evidence: observation.evidence,
            operatorIdHash,
            recordedAt,
            requestCaseHash: request.expectedRefundCaseHash,
            observedCaseHash: current.caseHash,
          });
          budgets.recordConfirmedRefundInTransaction(token, {
            intentId,
            evidenceId,
            refundTransactionId,
          });
          const confirmedRefund = db.prepare(
            'SELECT * FROM refunds WHERE id = ?',
          ).get(refund.id);
          const resolvedCase = db.prepare(
            'SELECT * FROM execution_resolutions WHERE intent_id = ?',
          ).get(intentId);
          const resolvedOutcome = db.prepare(
            'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
          ).get(intentId);
          appendEvent({
            entityType: 'buyer_outcome',
            entityId: intentId,
            eventType: 'buyer_outcome.revised',
            data: {
              status: resolvedOutcome.status,
              reasonCode: resolvedOutcome.reason_code,
              revision: number(resolvedOutcome.revision, 'refunded BuyerOutcome revision'),
              recordedAt: resolvedOutcome.recorded_at,
            },
          });
          appendEvent({
            entityType: 'refund',
            entityId: refund.id,
            eventType: 'refund.confirmed',
            data: {
              refundId: refund.id,
              intentId,
              originalTransactionId: confirmedRefund.original_transaction_id,
              refundTransactionId: confirmedRefund.refund_transaction_id,
              amountAtomic: confirmedRefund.amount_atomic,
              evidenceId,
              confirmedAt: confirmedRefund.updated_at,
            },
          });
          appendEvent({
            entityType: 'execution_resolution',
            entityId: intentId,
            eventType: 'execution_resolution.resolved',
            data: {
              intentId,
              state: resolvedCase.state,
              reasonCode: resolvedCase.reason_code,
              blocksWallet: number(
                resolvedCase.blocks_wallet,
                'refund execution resolution blocker',
              ) === 1,
              resolvedAt: resolvedCase.resolved_at,
            },
          });
          domain = frozenCopy({ status: 'refunded', reasonCode: 'REFUND_CONFIRMED' });
        });
      });
      if (observation.kind === 'unknown') return domain;
      const receipt = issueReconciliationReceipt(
        receipts,
        markAuthorityUnhealthy,
        intentId,
        predecessorHash,
      );
      return frozenCopy({ ...domain, receipt });
    });
  };

  const abandonCandidate = async (input) => {
    const request = reconciliationInput(input, [
      'intentId', 'kind', 'operatorIdHash', 'expectedCaseHash',
    ], [], 'candidate abandonment request');
    canonicalReconciliationToken(request.intentId, 'candidate intent ID');
    if (request.kind !== 'payment' && request.kind !== 'refund-observation') {
      throw new KernelError(
        'RECONCILIATION_INPUT',
        'candidate kind must be payment or refund-observation',
      );
    }
    canonicalReconciliationHash(request.operatorIdHash, 'candidate operator hash');
    canonicalReconciliationHash(request.expectedCaseHash, 'expected candidate case hash');
    return await authorityMutationCoordinator.runExclusive(() => (
      store.transaction((token) => {
        receipts.assertParityInTransaction(token);
        return store.within(token, ({ db, appendEvent }) => {
          if (request.kind === 'payment') {
            const paymentCase = loadPaymentCase(db, request.intentId);
            if (paymentCase.caseHash !== request.expectedCaseHash) {
              reconciliationConflict('displayed payment case hash is stale');
            }
            const candidate = paymentCase.candidates.find((row) => row.state === 'pending');
            if (!candidate) reconciliationConflict('no pending payment candidate can be abandoned');
            const abandonedAt = reconciliationClockTimestamp(
              now,
              'payment candidate abandonedAt',
              [
                candidate.created_at,
                candidate.updated_at,
                paymentCase.authority.attempt.updated_at,
                paymentCase.authority.outcome.recorded_at,
              ],
            );
            const changed = db.prepare(`UPDATE payment_reconciliation_candidates
              SET state = 'abandoned', updated_at = ?
              WHERE id = ? AND intent_id = ? AND state = 'pending'
                AND transaction_id = ? AND evidence_json IS NULL`).run(
              abandonedAt,
              candidate.id,
              request.intentId,
              candidate.transaction_id,
            );
            if (changed.changes !== 1n) reconciliationConflict('payment abandonment lost its race');
            appendEvent({
              entityType: 'payment_reconciliation_candidate',
              entityId: candidate.id,
              eventType: 'payment.candidate_abandoned',
              data: {
                intentId: request.intentId,
                transactionId: candidate.transaction_id,
                operatorIdHash: request.operatorIdHash,
                previousCaseHash: paymentCase.caseHash,
                abandonedAt,
              },
            });
            const nextCase = loadPaymentCase(db, request.intentId);
            return frozenCopy({
              intentId: request.intentId,
              kind: request.kind,
              caseHash: nextCase.caseHash,
            });
          }
          const refundCase = loadRefundCase(db, request.intentId);
          if (refundCase.caseHash !== request.expectedCaseHash) {
            reconciliationConflict('displayed refund case hash is stale');
          }
          const candidate = refundCase.openRefund;
          if (!candidate || candidate.refund_transaction_id === null) {
            reconciliationConflict('no named refund candidate can be abandoned');
          }
          const abandonedAt = reconciliationClockTimestamp(
            now,
            'refund candidate abandonedAt',
            [
              candidate.created_at,
              candidate.updated_at,
              refundCase.execution.recorded_at,
              refundCase.resolution.opened_at,
              refundCase.authority.outcome.recorded_at,
            ],
          );
          const changed = db.prepare(`UPDATE refunds
            SET state = 'abandoned', updated_at = ?
            WHERE id = ? AND intent_id = ? AND state IN ('pending','unresolved')
              AND refund_transaction_id = ? AND evidence_json IS NULL`).run(
            abandonedAt,
            candidate.id,
            request.intentId,
            candidate.refund_transaction_id,
          );
          if (changed.changes !== 1n) reconciliationConflict('refund abandonment lost its race');
          appendEvent({
            entityType: 'refund',
            entityId: candidate.id,
            eventType: 'refund.candidate_abandoned',
            data: {
              intentId: request.intentId,
              refundTransactionId: candidate.refund_transaction_id,
              operatorIdHash: request.operatorIdHash,
              previousCaseHash: refundCase.caseHash,
              abandonedAt,
            },
          });
          const nextCase = loadRefundCase(db, request.intentId);
          return frozenCopy({
            intentId: request.intentId,
            kind: request.kind,
            caseHash: nextCase.caseHash,
          });
        });
      })
    ));
  };

  return Object.freeze({
    reconcilePayment,
    reconcileExecution,
    observeRefund,
    abandonCandidate,
  });
}

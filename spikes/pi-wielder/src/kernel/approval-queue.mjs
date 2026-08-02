import { types as utilTypes } from 'node:util';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';
import {
  validateChallengeProjection,
  validatePolicyDocument,
} from './policy-engine.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const OPEN_DECISIONS = new Set(['pending', 'approved']);
const DECISIONS = new Set([
  'pending',
  'approved',
  'denied',
  'expired',
  'cancelled',
  'consumed',
]);
const CANCEL_REASONS = new Set([
  'POLICY_SUPERSEDED',
  'SESSION_CLOSED',
  'APPROVAL_CHALLENGE_CHANGED',
]);

function fail(code, message) {
  throw new KernelError(code, message);
}

function canonicalHash(value, label, code = 'APPROVAL_SCHEMA') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalAddress(value, label, code = 'APPROVAL_SCHEMA') {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical lower-case EVM address`);
  }
  return value;
}

function boundedToken(value, label, code = 'APPROVAL_SCHEMA') {
  try {
    return canonicalToken(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} must be one bounded canonical token`);
    throw error;
  }
}

function canonicalIndex(value, label, code = 'APPROVAL_SCHEMA') {
  const normalized = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(normalized) || normalized < 0
      || (typeof value === 'bigint' && BigInt(normalized) !== value)) {
    fail(code, `${label} must be one nonnegative safe integer`);
  }
  return normalized;
}

function canonicalLimit(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 1_000) {
    fail('APPROVAL_LIST_SCHEMA', 'approval list limit must be an integer from 1 through 1000');
  }
  return value;
}

function timestamp(value, label, code = 'APPROVAL_SCHEMA') {
  try {
    return canonicalTimestamp(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} must be a canonical timestamp`);
    throw error;
  }
}

function nowTimestamp(now, label = 'approval transition time') {
  return timestamp(now(), label, 'APPROVAL_TIME');
}

function parsePolicyRow(row) {
  if (!row) fail('APPROVAL_CORRUPTION', 'approval PolicyVersion is missing');
  try {
    const id = canonicalToken(row.id, 'approval PolicyVersion ID');
    const schemaVersion = canonicalIndex(row.schema_version, 'policy schema version');
    const policy = validatePolicyDocument(JSON.parse(row.canonical_json));
    const canonical = canonicalJson(policy);
    if (schemaVersion !== policy.schemaVersion
        || canonical !== row.canonical_json
        || sha256(canonical) !== row.policy_hash) {
      fail('APPROVAL_CORRUPTION', 'approval PolicyVersion bytes or hash changed');
    }
    canonicalTimestamp(row.applied_at, 'approval PolicyVersion appliedAt');
    return Object.freeze({ id, policy });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'approval PolicyVersion is invalid');
  }
}

function parseChallengeProjection(bytes, expectedHash) {
  try {
    const projection = validateChallengeProjection(JSON.parse(bytes));
    const canonical = canonicalJson(projection);
    if (canonical !== bytes || sha256(canonical) !== expectedHash) {
      fail('APPROVAL_CORRUPTION', 'approval challenge projection binding changed');
    }
    return projection;
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'approval challenge projection is invalid');
  }
}

function loadAuthority(db, intentId) {
  const intent = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(intentId);
  if (!intent) return null;
  const decision = db.prepare(
    'SELECT * FROM policy_decisions WHERE intent_id = ?',
  ).get(intentId);
  const session = db.prepare(
    'SELECT * FROM spend_sessions WHERE id = ?',
  ).get(intent.session_id);
  const enrollment = db.prepare(
    'SELECT state FROM agent_enrollments WHERE enrollment_hash = ?',
  ).get(intent.enrollment_hash);
  if (!decision || !session || !enrollment) {
    fail('APPROVAL_CORRUPTION', 'approval authority graph is incomplete');
  }
  const policyVersion = parsePolicyRow(db.prepare(
    'SELECT * FROM policy_versions WHERE id = ?',
  ).get(decision.policy_version_id));

  let canonicalIntentId;
  let sessionId;
  let intentHash;
  let intentChallengeHash;
  let decisionChallengeHash;
  let quoteId;
  let amountCeilingAtomic;
  let intentWallet;
  let sessionWallet;
  let policyVersionId;
  let acceptedIndex;
  let challengeReceivedAt;
  let decidedAt;
  try {
    canonicalIntentId = canonicalToken(intent.id, 'approval intent ID');
    sessionId = canonicalToken(intent.session_id, 'approval session ID');
    intentHash = canonicalHash(intent.intent_hash, 'approval intent hash', 'APPROVAL_CORRUPTION');
    intentChallengeHash = canonicalHash(
      intent.challenge_hash,
      'approval intent challenge hash',
      'APPROVAL_CORRUPTION',
    );
    decisionChallengeHash = canonicalHash(
      decision.challenge_hash,
      'approval decision challenge hash',
      'APPROVAL_CORRUPTION',
    );
    quoteId = canonicalHash(decision.quote_id, 'approval quote ID', 'APPROVAL_CORRUPTION');
    amountCeilingAtomic = canonicalAtomic(
      decision.amount_ceiling_atomic,
      'approval amount ceiling',
    ).text;
    intentWallet = canonicalAddress(
      intent.wallet_address,
      'approval intent wallet',
      'APPROVAL_CORRUPTION',
    );
    sessionWallet = canonicalAddress(
      session.wallet_address,
      'approval session wallet',
      'APPROVAL_CORRUPTION',
    );
    policyVersionId = canonicalToken(
      decision.policy_version_id,
      'approval policy version ID',
    );
    acceptedIndex = canonicalIndex(
      decision.accepted_index,
      'approval accepted index',
      'APPROVAL_CORRUPTION',
    );
    challengeReceivedAt = canonicalTimestamp(
      intent.challenge_received_at,
      'approval challenge receivedAt',
    );
    decidedAt = canonicalTimestamp(decision.decided_at, 'approval PolicyDecision decidedAt');
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'approval authority fields are invalid');
  }

  if (canonicalIntentId !== intentId
      || decision.intent_id !== intentId
      || decision.decision !== 'approval_required'
      || decision.reason_code !== 'HUMAN_APPROVAL_REQUIRED'
      || intentChallengeHash !== decisionChallengeHash
      || session.policy_version_id !== policyVersionId
      || policyVersion.id !== policyVersionId
      || intentWallet !== sessionWallet
      || intentWallet !== policyVersion.policy.wallet
      || quoteId !== sha256(canonicalJson({
        challengeHash: decisionChallengeHash,
        acceptedIndex,
      }))) {
    fail('APPROVAL_CORRUPTION', 'approval authority bindings disagree');
  }

  const projection = parseChallengeProjection(
    intent.challenge_projection_json,
    intentChallengeHash,
  );
  let requestUrlHash;
  try {
    requestUrlHash = canonicalHash(
      intent.request_url_hash,
      'approval request URL hash',
      'APPROVAL_CORRUPTION',
    );
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'approval request binding is invalid');
  }
  const seller = policyVersion.policy.sellers.find(
    (entry) => entry.origin === intent.seller_origin,
  ) ?? null;
  const compatible = projection.accepts.filter((candidate) => candidate.scheme === 'exact'
    && candidate.network === policyVersion.policy.network
    && candidate.asset === policyVersion.policy.asset
    && candidate.payTo === seller?.payTo
    && candidate.extra.name === 'USDC'
    && candidate.extra.version === '2'
    && (!Object.hasOwn(candidate.extra, 'assetTransferMethod')
      || candidate.extra.assetTransferMethod === 'eip3009'));
  if (acceptedIndex >= projection.accepts.length
      || compatible.length !== 1
      || projection.accepts.indexOf(compatible[0]) !== acceptedIndex
      || projection.accepts[acceptedIndex].amount !== amountCeilingAtomic
      || projection.x402Version !== 2
      || projection.resource.urlHash !== requestUrlHash
      || !seller
      || !seller.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
      || !policyVersion.policy.methods.includes(intent.method)) {
    fail('APPROVAL_CORRUPTION', 'approval selected offer binding changed');
  }

  const challengeDeadline = Date.parse(challengeReceivedAt)
    + policyVersion.policy.challengeMaxAgeMs;
  const approvalDeadline = Date.parse(decidedAt) + policyVersion.policy.approvalTtlMs;
  if (!Number.isSafeInteger(challengeDeadline) || !Number.isSafeInteger(approvalDeadline)
      || Date.parse(decidedAt) < Date.parse(challengeReceivedAt)) {
    fail('APPROVAL_CORRUPTION', 'approval authority time binding is invalid');
  }
  const expiresAt = new Date(Math.min(challengeDeadline, approvalDeadline)).toISOString();
  const activePolicyId = db.prepare(
    'SELECT value FROM metadata WHERE key = ?',
  ).get('active_policy_id')?.value ?? null;

  return Object.freeze({
    activePolicyId,
    binding: Object.freeze({
      intentId,
      intentHash,
      challengeHash: decisionChallengeHash,
      quoteId,
      amountCeilingAtomic,
      walletAddress: intentWallet,
      policyVersionId,
      acceptedIndex,
      expiresAt,
    }),
    challengeReceivedAt,
    decidedAt,
    enrollmentState: enrollment.state,
    intentState: intent.state,
    policy: policyVersion.policy,
    sessionId,
    sessionState: session.state,
  });
}

function requestInput(value) {
  const input = exactRecord(value, [
    'intentId',
    'intentHash',
    'challengeHash',
    'quoteId',
    'amountCeilingAtomic',
    'walletAddress',
    'policyVersionId',
    'acceptedIndex',
  ], [], 'APPROVAL_SCHEMA', 'approval request');
  return Object.freeze({
    intentId: boundedToken(input.intentId, 'approval intent ID'),
    intentHash: canonicalHash(input.intentHash, 'approval intent hash'),
    challengeHash: canonicalHash(input.challengeHash, 'approval challenge hash'),
    quoteId: canonicalHash(input.quoteId, 'approval quote ID'),
    amountCeilingAtomic: canonicalAtomic(
      input.amountCeilingAtomic,
      'approval amount ceiling',
    ).text,
    walletAddress: canonicalAddress(input.walletAddress, 'approval wallet'),
    policyVersionId: boundedToken(input.policyVersionId, 'approval policy version ID'),
    acceptedIndex: canonicalIndex(input.acceptedIndex, 'approval accepted index'),
  });
}

function consumptionInput(value) {
  const input = exactRecord(value, [
    'intentId',
    'intentHash',
    'challengeHash',
    'quoteId',
    'amountCeilingAtomic',
    'walletAddress',
    'policyVersionId',
    'acceptedIndex',
    'expiresAt',
  ], [], 'APPROVAL_SCHEMA', 'approval consumption binding');
  return Object.freeze({
    ...requestInput(Object.fromEntries(
      Object.entries(input).filter(([key]) => key !== 'expiresAt'),
    )),
    expiresAt: timestamp(input.expiresAt, 'approval expiresAt'),
  });
}

function recordBinding(record) {
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

function approvalEventRows(db, approvalId) {
  return db.prepare(`SELECT current_event.*,
      (SELECT prior_event.event_hash FROM events AS prior_event
        WHERE prior_event.sequence < current_event.sequence
        ORDER BY prior_event.sequence DESC LIMIT 1) AS actual_previous_hash
    FROM events AS current_event
    WHERE current_event.entity_type = 'approval' AND current_event.entity_id = ?
    ORDER BY current_event.sequence`).all(approvalId);
}

function eventData(row, requiredFields, label) {
  let data;
  try {
    data = JSON.parse(row.data_json);
    if (canonicalJson(data) !== row.data_json) {
      fail('APPROVAL_CORRUPTION', `${label} data is not canonical`);
    }
    return exactRecord(
      data,
      requiredFields,
      [],
      'APPROVAL_CORRUPTION',
      label,
    );
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', `${label} data is invalid`);
  }
}

function approvalEventEnvelope(row, approvalId) {
  try {
    const sequence = canonicalIndex(
      row.sequence,
      'approval event sequence',
      'APPROVAL_CORRUPTION',
    );
    if (sequence < 1
        || row.entity_type !== 'approval'
        || boundedToken(
          row.entity_id,
          'approval event entity ID',
          'APPROVAL_CORRUPTION',
        ) !== approvalId
        || !new Set([
          'approval.requested',
          'approval.approved',
          'approval.denied',
          'approval.expired',
          'approval.cancelled',
          'approval.consumed',
        ]).has(row.event_type)) {
      fail('APPROVAL_CORRUPTION', 'approval event envelope is invalid');
    }
    const createdAt = timestamp(
      row.created_at,
      'approval event createdAt',
      'APPROVAL_CORRUPTION',
    );
    const previousHash = row.previous_hash === null
      ? null
      : canonicalHash(
        row.previous_hash,
        'approval event previous hash',
        'APPROVAL_CORRUPTION',
      );
    const actualPreviousHash = row.actual_previous_hash === null
      ? null
      : canonicalHash(
        row.actual_previous_hash,
        'approval event actual previous hash',
        'APPROVAL_CORRUPTION',
      );
    const persistedHash = canonicalHash(
      row.event_hash,
      'approval event hash',
      'APPROVAL_CORRUPTION',
    );
    const data = JSON.parse(row.data_json);
    const expectedHash = sha256(canonicalJson({
      entityType: 'approval',
      entityId: approvalId,
      eventType: row.event_type,
      data,
      previousHash,
      createdAt,
    }));
    if (previousHash !== actualPreviousHash || persistedHash !== expectedHash) {
      fail('APPROVAL_CORRUPTION', 'approval event is not on the append-only event chain');
    }
    return Object.freeze({ createdAt, eventType: row.event_type, row });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'approval event envelope is invalid');
  }
}

function exactApprovalEventBinding(data, record) {
  const eventBinding = Object.freeze({
    intentId: boundedToken(
      data.intentId,
      'approval event intent ID',
      'APPROVAL_CORRUPTION',
    ),
    intentHash: canonicalHash(
      data.intentHash,
      'approval event intent hash',
      'APPROVAL_CORRUPTION',
    ),
  });
  if (eventBinding.intentId !== record.intentId
      || eventBinding.intentHash !== record.intentHash) {
    fail('APPROVAL_CORRUPTION', 'approval event differs from its SpendIntent authority');
  }
  return eventBinding;
}

function approvalLifecycleEvent(envelope, record) {
  const { eventType, row, createdAt } = envelope;
  let data;
  let at;
  let previousDecision = null;
  if (eventType === 'approval.requested') {
    data = eventData(row, [
      'intentId',
      'intentHash',
      'challengeHash',
      'quoteId',
      'amountCeilingAtomic',
      'walletAddress',
      'policyVersionId',
      'acceptedIndex',
      'expiresAt',
      'requestedAt',
    ], 'approval.requested event');
    const binding = Object.freeze({
      intentId: boundedToken(
        data.intentId,
        'approval request event intent ID',
        'APPROVAL_CORRUPTION',
      ),
      intentHash: canonicalHash(
        data.intentHash,
        'approval request event intent hash',
        'APPROVAL_CORRUPTION',
      ),
      challengeHash: canonicalHash(
        data.challengeHash,
        'approval request event challenge hash',
        'APPROVAL_CORRUPTION',
      ),
      quoteId: canonicalHash(
        data.quoteId,
        'approval request event quote ID',
        'APPROVAL_CORRUPTION',
      ),
      amountCeilingAtomic: canonicalAtomic(
        data.amountCeilingAtomic,
        'approval request event amount ceiling',
      ).text,
      walletAddress: canonicalAddress(
        data.walletAddress,
        'approval request event wallet',
        'APPROVAL_CORRUPTION',
      ),
      policyVersionId: boundedToken(
        data.policyVersionId,
        'approval request event PolicyVersion ID',
        'APPROVAL_CORRUPTION',
      ),
      acceptedIndex: canonicalIndex(
        data.acceptedIndex,
        'approval request event accepted index',
        'APPROVAL_CORRUPTION',
      ),
      expiresAt: timestamp(
        data.expiresAt,
        'approval request event expiresAt',
        'APPROVAL_CORRUPTION',
      ),
    });
    if (canonicalJson(binding) !== canonicalJson(recordBinding(record))) {
      fail('APPROVAL_CORRUPTION', 'approval.requested event binding changed');
    }
    at = timestamp(
      data.requestedAt,
      'approval request event requestedAt',
      'APPROVAL_CORRUPTION',
    );
  } else if (eventType === 'approval.approved') {
    data = eventData(row, [
      'intentId', 'intentHash', 'operatorIdHash', 'approvedAt',
    ], 'approval.approved event');
    exactApprovalEventBinding(data, record);
    const operatorIdHash = canonicalHash(
      data.operatorIdHash,
      'approval event operator hash',
      'APPROVAL_CORRUPTION',
    );
    if (operatorIdHash !== record.operatorIdHash) {
      fail('APPROVAL_CORRUPTION', 'approval.approved operator binding changed');
    }
    at = timestamp(data.approvedAt, 'approval event approvedAt', 'APPROVAL_CORRUPTION');
  } else if (eventType === 'approval.denied') {
    data = eventData(row, [
      'intentId', 'intentHash', 'operatorIdHash', 'reasonCode', 'deniedAt',
    ], 'approval.denied event');
    exactApprovalEventBinding(data, record);
    const operatorIdHash = canonicalHash(
      data.operatorIdHash,
      'approval denial event operator hash',
      'APPROVAL_CORRUPTION',
    );
    const reasonCode = boundedToken(
      data.reasonCode,
      'approval denial event reason',
      'APPROVAL_CORRUPTION',
    );
    if (operatorIdHash !== record.operatorIdHash || reasonCode !== record.reasonCode) {
      fail('APPROVAL_CORRUPTION', 'approval.denied event binding changed');
    }
    at = timestamp(data.deniedAt, 'approval event deniedAt', 'APPROVAL_CORRUPTION');
  } else if (eventType === 'approval.expired') {
    data = eventData(row, [
      'intentId', 'intentHash', 'previousDecision', 'reasonCode', 'expiredAt',
    ], 'approval.expired event');
    exactApprovalEventBinding(data, record);
    previousDecision = data.previousDecision;
    if (!OPEN_DECISIONS.has(previousDecision)
        || data.reasonCode !== 'APPROVAL_EXPIRED'
        || record.reasonCode !== 'APPROVAL_EXPIRED') {
      fail('APPROVAL_CORRUPTION', 'approval.expired event binding changed');
    }
    at = timestamp(data.expiredAt, 'approval event expiredAt', 'APPROVAL_CORRUPTION');
  } else if (eventType === 'approval.cancelled') {
    data = eventData(row, [
      'intentId', 'intentHash', 'previousDecision', 'reasonCode', 'cancelledAt',
    ], 'approval.cancelled event');
    exactApprovalEventBinding(data, record);
    previousDecision = data.previousDecision;
    if (!OPEN_DECISIONS.has(previousDecision)
        || !CANCEL_REASONS.has(data.reasonCode)
        || data.reasonCode !== record.reasonCode) {
      fail('APPROVAL_CORRUPTION', 'approval.cancelled event binding changed');
    }
    at = timestamp(data.cancelledAt, 'approval event cancelledAt', 'APPROVAL_CORRUPTION');
  } else {
    data = eventData(row, [
      'intentId', 'intentHash', 'consumedAt',
    ], 'approval.consumed event');
    exactApprovalEventBinding(data, record);
    at = timestamp(data.consumedAt, 'approval event consumedAt', 'APPROVAL_CORRUPTION');
  }
  if (Date.parse(at) > Date.parse(createdAt)) {
    fail('APPROVAL_CORRUPTION', 'approval transition event predates its recorded fact');
  }
  return Object.freeze({ at, createdAt, eventType, previousDecision });
}

function validateApprovalLifecycle(db, authority, record) {
  try {
    const events = approvalEventRows(db, record.approvalId).map(
      (row) => approvalLifecycleEvent(
        approvalEventEnvelope(row, record.approvalId),
        record,
      ),
    );
    const terminal = events.at(-1) ?? null;
    let expectedTypes;
    if (record.decision === 'pending') {
      expectedTypes = ['approval.requested'];
    } else if (record.decision === 'approved') {
      expectedTypes = ['approval.requested', 'approval.approved'];
    } else if (record.decision === 'denied') {
      expectedTypes = ['approval.requested', 'approval.denied'];
    } else if (record.decision === 'consumed') {
      expectedTypes = ['approval.requested', 'approval.approved', 'approval.consumed'];
    } else if (terminal?.previousDecision === 'pending') {
      expectedTypes = ['approval.requested', `approval.${record.decision}`];
    } else if (terminal?.previousDecision === 'approved') {
      expectedTypes = [
        'approval.requested',
        'approval.approved',
        `approval.${record.decision}`,
      ];
    } else {
      fail('APPROVAL_CORRUPTION', 'approval terminal event has no legal predecessor');
    }
    if (canonicalJson(events.map((event) => event.eventType)) !== canonicalJson(expectedTypes)) {
      fail('APPROVAL_CORRUPTION', 'approval event lifecycle is missing, duplicated, or reordered');
    }

    const requestedAt = events[0].at;
    if (Date.parse(requestedAt) < Date.parse(authority.decidedAt)
        || Date.parse(requestedAt) >= Date.parse(record.expiresAt)) {
      fail('APPROVAL_CORRUPTION', 'approval request chronology is invalid');
    }
    let predecessorAt = requestedAt;
    let predecessorCreatedAt = events[0].createdAt;
    for (const event of events.slice(1)) {
      if (Date.parse(event.at) < Date.parse(predecessorAt)
          || Date.parse(event.createdAt) < Date.parse(predecessorCreatedAt)) {
        fail('APPROVAL_CORRUPTION', 'approval event chronology regressed');
      }
      predecessorAt = event.at;
      predecessorCreatedAt = event.createdAt;
    }

    const approved = events.find((event) => event.eventType === 'approval.approved') ?? null;
    if (record.decision === 'approved' || record.decision === 'consumed') {
      if (approved?.at !== record.decidedAt) {
        fail('APPROVAL_CORRUPTION', 'approval row differs from its approval event');
      }
    } else if (record.decision !== 'pending' && terminal?.at !== record.decidedAt) {
      fail('APPROVAL_CORRUPTION', 'approval row differs from its terminal event');
    }
    if (record.decision === 'consumed' && terminal?.at !== record.consumedAt) {
      fail('APPROVAL_CORRUPTION', 'consumed approval differs from its event');
    }
    if (approved && Date.parse(approved.at) >= Date.parse(record.expiresAt)) {
      fail('APPROVAL_CORRUPTION', 'approval event occurred after immutable expiry');
    }
    if (record.decision === 'denied' && Date.parse(terminal.at) >= Date.parse(record.expiresAt)) {
      fail('APPROVAL_CORRUPTION', 'approval denial occurred after immutable expiry');
    }
    if (record.decision === 'consumed'
        && Date.parse(record.consumedAt) >= Date.parse(record.expiresAt)) {
      fail('APPROVAL_CORRUPTION', 'approval consumption occurred after immutable expiry');
    }
    if (record.decision === 'expired'
        && Date.parse(terminal.at) < Date.parse(record.expiresAt)) {
      fail('APPROVAL_CORRUPTION', 'approval expired before its immutable deadline');
    }
    if ((record.decision === 'expired' || record.decision === 'cancelled')) {
      if (terminal.previousDecision === 'pending' && record.operatorIdHash !== null) {
        fail('APPROVAL_CORRUPTION', 'pending approval terminal event gained an operator');
      }
      if (terminal.previousDecision === 'approved'
          && (!approved || record.operatorIdHash === null)) {
        fail('APPROVAL_CORRUPTION', 'approved terminal event lost its operator authority');
      }
    }
    return Object.freeze({
      approvedAt: approved?.at ?? null,
      lastTransitionAt: predecessorAt,
      requestedAt,
    });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'persisted approval lifecycle events are invalid');
  }
}

function rowToRecord(row) {
  if (!row) return null;
  try {
    const decision = row.decision;
    if (!DECISIONS.has(decision)) {
      fail('APPROVAL_CORRUPTION', 'persisted approval decision is invalid');
    }
    const operatorIdHash = row.operator_id_hash === null
      ? null
      : canonicalHash(row.operator_id_hash, 'approval operator hash', 'APPROVAL_CORRUPTION');
    const reasonCode = row.reason_code === null
      ? null
      : boundedToken(row.reason_code, 'approval reason code', 'APPROVAL_CORRUPTION');
    const decidedAt = row.decided_at === null
      ? null
      : timestamp(row.decided_at, 'approval decidedAt', 'APPROVAL_CORRUPTION');
    const consumedAt = row.consumed_at === null
      ? null
      : timestamp(row.consumed_at, 'approval consumedAt', 'APPROVAL_CORRUPTION');
    const expiresAt = timestamp(row.expires_at, 'approval expiresAt', 'APPROVAL_CORRUPTION');

    const lifecycleValid = (decision === 'pending'
        && operatorIdHash === null && reasonCode === null
        && decidedAt === null && consumedAt === null)
      || (decision === 'approved'
        && operatorIdHash !== null && reasonCode === null
        && decidedAt !== null && consumedAt === null)
      || (decision === 'denied'
        && operatorIdHash !== null && reasonCode !== null
        && decidedAt !== null && consumedAt === null)
      || (decision === 'expired'
        && reasonCode === 'APPROVAL_EXPIRED'
        && decidedAt !== null && consumedAt === null)
      || (decision === 'cancelled'
        && CANCEL_REASONS.has(reasonCode)
        && decidedAt !== null && consumedAt === null)
      || (decision === 'consumed'
        && operatorIdHash !== null && reasonCode === null
        && decidedAt !== null && consumedAt !== null);
    if (!lifecycleValid
        || (consumedAt !== null && Date.parse(consumedAt) < Date.parse(decidedAt))) {
      fail('APPROVAL_CORRUPTION', 'persisted approval lifecycle is invalid');
    }

    return frozenCopy({
      approvalId: canonicalToken(row.id, 'approval ID'),
      intentId: canonicalToken(row.intent_id, 'approval intent ID'),
      decision,
      operatorIdHash,
      intentHash: canonicalHash(row.intent_hash, 'approval intent hash'),
      challengeHash: canonicalHash(row.challenge_hash, 'approval challenge hash'),
      quoteId: canonicalHash(row.quote_id, 'approval quote ID'),
      acceptedIndex: canonicalIndex(
        row.accepted_index,
        'approval accepted index',
        'APPROVAL_CORRUPTION',
      ),
      amountCeilingAtomic: canonicalAtomic(
        row.amount_ceiling_atomic,
        'approval amount ceiling',
      ).text,
      walletAddress: canonicalAddress(
        row.wallet_address,
        'approval wallet',
        'APPROVAL_CORRUPTION',
      ),
      policyVersionId: canonicalToken(row.policy_version_id, 'approval policy version ID'),
      expiresAt,
      reasonCode,
      decidedAt,
      consumedAt,
    });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'APPROVAL_CORRUPTION') throw error;
    fail('APPROVAL_CORRUPTION', 'persisted approval row is invalid');
  }
}

function validatedRecord(db, row) {
  const record = rowToRecord(row);
  if (!record) return null;
  const authority = loadAuthority(db, record.intentId);
  if (!authority
      || canonicalJson(recordBinding(record)) !== canonicalJson(authority.binding)
      || record.policyVersionId !== authority.binding.policyVersionId
      || (record.decidedAt !== null && Date.parse(record.decidedAt) < Date.parse(authority.decidedAt))
      || (record.decision === 'approved' && Date.parse(record.decidedAt) >= Date.parse(record.expiresAt))
      || (record.decision === 'consumed' && Date.parse(record.consumedAt) >= Date.parse(record.expiresAt))) {
    fail('APPROVAL_CORRUPTION', 'persisted approval differs from its immutable authority');
  }
  const lifecycle = validateApprovalLifecycle(db, authority, record);
  return Object.freeze({ authority, lifecycle, record });
}

function exactBindingOrFail(left, right) {
  if (canonicalJson(left) !== canonicalJson(right)) {
    fail('APPROVAL_BINDING_MISMATCH', 'approval binding differs from immutable spend authority');
  }
}

function approvalById(db, approvalId) {
  return db.prepare('SELECT * FROM approvals WHERE id = ?').get(approvalId);
}

function approvalByIntent(db, intentId) {
  return db.prepare('SELECT * FROM approvals WHERE intent_id = ?').get(intentId);
}

function transitionTime(now, authority, label, predecessorAt = authority.decidedAt) {
  const at = nowTimestamp(now, label);
  if (Date.parse(at) < Date.parse(authority.decidedAt)
      || Date.parse(at) < Date.parse(predecessorAt)) {
    fail('APPROVAL_TIME', 'approval transition predates its authoritative predecessor');
  }
  return at;
}

export function createApprovalQueue({ store, idFactory, now }) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('approval queue requires a Wallet Kernel store');
  }
  if (typeof idFactory !== 'function' || utilTypes.isProxy(idFactory)) {
    throw new TypeError('approval queue requires an ID factory');
  }
  if (typeof now !== 'function' || utilTypes.isProxy(now)) {
    throw new TypeError('approval queue requires a clock');
  }

  const requestInTransaction = (token, value) => store.within(
    token,
    ({ db, appendEvent }) => {
      const requested = requestInput(value);
      const authority = loadAuthority(db, requested.intentId);
      if (!authority) {
        fail('APPROVAL_BINDING_MISMATCH', 'approval SpendIntent does not exist');
      }
      exactBindingOrFail(
        { ...requested, expiresAt: authority.binding.expiresAt },
        authority.binding,
      );

      const existingRow = approvalByIntent(db, requested.intentId);
      if (existingRow) return validatedRecord(db, existingRow).record;
      if (authority.intentState !== 'challenged'
          || authority.sessionState !== 'open'
          || authority.enrollmentState !== 'active'
          || authority.activePolicyId !== authority.binding.policyVersionId) {
        fail('APPROVAL_AUTHORITY_INACTIVE', 'new approval authority is not active');
      }

      const requestedAt = transitionTime(now, authority, 'approval requestedAt');
      if (Date.parse(requestedAt) >= Date.parse(authority.binding.expiresAt)) {
        fail('APPROVAL_EXPIRED', 'approval authority is already expired');
      }
      const pending = db.prepare(
        "SELECT COUNT(*) AS count FROM approvals WHERE decision = 'pending'",
      ).get().count;
      if (BigInt(pending) >= BigInt(authority.policy.maxPendingApprovals)) {
        fail('APPROVAL_CAPACITY', 'pending approval capacity is exhausted');
      }

      const approvalId = boundedToken(
        idFactory('approval'),
        'approval ID',
        'ID_FACTORY',
      );
      if (approvalById(db, approvalId)) {
        fail('APPROVAL_ID_CONFLICT', 'approval ID is already bound');
      }
      const binding = authority.binding;
      db.prepare(`INSERT INTO approvals
        (id, intent_id, decision, intent_hash, challenge_hash, quote_id,
         accepted_index, amount_ceiling_atomic, wallet_address,
         policy_version_id, expires_at)
        VALUES (?, ?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        approvalId,
        binding.intentId,
        binding.intentHash,
        binding.challengeHash,
        binding.quoteId,
        binding.acceptedIndex,
        binding.amountCeilingAtomic,
        binding.walletAddress,
        binding.policyVersionId,
        binding.expiresAt,
      );
      appendEvent({
        entityType: 'approval',
        entityId: approvalId,
        eventType: 'approval.requested',
        data: {
          ...binding,
          requestedAt,
        },
      });
      return validatedRecord(db, approvalById(db, approvalId)).record;
    },
  );

  const request = (binding) => store.transaction(
    (token) => requestInTransaction(token, binding),
  );

  const get = (approvalId) => {
    const id = canonicalToken(approvalId, 'approval ID');
    return store.transaction((token) => store.within(token, ({ db }) => {
      const row = approvalById(db, id);
      return row ? validatedRecord(db, row).record : null;
    }));
  };

  const list = (value) => {
    const input = exactRecord(
      value,
      ['limit'],
      ['state'],
      'APPROVAL_LIST_SCHEMA',
      'approval list query',
    );
    const limit = canonicalLimit(input.limit);
    const state = Object.hasOwn(input, 'state') ? input.state : null;
    if (state !== null && !DECISIONS.has(state)) {
      fail('APPROVAL_LIST_SCHEMA', 'approval list state is invalid');
    }
    return store.transaction((token) => store.within(token, ({ db }) => {
      const rows = state === null
        ? db.prepare('SELECT * FROM approvals ORDER BY expires_at, id LIMIT ?').all(limit)
        : db.prepare(`SELECT * FROM approvals
          WHERE decision = ? ORDER BY expires_at, id LIMIT ?`).all(state, limit);
      return Object.freeze(rows.map((row) => validatedRecord(db, row).record));
    }));
  };

  const approve = (value) => store.transaction((token) => store.within(
    token,
    ({ db, appendEvent }) => {
      const input = exactRecord(value, [
        'approvalId',
        'expectedIntentHash',
        'operatorIdHash',
      ], [], 'APPROVAL_DECISION_SCHEMA', 'approval decision');
      const approvalId = boundedToken(
        input.approvalId,
        'approval ID',
        'APPROVAL_DECISION_SCHEMA',
      );
      const expectedIntentHash = canonicalHash(
        input.expectedIntentHash,
        'expected approval intent hash',
        'APPROVAL_DECISION_SCHEMA',
      );
      const operatorIdHash = canonicalHash(
        input.operatorIdHash,
        'approval operator hash',
        'APPROVAL_DECISION_SCHEMA',
      );
      const currentRow = approvalById(db, approvalId);
      if (!currentRow) fail('APPROVAL_UNKNOWN', 'approval does not exist');
      const current = validatedRecord(db, currentRow);
      if (current.record.intentHash !== expectedIntentHash) {
        fail('APPROVAL_BINDING_MISMATCH', 'displayed intent hash is stale');
      }
      if (current.record.decision !== 'pending') {
        fail('APPROVAL_STATE_CONFLICT', 'approval is no longer pending');
      }
      const approvedAt = transitionTime(
        now,
        current.authority,
        'approval approvedAt',
        current.lifecycle.lastTransitionAt,
      );
      if (Date.parse(approvedAt) >= Date.parse(current.record.expiresAt)) {
        fail('APPROVAL_EXPIRED', 'approval expired before the operator decision');
      }
      const changed = db.prepare(`UPDATE approvals
        SET decision = 'approved', operator_id_hash = ?, decided_at = ?
        WHERE id = ? AND intent_hash = ? AND decision = 'pending' AND expires_at > ?`).run(
        operatorIdHash,
        approvedAt,
        approvalId,
        expectedIntentHash,
        approvedAt,
      );
      if (changed.changes !== 1n) {
        fail('APPROVAL_STATE_CONFLICT', 'approval decision lost its conditional update');
      }
      appendEvent({
        entityType: 'approval',
        entityId: approvalId,
        eventType: 'approval.approved',
        data: {
          intentId: current.record.intentId,
          intentHash: expectedIntentHash,
          operatorIdHash,
          approvedAt,
        },
      });
      return validatedRecord(db, approvalById(db, approvalId)).record;
    },
  ));

  const listDue = (value) => {
    const input = exactRecord(
      value,
      ['at', 'limit'],
      [],
      'APPROVAL_LIST_SCHEMA',
      'approval due query',
    );
    const at = timestamp(input.at, 'approval due time', 'APPROVAL_LIST_SCHEMA');
    const limit = canonicalLimit(input.limit);
    return store.transaction((token) => store.within(token, ({ db }) => {
      const rows = db.prepare(`SELECT approvals.* FROM approvals
        JOIN spend_intents ON spend_intents.id = approvals.intent_id
        WHERE (approvals.decision = 'pending' OR approvals.decision = 'approved')
          AND spend_intents.state = 'approval_pending'
          AND spend_intents.retry_matchable = 1
          AND approvals.expires_at <= ?
        ORDER BY approvals.expires_at, approvals.id LIMIT ?`).all(at, limit);
      return Object.freeze(rows.map((row) => {
        const record = validatedRecord(db, row).record;
        return Object.freeze({
          approvalId: record.approvalId,
          intentId: record.intentId,
          intentHash: record.intentHash,
        });
      }));
    }));
  };

  const findRetryable = (value) => {
    const input = exactRecord(value, [
      'sessionId',
      'intentHash',
    ], [], 'APPROVAL_RETRY_SCHEMA', 'approval retry lookup');
    const sessionId = boundedToken(
      input.sessionId,
      'approval retry session ID',
      'APPROVAL_RETRY_SCHEMA',
    );
    const intentHash = canonicalHash(
      input.intentHash,
      'approval retry intent hash',
      'APPROVAL_RETRY_SCHEMA',
    );
    return store.transaction((token) => store.within(token, ({ db }) => {
      const rows = db.prepare(`SELECT approvals.* FROM approvals
        JOIN spend_intents ON spend_intents.id = approvals.intent_id
        WHERE spend_intents.session_id = ? AND spend_intents.intent_hash = ?
          AND (approvals.decision = 'pending' OR approvals.decision = 'approved')
          AND spend_intents.state = 'approval_pending'
          AND spend_intents.retry_matchable = 1
        ORDER BY approvals.id`).all(sessionId, intentHash);
      if (rows.length > 1) fail('APPROVAL_CORRUPTION', 'retry approval authority is ambiguous');
      return rows.length === 0 ? null : validatedRecord(db, rows[0]).record;
    }));
  };

  const expireLoaded = ({ db, appendEvent }, current, at) => {
    if (!OPEN_DECISIONS.has(current.record.decision)) return null;
    if (Date.parse(at) < Date.parse(current.record.expiresAt)) {
      fail('APPROVAL_NOT_DUE', 'approval has not reached its immutable expiry');
    }
    if (Date.parse(at) < Date.parse(current.authority.decidedAt)
        || Date.parse(at) < Date.parse(current.lifecycle.lastTransitionAt)) {
      fail('APPROVAL_TIME', 'approval expiry predates its authoritative predecessor');
    }
    const previousDecision = current.record.decision;
    const changed = db.prepare(`UPDATE approvals
      SET decision = 'expired', reason_code = 'APPROVAL_EXPIRED', decided_at = ?
      WHERE id = ? AND intent_id = ? AND intent_hash = ?
        AND decision = ? AND expires_at <= ?`).run(
      at,
      current.record.approvalId,
      current.record.intentId,
      current.record.intentHash,
      previousDecision,
      at,
    );
    if (changed.changes !== 1n) {
      fail('APPROVAL_STATE_CONFLICT', 'approval expiry lost its conditional update');
    }
    appendEvent({
      entityType: 'approval',
      entityId: current.record.approvalId,
      eventType: 'approval.expired',
      data: {
        intentId: current.record.intentId,
        intentHash: current.record.intentHash,
        previousDecision,
        reasonCode: 'APPROVAL_EXPIRED',
        expiredAt: at,
      },
    });
    return validatedRecord(db, approvalById(db, current.record.approvalId)).record;
  };

  const consumeForInTransaction = (token, value) => store.within(
    token,
    ({ db, appendEvent }) => {
      const binding = consumptionInput(value);
      const row = approvalByIntent(db, binding.intentId);
      if (!row) {
        fail('APPROVAL_BINDING_MISMATCH', 'approval does not exist for the exact SpendIntent');
      }
      const current = validatedRecord(db, row);
      exactBindingOrFail(binding, current.authority.binding);
      if (current.record.decision !== 'approved') return null;
      const consumedAt = transitionTime(
        now,
        current.authority,
        'approval consumedAt',
        current.lifecycle.lastTransitionAt,
      );
      if (Date.parse(consumedAt) >= Date.parse(current.record.expiresAt)) {
        expireLoaded({ db, appendEvent }, current, consumedAt);
        return null;
      }
      if (Date.parse(consumedAt) < Date.parse(current.record.decidedAt)) {
        fail('APPROVAL_TIME', 'approval consumption predates operator approval');
      }
      const changed = db.prepare(`UPDATE approvals
        SET decision = 'consumed', consumed_at = ?
        WHERE id = ? AND intent_id = ? AND intent_hash = ?
          AND decision = 'approved' AND expires_at > ?`).run(
        consumedAt,
        current.record.approvalId,
        current.record.intentId,
        current.record.intentHash,
        consumedAt,
      );
      if (changed.changes !== 1n) {
        fail('APPROVAL_STATE_CONFLICT', 'approval consumption lost its conditional update');
      }
      appendEvent({
        entityType: 'approval',
        entityId: current.record.approvalId,
        eventType: 'approval.consumed',
        data: {
          intentId: current.record.intentId,
          intentHash: current.record.intentHash,
          consumedAt,
        },
      });
      return validatedRecord(db, approvalById(db, current.record.approvalId)).record;
    },
  );

  const denyForIntentInTransaction = (token, value) => store.within(
    token,
    ({ db, appendEvent }) => {
      const input = exactRecord(value, [
        'approvalId',
        'intentId',
        'expectedIntentHash',
        'operatorIdHash',
        'reasonCode',
      ], [], 'APPROVAL_DECISION_SCHEMA', 'approval denial');
      const approvalId = boundedToken(
        input.approvalId,
        'approval ID',
        'APPROVAL_DECISION_SCHEMA',
      );
      const intentId = boundedToken(
        input.intentId,
        'approval intent ID',
        'APPROVAL_DECISION_SCHEMA',
      );
      const expectedIntentHash = canonicalHash(
        input.expectedIntentHash,
        'expected approval intent hash',
        'APPROVAL_DECISION_SCHEMA',
      );
      const operatorIdHash = canonicalHash(
        input.operatorIdHash,
        'approval operator hash',
        'APPROVAL_DECISION_SCHEMA',
      );
      const reasonCode = boundedToken(
        input.reasonCode,
        'approval denial reason',
        'APPROVAL_DECISION_SCHEMA',
      );
      const row = approvalById(db, approvalId);
      if (!row) fail('APPROVAL_UNKNOWN', 'approval does not exist');
      const current = validatedRecord(db, row);
      if (current.record.intentId !== intentId
          || current.record.intentHash !== expectedIntentHash) {
        fail('APPROVAL_BINDING_MISMATCH', 'displayed approval binding is stale');
      }
      if (current.record.decision !== 'pending') {
        fail('APPROVAL_STATE_CONFLICT', 'only a pending approval can be denied');
      }
      const deniedAt = transitionTime(
        now,
        current.authority,
        'approval deniedAt',
        current.lifecycle.lastTransitionAt,
      );
      if (Date.parse(deniedAt) >= Date.parse(current.record.expiresAt)) {
        fail('APPROVAL_EXPIRED', 'approval expired before denial');
      }
      const changed = db.prepare(`UPDATE approvals
        SET decision = 'denied', operator_id_hash = ?, reason_code = ?, decided_at = ?
        WHERE id = ? AND intent_id = ? AND intent_hash = ?
          AND decision = 'pending' AND expires_at > ?`).run(
        operatorIdHash,
        reasonCode,
        deniedAt,
        approvalId,
        intentId,
        expectedIntentHash,
        deniedAt,
      );
      if (changed.changes !== 1n) {
        fail('APPROVAL_STATE_CONFLICT', 'approval denial lost its conditional update');
      }
      appendEvent({
        entityType: 'approval',
        entityId: approvalId,
        eventType: 'approval.denied',
        data: {
          intentId,
          intentHash: expectedIntentHash,
          operatorIdHash,
          reasonCode,
          deniedAt,
        },
      });
      return validatedRecord(db, approvalById(db, approvalId)).record;
    },
  );

  const expireForIntentInTransaction = (token, value) => store.within(
    token,
    ({ db, appendEvent }) => {
      const input = exactRecord(value, [
        'approvalId',
        'intentId',
        'expectedIntentHash',
        'at',
      ], [], 'APPROVAL_EXPIRY_SCHEMA', 'approval expiry');
      const approvalId = boundedToken(
        input.approvalId,
        'approval ID',
        'APPROVAL_EXPIRY_SCHEMA',
      );
      const intentId = boundedToken(
        input.intentId,
        'approval intent ID',
        'APPROVAL_EXPIRY_SCHEMA',
      );
      const expectedIntentHash = canonicalHash(
        input.expectedIntentHash,
        'expected approval intent hash',
        'APPROVAL_EXPIRY_SCHEMA',
      );
      const at = timestamp(input.at, 'approval expiry time', 'APPROVAL_EXPIRY_SCHEMA');
      const row = approvalById(db, approvalId);
      if (!row) fail('APPROVAL_UNKNOWN', 'approval does not exist');
      const current = validatedRecord(db, row);
      if (current.record.intentId !== intentId
          || current.record.intentHash !== expectedIntentHash) {
        fail('APPROVAL_BINDING_MISMATCH', 'displayed approval binding is stale');
      }
      return expireLoaded({ db, appendEvent }, current, at);
    },
  );

  const cancelForIntentInTransaction = (token, value) => store.within(
    token,
    ({ db, appendEvent }) => {
      const input = exactRecord(value, [
        'intentId',
        'reasonCode',
      ], [], 'APPROVAL_CANCEL_SCHEMA', 'approval cancellation');
      const intentId = boundedToken(
        input.intentId,
        'approval intent ID',
        'APPROVAL_CANCEL_SCHEMA',
      );
      if (!CANCEL_REASONS.has(input.reasonCode)) {
        fail('APPROVAL_CANCEL_REASON', 'approval cancellation reason is not allowed');
      }
      const row = approvalByIntent(db, intentId);
      if (!row) return null;
      const current = validatedRecord(db, row);
      if (!OPEN_DECISIONS.has(current.record.decision)) return null;
      const cancelledAt = transitionTime(
        now,
        current.authority,
        'approval cancelledAt',
        current.lifecycle.lastTransitionAt,
      );
      const changed = db.prepare(`UPDATE approvals
        SET decision = 'cancelled', reason_code = ?, decided_at = ?
        WHERE id = ? AND intent_id = ? AND intent_hash = ? AND decision = ?`).run(
        input.reasonCode,
        cancelledAt,
        current.record.approvalId,
        intentId,
        current.record.intentHash,
        current.record.decision,
      );
      if (changed.changes !== 1n) {
        fail('APPROVAL_STATE_CONFLICT', 'approval cancellation lost its conditional update');
      }
      appendEvent({
        entityType: 'approval',
        entityId: current.record.approvalId,
        eventType: 'approval.cancelled',
        data: {
          intentId,
          intentHash: current.record.intentHash,
          previousDecision: current.record.decision,
          reasonCode: input.reasonCode,
          cancelledAt,
        },
      });
      return validatedRecord(db, approvalById(db, current.record.approvalId)).record;
    },
  );

  return Object.freeze({
    request,
    requestInTransaction,
    get,
    list,
    approve,
    listDue,
    findRetryable,
    consumeForInTransaction,
    denyForIntentInTransaction,
    expireForIntentInTransaction,
    cancelForIntentInTransaction,
  });
}

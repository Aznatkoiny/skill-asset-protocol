import { types as utilTypes } from 'node:util';

import { WalletSigningError } from '../adapters/wallet-adapter-contract.mjs';
import {
  canonicalAtomic,
  canonicalEvmHash,
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

const DAY_MS = 24 * 60 * 60 * 1_000;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const DECIMAL_PATTERN = /^(0|[1-9][0-9]*)$/;

function fail(code, message) {
  throw new KernelError(code, message);
}

function closedInput(value, required, optional, code, label) {
  return exactRecord(value, required, optional, code, label);
}

function canonicalHash(value, label, code = 'BUDGET_CORRUPTION') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalEvmHashFor(value, label, code) {
  try {
    return canonicalEvmHash(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} is invalid`);
    throw error;
  }
}

function canonicalAddress(value, label, code = 'BUDGET_CORRUPTION') {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical lowercase EVM address`);
  }
  return value;
}

function canonicalOrigin(value, label, code = 'BUDGET_SCHEMA') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048) {
    fail(code, `${label} must be one bounded canonical origin`);
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(code, `${label} must be one canonical origin`);
  }
  const loopback = parsed.protocol === 'http:'
    && /^(?:127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(parsed.host);
  if ((parsed.protocol !== 'https:' && !loopback)
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.pathname !== '/'
      || parsed.search !== ''
      || parsed.hash !== ''
      || parsed.origin !== value) {
    fail(code, `${label} must be one canonical HTTPS or literal-loopback origin`);
  }
  return value;
}

function canonicalPersistedTimestamp(value, label, code = 'BUDGET_CORRUPTION') {
  try {
    return canonicalTimestamp(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} is not canonical`);
    throw error;
  }
}

function canonicalAtomicText(value, label, code = 'BUDGET_CORRUPTION') {
  try {
    return canonicalAtomic(value, label);
  } catch (error) {
    if (error instanceof KernelError) fail(code, `${label} is not canonical atomic text`);
    throw error;
  }
}

function safeInteger(value, label, code = 'BUDGET_CORRUPTION') {
  const number = typeof value === 'bigint' ? Number(value) : value;
  let exact = false;
  try {
    exact = Number.isSafeInteger(number) && number >= 0 && BigInt(number) === BigInt(value);
  } catch {
    exact = false;
  }
  if (!exact) {
    fail(code, `${label} must be one nonnegative safe integer`);
  }
  return number;
}

function assertTransitionChronology(transitionAt, entries) {
  const transition = canonicalPersistedTimestamp(
    transitionAt,
    'authoritative transition time',
    'BUDGET_CORRUPTION',
  );
  const transitionMilliseconds = Date.parse(transition);
  for (const [label, value] of entries) {
    if (value === null || value === undefined) continue;
    const timestamp = canonicalPersistedTimestamp(value, label, 'BUDGET_CORRUPTION');
    if (Date.parse(timestamp) > transitionMilliseconds) {
      fail('BUDGET_TIME', `${label} is later than the authoritative transition clock`);
    }
  }
}

function attemptChronology(attempt) {
  return [
    ['PaymentAttempt createdAt', attempt.created_at],
    ['PaymentAttempt updatedAt', attempt.updated_at],
    ['PaymentAttempt signingClaimedAt', attempt.signing_claimed_at],
    ['PaymentAttempt signedAt', attempt.signed_at],
    ['PaymentAttempt retryStartedAt', attempt.retry_started_at],
    ['PaymentAttempt settledAt', attempt.settled_at],
  ];
}

function parseCanonicalJson(value, label, code = 'BUDGET_CORRUPTION') {
  if (typeof value !== 'string') fail(code, `${label} must be canonical JSON text`);
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    fail(code, `${label} is not valid JSON`);
  }
  if (canonicalJson(parsed) !== value) fail(code, `${label} is not canonical JSON`);
  return parsed;
}

function localAttemptBindingHash(authority, attempt) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-attempt-binding.v1',
    intentHash: authority.intent.intent_hash,
    challengeHash: authority.intent.challenge_hash,
    quoteId: attempt.quote_id,
    paymentPayloadHash: sha256(attempt.payment_payload_json),
    paymentHeaderHash: attempt.payment_hash,
    network: authority.policyVersion.policy.network,
    payer: authority.session.wallet_address,
    payee: authority.projection.selected.payTo,
    asset: authority.policyVersion.policy.asset,
    amountAtomic: authority.amount.text,
    nonce: attempt.nonce,
    validAfter: attempt.valid_after,
    validBefore: attempt.valid_before,
  }));
}

function localRefundBindingHash(authority, attempt, refundTransactionId) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-binding.v1',
    intentHash: authority.intent.intent_hash,
    originalTransactionId: attempt.transaction_id,
    refundTransactionId,
    network: authority.policyVersion.policy.network,
    sellerOrigin: authority.intent.seller_origin,
    asset: authority.policyVersion.policy.asset,
    originalPayer: authority.session.wallet_address,
    originalPayee: authority.projection.selected.payTo,
    refundSource: authority.projection.seller.refundSource,
    refundSigner: authority.projection.seller.refundSigner,
    amountAtomic: authority.amount.text,
  }));
}

function assertGloballyUniqueTransaction(db, transactionId, {
  allowedPaymentIntentId = null,
  allowedPaymentCandidateId = null,
  allowedRefundId = null,
} = {}) {
  const groups = [
    {
      rows: db.prepare(`SELECT intent_id AS owner_id, transaction_id
        FROM payment_attempts WHERE transaction_id IS NOT NULL`).all(),
      allowedOwnerId: allowedPaymentIntentId,
      label: 'persisted payment transaction',
    },
    {
      rows: db.prepare(`SELECT id AS owner_id, transaction_id
        FROM payment_reconciliation_candidates`).all(),
      allowedOwnerId: allowedPaymentCandidateId,
      label: 'persisted payment candidate transaction',
    },
    {
      rows: db.prepare(`SELECT id AS owner_id, refund_transaction_id AS transaction_id
        FROM refunds WHERE refund_transaction_id IS NOT NULL`).all(),
      allowedOwnerId: allowedRefundId,
      label: 'persisted refund transaction',
    },
  ];
  for (const group of groups) {
    for (const row of group.rows) {
      const canonical = canonicalEvmHashFor(
        row.transaction_id,
        group.label,
        'TRANSACTION_BINDING_CORRUPTION',
      );
      if (row.transaction_id !== canonical) {
        fail('TRANSACTION_BINDING_CORRUPTION', `${group.label} is not canonical lowercase`);
      }
      if (canonical === transactionId && row.owner_id !== group.allowedOwnerId) {
        fail('TRANSACTION_REUSED', 'transaction is already bound to another authority row');
      }
    }
  }
}

function loadPolicyVersion(db, policyVersionId) {
  const id = canonicalToken(policyVersionId, 'policy version ID');
  const row = db.prepare('SELECT * FROM policy_versions WHERE id = ?').get(id);
  if (!row) fail('POLICY_DECISION_MISSING', 'PolicyVersion does not exist');
  const parsed = parseCanonicalJson(row.canonical_json, 'persisted policy JSON');
  let policy;
  try {
    policy = validatePolicyDocument(parsed);
  } catch (error) {
    if (error instanceof KernelError) fail('BUDGET_CORRUPTION', 'persisted policy is invalid');
    throw error;
  }
  const bytes = canonicalJson(policy);
  const hash = sha256(bytes);
  if (bytes !== row.canonical_json
      || hash !== row.policy_hash
      || Number(row.schema_version) !== policy.schemaVersion) {
    fail('BUDGET_CORRUPTION', 'persisted PolicyVersion binding changed');
  }
  if (row.predecessor_hash !== null) canonicalHash(row.predecessor_hash, 'policy predecessor');
  canonicalPersistedTimestamp(row.applied_at, 'policy appliedAt');
  return Object.freeze({ id, hash, policy });
}

function validateEnrollmentAndBinding(db, intent, session, { requireActive = true } = {}) {
  const enrollment = db.prepare(
    'SELECT * FROM agent_enrollments WHERE enrollment_hash = ?',
  ).get(intent.enrollment_hash);
  if (!enrollment) fail('AGENT_ENROLLMENT_REQUIRED', 'Spend Intent enrollment is missing');
  if (enrollment.state !== 'active' && enrollment.state !== 'revoked') {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment state is invalid');
  }
  if (requireActive && enrollment.state !== 'active') {
    fail('AGENT_REVOKED', 'Spend Intent enrollment is revoked');
  }
  const agentInstanceId = canonicalToken(enrollment.agent_instance_id, 'agent instance ID');
  const credentialDigest = canonicalHash(enrollment.credential_digest, 'credential digest');
  const enrollmentHash = canonicalHash(enrollment.enrollment_hash, 'enrollment hash');
  if (!/^[1-9][0-9]*$/.test(enrollment.agent_uid)
      || !/^[1-9][0-9]*$/.test(enrollment.agent_gid)
      || !Number.isSafeInteger(Number(enrollment.agent_uid))
      || !Number.isSafeInteger(Number(enrollment.agent_gid))) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted agent identity is invalid');
  }
  const descriptor = {
    schemaVersion: 1,
    agentInstanceId,
    credentialDigest,
    agentUid: enrollment.agent_uid,
    agentGid: enrollment.agent_gid,
  };
  if (sha256(canonicalJson(descriptor)) !== enrollmentHash
      || enrollmentHash !== intent.enrollment_hash) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment binding changed');
  }
  canonicalHash(enrollment.enrolled_by_operator_hash, 'enrollment operator hash');
  const enrolledAt = canonicalPersistedTimestamp(enrollment.enrolled_at, 'enrollment time');
  if (enrollment.state === 'active') {
    if (enrollment.revoked_by_operator_hash !== null || enrollment.revoked_at !== null) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'active enrollment has revocation fields');
    }
  } else {
    canonicalHash(enrollment.revoked_by_operator_hash, 'revocation operator hash');
    const revokedAt = canonicalPersistedTimestamp(enrollment.revoked_at, 'revocation time');
    if (Date.parse(revokedAt) < Date.parse(enrolledAt)) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'enrollment revocation predates enrollment');
    }
  }

  const bindings = db.prepare(
    'SELECT * FROM agent_session_bindings WHERE session_id = ? ORDER BY rowid',
  ).all(session.id);
  if (bindings.length !== 1) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session must have exactly one binding');
  }
  const binding = bindings[0];
  const sessionIsClosed = session.state === 'closed';
  if (binding.state !== (sessionIsClosed ? 'closed' : 'open')
      || binding.agent_instance_id !== agentInstanceId
      || binding.credential_digest !== credentialDigest
      || binding.enrollment_hash !== enrollmentHash
      || session.adapter_id !== `pi:${agentInstanceId}`) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session binding is not exact');
  }
  canonicalToken(binding.id, 'session binding ID');
  const createdAt = canonicalPersistedTimestamp(binding.created_at, 'binding createdAt');
  const lastSeenAt = canonicalPersistedTimestamp(binding.last_seen_at, 'binding lastSeenAt');
  const sessionClosedAt = session.closed_at === null
    ? null
    : canonicalPersistedTimestamp(session.closed_at, 'session closedAt');
  const bindingClosedAt = binding.closed_at === null
    ? null
    : canonicalPersistedTimestamp(binding.closed_at, 'binding closedAt');
  if (createdAt !== session.created_at
      || Date.parse(lastSeenAt) < Date.parse(createdAt)
      || (sessionIsClosed && (sessionClosedAt === null
        || bindingClosedAt !== sessionClosedAt || lastSeenAt !== sessionClosedAt))
      || (!sessionIsClosed && (sessionClosedAt !== null || bindingClosedAt !== null))) {
    fail('SESSION_AUTHORITY_AMBIGUOUS', 'Spend Session binding time changed');
  }
  return Object.freeze({ enrollmentHash, agentInstanceId });
}

function validateProjectionBinding(intent, decision, policyVersion) {
  if (typeof intent.challenge_projection_json !== 'string') {
    fail('POLICY_DECISION_CORRUPTION', 'authorized Spend Intent has no challenge projection');
  }
  const parsed = parseCanonicalJson(
    intent.challenge_projection_json,
    'Spend Intent challenge projection',
    'POLICY_DECISION_CORRUPTION',
  );
  let projection;
  try {
    projection = validateChallengeProjection(parsed);
  } catch (error) {
    if (error instanceof KernelError) {
      fail('POLICY_DECISION_CORRUPTION', 'Spend Intent challenge projection is invalid');
    }
    throw error;
  }
  const projectionBytes = canonicalJson(projection);
  const challengeHash = sha256(projectionBytes);
  const acceptedIndex = safeInteger(
    decision.accepted_index,
    'PolicyDecision accepted index',
    'POLICY_DECISION_CORRUPTION',
  );
  const selected = projection.accepts[acceptedIndex];
  const seller = policyVersion.policy.sellers.find(
    (candidate) => candidate.origin === intent.seller_origin,
  );
  if (projectionBytes !== intent.challenge_projection_json
      || challengeHash !== intent.challenge_hash
      || challengeHash !== decision.challenge_hash
      || decision.quote_id !== sha256(canonicalJson({ challengeHash, acceptedIndex }))
      || !selected
      || !seller
      || projection.x402Version !== 2
      || selected.scheme !== 'exact'
      || (Object.hasOwn(selected.extra, 'assetTransferMethod')
        && selected.extra.assetTransferMethod !== 'eip3009')
      || selected.extra.name !== 'USDC'
      || selected.extra.version !== '2'
      || selected.network !== policyVersion.policy.network
      || selected.asset !== policyVersion.policy.asset
      || selected.payTo !== seller.payTo
      || selected.amount !== decision.amount_ceiling_atomic
      || projection.resource.urlHash !== intent.request_url_hash
      || !seller.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
      || !policyVersion.policy.methods.includes(intent.method)) {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision no longer binds its exact challenge');
  }
  return Object.freeze({ projection, selected, seller, acceptedIndex, challengeHash });
}

function validateConsumedApproval(db, authority, at) {
  const rows = db.prepare('SELECT * FROM approvals WHERE intent_id = ? ORDER BY rowid')
    .all(authority.intent.id);
  if (authority.decision.decision === 'allow') {
    if (rows.length !== 0) {
      fail('APPROVAL_BINDING_MISMATCH', 'automatic PolicyDecision cannot consume approval');
    }
    return null;
  }
  if (rows.length !== 1) {
    fail('APPROVAL_REQUIRED', 'approval-required PolicyDecision needs one exact approval');
  }
  const approval = rows[0];
  const acceptedIndex = safeInteger(
    approval.accepted_index,
    'approval accepted index',
    'APPROVAL_BINDING_MISMATCH',
  );
  const expiresAt = canonicalPersistedTimestamp(
    approval.expires_at,
    'approval expiresAt',
    'APPROVAL_BINDING_MISMATCH',
  );
  const decidedAt = canonicalPersistedTimestamp(
    approval.decided_at,
    'approval decidedAt',
    'APPROVAL_BINDING_MISMATCH',
  );
  const consumedAt = canonicalPersistedTimestamp(
    approval.consumed_at,
    'approval consumedAt',
    'APPROVAL_BINDING_MISMATCH',
  );
  if (approval.decision !== 'consumed'
      || approval.intent_hash !== authority.intent.intent_hash
      || approval.challenge_hash !== authority.decision.challenge_hash
      || approval.quote_id !== authority.decision.quote_id
      || approval.amount_ceiling_atomic !== authority.decision.amount_ceiling_atomic
      || approval.wallet_address !== authority.session.wallet_address
      || approval.policy_version_id !== authority.policyVersion.id
      || acceptedIndex !== authority.projection.acceptedIndex
      || approval.operator_id_hash === null
      || approval.reason_code !== null
      || Date.parse(decidedAt) > Date.parse(consumedAt)
      || Date.parse(consumedAt) >= Date.parse(expiresAt)
      || Date.parse(at) < Date.parse(consumedAt)
      || Date.parse(at) >= Date.parse(expiresAt)) {
    fail('APPROVAL_BINDING_MISMATCH', 'consumed approval does not match exact spend authority');
  }
  canonicalToken(approval.id, 'approval ID');
  canonicalHash(
    approval.operator_id_hash,
    'approval operator hash',
    'APPROVAL_BINDING_MISMATCH',
  );
  return approval;
}

function loadReservationAuthority(db, intentId, { requireReservable = false, at } = {}) {
  const id = canonicalToken(intentId, 'intent ID');
  const intent = db.prepare('SELECT * FROM spend_intents WHERE id = ?').get(id);
  if (!intent) fail('INTENT_UNKNOWN', 'Spend Intent does not exist');
  const session = db.prepare('SELECT * FROM spend_sessions WHERE id = ?').get(intent.session_id);
  if (!session) fail('SESSION_UNKNOWN', 'Spend Session does not exist');
  const decision = db.prepare('SELECT * FROM policy_decisions WHERE intent_id = ?').get(id);
  if (!decision) fail('POLICY_DECISION_MISSING', 'Spend Intent has no PolicyDecision');
  const policyVersion = loadPolicyVersion(db, decision.policy_version_id);

  canonicalToken(session.id, 'session ID');
  canonicalOrigin(intent.seller_origin, 'persisted seller origin', 'BUDGET_CORRUPTION');
  canonicalAddress(session.wallet_address, 'session wallet');
  canonicalAddress(intent.wallet_address, 'intent wallet');
  canonicalHash(intent.enrollment_hash, 'intent enrollment hash');
  canonicalHash(intent.intent_hash, 'intent hash');
  canonicalHash(intent.challenge_hash, 'intent challenge hash');
  canonicalPersistedTimestamp(intent.created_at, 'intent createdAt');
  canonicalPersistedTimestamp(intent.updated_at, 'intent updatedAt');
  const challengeReceivedAt = canonicalPersistedTimestamp(
    intent.challenge_received_at,
    'intent challenge receivedAt',
  );
  canonicalPersistedTimestamp(session.created_at, 'session createdAt');
  const decidedAt = canonicalPersistedTimestamp(decision.decided_at, 'decision decidedAt');
  const amount = canonicalAtomicText(
    decision.amount_ceiling_atomic,
    'PolicyDecision amount ceiling',
    'POLICY_DECISION_CORRUPTION',
  );
  if (requireReservable && (decision.decision === 'deny' || amount.value === 0n)) {
    fail('POLICY_DENIED', 'denied or zero PolicyDecision cannot reserve money');
  }
  if (decision.decision !== 'allow' && decision.decision !== 'approval_required') {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision is not spend-authorizing');
  }
  if ((decision.decision === 'allow' && decision.reason_code !== 'WITHIN_AUTO_LIMIT')
      || (decision.decision === 'approval_required'
        && decision.reason_code !== 'HUMAN_APPROVAL_REQUIRED')) {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision reason is inconsistent');
  }
  const activePolicyId = db.prepare(
    'SELECT value FROM metadata WHERE key = ?',
  ).get('active_policy_id')?.value ?? null;
  if (session.policy_version_id !== policyVersion.id
      || decision.policy_version_id !== policyVersion.id
      || session.wallet_address !== policyVersion.policy.wallet
      || intent.wallet_address !== session.wallet_address) {
    fail('POLICY_DECISION_CORRUPTION', 'Spend authority is not aligned to active policy');
  }
  if (requireReservable && activePolicyId !== policyVersion.id) {
    fail('POLICY_NOT_ACTIVE', 'reservation requires the active PolicyVersion');
  }
  if (requireReservable && (intent.state !== 'authorized'
      || session.state !== 'open'
      || session.closed_at !== null)) {
    fail('INTENT_STATE_CONFLICT', 'reservation requires authorized intent in open session');
  }
  const enrollment = validateEnrollmentAndBinding(db, intent, session, {
    requireActive: requireReservable,
  });
  const projection = validateProjectionBinding(intent, decision, policyVersion);
  const amountValue = amount.value;
  const automatic = BigInt(projection.seller.autoApproveAtomic);
  const human = BigInt(projection.seller.humanApproveAtomic);
  const perRequest = BigInt(projection.seller.perRequestMaxAtomic);
  if (Date.parse(decidedAt) < Date.parse(challengeReceivedAt)
      || (decision.decision === 'allow' && amountValue > automatic)
      || (decision.decision === 'approval_required'
        && (amountValue <= automatic || amountValue > human || amountValue > perRequest))) {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision exceeds immutable policy authority');
  }
  if (requireReservable
      && (Date.parse(at) < Date.parse(challengeReceivedAt)
        || Date.parse(at) < Date.parse(decidedAt))) {
    fail('BUDGET_TIME', 'reservation clock predates its challenge or PolicyDecision');
  }
  if (requireReservable
      && Date.parse(at) - Date.parse(challengeReceivedAt)
        > policyVersion.policy.challengeMaxAgeMs) {
    fail('CHALLENGE_EXPIRED', 'Spend Intent challenge expired before reservation');
  }
  const authority = Object.freeze({
    intent,
    session,
    decision,
    policyVersion,
    projection,
    enrollment,
    amount,
  });
  if (requireReservable) validateConsumedApproval(db, authority, at);
  return authority;
}

function validateBudgetRow(row) {
  const intentId = canonicalToken(row.intent_id, 'budget intent ID');
  const sessionId = canonicalToken(row.session_id, 'budget session ID');
  const sellerOrigin = canonicalOrigin(
    row.seller_origin,
    'budget seller origin',
    'BUDGET_CORRUPTION',
  );
  const reserved = canonicalAtomicText(row.reserved_atomic, 'reserved amount');
  const committed = canonicalAtomicText(row.committed_atomic, 'committed amount');
  const released = canonicalAtomicText(row.released_atomic, 'released amount');
  const unresolved = canonicalAtomicText(row.unresolved_atomic, 'unresolved amount');
  const ceiling = canonicalAtomicText(row.decision_amount, 'decision amount');
  const updatedAt = canonicalPersistedTimestamp(row.updated_at, 'budget updatedAt');
  const committedAt = row.committed_at === null
    ? null
    : canonicalPersistedTimestamp(row.committed_at, 'budget committedAt');
  if (row.intent_session_id !== sessionId
      || row.intent_seller_origin !== sellerOrigin
      || row.intent_wallet_address !== row.session_wallet_address
      || reserved.value + committed.value + released.value + unresolved.value !== ceiling.value
      || ceiling.value <= 0n) {
    fail('BUDGET_CORRUPTION', 'BudgetReservation authority or conservation changed');
  }
  const dispositions = {
    reserved: [ceiling.value, 0n, 0n, 0n],
    committed: [0n, ceiling.value, 0n, 0n],
    released: [0n, 0n, ceiling.value, 0n],
    unresolved: [0n, 0n, 0n, ceiling.value],
  };
  const expected = dispositions[row.state];
  if (!expected
      || reserved.value !== expected[0]
      || committed.value !== expected[1]
      || released.value !== expected[2]
      || unresolved.value !== expected[3]
      || (row.state === 'committed' && committedAt === null)
      || ((row.state === 'reserved' || row.state === 'unresolved') && committedAt !== null)) {
    fail('BUDGET_CORRUPTION', 'BudgetReservation disposition is invalid');
  }
  return Object.freeze({
    intentId,
    sessionId,
    sellerOrigin,
    walletAddress: canonicalAddress(row.session_wallet_address, 'budget wallet'),
    reserved,
    committed,
    released,
    unresolved,
    ceiling,
    state: row.state,
    committedAt,
    updatedAt,
  });
}

const BUDGET_ROWS_SQL = `SELECT budget_reservations.*,
    spend_intents.session_id AS intent_session_id,
    spend_intents.seller_origin AS intent_seller_origin,
    spend_intents.wallet_address AS intent_wallet_address,
    spend_sessions.wallet_address AS session_wallet_address,
    policy_decisions.amount_ceiling_atomic AS decision_amount
  FROM budget_reservations
  LEFT JOIN spend_intents ON spend_intents.id = budget_reservations.intent_id
  LEFT JOIN spend_sessions ON spend_sessions.id = budget_reservations.session_id
  LEFT JOIN policy_decisions ON policy_decisions.intent_id = budget_reservations.intent_id`;

function validateBudgetEventCompleteness(db) {
  const eventEntities = db.prepare(`SELECT entity_id, event_type, COUNT(*) AS event_count
    FROM events
    WHERE entity_type = 'budget_reservation'
    GROUP BY entity_id, event_type
    ORDER BY entity_id, event_type`).all();
  const recognizedTypes = new Set([
    'budget.reserved',
    'budget.committed',
    'budget.released',
    'budget.held_unresolved',
    'budget.payment_resolved',
    'budget.refund_confirmed',
  ]);
  const summaries = new Map();
  for (const event of eventEntities) {
    let intentId;
    try {
      intentId = canonicalToken(event.entity_id, 'budget event intent ID');
    } catch (error) {
      if (error instanceof KernelError) {
        fail('BUDGET_CORRUPTION', 'budget event intent ID is invalid');
      }
      throw error;
    }
    const count = safeInteger(event.event_count, 'budget event count');
    if (!recognizedTypes.has(event.event_type) || count !== 1) {
      fail('BUDGET_CORRUPTION', 'budget event history is unknown or ambiguous');
    }
    const summary = summaries.get(intentId) ?? { reservedEvents: 0 };
    if (event.event_type === 'budget.reserved') summary.reservedEvents += count;
    summaries.set(intentId, summary);
  }
  const reservationCount = db.prepare(`SELECT COUNT(*) AS reservation_count
    FROM budget_reservations WHERE intent_id = ?`);
  for (const [intentId, summary] of summaries) {
    const count = safeInteger(
      reservationCount.get(intentId).reservation_count,
      'budget reservation count',
    );
    if (summary.reservedEvents !== 1 || count !== 1) {
      fail(
        'BUDGET_CORRUPTION',
        'budget event entity does not map to one complete BudgetReservation',
      );
    }
  }
}

function validateHistoricalBudgetAuthority(db, row) {
  let authority;
  try {
    authority = loadReservationAuthority(db, row.intentId);
  } catch (error) {
    if (error instanceof KernelError) {
      fail('BUDGET_CORRUPTION', 'BudgetReservation historical authority is invalid');
    }
    throw error;
  }
  if (authority.intent.id !== row.intentId
      || authority.intent.session_id !== row.sessionId
      || authority.session.id !== row.sessionId
      || authority.intent.seller_origin !== row.sellerOrigin
      || authority.intent.wallet_address !== row.walletAddress
      || authority.session.wallet_address !== row.walletAddress
      || authority.policyVersion.policy.wallet !== row.walletAddress
      || authority.amount.text !== row.ceiling.text) {
    fail('BUDGET_CORRUPTION', 'BudgetReservation substituted its historical authority');
  }
  return authority;
}

function validatedBudgetRows(db, where = '', parameters = []) {
  validateBudgetEventCompleteness(db);
  return db.prepare(`${BUDGET_ROWS_SQL} ${where}
    ORDER BY budget_reservations.intent_id`).all(...parameters).map((raw) => {
    const row = validateBudgetRow(raw);
    const authority = validateHistoricalBudgetAuthority(db, row);
    validateBudgetHistory(db, row, authority);
    return row;
  });
}

function walletBlockers(db, walletAddress, rows) {
  const unresolvedBudget = rows.some((row) => row.state === 'unresolved');
  const executionResolution = db.prepare(`SELECT execution_resolutions.intent_id
    FROM execution_resolutions
    JOIN spend_intents ON spend_intents.id = execution_resolutions.intent_id
    JOIN spend_sessions ON spend_sessions.id = spend_intents.session_id
    WHERE spend_sessions.wallet_address = ?
      AND execution_resolutions.state != 'resolved'
      AND execution_resolutions.blocks_wallet = 1
    LIMIT 1`).get(walletAddress);
  const refund = db.prepare(`SELECT refunds.id
    FROM refunds
    JOIN spend_intents ON spend_intents.id = refunds.intent_id
    JOIN spend_sessions ON spend_sessions.id = spend_intents.session_id
    WHERE spend_sessions.wallet_address = ?
      AND refunds.state IN ('pending','unresolved')
    LIMIT 1`).get(walletAddress);
  return Object.freeze({
    unresolvedBudget,
    resolutionRequired: Boolean(executionResolution || refund),
  });
}

function snapshotImpl(db, { sessionId, sellerOrigin, at }) {
  const session = db.prepare('SELECT * FROM spend_sessions WHERE id = ?').get(sessionId);
  if (!session) fail('SESSION_UNKNOWN', 'Spend Session does not exist');
  const walletAddress = canonicalAddress(session.wallet_address, 'session wallet');
  const rows = validatedBudgetRows(db).filter((row) => row.walletAddress === walletAddress);
  const exposure = (row) => row.reserved.value + row.committed.value + row.unresolved.value;
  const sum = (values) => values.reduce((total, value) => total + value, 0n);
  const sellerSessionExposure = sum(rows
    .filter((row) => row.sessionId === sessionId && row.sellerOrigin === sellerOrigin)
    .map(exposure));
  const sessionExposure = sum(rows
    .filter((row) => row.sessionId === sessionId)
    .map(exposure));
  const windowStart = Date.parse(at) - DAY_MS;
  const rollingCommitted = sum(rows
    .filter((row) => row.committed.value > 0n && Date.parse(row.committedAt) > windowStart)
    .map((row) => row.committed.value));
  const rollingActive = sum(rows.map((row) => row.reserved.value + row.unresolved.value));
  const blockers = walletBlockers(db, walletAddress, rows);
  return Object.freeze({
    public: frozenCopy({
      sellerSessionExposureAtomic: sellerSessionExposure.toString(),
      sessionExposureAtomic: sessionExposure.toString(),
      rolling24hExposureAtomic: (rollingCommitted + rollingActive).toString(),
      walletBlocked: blockers.unresolvedBudget || blockers.resolutionRequired,
    }),
    blockers,
    walletAddress,
    rows,
  });
}

function publicReservation(row) {
  return frozenCopy({
    intentId: row.intentId,
    sessionId: row.sessionId,
    sellerOrigin: row.sellerOrigin,
    reservedAtomic: row.reserved.text,
    committedAtomic: row.committed.text,
    releasedAtomic: row.released.text,
    unresolvedAtomic: row.unresolved.text,
    state: row.state,
    committedAt: row.committedAt,
    updatedAt: row.updatedAt,
  });
}

function readBudgetRow(db, intentId) {
  const rows = validatedBudgetRows(
    db,
    'WHERE budget_reservations.intent_id = ?',
    [intentId],
  );
  if (rows.length > 1) fail('BUDGET_CORRUPTION', 'BudgetReservation authority is ambiguous');
  return rows[0] ?? null;
}

function exactObject(value, required, optional, code, label) {
  try {
    return exactRecord(value, required, optional, code, label);
  } catch (error) {
    if (error instanceof KernelError && error.code !== code) {
      fail(code, `${label} is invalid`);
    }
    throw error;
  }
}

function validatePaymentPayload(bytes, authority, attempt) {
  const parsed = parseCanonicalJson(bytes, 'payment payload JSON', 'PAYMENT_ATTEMPT_CORRUPTION');
  const payment = exactObject(
    parsed,
    ['x402Version', 'resource', 'accepted', 'payload'],
    [],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'payment payload',
  );
  const resource = exactObject(
    payment.resource,
    ['url', 'description', 'mimeType'],
    [],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'payment resource',
  );
  const accepted = exactObject(
    payment.accepted,
    ['scheme', 'network', 'asset', 'amount', 'payTo', 'maxTimeoutSeconds', 'extra'],
    [],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'accepted payment requirement',
  );
  const extra = exactObject(
    accepted.extra,
    ['name', 'version'],
    ['assetTransferMethod'],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'accepted payment extra',
  );
  const payload = exactObject(
    payment.payload,
    ['signature', 'authorization'],
    [],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'payment payload body',
  );
  const authorization = exactObject(
    payload.authorization,
    ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'],
    [],
    'PAYMENT_ATTEMPT_CORRUPTION',
    'payment authorization',
  );
  let resourceUrl;
  try {
    resourceUrl = new URL(resource.url);
  } catch {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'persisted payment resource URL is invalid');
  }
  const selected = authority.projection.selected;
  const validAfter = canonicalAtomicText(
    authorization.validAfter,
    'authorization validAfter',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  const validBefore = canonicalAtomicText(
    authorization.validBefore,
    'authorization validBefore',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  if (payment.x402Version !== 2
      || resourceUrl.href !== resource.url
      || resourceUrl.origin !== authority.intent.seller_origin
      || resourceUrl.pathname !== authority.intent.resource_path
      || resourceUrl.username !== ''
      || resourceUrl.password !== ''
      || resourceUrl.hash !== ''
      || sha256(resource.url) !== authority.intent.request_url_hash
      || resource.description !== authority.projection.projection.resource.description
      || resource.mimeType !== authority.projection.projection.resource.mimeType
      || canonicalJson({ ...accepted, extra }) !== canonicalJson(selected)
      || typeof payload.signature !== 'string'
      || !/^0x[0-9a-fA-F]{130}$/.test(payload.signature)
      || canonicalAddress(
        authorization.from,
        'authorization payer',
        'PAYMENT_ATTEMPT_CORRUPTION',
      ) !== authority.session.wallet_address
      || canonicalAddress(
        authorization.to,
        'authorization payee',
        'PAYMENT_ATTEMPT_CORRUPTION',
      ) !== selected.payTo
      || canonicalAtomicText(
        authorization.value,
        'authorization value',
        'PAYMENT_ATTEMPT_CORRUPTION',
      ).text !== authority.amount.text
      || typeof authorization.nonce !== 'string'
      || !/^0x[0-9a-f]{64}$/.test(authorization.nonce)
      || authorization.nonce !== attempt.nonce
      || validAfter.text !== attempt.valid_after
      || validBefore.text !== attempt.valid_before
      || validBefore.value <= validAfter.value) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'persisted payment payload binding changed');
  }
  return frozenCopy(parsed);
}

function validatePaymentAttempt(db, authority, allowedStates) {
  const row = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?')
    .get(authority.intent.id);
  if (!row) fail('PAYMENT_ATTEMPT_MISSING', 'Spend Intent has no PaymentAttempt');
  if (!allowedStates.has(row.state)) {
    fail('PAYMENT_ATTEMPT_STATE', 'PaymentAttempt is not in the required state');
  }
  canonicalToken(row.id, 'payment attempt ID');
  if (row.intent_id !== authority.intent.id
      || row.payment_required_projection_json !== authority.intent.challenge_projection_json
      || safeInteger(
        row.accepted_index,
        'payment accepted index',
        'PAYMENT_ATTEMPT_CORRUPTION',
      ) !== authority.projection.acceptedIndex
      || row.quote_id !== authority.decision.quote_id) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt challenge binding changed');
  }
  const createdAt = canonicalPersistedTimestamp(
    row.created_at,
    'payment attempt createdAt',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  const updatedAt = canonicalPersistedTimestamp(
    row.updated_at,
    'payment attempt updatedAt',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt time regressed');
  }

  const claimFields = [
    row.nonce,
    row.valid_after,
    row.valid_before,
    row.signing_claimed_at,
  ];
  const signedPayloadFields = [
    row.payment_payload_json,
    row.payment_header,
    row.payment_hash,
    row.signed_at,
  ];
  const fullClaim = claimFields.every((value) => value !== null);
  const noClaim = claimFields.every((value) => value === null);
  const fullSignedPayload = signedPayloadFields.every((value) => value !== null);
  const noSignedPayload = signedPayloadFields.every((value) => value === null);
  if ((!fullClaim && !noClaim) || (!fullSignedPayload && !noSignedPayload)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt authority fields are partial');
  }
  if (fullSignedPayload && !fullClaim) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt signed bytes have no signing claim');
  }
  if (row.state === 'reserved') {
    if (!noClaim
        || !noSignedPayload
        || row.retry_started_at !== null
        || row.settlement_json !== null
        || row.transaction_id !== null
        || row.settled_at !== null) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'reserved PaymentAttempt contains later fields');
    }
    return Object.freeze({ row, paymentPayload: null });
  }
  if (row.state === 'rejected' && noClaim && noSignedPayload) {
    if (row.retry_started_at !== null
        || row.settlement_json !== null
        || row.transaction_id !== null
        || row.settled_at !== null
        || typeof row.reason_code !== 'string'
        || !/^[A-Z][A-Z0-9_]{0,99}$/.test(row.reason_code)) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'unsigned rejected PaymentAttempt is inconsistent');
    }
    return Object.freeze({ row, paymentPayload: null });
  }
  if (!fullClaim) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'advanced PaymentAttempt has no complete signing claim');
  }
  const signingClaimedAt = canonicalPersistedTimestamp(
    row.signing_claimed_at,
    'payment signing claimedAt',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  if (Date.parse(signingClaimedAt) < Date.parse(createdAt)
      || Date.parse(signingClaimedAt) > Date.parse(updatedAt)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt signing chronology is invalid');
  }
  if (!/^0x[0-9a-f]{64}$/.test(row.nonce)
      || !DECIMAL_PATTERN.test(row.valid_after)
      || !DECIMAL_PATTERN.test(row.valid_before)
      || BigInt(row.valid_before) <= BigInt(row.valid_after)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'authorization claim window is invalid');
  }
  if (row.state === 'signing' && fullSignedPayload) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'signing PaymentAttempt already contains signed bytes');
  }
  if (noSignedPayload
      && new Set(['signing', 'unresolved', 'rejected']).has(row.state)) {
    if (row.retry_started_at !== null
        || row.settlement_json !== null
        || row.transaction_id !== null
        || row.settled_at !== null) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'claim-only PaymentAttempt contains signed aftermath');
    }
    if (row.state === 'rejected'
        && (typeof row.reason_code !== 'string'
          || !/^[A-Z][A-Z0-9_]{0,99}$/.test(row.reason_code))) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'claim-only rejection has no stable reason');
    }
    return Object.freeze({ row, paymentPayload: null });
  }
  if (!fullSignedPayload
      || typeof row.payment_header !== 'string'
      || row.payment_header.length === 0
      || Buffer.byteLength(row.payment_header, 'utf8') > 16_384
      || /[^\x20-\x7e]/.test(row.payment_header)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'signed PaymentAttempt header is invalid');
  }
  canonicalHash(row.payment_hash, 'payment hash', 'PAYMENT_ATTEMPT_CORRUPTION');
  if (sha256(Buffer.from(row.payment_header, 'ascii')) !== row.payment_hash) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'payment hash does not match exact persisted header');
  }
  const signedAt = canonicalPersistedTimestamp(
    row.signed_at,
    'payment signedAt',
    'PAYMENT_ATTEMPT_CORRUPTION',
  );
  if (Date.parse(signedAt) < Date.parse(signingClaimedAt)
      || Date.parse(signedAt) > Date.parse(updatedAt)) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt signedAt chronology is invalid');
  }
  const needsRetry = new Set(['retrying', 'settled']).has(row.state)
    || (new Set(['unresolved', 'rejected']).has(row.state)
      && row.retry_started_at !== null);
  let retryStartedAt = null;
  if (needsRetry) {
    retryStartedAt = canonicalPersistedTimestamp(
      row.retry_started_at,
      'payment retry startedAt',
      'PAYMENT_ATTEMPT_CORRUPTION',
    );
    if (Date.parse(retryStartedAt) < Date.parse(signedAt)
        || Date.parse(retryStartedAt) > Date.parse(updatedAt)) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt retry chronology is invalid');
    }
  } else if (row.retry_started_at !== null) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt has an unexpected paid retry');
  }
  const paymentPayload = validatePaymentPayload(row.payment_payload_json, authority, row);
  if (row.state === 'settled') {
    if (row.settlement_json === null || row.transaction_id === null || row.settled_at === null) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'settled PaymentAttempt is incomplete');
    }
    parseCanonicalJson(row.settlement_json, 'payment settlement', 'PAYMENT_ATTEMPT_CORRUPTION');
    if (canonicalEvmHashFor(
      row.transaction_id,
      'payment transaction ID',
      'PAYMENT_ATTEMPT_CORRUPTION',
    ) !== row.transaction_id) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'payment transaction ID is not canonical lowercase');
    }
    const settledAt = canonicalPersistedTimestamp(
      row.settled_at,
      'payment settledAt',
      'PAYMENT_ATTEMPT_CORRUPTION',
    );
    if (Date.parse(settledAt) < Date.parse(retryStartedAt)
        || Date.parse(settledAt) > Date.parse(updatedAt)
        || settledAt !== updatedAt) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'PaymentAttempt settlement chronology is invalid');
    }
    if (row.reason_code !== null && row.reason_code !== 'TRUSTED_RECONCILIATION') {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'settled PaymentAttempt reason is invalid');
    }
  } else if (row.settlement_json !== null
      || row.transaction_id !== null
      || row.settled_at !== null) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'unsettled PaymentAttempt contains settlement fields');
  }
  if (row.state === 'rejected'
      && (typeof row.reason_code !== 'string'
        || !/^[A-Z][A-Z0-9_]{0,99}$/.test(row.reason_code))) {
    fail('PAYMENT_ATTEMPT_CORRUPTION', 'rejected PaymentAttempt has no stable reason');
  }
  return Object.freeze({ row, paymentPayload });
}

function validateSettlementEvidence(value) {
  if (!Object.isFrozen(value)) {
    fail('SETTLEMENT_EVIDENCE', 'settlement evidence must be a frozen classifier result');
  }
  const record = closedInput(value, [
    'source',
    'headerHash',
    'success',
    'transaction',
    'network',
    'payer',
    'paymentHash',
  ], ['amountAtomic'], 'SETTLEMENT_EVIDENCE', 'settlement evidence');
  if (record.source !== 'x402-payment-response' || record.success !== true) {
    fail('SETTLEMENT_EVIDENCE', 'settlement evidence is not a successful x402 response');
  }
  const normalized = {
    source: record.source,
    headerHash: canonicalHash(record.headerHash, 'settlement header hash', 'SETTLEMENT_EVIDENCE'),
    success: true,
    transaction: canonicalEvmHash(record.transaction, 'settlement transaction'),
    network: canonicalToken(record.network, 'settlement network'),
    payer: canonicalAddress(record.payer, 'settlement payer', 'SETTLEMENT_EVIDENCE'),
    ...(Object.hasOwn(record, 'amountAtomic') ? {
      amountAtomic: canonicalAtomicText(
        record.amountAtomic,
        'settlement amount',
        'SETTLEMENT_EVIDENCE',
      ).text,
    } : {}),
    paymentHash: canonicalHash(record.paymentHash, 'settlement payment hash', 'SETTLEMENT_EVIDENCE'),
  };
  return frozenCopy(normalized);
}

function loadBudgetEvent(db, intentId, eventType) {
  const rows = db.prepare(`SELECT data_json FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?
    ORDER BY sequence`).all('budget_reservation', intentId, eventType);
  if (rows.length === 0) return null;
  if (rows.length !== 1) fail('BUDGET_CORRUPTION', 'budget transition event is ambiguous');
  return parseCanonicalJson(rows[0].data_json, 'budget transition event');
}

function stableReason(value, label) {
  if (typeof value !== 'string' || !/^[A-Z][A-Z0-9_]{0,99}$/.test(value)) {
    fail('BUDGET_CORRUPTION', `${label} is not one stable reason code`);
  }
  return value;
}

function isExactPreSignRejection(value) {
  return WalletSigningError.isExact(
    value,
    'WALLET_PRE_SIGN_REJECTED',
    false,
  );
}

function validateBudgetHistory(db, row, authority) {
  const reserve = exactObject(
    loadBudgetEvent(db, row.intentId, 'budget.reserved'),
    [
      'sessionId',
      'sellerOrigin',
      'amountAtomic',
      'previousState',
      'nextState',
      'updatedAt',
    ],
    [],
    'BUDGET_CORRUPTION',
    'budget reserve event',
  );
  const reserveAt = canonicalPersistedTimestamp(
    reserve.updatedAt,
    'budget reserve event time',
  );
  if (canonicalToken(reserve.sessionId, 'budget reserve session ID') !== row.sessionId
      || canonicalOrigin(
        reserve.sellerOrigin,
        'budget reserve seller origin',
        'BUDGET_CORRUPTION',
      ) !== row.sellerOrigin
      || canonicalAtomicText(reserve.amountAtomic, 'budget reserve amount').text
        !== row.ceiling.text
      || reserve.previousState !== null
      || reserve.nextState !== 'reserved'
      || Date.parse(reserveAt) > Date.parse(row.updatedAt)) {
    fail('BUDGET_CORRUPTION', 'budget reserve event no longer binds its reservation');
  }

  const rawCommit = loadBudgetEvent(db, row.intentId, 'budget.committed');
  const rawRelease = loadBudgetEvent(db, row.intentId, 'budget.released');
  const rawHold = loadBudgetEvent(db, row.intentId, 'budget.held_unresolved');
  const rawPaymentResolution = loadBudgetEvent(db, row.intentId, 'budget.payment_resolved');
  const rawRefund = loadBudgetEvent(db, row.intentId, 'budget.refund_confirmed');

  const commit = rawCommit === null ? null : exactObject(rawCommit, [
    'amountAtomic',
    'transactionId',
    'paymentHash',
    'headerHash',
    'previousState',
    'nextState',
    'committedAt',
  ], [], 'BUDGET_CORRUPTION', 'budget commit event');
  if (commit) {
    const transactionId = canonicalEvmHashFor(
      commit.transactionId,
      'budget commit transaction',
      'BUDGET_CORRUPTION',
    );
    if (commit.transactionId !== transactionId
        || canonicalAtomicText(commit.amountAtomic, 'budget commit amount').text
          !== row.ceiling.text
        || canonicalHash(commit.paymentHash, 'budget commit payment hash')
          !== commit.paymentHash
        || canonicalHash(commit.headerHash, 'budget commit header hash') !== commit.headerHash
        || commit.previousState !== 'reserved'
        || commit.nextState !== 'committed') {
      fail('BUDGET_CORRUPTION', 'budget commit event binding changed');
    }
    canonicalPersistedTimestamp(commit.committedAt, 'budget commit event time');
  }

  const release = rawRelease === null ? null : exactObject(rawRelease, [
    'amountAtomic',
    'reasonCode',
    'previousState',
    'nextState',
    'releasedAt',
  ], [], 'BUDGET_CORRUPTION', 'budget release event');
  if (release) {
    if (canonicalAtomicText(release.amountAtomic, 'budget release amount').text
          !== row.ceiling.text
        || stableReason(release.reasonCode, 'budget release reason') !== release.reasonCode
        || release.previousState !== 'reserved'
        || release.nextState !== 'released') {
      fail('BUDGET_CORRUPTION', 'budget release event binding changed');
    }
    canonicalPersistedTimestamp(release.releasedAt, 'budget release event time');
    const rawAttempt = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?')
      .get(row.intentId);
    if (!rawAttempt && release.reasonCode === 'WALLET_PRE_SIGN_REJECTED') {
      fail('BUDGET_CORRUPTION', 'typed pre-sign release lost its claim-only PaymentAttempt');
    }
    if (rawAttempt) {
      let attempt;
      try {
        attempt = validatePaymentAttempt(db, authority, new Set(['rejected'])).row;
      } catch (error) {
        if (error instanceof KernelError) {
          fail('BUDGET_CORRUPTION', 'released PaymentAttempt history is invalid');
        }
        throw error;
      }
      const hasClaimOnly = attempt.signing_claimed_at !== null
        && attempt.payment_payload_json === null;
      if (attempt.payment_payload_json !== null
          || attempt.reason_code !== release.reasonCode
          || attempt.updated_at !== release.releasedAt
          || hasClaimOnly !== (release.reasonCode === 'WALLET_PRE_SIGN_REJECTED')) {
        fail('BUDGET_CORRUPTION', 'released PaymentAttempt no longer binds its release event');
      }
    }
  }

  const hold = rawHold === null ? null : exactObject(rawHold, [
    'amountAtomic',
    'reasonCode',
    'previousState',
    'nextState',
    'heldAt',
  ], [], 'BUDGET_CORRUPTION', 'budget unresolved-hold event');
  if (hold) {
    if (canonicalAtomicText(hold.amountAtomic, 'budget unresolved amount').text
          !== row.ceiling.text
        || stableReason(hold.reasonCode, 'budget unresolved reason') !== hold.reasonCode
        || hold.previousState !== 'reserved'
        || hold.nextState !== 'unresolved') {
      fail('BUDGET_CORRUPTION', 'budget unresolved-hold event binding changed');
    }
    canonicalPersistedTimestamp(hold.heldAt, 'budget unresolved event time');
  }

  let paymentResolution = null;
  if (rawPaymentResolution !== null) {
    if (rawPaymentResolution.outcome === 'settled') {
      paymentResolution = exactObject(rawPaymentResolution, [
        'evidenceId',
        'outcome',
        'transactionId',
        'amountAtomic',
        'previousState',
        'nextState',
        'buyerOutcomeRevision',
        'resolvedAt',
      ], [], 'BUDGET_CORRUPTION', 'settled payment resolution event');
      const transactionId = canonicalEvmHashFor(
        paymentResolution.transactionId,
        'resolved payment transaction',
        'BUDGET_CORRUPTION',
      );
      if (paymentResolution.transactionId !== transactionId
          || paymentResolution.previousState !== 'unresolved'
          || paymentResolution.nextState !== 'committed') {
        fail('BUDGET_CORRUPTION', 'settled payment resolution event binding changed');
      }
    } else if (rawPaymentResolution.outcome === 'rejected') {
      paymentResolution = exactObject(rawPaymentResolution, [
        'evidenceId',
        'outcome',
        'amountAtomic',
        'previousState',
        'nextState',
        'buyerOutcomeRevision',
        'resolvedAt',
      ], [], 'BUDGET_CORRUPTION', 'rejected payment resolution event');
      if (paymentResolution.previousState !== 'unresolved'
          || paymentResolution.nextState !== 'released') {
        fail('BUDGET_CORRUPTION', 'rejected payment resolution event binding changed');
      }
    } else {
      fail('BUDGET_CORRUPTION', 'budget payment resolution event outcome is invalid');
    }
    canonicalToken(paymentResolution.evidenceId, 'payment resolution evidence ID');
    if (canonicalAtomicText(
      paymentResolution.amountAtomic,
      'payment resolution amount',
    ).text !== row.ceiling.text
        || safeInteger(
          paymentResolution.buyerOutcomeRevision,
          'payment resolution BuyerOutcome revision',
        ) < 1) {
      fail('BUDGET_CORRUPTION', 'payment resolution event authority changed');
    }
    canonicalPersistedTimestamp(
      paymentResolution.resolvedAt,
      'payment resolution event time',
    );
  }

  const refund = rawRefund === null ? null : exactObject(rawRefund, [
    'evidenceId',
    'originalTransactionId',
    'refundTransactionId',
    'amountAtomic',
    'previousState',
    'nextState',
    'buyerOutcomeRevision',
    'confirmedAt',
  ], [], 'BUDGET_CORRUPTION', 'confirmed refund event');
  if (refund) {
    const originalTransactionId = canonicalEvmHashFor(
      refund.originalTransactionId,
      'refund event original transaction',
      'BUDGET_CORRUPTION',
    );
    const refundTransactionId = canonicalEvmHashFor(
      refund.refundTransactionId,
      'refund event transaction',
      'BUDGET_CORRUPTION',
    );
    if (refund.originalTransactionId !== originalTransactionId
        || refund.refundTransactionId !== refundTransactionId
        || originalTransactionId === refundTransactionId
        || canonicalAtomicText(refund.amountAtomic, 'refund event amount').text
          !== row.ceiling.text
        || canonicalToken(refund.evidenceId, 'refund event evidence ID') !== refund.evidenceId
        || safeInteger(refund.buyerOutcomeRevision, 'refund BuyerOutcome revision') < 1
        || refund.previousState !== 'committed'
        || refund.nextState !== 'released') {
      fail('BUDGET_CORRUPTION', 'confirmed refund event binding changed');
    }
    canonicalPersistedTimestamp(refund.confirmedAt, 'confirmed refund event time');
  }

  const noLaterEvents = (...events) => events.every((event) => event === null);
  const directCommit = commit !== null && hold === null && paymentResolution === null;
  const reconciledCommit = commit === null
    && hold !== null
    && paymentResolution?.outcome === 'settled';
  const assertCommittedOrigin = () => {
    if (!directCommit && !reconciledCommit) {
      fail('BUDGET_CORRUPTION', 'committed value has no unique authoritative origin');
    }
    const committedAt = directCommit ? commit.committedAt : paymentResolution.resolvedAt;
    if (row.committedAt !== committedAt) {
      fail('BUDGET_CORRUPTION', 'budget committedAt differs from its transition event');
    }
    const transactionId = directCommit
      ? commit.transactionId
      : paymentResolution.transactionId;
    let attempt;
    try {
      attempt = validatePaymentAttempt(db, authority, new Set(['settled'])).row;
    } catch (error) {
      if (error instanceof KernelError) {
        fail('BUDGET_CORRUPTION', 'committed PaymentAttempt history is invalid');
      }
      throw error;
    }
    if (attempt.transaction_id !== transactionId
        || attempt.settled_at !== committedAt
        || attempt.settlement_json === null) {
      fail('BUDGET_CORRUPTION', 'committed budget differs from its exact PaymentAttempt');
    }
    parseCanonicalJson(
      attempt.settlement_json,
      'committed payment settlement',
      'BUDGET_CORRUPTION',
    );
    return committedAt;
  };

  if (row.state === 'reserved') {
    if (!noLaterEvents(commit, release, hold, paymentResolution, refund)
        || row.updatedAt !== reserveAt) {
      fail('BUDGET_CORRUPTION', 'reserved budget history contains a later transition');
    }
    const rawAttempt = db.prepare('SELECT intent_id FROM payment_attempts WHERE intent_id = ?')
      .get(row.intentId);
    if (rawAttempt) {
      let attempt;
      try {
        attempt = validatePaymentAttempt(
          db,
          authority,
          new Set(['reserved', 'signing', 'signed', 'retrying']),
        ).row;
      } catch (error) {
        if (error instanceof KernelError) {
          fail('BUDGET_CORRUPTION', 'reserved PaymentAttempt history is invalid');
        }
        throw error;
      }
      const transitionAt = {
        reserved: attempt.created_at,
        signing: attempt.signing_claimed_at,
        signed: attempt.signed_at,
        retrying: attempt.retry_started_at,
      }[attempt.state];
      if (Date.parse(attempt.created_at) < Date.parse(reserveAt)
          || attempt.updated_at !== transitionAt
          || attempt.reason_code !== null) {
        fail('BUDGET_CORRUPTION', 'reserved PaymentAttempt chronology is invalid');
      }
    }
  } else if (row.state === 'unresolved') {
    if (hold === null
        || !noLaterEvents(commit, release, paymentResolution, refund)
        || row.updatedAt !== hold.heldAt) {
      fail('BUDGET_CORRUPTION', 'unresolved budget history is not exact');
    }
    const rawAttempt = db.prepare('SELECT intent_id FROM payment_attempts WHERE intent_id = ?')
      .get(row.intentId);
    if (rawAttempt) {
      let attempt;
      try {
        attempt = validatePaymentAttempt(
          db,
          authority,
          new Set(['signing', 'signed', 'retrying', 'unresolved']),
        ).row;
      } catch (error) {
        if (error instanceof KernelError) {
          fail('BUDGET_CORRUPTION', 'unresolved PaymentAttempt history is invalid');
        }
        throw error;
      }
      if (attempt.state === 'unresolved' && attempt.updated_at !== hold.heldAt) {
        fail('BUDGET_CORRUPTION', 'unresolved PaymentAttempt detached from its hold event');
      }
    }
  } else if (row.state === 'committed') {
    assertCommittedOrigin();
    if (!noLaterEvents(release, refund)
        || row.updatedAt !== row.committedAt) {
      fail('BUDGET_CORRUPTION', 'committed budget history is not exact');
    }
  } else if (row.state === 'released' && release !== null) {
    if (!noLaterEvents(commit, hold, paymentResolution, refund)
        || row.committedAt !== null
        || row.updatedAt !== release.releasedAt) {
      fail('BUDGET_CORRUPTION', 'ordinary release history is not exact');
    }
  } else if (row.state === 'released' && paymentResolution?.outcome === 'rejected') {
    if (hold === null
        || !noLaterEvents(commit, release, refund)
        || row.committedAt !== null
        || row.updatedAt !== paymentResolution.resolvedAt) {
      fail('BUDGET_CORRUPTION', 'rejected payment release history is not exact');
    }
    let attempt;
    try {
      attempt = validatePaymentAttempt(db, authority, new Set(['rejected'])).row;
    } catch (error) {
      if (error instanceof KernelError) {
        fail('BUDGET_CORRUPTION', 'trusted-rejected PaymentAttempt history is invalid');
      }
      throw error;
    }
    if (attempt.updated_at !== paymentResolution.resolvedAt) {
      fail('BUDGET_CORRUPTION', 'trusted-rejected attempt detached from its resolution event');
    }
  } else if (row.state === 'released' && refund !== null) {
    assertCommittedOrigin();
    if (release !== null || row.updatedAt !== refund.confirmedAt) {
      fail('BUDGET_CORRUPTION', 'refunded budget history is not exact');
    }
  } else {
    fail('BUDGET_CORRUPTION', 'BudgetReservation has no legal event history');
  }

  validateResolutionAndRefundHistory(db, row, refund);
  return row;
}

function validateResolutionAndRefundHistory(db, budget, refundEvent) {
  const execution = db.prepare('SELECT * FROM execution_outcomes WHERE intent_id = ?')
    .get(budget.intentId);
  const resolution = db.prepare('SELECT * FROM execution_resolutions WHERE intent_id = ?')
    .get(budget.intentId);
  const refunds = db.prepare('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid')
    .all(budget.intentId);

  if (execution) {
    if (!new Set(['succeeded', 'failed', 'unknown']).has(execution.state)) {
      fail('BUDGET_CORRUPTION', 'execution outcome state is invalid');
    }
    if (execution.http_status !== null) {
      const status = safeInteger(execution.http_status, 'execution HTTP status');
      if (status < 100 || status > 599) {
        fail('BUDGET_CORRUPTION', 'execution HTTP status is invalid');
      }
    }
    if (execution.response_hash !== null) {
      canonicalHash(execution.response_hash, 'execution response hash');
    }
    parseCanonicalJson(execution.metadata_json, 'execution metadata');
    canonicalPersistedTimestamp(execution.recorded_at, 'execution recordedAt');
  }

  if (resolution) {
    stableReason(resolution.reason_code, 'execution resolution reason');
    const openedAt = canonicalPersistedTimestamp(
      resolution.opened_at,
      'execution resolution openedAt',
    );
    const blocksWallet = safeInteger(resolution.blocks_wallet, 'execution resolution blocker');
    if (!new Set(['refund_pending', 'reconciliation_required', 'resolved'])
      .has(resolution.state)
        || blocksWallet > 1) {
      fail('BUDGET_CORRUPTION', 'execution resolution shape is invalid');
    }
    if (resolution.state === 'resolved') {
      const resolvedAt = canonicalPersistedTimestamp(
        resolution.resolved_at,
        'execution resolution resolvedAt',
      );
      if (blocksWallet !== 0 || Date.parse(resolvedAt) < Date.parse(openedAt)) {
        fail('BUDGET_CORRUPTION', 'resolved execution case is inconsistent');
      }
    } else if (blocksWallet !== 1 || resolution.resolved_at !== null) {
      fail('BUDGET_CORRUPTION', 'open execution case is not wallet-blocking');
    }
  }

  const attempt = db.prepare('SELECT transaction_id FROM payment_attempts WHERE intent_id = ?')
    .get(budget.intentId);
  const activeRefunds = [];
  const confirmedRefunds = [];
  for (const refund of refunds) {
    canonicalToken(refund.id, 'refund ID');
    const originalTransactionId = canonicalEvmHashFor(
      refund.original_transaction_id,
      'refund original transaction',
      'BUDGET_CORRUPTION',
    );
    if (refund.original_transaction_id !== originalTransactionId
        || refund.intent_id !== budget.intentId
        || refund.amount_atomic !== budget.ceiling.text
        || originalTransactionId !== attempt?.transaction_id
        || !new Set(['pending', 'unresolved', 'abandoned', 'confirmed', 'rejected'])
          .has(refund.state)) {
      fail('BUDGET_CORRUPTION', 'refund row no longer binds the committed payment');
    }
    const createdAt = canonicalPersistedTimestamp(refund.created_at, 'refund createdAt');
    const updatedAt = canonicalPersistedTimestamp(refund.updated_at, 'refund updatedAt');
    if (Date.parse(updatedAt) < Date.parse(createdAt)) {
      fail('BUDGET_CORRUPTION', 'refund time regressed');
    }
    if (refund.refund_transaction_id !== null) {
      const refundTransactionId = canonicalEvmHashFor(
        refund.refund_transaction_id,
        'refund transaction',
        'BUDGET_CORRUPTION',
      );
      if (refund.refund_transaction_id !== refundTransactionId
          || refundTransactionId === originalTransactionId) {
        fail('BUDGET_CORRUPTION', 'refund transaction binding is invalid');
      }
    }
    if (refund.evidence_json !== null) {
      parseCanonicalJson(refund.evidence_json, 'refund evidence');
    }
    if (refund.state === 'pending' || refund.state === 'unresolved') {
      activeRefunds.push(refund);
    }
    if (refund.state === 'confirmed') confirmedRefunds.push(refund);
  }

  if ((execution === undefined) !== (resolution === undefined && refunds.length === 0)) {
    if (!execution || (resolution && resolution.intent_id !== budget.intentId)) {
      fail('BUDGET_CORRUPTION', 'execution/refund authority is incomplete');
    }
  }
  if (!execution && (resolution || refunds.length > 0)) {
    fail('BUDGET_CORRUPTION', 'execution/refund authority has no execution outcome');
  }
  if (execution?.state === 'failed'
      && (!resolution || !new Set(['refund_pending', 'resolved']).has(resolution.state))) {
    fail('BUDGET_CORRUPTION', 'failed execution has no refund resolution');
  }
  if (execution?.state === 'unknown'
      && resolution?.state !== 'reconciliation_required') {
    fail('BUDGET_CORRUPTION', 'unknown execution has no reconciliation blocker');
  }
  if (resolution?.state === 'refund_pending') {
    const terminalHistoryOnly = refunds.length > 0
      && activeRefunds.length === 0
      && confirmedRefunds.length === 0
      && refunds.every((refund) => (
        (refund.state === 'abandoned' || refund.state === 'rejected')
          && refund.refund_transaction_id !== null
      ));
    if (execution?.state !== 'failed'
        || budget.state !== 'committed'
        || (activeRefunds.length !== 1 && !terminalHistoryOnly)
        || confirmedRefunds.length !== 0) {
      fail('BUDGET_CORRUPTION', 'refund-pending execution case is inconsistent');
    }
  } else if (resolution?.state === 'reconciliation_required') {
    if (execution?.state !== 'unknown'
        || budget.state !== 'committed'
        || refunds.length !== 0) {
      fail('BUDGET_CORRUPTION', 'execution reconciliation case is inconsistent');
    }
  } else if (activeRefunds.length !== 0) {
    fail('BUDGET_CORRUPTION', 'active refund has no refund-pending execution case');
  }

  if (refundEvent === null) {
    if (resolution?.state === 'resolved') {
      if (execution?.state === 'succeeded'
          && budget.state === 'committed'
          && refunds.length === 0
          && confirmedRefunds.length === 0) {
        const reconciliations = db.prepare(`SELECT * FROM reconciliations
          WHERE intent_id = ? AND kind = 'execution' AND outcome = 'execution_succeeded'
          ORDER BY rowid`).all(budget.intentId);
        if (reconciliations.length !== 1) {
          fail(
            'BUDGET_CORRUPTION',
            'resolved successful execution lacks one trusted reconciliation',
          );
        }
        const reconciliation = reconciliations[0];
        const evidence = parseCanonicalJson(
          reconciliation.evidence_json,
          'successful execution reconciliation evidence',
        );
        const proof = exactObject(evidence, [
          'kind', 'attestationHash', 'attestation',
        ], [], 'BUDGET_CORRUPTION', 'successful execution reconciliation evidence');
        if (proof.kind !== 'execution_attested'
            || canonicalHash(
              proof.attestationHash,
              'successful execution attestation hash',
            ) !== sha256(canonicalJson(proof.attestation))
            || reconciliation.recorded_at !== execution.recorded_at
            || reconciliation.recorded_at !== resolution.resolved_at) {
          fail(
            'BUDGET_CORRUPTION',
            'resolved successful execution reconciliation binding changed',
          );
        }
        return;
      }
      fail(
        'BUDGET_CORRUPTION',
        'resolved failed execution has no Task-5 confirmed-refund budget transition',
      );
    }
    if (confirmedRefunds.length !== 0) {
      fail('BUDGET_CORRUPTION', 'confirmed refund has no conserved budget transition');
    }
    return;
  }
  if (confirmedRefunds.length !== 1
      || execution?.state !== 'failed'
      || resolution?.state !== 'resolved'
      || Number(resolution.blocks_wallet) !== 0
      || resolution.resolved_at !== refundEvent.confirmedAt) {
    fail('BUDGET_CORRUPTION', 'confirmed refund terminal authority is inconsistent');
  }
  const refund = confirmedRefunds[0];
  if (refund.original_transaction_id !== refundEvent.originalTransactionId
      || refund.refund_transaction_id !== refundEvent.refundTransactionId
      || refund.updated_at !== refundEvent.confirmedAt
      || refund.evidence_json === null) {
    fail('BUDGET_CORRUPTION', 'confirmed refund differs from its budget event');
  }
  const reconciliation = db.prepare('SELECT * FROM reconciliations WHERE id = ?')
    .get(refundEvent.evidenceId);
  if (!reconciliation
      || reconciliation.intent_id !== budget.intentId
      || reconciliation.kind !== 'refund'
      || reconciliation.outcome !== 'refund_confirmed'
      || reconciliation.evidence_json !== refund.evidence_json) {
    fail('BUDGET_CORRUPTION', 'confirmed refund evidence authority changed');
  }
}

function loadReconciliation(db, intentId, evidenceId, kind, outcome) {
  const id = canonicalToken(evidenceId, 'reconciliation evidence ID');
  const row = db.prepare('SELECT * FROM reconciliations WHERE id = ?').get(id);
  if (!row
      || row.intent_id !== intentId
      || row.kind !== kind
      || row.outcome !== outcome) {
    fail('RECONCILIATION_EVIDENCE_MISMATCH', 'reconciliation evidence does not match payment');
  }
  const evidence = parseCanonicalJson(
    row.evidence_json,
    'reconciliation evidence',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  if (!evidence || typeof evidence !== 'object' || Array.isArray(evidence)) {
    fail('RECONCILIATION_EVIDENCE_MISMATCH', 'reconciliation evidence must be one object');
  }
  canonicalHash(
    row.operator_id_hash,
    'reconciliation operator hash',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  canonicalPersistedTimestamp(
    row.recorded_at,
    'reconciliation recordedAt',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  return Object.freeze({ id, row, evidence });
}

function validateSettledTransferEvidence(evidence, authority, attempt, candidateTransactionId) {
  const proof = exactObject(evidence, [
    'kind',
    'transactionId',
    'rpcProofHash',
    'localAttemptHash',
  ], [], 'RECONCILIATION_EVIDENCE_MISMATCH', 'settled-transfer proof');
  const transactionId = canonicalEvmHashFor(
    proof.transactionId,
    'settled-transfer transaction ID',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const rpcProofHash = canonicalHash(
    proof.rpcProofHash,
    'settled-transfer RPC proof hash',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const localHash = canonicalHash(
    proof.localAttemptHash,
    'settled-transfer local attempt hash',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  if (proof.kind !== 'settled_transfer'
      || proof.transactionId !== transactionId
      || transactionId !== candidateTransactionId
      || proof.rpcProofHash !== rpcProofHash
      || proof.localAttemptHash !== localHash
      || localHash !== localAttemptBindingHash(authority, attempt)) {
    fail(
      'RECONCILIATION_EVIDENCE_MISMATCH',
      'settled-transfer proof does not bind the exact persisted attempt and candidate',
    );
  }
  return frozenCopy(proof);
}

function validateConfirmedRefundEvidence(
  evidence,
  authority,
  attempt,
  refundTransactionId,
) {
  const proof = exactObject(evidence, [
    'kind',
    'originalTransactionId',
    'refundTransactionId',
    'attestationHash',
    'attestation',
    'rpcProofHash',
    'localRefundBindingHash',
  ], [], 'REFUND_EVIDENCE_MISMATCH', 'confirmed-refund proof');
  const originalTransactionId = canonicalEvmHashFor(
    proof.originalTransactionId,
    'refund proof original transaction ID',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const proofRefundTransactionId = canonicalEvmHashFor(
    proof.refundTransactionId,
    'refund proof transaction ID',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const attestationHash = canonicalHash(
    proof.attestationHash,
    'refund attestation hash',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const attestation = exactObject(proof.attestation, [
    'schemaVersion',
    'domain',
    'network',
    'sellerOrigin',
    'intentHash',
    'originalTransactionId',
    'refundTransactionId',
    'asset',
    'originalPayer',
    'originalPayee',
    'refundSource',
    'amountAtomic',
    'issuedAt',
    'expiresAt',
    'signer',
  ], [], 'REFUND_EVIDENCE_MISMATCH', 'refund attestation');
  const issuedAt = canonicalPersistedTimestamp(
    attestation.issuedAt,
    'refund attestation issuedAt',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const expiresAt = canonicalPersistedTimestamp(
    attestation.expiresAt,
    'refund attestation expiresAt',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const rpcProofHash = canonicalHash(
    proof.rpcProofHash,
    'refund RPC proof hash',
    'REFUND_EVIDENCE_MISMATCH',
  );
  const localHash = canonicalHash(
    proof.localRefundBindingHash,
    'local refund binding hash',
    'REFUND_EVIDENCE_MISMATCH',
  );
  if (proof.kind !== 'refund_attested_and_confirmed'
      || proof.originalTransactionId !== originalTransactionId
      || proof.refundTransactionId !== proofRefundTransactionId
      || originalTransactionId !== attempt.transaction_id
      || proofRefundTransactionId !== refundTransactionId
      || proof.attestationHash !== attestationHash
      || sha256(canonicalJson(attestation)) !== attestationHash
      || attestation.schemaVersion !== 1
      || attestation.domain !== 'wallet-kernel.refund.v1'
      || attestation.network !== authority.policyVersion.policy.network
      || attestation.sellerOrigin !== authority.intent.seller_origin
      || attestation.intentHash !== authority.intent.intent_hash
      || attestation.originalTransactionId !== originalTransactionId
      || attestation.refundTransactionId !== proofRefundTransactionId
      || attestation.asset !== authority.policyVersion.policy.asset
      || attestation.originalPayer !== authority.session.wallet_address
      || attestation.originalPayee !== authority.projection.selected.payTo
      || attestation.refundSource !== authority.projection.seller.refundSource
      || attestation.amountAtomic !== authority.amount.text
      || attestation.signer !== authority.projection.seller.refundSigner
      || Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(issuedAt) > 15 * 60 * 1_000
      || proof.rpcProofHash !== rpcProofHash
      || proof.localRefundBindingHash !== localHash
      || localHash !== localRefundBindingHash(authority, attempt, refundTransactionId)) {
    fail(
      'REFUND_EVIDENCE_MISMATCH',
      'confirmed-refund proof does not bind the exact payment, refund, and policy authority',
    );
  }
  return frozenCopy(proof);
}

function validateUnusedAuthorizationEvidence(
  evidence,
  authority,
  attempt,
  reconciliationRecordedAt,
  resolvedAt,
) {
  const proof = exactObject(evidence, [
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
  ], [], 'RECONCILIATION_EVIDENCE_MISMATCH', 'unused-authorization proof');
  const observedBlockNumber = canonicalAtomicText(
    proof.observedBlockNumber,
    'observed block number',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const observedBlockTimestamp = canonicalAtomicText(
    proof.observedBlockTimestamp,
    'observed block timestamp',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const validBefore = canonicalAtomicText(
    proof.validBefore,
    'authorization validBefore',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const confirmations = safeInteger(
    proof.confirmations,
    'reconciliation confirmations',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const recordedAt = canonicalPersistedTimestamp(
    reconciliationRecordedAt,
    'unused-authorization reconciliation recordedAt',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const resolutionTime = canonicalPersistedTimestamp(
    resolvedAt,
    'unused-authorization resolution time',
    'RECONCILIATION_EVIDENCE_MISMATCH',
  );
  const recordedEpochSeconds = BigInt(Math.floor(Date.parse(recordedAt) / 1_000));
  if (proof.kind !== 'authorization_unused_after_expiry'
      || proof.network !== authority.policyVersion.policy.network
      || canonicalAddress(
        proof.asset,
        'unused-authorization asset',
        'RECONCILIATION_EVIDENCE_MISMATCH',
      ) !== authority.policyVersion.policy.asset
      || canonicalAddress(
        proof.payer,
        'unused-authorization payer',
        'RECONCILIATION_EVIDENCE_MISMATCH',
      ) !== authority.session.wallet_address
      || typeof proof.nonce !== 'string'
      || !/^0x[0-9a-f]{64}$/.test(proof.nonce)
      || proof.nonce !== attempt.nonce
      || validBefore.text !== attempt.valid_before
      || proof.authorizationState !== false
      || observedBlockNumber.value <= 0n
      || canonicalEvmHashFor(
        proof.observedBlockHash,
        'observed block hash',
        'RECONCILIATION_EVIDENCE_MISMATCH',
      )
        !== proof.observedBlockHash
      || observedBlockTimestamp.value < validBefore.value
      || observedBlockTimestamp.value > recordedEpochSeconds
      || Date.parse(recordedAt) > Date.parse(resolutionTime)
      || confirmations < 1) {
    fail(
      'RECONCILIATION_EVIDENCE_MISMATCH',
      'only exact post-expiry unused-authorization proof can release a signed hold',
    );
  }
  return frozenCopy(proof);
}

function writeBuyerOutcome(
  db,
  intentId,
  status,
  reasonCode,
  recordedAt,
  expectedPredecessorStatus,
) {
  const current = db.prepare('SELECT * FROM buyer_outcomes WHERE intent_id = ?').get(intentId);
  if (!current) {
    fail('BUYER_OUTCOME_CORRUPTION', 'BuyerOutcome predecessor is missing');
  }
  if (current.status !== expectedPredecessorStatus
      || typeof current.reason_code !== 'string'
      || !/^[A-Z][A-Z0-9_]{0,99}$/.test(current.reason_code)) {
    fail('BUYER_OUTCOME_CORRUPTION', 'BuyerOutcome is not the exact legal predecessor');
  }
  canonicalPersistedTimestamp(
    current.recorded_at,
    'BuyerOutcome recordedAt',
    'BUYER_OUTCOME_CORRUPTION',
  );
  if (Date.parse(current.recorded_at) > Date.parse(recordedAt)) {
    fail('BUYER_OUTCOME_CORRUPTION', 'BuyerOutcome time regressed');
  }
  const revision = safeInteger(
    current.revision,
    'buyer outcome revision',
    'BUYER_OUTCOME_CORRUPTION',
  ) + 1;
  if (!Number.isSafeInteger(revision)) fail('BUDGET_CORRUPTION', 'buyer outcome revision overflowed');
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
  if (changed.changes !== 1n) fail('BUDGET_CONFLICT', 'buyer outcome update lost its race');
  return revision;
}

export function createBudgetLedger({ store, now }) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('budget ledger requires a Wallet Kernel store');
  }
  if (typeof now !== 'function' || utilTypes.isProxy(now)) {
    throw new TypeError('budget ledger requires an ordinary clock');
  }

  const prepareSnapshot = (input) => {
    const record = closedInput(
      input,
      ['sessionId', 'sellerOrigin'],
      ['at'],
      'BUDGET_SNAPSHOT_SCHEMA',
      'budget snapshot request',
    );
    return Object.freeze({
      sessionId: canonicalToken(record.sessionId, 'session ID'),
      sellerOrigin: canonicalOrigin(record.sellerOrigin, 'seller origin'),
      at: canonicalTimestamp(
        Object.hasOwn(record, 'at') ? record.at : now(),
        'budget snapshot time',
      ),
    });
  };

  const snapshotInTransaction = (token, input) => store.within(
    token,
    ({ db }) => snapshotImpl(db, prepareSnapshot(input)).public,
  );

  const snapshot = (input) => {
    const prepared = prepareSnapshot(input);
    return store.transaction((token) => store.within(
      token,
      ({ db }) => snapshotImpl(db, prepared).public,
    ));
  };

  const prepareReserve = (input) => {
    const record = closedInput(
      input,
      ['intentId', 'amountAtomic'],
      [],
      'BUDGET_RESERVE_SCHEMA',
      'budget reservation',
    );
    const amount = canonicalAtomicText(record.amountAtomic, 'reservation amount', 'BUDGET_RESERVE');
    if (amount.value <= 0n) fail('BUDGET_RESERVE', 'reservation amount must be positive');
    return Object.freeze({
      intentId: canonicalToken(record.intentId, 'intent ID'),
      amount,
    });
  };

  const reserveImpl = (db, appendEvent, prepared) => {
    if (readBudgetRow(db, prepared.intentId)) {
      fail('BUDGET_ALREADY_RESERVED', 'Spend Intent already owns a BudgetReservation');
    }
    const updatedAt = canonicalTimestamp(now(), 'budget reservedAt');
    const authority = loadReservationAuthority(db, prepared.intentId, {
      requireReservable: true,
      at: updatedAt,
    });
    if (authority.amount.text !== prepared.amount.text) {
      fail('BUDGET_AMOUNT_MISMATCH', 'reservation amount differs from PolicyDecision ceiling');
    }
    const current = snapshotImpl(db, {
      sessionId: authority.session.id,
      sellerOrigin: authority.intent.seller_origin,
      at: updatedAt,
    });
    if (current.blockers.unresolvedBudget) {
      fail('WALLET_UNRESOLVED', 'wallet has an unresolved payment hold');
    }
    if (current.blockers.resolutionRequired) {
      fail('WALLET_RESOLUTION_REQUIRED', 'wallet has unresolved execution or refund state');
    }
    const amount = prepared.amount.value;
    const { seller } = authority.projection;
    const policy = authority.policyVersion.policy;
    if (BigInt(current.public.sellerSessionExposureAtomic) + amount
          > BigInt(seller.sellerSessionMaxAtomic)
        || BigInt(current.public.sessionExposureAtomic) + amount
          > BigInt(policy.sessionMaxAtomic)
        || BigInt(current.public.rolling24hExposureAtomic) + amount
          > BigInt(policy.rolling24hMaxAtomic)) {
      fail('LIMIT_EXCEEDED', 'BudgetReservation exceeds an authoritative spend ceiling');
    }
    const inserted = db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, ?, ?, ?, '0', '0', '0', 'reserved', NULL, ?)`).run(
      prepared.intentId,
      authority.session.id,
      authority.intent.seller_origin,
      prepared.amount.text,
      updatedAt,
    );
    if (inserted.changes !== 1n) fail('BUDGET_CONFLICT', 'reservation insert lost its race');
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.reserved',
      data: {
        sessionId: authority.session.id,
        sellerOrigin: authority.intent.seller_origin,
        amountAtomic: prepared.amount.text,
        previousState: null,
        nextState: 'reserved',
        updatedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted) fail('BUDGET_CORRUPTION', 'new BudgetReservation disappeared');
    snapshotImpl(db, {
      sessionId: authority.session.id,
      sellerOrigin: authority.intent.seller_origin,
      at: updatedAt,
    });
    return publicReservation(persisted);
  };

  const reserveInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => reserveImpl(db, appendEvent, prepareReserve(input)),
  );

  const reserve = (input) => {
    const prepared = prepareReserve(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => reserveImpl(db, appendEvent, prepared),
    ));
  };

  const prepareCommit = (input) => {
    const record = closedInput(
      input,
      ['intentId', 'settlementEvidence'],
      [],
      'BUDGET_COMMIT_SCHEMA',
      'budget commit',
    );
    const settlementEvidence = validateSettlementEvidence(
      Object.getOwnPropertyDescriptor(input, 'settlementEvidence').value,
    );
    return Object.freeze({
      intentId: canonicalToken(record.intentId, 'intent ID'),
      settlementEvidence,
    });
  };

  const commitImpl = (db, appendEvent, prepared) => {
    const authority = loadReservationAuthority(db, prepared.intentId);
    const reservation = readBudgetRow(db, prepared.intentId);
    if (!reservation) fail('BUDGET_RESERVATION_MISSING', 'BudgetReservation does not exist');
    const evidence = prepared.settlementEvidence;
    const evidenceJson = canonicalJson(evidence);
    const transactionId = evidence.transaction;
    if (evidence.network !== authority.policyVersion.policy.network
        || evidence.payer !== authority.session.wallet_address
        || evidence.paymentHash === null
        || (Object.hasOwn(evidence, 'amountAtomic')
          && evidence.amountAtomic !== authority.amount.text)) {
      fail('SETTLEMENT_BINDING_MISMATCH', 'settlement evidence differs from persisted authority');
    }
    assertGloballyUniqueTransaction(db, transactionId, {
      allowedPaymentIntentId: prepared.intentId,
    });

    if (reservation.state === 'committed') {
      const attempt = validatePaymentAttempt(db, authority, new Set(['settled'])).row;
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.committed');
      if (attempt.transaction_id !== transactionId
          || attempt.payment_hash !== evidence.paymentHash
          || attempt.settlement_json !== evidenceJson
          || !event
          || event.transactionId !== transactionId
          || event.paymentHash !== evidence.paymentHash
          || event.headerHash !== evidence.headerHash
          || event.amountAtomic !== authority.amount.text
          || event.previousState !== 'reserved'
          || event.nextState !== 'committed') {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'committed payment replay differs from authority');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'reserved') {
      fail('BUDGET_STATE', 'only a reserved BudgetReservation can commit');
    }
    if (authority.intent.state !== 'retrying') {
      fail('PAYMENT_ATTEMPT_STATE', 'budget commit requires retrying Spend Intent');
    }
    const attempt = validatePaymentAttempt(db, authority, new Set(['retrying'])).row;
    if (attempt.payment_hash !== evidence.paymentHash) {
      fail('SETTLEMENT_BINDING_MISMATCH', 'settlement payment hash differs from paid retry');
    }
    const reused = db.prepare(`SELECT intent_id FROM payment_attempts
      WHERE transaction_id = ? AND intent_id != ?`).get(transactionId, prepared.intentId);
    if (reused) fail('TRANSACTION_REUSED', 'settlement transaction belongs to another intent');
    const committedAt = canonicalTimestamp(now(), 'budget committedAt');
    if (Date.parse(committedAt) < Date.parse(attempt.retry_started_at)) {
      fail('BUDGET_TIME', 'budget commit predates paid retry');
    }
    const attemptUpdate = db.prepare(`UPDATE payment_attempts
      SET state = 'settled', settlement_json = ?, transaction_id = ?, reason_code = NULL,
          settled_at = ?, updated_at = ?
      WHERE intent_id = ? AND state = 'retrying'
        AND settlement_json IS NULL AND transaction_id IS NULL AND settled_at IS NULL`).run(
      evidenceJson,
      transactionId,
      committedAt,
      committedAt,
      prepared.intentId,
    );
    if (attemptUpdate.changes !== 1n) {
      fail('PAYMENT_ATTEMPT_STATE', 'PaymentAttempt commit lost its race');
    }
    const budgetUpdate = db.prepare(`UPDATE budget_reservations
      SET reserved_atomic = '0', committed_atomic = ?, state = 'committed',
          committed_at = ?, updated_at = ?
      WHERE intent_id = ? AND state = 'reserved'
        AND reserved_atomic = ? AND committed_atomic = '0'
        AND released_atomic = '0' AND unresolved_atomic = '0'`).run(
      authority.amount.text,
      committedAt,
      committedAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (budgetUpdate.changes !== 1n) fail('BUDGET_CONFLICT', 'budget commit lost its race');
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.committed',
      data: {
        amountAtomic: authority.amount.text,
        transactionId,
        paymentHash: evidence.paymentHash,
        headerHash: evidence.headerHash,
        previousState: 'reserved',
        nextState: 'committed',
        committedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'committed') {
      fail('BUDGET_CORRUPTION', 'committed BudgetReservation disappeared');
    }
    const persistedAttempt = validatePaymentAttempt(
      db,
      authority,
      new Set(['settled']),
    ).row;
    if (persistedAttempt.transaction_id !== transactionId
        || persistedAttempt.payment_hash !== evidence.paymentHash
        || persistedAttempt.settlement_json !== evidenceJson) {
      fail('PAYMENT_ATTEMPT_CORRUPTION', 'committed transaction did not persist exactly');
    }
    snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: committedAt,
    });
    return publicReservation(persisted);
  };

  const commitInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => commitImpl(db, appendEvent, prepareCommit(input)),
  );

  const commit = (input) => {
    const prepared = prepareCommit(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => commitImpl(db, appendEvent, prepared),
    ));
  };

  const prepareReasonTransition = (input, { preSignField = false } = {}) => {
    let intentId;
    let reason;
    let preSignRejection;
    let hasPreSignRejection = false;
    if (preSignField) {
      if (!input || typeof input !== 'object' || utilTypes.isProxy(input)
          || Array.isArray(input) || Object.getPrototypeOf(input) !== Object.prototype) {
        fail('BUDGET_TRANSITION_SCHEMA', 'budget transition must be one plain object');
      }
      const keys = Reflect.ownKeys(input);
      const allowed = new Set(['intentId', 'reasonCode', 'preSignRejection']);
      const descriptors = new Map();
      if (!Object.hasOwn(input, 'intentId') || !Object.hasOwn(input, 'reasonCode')
          || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
        fail('BUDGET_TRANSITION_SCHEMA', 'budget transition fields do not match the closed schema');
      }
      for (const key of keys) {
        const descriptor = Object.getOwnPropertyDescriptor(input, key);
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
          fail('BUDGET_TRANSITION_SCHEMA', 'budget transition fields do not match the closed schema');
        }
        descriptors.set(key, descriptor.value);
      }
      intentId = descriptors.get('intentId');
      reason = descriptors.get('reasonCode');
      hasPreSignRejection = descriptors.has('preSignRejection');
      preSignRejection = descriptors.get('preSignRejection');
    } else {
      const record = closedInput(
        input,
        ['intentId', 'reasonCode'],
        [],
        'BUDGET_TRANSITION_SCHEMA',
        'budget transition',
      );
      intentId = record.intentId;
      reason = record.reasonCode;
    }
    if (typeof reason !== 'string'
        || !/^[A-Z][A-Z0-9_]{0,99}$/.test(reason)) {
      fail('BUDGET_REASON', 'budget reason code must be one stable uppercase token');
    }
    return Object.freeze({
      intentId: canonicalToken(intentId, 'intent ID'),
      reasonCode: reason,
      hasPreSignRejection,
      preSignRejection,
    });
  };

  const releaseImpl = (db, appendEvent, prepared) => {
    const typedPreSignRelease = prepared.hasPreSignRejection
      && isExactPreSignRejection(prepared.preSignRejection)
      && prepared.reasonCode === 'WALLET_PRE_SIGN_REJECTED';
    if (prepared.hasPreSignRejection && !typedPreSignRelease) {
      fail(
        'BUDGET_RELEASE_UNSAFE',
        'only the exact typed pre-sign rejection can release after a signing claim',
      );
    }
    if (prepared.reasonCode === 'WALLET_PRE_SIGN_REJECTED' && !typedPreSignRelease) {
      fail('BUDGET_RELEASE_UNSAFE', 'typed pre-sign release proof is required');
    }
    const authority = loadReservationAuthority(db, prepared.intentId);
    const reservation = readBudgetRow(db, prepared.intentId);
    if (!reservation) fail('BUDGET_RESERVATION_MISSING', 'BudgetReservation does not exist');
    if (reservation.state === 'released') {
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.released');
      const rawAttempt = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?')
        .get(prepared.intentId);
      if (rawAttempt) {
        const attempt = validatePaymentAttempt(db, authority, new Set(['rejected'])).row;
        const claimOnly = attempt.signing_claimed_at !== null
          && attempt.payment_payload_json === null;
        if (attempt.payment_payload_json !== null
            || attempt.reason_code !== prepared.reasonCode
            || claimOnly !== typedPreSignRelease) {
          fail('BUDGET_IDEMPOTENCY_CONFLICT', 'released payment attempt replay changed');
        }
      }
      if (!event
          || event.reasonCode !== prepared.reasonCode
          || event.amountAtomic !== authority.amount.text
          || event.previousState !== 'reserved'
          || event.nextState !== 'released') {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'budget release replay differs from authority');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'reserved') {
      fail('BUDGET_RELEASE_UNSAFE', 'only a definitely unsigned reservation can release');
    }
    const rawAttempt = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?')
      .get(prepared.intentId);
    const releasedAt = canonicalTimestamp(now(), 'budget releasedAt');
    if (typedPreSignRelease) {
      if (authority.intent.state !== 'signing' || !rawAttempt) {
        fail('BUDGET_RELEASE_UNSAFE', 'typed release requires the live signing boundary');
      }
      const attempt = validatePaymentAttempt(db, authority, new Set(['signing'])).row;
      assertTransitionChronology(releasedAt, attemptChronology(attempt));
      const attemptUpdate = db.prepare(`UPDATE payment_attempts
        SET state = 'rejected', reason_code = ?, updated_at = ?
        WHERE intent_id = ? AND state = 'signing'
          AND nonce IS NOT NULL AND valid_after IS NOT NULL AND valid_before IS NOT NULL
          AND signing_claimed_at IS NOT NULL AND payment_payload_json IS NULL
          AND payment_header IS NULL AND payment_hash IS NULL AND signed_at IS NULL
          AND retry_started_at IS NULL AND settlement_json IS NULL
          AND transaction_id IS NULL AND settled_at IS NULL`).run(
        prepared.reasonCode,
        releasedAt,
        prepared.intentId,
      );
      if (attemptUpdate.changes !== 1n) {
        fail('BUDGET_RELEASE_UNSAFE', 'PaymentAttempt is not one claim-only signing attempt');
      }
    } else {
      if (authority.intent.state !== 'authorized' && authority.intent.state !== 'reserved') {
        fail('BUDGET_RELEASE_UNSAFE', 'Spend Intent may have entered the signing boundary');
      }
      if (rawAttempt) validatePaymentAttempt(db, authority, new Set(['reserved']));
      if (rawAttempt) {
        const attemptUpdate = db.prepare(`UPDATE payment_attempts
          SET state = 'rejected', reason_code = ?, updated_at = ?
          WHERE intent_id = ? AND state = 'reserved'
            AND nonce IS NULL AND valid_after IS NULL AND valid_before IS NULL
            AND signing_claimed_at IS NULL AND payment_payload_json IS NULL
            AND payment_header IS NULL AND payment_hash IS NULL AND signed_at IS NULL`).run(
          prepared.reasonCode,
          releasedAt,
          prepared.intentId,
        );
        if (attemptUpdate.changes !== 1n) {
          fail('BUDGET_RELEASE_UNSAFE', 'PaymentAttempt is not definitely unsigned');
        }
      }
    }
    const changed = db.prepare(`UPDATE budget_reservations
      SET reserved_atomic = '0', released_atomic = ?, state = 'released', updated_at = ?
      WHERE intent_id = ? AND state = 'reserved'
        AND reserved_atomic = ? AND committed_atomic = '0'
        AND released_atomic = '0' AND unresolved_atomic = '0'`).run(
      authority.amount.text,
      releasedAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (changed.changes !== 1n) fail('BUDGET_CONFLICT', 'budget release lost its race');
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.released',
      data: {
        amountAtomic: authority.amount.text,
        reasonCode: prepared.reasonCode,
        previousState: 'reserved',
        nextState: 'released',
        releasedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'released') {
      fail('BUDGET_CORRUPTION', 'released BudgetReservation disappeared');
    }
    snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: releasedAt,
    });
    return publicReservation(persisted);
  };

  const releaseInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => releaseImpl(
      db,
      appendEvent,
      prepareReasonTransition(input, { preSignField: true }),
    ),
  );

  const release = (input) => {
    const prepared = prepareReasonTransition(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => releaseImpl(db, appendEvent, prepared),
    ));
  };

  const holdUnresolvedImpl = (db, appendEvent, prepared) => {
    const authority = loadReservationAuthority(db, prepared.intentId);
    const reservation = readBudgetRow(db, prepared.intentId);
    if (!reservation) fail('BUDGET_RESERVATION_MISSING', 'BudgetReservation does not exist');
    if (reservation.state === 'unresolved') {
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.held_unresolved');
      if (!event
          || event.reasonCode !== prepared.reasonCode
          || event.amountAtomic !== authority.amount.text
          || event.previousState !== 'reserved'
          || event.nextState !== 'unresolved') {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'unresolved hold replay differs from authority');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'reserved') {
      fail('BUDGET_STATE', 'only a reserved BudgetReservation can become unresolved');
    }
    const heldAt = canonicalTimestamp(now(), 'budget unresolvedAt');
    const changed = db.prepare(`UPDATE budget_reservations
      SET reserved_atomic = '0', unresolved_atomic = ?, state = 'unresolved', updated_at = ?
      WHERE intent_id = ? AND state = 'reserved'
        AND reserved_atomic = ? AND committed_atomic = '0'
        AND released_atomic = '0' AND unresolved_atomic = '0'`).run(
      authority.amount.text,
      heldAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (changed.changes !== 1n) fail('BUDGET_CONFLICT', 'unresolved hold lost its race');
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.held_unresolved',
      data: {
        amountAtomic: authority.amount.text,
        reasonCode: prepared.reasonCode,
        previousState: 'reserved',
        nextState: 'unresolved',
        heldAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'unresolved') {
      fail('BUDGET_CORRUPTION', 'unresolved BudgetReservation disappeared');
    }
    const after = snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: heldAt,
    });
    if (!after.blockers.unresolvedBudget) {
      fail('BUDGET_CORRUPTION', 'unresolved hold did not block its wallet');
    }
    return publicReservation(persisted);
  };

  const holdUnresolvedInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => holdUnresolvedImpl(
      db,
      appendEvent,
      prepareReasonTransition(input),
    ),
  );

  const holdUnresolved = (input) => {
    const prepared = prepareReasonTransition(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => holdUnresolvedImpl(db, appendEvent, prepared),
    ));
  };

  const preparePaymentResolution = (input) => {
    const record = closedInput(
      input,
      ['intentId', 'outcome', 'evidenceId'],
      [],
      'PAYMENT_RESOLUTION_SCHEMA',
      'payment resolution',
    );
    if (record.outcome !== 'settled' && record.outcome !== 'rejected') {
      fail('PAYMENT_RESOLUTION_OUTCOME', 'payment resolution must be settled or rejected');
    }
    return Object.freeze({
      intentId: canonicalToken(record.intentId, 'intent ID'),
      outcome: record.outcome,
      evidenceId: canonicalToken(record.evidenceId, 'reconciliation evidence ID'),
    });
  };

  const loadPaymentCandidates = (db, intentId) => db.prepare(`SELECT *
    FROM payment_reconciliation_candidates
    WHERE intent_id = ? ORDER BY rowid`).all(intentId);

  const validateCandidate = (candidate, intentId) => {
    canonicalToken(candidate.id, 'payment reconciliation candidate ID');
    const transactionId = canonicalEvmHash(
      candidate.transaction_id,
      'payment reconciliation transaction',
    );
    if (candidate.transaction_id !== transactionId
        || candidate.intent_id !== intentId
        || !new Set(['pending', 'abandoned', 'rejected', 'confirmed']).has(candidate.state)) {
      fail('RECONCILIATION_EVIDENCE_MISMATCH', 'payment candidate binding is invalid');
    }
    canonicalPersistedTimestamp(
      candidate.created_at,
      'payment candidate createdAt',
      'RECONCILIATION_EVIDENCE_MISMATCH',
    );
    canonicalPersistedTimestamp(
      candidate.updated_at,
      'payment candidate updatedAt',
      'RECONCILIATION_EVIDENCE_MISMATCH',
    );
    if (candidate.evidence_json !== null) {
      parseCanonicalJson(
        candidate.evidence_json,
        'payment candidate evidence',
        'RECONCILIATION_EVIDENCE_MISMATCH',
      );
    }
    return Object.freeze({ row: candidate, transactionId });
  };

  const assertResolvedBuyerOutcome = (db, intentId, status, reasonCode) => {
    const outcome = db.prepare('SELECT * FROM buyer_outcomes WHERE intent_id = ?').get(intentId);
    if (!outcome || outcome.status !== status || outcome.reason_code !== reasonCode) {
      fail('BUDGET_IDEMPOTENCY_CONFLICT', 'payment resolution BuyerOutcome changed');
    }
    safeInteger(outcome.revision, 'buyer outcome revision');
    canonicalPersistedTimestamp(outcome.recorded_at, 'buyer outcome recordedAt');
    return outcome;
  };

  const resolveSettledPayment = (
    db,
    appendEvent,
    prepared,
    authority,
    reservation,
    reconciliation,
  ) => {
    const evidenceJson = reconciliation.row.evidence_json;
    const candidates = loadPaymentCandidates(db, prepared.intentId).map(
      (candidate) => validateCandidate(candidate, prepared.intentId),
    );
    const liveCandidates = candidates.filter(
      (candidate) => candidate.row.state === 'pending' || candidate.row.state === 'confirmed',
    );
    if (liveCandidates.length !== 1) {
      fail(
        'RECONCILIATION_EVIDENCE_MISMATCH',
        'settled payment resolution requires one persisted transaction candidate',
      );
    }
    const candidate = liveCandidates[0];

    if (reservation.state === 'committed') {
      const attempt = validatePaymentAttempt(db, authority, new Set(['settled'])).row;
      validateSettledTransferEvidence(
        reconciliation.evidence,
        authority,
        attempt,
        candidate.transactionId,
      );
      assertGloballyUniqueTransaction(db, candidate.transactionId, {
        allowedPaymentIntentId: prepared.intentId,
        allowedPaymentCandidateId: candidate.row.id,
      });
      const execution = db.prepare('SELECT * FROM execution_outcomes WHERE intent_id = ?')
        .get(prepared.intentId);
      const resolution = db.prepare('SELECT * FROM execution_resolutions WHERE intent_id = ?')
        .get(prepared.intentId);
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.payment_resolved');
      const buyerOutcome = assertResolvedBuyerOutcome(
        db,
        prepared.intentId,
        'execution_unknown',
        'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
      );
      const replayNow = canonicalTimestamp(now(), 'payment reconciliation replay time');
      if (!event || Date.parse(event.resolvedAt) > Date.parse(replayNow)) {
        fail('BUDGET_TIME', 'payment reconciliation replay clock regressed');
      }
      assertTransitionChronology(event.resolvedAt, [
        ['BudgetReservation updatedAt', reservation.updatedAt],
        ['BudgetReservation committedAt', reservation.committedAt],
        ...attemptChronology(attempt),
        ['payment candidate createdAt', candidate.row.created_at],
        ['payment candidate updatedAt', candidate.row.updated_at],
        ['payment reconciliation recordedAt', reconciliation.row.recorded_at],
        ['execution outcome recordedAt', execution?.recorded_at],
        ['execution resolution openedAt', resolution?.opened_at],
        ['BuyerOutcome recordedAt', buyerOutcome.recorded_at],
      ]);
      if (attempt.transaction_id !== candidate.transactionId
          || attempt.settlement_json !== evidenceJson
          || candidate.row.state !== 'confirmed'
          || candidate.row.evidence_json !== evidenceJson
          || execution?.state !== 'unknown'
          || resolution?.state !== 'reconciliation_required'
          || BigInt(resolution?.blocks_wallet ?? 0) !== 1n
          || !event
          || event.evidenceId !== prepared.evidenceId
          || event.outcome !== 'settled'
          || event.transactionId !== candidate.transactionId
          || event.previousState !== 'unresolved'
          || event.nextState !== 'committed'
          || event.buyerOutcomeRevision !== Number(buyerOutcome.revision)) {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'settled payment resolution replay changed');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'unresolved') {
      fail('BUDGET_STATE', 'settled reconciliation requires one unresolved hold');
    }
    const attempt = validatePaymentAttempt(db, authority, new Set(['unresolved'])).row;
    if (candidate.row.state !== 'pending') {
      fail(
        'RECONCILIATION_EVIDENCE_MISMATCH',
        'unresolved payment requires one still-pending transaction candidate',
      );
    }
    if (attempt.payment_payload_json === null) {
      fail('RECONCILIATION_EVIDENCE_MISMATCH', 'settlement cannot bind an unpersisted signature');
    }
    if (candidate.row.evidence_json !== null) {
      fail(
        'RECONCILIATION_EVIDENCE_MISMATCH',
        'pending payment candidate already contains evidence',
      );
    }
    validateSettledTransferEvidence(
      reconciliation.evidence,
      authority,
      attempt,
      candidate.transactionId,
    );
    assertGloballyUniqueTransaction(db, candidate.transactionId, {
      allowedPaymentIntentId: prepared.intentId,
      allowedPaymentCandidateId: candidate.row.id,
    });
    const resolvedAt = canonicalTimestamp(now(), 'payment reconciliation time');
    const predecessorOutcome = db.prepare(
      'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
    ).get(prepared.intentId);
    assertTransitionChronology(resolvedAt, [
      ['BudgetReservation unresolvedAt', reservation.updatedAt],
      ...attemptChronology(attempt),
      ['payment candidate createdAt', candidate.row.created_at],
      ['payment candidate updatedAt', candidate.row.updated_at],
      ['payment reconciliation recordedAt', reconciliation.row.recorded_at],
      ['BuyerOutcome predecessor recordedAt', predecessorOutcome?.recorded_at],
    ]);
    if (candidate.row.state === 'pending') {
      const candidateUpdate = db.prepare(`UPDATE payment_reconciliation_candidates
        SET state = 'confirmed', evidence_json = ?, updated_at = ?
        WHERE id = ? AND intent_id = ? AND state = 'pending'
          AND transaction_id = ?`).run(
        evidenceJson,
        resolvedAt,
        candidate.row.id,
        prepared.intentId,
        candidate.transactionId,
      );
      if (candidateUpdate.changes !== 1n) {
        fail('RECONCILIATION_CONFLICT', 'payment candidate confirmation lost its race');
      }
    } else if (candidate.row.evidence_json !== evidenceJson) {
      fail('RECONCILIATION_EVIDENCE_MISMATCH', 'confirmed candidate evidence changed');
    }
    const attemptUpdate = db.prepare(`UPDATE payment_attempts
      SET state = 'settled', settlement_json = ?, transaction_id = ?,
          reason_code = 'TRUSTED_RECONCILIATION', settled_at = ?, updated_at = ?
      WHERE intent_id = ? AND state = 'unresolved'
        AND settlement_json IS NULL AND transaction_id IS NULL`).run(
      evidenceJson,
      candidate.transactionId,
      resolvedAt,
      resolvedAt,
      prepared.intentId,
    );
    if (attemptUpdate.changes !== 1n) {
      fail('PAYMENT_ATTEMPT_STATE', 'payment reconciliation lost its attempt race');
    }
    const budgetUpdate = db.prepare(`UPDATE budget_reservations
      SET unresolved_atomic = '0', committed_atomic = ?, state = 'committed',
          committed_at = ?, updated_at = ?
      WHERE intent_id = ? AND state = 'unresolved'
        AND unresolved_atomic = ? AND reserved_atomic = '0'
        AND committed_atomic = '0' AND released_atomic = '0'`).run(
      authority.amount.text,
      resolvedAt,
      resolvedAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (budgetUpdate.changes !== 1n) {
      fail('BUDGET_CONFLICT', 'payment reconciliation lost its budget race');
    }
    if (db.prepare('SELECT intent_id FROM execution_outcomes WHERE intent_id = ?')
      .get(prepared.intentId)
      || db.prepare('SELECT intent_id FROM execution_resolutions WHERE intent_id = ?')
        .get(prepared.intentId)) {
      fail('BUDGET_CORRUPTION', 'unresolved payment already owns execution state');
    }
    const executionMetadata = canonicalJson({
      reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
      reconciliationEvidenceId: prepared.evidenceId,
    });
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'unknown', NULL, NULL, ?, ?)`).run(
      prepared.intentId,
      executionMetadata,
      resolvedAt,
    );
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
      VALUES (?, 'reconciliation_required', ?, 1, ?, NULL)`).run(
      prepared.intentId,
      'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
      resolvedAt,
    );
    const buyerOutcomeRevision = writeBuyerOutcome(
      db,
      prepared.intentId,
      'execution_unknown',
      'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
      resolvedAt,
      'payment_unresolved',
    );
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.payment_resolved',
      data: {
        evidenceId: prepared.evidenceId,
        outcome: 'settled',
        transactionId: candidate.transactionId,
        amountAtomic: authority.amount.text,
        previousState: 'unresolved',
        nextState: 'committed',
        buyerOutcomeRevision,
        resolvedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'committed') {
      fail('BUDGET_CORRUPTION', 'reconciled committed budget disappeared');
    }
    const after = snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: resolvedAt,
    });
    if (!after.blockers.resolutionRequired) {
      fail('BUDGET_CORRUPTION', 'unknown reconciled execution did not block the wallet');
    }
    return publicReservation(persisted);
  };

  const resolveRejectedPayment = (
    db,
    appendEvent,
    prepared,
    authority,
    reservation,
    reconciliation,
  ) => {
    const candidates = loadPaymentCandidates(db, prepared.intentId).map(
      (candidate) => validateCandidate(candidate, prepared.intentId),
    );
    if (candidates.some((candidate) => candidate.row.state === 'confirmed')) {
      fail('RECONCILIATION_EVIDENCE_MISMATCH', 'confirmed payment cannot be rejected');
    }
    if (reservation.state === 'released') {
      const attempt = validatePaymentAttempt(db, authority, new Set(['rejected'])).row;
      if (attempt.payment_payload_json === null) {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'rejected payment proof lost its signed attempt');
      }
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.payment_resolved');
      const replayNow = canonicalTimestamp(now(), 'payment rejection replay time');
      if (!event || Date.parse(event.resolvedAt) > Date.parse(replayNow)) {
        fail('BUDGET_TIME', 'payment rejection replay clock regressed');
      }
      validateUnusedAuthorizationEvidence(
        reconciliation.evidence,
        authority,
        attempt,
        reconciliation.row.recorded_at,
        event.resolvedAt,
      );
      const buyerOutcome = assertResolvedBuyerOutcome(
        db,
        prepared.intentId,
        'payment_rejected',
        'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      );
      assertTransitionChronology(event.resolvedAt, [
        ['BudgetReservation updatedAt', reservation.updatedAt],
        ...attemptChronology(attempt),
        ...candidates.flatMap((candidate) => ([
          ['payment candidate createdAt', candidate.row.created_at],
          ['payment candidate updatedAt', candidate.row.updated_at],
        ])),
        ['payment reconciliation recordedAt', reconciliation.row.recorded_at],
        ['BuyerOutcome recordedAt', buyerOutcome.recorded_at],
      ]);
      if (attempt?.state !== 'rejected'
          || attempt.reason_code !== 'AUTHORIZATION_UNUSED_AFTER_EXPIRY'
          || candidates.some((candidate) => candidate.row.state === 'pending')
          || !event
          || event.evidenceId !== prepared.evidenceId
          || event.outcome !== 'rejected'
          || event.previousState !== 'unresolved'
          || event.nextState !== 'released'
          || event.buyerOutcomeRevision !== Number(buyerOutcome.revision)) {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'rejected payment resolution replay changed');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'unresolved') {
      fail('BUDGET_STATE', 'payment rejection requires one unresolved hold');
    }
    const attempt = validatePaymentAttempt(db, authority, new Set(['unresolved'])).row;
    if (attempt.payment_payload_json === null) {
      fail('RECONCILIATION_EVIDENCE_MISMATCH', 'unused proof needs persisted authorization');
    }
    const resolvedAt = canonicalTimestamp(now(), 'payment rejection time');
    const predecessorOutcome = db.prepare(
      'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
    ).get(prepared.intentId);
    assertTransitionChronology(resolvedAt, [
      ['BudgetReservation unresolvedAt', reservation.updatedAt],
      ...attemptChronology(attempt),
      ...candidates.flatMap((candidate) => ([
        ['payment candidate createdAt', candidate.row.created_at],
        ['payment candidate updatedAt', candidate.row.updated_at],
      ])),
      ['payment reconciliation recordedAt', reconciliation.row.recorded_at],
      ['BuyerOutcome predecessor recordedAt', predecessorOutcome?.recorded_at],
    ]);
    validateUnusedAuthorizationEvidence(
      reconciliation.evidence,
      authority,
      attempt,
      reconciliation.row.recorded_at,
      resolvedAt,
    );
    if (candidates.some((candidate) => (
      candidate.row.state === 'pending' && candidate.row.evidence_json !== null
    ))) {
      fail(
        'RECONCILIATION_EVIDENCE_MISMATCH',
        'pending payment candidate already contains evidence',
      );
    }
    for (const candidate of candidates.filter((item) => item.row.state === 'pending')) {
      const changed = db.prepare(`UPDATE payment_reconciliation_candidates
        SET state = 'rejected', evidence_json = ?, updated_at = ?
        WHERE id = ? AND intent_id = ? AND state = 'pending'`).run(
        reconciliation.row.evidence_json,
        resolvedAt,
        candidate.row.id,
        prepared.intentId,
      );
      if (changed.changes !== 1n) {
        fail('RECONCILIATION_CONFLICT', 'candidate rejection lost its race');
      }
    }
    const attemptUpdate = db.prepare(`UPDATE payment_attempts
      SET state = 'rejected', reason_code = ?, updated_at = ?
      WHERE intent_id = ? AND state = 'unresolved'
        AND transaction_id IS NULL AND settlement_json IS NULL`).run(
      'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      resolvedAt,
      prepared.intentId,
    );
    if (attemptUpdate.changes !== 1n) {
      fail('PAYMENT_ATTEMPT_STATE', 'payment rejection lost its attempt race');
    }
    const budgetUpdate = db.prepare(`UPDATE budget_reservations
      SET unresolved_atomic = '0', released_atomic = ?, state = 'released', updated_at = ?
      WHERE intent_id = ? AND state = 'unresolved'
        AND unresolved_atomic = ? AND reserved_atomic = '0'
        AND committed_atomic = '0' AND released_atomic = '0'`).run(
      authority.amount.text,
      resolvedAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (budgetUpdate.changes !== 1n) {
      fail('BUDGET_CONFLICT', 'payment rejection lost its budget race');
    }
    if (db.prepare('SELECT intent_id FROM execution_outcomes WHERE intent_id = ?')
      .get(prepared.intentId)) {
      fail('BUDGET_CORRUPTION', 'rejected unresolved payment already has execution state');
    }
    const buyerOutcomeRevision = writeBuyerOutcome(
      db,
      prepared.intentId,
      'payment_rejected',
      'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      resolvedAt,
      'payment_unresolved',
    );
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.payment_resolved',
      data: {
        evidenceId: prepared.evidenceId,
        outcome: 'rejected',
        amountAtomic: authority.amount.text,
        previousState: 'unresolved',
        nextState: 'released',
        buyerOutcomeRevision,
        resolvedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'released') {
      fail('BUDGET_CORRUPTION', 'rejected payment budget disappeared');
    }
    snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: resolvedAt,
    });
    return publicReservation(persisted);
  };

  const resolvePaymentImpl = (db, appendEvent, prepared) => {
    // This Task-5 ledger owns monetary, attempt, execution-case, and BuyerOutcome rows only.
    // Task 11 must compose the InTransaction form with the SpendIntent terminal transition
    // and retry_matchable = 0 under this same authority token before committing the aggregate.
    const authority = loadReservationAuthority(db, prepared.intentId);
    const reservation = readBudgetRow(db, prepared.intentId);
    if (!reservation) fail('BUDGET_RESERVATION_MISSING', 'BudgetReservation does not exist');
    const reconciliation = loadReconciliation(
      db,
      prepared.intentId,
      prepared.evidenceId,
      'payment',
      prepared.outcome,
    );
    return prepared.outcome === 'settled'
      ? resolveSettledPayment(
        db,
        appendEvent,
        prepared,
        authority,
        reservation,
        reconciliation,
      )
      : resolveRejectedPayment(
        db,
        appendEvent,
        prepared,
        authority,
        reservation,
        reconciliation,
      );
  };

  const resolvePaymentInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => resolvePaymentImpl(
      db,
      appendEvent,
      preparePaymentResolution(input),
    ),
  );

  const resolvePayment = (input) => {
    const prepared = preparePaymentResolution(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => resolvePaymentImpl(db, appendEvent, prepared),
    ));
  };

  const prepareRefund = (input) => {
    const record = closedInput(
      input,
      ['intentId', 'evidenceId', 'refundTransactionId'],
      [],
      'REFUND_CONFIRMATION_SCHEMA',
      'confirmed refund',
    );
    return Object.freeze({
      intentId: canonicalToken(record.intentId, 'intent ID'),
      evidenceId: canonicalToken(record.evidenceId, 'reconciliation evidence ID'),
      refundTransactionId: canonicalEvmHash(
        record.refundTransactionId,
        'refund transaction ID',
      ),
    });
  };

  const recordConfirmedRefundImpl = (db, appendEvent, prepared) => {
    const authority = loadReservationAuthority(db, prepared.intentId);
    const reservation = readBudgetRow(db, prepared.intentId);
    if (!reservation) fail('BUDGET_RESERVATION_MISSING', 'BudgetReservation does not exist');
    const reconciliation = loadReconciliation(
      db,
      prepared.intentId,
      prepared.evidenceId,
      'refund',
      'refund_confirmed',
    );
    const attempt = validatePaymentAttempt(db, authority, new Set(['settled'])).row;
    const refundRows = db.prepare('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid')
      .all(prepared.intentId);
    for (const row of refundRows.filter((candidate) => (
      candidate.refund_transaction_id !== null
    ))) {
      const transactionId = canonicalEvmHashFor(
        row.refund_transaction_id,
        'persisted refund transaction',
        'TRANSACTION_BINDING_CORRUPTION',
      );
      if (row.refund_transaction_id !== transactionId) {
        fail(
          'TRANSACTION_BINDING_CORRUPTION',
          'persisted refund transaction is not canonical lowercase',
        );
      }
    }
    const matching = refundRows.filter(
      (row) => row.refund_transaction_id === prepared.refundTransactionId,
    );
    if (matching.length !== 1) {
      fail('REFUND_EVIDENCE_MISMATCH', 'confirmed refund has no exact persisted candidate');
    }
    const refund = matching[0];
    canonicalToken(refund.id, 'refund ID');
    const refundAmount = canonicalAtomicText(
      refund.amount_atomic,
      'refund amount',
      'REFUND_EVIDENCE_MISMATCH',
    );
    const originalTransactionId = canonicalEvmHash(
      refund.original_transaction_id,
      'persisted original payment transaction',
    );
    if (refund.original_transaction_id !== originalTransactionId
        || originalTransactionId !== attempt.transaction_id
        || refundAmount.text !== authority.amount.text
        || prepared.refundTransactionId === attempt.transaction_id) {
      fail('REFUND_EVIDENCE_MISMATCH', 'refund does not bind the exact committed payment');
    }
    validateConfirmedRefundEvidence(
      reconciliation.evidence,
      authority,
      attempt,
      prepared.refundTransactionId,
    );
    assertGloballyUniqueTransaction(db, prepared.refundTransactionId, {
      allowedRefundId: refund.id,
    });
    const resolution = db.prepare('SELECT * FROM execution_resolutions WHERE intent_id = ?')
      .get(prepared.intentId);
    const execution = db.prepare('SELECT * FROM execution_outcomes WHERE intent_id = ?')
      .get(prepared.intentId);

    if (reservation.state === 'released') {
      const event = loadBudgetEvent(db, prepared.intentId, 'budget.refund_confirmed');
      const buyerOutcome = assertResolvedBuyerOutcome(
        db,
        prepared.intentId,
        'refunded',
        'REFUND_CONFIRMED',
      );
      const replayNow = canonicalTimestamp(now(), 'refund confirmation replay time');
      if (!event || Date.parse(event.confirmedAt) > Date.parse(replayNow)) {
        fail('BUDGET_TIME', 'refund confirmation replay clock regressed');
      }
      assertTransitionChronology(event.confirmedAt, [
        ['BudgetReservation updatedAt', reservation.updatedAt],
        ['BudgetReservation committedAt', reservation.committedAt],
        ...attemptChronology(attempt),
        ['refund createdAt', refund.created_at],
        ['refund updatedAt', refund.updated_at],
        ['refund reconciliation recordedAt', reconciliation.row.recorded_at],
        ['execution outcome recordedAt', execution?.recorded_at],
        ['execution resolution openedAt', resolution?.opened_at],
        ['execution resolution resolvedAt', resolution?.resolved_at],
        ['BuyerOutcome recordedAt', buyerOutcome.recorded_at],
      ]);
      if (refund.state !== 'confirmed'
          || refund.evidence_json !== reconciliation.row.evidence_json
          || resolution?.state !== 'resolved'
          || BigInt(resolution?.blocks_wallet ?? 1) !== 0n
          || !event
          || event.evidenceId !== prepared.evidenceId
          || event.refundTransactionId !== prepared.refundTransactionId
          || event.originalTransactionId !== attempt.transaction_id
          || event.previousState !== 'committed'
          || event.nextState !== 'released'
          || event.buyerOutcomeRevision !== Number(buyerOutcome.revision)) {
        fail('BUDGET_IDEMPOTENCY_CONFLICT', 'confirmed refund replay changed');
      }
      return publicReservation(reservation);
    }
    if (reservation.state !== 'committed'
        || execution?.state !== 'failed'
        || resolution?.state !== 'refund_pending'
        || BigInt(resolution.blocks_wallet) !== 1n
        || resolution.resolved_at !== null
        || (refund.state !== 'pending' && refund.state !== 'unresolved')
        || refund.evidence_json !== null) {
      fail('REFUND_STATE', 'refund confirmation requires one blocking full-refund case');
    }
    const confirmedAt = canonicalTimestamp(now(), 'refund confirmedAt');
    const predecessorOutcome = db.prepare(
      'SELECT * FROM buyer_outcomes WHERE intent_id = ?',
    ).get(prepared.intentId);
    assertTransitionChronology(confirmedAt, [
      ['BudgetReservation committedAt', reservation.committedAt],
      ['BudgetReservation updatedAt', reservation.updatedAt],
      ...attemptChronology(attempt),
      ['refund createdAt', refund.created_at],
      ['refund updatedAt', refund.updated_at],
      ['refund reconciliation recordedAt', reconciliation.row.recorded_at],
      ['execution outcome recordedAt', execution?.recorded_at],
      ['execution resolution openedAt', resolution?.opened_at],
      ['BuyerOutcome predecessor recordedAt', predecessorOutcome?.recorded_at],
    ]);
    const refundUpdate = db.prepare(`UPDATE refunds
      SET state = 'confirmed', evidence_json = ?, updated_at = ?
      WHERE id = ? AND intent_id = ? AND state = ?
        AND refund_transaction_id = ? AND original_transaction_id = ?
        AND amount_atomic = ? AND evidence_json IS NULL`).run(
      reconciliation.row.evidence_json,
      confirmedAt,
      refund.id,
      prepared.intentId,
      refund.state,
      prepared.refundTransactionId,
      attempt.transaction_id,
      authority.amount.text,
    );
    if (refundUpdate.changes !== 1n) {
      fail('REFUND_CONFLICT', 'refund confirmation lost its race');
    }
    const resolutionUpdate = db.prepare(`UPDATE execution_resolutions
      SET state = 'resolved', blocks_wallet = 0, resolved_at = ?
      WHERE intent_id = ? AND state = 'refund_pending'
        AND blocks_wallet = 1 AND resolved_at IS NULL`).run(
      confirmedAt,
      prepared.intentId,
    );
    if (resolutionUpdate.changes !== 1n) {
      fail('REFUND_CONFLICT', 'execution refund resolution lost its race');
    }
    const budgetUpdate = db.prepare(`UPDATE budget_reservations
      SET committed_atomic = '0', released_atomic = ?, state = 'released', updated_at = ?
      WHERE intent_id = ? AND state = 'committed'
        AND committed_atomic = ? AND reserved_atomic = '0'
        AND released_atomic = '0' AND unresolved_atomic = '0'`).run(
      authority.amount.text,
      confirmedAt,
      prepared.intentId,
      authority.amount.text,
    );
    if (budgetUpdate.changes !== 1n) {
      fail('BUDGET_CONFLICT', 'confirmed refund lost its budget race');
    }
    const buyerOutcomeRevision = writeBuyerOutcome(
      db,
      prepared.intentId,
      'refunded',
      'REFUND_CONFIRMED',
      confirmedAt,
      'execution_failed',
    );
    appendEvent({
      entityType: 'budget_reservation',
      entityId: prepared.intentId,
      eventType: 'budget.refund_confirmed',
      data: {
        evidenceId: prepared.evidenceId,
        originalTransactionId: attempt.transaction_id,
        refundTransactionId: prepared.refundTransactionId,
        amountAtomic: authority.amount.text,
        previousState: 'committed',
        nextState: 'released',
        buyerOutcomeRevision,
        confirmedAt,
      },
    });
    const persisted = readBudgetRow(db, prepared.intentId);
    if (!persisted || persisted.state !== 'released') {
      fail('BUDGET_CORRUPTION', 'refunded BudgetReservation disappeared');
    }
    snapshotImpl(db, {
      sessionId: persisted.sessionId,
      sellerOrigin: persisted.sellerOrigin,
      at: confirmedAt,
    });
    return publicReservation(persisted);
  };

  const recordConfirmedRefundInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => recordConfirmedRefundImpl(
      db,
      appendEvent,
      prepareRefund(input),
    ),
  );

  const recordConfirmedRefund = (input) => {
    const prepared = prepareRefund(input);
    return store.transaction((token) => store.within(
      token,
      ({ db, appendEvent }) => recordConfirmedRefundImpl(db, appendEvent, prepared),
    ));
  };

  return Object.freeze({
    snapshot,
    snapshotInTransaction,
    reserve,
    reserveInTransaction,
    commit,
    commitInTransaction,
    release,
    releaseInTransaction,
    holdUnresolved,
    holdUnresolvedInTransaction,
    resolvePayment,
    resolvePaymentInTransaction,
    recordConfirmedRefund,
    recordConfirmedRefundInTransaction,
  });
}

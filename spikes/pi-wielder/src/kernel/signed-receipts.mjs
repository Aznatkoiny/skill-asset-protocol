import crypto from 'node:crypto';

import {
  canonicalJson as signingCanonicalJson,
  receiptKeyId,
  verifySignedReceipt,
} from './receipt-signing.mjs';
import {
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
} from './canonical.mjs';

const OUTCOME_STATUSES = new Set([
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
const POLICY_DECISIONS = new Set(['allow', 'approval_required', 'deny']);
const APPROVAL_STATES = new Set([
  'not_required', 'pending', 'approved', 'denied', 'expired', 'cancelled', 'consumed',
]);
const EXECUTION_STATES = new Set(['none', 'succeeded', 'failed', 'unknown']);
const PAYMENT_STATES = new Set(['none', 'not_signed', 'unresolved', 'rejected', 'settled']);
const BUDGET_DISPOSITIONS = new Set(['reserved', 'committed', 'released', 'unresolved']);
const RECONCILIATION_KINDS = new Set(['payment', 'execution', 'refund']);
const RECONCILIATION_OUTCOMES = new Set([
  'settled', 'rejected', 'execution_succeeded', 'execution_failed',
  'execution_unknown', 'refund_confirmed', 'refund_rejected', 'unresolved',
]);
const REASON_CODE = /^[A-Z][A-Z0-9_]{0,127}$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const EVM_TRANSACTION = /^0x[0-9a-f]{64}$/;
const ATOMIC = /^(0|[1-9][0-9]*)$/;
const PRE_POLICY_DENIAL_REASONS = new Set([
  'PAYMENT_CHALLENGE_MALFORMED',
  'PAYMENT_CHALLENGE_OVERSIZED',
  'PAYMENT_CHALLENGE_EXPIRED',
]);
const POLICY_DENIAL_REASONS = new Set([
  'POLICY_DENIED',
  'X402_VERSION',
  'SCHEME_UNSUPPORTED',
  'NETWORK_MISMATCH',
  'ASSET_MISMATCH',
  'WALLET_MISMATCH',
  'METHOD_UNSUPPORTED',
  'SELLER_UNTRUSTED',
  'RESOURCE_PATH',
  'PAYEE_MISMATCH',
  'PAYMENT_OPTIONS_AMBIGUOUS',
  'CHALLENGE_EXPIRED',
  'PER_REQUEST_LIMIT',
  'SELLER_SESSION_LIMIT',
  'SESSION_LIMIT',
  'ROLLING_24H_LIMIT',
  'APPROVAL_CAPACITY',
]);
const APPROVAL_CANCELLATION_REASONS = new Set([
  'APPROVAL_CHALLENGE_CHANGED',
]);
const SESSION_CANCELLATION_REASONS = new Set([
  'POLICY_SUPERSEDED',
  'SESSION_CLOSED',
]);
const UNSIGNED_RELEASE_REASONS = new Set([
  'SIGNER_REJECTED',
  'NONCE_COLLISION',
  'WALLET_PRE_SIGN_REJECTED',
]);
const PRE_CLAIM_RELEASE_REASONS = new Set([
  'CHALLENGE_EXPIRED',
  'NONCE_COLLISION',
  'AGENT_REVOKED',
  'WALLET_RECOVERY_REQUIRED',
  'POLICY_SUPERSEDED',
  'SESSION_CLOSED',
]);
const PAYMENT_UNRESOLVED_REASONS = new Set([
  'PAID_RESPONSE_AMBIGUOUS',
  'PAYMENT_CANDIDATE_REJECTED',
  'RECOVERY_PAYMENT_AMBIGUOUS',
  'WALLET_SIGNATURE_AMBIGUOUS',
  'SIGNATURE_PERSISTENCE_UNCERTAIN',
  'SECOND_PAYMENT_REQUIRED',
  'SETTLEMENT_EVIDENCE_INVALID',
]);

function fail(code, message, options) {
  throw new KernelError(code, message, options);
}

function positiveInteger(value, label) {
  const numeric = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(numeric) || numeric < 1) {
    fail('RECEIPT_CORRUPTION', `${label} must be a positive safe integer`);
  }
  return numeric;
}

function optionalInteger(value, label) {
  if (value === null) return null;
  const numeric = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(numeric)) {
    fail('RECEIPT_CORRUPTION', `${label} must be a safe integer or null`);
  }
  return numeric;
}

function reasonCode(value, label) {
  if (typeof value !== 'string' || !REASON_CODE.test(value)) {
    fail('RECEIPT_CORRUPTION', `${label} must be one bounded stable reason code`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !SHA256.test(value)) {
    fail('RECEIPT_CORRUPTION', `${label} must be one canonical SHA-256 identifier`);
  }
  return value;
}

function atomic(value, label) {
  if (typeof value !== 'string' || !ATOMIC.test(value)) {
    fail('RECEIPT_CORRUPTION', `${label} must be canonical atomic text`);
  }
  return value;
}

function canonicalOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch (error) {
    fail('RECEIPT_CORRUPTION', 'receipt seller origin is invalid', { cause: error });
  }
  if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.username || parsed.password || parsed.pathname !== '/'
      || parsed.search || parsed.hash || parsed.origin !== value) {
    fail('RECEIPT_CORRUPTION', 'receipt seller origin must be one canonical HTTP origin');
  }
  return value;
}

function resourcePath(value) {
  if (typeof value !== 'string' || !value.startsWith('/')
      || value.includes('?') || value.includes('#') || value.includes('\\')) {
    fail('RECEIPT_CORRUPTION', 'receipt resource path must be canonical');
  }
  return value;
}

function parseCanonicalJson(value, label) {
  if (typeof value !== 'string') fail('RECEIPT_CORRUPTION', `${label} must be JSON text`);
  let parsed;
  try { parsed = JSON.parse(value); } catch (error) {
    fail('RECEIPT_CORRUPTION', `${label} is invalid JSON`, { cause: error });
  }
  if (signingCanonicalJson(parsed) !== value) {
    fail('RECEIPT_CORRUPTION', `${label} is not canonical JSON`);
  }
  return parsed;
}

function dataAccess(store) {
  return Object.freeze({
    one: (sql, parameters = []) => store.readOne(sql, parameters),
    all: (sql, parameters = []) => store.readAll(sql, parameters),
  });
}

function transactionAccess(db) {
  return Object.freeze({
    one: (sql, parameters = []) => db.prepare(sql).get(...parameters),
    all: (sql, parameters = []) => db.prepare(sql).all(...parameters),
  });
}

function readUnique(access, sql, parameters, label, { optional = false } = {}) {
  const rows = access.all(sql, parameters);
  if (rows.length === 0 && optional) return null;
  if (rows.length !== 1) fail('RECEIPT_CORRUPTION', `${label} must have exactly one row`);
  return rows[0];
}

function readSelectedPayment(access, intent, decision) {
  const attempt = readUnique(
    access,
    'SELECT * FROM payment_attempts WHERE intent_id = ? ORDER BY rowid',
    [intent.id],
    'PaymentAttempt',
    { optional: true },
  );
  if (!attempt) return { attempt: null, selected: null };
  if (!decision) fail('RECEIPT_CORRUPTION', 'PaymentAttempt exists without PolicyDecision');
  const projection = parseCanonicalJson(
    attempt.payment_required_projection_json,
    'PaymentAttempt challenge projection',
  );
  if (!projection || typeof projection !== 'object' || Array.isArray(projection)
      || !Array.isArray(projection.accepts)) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt challenge projection is invalid');
  }
  const index = optionalInteger(attempt.accepted_index, 'accepted payment index');
  const selected = projection.accepts[index];
  if (!selected || typeof selected !== 'object' || Array.isArray(selected)
      || attempt.payment_required_projection_json !== intent.challenge_projection_json
      || attempt.accepted_index !== decision.accepted_index
      || attempt.quote_id !== decision.quote_id) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt no longer binds its PolicyDecision');
  }
  atomic(selected.amount, 'payment amount');
  if (selected.amount !== decision.amount_ceiling_atomic
      || typeof selected.network !== 'string' || selected.network.length < 1
      || !EVM_ADDRESS.test(selected.asset) || !EVM_ADDRESS.test(selected.payTo)) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt selected payment is invalid');
  }
  return { attempt, selected };
}

function paymentAttemptMaterial(attempt) {
  const createdAt = canonicalTimestamp(attempt.created_at, 'PaymentAttempt createdAt');
  const updatedAt = canonicalTimestamp(attempt.updated_at, 'PaymentAttempt updatedAt');
  if (Date.parse(updatedAt) < Date.parse(createdAt)) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt updatedAt predates creation');
  }
  const claimFields = [
    attempt.nonce,
    attempt.valid_after,
    attempt.valid_before,
    attempt.signing_claimed_at,
  ];
  const signedFields = [
    attempt.payment_payload_json,
    attempt.payment_header,
    attempt.payment_hash,
    attempt.signed_at,
  ];
  const hasClaim = claimFields.every((value) => value !== null);
  const hasNoClaim = claimFields.every((value) => value === null);
  const hasSignedBytes = signedFields.every((value) => value !== null);
  const hasNoSignedBytes = signedFields.every((value) => value === null);
  const settlementFields = [
    attempt.settlement_json,
    attempt.transaction_id,
    attempt.settled_at,
  ];
  const hasSettlement = settlementFields.every((value) => value !== null);
  const hasNoSettlement = settlementFields.every((value) => value === null);
  if ((!hasClaim && !hasNoClaim) || (!hasSignedBytes && !hasNoSignedBytes)) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt claim or signed-byte projection is partial');
  }
  if (!hasSettlement && !hasNoSettlement) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt settlement projection is partial');
  }
  let signingClaimedAt = null;
  if (hasClaim) {
    if (typeof attempt.nonce !== 'string' || !/^0x[0-9a-f]{64}$/.test(attempt.nonce)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt signing claim nonce is invalid');
    }
    const validAfter = atomic(attempt.valid_after, 'PaymentAttempt validAfter');
    const validBefore = atomic(attempt.valid_before, 'PaymentAttempt validBefore');
    if (BigInt(validBefore) <= BigInt(validAfter)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt signing claim window is invalid');
    }
    signingClaimedAt = canonicalTimestamp(
      attempt.signing_claimed_at,
      'PaymentAttempt signing claimedAt',
    );
    if (Date.parse(signingClaimedAt) < Date.parse(createdAt)
        || Date.parse(signingClaimedAt) > Date.parse(updatedAt)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt signing-claim chronology is invalid');
    }
  }
  let signedAt = null;
  if (hasSignedBytes) {
    if (!hasClaim || typeof attempt.payment_payload_json !== 'string'
        || typeof attempt.payment_header !== 'string' || attempt.payment_header.length === 0) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt signed bytes have no complete claim');
    }
    parseCanonicalJson(attempt.payment_payload_json, 'PaymentAttempt payment payload');
    hash(attempt.payment_hash, 'PaymentAttempt payment hash');
    signedAt = canonicalTimestamp(attempt.signed_at, 'PaymentAttempt signedAt');
    if (Date.parse(signedAt) < Date.parse(signingClaimedAt)
        || Date.parse(signedAt) > Date.parse(updatedAt)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt signedAt chronology is invalid');
    }
  }
  const hasRetry = attempt.retry_started_at !== null;
  let retryStartedAt = null;
  if (hasRetry) {
    if (!hasSignedBytes) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt retry has no persisted signed bytes');
    }
    retryStartedAt = canonicalTimestamp(
      attempt.retry_started_at,
      'PaymentAttempt retry startedAt',
    );
    if (Date.parse(retryStartedAt) < Date.parse(signedAt)
        || Date.parse(retryStartedAt) > Date.parse(updatedAt)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt retry chronology is invalid');
    }
  }
  if (hasSettlement) {
    if (!hasRetry) {
      fail('RECEIPT_CORRUPTION', 'settled PaymentAttempt has no paid retry');
    }
    parseCanonicalJson(attempt.settlement_json, 'PaymentAttempt settlement');
    if (!EVM_TRANSACTION.test(attempt.transaction_id)) {
      fail('RECEIPT_CORRUPTION', 'settled PaymentAttempt transaction is invalid');
    }
    const settledAt = canonicalTimestamp(attempt.settled_at, 'PaymentAttempt settledAt');
    if (Date.parse(settledAt) < Date.parse(retryStartedAt)
        || Date.parse(settledAt) > Date.parse(updatedAt)
        || settledAt !== updatedAt) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt settlement chronology is invalid');
    }
  }
  const validState = {
    reserved: hasNoClaim && hasNoSignedBytes && !hasRetry && hasNoSettlement,
    signing: hasClaim && hasNoSignedBytes && !hasRetry && hasNoSettlement,
    signed: hasClaim && hasSignedBytes && !hasRetry && hasNoSettlement,
    retrying: hasClaim && hasSignedBytes && hasRetry && hasNoSettlement,
    unresolved: hasClaim && (hasNoSignedBytes || hasSignedBytes)
      && (!hasRetry || hasSignedBytes) && hasNoSettlement,
    settled: hasClaim && hasSignedBytes && hasRetry && hasSettlement,
    rejected: (hasNoClaim && hasNoSignedBytes)
      ? !hasRetry && hasNoSettlement
      : hasClaim && (hasNoSignedBytes || hasSignedBytes)
        && (!hasRetry || hasSignedBytes) && hasNoSettlement,
  }[attempt.state];
  if (!validState) {
    fail('RECEIPT_CORRUPTION', 'PaymentAttempt state contradicts its durable signing material');
  }
  if (['unresolved', 'rejected'].includes(attempt.state)) {
    reasonCode(attempt.reason_code, 'PaymentAttempt terminal reason');
  }
  if (attempt.state === 'settled'
      && attempt.reason_code !== null
      && attempt.reason_code !== 'TRUSTED_RECONCILIATION') {
    fail('RECEIPT_CORRUPTION', 'settled PaymentAttempt reason is invalid');
  }
  return Object.freeze({ hasClaim, hasSignedBytes });
}

function projectPayment(attempt, selected, outcomeReason) {
  if (!attempt) return { state: 'none' };
  const material = paymentAttemptMaterial(attempt);
  let state;
  if (attempt.state === 'settled') state = 'settled';
  else if (attempt.state === 'rejected') {
    reasonCode(attempt.reason_code, 'PaymentAttempt rejection reason');
    if (attempt.reason_code !== outcomeReason) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt rejection reason changed');
    }
    if ((outcomeReason === 'WALLET_PRE_SIGN_REJECTED' && !material.hasClaim)
        || (PRE_CLAIM_RELEASE_REASONS.has(outcomeReason) && material.hasClaim)) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt rejection contradicts its signing claim');
    }
    state = material.hasSignedBytes ? 'rejected' : 'not_signed';
  } else if (attempt.state === 'unresolved') {
    if (attempt.reason_code !== outcomeReason) {
      fail('RECEIPT_CORRUPTION', 'PaymentAttempt unresolved reason changed');
    }
    state = 'unresolved';
  }
  else if (['reserved', 'signing', 'signed', 'retrying'].includes(attempt.state)) {
    fail('RECEIPT_CORRUPTION', 'terminal receipt cannot retain a nonterminal PaymentAttempt');
  }
  else fail('RECEIPT_CORRUPTION', 'PaymentAttempt state is unsupported');
  if (!PAYMENT_STATES.has(state)) fail('RECEIPT_CORRUPTION', 'receipt payment state is invalid');
  const transactionId = attempt.transaction_id;
  if (state === 'settled') {
    if (!EVM_TRANSACTION.test(transactionId)) {
      fail('RECEIPT_CORRUPTION', 'settled payment requires a canonical transaction ID');
    }
  } else if (transactionId !== null) {
    fail('RECEIPT_CORRUPTION', 'unsettled payment must not expose a transaction ID');
  }
  return {
    state,
    amountAtomic: selected.amount,
    network: selected.network,
    asset: selected.asset,
    payTo: selected.payTo,
    transactionId,
  };
}

function projectExecution(access, intentId) {
  const row = readUnique(
    access,
    'SELECT * FROM execution_outcomes WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'ExecutionOutcome',
    { optional: true },
  );
  if (!row) return { state: 'none', httpStatus: null, responseHash: null };
  if (!EXECUTION_STATES.has(row.state) || row.state === 'none') {
    fail('RECEIPT_CORRUPTION', 'ExecutionOutcome state is invalid');
  }
  const httpStatus = optionalInteger(row.http_status, 'execution HTTP status');
  if (httpStatus !== null && (httpStatus < 100 || httpStatus > 599)) {
    fail('RECEIPT_CORRUPTION', 'execution HTTP status is invalid');
  }
  const responseHash = row.response_hash === null ? null : hash(row.response_hash, 'response hash');
  if (row.state === 'succeeded' && (httpStatus === null || httpStatus < 200 || httpStatus > 299)) {
    fail('RECEIPT_CORRUPTION', 'successful execution requires a 2xx HTTP status');
  }
  if (row.state === 'failed' && (httpStatus === null || httpStatus < 300)) {
    fail('RECEIPT_CORRUPTION', 'failed execution requires a known 3xx-5xx HTTP status');
  }
  if (row.state === 'unknown' && httpStatus !== null
      && (httpStatus < 200 || httpStatus > 299)) {
    fail('RECEIPT_CORRUPTION', 'unknown execution permits only a known 2xx HTTP status');
  }
  return { state: row.state, httpStatus, responseHash };
}

function projectBudget(access, intentId) {
  const row = readUnique(
    access,
    'SELECT * FROM budget_reservations WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'BudgetReservation',
    { optional: true },
  );
  if (!row) return null;
  if (!BUDGET_DISPOSITIONS.has(row.state)) {
    fail('RECEIPT_CORRUPTION', 'BudgetReservation state is invalid');
  }
  const parts = [
    atomic(row.reserved_atomic, 'reserved amount'),
    atomic(row.committed_atomic, 'committed amount'),
    atomic(row.released_atomic, 'released amount'),
    atomic(row.unresolved_atomic, 'unresolved amount'),
  ];
  const amountAtomic = parts.reduce((sum, part) => sum + BigInt(part), 0n).toString(10);
  const activeColumn = {
    reserved: row.reserved_atomic,
    committed: row.committed_atomic,
    released: row.released_atomic,
    unresolved: row.unresolved_atomic,
  }[row.state];
  if (activeColumn !== amountAtomic
      || parts.filter((part) => part !== '0').length !== 1) {
    fail('RECEIPT_CORRUPTION', 'BudgetReservation does not have one conserved disposition');
  }
  return { disposition: row.state, amountAtomic };
}

function projectReconciliation(access, intentId) {
  const rows = access.all(
    'SELECT * FROM reconciliations WHERE intent_id = ? ORDER BY rowid',
    [intentId],
  );
  if (rows.length === 0) return null;
  const row = rows.at(-1);
  canonicalToken(row.id, 'reconciliation ID');
  canonicalToken(row.kind, 'reconciliation kind');
  canonicalToken(row.outcome, 'reconciliation outcome');
  hash(row.operator_id_hash, 'reconciliation operator hash');
  canonicalTimestamp(row.recorded_at, 'reconciliation recordedAt');
  return {
    kind: row.kind,
    outcome: row.outcome,
    operatorIdHash: row.operator_id_hash,
    recordedAt: row.recorded_at,
  };
}

function projectRefund(access, intentId) {
  const rows = access.all('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid', [intentId]);
  if (rows.length === 0) return null;
  const row = rows.at(-1);
  canonicalToken(row.id, 'refund ID');
  atomic(row.amount_atomic, 'refund amount');
  if (!['pending', 'unresolved', 'abandoned', 'confirmed', 'rejected'].includes(row.state)) {
    fail('RECEIPT_CORRUPTION', 'refund state is invalid');
  }
  const transactionId = row.refund_transaction_id;
  if (transactionId !== null && !EVM_TRANSACTION.test(transactionId)) {
    fail('RECEIPT_CORRUPTION', 'refund candidate transaction ID is invalid');
  }
  if (row.state === 'confirmed') {
    if (transactionId === null) {
      fail('RECEIPT_CORRUPTION', 'confirmed refund requires a canonical transaction ID');
    }
    return { state: 'confirmed', amountAtomic: row.amount_atomic, transactionId };
  }

  const outcome = readUnique(
    access,
    'SELECT * FROM buyer_outcomes WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'BuyerOutcome',
  );
  const reconciliations = access.all(
    'SELECT * FROM reconciliations WHERE intent_id = ? ORDER BY rowid',
    [intentId],
  );
  const reconciliation = reconciliations.at(-1) ?? null;
  if (row.state === 'rejected'
      && (reconciliation?.kind !== 'refund'
        || reconciliation.outcome !== 'refund_rejected')) {
    fail('RECEIPT_CORRUPTION', 'rejected refund lacks its durable reconciliation');
  }

  let state = row.state;
  if (reconciliation?.kind === 'refund') {
    if (reconciliation.outcome === 'refund_confirmed') {
      fail('RECEIPT_CORRUPTION', 'confirmed refund reconciliation lacks a confirmed refund');
    }
    if (reconciliation.outcome === 'refund_rejected') state = 'rejected';
    if (reconciliation.outcome === 'unresolved') state = 'unresolved';
  } else if (reconciliation?.kind === 'execution'
      && reconciliation.outcome === 'execution_failed') {
    state = 'pending';
  } else if (['UPSTREAM_HTTP_FAILURE', 'UPSTREAM_FAILED'].includes(outcome.reason_code)) {
    state = 'pending';
  } else if (outcome.reason_code === 'REFUND_UNRESOLVED') {
    state = 'unresolved';
  }

  // A named refund candidate is operational reconciliation state. It is not
  // authoritative receipt state until trusted evidence revises BuyerOutcome.
  return { state, amountAtomic: row.amount_atomic, transactionId: null };
}

function validateReceiptSchema(value) {
  const receipt = exactRecord(value, [
    'schemaVersion', 'receiptId', 'revision', 'issuedAt', 'intent', 'outcome',
    'policy', 'approval', 'payment', 'execution', 'budget', 'reconciliation',
    'refund', 'supersedesReceiptHash',
  ], [], 'RECEIPT_SCHEMA', 'signed receipt');
  if (receipt.schemaVersion !== 1) fail('RECEIPT_SCHEMA', 'receipt schemaVersion must equal 1');
  canonicalToken(receipt.receiptId, 'receipt ID');
  positiveInteger(receipt.revision, 'receipt revision');
  canonicalTimestamp(receipt.issuedAt, 'receipt issuedAt');
  const intent = exactRecord(receipt.intent, [
    'id', 'requestId', 'intentHash', 'sessionId', 'sellerOrigin', 'resourcePath', 'purposeLabel',
  ], [], 'RECEIPT_SCHEMA', 'receipt intent');
  for (const [label, token] of [
    ['intent ID', intent.id], ['request ID', intent.requestId], ['session ID', intent.sessionId],
    ['purpose label', intent.purposeLabel],
  ]) canonicalToken(token, label);
  hash(intent.intentHash, 'receipt intent hash');
  canonicalOrigin(intent.sellerOrigin);
  resourcePath(intent.resourcePath);
  const outcome = exactRecord(receipt.outcome, ['status', 'reasonCode'], [],
    'RECEIPT_SCHEMA', 'receipt outcome');
  if (!OUTCOME_STATUSES.has(outcome.status)) fail('RECEIPT_SCHEMA', 'receipt outcome status is invalid');
  reasonCode(outcome.reasonCode, 'receipt outcome reason');
  if (receipt.policy !== null) {
    const policy = exactRecord(receipt.policy, ['versionId', 'decision', 'reasonCode'], [],
      'RECEIPT_SCHEMA', 'receipt policy');
    canonicalToken(policy.versionId, 'policy version ID');
    if (!POLICY_DECISIONS.has(policy.decision)) fail('RECEIPT_SCHEMA', 'receipt policy decision is invalid');
    reasonCode(policy.reasonCode, 'receipt policy reason');
  }
  const approval = exactRecord(receipt.approval, ['state', 'operatorIdHash'], [],
    'RECEIPT_SCHEMA', 'receipt approval');
  if (!APPROVAL_STATES.has(approval.state)) fail('RECEIPT_SCHEMA', 'receipt approval state is invalid');
  if (approval.operatorIdHash !== null) hash(approval.operatorIdHash, 'approval operator hash');
  const payment = exactRecord(receipt.payment, receipt.payment?.state === 'none'
    ? ['state']
    : ['state', 'amountAtomic', 'network', 'asset', 'payTo', 'transactionId'], [],
  'RECEIPT_SCHEMA', 'receipt payment');
  if (!PAYMENT_STATES.has(payment.state)) fail('RECEIPT_SCHEMA', 'receipt payment state is invalid');
  if (payment.state !== 'none') {
    atomic(payment.amountAtomic, 'receipt payment amount');
    if (typeof payment.network !== 'string' || payment.network.length < 1
        || !EVM_ADDRESS.test(payment.asset) || !EVM_ADDRESS.test(payment.payTo)
        || (payment.transactionId !== null && !EVM_TRANSACTION.test(payment.transactionId))
        || (payment.state === 'settled') !== (payment.transactionId !== null)) {
      fail('RECEIPT_SCHEMA', 'receipt payment binding is invalid');
    }
  }
  const execution = exactRecord(receipt.execution, ['state', 'httpStatus', 'responseHash'], [],
    'RECEIPT_SCHEMA', 'receipt execution');
  if (!EXECUTION_STATES.has(execution.state)) fail('RECEIPT_SCHEMA', 'receipt execution state is invalid');
  if (execution.httpStatus !== null && (!Number.isSafeInteger(execution.httpStatus)
      || execution.httpStatus < 100 || execution.httpStatus > 599)) {
    fail('RECEIPT_SCHEMA', 'receipt execution HTTP status is invalid');
  }
  if (execution.responseHash !== null) hash(execution.responseHash, 'receipt response hash');
  if ((execution.state === 'none'
      && (execution.httpStatus !== null || execution.responseHash !== null))
      || (execution.state === 'succeeded'
        && (execution.httpStatus < 200 || execution.httpStatus > 299
          || execution.responseHash === null))
      || (execution.state === 'failed'
        && (execution.httpStatus === null || execution.httpStatus < 300))
      || (execution.state === 'unknown' && execution.httpStatus !== null
        && (execution.httpStatus < 200 || execution.httpStatus > 299))) {
    fail('RECEIPT_SCHEMA', 'receipt execution fields disagree with its state');
  }
  if (receipt.budget !== null) {
    const budget = exactRecord(receipt.budget, ['disposition', 'amountAtomic'], [],
      'RECEIPT_SCHEMA', 'receipt budget');
    if (!BUDGET_DISPOSITIONS.has(budget.disposition)) fail('RECEIPT_SCHEMA', 'receipt budget disposition is invalid');
    atomic(budget.amountAtomic, 'receipt budget amount');
  }
  if (receipt.reconciliation !== null) {
    const reconciliation = exactRecord(receipt.reconciliation,
      ['kind', 'outcome', 'operatorIdHash', 'recordedAt'], [],
      'RECEIPT_SCHEMA', 'receipt reconciliation');
    if (!RECONCILIATION_KINDS.has(reconciliation.kind)
        || !RECONCILIATION_OUTCOMES.has(reconciliation.outcome)) {
      fail('RECEIPT_SCHEMA', 'receipt reconciliation projection is invalid');
    }
    hash(reconciliation.operatorIdHash, 'receipt reconciliation operator hash');
    canonicalTimestamp(reconciliation.recordedAt, 'receipt reconciliation recordedAt');
  }
  if (receipt.refund !== null) {
    const refund = exactRecord(receipt.refund, ['state', 'amountAtomic', 'transactionId'], [],
      'RECEIPT_SCHEMA', 'receipt refund');
    if (!['pending', 'unresolved', 'abandoned', 'confirmed', 'rejected'].includes(refund.state)) {
      fail('RECEIPT_SCHEMA', 'receipt refund state is invalid');
    }
    atomic(refund.amountAtomic, 'receipt refund amount');
    if ((refund.state === 'confirmed') !== (refund.transactionId !== null)
        || (refund.transactionId !== null && !EVM_TRANSACTION.test(refund.transactionId))) {
      fail('RECEIPT_SCHEMA', 'receipt refund transaction binding is invalid');
    }
  }
  const hasPredecessor = receipt.supersedesReceiptHash !== null;
  if ((receipt.revision === 1) === hasPredecessor
      || (hasPredecessor && !/^[0-9a-f]{64}$/.test(receipt.supersedesReceiptHash))) {
    fail('RECEIPT_SCHEMA', 'receipt predecessor hash is invalid');
  }
  validateReceiptConsistency(receipt);
  return frozenCopy(receipt);
}

function isNoExecution(execution) {
  return execution.state === 'none'
    && execution.httpStatus === null
    && execution.responseHash === null;
}

function isUnknownExecution(execution) {
  return execution.state === 'unknown';
}

function isNoPayment(receipt) {
  return receipt.payment.state === 'none' && receipt.budget === null;
}

function isReleasedUnsigned(receipt) {
  return receipt.payment.state === 'not_signed'
    && receipt.budget?.disposition === 'released'
    && receipt.payment.amountAtomic === receipt.budget.amountAtomic;
}

function isAutomaticAuthority(receipt) {
  return receipt.policy?.decision === 'allow'
    && receipt.policy.reasonCode === 'WITHIN_AUTO_LIMIT'
    && receipt.approval.state === 'not_required'
    && receipt.approval.operatorIdHash === null;
}

function isConsumedApprovalAuthority(receipt) {
  return receipt.policy?.decision === 'approval_required'
    && receipt.policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
    && receipt.approval.state === 'consumed'
    && receipt.approval.operatorIdHash !== null;
}

function hasSpendAuthority(receipt) {
  return isAutomaticAuthority(receipt) || isConsumedApprovalAuthority(receipt);
}

function hasNoSensitiveAftermath(receipt) {
  return receipt.reconciliation === null && receipt.refund === null;
}

function isSafeSessionCancellation(receipt) {
  const { approval, policy } = receipt;
  if (!isNoExecution(receipt.execution) || !hasNoSensitiveAftermath(receipt)) return false;
  if (isNoPayment(receipt)) {
    return (policy === null
        && approval.state === 'not_required'
        && approval.operatorIdHash === null)
      || isAutomaticAuthority(receipt)
      || (policy?.decision === 'approval_required'
        && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
        && ['not_required', 'cancelled'].includes(approval.state));
  }
  if (!isReleasedUnsigned(receipt)) return false;
  return isAutomaticAuthority(receipt) || isConsumedApprovalAuthority(receipt);
}

function requireProjection(condition, message) {
  if (!condition) fail('RECEIPT_SCHEMA', message);
}

function validateReconciliationConsistency(receipt) {
  const reconciliation = receipt.reconciliation;
  if (reconciliation === null) return;
  requireProjection(
    receipt.revision > 1,
    'trusted reconciliation requires a superseding receipt revision',
  );
  const allowedOutcomes = {
    payment: new Set(['settled', 'rejected', 'unresolved']),
    execution: new Set(['execution_succeeded', 'execution_failed', 'execution_unknown']),
    refund: new Set(['refund_confirmed', 'refund_rejected', 'unresolved']),
  }[reconciliation.kind];
  requireProjection(
    allowedOutcomes?.has(reconciliation.outcome),
    'receipt reconciliation kind and outcome contradict one another',
  );
  const matchesProjection = {
    settled: receipt.payment.state === 'settled'
      && receipt.budget?.disposition === 'committed',
    rejected: receipt.payment.state === 'rejected'
      && receipt.budget?.disposition === 'released'
      && isNoExecution(receipt.execution),
    unresolved: reconciliation.kind === 'payment'
      ? (receipt.payment.state === 'unresolved'
        && receipt.budget?.disposition === 'unresolved'
        && isNoExecution(receipt.execution))
      : (receipt.refund !== null
        && ['unresolved', 'abandoned'].includes(receipt.refund.state)
        && receipt.budget?.disposition === 'committed'),
    execution_succeeded: receipt.payment.state === 'settled'
      && receipt.execution.state === 'succeeded'
      && receipt.budget?.disposition === 'committed',
    execution_failed: receipt.payment.state === 'settled'
      && receipt.execution.state === 'failed'
      && receipt.budget?.disposition === 'committed',
    execution_unknown: receipt.payment.state === 'settled'
      && isUnknownExecution(receipt.execution)
      && receipt.budget?.disposition === 'committed',
    refund_confirmed: receipt.refund?.state === 'confirmed'
      && receipt.budget?.disposition === 'released',
    refund_rejected: receipt.refund?.state === 'rejected'
      && receipt.budget?.disposition === 'committed',
  }[reconciliation.outcome];
  requireProjection(
    matchesProjection,
    'receipt reconciliation outcome contradicts its durable projection',
  );
}

function validateRefundConsistency(receipt) {
  const refund = receipt.refund;
  if (refund === null) {
    requireProjection(
      receipt.reconciliation?.kind !== 'refund',
      'receipt refund reconciliation has no refund projection',
    );
    return;
  }
  requireProjection(
    receipt.payment.state === 'settled'
      && receipt.execution.state === 'failed'
      && refund.amountAtomic === receipt.payment.amountAtomic
      && refund.amountAtomic === receipt.budget?.amountAtomic,
    'receipt refund does not bind the exact settled payment and failed execution',
  );
  if (refund.state === 'confirmed') {
    requireProjection(
      receipt.revision > 1
        && receipt.outcome.status === 'refunded'
        && receipt.outcome.reasonCode === 'REFUND_CONFIRMED'
        && refund.transactionId !== receipt.payment.transactionId
        && receipt.budget?.disposition === 'released'
        && receipt.reconciliation?.kind === 'refund'
        && receipt.reconciliation.outcome === 'refund_confirmed',
      'confirmed refund projection is incomplete or contradictory',
    );
    return;
  }
  requireProjection(
    receipt.outcome.status === 'execution_failed'
      && receipt.budget?.disposition === 'committed',
    'unconfirmed refund must retain committed failed-execution authority',
  );
  if (refund.state === 'pending') {
    const attestedExecutionFailure = receipt.revision > 1
      && receipt.outcome.reasonCode === 'REFUND_UNRESOLVED'
      && receipt.reconciliation?.kind === 'execution'
      && receipt.reconciliation.outcome === 'execution_failed';
    requireProjection(
      (['UPSTREAM_HTTP_FAILURE', 'UPSTREAM_FAILED'].includes(receipt.outcome.reasonCode)
        && receipt.reconciliation === null)
        || attestedExecutionFailure,
      'pending refund projection is contradictory',
    );
  } else if (['unresolved', 'abandoned'].includes(refund.state)) {
    requireProjection(
      receipt.outcome.reasonCode === 'REFUND_UNRESOLVED'
        && (receipt.reconciliation === null
          || (receipt.reconciliation.kind === 'refund'
            && receipt.reconciliation.outcome === 'unresolved')),
      'unresolved refund projection is contradictory',
    );
  } else {
    requireProjection(
      refund.state === 'rejected'
        && receipt.outcome.reasonCode === 'REFUND_UNRESOLVED'
        && receipt.reconciliation?.kind === 'refund'
        && receipt.reconciliation.outcome === 'refund_rejected',
      'rejected refund projection is contradictory',
    );
  }
}

function validateReceiptConsistency(receipt) {
  const { approval, budget, execution, outcome, payment, policy, reconciliation, refund } = receipt;
  if ((policy === null && (approval.state !== 'not_required'
      || approval.operatorIdHash !== null || payment.state !== 'none' || budget !== null))
      || (policy?.decision === 'deny' && (approval.state !== 'not_required'
        || approval.operatorIdHash !== null || payment.state !== 'none' || budget !== null))
      || (approval.state !== 'not_required' && policy?.decision !== 'approval_required')
      || (['approved', 'denied', 'consumed'].includes(approval.state)
        && approval.operatorIdHash === null)
      || (['not_required', 'pending'].includes(approval.state)
        && approval.operatorIdHash !== null)
      || (payment.state !== 'none' && policy === null)
      || (payment.state !== 'none' && budget !== null
        && payment.amountAtomic !== budget.amountAtomic)) {
    fail('RECEIPT_SCHEMA', 'receipt authority projections contradict one another');
  }

  validateReconciliationConsistency(receipt);
  validateRefundConsistency(receipt);

  const noExecution = isNoExecution(execution);
  const noPayment = isNoPayment(receipt);
  const noAftermath = hasNoSensitiveAftermath(receipt);
  const paidCommitted = hasSpendAuthority(receipt)
    && payment.state === 'settled'
    && budget?.disposition === 'committed'
    && payment.amountAtomic === budget.amountAtomic;
  const reason = outcome.reasonCode;
  let matches = false;

  if (outcome.status === 'completed' && reason === 'ORDINARY_SUCCESS') {
    matches = policy === null && noPayment && noAftermath
      && approval.state === 'not_required' && execution.state === 'succeeded';
  } else if (outcome.status === 'upstream_failed' && reason === 'ORDINARY_HTTP_FAILURE') {
    matches = policy === null && noPayment && noAftermath
      && approval.state === 'not_required' && execution.state === 'failed'
      && execution.httpStatus >= 400 && execution.httpStatus <= 599;
  } else if (outcome.status === 'upstream_failed' && reason === 'UPSTREAM_TRANSPORT_FAILURE') {
    const ordinaryTransportFailure = policy === null
      && approval.state === 'not_required' && approval.operatorIdHash === null;
    const approvedRetryTransportFailure = policy?.decision === 'approval_required'
      && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
      && approval.state === 'approved' && approval.operatorIdHash !== null;
    matches = noPayment && noAftermath && isUnknownExecution(execution)
      && (ordinaryTransportFailure || approvedRetryTransportFailure);
  } else if (outcome.status === 'upstream_failed' && reason === 'RECOVERY_ABANDONED_UNSIGNED') {
    matches = policy === null && noPayment && noAftermath
      && approval.state === 'not_required' && noExecution;
  } else if (outcome.status === 'payment_denied' && PRE_POLICY_DENIAL_REASONS.has(reason)) {
    matches = policy === null && noPayment && noAftermath
      && approval.state === 'not_required' && noExecution;
  } else if (outcome.status === 'payment_denied' && POLICY_DENIAL_REASONS.has(reason)) {
    const deniedBeforeSpend = policy?.decision === 'deny' && policy.reasonCode === reason
      && approval.state === 'not_required' && approval.operatorIdHash === null
      && noPayment && noAftermath && noExecution;
    const expiredAfterReservation = reason === 'CHALLENGE_EXPIRED'
      && hasSpendAuthority(receipt) && isReleasedUnsigned(receipt)
      && noExecution && noAftermath;
    matches = deniedBeforeSpend || expiredAfterReservation;
  } else if (outcome.status === 'payment_denied' && reason === 'OPERATOR_DENIED') {
    matches = policy?.decision === 'approval_required'
      && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
      && approval.state === 'denied' && approval.operatorIdHash !== null
      && noPayment && noAftermath && noExecution;
  } else if (outcome.status === 'payment_denied' && reason === 'APPROVAL_EXPIRED') {
    matches = policy?.decision === 'approval_required'
      && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
      && approval.state === 'expired'
      && noPayment && noAftermath && noExecution;
  } else if (outcome.status === 'payment_denied'
      && APPROVAL_CANCELLATION_REASONS.has(reason)) {
    matches = policy?.decision === 'approval_required'
      && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
      && approval.state === 'cancelled'
      && noPayment && noAftermath && noExecution;
  } else if (outcome.status === 'payment_denied'
      && SESSION_CANCELLATION_REASONS.has(reason)) {
    matches = isSafeSessionCancellation(receipt);
  } else if (outcome.status === 'payment_denied'
      && ['AGENT_REVOKED', 'WALLET_RECOVERY_REQUIRED'].includes(reason)) {
    matches = hasSpendAuthority(receipt) && isReleasedUnsigned(receipt)
      && noExecution && noAftermath;
  } else if (outcome.status === 'payment_failed' && UNSIGNED_RELEASE_REASONS.has(reason)) {
    matches = hasSpendAuthority(receipt) && isReleasedUnsigned(receipt)
      && noExecution && noAftermath;
  } else if (outcome.status === 'payment_failed' && reason === 'RECOVERY_ABANDONED_UNSIGNED') {
    const recordedPolicyBeforeSpend = isAutomaticAuthority(receipt)
      || (policy?.decision === 'approval_required'
        && policy.reasonCode === 'HUMAN_APPROVAL_REQUIRED'
        && approval.state === 'not_required'
        && approval.operatorIdHash === null);
    matches = noExecution && noAftermath
      && ((recordedPolicyBeforeSpend && noPayment)
        || (hasSpendAuthority(receipt) && isReleasedUnsigned(receipt)));
  } else if (outcome.status === 'payment_unresolved'
      && PAYMENT_UNRESOLVED_REASONS.has(reason)) {
    matches = hasSpendAuthority(receipt) && payment.state === 'unresolved'
      && budget?.disposition === 'unresolved' && noExecution && refund === null
      && (reconciliation === null
        || (reconciliation.kind === 'payment' && reconciliation.outcome === 'unresolved'));
  } else if (outcome.status === 'payment_rejected'
      && reason === 'AUTHORIZATION_UNUSED_AFTER_EXPIRY') {
    matches = hasSpendAuthority(receipt) && payment.state === 'rejected'
      && budget?.disposition === 'released' && noExecution && refund === null
      && reconciliation?.kind === 'payment' && reconciliation.outcome === 'rejected';
  } else if (outcome.status === 'completed'
      && ['PAYMENT_SETTLED', 'EXECUTION_SUCCEEDED'].includes(reason)) {
    matches = paidCommitted && execution.state === 'succeeded' && noAftermath;
  } else if (outcome.status === 'completed'
      && reason === 'EXECUTION_RECONCILED_SUCCEEDED') {
    matches = receipt.revision > 1 && paidCommitted && execution.state === 'succeeded'
      && refund === null && reconciliation?.kind === 'execution'
      && reconciliation.outcome === 'execution_succeeded';
  } else if (outcome.status === 'execution_failed'
      && ['UPSTREAM_HTTP_FAILURE', 'UPSTREAM_FAILED'].includes(reason)) {
    matches = paidCommitted && execution.state === 'failed'
      && refund?.state === 'pending' && reconciliation === null;
  } else if (outcome.status === 'execution_failed' && reason === 'REFUND_UNRESOLVED') {
    const attestedFailure = receipt.revision > 1
      && refund?.state === 'pending'
      && reconciliation?.kind === 'execution'
      && reconciliation.outcome === 'execution_failed';
    matches = paidCommitted && execution.state === 'failed'
      && (['unresolved', 'abandoned', 'rejected'].includes(refund?.state)
        || attestedFailure);
  } else if (outcome.status === 'execution_unknown' && reason === 'PAID_RESPONSE_AMBIGUOUS') {
    matches = paidCommitted && isUnknownExecution(execution) && noAftermath;
  } else if (outcome.status === 'execution_unknown'
      && reason === 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN') {
    matches = receipt.revision > 1 && paidCommitted && isUnknownExecution(execution)
      && refund === null && reconciliation?.kind === 'payment'
      && reconciliation.outcome === 'settled';
  } else if (outcome.status === 'execution_unknown'
      && reason === 'RECOVERY_EXECUTION_MISSING') {
    matches = paidCommitted && isUnknownExecution(execution) && noAftermath;
  } else if (outcome.status === 'refunded' && reason === 'REFUND_CONFIRMED') {
    matches = hasSpendAuthority(receipt) && payment.state === 'settled'
      && budget?.disposition === 'released' && execution.state === 'failed'
      && refund?.state === 'confirmed' && reconciliation?.kind === 'refund'
      && reconciliation.outcome === 'refund_confirmed';
  }

  requireProjection(matches, 'receipt outcome reason contradicts its terminal projection');
}

function receiptRecordFromRow(row) {
  if (!row) return null;
  const receipt = validateReceiptSchema(parseCanonicalJson(row.receipt_json, 'signed receipt JSON'));
  const revision = positiveInteger(row.revision, 'signed receipt revision');
  const record = {
    id: row.id,
    intentId: row.intent_id,
    revision,
    receipt,
    receiptHash: row.receipt_hash,
    signature: row.signature,
    algorithm: row.algorithm,
    keyId: row.key_id,
    supersedesReceiptHash: row.supersedes_receipt_hash,
    createdAt: row.created_at,
  };
  canonicalToken(record.id, 'signed receipt ID');
  canonicalToken(record.intentId, 'signed receipt intent ID');
  canonicalTimestamp(record.createdAt, 'signed receipt createdAt');
  if (receipt.receiptId !== record.id || receipt.intent.id !== record.intentId
      || receipt.revision !== revision || receipt.issuedAt !== record.createdAt
      || receipt.supersedesReceiptHash !== record.supersedesReceiptHash) {
    fail('RECEIPT_CORRUPTION', 'signed receipt columns disagree with its projection');
  }
  return frozenCopy(record);
}

function buildProjection(access, { intentId, receiptId, issuedAt, supersedesReceiptHash }) {
  const intent = readUnique(
    access,
    'SELECT * FROM spend_intents WHERE id = ? ORDER BY rowid',
    [intentId],
    'Spend Intent',
  );
  const outcome = readUnique(
    access,
    'SELECT * FROM buyer_outcomes WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'BuyerOutcome',
  );
  if (!['terminal', 'unresolved'].includes(intent.state)) {
    fail('RECEIPT_NOT_TERMINAL', 'BuyerOutcome belongs to a nonterminal Spend Intent');
  }
  if (!OUTCOME_STATUSES.has(outcome.status)) fail('RECEIPT_CORRUPTION', 'BuyerOutcome status is invalid');
  reasonCode(outcome.reason_code, 'BuyerOutcome reason');
  const outcomeRecordedAt = canonicalTimestamp(outcome.recorded_at, 'BuyerOutcome recordedAt');
  if (Date.parse(issuedAt) < Date.parse(outcomeRecordedAt)) {
    fail('RECEIPT_TIME', 'receipt issuedAt predates its authoritative BuyerOutcome');
  }
  const decision = readUnique(
    access,
    'SELECT * FROM policy_decisions WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'PolicyDecision',
    { optional: true },
  );
  let policy = null;
  if (decision) {
    if (!POLICY_DECISIONS.has(decision.decision)) fail('RECEIPT_CORRUPTION', 'PolicyDecision is invalid');
    reasonCode(decision.reason_code, 'PolicyDecision reason');
    atomic(decision.amount_ceiling_atomic, 'PolicyDecision amount ceiling');
    policy = {
      versionId: canonicalToken(decision.policy_version_id, 'policy version ID'),
      decision: decision.decision,
      reasonCode: decision.reason_code,
    };
  }
  const approvalRow = readUnique(
    access,
    'SELECT * FROM approvals WHERE intent_id = ? ORDER BY rowid',
    [intentId],
    'Approval',
    { optional: true },
  );
  const approval = approvalRow
    ? {
      state: approvalRow.decision,
      operatorIdHash: approvalRow.operator_id_hash,
    }
    : { state: 'not_required', operatorIdHash: null };
  if (!APPROVAL_STATES.has(approval.state) || approval.state === 'not_required' && approvalRow) {
    fail('RECEIPT_CORRUPTION', 'Approval projection state is invalid');
  }
  if (approval.operatorIdHash !== null) hash(approval.operatorIdHash, 'approval operator hash');
  if (['approved', 'denied', 'consumed'].includes(approval.state)
      && approval.operatorIdHash === null) {
    fail('RECEIPT_CORRUPTION', 'authenticated approval decision lost its operator hash');
  }
  const { attempt, selected } = readSelectedPayment(access, intent, decision);
  const receipt = {
    schemaVersion: 1,
    receiptId: canonicalToken(receiptId, 'receipt ID'),
    revision: positiveInteger(outcome.revision, 'BuyerOutcome revision'),
    issuedAt: canonicalTimestamp(issuedAt, 'receipt issuedAt'),
    intent: {
      id: canonicalToken(intent.id, 'intent ID'),
      requestId: canonicalToken(intent.request_id, 'request ID'),
      intentHash: hash(intent.intent_hash, 'intent hash'),
      sessionId: canonicalToken(intent.session_id, 'session ID'),
      sellerOrigin: canonicalOrigin(intent.seller_origin),
      resourcePath: resourcePath(intent.resource_path),
      purposeLabel: canonicalToken(intent.purpose_label, 'purpose label'),
    },
    outcome: { status: outcome.status, reasonCode: outcome.reason_code },
    policy,
    approval,
    payment: projectPayment(attempt, selected, outcome.reason_code),
    execution: projectExecution(access, intentId),
    budget: projectBudget(access, intentId),
    reconciliation: projectReconciliation(access, intentId),
    refund: projectRefund(access, intentId),
    supersedesReceiptHash,
  };
  const validated = validateReceiptSchema(receipt);
  if (validated.outcome.reasonCode === 'PAYMENT_CANDIDATE_REJECTED') {
    const candidates = access.all(
      `SELECT * FROM payment_reconciliation_candidates
        WHERE intent_id = ? ORDER BY rowid`,
      [intentId],
    );
    const reconciliations = access.all(
      `SELECT * FROM reconciliations WHERE intent_id = ? ORDER BY rowid`,
      [intentId],
    );
    const reconciliation = reconciliations.at(-1);
    let rejectionEvidence = null;
    try {
      rejectionEvidence = JSON.parse(reconciliation?.evidence_json ?? 'null');
      if (signingCanonicalJson(rejectionEvidence) !== reconciliation?.evidence_json) {
        throw new Error('non-canonical');
      }
    } catch (cause) {
      fail(
        'RECEIPT_CORRUPTION',
        'payment candidate rejection reconciliation is malformed',
        { cause },
      );
    }
    const rejectedIndex = candidates.findIndex((candidate) => (
      candidate.state === 'rejected'
        && candidate.transaction_id === rejectionEvidence?.transactionId
        && candidate.evidence_json === reconciliation?.evidence_json
    ));
    const rejected = rejectedIndex < 0 ? null : candidates[rejectedIndex];
    const laterCandidates = rejectedIndex < 0 ? [] : candidates.slice(rejectedIndex + 1);
    if (validated.revision <= 1
        || validated.outcome.status !== 'payment_unresolved'
        || validated.payment.state !== 'unresolved'
        || validated.budget?.disposition !== 'unresolved'
        || validated.reconciliation?.kind !== 'payment'
        || validated.reconciliation.outcome !== 'unresolved'
        || reconciliation?.kind !== 'payment'
        || reconciliation.outcome !== 'unresolved'
        || !rejected
        || !EVM_TRANSACTION.test(rejected.transaction_id)
        || candidates.slice(0, rejectedIndex).some((candidate) => (
          candidate.state === 'pending' || candidate.state === 'confirmed'
        ))
        || laterCandidates.some((candidate) => (
          candidate.state !== 'pending' && candidate.state !== 'abandoned'
        ))) {
      fail(
        'RECEIPT_CORRUPTION',
        'payment candidate rejection lacks exact immutable rejected history',
      );
    }
    try {
      canonicalTimestamp(rejected.created_at, 'payment candidate createdAt');
      canonicalTimestamp(rejected.updated_at, 'payment candidate updatedAt');
    } catch (cause) {
      fail(
        'RECEIPT_CORRUPTION',
        'payment candidate rejection history is malformed',
        { cause },
      );
    }
  }
  return validated;
}

export function createSignedReceiptRepository({ store, signer, idFactory, now }) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('signed receipt repository requires a Wallet Kernel store');
  }
  if (!signer || signer.algorithm !== 'Ed25519' || typeof signer.signHash !== 'function'
      || typeof signer.publicKeyPem !== 'string' || typeof signer.keyId !== 'string') {
    throw new TypeError('signed receipt repository requires an Ed25519 signer');
  }
  let signingPublicKey;
  try { signingPublicKey = crypto.createPublicKey(signer.publicKeyPem); } catch (error) {
    throw new TypeError('signed receipt repository signer public key is invalid', { cause: error });
  }
  if (signingPublicKey.asymmetricKeyType !== 'ed25519'
      || receiptKeyId(signingPublicKey) !== signer.keyId) {
    throw new TypeError('signed receipt repository signer key ID must match its Ed25519 SPKI');
  }
  if (typeof idFactory !== 'function' || typeof now !== 'function') {
    throw new TypeError('signed receipt repository requires ID and clock functions');
  }
  const trust = Object.freeze({ publicKeyPem: signer.publicKeyPem, keyId: signer.keyId });

  const verify = (input) => {
    try {
      const record = exactRecord(input, [
        'id', 'intentId', 'revision', 'receipt', 'receiptHash', 'signature', 'algorithm',
        'keyId', 'supersedesReceiptHash', 'createdAt',
      ], [], 'RECEIPT_SCHEMA', 'signed receipt record');
      const normalized = receiptRecordFromRow({
        id: record.id,
        intent_id: record.intentId,
        revision: record.revision,
        receipt_json: signingCanonicalJson(record.receipt),
        receipt_hash: record.receiptHash,
        signature: record.signature,
        algorithm: record.algorithm,
        key_id: record.keyId,
        supersedes_receipt_hash: record.supersedesReceiptHash,
        created_at: record.createdAt,
      });
      return verifySignedReceipt(normalized, trust);
    } catch {
      return false;
    }
  };

  const assertHistory = (access, intentId) => {
    const rows = access.all(
      'SELECT * FROM signed_receipts WHERE intent_id = ? ORDER BY revision',
      [intentId],
    );
    let previousHash = null;
    let previousEventSequence = 0;
    for (let index = 0; index < rows.length; index += 1) {
      const record = receiptRecordFromRow(rows[index]);
      if (record.revision !== index + 1
          || record.supersedesReceiptHash !== previousHash
          || !verify(record)) {
        fail('RECEIPT_PARITY_REQUIRED', 'signed receipt history is incomplete or invalid');
      }
      const event = readUnique(
        access,
        `SELECT * FROM events WHERE entity_type = 'signed_receipt'
          AND entity_id = ? AND event_type = 'receipt.issued' ORDER BY sequence`,
        [record.id],
        'signed receipt event',
      );
      const eventData = exactRecord(
        parseCanonicalJson(event.data_json, 'signed receipt event JSON'),
        ['intentId', 'revision', 'receiptHash', 'keyId', 'supersedesReceiptHash'],
        [],
        'RECEIPT_PARITY_REQUIRED',
        'signed receipt event',
      );
      const eventSequence = positiveInteger(event.sequence, 'receipt event sequence');
      canonicalTimestamp(event.created_at, 'receipt event createdAt');
      if (eventData.intentId !== record.intentId
          || eventData.revision !== record.revision
          || eventData.receiptHash !== record.receiptHash
          || eventData.keyId !== record.keyId
          || eventData.supersedesReceiptHash !== record.supersedesReceiptHash
          || Date.parse(event.created_at) < Date.parse(record.createdAt)
          || eventSequence <= previousEventSequence) {
        fail('RECEIPT_PARITY_REQUIRED', 'signed receipt event disagrees with receipt history');
      }
      previousEventSequence = eventSequence;
      previousHash = record.receiptHash;
    }
    return rows.length === 0 ? null : receiptRecordFromRow(rows.at(-1));
  };

  const assertCurrentProjection = (access, record) => {
    if (record === null) return null;
    const projected = buildProjection(access, {
      intentId: record.intentId,
      receiptId: record.id,
      issuedAt: record.createdAt,
      supersedesReceiptHash: record.supersedesReceiptHash,
    });
    if (signingCanonicalJson(projected) !== signingCanonicalJson(record.receipt)) {
      fail('RECEIPT_PARITY_REQUIRED', 'current signed receipt disagrees with durable authority');
    }
    return record;
  };

  const assertParityWithAccess = (access) => {
    const outcomes = access.all('SELECT * FROM buyer_outcomes ORDER BY intent_id');
    const outcomeIds = new Set(outcomes.map((row) => row.intent_id));
    const orphans = access.all('SELECT intent_id FROM signed_receipts ORDER BY intent_id')
      .filter((row) => !outcomeIds.has(row.intent_id));
    if (orphans.length > 0) fail('RECEIPT_PARITY_REQUIRED', 'signed receipt has no BuyerOutcome');
    const receiptCount = access.one('SELECT COUNT(*) AS count FROM signed_receipts').count;
    const receiptEventCount = access.one(`SELECT COUNT(*) AS count FROM events
      WHERE entity_type = 'signed_receipt' AND event_type = 'receipt.issued'`).count;
    if (receiptCount !== receiptEventCount) {
      fail('RECEIPT_PARITY_REQUIRED', 'signed receipt event history is incomplete or ambiguous');
    }
    for (const outcome of outcomes) {
      const latest = assertHistory(access, outcome.intent_id);
      const revision = positiveInteger(outcome.revision, 'BuyerOutcome revision');
      if (!latest || latest.revision !== revision) {
        fail('RECEIPT_PARITY_REQUIRED', 'BuyerOutcome is missing its current signed receipt');
      }
      assertCurrentProjection(access, latest);
    }
    return true;
  };

  const assertRecoverableParityWithAccess = (access) => {
    const outcomes = access.all('SELECT * FROM buyer_outcomes ORDER BY intent_id');
    const outcomeIds = new Set(outcomes.map((row) => row.intent_id));
    const orphans = access.all('SELECT intent_id FROM signed_receipts ORDER BY intent_id')
      .filter((row) => !outcomeIds.has(row.intent_id));
    if (orphans.length > 0) fail('RECEIPT_PARITY_REQUIRED', 'signed receipt has no BuyerOutcome');
    const receiptCount = access.one('SELECT COUNT(*) AS count FROM signed_receipts').count;
    const receiptEventCount = access.one(`SELECT COUNT(*) AS count FROM events
      WHERE entity_type = 'signed_receipt' AND event_type = 'receipt.issued'`).count;
    if (receiptCount !== receiptEventCount) {
      fail('RECEIPT_PARITY_REQUIRED', 'signed receipt event history is incomplete or ambiguous');
    }
    for (const outcome of outcomes) {
      const latest = assertHistory(access, outcome.intent_id);
      const revision = positiveInteger(outcome.revision, 'BuyerOutcome revision');
      if (latest?.revision === revision) {
        assertCurrentProjection(access, latest);
        continue;
      }
      const exactRepairableTailGap = (latest === null && revision === 1)
        || (latest !== null && latest.revision === revision - 1);
      if (!exactRepairableTailGap) {
        fail('RECEIPT_PARITY_REQUIRED', 'missing receipt history cannot be reconstructed');
      }
    }
    return true;
  };

  const issueInTransaction = (token, {
    intentId,
    suppliedPredecessor,
    initialOnly,
    deferGlobalParity = false,
  }) => store.within(
    token,
    ({ db, appendEvent }) => {
      const access = transactionAccess(db);
      const outcome = readUnique(
        access,
        'SELECT * FROM buyer_outcomes WHERE intent_id = ? ORDER BY rowid',
        [intentId],
        'BuyerOutcome',
      );
      const revision = positiveInteger(outcome.revision, 'BuyerOutcome revision');
      const history = assertHistory(access, intentId);
      if (initialOnly && revision !== 1) {
        fail('RECEIPT_REVISION', 'initial receipt issuance requires BuyerOutcome revision 1');
      }
      const existing = access.one(
        'SELECT * FROM signed_receipts WHERE intent_id = ? AND revision = ?',
        [intentId, revision],
      );
      if (existing) {
        const record = receiptRecordFromRow(existing);
        if (history?.receiptHash !== record.receiptHash
            || !verify(record) || (suppliedPredecessor !== undefined
          && record.supersedesReceiptHash !== suppliedPredecessor)) {
          fail('RECEIPT_CONFLICT', 'existing signed receipt differs from requested revision');
        }
        const projected = buildProjection(access, {
          intentId,
          receiptId: record.id,
          issuedAt: record.createdAt,
          supersedesReceiptHash: record.supersedesReceiptHash,
        });
        if (signingCanonicalJson(projected) !== signingCanonicalJson(record.receipt)) {
          fail('RECEIPT_CONFLICT', 'existing signed receipt no longer projects current authority');
        }
        if (!deferGlobalParity) assertParityWithAccess(access);
        return record;
      }

      const previous = history;
      const expectedPredecessor = previous?.receiptHash ?? null;
      if ((previous === null && revision !== 1)
          || (previous !== null && previous.revision !== revision - 1)
          || (suppliedPredecessor !== undefined && suppliedPredecessor !== expectedPredecessor)) {
        fail('RECEIPT_REVISION', 'receipt revision requires its exact predecessor hash');
      }
      const receiptId = canonicalToken(idFactory('receipt'), 'receipt ID');
      const issuedAt = canonicalTimestamp(now(), 'receipt issuedAt');
      const receipt = buildProjection(access, {
        intentId,
        receiptId,
        issuedAt,
        supersedesReceiptHash: expectedPredecessor,
      });
      const receiptJson = signingCanonicalJson(receipt);
      const receiptHash = crypto.createHash('sha256').update(receiptJson).digest('hex');
      const signature = signer.signHash(receiptHash);
      const candidate = frozenCopy({
        id: receiptId,
        intentId,
        revision,
        receipt,
        receiptHash,
        signature,
        algorithm: signer.algorithm,
        keyId: signer.keyId,
        supersedesReceiptHash: expectedPredecessor,
        createdAt: issuedAt,
      });
      if (!verify(candidate)) fail('RECEIPT_SIGNATURE', 'receipt signer returned an invalid signature');
      const inserted = db.prepare(`INSERT INTO signed_receipts
        (id, intent_id, revision, receipt_json, receipt_hash, signature, algorithm,
         key_id, supersedes_receipt_hash, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        receiptId,
        intentId,
        revision,
        receiptJson,
        receiptHash,
        signature,
        signer.algorithm,
        signer.keyId,
        expectedPredecessor,
        issuedAt,
      );
      if (inserted.changes !== 1n) fail('RECEIPT_CONFLICT', 'receipt insert lost its race');
      appendEvent({
        entityType: 'signed_receipt',
        entityId: receiptId,
        eventType: 'receipt.issued',
        data: {
          intentId,
          revision,
          receiptHash,
          keyId: signer.keyId,
          supersedesReceiptHash: expectedPredecessor,
        },
      });
      if (!deferGlobalParity) assertParityWithAccess(access);
      return candidate;
    },
  );

  const issueForTerminal = (input) => {
    const { intentId } = exactRecord(input, ['intentId'], [],
      'RECEIPT_INPUT', 'terminal receipt request');
    const normalizedIntentId = canonicalToken(intentId, 'intent ID');
    return store.transaction((token) => issueInTransaction(token, {
      intentId: normalizedIntentId,
      suppliedPredecessor: undefined,
      initialOnly: true,
    }));
  };

  const issueRevisionForTerminal = (input) => {
    const request = exactRecord(input, ['intentId', 'supersedesReceiptHash'], [],
      'RECEIPT_INPUT', 'receipt revision request');
    const intentId = canonicalToken(request.intentId, 'intent ID');
    if (!/^[0-9a-f]{64}$/.test(request.supersedesReceiptHash)) {
      fail('RECEIPT_REVISION', 'receipt revision predecessor hash is invalid');
    }
    return store.transaction((token) => issueInTransaction(token, {
      intentId,
      suppliedPredecessor: request.supersedesReceiptHash,
      initialOnly: false,
    }));
  };

  const issueMissingTerminalReceipts = () => {
    return store.transaction((token) => store.within(token, ({ db }) => {
      const access = transactionAccess(db);
      const outcomes = access.all(
        'SELECT intent_id, revision FROM buyer_outcomes ORDER BY intent_id',
      );
      const issued = [];
      for (const outcome of outcomes) {
        const latest = assertHistory(access, outcome.intent_id);
        const revision = positiveInteger(outcome.revision, 'BuyerOutcome revision');
        if (latest?.revision === revision) continue;
        if (latest === null && revision === 1) {
          issued.push(issueInTransaction(token, {
            intentId: outcome.intent_id,
            suppliedPredecessor: undefined,
            initialOnly: true,
            deferGlobalParity: true,
          }));
        } else if (latest && latest.revision === revision - 1) {
          issued.push(issueInTransaction(token, {
            intentId: outcome.intent_id,
            suppliedPredecessor: latest.receiptHash,
            initialOnly: false,
            deferGlobalParity: true,
          }));
        } else {
          fail('RECEIPT_REVISION', 'missing receipt history cannot be reconstructed');
        }
      }
      assertParityWithAccess(access);
      return frozenCopy(issued);
    }));
  };

  const assertParityInTransaction = (token) => store.within(
    token,
    ({ db }) => assertParityWithAccess(transactionAccess(db)),
  );
  const assertRecoverableParityInTransaction = (token) => store.within(
    token,
    ({ db }) => assertRecoverableParityWithAccess(transactionAccess(db)),
  );
  const assertParity = () => store.transaction((token) => assertParityInTransaction(token));

  const latest = (intentId) => {
    const access = dataAccess(store);
    return assertCurrentProjection(
      access,
      assertHistory(access, canonicalToken(intentId, 'intent ID')),
    );
  };

  const list = (input) => {
    const request = exactRecord(input, ['sessionId', 'limit'], [],
      'RECEIPT_INPUT', 'receipt list request');
    const sessionId = canonicalToken(request.sessionId, 'session ID');
    if (!Number.isSafeInteger(request.limit) || request.limit < 1 || request.limit > 1_000) {
      fail('RECEIPT_INPUT', 'receipt list limit must be between 1 and 1000');
    }
    const access = dataAccess(store);
    const rows = access.all(`SELECT r.* FROM signed_receipts r
      JOIN spend_intents i ON i.id = r.intent_id
      WHERE i.session_id = ?
      ORDER BY r.created_at DESC, r.revision DESC, r.id DESC
      LIMIT ?`, [sessionId, request.limit]);
    for (const intentId of new Set(rows.map((row) => row.intent_id))) {
      assertCurrentProjection(access, assertHistory(access, intentId));
    }
    return frozenCopy(rows.map(receiptRecordFromRow));
  };

  return Object.freeze({
    issueForTerminal,
    issueRevisionForTerminal,
    issueMissingTerminalReceipts,
    assertParity,
    assertParityInTransaction,
    assertRecoverableParityInTransaction,
    latest,
    list,
    verify,
  });
}

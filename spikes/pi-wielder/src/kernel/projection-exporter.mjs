import crypto from 'node:crypto';

import {
  decodePaymentSignatureHeader,
  encodePaymentSignatureHeader,
} from '@x402/core/http';

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
import { receiptKeyId } from './receipt-signing.mjs';
import { createBudgetLedger } from './budget-ledger.mjs';
import {
  validateChallengeProjection,
  validatePolicyDocument,
} from './policy-engine.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,127}$/;
const ECDSA_SIGNATURE = /^0x[0-9a-f]{130}$/;
const SECP256K1_N = BigInt('0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141');
const SECP256K1_HALF_N = SECP256K1_N / 2n;
const FORBIDDEN_EXPORT_TERMS = /prompt|body|authorization|payment.signature|private|secret|token|stack|file.path/i;
const FILESYSTEM_PATH = /(?:file:\/\/|\/(?:Users|home|private|tmp|var|etc|opt|root|proc|sys|dev)\/|[A-Za-z]:\\)/i;
const APPROVAL_STATES = Object.freeze([
  'approved',
  'cancelled',
  'consumed',
  'denied',
  'expired',
  'pending',
]);
const ENFORCED_PROBES = Object.freeze({
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

function fail(code, message, options) {
  throw new KernelError(code, message, options);
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('PROJECTION_CORRUPTION', `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== 'string' || !ADDRESS.test(value)) {
    fail('PROJECTION_CORRUPTION', `${label} must be one lowercase EVM address`);
  }
  return value;
}

function canonicalReason(value, label) {
  if (typeof value !== 'string' || !REASON.test(value)) {
    fail('PROJECTION_CORRUPTION', `${label} must be one bounded reason code`);
  }
  return value;
}

function safeInteger(value, label) {
  const number = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    fail('PROJECTION_CORRUPTION', `${label} must be one nonnegative safe integer`);
  }
  return number;
}

function persistedToken(value, label, maximum) {
  try {
    return canonicalToken(value, label, maximum);
  } catch (error) {
    fail('PROJECTION_CORRUPTION', `${label} is not canonical`, { cause: error });
  }
}

function persistedTimestamp(value, label) {
  try {
    return canonicalTimestamp(value, label);
  } catch (error) {
    fail('PROJECTION_CORRUPTION', `${label} is not canonical`, { cause: error });
  }
}

function persistedAtomic(value, label) {
  try {
    return canonicalAtomic(value, label);
  } catch (error) {
    fail('PROJECTION_CORRUPTION', `${label} is not canonical atomic text`, { cause: error });
  }
}

function canonicalOrigin(value, label) {
  let parsed;
  try { parsed = new URL(value); } catch (error) {
    fail('PROJECTION_CORRUPTION', `${label} is not a URL origin`, { cause: error });
  }
  if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.username || parsed.password || parsed.pathname !== '/'
      || parsed.search || parsed.hash || parsed.origin !== value) {
    fail('PROJECTION_CORRUPTION', `${label} must be one credential-free HTTP origin`);
  }
  return value;
}

function parseCanonicalJson(text, label) {
  if (typeof text !== 'string') {
    fail('PROJECTION_CORRUPTION', `${label} must be canonical JSON text`);
  }
  let value;
  try { value = JSON.parse(text); } catch (error) {
    fail('PROJECTION_CORRUPTION', `${label} is invalid JSON`, { cause: error });
  }
  if (canonicalJson(value) !== text) {
    fail('PROJECTION_CORRUPTION', `${label} is not canonical JSON`);
  }
  return value;
}

function hashPrivateLabel(domain, key, value) {
  if (typeof value !== 'string') {
    fail('PROJECTION_CORRUPTION', `${key} must be text before sanitization`);
  }
  return sha256(canonicalJson({ domain, [key]: value }));
}

function assertSanitized(value, path = '$', seen = new WeakSet()) {
  if (FORBIDDEN_EXPORT_TERMS.test(path)) {
    fail('PROJECTION_SANITIZATION', 'projection field name is forbidden');
  }
  if (typeof value === 'string') {
    if (FORBIDDEN_EXPORT_TERMS.test(value) || FILESYSTEM_PATH.test(value)) {
      fail('PROJECTION_SANITIZATION', 'projection contains forbidden source material');
    }
    return;
  }
  if (!value || typeof value !== 'object') return;
  if (seen.has(value)) fail('PROJECTION_SANITIZATION', 'projection contains a cycle');
  seen.add(value);
  try {
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_EXPORT_TERMS.test(key)) {
        fail('PROJECTION_SANITIZATION', 'projection field name is forbidden');
      }
      assertSanitized(child, `${path}.${key}`, seen);
    }
  } finally {
    seen.delete(value);
  }
}

function validateStore(store) {
  const methods = ['transaction', 'within'];
  if (!store || typeof store !== 'object'
      || methods.some((method) => typeof store[method] !== 'function')) {
    throw new TypeError('projection exporter requires a readable Wallet Kernel store');
  }
}

function validateReceipts(receipts) {
  if (!receipts || typeof receipts !== 'object'
      || typeof receipts.assertParityInTransaction !== 'function'
      || typeof receipts.verify !== 'function') {
    throw new TypeError('projection exporter requires a signed receipt repository');
  }
}

function transactionAccess(db) {
  return Object.freeze({
    one: (sql, parameters = []) => db.prepare(sql).get(...parameters),
    all: (sql, parameters = []) => db.prepare(sql).all(...parameters),
  });
}

function normalizeSigner(signer) {
  if (!signer || typeof signer !== 'object'
      || signer.algorithm !== 'Ed25519'
      || typeof signer.signHash !== 'function'
      || typeof signer.publicKeyPem !== 'string'
      || typeof signer.keyId !== 'string') {
    throw new TypeError('projection exporter requires an Ed25519 signer');
  }
  let publicKey;
  try { publicKey = crypto.createPublicKey(signer.publicKeyPem); } catch (error) {
    throw new TypeError('projection exporter signer public key is invalid', { cause: error });
  }
  if (publicKey.asymmetricKeyType !== 'ed25519'
      || receiptKeyId(publicKey) !== signer.keyId) {
    throw new TypeError('projection exporter signer key ID must match its Ed25519 SPKI');
  }
  return Object.freeze({
    algorithm: 'Ed25519',
    keyId: signer.keyId,
    publicKey,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    signHash: (hashHex) => signer.signHash.call(signer, hashHex),
  });
}

function validateSessionRow(session) {
  persistedToken(session.id, 'Spend Session ID');
  persistedToken(session.adapter_id, 'wallet adapter ID');
  canonicalAddress(session.wallet_address, 'Spend Session wallet');
  persistedToken(session.policy_version_id, 'Spend Session policy version ID');
  const createdAt = persistedTimestamp(session.created_at, 'Spend Session createdAt');
  if (!['open', 'policy_blocked', 'closed'].includes(session.state)) {
    fail('PROJECTION_CORRUPTION', 'Spend Session state is invalid');
  }
  if ((session.state === 'closed') !== (session.closed_at !== null)) {
    fail('PROJECTION_CORRUPTION', 'Spend Session close fields disagree');
  }
  if (session.closed_at !== null) {
    const closedAt = persistedTimestamp(session.closed_at, 'Spend Session closedAt');
    if (Date.parse(closedAt) < Date.parse(createdAt)) {
      fail('PROJECTION_CORRUPTION', 'Spend Session closedAt predates creation');
    }
  }
  return session;
}

function projectPolicies(access) {
  const rows = access.all('SELECT * FROM policy_versions ORDER BY rowid');
  const byId = new Map();
  let previousHash = null;
  for (const row of rows) {
    persistedToken(row.id, 'PolicyVersion ID');
    const schemaVersion = safeInteger(row.schema_version, 'PolicyVersion schema version');
    if (schemaVersion !== 1) fail('PROJECTION_CORRUPTION', 'PolicyVersion schema is unsupported');
    const parsed = parseCanonicalJson(row.canonical_json, 'PolicyVersion document');
    let policy;
    try { policy = validatePolicyDocument(parsed); } catch (error) {
      if (error instanceof KernelError) {
        fail('PROJECTION_CORRUPTION', 'PolicyVersion document is invalid');
      }
      throw error;
    }
    const policyHash = canonicalHash(row.policy_hash, 'PolicyVersion hash');
    if (canonicalJson(policy) !== row.canonical_json
        || sha256(row.canonical_json) !== policyHash
        || row.predecessor_hash !== previousHash) {
      fail('PROJECTION_CORRUPTION', 'PolicyVersion hash chain changed');
    }
    const appliedAt = persistedTimestamp(row.applied_at, 'PolicyVersion appliedAt');
    const predecessor = rows[byId.size - 1];
    if (predecessor && Date.parse(appliedAt) < Date.parse(predecessor.applied_at)) {
      fail('PROJECTION_CORRUPTION', 'PolicyVersion time regressed');
    }
    byId.set(row.id, Object.freeze({ hash: policyHash, policy, row }));
    previousHash = policyHash;
  }
  const activeId = access.one("SELECT value FROM metadata WHERE key = 'active_policy_id'")?.value;
  const active = byId.get(activeId);
  if (!active) fail('PROJECTION_CORRUPTION', 'active PolicyVersion is missing');
  return Object.freeze({
    active,
    byId,
    historyHashes: Object.freeze(rows.map((row) => row.policy_hash)),
  });
}

function validateSessionBinding(access, session) {
  const bindings = access.all(
    'SELECT * FROM agent_session_bindings WHERE session_id = ? ORDER BY rowid',
    [session.id],
  );
  if (bindings.length !== 1) {
    fail('PROJECTION_CORRUPTION', 'Spend Session must have one exact agent binding');
  }
  const binding = bindings[0];
  persistedToken(binding.id, 'agent binding ID');
  if ((binding.state === 'open') !== (session.state !== 'closed')
      || (binding.state === 'closed') !== (session.state === 'closed')) {
    fail('PROJECTION_CORRUPTION', 'agent binding state disagrees with Spend Session');
  }
  const enrollments = access.all(
    'SELECT * FROM agent_enrollments WHERE enrollment_hash = ? ORDER BY rowid',
    [binding.enrollment_hash],
  );
  if (enrollments.length !== 1) {
    fail('PROJECTION_CORRUPTION', 'agent binding enrollment is missing or ambiguous');
  }
  const enrollment = enrollments[0];
  const descriptor = {
    schemaVersion: 1,
    agentInstanceId: enrollment.agent_instance_id,
    credentialDigest: canonicalHash(enrollment.credential_digest, 'agent credential digest'),
    agentUid: enrollment.agent_uid,
    agentGid: enrollment.agent_gid,
  };
  if (!/^[1-9][0-9]*$/.test(descriptor.agentUid)
      || !/^[1-9][0-9]*$/.test(descriptor.agentGid)
      || sha256(canonicalJson(descriptor)) !== enrollment.enrollment_hash
      || binding.agent_instance_id !== enrollment.agent_instance_id
      || binding.credential_digest !== enrollment.credential_digest
      || binding.enrollment_hash !== enrollment.enrollment_hash
      || session.adapter_id !== `pi:${enrollment.agent_instance_id}`) {
    fail('PROJECTION_CORRUPTION', 'agent enrollment binding changed');
  }
  const enrollmentHash = canonicalHash(enrollment.enrollment_hash, 'agent enrollment hash');
  if (!['active', 'revoked'].includes(enrollment.state)) {
    fail('PROJECTION_CORRUPTION', 'agent enrollment state is invalid');
  }
  const sessionCreatedAt = persistedTimestamp(session.created_at, 'Spend Session createdAt');
  const bindingCreatedAt = persistedTimestamp(binding.created_at, 'agent binding createdAt');
  const lastSeenAt = persistedTimestamp(binding.last_seen_at, 'agent binding lastSeenAt');
  const bindingClosedAt = binding.closed_at === null
    ? null
    : persistedTimestamp(binding.closed_at, 'agent binding closedAt');
  if (bindingCreatedAt !== sessionCreatedAt
      || Date.parse(lastSeenAt) < Date.parse(bindingCreatedAt)
      || (session.state === 'closed'
        && (bindingClosedAt !== session.closed_at || lastSeenAt !== session.closed_at))
      || (session.state !== 'closed' && bindingClosedAt !== null)) {
    fail('PROJECTION_CORRUPTION', 'agent binding chronology changed');
  }
  canonicalHash(enrollment.enrolled_by_operator_hash, 'enrollment operator hash');
  const enrolledAt = persistedTimestamp(enrollment.enrolled_at, 'agent enrolledAt');
  if (Date.parse(bindingCreatedAt) < Date.parse(enrolledAt)) {
    fail('PROJECTION_CORRUPTION', 'agent binding predates enrollment');
  }
  if (enrollment.state === 'active') {
    if (enrollment.revoked_by_operator_hash !== null || enrollment.revoked_at !== null) {
      fail('PROJECTION_CORRUPTION', 'active enrollment contains revocation fields');
    }
  } else {
    canonicalHash(enrollment.revoked_by_operator_hash, 'revocation operator hash');
    const revokedAt = persistedTimestamp(enrollment.revoked_at, 'agent revokedAt');
    if (Date.parse(revokedAt) < Date.parse(enrolledAt)) {
      fail('PROJECTION_CORRUPTION', 'agent revocation predates enrollment');
    }
  }
  const eventRows = access.all(`SELECT data_json FROM events
    WHERE entity_type = 'agent_enrollment' AND entity_id = ?
      AND event_type = 'agent.enrolled' ORDER BY sequence`, [enrollment.agent_instance_id]);
  if (eventRows.length !== 1) {
    fail('PROJECTION_CORRUPTION', 'agent enrollment creation event is missing or ambiguous');
  }
  const event = exactRecord(
    parseCanonicalJson(eventRows[0].data_json, 'agent enrollment event'),
    [
      'enrollmentHash', 'credentialDigest', 'agentUid', 'agentGid',
      'operatorIdHash', 'isolation', 'enrolledAt',
    ],
    [],
    'PROJECTION_CORRUPTION',
    'agent enrollment event',
  );
  if (event.enrollmentHash !== enrollmentHash
      || event.credentialDigest !== enrollment.credential_digest
      || event.agentUid !== enrollment.agent_uid
      || event.agentGid !== enrollment.agent_gid
      || canonicalHash(event.operatorIdHash, 'enrollment event operator hash')
        !== enrollment.enrolled_by_operator_hash
      || persistedTimestamp(event.enrolledAt, 'enrollment event enrolledAt') !== enrolledAt
      || !['simulated', 'pending_verification'].includes(event.isolation)) {
    fail('PROJECTION_CORRUPTION', 'agent enrollment event binding changed');
  }
  return Object.freeze({ binding, enrollment, enrollmentHash, isolationLabel: event.isolation });
}

function projectEnrollment(access, session, issuedAt, sessionAuthority = null) {
  const authority = sessionAuthority ?? validateSessionBinding(access, session);
  const { enrollment, enrollmentHash } = authority;

  const current = access.all(
    "SELECT * FROM isolation_attestations WHERE state = 'current' ORDER BY rowid",
  );
  if (current.length > 1
      || current.some((row) => row.enrollment_hash !== enrollmentHash)) {
    fail('PROJECTION_CORRUPTION', 'current isolation attestation is ambiguous or misbound');
  }
  let isolation = { status: authority.isolationLabel, preflightDigest: null };
  if (current.length === 1) {
    if (enrollment.state !== 'active' || authority.isolationLabel !== 'pending_verification') {
      fail(
        'PROJECTION_CORRUPTION',
        'only an active live enrollment can claim a current isolation report',
      );
    }
    const attestation = current[0];
    persistedToken(attestation.id, 'isolation attestation ID');
    const reportHash = canonicalHash(attestation.report_hash, 'isolation preflight digest');
    canonicalHash(
      attestation.imported_by_operator_hash,
      'isolation attestation operator hash',
    );
    if (attestation.superseded_at !== null) {
      fail('PROJECTION_CORRUPTION', 'current isolation attestation is superseded');
    }
    const { fresh, report } = validateEnforcedIsolationReport(
      attestation,
      enrollment,
      issuedAt,
    );
    if (sha256(canonicalJson(report)) !== reportHash) {
      fail('PROJECTION_CORRUPTION', 'isolation preflight digest changed');
    }
    isolation = {
      status: fresh ? 'enforced' : authority.isolationLabel,
      preflightDigest: reportHash,
    };
  }
  return Object.freeze({
    agentEnrollment: frozenCopy({
      enrollmentHash,
      identityHash: sha256(canonicalJson({
        domain: 'wallet-kernel.agent-identity.v1',
        agentUid: enrollment.agent_uid,
        agentGid: enrollment.agent_gid,
      })),
      state: enrollment.state,
    }),
    isolation: frozenCopy(isolation),
  });
}

function validateEnforcedIsolationReport(attestation, enrollment, issuedAt) {
  const report = exactRecord(
    parseCanonicalJson(attestation.report_json, 'current isolation report'),
    [
      'schemaVersion', 'enrollmentHash', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid',
      'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
      'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
      'systemdEffectiveConfigHash', 'environmentMetadataHash', 'probeResults',
      'probedAt', 'expiresAt',
    ],
    [],
    'PROJECTION_CORRUPTION',
    'current isolation report',
  );
  if (report.schemaVersion !== 1
      || report.enrollmentHash !== enrollment.enrollment_hash
      || report.agentUid !== enrollment.agent_uid
      || report.agentGid !== enrollment.agent_gid
      || !/^[1-9][0-9]*$/.test(report.kernelUid)
      || !/^[1-9][0-9]*$/.test(report.kernelGid)
      || report.kernelUid === report.agentUid) {
    fail('PROJECTION_CORRUPTION', 'current isolation report identity binding is invalid');
  }
  for (const name of [
    'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
    'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash', 'environmentMetadataHash',
  ]) canonicalHash(report[name], `isolation report ${name}`);
  const probes = exactRecord(
    report.probeResults,
    Object.keys(ENFORCED_PROBES),
    [],
    'PROJECTION_CORRUPTION',
    'isolation probe results',
  );
  if (Object.entries(ENFORCED_PROBES).some(([name, result]) => probes[name] !== result)) {
    fail('PROJECTION_CORRUPTION', 'current isolation report does not prove enforced isolation');
  }
  const probedAt = persistedTimestamp(report.probedAt, 'isolation report probedAt');
  const expiresAt = persistedTimestamp(report.expiresAt, 'isolation report expiresAt');
  const importedAt = persistedTimestamp(
    attestation.imported_at,
    'isolation attestation importedAt',
  );
  if (attestation.probed_at !== probedAt
      || attestation.expires_at !== expiresAt
      || Date.parse(expiresAt) <= Date.parse(probedAt)
      || Date.parse(expiresAt) - Date.parse(probedAt) > 15 * 60 * 1_000
      || Date.parse(importedAt) < Date.parse(probedAt)
      || Date.parse(importedAt) >= Date.parse(expiresAt)
      || Date.parse(importedAt) > Date.parse(issuedAt)
  ) {
    fail('PROJECTION_CORRUPTION', 'current isolation report has invalid timestamps');
  }
  return Object.freeze({ fresh: Date.parse(issuedAt) < Date.parse(expiresAt), report });
}

function canonicalTransactionId(value, label) {
  if (typeof value !== 'string' || !/^0x[0-9a-f]{64}$/.test(value)) {
    fail('PROJECTION_CORRUPTION', `${label} must be one canonical EVM transaction hash`);
  }
  return value;
}

function validateSessions(access, policies) {
  const rows = access.all('SELECT * FROM spend_sessions ORDER BY rowid');
  const byId = new Map();
  for (const raw of rows) {
    const session = validateSessionRow(raw);
    const policyVersion = policies.byId.get(session.policy_version_id);
    if (!policyVersion
        || session.wallet_address !== policyVersion.policy.wallet
        || Date.parse(session.created_at) < Date.parse(policyVersion.row.applied_at)) {
      fail('PROJECTION_CORRUPTION', 'Spend Session is detached from its PolicyVersion wallet');
    }
    const pinsActivePolicy = session.policy_version_id === policies.active.row.id;
    if ((session.state === 'open' && !pinsActivePolicy)
        || (session.state === 'policy_blocked' && pinsActivePolicy)) {
      fail('PROJECTION_CORRUPTION', 'Spend Session state disagrees with active policy lifecycle');
    }
    const bindingAuthority = validateSessionBinding(access, session);
    byId.set(session.id, Object.freeze({ session, policyVersion, ...bindingAuthority }));
  }
  return byId;
}

function validateDecision(access, intent, sessionAuthority) {
  const rows = access.all(
    'SELECT * FROM policy_decisions WHERE intent_id = ? ORDER BY rowid',
    [intent.id],
  );
  if (rows.length > 1) {
    fail('PROJECTION_CORRUPTION', 'Spend Intent PolicyDecision is ambiguous');
  }
  if (rows.length === 0) return Object.freeze({ decision: null, projection: null });
  const decision = rows[0];
  if (decision.intent_id !== intent.id
      || decision.policy_version_id !== sessionAuthority.policyVersion.row.id
      || !['allow', 'approval_required', 'deny'].includes(decision.decision)) {
    fail('PROJECTION_CORRUPTION', 'PolicyDecision authority was rebound');
  }
  canonicalReason(decision.reason_code, 'PolicyDecision reason');
  const challengeHash = canonicalHash(decision.challenge_hash, 'PolicyDecision challenge hash');
  const amount = persistedAtomic(decision.amount_ceiling_atomic, 'PolicyDecision amount ceiling');
  const decidedAt = persistedTimestamp(decision.decided_at, 'PolicyDecision decidedAt');
  if (intent.challenge_projection_json === null
      || intent.challenge_hash === null
      || intent.challenge_received_at === null) {
    fail('PROJECTION_CORRUPTION', 'PolicyDecision has no complete challenge authority');
  }
  const parsed = parseCanonicalJson(
    intent.challenge_projection_json,
    'Spend Intent challenge projection',
  );
  let projection;
  try {
    projection = validateChallengeProjection(parsed);
  } catch (error) {
    fail('PROJECTION_CORRUPTION', 'Spend Intent challenge projection is invalid', { cause: error });
  }
  const projectionJson = canonicalJson(projection);
  const receivedAt = persistedTimestamp(
    intent.challenge_received_at,
    'Spend Intent challenge receivedAt',
  );
  if (projectionJson !== intent.challenge_projection_json
      || sha256(projectionJson) !== intent.challenge_hash
      || intent.challenge_hash !== challengeHash
      || Date.parse(receivedAt) < Date.parse(intent.created_at)
      || Date.parse(decidedAt) < Date.parse(receivedAt)
      || Date.parse(decidedAt) > Date.parse(intent.updated_at)) {
    fail('PROJECTION_CORRUPTION', 'PolicyDecision challenge or chronology changed');
  }
  const bothQuoteFieldsNull = decision.accepted_index === null && decision.quote_id === null;
  const bothQuoteFieldsPresent = decision.accepted_index !== null && decision.quote_id !== null;
  if (!bothQuoteFieldsNull && !bothQuoteFieldsPresent) {
    fail('PROJECTION_CORRUPTION', 'PolicyDecision quote fields are partial');
  }
  if (bothQuoteFieldsNull) {
    if (decision.decision !== 'deny' || amount.value !== 0n) {
      fail('PROJECTION_CORRUPTION', 'spend-authorizing PolicyDecision has no selected quote');
    }
  } else {
    const acceptedIndex = safeInteger(
      decision.accepted_index,
      'PolicyDecision accepted index',
    );
    canonicalHash(decision.quote_id, 'PolicyDecision quote ID');
    if (decision.quote_id !== sha256(canonicalJson({
      challengeHash,
      acceptedIndex,
    }))) {
      fail('PROJECTION_CORRUPTION', 'PolicyDecision quote ID lost its canonical binding');
    }
    const selected = projection.accepts[acceptedIndex];
    const policy = sessionAuthority.policyVersion.policy;
    const seller = policy.sellers.find((candidate) => candidate.origin === intent.seller_origin);
    const amountValue = amount.value;
    const automatic = seller ? BigInt(seller.autoApproveAtomic) : 0n;
    const human = seller ? BigInt(seller.humanApproveAtomic) : 0n;
    const perRequest = seller ? BigInt(seller.perRequestMaxAtomic) : 0n;
    if (!selected
        || !seller
        || selected.amount !== amount.text
        || selected.network !== policy.network
        || selected.asset !== policy.asset
        || selected.payTo !== seller.payTo
        || projection.resource.urlHash !== intent.request_url_hash
        || !policy.methods.includes(intent.method)
        || !seller.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
        || (decision.decision === 'allow' && (decision.reason_code !== 'WITHIN_AUTO_LIMIT'
          || amountValue > automatic))
        || (decision.decision === 'approval_required'
          && (decision.reason_code !== 'HUMAN_APPROVAL_REQUIRED'
            || amountValue <= automatic || amountValue > human || amountValue > perRequest))) {
      fail('PROJECTION_CORRUPTION', 'PolicyDecision selected quote lost policy authority');
    }
    if (decision.decision !== 'deny' && amount.value === 0n) {
      fail('PROJECTION_CORRUPTION', 'spend-authorizing PolicyDecision has a zero ceiling');
    }
  }
  return Object.freeze({ decision, projection });
}

function validateOutcome(access, intent) {
  const rows = access.all(
    'SELECT * FROM buyer_outcomes WHERE intent_id = ? ORDER BY rowid',
    [intent.id],
  );
  if (rows.length > 1) fail('PROJECTION_CORRUPTION', 'BuyerOutcome is ambiguous');
  if (rows.length === 0) return null;
  const outcome = rows[0];
  const allowed = new Set([
    'completed', 'upstream_failed', 'payment_denied', 'payment_failed',
    'payment_unresolved', 'payment_rejected', 'execution_failed',
    'execution_unknown', 'refunded',
  ]);
  const revision = safeInteger(outcome.revision, 'BuyerOutcome revision');
  const recordedAt = persistedTimestamp(outcome.recorded_at, 'BuyerOutcome recordedAt');
  if (outcome.intent_id !== intent.id
      || !allowed.has(outcome.status)
      || revision < 1
      || Date.parse(recordedAt) < Date.parse(intent.created_at)) {
    fail('PROJECTION_CORRUPTION', 'BuyerOutcome is invalid or detached');
  }
  canonicalReason(outcome.reason_code, 'BuyerOutcome reason');
  return outcome;
}

function validateIntents(access, sessions) {
  const rows = access.all('SELECT * FROM spend_intents ORDER BY rowid');
  const byId = new Map();
  const states = new Set([
    'captured', 'challenged', 'approval_pending', 'authorized', 'reserved',
    'signing', 'signed', 'retrying', 'unresolved', 'terminal',
  ]);
  for (const intent of rows) {
    persistedToken(intent.id, 'Spend Intent ID');
    persistedToken(intent.request_id, 'Spend Intent request ID');
    persistedToken(intent.session_id, 'Spend Intent session ID');
    persistedToken(intent.route_id, 'Spend Intent route ID');
    persistedToken(intent.method, 'Spend Intent method');
    persistedToken(intent.purpose_label, 'Spend Intent purpose label');
    persistedToken(intent.correlation_id, 'Spend Intent correlation ID');
    persistedToken(intent.idempotency_key, 'Spend Intent idempotency key');
    const sessionAuthority = sessions.get(intent.session_id);
    if (!sessionAuthority
        || intent.wallet_address !== sessionAuthority.session.wallet_address
        || intent.enrollment_hash !== sessionAuthority.enrollmentHash) {
      fail('PROJECTION_CORRUPTION', 'Spend Intent wallet or session authority was rebound');
    }
    canonicalAddress(intent.wallet_address, 'Spend Intent wallet');
    canonicalHash(intent.enrollment_hash, 'Spend Intent enrollment hash');
    canonicalHash(intent.request_url_hash, 'Spend Intent request URL hash');
    canonicalHash(intent.body_hash, 'Spend Intent body hash');
    canonicalHash(intent.header_allowlist_hash, 'Spend Intent header allowlist hash');
    canonicalHash(intent.ordinary_fingerprint, 'Spend Intent ordinary fingerprint');
    canonicalHash(intent.intent_hash, 'Spend Intent hash');
    canonicalOrigin(intent.seller_origin, 'Spend Intent seller origin');
    if (typeof intent.resource_path !== 'string'
        || !intent.resource_path.startsWith('/')
        || /[\u0000-\u001f\u007f]/.test(intent.resource_path)
        || !states.has(intent.state)
        || safeInteger(intent.retry_matchable, 'Spend Intent retry flag') > 1) {
      fail('PROJECTION_CORRUPTION', 'Spend Intent persisted shape is invalid');
    }
    const createdAt = persistedTimestamp(intent.created_at, 'Spend Intent createdAt');
    const updatedAt = persistedTimestamp(intent.updated_at, 'Spend Intent updatedAt');
    if (Date.parse(createdAt) < Date.parse(sessionAuthority.session.created_at)
        || Date.parse(updatedAt) < Date.parse(createdAt)) {
      fail('PROJECTION_CORRUPTION', 'Spend Intent lifecycle time regressed');
    }
    const challengeFields = [
      intent.challenge_projection_json,
      intent.challenge_hash,
      intent.challenge_received_at,
    ];
    if (!challengeFields.every((value) => value === null)
        && !challengeFields.every((value) => value !== null)) {
      fail('PROJECTION_CORRUPTION', 'Spend Intent challenge fields are partial');
    }
    if (intent.challenge_hash !== null) canonicalHash(intent.challenge_hash, 'Spend Intent challenge hash');
    const { decision, projection } = validateDecision(access, intent, sessionAuthority);
    const outcome = validateOutcome(access, intent);
    byId.set(intent.id, Object.freeze({
      intent,
      sessionAuthority,
      decision,
      projection,
      outcome,
    }));
  }
  return byId;
}

function validateCanonicalPaymentPayload(row, authority) {
  const payment = exactRecord(
    parseCanonicalJson(row.payment_payload_json, 'PaymentAttempt payload'),
    ['x402Version', 'resource', 'accepted', 'payload'],
    [],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt payload',
  );
  const resource = exactRecord(
    payment.resource,
    ['url', 'description', 'mimeType'],
    [],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt resource',
  );
  const accepted = exactRecord(
    payment.accepted,
    ['scheme', 'network', 'asset', 'amount', 'payTo', 'maxTimeoutSeconds', 'extra'],
    [],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt accepted offer',
  );
  exactRecord(
    accepted.extra,
    ['name', 'version'],
    ['assetTransferMethod'],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt accepted extra',
  );
  const body = exactRecord(
    payment.payload,
    ['signature', 'authorization'],
    [],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt signed payload',
  );
  const authorization = exactRecord(
    body.authorization,
    ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'],
    [],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt EIP-3009 authorization',
  );
  let resourceUrl;
  try { resourceUrl = new URL(resource.url); } catch (error) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt resource URL is invalid', { cause: error });
  }
  const selected = authority.projection.accepts[row.accepted_index];
  if (payment.x402Version !== 2
      || resourceUrl.href !== resource.url
      || resourceUrl.origin !== authority.intent.seller_origin
      || resourceUrl.pathname !== authority.intent.resource_path
      || resourceUrl.username || resourceUrl.password || resourceUrl.hash
      || sha256(resource.url) !== authority.intent.request_url_hash
      || resource.description !== authority.projection.resource.description
      || resource.mimeType !== authority.projection.resource.mimeType
      || canonicalJson(accepted) !== canonicalJson(selected)
      || authorization.from !== authority.intent.wallet_address
      || authorization.to !== selected.payTo
      || authorization.value !== authority.decision.amount_ceiling_atomic
      || authorization.nonce !== row.nonce
      || authorization.validAfter !== row.valid_after
      || authorization.validBefore !== row.valid_before) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt payload binding changed');
  }

  const signature = body.signature;
  if (typeof signature !== 'string' || !ECDSA_SIGNATURE.test(signature)) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt signature is not canonical EOA bytes');
  }
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130), 16);
  if (r <= 0n || r >= SECP256K1_N || s <= 0n || s > SECP256K1_HALF_N
      || ![27, 28].includes(v)) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt signature is not canonical low-s EOA form');
  }

  let decoded;
  try { decoded = decodePaymentSignatureHeader(row.payment_header); } catch (error) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt header is not canonical x402', { cause: error });
  }
  if (canonicalJson(decoded) !== row.payment_payload_json
      || encodePaymentSignatureHeader(decoded) !== row.payment_header
      || Buffer.from(row.payment_header, 'ascii').toString('ascii') !== row.payment_header
      || sha256(Buffer.from(row.payment_header, 'ascii')) !== row.payment_hash) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt header lost its canonical payload binding');
  }
  return payment;
}

function validateAttemptEvents(access, row, authority) {
  const events = access.all(`SELECT entity_id, event_type, data_json FROM events
    WHERE entity_type = 'payment_attempt' AND (entity_id = ? OR entity_id = ?)
    ORDER BY sequence`, [row.id, row.intent_id]);
  const expected = [{
    entityId: row.id,
    eventType: 'payment.reserved',
    data: {
      intentId: row.intent_id,
      policyVersionId: authority.decision.policy_version_id,
      quoteId: row.quote_id,
      createdAt: row.created_at,
    },
  }];
  if (row.signing_claimed_at !== null) {
    expected.push({
      entityId: row.intent_id,
      eventType: 'payment.signing_claimed',
      data: {
        nonce: row.nonce,
        validAfter: row.valid_after,
        validBefore: row.valid_before,
        signingClaimedAt: row.signing_claimed_at,
      },
    });
  }
  if (row.signed_at !== null) {
    expected.push({
      entityId: row.intent_id,
      eventType: 'payment.signed',
      data: { paymentHash: row.payment_hash, signedAt: row.signed_at },
    });
  }
  if (row.retry_started_at !== null) {
    expected.push({
      entityId: row.intent_id,
      eventType: 'payment.retrying',
      data: { retryStartedAt: row.retry_started_at },
    });
  }
  const holdRows = access.all(`SELECT data_json FROM events
    WHERE entity_type = 'budget_reservation' AND entity_id = ?
      AND event_type = 'budget.held_unresolved' ORDER BY sequence`, [row.intent_id]);
  if (holdRows.length > 1) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt unresolved provenance is ambiguous');
  }
  const hold = holdRows.length === 1
    ? parseCanonicalJson(holdRows[0].data_json, 'budget unresolved event')
    : null;
  if (row.state === 'unresolved' || hold !== null) {
    expected.push({
      entityId: row.intent_id,
      eventType: 'payment.unresolved',
      data: {
        reasonCode: row.state === 'unresolved' ? row.reason_code : hold?.reasonCode,
        recordedAt: row.state === 'unresolved' ? row.updated_at : hold?.heldAt,
      },
    });
  }
  const actual = events.map((event) => ({
    entityId: event.entity_id,
    eventType: event.event_type,
    data: parseCanonicalJson(event.data_json, 'PaymentAttempt transition event'),
  }));
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt transition provenance changed');
  }
}

function validateSettlement(row, authority) {
  if (row.reason_code === 'TRUSTED_RECONCILIATION') {
    const proof = exactRecord(
      parseCanonicalJson(row.settlement_json, 'trusted payment settlement'),
      ['kind', 'transactionId', 'rpcProofHash', 'localAttemptHash'],
      [],
      'PROJECTION_CORRUPTION',
      'trusted payment settlement',
    );
    canonicalHash(proof.rpcProofHash, 'trusted settlement RPC proof hash');
    canonicalHash(proof.localAttemptHash, 'trusted settlement local attempt hash');
    if (proof.kind !== 'settled_transfer' || proof.transactionId !== row.transaction_id) {
      fail('PROJECTION_CORRUPTION', 'trusted payment settlement binding changed');
    }
    return proof;
  }
  const settlement = exactRecord(
    parseCanonicalJson(row.settlement_json, 'PaymentAttempt settlement'),
    ['source', 'headerHash', 'success', 'transaction', 'network', 'payer', 'paymentHash'],
    ['amountAtomic'],
    'PROJECTION_CORRUPTION',
    'PaymentAttempt settlement',
  );
  canonicalHash(settlement.headerHash, 'PaymentAttempt settlement header hash');
  const amountMatches = !Object.hasOwn(settlement, 'amountAtomic')
    || settlement.amountAtomic === authority.decision.amount_ceiling_atomic;
  if (settlement.source !== 'x402-payment-response'
      || settlement.success !== true
      || settlement.transaction !== row.transaction_id
      || settlement.network !== authority.projection.accepts[row.accepted_index].network
      || settlement.payer !== authority.intent.wallet_address
      || settlement.paymentHash !== row.payment_hash
      || !amountMatches) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt settlement binding changed');
  }
  return settlement;
}

function validateAttemptRow(access, row, authority) {
  persistedToken(row.id, 'PaymentAttempt ID');
  if (row.intent_id !== authority.intent.id
      || !['reserved', 'signing', 'signed', 'retrying', 'unresolved', 'settled', 'rejected']
        .includes(row.state)
      || row.payment_required_projection_json !== authority.intent.challenge_projection_json
      || safeInteger(row.accepted_index, 'PaymentAttempt accepted index')
        !== safeInteger(authority.decision.accepted_index, 'PolicyDecision accepted index')
      || row.quote_id !== authority.decision.quote_id) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt challenge authority was rebound');
  }
  persistedToken(row.quote_id, 'PaymentAttempt quote ID');
  parseCanonicalJson(row.payment_required_projection_json, 'PaymentAttempt challenge projection');
  const createdAt = persistedTimestamp(row.created_at, 'PaymentAttempt createdAt');
  const updatedAt = persistedTimestamp(row.updated_at, 'PaymentAttempt updatedAt');
  if (Date.parse(createdAt) < Date.parse(authority.decision.decided_at)
      || Date.parse(updatedAt) < Date.parse(createdAt)) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt chronology changed');
  }
  if (row.reason_code !== null) canonicalReason(row.reason_code, 'PaymentAttempt reason');

  const claimFields = [row.nonce, row.valid_after, row.valid_before, row.signing_claimed_at];
  const signedFields = [row.payment_payload_json, row.payment_header, row.payment_hash, row.signed_at];
  const settlementFields = [row.settlement_json, row.transaction_id, row.settled_at];
  const allOrNone = (fields) => fields.every((value) => value !== null)
    || fields.every((value) => value === null);
  if (!allOrNone(claimFields) || !allOrNone(signedFields) || !allOrNone(settlementFields)) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt durable authority fields are partial');
  }
  const hasClaim = claimFields[0] !== null;
  const hasSigned = signedFields[0] !== null;
  const hasSettlement = settlementFields[0] !== null;
  let signingClaimedAt = null;
  let signedAt = null;
  let retryStartedAt = null;
  let settledAt = null;
  if (hasClaim) {
    if (!/^0x[0-9a-f]{64}$/.test(row.nonce)) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt nonce is not canonical');
    }
    const validAfter = persistedAtomic(row.valid_after, 'PaymentAttempt validAfter');
    const validBefore = persistedAtomic(row.valid_before, 'PaymentAttempt validBefore');
    signingClaimedAt = persistedTimestamp(
      row.signing_claimed_at,
      'PaymentAttempt signing claimedAt',
    );
    if (validBefore.value <= validAfter.value
        || validAfter.text !== '0'
        || Date.parse(signingClaimedAt) < Date.parse(createdAt)
        || Date.parse(signingClaimedAt) > Date.parse(updatedAt)) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt signing claim is invalid');
    }
    const selected = authority.projection.accepts[row.accepted_index];
    const approval = access.one('SELECT expires_at FROM approvals WHERE intent_id = ?', [row.intent_id]);
    const expectedValidBefore = Math.min(
      Math.floor(Date.parse(signingClaimedAt) / 1_000) + selected.maxTimeoutSeconds,
      Math.floor((Date.parse(authority.intent.challenge_received_at)
        + authority.sessionAuthority.policyVersion.policy.challengeMaxAgeMs) / 1_000),
      approval === undefined
        ? Number.POSITIVE_INFINITY
        : Math.floor(Date.parse(approval.expires_at) / 1_000),
    );
    if (!Number.isSafeInteger(expectedValidBefore)
        || row.valid_before !== String(expectedValidBefore)) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt authorization window changed');
    }
  }
  if (hasSigned) {
    if (!hasClaim || typeof row.payment_header !== 'string' || row.payment_header.length === 0
        || Buffer.byteLength(row.payment_header, 'utf8') > 16_384) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt signed bytes are invalid');
    }
    canonicalHash(row.payment_hash, 'PaymentAttempt hash');
    signedAt = persistedTimestamp(row.signed_at, 'PaymentAttempt signedAt');
    if (sha256(row.payment_header) !== row.payment_hash
        || Date.parse(signedAt) < Date.parse(signingClaimedAt)
        || Date.parse(signedAt) > Date.parse(updatedAt)) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt signed bytes lost their binding');
    }
    validateCanonicalPaymentPayload(row, authority);
  }
  if (row.retry_started_at !== null) {
    retryStartedAt = persistedTimestamp(row.retry_started_at, 'PaymentAttempt retry startedAt');
    if (!hasSigned
        || Date.parse(retryStartedAt) < Date.parse(signedAt)
        || Date.parse(retryStartedAt) > Date.parse(updatedAt)) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt retry chronology is invalid');
    }
  }
  if (hasSettlement) {
    if (!hasSigned || retryStartedAt === null) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt settlement has no paid retry');
    }
    canonicalTransactionId(row.transaction_id, 'PaymentAttempt transaction');
    settledAt = persistedTimestamp(row.settled_at, 'PaymentAttempt settledAt');
    if (Date.parse(settledAt) < Date.parse(retryStartedAt)
        || settledAt !== updatedAt) {
      fail('PROJECTION_CORRUPTION', 'PaymentAttempt settlement chronology is invalid');
    }
    validateSettlement(row, authority);
  }
  const shapeIsLegal = {
    reserved: !hasClaim && !hasSigned && row.retry_started_at === null && !hasSettlement,
    signing: hasClaim && !hasSigned && row.retry_started_at === null && !hasSettlement,
    signed: hasClaim && hasSigned && row.retry_started_at === null && !hasSettlement,
    retrying: hasClaim && hasSigned && retryStartedAt !== null && !hasSettlement,
    unresolved: hasClaim && !hasSettlement,
    settled: hasClaim && hasSigned && retryStartedAt !== null && hasSettlement,
    rejected: !hasSettlement && row.reason_code !== null,
  }[row.state];
  const reasonIsLegal = (['reserved', 'signing', 'signed', 'retrying'].includes(row.state)
      && row.reason_code === null)
    || (['unresolved', 'rejected'].includes(row.state) && row.reason_code !== null)
    || (row.state === 'settled'
      && [null, 'TRUSTED_RECONCILIATION'].includes(row.reason_code));
  if (!shapeIsLegal || !reasonIsLegal) {
    fail('PROJECTION_CORRUPTION', 'PaymentAttempt state owns illegal fields');
  }
  validateAttemptEvents(access, row, authority);
  return row;
}

function validateExecutionRows(access, budget, authority, attempt) {
  const executionRows = access.all(
    'SELECT * FROM execution_outcomes WHERE intent_id = ? ORDER BY rowid',
    [budget.intent_id],
  );
  const resolutionRows = access.all(
    'SELECT * FROM execution_resolutions WHERE intent_id = ? ORDER BY rowid',
    [budget.intent_id],
  );
  if (executionRows.length > 1 || resolutionRows.length > 1) {
    fail('PROJECTION_CORRUPTION', 'execution authority is ambiguous');
  }
  const execution = executionRows[0] ?? null;
  const resolution = resolutionRows[0] ?? null;
  if (execution) {
    if (execution.intent_id !== budget.intent_id
        || !['succeeded', 'failed', 'unknown'].includes(execution.state)) {
      fail('PROJECTION_CORRUPTION', 'execution outcome is invalid');
    }
    const status = execution.http_status === null
      ? null
      : safeInteger(execution.http_status, 'execution HTTP status');
    if (status !== null && (status < 100 || status > 599)) {
      fail('PROJECTION_CORRUPTION', 'execution HTTP status is invalid');
    }
    if (execution.response_hash !== null) canonicalHash(execution.response_hash, 'execution response hash');
    parseCanonicalJson(execution.metadata_json, 'execution metadata');
    const recordedAt = persistedTimestamp(execution.recorded_at, 'execution recordedAt');
    if (attempt?.settled_at !== null
        && Date.parse(recordedAt) < Date.parse(attempt.settled_at)) {
      fail('PROJECTION_CORRUPTION', 'execution predates payment settlement');
    }
    if ((execution.state === 'succeeded'
        && (status === null || status < 200 || status > 299 || execution.response_hash === null))
        || (execution.state === 'failed' && (status === null || status < 300))
        || (execution.state === 'unknown'
          && status !== null && (status < 200 || status > 299))) {
      fail('PROJECTION_CORRUPTION', 'execution state, status, and response hash disagree');
    }
  }
  if (resolution) {
    if (!execution
        || resolution.intent_id !== budget.intent_id
        || !['refund_pending', 'reconciliation_required', 'resolved'].includes(resolution.state)) {
      fail('PROJECTION_CORRUPTION', 'execution resolution is detached');
    }
    canonicalReason(resolution.reason_code, 'execution resolution reason');
    const openedAt = persistedTimestamp(resolution.opened_at, 'execution resolution openedAt');
    const blocksWallet = safeInteger(resolution.blocks_wallet, 'execution resolution blocker');
    const executionRecordedAt = Date.parse(execution.recorded_at);
    if (blocksWallet > 1
        || (resolution.state === 'resolved') !== (resolution.resolved_at !== null)
        || (resolution.state === 'resolved' && blocksWallet !== 0)
        || (resolution.state !== 'resolved' && blocksWallet !== 1)
        || (resolution.state !== 'resolved' && Date.parse(openedAt) < executionRecordedAt)) {
      fail('PROJECTION_CORRUPTION', 'execution resolution state is inconsistent');
    }
    if (resolution.resolved_at !== null) {
      const resolvedAt = persistedTimestamp(
        resolution.resolved_at,
        'execution resolution resolvedAt',
      );
      if (Date.parse(resolvedAt) < Date.parse(openedAt)
          || Date.parse(resolvedAt) < executionRecordedAt) {
        fail('PROJECTION_CORRUPTION', 'execution resolution time regressed');
      }
    }
  }

  const refunds = access.all('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid', [budget.intent_id]);
  const activeRefunds = [];
  const confirmedRefunds = [];
  for (const refund of refunds) {
    persistedToken(refund.id, 'refund ID');
    if (!attempt
        || refund.intent_id !== budget.intent_id
        || refund.original_transaction_id !== attempt.transaction_id
        || refund.amount_atomic !== authority.decision.amount_ceiling_atomic
        || !['pending', 'unresolved', 'abandoned', 'confirmed', 'rejected'].includes(refund.state)) {
      fail('PROJECTION_CORRUPTION', 'refund authority was rebound');
    }
    canonicalTransactionId(refund.original_transaction_id, 'refund original transaction');
    persistedAtomic(refund.amount_atomic, 'refund amount');
    const createdAt = persistedTimestamp(refund.created_at, 'refund createdAt');
    const updatedAt = persistedTimestamp(refund.updated_at, 'refund updatedAt');
    if (Date.parse(createdAt) < Date.parse(attempt.settled_at)
        || Date.parse(updatedAt) < Date.parse(createdAt)) {
      fail('PROJECTION_CORRUPTION', 'refund chronology changed');
    }
    if (refund.evidence_json !== null) parseCanonicalJson(refund.evidence_json, 'refund evidence');
    if (refund.refund_transaction_id !== null) {
      canonicalTransactionId(refund.refund_transaction_id, 'refund transaction');
      if (refund.refund_transaction_id === refund.original_transaction_id) {
        fail('PROJECTION_CORRUPTION', 'refund reused the payment transaction');
      }
    }
    if (refund.state === 'confirmed'
        && (refund.refund_transaction_id === null || refund.evidence_json === null)) {
      fail('PROJECTION_CORRUPTION', 'confirmed refund has no exact evidence');
    }
    if (['pending', 'unresolved'].includes(refund.state)) activeRefunds.push(refund);
    if (refund.state === 'confirmed') confirmedRefunds.push(refund);
  }
  if (activeRefunds.length > 1 || confirmedRefunds.length > 1) {
    fail('PROJECTION_CORRUPTION', 'refund authority is ambiguous');
  }
  return Object.freeze({ execution, resolution, refunds, activeRefunds, confirmedRefunds });
}

function validatePaymentCandidates(access, budget, attempt) {
  const rows = access.all(
    'SELECT * FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid',
    [budget.intent_id],
  );
  let pendingCount = 0;
  for (const row of rows) {
    persistedToken(row.id, 'payment reconciliation candidate ID');
    if (row.intent_id !== budget.intent_id
        || !['pending', 'abandoned', 'rejected', 'confirmed'].includes(row.state)) {
      fail('PROJECTION_CORRUPTION', 'payment reconciliation candidate is detached');
    }
    canonicalTransactionId(row.transaction_id, 'payment reconciliation transaction');
    const createdAt = persistedTimestamp(row.created_at, 'payment candidate createdAt');
    const updatedAt = persistedTimestamp(row.updated_at, 'payment candidate updatedAt');
    if (Date.parse(createdAt) < Date.parse(attempt.created_at)
        || Date.parse(updatedAt) < Date.parse(createdAt)) {
      fail('PROJECTION_CORRUPTION', 'payment candidate chronology changed');
    }
    if (row.evidence_json !== null) parseCanonicalJson(row.evidence_json, 'payment candidate evidence');
    if (row.state === 'pending') pendingCount += 1;
  }
  if (pendingCount > 1 || (pendingCount === 1 && budget.state !== 'unresolved')) {
    fail('PROJECTION_CORRUPTION', 'pending payment reconciliation is not an unresolved hold');
  }
  return rows;
}

function validateDirectCommitEvent(access, budget, attempt, authority) {
  const rows = access.all(`SELECT data_json FROM events
    WHERE entity_type = 'budget_reservation' AND entity_id = ?
      AND event_type = 'budget.committed' ORDER BY sequence`, [budget.intent_id]);
  if (attempt.reason_code === 'TRUSTED_RECONCILIATION') {
    if (rows.length !== 0) {
      fail('PROJECTION_CORRUPTION', 'trusted reconciliation gained a direct commit event');
    }
    return;
  }
  if (rows.length !== 1) {
    fail('PROJECTION_CORRUPTION', 'direct payment commit event is missing or ambiguous');
  }
  const settlement = parseCanonicalJson(attempt.settlement_json, 'direct payment settlement');
  const event = exactRecord(
    parseCanonicalJson(rows[0].data_json, 'budget.committed event'),
    [
      'amountAtomic', 'transactionId', 'paymentHash', 'headerHash',
      'previousState', 'nextState', 'committedAt',
    ],
    [],
    'PROJECTION_CORRUPTION',
    'budget.committed event',
  );
  if (event.amountAtomic !== authority.decision.amount_ceiling_atomic
      || event.transactionId !== attempt.transaction_id
      || event.paymentHash !== attempt.payment_hash
      || event.headerHash !== settlement.headerHash
      || event.previousState !== 'reserved'
      || event.nextState !== 'committed'
      || event.committedAt !== attempt.settled_at) {
    fail('PROJECTION_CORRUPTION', 'direct payment commit proof binding changed');
  }
}

function validateBudgetRows(access, intents) {
  const rawRows = access.all('SELECT * FROM budget_reservations ORDER BY intent_id');
  const validated = [];
  for (const budget of rawRows) {
    persistedToken(budget.intent_id, 'BudgetReservation intent ID');
    persistedToken(budget.session_id, 'BudgetReservation session ID');
    const authority = intents.get(budget.intent_id);
    if (!authority
        || !authority.decision
        || !['allow', 'approval_required'].includes(authority.decision.decision)
        || budget.session_id !== authority.intent.session_id
        || budget.seller_origin !== authority.intent.seller_origin) {
      fail('PROJECTION_CORRUPTION', 'BudgetReservation historical authority was rebound');
    }
    canonicalOrigin(budget.seller_origin, 'BudgetReservation seller origin');
    const ceiling = persistedAtomic(
      authority.decision.amount_ceiling_atomic,
      'BudgetReservation PolicyDecision ceiling',
    );
    const amounts = {
      reserved: persistedAtomic(budget.reserved_atomic, 'BudgetReservation reserved amount'),
      committed: persistedAtomic(budget.committed_atomic, 'BudgetReservation committed amount'),
      released: persistedAtomic(budget.released_atomic, 'BudgetReservation released amount'),
      unresolved: persistedAtomic(budget.unresolved_atomic, 'BudgetReservation unresolved amount'),
    };
    if (ceiling.value <= 0n
        || Object.values(amounts).reduce((sum, amount) => sum + amount.value, 0n)
          !== ceiling.value
        || !Object.hasOwn(amounts, budget.state)
        || Object.entries(amounts).some(([state, amount]) => (
          amount.value !== (state === budget.state ? ceiling.value : 0n)
        ))) {
      fail('PROJECTION_CORRUPTION', 'BudgetReservation conservation or disposition changed');
    }
    const updatedAt = persistedTimestamp(budget.updated_at, 'BudgetReservation updatedAt');
    const committedAt = budget.committed_at === null
      ? null
      : persistedTimestamp(budget.committed_at, 'BudgetReservation committedAt');
    if (Date.parse(updatedAt) < Date.parse(authority.decision.decided_at)
        || (['reserved', 'unresolved'].includes(budget.state) && committedAt !== null)
        || (budget.state === 'committed' && committedAt === null)
        || (committedAt !== null && Date.parse(committedAt) > Date.parse(updatedAt))) {
      fail('PROJECTION_CORRUPTION', 'BudgetReservation chronology or state is invalid');
    }

    const attemptRows = access.all(
      'SELECT * FROM payment_attempts WHERE intent_id = ? ORDER BY rowid',
      [budget.intent_id],
    );
    if (attemptRows.length > 1
        || (budget.state !== 'released' && attemptRows.length !== 1)) {
      fail('PROJECTION_CORRUPTION', 'BudgetReservation has no exact PaymentAttempt');
    }
    const attempt = attemptRows.length === 0
      ? null
      : validateAttemptRow(access, attemptRows[0], authority);
    const candidates = attempt ? validatePaymentCandidates(access, budget, attempt) : [];
    const aftermath = validateExecutionRows(access, budget, authority, attempt);
    const { execution, resolution, activeRefunds, confirmedRefunds, refunds } = aftermath;

    if (budget.state === 'reserved') {
      if (!['reserved', 'signing', 'signed', 'retrying'].includes(attempt.state)
          || authority.intent.state !== attempt.state
          || execution || resolution || refunds.length > 0) {
        fail('PROJECTION_CORRUPTION', 'reserved budget owns illegal payment aftermath');
      }
    } else if (budget.state === 'unresolved') {
      if (authority.intent.state !== 'unresolved'
          || attempt.state !== 'unresolved'
          || attempt.updated_at !== budget.updated_at
          || authority.outcome?.status !== 'payment_unresolved'
          || authority.outcome.reason_code !== attempt.reason_code
          || execution || resolution || refunds.length > 0) {
        fail('PROJECTION_CORRUPTION', 'unresolved budget owns illegal payment aftermath');
      }
    } else if (budget.state === 'committed') {
      if (authority.intent.state !== 'terminal'
          || attempt.state !== 'settled'
          || attempt.settled_at !== committedAt
          || budget.updated_at !== committedAt
          || !execution
          || !authority.outcome) {
        fail('PROJECTION_CORRUPTION', 'committed budget has no settled PaymentAttempt');
      }
      validateDirectCommitEvent(access, budget, attempt, authority);
      if (execution.state === 'succeeded') {
        const reconciled = authority.outcome.reason_code === 'EXECUTION_RECONCILED_SUCCEEDED';
        const direct = ['PAYMENT_SETTLED', 'EXECUTION_SUCCEEDED']
          .includes(authority.outcome.reason_code);
        const exactReconciledResolution = reconciled
          && resolution?.state === 'resolved'
          && resolution.reason_code === 'EXECUTION_RECONCILED_SUCCEEDED'
          && resolution.resolved_at === execution.recorded_at;
        if (authority.outcome.status !== 'completed'
            || (!direct && !reconciled)
            || (direct && resolution !== null)
            || (reconciled && !exactReconciledResolution)
            || refunds.length > 0) {
          fail('PROJECTION_CORRUPTION', 'successful execution owns invalid resolution aftermath');
        }
      } else if (execution.state === 'failed'
          && (authority.outcome.status !== 'execution_failed'
            || !resolution
            || resolution.state !== 'refund_pending'
            || refunds.length !== 1
            || confirmedRefunds.length !== 0
            || (refunds[0].state === 'pending'
              && authority.outcome.reason_code !== resolution.reason_code)
            || (refunds[0].state !== 'pending'
              && (!['unresolved', 'abandoned', 'rejected'].includes(refunds[0].state)
                || authority.outcome.reason_code !== 'REFUND_UNRESOLVED')))) {
        fail('PROJECTION_CORRUPTION', 'failed execution has no exact pending refund');
      } else if (execution.state === 'unknown'
          && (authority.outcome.status !== 'execution_unknown'
            || !resolution
            || authority.outcome.reason_code !== resolution.reason_code
            || resolution.state !== 'reconciliation_required' || refunds.length !== 0)) {
        fail('PROJECTION_CORRUPTION', 'unknown execution has no exact reconciliation blocker');
      }
    } else {
      const refunded = committedAt !== null;
      if (!refunded) {
        if (authority.intent.state !== 'terminal'
            || !authority.outcome
            || !['payment_denied', 'payment_failed', 'payment_rejected']
              .includes(authority.outcome.status)
            || (attempt && attempt.state !== 'rejected')
            || (attempt && authority.outcome.reason_code !== attempt.reason_code)
            || (attempt && attempt.updated_at !== budget.updated_at)
            || execution || resolution || refunds.length > 0) {
          fail('PROJECTION_CORRUPTION', 'released unsigned budget owns paid aftermath');
        }
      } else if (authority.intent.state !== 'terminal'
          || authority.outcome?.status !== 'refunded'
          || authority.outcome.reason_code !== 'REFUND_CONFIRMED'
          || !attempt
          || attempt.state !== 'settled'
          || attempt.settled_at !== committedAt
          || execution?.state !== 'failed'
          || resolution?.state !== 'resolved'
          || resolution.resolved_at !== budget.updated_at
          || activeRefunds.length !== 0
          || confirmedRefunds.length !== 1
          || confirmedRefunds[0].updated_at !== budget.updated_at) {
        fail('PROJECTION_CORRUPTION', 'refunded budget has incomplete terminal authority');
      }
    }
    validated.push(Object.freeze({
      budget,
      authority,
      attempt,
      candidates,
      ...aftermath,
    }));
  }
  const reservationIds = new Set(validated.map(({ budget }) => budget.intent_id));
  for (const [table, label] of [
    ['payment_attempts', 'PaymentAttempt'],
    ['payment_reconciliation_candidates', 'payment reconciliation candidate'],
    ['execution_resolutions', 'execution resolution'],
    ['refunds', 'refund'],
  ]) {
    const orphans = access.all(`SELECT intent_id FROM ${table} ORDER BY rowid`)
      .filter((row) => !reservationIds.has(row.intent_id));
    if (orphans.length > 0) {
      fail('PROJECTION_CORRUPTION', `${label} has no BudgetReservation authority`);
    }
  }
  return validated;
}

function aggregateBudgetRows(rows, label) {
  const total = {
    reservedAtomic: 0n,
    committedAtomic: 0n,
    releasedAtomic: 0n,
    unresolvedAtomic: 0n,
  };
  for (const { budget } of rows) {
    for (const [output, column] of [
      ['reservedAtomic', 'reserved_atomic'],
      ['committedAtomic', 'committed_atomic'],
      ['releasedAtomic', 'released_atomic'],
      ['unresolvedAtomic', 'unresolved_atomic'],
    ]) total[output] += persistedAtomic(budget[column], `${label} ${output}`).value;
  }
  return frozenCopy({
    reservedAtomic: total.reservedAtomic.toString(),
    committedAtomic: total.committedAtomic.toString(),
    releasedAtomic: total.releasedAtomic.toString(),
    unresolvedAtomic: total.unresolvedAtomic.toString(),
    exposureAtomic: (
      total.reservedAtomic + total.committedAtomic + total.unresolvedAtomic
    ).toString(),
  });
}

function projectBudgets(rows, session) {
  const walletRows = rows.filter(({ authority }) => (
    authority.sessionAuthority.session.wallet_address === session.wallet_address
  ));
  return frozenCopy({
    session: aggregateBudgetRows(
      walletRows.filter(({ budget }) => budget.session_id === session.id),
      'session budget',
    ),
    wallet: aggregateBudgetRows(walletRows, 'wallet budget'),
  });
}

function exactApprovalEvent(row, eventType, expectedData) {
  if (!row || row.event_type !== eventType
      || canonicalJson(parseCanonicalJson(row.data_json, `${eventType} event`))
        !== canonicalJson(expectedData)) {
    fail('PROJECTION_CORRUPTION', `Approval ${eventType} provenance changed`);
  }
  const transitionAt = Object.values(expectedData).at(-1);
  const createdAt = persistedTimestamp(row.created_at, `${eventType} event createdAt`);
  if (typeof transitionAt !== 'string' || Date.parse(transitionAt) > Date.parse(createdAt)) {
    fail('PROJECTION_CORRUPTION', `Approval ${eventType} chronology changed`);
  }
  return transitionAt;
}

function validateApprovalEvents(access, row, authority) {
  const events = access.all(`SELECT event_type, data_json, created_at FROM events
    WHERE entity_type = 'approval' AND entity_id = ? ORDER BY sequence`, [row.id]);
  const persistedRequest = events[0]
    ? parseCanonicalJson(events[0].data_json, 'approval.requested event')
    : null;
  const requestedAt = persistedRequest?.requestedAt;
  const requestData = {
    intentId: row.intent_id,
    intentHash: row.intent_hash,
    challengeHash: row.challenge_hash,
    quoteId: row.quote_id,
    amountCeilingAtomic: row.amount_ceiling_atomic,
    walletAddress: row.wallet_address,
    policyVersionId: row.policy_version_id,
    acceptedIndex: Number(row.accepted_index),
    expiresAt: row.expires_at,
    requestedAt,
  };
  let lastAt = exactApprovalEvent(events[0], 'approval.requested', requestData);
  if (Date.parse(lastAt) < Date.parse(authority.decision.decided_at)
      || Date.parse(lastAt) >= Date.parse(row.expires_at)) {
    fail('PROJECTION_CORRUPTION', 'Approval request chronology changed');
  }
  let index = 1;
  let previousDecision = 'pending';
  const approve = (bindRowDecision) => {
    const persistedApproval = events[index]
      ? parseCanonicalJson(events[index].data_json, 'approval.approved event')
      : null;
    const expectedApprovedAt = bindRowDecision ? row.decided_at : persistedApproval?.approvedAt;
    const approvedAt = exactApprovalEvent(events[index], 'approval.approved', {
      intentId: row.intent_id,
      intentHash: row.intent_hash,
      operatorIdHash: row.operator_id_hash,
      approvedAt: expectedApprovedAt,
    });
    if (Date.parse(approvedAt) < Date.parse(lastAt)
        || Date.parse(approvedAt) >= Date.parse(row.expires_at)) {
      fail('PROJECTION_CORRUPTION', 'Approval approval chronology changed');
    }
    lastAt = approvedAt;
    previousDecision = 'approved';
    index += 1;
  };

  if (['approved', 'consumed'].includes(row.decision)) approve(true);
  if (row.decision === 'denied') {
    const deniedAt = exactApprovalEvent(events[index], 'approval.denied', {
      intentId: row.intent_id,
      intentHash: row.intent_hash,
      operatorIdHash: row.operator_id_hash,
      reasonCode: row.reason_code,
      deniedAt: row.decided_at,
    });
    if (Date.parse(deniedAt) < Date.parse(lastAt)
        || Date.parse(deniedAt) >= Date.parse(row.expires_at)) {
      fail('PROJECTION_CORRUPTION', 'Approval denial chronology changed');
    }
    lastAt = deniedAt;
    index += 1;
  } else if (row.decision === 'consumed') {
    const consumedAt = exactApprovalEvent(events[index], 'approval.consumed', {
      intentId: row.intent_id,
      intentHash: row.intent_hash,
      consumedAt: row.consumed_at,
    });
    if (Date.parse(consumedAt) < Date.parse(lastAt)
        || Date.parse(consumedAt) >= Date.parse(row.expires_at)) {
      fail('PROJECTION_CORRUPTION', 'Approval consumption chronology changed');
    }
    index += 1;
  } else if (['expired', 'cancelled'].includes(row.decision)) {
    const terminal = events.at(-1);
    const terminalData = terminal
      ? parseCanonicalJson(terminal.data_json, `approval.${row.decision} event`)
      : null;
    previousDecision = terminalData?.previousDecision;
    if (!['pending', 'approved'].includes(previousDecision)) {
      fail('PROJECTION_CORRUPTION', 'Approval terminal event has no legal predecessor');
    }
    if (previousDecision === 'approved') approve(false);
    const timeField = row.decision === 'expired' ? 'expiredAt' : 'cancelledAt';
    const terminalAt = exactApprovalEvent(events[index], `approval.${row.decision}`, {
      intentId: row.intent_id,
      intentHash: row.intent_hash,
      previousDecision,
      reasonCode: row.reason_code,
      [timeField]: row.decided_at,
    });
    if (Date.parse(terminalAt) < Date.parse(lastAt)
        || (row.decision === 'expired'
          && Date.parse(terminalAt) < Date.parse(row.expires_at))) {
      fail('PROJECTION_CORRUPTION', 'Approval terminal chronology changed');
    }
    index += 1;
  }
  if (events.length !== index) {
    fail('PROJECTION_CORRUPTION', 'Approval event lifecycle is missing, duplicated, or reordered');
  }
  if ((['expired', 'cancelled'].includes(row.decision)
      && previousDecision === 'pending' && row.operator_id_hash !== null)
      || (['expired', 'cancelled'].includes(row.decision)
        && previousDecision === 'approved' && row.operator_id_hash === null)) {
    fail('PROJECTION_CORRUPTION', 'Approval terminal event lost predecessor authority');
  }
}

function projectApprovals(access, intents, session) {
  const counts = Object.fromEntries(APPROVAL_STATES.map((state) => [state, 0]));
  const rows = access.all('SELECT * FROM approvals ORDER BY id');
  for (const row of rows) {
    persistedToken(row.id, 'Approval ID');
    const authority = intents.get(row.intent_id);
    if (!authority
        || !authority.decision
        || authority.decision.decision !== 'approval_required'
        || !Object.hasOwn(counts, row.decision)
        || row.intent_hash !== authority.intent.intent_hash
        || row.challenge_hash !== authority.decision.challenge_hash
        || row.quote_id !== authority.decision.quote_id
        || safeInteger(row.accepted_index, 'Approval accepted index')
          !== safeInteger(authority.decision.accepted_index, 'PolicyDecision accepted index')
        || row.amount_ceiling_atomic !== authority.decision.amount_ceiling_atomic
        || row.wallet_address !== authority.sessionAuthority.session.wallet_address
        || row.policy_version_id !== authority.sessionAuthority.policyVersion.row.id) {
      fail('PROJECTION_CORRUPTION', 'Approval authority was rebound');
    }
    canonicalHash(row.intent_hash, 'Approval intent hash');
    canonicalHash(row.challenge_hash, 'Approval challenge hash');
    canonicalHash(row.quote_id, 'Approval quote hash');
    canonicalAddress(row.wallet_address, 'Approval wallet');
    persistedAtomic(row.amount_ceiling_atomic, 'Approval amount ceiling');
    const expiresAt = persistedTimestamp(row.expires_at, 'Approval expiresAt');
    const decidedAt = row.decided_at === null
      ? null
      : persistedTimestamp(row.decided_at, 'Approval decidedAt');
    const consumedAt = row.consumed_at === null
      ? null
      : persistedTimestamp(row.consumed_at, 'Approval consumedAt');
    if (row.operator_id_hash !== null) canonicalHash(row.operator_id_hash, 'Approval operator hash');
    if (row.reason_code !== null) canonicalReason(row.reason_code, 'Approval reason');
    const policy = authority.sessionAuthority.policyVersion.policy;
    const expectedExpiresAt = new Date(Math.min(
      Date.parse(authority.intent.challenge_received_at) + policy.challengeMaxAgeMs,
      Date.parse(authority.decision.decided_at) + policy.approvalTtlMs,
    )).toISOString();
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
        && ['POLICY_SUPERSEDED', 'SESSION_CLOSED', 'APPROVAL_CHALLENGE_CHANGED']
          .includes(row.reason_code)
        && decidedAt !== null && consumedAt === null)
      || (row.decision === 'consumed'
        && row.operator_id_hash !== null && row.reason_code === null
        && decidedAt !== null && consumedAt !== null);
    if (expiresAt !== expectedExpiresAt
        || !lifecycleValid
        || (decidedAt !== null && Date.parse(decidedAt) < Date.parse(authority.decision.decided_at))
        || (['approved', 'denied'].includes(row.decision)
          && Date.parse(decidedAt) >= Date.parse(expiresAt))
        || (consumedAt !== null && (Date.parse(consumedAt) < Date.parse(decidedAt)
          || Date.parse(consumedAt) >= Date.parse(expiresAt)))) {
      fail('PROJECTION_CORRUPTION', 'Approval lifecycle is inconsistent');
    }
    validateApprovalEvents(access, row, authority);
    if (authority.intent.session_id === session.id) counts[row.decision] += 1;
  }
  return frozenCopy(counts);
}

function projectBlockers(rows, walletAddress) {
  const payment = new Map();
  const execution = new Map();
  const refund = new Map();
  for (const item of rows) {
    if (item.authority.sessionAuthority.session.wallet_address !== walletAddress) continue;
    const intentId = item.budget.intent_id;
    const hasPendingCandidate = item.candidates.some((candidate) => candidate.state === 'pending');
    if (item.budget.state === 'unresolved' || hasPendingCandidate) {
      const reason = item.attempt?.reason_code
        ?? item.authority.outcome?.reason_code
        ?? 'PAYMENT_UNRESOLVED';
      payment.set(intentId, canonicalReason(reason, 'payment blocker reason'));
    }
    if (item.resolution?.state !== 'resolved' && item.resolution?.blocks_wallet === 1n) {
      execution.set(
        intentId,
        canonicalReason(item.resolution.reason_code, 'execution blocker reason'),
      );
    }
    for (const active of item.activeRefunds) {
      refund.set(
        intentId,
        active.state === 'pending' ? 'REFUND_PENDING' : 'REFUND_UNRESOLVED',
      );
    }
  }
  const reasonCodes = (entries) => [...new Set(entries.values())].sort();
  const blockedIntents = new Set([...payment.keys(), ...execution.keys(), ...refund.keys()]);
  return frozenCopy({
    blockedIntentCount: blockedIntents.size,
    execution: { openCount: execution.size, reasonCodes: reasonCodes(execution) },
    payment: { openCount: payment.size, reasonCodes: reasonCodes(payment) },
    refund: { openCount: refund.size, reasonCodes: reasonCodes(refund) },
    walletBlocked: blockedIntents.size > 0,
  });
}

function projectIntents(intents, session) {
  const rows = [...intents.values()]
    .filter(({ intent }) => intent.session_id === session.id)
    .sort((left, right) => left.intent.created_at.localeCompare(right.intent.created_at)
      || left.intent.id.localeCompare(right.intent.id));
  return frozenCopy(rows.map(({ intent: row, outcome: persistedOutcome }) => {
    const outcome = persistedOutcome === null
      ? null
      : {
        status: persistedToken(persistedOutcome.status, 'BuyerOutcome status'),
        reasonCode: canonicalReason(persistedOutcome.reason_code, 'BuyerOutcome reason'),
        revision: safeInteger(persistedOutcome.revision, 'BuyerOutcome revision'),
      };
    return {
      intentHash: canonicalHash(row.intent_hash, 'Spend Intent hash'),
      requestIdHash: hashPrivateLabel(
        'wallet-kernel.request-identity.v1',
        'requestId',
        row.request_id,
      ),
      routeHash: hashPrivateLabel('wallet-kernel.route-identity.v1', 'routeId', row.route_id),
      method: persistedToken(row.method, 'Spend Intent method'),
      sellerOrigin: canonicalOrigin(row.seller_origin, 'Spend Intent seller origin'),
      requestUrlHash: canonicalHash(row.request_url_hash, 'Spend Intent request URL hash'),
      resourceHash: hashPrivateLabel(
        'wallet-kernel.resource-identity.v1',
        'resourcePath',
        row.resource_path,
      ),
      purposeHash: hashPrivateLabel(
        'wallet-kernel.purpose-identity.v1',
        'purposeLabel',
        row.purpose_label,
      ),
      correlationHash: hashPrivateLabel(
        'wallet-kernel.correlation-identity.v1',
        'correlationId',
        row.correlation_id,
      ),
      state: row.state,
      outcome,
      createdAt: persistedTimestamp(row.created_at, 'Spend Intent createdAt'),
      updatedAt: persistedTimestamp(row.updated_at, 'Spend Intent updatedAt'),
    };
  }));
}

function projectReceipts(access, receipts, session) {
  const rows = access.all(`SELECT signed_receipts.*
    FROM signed_receipts
    JOIN spend_intents ON spend_intents.id = signed_receipts.intent_id
    WHERE spend_intents.session_id = ?
    ORDER BY signed_receipts.intent_id, signed_receipts.revision`, [session.id]);
  const projected = rows.map((row) => {
    const revision = safeInteger(row.revision, 'signed receipt revision');
    if (revision < 1) fail('PROJECTION_CORRUPTION', 'signed receipt revision must be positive');
    const record = {
      id: persistedToken(row.id, 'signed receipt ID'),
      intentId: persistedToken(row.intent_id, 'signed receipt intent ID'),
      revision,
      receipt: parseCanonicalJson(row.receipt_json, 'signed receipt projection'),
      receiptHash: row.receipt_hash,
      signature: row.signature,
      algorithm: row.algorithm,
      keyId: row.key_id,
      supersedesReceiptHash: row.supersedes_receipt_hash,
      createdAt: persistedTimestamp(row.created_at, 'signed receipt createdAt'),
    };
    if (!receipts.verify(record)) {
      fail('RECEIPT_PARITY_REQUIRED', 'projection contains an invalid signed receipt');
    }
    return record;
  });
  return frozenCopy(projected);
}

function verifyEventChain(access) {
  const rows = access.all('SELECT * FROM events ORDER BY sequence');
  let previousHash = null;
  let expectedSequence = 1;
  let head = null;
  for (const row of rows) {
    try {
      const sequence = safeInteger(row.sequence, 'event sequence');
      const entityType = persistedToken(row.entity_type, 'event entity type');
      const entityId = persistedToken(row.entity_id, 'event entity ID');
      const eventType = persistedToken(row.event_type, 'event type');
      const data = parseCanonicalJson(row.data_json, 'event data');
      const createdAt = persistedTimestamp(row.created_at, 'event createdAt');
      const eventHash = canonicalHash(row.event_hash, 'event hash');
      if (!data || typeof data !== 'object' || Array.isArray(data)
          || sequence !== expectedSequence
          || row.previous_hash !== previousHash
          || eventHash !== sha256(canonicalJson({
            entityType,
            entityId,
            eventType,
            data,
            previousHash,
            createdAt,
          }))) {
        fail('PROJECTION_EVENT_CHAIN', 'authority event hash chain is invalid');
      }
      previousHash = eventHash;
      expectedSequence += 1;
      head = Object.freeze({ eventHash, createdAt });
    } catch (error) {
      if (error instanceof KernelError && error.code === 'PROJECTION_EVENT_CHAIN') throw error;
      fail('PROJECTION_EVENT_CHAIN', 'authority event hash chain is invalid', { cause: error });
    }
  }
  return head;
}

export function createProjectionExporter({ store, receipts, signer, now }) {
  validateStore(store);
  validateReceipts(receipts);
  const exportSigner = normalizeSigner(signer);
  if (typeof now !== 'function') throw new TypeError('projection exporter requires a clock');
  const budgetLedger = createBudgetLedger({ store, now });

  const snapshot = (input) => {
    const request = exactRecord(
      input,
      ['sessionId'],
      [],
      'PROJECTION_INPUT',
      'projection snapshot request',
    );
    const sessionId = canonicalToken(request.sessionId, 'projection Spend Session ID');
    return store.transaction((token) => {
      receipts.assertParityInTransaction(token);
      return store.within(token, ({ db }) => {
        const access = transactionAccess(db);
        const schemaVersion = safeInteger(
          access.one('SELECT user_version FROM pragma_user_version')?.user_version,
          'Wallet Kernel schema version',
        );
        if (schemaVersion !== 1) {
          fail('PROJECTION_CORRUPTION', 'Wallet Kernel schema version is unsupported');
        }
        const eventHead = verifyEventChain(access);
        const issuedAt = canonicalTimestamp(now(), 'projection issuedAt');
        if (eventHead && Date.parse(issuedAt) < Date.parse(eventHead.createdAt)) {
          fail('PROJECTION_TIME', 'projection issuedAt predates its authority event head');
        }

        const policyState = projectPolicies(access);
        const sessions = validateSessions(access, policyState);
        const target = sessions.get(sessionId);
        if (!target) fail('SESSION_UNKNOWN', 'Spend Session does not exist');
        const session = target.session;
        try {
          budgetLedger.snapshotInTransaction(token, {
            sessionId: session.id,
            sellerOrigin: target.policyVersion.policy.sellers[0].origin,
            at: issuedAt,
          });
        } catch (error) {
          if (error instanceof KernelError) {
            fail('PROJECTION_CORRUPTION', 'budget authority cannot be projected', { cause: error });
          }
          throw error;
        }
        const intents = validateIntents(access, sessions);
        const budgetRows = validateBudgetRows(access, intents);
        const enrollment = projectEnrollment(access, session, issuedAt, target);
        const projection = {
          schemaVersion: 1,
          domain: 'wallet-kernel.sanitized-projection.v1',
          authoritySchemaVersion: schemaVersion,
          sessionHash: hashPrivateLabel(
            'wallet-kernel.session-identity.v1',
            'sessionId',
            session.id,
          ),
          sessionState: session.state,
          wallet: {
            address: session.wallet_address,
            adapterHash: sha256(canonicalJson({
              domain: 'wallet-kernel.adapter-identity.v1',
              adapterId: session.adapter_id,
            })),
          },
          agentEnrollment: enrollment.agentEnrollment,
          isolation: enrollment.isolation,
          policies: {
            activePolicyHash: policyState.active.hash,
            sessionPolicyHash: target.policyVersion.hash,
            historyHashes: policyState.historyHashes,
          },
          budgets: projectBudgets(budgetRows, session),
          approvals: projectApprovals(access, intents, session),
          blockers: projectBlockers(budgetRows, session.wallet_address),
          intents: projectIntents(intents, session),
          signedReceipts: projectReceipts(access, receipts, session),
          eventHeadHash: eventHead?.eventHash ?? null,
          issuedAt,
        };
        assertSanitized(projection);
        return frozenCopy(projection);
      });
    });
  };

  const exportSigned = (input) => {
    const projection = snapshot(input);
    const unsigned = {
      schemaVersion: 1,
      domain: 'wallet-kernel.projection-export.v1',
      projection,
      algorithm: exportSigner.algorithm,
      keyId: exportSigner.keyId,
      publicKeyPem: exportSigner.publicKeyPem,
    };
    const projectionHash = sha256(canonicalJson(unsigned));
    const hashHex = projectionHash.slice('sha256:'.length);
    const signature = exportSigner.signHash(hashHex);
    let signatureBytes;
    try { signatureBytes = Buffer.from(signature, 'base64'); } catch {
      fail('PROJECTION_SIGNATURE', 'projection signer returned an invalid signature');
    }
    if (typeof signature !== 'string'
        || signatureBytes.length !== 64
        || signatureBytes.toString('base64') !== signature
        || !crypto.verify(
          null,
          Buffer.from(hashHex, 'hex'),
          exportSigner.publicKey,
          signatureBytes,
        )) {
      fail('PROJECTION_SIGNATURE', 'projection signer returned an invalid signature');
    }
    const bundle = {
      ...unsigned,
      projectionHash,
      signature,
    };
    assertSanitized(bundle);
    return frozenCopy(bundle);
  };

  return Object.freeze({ snapshot, exportSigned });
}

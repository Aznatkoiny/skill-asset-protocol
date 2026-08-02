import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';
import {
  validatePolicyDocument,
  validatePolicyEvaluation,
  validateChallengeProjection,
} from './policy-engine.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;

function fail(code, message) {
  throw new KernelError(code, message);
}

function canonicalHash(value, label, code = 'POLICY_CORRUPTION') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function rowToPolicyVersion(row) {
  if (!row) return null;
  let parsed;
  try {
    parsed = JSON.parse(row.canonical_json);
  } catch {
    return fail('POLICY_CORRUPTION', 'persisted policy JSON is invalid');
  }
  const policy = validatePolicyDocument(parsed);
  const canonical = canonicalJson(policy);
  const hash = sha256(canonical);
  if (canonical !== row.canonical_json || hash !== row.policy_hash) {
    fail('POLICY_CORRUPTION', 'persisted policy bytes or hash changed');
  }
  const schemaVersion = Number(row.schema_version);
  if (schemaVersion !== policy.schemaVersion) {
    fail('POLICY_CORRUPTION', 'persisted policy schema version changed');
  }
  if (row.predecessor_hash !== null) {
    canonicalHash(row.predecessor_hash, 'policy predecessor hash');
  }
  return frozenCopy({
    id: canonicalToken(row.id, 'policy version ID'),
    schemaVersion,
    policy,
    canonicalJson: canonical,
    hash,
    predecessorHash: row.predecessor_hash,
    appliedAt: canonicalTimestamp(row.applied_at, 'policy appliedAt'),
  });
}

function rowToDecision(row) {
  if (!row) return null;
  return Object.freeze({
    intentId: row.intent_id,
    policyVersionId: row.policy_version_id,
    decision: row.decision,
    reasonCode: row.reason_code,
    challengeHash: row.challenge_hash,
    acceptedIndex: row.accepted_index === null ? null : Number(row.accepted_index),
    quoteId: row.quote_id,
    amountCeilingAtomic: row.amount_ceiling_atomic,
    decidedAt: row.decided_at,
  });
}

function sameDecision(left, right) {
  const semantic = (value) => ({
    intentId: value.intentId,
    policyVersionId: value.policyVersionId,
    decision: value.decision,
    reasonCode: value.reasonCode,
    challengeHash: value.challengeHash,
    acceptedIndex: value.acceptedIndex,
    quoteId: value.quoteId,
    amountCeilingAtomic: value.amountCeilingAtomic,
  });
  return canonicalJson(semantic(left)) === canonicalJson(semantic(right));
}

function parsePersistedProjection(bytes) {
  if (typeof bytes !== 'string') {
    fail('POLICY_DECISION_CORRUPTION', 'SpendIntent challenge projection is missing');
  }
  let parsed;
  try {
    parsed = JSON.parse(bytes);
  } catch {
    fail('POLICY_DECISION_CORRUPTION', 'SpendIntent challenge projection is invalid JSON');
  }
  let projection;
  try {
    projection = validateChallengeProjection(parsed);
  } catch (error) {
    if (error instanceof KernelError) {
      fail('POLICY_DECISION_CORRUPTION', 'SpendIntent challenge projection is invalid');
    }
    throw error;
  }
  if (canonicalJson(projection) !== bytes) {
    fail('POLICY_DECISION_CORRUPTION', 'SpendIntent challenge projection is not canonical');
  }
  return projection;
}

function candidateStages(policy, seller, accepts) {
  const scheme = accepts.filter((candidate) => candidate.scheme === 'exact'
    && (!Object.hasOwn(candidate.extra, 'assetTransferMethod')
      || candidate.extra.assetTransferMethod === 'eip3009'));
  const network = scheme.filter((candidate) => candidate.network === policy.network);
  const asset = network.filter((candidate) => candidate.asset === policy.asset
    && candidate.extra.name === 'USDC'
    && candidate.extra.version === '2');
  const payee = seller
    ? asset.filter((candidate) => candidate.payTo === seller.payTo)
    : [];
  return { scheme, network, asset, payee };
}

function persistedPreselectionReason({ policy, projection, intent }) {
  const seller = policy.sellers.find((entry) => entry.origin === intent.seller_origin) ?? null;
  const stages = candidateStages(policy, seller, projection.accepts);
  if (projection.x402Version !== 2) return { reasonCode: 'X402_VERSION', seller, stages };
  if (stages.scheme.length === 0) {
    return { reasonCode: 'SCHEME_UNSUPPORTED', seller, stages };
  }
  if (stages.network.length === 0) return { reasonCode: 'NETWORK_MISMATCH', seller, stages };
  if (stages.asset.length === 0) return { reasonCode: 'ASSET_MISMATCH', seller, stages };
  if (intent.wallet_address !== policy.wallet || intent.session_wallet_address !== policy.wallet) {
    return { reasonCode: 'WALLET_MISMATCH', seller, stages };
  }
  if (!policy.methods.includes(intent.method)) {
    return { reasonCode: 'METHOD_UNSUPPORTED', seller, stages };
  }
  if (!seller) return { reasonCode: 'SELLER_UNTRUSTED', seller, stages };
  if (!seller.pathPrefixes.some((prefix) => intent.resource_path.startsWith(prefix))
      || projection.resource.urlHash !== intent.request_url_hash) {
    return { reasonCode: 'RESOURCE_PATH', seller, stages };
  }
  if (stages.payee.length === 0) return { reasonCode: 'PAYEE_MISMATCH', seller, stages };
  if (stages.payee.length > 1) {
    return { reasonCode: 'PAYMENT_OPTIONS_AMBIGUOUS', seller, stages };
  }
  return { reasonCode: null, seller, stages };
}

function preselectionReasonIsReproducible(evaluationReason, staticResult, projection) {
  if (evaluationReason === staticResult.reasonCode) return true;
  if (evaluationReason === 'NETWORK_MISMATCH') {
    return projection.x402Version === 2 && staticResult.stages.scheme.length > 0;
  }
  if (evaluationReason === 'WALLET_MISMATCH') {
    return projection.x402Version === 2
      && staticResult.stages.scheme.length > 0
      && staticResult.stages.network.length > 0
      && staticResult.stages.asset.length > 0;
  }
  return false;
}

function assertPersistedEvaluationBinding({
  policyVersion,
  intent,
  projection,
  evaluation,
  decidedAt,
}) {
  const projectionHash = sha256(canonicalJson(projection));
  if (projectionHash !== intent.challenge_hash
      || projectionHash !== evaluation.challengeHash) {
    fail('POLICY_DECISION_CORRUPTION', 'challenge projection hash binding changed');
  }
  const receivedAt = canonicalTimestamp(
    intent.challenge_received_at,
    'SpendIntent challenge receivedAt',
  );
  const elapsed = Date.parse(decidedAt) - Date.parse(receivedAt);
  if (elapsed < 0) {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision predates its challenge');
  }

  const staticResult = persistedPreselectionReason({
    policy: policyVersion.policy,
    projection,
    intent,
  });
  if (evaluation.acceptedIndex === null) {
    if (evaluation.decision !== 'deny'
        || !preselectionReasonIsReproducible(
          evaluation.reasonCode,
          staticResult,
          projection,
        )) {
      fail('POLICY_DECISION_CORRUPTION', 'preselection PolicyDecision is not reproducible');
    }
    return;
  }
  if (staticResult.reasonCode !== null) {
    fail('POLICY_DECISION_CORRUPTION', 'selected PolicyDecision bypasses a static denial');
  }

  const selected = staticResult.stages.payee[0];
  const selectedIndex = projection.accepts.indexOf(selected);
  if (selectedIndex !== evaluation.acceptedIndex
      || selected?.amount !== evaluation.amountCeilingAtomic) {
    fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision selected candidate binding changed');
  }
  const amount = BigInt(selected.amount);
  const automatic = BigInt(staticResult.seller.autoApproveAtomic);
  const human = BigInt(staticResult.seller.humanApproveAtomic);
  const perRequest = BigInt(staticResult.seller.perRequestMaxAtomic);
  const expired = elapsed > policyVersion.policy.challengeMaxAgeMs;

  if (evaluation.decision === 'allow') {
    if (expired || evaluation.reasonCode !== 'WITHIN_AUTO_LIMIT' || amount > automatic) {
      fail('POLICY_DECISION_CORRUPTION', 'automatic PolicyDecision exceeds static authority');
    }
    return;
  }
  if (evaluation.decision === 'approval_required') {
    if (expired
        || evaluation.reasonCode !== 'HUMAN_APPROVAL_REQUIRED'
        || amount <= automatic
        || amount > human
        || amount > perRequest) {
      fail('POLICY_DECISION_CORRUPTION', 'approval PolicyDecision exceeds static authority');
    }
    return;
  }
  if (evaluation.reasonCode === 'CHALLENGE_EXPIRED') {
    if (!expired) fail('POLICY_DECISION_CORRUPTION', 'challenge-expired denial is premature');
    return;
  }
  if (expired) {
    fail('POLICY_DECISION_CORRUPTION', 'expired challenge has the wrong denial reason');
  }
  if (evaluation.reasonCode === 'PER_REQUEST_LIMIT') {
    if (amount <= human && amount <= perRequest) {
      fail('POLICY_DECISION_CORRUPTION', 'per-request denial is below its static limit');
    }
    return;
  }
  if (amount > human || amount > perRequest) {
    fail('POLICY_DECISION_CORRUPTION', 'selected denial bypasses per-request precedence');
  }
  if (evaluation.reasonCode === 'APPROVAL_CAPACITY' && amount <= automatic) {
    fail('POLICY_DECISION_CORRUPTION', 'approval-capacity denial needs human approval');
  }
}

export function createPolicyRepository(store) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('policy repository requires a Wallet Kernel store');
  }

  const loadById = (database, id) => rowToPolicyVersion(database.prepare(
    'SELECT * FROM policy_versions WHERE id = ?',
  ).get(id));

  const loadActive = (database) => {
    const activeId = database.prepare(
      'SELECT value FROM metadata WHERE key = ?',
    ).get('active_policy_id')?.value;
    if (activeId === undefined) {
      const count = database.prepare('SELECT COUNT(*) AS count FROM policy_versions').get().count;
      if (BigInt(count) !== 0n) {
        fail('POLICY_CORRUPTION', 'policy history exists without an active version');
      }
      return null;
    }
    const active = loadById(database, activeId);
    if (!active) fail('POLICY_CORRUPTION', 'active policy metadata points to no version');
    return active;
  };

  const apply = (document, appliedAt) => {
    const policy = validatePolicyDocument(document);
    const canonical = canonicalJson(policy);
    const hash = sha256(canonical);
    const timestamp = canonicalTimestamp(appliedAt, 'policy appliedAt');

    return store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
      const current = loadActive(db);
      const liveSessions = db.prepare(`SELECT id, wallet_address, state
        FROM spend_sessions
        WHERE state IN ('open', 'policy_blocked')
        ORDER BY id`).all();
      if (liveSessions.some((session) => session.wallet_address !== policy.wallet)) {
        fail(
          'POLICY_WALLET_MISMATCH',
          'new policy wallet differs from a live Spend Session wallet',
        );
      }
      if (current?.hash === hash) {
        return frozenCopy({
          policyVersion: current,
          blockedSessionIds: [],
          idempotent: true,
        });
      }
      if (db.prepare('SELECT id FROM policy_versions WHERE policy_hash = ?').get(hash)) {
        fail(
          'POLICY_VERSION_REUSE',
          'an inactive immutable policy hash cannot be inserted or silently reactivated',
        );
      }

      const count = BigInt(db.prepare(
        'SELECT COUNT(*) AS count FROM policy_versions',
      ).get().count);
      if (count >= BigInt(Number.MAX_SAFE_INTEGER)) {
        fail('POLICY_CORRUPTION', 'policy version sequence exceeded its safe boundary');
      }
      const id = `policy-${Number(count) + 1}`;
      const predecessorHash = current?.hash ?? null;
      db.prepare(`INSERT INTO policy_versions
        (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(id, policy.schemaVersion, canonical, hash, predecessorHash, timestamp);
      db.prepare(`INSERT INTO metadata(key, value) VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value`)
        .run('active_policy_id', id);

      const blockedSessionIds = liveSessions
        .filter((session) => session.state === 'open')
        .map((session) => session.id);
      for (const sessionId of blockedSessionIds) {
        const result = db.prepare(`UPDATE spend_sessions
          SET state = 'policy_blocked'
          WHERE id = ? AND state = 'open'`).run(sessionId);
        if (result.changes !== 1n) {
          fail('POLICY_CORRUPTION', 'open Spend Session changed during policy apply');
        }
      }

      appendEvent({
        entityType: 'policy',
        entityId: id,
        eventType: 'policy.applied',
        data: {
          policyHash: hash,
          predecessorHash,
          blockedSessionIds,
        },
      });
      for (const sessionId of blockedSessionIds) {
        appendEvent({
          entityType: 'spend_session',
          entityId: sessionId,
          eventType: 'session.policy_blocked',
          data: {
            previousPolicyVersionId: current?.id ?? null,
            targetPolicyVersionId: id,
          },
        });
      }

      const policyVersion = loadById(db, id);
      return frozenCopy({
        policyVersion,
        blockedSessionIds,
        idempotent: false,
      });
    }));
  };

  const active = () => {
    const activeId = store.getMetadata('active_policy_id');
    if (activeId === null) {
      const rows = store.readAll('SELECT id FROM policy_versions');
      if (rows.length !== 0) {
        fail('POLICY_CORRUPTION', 'policy history exists without an active version');
      }
      return null;
    }
    const policyVersion = rowToPolicyVersion(store.readOne(
      'SELECT * FROM policy_versions WHERE id = ?',
      [activeId],
    ));
    if (!policyVersion) fail('POLICY_CORRUPTION', 'active policy version is missing');
    return policyVersion;
  };

  const history = () => Object.freeze(store.readAll(
    'SELECT * FROM policy_versions ORDER BY rowid',
  ).map(rowToPolicyVersion));

  const get = (id) => rowToPolicyVersion(store.readOne(
    'SELECT * FROM policy_versions WHERE id = ?',
    [canonicalToken(id, 'policy version ID')],
  ));

  const recordDecisionInTransaction = (token, input) => store.within(
    token,
    ({ db, appendEvent }) => {
      const record = exactRecord(input, [
        'intentId',
        'policyVersionId',
        'evaluation',
        'decidedAt',
      ], [], 'POLICY_DECISION_SCHEMA', 'policy decision write');
      const intentId = canonicalToken(record.intentId, 'decision intent ID');
      const policyVersionId = canonicalToken(
        record.policyVersionId,
        'decision policy version ID',
      );
      const decidedAt = canonicalTimestamp(record.decidedAt, 'decision decidedAt');
      const existing = rowToDecision(db.prepare(
        'SELECT * FROM policy_decisions WHERE intent_id = ?',
      ).get(intentId));
      let evaluation;
      try {
        evaluation = validatePolicyEvaluation(record.evaluation);
      } catch (error) {
        if (existing) {
          fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision replay is not a valid result');
        }
        throw error;
      }
      if (existing && existing.policyVersionId !== policyVersionId) {
        fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision replay changed PolicyVersion');
      }
      const policyVersion = loadById(db, policyVersionId);
      if (!policyVersion) fail('POLICY_DECISION_MISSING', 'PolicyVersion does not exist');
      const intent = db.prepare(`SELECT spend_intents.method,
          spend_intents.request_url_hash,
          spend_intents.seller_origin,
          spend_intents.resource_path,
          spend_intents.wallet_address,
          spend_intents.challenge_projection_json,
          spend_intents.challenge_hash,
          spend_intents.challenge_received_at,
          spend_sessions.wallet_address AS session_wallet_address,
          spend_sessions.policy_version_id AS session_policy_version_id
        FROM spend_intents
        JOIN spend_sessions ON spend_sessions.id = spend_intents.session_id
        WHERE spend_intents.id = ?`).get(intentId);
      if (!intent) fail('POLICY_DECISION_MISSING', 'SpendIntent does not exist');
      if (intent.session_policy_version_id !== policyVersionId) {
        fail('POLICY_DECISION_CORRUPTION', 'SpendIntent session policy binding changed');
      }
      if (evaluation.policyHash !== policyVersion.hash) {
        fail('POLICY_HASH_MISMATCH', 'evaluation policy hash does not match PolicyVersion');
      }
      if (intent.challenge_hash !== evaluation.challengeHash) {
        fail('POLICY_CHALLENGE_MISMATCH', 'evaluation challenge hash does not match SpendIntent');
      }

      const projection = parsePersistedProjection(intent.challenge_projection_json);

      const expected = Object.freeze({
        intentId,
        policyVersionId,
        decision: evaluation.decision,
        reasonCode: evaluation.reasonCode,
        challengeHash: evaluation.challengeHash,
        acceptedIndex: evaluation.acceptedIndex,
        quoteId: evaluation.quoteId,
        amountCeilingAtomic: evaluation.amountCeilingAtomic,
        decidedAt,
      });
      if (existing) {
        if (!sameDecision(existing, expected)) {
          fail('POLICY_DECISION_CORRUPTION', 'PolicyDecision replay differs from persisted row');
        }
        assertPersistedEvaluationBinding({
          policyVersion,
          intent,
          projection,
          evaluation,
          decidedAt: existing.decidedAt,
        });
        return existing;
      }

      assertPersistedEvaluationBinding({
        policyVersion,
        intent,
        projection,
        evaluation,
        decidedAt,
      });

      db.prepare(`INSERT INTO policy_decisions
        (intent_id, policy_version_id, decision, reason_code, challenge_hash,
         accepted_index, quote_id, amount_ceiling_atomic, decided_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(
          intentId,
          policyVersionId,
          evaluation.decision,
          evaluation.reasonCode,
          evaluation.challengeHash,
          evaluation.acceptedIndex,
          evaluation.quoteId,
          evaluation.amountCeilingAtomic,
          decidedAt,
        );
      appendEvent({
        entityType: 'spend_intent',
        entityId: intentId,
        eventType: 'policy.decision_recorded',
        data: {
          policyVersionId,
          decision: evaluation.decision,
          reasonCode: evaluation.reasonCode,
          challengeHash: evaluation.challengeHash,
          acceptedIndex: evaluation.acceptedIndex,
          quoteId: evaluation.quoteId,
          amountCeilingAtomic: evaluation.amountCeilingAtomic,
          decidedAt,
        },
      });
      return expected;
    },
  );

  return Object.freeze({
    apply,
    active,
    history,
    get,
    recordDecisionInTransaction,
  });
}

import { canonicalJson, sha256, KernelError } from '../kernel/canonical.mjs';

export function bindingRows(store, intents, enrollment) {
  return store.readAll(`SELECT * FROM agent_session_bindings
    WHERE agent_instance_id = ? AND enrollment_hash = ? AND state = 'open'
    ORDER BY id`, [enrollment.agentInstanceId, enrollment.enrollmentHash]).map((row) => (
    Object.freeze({
      bindingId: row.id,
      agentInstanceId: row.agent_instance_id,
      credentialDigest: row.credential_digest,
      enrollmentHash: row.enrollment_hash,
      state: row.state,
      session: intents.getSession(row.session_id),
    })
  ));
}

function sessionRows(store, intents) {
  return store.readAll('SELECT id FROM spend_sessions ORDER BY created_at, id')
    .map((row) => intents.getSession(row.id));
}

function publicPolicy(version, activeId) {
  return Object.freeze({
    versionId: version.id,
    policy: version.policy,
    policyHash: version.hash,
    predecessorHash: version.predecessorHash,
    createdAt: version.appliedAt,
    active: version.id === activeId,
  });
}

function publicApproval(record) {
  return Object.freeze({
    approvalId: record.approvalId,
    intentId: record.intentId,
    decision: record.decision,
    intentHash: record.intentHash,
    challengeHash: record.challengeHash,
    quoteId: record.quoteId,
    acceptedIndex: record.acceptedIndex,
    amountAtomic: record.amountCeilingAtomic,
    walletAddress: record.walletAddress,
    policyVersionId: record.policyVersionId,
    expiresAt: record.expiresAt,
    reasonCode: record.reasonCode,
    recordedAt: record.decidedAt,
  });
}

function allReceipts(store, receipts) {
  const result = [];
  for (const row of store.readAll('SELECT DISTINCT intent_id FROM signed_receipts ORDER BY intent_id')) {
    const current = receipts.latest(row.intent_id);
    if (current) result.push(current);
  }
  return Object.freeze(result);
}

function normalizedEvents(store) {
  return Object.freeze(store.events().map((row) => {
    let data = {};
    try { data = JSON.parse(row.data_json); } catch {}
    const amountAtomic = [
      data.amountAtomic, data.amountCeilingAtomic, data.reservedAtomic,
      data.committedAtomic, data.releasedAtomic,
    ].find((value) => typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value)) ?? null;
    const transactionId = [
      data.transactionId, data.paymentTransactionId, data.refundTransactionId,
    ].find((value) => typeof value === 'string' && /^0x[0-9a-f]{64}$/u.test(value)) ?? null;
    return Object.freeze({
      id: String(row.sequence),
      kind: row.event_type,
      hash: sha256(canonicalJson({
        domain: 'wallet-kernel.normalized-entity.v1',
        entityType: row.entity_type,
        entityId: row.entity_id,
      })),
      decision: typeof data.decision === 'string' ? data.decision : null,
      amountAtomic,
      transactionId,
      receiptHash: typeof data.receiptHash === 'string' ? data.receiptHash : null,
      eventHash: row.event_hash,
      previousEventHash: row.previous_hash,
      createdAt: row.created_at,
    });
  }));
}

function persistedNumber(value, label) {
  const number = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw new KernelError('RUNTIME_AUTHORITY', `${label} is invalid`);
  }
  return number;
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
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
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
      httpStatus: execution.http_status === null
        ? null
        : persistedNumber(execution.http_status, 'execution HTTP status'),
      responseHash: execution.response_hash,
      metadataHash: sha256(execution.metadata_json),
      recordedAt: execution.recorded_at,
    },
    resolution: {
      state: resolution.state,
      reasonCode: resolution.reason_code,
      openedAt: resolution.opened_at,
    },
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
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
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
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

function reconciliationCases(store) {
  const result = [];
  const intents = store.readAll('SELECT * FROM spend_intents ORDER BY created_at, id');
  for (const intent of intents) {
    const attempt = store.readOne('SELECT * FROM payment_attempts WHERE intent_id = ?', [intent.id]);
    const budget = store.readOne('SELECT * FROM budget_reservations WHERE intent_id = ?', [intent.id]);
    const outcome = store.readOne('SELECT * FROM buyer_outcomes WHERE intent_id = ?', [intent.id]);
    if (!attempt || !budget || !outcome) continue;
    const authority = Object.freeze({ intent, attempt, budget, outcome });
    if (intent.state === 'unresolved' && attempt.state === 'unresolved'
        && budget.state === 'unresolved' && outcome.status === 'payment_unresolved') {
      const candidates = store.readAll(
        'SELECT * FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid',
        [intent.id],
      );
      result.push(Object.freeze({
        kind: 'payment',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: paymentCaseHash(authority, candidates),
        paymentTransactionId: candidates.find((row) => row.state === 'pending')?.transaction_id ?? null,
      }));
      continue;
    }
    const execution = store.readOne('SELECT * FROM execution_outcomes WHERE intent_id = ?', [intent.id]);
    const resolution = store.readOne(
      'SELECT * FROM execution_resolutions WHERE intent_id = ?',
      [intent.id],
    );
    if (!execution || !resolution) continue;
    if (outcome.status === 'execution_unknown' && execution.state === 'unknown'
        && resolution.state === 'reconciliation_required') {
      result.push(Object.freeze({
        kind: 'execution',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: executionCaseHash(authority, execution, resolution),
        transactionId: attempt.transaction_id,
      }));
      continue;
    }
    if (outcome.status === 'execution_failed' && execution.state === 'failed'
        && resolution.state === 'refund_pending') {
      const refunds = store.readAll('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid', [intent.id]);
      const open = refunds.find((row) => row.state === 'pending' || row.state === 'unresolved');
      result.push(Object.freeze({
        kind: 'refund-observation',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: refundCaseHash(authority, execution, resolution, refunds),
        originalTransactionId: attempt.transaction_id,
        refundTransactionId: open?.refund_transaction_id ?? null,
      }));
    }
  }
  return Object.freeze(result);
}


/** Read-only Operator projection backed by the same authoritative repositories. */
export function createRuntimeOperatorReads({store, intents, policies, approvals, receipts, exporter, signer, walletIdentity, mode}) {
  const currentSessionId = () => store.readOne(`SELECT id FROM spend_sessions
    WHERE state IN ('open','policy_blocked') ORDER BY created_at DESC, id DESC LIMIT 1`)?.id ?? null;
  return Object.freeze({
    async overview() {
      const active = policies.active();
      const sessionId = currentSessionId();
      return Object.freeze({
        status: 'ready',
        deployment: mode === 'cdp-testnet' ? 'verified' : 'simulated',
        wallet: {address: walletIdentity.address, network: walletIdentity.network},
        policyVersion: publicPolicy(active, active.id),
        sessions: sessionRows(store, intents),
        approvals: approvals.list({limit: 1000}).map(publicApproval),
        receipts: allReceipts(store, receipts),
        reconciliations: reconciliationCases(store),
        events: normalizedEvents(store),
        projection: sessionId === null ? null : exporter.exportSigned({sessionId}),
      });
    },
    async listPolicies() {
      const active = policies.active();
      return {items: policies.history().map(version => publicPolicy(version, active.id))};
    },
    async walletIdentity() {return {address: walletIdentity.address};},
    async listApprovals({state}) {
      return {items: approvals.list({limit:1000, ...(state === null ? {} : {state})}).map(publicApproval)};
    },
    async listReceipts() {return {items: allReceipts(store, receipts)};},
    async getReceipt({receiptId}) {
      const row = store.readOne(`SELECT spend_intents.session_id FROM signed_receipts
        JOIN spend_intents ON spend_intents.id = signed_receipts.intent_id
        WHERE signed_receipts.id = ?`, [receiptId]);
      if (!row) return null;
      return receipts.list({sessionId: row.session_id, limit:1000}).find(entry=>entry.id===receiptId) ?? null;
    },
    async exportSession({sessionId}) {return exporter.exportSigned({sessionId});},
    async receiptPublicKey() {
      return {algorithm: signer.algorithm, keyId: signer.keyId, publicKeyPem: signer.publicKeyPem};
    },
  });
}

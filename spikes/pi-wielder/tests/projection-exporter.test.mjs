import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { encodePaymentSignatureHeader } from '@x402/core/http';
import { authorizationTypes } from '@x402/evm';
import { getAddress, keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import {
  canonicalJson,
  KernelError,
  sha256,
} from '../src/kernel/canonical.mjs';
import {
  createReceiptSigner,
} from '../src/kernel/receipt-signing.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { createProjectionExporter } from '../src/kernel/projection-exporter.mjs';

const NOW = '2026-07-31T12:00:01.000Z';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const PAYMENT_ACCOUNT = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-projection-exporter-test-only')),
);
const WALLET = PAYMENT_ACCOUNT.address.toLowerCase();
const SELLER = 'https://seller.example';
const AGENT_INSTANCE_ID = Buffer.alloc(16, 7).toString('base64url');
const VALID_AFTER = '0';
const VALID_BEFORE = String(Math.floor(Date.parse(NOW) / 1_000) + 60);
const APPROVAL_EXPIRES_AT = new Date(Date.parse(NOW) + 60_000).toISOString();
const FORBIDDEN_EXPORT_TERMS = /prompt|body|authorization|payment.signature|private|secret|token|stack|file.path/i;
const AUTHORITY_TABLES = Object.freeze([
  'metadata',
  'policy_versions',
  'spend_sessions',
  'agent_enrollments',
  'isolation_attestations',
  'agent_session_bindings',
  'spend_intents',
  'policy_decisions',
  'budget_reservations',
  'approvals',
  'payment_attempts',
  'payment_reconciliation_candidates',
  'execution_outcomes',
  'execution_resolutions',
  'refunds',
  'reconciliations',
  'buyer_outcomes',
  'signed_receipts',
  'events',
]);

const POLICY = Object.freeze({
  schemaVersion: 1,
  network: NETWORK,
  asset: ASSET,
  wallet: WALLET,
  methods: ['GET', 'POST'],
  sellers: [{
    origin: SELLER,
    pathPrefixes: ['/paid/'],
    payTo: PAY_TO,
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: PAY_TO,
    refundSigner: PAY_TO,
    refundSource: '0x3000000000000000000000000000000000000000',
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  }],
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60000,
  approvalTtlMs: 300000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
});

function assertDeepFrozen(value, seen = new WeakSet()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return;
  seen.add(value);
  assert.equal(Object.isFrozen(value), true);
  for (const child of Object.values(value)) assertDeepFrozen(child, seen);
}

function scanForbidden(value, path = '$') {
  assert.doesNotMatch(path, FORBIDDEN_EXPORT_TERMS);
  if (typeof value === 'string') {
    assert.doesNotMatch(value, FORBIDDEN_EXPORT_TERMS);
    assert.doesNotMatch(value, /(?:file:\/\/|\/(?:Users|home|private|tmp|var|etc|opt|root|proc|sys|dev)\/|[A-Za-z]:\\)/i);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert.doesNotMatch(key, FORBIDDEN_EXPORT_TERMS);
    scanForbidden(child, `${path}.${key}`);
  }
}

function authorityRows(store) {
  return Object.fromEntries(AUTHORITY_TABLES.map((table) => [
    table,
    store.readAll(`SELECT * FROM ${table} ORDER BY rowid`),
  ]));
}

function challenge(amountAtomic) {
  return {
    x402Version: 2,
    resource: {
      urlHash: sha256(`${SELLER}/paid/infer`),
      description: 'safe commercial fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount: amountAtomic,
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
  };
}

async function exactPaymentFixture(amountAtomic, suffix) {
  const nonce = `0x${sha256(canonicalJson({
    domain: 'projection-exporter.payment-nonce.v1',
    suffix,
  })).slice('sha256:'.length)}`;
  const accepted = challenge(amountAtomic).accepts[0];
  const typedData = {
    domain: {
      name: 'USDC',
      version: '2',
      chainId: 84532,
      verifyingContract: getAddress(ASSET),
    },
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: getAddress(WALLET),
      to: getAddress(PAY_TO),
      value: BigInt(amountAtomic),
      validAfter: BigInt(VALID_AFTER),
      validBefore: BigInt(VALID_BEFORE),
      nonce,
    },
  };
  const signature = await PAYMENT_ACCOUNT.signTypedData(typedData);
  const payload = {
    x402Version: 2,
    resource: {
      url: `${SELLER}/paid/infer`,
      description: 'safe commercial fixture',
      mimeType: 'application/json',
    },
    accepted,
    payload: {
      signature,
      authorization: {
        from: WALLET,
        to: PAY_TO,
        value: amountAtomic,
        validAfter: VALID_AFTER,
        validBefore: VALID_BEFORE,
        nonce,
      },
    },
  };
  const header = encodePaymentSignatureHeader(payload);
  return Object.freeze({
    header,
    hash: sha256(Buffer.from(header, 'ascii')),
    json: canonicalJson(payload),
    nonce,
    payload: Object.freeze(payload),
  });
}

const EXACT_PAYMENTS = Object.freeze({
  failed: await exactPaymentFixture('70000', 'failed'),
  gap: await exactPaymentFixture('50000', 'gap'),
  success: await exactPaymentFixture('50000', 'success'),
  unresolved: await exactPaymentFixture('50000', 'unresolved'),
});

function directSettlement(payment, transactionId, suffix) {
  return Object.freeze({
    source: 'x402-payment-response',
    headerHash: sha256(`settlement-header-${suffix}`),
    success: true,
    transaction: transactionId,
    network: NETWORK,
    payer: WALLET,
    amountAtomic: payment.payload.accepted.amount,
    paymentHash: payment.hash,
  });
}

function appendReserveAndPaymentEvents(appendEvent, intent, paymentId, payment) {
  appendEvent({
    entityType: 'budget_reservation',
    entityId: intent.id,
    eventType: 'budget.reserved',
    data: {
      sessionId: 'session-1',
      sellerOrigin: SELLER,
      amountAtomic: intent.projection.accepts[0].amount,
      previousState: null,
      nextState: 'reserved',
      updatedAt: NOW,
    },
  });
  if (paymentId === null) return;
  appendEvent({
    entityType: 'payment_attempt',
    entityId: paymentId,
    eventType: 'payment.reserved',
    data: {
      intentId: intent.id,
      policyVersionId: 'policy-1',
      quoteId: intent.quoteId,
      createdAt: NOW,
    },
  });
  if (!payment) return;
  appendEvent({
    entityType: 'payment_attempt',
    entityId: intent.id,
    eventType: 'payment.signing_claimed',
    data: {
      nonce: payment.nonce,
      validAfter: VALID_AFTER,
      validBefore: VALID_BEFORE,
      signingClaimedAt: NOW,
    },
  });
  appendEvent({
    entityType: 'payment_attempt',
    entityId: intent.id,
    eventType: 'payment.signed',
    data: { paymentHash: payment.hash, signedAt: NOW },
  });
  appendEvent({
    entityType: 'payment_attempt',
    entityId: intent.id,
    eventType: 'payment.retrying',
    data: { retryStartedAt: NOW },
  });
}

function appendCommitEvent(appendEvent, intent, payment, settlement) {
  appendEvent({
    entityType: 'budget_reservation',
    entityId: intent.id,
    eventType: 'budget.committed',
    data: {
      amountAtomic: intent.projection.accepts[0].amount,
      transactionId: settlement.transaction,
      paymentHash: payment.hash,
      headerHash: settlement.headerHash,
      previousState: 'reserved',
      nextState: 'committed',
      committedAt: NOW,
    },
  });
}

function addIntent(db, {
  id,
  state,
  amountAtomic,
  suffix,
}) {
  const projection = challenge(amountAtomic);
  const projectionJson = canonicalJson(projection);
  const challengeHash = sha256(projectionJson);
  const quoteId = sha256(canonicalJson({ challengeHash, acceptedIndex: 0 }));
  const intentHash = sha256(canonicalJson({ domain: 'fixture.intent.v1', id }));
  db.prepare(`INSERT INTO spend_intents
    (id, request_id, session_id, enrollment_hash, route_id, method, request_url_hash,
     seller_origin, resource_path, body_hash, header_allowlist_hash, ordinary_fingerprint,
     purpose_label, correlation_id, idempotency_key, wallet_address, intent_hash,
     challenge_projection_json, challenge_hash, challenge_received_at, state, created_at, updated_at)
    VALUES (?, ?, 'session-1', ?, ?, 'POST', ?, ?, '/paid/infer', ?, ?, ?,
      'skill.invoke', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      id,
      `request-${suffix}`,
      enrollmentHash(),
      `route-${suffix}`,
      sha256(`${SELLER}/paid/infer`),
      SELLER,
      sha256(`raw prompt body ${suffix}`),
      sha256(`authorization header ${suffix}`),
      sha256(`ordinary-${suffix}`),
      `correlation-${suffix}`,
      `idempotency-${suffix}`,
      WALLET,
      intentHash,
      projectionJson,
      challengeHash,
      NOW,
      state,
      NOW,
      NOW,
    );
  db.prepare(`INSERT INTO policy_decisions
    (intent_id, policy_version_id, decision, reason_code, challenge_hash,
     accepted_index, quote_id, amount_ceiling_atomic, decided_at)
    VALUES (?, 'policy-1', ?, ?, ?, 0, ?, ?, ?)`)
    .run(
      id,
      state === 'approval_pending' ? 'approval_required' : 'allow',
      state === 'approval_pending' ? 'HUMAN_APPROVAL_REQUIRED' : 'WITHIN_AUTO_LIMIT',
      challengeHash,
      quoteId,
      amountAtomic,
      NOW,
    );
  return { id, intentHash, projection, projectionJson, quoteId };
}

function enrollmentDescriptor() {
  return {
    schemaVersion: 1,
    agentInstanceId: AGENT_INSTANCE_ID,
    credentialDigest: sha256('fixture-agent-capability'),
    agentUid: '501',
    agentGid: '20',
  };
}

function enrollmentHash() {
  return sha256(canonicalJson(enrollmentDescriptor()));
}

function countedSigner() {
  const base = createReceiptSigner();
  const counter = { calls: 0 };
  const signer = Object.freeze({
    algorithm: base.algorithm,
    keyId: base.keyId,
    publicKeyPem: base.publicKeyPem,
    persistent: base.persistent,
    signHash(hashHex) {
      counter.calls += 1;
      return base.signHash(hashHex);
    },
  });
  return { counter, signer };
}

function setup(t, {
  isolation = 'simulated',
  currentAttestation = null,
  attestationImportedAt = NOW,
} = {}) {
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => NOW,
  });
  t.after(() => store.close());
  const { counter, signer } = countedSigner();
  let receiptSequence = 0;
  const receipts = createSignedReceiptRepository({
    store,
    signer,
    idFactory: () => `receipt-${++receiptSequence}`,
    now: () => NOW,
  });
  const descriptor = enrollmentDescriptor();
  const descriptorHash = enrollmentHash();
  const policyJson = canonicalJson(POLICY);

  store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
    db.prepare(`INSERT INTO policy_versions
      (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
      VALUES ('policy-1', 1, ?, ?, NULL, ?)`)
      .run(policyJson, sha256(policyJson), NOW);
    db.prepare("INSERT INTO metadata(key, value) VALUES ('active_policy_id', 'policy-1')").run();
    db.prepare(`INSERT INTO agent_enrollments
      (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
       state, enrolled_by_operator_hash, enrolled_at)
      VALUES (?, ?, ?, '501', '20', 'active', ?, ?)`)
      .run(
        AGENT_INSTANCE_ID,
        descriptor.credentialDigest,
        descriptorHash,
        sha256('operator raw identity must stay hashed'),
        NOW,
      );
    appendEvent({
      entityType: 'agent_enrollment',
      entityId: AGENT_INSTANCE_ID,
      eventType: 'agent.enrolled',
      data: {
        enrollmentHash: descriptorHash,
        credentialDigest: descriptor.credentialDigest,
        agentUid: '501',
        agentGid: '20',
        operatorIdHash: sha256('operator raw identity must stay hashed'),
        isolation,
        enrolledAt: NOW,
      },
    });
    db.prepare(`INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
      VALUES ('session-1', ?, ?, 'policy-1', 'open', ?, NULL)`)
      .run(`pi:${AGENT_INSTANCE_ID}`, WALLET, NOW);
    db.prepare(`INSERT INTO agent_session_bindings
      (id, agent_instance_id, credential_digest, enrollment_hash, session_id, state,
       created_at, last_seen_at, closed_at)
      VALUES ('binding-1', ?, ?, ?, 'session-1', 'open', ?, ?, NULL)`)
      .run(AGENT_INSTANCE_ID, descriptor.credentialDigest, descriptorHash, NOW, NOW);

    if (currentAttestation) {
      const reportJson = canonicalJson(currentAttestation);
      db.prepare(`INSERT INTO isolation_attestations
        (id, report_hash, enrollment_hash, report_json, state,
         imported_by_operator_hash, probed_at, expires_at, imported_at, superseded_at)
        VALUES ('attestation-current', ?, ?, ?, 'current', ?, ?, ?, ?, NULL)`)
        .run(
          sha256(reportJson),
          descriptorHash,
          reportJson,
          sha256('attestation operator'),
          currentAttestation.probedAt ?? NOW,
          currentAttestation.expiresAt ?? '2026-07-31T12:15:00.000Z',
          attestationImportedAt,
        );
    } else {
      const dangerousReport = canonicalJson({
        providerError: 'stack trace in /Users/alice/private/wallet.key',
        rawCredential: 'top-secret-token',
      });
      db.prepare(`INSERT INTO isolation_attestations
        (id, report_hash, enrollment_hash, report_json, state,
         imported_by_operator_hash, probed_at, expires_at, imported_at, superseded_at)
        VALUES ('attestation-old', ?, ?, ?, 'superseded', ?, ?, ?, ?, ?)`)
        .run(
          sha256(dangerousReport),
          descriptorHash,
          dangerousReport,
          sha256('attestation operator'),
          NOW,
          '2026-07-31T12:15:00.000Z',
          NOW,
          NOW,
        );
    }

    const success = addIntent(db, {
      id: 'intent-success', state: 'terminal', amountAtomic: '50000', suffix: 'success',
    });
    const successPayment = EXACT_PAYMENTS.success;
    const successTransaction = `0x${'ab'.repeat(32)}`;
    const successSettlement = directSettlement(
      successPayment,
      successTransaction,
      'success',
    );
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, settlement_json, transaction_id, signing_claimed_at,
       signed_at, retry_started_at, settled_at, created_at, updated_at)
      VALUES ('payment-success', ?, 'settled', ?, 0, ?, ?, ?, ?, ?,
       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        success.id,
        success.projectionJson,
        successPayment.json,
        successPayment.header,
        successPayment.hash,
        success.quoteId,
        successPayment.nonce,
        VALID_AFTER,
        VALID_BEFORE,
        canonicalJson(successSettlement),
        successTransaction,
        NOW,
        NOW,
        NOW,
        NOW,
        NOW,
        NOW,
      );
    db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, 'session-1', ?, '0', '50000', '0', '0', 'committed', ?, ?)`)
      .run(success.id, SELLER, NOW, NOW);
    appendReserveAndPaymentEvents(
      appendEvent,
      success,
      'payment-success',
      successPayment,
    );
    appendCommitEvent(appendEvent, success, successPayment, successSettlement);
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'succeeded', 200, ?, ?, ?)`)
      .run(
        success.id,
        sha256('{"ok":true}'),
        canonicalJson({ providerError: 'stack at /private/tmp/provider.js', responseBody: 'secret' }),
        NOW,
      );
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'completed', 'PAYMENT_SETTLED', 1, ?)`)
      .run(success.id, NOW);

    const pending = addIntent(db, {
      id: 'intent-pending', state: 'approval_pending', amountAtomic: '150000', suffix: 'pending',
    });
    db.prepare(`INSERT INTO approvals
      (id, intent_id, decision, operator_id_hash, intent_hash, challenge_hash,
       quote_id, accepted_index, amount_ceiling_atomic, wallet_address,
       policy_version_id, expires_at, reason_code, decided_at, consumed_at)
      VALUES ('approval-1', ?, 'pending', NULL, ?, ?, ?, 0,
       '150000', ?, 'policy-1', ?, NULL, NULL, NULL)`)
      .run(
        pending.id,
        pending.intentHash,
        sha256(pending.projectionJson),
        pending.quoteId,
        WALLET,
        APPROVAL_EXPIRES_AT,
      );
    appendEvent({
      entityType: 'approval',
      entityId: 'approval-1',
      eventType: 'approval.requested',
      data: {
        intentId: pending.id,
        intentHash: pending.intentHash,
        challengeHash: sha256(pending.projectionJson),
        quoteId: pending.quoteId,
        amountCeilingAtomic: '150000',
        walletAddress: WALLET,
        policyVersionId: 'policy-1',
        acceptedIndex: 0,
        expiresAt: APPROVAL_EXPIRES_AT,
        requestedAt: NOW,
      },
    });

    const failed = addIntent(db, {
      id: 'intent-failed', state: 'terminal', amountAtomic: '70000', suffix: 'failed',
    });
    const failedPayment = EXACT_PAYMENTS.failed;
    const failedTransaction = `0x${'cd'.repeat(32)}`;
    const failedSettlement = directSettlement(
      failedPayment,
      failedTransaction,
      'failed',
    );
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, settlement_json, transaction_id, signing_claimed_at,
       signed_at, retry_started_at, settled_at, created_at, updated_at)
      VALUES ('payment-failed', ?, 'settled', ?, 0, ?, ?, ?, ?, ?,
       ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        failed.id,
        failed.projectionJson,
        failedPayment.json,
        failedPayment.header,
        failedPayment.hash,
        failed.quoteId,
        failedPayment.nonce,
        VALID_AFTER,
        VALID_BEFORE,
        canonicalJson(failedSettlement),
        failedTransaction,
        NOW,
        NOW,
        NOW,
        NOW,
        NOW,
        NOW,
      );
    db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, 'session-1', ?, '0', '70000', '0', '0', 'committed', ?, ?)`)
      .run(failed.id, SELLER, NOW, NOW);
    appendReserveAndPaymentEvents(
      appendEvent,
      failed,
      'payment-failed',
      failedPayment,
    );
    appendCommitEvent(appendEvent, failed, failedPayment, failedSettlement);
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'failed', 500, ?, ?, ?)`)
      .run(failed.id, sha256('provider failure'), canonicalJson({ stack: '/tmp/error.js' }), NOW);
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
      VALUES (?, 'refund_pending', 'UPSTREAM_HTTP_FAILURE', 1, ?, NULL)`)
      .run(failed.id, NOW);
    db.prepare(`INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state, evidence_json,
       refund_transaction_id, created_at, updated_at)
      VALUES ('refund-1', ?, ?, '70000', 'pending', NULL, NULL, ?, ?)`)
      .run(failed.id, `0x${'cd'.repeat(32)}`, NOW, NOW);
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'execution_failed', 'UPSTREAM_HTTP_FAILURE', 1, ?)`)
      .run(failed.id, NOW);
  }));

  receipts.issueMissingTerminalReceipts();
  const exporter = createProjectionExporter({ store, receipts, signer, now: () => NOW });
  return { counter, exporter, receipts, signer, store };
}

function validIsolationReport() {
  return {
    schemaVersion: 1,
    enrollmentHash: enrollmentHash(),
    kernelUid: '502',
    kernelGid: '20',
    agentUid: '501',
    agentGid: '20',
    authorityMetadataHash: sha256('authority metadata'),
    credentialMetadataHash: sha256('credential metadata'),
    releaseManifestHash: sha256('release manifest'),
    releaseTreeHash: sha256('release tree'),
    nodeExecutableHash: sha256('node executable'),
    serviceArtifactsHash: sha256('service artifacts'),
    systemdEffectiveConfigHash: sha256('systemd effective config'),
    environmentMetadataHash: sha256('environment metadata'),
    probeResults: {
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
    },
    probedAt: '2026-07-31T12:00:00.000Z',
    expiresAt: '2026-07-31T12:15:00.000Z',
  };
}

function assertProjectionCorruption(operation) {
  assert.throws(
    operation,
    (error) => error instanceof KernelError && error.code === 'PROJECTION_CORRUPTION',
  );
}

function parityBypassExporter(context) {
  return createProjectionExporter({
    store: context.store,
    receipts: Object.freeze({
      assertParityInTransaction() { return true; },
      verify: (record) => context.receipts.verify(record),
    }),
    signer: context.signer,
    now: () => NOW,
  });
}

function rewritePayment(store, intentId, mutate, { arbitraryHeader = null } = {}) {
  store.transaction((token) => store.within(token, ({ db }) => {
    const row = db.prepare('SELECT * FROM payment_attempts WHERE intent_id = ?').get(intentId);
    assert.ok(row);
    const payload = JSON.parse(row.payment_payload_json);
    mutate(payload, row);
    const payloadJson = canonicalJson(payload);
    const header = arbitraryHeader ?? encodePaymentSignatureHeader(payload);
    db.prepare(`UPDATE payment_attempts
      SET payment_payload_json = ?, payment_header = ?, payment_hash = ?,
          nonce = ?, valid_after = ?, valid_before = ?
      WHERE intent_id = ?`).run(
      payloadJson,
      header,
      sha256(Buffer.from(header, 'ascii')),
      row.nonce,
      row.valid_after,
      row.valid_before,
      intentId,
    );
  }));
}

function appendPendingApproval(db, appendEvent, intent, {
  approvalId,
  includeEvent = true,
} = {}) {
  db.prepare(`INSERT INTO approvals
    (id, intent_id, decision, operator_id_hash, intent_hash, challenge_hash,
     quote_id, accepted_index, amount_ceiling_atomic, wallet_address,
     policy_version_id, expires_at, reason_code, decided_at, consumed_at)
    VALUES (?, ?, 'pending', NULL, ?, ?, ?, 0, ?, ?, 'policy-1', ?, NULL, NULL, NULL)`)
    .run(
      approvalId,
      intent.id,
      intent.intentHash,
      sha256(intent.projectionJson),
      intent.quoteId,
      intent.projection.accepts[0].amount,
      WALLET,
      APPROVAL_EXPIRES_AT,
    );
  if (!includeEvent) return;
  appendEvent({
    entityType: 'approval',
    entityId: approvalId,
    eventType: 'approval.requested',
    data: {
      intentId: intent.id,
      intentHash: intent.intentHash,
      challengeHash: sha256(intent.projectionJson),
      quoteId: intent.quoteId,
      amountCeilingAtomic: intent.projection.accepts[0].amount,
      walletAddress: WALLET,
      policyVersionId: 'policy-1',
      acceptedIndex: 0,
      expiresAt: APPROVAL_EXPIRES_AT,
      requestedAt: NOW,
    },
  });
}

function seedReservedBudget(store, {
  suffix,
  reservedAtomic = '50000',
  includeAttempt = true,
  includePaymentEvents = true,
} = {}) {
  store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
    const intent = addIntent(db, {
      id: `intent-${suffix}`,
      state: 'reserved',
      amountAtomic: '50000',
      suffix,
    });
    db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, 'session-1', ?, ?, '0', '0', '0', 'reserved', NULL, ?)`)
      .run(intent.id, SELLER, reservedAtomic, NOW);
    if (includeAttempt) {
      db.prepare(`INSERT INTO payment_attempts
        (id, intent_id, state, payment_required_projection_json, accepted_index,
         quote_id, created_at, updated_at)
        VALUES (?, ?, 'reserved', ?, 0, ?, ?, ?)`)
        .run(
          `payment-${suffix}`,
          intent.id,
          intent.projectionJson,
          intent.quoteId,
          NOW,
          NOW,
        );
    }
    appendReserveAndPaymentEvents(
      appendEvent,
      intent,
      includeAttempt && includePaymentEvents ? `payment-${suffix}` : null,
      null,
    );
  }));
}

function seedUnresolvedPaymentBlocker(context, suffix = 'unresolved') {
  context.store.transaction((token) => context.store.within(token, ({ db, appendEvent }) => {
    const intent = addIntent(db, {
      id: `intent-${suffix}`,
      state: 'unresolved',
      amountAtomic: '50000',
      suffix,
    });
    db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, 'session-1', ?, '0', '0', '0', '50000', 'unresolved', NULL, ?)`)
      .run(intent.id, SELLER, NOW);
    const payment = EXACT_PAYMENTS.unresolved;
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, reason_code, signing_claimed_at, signed_at,
       retry_started_at, created_at, updated_at)
      VALUES (?, ?, 'unresolved', ?, 0, ?, ?, ?, ?, ?, ?, ?,
       'PAID_RESPONSE_AMBIGUOUS', ?, ?, ?, ?, ?)`)
      .run(
        `payment-${suffix}`,
        intent.id,
        intent.projectionJson,
        payment.json,
        payment.header,
        payment.hash,
        intent.quoteId,
        payment.nonce,
        VALID_AFTER,
        VALID_BEFORE,
        NOW,
        NOW,
        NOW,
        NOW,
        NOW,
      );
    db.prepare(`INSERT INTO payment_reconciliation_candidates
      (id, intent_id, transaction_id, state, evidence_json, created_at, updated_at)
      VALUES (?, ?, ?, 'pending', NULL, ?, ?)`)
      .run(
        `candidate-${suffix}`,
        intent.id,
        `0x${'ef'.repeat(32)}`,
        NOW,
        NOW,
      );
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'payment_unresolved', 'PAID_RESPONSE_AMBIGUOUS', 1, ?)`)
      .run(intent.id, NOW);
    appendReserveAndPaymentEvents(
      appendEvent,
      intent,
      `payment-${suffix}`,
      payment,
    );
    appendEvent({
      entityType: 'budget_reservation',
      entityId: intent.id,
      eventType: 'budget.held_unresolved',
      data: {
        amountAtomic: '50000',
        reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
        previousState: 'reserved',
        nextState: 'unresolved',
        heldAt: NOW,
      },
    });
    appendEvent({
      entityType: 'payment_attempt',
      entityId: intent.id,
      eventType: 'payment.unresolved',
      data: { reasonCode: 'PAID_RESPONSE_AMBIGUOUS', recordedAt: NOW },
    });
  }));
  context.receipts.issueForTerminal({ intentId: `intent-${suffix}` });
}

function leaves(value, path = []) {
  if (!value || typeof value !== 'object') return [{ path, value }];
  return Object.entries(value).flatMap(([key, child]) => leaves(child, [...path, key]));
}

function tamperAt(value, path) {
  const copy = structuredClone(value);
  let target = copy;
  for (const key of path.slice(0, -1)) target = target[key];
  const key = path.at(-1);
  const original = target[key];
  if (typeof original === 'string') target[key] = `${original}x`;
  else if (typeof original === 'number') target[key] = original + 1;
  else if (typeof original === 'boolean') target[key] = !original;
  else if (original === null) target[key] = 'changed';
  else throw new Error(`unsupported test leaf at ${path.join('.')}`);
  return copy;
}

function verifyInFreshProcess(values) {
  const verifier = String.raw`
    import crypto from 'node:crypto';
    const canonicalize = (value) => Array.isArray(value)
      ? value.map(canonicalize)
      : value && typeof value === 'object'
        ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]))
        : value;
    const canonicalJson = (value) => JSON.stringify(canonicalize(value));
    const verify = (bundle) => {
      try {
        if (!bundle || Object.getPrototypeOf(bundle) !== Object.prototype
            || Object.keys(bundle).sort().join(',') !== [
              'algorithm', 'domain', 'keyId', 'projection', 'projectionHash',
              'publicKeyPem', 'schemaVersion', 'signature',
            ].sort().join(',')) return false;
        if (bundle.schemaVersion !== 1
            || bundle.domain !== 'wallet-kernel.projection-export.v1'
            || bundle.algorithm !== 'Ed25519'
            || !/^sha256:[0-9a-f]{64}$/.test(bundle.projectionHash)) return false;
        const key = crypto.createPublicKey(bundle.publicKeyPem);
        const keyId = 'sha256:' + crypto.createHash('sha256')
          .update(key.export({ type: 'spki', format: 'der' })).digest('hex');
        if (key.asymmetricKeyType !== 'ed25519' || keyId !== bundle.keyId) return false;
        const unsigned = {
          schemaVersion: bundle.schemaVersion,
          domain: bundle.domain,
          projection: bundle.projection,
          algorithm: bundle.algorithm,
          keyId: bundle.keyId,
          publicKeyPem: bundle.publicKeyPem,
        };
        const hash = crypto.createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
        if (bundle.projectionHash !== 'sha256:' + hash) return false;
        const signature = Buffer.from(bundle.signature, 'base64');
        return signature.length === 64
          && signature.toString('base64') === bundle.signature
          && crypto.verify(null, Buffer.from(hash, 'hex'), key, signature);
      } catch { return false; }
    };
    let text = '';
    for await (const chunk of process.stdin) text += chunk;
    process.stdout.write(JSON.stringify(JSON.parse(text).map(verify)));
  `;
  const child = spawnSync(process.execPath, ['--input-type=module', '-e', verifier], {
    encoding: 'utf8',
    input: JSON.stringify(values),
  });
  assert.equal(child.status, 0, child.stderr);
  return JSON.parse(child.stdout);
}

test('snapshot is a closed frozen one-way sanitized authority projection', (t) => {
  const { counter, exporter, store } = setup(t);
  const callsBefore = counter.calls;
  const rowsBefore = authorityRows(store);

  assert.deepEqual(Object.keys(exporter), ['snapshot', 'exportSigned']);
  assert.equal(Object.isFrozen(exporter), true);
  const snapshot = exporter.snapshot({ sessionId: 'session-1' });

  assert.equal(counter.calls, callsBefore);
  assert.deepEqual(authorityRows(store), rowsBefore);
  assert.equal(snapshot.schemaVersion, 1);
  assert.equal(snapshot.domain, 'wallet-kernel.sanitized-projection.v1');
  assert.equal(snapshot.authoritySchemaVersion, 1);
  assert.deepEqual(snapshot.wallet, {
    address: WALLET,
    adapterHash: sha256(canonicalJson({
      domain: 'wallet-kernel.adapter-identity.v1',
      adapterId: `pi:${AGENT_INSTANCE_ID}`,
    })),
  });
  assert.equal(snapshot.agentEnrollment.state, 'active');
  assert.equal(snapshot.agentEnrollment.enrollmentHash, enrollmentHash());
  assert.equal(snapshot.agentEnrollment.identityHash, sha256(canonicalJson({
    domain: 'wallet-kernel.agent-identity.v1',
    agentUid: '501',
    agentGid: '20',
  })));
  assert.deepEqual(snapshot.isolation, { status: 'simulated', preflightDigest: null });
  assert.deepEqual(snapshot.budgets.session, {
    reservedAtomic: '0',
    committedAtomic: '120000',
    releasedAtomic: '0',
    unresolvedAtomic: '0',
    exposureAtomic: '120000',
  });
  assert.deepEqual(snapshot.budgets.wallet, snapshot.budgets.session);
  assert.deepEqual(snapshot.approvals, {
    approved: 0,
    cancelled: 0,
    consumed: 0,
    denied: 0,
    expired: 0,
    pending: 1,
  });
  assert.deepEqual(snapshot.blockers, {
    blockedIntentCount: 1,
    execution: { openCount: 1, reasonCodes: ['UPSTREAM_HTTP_FAILURE'] },
    payment: { openCount: 0, reasonCodes: [] },
    refund: { openCount: 1, reasonCodes: ['REFUND_PENDING'] },
    walletBlocked: true,
  });
  assert.equal(snapshot.intents.length, 3);
  assert.equal(snapshot.signedReceipts.length, 2);
  assert.equal(snapshot.eventHeadHash, store.events().at(-1).event_hash);
  assert.equal(snapshot.issuedAt, NOW);
  assertDeepFrozen(snapshot);
  scanForbidden(snapshot);

  const serialized = JSON.stringify(snapshot);
  for (const sensitive of [
    'Bearer top-secret-token',
    'raw body',
    'rawPaymentPayload',
    '/Users/alice/private/wallet.key',
    '/private/tmp/provider.js',
    '/tmp/error.js',
    'providerError',
  ]) assert.equal(serialized.includes(sensitive), false);
});

test('exportSigned binds every field and verifies in one fresh process', (t) => {
  const { counter, exporter, store } = setup(t);
  const callsBefore = counter.calls;
  const rowsBefore = authorityRows(store);
  const signed = exporter.exportSigned({ sessionId: 'session-1' });

  assert.equal(counter.calls, callsBefore + 1);
  assert.deepEqual(authorityRows(store), rowsBefore);
  assertDeepFrozen(signed);
  scanForbidden(signed);
  const variants = [signed, ...leaves(signed).map(({ path }) => tamperAt(signed, path))];
  const results = verifyInFreshProcess(variants);
  assert.equal(results[0], true);
  assert.equal(results.slice(1).every((valid) => valid === false), true);
});

test('only an exact current unexpired isolation proof can claim enforced', (t) => {
  const report = validIsolationReport();
  const { exporter } = setup(t, {
    isolation: 'pending_verification',
    currentAttestation: report,
  });
  const snapshot = exporter.snapshot({ sessionId: 'session-1' });
  assert.deepEqual(snapshot.isolation, {
    status: 'enforced',
    preflightDigest: sha256(canonicalJson(report)),
  });
  const projectedKeys = [];
  const collectKeys = (value) => {
    if (!value || typeof value !== 'object') return;
    for (const [key, child] of Object.entries(value)) {
      projectedKeys.push(key);
      collectKeys(child);
    }
  };
  collectKeys(snapshot);
  for (const rawIdentityKey of ['agentUid', 'agentGid', 'kernelUid', 'kernelGid']) {
    assert.equal(projectedKeys.includes(rawIdentityKey), false);
  }
});

test('opaque current attestation cannot be mislabeled enforced', (t) => {
  const { exporter } = setup(t, {
    isolation: 'pending_verification',
    currentAttestation: {
      probedAt: '2026-07-31T12:00:00.000Z',
      expiresAt: '2026-07-31T12:15:00.000Z',
      result: 'current is not proof',
    },
  });
  assert.throws(
    () => exporter.snapshot({ sessionId: 'session-1' }),
    (error) => error instanceof KernelError && error.code === 'PROJECTION_CORRUPTION',
  );
});

test('an exact expired preflight keeps its digest but falls back to pending verification', (t) => {
  const report = {
    ...validIsolationReport(),
    probedAt: '2026-07-31T11:45:00.000Z',
    expiresAt: '2026-07-31T12:00:00.000Z',
  };
  const { exporter } = setup(t, {
    isolation: 'pending_verification',
    currentAttestation: report,
    attestationImportedAt: '2026-07-31T11:45:01.000Z',
  });
  assert.deepEqual(exporter.snapshot({ sessionId: 'session-1' }).isolation, {
    status: 'pending_verification',
    preflightDigest: sha256(canonicalJson(report)),
  });
});

test('a current preflight forged onto a revoked enrollment is corruption', (t) => {
  const { exporter, store } = setup(t, {
    isolation: 'pending_verification',
    currentAttestation: validIsolationReport(),
  });
  store.transaction((token) => store.within(token, ({ db }) => {
    db.prepare(`UPDATE agent_enrollments
      SET state = 'revoked', revoked_by_operator_hash = ?, revoked_at = ?
      WHERE enrollment_hash = ?`)
      .run(sha256('revoking operator'), NOW, enrollmentHash());
  }));
  assert.throws(
    () => exporter.snapshot({ sessionId: 'session-1' }),
    (error) => error instanceof KernelError && error.code === 'PROJECTION_CORRUPTION',
  );
});

test('future-dated isolation import can never be projected as enforced', (t) => {
  const { exporter } = setup(t, {
    isolation: 'pending_verification',
    currentAttestation: validIsolationReport(),
    attestationImportedAt: '2026-07-31T12:00:02.000Z',
  });
  assertProjectionCorruption(() => exporter.snapshot({ sessionId: 'session-1' }));
});

test('parity, all reads, and event-head capture share one transaction token', (t) => {
  const context = setup(t);
  let nestedCommitBlocked = false;
  const guardedReceipts = Object.freeze({
    assertParity() {
      throw new Error('independent receipt parity read escaped the snapshot transaction');
    },
    assertParityInTransaction(token) {
      context.receipts.assertParityInTransaction(token);
      assert.throws(
        () => context.store.mutate({
          entityType: 'race_probe',
          entityId: 'race-probe-1',
          eventType: 'race.commit',
          data: { shouldCommit: false },
        }, () => null),
        /nested authority transaction is forbidden/,
      );
      nestedCommitBlocked = true;
      return true;
    },
    verify: (record) => context.receipts.verify(record),
  });
  const transactionOnlyStore = Object.freeze({
    transaction: (operation) => context.store.transaction(operation),
    within: (token, operation) => context.store.within(token, operation),
    readOne() { throw new Error('independent projection read escaped its transaction'); },
    readAll() { throw new Error('independent projection read escaped its transaction'); },
    verifyEventChain() { throw new Error('event verification escaped its transaction'); },
    pragma() { throw new Error('schema verification escaped its transaction'); },
  });
  const exporter = createProjectionExporter({
    store: transactionOnlyStore,
    receipts: guardedReceipts,
    signer: context.signer,
    now: () => NOW,
  });
  const before = authorityRows(context.store);
  const snapshot = exporter.snapshot({ sessionId: 'session-1' });
  assert.equal(nestedCommitBlocked, true);
  assert.equal(snapshot.eventHeadHash, context.store.events().at(-1).event_hash);
  assert.deepEqual(authorityRows(context.store), before);
});

test('export signing begins only after the frozen snapshot transaction closes', (t) => {
  const context = setup(t);
  let signerEnteredAfterSnapshot = false;
  const transactionCheckingSigner = Object.freeze({
    algorithm: context.signer.algorithm,
    keyId: context.signer.keyId,
    publicKeyPem: context.signer.publicKeyPem,
    persistent: context.signer.persistent,
    signHash(hashHex) {
      const eventCount = context.store.transaction((token) => context.store.within(
        token,
        ({ db }) => Number(db.prepare('SELECT COUNT(*) AS count FROM events').get().count),
      ));
      assert.ok(eventCount > 0);
      signerEnteredAfterSnapshot = true;
      return context.signer.signHash(hashHex);
    },
  });
  const exporter = createProjectionExporter({
    store: context.store,
    receipts: context.receipts,
    signer: transactionCheckingSigner,
    now: () => NOW,
  });
  const before = authorityRows(context.store);
  const signed = exporter.exportSigned({ sessionId: 'session-1' });
  assert.equal(signerEnteredAfterSnapshot, true);
  assert.equal(Object.isFrozen(signed.projection), true);
  assert.deepEqual(authorityRows(context.store), before);
});

test('corrupt nonterminal reservations fail before aggregate budget projection', async (t) => {
  await t.test('conservation differs from the PolicyDecision ceiling', () => {
    const context = setup(t);
    seedReservedBudget(context.store, { suffix: 'bad-conservation', reservedAtomic: '49999' });
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
  await t.test('reservation has no exact PaymentAttempt', () => {
    const context = setup(t);
    seedReservedBudget(context.store, { suffix: 'missing-attempt', includeAttempt: false });
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
});

test('wallet blockers cover payment, execution, and refund classes without double counting', (t) => {
  const context = setup(t);
  seedUnresolvedPaymentBlocker(context);
  const { blockers } = context.exporter.snapshot({ sessionId: 'session-1' });
  assert.deepEqual(blockers, {
    blockedIntentCount: 2,
    execution: { openCount: 1, reasonCodes: ['UPSTREAM_HTTP_FAILURE'] },
    payment: { openCount: 1, reasonCodes: ['PAID_RESPONSE_AMBIGUOUS'] },
    refund: { openCount: 1, reasonCodes: ['REFUND_PENDING'] },
    walletBlocked: true,
  });
});

test('wallet, session policy, intent, and reservation authority cannot be rebound', async (t) => {
  const OTHER_WALLET = '0x4000000000000000000000000000000000000000';
  await t.test('PolicyVersion wallet', () => {
    const context = setup(t);
    const changed = canonicalJson({ ...structuredClone(POLICY), wallet: OTHER_WALLET });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE policy_versions SET canonical_json = ?, policy_hash = ?
        WHERE id = 'policy-1'`).run(changed, sha256(changed));
    }));
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
  await t.test('Spend Session wallet', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE spend_sessions SET wallet_address = ? WHERE id = 'session-1'")
        .run(OTHER_WALLET);
    }));
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
  await t.test('Spend Session PolicyVersion', () => {
    const context = setup(t);
    const policy1 = context.store.readOne(
      "SELECT policy_hash FROM policy_versions WHERE id = 'policy-1'",
    ).policy_hash;
    const changed = canonicalJson({ ...structuredClone(POLICY), sessionMaxAtomic: '2000001' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO policy_versions
        (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
        VALUES ('policy-2', 1, ?, ?, ?, ?)`)
        .run(changed, sha256(changed), policy1, NOW);
      db.prepare("UPDATE metadata SET value = 'policy-2' WHERE key = 'active_policy_id'").run();
      db.prepare("UPDATE spend_sessions SET policy_version_id = 'policy-2' WHERE id = 'session-1'")
        .run();
    }));
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
  await t.test('Spend Intent wallet', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE spend_intents SET wallet_address = ? WHERE id = 'intent-pending'")
        .run(OTHER_WALLET);
    }));
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
  await t.test('BudgetReservation session', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO spend_sessions
        (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
        VALUES ('session-2', ?, ?, 'policy-1', 'closed', ?, ?)`)
        .run(`pi:${AGENT_INSTANCE_ID}`, WALLET, NOW, NOW);
      db.prepare(`INSERT INTO agent_session_bindings
        (id, agent_instance_id, credential_digest, enrollment_hash, session_id, state,
         created_at, last_seen_at, closed_at)
        VALUES ('binding-2', ?, ?, ?, 'session-2', 'closed', ?, ?, ?)`)
        .run(
          AGENT_INSTANCE_ID,
          enrollmentDescriptor().credentialDigest,
          enrollmentHash(),
          NOW,
          NOW,
          NOW,
        );
      db.prepare(`UPDATE budget_reservations SET session_id = 'session-2'
        WHERE intent_id = 'intent-success'`).run();
    }));
    assertProjectionCorruption(() => context.exporter.snapshot({ sessionId: 'session-1' }));
  });
});

test('canonical x402 PaymentAttempt bytes remain exactly bound to persisted authority', async (t) => {
  await t.test('resource URL substitution', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload) => {
      payload.resource.url = `${SELLER}/paid/other`;
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('accepted network substitution', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload) => {
      payload.accepted.network = 'eip155:1';
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('authorization payer substitution', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload) => {
      payload.payload.authorization.from = '0x4000000000000000000000000000000000000000';
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('authorization nonce and row nonce move together', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload, row) => {
      const changed = `0x${'44'.repeat(32)}`;
      payload.payload.authorization.nonce = changed;
      row.nonce = changed;
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('authorization window and row window move together', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload, row) => {
      const changed = String(BigInt(VALID_BEFORE) - 1n);
      payload.payload.authorization.validBefore = changed;
      row.valid_before = changed;
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('noncanonical Circle signature recovery byte', () => {
    const context = setup(t);
    rewritePayment(context.store, 'intent-success', (payload) => {
      payload.payload.signature = `${payload.payload.signature.slice(0, -2)}00`;
    });
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('arbitrary header with a recomputed hash', () => {
    const context = setup(t);
    rewritePayment(
      context.store,
      'intent-success',
      () => {},
      { arbitraryHeader: 'arbitrary-payment-header' },
    );
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('settlement proof substitution', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      const row = db.prepare(
        "SELECT settlement_json FROM payment_attempts WHERE intent_id = 'intent-success'",
      ).get();
      const settlement = JSON.parse(row.settlement_json);
      settlement.payer = '0x4000000000000000000000000000000000000000';
      db.prepare("UPDATE payment_attempts SET settlement_json = ? WHERE intent_id = 'intent-success'")
        .run(canonicalJson(settlement));
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
});

test('joined spend lifecycle rejects impossible final-serving projections', async (t) => {
  await t.test('captured intent cannot own a reservation', () => {
    const context = setup(t);
    seedReservedBudget(context.store, { suffix: 'captured-reservation' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE spend_intents SET state = 'captured' WHERE id = 'intent-captured-reservation'")
        .run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('retrying intent cannot own settled payment authority', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE spend_intents SET state = 'retrying' WHERE id = 'intent-success'").run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('committed payment requires an execution outcome', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("DELETE FROM execution_outcomes WHERE intent_id = 'intent-success'").run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('succeeded execution requires a 2xx status', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE execution_outcomes SET http_status = 500 WHERE intent_id = 'intent-success'")
        .run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('succeeded execution requires a response hash', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE execution_outcomes SET response_hash = NULL WHERE intent_id = 'intent-success'")
        .run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('succeeded execution requires the completed buyer outcome', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'execution_failed', reason_code = 'UPSTREAM_HTTP_FAILURE'
        WHERE intent_id = 'intent-success'`).run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
});

test('Approval rows require approval_required authority, exact expiry, and event provenance', async (t) => {
  await t.test('allow decision cannot gain an Approval row', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db, appendEvent }) => {
      const row = db.prepare("SELECT * FROM spend_intents WHERE id = 'intent-success'").get();
      appendPendingApproval(db, appendEvent, {
        id: row.id,
        intentHash: row.intent_hash,
        projectionJson: row.challenge_projection_json,
        quoteId: db.prepare(
          "SELECT quote_id FROM policy_decisions WHERE intent_id = 'intent-success'",
        ).get().quote_id,
        projection: JSON.parse(row.challenge_projection_json),
      }, { approvalId: 'approval-allow' });
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('approved row cannot omit operator authority', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE approvals SET decision = 'approved', decided_at = ? WHERE id = 'approval-1'")
        .run(NOW);
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('immutable expiry is derived exactly', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE approvals SET expires_at = ? WHERE id = 'approval-1'")
        .run(new Date(Date.parse(APPROVAL_EXPIRES_AT) + 1).toISOString());
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('approval.requested event is mandatory', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db, appendEvent }) => {
      const intent = addIntent(db, {
        id: 'intent-missing-approval-event',
        state: 'approval_pending',
        amountAtomic: '150000',
        suffix: 'missing-approval-event',
      });
      appendPendingApproval(db, appendEvent, intent, {
        approvalId: 'approval-missing-event',
        includeEvent: false,
      });
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
});

test('Spend Session state and active PolicyVersion lifecycle remain aligned', async (t) => {
  await t.test('open session must pin the active policy', () => {
    const context = setup(t);
    const policy1 = context.store.readOne(
      "SELECT policy_hash FROM policy_versions WHERE id = 'policy-1'",
    ).policy_hash;
    const changed = canonicalJson({ ...structuredClone(POLICY), sessionMaxAtomic: '2000001' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO policy_versions
        (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
        VALUES ('policy-2', 1, ?, ?, ?, ?)`)
        .run(changed, sha256(changed), policy1, NOW);
      db.prepare("UPDATE metadata SET value = 'policy-2' WHERE key = 'active_policy_id'").run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
  await t.test('policy_blocked session cannot still pin active policy', () => {
    const context = setup(t);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare("UPDATE spend_sessions SET state = 'policy_blocked' WHERE id = 'session-1'").run();
    }));
    assertProjectionCorruption(() => parityBypassExporter(context).snapshot({ sessionId: 'session-1' }));
  });
});

test('closed input, receipt parity, and event-chain corruption fail before export', (t) => {
  const first = setup(t);
  assert.throws(
    () => first.exporter.snapshot({ sessionId: 'session-1', restore: true }),
    (error) => error instanceof KernelError && error.code === 'PROJECTION_INPUT',
  );
  assert.throws(
    () => first.exporter.snapshot({ sessionId: 'missing-session' }),
    (error) => error instanceof KernelError && error.code === 'SESSION_UNKNOWN',
  );

  const second = setup(t);
  second.store.transaction((token) => second.store.within(token, ({ db }) => {
    db.prepare("UPDATE signed_receipts SET signature = 'AAAA' WHERE id = 'receipt-1'").run();
  }));
  assert.throws(
    () => second.exporter.exportSigned({ sessionId: 'session-1' }),
    (error) => error instanceof KernelError && error.code === 'RECEIPT_PARITY_REQUIRED',
  );

  const third = setup(t);
  third.store.transaction((token) => third.store.within(token, ({ db }) => {
    db.prepare("UPDATE events SET event_hash = ? WHERE sequence = 1")
      .run(sha256('tampered event head'));
  }));
  assert.throws(
    () => third.exporter.snapshot({ sessionId: 'session-1' }),
    (error) => error instanceof KernelError && error.code === 'PROJECTION_EVENT_CHAIN',
  );
});

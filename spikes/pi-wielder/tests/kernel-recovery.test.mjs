import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { createIsolationAttestationRepository, validateIsolationReportBytes } from '../src/agent/isolation-preflight.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { createApprovalQueue } from '../src/kernel/approval-queue.mjs';
import { createBudgetLedger } from '../src/kernel/budget-ledger.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { evaluateSpendPolicy } from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { createReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import { createReconciler, recoverKernelAuthority } from '../src/kernel/recovery.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));
const CLOCKS = new WeakMap();

function sequenceIds() {
  let value = 0;
  return (kind) => `${kind}-${++value}`;
}

function setup(t, {
  fileAuthority = null,
  signer = createReceiptSigner(),
} = {}) {
  const clock = { value: NOW };
  const store = openKernelStore(fileAuthority ? {
    filePath: fileAuthority.databasePath,
    pathTrust: fileAuthority.pathTrust,
    now: () => clock.value,
  } : {
    filePath: ':memory:',
    allowMemory: true,
    now: () => clock.value,
  });
  t.after(() => store.close());
  const now = () => clock.value;
  const intents = createIntentRepository({
    store,
    idFactory: sequenceIds(),
    now,
    routeMetadata: Object.freeze({
      'paid-infer': Object.freeze({
        description: 'offline fixture',
        mimeType: 'application/json',
      }),
    }),
  });
  const receipts = createSignedReceiptRepository({
    store,
    signer,
    idFactory: sequenceIds(),
    now,
  });
  const dependencies = {
    store,
    intents,
    budgets: createBudgetLedger({ store, now }),
    approvals: createApprovalQueue({ store, idFactory: sequenceIds(), now }),
    receipts,
    now,
  };
  CLOCKS.set(dependencies, clock);
  return dependencies;
}

function temporaryFileAuthority(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-recovery-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return Object.freeze({
    databasePath: path.join(directory, 'kernel.sqlite'),
    pathTrust: Object.freeze({
      mode: 'deterministic',
      trustedAncestor: directory,
      kernelUid: process.getuid(),
      agentUid: process.getuid(),
    }),
  });
}

function enforcedIsolationReport(enrollmentHash, {
  expiresAt = '2026-07-31T12:15:00.000Z',
} = {}) {
  return {
    schemaVersion: 1,
    enrollmentHash,
    kernelUid: '502',
    kernelGid: '20',
    agentUid: DESCRIPTOR.agentUid,
    agentGid: DESCRIPTOR.agentGid,
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
    probedAt: NOW,
    expiresAt,
  };
}

function insertCurrentIsolation(context, enrollmentHash, report) {
  const reportJson = canonicalJson(report);
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO isolation_attestations
      (id, report_hash, enrollment_hash, report_json, state,
       imported_by_operator_hash, probed_at, expires_at, imported_at, superseded_at)
      VALUES ('isolation-current', ?, ?, ?, 'current', ?, ?, ?, ?, NULL)`).run(
      sha256(reportJson),
      enrollmentHash,
      reportJson,
      OPERATOR_HASH,
      report.probedAt,
      report.expiresAt,
      NOW,
    );
  }));
}

function seedCapturedAuthority(context) {
  const policies = createPolicyRepository(context.store);
  const policyVersion = policies.apply(structuredClone(BASE_POLICY), NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store: context.store, now: context.now });
  enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: sha256(canonicalJson(DESCRIPTOR)),
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const session = context.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: policyVersion.id,
  });
  const request = {
    routeId: 'paid-infer',
    method: 'POST',
    requestUrl: `${SELLER}/paid/infer`,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from('{}'),
    purposeLabel: 'skill.invoke',
    correlationId: 'recovery-fixture',
  };
  const intent = context.intents.captureIntent({ sessionId: session.id, ...request });
  return { intent, policies, policyVersion, request, session };
}

function attachDecision(context, seeded, amount) {
  const paymentRequired = {
    x402Version: 2,
    error: 'not persisted',
    resource: {
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: seeded.policyVersion.policy.network,
      asset: seeded.policyVersion.policy.asset,
      amount,
      payTo: seeded.policyVersion.policy.sellers[0].payTo,
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
  };
  context.intents.attachChallenge({
    intentId: seeded.intent.id,
    paymentRequired,
    challengeReceivedAt: NOW,
  });
  seeded.challenge = paymentRequired;
  const evaluation = evaluateSpendPolicy({
    policy: seeded.policyVersion.policy,
    policyVersion: { id: seeded.policyVersion.id, hash: seeded.policyVersion.hash },
    intent: {
      id: seeded.intent.id,
      method: seeded.request.method,
      requestUrl: seeded.request.requestUrl,
      sellerOrigin: SELLER,
      resourcePath: '/paid/infer',
      walletAddress: WALLET,
    },
    wallet: {
      provider: 'deterministic',
      walletId: 'buyer',
      address: WALLET,
      network: seeded.policyVersion.policy.network,
    },
    paymentRequired,
    challengeReceivedAtMs: Date.parse(NOW),
    nowMs: Date.parse(NOW),
    budgetSnapshot: {
      sellerSessionExposureAtomic: '0',
      sessionExposureAtomic: '0',
      rolling24hExposureAtomic: '0',
      pendingApprovalCount: 0,
    },
  });
  context.store.transaction((token) => seeded.policies.recordDecisionInTransaction(token, {
    intentId: seeded.intent.id,
    policyVersionId: seeded.policyVersion.id,
    evaluation,
    decidedAt: NOW,
  }));
  return evaluation;
}

function seedPaymentCrashGap(context, state) {
  const seeded = seedCapturedAuthority(context);
  const evaluation = attachDecision(context, seeded, '50000');
  assert.equal(evaluation.decision, 'allow');
  context.intents.transition({
    intentId: seeded.intent.id,
    expectedState: 'challenged',
    nextState: 'authorized',
    reasonCode: 'POLICY_ALLOWED',
  });
  context.budgets.reserve({
    intentId: seeded.intent.id,
    amountAtomic: evaluation.amountCeilingAtomic,
  });
  const projectionJson = context.store.readOne(
    'SELECT challenge_projection_json FROM spend_intents WHERE id = ?', [seeded.intent.id],
  ).challenge_projection_json;
  const projection = JSON.parse(projectionJson);
  const nonce = `0x${'11'.repeat(32)}`;
  const paymentHeader = 'recovery-signed-payment-header';
  const paymentPayloadJson = canonicalJson({
    x402Version: 2,
    resource: seeded.challenge.resource,
    accepted: seeded.challenge.accepts[0],
    payload: {
      signature: `0x${'22'.repeat(65)}`,
      authorization: {
        from: WALLET,
        to: projection.accepts[0].payTo,
        value: evaluation.amountCeilingAtomic,
        validAfter: '0',
        validBefore: '1785502860',
        nonce,
      },
    },
  });
  const claimed = state !== 'reserved';
  const signed = state === 'signed' || state === 'retrying';
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, signing_claimed_at, signed_at, retry_started_at,
       created_at, updated_at)
      VALUES ('payment-recovery', ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      seeded.intent.id,
      state,
      projectionJson,
      signed ? paymentPayloadJson : null,
      signed ? paymentHeader : null,
      signed ? sha256(Buffer.from(paymentHeader, 'ascii')) : null,
      evaluation.quoteId,
      claimed ? nonce : null,
      claimed ? '0' : null,
      claimed ? '1785502860' : null,
      claimed ? NOW : null,
      signed ? NOW : null,
      state === 'retrying' ? NOW : null,
      NOW,
      NOW,
    );
  }));
  const transitions = [
    ['authorized', 'reserved'],
    ['reserved', 'signing'],
    ['signing', 'signed'],
    ['signed', 'retrying'],
  ];
  const finalIndex = transitions.findIndex(([, next]) => next === state);
  for (const [expectedState, nextState] of transitions.slice(0, finalIndex + 1)) {
    context.intents.transition({
      intentId: seeded.intent.id,
      expectedState,
      nextState,
      reasonCode: `TEST_${nextState.toUpperCase()}`,
    });
  }
  return { ...seeded, paymentHeader, paymentPayloadJson };
}

function seedPendingApproval(context) {
  const seeded = seedCapturedAuthority(context);
  const evaluation = attachDecision(context, seeded, '200000');
  assert.equal(evaluation.decision, 'approval_required');
  const approval = context.approvals.request(Object.freeze({
    intentId: seeded.intent.id,
    intentHash: seeded.intent.intentHash,
    challengeHash: evaluation.challengeHash,
    quoteId: evaluation.quoteId,
    amountCeilingAtomic: evaluation.amountCeilingAtomic,
    walletAddress: WALLET,
    policyVersionId: seeded.policyVersion.id,
    acceptedIndex: evaluation.acceptedIndex,
  }));
  context.intents.transition({
    intentId: seeded.intent.id,
    expectedState: 'challenged',
    nextState: 'approval_pending',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
  });
  return { ...seeded, approval };
}

function currentPaymentCaseHash(store, intentId) {
  const intent = store.readOne('SELECT * FROM spend_intents WHERE id = ?', [intentId]);
  const attempt = store.readOne('SELECT * FROM payment_attempts WHERE intent_id = ?', [intentId]);
  const budget = store.readOne('SELECT * FROM budget_reservations WHERE intent_id = ?', [intentId]);
  const outcome = store.readOne('SELECT * FROM buyer_outcomes WHERE intent_id = ?', [intentId]);
  const history = store.readAll(`SELECT * FROM payment_reconciliation_candidates
    WHERE intent_id = ? ORDER BY rowid`, [intentId]);
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-reconciliation-case.v1',
    intentId,
    intentHash: intent.intent_hash,
    attemptState: attempt.state,
    budgetState: budget.state,
    buyerOutcomeRevision: Number(outcome.revision),
    history: history.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      state: row.state,
      evidenceHash: row.evidence_json === null ? null : sha256(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function rewriteAndResealEvents(store, rewrite) {
  store.transaction((token) => store.within(token, ({ db }) => {
    rewrite(db);
    const rows = db.prepare('SELECT * FROM events ORDER BY sequence').all();
    for (const row of rows) {
      db.prepare(`UPDATE events
        SET previous_hash = NULL, event_hash = ?
        WHERE sequence = ?`).run(`temporary-event-${row.sequence}`, row.sequence);
    }
    let previousHash = null;
    for (const row of rows) {
      const eventHash = sha256(canonicalJson({
        entityType: row.entity_type,
        entityId: row.entity_id,
        eventType: row.event_type,
        data: JSON.parse(row.data_json),
        previousHash,
        createdAt: row.created_at,
      }));
      db.prepare(`UPDATE events
        SET previous_hash = ?, event_hash = ?
        WHERE sequence = ?`).run(previousHash, eventHash, row.sequence);
      previousHash = eventHash;
    }
  }));
  assert.equal(store.verifyEventChain(), true);
}

test('recovery audits a pristine authority and is idempotent', (t) => {
  const context = setup(t);

  const first = recoverKernelAuthority(context);
  const eventCount = context.store.events().length;
  const second = recoverKernelAuthority(context);

  assert.equal(first.ready, true);
  assert.equal(first.repairedIntentCount, 0);
  assert.equal(first.repairedReceiptCount, 0);
  assert.deepEqual(second, first);
  assert.equal(context.store.events().length, eventCount);
  assert.ok(Object.isFrozen(first));
});

test('recovery retains each legal enrollment and session authority shape', async (t) => {
  await t.test('active enrollment before its first session', (st) => {
    const context = setup(st);
    createPolicyRepository(context.store).apply(structuredClone(BASE_POLICY), NOW);
    const enrollment = createAgentEnrollmentRepository({
      store: context.store,
      now: context.now,
    }).enroll({
      descriptor: DESCRIPTOR,
      expectedDescriptorHash: sha256(canonicalJson(DESCRIPTOR)),
      operatorIdHash: OPERATOR_HASH,
      mode: 'cdp-testnet',
      kernelUid: 502,
      kernelGid: 502,
      expectedAgentUid: 501,
      expectedAgentGid: 20,
    });
    insertCurrentIsolation(
      context,
      enrollment.enrollmentHash,
      enforcedIsolationReport(enrollment.enrollmentHash),
    );

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 0);
    assert.equal(context.store.readOne(
      "SELECT COUNT(*) AS count FROM agent_enrollments WHERE state = 'active'",
    ).count, 1n);
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM spend_sessions',
    ).count, 0n);
  });

  await t.test('refreshed isolation attestation binds its superseded predecessor', (st) => {
    const context = setup(st);
    createPolicyRepository(context.store).apply(structuredClone(BASE_POLICY), NOW);
    const enrollment = createAgentEnrollmentRepository({
      store: context.store,
      now: context.now,
    }).enroll({
      descriptor: DESCRIPTOR,
      expectedDescriptorHash: sha256(canonicalJson(DESCRIPTOR)),
      operatorIdHash: OPERATOR_HASH,
      mode: 'cdp-testnet',
      kernelUid: 502,
      kernelGid: 502,
      expectedAgentUid: 501,
      expectedAgentGid: 20,
    });
    let id = 0;
    const attestations = createIsolationAttestationRepository({
      store: context.store,
      now: context.now,
      idFactory: () => `isolation-refresh-${++id}`,
    });
    const firstReport = enforcedIsolationReport(enrollment.enrollmentHash);
    attestations.importCurrent({
      reportBytes: Buffer.from(`${canonicalJson(firstReport)}\n`),
      expectedReportHash: sha256(canonicalJson(firstReport)),
      operatorIdHash: OPERATOR_HASH,
    });
    CLOCKS.get(context).value = '2026-07-31T12:02:00.000Z';
    const replacementReport = {
      ...enforcedIsolationReport(enrollment.enrollmentHash, {
        expiresAt: '2026-07-31T12:14:00.000Z',
      }),
      authorityMetadataHash: sha256('refreshed authority metadata'),
      probedAt: '2026-07-31T12:01:00.000Z',
    };
    attestations.importCurrent({
      reportBytes: Buffer.from(`${canonicalJson(replacementReport)}\n`),
      expectedReportHash: sha256(canonicalJson(replacementReport)),
      operatorIdHash: OPERATOR_HASH,
    });

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(context.store.readOne(
      "SELECT COUNT(*) AS count FROM isolation_attestations WHERE state = 'current'",
    ).count, 1n);
    assert.equal(context.store.readOne(
      "SELECT COUNT(*) AS count FROM isolation_attestations WHERE state = 'superseded'",
    ).count, 1n);
  });

  await t.test('expired isolation history can be renewed without admitting the expired report', (st) => {
    const context = setup(st);
    seedCapturedAuthority(context);
    // Finish the unsigned intent first, retaining its real receipt and history.
    recoverKernelAuthority(context);
    const enrollmentHash = sha256(canonicalJson(DESCRIPTOR));
    let id = 0;
    const attestations = createIsolationAttestationRepository({ store: context.store,
      now: context.now, idFactory: () => `isolation-renewal-${++id}` });
    const first = enforcedIsolationReport(enrollmentHash);
    const bytes = report => Buffer.from(`${canonicalJson(report)}\n`);
    const importReport = report => attestations.importCurrent({ reportBytes: bytes(report),
      expectedReportHash: sha256(canonicalJson(report)), operatorIdHash: OPERATOR_HASH });
    const lookup = report => attestations.currentFor({ enrollmentHash,
      authorityMetadataHash: report.authorityMetadataHash,
      releaseManifestHash: report.releaseManifestHash,
      expectedReportHash: sha256(canonicalJson(report)) });
    const firstImport = importReport(first);
    const before = Object.fromEntries(['spend_intents', 'budget_reservations', 'payment_attempts',
      'buyer_outcomes', 'signed_receipts', 'isolation_attestations', 'events']
      .map(table => [table, context.store.readAll(`SELECT * FROM ${table}`)]));
    CLOCKS.get(context).value = first.expiresAt;

    assert.throws(() => validateIsolationReportBytes(bytes(first), { now: context.now }),
      { code: 'ISOLATION_EXPIRED' });
    assert.equal(lookup(first), null);
    const recovered = recoverKernelAuthority(context);
    assert.equal(recovered.ready, true);
    assert.equal(recovered.repairedIntentCount, 0);
    assert.equal(recovered.repairedReceiptCount, 0);
    for (const [table, rows] of Object.entries(before)) {
      assert.deepEqual(context.store.readAll(`SELECT * FROM ${table}`), rows, table);
    }
    assert.equal(lookup(first), null, 'historical recovery cannot renew admission');

    const replacement = { ...first, probedAt: context.now(),
      expiresAt: '2026-07-31T12:30:00.000Z' };
    const replacementImport = importReport(replacement);
    assert.equal(recoverKernelAuthority(context).ready, true);
    assert.equal(validateIsolationReportBytes(bytes(replacement), { now: context.now }).reportHash,
      replacementImport.reportHash);
    assert.equal(lookup(replacement).reportHash, replacementImport.reportHash);
    assert.equal(lookup(first), null);
    assert.equal(context.store.readOne('SELECT state FROM isolation_attestations WHERE id = ?',
      [firstImport.id]).state, 'superseded');
    assert.equal(context.store.events().filter(event => event.event_type === 'isolation.attestation_superseded').length, 1);
  });

  await t.test('guarded closed session with retained active enrollment', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    recoverKernelAuthority(context);
    const currentSession = context.intents.getSession(seeded.session.id);
    context.store.transaction((token) => context.intents.closeBoundSessionInTransaction(token, {
      sessionId: seeded.session.id,
      expectedSessionHash: currentSession.sessionHash,
    }));

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 0);
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_sessions WHERE id = ?', [seeded.session.id],
    ).state, 'closed');
  });

  await t.test('policy-blocked session', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    const replacementPolicy = structuredClone(BASE_POLICY);
    replacementPolicy.rolling24hMaxAtomic = '9999999';
    createPolicyRepository(context.store).apply(replacementPolicy, NOW);

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 1);
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_sessions WHERE id = ?', [seeded.session.id],
    ).state, 'policy_blocked');
  });

  await t.test('completed policy transition with replacement session', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    recoverKernelAuthority(context);
    const replacementPolicy = structuredClone(BASE_POLICY);
    replacementPolicy.rolling24hMaxAtomic = '9999999';
    const target = createPolicyRepository(context.store).apply(
      replacementPolicy,
      NOW,
    ).policyVersion;
    const blocked = context.intents.getSession(seeded.session.id);
    const transition = context.store.transaction((token) => (
      context.intents.transitionBlockedSessionInTransaction(token, {
        sessionId: seeded.session.id,
        targetPolicyVersionId: target.id,
        expectedSessionHash: blocked.sessionHash,
      })
    ));

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 0);
    assert.equal(transition.previousSession.state, 'closed');
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_sessions WHERE id = ?', [transition.replacementSession.id],
    ).state, 'open');
  });

  await t.test('revoked enrollment with a retained open binding', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    createAgentEnrollmentRepository({ store: context.store, now: context.now }).revoke({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      expectedEnrollmentHash: sha256(canonicalJson(DESCRIPTOR)),
      operatorIdHash: OPERATOR_HASH,
    });

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 1);
    assert.equal(context.store.readOne(
      'SELECT state FROM agent_enrollments WHERE agent_instance_id = ?',
      [DESCRIPTOR.agentInstanceId],
    ).state, 'revoked');
    assert.equal(context.store.readOne(
      'SELECT state FROM agent_session_bindings WHERE session_id = ?', [seeded.session.id],
    ).state, 'open');
  });
});

test('file-backed recovery survives two reopen boundaries without replaying signed work', (t) => {
  const fileAuthority = temporaryFileAuthority(t);
  const signer = createReceiptSigner();
  const first = setup(t, { fileAuthority, signer });
  const seeded = seedPaymentCrashGap(first, 'signed');
  const persistedPayload = first.store.readOne(
    'SELECT payment_payload_json FROM payment_attempts WHERE intent_id = ?',
    [seeded.intent.id],
  ).payment_payload_json;
  first.store.close();

  const reopened = setup(t, { fileAuthority, signer });
  const repaired = recoverKernelAuthority(reopened);
  assert.equal(repaired.ready, true);
  assert.equal(repaired.repairedIntentCount, 1);
  assert.equal(repaired.repairedReceiptCount, 1);
  assert.equal(reopened.store.readOne(
    'SELECT payment_payload_json FROM payment_attempts WHERE intent_id = ?',
    [seeded.intent.id],
  ).payment_payload_json, persistedPayload);
  assert.equal(reopened.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?',
    [seeded.intent.id],
  ).state, 'unresolved');
  assert.equal(reopened.store.readOne(
    'SELECT COUNT(*) AS count FROM payment_attempts WHERE intent_id = ?',
    [seeded.intent.id],
  ).count, 1n);
  reopened.store.close();

  const secondReopen = setup(t, { fileAuthority, signer });
  const idempotent = recoverKernelAuthority(secondReopen);
  assert.equal(idempotent.ready, true);
  assert.equal(idempotent.repairedIntentCount, 0);
  assert.equal(idempotent.repairedReceiptCount, 0);
  assert.equal(secondReopen.receipts.assertParity(), true);
  secondReopen.store.close();
});

test('recovery rejects a real foreign-key violation before making repairs', (t) => {
  const context = setup(t);
  context.store.execForTest('PRAGMA foreign_keys = OFF');
  context.store.execForTest(`INSERT INTO spend_sessions
    (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
    VALUES ('orphan', 'pi:orphan', '0x1000000000000000000000000000000000000000',
      'missing-policy', 'closed', '${NOW}', '${NOW}')`);
  context.store.execForTest('PRAGMA foreign_keys = ON');

  assert.throws(
    () => recoverKernelAuthority(context),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
  assert.equal(context.store.events().length, 0);
});

test('recovery rejects well-formed cross-table and lifecycle corruption with zero repair', async (t) => {
  await t.test('enrollment creation event substitution', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    rewriteAndResealEvents(context.store, (db) => {
      const row = db.prepare("SELECT * FROM events WHERE event_type = 'agent.enrolled'").get();
      const data = JSON.parse(row.data_json);
      data.operatorIdHash = `sha256:${'ef'.repeat(32)}`;
      db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
        .run(canonicalJson(data), row.sequence);
    });

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'captured');
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
    ).count, 0n);
  });

  await t.test('approval request event substitution', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    rewriteAndResealEvents(context.store, (db) => {
      const row = db.prepare("SELECT * FROM events WHERE event_type = 'approval.requested'").get();
      const data = JSON.parse(row.data_json);
      data.acceptedIndex += 1;
      db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
        .run(canonicalJson(data), row.sequence);
    });

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'pending');
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'approval_pending');
  });

  await t.test('consumed approval without its aggregate reservation', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    const approved = context.approvals.approve({
      approvalId: seeded.approval.approvalId,
    expectedIntentHash: seeded.intent.intentHash,
      operatorIdHash: OPERATOR_HASH,
    });
    context.store.transaction((token) => context.approvals.consumeForInTransaction(token, {
      intentId: approved.intentId,
      intentHash: approved.intentHash,
      challengeHash: approved.challengeHash,
      quoteId: approved.quoteId,
      amountCeilingAtomic: approved.amountCeilingAtomic,
      walletAddress: approved.walletAddress,
      policyVersionId: approved.policyVersionId,
      acceptedIndex: approved.acceptedIndex,
      expiresAt: approved.expiresAt,
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'consumed');
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM budget_reservations WHERE intent_id = ?',
      [seeded.intent.id],
    ).count, 0n);
  });

  await t.test('Spend Intent immutable hash projection substitution', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare('UPDATE spend_intents SET body_hash = ? WHERE id = ?')
        .run(sha256('substituted request body'), seeded.intent.id);
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
    ).count, 0n);
  });

  await t.test('coordinated seller URL rebind cannot replace intent genesis authority', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    const sellerOrigin = 'https://rebound.example';
    const resourcePath = '/paid/rebound';
    const requestUrlHash = sha256(`${sellerOrigin}${resourcePath}`);
    const intentHash = sha256(canonicalJson({
      requestId: seeded.intent.requestId,
      sessionId: seeded.intent.sessionId,
      enrollmentHash: seeded.intent.enrollmentHash,
      routeId: seeded.intent.routeId,
      method: seeded.intent.method,
      requestUrlHash,
      sellerOrigin,
      resourcePath,
      bodyHash: seeded.intent.bodyHash,
      headerAllowlistHash: seeded.intent.headerAllowlistHash,
      purposeLabel: seeded.intent.purposeLabel,
      correlationId: seeded.intent.correlationId,
      walletAddress: seeded.intent.walletAddress,
      policyVersionId: seeded.policyVersion.id,
    }));
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE spend_intents
        SET seller_origin = ?, resource_path = ?, request_url_hash = ?, intent_hash = ?
        WHERE id = ?`).run(
        sellerOrigin,
        resourcePath,
        requestUrlHash,
        intentHash,
        seeded.intent.id,
      );
    }));
    rewriteAndResealEvents(context.store, (db) => {
      const row = db.prepare("SELECT * FROM events WHERE event_type = 'intent.captured'").get();
      const data = JSON.parse(row.data_json);
      data.requestUrlHash = requestUrlHash;
      data.intentHash = intentHash;
      db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
        .run(canonicalJson(data), row.sequence);
    });

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
    ).count, 0n);
  });

  await t.test('PolicyVersion predecessor substitution', (st) => {
    const context = setup(st);
    const policies = createPolicyRepository(context.store);
    policies.apply(structuredClone(BASE_POLICY), NOW);
    const replacement = structuredClone(BASE_POLICY);
    replacement.rolling24hMaxAtomic = '9999999';
    const second = policies.apply(replacement, NOW).policyVersion;
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare('UPDATE policy_versions SET predecessor_hash = ? WHERE id = ?')
        .run(sha256('substituted predecessor'), second.id);
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.events().filter(
      (event) => event.event_type === 'policy.applied',
    ).length, 2);
  });

  await t.test('expired isolation report with a weakened enforced probe blocks all recovery writes', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    const enrollmentHash = sha256(canonicalJson(DESCRIPTOR));
    const report = enforcedIsolationReport(enrollmentHash);
    report.probeResults.database = 'READABLE';
    insertCurrentIsolation(context, enrollmentHash, report);
    CLOCKS.get(context).value = report.expiresAt;
    const beforeEvents = context.store.events();

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.deepEqual(context.store.events(), beforeEvents);
    assert.equal(context.store.readOne('SELECT state FROM spend_intents WHERE id = ?',
      [seeded.intent.id]).state, 'captured');
    assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM buyer_outcomes').count, 0n);
    assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);
  });

  await t.test('current isolation import from the future blocks all recovery writes', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    const enrollmentHash = sha256(canonicalJson(DESCRIPTOR));
    insertCurrentIsolation(context, enrollmentHash, enforcedIsolationReport(enrollmentHash));
    context.store.transaction(token => context.store.within(token, ({ db }) => {
      db.prepare('UPDATE isolation_attestations SET imported_at = ? WHERE id = ?')
        .run('2026-07-31T12:00:00.001Z', 'isolation-current');
    }));
    const beforeEvents = context.store.events();

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.deepEqual(context.store.events(), beforeEvents);
    assert.equal(context.store.readOne('SELECT state FROM spend_intents WHERE id = ?',
      [seeded.intent.id]).state, 'captured');
    assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM buyer_outcomes').count, 0n);
    assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);
  });

  await t.test('replacement supersession without an exact replacement attestation', (st) => {
    const context = setup(st);
    createPolicyRepository(context.store).apply(structuredClone(BASE_POLICY), NOW);
    const enrollments = createAgentEnrollmentRepository({ store: context.store, now: context.now });
    const enrollment = enrollments.enroll({
      descriptor: DESCRIPTOR,
      expectedDescriptorHash: sha256(canonicalJson(DESCRIPTOR)),
      operatorIdHash: OPERATOR_HASH,
      mode: 'cdp-testnet',
      kernelUid: 502,
      kernelGid: 502,
      expectedAgentUid: 501,
      expectedAgentGid: 20,
    });
    const report = enforcedIsolationReport(enrollment.enrollmentHash);
    createIsolationAttestationRepository({
      store: context.store,
      now: context.now,
      idFactory: () => 'isolation-revoked-fixture',
    }).importCurrent({
      reportBytes: Buffer.from(`${canonicalJson(report)}\n`),
      expectedReportHash: sha256(canonicalJson(report)),
      operatorIdHash: OPERATOR_HASH,
    });
    enrollments.revoke({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      expectedEnrollmentHash: enrollment.enrollmentHash,
      operatorIdHash: OPERATOR_HASH,
    });
    rewriteAndResealEvents(context.store, (db) => {
      const row = db.prepare(
        "SELECT * FROM events WHERE event_type = 'isolation.attestation_superseded'",
      ).get();
      const data = JSON.parse(row.data_json);
      data.reasonCode = 'ATTESTATION_REPLACED';
      db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
        .run(canonicalJson(data), row.sequence);
    });

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
  });

  await t.test('session-to-enrollment binding substitution', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare('UPDATE spend_sessions SET adapter_id = ? WHERE id = ?').run(
        `pi:${Buffer.alloc(16, 2).toString('base64url')}`,
        seeded.session.id,
      );
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'captured');
  });

  await t.test('orphan open session', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO spend_sessions
        (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
        VALUES ('orphan-open-session', 'pi:orphan-open-agent', ?, ?, 'open', ?, NULL)`)
        .run(WALLET, seeded.policyVersion.id, NOW);
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
    ).count, 0n);
  });

  await t.test('active unbound enrollment beside retained revoked open authority', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    const enrollments = createAgentEnrollmentRepository({ store: context.store, now: context.now });
    enrollments.revoke({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      expectedEnrollmentHash: sha256(canonicalJson(DESCRIPTOR)),
      operatorIdHash: OPERATOR_HASH,
    });
    const descriptor = Object.freeze({
      schemaVersion: 1,
      agentInstanceId: Buffer.alloc(16, 1).toString('base64url'),
      credentialDigest: `sha256:${'bc'.repeat(32)}`,
      agentUid: '503',
      agentGid: '504',
    });
    const enrollmentHash = sha256(canonicalJson(descriptor));
    context.store.transaction((token) => context.store.within(token, ({ db, appendEvent }) => {
      db.prepare(`INSERT INTO agent_enrollments
        (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
         state, enrolled_by_operator_hash, enrolled_at, revoked_by_operator_hash, revoked_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?, NULL, NULL)`).run(
        descriptor.agentInstanceId,
        descriptor.credentialDigest,
        enrollmentHash,
        descriptor.agentUid,
        descriptor.agentGid,
        OPERATOR_HASH,
        NOW,
      );
      appendEvent({
        entityType: 'agent_enrollment',
        entityId: descriptor.agentInstanceId,
        eventType: 'agent.enrolled',
        data: {
          enrollmentHash,
          credentialDigest: descriptor.credentialDigest,
          agentUid: descriptor.agentUid,
          agentGid: descriptor.agentGid,
          operatorIdHash: OPERATOR_HASH,
          isolation: 'pending_verification',
          enrolledAt: NOW,
        },
      });
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'captured');
  });

  await t.test('conflicting existing receipt projection', (st) => {
    const context = setup(st);
    const seeded = seedCapturedAuthority(context);
    recoverKernelAuthority(context);
    const beforeEvents = context.store.events().length;
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare('UPDATE signed_receipts SET receipt_hash = ? WHERE intent_id = ?')
        .run(sha256('substituted outcome'), seeded.intent.id);
    }));

    assert.throws(
      () => recoverKernelAuthority(context),
      (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
    );
    assert.equal(context.store.events().length, beforeEvents);
    assert.equal(context.store.readOne(
      'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', [seeded.intent.id],
    ).count, 1n);
  });
});

test('a fault after the first recovery write rolls back the whole aggregate repair', (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'reserved');
  const beforeEvents = context.store.events().length;
  const faultingBudgets = {
    snapshotInTransaction: (...args) => context.budgets.snapshotInTransaction(...args),
    holdUnresolvedInTransaction: (...args) => (
      context.budgets.holdUnresolvedInTransaction(...args)
    ),
    releaseInTransaction: (...args) => {
      context.budgets.releaseInTransaction(...args);
      throw new Error('fault after budget release');
    },
  };

  assert.throws(
    () => recoverKernelAuthority({ ...context, budgets: faultingBudgets }),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
  ).state, 'reserved');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
  ).state, 'reserved');
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [seeded.intent.id],
  ).state, 'reserved');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
  ).count, 0n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', [seeded.intent.id],
  ).count, 0n);
  assert.equal(context.store.events().length, beforeEvents);
  assert.equal(context.store.verifyEventChain(), true);
});

test('recovery rejects a clock regression after classification with zero repair writes', (t) => {
  const context = setup(t);
  const seeded = seedCapturedAuthority(context);
  const beforeEvents = context.store.events().length;
  let calls = 0;
  const regressingNow = () => {
    calls += 1;
    return calls === 1 ? NOW : '2026-07-31T11:59:59.999Z';
  };

  assert.throws(
    () => recoverKernelAuthority({ ...context, now: regressingNow }),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
  assert.equal(context.store.readOne(
    'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
  ).state, 'captured');
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
  ).count, 0n);
  assert.equal(context.store.events().length, beforeEvents);
});

test('recovery terminalizes captured unsigned work and repairs its first receipt once', (t) => {
  const context = setup(t);
  const { intent } = seedCapturedAuthority(context);

  const first = recoverKernelAuthority(context);
  const eventCount = context.store.events().length;
  const receipt = context.receipts.latest(intent.id);
  assert.deepEqual({
    state: context.store.readOne('SELECT state FROM spend_intents WHERE id = ?', [intent.id]).state,
    status: context.store.readOne(
      'SELECT status FROM buyer_outcomes WHERE intent_id = ?', [intent.id],
    ).status,
    reasonCode: receipt.receipt.outcome.reasonCode,
    revision: receipt.revision,
  }, {
    state: 'terminal',
    status: 'upstream_failed',
    reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
    revision: 1,
  });
  assert.equal(first.repairedIntentCount, 1);
  assert.equal(first.repairedReceiptCount, 1);
  assert.equal(context.receipts.assertParity(), true);

  const second = recoverKernelAuthority(context);
  assert.equal(second.repairedIntentCount, 0);
  assert.equal(second.repairedReceiptCount, 0);
  assert.equal(context.store.events().length, eventCount);
});

test('recovery uses persisted challenged decisions without inventing spend authority', async (t) => {
  for (const scenario of [
    {
      name: 'allow decision',
      amount: '50000',
      decision: 'allow',
      status: 'payment_failed',
      reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
    },
    {
      name: 'deny decision',
      amount: '500001',
      decision: 'deny',
      status: 'payment_denied',
      reasonCode: null,
    },
  ]) {
    await t.test(scenario.name, (st) => {
      const context = setup(st);
      const seeded = seedCapturedAuthority(context);
      const evaluation = attachDecision(context, seeded, scenario.amount);
      assert.equal(evaluation.decision, scenario.decision);

      const report = recoverKernelAuthority(context);
      const outcome = context.store.readOne(
        'SELECT * FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
      );
      const expectedReason = scenario.reasonCode ?? evaluation.reasonCode;
      assert.equal(outcome.status, scenario.status);
      assert.equal(outcome.reason_code, expectedReason);
      assert.equal(report.repairedIntentCount, 1);
      assert.equal(report.repairedReceiptCount, 1);
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM budget_reservations WHERE intent_id = ?',
        [seeded.intent.id],
      ).count, 0n);
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM payment_attempts WHERE intent_id = ?',
        [seeded.intent.id],
      ).count, 0n);
      assert.equal(context.receipts.latest(seeded.intent.id).receipt.outcome.reasonCode,
        expectedReason);
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('recovery releases reserved work but retains every claimed signature as unresolved', async (t) => {
  for (const state of ['reserved', 'signing', 'signed', 'retrying']) {
    await t.test(state, (st) => {
      const context = setup(st);
      const seeded = seedPaymentCrashGap(context, state);
      const before = context.store.readOne(
        'SELECT * FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
      );

      const report = recoverKernelAuthority(context);
      const intent = context.store.readOne(
        'SELECT * FROM spend_intents WHERE id = ?', [seeded.intent.id],
      );
      const attempt = context.store.readOne(
        'SELECT * FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
      );
      const budget = context.store.readOne(
        'SELECT * FROM budget_reservations WHERE intent_id = ?', [seeded.intent.id],
      );
      const receipt = context.receipts.latest(seeded.intent.id);
      assert.equal(report.repairedIntentCount, 1);
      assert.equal(report.repairedReceiptCount, 1);
      if (state === 'reserved') {
        assert.equal(intent.state, 'terminal');
        assert.equal(attempt.state, 'rejected');
        assert.equal(budget.state, 'released');
        assert.equal(receipt.receipt.outcome.status, 'payment_failed');
        assert.equal(receipt.receipt.payment.state, 'not_signed');
      } else {
        assert.equal(intent.state, 'unresolved');
        assert.equal(intent.retry_matchable, 1n);
        assert.equal(attempt.state, 'unresolved');
        assert.equal(attempt.reason_code, 'RECOVERY_PAYMENT_AMBIGUOUS');
        assert.equal(budget.state, 'unresolved');
        assert.equal(receipt.receipt.outcome.status, 'payment_unresolved');
        assert.equal(receipt.receipt.outcome.reasonCode, 'RECOVERY_PAYMENT_AMBIGUOUS');
        assert.equal(receipt.receipt.payment.state, 'unresolved');
        assert.equal(attempt.nonce, before.nonce);
        assert.equal(attempt.payment_payload_json, before.payment_payload_json);
        assert.equal(attempt.payment_header, before.payment_header);
      }
      assert.equal(context.receipts.assertParity(), true);
    });
  }
});

test('recovery binds an ambiguous payment to its durable hold when the clock advances', async (t) => {
  for (const state of ['signing', 'signed', 'retrying']) {
    await t.test(state, (st) => {
      const context = setup(st);
      const seeded = seedPaymentCrashGap(context, state);
      const before = context.store.readOne(
        'SELECT * FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
      );
      let milliseconds = Date.parse(NOW) + 1_000;
      Object.defineProperty(CLOCKS.get(context), 'value', {
        get: () => new Date(milliseconds++).toISOString(),
      });

      const report = recoverKernelAuthority(context);
      assert.equal(report.ready, true);
      assert.equal(report.unresolvedIntentCount, 1);
      const attempt = context.store.readOne(
        'SELECT * FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
      );
      const budget = context.store.readOne(
        'SELECT * FROM budget_reservations WHERE intent_id = ?', [seeded.intent.id],
      );
      const event = JSON.parse(context.store.readOne(`SELECT data_json FROM events
        WHERE entity_id = ? AND event_type = 'payment.unresolved'`, [seeded.intent.id]).data_json);
      assert.equal(attempt.updated_at, budget.updated_at);
      assert.equal(event.recordedAt, budget.updated_at);
      for (const field of ['nonce', 'payment_payload_json', 'payment_header', 'payment_hash',
        'signing_claimed_at', 'signed_at', 'retry_started_at']) {
        assert.equal(attempt[field], before[field], `${field} must survive recovery`);
      }
      assert.equal(context.receipts.latest(seeded.intent.id).receipt.payment.state, 'unresolved');
      assert.equal(context.receipts.assertParity(), true);
      assert.equal(recoverKernelAuthority(context).repairedIntentCount, 0);
    });
  }
});

test('recovery retains live approval authority and atomically expires only due work', async (t) => {
  await t.test('unexpired pending approval', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    const eventCount = context.store.events().length;

    const report = recoverKernelAuthority(context);
    assert.equal(report.repairedIntentCount, 0);
    assert.equal(report.pendingApprovalCount, 1);
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'pending');
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'approval_pending');
    assert.equal(context.store.events().length, eventCount);
  });

  await t.test('expired pending approval', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    CLOCKS.get(context).value = new Date(Date.parse(seeded.approval.expiresAt) + 1).toISOString();

    const report = recoverKernelAuthority(context);
    assert.equal(report.repairedIntentCount, 1);
    assert.equal(report.repairedReceiptCount, 1);
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'expired');
    assert.equal(context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state, 'terminal');
    const receipt = context.receipts.latest(seeded.intent.id);
    assert.equal(receipt.receipt.outcome.status, 'payment_denied');
    assert.equal(receipt.receipt.outcome.reasonCode, 'APPROVAL_EXPIRED');
    assert.equal(context.receipts.assertParity(), true);
  });

  await t.test('unexpired approved but unconsumed authority', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    context.approvals.approve({
      approvalId: seeded.approval.approvalId,
    expectedIntentHash: seeded.intent.intentHash,
      operatorIdHash: OPERATOR_HASH,
    });

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 0);
    assert.equal(report.pendingApprovalCount, 1);
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'approved');
  });

  await t.test('expired approved but unconsumed authority', (st) => {
    const context = setup(st);
    const seeded = seedPendingApproval(context);
    context.approvals.approve({
      approvalId: seeded.approval.approvalId,
    expectedIntentHash: seeded.intent.intentHash,
      operatorIdHash: OPERATOR_HASH,
    });
    CLOCKS.get(context).value = new Date(Date.parse(seeded.approval.expiresAt) + 1).toISOString();

    const report = recoverKernelAuthority(context);
    assert.equal(report.ready, true);
    assert.equal(report.repairedIntentCount, 1);
    assert.equal(context.store.readOne(
      'SELECT decision FROM approvals WHERE id = ?', [seeded.approval.approvalId],
    ).decision, 'expired');
    assert.equal(context.receipts.latest(seeded.intent.id).receipt.outcome.reasonCode,
      'APPROVAL_EXPIRED');
    assert.equal(context.receipts.assertParity(), true);
  });
});

test('recovery opens one blocking execution case for a committed payment with no execution row', (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  const transactionId = `0x${'81'.repeat(32)}`;
  const paymentHash = context.store.readOne(
    'SELECT payment_hash FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
  ).payment_hash;
  context.budgets.commit({
    intentId: seeded.intent.id,
    settlementEvidence: Object.freeze({
      source: 'x402-payment-response',
      headerHash: sha256('recovery-settlement-header'),
      success: true,
      transaction: transactionId,
      network: seeded.policyVersion.policy.network,
      payer: WALLET,
      amountAtomic: '50000',
      paymentHash,
    }),
  });
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM execution_outcomes WHERE intent_id = ?', [seeded.intent.id],
  ).count, 0n);

  const report = recoverKernelAuthority(context);
  assert.equal(report.repairedIntentCount, 1);
  assert.equal(report.repairedReceiptCount, 1);
  assert.deepEqual({
    intent: context.store.readOne(
      'SELECT state FROM spend_intents WHERE id = ?', [seeded.intent.id],
    ).state,
    payment: context.store.readOne(
      'SELECT state FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
    ).state,
    budget: context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [seeded.intent.id],
    ).state,
    execution: context.store.readOne(
      'SELECT state FROM execution_outcomes WHERE intent_id = ?', [seeded.intent.id],
    ).state,
    resolution: context.store.readOne(
      'SELECT state FROM execution_resolutions WHERE intent_id = ?', [seeded.intent.id],
    ).state,
  }, {
    intent: 'terminal',
    payment: 'settled',
    budget: 'committed',
    execution: 'unknown',
    resolution: 'reconciliation_required',
  });
  const receipt = context.receipts.latest(seeded.intent.id);
  assert.equal(receipt.receipt.outcome.status, 'execution_unknown');
  assert.equal(receipt.receipt.outcome.reasonCode, 'RECOVERY_EXECUTION_MISSING');
  assert.equal(receipt.receipt.payment.transactionId, transactionId);
  assert.equal(context.budgets.snapshot({
    sessionId: seeded.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assert.equal(context.receipts.assertParity(), true);
});

test('receipt issuance failure closes authority and recovery repairs only the exact tail gap', async (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  recoverKernelAuthority(context);
  const transactionId = `0x${'80'.repeat(32)}`;
  const failures = [];
  const receiptFailure = new Error('injected receipt signer failure');
  const failingReceipts = Object.freeze({
    assertParityInTransaction: (...args) => context.receipts.assertParityInTransaction(...args),
    latest: (...args) => context.receipts.latest(...args),
    issueRevisionForTerminal: () => { throw receiptFailure; },
  });
  const reconciler = createReconciler({
    store: context.store,
    budgets: context.budgets,
    receipts: failingReceipts,
    resolver: Object.freeze({
      observePayment: (binding) => Object.freeze({
        kind: 'settled_transfer',
        rpcTransferProof: Object.freeze({
          source: 'base-sepolia-rpc',
          network: seeded.policyVersion.policy.network,
          transactionId: binding.candidate.transactionId,
          blockHash: `0x${'89'.repeat(32)}`,
          blockNumber: '1234583',
          transactionStatus: 'success',
          confirmations: 3,
          transferLogIndex: 1,
          authorizationLogIndex: 2,
          tokenContract: seeded.policyVersion.policy.asset,
          from: WALLET,
          to: seeded.policyVersion.policy.sellers[0].payTo,
          valueAtomic: '50000',
          authorizationNonce: `0x${'11'.repeat(32)}`,
          observedAt: NOW,
        }),
      }),
      observeExecution: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
      observeRefund: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
    }),
    now: context.now,
    idFactory: sequenceIds(),
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) { return operation(); },
    }),
    markAuthorityUnhealthy: (reasonCode) => failures.push(reasonCode),
  });

  await assert.rejects(
    reconciler.reconcilePayment({
      intentId: seeded.intent.id,
      operatorIdHash: OPERATOR_HASH,
      expectedIntentHash: seeded.intent.intentHash,
      paymentTransactionId: transactionId,
      expectedPaymentCaseHash: currentPaymentCaseHash(context.store, seeded.intent.id),
    }),
    (error) => error === receiptFailure,
  );
  assert.deepEqual(failures, ['RECEIPT_PARITY_REQUIRED']);
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?', [seeded.intent.id],
  ).state, 'settled');
  assert.equal(context.store.readOne(
    'SELECT revision FROM buyer_outcomes WHERE intent_id = ?', [seeded.intent.id],
  ).revision, 2n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', [seeded.intent.id],
  ).count, 1n);

  const repaired = recoverKernelAuthority(context);
  assert.equal(repaired.ready, true);
  assert.equal(repaired.repairedIntentCount, 0);
  assert.equal(repaired.repairedReceiptCount, 1);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', [seeded.intent.id],
  ).count, 2n);
  assert.equal(context.receipts.assertParity(), true);
});

test('recovery revalidates rejected, abandoned, replacement, and confirmed payment case history', async (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  recoverKernelAuthority(context);
  let observationCount = 0;
  const reconciler = createReconciler({
    store: context.store,
    budgets: context.budgets,
    receipts: context.receipts,
    resolver: Object.freeze({
      observePayment: (binding) => {
        observationCount += 1;
        if (observationCount === 1 || observationCount === 3) {
          return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_RECEIPT_MISSING' });
        }
        if (observationCount === 2) {
          return Object.freeze({
            kind: 'payment_candidate_rejected',
            rejectionProof: Object.freeze({
              source: 'base-sepolia-rpc',
              network: seeded.policyVersion.policy.network,
              transactionId: binding.candidate.transactionId,
              blockHash: `0x${'8a'.repeat(32)}`,
              blockNumber: '1234584',
              transactionStatus: 'reverted',
              confirmations: 3,
              reasonCode: 'TRANSACTION_REVERTED',
              observedAt: NOW,
            }),
          });
        }
        return Object.freeze({
          kind: 'settled_transfer',
          rpcTransferProof: Object.freeze({
            source: 'base-sepolia-rpc',
            network: seeded.policyVersion.policy.network,
            transactionId: binding.candidate.transactionId,
            blockHash: `0x${'8b'.repeat(32)}`,
            blockNumber: '1234585',
            transactionStatus: 'success',
            confirmations: 3,
            transferLogIndex: 1,
            authorizationLogIndex: 2,
            tokenContract: seeded.policyVersion.policy.asset,
            from: WALLET,
            to: seeded.policyVersion.policy.sellers[0].payTo,
            valueAtomic: '50000',
            authorizationNonce: `0x${'11'.repeat(32)}`,
            observedAt: NOW,
          }),
        });
      },
      observeExecution: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
      observeRefund: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
    }),
    now: context.now,
    idFactory: sequenceIds(),
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) { return operation(); },
    }),
    markAuthorityUnhealthy: () => undefined,
  });
  const firstTransactionId = `0x${'8c'.repeat(32)}`;
  const firstPending = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: firstTransactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, seeded.intent.id),
  });
  const rejected = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: firstTransactionId,
    expectedPaymentCaseHash: firstPending.paymentCaseHash,
  });
  const secondTransactionId = `0x${'8d'.repeat(32)}`;
  const secondPending = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: secondTransactionId,
    expectedPaymentCaseHash: rejected.paymentCaseHash,
  });
  const abandoned = await reconciler.abandonCandidate({
    intentId: seeded.intent.id,
    kind: 'payment',
    operatorIdHash: OPERATOR_HASH,
    expectedCaseHash: secondPending.paymentCaseHash,
  });
  const confirmedTransactionId = `0x${'8e'.repeat(32)}`;
  const settled = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: confirmedTransactionId,
    expectedPaymentCaseHash: abandoned.caseHash,
  });
  assert.equal(settled.status, 'execution_unknown');
  assert.deepEqual(context.store.readAll(`SELECT transaction_id, state
    FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid`,
  [seeded.intent.id]).map((row) => ({
    transactionId: row.transaction_id,
    state: row.state,
  })), [
    { transactionId: firstTransactionId, state: 'rejected' },
    { transactionId: secondTransactionId, state: 'abandoned' },
    { transactionId: confirmedTransactionId, state: 'confirmed' },
  ]);

  const report = recoverKernelAuthority(context);
  assert.equal(report.ready, true);
  assert.equal(report.repairedIntentCount, 0);
  assert.equal(context.receipts.assertParity(), true);
});

test('recovery accepts an unused-authorization resolution that rejects a pending candidate', async (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  recoverKernelAuthority(context);
  let observationCount = 0;
  const reconciler = createReconciler({
    store: context.store,
    budgets: context.budgets,
    receipts: context.receipts,
    resolver: Object.freeze({
      observePayment: () => {
        observationCount += 1;
        if (observationCount === 1) {
          return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_RECEIPT_MISSING' });
        }
        return Object.freeze({
          kind: 'authorization_unused_after_expiry',
          network: seeded.policyVersion.policy.network,
          asset: seeded.policyVersion.policy.asset,
          payer: WALLET,
          nonce: `0x${'11'.repeat(32)}`,
          validBefore: '1785502860',
          authorizationState: false,
          observedBlockNumber: '1234586',
          observedBlockHash: `0x${'8f'.repeat(32)}`,
          observedBlockTimestamp: '1785502920',
          confirmations: 3,
        });
      },
      observeExecution: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
      observeRefund: () => Object.freeze({
        kind: 'unknown',
        reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
      }),
    }),
    now: context.now,
    idFactory: sequenceIds(),
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) { return operation(); },
    }),
    markAuthorityUnhealthy: () => undefined,
  });
  const transactionId = `0x${'90'.repeat(32)}`;
  const pending = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: transactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, seeded.intent.id),
  });
  CLOCKS.get(context).value = '2026-07-31T13:02:00.000Z';
  const rejected = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    expectedPaymentCaseHash: pending.paymentCaseHash,
  });
  assert.equal(rejected.status, 'payment_rejected');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?',
    [transactionId],
  ).state, 'rejected');

  const report = recoverKernelAuthority(context);
  assert.equal(report.ready, true);
  assert.equal(report.repairedIntentCount, 0);
  assert.equal(context.receipts.assertParity(), true);
});

test('recovery accepts an exact confirmed payment candidate that owns the settled transaction', async (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  recoverKernelAuthority(context);
  const transactionId = `0x${'82'.repeat(32)}`;
  const resolver = Object.freeze({
    observePayment: (binding) => Object.freeze({
      kind: 'settled_transfer',
      rpcTransferProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: seeded.policyVersion.policy.network,
        transactionId: binding.candidate.transactionId,
        blockHash: `0x${'83'.repeat(32)}`,
        blockNumber: '1234580',
        transactionStatus: 'success',
        confirmations: 3,
        transferLogIndex: 1,
        authorizationLogIndex: 2,
        tokenContract: seeded.policyVersion.policy.asset,
        from: WALLET,
        to: seeded.policyVersion.policy.sellers[0].payTo,
        valueAtomic: '50000',
        authorizationNonce: `0x${'11'.repeat(32)}`,
        observedAt: NOW,
      }),
    }),
    observeExecution: (binding) => {
      const attestation = Object.freeze({
        schemaVersion: 1,
        domain: 'wallet-kernel.execution.v1',
        network: seeded.policyVersion.policy.network,
        sellerOrigin: SELLER,
        intentHash: binding.intentHash,
        transactionId: binding.transactionId,
        outcome: 'succeeded',
        httpStatus: 200,
        responseHash: sha256(Buffer.from('recovered execution evidence')),
        issuedAt: '2026-07-31T11:59:00.000Z',
        expiresAt: '2026-07-31T12:05:00.000Z',
        signer: seeded.policyVersion.policy.sellers[0].executionSigner,
      });
      return Object.freeze({
        kind: 'execution_attested',
        attestation,
        attestationHash: sha256(canonicalJson(attestation)),
      });
    },
    observeRefund: () => Object.freeze({
      kind: 'unknown',
      reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED',
    }),
  });
  const reconciler = createReconciler({
    store: context.store,
    budgets: context.budgets,
    receipts: context.receipts,
    resolver,
    now: context.now,
    idFactory: sequenceIds(),
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) { return operation(); },
    }),
    markAuthorityUnhealthy: () => undefined,
  });
  const settled = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId: transactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, seeded.intent.id),
  });
  assert.equal(settled.status, 'execution_unknown');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_reconciliation_candidates WHERE transaction_id = ?', [transactionId],
  ).state, 'confirmed');

  const report = recoverKernelAuthority(context);
  assert.equal(report.ready, true);
  assert.equal(report.repairedIntentCount, 0);
  assert.equal(context.receipts.assertParity(), true);

  const execution = await reconciler.reconcileExecution({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    expectedExecutionCaseHash: settled.executionCaseHash,
  });
  assert.equal(execution.status, 'completed');
  const completedReport = recoverKernelAuthority(context);
  assert.equal(completedReport.ready, true);
  assert.equal(completedReport.repairedIntentCount, 0);
  assert.equal(context.receipts.assertParity(), true);

  const paymentReconciliation = context.store.readOne(`SELECT * FROM reconciliations
    WHERE intent_id = ? AND kind = 'payment' AND outcome = 'settled'`, [seeded.intent.id]);
  const originalExecutionMetadata = canonicalJson({
    reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    reconciliationEvidenceId: paymentReconciliation.id,
  });
  const executionRecordedEvent = context.store.events().find((event) => (
    event.entity_type === 'execution_outcome'
      && event.entity_id === seeded.intent.id
      && event.event_type === 'execution.recorded'
  ));
  assert.equal(
    JSON.parse(executionRecordedEvent.data_json).metadataHash,
    sha256(originalExecutionMetadata),
  );

  const substitutedCaseHash = sha256('substituted execution case');
  rewriteAndResealEvents(context.store, (db) => {
    const row = db.prepare(`SELECT * FROM events
      WHERE entity_type = 'reconciliation' AND event_type = 'reconciliation.recorded'
        AND json_extract(data_json, '$.kind') = 'execution'`).get();
    const data = JSON.parse(row.data_json);
    data.requestCaseHash = substitutedCaseHash;
    data.observedCaseHash = substitutedCaseHash;
    db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
      .run(canonicalJson(data), row.sequence);
  });
  assert.throws(
    () => recoverKernelAuthority(context),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
  rewriteAndResealEvents(context.store, (db) => {
    const row = db.prepare(`SELECT * FROM events
      WHERE entity_type = 'reconciliation' AND event_type = 'reconciliation.recorded'
        AND json_extract(data_json, '$.kind') = 'execution'`).get();
    const data = JSON.parse(row.data_json);
    data.requestCaseHash = settled.executionCaseHash;
    data.observedCaseHash = settled.executionCaseHash;
    db.prepare('UPDATE events SET data_json = ? WHERE sequence = ?')
      .run(canonicalJson(data), row.sequence);
  });
  assert.equal(recoverKernelAuthority(context).ready, true);

  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`UPDATE payment_reconciliation_candidates
      SET updated_at = '2026-07-31T12:00:01.000Z'
      WHERE transaction_id = ?`).run(transactionId);
  }));
  assert.throws(
    () => recoverKernelAuthority(context),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
});

test('recovery audits failed execution and confirmed refund reconciliation histories', async (t) => {
  const context = setup(t);
  const seeded = seedPaymentCrashGap(context, 'retrying');
  recoverKernelAuthority(context);
  const seller = seeded.policyVersion.policy.sellers[0];
  const paymentTransactionId = `0x${'84'.repeat(32)}`;
  const rejectedRefundTransactionId = `0x${'85'.repeat(32)}`;
  const abandonedRefundTransactionId = `0x${'91'.repeat(32)}`;
  const refundTransactionId = `0x${'92'.repeat(32)}`;
  let refundObservationCount = 0;
  const resolver = Object.freeze({
    observePayment: (binding) => Object.freeze({
      kind: 'settled_transfer',
      rpcTransferProof: Object.freeze({
        source: 'base-sepolia-rpc',
        network: seeded.policyVersion.policy.network,
        transactionId: binding.candidate.transactionId,
        blockHash: `0x${'86'.repeat(32)}`,
        blockNumber: '1234581',
        transactionStatus: 'success',
        confirmations: 3,
        transferLogIndex: 1,
        authorizationLogIndex: 2,
        tokenContract: seeded.policyVersion.policy.asset,
        from: WALLET,
        to: seller.payTo,
        valueAtomic: '50000',
        authorizationNonce: `0x${'11'.repeat(32)}`,
        observedAt: NOW,
      }),
    }),
    observeExecution: (binding) => {
      const attestation = Object.freeze({
        schemaVersion: 1,
        domain: 'wallet-kernel.execution.v1',
        network: seeded.policyVersion.policy.network,
        sellerOrigin: SELLER,
        intentHash: binding.intentHash,
        transactionId: binding.transactionId,
        outcome: 'failed',
        httpStatus: 503,
        responseHash: null,
        issuedAt: '2026-07-31T11:59:00.000Z',
        expiresAt: '2026-07-31T12:05:00.000Z',
        signer: seller.executionSigner,
      });
      return Object.freeze({
        kind: 'execution_attested',
        attestation,
        attestationHash: sha256(canonicalJson(attestation)),
      });
    },
    observeRefund: (binding) => {
      refundObservationCount += 1;
      if (refundObservationCount === 1 || refundObservationCount === 3) {
        return Object.freeze({
          kind: 'unknown',
          reasonCode: 'RPC_RECEIPT_MISSING',
        });
      }
      if (refundObservationCount === 2) {
        return Object.freeze({
          kind: 'refund_candidate_rejected',
          rejectionProof: Object.freeze({
            source: 'base-sepolia-rpc',
            network: seeded.policyVersion.policy.network,
            transactionId: binding.refundTransactionId,
            blockHash: `0x${'93'.repeat(32)}`,
            blockNumber: '1234582',
            transactionStatus: 'reverted',
            confirmations: 3,
            reasonCode: 'TRANSACTION_REVERTED',
            observedAt: NOW,
          }),
        });
      }
      const attestation = Object.freeze({
        schemaVersion: 1,
        domain: 'wallet-kernel.refund.v1',
        network: seeded.policyVersion.policy.network,
        sellerOrigin: SELLER,
        intentHash: binding.intentHash,
        originalTransactionId: binding.originalTransactionId,
        refundTransactionId: binding.refundTransactionId,
        asset: seeded.policyVersion.policy.asset,
        originalPayer: WALLET,
        originalPayee: seller.payTo,
        refundSource: seller.refundSource,
        amountAtomic: '50000',
        issuedAt: '2026-07-31T11:59:00.000Z',
        expiresAt: '2026-07-31T12:05:00.000Z',
        signer: seller.refundSigner,
      });
      return Object.freeze({
        kind: 'refund_attested_and_confirmed',
        attestation,
        attestationHash: sha256(canonicalJson(attestation)),
        rpcTransferProof: Object.freeze({
          source: 'base-sepolia-rpc',
          network: seeded.policyVersion.policy.network,
          transactionId: binding.refundTransactionId,
          blockHash: `0x${'87'.repeat(32)}`,
          blockNumber: '1234582',
          transactionStatus: 'success',
          confirmations: 3,
          transferLogIndex: 3,
          tokenContract: seeded.policyVersion.policy.asset,
          from: seller.refundSource,
          to: WALLET,
          valueAtomic: '50000',
          observedAt: NOW,
        }),
      });
    },
  });
  const reconciler = createReconciler({
    store: context.store,
    budgets: context.budgets,
    receipts: context.receipts,
    resolver,
    now: context.now,
    idFactory: sequenceIds(),
    authorityMutationCoordinator: Object.freeze({
      runExclusive(operation) { return operation(); },
    }),
    markAuthorityUnhealthy: () => undefined,
  });
  const payment = await reconciler.reconcilePayment({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    paymentTransactionId,
    expectedPaymentCaseHash: currentPaymentCaseHash(context.store, seeded.intent.id),
  });
  const execution = await reconciler.reconcileExecution({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    expectedExecutionCaseHash: payment.executionCaseHash,
  });
  const firstPending = await reconciler.observeRefund({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    refundTransactionId: rejectedRefundTransactionId,
    expectedRefundCaseHash: execution.refundCaseHash,
  });
  const rejected = await reconciler.observeRefund({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    refundTransactionId: rejectedRefundTransactionId,
    expectedRefundCaseHash: firstPending.refundCaseHash,
  });
  const secondPending = await reconciler.observeRefund({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    refundTransactionId: abandonedRefundTransactionId,
    expectedRefundCaseHash: rejected.refundCaseHash,
  });
  const abandoned = await reconciler.abandonCandidate({
    intentId: seeded.intent.id,
    kind: 'refund-observation',
    operatorIdHash: OPERATOR_HASH,
    expectedCaseHash: secondPending.refundCaseHash,
  });
  const refund = await reconciler.observeRefund({
    intentId: seeded.intent.id,
    operatorIdHash: OPERATOR_HASH,
    expectedIntentHash: seeded.intent.intentHash,
    refundTransactionId,
    expectedRefundCaseHash: abandoned.caseHash,
  });
  assert.equal(refund.status, 'refunded');
  assert.deepEqual(context.store.readAll(`SELECT refund_transaction_id, state
    FROM refunds WHERE intent_id = ? ORDER BY rowid`, [seeded.intent.id]).map((row) => ({
    transactionId: row.refund_transaction_id,
    state: row.state,
  })), [
    { transactionId: rejectedRefundTransactionId, state: 'rejected' },
    { transactionId: abandonedRefundTransactionId, state: 'abandoned' },
    { transactionId: refundTransactionId, state: 'confirmed' },
  ]);

  const report = recoverKernelAuthority(context);
  assert.equal(report.ready, true);
  assert.equal(report.repairedIntentCount, 0);
  assert.equal(context.receipts.assertParity(), true);

  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    const row = db.prepare(`SELECT * FROM reconciliations
      WHERE intent_id = ? AND kind = 'refund' AND outcome = 'refund_confirmed'`)
      .get(seeded.intent.id);
    const evidence = JSON.parse(row.evidence_json);
    evidence.rpcProofHash = sha256('substituted refund RPC proof');
    db.prepare('UPDATE reconciliations SET evidence_json = ? WHERE id = ?')
      .run(canonicalJson(evidence), row.id);
  }));
  assert.throws(
    () => recoverKernelAuthority(context),
    (error) => error?.code === 'AUTHORITY_SEMANTIC_CORRUPTION',
  );
});

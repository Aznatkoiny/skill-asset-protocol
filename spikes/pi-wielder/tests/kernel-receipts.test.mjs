import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { sha256 } from '../src/kernel/canonical.mjs';
import {
  canonicalJson,
  createReceiptSigner,
  loadOrCreateReceiptSigner,
  verifySignedReceipt,
} from '../src/kernel/receipt-signing.mjs';
import { createSignedReceiptRepository } from '../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:01.000Z';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';

function authority(t, prefix = 'wallet-kernel-receipts-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    databasePath: path.join(directory, 'kernel.sqlite'),
    directory,
    keyPath: path.join(directory, 'receipt-key.pem'),
    pathTrust,
  };
}

function receiptFixture() {
  return {
    schemaVersion: 1,
    receiptId: 'receipt-1',
    revision: 1,
    issuedAt: NOW,
    intent: {
      id: 'intent-1',
      requestId: 'request-1',
      intentHash: sha256(canonicalJson({ fixture: 'intent-1' })),
      sessionId: 'session-1',
      sellerOrigin: SELLER,
      resourcePath: '/paid/infer',
      purposeLabel: 'skill.invoke',
    },
    outcome: { status: 'completed', reasonCode: 'PAYMENT_SETTLED' },
    policy: { versionId: 'policy-1', decision: 'allow', reasonCode: 'WITHIN_AUTO_LIMIT' },
    approval: { state: 'not_required', operatorIdHash: null },
    payment: {
      state: 'settled',
      amountAtomic: '50000',
      network: NETWORK,
      asset: ASSET,
      payTo: PAY_TO,
      transactionId: `0x${'ab'.repeat(32)}`,
    },
    execution: {
      state: 'succeeded',
      httpStatus: 200,
      responseHash: sha256(Buffer.from('{"ok":true}', 'utf8')),
    },
    budget: { disposition: 'committed', amountAtomic: '50000' },
    reconciliation: null,
    refund: null,
    supersedesReceiptHash: null,
  };
}

function challengeProjection(amountAtomic = '50000') {
  return {
    x402Version: 2,
    resource: {
      urlHash: sha256(`${SELLER}/paid/infer`),
      description: 'not included in a buyer receipt',
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

function seedBaseAuthority(store) {
  store.transaction((token) => store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO policy_versions
      (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
      VALUES ('policy-1', 1, '{}', ?, NULL, ?)`).run(sha256('policy-1'), NOW);
    db.prepare(`INSERT INTO agent_enrollments
      (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
       state, enrolled_by_operator_hash, enrolled_at)
      VALUES ('agent-1', ?, ?, '501', '20', 'active', ?, ?)`).run(
      sha256('credential-1'), sha256('enrollment-1'), sha256('operator-1'), NOW,
    );
    db.prepare(`INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
      VALUES ('session-1', 'pi:agent-1', ?, 'policy-1', 'open', ?, NULL)`).run(WALLET, NOW);
  }));
}

function setupRepository(t, {
  clock = { value: NOW },
  fileAuthority = null,
  signer = createReceiptSigner(),
  seedAuthority = true,
} = {}) {
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
  let receiptId = 0;
  const receipts = createSignedReceiptRepository({
    store,
    signer,
    idFactory: () => `receipt-${++receiptId}`,
    now: () => clock.value,
  });
  if (seedAuthority) seedBaseAuthority(store);
  return { clock, receipts, signer, store };
}

function seedIntent(store, {
  id = 'intent-1',
  requestId = 'request-1',
  state = 'terminal',
  challenge = null,
} = {}) {
  const intentHash = sha256(canonicalJson({ fixture: id }));
  const challengeJson = challenge === null ? null : canonicalJson(challenge);
  const challengeHash = challenge === null ? null : sha256(challengeJson);
  store.transaction((token) => store.within(token, ({ db }) => db.prepare(`INSERT INTO spend_intents
    (id, request_id, session_id, enrollment_hash, route_id, method, request_url_hash,
     seller_origin, resource_path, body_hash, header_allowlist_hash, ordinary_fingerprint,
     purpose_label, correlation_id, idempotency_key, wallet_address, intent_hash,
     challenge_projection_json, challenge_hash, challenge_received_at, state, created_at, updated_at)
    VALUES (?, ?, 'session-1', ?, 'paid-infer', 'POST', ?, ?, '/paid/infer', ?, ?, ?,
      'skill.invoke', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(
      id,
      requestId,
      sha256('enrollment-1'),
      sha256(`${id}:url`),
      SELLER,
      sha256(`${id}:body`),
      sha256(`${id}:headers`),
      sha256(`${id}:ordinary`),
      `correlation-${id}`,
      `idempotency-${id}`,
      WALLET,
      intentHash,
      challengeJson,
      challengeHash,
      challenge === null ? null : NOW,
      state,
      NOW,
      NOW,
    )));
  return { challengeHash, id, intentHash, requestId };
}

function seedSettledSuccess(context) {
  const challenge = challengeProjection();
  const intent = seedIntent(context.store, { challenge });
  const responseHash = sha256(Buffer.from('{"ok":true}', 'utf8'));
  const paymentHeader = 'settled-fixture-payment-header';
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO policy_decisions
      (intent_id, policy_version_id, decision, reason_code, challenge_hash,
       accepted_index, quote_id, amount_ceiling_atomic, decided_at)
      VALUES (?, 'policy-1', 'allow', 'WITHIN_AUTO_LIMIT', ?, 0, 'quote-1', '50000', ?)`)
      .run(intent.id, intent.challengeHash, NOW);
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, signing_claimed_at, signed_at, retry_started_at,
       settlement_json, transaction_id, settled_at, created_at, updated_at)
      VALUES ('payment-1', ?, 'settled', ?, 0, ?, ?, ?, 'quote-1', ?, ?, ?, ?, ?, ?,
        '{}', ?, ?, ?, ?)`)
      .run(
        intent.id,
        canonicalJson(challenge),
        canonicalJson({ paymentSignature: 'settled-fixture-signature' }),
        paymentHeader,
        sha256(paymentHeader),
        `0x${'11'.repeat(32)}`,
        '1785502800',
        '1785502860',
        NOW,
        NOW,
        NOW,
        `0x${'ab'.repeat(32)}`,
        NOW,
        NOW,
        NOW,
      );
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'succeeded', 200, ?, '{}', ?)`).run(intent.id, responseHash, NOW);
    db.prepare(`INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, committed_at, updated_at)
      VALUES (?, 'session-1', ?, '0', '50000', '0', '0', 'committed', ?, ?)`)
      .run(intent.id, SELLER, NOW, NOW);
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'completed', 'PAYMENT_SETTLED', 1, ?)`).run(intent.id, NOW);
  }));
  return { ...intent, responseHash };
}

function seedScenario(context, scenario) {
  const needsChallenge = Boolean(
    scenario.policyDecision || scenario.paymentState || scenario.approvalState,
  );
  const challenge = needsChallenge ? challengeProjection() : null;
  const intent = seedIntent(context.store, {
    id: scenario.intentId ?? 'intent-1',
    requestId: scenario.requestId ?? `request-${scenario.intentId ?? '1'}`,
    challenge,
    state: scenario.intentState ?? 'terminal',
  });
  const operatorIdHash = sha256('authenticated-operator');
  context.store.transaction((token) => context.store.within(token, ({ db, appendEvent }) => {
    if (scenario.policyDecision) {
      db.prepare(`INSERT INTO policy_decisions
        (intent_id, policy_version_id, decision, reason_code, challenge_hash,
         accepted_index, quote_id, amount_ceiling_atomic, decided_at)
        VALUES (?, 'policy-1', ?, ?, ?, 0, 'quote-1', '50000', ?)`)
        .run(
          intent.id,
          scenario.policyDecision,
          scenario.policyReason ?? 'WITHIN_AUTO_LIMIT',
          intent.challengeHash,
          NOW,
        );
    }
    if (scenario.approvalState) {
      db.prepare(`INSERT INTO approvals
        (id, intent_id, decision, operator_id_hash, intent_hash, challenge_hash,
         quote_id, accepted_index, amount_ceiling_atomic, wallet_address,
         policy_version_id, expires_at, reason_code, decided_at, consumed_at)
        VALUES ('approval-1', ?, ?, ?, ?, ?, 'quote-1', 0, '50000', ?,
          'policy-1', '2026-07-31T12:05:00.000Z', ?, ?, NULL)`)
        .run(
          intent.id,
          scenario.approvalState,
          scenario.operatorHash === false ? null : operatorIdHash,
          intent.intentHash,
          intent.challengeHash,
          WALLET,
          scenario.approvalReason ?? scenario.reasonCode,
          ['pending'].includes(scenario.approvalState) ? null : NOW,
        );
    }
    if (scenario.paymentState) {
      const transactionId = scenario.paymentState === 'settled'
        ? `0x${'ab'.repeat(32)}`
        : null;
      const claimOnly = scenario.claimOnly === true;
      const hasSignedPayload = scenario.unsignedAttempt !== true
        && scenario.paymentState !== 'reserved'
        && scenario.paymentState !== 'signing';
      const hasSigningClaim = claimOnly || hasSignedPayload;
      const hasRetry = ['retrying', 'settled'].includes(scenario.paymentState);
      const settlementJson = scenario.paymentState === 'settled' ? '{}' : null;
      const paymentReasonCode = scenario.paymentReasonCode
        ?? (['unresolved', 'rejected'].includes(scenario.paymentState)
          ? scenario.reasonCode
          : null);
      db.prepare(`INSERT INTO payment_attempts
        (id, intent_id, state, payment_required_projection_json, accepted_index,
         payment_payload_json, payment_header, payment_hash, quote_id, transaction_id,
         reason_code, nonce, valid_after, valid_before, signing_claimed_at, signed_at,
         retry_started_at, settlement_json, settled_at, created_at, updated_at)
        VALUES ('payment-1', ?, ?, ?, 0, ?, ?, ?, 'quote-1', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(
          intent.id,
          scenario.paymentState,
          canonicalJson(challenge),
          hasSignedPayload ? canonicalJson({
            paymentSignature: 'RAW_PAYMENT_SIGNATURE_SENTINEL',
            cdpCredential: 'RAW_CDP_CREDENTIAL_SENTINEL',
          }) : null,
          hasSignedPayload ? 'RAW_PAYMENT_HEADER_SENTINEL' : null,
          hasSignedPayload ? sha256('RAW_PAYMENT_HEADER_SENTINEL') : null,
          transactionId,
          paymentReasonCode,
          hasSigningClaim ? `0x${'11'.repeat(32)}` : null,
          hasSigningClaim ? '1785502800' : null,
          hasSigningClaim ? '1785502860' : null,
          hasSigningClaim ? NOW : null,
          hasSignedPayload ? NOW : null,
          hasRetry ? NOW : null,
          settlementJson,
          transactionId === null ? null : NOW,
          NOW,
          NOW,
        );
    }
    if (scenario.executionState) {
      const httpStatus = scenario.executionState === 'succeeded'
        ? 200
        : scenario.executionState === 'failed'
          ? (Object.hasOwn(scenario, 'httpStatus') ? scenario.httpStatus : 503)
          : (Object.hasOwn(scenario, 'httpStatus') ? scenario.httpStatus : null);
      const responseHash = Object.hasOwn(scenario, 'executionResponseHash')
        ? scenario.executionResponseHash
        : scenario.executionState === 'unknown'
          ? null
          : sha256(Buffer.from(`response:${scenario.name}`, 'utf8'));
      db.prepare(`INSERT INTO execution_outcomes
        (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
        VALUES (?, ?, ?, ?, ?, ?)`)
        .run(
          intent.id,
          scenario.executionState,
          httpStatus,
          responseHash,
          canonicalJson({ providerException: 'RAW_PROVIDER_EXCEPTION_SENTINEL' }),
          NOW,
        );
    }
    if (scenario.budgetState) {
      const values = {
        reserved: ['50000', '0', '0', '0'],
        committed: ['0', '50000', '0', '0'],
        released: ['0', '0', '50000', '0'],
        unresolved: ['0', '0', '0', '50000'],
      }[scenario.budgetState];
      db.prepare(`INSERT INTO budget_reservations
        (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
         released_atomic, unresolved_atomic, state, committed_at, updated_at)
        VALUES (?, 'session-1', ?, ?, ?, ?, ?, ?, ?, ?)`)
        .run(
          intent.id,
          SELLER,
          ...values,
          scenario.budgetState,
          scenario.budgetState === 'committed' ? NOW : null,
          NOW,
        );
    }
    if (scenario.refundState) {
      db.prepare(`INSERT INTO refunds
        (id, intent_id, original_transaction_id, amount_atomic, state, evidence_json,
         refund_transaction_id, created_at, updated_at)
        VALUES ('refund-1', ?, ?, '50000', ?, ?, ?, ?, ?)`)
        .run(
          intent.id,
          `0x${'ab'.repeat(32)}`,
          scenario.refundState,
          canonicalJson({ providerException: 'RAW_REFUND_EVIDENCE_SENTINEL' }),
          scenario.refundState === 'confirmed' ? `0x${'cd'.repeat(32)}` : null,
          NOW,
          NOW,
        );
    }
    if (scenario.reconciliationKind) {
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-1', ?, ?, ?, ?, ?, ?)`)
        .run(
          intent.id,
          scenario.reconciliationKind,
          scenario.reconciliationOutcome,
          canonicalJson({ providerException: 'RAW_RECONCILIATION_EVIDENCE_SENTINEL' }),
          operatorIdHash,
          NOW,
        );
    }
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, ?, ?, 1, ?)`).run(
      intent.id,
      scenario.status,
      scenario.reasonCode,
      NOW,
    );
    appendEvent({
      entityType: 'buyer_outcome',
      entityId: intent.id,
      eventType: 'buyer_outcome.fixture_recorded',
      data: {
        body: 'RAW_BODY_SENTINEL',
        prompt: 'RAW_PROMPT_SENTINEL',
        operatorToken: 'RAW_OPERATOR_TOKEN_SENTINEL',
        stack: 'RAW_STACK_SENTINEL',
        sellerText: 'RAW_SELLER_ERROR_SENTINEL',
        paymentHeader: 'RAW_PAYMENT_HEADER_SENTINEL',
      },
    });
  }));
  return { intent, operatorIdHash };
}

function signReceipt(signer, receipt) {
  const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
  return {
    receipt,
    receiptHash,
    signature: signer.signHash(receiptHash),
    algorithm: signer.algorithm,
    keyId: signer.keyId,
  };
}

function signedRecordForReceipt(signer, receipt) {
  return {
    id: receipt.receiptId,
    intentId: receipt.intent.id,
    revision: receipt.revision,
    ...signReceipt(signer, receipt),
    supersedesReceiptHash: receipt.supersedesReceiptHash,
    createdAt: receipt.issuedAt,
  };
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (code === 0) resolve(stdout.trim());
      else reject(new Error(`receipt-key worker exited ${code ?? signal}: ${stderr}`));
    });
  });
}

test('generic Ed25519 receipts verify with public trust and reject every mutation', () => {
  const signer = createReceiptSigner();
  const receipt = receiptFixture();
  const bundle = signReceipt(signer, receipt);
  const trust = { publicKeyPem: signer.publicKeyPem, keyId: signer.keyId };
  assert.equal(verifySignedReceipt(bundle, trust), true);

  for (const mutate of [
    (copy) => { copy.receipt.outcome.reasonCode = 'MUTATED'; },
    (copy) => { copy.signature = `${copy.signature.slice(0, -2)}AA`; },
    (copy) => { copy.receipt.unexpected = true; },
    (copy) => { copy.receipt.payment.amountAtomic = '050000'; },
  ]) {
    const copy = structuredClone(bundle);
    mutate(copy);
    assert.equal(verifySignedReceipt(copy, trust), false);
  }

  const wrong = createReceiptSigner();
  assert.equal(verifySignedReceipt(bundle, {
    publicKeyPem: wrong.publicKeyPem,
    keyId: wrong.keyId,
  }), false);
});

test('persistent receipt key initialization is atomic, stable, and fail-closed', async (t) => {
  const fixture = authority(t);
  const first = loadOrCreateReceiptSigner(fixture.keyPath, { pathTrust: fixture.pathTrust });
  const reopened = loadOrCreateReceiptSigner(fixture.keyPath, { pathTrust: fixture.pathTrust });
  assert.equal(first.keyId, reopened.keyId);
  assert.equal(first.persistent, true);
  assert.equal(fs.statSync(fixture.keyPath).mode & 0o777, 0o600);

  const rsaPrivateKey = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
    .privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  for (const invalid of [
    '',
    'not a key\n',
    `${fs.readFileSync(fixture.keyPath, 'utf8')}not-whitespace`,
    rsaPrivateKey,
  ]) {
    const invalidFixture = authority(t, 'wallet-kernel-invalid-receipt-key-');
    fs.writeFileSync(invalidFixture.keyPath, invalid, { mode: 0o600 });
    assert.throws(
      () => loadOrCreateReceiptSigner(invalidFixture.keyPath, {
        pathTrust: invalidFixture.pathTrust,
      }),
      /empty|invalid|trailing|Ed25519|private key/i,
    );
    assert.equal(fs.readFileSync(invalidFixture.keyPath, 'utf8'), invalid);
  }

  const raced = authority(t, 'wallet-kernel-receipt-key-race-');
  const moduleUrl = new URL('../src/kernel/receipt-signing.mjs', import.meta.url).href;
  const worker = [
    `import { loadOrCreateReceiptSigner } from ${JSON.stringify(moduleUrl)};`,
    `const pathTrust = Object.freeze(${JSON.stringify(raced.pathTrust)});`,
    `process.stdout.write(loadOrCreateReceiptSigner(${JSON.stringify(raced.keyPath)}, { pathTrust }).keyId);`,
  ].join('\n');
  const children = [0, 1].map(() => spawn(process.execPath, [
    '--input-type=module', '-e', worker,
  ], { stdio: ['ignore', 'pipe', 'pipe'] }));
  const keyIds = await Promise.all(children.map(waitForExit));
  assert.equal(keyIds[0], keyIds[1]);
  assert.equal(loadOrCreateReceiptSigner(raced.keyPath, {
    pathTrust: raced.pathTrust,
  }).keyId, keyIds[0]);
  assert.deepEqual(
    fs.readdirSync(raced.directory).filter((name) => name.includes('.tmp-')),
    [],
  );
});

test('repository signs the exact closed terminal projection and exposes verified immutable records', (t) => {
  const context = setupRepository(t);
  seedSettledSuccess(context);

  assert.equal(Object.isFrozen(context.receipts), true);
  assert.deepEqual(Object.keys(context.receipts), [
    'issueForTerminal',
    'issueRevisionForTerminal',
    'issueMissingTerminalReceipts',
    'assertParity',
    'assertParityInTransaction',
    'assertRecoverableParityInTransaction',
    'latest',
    'list',
    'verify',
  ]);

  const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
  assert.deepEqual(record.receipt, receiptFixture());
  assert.equal(record.id, 'receipt-1');
  assert.equal(record.intentId, 'intent-1');
  assert.equal(record.revision, 1);
  assert.equal(context.receipts.verify(record), true);
  assert.equal(Object.isFrozen(record), true);
  assert.equal(Object.isFrozen(record.receipt), true);
  assert.deepEqual(context.receipts.latest('intent-1'), record);
  assert.deepEqual(context.receipts.list({ sessionId: 'session-1', limit: 10 }), [record]);
  assert.deepEqual(context.receipts.issueForTerminal({ intentId: 'intent-1' }), record);
  assert.equal(context.store.events().filter(
    (event) => event.event_type === 'receipt.issued',
  ).length, 1);

  for (const mutate of [
    (copy) => { copy.receipt.outcome.status = 'refunded'; },
    (copy) => { copy.receipt.payment.amountAtomic = '050000'; },
    (copy) => { copy.receipt.secret = 'raw-provider-output'; },
    (copy) => { copy.signature = `${copy.signature.slice(0, -2)}AA`; },
  ]) {
    const changed = structuredClone(record);
    mutate(changed);
    assert.equal(context.receipts.verify(changed), false);
  }

  const maliciousReceipt = { ...structuredClone(record.receipt), secret: 'signed-but-forbidden' };
  const malicious = {
    ...record,
    ...signReceipt(context.signer, maliciousReceipt),
    receipt: maliciousReceipt,
  };
  assert.equal(context.receipts.verify(malicious), false);
});

test('every closed terminal buyer outcome receives one redacted authoritative receipt', async (t) => {
  const scenarios = [
    {
      name: 'ordinary non-402 success', status: 'completed', reasonCode: 'ORDINARY_SUCCESS',
      executionState: 'succeeded', expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'ordinary non-402 HTTP failure', status: 'upstream_failed',
      reasonCode: 'ORDINARY_HTTP_FAILURE', executionState: 'failed', httpStatus: 503,
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'unpaid transport timeout', status: 'upstream_failed',
      reasonCode: 'UPSTREAM_TRANSPORT_FAILURE', executionState: 'unknown',
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'malformed payment challenge', status: 'payment_denied',
      reasonCode: 'PAYMENT_CHALLENGE_MALFORMED', expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'oversized payment challenge', status: 'payment_denied',
      reasonCode: 'PAYMENT_CHALLENGE_OVERSIZED', expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'expired payment challenge', status: 'payment_denied',
      reasonCode: 'PAYMENT_CHALLENGE_EXPIRED', expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'policy denied', status: 'payment_denied', reasonCode: 'POLICY_DENIED',
      policyDecision: 'deny', policyReason: 'POLICY_DENIED', expectedPayment: 'none',
      expectedBudget: null,
    },
    {
      name: 'approval denied', status: 'payment_denied', reasonCode: 'OPERATOR_DENIED',
      policyDecision: 'approval_required', policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'denied', expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'approval expired', status: 'payment_denied', reasonCode: 'APPROVAL_EXPIRED',
      policyDecision: 'approval_required', policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'expired', operatorHash: false, expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'approval challenge changed', status: 'payment_denied',
      reasonCode: 'APPROVAL_CHALLENGE_CHANGED', policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED', approvalState: 'cancelled',
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'policy transition cancels unsigned work', status: 'payment_denied',
      reasonCode: 'POLICY_SUPERSEDED', policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED', approvalState: 'cancelled',
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'guarded session close cancels unsigned work', status: 'payment_denied',
      reasonCode: 'SESSION_CLOSED', policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED', approvalState: 'cancelled',
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'unsigned signing failure', status: 'payment_failed', reasonCode: 'SIGNER_REJECTED',
      policyDecision: 'allow', paymentState: 'rejected', unsignedAttempt: true,
      budgetState: 'released',
      expectedPayment: 'not_signed', expectedBudget: 'released',
    },
    {
      name: 'typed pre-signer rejection', status: 'payment_failed',
      reasonCode: 'WALLET_PRE_SIGN_REJECTED', policyDecision: 'allow',
      paymentState: 'rejected', unsignedAttempt: true, claimOnly: true,
      budgetState: 'released', expectedPayment: 'not_signed', expectedBudget: 'released',
    },
    {
      name: 'nonce collision releases unsigned work', status: 'payment_failed',
      reasonCode: 'NONCE_COLLISION', policyDecision: 'allow', paymentState: 'rejected',
      unsignedAttempt: true, budgetState: 'released', expectedPayment: 'not_signed',
      expectedBudget: 'released',
    },
    {
      name: 'revocation releases unsigned work', status: 'payment_denied',
      reasonCode: 'AGENT_REVOKED', policyDecision: 'allow', paymentState: 'rejected',
      unsignedAttempt: true, budgetState: 'released', expectedPayment: 'not_signed',
      expectedBudget: 'released',
    },
    {
      name: 'wallet blocker releases unsigned work', status: 'payment_denied',
      reasonCode: 'WALLET_RECOVERY_REQUIRED', policyDecision: 'allow',
      paymentState: 'rejected', unsignedAttempt: true, budgetState: 'released',
      expectedPayment: 'not_signed', expectedBudget: 'released',
    },
    {
      name: 'signed payment unresolved', status: 'payment_unresolved',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS', policyDecision: 'allow',
      paymentState: 'unresolved', budgetState: 'unresolved', intentState: 'unresolved',
      expectedPayment: 'unresolved', expectedBudget: 'unresolved',
    },
    {
      name: 'ambiguous wallet signature', status: 'payment_unresolved',
      reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS', policyDecision: 'allow',
      paymentState: 'unresolved', budgetState: 'unresolved', intentState: 'unresolved',
      expectedPayment: 'unresolved', expectedBudget: 'unresolved',
    },
    {
      name: 'recovery abandons captured unsigned work', status: 'upstream_failed',
      reasonCode: 'RECOVERY_ABANDONED_UNSIGNED', expectedPayment: 'none',
      expectedBudget: null,
    },
    {
      name: 'recovery abandons challenged unsigned work', status: 'payment_failed',
      reasonCode: 'RECOVERY_ABANDONED_UNSIGNED', policyDecision: 'allow',
      expectedPayment: 'none', expectedBudget: null,
    },
    {
      name: 'recovery retains ambiguous payment hold', status: 'payment_unresolved',
      reasonCode: 'RECOVERY_PAYMENT_AMBIGUOUS', policyDecision: 'allow',
      paymentState: 'unresolved', budgetState: 'unresolved', intentState: 'unresolved',
      expectedPayment: 'unresolved', expectedBudget: 'unresolved',
    },
    {
      name: 'payment settled and execution succeeded', status: 'completed',
      reasonCode: 'PAYMENT_SETTLED', policyDecision: 'allow', paymentState: 'settled',
      executionState: 'succeeded', budgetState: 'committed', expectedPayment: 'settled',
      expectedBudget: 'committed',
    },
    {
      name: 'payment settled and execution failed', status: 'execution_failed',
      reasonCode: 'UPSTREAM_HTTP_FAILURE', policyDecision: 'allow', paymentState: 'settled',
      executionState: 'failed', budgetState: 'committed', expectedPayment: 'settled',
      expectedBudget: 'committed', refundState: 'pending',
    },
    {
      name: 'payment settled and execution unknown', status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS', policyDecision: 'allow', paymentState: 'settled',
      executionState: 'unknown', budgetState: 'committed', expectedPayment: 'settled',
      expectedBudget: 'committed',
    },
    {
      name: 'recovery supplies missing execution as unknown', status: 'execution_unknown',
      reasonCode: 'RECOVERY_EXECUTION_MISSING', policyDecision: 'allow',
      paymentState: 'settled', executionState: 'unknown', budgetState: 'committed',
      expectedPayment: 'settled', expectedBudget: 'committed',
    },
    {
      name: 'refund unresolved', status: 'execution_failed', reasonCode: 'REFUND_UNRESOLVED',
      policyDecision: 'allow', paymentState: 'settled', executionState: 'failed',
      budgetState: 'committed', refundState: 'unresolved', expectedPayment: 'settled',
      expectedBudget: 'committed',
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.name, (st) => {
      const context = setupRepository(st);
      const { operatorIdHash } = seedScenario(context, scenario);
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(record.receipt.outcome.status, scenario.status);
      assert.equal(record.receipt.outcome.reasonCode, scenario.reasonCode);
      assert.equal(record.receipt.payment.state, scenario.expectedPayment);
      assert.equal(record.receipt.budget?.disposition ?? null, scenario.expectedBudget);
      assert.equal(record.receipt.execution.state, scenario.executionState ?? 'none');
      assert.equal(record.receipt.policy?.decision ?? null, scenario.policyDecision ?? null);
      assert.equal(record.receipt.approval.state, scenario.approvalState ?? 'not_required');
      if (scenario.approvalState === 'denied') {
        assert.equal(record.receipt.approval.operatorIdHash, operatorIdHash);
      }
      assert.equal(context.receipts.verify(record), true);
      assert.equal(context.receipts.assertParity(), true);
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', ['intent-1'],
      ).count, 1n);
      const serialized = canonicalJson(record.receipt);
      for (const forbidden of [
        'RAW_SELLER_ERROR_SENTINEL',
        'RAW_BODY_SENTINEL',
        'RAW_PROMPT_SENTINEL',
        'RAW_OPERATOR_TOKEN_SENTINEL',
        'RAW_CDP_CREDENTIAL_SENTINEL',
        'RAW_PAYMENT_SIGNATURE_SENTINEL',
        'RAW_PAYMENT_HEADER_SENTINEL',
        'RAW_STACK_SENTINEL',
        'RAW_PROVIDER_EXCEPTION_SENTINEL',
        'RAW_REFUND_EVIDENCE_SENTINEL',
        'RAW_RECONCILIATION_EVIDENCE_SENTINEL',
      ]) assert.equal(serialized.includes(forbidden), false);
    });
  }
});

test('unsigned rejected attempts project not_signed only from durable absence of signed bytes', async (t) => {
  const scenarios = [
    {
      reasonCode: 'NONCE_COLLISION',
      status: 'payment_failed',
      claimOnly: false,
    },
    {
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      status: 'payment_failed',
      claimOnly: true,
    },
    {
      reasonCode: 'AGENT_REVOKED',
      status: 'payment_denied',
      claimOnly: false,
    },
    {
      reasonCode: 'WALLET_RECOVERY_REQUIRED',
      status: 'payment_denied',
      claimOnly: false,
    },
  ];

  for (const scenario of scenarios) {
    await t.test(scenario.reasonCode, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: scenario.reasonCode,
        status: scenario.status,
        reasonCode: scenario.reasonCode,
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        claimOnly: scenario.claimOnly,
        budgetState: 'released',
      });
      const raw = context.store.readOne(`SELECT payment_payload_json, payment_header,
        payment_hash, signed_at, nonce, valid_after, valid_before, signing_claimed_at
        FROM payment_attempts WHERE intent_id = 'intent-1'`);
      assert.deepEqual(
        [raw.payment_payload_json, raw.payment_header, raw.payment_hash, raw.signed_at],
        [null, null, null, null],
      );
      assert.equal(raw.signing_claimed_at !== null, scenario.claimOnly);
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(record.receipt.payment.state, 'not_signed');
      assert.equal(record.receipt.payment.transactionId, null);
      assert.equal(record.receipt.budget.disposition, 'released');
      assert.equal(context.receipts.verify(record), true);
    });
  }
});

test('terminal unresolved receipts require the durable PaymentAttempt unresolved state', async (t) => {
  for (const paymentState of ['signing', 'signed', 'retrying']) {
    await t.test(`${paymentState} remains nonterminal`, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: `nonterminal-${paymentState}`,
        status: 'payment_unresolved',
        reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
        policyDecision: 'allow',
        paymentState,
        unsignedAttempt: paymentState === 'signing',
        claimOnly: paymentState === 'signing',
        budgetState: 'unresolved',
        intentState: 'unresolved',
      });
      if (paymentState === 'retrying') {
        context.store.execForTest(`UPDATE payment_attempts SET retry_started_at = '${NOW}'
          WHERE intent_id = 'intent-1'`);
      }
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /state|terminal|unresolved|payment|projection/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }

  for (const shape of [
    { name: 'claim-only unresolved', unsignedAttempt: true, claimOnly: true },
    { name: 'full-signed unresolved', unsignedAttempt: false, claimOnly: false },
  ]) {
    await t.test(shape.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...shape,
        status: 'payment_unresolved',
        reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
        policyDecision: 'allow',
        paymentState: 'unresolved',
        budgetState: 'unresolved',
        intentState: 'unresolved',
      });
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(record.receipt.payment.state, 'unresolved');
      assert.equal(record.receipt.budget.disposition, 'unresolved');
      assert.equal(context.receipts.verify(record), true);
    });
  }
});

test('receipt issuance rejects terminal PaymentAttempt chronology corruption by state', async (t) => {
  const cases = [
    {
      state: 'unresolved',
      seed(context) {
        seedScenario(context, {
          name: 'chronology-unresolved',
          status: 'payment_unresolved',
          reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
          policyDecision: 'allow',
          paymentState: 'unresolved',
          budgetState: 'unresolved',
          intentState: 'unresolved',
        });
        context.store.execForTest(`UPDATE payment_attempts SET retry_started_at = '${NOW}'
          WHERE intent_id = 'intent-1'`);
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET retry_started_at = '2026-07-31T11:59:59.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      state: 'rejected',
      seed(context) {
        seedScenario(context, {
          name: 'chronology-rejected',
          status: 'payment_failed',
          reasonCode: 'WALLET_PRE_SIGN_REJECTED',
          policyDecision: 'allow',
          paymentState: 'rejected',
          unsignedAttempt: true,
          claimOnly: true,
          budgetState: 'released',
        });
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET signing_claimed_at = '2026-07-31T12:00:02.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      state: 'settled',
      seed(context) {
        seedSettledSuccess(context);
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET settled_at = '2026-07-31T11:59:59.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
  ];

  for (const entry of cases) {
    await t.test(entry.state, (st) => {
      const context = setupRepository(st);
      entry.seed(context);
      entry.corrupt(context.store);
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /chronology|time|attempt|payment|corrupt/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('receipt reads and parity reproject current terminal PaymentAttempt chronology', async (t) => {
  const cases = [
    {
      state: 'unresolved',
      seed(context) {
        seedScenario(context, {
          name: 'read-chronology-unresolved',
          status: 'payment_unresolved',
          reasonCode: 'WALLET_SIGNATURE_AMBIGUOUS',
          policyDecision: 'allow',
          paymentState: 'unresolved',
          budgetState: 'unresolved',
          intentState: 'unresolved',
        });
        context.store.execForTest(`UPDATE payment_attempts SET retry_started_at = '${NOW}'
          WHERE intent_id = 'intent-1'`);
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET retry_started_at = '2026-07-31T11:59:59.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      state: 'rejected',
      seed(context) {
        seedScenario(context, {
          name: 'read-chronology-rejected',
          status: 'payment_failed',
          reasonCode: 'WALLET_PRE_SIGN_REJECTED',
          policyDecision: 'allow',
          paymentState: 'rejected',
          unsignedAttempt: true,
          claimOnly: true,
          budgetState: 'released',
        });
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET signing_claimed_at = '2026-07-31T12:00:02.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      state: 'settled',
      seed(context) {
        seedSettledSuccess(context);
      },
      corrupt(store) {
        store.execForTest(`UPDATE payment_attempts
          SET settled_at = '2026-07-31T11:59:59.000Z'
          WHERE intent_id = 'intent-1'`);
      },
    },
  ];

  for (const entry of cases) {
    await t.test(entry.state, (st) => {
      const context = setupRepository(st);
      entry.seed(context);
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(context.receipts.verify(record), true);
      entry.corrupt(context.store);
      assert.throws(
        () => context.receipts.latest('intent-1'),
        /chronology|time|attempt|payment|corrupt|parity/i,
      );
      assert.throws(
        () => context.receipts.list({ sessionId: 'session-1', limit: 10 }),
        /chronology|time|attempt|payment|corrupt|parity/i,
      );
      assert.throws(
        () => context.receipts.assertParity(),
        /chronology|time|attempt|payment|corrupt|parity/i,
      );
    });
  }
});

test('receipt issuance rejects substituted reasons and contradictory claim or signed-byte groups', async (t) => {
  const contradictions = [
    {
      name: 'typed pre-sign rejection lost its retained signing claim',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        budgetState: 'released',
      },
      mutate() {},
    },
    {
      name: 'nonce collision improperly retained an uncommitted signing claim',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'NONCE_COLLISION',
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        claimOnly: true,
        budgetState: 'released',
      },
      mutate() {},
    },
    {
      name: 'unsigned attempt reason differs from BuyerOutcome',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'NONCE_COLLISION',
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        budgetState: 'released',
      },
      mutate(store) {
        store.execForTest(`UPDATE payment_attempts SET reason_code = 'AGENT_REVOKED'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      name: 'claim-only rejection has a partial durable window',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        claimOnly: true,
        budgetState: 'released',
      },
      mutate(store) {
        store.execForTest(`UPDATE payment_attempts SET valid_before = NULL
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      name: 'reserved attempt contains signed bytes without a claim',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'SIGNER_REJECTED',
        policyDecision: 'allow',
        paymentState: 'reserved',
        budgetState: 'released',
      },
      mutate(store) {
        store.execForTest(`UPDATE payment_attempts
          SET payment_payload_json = '{}', payment_header = 'forged-header',
            payment_hash = '${sha256('forged-header')}', signed_at = '${NOW}'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      name: 'released terminal attempt remains reserved',
      scenario: {
        status: 'payment_failed',
        reasonCode: 'NONCE_COLLISION',
        policyDecision: 'allow',
        paymentState: 'reserved',
        budgetState: 'released',
      },
      mutate() {},
    },
    {
      name: 'signed unresolved attempt lost its signing claim',
      scenario: {
        status: 'payment_unresolved',
        reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
        policyDecision: 'allow',
        paymentState: 'unresolved',
        budgetState: 'unresolved',
        intentState: 'unresolved',
      },
      mutate(store) {
        store.execForTest(`UPDATE payment_attempts
          SET nonce = NULL, valid_after = NULL, valid_before = NULL, signing_claimed_at = NULL
          WHERE intent_id = 'intent-1'`);
      },
    },
  ];

  for (const contradiction of contradictions) {
    await t.test(contradiction.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: contradiction.name,
        ...contradiction.scenario,
      });
      contradiction.mutate(context.store);
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /payment|claim|signed|reason|projection|corrupt/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('CHALLENGE_EXPIRED distinguishes policy denial from exact pre-claim release', async (t) => {
  const releasedShapes = [
    {
      name: 'automatic authority',
      policyDecision: 'allow',
    },
    {
      name: 'consumed approval authority',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'consumed',
    },
  ];
  for (const shape of releasedShapes) {
    await t.test(`pre-claim release: ${shape.name}`, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...shape,
        name: `challenge-expired-${shape.name}`,
        status: 'payment_denied',
        reasonCode: 'CHALLENGE_EXPIRED',
        paymentState: 'rejected',
        unsignedAttempt: true,
        budgetState: 'released',
      });
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(record.receipt.outcome.reasonCode, 'CHALLENGE_EXPIRED');
      assert.equal(record.receipt.payment.state, 'not_signed');
      assert.equal(record.receipt.budget.disposition, 'released');
      assert.deepEqual(record.receipt.execution, {
        state: 'none',
        httpStatus: null,
        responseHash: null,
      });
      assert.equal(record.receipt.reconciliation, null);
      assert.equal(record.receipt.refund, null);
      assert.equal(context.receipts.verify(record), true);
      assert.equal(context.receipts.assertParity(), true);
    });
  }

  await t.test('policy denial retains its no-spend meaning', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'challenge-expired-policy-denial',
      status: 'payment_denied',
      reasonCode: 'CHALLENGE_EXPIRED',
      policyDecision: 'deny',
      policyReason: 'CHALLENGE_EXPIRED',
    });
    const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    assert.equal(record.receipt.policy.decision, 'deny');
    assert.deepEqual(record.receipt.payment, { state: 'none' });
    assert.equal(record.receipt.budget, null);
    assert.equal(context.receipts.verify(record), true);
  });

  const contradictions = [
    {
      name: 'signing claim exists',
      claimOnly: true,
    },
    {
      name: 'PaymentAttempt reason differs',
      mutate(store) {
        store.execForTest(`UPDATE payment_attempts SET reason_code = 'SIGNER_REJECTED'
          WHERE intent_id = 'intent-1'`);
      },
    },
    {
      name: 'released budget is missing',
      budgetState: null,
    },
    {
      name: 'budget remains unresolved',
      budgetState: 'unresolved',
    },
    {
      name: 'execution aftermath exists',
      executionState: 'unknown',
    },
    {
      name: 'reconciliation aftermath exists',
      reconciliationKind: 'payment',
      reconciliationOutcome: 'unresolved',
    },
    {
      name: 'refund aftermath exists',
      refundState: 'unresolved',
    },
  ];
  for (const contradiction of contradictions) {
    await t.test(contradiction.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: `challenge-expired-${contradiction.name}`,
        status: 'payment_denied',
        reasonCode: 'CHALLENGE_EXPIRED',
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        budgetState: 'released',
        ...contradiction,
      });
      contradiction.mutate?.(context.store);
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /claim|reason|budget|execution|reconciliation|refund|projection|authority|contradict/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('policy and session cancellation accept every safe unsigned terminal authority shape', async (t) => {
  const validShapes = [
    {
      name: 'automatic before reservation',
      policyDecision: 'allow',
      expectedApproval: 'not_required',
      expectedPayment: 'none',
    },
    {
      name: 'pending approval cancelled before reservation',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'cancelled',
      operatorHash: false,
      expectedApproval: 'cancelled',
      expectedPayment: 'none',
    },
    {
      name: 'automatic unsigned reservation released',
      policyDecision: 'allow',
      paymentState: 'rejected',
      unsignedAttempt: true,
      budgetState: 'released',
      expectedApproval: 'not_required',
      expectedPayment: 'not_signed',
    },
    {
      name: 'consumed approval remains consumed after unsigned release',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'consumed',
      paymentState: 'rejected',
      unsignedAttempt: true,
      budgetState: 'released',
      expectedApproval: 'consumed',
      expectedPayment: 'not_signed',
    },
  ];
  for (const reasonCode of ['POLICY_SUPERSEDED', 'SESSION_CLOSED']) {
    for (const shape of validShapes) {
      await t.test(`${reasonCode}: ${shape.name}`, (st) => {
        const context = setupRepository(st);
        seedScenario(context, {
          ...shape,
          name: `${reasonCode}-${shape.name}`,
          status: 'payment_denied',
          reasonCode,
        });
        const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
        assert.equal(record.receipt.approval.state, shape.expectedApproval);
        assert.equal(record.receipt.payment.state, shape.expectedPayment);
        assert.equal(
          record.receipt.budget?.disposition ?? null,
          shape.expectedPayment === 'none' ? null : 'released',
        );
        assert.equal(context.receipts.verify(record), true);
      });
    }
  }
});

test('pre-decision session cancellation requires an exact empty spend-authority projection', async (t) => {
  for (const reasonCode of ['POLICY_SUPERSEDED', 'SESSION_CLOSED']) {
    await t.test(`${reasonCode}: captured before decision`, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: `${reasonCode}-captured-before-decision`,
        status: 'payment_denied',
        reasonCode,
      });
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.equal(record.receipt.policy, null);
      assert.deepEqual(record.receipt.approval, {
        state: 'not_required',
        operatorIdHash: null,
      });
      assert.deepEqual(record.receipt.payment, { state: 'none' });
      assert.equal(record.receipt.budget, null);
      assert.deepEqual(record.receipt.execution, {
        state: 'none',
        httpStatus: null,
        responseHash: null,
      });
      assert.equal(context.receipts.verify(record), true);
    });
  }

  const contradictions = [
    {
      name: 'unrelated deny decision',
      policyDecision: 'deny',
      policyReason: 'POLICY_DENIED',
    },
    {
      name: 'payment evidence without a decision',
      paymentState: 'rejected',
      unsignedAttempt: true,
    },
    {
      name: 'budget evidence without a decision',
      budgetState: 'released',
    },
    {
      name: 'execution evidence without a decision',
      executionState: 'unknown',
      httpStatus: 206,
    },
  ];
  for (const contradiction of contradictions) {
    await t.test(contradiction.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...contradiction,
        name: `pre-decision-${contradiction.name}`,
        status: 'payment_denied',
        reasonCode: 'SESSION_CLOSED',
      });
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /policy|payment|budget|execution|projection|authority|contradict/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('policy and session cancellation reject nonterminal approval and sensitive aftermath', async (t) => {
  const contradictions = [
    {
      name: 'pending approval was not cancelled',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'pending',
      operatorHash: false,
    },
    {
      name: 'approved approval was not cancelled',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'approved',
    },
    {
      name: 'consumed approval lost its mandatory reservation',
      policyDecision: 'approval_required',
      policyReason: 'HUMAN_APPROVAL_REQUIRED',
      approvalState: 'consumed',
    },
    {
      name: 'signed authorization cannot be called unsigned',
      policyDecision: 'allow',
      paymentState: 'rejected',
      budgetState: 'released',
    },
    {
      name: 'payment without its released budget',
      policyDecision: 'allow',
      paymentState: 'rejected',
      unsignedAttempt: true,
    },
    {
      name: 'released budget without its payment attempt',
      policyDecision: 'allow',
      budgetState: 'released',
    },
    {
      name: 'execution aftermath survives cancellation',
      policyDecision: 'allow',
      executionState: 'unknown',
      httpStatus: 206,
    },
    {
      name: 'reconciliation aftermath survives cancellation',
      policyDecision: 'allow',
      reconciliationKind: 'execution',
      reconciliationOutcome: 'execution_unknown',
    },
  ];

  for (const contradiction of contradictions) {
    await t.test(contradiction.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...contradiction,
        status: 'payment_denied',
        reasonCode: 'SESSION_CLOSED',
      });
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /projection|contradict|authority|reconciliation|payment/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('policy and session cancellation reject every claim-only payment attempt', async (t) => {
  for (const reasonCode of ['POLICY_SUPERSEDED', 'SESSION_CLOSED']) {
    await t.test(reasonCode, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: `${reasonCode}-claim-only`,
        status: 'payment_denied',
        reasonCode,
        policyDecision: 'allow',
        paymentState: 'rejected',
        unsignedAttempt: true,
        claimOnly: true,
        budgetState: 'released',
      });
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /claim|unsigned|payment|projection|contradict/i,
      );
      assert.equal(context.store.readOne(
        'SELECT COUNT(*) AS count FROM signed_receipts',
      ).count, 0n);
    });
  }
});

test('execution projection retains partial evidence while its explicit state remains authoritative', async (t) => {
  const partialResponseHash = sha256('partial-response-bytes');
  const validExecutions = [
    {
      name: 'redirect failed without a body hash',
      status: 'execution_failed',
      reasonCode: 'UPSTREAM_HTTP_FAILURE',
      executionState: 'failed',
      httpStatus: 302,
      executionResponseHash: null,
      refundState: 'pending',
    },
    {
      name: 'server failed without a body hash',
      status: 'execution_failed',
      reasonCode: 'UPSTREAM_HTTP_FAILURE',
      executionState: 'failed',
      httpStatus: 599,
      executionResponseHash: null,
      refundState: 'pending',
    },
    {
      name: 'unknown with status only',
      status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      executionState: 'unknown',
      httpStatus: 206,
      executionResponseHash: null,
    },
    {
      name: 'unknown with response hash only',
      status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      executionState: 'unknown',
      httpStatus: null,
      executionResponseHash: partialResponseHash,
    },
    {
      name: 'unknown with independently known status and hash',
      status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      executionState: 'unknown',
      httpStatus: 299,
      executionResponseHash: partialResponseHash,
    },
  ];

  for (const scenario of validExecutions) {
    await t.test(scenario.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...scenario,
        policyDecision: 'allow',
        paymentState: 'settled',
        budgetState: 'committed',
      });
      const record = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      assert.deepEqual(record.receipt.execution, {
        state: scenario.executionState,
        httpStatus: scenario.httpStatus,
        responseHash: scenario.executionResponseHash,
      });
      assert.equal(context.receipts.verify(record), true);
    });
  }

  const invalidExecutions = [
    {
      name: 'failed without a known status',
      httpStatus: null,
      executionResponseHash: null,
    },
    {
      name: 'failed with a 2xx status',
      httpStatus: 299,
      executionResponseHash: null,
    },
    {
      name: 'failed with a malformed optional hash',
      httpStatus: 500,
      executionResponseHash: 'not-a-hash',
    },
  ];
  for (const scenario of invalidExecutions) {
    await t.test(scenario.name, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        ...scenario,
        status: 'execution_failed',
        reasonCode: 'UPSTREAM_HTTP_FAILURE',
        policyDecision: 'allow',
        paymentState: 'settled',
        executionState: 'failed',
        budgetState: 'committed',
        refundState: 'pending',
      });
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /status|hash|projection|fields/i,
      );
    });
  }

  for (const httpStatus of [300, 503, 599]) {
    await t.test(`unknown cannot retain definitive failure status ${httpStatus}`, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: `unknown-status-${httpStatus}`,
        status: 'execution_unknown',
        reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
        policyDecision: 'allow',
        paymentState: 'settled',
        executionState: 'unknown',
        httpStatus,
        executionResponseHash: partialResponseHash,
        budgetState: 'committed',
      });
      assert.throws(
        () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
        /status|unknown|projection|execution/i,
      );
    });
  }
});

test('trusted payment, execution, and refund facts create exact superseding revisions', async (t) => {
  await t.test('payment reconciliation', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'initial unresolved payment',
      status: 'payment_unresolved',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      policyDecision: 'allow',
      paymentState: 'unresolved',
      budgetState: 'unresolved',
      intentState: 'unresolved',
      expectedPayment: 'unresolved',
      expectedBudget: 'unresolved',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    assert.equal(context.store.transaction(
      (token) => context.receipts.assertParityInTransaction(token),
    ), true);

    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`UPDATE payment_attempts
        SET state = 'settled', retry_started_at = ?, settlement_json = '{}',
          transaction_id = ?, reason_code = 'TRUSTED_RECONCILIATION',
          settled_at = ?, updated_at = ? WHERE intent_id = ?`)
        .run(NOW, `0x${'ab'.repeat(32)}`, NOW, NOW, 'intent-1');
      db.prepare(`UPDATE budget_reservations
        SET unresolved_atomic = '0', committed_atomic = '50000', state = 'committed',
          committed_at = ?, updated_at = ? WHERE intent_id = ?`).run(NOW, NOW, 'intent-1');
      db.prepare(`INSERT INTO execution_outcomes
        (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
        VALUES (?, 'unknown', NULL, NULL, '{}', ?)`).run('intent-1', NOW);
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-payment', ?, 'payment', 'settled', '{}', ?, ?)`)
        .run('intent-1', sha256('operator-payment'), NOW);
      db.prepare(`UPDATE spend_intents SET state = 'terminal', updated_at = ? WHERE id = ?`)
        .run(NOW, 'intent-1');
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'execution_unknown', reason_code = 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
          revision = 2, recorded_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
    }));
    assert.throws(() => context.receipts.assertParity(), /missing.*current|parity/i);
    assert.throws(() => context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: '0'.repeat(64),
    }), /predecessor/i);
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.revision, 2);
    assert.equal(second.receipt.supersedesReceiptHash, first.receiptHash);
    assert.equal(second.receipt.outcome.status, 'execution_unknown');
    assert.equal(second.receipt.reconciliation.kind, 'payment');
    assert.equal(second.receipt.reconciliation.outcome, 'settled');
    assert.equal(second.receipt.payment.state, 'settled');
    assert.equal(second.receipt.budget.disposition, 'committed');
    assert.equal(context.receipts.verify(first), true);
    assert.equal(context.receipts.verify(second), true);
    assert.equal(context.receipts.assertParity(), true);
    assert.throws(
      () => context.receipts.issueForTerminal({ intentId: 'intent-1' }),
      /initial.*revision 1/i,
    );
  });

  await t.test('rejected payment reconciliation', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'initial unresolved authorization',
      status: 'payment_unresolved',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      policyDecision: 'allow',
      paymentState: 'unresolved',
      budgetState: 'unresolved',
      intentState: 'unresolved',
      expectedPayment: 'unresolved',
      expectedBudget: 'unresolved',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`UPDATE payment_attempts SET state = 'rejected', reason_code = ?,
        updated_at = ? WHERE intent_id = ?`).run(
        'AUTHORIZATION_UNUSED_AFTER_EXPIRY', NOW, 'intent-1',
      );
      db.prepare(`UPDATE budget_reservations
        SET unresolved_atomic = '0', released_atomic = '50000', state = 'released',
          updated_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-rejected-payment', ?, 'payment', 'rejected', '{}', ?, ?)`).run(
        'intent-1', sha256('operator-rejected-payment'), NOW,
      );
      db.prepare(`UPDATE spend_intents SET state = 'terminal', updated_at = ? WHERE id = ?`)
        .run(NOW, 'intent-1');
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'payment_rejected', reason_code = 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
          revision = 2, recorded_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
    }));
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1',
      supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.revision, 2);
    assert.equal(second.receipt.outcome.status, 'payment_rejected');
    assert.equal(second.receipt.payment.state, 'rejected');
    assert.equal(second.receipt.budget.disposition, 'released');
    assert.equal(second.receipt.reconciliation.kind, 'payment');
    assert.equal(second.receipt.reconciliation.outcome, 'rejected');
    assert.equal(context.receipts.verify(second), true);
    assert.equal(context.receipts.assertParity(), true);
  });

  await t.test('execution reconciliation', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'initial unknown execution',
      status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      policyDecision: 'allow',
      paymentState: 'settled',
      executionState: 'unknown',
      budgetState: 'committed',
      expectedPayment: 'settled',
      expectedBudget: 'committed',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    const responseHash = sha256(Buffer.from('{"reconciled":true}', 'utf8'));
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`UPDATE execution_outcomes
        SET state = 'succeeded', http_status = 200, response_hash = ?, recorded_at = ?
        WHERE intent_id = ?`).run(responseHash, NOW, 'intent-1');
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-execution', ?, 'execution', 'execution_succeeded', '{}', ?, ?)`)
        .run('intent-1', sha256('operator-execution'), NOW);
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'completed', reason_code = 'EXECUTION_RECONCILED_SUCCEEDED',
          revision = 2, recorded_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
    }));
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.receipt.execution.state, 'succeeded');
    assert.equal(second.receipt.execution.responseHash, responseHash);
    assert.equal(second.receipt.reconciliation.kind, 'execution');
    assert.equal(second.receipt.outcome.status, 'completed');
    assert.equal(context.receipts.assertParity(), true);
  });

  await t.test('confirmed refund', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'initial unresolved refund',
      status: 'execution_failed',
      reasonCode: 'REFUND_UNRESOLVED',
      policyDecision: 'allow',
      paymentState: 'settled',
      executionState: 'failed',
      budgetState: 'committed',
      refundState: 'unresolved',
      expectedPayment: 'settled',
      expectedBudget: 'committed',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`UPDATE refunds SET state = 'confirmed', refund_transaction_id = ?,
        evidence_json = '{}', updated_at = ? WHERE intent_id = ?`)
        .run(`0x${'cd'.repeat(32)}`, NOW, 'intent-1');
      db.prepare(`UPDATE budget_reservations
        SET committed_atomic = '0', released_atomic = '50000', state = 'released',
          updated_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-refund', ?, 'refund', 'refund_confirmed', '{}', ?, ?)`)
        .run('intent-1', sha256('operator-refund'), NOW);
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'refunded', reason_code = 'REFUND_CONFIRMED', revision = 2,
          recorded_at = ? WHERE intent_id = ?`).run(NOW, 'intent-1');
    }));
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.receipt.refund.state, 'confirmed');
    assert.equal(second.receipt.refund.transactionId, `0x${'cd'.repeat(32)}`);
    assert.equal(second.receipt.budget.disposition, 'released');
    assert.equal(second.receipt.outcome.status, 'refunded');
    assert.equal(second.receipt.reconciliation.kind, 'refund');
    assert.equal(context.receipts.assertParity(), true);
    assert.deepEqual(
      context.receipts.list({ sessionId: 'session-1', limit: 10 }).map((row) => row.revision),
      [2, 1],
    );
    const originalEventData = context.store.readOne(
      "SELECT data_json FROM events WHERE entity_type = 'signed_receipt' AND entity_id = ?",
      [second.id],
    ).data_json;
    const wrongPredecessorReceipt = structuredClone(second.receipt);
    wrongPredecessorReceipt.supersedesReceiptHash = 'd'.repeat(64);
    const wrongPredecessor = {
      ...second,
      ...signReceipt(context.signer, wrongPredecessorReceipt),
      receipt: wrongPredecessorReceipt,
      supersedesReceiptHash: wrongPredecessorReceipt.supersedesReceiptHash,
    };
    const wrongEventData = canonicalJson({
      ...JSON.parse(originalEventData),
      receiptHash: wrongPredecessor.receiptHash,
      supersedesReceiptHash: wrongPredecessor.supersedesReceiptHash,
    });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE signed_receipts SET receipt_json = ?, receipt_hash = ?, signature = ?,
        supersedes_receipt_hash = ? WHERE id = ?`).run(
        canonicalJson(wrongPredecessorReceipt),
        wrongPredecessor.receiptHash,
        wrongPredecessor.signature,
        wrongPredecessor.supersedesReceiptHash,
        second.id,
      );
      db.prepare("UPDATE events SET data_json = ? WHERE entity_type = 'signed_receipt' AND entity_id = ?")
        .run(wrongEventData, second.id);
    }));
    assert.throws(() => context.receipts.latest('intent-1'), /history|parity|predecessor/i);
    assert.throws(
      () => context.receipts.list({ sessionId: 'session-1', limit: 10 }),
      /history|parity|predecessor/i,
    );
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE signed_receipts SET receipt_json = ?, receipt_hash = ?, signature = ?,
        supersedes_receipt_hash = ? WHERE id = ?`).run(
        canonicalJson(second.receipt),
        second.receiptHash,
        second.signature,
        second.supersedesReceiptHash,
        second.id,
      );
      db.prepare("UPDATE events SET data_json = ? WHERE entity_type = 'signed_receipt' AND entity_id = ?")
        .run(originalEventData, second.id);
    }));
    context.store.execForTest("DELETE FROM events WHERE entity_type = 'signed_receipt' AND entity_id = 'receipt-1'");
    context.store.execForTest("DELETE FROM signed_receipts WHERE intent_id = 'intent-1' AND revision = 1");
    assert.throws(() => context.receipts.latest('intent-1'), /history|parity|revision/i);
    assert.throws(
      () => context.receipts.list({ sessionId: 'session-1', limit: 10 }),
      /history|parity|revision/i,
    );
  });
});

test('Task 11 candidate rejection and attested execution failure have exact revisions', async (t) => {
  await t.test('payment candidate rejection retains the full unresolved hold', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'candidate-rejection-predecessor',
      status: 'payment_unresolved',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      policyDecision: 'allow',
      paymentState: 'unresolved',
      budgetState: 'unresolved',
      intentState: 'unresolved',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    const candidateTransactionId = `0x${'31'.repeat(32)}`;
    const rejectionEvidence = canonicalJson({
      kind: 'payment_candidate_rejected',
      transactionId: candidateTransactionId,
      reasonCode: 'TRANSACTION_REVERTED',
      rpcProofHash: sha256('candidate-rejection-proof'),
    });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`INSERT INTO payment_reconciliation_candidates
        (id, intent_id, transaction_id, state, evidence_json, created_at, updated_at)
        VALUES ('candidate-1', 'intent-1', ?, 'pending', ?, ?, ?)`).run(
        candidateTransactionId,
        rejectionEvidence,
        NOW,
        NOW,
      );
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-candidate-rejected', 'intent-1', 'payment', 'unresolved',
          ?, ?, ?)`).run(rejectionEvidence, sha256('candidate-rejection-operator'), NOW);
      db.prepare(`UPDATE buyer_outcomes
        SET reason_code = 'PAYMENT_CANDIDATE_REJECTED', revision = 2, recorded_at = ?
        WHERE intent_id = 'intent-1'`).run(NOW);
      db.prepare(`UPDATE payment_attempts
        SET reason_code = 'PAYMENT_CANDIDATE_REJECTED'
        WHERE intent_id = 'intent-1' AND state = 'unresolved'`).run();
    }));
    assert.throws(() => context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    }), /candidate|rejected|projection|history/i);

    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE payment_reconciliation_candidates
        SET state = 'rejected' WHERE id = 'candidate-1'`).run();
    }));
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.revision, 2);
    assert.equal(second.receipt.outcome.status, 'payment_unresolved');
    assert.equal(second.receipt.outcome.reasonCode, 'PAYMENT_CANDIDATE_REJECTED');
    assert.equal(second.receipt.payment.state, 'unresolved');
    assert.equal(second.receipt.budget.disposition, 'unresolved');
    assert.equal(second.receipt.reconciliation.kind, 'payment');
    assert.equal(second.receipt.reconciliation.outcome, 'unresolved');
    assert.equal(context.receipts.assertParity(), true);
  });

  await t.test('verified execution failure opens one full refund-pending revision', (st) => {
    const context = setupRepository(st);
    seedScenario(context, {
      name: 'execution-failure-predecessor',
      status: 'execution_unknown',
      reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
      policyDecision: 'allow',
      paymentState: 'settled',
      executionState: 'unknown',
      budgetState: 'committed',
    });
    const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      assert.equal(context.receipts.assertParityInTransaction(token), true);
      db.prepare(`UPDATE execution_outcomes
        SET state = 'failed', http_status = 503, response_hash = NULL, recorded_at = ?
        WHERE intent_id = 'intent-1'`).run(NOW);
      db.prepare(`INSERT INTO execution_resolutions
        (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
        VALUES ('intent-1', 'refund_pending', 'REFUND_UNRESOLVED', 1, ?, NULL)`).run(NOW);
      db.prepare(`INSERT INTO refunds
        (id, intent_id, original_transaction_id, amount_atomic, state,
         evidence_json, refund_transaction_id, created_at, updated_at)
        VALUES ('refund-attested-failure', 'intent-1', ?, '1', 'pending', NULL, NULL, ?, ?)`).run(
        `0x${'ab'.repeat(32)}`,
        NOW,
        NOW,
      );
      db.prepare(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-execution-failed', 'intent-1', 'execution',
          'execution_failed', '{}', ?, ?)`).run(sha256('execution-failed-operator'), NOW);
      db.prepare(`UPDATE buyer_outcomes
        SET status = 'execution_failed', reason_code = 'REFUND_UNRESOLVED',
          revision = 2, recorded_at = ? WHERE intent_id = 'intent-1'`).run(NOW);
    }));
    assert.throws(() => context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    }), /refund|amount|projection/i);

    context.store.transaction((token) => context.store.within(token, ({ db }) => {
      db.prepare(`UPDATE refunds SET amount_atomic = '50000'
        WHERE id = 'refund-attested-failure'`).run();
    }));
    const second = context.receipts.issueRevisionForTerminal({
      intentId: 'intent-1', supersedesReceiptHash: first.receiptHash,
    });
    assert.equal(second.revision, 2);
    assert.equal(second.receipt.outcome.status, 'execution_failed');
    assert.equal(second.receipt.outcome.reasonCode, 'REFUND_UNRESOLVED');
    assert.equal(second.receipt.execution.state, 'failed');
    assert.equal(second.receipt.refund.state, 'pending');
    assert.equal(second.receipt.refund.amountAtomic, '50000');
    assert.equal(second.receipt.budget.disposition, 'committed');
    assert.equal(second.receipt.reconciliation.kind, 'execution');
    assert.equal(second.receipt.reconciliation.outcome, 'execution_failed');
    assert.equal(context.receipts.assertParity(), true);
  });

  for (const scenario of [
    {
      name: 'pending refund candidate',
      reasonCode: 'UPSTREAM_HTTP_FAILURE',
      refundState: 'pending',
    },
    {
      name: 'legacy unresolved refund candidate',
      reasonCode: 'REFUND_UNRESOLVED',
      refundState: 'unresolved',
    },
  ]) {
    await t.test(`${scenario.name} binding and abandonment do not revise its receipt`, (st) => {
      const context = setupRepository(st);
      seedScenario(context, {
        name: scenario.name,
        status: 'execution_failed',
        reasonCode: scenario.reasonCode,
        policyDecision: 'allow',
        paymentState: 'settled',
        executionState: 'failed',
        budgetState: 'committed',
        refundState: scenario.refundState,
      });
      const first = context.receipts.issueForTerminal({ intentId: 'intent-1' });
      const transactionId = `0x${'45'.repeat(32)}`;

      context.store.transaction((token) => context.store.within(token, ({ db }) => {
        assert.equal(context.receipts.assertParityInTransaction(token), true);
        db.prepare(`UPDATE refunds
          SET refund_transaction_id = ?, evidence_json = NULL, updated_at = ?
          WHERE intent_id = 'intent-1'`).run(transactionId, NOW);
      }));
      assert.equal(context.receipts.assertParity(), true);
      assert.equal(context.receipts.latest('intent-1').receiptHash, first.receiptHash);
      assert.deepEqual(context.receipts.latest('intent-1').receipt.refund, {
        state: scenario.refundState,
        amountAtomic: '50000',
        transactionId: null,
      });

      context.store.transaction((token) => context.store.within(token, ({ db }) => {
        assert.equal(context.receipts.assertParityInTransaction(token), true);
        db.prepare(`UPDATE refunds
          SET state = 'abandoned', updated_at = ?
          WHERE intent_id = 'intent-1' AND refund_transaction_id = ?`).run(
          NOW,
          transactionId,
        );
      }));
      assert.equal(context.receipts.assertParity(), true);
      assert.equal(context.receipts.latest('intent-1').receiptHash, first.receiptHash);
      assert.deepEqual(context.receipts.latest('intent-1').receipt.refund, {
        state: scenario.refundState,
        amountAtomic: '50000',
        transactionId: null,
      });
    });
  }
});

test('reopen recovery signs one exact missing revision without replaying money or events', (t) => {
  const fileAuthority = authority(t, 'wallet-kernel-receipt-recovery-');
  const signer = loadOrCreateReceiptSigner(fileAuthority.keyPath, {
    pathTrust: fileAuthority.pathTrust,
  });
  const failingSigner = Object.freeze({
    algorithm: signer.algorithm,
    keyId: signer.keyId,
    persistent: true,
    publicKeyPem: signer.publicKeyPem,
    signHash() { throw new Error('injected post-domain receipt signing failure'); },
  });
  const first = setupRepository(t, { fileAuthority, signer: failingSigner });
  seedScenario(first, {
    name: 'recovery settlement',
    status: 'completed',
    reasonCode: 'PAYMENT_SETTLED',
    policyDecision: 'allow',
    paymentState: 'settled',
    executionState: 'succeeded',
    budgetState: 'committed',
    expectedPayment: 'settled',
    expectedBudget: 'committed',
  });
  const beforeEvents = first.store.events().map((row) => ({
    sequence: row.sequence,
    eventHash: row.event_hash,
    eventType: row.event_type,
  }));
  const beforeMoney = first.store.readOne(`SELECT state, committed_atomic, released_atomic,
    unresolved_atomic, committed_at FROM budget_reservations WHERE intent_id = ?`, ['intent-1']);
  const beforePayment = first.store.readOne(`SELECT state, transaction_id, settled_at
    FROM payment_attempts WHERE intent_id = ?`, ['intent-1']);

  assert.throws(
    () => first.receipts.issueForTerminal({ intentId: 'intent-1' }),
    /injected post-domain receipt signing failure/,
  );
  assert.equal(first.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);
  assert.deepEqual(first.store.events().map((row) => ({
    sequence: row.sequence,
    eventHash: row.event_hash,
    eventType: row.event_type,
  })), beforeEvents);
  first.store.close();

  const reopened = setupRepository(t, {
    fileAuthority,
    signer,
    seedAuthority: false,
  });
  assert.throws(() => reopened.receipts.assertParity(), /missing.*current|parity/i);
  const repaired = reopened.receipts.issueMissingTerminalReceipts();
  assert.equal(repaired.length, 1);
  assert.equal(repaired[0].revision, 1);
  assert.equal(reopened.receipts.verify(repaired[0]), true);
  assert.equal(reopened.receipts.assertParity(), true);
  assert.deepEqual(reopened.receipts.issueMissingTerminalReceipts(), []);
  assert.deepEqual(reopened.store.readOne(`SELECT state, committed_atomic, released_atomic,
    unresolved_atomic, committed_at FROM budget_reservations WHERE intent_id = ?`, ['intent-1']), beforeMoney);
  assert.deepEqual(reopened.store.readOne(`SELECT state, transaction_id, settled_at
    FROM payment_attempts WHERE intent_id = ?`, ['intent-1']), beforePayment);
  const afterEvents = reopened.store.events().map((row) => ({
    sequence: row.sequence,
    eventHash: row.event_hash,
    eventType: row.event_type,
  }));
  assert.deepEqual(afterEvents.slice(0, beforeEvents.length), beforeEvents);
  assert.deepEqual(afterEvents.slice(beforeEvents.length).map((event) => event.eventType), [
    'receipt.issued',
  ]);
  assert.equal(reopened.store.readOne(
    'SELECT COUNT(*) AS count FROM buyer_outcomes WHERE intent_id = ?', ['intent-1'],
  ).count, 1n);
  assert.equal(reopened.store.verifyEventChain(), true);
});

test('parity binds every signed receipt to one exact receipt event and fails closed on history gaps', (t) => {
  const missingEvent = setupRepository(t);
  seedSettledSuccess(missingEvent);
  missingEvent.receipts.issueForTerminal({ intentId: 'intent-1' });
  missingEvent.store.execForTest("DELETE FROM events WHERE event_type = 'receipt.issued'");
  assert.throws(() => missingEvent.receipts.assertParity(), /receipt.*event|parity/i);
  assert.throws(() => missingEvent.receipts.latest('intent-1'), /receipt.*event|parity/i);
  assert.throws(
    () => missingEvent.receipts.list({ sessionId: 'session-1', limit: 10 }),
    /receipt.*event|parity/i,
  );
  assert.throws(
    () => missingEvent.receipts.issueForTerminal({ intentId: 'intent-1' }),
    /receipt.*event|parity/i,
  );

  const skippedRevision = setupRepository(t);
  seedSettledSuccess(skippedRevision);
  skippedRevision.receipts.issueForTerminal({ intentId: 'intent-1' });
  skippedRevision.store.execForTest(
    "UPDATE buyer_outcomes SET revision = 3, reason_code = 'IMPOSSIBLE_GAP' WHERE intent_id = 'intent-1'",
  );
  assert.throws(
    () => skippedRevision.receipts.issueMissingTerminalReceipts(),
    /cannot be reconstructed|revision/i,
  );
  assert.equal(skippedRevision.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts WHERE intent_id = ?', ['intent-1'],
  ).count, 1n);

  const substitutedOutcome = setupRepository(t);
  seedSettledSuccess(substitutedOutcome);
  substitutedOutcome.receipts.issueForTerminal({ intentId: 'intent-1' });
  substitutedOutcome.store.execForTest(
    "UPDATE buyer_outcomes SET reason_code = 'SUBSTITUTED_REASON' WHERE intent_id = 'intent-1'",
  );
  assert.throws(
    () => substitutedOutcome.receipts.assertParity(),
    /disagrees|parity|projection|reason/i,
  );
});

test('closed projections reject contradictory authority, impossible clocks, and re-signed invalid shapes', (t) => {
  const clock = { value: NOW };
  const signer = createReceiptSigner();
  let signCalls = 0;
  const countingSigner = Object.freeze({
    ...signer,
    signHash(hashHex) {
      signCalls += 1;
      return signer.signHash(hashHex);
    },
  });
  const regressed = setupRepository(t, { clock, signer: countingSigner });
  seedSettledSuccess(regressed);
  clock.value = '2026-07-31T12:00:00.000Z';
  assert.throws(
    () => regressed.receipts.issueForTerminal({ intentId: 'intent-1' }),
    /predates|time|issuedAt/i,
  );
  assert.equal(signCalls, 0);
  assert.equal(regressed.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);

  const contradictory = setupRepository(t);
  seedSettledSuccess(contradictory);
  contradictory.store.execForTest(`UPDATE buyer_outcomes
    SET status = 'refunded', reason_code = 'REFUND_CONFIRMED' WHERE intent_id = 'intent-1'`);
  assert.throws(
    () => contradictory.receipts.issueForTerminal({ intentId: 'intent-1' }),
    /projection|outcome|refund|contradict/i,
  );
  assert.equal(contradictory.store.readOne(
    'SELECT COUNT(*) AS count FROM signed_receipts',
  ).count, 0n);

  const valid = setupRepository(t, { signer });
  seedSettledSuccess(valid);
  const record = valid.receipts.issueForTerminal({ intentId: 'intent-1' });
  for (const mutate of [
    (receipt) => { receipt.payment.state = 'unresolved'; },
    (receipt) => {
      receipt.execution = { state: 'none', httpStatus: 200, responseHash: null };
    },
    (receipt) => {
      receipt.outcome = { status: 'completed', reasonCode: 'PAYMENT_SETTLED' };
      receipt.execution = {
        state: 'failed',
        httpStatus: 500,
        responseHash: sha256('failed'),
      };
    },
    (receipt) => {
      receipt.outcome = { status: 'execution_unknown', reasonCode: 'PAID_RESPONSE_AMBIGUOUS' };
      receipt.execution = {
        state: 'unknown',
        httpStatus: 503,
        responseHash: sha256('known-failure'),
      };
    },
  ]) {
    const receipt = structuredClone(record.receipt);
    mutate(receipt);
    const resigned = { ...record, ...signReceipt(signer, receipt), receipt };
    assert.equal(valid.receipts.verify(resigned), false);
  }
});

test('terminal reason codes enforce their exact closed authority and execution projections', (t) => {
  const signer = createReceiptSigner();
  const context = setupRepository(t, { signer });
  const noPayment = ({ status, reasonCode, execution }) => {
    const receipt = receiptFixture();
    receipt.outcome = { status, reasonCode };
    receipt.policy = null;
    receipt.approval = { state: 'not_required', operatorIdHash: null };
    receipt.payment = { state: 'none' };
    receipt.execution = execution;
    receipt.budget = null;
    receipt.reconciliation = null;
    receipt.refund = null;
    return receipt;
  };
  const noExecution = { state: 'none', httpStatus: null, responseHash: null };
  const ordinarySuccess = noPayment({
    status: 'completed',
    reasonCode: 'ORDINARY_SUCCESS',
    execution: {
      state: 'succeeded',
      httpStatus: 200,
      responseHash: sha256('ordinary-success'),
    },
  });
  const ordinaryHttpFailure = noPayment({
    status: 'upstream_failed',
    reasonCode: 'ORDINARY_HTTP_FAILURE',
    execution: {
      state: 'failed',
      httpStatus: 503,
      responseHash: sha256('ordinary-http-failure'),
    },
  });
  const transportFailure = noPayment({
    status: 'upstream_failed',
    reasonCode: 'UPSTREAM_TRANSPORT_FAILURE',
    execution: { state: 'unknown', httpStatus: null, responseHash: null },
  });
  const approvedRetryTransportFailure = structuredClone(transportFailure);
  approvedRetryTransportFailure.policy = {
    versionId: 'policy-1',
    decision: 'approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
  };
  approvedRetryTransportFailure.approval = {
    state: 'approved',
    operatorIdHash: sha256('approved-retry-operator'),
  };
  const malformedChallenge = noPayment({
    status: 'payment_denied',
    reasonCode: 'PAYMENT_CHALLENGE_MALFORMED',
    execution: noExecution,
  });
  const policyDenied = noPayment({
    status: 'payment_denied',
    reasonCode: 'POLICY_DENIED',
    execution: noExecution,
  });
  policyDenied.policy = {
    versionId: 'policy-1',
    decision: 'deny',
    reasonCode: 'POLICY_DENIED',
  };
  const operatorDenied = noPayment({
    status: 'payment_denied',
    reasonCode: 'OPERATOR_DENIED',
    execution: noExecution,
  });
  operatorDenied.policy = {
    versionId: 'policy-1',
    decision: 'approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
  };
  operatorDenied.approval = { state: 'denied', operatorIdHash: sha256('operator-denied') };
  const approvalExpired = structuredClone(operatorDenied);
  approvalExpired.outcome.reasonCode = 'APPROVAL_EXPIRED';
  approvalExpired.approval = { state: 'expired', operatorIdHash: null };
  const cancelled = structuredClone(operatorDenied);
  cancelled.outcome.reasonCode = 'APPROVAL_CHALLENGE_CHANGED';
  cancelled.approval = { state: 'cancelled', operatorIdHash: null };
  const signingFailed = receiptFixture();
  signingFailed.outcome = { status: 'payment_failed', reasonCode: 'SIGNER_REJECTED' };
  signingFailed.payment = {
    ...signingFailed.payment,
    state: 'not_signed',
    transactionId: null,
  };
  signingFailed.execution = noExecution;
  signingFailed.budget = { disposition: 'released', amountAtomic: '50000' };
  const abandonedBeforeApproval = noPayment({
    status: 'payment_failed',
    reasonCode: 'RECOVERY_ABANDONED_UNSIGNED',
    execution: noExecution,
  });
  abandonedBeforeApproval.policy = {
    versionId: 'policy-1',
    decision: 'approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
  };

  const contradictions = [
    {
      name: 'unknown stable-looking reason',
      valid: ordinarySuccess,
      mutate(receipt) { receipt.outcome.reasonCode = 'UNKNOWN_TERMINAL_REASON'; },
    },
    {
      name: 'ordinary success paired with HTTP-failure reason',
      valid: ordinarySuccess,
      mutate(receipt) { receipt.outcome.reasonCode = 'ORDINARY_HTTP_FAILURE'; },
    },
    {
      name: 'ordinary HTTP failure with transport-unknown execution',
      valid: ordinaryHttpFailure,
      mutate(receipt) {
        receipt.execution = { state: 'unknown', httpStatus: null, responseHash: null };
      },
    },
    {
      name: 'ordinary HTTP failure with redirect status',
      valid: ordinaryHttpFailure,
      mutate(receipt) { receipt.execution.httpStatus = 302; },
    },
    {
      name: 'transport failure inventing an HTTP response',
      valid: transportFailure,
      mutate(receipt) {
        receipt.execution = {
          state: 'failed',
          httpStatus: 503,
          responseHash: sha256('invented-transport-response'),
        };
      },
    },
    {
      name: 'approved retry transport failure cannot cancel historical approval',
      valid: approvedRetryTransportFailure,
      mutate(receipt) {
        receipt.approval = { state: 'cancelled', operatorIdHash: null };
      },
    },
    {
      name: 'approved retry transport failure cannot consume spend authority',
      valid: approvedRetryTransportFailure,
      mutate(receipt) { receipt.approval.state = 'consumed'; },
    },
    {
      name: 'approved retry transport failure requires its approval-required decision',
      valid: approvedRetryTransportFailure,
      mutate(receipt) { receipt.policy = null; },
    },
    {
      name: 'approved retry transport failure cannot invent payment authority',
      valid: approvedRetryTransportFailure,
      mutate(receipt) {
        receipt.payment = {
          state: 'not_signed',
          amountAtomic: '50000',
          network: NETWORK,
          asset: ASSET,
          payTo: PAY_TO,
          transactionId: null,
        };
        receipt.budget = { disposition: 'released', amountAtomic: '50000' };
      },
    },
    {
      name: 'pre-policy malformed challenge with invented policy decision',
      valid: malformedChallenge,
      mutate(receipt) {
        receipt.policy = {
          versionId: 'policy-1', decision: 'deny', reasonCode: 'POLICY_DENIED',
        };
      },
    },
    {
      name: 'policy denial without its deny decision',
      valid: policyDenied,
      mutate(receipt) { receipt.policy = null; },
    },
    {
      name: 'operator denial without authenticated denied approval',
      valid: operatorDenied,
      mutate(receipt) { receipt.approval = { state: 'expired', operatorIdHash: null }; },
    },
    {
      name: 'approval expiry mislabeled as cancellation',
      valid: approvalExpired,
      mutate(receipt) { receipt.approval = { state: 'cancelled', operatorIdHash: null }; },
    },
    {
      name: 'guarded cancellation retaining unsigned payment authority',
      valid: cancelled,
      mutate(receipt) {
        receipt.payment = {
          state: 'not_signed',
          amountAtomic: '50000',
          network: NETWORK,
          asset: ASSET,
          payTo: PAY_TO,
          transactionId: null,
        };
        receipt.budget = { disposition: 'released', amountAtomic: '50000' };
      },
    },
    {
      name: 'signer failure without its released reservation',
      valid: signingFailed,
      mutate(receipt) {
        receipt.payment = { state: 'none' };
        receipt.budget = null;
      },
    },
    {
      name: 'recovery-before-approval cannot invent a denied approval',
      valid: abandonedBeforeApproval,
      mutate(receipt) {
        receipt.approval = { state: 'denied', operatorIdHash: sha256('invented-operator') };
      },
    },
  ];

  for (const contradiction of contradictions) {
    assert.equal(
      context.receipts.verify(signedRecordForReceipt(signer, contradiction.valid)),
      true,
      `${contradiction.name} valid control`,
    );
    const invalid = structuredClone(contradiction.valid);
    contradiction.mutate(invalid);
    assert.equal(
      context.receipts.verify(signedRecordForReceipt(signer, invalid)),
      false,
      contradiction.name,
    );
  }

  let signCalls = 0;
  const countingSigner = Object.freeze({
    ...signer,
    signHash(hashHex) {
      signCalls += 1;
      return signer.signHash(hashHex);
    },
  });
  const persisted = setupRepository(t, { signer: countingSigner });
  seedScenario(persisted, {
    name: 'unknown reason authority row',
    status: 'completed',
    reasonCode: 'UNKNOWN_TERMINAL_REASON',
    executionState: 'succeeded',
    expectedPayment: 'none',
    expectedBudget: null,
  });
  assert.throws(
    () => persisted.receipts.issueForTerminal({ intentId: 'intent-1' }),
    /reason|projection|unsupported/i,
  );
  assert.equal(signCalls, 0);
});

test('standalone verification closes revision, refund, and reconciliation semantics', (t) => {
  const signer = createReceiptSigner();
  const context = setupRepository(t, { signer });
  const expectInvalid = (name, validReceipt, mutate) => {
    assert.equal(
      context.receipts.verify(signedRecordForReceipt(signer, validReceipt)),
      true,
      `${name} valid control`,
    );
    const invalid = structuredClone(validReceipt);
    mutate(invalid);
    assert.equal(
      context.receipts.verify(signedRecordForReceipt(signer, invalid)),
      false,
      name,
    );
  };

  expectInvalid('revision one cannot claim a predecessor', receiptFixture(), (receipt) => {
    receipt.supersedesReceiptHash = 'a'.repeat(64);
  });
  expectInvalid('revision two requires a predecessor', {
    ...receiptFixture(),
    revision: 2,
    supersedesReceiptHash: 'a'.repeat(64),
  }, (receipt) => {
    receipt.supersedesReceiptHash = null;
  });

  const confirmedRefund = receiptFixture();
  confirmedRefund.revision = 2;
  confirmedRefund.supersedesReceiptHash = 'a'.repeat(64);
  confirmedRefund.outcome = { status: 'refunded', reasonCode: 'REFUND_CONFIRMED' };
  confirmedRefund.execution = {
    state: 'failed',
    httpStatus: 503,
    responseHash: sha256('failed-before-refund'),
  };
  confirmedRefund.budget = { disposition: 'released', amountAtomic: '50000' };
  confirmedRefund.reconciliation = {
    kind: 'refund',
    outcome: 'refund_confirmed',
    operatorIdHash: sha256('refund-operator'),
    recordedAt: NOW,
  };
  confirmedRefund.refund = {
    state: 'confirmed',
    amountAtomic: '50000',
    transactionId: `0x${'cd'.repeat(32)}`,
  };
  for (const [name, mutate] of [
    ['confirmed refund requires its transaction', (receipt) => {
      receipt.refund.transactionId = null;
    }],
    ['confirmed refund amount equals payment and budget', (receipt) => {
      receipt.refund.amountAtomic = '40000';
    }],
    ['confirmed refund transaction differs from the original payment', (receipt) => {
      receipt.refund.transactionId = receipt.payment.transactionId;
    }],
    ['confirmed refund requires matching reconciliation', (receipt) => {
      receipt.reconciliation = null;
    }],
    ['confirmed refund cannot be an initial revision', (receipt) => {
      receipt.revision = 1;
      receipt.supersedesReceiptHash = null;
    }],
  ]) expectInvalid(name, confirmedRefund, mutate);

  const pendingRefund = structuredClone(confirmedRefund);
  pendingRefund.revision = 1;
  pendingRefund.supersedesReceiptHash = null;
  pendingRefund.outcome = { status: 'execution_failed', reasonCode: 'UPSTREAM_HTTP_FAILURE' };
  pendingRefund.budget = { disposition: 'committed', amountAtomic: '50000' };
  pendingRefund.reconciliation = null;
  pendingRefund.refund = { state: 'pending', amountAtomic: '50000', transactionId: null };
  for (const [name, mutate] of [
    ['pending refund cannot expose a transaction', (receipt) => {
      receipt.refund.transactionId = `0x${'ef'.repeat(32)}`;
    }],
    ['pending refund amount equals committed payment', (receipt) => {
      receipt.refund.amountAtomic = '40000';
    }],
    ['pending refund keeps its initial failure reason', (receipt) => {
      receipt.outcome.reasonCode = 'REFUND_UNRESOLVED';
    }],
  ]) expectInvalid(name, pendingRefund, mutate);

  const unresolvedRefund = structuredClone(pendingRefund);
  unresolvedRefund.outcome.reasonCode = 'REFUND_UNRESOLVED';
  unresolvedRefund.refund.state = 'unresolved';
  expectInvalid('unresolved refund cannot masquerade as pending', unresolvedRefund, (receipt) => {
    receipt.outcome.reasonCode = 'UPSTREAM_HTTP_FAILURE';
  });

  const paymentReconciliation = receiptFixture();
  paymentReconciliation.revision = 2;
  paymentReconciliation.supersedesReceiptHash = 'b'.repeat(64);
  paymentReconciliation.outcome = {
    status: 'execution_unknown',
    reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
  };
  paymentReconciliation.execution = { state: 'unknown', httpStatus: null, responseHash: null };
  paymentReconciliation.reconciliation = {
    kind: 'payment',
    outcome: 'settled',
    operatorIdHash: sha256('payment-reconciliation-operator'),
    recordedAt: NOW,
  };
  for (const [name, mutate] of [
    ['trusted reconciliation requires a superseding revision', (receipt) => {
      receipt.revision = 1;
      receipt.supersedesReceiptHash = null;
    }],
    ['reconciliation kind closes its outcome vocabulary', (receipt) => {
      receipt.reconciliation = { ...receipt.reconciliation, kind: 'refund' };
    }],
    ['settled payment reconciliation requires settled payment', (receipt) => {
      receipt.reconciliation = { ...receipt.reconciliation, outcome: 'rejected' };
    }],
  ]) expectInvalid(name, paymentReconciliation, mutate);

  const executionReconciliation = receiptFixture();
  executionReconciliation.revision = 2;
  executionReconciliation.supersedesReceiptHash = 'c'.repeat(64);
  executionReconciliation.outcome = {
    status: 'completed',
    reasonCode: 'EXECUTION_RECONCILED_SUCCEEDED',
  };
  executionReconciliation.reconciliation = {
    kind: 'execution',
    outcome: 'execution_succeeded',
    operatorIdHash: sha256('execution-reconciliation-operator'),
    recordedAt: NOW,
  };
  expectInvalid('execution reconciliation must agree with execution', executionReconciliation,
    (receipt) => {
      receipt.reconciliation = { ...receipt.reconciliation, outcome: 'execution_failed' };
    });
});

test('approved-retry transport failure issues only its narrow no-spend receipt projection', (t) => {
  const context = setupRepository(t);
  seedScenario(context, {
    name: 'approved-retry-transport-failure',
    status: 'upstream_failed',
    reasonCode: 'UPSTREAM_TRANSPORT_FAILURE',
    policyDecision: 'approval_required',
    policyReason: 'HUMAN_APPROVAL_REQUIRED',
    approvalState: 'approved',
    approvalReason: null,
    executionState: 'unknown',
    httpStatus: null,
    expectedPayment: 'none',
    expectedBudget: null,
  });

  const signed = context.receipts.issueForTerminal({ intentId: 'intent-1' });

  assert.equal(context.receipts.verify(signed), true);
  assert.deepEqual(signed.receipt.policy, {
    versionId: 'policy-1',
    decision: 'approval_required',
    reasonCode: 'HUMAN_APPROVAL_REQUIRED',
  });
  assert.equal(signed.receipt.approval.state, 'approved');
  assert.match(signed.receipt.approval.operatorIdHash, /^sha256:[0-9a-f]{64}$/);
  assert.deepEqual(signed.receipt.payment, { state: 'none' });
  assert.equal(signed.receipt.budget, null);
  assert.deepEqual(signed.receipt.execution, {
    state: 'unknown',
    httpStatus: null,
    responseHash: null,
  });
  assert.equal(signed.receipt.reconciliation, null);
  assert.equal(signed.receipt.refund, null);
  assert.equal(context.receipts.assertParity(), true);
});

test('normal issuance preserves global parity and multi-gap recovery is all-or-nothing', (t) => {
  const context = setupRepository(t);
  for (const [intentId, status, reasonCode, executionState] of [
    ['intent-a', 'completed', 'ORDINARY_SUCCESS', 'succeeded'],
    ['intent-b', 'upstream_failed', 'UPSTREAM_TRANSPORT_FAILURE', 'unknown'],
  ]) seedScenario(context, {
    intentId,
    requestId: `request-${intentId}`,
    name: intentId,
    status,
    reasonCode,
    executionState,
    expectedPayment: 'none',
    expectedBudget: null,
  });
  assert.throws(
    () => context.receipts.issueForTerminal({ intentId: 'intent-a' }),
    /parity|missing.*current/i,
  );
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);
  const repaired = context.receipts.issueMissingTerminalReceipts();
  assert.equal(repaired.length, 2);
  assert.equal(context.receipts.assertParity(), true);

  const baseSigner = createReceiptSigner();
  let calls = 0;
  const secondFailure = Object.freeze({
    ...baseSigner,
    signHash(hashHex) {
      calls += 1;
      if (calls === 2) throw new Error('second recovery signature failed');
      return baseSigner.signHash(hashHex);
    },
  });
  const rollback = setupRepository(t, { signer: secondFailure });
  for (const intentId of ['intent-a', 'intent-b']) seedScenario(rollback, {
    intentId,
    requestId: `request-${intentId}`,
    name: intentId,
    status: 'completed',
    reasonCode: 'ORDINARY_SUCCESS',
    executionState: 'succeeded',
    expectedPayment: 'none',
    expectedBudget: null,
  });
  const eventsBefore = rollback.store.events().length;
  assert.throws(
    () => rollback.receipts.issueMissingTerminalReceipts(),
    /second recovery signature failed/,
  );
  assert.equal(rollback.store.readOne('SELECT COUNT(*) AS count FROM signed_receipts').count, 0n);
  assert.equal(rollback.store.events().length, eventsBefore);
});

test('repository authenticates the injected Ed25519 signer identity before use', (t) => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true, now: () => NOW });
  t.after(() => store.close());
  const signer = createReceiptSigner();
  assert.throws(() => createSignedReceiptRepository({
    store,
    signer: Object.freeze({ ...signer, keyId: sha256('substituted-key-id') }),
    idFactory: () => 'receipt-1',
    now: () => NOW,
  }), /key ID|SPKI|signer/i);
  const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  assert.throws(() => createSignedReceiptRepository({
    store,
    signer: Object.freeze({
      algorithm: 'Ed25519',
      keyId: signer.keyId,
      publicKeyPem: rsa.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
      signHash: signer.signHash,
    }),
    idFactory: () => 'receipt-1',
    now: () => NOW,
  }), /Ed25519|signer/i);
});

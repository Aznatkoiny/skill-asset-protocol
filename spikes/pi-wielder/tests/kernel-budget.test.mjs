import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { WalletSigningError } from '../src/adapters/wallet-adapter-contract.mjs';
import { createBudgetLedger } from '../src/kernel/budget-ledger.mjs';
import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import {
  evaluateSpendPolicy,
  projectPaymentRequired,
} from '../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:00.000Z';
const AFTER_EXPIRY = '2026-07-31T13:02:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const ROUTE_METADATA = Object.freeze({
  'paid-infer': Object.freeze({
    description: 'offline fixture',
    mimeType: 'application/json',
  }),
});
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));
const RACE_FIXTURE = fileURLToPath(new URL('./fixtures/budget-writer.mjs', import.meta.url));
const ZERO_BUDGET = Object.freeze({
  sellerSessionExposureAtomic: '0',
  sessionExposureAtomic: '0',
  rolling24hExposureAtomic: '0',
  walletBlocked: false,
});

function testPolicy(overrides = {}) {
  const document = structuredClone(BASE_POLICY);
  Object.assign(document, overrides);
  document.sellers[0] = {
    ...document.sellers[0],
    perRequestMaxAtomic: '1000000',
    autoApproveAtomic: '1000000',
    humanApproveAtomic: '1000000',
    sellerSessionMaxAtomic: '1000000',
    ...(overrides.seller ?? {}),
  };
  delete document.seller;
  document.sessionMaxAtomic = overrides.sessionMaxAtomic ?? '2000000';
  document.rolling24hMaxAtomic = overrides.rolling24hMaxAtomic ?? '5000000';
  return document;
}

function paymentRequired(amountAtomic) {
  return {
    x402Version: 2,
    error: 'seller prose is not persisted',
    resource: {
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
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

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function authority(t, prefix = 'wallet-kernel-budget-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    directory,
    databasePath: path.join(directory, 'kernel.sqlite'),
    pathTrust,
  };
}

function setup(t, {
  fileAuthority = null,
  policyDocument = testPolicy(),
  now = () => NOW,
} = {}) {
  const store = openKernelStore(fileAuthority ? {
    filePath: fileAuthority.databasePath,
    pathTrust: fileAuthority.pathTrust,
    now,
  } : {
    filePath: ':memory:',
    allowMemory: true,
    now,
  });
  t.after(() => {
    try { store.close(); } catch {}
  });
  const policies = createPolicyRepository(store);
  const activePolicy = policies.apply(policyDocument, NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store, now });
  const enrolled = enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const intents = createIntentRepository({
    store,
    idFactory: sequenceIds(),
    now,
    routeMetadata: ROUTE_METADATA,
  });
  const session = intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  const ledger = createBudgetLedger({ store, now });
  return {
    activePolicy,
    enrolled,
    enrollments,
    intents,
    ledger,
    now,
    policies,
    policyDocument,
    session,
    store,
  };
}

function rotateSessionPolicy(context) {
  const document = testPolicy();
  document.challengeMaxAgeMs += 1;
  const policyVersion = context.policies.apply(
    document,
    '2026-07-31T12:01:00.000Z',
  ).policyVersion;
  const blocked = context.intents.getSession(context.session.id);
  assert.equal(blocked.state, 'policy_blocked');
  const transitioned = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: policyVersion.id,
      expectedSessionHash: blocked.sessionHash,
    })
  ));
  return Object.freeze({
    ...context,
    activePolicy: policyVersion,
    policyDocument: document,
    session: transitioned.replacementSession,
  });
}

function requestFor(label) {
  return {
    routeId: 'paid-infer',
    method: 'POST',
    requestUrl: `${SELLER}/paid/infer`,
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from(canonicalJson({ label }), 'utf8'),
    purposeLabel: 'skill.invoke',
    correlationId: `pi-call-${label}`,
  };
}

function authorizeIntent(context, {
  amountAtomic,
  label,
  budgetSnapshot,
} = {}) {
  const request = requestFor(label);
  const captured = context.intents.captureIntent({
    sessionId: context.session.id,
    ...request,
  });
  const challenge = paymentRequired(amountAtomic);
  context.intents.attachChallenge({
    intentId: captured.id,
    paymentRequired: challenge,
    challengeReceivedAt: NOW,
  });
  const snapshot = budgetSnapshot ?? context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  });
  const evaluation = evaluateSpendPolicy({
    policy: context.activePolicy.policy,
    policyVersion: {
      id: context.activePolicy.id,
      hash: context.activePolicy.hash,
    },
    intent: {
      id: captured.id,
      method: request.method,
      requestUrl: request.requestUrl,
      sellerOrigin: SELLER,
      resourcePath: '/paid/infer',
      walletAddress: WALLET,
    },
    wallet: {
      provider: 'deterministic',
      walletId: 'buyer-a',
      address: WALLET,
      network: NETWORK,
    },
    paymentRequired: challenge,
    challengeReceivedAtMs: Date.parse(NOW),
    nowMs: Date.parse(NOW),
    budgetSnapshot: {
      sellerSessionExposureAtomic: snapshot.sellerSessionExposureAtomic,
      sessionExposureAtomic: snapshot.sessionExposureAtomic,
      rolling24hExposureAtomic: snapshot.rolling24hExposureAtomic,
      pendingApprovalCount: 0,
    },
  });
  assert.equal(evaluation.decision, 'allow');
  context.store.transaction((token) => context.policies.recordDecisionInTransaction(token, {
    intentId: captured.id,
    policyVersionId: context.activePolicy.id,
    evaluation,
    decidedAt: NOW,
  }));
  context.intents.transition({
    intentId: captured.id,
    expectedState: 'challenged',
    nextState: 'authorized',
    reasonCode: 'POLICY_ALLOWED',
  });
  return Object.freeze({
    challenge,
    decision: evaluation,
    id: captured.id,
    request,
  });
}

function transitionToRetrying(context, intentId) {
  for (const [expectedState, nextState] of [
    ['authorized', 'reserved'],
    ['reserved', 'signing'],
    ['signing', 'signed'],
    ['signed', 'retrying'],
  ]) {
    context.intents.transition({
      intentId,
      expectedState,
      nextState,
      reasonCode: `TEST_${nextState.toUpperCase()}`,
    });
  }
}

function seedRetryingPaymentAttempt(context, intent, {
  paymentHeader = 'fixture-payment-header',
} = {}) {
  const transitionAt = context.store.readOne(
    'SELECT updated_at FROM budget_reservations WHERE intent_id = ?', [intent.id],
  )?.updated_at ?? NOW;
  const paymentHash = sha256(Buffer.from(paymentHeader, 'ascii'));
  const projection = projectPaymentRequired(intent.challenge);
  const nonce = `0x${sha256(canonicalJson({ intentId: intent.id })).slice('sha256:'.length)}`;
  const paymentPayload = {
    x402Version: 2,
    resource: intent.challenge.resource,
    accepted: intent.challenge.accepts[0],
    payload: {
      signature: `0x${'11'.repeat(65)}`,
      authorization: {
        from: WALLET,
        to: PAY_TO,
        value: intent.decision.amountCeilingAtomic,
        validAfter: '0',
        validBefore: '1785502860',
        nonce,
      },
    },
  };
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, signing_claimed_at, signed_at, retry_started_at,
       created_at, updated_at)
      VALUES (?, ?, 'retrying', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      `payment-${intent.id}`,
      intent.id,
      canonicalJson(projection),
      intent.decision.acceptedIndex,
      canonicalJson(paymentPayload),
      paymentHeader,
      paymentHash,
      intent.decision.quoteId,
      nonce,
      '0',
      '1785502860',
      transitionAt,
      transitionAt,
      transitionAt,
      transitionAt,
      transitionAt,
    );
  }));
  transitionToRetrying(context, intent.id);
  return Object.freeze({ paymentHash, paymentHeader });
}

function seedClaimOnlySigningPaymentAttempt(context, intent, {
  nonce = `0x${sha256(canonicalJson({ claimOnlyIntentId: intent.id })).slice('sha256:'.length)}`,
  validAfter = '1785502800',
  validBefore = '1785502860',
  signingClaimedAt = NOW,
} = {}) {
  const projection = projectPaymentRequired(intent.challenge);
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       quote_id, nonce, valid_after, valid_before, signing_claimed_at,
       created_at, updated_at)
      VALUES (?, ?, 'signing', ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      `payment-${intent.id}`,
      intent.id,
      canonicalJson(projection),
      intent.decision.acceptedIndex,
      intent.decision.quoteId,
      nonce,
      validAfter,
      validBefore,
      signingClaimedAt,
      NOW,
      signingClaimedAt,
    );
  }));
  context.intents.transition({
    intentId: intent.id,
    expectedState: 'authorized',
    nextState: 'reserved',
    reasonCode: 'TEST_RESERVED',
  });
  context.intents.transition({
    intentId: intent.id,
    expectedState: 'reserved',
    nextState: 'signing',
    reasonCode: 'TEST_SIGNING',
  });
  return Object.freeze({ nonce, signingClaimedAt, validAfter, validBefore });
}

function seedReservedPaymentAttempt(context, intent) {
  const projection = projectPaymentRequired(intent.challenge);
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       quote_id, created_at, updated_at)
      VALUES (?, ?, 'reserved', ?, ?, ?, ?, ?)`).run(
      `payment-${intent.id}`,
      intent.id,
      canonicalJson(projection),
      intent.decision.acceptedIndex,
      intent.decision.quoteId,
      NOW,
      NOW,
    );
  }));
  context.intents.transition({
    intentId: intent.id,
    expectedState: 'authorized',
    nextState: 'reserved',
    reasonCode: 'TEST_RESERVED',
  });
}

function seedSignedPaymentAttempt(context, intent, {
  paymentHeader = 'fixture-signed-payment-header',
} = {}) {
  const paymentHash = sha256(Buffer.from(paymentHeader, 'ascii'));
  const projection = projectPaymentRequired(intent.challenge);
  const nonce = `0x${sha256(canonicalJson({ signedIntentId: intent.id })).slice('sha256:'.length)}`;
  const paymentPayload = {
    x402Version: 2,
    resource: intent.challenge.resource,
    accepted: intent.challenge.accepts[0],
    payload: {
      signature: `0x${'11'.repeat(65)}`,
      authorization: {
        from: WALLET,
        to: PAY_TO,
        value: intent.decision.amountCeilingAtomic,
        validAfter: '0',
        validBefore: '1785502860',
        nonce,
      },
    },
  };
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index,
       payment_payload_json, payment_header, payment_hash, quote_id, nonce,
       valid_after, valid_before, signing_claimed_at, signed_at, created_at, updated_at)
      VALUES (?, ?, 'signed', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      `payment-${intent.id}`,
      intent.id,
      canonicalJson(projection),
      intent.decision.acceptedIndex,
      canonicalJson(paymentPayload),
      paymentHeader,
      paymentHash,
      intent.decision.quoteId,
      nonce,
      '0',
      '1785502860',
      NOW,
      NOW,
      NOW,
      NOW,
    );
  }));
  for (const [expectedState, nextState] of [
    ['authorized', 'reserved'],
    ['reserved', 'signing'],
    ['signing', 'signed'],
  ]) {
    context.intents.transition({
      intentId: intent.id,
      expectedState,
      nextState,
      reasonCode: `TEST_${nextState.toUpperCase()}`,
    });
  }
  return Object.freeze({ paymentHash, paymentHeader });
}

function settlementEvidence({ intent, paymentHash, transactionPair = 'aa' }) {
  return Object.freeze({
    source: 'x402-payment-response',
    headerHash: sha256(Buffer.from(`settlement-${intent.id}`, 'ascii')),
    success: true,
    transaction: `0x${transactionPair.repeat(32)}`,
    network: NETWORK,
    payer: WALLET,
    amountAtomic: intent.decision.amountCeilingAtomic,
    paymentHash,
  });
}

function assertKernelError(operation, code) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, code);
    return true;
  });
}

function assertConserved(context, intentId) {
  const row = context.store.readOne(
    'SELECT * FROM budget_reservations WHERE intent_id = ?', [intentId],
  );
  assert.ok(row);
  const ceiling = context.store.readOne(
    'SELECT amount_ceiling_atomic FROM policy_decisions WHERE intent_id = ?', [intentId],
  ).amount_ceiling_atomic;
  const total = BigInt(row.reserved_atomic)
    + BigInt(row.committed_atomic)
    + BigInt(row.released_atomic)
    + BigInt(row.unresolved_atomic);
  assert.equal(total.toString(), ceiling);
  for (const value of [
    row.reserved_atomic,
    row.committed_atomic,
    row.released_atomic,
    row.unresolved_atomic,
  ]) assert.equal(typeof value, 'string');
}

function commitIntent(context, intent, transactionPair = 'aa') {
  context.ledger.reserve({
    intentId: intent.id,
    amountAtomic: intent.decision.amountCeilingAtomic,
  });
  const signed = seedRetryingPaymentAttempt(context, intent);
  const evidence = settlementEvidence({ intent, paymentHash: signed.paymentHash, transactionPair });
  context.ledger.commit({ intentId: intent.id, settlementEvidence: evidence });
  return Object.freeze({ evidence, signed });
}

function makeSignedUnresolved(context, intent, reasonCode = 'PAID_RESPONSE_AMBIGUOUS') {
  context.ledger.reserve({
    intentId: intent.id,
    amountAtomic: intent.decision.amountCeilingAtomic,
  });
  const signed = seedRetryingPaymentAttempt(context, intent);
  context.store.transaction((token) => {
    const held = context.ledger.holdUnresolvedInTransaction(token, {
      intentId: intent.id,
      reasonCode,
    });
    context.store.within(token, ({ db }) => {
      const changed = db.prepare(`UPDATE payment_attempts
        SET state = 'unresolved', reason_code = ?, updated_at = ?
        WHERE intent_id = ? AND state = 'retrying'`).run(reasonCode, NOW, intent.id);
      assert.equal(changed.changes, 1n);
      db.prepare(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES (?, 'payment_unresolved', ?, 1, ?)`).run(intent.id, reasonCode, NOW);
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'retrying',
      nextState: 'unresolved',
      reasonCode,
    });
    return held;
  });
  return signed;
}

function localAttemptHash(context, intentId) {
  const attempt = context.store.readOne(
    'SELECT * FROM payment_attempts WHERE intent_id = ?', [intentId],
  );
  const intent = context.store.readOne(
    'SELECT * FROM spend_intents WHERE id = ?', [intentId],
  );
  const decision = context.store.readOne(
    'SELECT * FROM policy_decisions WHERE intent_id = ?', [intentId],
  );
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-attempt-binding.v1',
    intentHash: intent.intent_hash,
    challengeHash: intent.challenge_hash,
    quoteId: attempt.quote_id,
    paymentPayloadHash: sha256(attempt.payment_payload_json),
    paymentHeaderHash: attempt.payment_hash,
    network: context.activePolicy.policy.network,
    payer: WALLET,
    payee: PAY_TO,
    asset: context.activePolicy.policy.asset,
    amountAtomic: decision.amount_ceiling_atomic,
    nonce: attempt.nonce,
    validAfter: attempt.valid_after,
    validBefore: attempt.valid_before,
  }));
}

function localRefundHash(context, intentId, refundTransactionId) {
  const attempt = context.store.readOne(
    'SELECT * FROM payment_attempts WHERE intent_id = ?', [intentId],
  );
  const intent = context.store.readOne(
    'SELECT * FROM spend_intents WHERE id = ?', [intentId],
  );
  const decision = context.store.readOne(
    'SELECT amount_ceiling_atomic FROM policy_decisions WHERE intent_id = ?', [intentId],
  );
  const seller = context.activePolicy.policy.sellers[0];
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-binding.v1',
    intentHash: intent.intent_hash,
    originalTransactionId: attempt.transaction_id,
    refundTransactionId,
    network: context.activePolicy.policy.network,
    sellerOrigin: SELLER,
    asset: context.activePolicy.policy.asset,
    originalPayer: WALLET,
    originalPayee: PAY_TO,
    refundSource: seller.refundSource,
    refundSigner: seller.refundSigner,
    amountAtomic: decision.amount_ceiling_atomic,
  }));
}

function refundAttestation(context, intentId, originalTransactionId, refundTransactionId) {
  const intent = context.store.readOne(
    'SELECT * FROM spend_intents WHERE id = ?', [intentId],
  );
  const decision = context.store.readOne(
    'SELECT amount_ceiling_atomic FROM policy_decisions WHERE intent_id = ?', [intentId],
  );
  const seller = context.activePolicy.policy.sellers[0];
  return Object.freeze({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund.v1',
    network: context.activePolicy.policy.network,
    sellerOrigin: SELLER,
    intentHash: intent.intent_hash,
    originalTransactionId,
    refundTransactionId,
    asset: context.activePolicy.policy.asset,
    originalPayer: WALLET,
    originalPayee: PAY_TO,
    refundSource: seller.refundSource,
    amountAtomic: decision.amount_ceiling_atomic,
    issuedAt: NOW,
    expiresAt: '2026-07-31T12:15:00.000Z',
    signer: seller.refundSigner,
  });
}

function insertReconciliation(context, {
  id,
  intentId,
  kind,
  outcome,
  evidence,
  recordedAt = NOW,
}) {
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO reconciliations
      (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
      id,
      intentId,
      kind,
      outcome,
      canonicalJson(evidence),
      OPERATOR_HASH,
      recordedAt,
    );
  }));
}

function insertPaymentCandidate(context, {
  intentId,
  transactionId,
  id = `candidate-${intentId}`,
}) {
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO payment_reconciliation_candidates
      (id, intent_id, transaction_id, state, created_at, updated_at)
      VALUES (?, ?, ?, 'pending', ?, ?)`).run(
      id,
      intentId,
      transactionId,
      NOW,
      NOW,
    );
  }));
  return id;
}

function settledTransferProof(context, intent, transactionId) {
  return Object.freeze({
    kind: 'settled_transfer',
    transactionId,
    rpcProofHash: sha256(canonicalJson({ fixture: `settled-${intent.id}` })),
    localAttemptHash: localAttemptHash(context, intent.id),
  });
}

function unusedAuthorizationProof(context, intent) {
  const attempt = context.store.readOne(
    'SELECT * FROM payment_attempts WHERE intent_id = ?', [intent.id],
  );
  return Object.freeze({
    kind: 'authorization_unused_after_expiry',
    network: NETWORK,
    asset: ASSET,
    payer: WALLET,
    nonce: attempt.nonce,
    validBefore: attempt.valid_before,
    authorizationState: false,
    observedBlockNumber: '1234570',
    observedBlockHash: `0x${'ef'.repeat(32)}`,
    observedBlockTimestamp: attempt.valid_before,
    confirmations: 3,
  });
}

function eventHead(context) {
  return context.store.events().map((event) => event.event_hash);
}

function plainRow(row) {
  return row === undefined ? undefined : { ...row };
}

function childResult(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
}

async function waitForFiles(files, timeoutMilliseconds = 5_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (!files.every((file) => fs.existsSync(file))) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for budget writers');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

test('conserves the full ceiling through reserve, commit, release, and unresolved hold', (t) => {
  const context = setup(t);
  assert.deepEqual(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), {
    sellerSessionExposureAtomic: '0',
    sessionExposureAtomic: '0',
    rolling24hExposureAtomic: '0',
    walletBlocked: false,
  });

  const first = authorizeIntent(context, { amountAtomic: '250000', label: 'first' });
  context.ledger.reserve({ intentId: first.id, amountAtomic: '250000' });
  assertConserved(context, first.id);
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).sessionExposureAtomic, '250000');
  const signed = seedRetryingPaymentAttempt(context, first);
  context.ledger.commit({
    intentId: first.id,
    settlementEvidence: settlementEvidence({ intent: first, paymentHash: signed.paymentHash }),
  });
  assertConserved(context, first.id);
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).rolling24hExposureAtomic, '250000');

  const second = authorizeIntent(context, { amountAtomic: '300000', label: 'second' });
  context.ledger.reserve({ intentId: second.id, amountAtomic: '300000' });
  assertConserved(context, second.id);
  context.ledger.release({ intentId: second.id, reasonCode: 'SIGNER_REJECTED' });
  assertConserved(context, second.id);
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).sessionExposureAtomic, '250000');

  const third = authorizeIntent(context, { amountAtomic: '400000', label: 'third' });
  context.ledger.reserve({ intentId: third.id, amountAtomic: '400000' });
  assertConserved(context, third.id);
  context.ledger.holdUnresolved({
    intentId: third.id,
    reasonCode: 'PAID_RESPONSE_AMBIGUOUS',
  });
  assertConserved(context, third.id);
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);

  const fourth = authorizeIntent(context, { amountAtomic: '1', label: 'fourth' });
  assertKernelError(
    () => context.ledger.reserve({ intentId: fourth.id, amountAtomic: '1' }),
    'WALLET_UNRESOLVED',
  );

  for (const row of context.store.readAll('SELECT * FROM budget_reservations ORDER BY rowid')) {
    const total = BigInt(row.reserved_atomic)
      + BigInt(row.committed_atomic)
      + BigInt(row.released_atomic)
      + BigInt(row.unresolved_atomic);
    const ceiling = context.store.readOne(
      'SELECT amount_ceiling_atomic FROM policy_decisions WHERE intent_id = ?',
      [row.intent_id],
    ).amount_ceiling_atomic;
    assert.equal(total.toString(), ceiling);
    for (const value of [
      row.reserved_atomic,
      row.committed_atomic,
      row.released_atomic,
      row.unresolved_atomic,
    ]) assert.equal(typeof value, 'string');
  }
  assert.equal(context.store.verifyEventChain(), true);
});

test('a Spend Intent cannot reserve twice and an amount cannot substitute its decision ceiling', (t) => {
  const context = setup(t);
  const intent = authorizeIntent(context, { amountAtomic: '250000', label: 'duplicate' });
  assertKernelError(
    () => context.ledger.reserve({ intentId: intent.id, amountAtomic: '249999' }),
    'BUDGET_AMOUNT_MISMATCH',
  );
  context.ledger.reserve({ intentId: intent.id, amountAtomic: '250000' });
  assertKernelError(
    () => context.ledger.reserve({ intentId: intent.id, amountAtomic: '250000' }),
    'BUDGET_ALREADY_RESERVED',
  );
});

test('reserved budgets expose only exact in-flight PaymentAttempt states', async (t) => {
  const snapshotAt = '2026-07-31T12:00:02.000Z';
  const before = '2026-07-31T11:59:59.000Z';
  const after = '2026-07-31T12:00:01.000Z';

  const fixture = (st, state, label) => {
    const context = setup(st);
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `reserved-attempt-${state}-${label}`,
    });
    context.ledger.reserve({ intentId: intent.id, amountAtomic: '100' });
    if (state === 'reserved') seedReservedPaymentAttempt(context, intent);
    else if (state === 'signing') seedClaimOnlySigningPaymentAttempt(context, intent);
    else if (state === 'signed') seedSignedPaymentAttempt(context, intent);
    else if (state === 'retrying') seedRetryingPaymentAttempt(context, intent);
    return { context, intent };
  };

  const assertVisible = (context, intent) => {
    assert.equal(context.ledger.snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: snapshotAt,
    }).sessionExposureAtomic, '100');
    assertKernelError(() => context.ledger.reserve({
      intentId: intent.id,
      amountAtomic: '100',
    }), 'BUDGET_ALREADY_RESERVED');
  };

  const assertCorrupt = (context, intent) => {
    assertKernelError(() => context.ledger.snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: snapshotAt,
    }), 'BUDGET_CORRUPTION');
    assertKernelError(() => context.ledger.reserve({
      intentId: intent.id,
      amountAtomic: '100',
    }), 'BUDGET_CORRUPTION');
  };

  await t.test('no PaymentAttempt is visible before its aggregate insert', (st) => {
    const { context, intent } = fixture(st, 'none', 'legal');
    assertVisible(context, intent);
  });

  for (const state of ['reserved', 'signing', 'signed', 'retrying']) {
    await t.test(`${state} exact material is visible`, (st) => {
      const { context, intent } = fixture(st, state, 'legal');
      assertVisible(context, intent);
    });
  }

  const corruptions = {
    reserved: [
      ['challenge binding substitution', "quote_id = 'quote-substituted'"],
      ['created before reservation', `created_at = '${before}'`],
      ['updatedAt detached from reservation', `updated_at = '${after}'`],
      ['unexpected terminal reason', "reason_code = 'UNEXPECTED_REASON'"],
    ],
    signing: [
      ['partial signing claim', 'nonce = NULL'],
      ['signing claim before creation', `signing_claimed_at = '${before}'`],
      ['updatedAt detached from signing claim', `updated_at = '${after}'`],
      ['unexpected terminal reason', "reason_code = 'UNEXPECTED_REASON'"],
    ],
    signed: [
      ['payment hash substitution', `payment_hash = 'sha256:${'00'.repeat(32)}'`],
      ['signedAt before signing claim', `signed_at = '${before}'`],
      ['updatedAt detached from signed transition', `updated_at = '${after}'`],
      ['unexpected terminal reason', "reason_code = 'UNEXPECTED_REASON'"],
    ],
    retrying: [
      ['missing retry timestamp', 'retry_started_at = NULL'],
      ['retry before signed bytes', `retry_started_at = '${before}'`],
      ['updatedAt detached from retry transition', `updated_at = '${after}'`],
      ['unexpected terminal reason', "reason_code = 'UNEXPECTED_REASON'"],
    ],
  };

  for (const [state, cases] of Object.entries(corruptions)) {
    for (const [name, assignment] of cases) {
      await t.test(`${state}: ${name}`, (st) => {
        const { context, intent } = fixture(st, state, name.replaceAll(' ', '-'));
        context.store.execForTest(`UPDATE payment_attempts SET ${assignment}
          WHERE intent_id = '${intent.id}'`);
        assertCorrupt(context, intent);
      });
    }
  }

  for (const illegalState of ['unresolved', 'rejected', 'settled']) {
    await t.test(`reserved budget rejects ${illegalState} PaymentAttempt`, (st) => {
      const sourceState = illegalState === 'rejected' ? 'reserved' : 'retrying';
      const { context, intent } = fixture(st, sourceState, `illegal-${illegalState}`);
      if (illegalState === 'unresolved') {
        context.store.execForTest(`UPDATE payment_attempts
          SET state = 'unresolved', reason_code = 'PAID_RESPONSE_AMBIGUOUS'
          WHERE intent_id = '${intent.id}'`);
      } else if (illegalState === 'rejected') {
        context.store.execForTest(`UPDATE payment_attempts
          SET state = 'rejected', reason_code = 'SIGNER_REJECTED'
          WHERE intent_id = '${intent.id}'`);
      } else {
        context.store.execForTest(`UPDATE payment_attempts SET state = 'settled',
          settlement_json = '{}', transaction_id = '0x${'ab'.repeat(32)}',
          settled_at = '${NOW}' WHERE intent_id = '${intent.id}'`);
      }
      assertCorrupt(context, intent);
    });
  }
});

test('reservation rejects a local clock before its immutable challenge and decision', (t) => {
  let clock = NOW;
  const context = setup(t, { now: () => clock });
  const intent = authorizeIntent(context, { amountAtomic: '100', label: 'regressed-clock' });
  const before = eventHead(context);
  clock = '2026-07-31T11:59:59.999Z';
  assertKernelError(() => context.ledger.reserve({
    intentId: intent.id,
    amountAtomic: '100',
  }), 'BUDGET_TIME');
  assert.equal(context.store.readOne(
    'SELECT intent_id FROM budget_reservations WHERE intent_id = ?', [intent.id],
  ), undefined);
  assert.deepEqual(eventHead(context), before);
});

test('seller, session, and rolling ceilings accept exact totals and reject one atomic over', (t) => {
  const cases = [
    {
      label: 'seller',
      policy: testPolicy({
        seller: { sellerSessionMaxAtomic: '1000000' },
        sessionMaxAtomic: '2000000',
        rolling24hMaxAtomic: '5000000',
      }),
    },
    {
      label: 'session',
      policy: testPolicy({
        seller: { sellerSessionMaxAtomic: '2000000' },
        sessionMaxAtomic: '1000000',
        rolling24hMaxAtomic: '5000000',
      }),
    },
    {
      label: 'rolling',
      policy: testPolicy({
        seller: { sellerSessionMaxAtomic: '2000000' },
        sessionMaxAtomic: '2000000',
        rolling24hMaxAtomic: '1000000',
      }),
    },
  ];

  for (const fixture of cases) {
    const context = setup(t, { policyDocument: fixture.policy });
    const first = authorizeIntent(context, {
      amountAtomic: '600000',
      label: `${fixture.label}-first`,
      budgetSnapshot: ZERO_BUDGET,
    });
    const exact = authorizeIntent(context, {
      amountAtomic: '400000',
      label: `${fixture.label}-exact`,
      budgetSnapshot: ZERO_BUDGET,
    });
    const over = authorizeIntent(context, {
      amountAtomic: '1',
      label: `${fixture.label}-over`,
      budgetSnapshot: ZERO_BUDGET,
    });
    context.ledger.reserve({ intentId: first.id, amountAtomic: '600000' });
    context.ledger.reserve({ intentId: exact.id, amountAtomic: '400000' });
    assertKernelError(
      () => context.ledger.reserve({ intentId: over.id, amountAtomic: '1' }),
      'LIMIT_EXCEEDED',
    );
    const snapshot = context.ledger.snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: NOW,
    });
    assert.equal(snapshot.sellerSessionExposureAtomic, '1000000');
    assert.equal(snapshot.sessionExposureAtomic, '1000000');
    assert.equal(snapshot.rolling24hExposureAtomic, '1000000');
  }
});

test('rolling exposure excludes the exact 24-hour boundary but retains every active hold', (t) => {
  let clock = NOW;
  const context = setup(t, { now: () => clock });
  const boundary = authorizeIntent(context, {
    amountAtomic: '100',
    label: 'boundary',
    budgetSnapshot: ZERO_BUDGET,
  });
  const inside = authorizeIntent(context, {
    amountAtomic: '200',
    label: 'inside',
    budgetSnapshot: ZERO_BUDGET,
  });
  const oldActive = authorizeIntent(context, {
    amountAtomic: '300',
    label: 'old-active',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: oldActive.id, amountAtomic: '300' });
  commitIntent(context, boundary, 'b1');
  clock = '2026-07-31T12:00:00.001Z';
  commitIntent(context, inside, 'b2');
  const snapshot = context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: '2026-08-01T12:00:00.000Z',
  });
  assert.deepEqual(snapshot, {
    sellerSessionExposureAtomic: '600',
    sessionExposureAtomic: '600',
    rolling24hExposureAtomic: '500',
    walletBlocked: false,
  });
});

test('execution and refund blockers are wallet-wide and both must close', (t) => {
  const refundContext = setup(t);
  const paid = authorizeIntent(refundContext, {
    amountAtomic: '250000',
    label: 'blocked-refund-paid',
  });
  const { evidence } = commitIntent(refundContext, paid);
  const target = authorizeIntent(refundContext, {
    amountAtomic: '1',
    label: 'blocked-refund-target',
    budgetSnapshot: ZERO_BUDGET,
  });
  refundContext.store.transaction((token) => refundContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'failed', 500, ?, ?, ?)`).run(
      paid.id,
      sha256(Buffer.from('failed response')),
      canonicalJson({ source: 'test' }),
      NOW,
    );
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at)
      VALUES (?, 'refund_pending', 'UPSTREAM_FAILED', 1, ?)`).run(paid.id, NOW);
    db.prepare(`INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'pending', ?, ?)`).run(
      `refund-${paid.id}`,
      paid.id,
      evidence.transaction,
      paid.decision.amountCeilingAtomic,
      NOW,
      NOW,
    );
  }));

  assert.equal(refundContext.ledger.snapshot({
    sessionId: refundContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assertKernelError(
    () => refundContext.ledger.reserve({ intentId: target.id, amountAtomic: '1' }),
    'WALLET_RESOLUTION_REQUIRED',
  );

  refundContext.store.transaction((token) => refundContext.store.within(token, ({ db }) => {
    db.prepare(`UPDATE refunds
      SET state = 'confirmed', evidence_json = ?, refund_transaction_id = ?, updated_at = ?
      WHERE intent_id = ?`).run(
      canonicalJson({ source: 'test-only' }),
      `0x${'ef'.repeat(32)}`,
      NOW,
      paid.id,
    );
  }));
  assertKernelError(() => refundContext.ledger.snapshot({
    sessionId: refundContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');

  const splitContext = setup(t);
  const splitPaid = authorizeIntent(splitContext, {
    amountAtomic: '100',
    label: 'split-resolution-paid',
  });
  const splitPayment = commitIntent(splitContext, splitPaid, 'dd');
  splitContext.store.transaction((token) => splitContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'failed', 500, ?, ?, ?)`).run(
      splitPaid.id,
      sha256(Buffer.from('split failed response')),
      canonicalJson({ source: 'test' }),
      NOW,
    );
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
      VALUES (?, 'resolved', 'UPSTREAM_FAILED', 0, ?, ?)`).run(splitPaid.id, NOW, NOW);
    db.prepare(`INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'rejected', ?, ?)`).run(
      `refund-${splitPaid.id}`,
      splitPaid.id,
      splitPayment.evidence.transaction,
      splitPaid.decision.amountCeilingAtomic,
      NOW,
      NOW,
    );
  }));
  assertKernelError(() => splitContext.ledger.snapshot({
    sessionId: splitContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');

  const unknownContext = setup(t);
  const unknown = authorizeIntent(unknownContext, {
    amountAtomic: '100',
    label: 'blocked-unknown-paid',
  });
  commitIntent(unknownContext, unknown, 'de');
  const unknownTarget = authorizeIntent(unknownContext, {
    amountAtomic: '1',
    label: 'blocked-unknown-target',
    budgetSnapshot: ZERO_BUDGET,
  });
  unknownContext.store.transaction((token) => unknownContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'unknown', NULL, NULL, ?, ?)`).run(
      unknown.id,
      canonicalJson({ source: 'test' }),
      NOW,
    );
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at)
      VALUES (?, 'reconciliation_required', 'EXECUTION_UNKNOWN', 1, ?)`).run(
      unknown.id,
      NOW,
    );
  }));
  assert.equal(unknownContext.ledger.snapshot({
    sessionId: unknownContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  assertKernelError(
    () => unknownContext.ledger.reserve({ intentId: unknownTarget.id, amountAtomic: '1' }),
    'WALLET_RESOLUTION_REQUIRED',
  );
  unknownContext.store.transaction((token) => unknownContext.store.within(token, ({ db }) => {
    db.prepare(`UPDATE execution_outcomes
      SET state = 'succeeded', http_status = 200, response_hash = ?, recorded_at = ?
      WHERE intent_id = ?`).run(
      sha256(Buffer.from('late execution evidence')),
      NOW,
      unknown.id,
    );
  }));
  assertKernelError(() => unknownContext.ledger.snapshot({
    sessionId: unknownContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  unknownContext.store.transaction((token) => unknownContext.store.within(token, ({ db }) => {
    db.prepare(`UPDATE execution_resolutions
      SET state = 'resolved', blocks_wallet = 0, resolved_at = ?
      WHERE intent_id = ?`).run(NOW, unknown.id);
  }));
  assertKernelError(() => unknownContext.ledger.snapshot({
    sessionId: unknownContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assert.equal(unknownContext.store.readOne(
    'SELECT intent_id FROM budget_reservations WHERE intent_id = ?', [unknownTarget.id],
  ), undefined);
});

test('a blocker in a replacement Spend Session blocks every session for the wallet', (t) => {
  const originalContext = setup(t);
  const replacementContext = rotateSessionPolicy(originalContext);
  const held = authorizeIntent(replacementContext, {
    amountAtomic: '100',
    label: 'replacement-session-hold',
  });
  makeSignedUnresolved(replacementContext, held);

  assert.equal(originalContext.ledger.snapshot({
    sessionId: originalContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);
  const target = authorizeIntent(replacementContext, {
    amountAtomic: '1',
    label: 'replacement-session-target',
    budgetSnapshot: ZERO_BUDGET,
  });
  assertKernelError(() => replacementContext.ledger.reserve({
    intentId: target.id,
    amountAtomic: '1',
  }), 'WALLET_UNRESOLVED');
  assert.equal(replacementContext.store.readOne(
    'SELECT intent_id FROM budget_reservations WHERE intent_id = ?', [target.id],
  ), undefined);
});

test('file-backed snapshots survive reopen without numeric monetary projections', (t) => {
  const fileAuthority = authority(t, 'wallet-kernel-budget-reopen-');
  const context = setup(t, { fileAuthority });
  const intent = authorizeIntent(context, { amountAtomic: '250000', label: 'reopen' });
  context.ledger.reserve({ intentId: intent.id, amountAtomic: '250000' });
  const before = context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  });
  context.store.close();

  const reopened = openKernelStore({
    filePath: fileAuthority.databasePath,
    pathTrust: fileAuthority.pathTrust,
    now: () => NOW,
  });
  try {
    const after = createBudgetLedger({ store: reopened, now: () => NOW }).snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: NOW,
    });
    assert.deepEqual(after, before);
    for (const [key, value] of Object.entries(after)) {
      if (key.endsWith('Atomic')) assert.equal(typeof value, 'string');
    }
  } finally {
    reopened.close();
  }
});

test('two processes cannot oversubscribe one seller/session ceiling', async (t) => {
  const fileAuthority = authority(t, 'wallet-kernel-budget-race-');
  const context = setup(t, { fileAuthority });
  const first = authorizeIntent(context, {
    amountAtomic: '600000',
    label: 'race-first',
    budgetSnapshot: ZERO_BUDGET,
  });
  const second = authorizeIntent(context, {
    amountAtomic: '600000',
    label: 'race-second',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.store.close();

  const releaseFile = path.join(fileAuthority.directory, 'release');
  const readyFiles = [
    path.join(fileAuthority.directory, 'ready-first'),
    path.join(fileAuthority.directory, 'ready-second'),
  ];
  const children = [first, second].map((intent, index) => spawn(process.execPath, [
    '--no-warnings',
    RACE_FIXTURE,
    fileAuthority.databasePath,
    fileAuthority.directory,
    intent.id,
    '600000',
    NOW,
    readyFiles[index],
    releaseFile,
  ], { stdio: ['ignore', 'pipe', 'pipe'] }));
  const resultsPromise = Promise.all(children.map(childResult));
  await waitForFiles(readyFiles);
  fs.writeFileSync(releaseFile, 'release', { flag: 'wx', mode: 0o600 });
  const results = await resultsPromise;
  for (const result of results) {
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.signal, null);
    assert.equal(result.stderr, '');
  }
  assert.deepEqual(
    results.map((result) => result.stdout.trim()).sort(),
    ['LIMIT_EXCEEDED', 'reserved'],
  );

  const reopened = openKernelStore({
    filePath: fileAuthority.databasePath,
    pathTrust: fileAuthority.pathTrust,
    now: () => NOW,
  });
  try {
    const rows = reopened.readAll('SELECT * FROM budget_reservations ORDER BY intent_id');
    assert.equal(rows.length, 1);
    assert.equal(rows[0].reserved_atomic, '600000');
    assert.equal(reopened.verifyEventChain(), true);
  } finally {
    reopened.close();
  }
});

test('commit is exact-replay idempotent and rejects state, binding, and transaction reuse', (t) => {
  const context = setup(t);
  const first = authorizeIntent(context, { amountAtomic: '250000', label: 'commit-first' });
  const committed = commitIntent(context, first, 'aa');
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, transaction_id, settlement_json FROM payment_attempts
      WHERE intent_id = ?`, [first.id],
  )), {
    state: 'settled',
    transaction_id: committed.evidence.transaction,
    settlement_json: canonicalJson(committed.evidence),
  });
  assertConserved(context, first.id);
  const eventsAfterCommit = context.store.events();
  const replay = context.ledger.commit({
    intentId: first.id,
    settlementEvidence: committed.evidence,
  });
  assert.equal(replay.state, 'committed');
  assert.deepEqual(context.store.events(), eventsAfterCommit);
  assertKernelError(() => context.ledger.commit({
    intentId: first.id,
    settlementEvidence: Object.freeze({
      ...committed.evidence,
      transaction: `0x${'bb'.repeat(32)}`,
    }),
  }), 'BUDGET_IDEMPOTENCY_CONFLICT');

  const second = authorizeIntent(context, {
    amountAtomic: '250000',
    label: 'commit-second',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: second.id, amountAtomic: '250000' });
  const signedSecond = seedRetryingPaymentAttempt(context, second);
  assertKernelError(() => context.ledger.commit({
    intentId: second.id,
    settlementEvidence: Object.freeze({
      ...settlementEvidence({ intent: second, paymentHash: signedSecond.paymentHash }),
      transaction: `0x${'AA'.repeat(32)}`,
    }),
  }), 'TRANSACTION_REUSED');

  const missing = authorizeIntent(context, {
    amountAtomic: '1',
    label: 'commit-missing',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: missing.id, amountAtomic: '1' });
  transitionToRetrying(context, missing.id);
  assertKernelError(() => context.ledger.commit({
    intentId: missing.id,
    settlementEvidence: settlementEvidence({
      intent: missing,
      paymentHash: `sha256:${'12'.repeat(32)}`,
      transactionPair: 'cc',
    }),
  }), 'PAYMENT_ATTEMPT_MISSING');

  const bound = authorizeIntent(context, {
    amountAtomic: '1',
    label: 'commit-bound',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: bound.id, amountAtomic: '1' });
  const signedBound = seedRetryingPaymentAttempt(context, bound);
  assertKernelError(() => context.ledger.commit({
    intentId: bound.id,
    settlementEvidence: Object.freeze({
      ...settlementEvidence({
        intent: bound,
        paymentHash: signedBound.paymentHash,
        transactionPair: 'dd',
      }),
      payer: '0x4000000000000000000000000000000000000000',
    }),
  }), 'SETTLEMENT_BINDING_MISMATCH');
  assertKernelError(() => context.ledger.commit({
    intentId: bound.id,
    settlementEvidence: Object.freeze({
      ...settlementEvidence({
        intent: bound,
        paymentHash: signedBound.paymentHash,
        transactionPair: 'dd',
      }),
      amountAtomic: '2',
    }),
  }), 'SETTLEMENT_BINDING_MISMATCH');
  assertKernelError(() => context.ledger.commit({
    intentId: bound.id,
    settlementEvidence: Object.freeze({
      ...settlementEvidence({
        intent: bound,
        paymentHash: signedBound.paymentHash,
        transactionPair: 'dd',
      }),
      injected: true,
    }),
  }), 'SETTLEMENT_EVIDENCE');

  const wrongStateContext = setup(t);
  const wrongState = authorizeIntent(wrongStateContext, {
    amountAtomic: '1',
    label: 'commit-wrong-attempt-state',
    budgetSnapshot: ZERO_BUDGET,
  });
  wrongStateContext.ledger.reserve({ intentId: wrongState.id, amountAtomic: '1' });
  const signedWrongState = seedRetryingPaymentAttempt(wrongStateContext, wrongState);
  wrongStateContext.store.transaction((token) => wrongStateContext.store.within(token, ({ db }) => {
    db.prepare("UPDATE payment_attempts SET state = 'signed' WHERE intent_id = ?")
      .run(wrongState.id);
  }));
  assertKernelError(() => wrongStateContext.ledger.commit({
    intentId: wrongState.id,
    settlementEvidence: settlementEvidence({
      intent: wrongState,
      paymentHash: signedWrongState.paymentHash,
      transactionPair: 'de',
    }),
  }), 'BUDGET_CORRUPTION');
  assert.equal(wrongStateContext.store.readOne(
    'SELECT transaction_id FROM payment_attempts WHERE intent_id = ?', [wrongState.id],
  ).transaction_id, null);
  assert.equal(wrongStateContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [wrongState.id],
  ).state, 'reserved');

  const atomic = authorizeIntent(context, {
    amountAtomic: '1',
    label: 'commit-atomic-attempt',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: atomic.id, amountAtomic: '1' });
  const signedAtomic = seedRetryingPaymentAttempt(context, atomic);
  const atomicEvidence = settlementEvidence({
    intent: atomic,
    paymentHash: signedAtomic.paymentHash,
    transactionPair: 'df',
  });
  const beforeAtomic = eventHead(context);
  assert.throws(() => context.store.transaction((token) => {
    context.ledger.commitInTransaction(token, {
      intentId: atomic.id,
      settlementEvidence: atomicEvidence,
    });
    throw new Error('commit aggregate rollback');
  }), /commit aggregate rollback/);
  assert.deepEqual(eventHead(context), beforeAtomic);
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, transaction_id, settlement_json FROM payment_attempts
      WHERE intent_id = ?`, [atomic.id],
  )), { state: 'retrying', transaction_id: null, settlement_json: null });
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [atomic.id],
  ).state, 'reserved');
  assertConserved(context, atomic.id);
});

test('snapshot and exact commit replay reject every persisted payment chronology break', async (t) => {
  const before = '2026-07-31T11:59:59.000Z';
  const after = '2026-07-31T12:00:01.000Z';
  const snapshotAt = '2026-07-31T12:00:02.000Z';
  const corruptions = [
    {
      name: 'signedAt before its signing claim',
      assignment: `signed_at = '${before}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'signedAt after updatedAt',
      assignment: `signed_at = '${after}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'retryStartedAt before signedAt',
      assignment: `retry_started_at = '${before}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'retryStartedAt after updatedAt',
      assignment: `retry_started_at = '${after}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'settledAt before retryStartedAt',
      assignment: `settled_at = '${before}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'settledAt after updatedAt',
      assignment: `settled_at = '${after}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
    {
      name: 'settled transition detached from its commit event',
      assignment: `settled_at = '${after}', updated_at = '${after}'`,
      replayCode: 'BUDGET_CORRUPTION',
    },
  ];

  const corruptedCommitted = (st, corruption, operation) => {
    const context = setup(st);
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `chronology-${operation}-${corruption.name.replaceAll(' ', '-')}`,
    });
    const committed = commitIntent(context, intent, '4a');
    context.store.execForTest(`UPDATE payment_attempts SET ${corruption.assignment}
      WHERE intent_id = '${intent.id}'`);
    return { committed, context, intent };
  };

  for (const corruption of corruptions) {
    await t.test(`${corruption.name}: snapshot`, (st) => {
      const { context } = corruptedCommitted(st, corruption, 'snapshot');
      assertKernelError(() => context.ledger.snapshot({
        sessionId: context.session.id,
        sellerOrigin: SELLER,
        at: snapshotAt,
      }), 'BUDGET_CORRUPTION');
    });

    await t.test(`${corruption.name}: exact commit replay`, (st) => {
      const { committed, context, intent } = corruptedCommitted(st, corruption, 'replay');
      assertKernelError(() => context.ledger.commit({
        intentId: intent.id,
        settlementEvidence: committed.evidence,
      }), corruption.replayCode);
    });
  }
});

test('snapshots reject unresolved and trusted-rejected attempt chronology corruption', async (t) => {
  const before = '2026-07-31T11:59:59.000Z';
  const corruptions = [
    {
      name: 'signedAt after updatedAt',
      assignment(after) { return `signed_at = '${after}'`; },
    },
    {
      name: 'retryStartedAt before signedAt',
      assignment() { return `retry_started_at = '${before}'`; },
    },
    {
      name: 'updatedAt detached from terminal transition',
      assignment(after) { return `updated_at = '${after}'`; },
    },
  ];

  const unresolvedFixture = (st, corruption) => {
    const context = setup(st);
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `unresolved-history-${corruption.name.replaceAll(' ', '-')}`,
    });
    makeSignedUnresolved(context, intent);
    const after = '2026-07-31T12:00:01.000Z';
    context.store.execForTest(`UPDATE payment_attempts
      SET ${corruption.assignment(after)} WHERE intent_id = '${intent.id}'`);
    return { context, snapshotAt: '2026-07-31T12:00:02.000Z' };
  };

  const rejectedFixture = (st, corruption) => {
    let clock = NOW;
    const context = setup(st, { now: () => clock });
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `rejected-history-${corruption.name.replaceAll(' ', '-')}`,
    });
    makeSignedUnresolved(context, intent);
    insertPaymentCandidate(context, {
      intentId: intent.id,
      transactionId: `0x${'62'.repeat(32)}`,
    });
    insertReconciliation(context, {
      id: `rejected-history-proof-${intent.id}`,
      intentId: intent.id,
      kind: 'payment',
      outcome: 'rejected',
      evidence: unusedAuthorizationProof(context, intent),
      recordedAt: AFTER_EXPIRY,
    });
    clock = AFTER_EXPIRY;
    context.store.transaction((token) => {
      context.ledger.resolvePaymentInTransaction(token, {
        intentId: intent.id,
        outcome: 'rejected',
        evidenceId: `rejected-history-proof-${intent.id}`,
      });
      context.intents.transitionInTransaction(token, {
        intentId: intent.id,
        expectedState: 'unresolved',
        nextState: 'terminal',
        reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      });
    });
    const after = '2026-07-31T13:02:01.000Z';
    context.store.execForTest(`UPDATE payment_attempts
      SET ${corruption.assignment(after)} WHERE intent_id = '${intent.id}'`);
    return { context, snapshotAt: '2026-07-31T13:02:02.000Z' };
  };

  for (const [state, fixture] of [
    ['unresolved', unresolvedFixture],
    ['trusted-rejected', rejectedFixture],
  ]) {
    for (const corruption of corruptions) {
      await t.test(`${state}: ${corruption.name}`, (st) => {
        const { context, snapshotAt } = fixture(st, corruption);
        assertKernelError(() => context.ledger.snapshot({
          sessionId: context.session.id,
          sellerOrigin: SELLER,
          at: snapshotAt,
        }), 'BUDGET_CORRUPTION');
      });
    }
  }
});

test('release and unresolved hold have exact replay semantics and never trust shaped errors', (t) => {
  const context = setup(t);
  const released = authorizeIntent(context, { amountAtomic: '100', label: 'released' });
  context.ledger.reserve({ intentId: released.id, amountAtomic: '100' });
  const releasedProjection = context.ledger.release({
    intentId: released.id,
    reasonCode: 'UNSIGNED_CANCELLED',
  });
  const eventsAfterRelease = context.store.events();
  assert.equal(releasedProjection.state, 'released');
  assert.deepEqual(context.ledger.release({
    intentId: released.id,
    reasonCode: 'UNSIGNED_CANCELLED',
  }), releasedProjection);
  assert.deepEqual(context.store.events(), eventsAfterRelease);
  assertKernelError(() => context.ledger.release({
    intentId: released.id,
    reasonCode: 'DIFFERENT_REASON',
  }), 'BUDGET_IDEMPOTENCY_CONFLICT');

  const shaped = authorizeIntent(context, { amountAtomic: '300', label: 'shaped' });
  context.ledger.reserve({ intentId: shaped.id, amountAtomic: '300' });
  const held = authorizeIntent(context, { amountAtomic: '200', label: 'held' });
  context.ledger.reserve({ intentId: held.id, amountAtomic: '200' });
  const heldProjection = context.ledger.holdUnresolved({
    intentId: held.id,
    reasonCode: 'SIGNATURE_MAY_EXIST',
  });
  const eventsAfterHold = context.store.events();
  assert.equal(heldProjection.state, 'unresolved');
  assert.deepEqual(context.ledger.holdUnresolved({
    intentId: held.id,
    reasonCode: 'SIGNATURE_MAY_EXIST',
  }), heldProjection);
  assert.deepEqual(context.store.events(), eventsAfterHold);
  assertKernelError(() => context.ledger.holdUnresolved({
    intentId: held.id,
    reasonCode: 'DIFFERENT_REASON',
  }), 'BUDGET_IDEMPOTENCY_CONFLICT');
  assertKernelError(() => context.ledger.release({
    intentId: held.id,
    reasonCode: 'UNSAFE_RELEASE',
  }), 'BUDGET_RELEASE_UNSAFE');

  const beforeRows = context.store.readAll(
    'SELECT * FROM budget_reservations WHERE intent_id = ?', [shaped.id],
  );
  const beforeEvents = context.store.events();
  assertKernelError(() => context.store.transaction((token) => (
    context.ledger.releaseInTransaction(token, {
      intentId: shaped.id,
      reasonCode: 'SIGNER_REJECTED',
      preSignRejection: {
        code: 'WALLET_PRE_SIGN_REJECTED',
        signatureMayExist: false,
      },
    })
  )), 'BUDGET_RELEASE_UNSAFE');
  assert.deepEqual(context.store.readAll(
    'SELECT * FROM budget_reservations WHERE intent_id = ?', [shaped.id],
  ), beforeRows);
  assert.deepEqual(context.store.events(), beforeEvents);
});

test('claim-only signing releases only for the exact imported pre-sign rejection type', (t) => {
  const context = setup(t);
  const intent = authorizeIntent(context, {
    amountAtomic: '100',
    label: 'typed-pre-sign-release',
  });
  context.ledger.reserve({ intentId: intent.id, amountAtomic: '100' });
  const claim = seedClaimOnlySigningPaymentAttempt(context, intent);
  const rejection = new WalletSigningError(
    'WALLET_PRE_SIGN_REJECTED',
    'deterministic validation failed before the signer boundary',
    { signatureMayExist: false },
  );

  const beforeRollback = {
    attempt: plainRow(context.store.readOne(
      'SELECT * FROM payment_attempts WHERE intent_id = ?', [intent.id],
    )),
    budget: plainRow(context.store.readOne(
      'SELECT * FROM budget_reservations WHERE intent_id = ?', [intent.id],
    )),
    events: eventHead(context),
  };
  assert.throws(() => context.store.transaction((token) => {
    context.ledger.releaseInTransaction(token, {
      intentId: intent.id,
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      preSignRejection: rejection,
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'signing',
      nextState: 'unresolved',
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
    });
    throw new Error('typed release rollback sentinel');
  }), /typed release rollback sentinel/);
  assert.deepEqual(plainRow(context.store.readOne(
    'SELECT * FROM payment_attempts WHERE intent_id = ?', [intent.id],
  )), beforeRollback.attempt);
  assert.deepEqual(plainRow(context.store.readOne(
    'SELECT * FROM budget_reservations WHERE intent_id = ?', [intent.id],
  )), beforeRollback.budget);
  assert.deepEqual(eventHead(context), beforeRollback.events);

  const released = context.store.transaction((token) => {
    const result = context.ledger.releaseInTransaction(token, {
      intentId: intent.id,
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      preSignRejection: rejection,
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'signing',
      nextState: 'unresolved',
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
    });
    return result;
  });
  assert.equal(released.state, 'released');
  assertConserved(context, intent.id);
  assert.deepEqual(plainRow(context.store.readOne(`SELECT state, reason_code, nonce,
      valid_after, valid_before, signing_claimed_at, payment_payload_json,
      payment_header, payment_hash, signed_at, retry_started_at, settlement_json,
      transaction_id, settled_at
    FROM payment_attempts WHERE intent_id = ?`, [intent.id])), {
    state: 'rejected',
    reason_code: 'WALLET_PRE_SIGN_REJECTED',
    nonce: claim.nonce,
    valid_after: claim.validAfter,
    valid_before: claim.validBefore,
    signing_claimed_at: claim.signingClaimedAt,
    payment_payload_json: null,
    payment_header: null,
    payment_hash: null,
    signed_at: null,
    retry_started_at: null,
    settlement_json: null,
    transaction_id: null,
    settled_at: null,
  });
  assert.equal(context.intents.getIntent(intent.id).state, 'terminal');
  const releaseEvents = context.store.events().filter(
    (event) => event.entity_type === 'budget_reservation'
      && event.entity_id === intent.id
      && event.event_type === 'budget.released',
  );
  assert.equal(releaseEvents.length, 1);
});

test('claim-only signing rejects shaped, subclassed, ambiguous, and mismatched release proof', (t) => {
  const context = setup(t);
  class DerivedSigningError extends WalletSigningError {}
  const proofs = [
    {
      name: 'plain shaped object',
      value: { code: 'WALLET_PRE_SIGN_REJECTED', signatureMayExist: false },
    },
    {
      name: 'forged prototype object',
      value: Object.assign(Object.create(WalletSigningError.prototype), {
        code: 'WALLET_PRE_SIGN_REJECTED',
        signatureMayExist: false,
      }),
    },
    {
      name: 'native Error with forged exact prototype',
      value: (() => {
        const error = Object.assign(new Error('forged native error'), {
          code: 'WALLET_PRE_SIGN_REJECTED',
          signatureMayExist: false,
        });
        Object.setPrototypeOf(error, WalletSigningError.prototype);
        return error;
      })(),
    },
    {
      name: 'subclass instance',
      value: new DerivedSigningError(
        'WALLET_PRE_SIGN_REJECTED',
        'subclassed rejection',
        { signatureMayExist: false },
      ),
    },
    {
      name: 'subclass with normalized exact prototype',
      value: (() => {
        const error = new DerivedSigningError(
          'WALLET_PRE_SIGN_REJECTED',
          'prototype-normalized subclass',
          { signatureMayExist: false },
        );
        Object.setPrototypeOf(error, WalletSigningError.prototype);
        return error;
      })(),
    },
    {
      name: 'may-exist rejection',
      value: new WalletSigningError(
        'WALLET_PRE_SIGN_REJECTED',
        'signer boundary entered',
        { signatureMayExist: true },
      ),
    },
    {
      name: 'wrong typed code',
      value: new WalletSigningError(
        'WALLET_SIGNATURE_AMBIGUOUS',
        'ambiguous signer result',
        { signatureMayExist: false },
      ),
    },
  ];

  for (const [index, proof] of proofs.entries()) {
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `unsafe-pre-sign-${index}`,
    });
    context.ledger.reserve({ intentId: intent.id, amountAtomic: '100' });
    seedClaimOnlySigningPaymentAttempt(context, intent);
    const before = eventHead(context);
    assertKernelError(() => context.store.transaction((token) => (
      context.ledger.releaseInTransaction(token, {
        intentId: intent.id,
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
        preSignRejection: proof.value,
      })
    )), 'BUDGET_RELEASE_UNSAFE');
    assert.equal(context.store.readOne(
      'SELECT state FROM payment_attempts WHERE intent_id = ?', [intent.id],
    ).state, 'signing', proof.name);
    assert.equal(context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [intent.id],
    ).state, 'reserved', proof.name);
    assert.deepEqual(eventHead(context), before, proof.name);
  }

  const mismatchedReason = authorizeIntent(context, {
    amountAtomic: '100',
    label: 'typed-proof-reason-mismatch',
  });
  context.ledger.reserve({ intentId: mismatchedReason.id, amountAtomic: '100' });
  seedClaimOnlySigningPaymentAttempt(context, mismatchedReason);
  assertKernelError(() => context.store.transaction((token) => (
    context.ledger.releaseInTransaction(token, {
      intentId: mismatchedReason.id,
      reasonCode: 'SIGNER_REJECTED',
      preSignRejection: new WalletSigningError(
        'WALLET_PRE_SIGN_REJECTED',
        'exact typed rejection',
        { signatureMayExist: false },
      ),
    })
  )), 'BUDGET_RELEASE_UNSAFE');

  for (const scoped of [false, true]) {
    const missingProof = authorizeIntent(context, {
      amountAtomic: '100',
      label: `typed-proof-missing-${scoped ? 'scoped' : 'standalone'}`,
    });
    context.ledger.reserve({ intentId: missingProof.id, amountAtomic: '100' });
    const operation = () => scoped
      ? context.store.transaction((token) => context.ledger.releaseInTransaction(token, {
        intentId: missingProof.id,
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      }))
      : context.ledger.release({
        intentId: missingProof.id,
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      });
    assertKernelError(operation, 'BUDGET_RELEASE_UNSAFE');
    assert.equal(context.store.readOne(
      'SELECT state FROM budget_reservations WHERE intent_id = ?', [missingProof.id],
    ).state, 'reserved');
  }
});

test('snapshots revalidate the retained claim-only release history', (t) => {
  const corruptions = [
    {
      name: 'deleted claim-only attempt',
      mutate(store, intentId) {
        store.execForTest(`DELETE FROM payment_attempts WHERE intent_id = '${intentId}'`);
      },
    },
    {
      name: 'cleared claim window',
      mutate(store, intentId) {
        store.execForTest(`UPDATE payment_attempts
          SET nonce = NULL, valid_after = NULL, valid_before = NULL, signing_claimed_at = NULL
          WHERE intent_id = '${intentId}'`);
      },
    },
    {
      name: 'substituted release reason',
      mutate(store, intentId) {
        store.execForTest(`UPDATE payment_attempts SET reason_code = 'SIGNER_REJECTED'
          WHERE intent_id = '${intentId}'`);
      },
    },
    {
      name: 'attempt update detached from release event',
      mutate(store, intentId) {
        store.execForTest(`UPDATE payment_attempts
          SET updated_at = '2026-07-31T12:00:01.000Z'
          WHERE intent_id = '${intentId}'`);
      },
    },
    {
      name: 'claim timestamp after terminal release',
      mutate(store, intentId) {
        store.execForTest(`UPDATE payment_attempts
          SET signing_claimed_at = '2026-07-31T12:00:01.000Z'
          WHERE intent_id = '${intentId}'`);
      },
    },
  ];
  for (const corruption of corruptions) {
    const context = setup(t);
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `history-${corruption.name.replaceAll(' ', '-')}`,
    });
    context.ledger.reserve({ intentId: intent.id, amountAtomic: '100' });
    seedClaimOnlySigningPaymentAttempt(context, intent);
    context.store.transaction((token) => context.ledger.releaseInTransaction(token, {
      intentId: intent.id,
      reasonCode: 'WALLET_PRE_SIGN_REJECTED',
      preSignRejection: new WalletSigningError(
        'WALLET_PRE_SIGN_REJECTED',
        'exact typed rejection',
        { signatureMayExist: false },
      ),
    }));
    assert.equal(context.ledger.snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: NOW,
    }).walletBlocked, false);
    corruption.mutate(context.store, intent.id);
    assertKernelError(() => context.ledger.snapshot({
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: NOW,
    }), 'BUDGET_CORRUPTION');
  }
});

test('claim and payload field groups fail closed when partial or attached to an illegal state', (t) => {
  const exactRejection = new WalletSigningError(
    'WALLET_PRE_SIGN_REJECTED',
    'exact typed rejection',
    { signatureMayExist: false },
  );
  for (const [index, [name, corrupt]] of [
    ['partial claim', (context, intent) => {
      context.store.execForTest(
        `UPDATE payment_attempts SET valid_before = NULL WHERE intent_id = '${intent.id}'`,
      );
    }],
    ['partial payload', (context, intent) => {
      context.store.execForTest(
        `UPDATE payment_attempts SET payment_payload_json = '{}' WHERE intent_id = '${intent.id}'`,
      );
    }],
    ['full signed payload while state remains signing', (context, intent) => {
      const claim = context.store.readOne(
        'SELECT nonce, valid_after, valid_before FROM payment_attempts WHERE intent_id = ?',
        [intent.id],
      );
      const paymentHeader = 'claim-bound-but-premature-signed-header';
      const paymentPayload = {
        x402Version: 2,
        resource: intent.challenge.resource,
        accepted: intent.challenge.accepts[0],
        payload: {
          signature: `0x${'11'.repeat(65)}`,
          authorization: {
            from: WALLET,
            to: PAY_TO,
            value: intent.decision.amountCeilingAtomic,
            validAfter: claim.valid_after,
            validBefore: claim.valid_before,
            nonce: claim.nonce,
          },
        },
      };
      context.store.transaction((token) => context.store.within(token, ({ db }) => {
        db.prepare(`UPDATE payment_attempts
          SET payment_payload_json = ?, payment_header = ?, payment_hash = ?, signed_at = ?
          WHERE intent_id = ?`).run(
          canonicalJson(paymentPayload),
          paymentHeader,
          sha256(Buffer.from(paymentHeader, 'ascii')),
          NOW,
          intent.id,
        );
      }));
    }],
  ].entries()) {
    const context = setup(t);
    const intent = authorizeIntent(context, {
      amountAtomic: '100',
      label: `claim-corruption-${index}-${name.replaceAll(' ', '-')}`,
    });
    context.ledger.reserve({ intentId: intent.id, amountAtomic: '100' });
    seedClaimOnlySigningPaymentAttempt(context, intent);
    corrupt(context, intent);
    assertKernelError(() => context.store.transaction((token) => (
      context.ledger.releaseInTransaction(token, {
        intentId: intent.id,
        reasonCode: 'WALLET_PRE_SIGN_REJECTED',
        preSignRejection: exactRejection,
      })
    )), 'BUDGET_CORRUPTION');
  }
});

test('scoped operations require a live opaque token and roll back with their caller', (t) => {
  let clockReads = 0;
  const context = setup(t, { now: () => {
    clockReads += 1;
    return NOW;
  } });
  const intent = authorizeIntent(context, { amountAtomic: '100', label: 'scoped' });
  const eventsBefore = context.store.events();
  assert.throws(() => context.store.transaction((token) => {
    context.ledger.reserveInTransaction(token, {
      intentId: intent.id,
      amountAtomic: '100',
    });
    throw new Error('rollback sentinel');
  }), /rollback sentinel/);
  assert.equal(context.store.readOne(
    'SELECT intent_id FROM budget_reservations WHERE intent_id = ?', [intent.id],
  ), undefined);
  assert.deepEqual(context.store.events(), eventsBefore);

  const forged = Object.freeze(Object.create(null));
  let attackerInputReads = 0;
  const attackerInput = new Proxy(Object.create(null), {
    ownKeys() {
      attackerInputReads += 1;
      throw new Error('attacker input was inspected');
    },
    getOwnPropertyDescriptor() {
      attackerInputReads += 1;
      throw new Error('attacker input was inspected');
    },
  });
  const beforeForged = {
    clockReads,
    events: eventHead(context),
  };
  for (const operation of [
    context.ledger.snapshotInTransaction,
    context.ledger.reserveInTransaction,
    context.ledger.commitInTransaction,
    context.ledger.releaseInTransaction,
    context.ledger.holdUnresolvedInTransaction,
    context.ledger.resolvePaymentInTransaction,
    context.ledger.recordConfirmedRefundInTransaction,
  ]) {
    assert.throws(() => operation(forged, attackerInput), /invalid authority transaction/);
  }
  assert.equal(attackerInputReads, 0);
  assert.equal(clockReads, beforeForged.clockReads);
  assert.deepEqual(eventHead(context), beforeForged.events);
  let stale;
  context.store.transaction((token) => {
    stale = token;
    return context.ledger.snapshotInTransaction(token, {
      sessionId: context.session.id,
      sellerOrigin: SELLER,
      at: NOW,
    });
  });
  const beforeStale = { clockReads, events: eventHead(context) };
  assert.throws(() => context.ledger.reserveInTransaction(stale, {
    intentId: 'A'.repeat(100_000),
    amountAtomic: '9'.repeat(100_000),
  }), /invalid authority transaction/);
  assert.equal(clockReads, beforeStale.clockReads);
  assert.deepEqual(eventHead(context), beforeStale.events);
});

test('a prior signing claim can commit and unsigned work can release after rotation and revocation', (t) => {
  const context = setup(t);
  const signed = authorizeIntent(context, { amountAtomic: '250000', label: 'epoch-signed' });
  context.ledger.reserve({ intentId: signed.id, amountAtomic: '250000' });
  const signedAttempt = seedRetryingPaymentAttempt(context, signed);
  const unsigned = authorizeIntent(context, {
    amountAtomic: '100',
    label: 'epoch-unsigned',
    budgetSnapshot: ZERO_BUDGET,
  });
  context.ledger.reserve({ intentId: unsigned.id, amountAtomic: '100' });

  const rotated = testPolicy();
  rotated.challengeMaxAgeMs += 1;
  context.policies.apply(rotated, '2026-07-31T12:00:01.000Z');
  context.enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });

  assert.equal(context.ledger.commit({
    intentId: signed.id,
    settlementEvidence: settlementEvidence({
      intent: signed,
      paymentHash: signedAttempt.paymentHash,
      transactionPair: '9a',
    }),
  }).state, 'committed');
  assert.equal(context.ledger.release({
    intentId: unsigned.id,
    reasonCode: 'AGENT_REVOKED',
  }).state, 'released');
  assert.equal(context.store.verifyEventChain(), true);
});

test('trusted settled reconciliation binds proof and atomically preserves the outer aggregate', (t) => {
  const context = setup(t);
  const intent = authorizeIntent(context, {
    amountAtomic: '250000',
    label: 'settled-reconciliation',
  });
  makeSignedUnresolved(context, intent);
  const transactionId = `0x${'31'.repeat(32)}`;
  const candidateId = insertPaymentCandidate(context, { intentId: intent.id, transactionId });
  insertReconciliation(context, {
    id: 'settled-generic-proof',
    intentId: intent.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: { source: 'operator-assertion', transactionId },
  });

  const beforeRejectedProof = eventHead(context);
  assertKernelError(() => context.store.transaction((token) => {
    const budget = context.ledger.resolvePaymentInTransaction(token, {
      intentId: intent.id,
      outcome: 'settled',
      evidenceId: 'settled-generic-proof',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    });
    return budget;
  }), 'RECONCILIATION_EVIDENCE_MISMATCH');
  assert.deepEqual(eventHead(context), beforeRejectedProof);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [intent.id],
  ).state, 'unresolved');
  assert.equal(context.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?', [intent.id],
  ).state, 'unresolved');
  assert.equal(context.store.readOne(
    'SELECT state FROM spend_intents WHERE id = ?', [intent.id],
  ).state, 'unresolved');

  const proof = settledTransferProof(context, intent, transactionId);
  insertReconciliation(context, {
    id: 'settled-exact-proof',
    intentId: intent.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: proof,
  });
  const result = context.store.transaction((token) => {
    const budget = context.ledger.resolvePaymentInTransaction(token, {
      intentId: intent.id,
      outcome: 'settled',
      evidenceId: 'settled-exact-proof',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    });
    return budget;
  });
  assert.equal(result.state, 'committed');
  assert.equal(result.committedAtomic, '250000');
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, transaction_id, settlement_json, reason_code
      FROM payment_attempts WHERE intent_id = ?`, [intent.id],
  )), {
    state: 'settled',
    transaction_id: transactionId,
    settlement_json: canonicalJson(proof),
    reason_code: 'TRUSTED_RECONCILIATION',
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, evidence_json FROM payment_reconciliation_candidates
      WHERE id = ?`, [candidateId],
  )), { state: 'confirmed', evidence_json: canonicalJson(proof) });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, metadata_json FROM execution_outcomes WHERE intent_id = ?`, [intent.id],
  )), {
    state: 'unknown',
    metadata_json: canonicalJson({
      reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
      reconciliationEvidenceId: 'settled-exact-proof',
    }),
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, reason_code, blocks_wallet, resolved_at
      FROM execution_resolutions WHERE intent_id = ?`, [intent.id],
  )), {
    state: 'reconciliation_required',
    reason_code: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    blocks_wallet: 1n,
    resolved_at: null,
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT status, reason_code, revision FROM buyer_outcomes WHERE intent_id = ?`, [intent.id],
  )), {
    status: 'execution_unknown',
    reason_code: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    revision: 2n,
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, retry_matchable FROM spend_intents WHERE id = ?`, [intent.id],
  )), { state: 'terminal', retry_matchable: 0n });
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);

  const afterResolution = eventHead(context);
  assert.deepEqual(context.ledger.resolvePayment({
    intentId: intent.id,
    outcome: 'settled',
    evidenceId: 'settled-exact-proof',
  }), result);
  assert.deepEqual(eventHead(context), afterResolution);
  assert.equal(context.store.verifyEventChain(), true);
});

test('trusted rejected reconciliation needs exact post-expiry proof and revalidates replay', (t) => {
  let clock = NOW;
  const context = setup(t, { now: () => clock });
  const intent = authorizeIntent(context, {
    amountAtomic: '250000',
    label: 'rejected-reconciliation',
  });
  makeSignedUnresolved(context, intent);
  const transactionId = `0x${'32'.repeat(32)}`;
  const candidateId = insertPaymentCandidate(context, { intentId: intent.id, transactionId });
  const proof = unusedAuthorizationProof(context, intent);
  insertReconciliation(context, {
    id: 'rejected-pre-expiry-proof',
    intentId: intent.id,
    kind: 'payment',
    outcome: 'rejected',
    evidence: {
      ...proof,
      observedBlockTimestamp: (BigInt(proof.validBefore) - 1n).toString(),
    },
  });
  const beforePreExpiry = eventHead(context);
  assertKernelError(() => context.store.transaction((token) => {
    context.ledger.resolvePaymentInTransaction(token, {
      intentId: intent.id,
      outcome: 'rejected',
      evidenceId: 'rejected-pre-expiry-proof',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    });
  }), 'RECONCILIATION_EVIDENCE_MISMATCH');
  assert.deepEqual(eventHead(context), beforePreExpiry);

  insertReconciliation(context, {
    id: 'rejected-exact-proof',
    intentId: intent.id,
    kind: 'payment',
    outcome: 'rejected',
    evidence: proof,
    recordedAt: AFTER_EXPIRY,
  });
  clock = AFTER_EXPIRY;
  const result = context.store.transaction((token) => {
    const budget = context.ledger.resolvePaymentInTransaction(token, {
      intentId: intent.id,
      outcome: 'rejected',
      evidenceId: 'rejected-exact-proof',
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    });
    return budget;
  });
  assert.equal(result.state, 'released');
  assert.equal(result.releasedAtomic, '250000');
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, reason_code, transaction_id, settlement_json, settled_at
      FROM payment_attempts WHERE intent_id = ?`, [intent.id],
  )), {
    state: 'rejected',
    reason_code: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    transaction_id: null,
    settlement_json: null,
    settled_at: null,
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, evidence_json FROM payment_reconciliation_candidates
      WHERE id = ?`, [candidateId],
  )), { state: 'rejected', evidence_json: canonicalJson(proof) });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT status, reason_code, revision FROM buyer_outcomes WHERE intent_id = ?`, [intent.id],
  )), {
    status: 'payment_rejected',
    reason_code: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    revision: 2n,
  });
  assert.equal(context.store.readOne(
    'SELECT intent_id FROM execution_outcomes WHERE intent_id = ?', [intent.id],
  ), undefined);
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, false);

  const afterResolution = eventHead(context);
  assert.deepEqual(context.ledger.resolvePayment({
    intentId: intent.id,
    outcome: 'rejected',
    evidenceId: 'rejected-exact-proof',
  }), result);
  assert.deepEqual(eventHead(context), afterResolution);

  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare('UPDATE reconciliations SET evidence_json = ? WHERE id = ?').run(
      canonicalJson({ ...proof, confirmations: 0 }),
      'rejected-exact-proof',
    );
  }));
  assertKernelError(() => context.ledger.resolvePayment({
    intentId: intent.id,
    outcome: 'rejected',
    evidenceId: 'rejected-exact-proof',
  }), 'RECONCILIATION_EVIDENCE_MISMATCH');
  assert.deepEqual(eventHead(context), afterResolution);
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare('UPDATE reconciliations SET evidence_json = ? WHERE id = ?').run(
      canonicalJson(proof),
      'rejected-exact-proof',
    );
  }));

  const attempt = context.store.readOne(
    'SELECT payment_hash FROM payment_attempts WHERE intent_id = ?', [intent.id],
  );
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare('UPDATE payment_attempts SET payment_hash = ? WHERE intent_id = ?').run(
      sha256(Buffer.from('corrupt-payment-header')),
      intent.id,
    );
  }));
  assertKernelError(() => context.ledger.resolvePayment({
    intentId: intent.id,
    outcome: 'rejected',
    evidenceId: 'rejected-exact-proof',
  }), 'BUDGET_CORRUPTION');
  assert.deepEqual(eventHead(context), afterResolution);
  context.store.transaction((token) => context.store.within(token, ({ db }) => {
    db.prepare('UPDATE payment_attempts SET payment_hash = ? WHERE intent_id = ?').run(
      attempt.payment_hash,
      intent.id,
    );
  }));
  assert.equal(context.store.verifyEventChain(), true);
});

test('confirmed refund is evidence-bound, atomic, and releases committed exposure once', (t) => {
  const context = setup(t);
  const intent = authorizeIntent(context, { amountAtomic: '250000', label: 'full-refund' });
  const { evidence } = commitIntent(context, intent, '33');
  const refundTransactionId = `0x${'34'.repeat(32)}`;
  context.store.transaction((token) => {
    context.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO execution_outcomes
        (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
        VALUES (?, 'failed', 500, ?, ?, ?)`).run(
        intent.id,
        sha256(Buffer.from('failed execution')),
        canonicalJson({ source: 'test' }),
        NOW,
      );
      db.prepare(`INSERT INTO execution_resolutions
        (intent_id, state, reason_code, blocks_wallet, opened_at)
        VALUES (?, 'refund_pending', 'UPSTREAM_FAILED', 1, ?)`).run(intent.id, NOW);
      db.prepare(`INSERT INTO refunds
        (id, intent_id, original_transaction_id, amount_atomic, state,
         refund_transaction_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`).run(
        `refund-${intent.id}`,
        intent.id,
        evidence.transaction,
        intent.decision.amountCeilingAtomic,
        refundTransactionId,
        NOW,
        NOW,
      );
      db.prepare(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES (?, 'execution_failed', 'UPSTREAM_FAILED', 1, ?)`).run(intent.id, NOW);
    });
    context.intents.transitionInTransaction(token, {
      intentId: intent.id,
      expectedState: 'retrying',
      nextState: 'terminal',
      reasonCode: 'UPSTREAM_FAILED',
    });
  });
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, true);

  insertReconciliation(context, {
    id: 'refund-generic-proof',
    intentId: intent.id,
    kind: 'refund',
    outcome: 'refund_confirmed',
    evidence: { transactionId: refundTransactionId, source: 'operator-assertion' },
  });
  const beforeBadRefund = eventHead(context);
  assertKernelError(() => context.ledger.recordConfirmedRefund({
    intentId: intent.id,
    evidenceId: 'refund-generic-proof',
    refundTransactionId,
  }), 'REFUND_EVIDENCE_MISMATCH');
  assert.deepEqual(eventHead(context), beforeBadRefund);
  assert.equal(context.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [intent.id],
  ).state, 'committed');

  const attestation = refundAttestation(
    context,
    intent.id,
    evidence.transaction,
    refundTransactionId,
  );
  const proof = Object.freeze({
    kind: 'refund_attested_and_confirmed',
    originalTransactionId: evidence.transaction,
    refundTransactionId,
    attestationHash: sha256(canonicalJson(attestation)),
    attestation,
    rpcProofHash: sha256(canonicalJson({ fixture: `refund-rpc-${intent.id}` })),
    localRefundBindingHash: localRefundHash(context, intent.id, refundTransactionId),
  });
  insertReconciliation(context, {
    id: 'refund-exact-proof',
    intentId: intent.id,
    kind: 'refund',
    outcome: 'refund_confirmed',
    evidence: proof,
  });
  const result = context.ledger.recordConfirmedRefund({
    intentId: intent.id,
    evidenceId: 'refund-exact-proof',
    refundTransactionId,
  });
  assert.equal(result.state, 'released');
  assert.equal(result.releasedAtomic, '250000');
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, evidence_json, original_transaction_id, refund_transaction_id
      FROM refunds WHERE intent_id = ?`, [intent.id],
  )), {
    state: 'confirmed',
    evidence_json: canonicalJson(proof),
    original_transaction_id: evidence.transaction,
    refund_transaction_id: refundTransactionId,
  });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT state, blocks_wallet, resolved_at FROM execution_resolutions
      WHERE intent_id = ?`, [intent.id],
  )), { state: 'resolved', blocks_wallet: 0n, resolved_at: NOW });
  assert.deepEqual(plainRow(context.store.readOne(
    `SELECT status, reason_code, revision FROM buyer_outcomes WHERE intent_id = ?`, [intent.id],
  )), { status: 'refunded', reason_code: 'REFUND_CONFIRMED', revision: 2n });
  assert.equal(context.ledger.snapshot({
    sessionId: context.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }).walletBlocked, false);

  const afterRefund = eventHead(context);
  assert.deepEqual(context.ledger.recordConfirmedRefund({
    intentId: intent.id,
    evidenceId: 'refund-exact-proof',
    refundTransactionId,
  }), result);
  assert.deepEqual(eventHead(context), afterRefund);
  assert.equal(context.store.verifyEventChain(), true);
});

test('refund-pending snapshots retain a full block with only abandoned or rejected history', async (t) => {
  for (const historicalState of ['abandoned', 'rejected']) {
    await t.test(historicalState, (st) => {
      const fileAuthority = authority(st, `wallet-kernel-refund-history-${historicalState}-`);
      const context = setup(st, { fileAuthority });
      const intent = authorizeIntent(context, {
        amountAtomic: '250000',
        label: `refund-history-${historicalState}`,
      });
      const { evidence } = commitIntent(context, intent, historicalState === 'abandoned' ? '71' : '72');
      const refundTransactionId = `0x${(historicalState === 'abandoned' ? '73' : '74').repeat(32)}`;
      context.store.transaction((token) => {
        context.store.within(token, ({ db }) => {
          db.prepare(`INSERT INTO execution_outcomes
            (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
            VALUES (?, 'failed', 500, NULL, '{}', ?)`).run(intent.id, NOW);
          db.prepare(`INSERT INTO execution_resolutions
            (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
            VALUES (?, 'refund_pending', 'REFUND_UNRESOLVED', 1, ?, NULL)`).run(
            intent.id,
            NOW,
          );
          db.prepare(`INSERT INTO refunds
            (id, intent_id, original_transaction_id, amount_atomic, state,
             evidence_json, refund_transaction_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
            `refund-history-${historicalState}`,
            intent.id,
            evidence.transaction,
            intent.decision.amountCeilingAtomic,
            historicalState,
            historicalState === 'rejected'
              ? canonicalJson({ kind: 'refund_candidate_rejected', fixture: true })
              : null,
            refundTransactionId,
            NOW,
            NOW,
          );
          db.prepare(`INSERT INTO buyer_outcomes
            (intent_id, status, reason_code, revision, recorded_at)
            VALUES (?, 'execution_failed', 'REFUND_UNRESOLVED', 1, ?)`).run(intent.id, NOW);
        });
        context.intents.transitionInTransaction(token, {
          intentId: intent.id,
          expectedState: 'retrying',
          nextState: 'terminal',
          reasonCode: 'REFUND_UNRESOLVED',
        });
      });

      const snapshot = context.ledger.snapshot({
        sessionId: context.session.id,
        sellerOrigin: SELLER,
        at: NOW,
      });
      assert.equal(snapshot.walletBlocked, true);
      assert.equal(snapshot.sessionExposureAtomic, intent.decision.amountCeilingAtomic);
      assert.equal(context.store.readOne(
        `SELECT COUNT(*) AS count FROM refunds
          WHERE intent_id = ? AND state IN ('pending','unresolved')`,
        [intent.id],
      ).count, 0n);
      assertConserved(context, intent.id);

      context.store.close();
      const reopenedStore = openKernelStore({
        filePath: fileAuthority.databasePath,
        pathTrust: fileAuthority.pathTrust,
        now: () => NOW,
      });
      st.after(() => reopenedStore.close());
      const reopenedLedger = createBudgetLedger({ store: reopenedStore, now: () => NOW });
      const reopenedSnapshot = reopenedLedger.snapshot({
        sessionId: context.session.id,
        sellerOrigin: SELLER,
        at: NOW,
      });
      assert.equal(reopenedSnapshot.walletBlocked, true);
      assert.equal(reopenedSnapshot.sessionExposureAtomic, intent.decision.amountCeilingAtomic);
    });
  }
});

test('trusted reconciliation times cannot backdate committed spend or release a future refund', (t) => {
  const evidenceTime = '2026-08-01T13:00:00.000Z';
  let settledClock = NOW;
  const settledContext = setup(t, { now: () => settledClock });
  const unsettled = authorizeIntent(settledContext, {
    amountAtomic: '100',
    label: 'settled-clock-order',
  });
  makeSignedUnresolved(settledContext, unsettled);
  const transactionId = `0x${'3d'.repeat(32)}`;
  insertPaymentCandidate(settledContext, { intentId: unsettled.id, transactionId });
  insertReconciliation(settledContext, {
    id: 'future-settlement-proof',
    intentId: unsettled.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: settledTransferProof(settledContext, unsettled, transactionId),
    recordedAt: evidenceTime,
  });
  settledClock = '2026-07-31T12:00:01.000Z';
  const beforeSettlement = eventHead(settledContext);
  assertKernelError(() => settledContext.ledger.resolvePayment({
    intentId: unsettled.id,
    outcome: 'settled',
    evidenceId: 'future-settlement-proof',
  }), 'BUDGET_TIME');
  assert.deepEqual(eventHead(settledContext), beforeSettlement);
  assert.equal(settledContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [unsettled.id],
  ).state, 'unresolved');
  assert.equal(settledContext.store.readOne(
    'SELECT state FROM payment_attempts WHERE intent_id = ?', [unsettled.id],
  ).state, 'unresolved');

  settledClock = evidenceTime;
  settledContext.store.transaction((token) => {
    settledContext.ledger.resolvePaymentInTransaction(token, {
      intentId: unsettled.id,
      outcome: 'settled',
      evidenceId: 'future-settlement-proof',
    });
    settledContext.intents.transitionInTransaction(token, {
      intentId: unsettled.id,
      expectedState: 'unresolved',
      nextState: 'terminal',
      reasonCode: 'PAYMENT_RECONCILED_EXECUTION_UNKNOWN',
    });
  });
  assert.equal(settledContext.store.readOne(
    'SELECT committed_at FROM budget_reservations WHERE intent_id = ?', [unsettled.id],
  ).committed_at, evidenceTime);
  assert.equal(settledContext.ledger.snapshot({
    sessionId: settledContext.session.id,
    sellerOrigin: SELLER,
    at: evidenceTime,
  }).rolling24hExposureAtomic, '100');

  let refundClock = NOW;
  const refundContext = setup(t, { now: () => refundClock });
  const paid = authorizeIntent(refundContext, {
    amountAtomic: '100',
    label: 'refund-clock-order',
  });
  const committed = commitIntent(refundContext, paid, '3e');
  const refundTransactionId = `0x${'3f'.repeat(32)}`;
  refundContext.store.transaction((token) => {
    refundContext.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO execution_outcomes
        (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
        VALUES (?, 'failed', 500, ?, ?, ?)`).run(
        paid.id,
        sha256(Buffer.from('future refund failed execution')),
        canonicalJson({ source: 'test' }),
        NOW,
      );
      db.prepare(`INSERT INTO execution_resolutions
        (intent_id, state, reason_code, blocks_wallet, opened_at)
        VALUES (?, 'refund_pending', 'UPSTREAM_FAILED', 1, ?)`).run(paid.id, NOW);
      db.prepare(`INSERT INTO refunds
        (id, intent_id, original_transaction_id, amount_atomic, state,
         refund_transaction_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`).run(
        `refund-${paid.id}`,
        paid.id,
        committed.evidence.transaction,
        paid.decision.amountCeilingAtomic,
        refundTransactionId,
        NOW,
        NOW,
      );
      db.prepare(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES (?, 'execution_failed', 'UPSTREAM_FAILED', 1, ?)`).run(paid.id, NOW);
    });
    refundContext.intents.transitionInTransaction(token, {
      intentId: paid.id,
      expectedState: 'retrying',
      nextState: 'terminal',
      reasonCode: 'UPSTREAM_FAILED',
    });
  });
  const attestation = refundAttestation(
    refundContext,
    paid.id,
    committed.evidence.transaction,
    refundTransactionId,
  );
  const refundProof = Object.freeze({
    kind: 'refund_attested_and_confirmed',
    originalTransactionId: committed.evidence.transaction,
    refundTransactionId,
    attestationHash: sha256(canonicalJson(attestation)),
    attestation,
    rpcProofHash: sha256(canonicalJson({ fixture: 'future-refund-rpc' })),
    localRefundBindingHash: localRefundHash(refundContext, paid.id, refundTransactionId),
  });
  insertReconciliation(refundContext, {
    id: 'future-refund-proof',
    intentId: paid.id,
    kind: 'refund',
    outcome: 'refund_confirmed',
    evidence: refundProof,
    recordedAt: evidenceTime,
  });
  refundClock = '2026-07-31T12:00:01.000Z';
  const beforeRefund = eventHead(refundContext);
  assertKernelError(() => refundContext.ledger.recordConfirmedRefund({
    intentId: paid.id,
    evidenceId: 'future-refund-proof',
    refundTransactionId,
  }), 'BUDGET_TIME');
  assert.deepEqual(eventHead(refundContext), beforeRefund);
  assert.equal(refundContext.store.readOne(
    'SELECT state FROM refunds WHERE intent_id = ?', [paid.id],
  ).state, 'pending');
  assert.equal(refundContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [paid.id],
  ).state, 'committed');

  refundClock = evidenceTime;
  assert.equal(refundContext.ledger.recordConfirmedRefund({
    intentId: paid.id,
    evidenceId: 'future-refund-proof',
    refundTransactionId,
  }).state, 'released');
  assert.equal(refundContext.store.readOne(
    'SELECT updated_at FROM refunds WHERE intent_id = ?', [paid.id],
  ).updated_at, evidenceTime);
});

test('snapshots fail closed when reservation authority or event-bound history is hidden', (t) => {
  const reboundContext = setup(t);
  const rebound = authorizeIntent(reboundContext, {
    amountAtomic: '250000',
    label: 'corrupt-session-rebind',
  });
  reboundContext.ledger.reserve({ intentId: rebound.id, amountAtomic: '250000' });
  reboundContext.store.transaction((token) => reboundContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
      VALUES ('foreign-session', 'pi:foreign-agent', ?, ?, 'closed', ?, ?)`).run(
      '0x9000000000000000000000000000000000000000',
      reboundContext.activePolicy.id,
      NOW,
      NOW,
    );
    db.prepare('UPDATE budget_reservations SET session_id = ? WHERE intent_id = ?').run(
      'foreign-session',
      rebound.id,
    );
  }));
  assertKernelError(() => reboundContext.ledger.snapshot({
    sessionId: reboundContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assert.equal(reboundContext.store.verifyEventChain(), true);

  const walletRebindContext = setup(t);
  const walletRebound = authorizeIntent(walletRebindContext, {
    amountAtomic: '250000',
    label: 'corrupt-wallet-rebind',
  });
  commitIntent(walletRebindContext, walletRebound, '3c');
  walletRebindContext.store.transaction((token) => {
    walletRebindContext.store.within(token, ({ db }) => {
      db.prepare(`INSERT INTO execution_outcomes
        (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
        VALUES (?, 'succeeded', 200, ?, ?, ?)`).run(
        walletRebound.id,
        sha256(Buffer.from('wallet-rebind terminal response')),
        canonicalJson({ source: 'test' }),
        NOW,
      );
      db.prepare(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES (?, 'completed', 'EXECUTION_SUCCEEDED', 1, ?)`).run(
        walletRebound.id,
        NOW,
      );
    });
    walletRebindContext.intents.transitionInTransaction(token, {
      intentId: walletRebound.id,
      expectedState: 'retrying',
      nextState: 'terminal',
      reasonCode: 'EXECUTION_SUCCEEDED',
    });
  });
  const replacementContext = rotateSessionPolicy(walletRebindContext);
  const walletRebindTarget = authorizeIntent(replacementContext, {
    amountAtomic: '1',
    label: 'corrupt-wallet-rebind-target',
    budgetSnapshot: ZERO_BUDGET,
  });
  walletRebindContext.store.transaction((token) => (
    walletRebindContext.store.within(token, ({ db }) => {
      const substitutedWallet = '0x9000000000000000000000000000000000000000';
      db.prepare('UPDATE spend_sessions SET wallet_address = ? WHERE id = ?').run(
        substitutedWallet,
        walletRebindContext.session.id,
      );
      db.prepare('UPDATE spend_intents SET wallet_address = ? WHERE id = ?').run(
        substitutedWallet,
        walletRebound.id,
      );
    })
  ));
  assertKernelError(() => replacementContext.ledger.snapshot({
    sessionId: replacementContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assertKernelError(() => replacementContext.ledger.reserve({
    intentId: walletRebindTarget.id,
    amountAtomic: '1',
  }), 'BUDGET_CORRUPTION');
  assert.equal(walletRebindContext.store.verifyEventChain(), true);

  const missingDecisionContext = setup(t);
  const missingDecision = authorizeIntent(missingDecisionContext, {
    amountAtomic: '250000',
    label: 'corrupt-missing-decision',
  });
  missingDecisionContext.ledger.reserve({
    intentId: missingDecision.id,
    amountAtomic: '250000',
  });
  missingDecisionContext.store.transaction((token) => (
    missingDecisionContext.store.within(token, ({ db }) => {
      db.prepare('DELETE FROM policy_decisions WHERE intent_id = ?').run(missingDecision.id);
    })
  ));
  assertKernelError(() => missingDecisionContext.ledger.snapshot({
    sessionId: missingDecisionContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assert.equal(missingDecisionContext.store.verifyEventChain(), true);

  const missingReservationContext = setup(t);
  const missingReservation = authorizeIntent(missingReservationContext, {
    amountAtomic: '250000',
    label: 'corrupt-missing-reservation',
  });
  commitIntent(missingReservationContext, missingReservation, '3b');
  const missingReservationTarget = authorizeIntent(missingReservationContext, {
    amountAtomic: '1',
    label: 'corrupt-missing-reservation-target',
    budgetSnapshot: ZERO_BUDGET,
  });
  missingReservationContext.store.transaction((token) => (
    missingReservationContext.store.within(token, ({ db }) => {
      db.prepare('DELETE FROM budget_reservations WHERE intent_id = ?').run(
        missingReservation.id,
      );
    })
  ));
  assertKernelError(() => missingReservationContext.ledger.snapshot({
    sessionId: missingReservationContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assertKernelError(() => missingReservationContext.ledger.reserve({
    intentId: missingReservationTarget.id,
    amountAtomic: '1',
  }), 'BUDGET_CORRUPTION');
  assert.equal(missingReservationContext.store.verifyEventChain(), true);

  const backdatedContext = setup(t);
  const backdated = authorizeIntent(backdatedContext, {
    amountAtomic: '250000',
    label: 'corrupt-committed-at',
  });
  commitIntent(backdatedContext, backdated, '35');
  backdatedContext.store.transaction((token) => backdatedContext.store.within(token, ({ db }) => {
    db.prepare('UPDATE budget_reservations SET committed_at = ? WHERE intent_id = ?').run(
      '2026-07-01T12:00:00.000Z',
      backdated.id,
    );
  }));
  assertKernelError(() => backdatedContext.ledger.snapshot({
    sessionId: backdatedContext.session.id,
    sellerOrigin: SELLER,
    at: NOW,
  }), 'BUDGET_CORRUPTION');
  assert.equal(backdatedContext.store.verifyEventChain(), true);
});

test('payment reconciliation rejects case variants and cross-table transaction reuse', (t) => {
  const caseContext = setup(t);
  const target = authorizeIntent(caseContext, { amountAtomic: '100', label: 'case-target' });
  makeSignedUnresolved(caseContext, target);
  const other = authorizeIntent(caseContext, {
    amountAtomic: '100',
    label: 'case-other',
    budgetSnapshot: ZERO_BUDGET,
  });
  seedRetryingPaymentAttempt(caseContext, other);
  const transactionId = `0x${'ab'.repeat(32)}`;
  insertPaymentCandidate(caseContext, { intentId: target.id, transactionId });
  insertPaymentCandidate(caseContext, {
    intentId: other.id,
    transactionId: `0x${'AB'.repeat(32)}`,
  });
  insertReconciliation(caseContext, {
    id: 'case-variant-proof',
    intentId: target.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: settledTransferProof(caseContext, target, transactionId),
  });
  const beforeCaseVariant = eventHead(caseContext);
  assertKernelError(() => caseContext.ledger.resolvePayment({
    intentId: target.id,
    outcome: 'settled',
    evidenceId: 'case-variant-proof',
  }), 'TRANSACTION_BINDING_CORRUPTION');
  assert.deepEqual(eventHead(caseContext), beforeCaseVariant);
  assert.equal(caseContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [target.id],
  ).state, 'unresolved');

  const reuseContext = setup(t);
  const reused = authorizeIntent(reuseContext, { amountAtomic: '100', label: 'reuse-target' });
  makeSignedUnresolved(reuseContext, reused);
  const reusedTransactionId = `0x${'36'.repeat(32)}`;
  insertPaymentCandidate(reuseContext, {
    intentId: reused.id,
    transactionId: reusedTransactionId,
  });
  const foreignIntent = authorizeIntent(reuseContext, {
    amountAtomic: '1',
    label: 'reuse-foreign-owner',
    budgetSnapshot: ZERO_BUDGET,
  });
  reuseContext.store.transaction((token) => reuseContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state,
       refund_transaction_id, created_at, updated_at)
      VALUES ('foreign-refund', ?, ?, '1', 'abandoned', ?, ?, ?)`).run(
      foreignIntent.id,
      `0x${'37'.repeat(32)}`,
      reusedTransactionId,
      NOW,
      NOW,
    );
  }));
  insertReconciliation(reuseContext, {
    id: 'cross-table-reuse-proof',
    intentId: reused.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: settledTransferProof(reuseContext, reused, reusedTransactionId),
  });
  const beforeReuse = eventHead(reuseContext);
  assertKernelError(() => reuseContext.ledger.resolvePayment({
    intentId: reused.id,
    outcome: 'settled',
    evidenceId: 'cross-table-reuse-proof',
  }), 'TRANSACTION_REUSED');
  assert.deepEqual(eventHead(reuseContext), beforeReuse);
  assert.equal(reuseContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [reused.id],
  ).state, 'unresolved');
});

test('first trusted transitions reject rows finalized outside their atomic mutation', (t) => {
  const paymentContext = setup(t);
  const payment = authorizeIntent(paymentContext, {
    amountAtomic: '100',
    label: 'preconfirmed-payment',
  });
  makeSignedUnresolved(paymentContext, payment);
  const paymentTransactionId = `0x${'38'.repeat(32)}`;
  const candidateId = insertPaymentCandidate(paymentContext, {
    intentId: payment.id,
    transactionId: paymentTransactionId,
  });
  const paymentProof = settledTransferProof(
    paymentContext,
    payment,
    paymentTransactionId,
  );
  paymentContext.store.transaction((token) => paymentContext.store.within(token, ({ db }) => {
    db.prepare(`UPDATE payment_reconciliation_candidates
      SET state = 'confirmed', evidence_json = ? WHERE id = ?`).run(
      canonicalJson(paymentProof),
      candidateId,
    );
  }));
  insertReconciliation(paymentContext, {
    id: 'preconfirmed-payment-proof',
    intentId: payment.id,
    kind: 'payment',
    outcome: 'settled',
    evidence: paymentProof,
  });
  const beforePayment = eventHead(paymentContext);
  assertKernelError(() => paymentContext.ledger.resolvePayment({
    intentId: payment.id,
    outcome: 'settled',
    evidenceId: 'preconfirmed-payment-proof',
  }), 'RECONCILIATION_EVIDENCE_MISMATCH');
  assert.deepEqual(eventHead(paymentContext), beforePayment);
  assert.equal(paymentContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [payment.id],
  ).state, 'unresolved');

  const refundContext = setup(t);
  const paid = authorizeIntent(refundContext, {
    amountAtomic: '100',
    label: 'preconfirmed-refund',
  });
  const committed = commitIntent(refundContext, paid, '39');
  const refundTransactionId = `0x${'3a'.repeat(32)}`;
  refundContext.store.transaction((token) => refundContext.store.within(token, ({ db }) => {
    db.prepare(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
      VALUES (?, 'failed', 500, ?, ?, ?)`).run(
      paid.id,
      sha256(Buffer.from('preconfirmed failed execution')),
      canonicalJson({ source: 'test' }),
      NOW,
    );
    db.prepare(`INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at)
      VALUES (?, 'refund_pending', 'UPSTREAM_FAILED', 1, ?)`).run(paid.id, NOW);
    db.prepare(`INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state,
       refund_transaction_id, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'pending', ?, ?, ?)`).run(
      `refund-${paid.id}`,
      paid.id,
      committed.evidence.transaction,
      paid.decision.amountCeilingAtomic,
      refundTransactionId,
      NOW,
      NOW,
    );
    db.prepare(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES (?, 'execution_failed', 'UPSTREAM_FAILED', 1, ?)`).run(paid.id, NOW);
  }));
  const attestation = refundAttestation(
    refundContext,
    paid.id,
    committed.evidence.transaction,
    refundTransactionId,
  );
  const refundProof = Object.freeze({
    kind: 'refund_attested_and_confirmed',
    originalTransactionId: committed.evidence.transaction,
    refundTransactionId,
    attestationHash: sha256(canonicalJson(attestation)),
    attestation,
    rpcProofHash: sha256(canonicalJson({ fixture: 'preconfirmed-refund-rpc' })),
    localRefundBindingHash: localRefundHash(refundContext, paid.id, refundTransactionId),
  });
  refundContext.store.transaction((token) => refundContext.store.within(token, ({ db }) => {
    db.prepare(`UPDATE refunds SET state = 'confirmed', evidence_json = ?
      WHERE intent_id = ?`).run(canonicalJson(refundProof), paid.id);
  }));
  insertReconciliation(refundContext, {
    id: 'preconfirmed-refund-proof',
    intentId: paid.id,
    kind: 'refund',
    outcome: 'refund_confirmed',
    evidence: refundProof,
  });
  const beforeRefund = eventHead(refundContext);
  assertKernelError(() => refundContext.ledger.recordConfirmedRefund({
    intentId: paid.id,
    evidenceId: 'preconfirmed-refund-proof',
    refundTransactionId,
  }), 'BUDGET_CORRUPTION');
  assert.deepEqual(eventHead(refundContext), beforeRefund);
  assert.equal(refundContext.store.readOne(
    'SELECT state FROM budget_reservations WHERE intent_id = ?', [paid.id],
  ).state, 'committed');
});

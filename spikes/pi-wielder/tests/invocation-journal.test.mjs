import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  canonicalJson,
  createInvocationJournal,
  createReceiptSigner,
  loadOrCreateReceiptSigner,
  receiptKeyId,
  verifySignedReceipt,
} from '../src/invocation-journal.mjs';
import {
  artifactDigest,
  createPendingExecutionAccounting,
  createExecutionQuote,
  finalizeExecutionAccounting,
} from '../src/execution-economics.mjs';

const payer = `0x${'1'.repeat(40)}`;
const payTo = `0x${'d'.repeat(40)}`;
const settlementReference = `0x${'2'.repeat(64)}`;
const txHash = `0x${'3'.repeat(64)}`;

const declaration = Object.freeze({
  idempotencyKey: 'idem-0001',
  mode: 'external',
  skillId: 'skill-a',
  skillVersionHash: `sha256:${'a'.repeat(64)}`,
  requestHash: `sha256:${'b'.repeat(64)}`,
  creatorId: 'creator-a',
  beneficiaryId: null,
});

const royaltyGraph = Object.freeze({
  'skill-a': Object.freeze({
    parentIds: Object.freeze([]),
    inheritBps: 0,
    holders: Object.freeze([{ recipientId: 'creator-a', bps: 10_000 }]),
  }),
});
const executionQuote = createExecutionQuote({
  schemaVersion: 2,
  grossAtomic: '250000',
  model: 'claude-sonnet-4-6',
  maxInputTokens: 16384,
  maxOutputTokens: 2048,
  promptBytes: 100,
  estimatedInputTokens: 356,
  settlementCostAtomic: '1000',
  refundReserveAtomic: '5000',
  protocolFeeBps: 250,
  leafSkillId: 'skill-a',
  skillId: 'skill-a',
  skillVersion: 'skill-a/2026-07-17-v1',
  artifactHash: artifactDigest('test Skill artifact'),
  skills: royaltyGraph,
});

const requirements = Object.freeze({
  scheme: 'exact',
  network: 'base-sepolia',
  maxAmountRequired: '250000',
  resource: 'http://seller.test/invoke/skill-a',
  description: 'Invoke skill-a',
  mimeType: 'application/json',
  payTo,
  maxTimeoutSeconds: 60,
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  extra: {
    name: 'USDC',
    version: '2',
    requestHash: declaration.requestHash,
    quoteId: executionQuote.quoteId,
    issuedAt: '2026-07-17T12:00:00.000Z',
    expiresAt: '2026-07-17T12:01:00.000Z',
  },
});

const quote = Object.freeze({
  schemaVersion: 2,
  quoteId: requirements.extra.quoteId,
  amountAtomic: requirements.maxAmountRequired,
  currency: 'USDC',
  network: requirements.network,
  asset: requirements.asset,
  payTo: requirements.payTo,
  resource: requirements.resource,
  requestHash: requirements.extra.requestHash,
  requirementsHash: `sha256:${'e'.repeat(64)}`,
  expiresAt: requirements.extra.expiresAt,
  requirements,
  executionQuote,
});

const legacyQuote = Object.freeze(Object.fromEntries(
  Object.entries(quote).filter(([key]) => !['schemaVersion', 'executionQuote'].includes(key)),
));

function fixture(overrides = {}) {
  let tick = 0;
  return createInvocationJournal({
    now: () => new Date(Date.UTC(2026, 6, 17, 12, 0, tick++)).toISOString(),
    createId: () => 'inv-0001',
    signer: createReceiptSigner(),
    ...overrides,
  });
}

const trustFor = (journal) => ({
  publicKeyPem: journal.signingPublicKeyPem,
  keyId: journal.signingKeyId,
});

test('receipt key IDs are exactly one SHA-256 digest of SPKI DER', () => {
  const signer = createReceiptSigner();
  const publicKey = crypto.createPublicKey(signer.publicKeyPem);
  const der = publicKey.export({ type: 'spki', format: 'der' });
  const expected = `sha256:${crypto.createHash('sha256').update(der).digest('hex')}`;
  const doubleHashed = `sha256:${crypto.createHash('sha256')
    .update(Buffer.from(expected.slice('sha256:'.length), 'hex')).digest('hex')}`;
  assert.equal(receiptKeyId(signer.publicKeyPem), expected);
  assert.equal(signer.keyId, expected);
  assert.notEqual(signer.keyId, doubleHashed);
});

function offer(journal, input = declaration) {
  journal.requestInvocation(input);
  journal.offerExternalPayment(input.idempotencyKey, quote);
}

function settle(journal, input = declaration) {
  offer(journal, input);
  journal.markExternalPaymentSigned(input.idempotencyKey, { settlementReference, payer });
  journal.markExternalPaymentSettled(input.idempotencyKey, {
    settlementReference,
    txHash,
    payer,
  });
}

function pendingFailureAccounting(failureClass = 'UPSTREAM_PROVIDER_ERROR') {
  return structuredClone(createPendingExecutionAccounting({
    quote: executionQuote,
    usage: null,
    failureClass,
    reason: 'provider execution failed',
  }));
}

function legacyPendingFailureAccounting() {
  return {
    grossAtomic: '250000',
    allocationState: 'pending_cogs_reconciliation',
    holderCredits: [],
    ancestorCredits: [],
    journalEntries: [{
      category: 'unresolved-execution-accounting',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'hold:execution-accounting-reconciliation',
      amountAtomic: '250000',
    }],
  };
}

function finalizedAccounting() {
  return structuredClone(finalizeExecutionAccounting({
    quote: executionQuote,
    usage: {
      schemaVersion: 2,
      model: executionQuote.model,
      inputTokens: 42,
      outputTokens: 42,
    },
    leafSkillId: 'skill-a',
    skills: royaltyGraph,
  }));
}

test('exact retries are no-ops and conflicting idempotency reuse fails closed', () => {
  const journal = fixture();
  const first = journal.requestInvocation(declaration);
  assert.deepEqual(journal.requestInvocation(declaration), first);
  assert.equal(journal.events.length, 1);
  assert.throws(() => journal.requestInvocation({
    ...declaration,
    skillVersionHash: `sha256:${'f'.repeat(64)}`,
  }), /idempotency key already binds/);
  assert.equal(journal.events.length, 1);
});

test('atomic journal fields reject numeric coercion before state changes', () => {
  const journal = fixture();
  journal.requestInvocation(declaration);
  assert.throws(() => journal.offerExternalPayment(declaration.idempotencyKey, {
    ...quote,
    amountAtomic: 250000,
  }), /must be a string/);
  assert.equal(journal.events.length, 1);
  assert.equal(journal.getByIdempotencyKey(declaration.idempotencyKey).quote, null);
});

test('a settled execution failure keeps its transaction, full-gross hold, and HTTP status', () => {
  const journal = fixture();
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'failed',
    failureClass: 'UPSTREAM_500',
    message: 'provider returned HTTP 500',
    outcomeHash: null,
    httpStatus: 500,
    accounting: pendingFailureAccounting('UPSTREAM_500'),
  });
  const bundle = journal.issueReceipt(declaration.idempotencyKey);
  assert.equal(bundle.receipt.schemaVersion, 2);
  assert.equal(bundle.receipt.quote.executionQuote.quoteId, requirements.extra.quoteId);
  assert.equal(bundle.receipt.payment.state, 'settled');
  assert.equal(bundle.receipt.payment.txHash, txHash);
  assert.equal(bundle.receipt.execution.state, 'failed');
  assert.equal(bundle.receipt.execution.httpStatus, 500);
  assert.deepEqual(bundle.receipt.accounting, pendingFailureAccounting('UPSTREAM_500'));
  assert.equal(verifySignedReceipt(bundle, trustFor(journal)), true);
});

test('v2 terminal accounting rejects nonconservation, false unknown zero, and quote mismatch before append', () => {
  const invalidAccounting = [
    (value) => { value.royaltyPoolAtomic = '1'; },
    (value) => { value.executionCogs.actualAtomic = '0'; },
    (value) => { value.quoteId = `sha256:${'9'.repeat(64)}`; },
    (value) => { value.journalEntries[0].amountAtomic = '249999'; },
    (value) => { value.holderCredits.push({
      recipientId: 'attacker', viaSkillId: 'skill-a', depth: 0, kind: 'holder', amountAtomic: '1',
    }); },
  ];
  for (const mutate of invalidAccounting) {
    const journal = fixture();
    settle(journal);
    const claim = journal.startExecution(declaration.idempotencyKey);
    const accounting = pendingFailureAccounting();
    mutate(accounting);
    const before = journal.events.length;
    assert.throws(() => journal.finishExecution(declaration.idempotencyKey, {
      executionAttemptId: claim.record.execution.executionAttemptId,
      outcome: 'failed',
      failureClass: 'UPSTREAM_PROVIDER_ERROR',
      message: 'safe provider failure',
      outcomeHash: null,
      httpStatus: 500,
      accounting,
    }), /accounting|COGS|Royalty|quote|hold|conserve/i);
    assert.equal(journal.events.length, before);
    assert.equal(journal.getByIdempotencyKey(declaration.idempotencyKey).execution.state, 'executing');
  }
});

test('v2 success requires known finalized accounting and exact terminal hash/status semantics', () => {
  for (const mutation of [
    { accounting: pendingFailureAccounting() },
    { outcomeHash: null },
    { failureClass: 'FALSE_SUCCESS' },
    { message: 'false success' },
    { httpStatus: 500 },
  ]) {
    const journal = fixture();
    settle(journal);
    const claim = journal.startExecution(declaration.idempotencyKey);
    assert.throws(() => journal.finishExecution(declaration.idempotencyKey, {
      executionAttemptId: claim.record.execution.executionAttemptId,
      outcome: 'succeeded',
      failureClass: null,
      message: null,
      outcomeHash: `sha256:${'7'.repeat(64)}`,
      httpStatus: 200,
      accounting: finalizedAccounting(),
      ...mutation,
    }), /success|finalized|hash|status|failure|message/i);
    assert.equal(journal.getByIdempotencyKey(declaration.idempotencyKey).execution.state, 'executing');
  }
});

test('v2 finalized accounting binds quote-fixed costs, quoted usage, and exact credit destinations', () => {
  const invalidAccounting = [
    (value) => {
      value.settlementCostAtomic = '999';
      value.royaltyPoolAtomic = '236995';
      value.journalEntries.find((entry) => entry.category === 'settlement-cogs').amountAtomic = '999';
      value.holderCredits[0].amountAtomic = '236995';
      value.journalEntries.find((entry) => entry.category === 'royalty-holder').amountAtomic = '236995';
    },
    (value) => {
      value.executionCogs.actualAtomic = '79873';
      value.executionCogs.chargedAtomic = '79873';
      value.executionCostAtomic = '79873';
      value.royaltyPoolAtomic = '157877';
      value.journalEntries.find((entry) => entry.category === 'execution-cogs').amountAtomic = '79873';
      value.holderCredits[0].amountAtomic = '157877';
      value.journalEntries.find((entry) => entry.category === 'royalty-holder').amountAtomic = '157877';
    },
    (value) => { value.executionCogs.usage.model = 'unquoted-model'; },
    (value) => {
      value.journalEntries.find((entry) => entry.category === 'protocol-fee').creditAccountId = 'attacker:fee';
    },
    (value) => {
      value.journalEntries.find((entry) => entry.category === 'royalty-holder').creditAccountId = 'royalty:attacker';
    },
  ];
  for (const mutate of invalidAccounting) {
    const journal = fixture();
    settle(journal);
    const claim = journal.startExecution(declaration.idempotencyKey);
    const accounting = finalizedAccounting();
    mutate(accounting);
    const before = journal.events.length;
    assert.throws(() => journal.finishExecution(declaration.idempotencyKey, {
      executionAttemptId: claim.record.execution.executionAttemptId,
      outcome: 'succeeded',
      failureClass: null,
      message: null,
      outcomeHash: `sha256:${'7'.repeat(64)}`,
      httpStatus: 200,
      accounting,
    }), /accounting|COGS|quote|usage|journal|credit|category/i);
    assert.equal(journal.events.length, before);
  }
});

test('v2 failure class matches its pending COGS hold before signing a receipt', () => {
  const journal = fixture();
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  assert.throws(() => journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'failed',
    failureClass: 'COGS_UNKNOWN',
    message: 'provider usage unavailable',
    outcomeHash: null,
    httpStatus: 500,
    accounting: pendingFailureAccounting('UPSTREAM_PROVIDER_ERROR'),
  }), /failure class/i);
  assert.equal(journal.getByIdempotencyKey(declaration.idempotencyKey).execution.state, 'executing');
});

test('an unresolved settlement reconciles once by its payment reference', () => {
  const journal = fixture();
  offer(journal);
  journal.markExternalPaymentSigned(declaration.idempotencyKey, { settlementReference, payer });
  journal.markExternalPaymentUnresolved(declaration.idempotencyKey, { reason: 'facilitator response lost' });
  const before = journal.events.length;
  journal.reconcileExternalSettlement({ settlementReference, txHash, payer });
  journal.reconcileExternalSettlement({ settlementReference, txHash, payer });
  assert.equal(journal.events.length, before + 1);
  assert.equal(journal.getBySettlementReference(settlementReference).payment.state, 'settled');
  assert.equal(journal.getByTxHash(txHash).idempotencyKey, declaration.idempotencyKey);
});

test('settlement and transaction indexes canonicalize and reject collisions', () => {
  const journal = fixture();
  const second = { ...declaration, idempotencyKey: 'idem-0002', requestHash: `sha256:${'9'.repeat(64)}` };
  offer(journal);
  journal.markExternalPaymentSigned(declaration.idempotencyKey, {
    settlementReference: settlementReference.toUpperCase().replace('0X', '0x'),
    payer: payer.toUpperCase().replace('0X', '0x'),
  });
  assert.equal(journal.getByIdempotencyKey(declaration.idempotencyKey).payment.payer, payer);
  offer(journal, second);
  assert.throws(() => journal.markExternalPaymentSigned(second.idempotencyKey, {
    settlementReference,
    payer,
  }), /settlement reference already binds/);
});

test('payment authorization claim distinguishes the first signer from exact retries', () => {
  const journal = fixture();
  offer(journal);
  const first = journal.claimExternalPaymentSigned(declaration.idempotencyKey, { settlementReference, payer });
  const retry = journal.claimExternalPaymentSigned(declaration.idempotencyKey, { settlementReference, payer });
  assert.equal(first.claimed, true);
  assert.equal(retry.claimed, false);
  assert.equal(retry.record.payment.state, 'signed');
  assert.equal(journal.events.filter((event) => event.type === 'payment.signed').length, 1);
});

test('verified payment header identity is append-only and rejects a conflicting replay', () => {
  const journal = fixture();
  offer(journal);
  const verifiedPaymentHash = `sha256:${'a'.repeat(64)}`;
  journal.recordExternalPaymentVerification(declaration.idempotencyKey, { verifiedPaymentHash });
  journal.recordExternalPaymentVerification(declaration.idempotencyKey, { verifiedPaymentHash });
  assert.equal(journal.getVerifiedPaymentHash(declaration.idempotencyKey), verifiedPaymentHash);
  assert.equal(
    journal.events.filter((event) => event.type === 'payment.authorization_verified').length,
    1,
  );
  assert.throws(
    () => journal.recordExternalPaymentVerification(declaration.idempotencyKey, {
      verifiedPaymentHash: `sha256:${'b'.repeat(64)}`,
    }),
    /different verified payment authorization/,
  );
});

function temporaryAuthority(prefix = 'collar-journal-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  return {
    directory,
    filePath: path.join(directory, 'events.jsonl'),
    signingKeyPath: path.join(directory, 'receipt-key.pem'),
  };
}

function writeLegacyV1Journal({ terminal }) {
  const authority = temporaryAuthority('collar-legacy-v1-');
  const keys = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(
    authority.signingKeyPath,
    keys.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    { mode: 0o600 },
  );
  const signer = createReceiptSigner(keys, { persistent: true });
  const events = [];
  let previousHash = null;
  const append = (type, data) => {
    const sequence = events.length + 1;
    const unsigned = {
      schemaVersion: 1,
      eventId: `event-${String(sequence).padStart(8, '0')}`,
      sequence,
      previousHash,
      type,
      idempotencyKey: declaration.idempotencyKey,
      at: new Date(Date.UTC(2026, 6, 16, 12, 0, sequence)).toISOString(),
      data,
      keyId: signer.keyId,
    };
    const eventHash = crypto.createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
    const event = { ...unsigned, eventHash, eventSignature: signer.signHash(eventHash) };
    events.push(event);
    previousHash = eventHash;
  };
  append('invocation.requested', {
    invocationId: 'inv-legacy-v1',
    mode: declaration.mode,
    skill: { id: declaration.skillId, versionHash: declaration.skillVersionHash },
    requestHash: declaration.requestHash,
    creatorId: declaration.creatorId,
    beneficiaryId: declaration.beneficiaryId,
  });
  append('payment.offered', { quote: legacyQuote });
  if (terminal) {
    append('payment.signed', { settlementReference, payer });
    append('payment.settled', { settlementReference, txHash, payer });
    append('execution.started', { executionAttemptId: 'attempt:legacy-v1' });
    append('execution.finished', {
      executionAttemptId: 'attempt:legacy-v1',
      outcome: 'failed',
      outcomeHash: null,
      failureClass: 'LEGACY_FAILURE',
      message: 'legacy terminal failure',
      httpStatus: 500,
      accounting: legacyPendingFailureAccounting(),
    });
  }
  fs.writeFileSync(
    authority.filePath,
    `${events.map((event) => JSON.stringify(event)).join('\n')}\n`,
    { mode: 0o600 },
  );
  return { ...authority, signer };
}

test('legacy v1 terminal history replays without relabeling while nonterminal v1 cannot upgrade', () => {
  const terminalAuthority = writeLegacyV1Journal({ terminal: true });
  const terminal = createInvocationJournal(terminalAuthority);
  const receipt = terminal.issueReceipt(declaration.idempotencyKey);
  assert.equal(receipt.receipt.schemaVersion, 1);
  assert.equal(receipt.receipt.quote.executionQuote, undefined);
  assert.ok(terminal.events.every((event) => event.schemaVersion === 1));
  assert.equal(verifySignedReceipt(receipt, trustFor(terminal)), true);

  const outstandingAuthority = writeLegacyV1Journal({ terminal: false });
  const outstanding = createInvocationJournal(outstandingAuthority);
  assert.throws(
    () => outstanding.offerExternalPayment(declaration.idempotencyKey, quote),
    /legacy nonterminal Invocation cannot be upgraded/,
  );
  assert.equal(outstanding.events.length, 2);
});

test('JSONL replay reconstructs a terminal record and refuses rewritten signed history', () => {
  const { filePath, signingKeyPath } = temporaryAuthority();
  const journal = createInvocationJournal({ filePath, signingKeyPath, createId: () => 'inv-persistent' });
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'succeeded',
    failureClass: null,
    message: null,
    outcomeHash: `sha256:${'7'.repeat(64)}`,
    httpStatus: 200,
    accounting: finalizedAccounting(),
  });
  const original = journal.issueReceipt(declaration.idempotencyKey);
  assert.ok(journal.events.every((event) => event.schemaVersion === 2));
  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.deepEqual(reopened.getByIdempotencyKey(declaration.idempotencyKey), journal.getByIdempotencyKey(declaration.idempotencyKey));
  assert.deepEqual(reopened.issueReceipt(declaration.idempotencyKey), original);
  assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(signingKeyPath).mode & 0o777, 0o600);

  const lines = fs.readFileSync(filePath, 'utf8').trimEnd().split('\n');
  const event = JSON.parse(lines[0]);
  event.data.creatorId = 'attacker';
  const { eventHash: ignoredHash, eventSignature: preservedSignature, ...unsigned } = event;
  event.eventHash = crypto.createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
  event.eventSignature = preservedSignature;
  lines[0] = JSON.stringify(event);
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, { mode: 0o600 });
  assert.throws(() => createInvocationJournal({ filePath, signingKeyPath }), /event signature mismatch/);
});

test('a rejected transition is validated before append and leaves durable bytes replayable', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-prevalidate-');
  const journal = createInvocationJournal({ filePath, signingKeyPath });
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  const before = fs.readFileSync(filePath);
  assert.throws(() => journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'failed',
    failureClass: 'FAULT',
    message: 'invalid status must not append',
    outcomeHash: null,
    httpStatus: 99,
    accounting: pendingFailureAccounting(),
  }), /HTTP status/);
  assert.deepEqual(fs.readFileSync(filePath), before);
  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.equal(reopened.getByIdempotencyKey(declaration.idempotencyKey).execution.state, 'executing');
});

test('a malicious persistent signer cannot write an unverifiable first event', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-malicious-signer-');
  const authority = loadOrCreateReceiptSigner(signingKeyPath);
  const maliciousSigner = Object.freeze({
    persistent: true,
    algorithm: 'Ed25519',
    publicKeyPem: authority.publicKeyPem,
    keyId: authority.keyId,
    signHash: () => Buffer.alloc(64, 0x5a).toString('base64'),
  });
  const journal = createInvocationJournal({ filePath, signingKeyPath, signer: maliciousSigner });
  assert.throws(
    () => journal.requestInvocation(declaration),
    /generated journal event signature does not match the persistent receipt key/,
  );
  assert.deepEqual(journal.events, []);
  assert.equal(fs.existsSync(filePath), false);
  assert.equal(fs.existsSync(`${filePath}.lock`), false);

  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.deepEqual(reopened.events, []);
  assert.doesNotThrow(() => reopened.requestInvocation(declaration));
  assert.equal(reopened.events.length, 1);
});

test('persistent authority rejects checkout, symlink, relative, non-file, and broad-permission paths', () => {
  const { directory, filePath, signingKeyPath } = temporaryAuthority('collar-paths-');
  const journal = createInvocationJournal({ filePath, signingKeyPath });
  journal.requestInvocation(declaration);
  fs.chmodSync(filePath, 0o644);
  assert.throws(() => createInvocationJournal({ filePath, signingKeyPath }), /exactly 0600/);
  fs.chmodSync(filePath, 0o600);
  const keyLink = path.join(directory, 'key-link.pem');
  fs.symlinkSync(signingKeyPath, keyLink);
  assert.throws(() => createInvocationJournal({ filePath: path.join(directory, 'other.jsonl'), signingKeyPath: keyLink }), /non-symlink/);
  const directoryTarget = path.join(directory, 'not-a-file');
  fs.mkdirSync(directoryTarget);
  assert.throws(() => createInvocationJournal({ filePath: directoryTarget, signingKeyPath }), /regular non-symlink file/);
  assert.throws(() => createInvocationJournal({ filePath: 'relative.jsonl', signingKeyPath }), /explicit absolute/);
  assert.throws(() => createInvocationJournal({
    filePath: fileURLToPath(new URL('../unsafe-journal.jsonl', import.meta.url)),
    signingKeyPath,
  }), /outside the repository checkout/);
});

test('a receipt cannot authenticate itself and tampering invalidates it', () => {
  const journal = fixture();
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'failed', failureClass: 'FAULT', message: 'fault', outcomeHash: null,
    httpStatus: 500, accounting: pendingFailureAccounting('FAULT'),
  });
  const bundle = journal.issueReceipt(declaration.idempotencyKey);
  const tampered = structuredClone(bundle);
  tampered.receipt.payment.txHash = `0x${'9'.repeat(64)}`;
  assert.equal(verifySignedReceipt(tampered, trustFor(journal)), false);
  const attacker = fixture({ createId: () => 'inv-attacker' });
  settle(attacker);
  const attackerClaim = attacker.startExecution(declaration.idempotencyKey);
  attacker.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: attackerClaim.record.execution.executionAttemptId,
    outcome: 'failed', failureClass: 'FAULT', message: 'fault', outcomeHash: null,
    httpStatus: 500, accounting: pendingFailureAccounting('FAULT'),
  });
  assert.equal(verifySignedReceipt(attacker.issueReceipt(declaration.idempotencyKey), trustFor(journal)), false);
});

test('refund reverses only a terminal failed full-gross hold and issues a signed revision', () => {
  const journal = fixture();
  settle(journal);
  const claim = journal.startExecution(declaration.idempotencyKey);
  journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: claim.record.execution.executionAttemptId,
    outcome: 'failed', failureClass: 'COGS_UNKNOWN', message: 'fault', outcomeHash: null,
    httpStatus: 500, accounting: pendingFailureAccounting('COGS_UNKNOWN'),
  });
  const original = journal.issueReceipt(declaration.idempotencyKey);
  const request = {
    refundAttemptId: 'refund-attempt-0001',
    reason: 'settled execution failure',
    refundReference: `refund:${'5'.repeat(64)}`,
    refundAmountAtomic: '250000',
  };
  const firstClaim = journal.startRefund(declaration.idempotencyKey, {
    refundAttemptId: request.refundAttemptId,
  });
  assert.equal(firstClaim.started, true);
  assert.equal(journal.startRefund(declaration.idempotencyKey).started, false);
  assert.throws(() => journal.refundExternalPayment(declaration.idempotencyKey, { ...request, refundAmountAtomic: '249999' }), /full settled gross/);
  journal.refundExternalPayment(declaration.idempotencyKey, request);
  const revised = journal.issueReceipt(declaration.idempotencyKey);
  assert.equal(revised.receipt.revision, 2);
  assert.equal(revised.receipt.supersedesReceiptHash, original.receiptHash);
  assert.equal(revised.receipt.payment.state, 'refunded');
  assert.equal(revised.receipt.payment.refundAmountAtomic, '250000');
  assert.equal(revised.receipt.payment.refundAccounting.reversalEntries.length, 2);
  assert.equal(verifySignedReceipt(original, trustFor(journal)), true);
  assert.equal(verifySignedReceipt(revised, trustFor(journal)), true);
});

test('refund execution is durably claimed once and ambiguous outcomes remain unresolved', () => {
  const journal = fixture();
  settle(journal);
  const execution = journal.startExecution(declaration.idempotencyKey);
  journal.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: execution.record.execution.executionAttemptId,
    outcome: 'failed', failureClass: 'COGS_UNKNOWN', message: 'safe failure', outcomeHash: null,
    httpStatus: 500, accounting: pendingFailureAccounting('COGS_UNKNOWN'),
  });
  journal.issueReceipt(declaration.idempotencyKey);

  const claim = journal.startRefund(declaration.idempotencyKey, {
    refundAttemptId: 'refund-attempt-crash',
  });
  assert.equal(claim.started, true);
  assert.equal(journal.startRefund(declaration.idempotencyKey).started, false);
  journal.markRefundUnresolved(declaration.idempotencyKey, {
    refundAttemptId: 'refund-attempt-crash',
    reason: 'trusted refund outcome unresolved',
  });
  assert.equal(journal.startRefund(declaration.idempotencyKey).started, false);
  const unresolved = journal.getByIdempotencyKey(declaration.idempotencyKey);
  assert.deepEqual(unresolved.payment.refundExecution, {
    state: 'unresolved',
    refundAttemptId: 'refund-attempt-crash',
    reason: 'trusted refund outcome unresolved',
  });
  assert.equal(journal.events.filter((event) => event.type === 'refund.started').length, 1);
  assert.equal(journal.events.filter((event) => event.type === 'refund.unresolved').length, 1);

  assert.throws(() => journal.refundExternalPayment(declaration.idempotencyKey, {
    refundAttemptId: 'another-attempt',
    reason: 'trusted full-gross refund confirmed',
    refundReference: 'trusted-refund',
    refundAmountAtomic: '250000',
  }), /refund attempt/);
  journal.refundExternalPayment(declaration.idempotencyKey, {
    refundAttemptId: 'refund-attempt-crash',
    reason: 'trusted full-gross refund confirmed',
    refundReference: 'trusted-refund',
    refundAmountAtomic: '250000',
  });
  const terminal = journal.getByIdempotencyKey(declaration.idempotencyKey);
  assert.equal(terminal.payment.refundExecution.state, 'confirmed');
  assert.equal(journal.startRefund(declaration.idempotencyKey).started, false);
});

test('separate journal instances observe one durable refund claim', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-refund-claim-');
  const first = createInvocationJournal({ filePath, signingKeyPath });
  settle(first);
  const execution = first.startExecution(declaration.idempotencyKey);
  first.finishExecution(declaration.idempotencyKey, {
    executionAttemptId: execution.record.execution.executionAttemptId,
    outcome: 'failed', failureClass: 'COGS_UNKNOWN', message: 'safe failure', outcomeHash: null,
    httpStatus: 500, accounting: pendingFailureAccounting('COGS_UNKNOWN'),
  });
  first.issueReceipt(declaration.idempotencyKey);
  const second = createInvocationJournal({ filePath, signingKeyPath });
  assert.equal(first.startRefund(declaration.idempotencyKey).started, true);
  assert.equal(second.startRefund(declaration.idempotencyKey).started, false);
  assert.equal(second.events.filter((event) => event.type === 'refund.started').length, 1);
  assert.equal(
    first.getByIdempotencyKey(declaration.idempotencyKey).payment.refundExecution.refundAttemptId,
    second.getByIdempotencyKey(declaration.idempotencyKey).payment.refundExecution.refundAttemptId,
  );
});

test('separate journal instances observe one durable execution claim', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-execution-claim-');
  const first = createInvocationJournal({ filePath, signingKeyPath });
  settle(first);
  const second = createInvocationJournal({ filePath, signingKeyPath });
  assert.equal(first.startExecution(declaration.idempotencyKey).started, true);
  const losingClaim = second.startExecution(declaration.idempotencyKey);
  assert.equal(losingClaim.started, false);
  assert.equal(losingClaim.record.execution.state, 'executing');
  assert.equal(second.events.filter((event) => event.type === 'execution.started').length, 1);
});

const waitForExit = (child) => new Promise((resolve, reject) => {
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.once('error', reject);
  child.once('exit', (code, signal) => code === 0
    ? resolve()
    : reject(new Error(`fixture exited ${code ?? signal}: ${stderr}`)));
});

async function waitForFiles(paths) {
  for (let attempt = 0; attempt < 300; attempt += 1) {
    if (paths.every((candidate) => fs.existsSync(candidate))) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`fixtures did not become ready: ${paths.join(', ')}`);
}

test('two same-host processes serialize signed hash-chained appends', async () => {
  const { directory, filePath, signingKeyPath } = temporaryAuthority('collar-writers-');
  const barrierPath = path.join(directory, 'start');
  loadOrCreateReceiptSigner(signingKeyPath);
  const worker = fileURLToPath(new URL('./journal-writer-fixture.mjs', import.meta.url));
  const keys = ['idem-process-a', 'idem-process-b'];
  const children = keys.map((key) => spawn(process.execPath, [
    worker, filePath, signingKeyPath, barrierPath, key, path.join(directory, `${key}.ready`),
  ], { stdio: ['ignore', 'ignore', 'pipe'] }));
  await waitForFiles(keys.map((key) => path.join(directory, `${key}.ready`)));
  fs.writeFileSync(barrierPath, 'go', { flag: 'wx' });
  await Promise.all(children.map(waitForExit));
  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.ok(reopened.getByIdempotencyKey(keys[0]));
  assert.ok(reopened.getByIdempotencyKey(keys[1]));
  assert.deepEqual(reopened.events.map(({ sequence }) => sequence), [1, 2]);
  assert.equal(reopened.events[1].previousHash, reopened.events[0].eventHash);
});

test('a second process sees the complete frozen offer from the first', async () => {
  const { directory, filePath, signingKeyPath } = temporaryAuthority('collar-reader-');
  const outputPath = path.join(directory, 'quote.json');
  const writer = createInvocationJournal({ filePath, signingKeyPath });
  offer(writer);
  const child = spawn(process.execPath, [
    fileURLToPath(new URL('./journal-reader-fixture.mjs', import.meta.url)),
    filePath, signingKeyPath, declaration.idempotencyKey, outputPath,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  await waitForExit(child);
  assert.deepEqual(JSON.parse(fs.readFileSync(outputPath, 'utf8')), requirements);
});

test('explicit stale-lock recovery uses an immutable lease claim and never deletes a replacement owner', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-lock-');
  let armed = false;
  const stale = {
    leaseId: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    hostname: os.hostname(),
    pid: 999_999_999,
    startedAtUtc: '2026-07-17T12:00:00.000Z',
  };
  const movedReplacement = {
    ...stale,
    leaseId: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    pid: process.pid,
    startedAtUtc: '2026-07-17T12:00:01.000Z',
  };
  const newOwner = {
    ...stale,
    leaseId: 'cccccccccccccccccccccccccccccccc',
    pid: process.pid,
    startedAtUtc: '2026-07-17T12:00:02.000Z',
  };
  const hooks = {
    isProcessAlive: () => {
      if (armed) {
        const replacementPath = `${filePath}.lock.replacement`;
        fs.writeFileSync(replacementPath, `${JSON.stringify(movedReplacement)}\n`, { flag: 'wx', mode: 0o600 });
        fs.renameSync(replacementPath, `${filePath}.lock`);
      }
      return false;
    },
    afterLeaseClaim: () => {
      if (armed) fs.writeFileSync(`${filePath}.lock`, `${JSON.stringify(newOwner)}\n`, { flag: 'wx', mode: 0o600 });
    },
  };
  const journal = createInvocationJournal({ filePath, signingKeyPath, lockTestHooks: hooks });
  fs.writeFileSync(`${filePath}.lock`, `${JSON.stringify(stale)}\n`, { flag: 'wx', mode: 0o600 });
  armed = true;
  assert.throws(() => journal.recoverStaleLock({ expectedLeaseId: stale.leaseId }), /retained at|owner changed/);
  assert.deepEqual(JSON.parse(fs.readFileSync(`${filePath}.lock`, 'utf8')), newOwner);
  assert.equal(fs.readdirSync(path.dirname(filePath)).filter((name) => name.endsWith('.claim')).length, 1);
});

test('malformed, unknown-liveness, and different-host locks fail closed', () => {
  for (const scenario of ['malformed', 'unknown', 'different-host']) {
    const { filePath, signingKeyPath } = temporaryAuthority(`collar-lock-${scenario}-`);
    const journal = createInvocationJournal({
      filePath,
      signingKeyPath,
      lockTestHooks: scenario === 'unknown' ? { isProcessAlive: () => undefined } : {},
    });
    const lockPath = `${filePath}.lock`;
    const owner = {
      leaseId: 'dddddddddddddddddddddddddddddddd',
      hostname: scenario === 'different-host' ? 'other-host.example' : os.hostname(),
      pid: 999_999_998,
      startedAtUtc: '2026-07-17T12:00:00.000Z',
    };
    fs.writeFileSync(
      lockPath,
      scenario === 'malformed' ? '{not-json}\n' : `${JSON.stringify(owner)}\n`,
      { flag: 'wx', mode: 0o600 },
    );
    if (scenario === 'malformed') {
      assert.throws(() => journal.recoverStaleLock({ expectedLeaseId: owner.leaseId }), /malformed/);
    } else if (scenario === 'unknown') {
      assert.throws(() => journal.recoverStaleLock({ expectedLeaseId: owner.leaseId }), /no boolean proof/);
    } else {
      assert.throws(() => journal.recoverStaleLock({ expectedLeaseId: owner.leaseId }), /different host/);
    }
    assert.equal(fs.existsSync(lockPath), true);
  }
});

test('same-host process-probe errors fail closed and exact stale recovery succeeds only with absence proof', () => {
  const denied = temporaryAuthority('collar-lock-eperm-');
  const deniedJournal = createInvocationJournal({
    filePath: denied.filePath,
    signingKeyPath: denied.signingKeyPath,
    lockTestHooks: { isProcessAlive: () => {
      const error = new Error('EPERM');
      error.code = 'EPERM';
      throw error;
    } },
  });
  const deniedOwner = {
    leaseId: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    hostname: os.hostname(),
    pid: 999_999_997,
    startedAtUtc: '2026-07-17T12:00:00.000Z',
  };
  fs.writeFileSync(`${denied.filePath}.lock`, `${JSON.stringify(deniedOwner)}\n`, { flag: 'wx', mode: 0o600 });
  assert.throws(() => deniedJournal.recoverStaleLock({ expectedLeaseId: deniedOwner.leaseId }), /EPERM/);
  assert.equal(fs.existsSync(`${denied.filePath}.lock`), true);

  const recoverable = temporaryAuthority('collar-lock-recover-');
  const recoverableJournal = createInvocationJournal({
    filePath: recoverable.filePath,
    signingKeyPath: recoverable.signingKeyPath,
    lockTestHooks: { isProcessAlive: () => false },
  });
  const recoverableOwner = { ...deniedOwner, leaseId: 'ffffffffffffffffffffffffffffffff' };
  fs.writeFileSync(`${recoverable.filePath}.lock`, `${JSON.stringify(recoverableOwner)}\n`, { flag: 'wx', mode: 0o600 });
  assert.throws(() => recoverableJournal.recoverStaleLock({
    expectedLeaseId: '00000000000000000000000000000000',
  }), /does not match/);
  recoverableJournal.recoverStaleLock({ expectedLeaseId: recoverableOwner.leaseId });
  assert.equal(fs.existsSync(`${recoverable.filePath}.lock`), false);
  assert.deepEqual(recoverableJournal.events, []);
});

test('normal lease release never unlinks a replacement owner and uses private lock/claim paths', () => {
  const { directory, filePath, signingKeyPath } = temporaryAuthority('collar-lock-release-');
  const replacementOwner = {
    leaseId: 'abababababababababababababababab',
    hostname: os.hostname(),
    pid: process.pid,
    startedAtUtc: '2026-07-17T12:00:03.000Z',
  };
  let observedMode = null;
  const journal = createInvocationJournal({
    filePath,
    signingKeyPath,
    now: () => {
      observedMode = fs.statSync(`${filePath}.lock`).mode & 0o777;
      const replacementPath = `${filePath}.lock.replacement`;
      fs.writeFileSync(replacementPath, `${JSON.stringify(replacementOwner)}\n`, { flag: 'wx', mode: 0o600 });
      fs.renameSync(replacementPath, `${filePath}.lock`);
      return '2026-07-17T12:00:04.000Z';
    },
  });
  assert.throws(() => journal.requestInvocation(declaration), /lease CAS failed.*restored/);
  assert.equal(observedMode, 0o600);
  assert.deepEqual(JSON.parse(fs.readFileSync(`${filePath}.lock`, 'utf8')), replacementOwner);
  assert.equal(fs.readdirSync(directory).filter((name) => name.endsWith('.claim')).length, 0);
  assert.equal(journal.lockPath, `${filePath}.lock`);
});

test('lease-acquisition failure never read-then-unlinks a replacement owner', () => {
  const { filePath, signingKeyPath } = temporaryAuthority('collar-lock-acquire-');
  let armed = false;
  const replacementOwner = {
    leaseId: 'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd',
    hostname: os.hostname(),
    pid: process.pid,
    startedAtUtc: '2026-07-17T12:00:05.000Z',
  };
  const journal = createInvocationJournal({
    filePath,
    signingKeyPath,
    lockTestHooks: {
      afterLeaseCreated(lockPath) {
        if (!armed) return;
        const replacementPath = `${lockPath}.replacement`;
        fs.writeFileSync(replacementPath, `${JSON.stringify(replacementOwner)}\n`, { flag: 'wx', mode: 0o600 });
        fs.renameSync(replacementPath, lockPath);
        throw new Error('injected post-create failure');
      },
    },
  });
  armed = true;
  assert.throws(() => journal.requestInvocation(declaration), /injected post-create failure/);
  assert.deepEqual(JSON.parse(fs.readFileSync(`${filePath}.lock`, 'utf8')), replacementOwner);
});

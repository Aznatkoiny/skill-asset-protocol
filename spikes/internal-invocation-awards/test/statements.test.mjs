import assert from 'node:assert/strict';
import {
  createHash,
  generateKeyPairSync,
  sign as cryptoSign,
} from 'node:crypto';
import test from 'node:test';

import { receiptSequenceScope } from '../src/receipt-ledger.mjs';

import {
  buildInvocationReceipt,
  buildStatement,
  canonicalReceiptBytes,
  canonicalStatementBytes,
  receiptHash,
  receiptMerkleRoot,
  renderJsonl,
  signReceipt,
  signStatement,
  statementHash,
  verifyReceipt,
  verifyStatement,
} from '../src/statements.mjs';

const NOW = '2026-07-17T00:01:00.000Z';
const SKILL_HASH = `sha256:${'1'.repeat(64)}`;
const OUTPUT_HASH = `sha256:${'a'.repeat(64)}`;

function successRecords(sequence = 1, suffix = '001') {
  const quote = {
    schemaVersion: 1,
    quoteId: `quote-${suffix}`,
    invocationId: `inv-${suffix}`,
    idempotencyKey: `run-${suffix}`,
    skillId: 'ledger-recon',
    skillVersionHash: SKILL_HASH,
    creatorId: 'sam',
    wielderId: 'megacorp-internal-agent',
    initiatingPrincipalId: 'jordan',
    principalAttestationId: `attestation-${suffix}`,
    beneficiaryId: 'megacorp',
    costCenter: 'platform-engineering',
    policyId: 'policy-megacorp-ledger-recon',
    policyVersion: 1,
    policyHash: `sha256:${'2'.repeat(64)}`,
    maxExecutionCostAtomic: '1000000',
    protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000',
    maxInvocationAwardAtomic: '2000000',
    maxGrossAtomic: '3050000',
    expiresAt: '2026-07-17T00:05:00.000Z',
  };
  const reservation = {
    schemaVersion: 1,
    reservationId: `res-${suffix}`,
    quote,
    state: 'consumed',
    reservedAtomic: '3050000',
    revision: 2,
    executionAttemptId: `attempt-${suffix}`,
    authorizedAt: NOW,
    startedAt: NOW,
    finalizedAt: NOW,
  };
  const invocation = {
    schemaVersion: 1,
    invocationId: quote.invocationId,
    idempotencyKey: quote.idempotencyKey,
    quoteId: quote.quoteId,
    reservationId: reservation.reservationId,
    skillId: quote.skillId,
    skillVersionHash: quote.skillVersionHash,
    skillRegistrationId: 'registration-ledger-recon-v1',
    creatorId: 'sam',
    wielderId: quote.wielderId,
    initiatingPrincipalId: quote.initiatingPrincipalId,
    principalAttestationId: quote.principalAttestationId,
    principalAttestationHash: `sha256:${'3'.repeat(64)}`,
    beneficiaryId: 'megacorp',
    costCenter: quote.costCenter,
    policyId: quote.policyId,
    policyVersion: 1,
    policyHash: quote.policyHash,
    period: '2026-07',
    currency: 'USD',
    atomicScale: 6,
    state: 'succeeded',
    revision: 2,
    credentialNonce: '1'.padStart(64, '0'),
    credentialIssuedAt: NOW,
    credentialExpiresAt: quote.expiresAt,
    executionAttemptId: reservation.executionAttemptId,
    authorizedAt: NOW,
    startedAt: NOW,
    finalizedAt: NOW,
    executionCostStatus: 'known',
    executionCostAtomic: '700000',
    protocolFeeAtomic: '25000',
    refundReserveAtomic: '25000',
    maxInvocationAwardAtomic: '2000000',
    invocationAwardAtomic: '2000000',
    releasedAtomic: '300000',
    heldReservationAtomic: '0',
    awardId: `award-${suffix}`,
    outputHash: OUTPUT_HASH,
    failureClass: null,
    unresolvedReason: null,
    externalRoyaltyCreditsAtomic: '0',
    employerSelfCreditAtomic: '0',
    journalEntries: [
      { category: 'execution-cogs', debitAccountId: 'employer:invocation-gross', creditAccountId: 'provider:execution', amountAtomic: '700000' },
      { category: 'protocol-fee', debitAccountId: 'employer:invocation-gross', creditAccountId: 'protocol:treasury', amountAtomic: '25000' },
      { category: 'refund-reserve', debitAccountId: 'employer:invocation-gross', creditAccountId: 'reserve:refund', amountAtomic: '25000' },
      { category: 'invocation-award', debitAccountId: 'employer:invocation-gross', creditAccountId: 'employee:sam', amountAtomic: '2000000' },
    ],
    receiptSequence: sequence,
    receiptSequenceScope: receiptSequenceScope({
      employerId: 'megacorp', creatorId: 'sam', currency: 'USD', atomicScale: 6,
    }),
  };
  const award = {
    schemaVersion: 1,
    awardId: invocation.awardId,
    invocationId: invocation.invocationId,
    recipientId: 'sam',
    policyId: invocation.policyId,
    policyVersion: 1,
    period: '2026-07',
    currency: 'USD',
    atomicScale: 6,
    amountAtomic: '2000000',
    state: 'earned',
    measuredAt: NOW,
    earnedAt: NOW,
    payableAt: null,
    paidAt: null,
  };
  return { invocation, reservation, award };
}

function unresolvedRecords(sequence = 2) {
  const records = successRecords(sequence, 'unresolved');
  return {
    reservation: { ...records.reservation, state: 'held_unresolved' },
    award: null,
    invocation: {
      ...records.invocation,
      state: 'unresolved',
      executionCostStatus: 'unresolved',
      executionCostAtomic: null,
      protocolFeeAtomic: '0',
      refundReserveAtomic: '0',
      invocationAwardAtomic: '0',
      releasedAtomic: '0',
      heldReservationAtomic: '3050000',
      awardId: null,
      outputHash: null,
      unresolvedReason: 'cost_unknown',
      journalEntries: [],
    },
  };
}

function signerFixture() {
  const receipt = generateKeyPairSync('ed25519');
  const statement = generateKeyPairSync('ed25519');
  return {
    receipt,
    statement,
    receiptTrust: {
      'collar-receipt-key-2026-07': receipt.publicKey.export({ type: 'spki', format: 'pem' }),
    },
    statementTrust: {
      'collar-statement-key-2026-07': statement.publicKey.export({ type: 'spki', format: 'pem' }),
    },
  };
}

function signedSuccess(signers, sequence = 1, suffix = '001') {
  return signReceipt(buildInvocationReceipt({
    ...successRecords(sequence, suffix),
    employerId: 'megacorp',
    receiptSignerId: 'collar-receipt-key-2026-07',
  }), signers.receipt.privateKey);
}

function signedSuccessInPeriod(signers, sequence, suffix, period, occurredAt) {
  const records = successRecords(sequence, suffix);
  return signReceipt(buildInvocationReceipt({
    invocation: {
      ...records.invocation,
      period,
      authorizedAt: occurredAt,
      startedAt: occurredAt,
      finalizedAt: occurredAt,
    },
    reservation: {
      ...records.reservation,
      authorizedAt: occurredAt,
      startedAt: occurredAt,
      finalizedAt: occurredAt,
    },
    award: {
      ...records.award,
      period,
      measuredAt: occurredAt,
      earnedAt: occurredAt,
    },
    employerId: 'megacorp',
    receiptSignerId: 'collar-receipt-key-2026-07',
  }), signers.receipt.privateKey);
}

function signedJulyStatement(signers, receipts, suffix) {
  return signStatement(buildStatement({
    statementId: `statement-july-${suffix}`,
    employerId: 'megacorp',
    creatorId: 'sam',
    period: '2026-07',
    currency: 'USD',
    atomicScale: 6,
    openingPayableAtomic: '0',
    receipts,
    payableAdvances: [],
    reversals: [],
    payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  }), signers.statement.privateKey);
}

function expectedMerkleRoot(receipts) {
  const digest = (bytes) => createHash('sha256').update(bytes).digest();
  if (receipts.length === 0) {
    return `sha256:${digest(Buffer.from('internal-invocation-awards:receipt-merkle:v1:empty')).toString('hex')}`;
  }
  let level = receipts.map((receipt) => digest(Buffer.concat([
    Buffer.from('internal-invocation-awards:receipt-merkle:v1:leaf\0'),
    Buffer.from(receiptHash(receipt).slice(7), 'hex'),
  ])));
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      const left = level[index];
      const right = level[index + 1] ?? left;
      next.push(digest(Buffer.concat([
        Buffer.from('internal-invocation-awards:receipt-merkle:v1:node\0'),
        left,
        right,
      ])));
    }
    level = next;
  }
  return `sha256:${level[0].toString('hex')}`;
}

test('employer and employee verify identical exact receipt bytes through a trusted key ID', () => {
  const signers = signerFixture();
  const unsigned = buildInvocationReceipt({
    ...successRecords(), employerId: 'megacorp', receiptSignerId: 'collar-receipt-key-2026-07',
  });
  const signed = signReceipt(unsigned, signers.receipt.privateKey);
  const employer = verifyReceipt(signed, { trustedReceiptSigners: signers.receiptTrust });
  const employee = verifyReceipt(signed, { trustedReceiptSigners: signers.receiptTrust });
  assert.deepEqual(employer, employee);
  assert.deepEqual(canonicalReceiptBytes(employer), canonicalReceiptBytes(employee));
  assert.equal(employer.externalSettlementHash, null);
  assert.equal(employer.externalRoyaltyCreditsAtomic, '0');
  assert.equal(employer.employerSelfCreditAtomic, '0');
  assert.equal(employer.journalEntries.length, 4);
  assert.match(receiptHash(signed), /^sha256:[0-9a-f]{64}$/);
  assert.doesNotThrow(() => JSON.stringify(signed));
  assert.throws(
    () => verifyReceipt({ ...signed, invocationAwardAtomic: '1999999' }, { trustedReceiptSigners: signers.receiptTrust }),
    /signature|journal|consumed/,
  );
  assert.throws(
    () => verifyReceipt({ ...signed, publicKeyPem: 'self-declared' }, { trustedReceiptSigners: signers.receiptTrust }),
    /unknown key publicKeyPem/,
  );
  const wrongJournal = {
    ...unsigned,
    journalEntries: unsigned.journalEntries.map((entry, index) => (
      index === 3 ? { ...entry, creditAccountId: 'employee:attacker' } : entry
    )),
  };
  assert.throws(() => signReceipt(wrongJournal, signers.receipt.privateKey), /shared kernel allocation/);
});

test('unresolved receipt claims neither zero COGS nor release nor award', () => {
  const signers = signerFixture();
  const unsigned = buildInvocationReceipt({
    ...unresolvedRecords(), employerId: 'megacorp', receiptSignerId: 'collar-receipt-key-2026-07',
  });
  const signed = signReceipt(unsigned, signers.receipt.privateKey);
  const verified = verifyReceipt(signed, { trustedReceiptSigners: signers.receiptTrust });
  assert.equal(verified.executionCostStatus, 'unresolved');
  assert.equal(verified.executionCostAtomic, null);
  assert.equal(verified.heldReservationAtomic, '3050000');
  assert.equal(verified.releasedAtomic, '0');
  assert.equal(verified.invocationAwardAtomic, '0');
  assert.equal(verified.awardState, null);
  assert.deepEqual(verified.journalEntries, []);
});

test('cancelled authorization has one signed release receipt in the independent sequence', () => {
  const signers = signerFixture();
  const records = successRecords(1, 'cancelled');
  const reservation = { ...records.reservation, state: 'released', executionAttemptId: null };
  const invocation = {
    ...records.invocation,
    state: 'cancelled',
    executionAttemptId: null,
    executionCostStatus: null,
    executionCostAtomic: null,
    protocolFeeAtomic: '0',
    refundReserveAtomic: '0',
    invocationAwardAtomic: '0',
    releasedAtomic: '3050000',
    awardId: null,
    outputHash: null,
    journalEntries: [],
  };
  const receipt = signReceipt(buildInvocationReceipt({
    invocation,
    reservation,
    award: null,
    employerId: 'megacorp',
    receiptSignerId: 'collar-receipt-key-2026-07',
  }), signers.receipt.privateKey);
  const verified = verifyReceipt(receipt, { trustedReceiptSigners: signers.receiptTrust });
  assert.equal(verified.receiptType, 'internal_invocation_cancelled');
  assert.equal(verified.releasedAtomic, '3050000');
  const statement = buildStatement({
    statementId: 'statement-cancelled', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [receipt], payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  assert.equal(statement.releaseTotalAtomic, '3050000');
  assert.equal(statement.earnedAwardTotalAtomic, '0');
  assert.equal(statement.closingPayableAtomic, '0');
});

test('whole statement authenticates economics and earned is not payable until advanced', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const unsigned = buildStatement({
    statementId: 'statement-megacorp-sam-2026-07',
    employerId: 'megacorp',
    creatorId: 'sam',
    period: '2026-07',
    currency: 'USD',
    atomicScale: 6,
    openingPayableAtomic: '0',
    receipts: [receipt],
    payableAdvances: [],
    reversals: [],
    payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  assert.equal(unsigned.earnedAwardTotalAtomic, '2000000');
  assert.equal(unsigned.payableAdvanceTotalAtomic, '0');
  assert.equal(unsigned.closingPayableAtomic, '0');
  const signed = signStatement(unsigned, signers.statement.privateKey);
  const options = {
    signedReceipts: [receipt],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: signers.statementTrust,
  };
  const employer = verifyStatement(signed, options);
  const employee = verifyStatement(signed, options);
  assert.deepEqual(employer, employee);
  assert.deepEqual(canonicalStatementBytes(employer), canonicalStatementBytes(employee));
  assert.doesNotThrow(() => JSON.stringify(signed));
});

test('payable advances, reversal semantics, and payments determine payable closing', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const hash = receiptHash(receipt);
  const prior = signedJulyStatement(signers, [receipt], 'payable-events');
  const eventAt = '2026-08-17T00:01:00.000Z';
  const unsigned = buildStatement({
    statementId: 'statement-with-payable-events',
    employerId: 'megacorp', creatorId: 'sam', period: '2026-08',
    currency: 'USD', atomicScale: 6, openingPayableAtomic: prior.closingPayableAtomic,
    receipts: [], historicalReceipts: [receipt], priorStatement: prior,
    payableAdvances: [{
      advanceId: 'advance-001', receiptHash: hash, amountAtomic: '1000000', advancedAt: eventAt,
    }],
    reversals: [
      { reversalId: 'reversal-earned', receiptHash: hash, amountAtomic: '200000', balanceEffect: 'earned_only', reason: 'quality_adjustment', occurredAt: eventAt },
      { reversalId: 'reversal-payable', receiptHash: hash, amountAtomic: '100000', balanceEffect: 'payable', reason: 'duplicate_advance', occurredAt: eventAt },
    ],
    payments: [{ paymentId: 'payment-001', amountAtomic: '250000', paidAt: eventAt, railReference: 'simulated-payroll-ref' }],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  assert.equal(unsigned.earnedAwardTotalAtomic, '0');
  assert.equal(unsigned.awardActivity[0].earnedAtomic, '2000000');
  assert.equal(unsigned.reversalTotalAtomic, '300000');
  assert.equal(unsigned.payableReversalTotalAtomic, '100000');
  assert.equal(unsigned.paymentTotalAtomic, '250000');
  assert.equal(unsigned.closingPayableAtomic, '650000');
  const signed = signStatement(unsigned, signers.statement.privateKey);
  assert.doesNotThrow(() => verifyStatement(signed, {
    signedReceipts: [],
    historicalSignedReceipts: [receipt],
    priorStatements: [{ signedStatement: prior, signedReceipts: [receipt] }],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: signers.statementTrust,
  }));
  assert.throws(() => buildStatement({
    statementId: 'over-reversed', employerId: 'megacorp', creatorId: 'sam', period: '2026-08',
    currency: 'USD', atomicScale: 6, openingPayableAtomic: prior.closingPayableAtomic,
    receipts: [], historicalReceipts: [receipt], priorStatement: prior,
    payableAdvances: [], payments: [], statementSignerId: 'collar-statement-key-2026-07',
    reversals: [{ reversalId: 'r', receiptHash: hash, amountAtomic: '1', balanceEffect: 'payable', reason: 'bad', occurredAt: eventAt }],
  }), /payable reversal exceeds advanced amount/);
});

test('monthly-in-arrears rejects advancing or paying a current-period award', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const hash = receiptHash(receipt);
  assert.throws(() => buildStatement({
    statementId: 'same-period-advance', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [receipt], historicalReceipts: [], priorStatement: null,
    payableAdvances: [{
      advanceId: 'advance-same-period', receiptHash: hash, amountAtomic: '1',
      advancedAt: NOW,
    }],
    reversals: [],
    payments: [{
      paymentId: 'payment-same-period', amountAtomic: '1', paidAt: NOW,
      railReference: 'same-period-payment',
    }],
    statementSignerId: 'collar-statement-key-2026-07',
  }), /payable advance must reference an authenticated historical receipt/);
});

test('receipt occurrence month blocks the July-to-August payable bypass', () => {
  const signers = signerFixture();
  const occurredAt = '2026-08-01T00:01:00.000Z';
  const records = successRecords(1, 'late-july');
  assert.throws(() => {
    const receipt = signReceipt(buildInvocationReceipt({
      invocation: {
        ...records.invocation,
        finalizedAt: occurredAt,
      },
      reservation: {
        ...records.reservation,
        finalizedAt: occurredAt,
      },
      award: {
        ...records.award,
        measuredAt: occurredAt,
        earnedAt: occurredAt,
      },
      employerId: 'megacorp',
      receiptSignerId: 'collar-receipt-key-2026-07',
    }), signers.receipt.privateKey);
    const july = signedJulyStatement(signers, [receipt], 'late-july');
    const hash = receiptHash(receipt);
    return buildStatement({
      statementId: 'statement-immediate-august-payment',
      employerId: 'megacorp', creatorId: 'sam', period: '2026-08',
      currency: 'USD', atomicScale: 6, openingPayableAtomic: july.closingPayableAtomic,
      receipts: [], historicalReceipts: [receipt], priorStatement: july,
      payableAdvances: [{
        advanceId: 'advance-immediate', receiptHash: hash,
        amountAtomic: '2000000', advancedAt: occurredAt,
      }],
      reversals: [],
      payments: [{
        paymentId: 'payment-immediate', amountAtomic: '2000000',
        paidAt: occurredAt, railReference: 'simulated-immediate-payment',
      }],
      statementSignerId: 'collar-statement-key-2026-07',
    });
  }, /receipt occurredAt must fall within receipt period 2026-07/);
});

test('receipt verification rejects a correctly signed occurrence outside its period', () => {
  const signers = signerFixture();
  const valid = signedSuccess(signers, 1, 'verification-period');
  const { signature: _signature, ...unsigned } = valid;
  const mismatched = {
    ...unsigned,
    occurredAt: '2026-08-01T00:01:00.000Z',
  };
  const mismatchedSigned = {
    ...mismatched,
    signature: cryptoSign(
      null,
      new TextEncoder().encode(JSON.stringify(mismatched)),
      signers.receipt.privateKey,
    ).toString('base64'),
  };
  assert.throws(() => verifyReceipt(mismatchedSigned, {
    trustedReceiptSigners: signers.receiptTrust,
  }), /receipt occurredAt must fall within receipt period 2026-07/);
});

test('receipt and statement verification reject RSA-512 and private-key trust material', () => {
  const signers = signerFixture();
  const rsa = generateKeyPairSync('rsa', { modulusLength: 512 });
  const unsignedReceipt = buildInvocationReceipt({
    ...successRecords(), employerId: 'megacorp', receiptSignerId: 'rsa-receipt',
  });
  const rsaReceipt = signReceipt(unsignedReceipt, rsa.privateKey);
  assert.throws(() => verifyReceipt(rsaReceipt, {
    trustedReceiptSigners: {
      'rsa-receipt': rsa.publicKey.export({ type: 'spki', format: 'pem' }),
    },
  }), /Ed25519/);

  const receipt = signedSuccess(signers);
  const unsignedStatement = buildStatement({
    statementId: 'rsa-statement', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [receipt], payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'rsa-statement-signer',
  });
  const rsaStatement = signStatement(unsignedStatement, rsa.privateKey);
  assert.throws(() => verifyStatement(rsaStatement, {
    signedReceipts: [receipt],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: {
      'rsa-statement-signer': rsa.publicKey.export({ type: 'spki', format: 'pem' }),
    },
  }), /Ed25519/);

  const privatePem = signers.receipt.privateKey.export({ type: 'pkcs8', format: 'pem' });
  assert.throws(() => verifyReceipt(receipt, {
    trustedReceiptSigners: { 'collar-receipt-key-2026-07': privatePem },
  }), /public SPKI PEM/);
});

test('receipt verification rejects inherited signer-map entries', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers, 1, 'inherited-receipt-key');
  const inheritedTrust = Object.create({
    'collar-receipt-key-2026-07': signers.receipt.publicKey.export({
      type: 'spki', format: 'pem',
    }),
  });
  assert.throws(() => verifyReceipt(receipt, {
    trustedReceiptSigners: inheritedTrust,
  }), /receipt signer trust map must be a plain object/);
});

test('statement verification does not trust a prototype-polluted empty signer map', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers, 1, 'inherited-statement-key');
  const unsigned = buildStatement({
    statementId: 'statement-inherited-key', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [receipt], payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  const signed = signStatement(unsigned, signers.statement.privateKey);
  Object.prototype['collar-statement-key-2026-07'] = signers.statement.publicKey.export({
    type: 'spki', format: 'pem',
  });
  try {
    assert.throws(() => verifyStatement(signed, {
      signedReceipts: [receipt],
      trustedReceiptSigners: signers.receiptTrust,
      trustedStatementSigners: {},
    }), /statement signer key ID collar-statement-key-2026-07 is not trusted/);
  } finally {
    delete Object.prototype['collar-statement-key-2026-07'];
  }
});

test('August can authenticate a July award without recounting July economics', () => {
  const signers = signerFixture();
  const julyReceipt = signedSuccess(signers, 1, 'july');
  const julyHash = receiptHash(julyReceipt);
  const julyUnsigned = buildStatement({
    statementId: 'statement-2026-07', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [julyReceipt], payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  const july = signStatement(julyUnsigned, signers.statement.privateKey);

  const augustUnsigned = buildStatement({
    statementId: 'statement-2026-08', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-08', currency: 'USD', atomicScale: 6,
    openingPayableAtomic: july.closingPayableAtomic,
    receipts: [], historicalReceipts: [julyReceipt], priorStatement: july,
    payableAdvances: [{
      advanceId: 'advance-august', receiptHash: julyHash, amountAtomic: '1000000',
      advancedAt: '2026-08-01T00:00:00.000Z',
    }],
    reversals: [{
      reversalId: 'reversal-august', receiptHash: julyHash, amountAtomic: '100000',
      balanceEffect: 'payable', reason: 'duplicate_advance',
      occurredAt: '2026-08-02T00:00:00.000Z',
    }],
    payments: [{
      paymentId: 'payment-august', amountAtomic: '250000',
      paidAt: '2026-08-03T00:00:00.000Z', railReference: 'simulated-august-payroll',
    }],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  assert.equal(augustUnsigned.priorStatementHash, statementHash(july));
  assert.equal(augustUnsigned.priorClosingPayableAtomic, '0');
  assert.equal(augustUnsigned.lastRecognizedReceiptSequence, 1);
  assert.deepEqual(augustUnsigned.historicalReceiptHashes, [julyHash]);
  assert.equal(augustUnsigned.reservationTotalAtomic, '0');
  assert.equal(augustUnsigned.releaseTotalAtomic, '0');
  assert.equal(augustUnsigned.chargeTotalAtomic, '0');
  assert.equal(augustUnsigned.earnedAwardTotalAtomic, '0');
  assert.equal(augustUnsigned.closingPayableAtomic, '650000');
  const august = signStatement(augustUnsigned, signers.statement.privateKey);
  assert.doesNotThrow(() => verifyStatement(august, {
    signedReceipts: [],
    historicalSignedReceipts: [julyReceipt],
    priorStatements: [{ signedStatement: july, signedReceipts: [julyReceipt] }],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: signers.statementTrust,
  }));
  assert.throws(() => buildStatement({
    ...{
      statementId: 'bad-opening', employerId: 'megacorp', creatorId: 'sam',
      period: '2026-08', currency: 'USD', atomicScale: 6, openingPayableAtomic: '1',
      receipts: [], historicalReceipts: [julyReceipt], priorStatement: july,
      payableAdvances: [], reversals: [], payments: [],
      statementSignerId: 'collar-statement-key-2026-07',
    },
  }), /opening payable must equal authenticated prior closing payable/);
  assert.throws(() => buildStatement({
    statementId: 'missing-chain', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-08', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [], historicalReceipts: [julyReceipt], priorStatement: null,
    payableAdvances: [{
      advanceId: 'advance-without-chain', receiptHash: julyHash, amountAtomic: '1',
      advancedAt: '2026-08-01T00:00:00.000Z',
    }],
    reversals: [], payments: [], statementSignerId: 'collar-statement-key-2026-07',
  }), /historical receipt is not authenticated by the prior statement chain/);

  for (const duplicate of [
    { payableAdvances: [{ advanceId: 'advance-august', receiptHash: julyHash, amountAtomic: '1', advancedAt: '2026-09-01T00:00:00.000Z' }], reversals: [], payments: [] },
    { payableAdvances: [], reversals: [{ reversalId: 'reversal-august', receiptHash: julyHash, amountAtomic: '1', balanceEffect: 'payable', reason: 'duplicate', occurredAt: '2026-09-01T00:00:00.000Z' }], payments: [] },
    { payableAdvances: [], reversals: [], payments: [{ paymentId: 'payment-august', amountAtomic: '1', paidAt: '2026-09-01T00:00:00.000Z', railReference: 'duplicate' }] },
  ]) {
    assert.throws(() => buildStatement({
      statementId: 'statement-2026-09', employerId: 'megacorp', creatorId: 'sam',
      period: '2026-09', currency: 'USD', atomicScale: 6,
      openingPayableAtomic: august.closingPayableAtomic,
      receipts: [], historicalReceipts: [julyReceipt], priorStatement: august,
      statementSignerId: 'collar-statement-key-2026-07',
      ...duplicate,
    }), /ID already appeared in a prior statement/);
  }

  assert.throws(() => buildStatement({
    statementId: 'renamed-payment-replay', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-09', currency: 'USD', atomicScale: 6,
    openingPayableAtomic: august.closingPayableAtomic,
    receipts: [], historicalReceipts: [julyReceipt], priorStatement: august,
    payableAdvances: [], reversals: [],
    payments: [{
      paymentId: 'renamed-payment-id', amountAtomic: '1',
      paidAt: '2026-09-01T00:00:00.000Z',
      railReference: 'simulated-august-payroll',
    }],
    statementSignerId: 'collar-statement-key-2026-07',
  }), /payment railReference ID already appeared/);
});

test('signed receipt cursor rejects cross-period gaps and survives receipt-free months', () => {
  const signers = signerFixture();
  const julyReceipt = signedSuccess(signers, 1, 'cursor-july');
  const july = signStatement(buildStatement({
    statementId: 'cursor-2026-07', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [julyReceipt], payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  }), signers.statement.privateKey);
  assert.equal(july.lastRecognizedReceiptSequence, 1);

  const august = signStatement(buildStatement({
    statementId: 'cursor-2026-08', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-08', currency: 'USD', atomicScale: 6,
    openingPayableAtomic: july.closingPayableAtomic,
    receipts: [], historicalReceipts: [], priorStatement: july,
    payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  }), signers.statement.privateKey);
  assert.equal(august.firstReceiptSequence, null);
  assert.equal(august.lastReceiptSequence, null);
  assert.equal(august.lastRecognizedReceiptSequence, 1);

  const septemberReceipt = signedSuccessInPeriod(
    signers,
    2,
    'cursor-september',
    '2026-09',
    '2026-09-01T00:01:00.000Z',
  );
  const september = signStatement(buildStatement({
    statementId: 'cursor-2026-09', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-09', currency: 'USD', atomicScale: 6,
    openingPayableAtomic: august.closingPayableAtomic,
    receipts: [septemberReceipt], historicalReceipts: [], priorStatement: august,
    payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  }), signers.statement.privateKey);
  assert.equal(september.lastRecognizedReceiptSequence, 2);
  assert.doesNotThrow(() => verifyStatement(september, {
    signedReceipts: [septemberReceipt],
    priorStatements: [
      { signedStatement: july, signedReceipts: [julyReceipt] },
      { signedStatement: august, signedReceipts: [] },
    ],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: signers.statementTrust,
  }));

  const skipped = signedSuccessInPeriod(
    signers,
    3,
    'cursor-skipped',
    '2026-09',
    '2026-09-02T00:01:00.000Z',
  );
  assert.throws(() => buildStatement({
    statementId: 'cursor-gap', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-09', currency: 'USD', atomicScale: 6,
    openingPayableAtomic: august.closingPayableAtomic,
    receipts: [skipped], historicalReceipts: [], priorStatement: august,
    payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  }), /sequence gap across periods: expected 2, received 3/);
});

test('statement economic events must occur in their signed statement period', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const hash = receiptHash(receipt);
  const base = {
    statementId: 'period-bound-events', employerId: 'megacorp', creatorId: 'sam',
    period: '2026-07', currency: 'USD', atomicScale: 6, openingPayableAtomic: '0',
    receipts: [receipt], statementSignerId: 'collar-statement-key-2026-07',
  };
  assert.throws(() => buildStatement({
    ...base,
    payableAdvances: [{
      advanceId: 'advance-outside', receiptHash: hash, amountAtomic: '1',
      advancedAt: '2026-08-01T00:00:00.000Z',
    }],
    reversals: [], payments: [],
  }), /advance advancedAt must fall within statement period/);
  assert.throws(() => buildStatement({
    ...base, payableAdvances: [],
    reversals: [{
      reversalId: 'reversal-outside', receiptHash: hash, amountAtomic: '1',
      balanceEffect: 'earned_only', reason: 'outside-period',
      occurredAt: '2026-08-01T00:00:00.000Z',
    }],
    payments: [],
  }), /reversal occurredAt must fall within statement period/);
  assert.throws(() => buildStatement({
    ...base, payableAdvances: [], reversals: [],
    payments: [{
      paymentId: 'payment-outside', amountAtomic: '0',
      paidAt: '2026-08-01T00:00:00.000Z', railReference: 'outside-period-ref',
    }],
  }), /payment paidAt must fall within statement period/);
});

test('statement sequence continuity and domain-separated Merkle rules are deterministic', () => {
  const signers = signerFixture();
  const receipt1 = signedSuccess(signers, 1, '001');
  const receipt2 = signedSuccess(signers, 2, '002');
  const receipt3 = signedSuccess(signers, 3, '003');
  const build = (receipts) => buildStatement({
    statementId: 'statement-sequences', employerId: 'megacorp', creatorId: 'sam', period: '2026-07',
    currency: 'USD', atomicScale: 6, openingPayableAtomic: '0', receipts,
    payableAdvances: [], reversals: [], payments: [],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  const oddA = build([receipt3, receipt1, receipt2]);
  const oddB = build([receipt1, receipt2, receipt3]);
  assert.equal(oddA.receiptMerkleRoot, oddB.receiptMerkleRoot);
  assert.equal(oddA.receiptMerkleRoot, expectedMerkleRoot([receipt1, receipt2, receipt3]));
  assert.deepEqual(oddA.receiptHashes, oddB.receiptHashes);
  assert.throws(() => build([receipt1, receipt3]), /statement sequence gap: expected 2, received 3/);

  const empty = build([]);
  assert.equal(empty.firstReceiptSequence, null);
  assert.equal(empty.lastReceiptSequence, null);
  assert.equal(empty.receiptMerkleRoot, expectedMerkleRoot([]));
  assert.equal(receiptMerkleRoot([receipt1]), expectedMerkleRoot([receipt1]));
  assert.notEqual(empty.receiptMerkleRoot, receiptMerkleRoot([receipt1]));
});

test('whole-statement and receipt trust roots reject tampering and attacker resigning', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const receipt2 = signedSuccess(signers, 2, '002');
  const receipt3 = signedSuccess(signers, 3, '003');
  const hash = receiptHash(receipt);
  const prior = signedJulyStatement(signers, [receipt, receipt2, receipt3], 'trust');
  const eventAt = '2026-08-17T00:01:00.000Z';
  const unsigned = buildStatement({
    statementId: 'statement-trust', employerId: 'megacorp', creatorId: 'sam', period: '2026-08',
    currency: 'USD', atomicScale: 6, openingPayableAtomic: prior.closingPayableAtomic,
    receipts: [], historicalReceipts: [receipt], priorStatement: prior,
    payableAdvances: [{ advanceId: 'advance-001', receiptHash: hash, amountAtomic: '1000000', advancedAt: eventAt }],
    reversals: [{ reversalId: 'reversal-001', receiptHash: hash, amountAtomic: '100000', balanceEffect: 'payable', reason: 'duplicate_advance', occurredAt: eventAt }],
    payments: [{ paymentId: 'payment-001', amountAtomic: '250000', paidAt: eventAt, railReference: 'simulated-payroll-ref' }],
    statementSignerId: 'collar-statement-key-2026-07',
  });
  const signed = signStatement(unsigned, signers.statement.privateKey);
  const options = {
    signedReceipts: [], historicalSignedReceipts: [receipt],
    priorStatements: [{ signedStatement: prior, signedReceipts: [receipt, receipt2, receipt3] }],
    trustedReceiptSigners: signers.receiptTrust,
    trustedStatementSigners: signers.statementTrust,
  };
  const replacePayment = (changes) => ({ payments: [{ ...signed.payments[0], ...changes }] });
  const replaceReversal = (changes) => ({ reversals: [{ ...signed.reversals[0], ...changes }] });
  const replaceAdvance = (changes) => ({ payableAdvances: [{ ...signed.payableAdvances[0], ...changes }] });
  const mutations = [
    ['statementId', { statementId: 'changed' }],
    ['employerId', { employerId: 'other-employer' }],
    ['creatorId', { creatorId: 'other-creator' }],
    ['period', { period: '2026-09' }],
    ['currency', { currency: 'EUR' }],
    ['atomicScale', { atomicScale: 2 }],
    ['openingPayableAtomic', { openingPayableAtomic: '1' }],
    ['priorStatementHash', { priorStatementHash: `sha256:${'0'.repeat(64)}` }],
    ['historicalReceiptHashes', { historicalReceiptHashes: [] }],
    ['firstReceiptSequence', { firstReceiptSequence: 2 }],
    ['lastReceiptSequence', { lastReceiptSequence: 2 }],
    ['lastRecognizedReceiptSequence', { lastRecognizedReceiptSequence: 2 }],
    ['receiptHashes', { receiptHashes: [`sha256:${'0'.repeat(64)}`] }],
    ['receiptMerkleRoot', { receiptMerkleRoot: `sha256:${'0'.repeat(64)}` }],
    ['reservationTotalAtomic', { reservationTotalAtomic: '1' }],
    ['releaseTotalAtomic', { releaseTotalAtomic: '1' }],
    ['chargeTotalAtomic', { chargeTotalAtomic: '1' }],
    ['earnedAwardTotalAtomic', { earnedAwardTotalAtomic: '1' }],
    ['payableAdvanceTotalAtomic', { payableAdvanceTotalAtomic: '1' }],
    ['reversalTotalAtomic', { reversalTotalAtomic: '1' }],
    ['payableReversalTotalAtomic', { payableReversalTotalAtomic: '1' }],
    ['paymentTotalAtomic', { paymentTotalAtomic: '1' }],
    ['closingPayableAtomic', { closingPayableAtomic: '1' }],
    ['statementSignerId', { statementSignerId: 'unknown-statement-key' }],
    ['advanceId', replaceAdvance({ advanceId: 'advance-002' })],
    ['advance receiptHash', replaceAdvance({ receiptHash: `sha256:${'0'.repeat(64)}` })],
    ['advance amountAtomic', replaceAdvance({ amountAtomic: '999999' })],
    ['advance advancedAt', replaceAdvance({ advancedAt: '2026-08-17T00:02:00.000Z' })],
    ['reversalId', replaceReversal({ reversalId: 'reversal-002' })],
    ['reversal receiptHash', replaceReversal({ receiptHash: `sha256:${'0'.repeat(64)}` })],
    ['reversal amountAtomic', replaceReversal({ amountAtomic: '99999' })],
    ['reversal balanceEffect', replaceReversal({ balanceEffect: 'earned_only' })],
    ['reversal reason', replaceReversal({ reason: 'other_reason' })],
    ['reversal occurredAt', replaceReversal({ occurredAt: '2026-08-17T00:02:00.000Z' })],
    ['paymentId', replacePayment({ paymentId: 'payment-002' })],
    ['payment amountAtomic', replacePayment({ amountAtomic: '249999' })],
    ['payment paidAt', replacePayment({ paidAt: '2026-08-17T00:02:00.000Z' })],
    ['payment railReference', replacePayment({ railReference: 'other-reference' })],
  ];
  for (const [label, mutation] of mutations) {
    assert.throws(
      () => verifyStatement({ ...signed, ...mutation }, options),
      /signature|recompute|trusted|period|cursor|sequence/,
      label,
    );
  }
  const attacker = generateKeyPairSync('ed25519');
  const attackerSigned = signStatement(unsigned, attacker.privateKey);
  assert.throws(() => verifyStatement(attackerSigned, options), /signature/);
  assert.throws(() => verifyStatement({ ...signed, publicKeyPem: 'self-declared' }, options), /unknown key publicKeyPem/);
});

test('sortable statement event IDs are normalized ASCII and code-unit deterministic', () => {
  const signers = signerFixture();
  const receipt = signedSuccess(signers);
  const hash = receiptHash(receipt);
  const prior = signedJulyStatement(signers, [receipt], 'id-order');
  const eventAt = '2026-08-17T00:01:00.000Z';
  const base = {
    statementId: 'statement-id-order', employerId: 'megacorp', creatorId: 'sam', period: '2026-08',
    currency: 'USD', atomicScale: 6, openingPayableAtomic: prior.closingPayableAtomic,
    receipts: [], historicalReceipts: [receipt], priorStatement: prior,
    reversals: [], payments: [], statementSignerId: 'collar-statement-key-2026-07',
  };
  const statement = buildStatement({
    ...base,
    payableAdvances: [
      { advanceId: 'b', receiptHash: hash, amountAtomic: '1', advancedAt: eventAt },
      { advanceId: 'A', receiptHash: hash, amountAtomic: '1', advancedAt: eventAt },
      { advanceId: 'a', receiptHash: hash, amountAtomic: '1', advancedAt: eventAt },
    ],
  });
  assert.deepEqual(statement.payableAdvances.map((row) => row.advanceId), ['A', 'a', 'b']);
  assert.throws(() => buildStatement({
    ...base,
    payableAdvances: [{ advanceId: 'é', receiptHash: hash, amountAtomic: '1', advancedAt: eventAt }],
  }), /normalized ASCII identifier/);
});

test('JSONL output is canonical, newline terminated, and rejects BigInt', () => {
  const rendered = renderJsonl([{ z: 1, a: { y: 2, b: 3 } }]);
  assert.equal(rendered, '{"a":{"b":3,"y":2},"z":1}\n');
  assert.throws(() => renderJsonl([{ amountAtomic: 1n }]), /BigInt|JSON-safe/);
});

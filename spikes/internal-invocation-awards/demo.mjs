import assert from 'node:assert/strict';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';

import { signBudget } from './src/budget.mjs';
import { signCredential, signPrincipalAttestation } from './src/credentials.mjs';
import {
  authorizeInternalInvocation,
  createEngineState,
  executeAuthorizedInvocation,
} from './src/engine.mjs';
import {
  buildStatement,
  receiptHash,
  signStatement,
  verifyReceipt,
  verifyStatement,
} from './src/statements.mjs';
import { policyHash, skillRegistrationKey } from './src/schema.mjs';
import { InMemoryEngineStore } from './src/store.mjs';

const NOW = '2026-07-17T00:01:00.000Z';
const POLICY_ID = 'policy-megacorp-ledger-recon';
const RECEIPT_SIGNER_ID = 'collar-receipt-key-2026-07';
const STATEMENT_SIGNER_ID = 'collar-statement-key-2026-07';

// Any accidental attempt to leave the process fails the demonstration immediately.
globalThis.fetch = async () => {
  throw new Error('network access is forbidden in the internal Invocation award spike');
};

const finance = generateKeyPairSync('ed25519');
const authorizer = generateKeyPairSync('ed25519');
const manager = generateKeyPairSync('ed25519');
const identity = generateKeyPairSync('ed25519');
const receiptSigner = generateKeyPairSync('ed25519');
const statementSigner = generateKeyPairSync('ed25519');

const policy = {
  schemaVersion: 1,
  policyId: POLICY_ID,
  version: 1,
  status: 'active',
  currency: 'USD',
  atomicScale: 6,
  employerId: 'megacorp',
  effectiveAt: '2026-07-17T00:00:00.000Z',
  expiresAt: '2026-08-01T00:00:00.000Z',
  permittedSkillIds: ['ledger-recon'],
  permittedCreatorIds: ['sam'],
  permittedWielderIds: ['megacorp-internal-agent'],
  permittedInitiatingPrincipalIds: ['jordan'],
  permittedCostCenters: ['platform-engineering'],
  maxQuoteAtomic: '4000000',
  awardRule: {
    type: 'residual_after_execution_fee_and_reserve',
    awardRateBps: 10000,
    rateBase: 'post_cost_residual',
    rounding: 'floor_atomic',
  },
  maxAwardPerInvocationAtomic: '2000000',
  maxAwardPerPeriodAtomic: '100000000',
  selfInvocation: 'manager_approval_required',
  permittedManagerSignerIds: ['manager-alex'],
  permittedCredentialAuthorizerIds: ['megacorp-collar-authorizer'],
  permittedIdentitySignerIds: ['megacorp-identity'],
  permittedFinanceSignerIds: ['megacorp-finance'],
  vestingRule: 'none',
  paymentSchedule: 'monthly_in_arrears',
  terminationTreatment: 'earned_remains_payable_unearned_cancelled',
  paymentRail: 'employer_payroll_or_ap',
};

const signedBudget = signBudget({
  schemaVersion: 1,
  budgetId: 'budget-megacorp-2026-07',
  policyId: POLICY_ID,
  policyVersion: 1,
  policyHash: policyHash(policy),
  period: '2026-07',
  currency: 'USD',
  atomicScale: 6,
  allocatedAtomic: '1000000000',
  effectiveAt: '2026-07-17T00:00:00.000Z',
  expiresAt: '2026-08-01T00:00:00.000Z',
  signerId: 'megacorp-finance',
}, finance.privateKey);

const quote = {
  schemaVersion: 1,
  quoteId: 'quote-inv-001',
  invocationId: 'inv-001',
  idempotencyKey: 'run-ledger-recon-001',
  skillId: 'ledger-recon',
  skillVersionHash: `sha256:${'1'.repeat(64)}`,
  creatorId: 'sam',
  wielderId: 'megacorp-internal-agent',
  initiatingPrincipalId: 'jordan',
  principalAttestationId: 'principal-attestation-inv-001',
  beneficiaryId: 'megacorp',
  costCenter: 'platform-engineering',
  policyId: POLICY_ID,
  policyVersion: 1,
  policyHash: policyHash(policy),
  maxExecutionCostAtomic: '1000000',
  protocolFeeAtomic: '25000',
  refundReserveAtomic: '25000',
  maxInvocationAwardAtomic: '2000000',
  maxGrossAtomic: '3050000',
  expiresAt: '2026-07-17T00:05:00.000Z',
};

const store = new InMemoryEngineStore(createEngineState({
  signedBudget,
  policies: { [`${POLICY_ID}@1`]: policy },
  skillRegistrations: {
    [skillRegistrationKey(quote.skillId, quote.skillVersionHash)]: {
      schemaVersion: 1,
      registrationId: 'registration-ledger-recon-v1',
      skillId: quote.skillId,
      skillVersionHash: quote.skillVersionHash,
      creatorId: quote.creatorId,
      employerId: 'megacorp',
      status: 'active',
      effectiveAt: '2026-07-17T00:00:00.000Z',
      expiresAt: '2026-08-01T00:00:00.000Z',
    },
  },
  financeSigners: {
    'megacorp-finance': finance.publicKey.export({ type: 'spki', format: 'pem' }),
  },
  managerSigners: {
    'manager-alex': manager.publicKey.export({ type: 'spki', format: 'pem' }),
  },
  credentialAuthorizers: {
    'megacorp-collar-authorizer': authorizer.publicKey.export({ type: 'spki', format: 'pem' }),
  },
  identitySigners: {
    'megacorp-identity': identity.publicKey.export({ type: 'spki', format: 'pem' }),
  },
  receiptSigners: {
    [RECEIPT_SIGNER_ID]: receiptSigner.publicKey.export({ type: 'spki', format: 'pem' }),
  },
  clock: () => NOW,
  receiptSigner: {
    signerId: RECEIPT_SIGNER_ID,
    sign: (bytes) => cryptoSign(null, bytes, receiptSigner.privateKey).toString('base64'),
  },
}));

const initiatingPrincipalAttestation = signPrincipalAttestation({
  schemaVersion: 1,
  attestationId: quote.principalAttestationId,
  identitySignerId: 'megacorp-identity',
  principalId: quote.initiatingPrincipalId,
  invocationId: quote.invocationId,
  idempotencyKey: quote.idempotencyKey,
  skillId: quote.skillId,
  skillVersionHash: quote.skillVersionHash,
  creatorId: quote.creatorId,
  wielderId: quote.wielderId,
  beneficiaryId: quote.beneficiaryId,
  policyId: quote.policyId,
  policyVersion: quote.policyVersion,
  policyHash: quote.policyHash,
  nonce: '2'.padStart(64, '0'),
  issuedAt: NOW,
  expiresAt: quote.expiresAt,
}, identity.privateKey);

const authorized = await authorizeInternalInvocation({
  store,
  quote,
  expectedRevision: 0,
  expectedBudgetRevision: 0,
  reservationId: 'res-inv-001',
  credentialNonce: '1'.padStart(64, '0'),
  credentialIssuedAt: NOW,
  credentialExpiresAt: '2026-07-17T00:10:00.000Z',
  credentialAuthorizerId: 'megacorp-collar-authorizer',
  principalAttestation: initiatingPrincipalAttestation,
  managerApproval: null,
});
assert.equal(authorized.reservation.state, 'reserved');
assert.equal(authorized.reservation.reservedAtomic, '3050000');

// The credential is signed only after the exact reservation-bound payload is persisted.
const credential = signCredential(authorized.credentialPayload, authorizer.privateKey);
const completed = await executeAuthorizedInvocation({
  store,
  quote,
  credential,
  executor: async () => ({
    kind: 'succeeded',
    executionCostAtomic: '700000',
    outputHash: `sha256:${'a'.repeat(64)}`,
  }),
});
assert.equal(completed.invocation.state, 'succeeded');
assert.equal(completed.budget.consumedAtomic, '2750000');
assert.equal(completed.budget.releasedAtomic, '300000');
assert.equal(completed.award.amountAtomic, '2000000');
assert.equal(completed.award.state, 'earned');
assert.doesNotThrow(() => JSON.stringify(completed));

const receiptTrust = {
  [RECEIPT_SIGNER_ID]: receiptSigner.publicKey.export({ type: 'spki', format: 'pem' }),
};
const signedReceipt = completed.receipt;
assert.equal(completed.receiptHash, receiptHash(signedReceipt));
const employerReceipt = verifyReceipt(signedReceipt, { trustedReceiptSigners: receiptTrust });
const employeeReceipt = verifyReceipt(signedReceipt, { trustedReceiptSigners: receiptTrust });
assert.deepEqual(employerReceipt, employeeReceipt);

const unsignedStatement = buildStatement({
  statementId: 'statement-megacorp-sam-2026-07',
  employerId: 'megacorp',
  creatorId: 'sam',
  period: '2026-07',
  currency: 'USD',
  atomicScale: 6,
  openingPayableAtomic: '0',
  receipts: [signedReceipt],
  payableAdvances: [],
  reversals: [],
  payments: [],
  statementSignerId: STATEMENT_SIGNER_ID,
});
assert.equal(unsignedStatement.earnedAwardTotalAtomic, '2000000');
assert.equal(unsignedStatement.closingPayableAtomic, '0');
const signedStatement = signStatement(unsignedStatement, statementSigner.privateKey);
const statementVerification = {
  signedReceipts: [signedReceipt],
  trustedReceiptSigners: receiptTrust,
  trustedStatementSigners: {
    [STATEMENT_SIGNER_ID]: statementSigner.publicKey.export({ type: 'spki', format: 'pem' }),
  },
};
const employerStatement = verifyStatement(signedStatement, statementVerification);
const employeeStatement = verifyStatement(signedStatement, statementVerification);
assert.deepEqual(employerStatement, employeeStatement);

function formatAtomic(value, scale) {
  const amount = BigInt(value);
  const denominator = 10n ** BigInt(scale);
  return `${amount / denominator}.${String(amount % denominator).padStart(scale, '0')}`;
}

console.log('INTERNAL INVOCATION AWARD SPIKE — SIMULATED ACCOUNTING, NO REAL FUNDS');
console.log(`invocation ${completed.invocation.invocationId}: ${completed.invocation.state}`);
console.log(`reserved ${formatAtomic(authorized.reservation.reservedAtomic, 6)} USD`);
console.log(`consumed ${formatAtomic(completed.budget.consumedAtomic, 6)} USD`);
console.log(`released ${formatAtomic(completed.budget.releasedAtomic, 6)} USD`);
console.log(`employee-Creator Invocation award ${formatAtomic(completed.award.amountAtomic, 6)} USD: earned, not paid`);
console.log('external Wielder required: no');
console.log('external Royalty-claim credits: 0');
console.log('platform-held balance: 0');
console.log('receipt signature: verified by employer and employee');
console.log('statement signature and economic totals: verified by employer and employee');
console.log('RESULT: accounting path demonstrated; demand, payroll, tax, employment-law, securities, and custody validation remain not-run');

# Collar Invocation Journal Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Collar the authoritative append-only source for every external Invocation, including settled failures and response-loss reconciliation, and issue tamper-evident signed receipts.

**Architecture:** Introduce an append-only JSONL event journal whose reducer owns Invocation, payment, and execution state. The x402 seller emits lifecycle hooks keyed by one client idempotency key; the Collar records the offer, signed authorization, settlement, execution outcome, and signed receipt, while the Wielder stores only the returned receipt view. Every amount is a canonical atomic-USDC string backed by `prototype/atomic-money.mjs`.

**Tech Stack:** Node.js 20+, ECMAScript modules, Hono, built-in `node:test`, `node:assert/strict`, Node `crypto` Ed25519/SHA-256, JSONL persistence; Base Sepolia/mock facilitator only, never mainnet or real funds.

---

## Prerequisite and file map

Complete `docs/superpowers/plans/2026-07-17-atomic-money-kernel.md` first.

- Create `spikes/pi-wielder/src/invocation-journal.mjs`: event schema, transition reducer, JSONL replay, indexes, reconciliation, canonical receipt signing, and verification.
- Create `spikes/pi-wielder/tests/invocation-journal.test.mjs`: transition, idempotency, persistence, receipt, and reconciliation tests.
- Create `spikes/pi-wielder/tests/journal-writer-fixture.mjs`: child-process fixture for same-host writer serialization.
- Create `spikes/pi-wielder/tests/journal-reader-fixture.mjs`: child-process fixture for cross-process frozen-offer visibility.
- Create `spikes/pi-wielder/tests/collar-failure.test.mjs`: offline settled-then-500 integration test.
- Modify `spikes/pi-wielder/src/x402-seller.mjs`: atomic amount context, required idempotency key, and lifecycle hooks.
- Modify `spikes/pi-wielder/src/collar.mjs`: authoritative journal integration and signed terminal receipts.
- Modify `spikes/pi-wielder/src/proxy.mjs`: preserve one idempotency key across challenge/retry and cache returned receipts for success and failure.
- Modify `spikes/pi-wielder/src/ledger.mjs`: render the Wielder-side store explicitly as a receipt view.
- Modify `spikes/pi-wielder/e2e.mjs`: assert Collar authority and receipt equivalence.
- Modify `spikes/pi-wielder/package.json`: add focused offline test scripts.
- Modify `.gitignore`: defensively exclude local journal locks and private-key files.

## Journal types and transition contract

The journal serializes atomic values as base-10 strings because JSON cannot encode
`bigint`. It converts them back to `bigint` only when calling `atomic-money.mjs`.

```js
// InvocationRecord (JSON-safe)
{
  schemaVersion: 1,
  invocationId: 'inv-...',
  idempotencyKey: 'caller-generated-uuid',
  mode: 'external',
  skill: { id: 'skill-id', versionHash: 'sha256:...' },
  requestHash: 'sha256:...',
  creatorId: 'creator',
  wielderId: '0x...' | null,
  beneficiaryId: '0x...' | null,
  quote: {
    quoteId: 'sha256:...', amountAtomic: '250000', currency: 'USDC',
    network: 'base-sepolia', asset: '0x...', payTo: '0x...', resource: 'http://...',
    requestHash: 'sha256:...', requirementsHash: 'sha256:...',
    expiresAt: '2026-07-17T12:00:00.000Z',
    requirements: PaymentRequirements // complete frozen JSON envelope, not a reconstruction
  } | null,
  payment: {
    state: null | 'offered' | 'signed' | 'settled' | 'rejected' | 'unresolved' | 'refunded',
    settlementReference: '0x...' | null, txHash: '0x...' | null,
    payer: '0x...' | null, reason: string | null,
    refundReference: string | null, refundAmountAtomic: string | null,
    refundAccounting: null | {
      priorAllocationState: 'pending_cogs_reconciliation',
      reversalEntries: JournalEntry[] // exact derived hold reversal + refund disbursement
    }
  },
  execution: {
    state: 'requested' | 'quoted' | 'authorized' | 'executing' | 'succeeded' | 'failed' | 'cancelled',
    executionAttemptId: string | null,
    outcomeHash: 'sha256:...' | null, failureClass: string | null, message: string | null
  },
  accounting: object | null,
  receipt: SignedInvocationReceipt | null,
  createdAt: ISODate,
  updatedAt: ISODate,
  lastSequence: number
}
```

Only these transitions are legal:

```text
requestInvocation -> offerExternalPayment -> markExternalPaymentSigned
markExternalPaymentSigned -> markExternalPaymentSettled | markExternalPaymentUnresolved | rejectExternalPayment
markExternalPaymentUnresolved -> reconcileExternalSettlement
markExternalPaymentSettled -> startExecution
startExecution -> finishExecution(succeeded | failed | cancelled)
finishExecution(failed with full-gross pending reconciliation) -> refundExternalPayment
terminal execution -> issueReceipt
```

Repeated calls carrying exactly the same idempotency key and payload are no-ops. A
different payload under an existing key fails closed.

### Task 1: Build and replay the append-only journal

**Files:**
- Create: `spikes/pi-wielder/src/invocation-journal.mjs`
- Create: `spikes/pi-wielder/tests/invocation-journal.test.mjs`
- Modify: `spikes/pi-wielder/package.json:7-13`
- Modify: `.gitignore`

- [ ] **Step 1: Add focused offline test commands**

Replace the scripts object in `spikes/pi-wielder/package.json` with:

```json
"scripts": {
  "test": "node --test tests/*.test.mjs",
  "test:journal": "node --test tests/invocation-journal.test.mjs",
  "e2e": "MOCK_FACILITATOR=1 MOCK_LLM=1 node e2e.mjs",
  "collar": "node src/collar.mjs",
  "gateway": "node src/gateway.mjs",
  "proxy": "node src/proxy.mjs"
}
```

Append these defensive local-state patterns to the repository `.gitignore`:

```gitignore
# Collar journal authority and signing material must stay outside the checkout.
*.lock
*.pem
*.key
```

The runtime still requires `COLLAR_SIGNING_KEY_FILE` to be an explicit absolute path
outside the checkout; these patterns are belt-and-braces, not the primary control.

- [ ] **Step 2: Write the failing journal contract tests**

Create `spikes/pi-wielder/tests/invocation-journal.test.mjs`:

```js
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  canonicalJson,
  createInvocationJournal,
  createReceiptSigner,
  loadOrCreateReceiptSigner,
  verifySignedReceipt,
} from '../src/invocation-journal.mjs';

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

const declaration = {
  idempotencyKey: 'idem-0001',
  mode: 'external',
  skillId: 'skill-a',
  skillVersionHash: `sha256:${'a'.repeat(64)}`,
  requestHash: `sha256:${'d'.repeat(64)}`,
  creatorId: 'creator-a',
  beneficiaryId: null,
};

const quote = {
  quoteId: `sha256:${'b'.repeat(64)}`,
  amountAtomic: '250000',
  currency: 'USDC',
  network: 'base-sepolia',
  asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
  payTo: '0x000000000000000000000000000000000000dEaD',
  resource: 'http://127.0.0.1:8404/invoke/skill-a',
  requestHash: `sha256:${'d'.repeat(64)}`,
  requirementsHash: `sha256:${'e'.repeat(64)}`,
  expiresAt: '2026-07-17T12:01:00.000Z',
  requirements: {
    scheme: 'exact', network: 'base-sepolia', maxAmountRequired: '250000',
    resource: 'http://127.0.0.1:8404/invoke/skill-a', description: 'Invoke skill-a',
    mimeType: 'application/json', payTo: '0x000000000000000000000000000000000000dEaD',
    maxTimeoutSeconds: 60, asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e',
    extra: {
      name: 'USDC', version: '2', requestHash: `sha256:${'d'.repeat(64)}`,
      quoteId: `sha256:${'b'.repeat(64)}`,
      issuedAt: '2026-07-17T12:00:00.000Z', expiresAt: '2026-07-17T12:01:00.000Z',
    },
  },
};

function settle(journal) {
  journal.requestInvocation(declaration);
  journal.offerExternalPayment('idem-0001', quote);
  journal.markExternalPaymentSigned('idem-0001', {
    settlementReference: `0x${'1'.repeat(64)}`,
    payer: '0x1000000000000000000000000000000000000000',
  });
  journal.markExternalPaymentSettled('idem-0001', {
    settlementReference: `0x${'1'.repeat(64)}`,
    txHash: `0x${'2'.repeat(64)}`,
    payer: '0x1000000000000000000000000000000000000000',
  });
}

test('a settled execution failure remains attached to its transaction', () => {
  const journal = fixture();
  settle(journal);
  journal.startExecution('idem-0001');
  journal.finishExecution('idem-0001', {
    outcome: 'failed',
    failureClass: 'UPSTREAM_500',
    message: 'provider returned HTTP 500',
    outcomeHash: null,
    accounting: null,
  });
  const bundle = journal.issueReceipt('idem-0001');
  const record = journal.getByIdempotencyKey('idem-0001');

  assert.equal(record.payment.state, 'settled');
  assert.equal(record.payment.txHash, `0x${'2'.repeat(64)}`);
  assert.equal(record.execution.state, 'failed');
  assert.equal(record.execution.failureClass, 'UPSTREAM_500');
  assert.equal(bundle.receipt.payment.txHash, record.payment.txHash);
  assert.equal(verifySignedReceipt(bundle, trustFor(journal)), true);
});

test('exact retries are no-ops and conflicting idempotency reuse fails closed', () => {
  const journal = fixture();
  const first = journal.requestInvocation(declaration);
  const repeated = journal.requestInvocation(declaration);
  assert.deepEqual(repeated, first);
  assert.equal(journal.events.length, 1);
  assert.throws(() => journal.requestInvocation({
    ...declaration,
    skillVersionHash: `sha256:${'f'.repeat(64)}`,
  }), /idempotency key already binds/);
  assert.equal(journal.events.length, 1);
});

test('an unresolved settlement reconciles once by its payment reference', () => {
  const journal = fixture();
  journal.requestInvocation(declaration);
  journal.offerExternalPayment('idem-0001', quote);
  journal.markExternalPaymentSigned('idem-0001', {
    settlementReference: `0x${'3'.repeat(64)}`,
    payer: '0x1000000000000000000000000000000000000000',
  });
  journal.markExternalPaymentUnresolved('idem-0001', { reason: 'facilitator response lost' });
  const eventCount = journal.events.length;
  journal.reconcileExternalSettlement({
    settlementReference: `0x${'3'.repeat(64)}`,
    txHash: `0x${'4'.repeat(64)}`,
    payer: '0x1000000000000000000000000000000000000000',
  });
  journal.reconcileExternalSettlement({
    settlementReference: `0x${'3'.repeat(64)}`,
    txHash: `0x${'4'.repeat(64)}`,
    payer: '0x1000000000000000000000000000000000000000',
  });
  assert.equal(journal.events.length, eventCount + 1);
  assert.equal(journal.getBySettlementReference(`0x${'3'.repeat(64)}`).payment.state, 'settled');
  assert.equal(journal.getByTxHash(`0x${'4'.repeat(64)}`).idempotencyKey, 'idem-0001');
});

test('nonce, address, and tx indexes canonicalize lowercase and reject cross-case collisions', () => {
  const journal = fixture();
  for (const key of ['idem-case-a', 'idem-case-b', 'idem-case-c']) {
    journal.requestInvocation({ ...declaration, idempotencyKey: key });
    journal.offerExternalPayment(key, quote);
  }
  const nonce = `0x${'ab'.repeat(32)}`;
  const payerMixed = `0x${'Aa'.repeat(20)}`;
  const payerCanonical = payerMixed.toLowerCase();
  journal.markExternalPaymentSigned('idem-case-a', { settlementReference: nonce.toUpperCase().replace('0X', '0x'), payer: payerMixed });
  assert.equal(journal.getByIdempotencyKey('idem-case-a').payment.settlementReference, nonce);
  assert.equal(journal.getByIdempotencyKey('idem-case-a').payment.payer, payerCanonical);
  assert.throws(() => journal.markExternalPaymentSigned('idem-case-b', {
    settlementReference: nonce,
    payer: payerCanonical,
  }), /settlement reference already binds/);

  const otherNonce = `0x${'ef'.repeat(32)}`;
  journal.markExternalPaymentSigned('idem-case-c', { settlementReference: otherNonce, payer: payerCanonical });
  const txHash = `0x${'cd'.repeat(32)}`;
  journal.markExternalPaymentSettled('idem-case-a', { settlementReference: nonce, txHash: txHash.toUpperCase().replace('0X', '0x'), payer: payerCanonical });
  assert.equal(journal.getByTxHash(txHash.toUpperCase().replace('0X', '0x')).payment.txHash, txHash);
  assert.throws(() => journal.markExternalPaymentSettled('idem-case-c', {
    settlementReference: otherNonce,
    txHash,
    payer: payerCanonical,
  }), /transaction hash already binds/);
});

test('JSONL replay reconstructs the same terminal record and signed receipt', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-journal-')));
  const filePath = path.join(dir, 'events.jsonl');
  const signingKeyPath = path.join(dir, 'collar-receipt-key.pem');
  const journal = fixture({ filePath, signer: undefined, signingKeyPath });
  settle(journal);
  journal.startExecution('idem-0001');
  journal.finishExecution('idem-0001', {
    outcome: 'succeeded',
    failureClass: null,
    message: null,
    outcomeHash: `sha256:${'c'.repeat(64)}`,
    accounting: { grossAtomic: '250000' },
  });
  const original = journal.issueReceipt('idem-0001');

  assert.throws(() => createInvocationJournal({ filePath, signingKeyPath, signer: createReceiptSigner() }),
    /persistent journal refuses an ephemeral receipt signer/);
  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.deepEqual(reopened.getByIdempotencyKey('idem-0001'), journal.getByIdempotencyKey('idem-0001'));
  assert.deepEqual(reopened.getByIdempotencyKey('idem-0001').quote.requirements, quote.requirements);
  assert.deepEqual(reopened.issueReceipt('idem-0001'), original);
  assert.equal(verifySignedReceipt(reopened.issueReceipt('idem-0001'), trustFor(reopened)), true);
  assert.equal(fs.statSync(signingKeyPath).mode & 0o777, 0o600);
});

test('recomputed event hashes cannot turn a rewritten journal into Collar authority', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-tamper-')));
  const filePath = path.join(dir, 'events.jsonl');
  const signingKeyPath = path.join(dir, 'collar-receipt-key.pem');
  const journal = fixture({ filePath, signer: undefined, signingKeyPath });
  journal.requestInvocation(declaration);
  const event = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  event.data.creatorId = 'attacker';
  const { eventHash: ignoredHash, eventSignature: preservedSignature, ...unsigned } = event;
  event.eventHash = crypto.createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
  event.eventSignature = preservedSignature;
  fs.writeFileSync(filePath, `${JSON.stringify(event)}\n`);
  assert.throws(
    () => createInvocationJournal({ filePath, signingKeyPath }),
    /event signature mismatch/,
  );
});

test('persistent authority rejects checkout, symlink, non-file, noncanonical, and broad-permission paths', () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-paths-')));
  const filePath = path.join(dir, 'events.jsonl');
  const signingKeyPath = path.join(dir, 'receipt-key.pem');
  const journal = createInvocationJournal({ filePath, signingKeyPath });
  journal.requestInvocation(declaration);
  assert.equal(fs.statSync(filePath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(signingKeyPath).mode & 0o777, 0o600);

  fs.chmodSync(filePath, 0o644);
  assert.throws(() => createInvocationJournal({ filePath, signingKeyPath }), /exactly 0600/);
  fs.chmodSync(filePath, 0o600);
  const keyLink = path.join(dir, 'key-link.pem');
  fs.symlinkSync(signingKeyPath, keyLink);
  assert.throws(() => createInvocationJournal({ filePath: path.join(dir, 'other.jsonl'), signingKeyPath: keyLink }), /non-symlink/);
  const directoryLink = path.join(os.tmpdir(), `collar-dir-link-${crypto.randomUUID()}`);
  fs.symlinkSync(dir, directoryLink);
  assert.throws(() => createInvocationJournal({
    filePath: path.join(directoryLink, 'through-link.jsonl'),
    signingKeyPath,
  }), /symlinked directory/);
  fs.unlinkSync(directoryLink);
  const directoryTarget = path.join(dir, 'not-a-file');
  fs.mkdirSync(directoryTarget);
  assert.throws(() => createInvocationJournal({ filePath: directoryTarget, signingKeyPath }), /regular non-symlink file/);
  assert.throws(() => createInvocationJournal({ filePath: 'relative.jsonl', signingKeyPath }), /explicit absolute/);
  assert.throws(() => createInvocationJournal({
    filePath: path.resolve('spikes/pi-wielder/unsafe-journal.jsonl'), signingKeyPath,
  }), /outside the repository checkout/);
});

test('tampering invalidates a signed receipt', () => {
  const journal = fixture();
  settle(journal);
  journal.startExecution('idem-0001');
  journal.finishExecution('idem-0001', {
    outcome: 'failed', failureClass: 'FAULT', message: 'fault', outcomeHash: null, accounting: null,
  });
  const bundle = journal.issueReceipt('idem-0001');
  const tampered = structuredClone(bundle);
  tampered.receipt.payment.txHash = `0x${'9'.repeat(64)}`;
  assert.equal(verifySignedReceipt(tampered, trustFor(journal)), false);

  const attacker = fixture({ createId: () => 'inv-attacker' });
  settle(attacker);
  attacker.startExecution('idem-0001');
  attacker.finishExecution('idem-0001', {
    outcome: 'failed', failureClass: 'FAULT', message: 'fault', outcomeHash: null, accounting: null,
  });
  assert.equal(verifySignedReceipt(attacker.issueReceipt('idem-0001'), trustFor(journal)), false);
});

test('refund v1 reverses only a terminal failed full-gross reconciliation hold', () => {
  const journal = fixture();
  settle(journal);
  const request = {
    reason: 'settled execution failure',
    refundReference: `refund:${'5'.repeat(64)}`,
    refundAmountAtomic: '250000',
  };
  assert.throws(() => journal.refundExternalPayment('idem-0001', request), /terminal failed/);
  journal.startExecution('idem-0001');
  assert.throws(() => journal.refundExternalPayment('idem-0001', request), /terminal failed/);
  const pending = {
    grossAtomic: '250000',
    allocationState: 'pending_cogs_reconciliation',
    holderCredits: [], ancestorCredits: [],
    journalEntries: [{
      category: 'unresolved-execution-accounting',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'hold:execution-accounting-reconciliation',
      amountAtomic: '250000',
    }],
  };
  journal.finishExecution('idem-0001', {
    outcome: 'failed', failureClass: 'COGS_UNKNOWN', message: 'fault', outcomeHash: null, accounting: pending,
  });
  const original = journal.issueReceipt('idem-0001');
  assert.throws(() => journal.refundExternalPayment('idem-0001', { ...request, refundAmountAtomic: '249999' }), /full settled gross/);
  journal.refundExternalPayment('idem-0001', request);
  const revised = journal.issueReceipt('idem-0001');
  assert.equal(revised.receipt.revision, 2);
  assert.equal(revised.receipt.supersedesReceiptHash, original.receiptHash);
  assert.equal(revised.receipt.payment.state, 'refunded');
  assert.equal(revised.receipt.payment.refundAmountAtomic, '250000');
  assert.deepEqual(revised.receipt.payment.refundAccounting, {
    priorAllocationState: 'pending_cogs_reconciliation',
    reversalEntries: [{
      category: 'refund-reverse-reconciliation-hold',
      debitAccountId: 'hold:execution-accounting-reconciliation',
      creditAccountId: 'wielder:external-gross',
      amountAtomic: '250000',
    }, {
      category: 'refund-disbursement',
      debitAccountId: 'wielder:external-gross',
      creditAccountId: 'refund:0x1000000000000000000000000000000000000000',
      amountAtomic: '250000',
    }],
  });
  const allEntries = [...pending.journalEntries, ...revised.receipt.payment.refundAccounting.reversalEntries];
  const balances = new Map();
  for (const entry of allEntries) {
    balances.set(entry.debitAccountId, (balances.get(entry.debitAccountId) ?? 0n) - BigInt(entry.amountAtomic));
    balances.set(entry.creditAccountId, (balances.get(entry.creditAccountId) ?? 0n) + BigInt(entry.amountAtomic));
  }
  assert.equal([...balances.values()].reduce((sum, value) => sum + value, 0n), 0n);
  assert.equal(balances.get('hold:execution-accounting-reconciliation'), 0n);
  assert.equal(balances.get('refund:0x1000000000000000000000000000000000000000'), 250000n);
  assert.deepEqual(journal.refundExternalPayment('idem-0001', request).payment.refundAccounting,
    revised.receipt.payment.refundAccounting);
  assert.equal(verifySignedReceipt(original, trustFor(journal)), true);
  assert.equal(verifySignedReceipt(revised, trustFor(journal)), true);
  assert.equal(journal.events.filter((event) => event.type === 'receipt.issued').length, 2);
});

test('refund v1 rejects successful/finalized credits instead of leaving claims and returning gross', () => {
  const journal = fixture();
  settle(journal);
  journal.startExecution('idem-0001');
  journal.finishExecution('idem-0001', {
    outcome: 'succeeded', failureClass: null, message: null, outcomeHash: `sha256:${'9'.repeat(64)}`,
    accounting: {
      grossAtomic: '250000', allocationState: 'finalized',
      holderCredits: [{ recipientId: 'creator', amountAtomic: '250000' }],
      ancestorCredits: [], journalEntries: [],
    },
  });
  assert.throws(() => journal.refundExternalPayment('idem-0001', {
    reason: 'not legal', refundReference: `refund:${'8'.repeat(64)}`, refundAmountAtomic: '250000',
  }), /terminal failed full-gross reconciliation/);
});

const waitForExit = (child) => new Promise((resolve, reject) => {
  let stderr = '';
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.once('error', reject);
  child.once('exit', (code, signal) => code === 0
    ? resolve()
    : reject(new Error(`writer exited ${code ?? signal}: ${stderr}`)));
});

async function waitForFiles(paths) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (paths.every((candidate) => fs.existsSync(candidate))) return;
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  throw new Error(`writers did not become ready: ${paths.join(', ')}`);
}

test('two same-host processes serialize durable hash-chained writes without losing either Invocation', async () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-writers-')));
  const filePath = path.join(dir, 'events.jsonl');
  const signingKeyPath = path.join(dir, 'collar-receipt-key.pem');
  const barrierPath = path.join(dir, 'start');
  loadOrCreateReceiptSigner(signingKeyPath);
  const worker = path.resolve('spikes/pi-wielder/tests/journal-writer-fixture.mjs');
  const children = ['idem-process-a', 'idem-process-b'].map((key) => spawn(
    process.execPath,
    [worker, filePath, signingKeyPath, barrierPath, key, path.join(dir, `${key}.ready`)],
    { stdio: ['ignore', 'ignore', 'pipe'] },
  ));
  await waitForFiles(['idem-process-a', 'idem-process-b'].map((key) => path.join(dir, `${key}.ready`)));
  fs.writeFileSync(barrierPath, 'go', { flag: 'wx' });
  await Promise.all(children.map(waitForExit));

  const reopened = createInvocationJournal({ filePath, signingKeyPath });
  assert.ok(reopened.getByIdempotencyKey('idem-process-a'));
  assert.ok(reopened.getByIdempotencyKey('idem-process-b'));
  assert.deepEqual(reopened.events.map(({ sequence }) => sequence), [1, 2]);
  assert.equal(reopened.events[0].previousHash, null);
  assert.equal(reopened.events[1].previousHash, reopened.events[0].eventHash);
});

test('a second process sees the complete frozen offer written by the first process', async () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'collar-reader-')));
  const filePath = path.join(dir, 'events.jsonl');
  const signingKeyPath = path.join(dir, 'collar-receipt-key.pem');
  const outputPath = path.join(dir, 'quote.json');
  const writer = createInvocationJournal({ filePath, signingKeyPath });
  writer.requestInvocation(declaration);
  writer.offerExternalPayment(declaration.idempotencyKey, quote);
  const child = spawn(process.execPath, [
    path.resolve('spikes/pi-wielder/tests/journal-reader-fixture.mjs'),
    filePath, signingKeyPath, declaration.idempotencyKey, outputPath,
  ], { stdio: ['ignore', 'ignore', 'pipe'] });
  await waitForExit(child);
  assert.deepEqual(JSON.parse(fs.readFileSync(outputPath, 'utf8')), quote.requirements);
});
```

Create `spikes/pi-wielder/tests/journal-writer-fixture.mjs`:

```js
import fs from 'node:fs';

import { createInvocationJournal } from '../src/invocation-journal.mjs';

const [filePath, signingKeyPath, barrierPath, idempotencyKey, readyPath] = process.argv.slice(2);
const journal = createInvocationJournal({ filePath, signingKeyPath });
fs.writeFileSync(readyPath, 'ready', { flag: 'wx' });
while (!fs.existsSync(barrierPath)) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 5);
const digit = idempotencyKey.endsWith('-a') ? '1' : '2';
journal.requestInvocation({
  idempotencyKey,
  mode: 'external',
  skillId: 'skill-a',
  skillVersionHash: `sha256:${'a'.repeat(64)}`,
  requestHash: `sha256:${digit.repeat(64)}`,
  creatorId: 'creator-a',
  beneficiaryId: null,
});
```

Create `spikes/pi-wielder/tests/journal-reader-fixture.mjs`:

```js
import fs from 'node:fs';

import { createInvocationJournal } from '../src/invocation-journal.mjs';

const [filePath, signingKeyPath, idempotencyKey, outputPath] = process.argv.slice(2);
const journal = createInvocationJournal({ filePath, signingKeyPath });
const requirements = journal.getByIdempotencyKey(idempotencyKey)?.quote?.requirements;
if (!requirements) throw new Error('persisted frozen offer is not visible');
fs.writeFileSync(outputPath, JSON.stringify(requirements), { flag: 'wx' });
```

- [ ] **Step 3: Run the focused test and verify the journal is missing**

Run: `npm run test:journal --prefix spikes/pi-wielder`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/invocation-journal.mjs`.

- [ ] **Step 4: Implement the append-only journal and signer**

Create `spikes/pi-wielder/src/invocation-journal.mjs`:

```js
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TERMINAL_EXECUTION = new Set(['succeeded', 'failed', 'cancelled']);
const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]));
  }
  return value;
}

export const canonicalJson = (value) => JSON.stringify(canonicalize(value));
const same = (left, right) => canonicalJson(left) === canonicalJson(right);
const copy = (value) => structuredClone(value);

function requireText(value, label) {
  const text = String(value ?? '').trim();
  if (!text) throw new Error(`${label} must be non-empty`);
  return text;
}

function requireAtomicString(value, label) {
  const text = requireText(value, label);
  if (!/^(0|[1-9]\d*)$/.test(text)) throw new Error(`${label} must be a canonical non-negative atomic string`);
  return text;
}

function canonicalHex(value, bytes, label) {
  const text = requireText(value, label);
  if (!new RegExp(`^0x[0-9a-fA-F]{${bytes * 2}}$`).test(text)) {
    throw new Error(`${label} must be a ${bytes}-byte hex identifier`);
  }
  return text.toLowerCase();
}

const canonicalAddress = (value, label) => canonicalHex(value, 20, label);
const canonicalBytes32 = (value, label) => canonicalHex(value, 32, label);

function safePersistentPath(input, label, { allowMissing = true } = {}) {
  if (!path.isAbsolute(input ?? '')) throw new Error(`${label} must be an explicit absolute path`);
  const lexical = path.resolve(input);
  const lexicalParent = path.dirname(lexical);
  const realParent = fs.realpathSync(lexicalParent);
  if (realParent !== lexicalParent) throw new Error(`${label} must not traverse a symlinked directory`);
  const candidate = path.join(realParent, path.basename(lexical));
  const relative = path.relative(CHECKOUT_ROOT, candidate);
  if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
    throw new Error(`${label} must be outside the repository checkout`);
  }
  if (fs.existsSync(candidate)) {
    const stat = fs.lstatSync(candidate);
    if (stat.isSymbolicLink() || !stat.isFile()) throw new Error(`${label} must be a regular non-symlink file`);
    if ((stat.mode & 0o777) !== 0o600) throw new Error(`${label} permissions must be exactly 0600`);
    if (fs.realpathSync(candidate) !== candidate) throw new Error(`${label} must be canonical`);
  } else if (!allowMissing) {
    throw new Error(`${label} does not exist`);
  }
  return candidate;
}

function requireRecord(records, key) {
  const record = records.get(key);
  if (!record) throw new Error(`unknown idempotency key '${key}'`);
  return record;
}

function assertState(record, allowed, action) {
  if (!allowed.includes(record.execution.state)) {
    throw new Error(`${action} cannot run from execution state '${record.execution.state}'`);
  }
}

export function createReceiptSigner(keys = {}, { persistent = false } = {}) {
  const pair = keys.privateKey && keys.publicKey
    ? { privateKey: keys.privateKey, publicKey: keys.publicKey }
    : crypto.generateKeyPairSync('ed25519');
  const publicKeyPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keyId = `sha256:${crypto.createHash('sha256')
    .update(pair.publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex')}`;
  return Object.freeze({
    algorithm: 'Ed25519',
    publicKeyPem,
    keyId,
    persistent,
    signHash(hashHex) {
      return crypto.sign(null, Buffer.from(hashHex, 'hex'), pair.privateKey).toString('base64');
    },
  });
}

const lockWait = new Int32Array(new SharedArrayBuffer(4));

function withFileLock(lockPath, operation, timeoutMs = 5_000) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  const deadline = Date.now() + timeoutMs;
  let descriptor;
  while (descriptor == null) {
    try {
      descriptor = fs.openSync(lockPath, 'wx', 0o600);
      fs.writeFileSync(descriptor, canonicalJson({ pid: process.pid, acquiredAt: new Date().toISOString() }));
      fs.fsyncSync(descriptor);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
      try {
        const owner = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
        process.kill(owner.pid, 0);
      } catch (ownerError) {
        if (ownerError.code === 'ESRCH') {
          fs.unlinkSync(lockPath);
          continue;
        }
      }
      if (Date.now() >= deadline) throw new Error(`timed out acquiring journal lock '${lockPath}'`);
      Atomics.wait(lockWait, 0, 0, 10);
    }
  }
  try {
    return operation();
  } finally {
    fs.closeSync(descriptor);
    fs.unlinkSync(lockPath);
  }
}

function fsyncDirectory(directory) {
  const descriptor = fs.openSync(directory, 'r');
  try { fs.fsyncSync(descriptor); } finally { fs.closeSync(descriptor); }
}

export function loadOrCreateReceiptSigner(keyPath, { lockPath = `${keyPath}.lock` } = {}) {
  const canonicalKeyPath = safePersistentPath(keyPath, 'persistent receipt key');
  const canonicalLockPath = `${canonicalKeyPath}.lock`;
  if (lockPath !== canonicalLockPath) throw new Error('receipt-key lock must be derived from the canonical key path');
  return withFileLock(canonicalLockPath, () => {
    let privateKey;
    if (fs.existsSync(canonicalKeyPath)) {
      privateKey = crypto.createPrivateKey(fs.readFileSync(canonicalKeyPath, 'utf8'));
    } else {
      fs.mkdirSync(path.dirname(keyPath), { recursive: true });
      const pair = crypto.generateKeyPairSync('ed25519');
      privateKey = pair.privateKey;
      const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
      const temporary = `${canonicalKeyPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
      const descriptor = fs.openSync(temporary, 'wx', 0o600);
      try {
        fs.writeFileSync(descriptor, pem);
        fs.fsyncSync(descriptor);
      } finally {
        fs.closeSync(descriptor);
      }
      fs.renameSync(temporary, canonicalKeyPath);
      fsyncDirectory(path.dirname(canonicalKeyPath));
    }
    return createReceiptSigner(
      { privateKey, publicKey: crypto.createPublicKey(privateKey) },
      { persistent: true },
    );
  });
}

export function verifySignedReceipt(bundle, { publicKeyPem, keyId }) {
  try {
    if (bundle.algorithm !== 'Ed25519') return false;
    if (bundle.keyId !== keyId) return false;
    const expectedHash = crypto.createHash('sha256').update(canonicalJson(bundle.receipt)).digest('hex');
    if (expectedHash !== bundle.receiptHash) return false;
    return crypto.verify(
      null,
      Buffer.from(expectedHash, 'hex'),
      crypto.createPublicKey(publicKeyPem),
      Buffer.from(bundle.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (!same(actual, wanted)) throw new Error(`${label} has unexpected fields`);
}

const EVENT_DATA_KEYS = Object.freeze({
  'invocation.requested': ['invocationId', 'mode', 'skill', 'requestHash', 'creatorId', 'beneficiaryId'],
  'payment.offered': ['quote'],
  'payment.signed': ['settlementReference', 'payer'],
  'payment.settled': ['settlementReference', 'txHash', 'payer'],
  'payment.unresolved': ['reason'],
  'payment.rejected': ['reason'],
  'payment.refunded': ['reason', 'refundReference', 'refundAmountAtomic', 'reversalEntries'],
  'execution.started': ['executionAttemptId'],
  'execution.finished': ['executionAttemptId', 'outcome', 'outcomeHash', 'failureClass', 'message', 'accounting'],
  'receipt.issued': ['bundle'],
});

function deriveFullGrossRefundReversal(record) {
  if (record.payment.state !== 'settled' || record.execution.state !== 'failed'
    || record.accounting?.allocationState !== 'pending_cogs_reconciliation') {
    throw new Error('refund v1 requires a settled terminal failed full-gross reconciliation');
  }
  if ((record.accounting.holderCredits?.length ?? 0) !== 0
    || (record.accounting.ancestorCredits?.length ?? 0) !== 0) {
    throw new Error('refund v1 refuses accounting with finalized Royalty claims');
  }
  const [hold, ...extra] = record.accounting.journalEntries ?? [];
  if (extra.length || !hold
    || hold.category !== 'unresolved-execution-accounting'
    || hold.debitAccountId !== 'wielder:external-gross'
    || hold.creditAccountId !== 'hold:execution-accounting-reconciliation'
    || hold.amountAtomic !== record.quote.amountAtomic
    || record.accounting.grossAtomic !== record.quote.amountAtomic) {
    throw new Error('refund v1 requires one exact full-gross reconciliation hold');
  }
  return [{
    category: 'refund-reverse-reconciliation-hold',
    debitAccountId: hold.creditAccountId,
    creditAccountId: hold.debitAccountId,
    amountAtomic: hold.amountAtomic,
  }, {
    category: 'refund-disbursement',
    debitAccountId: 'wielder:external-gross',
    creditAccountId: `refund:${record.payment.payer}`,
    amountAtomic: record.quote.amountAtomic,
  }];
}

function receiptPayload(record) {
  return {
    schemaVersion: 1,
    revision: record.receiptHistory.length + 1,
    supersedesReceiptHash: record.receiptHistory.at(-1)?.receiptHash ?? null,
    sequence: record.lastSequence,
    invocationId: record.invocationId,
    idempotencyKey: record.idempotencyKey,
    mode: record.mode,
    skill: record.skill,
    requestHash: record.requestHash,
    creatorId: record.creatorId,
    wielderId: record.wielderId,
    beneficiaryId: record.beneficiaryId,
    quote: record.quote,
    payment: record.payment,
    execution: record.execution,
    accounting: record.accounting,
    createdAt: record.createdAt,
    completedAt: record.updatedAt,
  };
}

export function createInvocationJournal({
  filePath = null,
  signingKeyPath = null,
  now = () => new Date().toISOString(),
  createId = () => `inv-${crypto.randomUUID()}`,
  signer = null,
} = {}) {
  const journalPath = filePath ? safePersistentPath(filePath, 'persistent journal') : null;
  const lockPath = journalPath ? `${journalPath}.lock` : null;
  const canonicalSigningKeyPath = journalPath
    ? safePersistentPath(signingKeyPath, 'persistent receipt key')
    : null;
  if (journalPath && journalPath === canonicalSigningKeyPath) throw new Error('journal and signing key paths must differ');
  if (journalPath && signer && signer.persistent !== true) {
    throw new Error('persistent journal refuses an ephemeral receipt signer');
  }
  const diskSigner = journalPath
    ? loadOrCreateReceiptSigner(canonicalSigningKeyPath)
    : null;
  if (signer && diskSigner && signer.keyId !== diskSigner.keyId) {
    throw new Error('injected receipt signer does not match persistent signingKeyPath');
  }
  const receiptSigner = signer ?? diskSigner ?? createReceiptSigner();
  const records = new Map();
  const settlementReferences = new Map();
  const transactionHashes = new Map();
  const eventLog = [];
  let nextSequence = 1;
  let headHash = null;

  function validateQuote(quote) {
    exactKeys(quote, [
      'quoteId', 'amountAtomic', 'currency', 'network', 'asset', 'payTo', 'resource',
      'requestHash', 'requirementsHash', 'expiresAt', 'requirements',
    ], 'payment quote');
    requireText(quote.quoteId, 'quoteId');
    requireAtomicString(quote.amountAtomic, 'amountAtomic');
    if (quote.currency !== 'USDC') throw new Error("currency must be 'USDC'");
    for (const field of ['network', 'resource', 'requestHash', 'requirementsHash', 'expiresAt']) {
      requireText(quote[field], field);
    }
    if (canonicalAddress(quote.asset, 'asset') !== quote.asset
      || canonicalAddress(quote.payTo, 'payTo') !== quote.payTo) {
      throw new Error('indexed quote addresses must use canonical lowercase hex');
    }
    exactKeys(quote.requirements, [
      'scheme', 'network', 'maxAmountRequired', 'resource', 'description', 'mimeType',
      'payTo', 'maxTimeoutSeconds', 'asset', 'extra',
    ], 'frozen PaymentRequirements');
    exactKeys(quote.requirements.extra, ['name', 'version', 'requestHash', 'quoteId', 'issuedAt', 'expiresAt'], 'PaymentRequirements.extra');
    if (quote.requirements.maxAmountRequired !== quote.amountAtomic
      || quote.requirements.network !== quote.network
      || canonicalAddress(quote.requirements.asset, 'requirements.asset') !== quote.asset
      || canonicalAddress(quote.requirements.payTo, 'requirements.payTo') !== quote.payTo
      || quote.requirements.resource !== quote.resource
      || quote.requirements.extra.requestHash !== quote.requestHash
      || quote.requirements.extra.quoteId !== quote.quoteId
      || quote.requirements.extra.expiresAt !== quote.expiresAt) {
      throw new Error('frozen x402 requirements do not match indexed quote fields');
    }
  }

  function validateEventForApply(event) {
    exactKeys(event, [
      'schemaVersion', 'eventId', 'sequence', 'previousHash', 'type', 'idempotencyKey',
      'at', 'data', 'keyId', 'eventHash', 'eventSignature',
    ], 'journal event');
    if (event.schemaVersion !== 1 || event.eventId !== `event-${String(event.sequence).padStart(8, '0')}`) {
      throw new Error('journal event schema or identifier is invalid');
    }
    if (!Number.isSafeInteger(event.sequence) || event.sequence < 1 || !Number.isFinite(Date.parse(event.at))) {
      throw new Error('journal event sequence or timestamp is invalid');
    }
    requireText(event.idempotencyKey, 'event.idempotencyKey');
    const dataKeys = EVENT_DATA_KEYS[event.type];
    if (!dataKeys) throw new Error(`unknown journal event '${event.type}'`);
    exactKeys(event.data, dataKeys, `${event.type}.data`);
    const record = records.get(event.idempotencyKey);
    switch (event.type) {
      case 'invocation.requested':
        if (record) throw new Error(`duplicate request event for '${event.idempotencyKey}'`);
        requireText(event.data.invocationId, 'invocationId');
        if (event.data.mode !== 'external') throw new Error("journal plan supports mode 'external' only");
        exactKeys(event.data.skill, ['id', 'versionHash'], 'skill');
        requireText(event.data.skill.id, 'skill.id');
        requireText(event.data.skill.versionHash, 'skill.versionHash');
        requireText(event.data.requestHash, 'requestHash');
        requireText(event.data.creatorId, 'creatorId');
        if (event.data.beneficiaryId != null) requireText(event.data.beneficiaryId, 'beneficiaryId');
        break;
      case 'payment.offered':
        if (!record || record.execution.state !== 'requested' || record.payment.state !== null || record.quote !== null) {
          throw new Error('payment.offered requires one unquoted requested Invocation');
        }
        validateQuote(event.data.quote);
        break;
      case 'payment.signed':
        if (!record || record.payment.state !== 'offered') throw new Error('payment.signed requires offered payment');
        if (canonicalBytes32(event.data.settlementReference, 'settlementReference') !== event.data.settlementReference
          || canonicalAddress(event.data.payer, 'payer') !== event.data.payer) {
          throw new Error('signed payment identifiers must use canonical lowercase hex');
        }
        assertUnique(settlementReferences, event.data.settlementReference, event.idempotencyKey, 'settlement reference');
        break;
      case 'payment.settled':
        if (!record || !['signed', 'unresolved'].includes(record.payment.state)) throw new Error('payment.settled requires signed or unresolved payment');
        if (record.payment.settlementReference !== event.data.settlementReference || record.payment.payer !== event.data.payer) {
          throw new Error('settlement does not match signed payment');
        }
        if (canonicalBytes32(event.data.txHash, 'txHash') !== event.data.txHash
          || canonicalBytes32(event.data.settlementReference, 'settlementReference') !== event.data.settlementReference
          || canonicalAddress(event.data.payer, 'payer') !== event.data.payer) {
          throw new Error('settlement identifiers must use canonical lowercase hex');
        }
        assertUnique(transactionHashes, event.data.txHash, event.idempotencyKey, 'transaction hash');
        break;
      case 'payment.unresolved':
        if (!record || record.payment.state !== 'signed') throw new Error('payment.unresolved requires signed payment');
        requireText(event.data.reason, 'reason');
        break;
      case 'payment.rejected':
        if (!record || !['offered', 'signed', 'unresolved'].includes(record.payment.state)) throw new Error('payment.rejected has invalid predecessor');
        requireText(event.data.reason, 'reason');
        break;
      case 'payment.refunded':
        if (!record) throw new Error('payment.refunded requires an Invocation');
        requireText(event.data.reason, 'reason');
        requireText(event.data.refundReference, 'refundReference');
        requireAtomicString(event.data.refundAmountAtomic, 'refundAmountAtomic');
        if (event.data.refundAmountAtomic !== record.quote.amountAtomic) {
          throw new Error('refund v1 must return the full settled gross');
        }
        if (!same(event.data.reversalEntries, deriveFullGrossRefundReversal(record))) {
          throw new Error('refund reversal entries do not exactly reverse the pending hold');
        }
        break;
      case 'execution.started':
        if (!record || record.payment.state !== 'settled' || record.execution.state !== 'authorized') throw new Error('execution.started requires authorized settled payment');
        requireText(event.data.executionAttemptId, 'executionAttemptId');
        break;
      case 'execution.finished':
        if (!record || record.execution.state !== 'executing') throw new Error('execution.finished requires executing state');
        if (event.data.executionAttemptId !== record.execution.executionAttemptId) throw new Error('execution attempt does not match atomic claim');
        if (!TERMINAL_EXECUTION.has(event.data.outcome)) throw new Error('execution outcome is not terminal');
        break;
      case 'receipt.issued': {
        if (!record || !TERMINAL_EXECUTION.has(record.execution.state) || record.receipt) throw new Error('receipt.issued requires one unreceipted terminal Invocation');
        if (!same(event.data.bundle.receipt, receiptPayload(record))) throw new Error('receipt does not byte-bind the immediately derived Invocation record');
        if (!verifySignedReceipt(event.data.bundle, { publicKeyPem: receiptSigner.publicKeyPem, keyId: receiptSigner.keyId })) {
          throw new Error('receipt signature does not match the pinned Collar key');
        }
        break;
      }
      default:
        throw new Error(`unknown journal event '${event.type}'`);
    }
  }

  function apply(event) {
    validateEventForApply(event);
    let record = records.get(event.idempotencyKey);
    switch (event.type) {
      case 'invocation.requested':
        if (record) throw new Error(`duplicate request event for '${event.idempotencyKey}'`);
        record = {
          schemaVersion: 1,
          invocationId: event.data.invocationId,
          idempotencyKey: event.idempotencyKey,
          mode: event.data.mode,
          skill: event.data.skill,
          requestHash: event.data.requestHash,
          creatorId: event.data.creatorId,
          wielderId: null,
          beneficiaryId: event.data.beneficiaryId,
          quote: null,
          payment: {
            state: null,
            settlementReference: null,
            txHash: null,
            payer: null,
            reason: null,
            refundReference: null,
            refundAmountAtomic: null,
            refundAccounting: null,
          },
          execution: {
            state: 'requested', executionAttemptId: null,
            outcomeHash: null, failureClass: null, message: null,
          },
          accounting: null,
          receipt: null,
          receiptHistory: [],
          createdAt: event.at,
          updatedAt: event.at,
          lastSequence: event.sequence,
        };
        records.set(event.idempotencyKey, record);
        break;
      case 'payment.offered':
        record.quote = event.data.quote;
        record.payment.state = 'offered';
        record.execution.state = 'quoted';
        break;
      case 'payment.signed':
        record.payment = {
          ...record.payment,
          state: 'signed',
          settlementReference: event.data.settlementReference,
          payer: event.data.payer,
          reason: null,
        };
        record.wielderId = event.data.payer;
        record.beneficiaryId ??= event.data.payer;
        settlementReferences.set(event.data.settlementReference, event.idempotencyKey);
        break;
      case 'payment.settled':
        record.payment = {
          ...record.payment,
          state: 'settled',
          settlementReference: event.data.settlementReference,
          txHash: event.data.txHash,
          payer: event.data.payer,
          reason: null,
        };
        record.wielderId = event.data.payer;
        record.beneficiaryId ??= event.data.payer;
        record.execution.state = 'authorized';
        settlementReferences.set(event.data.settlementReference, event.idempotencyKey);
        transactionHashes.set(event.data.txHash, event.idempotencyKey);
        break;
      case 'payment.unresolved':
        record.payment.state = 'unresolved';
        record.payment.reason = event.data.reason;
        break;
      case 'payment.rejected':
        record.payment.state = 'rejected';
        record.payment.reason = event.data.reason;
        record.execution.state = 'cancelled';
        break;
      case 'payment.refunded':
        record.payment.state = 'refunded';
        record.payment.reason = event.data.reason;
        record.payment.refundReference = event.data.refundReference;
        record.payment.refundAmountAtomic = event.data.refundAmountAtomic;
        record.payment.refundAccounting = {
          priorAllocationState: 'pending_cogs_reconciliation',
          reversalEntries: event.data.reversalEntries,
        };
        record.receipt = null;
        break;
      case 'execution.started':
        record.execution.state = 'executing';
        record.execution.executionAttemptId = event.data.executionAttemptId;
        break;
      case 'execution.finished':
        record.execution = {
          state: event.data.outcome,
          executionAttemptId: event.data.executionAttemptId,
          outcomeHash: event.data.outcomeHash,
          failureClass: event.data.failureClass,
          message: event.data.message,
        };
        record.accounting = event.data.accounting;
        break;
      case 'receipt.issued':
        record.receipt = event.data.bundle;
        record.receiptHistory.push(event.data.bundle);
        break;
      default:
        throw new Error(`unknown journal event '${event.type}'`);
    }
    record.updatedAt = event.at;
    record.lastSequence = event.sequence;
  }

  const calculateEventHash = (eventWithoutHash) => crypto.createHash('sha256')
    .update(canonicalJson(eventWithoutHash)).digest('hex');

  function readVerifiedDiskEvents() {
    if (!journalPath || !fs.existsSync(journalPath)) return [];
    const text = fs.readFileSync(journalPath, 'utf8');
    if (!text) return [];
    if (!text.endsWith('\n')) throw new Error('journal has a torn or unterminated final event');
    const lines = text.slice(0, -1).split('\n');
    let previousHash = null;
    return lines.map((line, index) => {
      if (!line) throw new Error(`journal contains a blank event at sequence ${index + 1}`);
      const event = JSON.parse(line);
      if (event.sequence !== index + 1) throw new Error(`journal sequence gap at ${index + 1}`);
      if (event.previousHash !== previousHash) throw new Error(`journal hash-chain predecessor mismatch at ${index + 1}`);
      const { eventHash, eventSignature, ...unsigned } = event;
      const expectedHash = calculateEventHash(unsigned);
      if (eventHash !== expectedHash) throw new Error(`journal event hash mismatch at ${index + 1}`);
      if (event.keyId !== receiptSigner.keyId || !crypto.verify(
        null,
        Buffer.from(eventHash, 'hex'),
        crypto.createPublicKey(receiptSigner.publicKeyPem),
        Buffer.from(eventSignature, 'base64'),
      )) throw new Error(`journal event signature mismatch at ${index + 1}`);
      previousHash = eventHash;
      return event;
    });
  }

  function syncFromDisk() {
    const diskEvents = readVerifiedDiskEvents();
    for (let index = 0; index < eventLog.length; index += 1) {
      if (!same(eventLog[index], diskEvents[index])) throw new Error(`journal history changed at sequence ${index + 1}`);
    }
    for (const event of diskEvents.slice(eventLog.length)) {
      apply(event);
      eventLog.push(event);
    }
    nextSequence = diskEvents.length + 1;
    headHash = diskEvents.at(-1)?.eventHash ?? null;
  }

  function refreshFromAuthority() {
    if (journalPath) withFileLock(lockPath, syncFromDisk);
  }

  function append(type, idempotencyKey, data) {
    const expectedRecordSequence = records.get(idempotencyKey)?.lastSequence ?? 0;
    const write = () => {
      if (journalPath) syncFromDisk();
      const currentRecordSequence = records.get(idempotencyKey)?.lastSequence ?? 0;
      if (currentRecordSequence !== expectedRecordSequence) {
        const error = new Error(`journal compare-and-swap conflict for '${idempotencyKey}'`);
        error.name = 'JournalConflictError';
        error.code = 'JOURNAL_CONFLICT';
        throw error;
      }
      const unsigned = {
        schemaVersion: 1,
        eventId: `event-${String(nextSequence).padStart(8, '0')}`,
        sequence: nextSequence,
        previousHash: headHash,
        type,
        idempotencyKey,
        at: now(),
        data,
        keyId: receiptSigner.keyId,
      };
      const eventHash = calculateEventHash(unsigned);
      const event = {
        ...unsigned,
        eventHash,
        eventSignature: receiptSigner.signHash(eventHash),
      };
      if (journalPath) {
        const existed = fs.existsSync(journalPath);
        const descriptor = fs.openSync(journalPath, 'a', 0o600);
        try {
          fs.writeFileSync(descriptor, `${JSON.stringify(event)}\n`);
          fs.fsyncSync(descriptor);
        } finally {
          fs.closeSync(descriptor);
        }
        if (!existed) fsyncDirectory(path.dirname(journalPath));
      }
      apply(event);
      eventLog.push(event);
      nextSequence += 1;
      headHash = event.eventHash;
      return event;
    };
    return journalPath ? withFileLock(lockPath, write) : write();
  }

  function assertUnique(index, value, key, label) {
    const existing = index.get(value);
    if (existing && existing !== key) throw new Error(`${label} already binds idempotency key '${existing}'`);
  }

  function requestInvocation(input) {
    refreshFromAuthority();
    const key = requireText(input.idempotencyKey, 'idempotencyKey');
    const declaration = {
      mode: input.mode === 'external' ? 'external' : (() => { throw new Error("journal plan supports mode 'external' only"); })(),
      skill: {
        id: requireText(input.skillId, 'skillId'),
        versionHash: requireText(input.skillVersionHash, 'skillVersionHash'),
      },
      requestHash: requireText(input.requestHash, 'requestHash'),
      creatorId: requireText(input.creatorId, 'creatorId'),
      beneficiaryId: input.beneficiaryId == null ? null : requireText(input.beneficiaryId, 'beneficiaryId'),
    };
    const existing = records.get(key);
    if (existing) {
      const bound = {
        mode: existing.mode,
        skill: existing.skill,
        requestHash: existing.requestHash,
        creatorId: existing.creatorId,
        beneficiaryId: existing.beneficiaryId,
      };
      if (!same(bound, declaration)) throw new Error(`idempotency key already binds a different Invocation declaration`);
      return copy(existing);
    }
    append('invocation.requested', key, { invocationId: createId(), ...declaration });
    return copy(records.get(key));
  }

  function offerExternalPayment(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (!input.requirements || typeof input.requirements !== 'object' || Array.isArray(input.requirements)) {
      throw new Error('requirements must contain the complete frozen x402 envelope');
    }
    const requirements = copy(input.requirements);
    const quote = {
      quoteId: requireText(input.quoteId, 'quoteId'),
      amountAtomic: requireAtomicString(input.amountAtomic, 'amountAtomic'),
      currency: input.currency === 'USDC' ? 'USDC' : (() => { throw new Error("currency must be 'USDC'"); })(),
      network: requireText(input.network, 'network'),
      asset: canonicalAddress(input.asset, 'asset'),
      payTo: canonicalAddress(input.payTo, 'payTo'),
      resource: requireText(input.resource, 'resource'),
      requestHash: requireText(input.requestHash, 'requestHash'),
      requirementsHash: requireText(input.requirementsHash, 'requirementsHash'),
      expiresAt: requireText(input.expiresAt, 'expiresAt'),
      requirements,
    };
    if (requirements.maxAmountRequired !== quote.amountAtomic
      || requirements.network !== quote.network
      || canonicalAddress(requirements.asset, 'requirements.asset') !== quote.asset
      || canonicalAddress(requirements.payTo, 'requirements.payTo') !== quote.payTo
      || requirements.resource !== quote.resource
      || requirements.extra?.requestHash !== quote.requestHash
      || requirements.extra?.quoteId !== quote.quoteId
      || requirements.extra?.expiresAt !== quote.expiresAt) {
      throw new Error('frozen x402 requirements do not match indexed quote fields');
    }
    if (record.quote) {
      if (!same(record.quote, quote)) throw new Error('idempotency key already binds a different quote');
      return copy(record);
    }
    assertState(record, ['requested'], 'offerExternalPayment');
    append('payment.offered', key, { quote });
    return copy(records.get(key));
  }

  function markExternalPaymentSigned(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const settlementReference = canonicalBytes32(input.settlementReference, 'settlementReference');
    const payer = canonicalAddress(input.payer, 'payer');
    if (record.payment.settlementReference) {
      if (record.payment.settlementReference !== settlementReference || record.payment.payer !== payer) {
        throw new Error('idempotency key already binds a different signed payment');
      }
      return copy(record);
    }
    if (record.payment.state !== 'offered') throw new Error(`markExternalPaymentSigned cannot run from payment state '${record.payment.state}'`);
    assertUnique(settlementReferences, settlementReference, key, 'settlement reference');
    append('payment.signed', key, { settlementReference, payer });
    return copy(records.get(key));
  }

  function markExternalPaymentSettled(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const settlementReference = canonicalBytes32(input.settlementReference, 'settlementReference');
    const txHash = canonicalBytes32(input.txHash, 'txHash');
    const payer = canonicalAddress(input.payer, 'payer');
    if (record.payment.state === 'settled') {
      if (record.payment.settlementReference !== settlementReference || record.payment.txHash !== txHash || record.payment.payer !== payer) {
        throw new Error('idempotency key already binds a different settlement');
      }
      return copy(record);
    }
    if (!['signed', 'unresolved'].includes(record.payment.state)) {
      throw new Error(`markExternalPaymentSettled cannot run from payment state '${record.payment.state}'`);
    }
    if (record.payment.settlementReference !== settlementReference) throw new Error('settlement reference does not match signed payment');
    if (record.payment.payer !== payer) throw new Error('settlement payer does not match signed payment');
    assertUnique(transactionHashes, txHash, key, 'transaction hash');
    append('payment.settled', key, { settlementReference, txHash, payer });
    return copy(records.get(key));
  }

  function markExternalPaymentUnresolved(key, { reason }) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.payment.state === 'unresolved' && record.payment.reason === reason) return copy(record);
    if (record.payment.state !== 'signed') throw new Error(`markExternalPaymentUnresolved cannot run from payment state '${record.payment.state}'`);
    append('payment.unresolved', key, { reason: requireText(reason, 'reason') });
    return copy(records.get(key));
  }

  function reconcileExternalSettlement({ settlementReference, txHash, payer }) {
    refreshFromAuthority();
    const reference = canonicalBytes32(settlementReference, 'settlementReference');
    const key = settlementReferences.get(reference);
    if (!key) throw new Error(`unknown settlement reference '${reference}'`);
    return markExternalPaymentSettled(key, { settlementReference: reference, txHash, payer });
  }

  function rejectExternalPayment(key, { reason }) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.payment.state === 'rejected' && record.payment.reason === reason) return copy(record);
    if (!['offered', 'signed', 'unresolved'].includes(record.payment.state)) {
      throw new Error(`rejectExternalPayment cannot run from payment state '${record.payment.state}'`);
    }
    append('payment.rejected', key, { reason: requireText(reason, 'reason') });
    return copy(records.get(key));
  }

  function refundExternalPayment(key, { reason, refundReference, refundAmountAtomic }) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.payment.state === 'refunded') {
      const existing = {
        reason: record.payment.reason,
        refundReference: record.payment.refundReference,
        refundAmountAtomic: record.payment.refundAmountAtomic,
        reversalEntries: record.payment.refundAccounting.reversalEntries,
      };
      const requested = {
        reason: requireText(reason, 'reason'),
        refundReference: requireText(refundReference, 'refundReference'),
        refundAmountAtomic: requireAtomicString(refundAmountAtomic, 'refundAmountAtomic'),
        reversalEntries: record.payment.refundAccounting.reversalEntries,
      };
      if (!same(existing, requested)) throw new Error('Invocation already binds a different refund');
      return copy(record);
    }
    const refund = {
      reason: requireText(reason, 'reason'),
      refundReference: requireText(refundReference, 'refundReference'),
      refundAmountAtomic: requireAtomicString(refundAmountAtomic, 'refundAmountAtomic'),
      reversalEntries: deriveFullGrossRefundReversal(record),
    };
    if (refund.refundAmountAtomic !== record.quote.amountAtomic) {
      throw new Error('refund v1 must return the full settled gross');
    }
    append('payment.refunded', key, refund);
    return copy(records.get(key));
  }

  function startExecution(key, { executionAttemptId = null } = {}) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.execution.state === 'executing') return { started: false, record: copy(record) };
    if (record.payment.state !== 'settled') throw new Error('external execution requires a settled payment');
    assertState(record, ['authorized'], 'startExecution');
    const attempt = executionAttemptId ?? `attempt:${crypto.createHash('sha256')
      .update(`${record.invocationId}\n${record.requestHash}`).digest('hex')}`;
    append('execution.started', key, { executionAttemptId: requireText(attempt, 'executionAttemptId') });
    return { started: true, record: copy(records.get(key)) };
  }

  function finishExecution(key, input) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    const outcome = requireText(input.outcome, 'outcome');
    if (!TERMINAL_EXECUTION.has(outcome)) throw new Error(`unsupported execution outcome '${outcome}'`);
    const data = {
      executionAttemptId: requireText(input.executionAttemptId ?? record.execution.executionAttemptId, 'executionAttemptId'),
      outcome,
      outcomeHash: input.outcomeHash ?? null,
      failureClass: input.failureClass ?? null,
      message: input.message ?? null,
      accounting: input.accounting ?? null,
    };
    if (TERMINAL_EXECUTION.has(record.execution.state)) {
      const terminal = { ...record.execution, accounting: record.accounting };
      const expected = {
        state: data.outcome,
        executionAttemptId: data.executionAttemptId,
        outcomeHash: data.outcomeHash,
        failureClass: data.failureClass,
        message: data.message,
        accounting: data.accounting,
      };
      if (!same(terminal, expected)) throw new Error('idempotency key already binds a different execution outcome');
      return copy(record);
    }
    assertState(record, ['executing'], 'finishExecution');
    append('execution.finished', key, data);
    return copy(records.get(key));
  }

  function issueReceipt(key) {
    refreshFromAuthority();
    const record = requireRecord(records, key);
    if (record.receipt) return copy(record.receipt);
    if (!TERMINAL_EXECUTION.has(record.execution.state)) throw new Error('receipt requires a terminal execution outcome');
    const receipt = receiptPayload(record);
    const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
    const bundle = {
      receipt,
      receiptHash,
      signature: receiptSigner.signHash(receiptHash),
      algorithm: receiptSigner.algorithm,
      keyId: receiptSigner.keyId,
    };
    append('receipt.issued', key, { bundle });
    return copy(bundle);
  }

  if (journalPath) withFileLock(lockPath, syncFromDisk);
  return Object.freeze({
    requestInvocation,
    offerExternalPayment,
    markExternalPaymentSigned,
    markExternalPaymentSettled,
    markExternalPaymentUnresolved,
    reconcileExternalSettlement,
    rejectExternalPayment,
    refundExternalPayment,
    startExecution,
    finishExecution,
    issueReceipt,
    getByIdempotencyKey: (key) => {
      refreshFromAuthority();
      return records.has(key) ? copy(records.get(key)) : null;
    },
    getBySettlementReference: (reference) => {
      refreshFromAuthority();
      const key = settlementReferences.get(canonicalBytes32(reference, 'settlementReference'));
      return key ? copy(records.get(key)) : null;
    },
    getByTxHash: (txHash) => {
      refreshFromAuthority();
      const key = transactionHashes.get(canonicalBytes32(txHash, 'txHash'));
      return key ? copy(records.get(key)) : null;
    },
    get events() { refreshFromAuthority(); return copy(eventLog); },
    signingPublicKeyPem: receiptSigner.publicKeyPem,
    signingKeyId: receiptSigner.keyId,
  });
}
```

- [ ] **Step 5: Run the journal tests**

Run: `npm run test:journal --prefix spikes/pi-wielder`

Expected: PASS, 12 tests and 0 failures, including two independent Node processes
writing one sequence/hash chain without a lost or torn event and a fresh process reading
the complete frozen offer needed by `loadFrozenOffer`.

- [ ] **Step 6: Commit the authoritative journal core**

```bash
git add .gitignore spikes/pi-wielder/package.json spikes/pi-wielder/src/invocation-journal.mjs spikes/pi-wielder/tests/invocation-journal.test.mjs spikes/pi-wielder/tests/journal-writer-fixture.mjs spikes/pi-wielder/tests/journal-reader-fixture.mjs
git commit -m "feat: add authoritative Invocation journal"
```

### Task 2: Emit x402 payment lifecycle events under one idempotency key

**Files:**
- Modify: `spikes/pi-wielder/src/x402-seller.mjs:35-152`
- Modify: `spikes/pi-wielder/src/proxy.mjs:34-81`
- Create: `spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

- [ ] **Step 1: Write a failing x402 lifecycle contract test**

Create `spikes/pi-wielder/tests/x402-lifecycle.test.mjs`:

```js
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { Hono } from 'hono';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { payingFetch } from '../src/proxy.mjs';
import {
  APPROVED_LIVE_FACILITATOR_BASE,
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  x402Paywall,
} from '../src/x402-seller.mjs';

test('challenge and retry emit one ordered lifecycle under one idempotency key', async () => {
  const facilitator = createMockFacilitator();
  const facilitatorTransport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  const calls = [];
  const lifecycle = Object.fromEntries([
    'onOffered', 'onSigned', 'onSettled', 'onUnresolved', 'onRejected',
  ].map((name) => [name, async (payload) => calls.push([name, payload])]));
  const app = new Hono();
  app.post('/resource', x402Paywall({
    price: '0.25',
    payTo: '0x000000000000000000000000000000000000dEaD',
    facilitatorTransport,
    lifecycle,
  }), (c) => c.json({ ok: true }));

  const result = await payingFetch(
      throwawayAccount(),
      'http://seller.test/resource',
      { method: 'POST', body: '{}' },
      { fetchImpl: (url, init) => app.request(url, init), idempotencyKey: 'idem-lifecycle' },
    );
  assert.equal(result.res.status, 200);
  assert.deepEqual(calls.map(([name]) => name), ['onOffered', 'onSigned', 'onSettled']);
  assert.ok(calls.every(([, payload]) => payload.idempotencyKey === 'idem-lifecycle'));
  assert.deepEqual(calls[0][1].requirements, calls[1][1].requirements);
  assert.match(calls[0][1].requirements.extra.requestHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(calls[2][1].settlementReference, result.settlementReference);
  assert.equal(calls[2][1].txHash, result.txHash);
});

test('a restarted paywall recovers the complete byte-identical frozen offer before accepting the paid retry', async () => {
  const facilitator = createMockFacilitator();
  const facilitatorTransport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  let persistedRequirements = null;
  let fetchCount = 0;
  const beforeRestart = new Hono();
  beforeRestart.post('/resource', x402Paywall({
    price: '0.25',
    payTo: '0x000000000000000000000000000000000000dEaD',
    facilitatorTransport,
    lifecycle: {
      async onOffered({ requirements }) { persistedRequirements = structuredClone(requirements); },
    },
  }), (c) => c.json({ shouldNotExecute: true }));
  const afterRestart = new Hono();
  afterRestart.post('/resource', x402Paywall({
    price: '9.99',
    payTo: '0x0000000000000000000000000000000000000001',
    facilitatorTransport,
    lifecycle: {
      async loadFrozenOffer() { return structuredClone(persistedRequirements); },
    },
  }), (c) => c.json({ ok: true }));

  const result = await payingFetch(
      throwawayAccount(),
      'http://seller.test/resource',
      { method: 'POST', body: '{"input":"same bytes"}' },
      {
        idempotencyKey: 'idem-restart',
        fetchImpl: (url, init) => (++fetchCount === 1 ? beforeRestart : afterRestart).request(url, init),
      },
    );
  assert.equal(result.res.status, 200);
  assert.equal(fetchCount, 2);
  assert.equal(persistedRequirements.maxAmountRequired, '250000');
  assert.equal(persistedRequirements.payTo, '0x000000000000000000000000000000000000dEaD');
});

test('a paid request without Idempotency-Key is rejected before signing or settlement', async () => {
  const app = new Hono();
  app.post('/resource', x402Paywall({
    price: '0.25',
    payTo: '0x000000000000000000000000000000000000dEaD',
    facilitatorTransport: createMockFacilitatorTransport(async () => { throw new Error('must not run'); }),
  }), (c) => c.json({ ok: true }));
  const res = await app.request('http://seller.test/resource', { method: 'POST', body: '{}' });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /Idempotency-Key/);
});

test('live facilitator configuration pins one exact HTTPS origin and base path before authorization exists', () => {
  let networkCalls = 0;
  for (const malicious of [
    'http://x402.org/facilitator',
    'https://user:pass@x402.org/facilitator',
    'https://x402.org:8443/facilitator',
    'https://x402.org/facilitator/',
    'https://x402.org/facilitator/verify',
    'https://x402.org/facilitator?next=https://evil.test',
    'https://x402.org/facilitator#evil',
  ]) {
    assert.throws(() => createLiveFacilitatorTransport(malicious, async () => { networkCalls += 1; }),
      (error) => error.code === 'FACILITATOR_NOT_APPROVED');
  }
  assert.equal(networkCalls, 0);
  assert.doesNotThrow(() => createLiveFacilitatorTransport(
    APPROVED_LIVE_FACILITATOR_BASE,
    async () => { networkCalls += 1; },
  ));
});

test('verify and settle disable redirects so signed authorization cannot follow a new destination', async () => {
  for (const redirectOperation of ['verify', 'settle']) {
    const destinations = [];
    const transport = createMockFacilitatorTransport(async (url, init) => {
      const operation = new URL(url).pathname.slice(1);
      destinations.push([url, init.redirect]);
      if (operation === redirectOperation) {
        return new Response(null, { status: 302, headers: { location: 'https://evil.test/collect' } });
      }
      return new Response(JSON.stringify({ isValid: true }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    });
    const app = new Hono();
    app.post('/resource', x402Paywall({
      price: '0.25', payTo: '0x000000000000000000000000000000000000dEaD',
      facilitatorTransport: transport,
    }), (c) => c.json({ ok: true }));
    const result = await payingFetch(throwawayAccount(), 'http://seller.test/resource',
      { method: 'POST', body: '{}' }, { fetchImpl: (url, init) => app.request(url, init) });
    assert.equal(result.res.status, 503);
    assert.equal(destinations.at(-1)[0], `http://facilitator.invalid/${redirectOperation}`);
    assert.ok(destinations.every(([, redirect]) => redirect === 'error'));
    assert.ok(destinations.every(([url]) => !url.startsWith('https://evil.test')));
  }
});
```

- [ ] **Step 2: Run the test and verify `payingFetch` is not exported**

Run: `node --test spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

Expected: FAIL because `payingFetch` is not exported and the paywall has no lifecycle contract.

- [ ] **Step 3: Replace float conversion with the atomic boundary**

At the top of `spikes/pi-wielder/src/x402-seller.mjs`, add:

```js
import crypto from 'node:crypto';
import { formatUsdc, parseUsdc } from '../../../prototype/atomic-money.mjs';
```

Replace the two conversion exports with:

```js
export const usdcToAtomic = (usdc) => parseUsdc(usdc).toString();
export const atomicToUsdc = (atomic) => formatUsdc(BigInt(atomic));
```

Update the historical display assertion in `tests/atomic-boundary.test.mjs` to expect
`'0.250000'`, not `0.25`. No money value crosses back through a JavaScript `number`;
x402 requirements, receipts, ledger state, and UI display helpers all use canonical strings.

- [ ] **Step 4: Add the lifecycle hook contract to `x402Paywall`**

Change the function signature to:

```js
export function x402Paywall({
  price,
  payTo,
  facilitatorTransport,
  description = '',
  lifecycle = {},
}) {
```

Add these constructors above `x402Paywall`; the private `WeakSet` prevents callers from
smuggling an arbitrary structural object into the transport boundary:

```js
export const APPROVED_LIVE_FACILITATOR_BASE = 'https://x402.org/facilitator';
const authorizedTransports = new WeakSet();

function authorizeTransport(transport) {
  authorizedTransports.add(transport);
  return Object.freeze(transport);
}

export function createMockFacilitatorTransport(fetchImpl) {
  if (typeof fetchImpl !== 'function') throw new TypeError('mock facilitator requires an injected fetch/app');
  return authorizeTransport({
    mode: 'mock', baseUrl: 'http://facilitator.invalid', fetchImpl,
  });
}

export function createLiveFacilitatorTransport(rawBaseUrl, fetchImpl = fetch) {
  // Exact-string pinning intentionally rejects credentials, explicit ports, query,
  // fragment, trailing slash, alternate paths, schemes, and origins before any fetch.
  if (rawBaseUrl !== APPROVED_LIVE_FACILITATOR_BASE) {
    const error = new Error('live facilitator is not the pinned approved endpoint');
    error.code = 'FACILITATOR_NOT_APPROVED';
    throw error;
  }
  const parsed = new URL(rawBaseUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
    || parsed.port || parsed.search || parsed.hash || parsed.pathname !== '/facilitator') {
    const error = new Error('live facilitator endpoint violates the approved HTTPS contract');
    error.code = 'FACILITATOR_NOT_APPROVED';
    throw error;
  }
  return authorizeTransport({ mode: 'live', baseUrl: rawBaseUrl, fetchImpl });
}

function requireFacilitatorTransport(transport) {
  if (!transport || !authorizedTransports.has(transport)) {
    throw new Error('facilitatorTransport must come from an approved live or injected-mock constructor');
  }
  return transport;
}
```

At `x402Paywall` construction—not inside the request handler—call
`const transport = requireFacilitatorTransport(facilitatorTransport);`. Therefore bad
live configuration fails before a Wielder can sign and no authorization can be sent.

Inside `x402Paywall`, add this cache next to the existing `consumed` set:

```js
  const frozenOffers = new Map(); // idempotency key -> byte-stable PaymentRequirements
```

Replace the per-request requirements construction, key check, and no-payment branch
with the complete frozen-envelope block below. Hono caches the request text, so the
downstream JSON handler still receives the same bytes.

```js
    const idempotencyKey = c.req.header('Idempotency-Key')?.trim();
    if (!idempotencyKey) return c.json({ error: 'Idempotency-Key header is required' }, 400);
    const paymentHeader = c.req.header('X-PAYMENT');
    const requestBody = await c.req.text();
    const requestHash = `sha256:${crypto.createHash('sha256')
      .update(`${c.req.method}\n${c.req.url}\n${requestBody}`)
      .digest('hex')}`;

    let requirements = frozenOffers.get(idempotencyKey);
    if (!requirements) {
      const recovered = await lifecycle.loadFrozenOffer?.({ idempotencyKey });
      if (recovered) {
        requirements = structuredClone(recovered);
        frozenOffers.set(idempotencyKey, requirements);
      }
    }
    if (requirements) {
      if (requirements.extra.requestHash !== requestHash) {
        return c.json({ error: 'Idempotency-Key already binds a different request body' }, 409);
      }
    } else {
      if (paymentHeader) return c.json({ error: 'paid retry has no prior frozen x402 offer' }, 409);
      const priceUsdc = typeof price === 'function' ? await price(c) : price;
      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 60_000).toISOString();
      const base = {
        scheme: 'exact',
        network: NETWORK,
        maxAmountRequired: usdcToAtomic(priceUsdc),
        resource: c.req.url,
        description,
        mimeType: 'application/json',
        payTo,
        maxTimeoutSeconds: 60,
        asset: USDC_ADDRESS,
      };
      const quoteId = `sha256:${crypto.createHash('sha256')
        .update(JSON.stringify({ ...base, requestHash, issuedAt, expiresAt }))
        .digest('hex')}`;
      requirements = {
        ...base,
        extra: {
          name: USDC_EIP712.name,
          version: USDC_EIP712.version,
          requestHash,
          quoteId,
          issuedAt,
          expiresAt,
        },
      };
      frozenOffers.set(idempotencyKey, requirements);
    }

    if (!paymentHeader) {
      await lifecycle.onOffered?.({
        idempotencyKey,
        requirements,
        expiresAt: requirements.extra.expiresAt,
      });
      return c.json(
        { x402Version: X402_VERSION, error: 'X-PAYMENT header is required', accepts: [requirements] },
        402,
      );
    }
```

Delete the original `priceUsdc`, `requirements`, `paymentHeader`, and no-payment block.
The exact same requirements object now drives the challenge, retry verification,
journal `requirementsHash`, and Wielder policy fingerprint.

`loadFrozenOffer` is the restart boundary: the Collar returns the complete persisted
`record.quote.requirements` envelope. Do not regenerate timestamps, `quoteId`, resource,
or any other field from hashes. A post-restart challenge and paid retry therefore use
the same JSON property/value envelope that the original Wielder accepted.

After decoding `paymentPayload` and before facilitator verification, add:

```js
    const settlementReference = paymentPayload?.payload?.authorization?.nonce;
    const payer = paymentPayload?.payload?.authorization?.from;
    if (!settlementReference || !payer) {
      await lifecycle.onRejected?.({ idempotencyKey, reason: 'payment authorization lacks nonce or payer' });
      return c.json({ x402Version: X402_VERSION, error: 'payment authorization lacks nonce or payer', accepts: [requirements] }, 402);
    }
    let priorDecision = null;
    try {
      priorDecision = await lifecycle.onSigned?.({
        idempotencyKey,
        settlementReference,
        payer,
        requirements,
      });
    } catch (error) {
      return c.json({ error: error.message }, 409);
    }
    if (priorDecision?.kind === 'terminal') {
      const replay = c.json({ replayed: true, receipt: priorDecision.receipt }, 200);
      replay.headers.set('X-PAYMENT-RESPONSE', jsonToB64({
        success: true,
        transaction: priorDecision.txHash,
        network: NETWORK,
        payer: priorDecision.payer,
        settlementReference,
      }));
      return replay;
    }
    if (priorDecision?.kind === 'execution_unresolved') {
      return c.json({
        error: 'execution outcome unresolved; trusted executor reconciliation is required',
        executionAttemptId: priorDecision.executionAttemptId,
      }, 503);
    }
```

Replace the verify/settle block with this fault-aware and reconciliation-aware version:

```js
    let settle;
    let facilitatorMs = 0;
    if (priorDecision?.kind === 'settled') {
      settle = {
        success: true,
        transaction: priorDecision.txHash,
        payer: priorDecision.payer,
        network: NETWORK,
      };
    } else {
      const tFacilitator = performance.now();
      try {
        const verify = await postJson(transport, 'verify', facilitatorBody);
        if (!verify?.isValid) {
          const reason = `payment verification failed: ${verify?.invalidReason ?? 'unknown'}`;
          await lifecycle.onRejected?.({ idempotencyKey, reason, settlementReference, payer });
          return c.json({ x402Version: X402_VERSION, error: reason, accepts: [requirements] }, 402);
        }
        settle = await postJson(transport, 'settle', facilitatorBody);
      } catch (error) {
        await lifecycle.onUnresolved?.({
          idempotencyKey,
          settlementReference,
          payer,
          reason: `facilitator response unresolved: ${error.message}`,
        });
        return c.json({ error: 'payment settlement unresolved', settlementReference }, 503);
      }
      facilitatorMs = performance.now() - tFacilitator;
    }
    if (!settle?.success) {
      const reason = `payment settlement failed: ${settle?.errorReason ?? 'unknown'}`;
      await lifecycle.onRejected?.({ idempotencyKey, reason, settlementReference, payer });
      return c.json({ x402Version: X402_VERSION, error: reason, accepts: [requirements] }, 402);
    }
    if (priorDecision?.kind !== 'settled') {
      await lifecycle.onSettled?.({
        idempotencyKey,
        settlementReference,
        txHash: settle.transaction,
        payer: settle.payer ?? payer,
        amountAtomic: requirements.maxAmountRequired,
        requirements,
      });
    }
```

Remove the old duplicate verify/settle declarations and failure branches. Extend the
existing `c.set('x402', ...)` payload to exactly:

```js
    c.set('x402', {
      idempotencyKey,
      settlementReference,
      txHash: settle.transaction,
      payer: settle.payer ?? payer,
      amountAtomic: requirements.maxAmountRequired,
      requirements,
    });
```

- [ ] **Step 5: Export `payingFetch` and preserve one key across both requests**

Add `import { formatUsdc } from '../../../prototype/atomic-money.mjs';` to
`proxy.mjs`; this is a display-string boundary, not seller-side trust logic.

Change the `payingFetch` signature in `spikes/pi-wielder/src/proxy.mjs` to:

```js
export async function payingFetch(account, url, init, {
  fetchImpl = fetch,
  idempotencyKey = crypto.randomUUID(),
} = {}) {
```

Replace both fetch calls with these exact forms:

```js
  const requestHeaders = { ...init.headers, 'Idempotency-Key': idempotencyKey };
  const first = await fetchImpl(url, { ...init, headers: requestHeaders });
```

```js
  const res = await fetchImpl(url, {
    ...init,
    headers: { ...requestHeaders, 'X-PAYMENT': xPayment },
  });
```

Read the settlement response once and extend the returned object:

```js
  const paymentResponse = res.headers.get('X-PAYMENT-RESPONSE');
  const settlement = paymentResponse ? unb64(paymentResponse) : null;
  return {
    res,
    paid: true,
    xPayment,
    idempotencyKey,
    settlementReference: authorization.nonce,
    txHash: settlement?.transaction ?? null,
    payer: account.address.toLowerCase(),
    requestHash: req.extra.requestHash,
    quoteId: req.extra.quoteId,
    amountAtomic: String(req.maxAmountRequired),
    amountDisplay: formatUsdc(BigInt(req.maxAmountRequired)),
    timings: { ms402, msSign, msFacilitator, msPaidRoundtrip, msOverhead: ms402 + msSign + (msFacilitator || 0) },
  };
```

Delete the original return block so the retry still occurs exactly once.

Add `settlementReference` to the normal `X-PAYMENT-RESPONSE` payload as well:

```js
jsonToB64({
  success: true,
  transaction: settle.transaction,
  network: NETWORK,
  payer: settle.payer ?? payer,
  settlementReference,
})
```

Finally, replace `postJson` with a strict injectable transport:

```js
async function postJson(transport, operation, body) {
  if (!['verify', 'settle'].includes(operation)) throw new Error('invalid facilitator operation');
  const url = `${transport.baseUrl}/${operation}`;
  const res = await transport.fetchImpl(url, {
    method: 'POST',
    redirect: 'error',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`facilitator HTTP ${res.status}`);
  const json = await res.json().catch(() => null);
  if (!json) throw new Error('facilitator returned no JSON result');
  return json;
}
```

- [ ] **Step 6: Run the lifecycle tests**

Run: `node --test spikes/pi-wielder/tests/x402-lifecycle.test.mjs`

Expected: PASS, 5 tests and 0 failures, including endpoint pinning, redirect refusal,
and full frozen-offer recovery across
a simulated paywall process restart.

- [ ] **Step 7: Commit lifecycle correlation**

```bash
git add spikes/pi-wielder/src/x402-seller.mjs spikes/pi-wielder/src/proxy.mjs spikes/pi-wielder/tests/x402-lifecycle.test.mjs
git commit -m "feat: journal x402 payment lifecycle"
```

### Task 3: Make the Collar own execution outcomes and signed receipts

**Files:**
- Modify: `spikes/pi-wielder/src/collar.mjs:1-142`
- Create: `spikes/pi-wielder/tests/collar-failure.test.mjs`

- [ ] **Step 1: Write the failing settled-then-500 integration test**

Create `spikes/pi-wielder/tests/collar-failure.test.mjs`:

```js
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import { chooseFacilitator, startCollar, SKILL_ID } from '../src/collar.mjs';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { payingFetch, startProxy } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { verifySignedReceipt } from '../src/invocation-journal.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';

test('standalone settlement defaults to an injected offline mock and never a live URL', async () => {
  let mockStarts = 0;
  const selected = await chooseFacilitator({
    env: {},
    startMock: async () => { mockStarts += 1; return createMockFacilitator(); },
  });
  assert.equal(selected.mode, 'mock');
  assert.equal(typeof selected.transport, 'object');
  assert.equal(mockStarts, 1);
  await assert.rejects(() => chooseFacilitator({ env: { ALLOW_LIVE_X402: '1' } }), /requires/);
});

test('settled-then-500 remains authoritative and queryable without another debit', async () => {
  const facilitator = createMockFacilitator();
  const collar = await startCollar({
    facilitatorTransport: createMockFacilitatorTransport((url, init) => facilitator.request(url, init)),
    executeSkill: async () => { throw new Error('injected provider fault'); },
  });
  const proxy = await startProxy({
    account: throwawayAccount(),
    collarUrl: collar.url,
    trustedCollarPublicKeyPem: collar.signingPublicKeyPem,
    trustedCollarKeyId: collar.signingKeyId,
  });

  try {
    const res = await fetch(`${proxy.url}/invoke/${SKILL_ID}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ input: 'trigger the injected failure' }),
    });
    const body = await res.json();
    assert.equal(res.status, 500);
    assert.equal(verifySignedReceipt(body.receipt, {
      publicKeyPem: collar.signingPublicKeyPem,
      keyId: collar.signingKeyId,
    }), true);
    assert.equal(body.receipt.receipt.payment.state, 'settled');
    assert.match(body.receipt.receipt.payment.txHash, /^0x[0-9a-f]{64}$/);
    assert.equal(body.receipt.receipt.execution.state, 'failed');

    const reference = body.receipt.receipt.payment.settlementReference;
    const eventCount = collar.journal.events.length;
    const reconciled = await fetch(`${collar.url}/receipts/by-settlement/${reference}`);
    assert.equal(reconciled.status, 200);
    assert.deepEqual((await reconciled.json()).receipt, body.receipt);
    assert.equal(collar.journal.events.length, eventCount);
    assert.equal(collar.journal.events.filter((event) => event.type === 'payment.settled').length, 1);
  } finally {
    proxy.close();
    collar.close();
  }
});

test('trusted reconciliation resumes once and exact retries return the cached receipt', async () => {
  const facilitatorApp = createMockFacilitator();
  let lostSettlement = null;
  let settleCalls = 0;
  let executions = 0;
  const facilitatorFetch = async (url, init) => {
    const response = await facilitatorApp.request(url, init);
    if (new URL(url).pathname === '/settle') {
      settleCalls += 1;
      lostSettlement = await response.clone().json();
      throw new Error('injected lost facilitator response');
    }
    return response;
  };
  const collar = await startCollar({
    facilitatorTransport: createMockFacilitatorTransport(facilitatorFetch),
    resolveSettlement: async ({ settlementReference, amountAtomic }) => ({
      settled: true,
      settlementReference,
      amountAtomic,
      txHash: lostSettlement.transaction,
      payer: lostSettlement.payer,
    }),
    executeSkill: async ({ input }) => {
      executions += 1;
      return { output: `executed ${input}` };
    },
  });
  const account = throwawayAccount();
  const idempotencyKey = 'idem-response-loss';
  const requestBody = JSON.stringify({ input: 'same bytes' });

  try {
    const first = await payingFetch(account, `${collar.url}/invoke/${SKILL_ID}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
    }, { idempotencyKey });
    assert.equal(first.res.status, 503);
    assert.equal(collar.journal.getBySettlementReference(first.settlementReference).payment.state, 'unresolved');

    const reconcile = await fetch(`${collar.url}/reconcile/by-settlement/${first.settlementReference}`, { method: 'POST' });
    assert.equal(reconcile.status, 200);
    assert.equal((await reconcile.json()).txHash, lostSettlement.transaction);

    const retry = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'X-PAYMENT': first.xPayment,
      },
      body: requestBody,
    });
    assert.equal(retry.status, 200);
    const terminalBody = await retry.json();
    assert.equal(executions, 1);
    assert.equal(verifySignedReceipt(terminalBody.receipt, {
      publicKeyPem: collar.signingPublicKeyPem,
      keyId: collar.signingKeyId,
    }), true);

    const exactRetry = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'X-PAYMENT': first.xPayment,
      },
      body: requestBody,
    });
    assert.equal(exactRetry.status, 200);
    const cachedBody = await exactRetry.json();
    assert.equal(cachedBody.replayed, true);
    assert.deepEqual(cachedBody.receipt, terminalBody.receipt);
    assert.equal(executions, 1);

    const conflictingRetry = await fetch(`${collar.url}/invoke/${SKILL_ID}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'Idempotency-Key': idempotencyKey,
        'X-PAYMENT': first.xPayment,
      },
      body: JSON.stringify({ input: 'different bytes' }),
    });
    assert.equal(conflictingRetry.status, 409);
    assert.equal(executions, 1);
    assert.equal(settleCalls, 1);
    assert.equal(collar.journal.events.filter((event) => event.type === 'payment.settled').length, 1);
    assert.equal(collar.journal.events.filter((event) => event.type === 'execution.started').length, 1);
  } finally {
    collar.close();
  }
});

async function prepareReconciledRetry({ executeSkill, lifecycleFaults = {} }) {
  const facilitatorApp = createMockFacilitator();
  let lostSettlement;
  const facilitatorFetch = async (url, init) => {
    const response = await facilitatorApp.request(url, init);
    if (new URL(url).pathname === '/settle') {
      lostSettlement = await response.clone().json();
      throw new Error('injected response loss before execution');
    }
    return response;
  };
  const collar = await startCollar({
    facilitatorTransport: createMockFacilitatorTransport(facilitatorFetch), executeSkill, lifecycleFaults,
    resolveSettlement: async ({ settlementReference, amountAtomic }) => ({
      settled: true, settlementReference, amountAtomic,
      txHash: lostSettlement.transaction, payer: lostSettlement.payer,
    }),
  });
  const idempotencyKey = `idem-crash-${crypto.randomUUID()}`;
  const requestBody = JSON.stringify({ input: 'same bytes' });
  const first = await payingFetch(throwawayAccount(), `${collar.url}/invoke/${SKILL_ID}`, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: requestBody,
  }, { idempotencyKey });
  assert.equal(first.res.status, 503);
  const reconcile = await fetch(`${collar.url}/reconcile/by-settlement/${first.settlementReference}`, { method: 'POST' });
  assert.equal(reconcile.status, 200);
  const retry = () => fetch(`${collar.url}/invoke/${SKILL_ID}`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json', 'Idempotency-Key': idempotencyKey,
      'X-PAYMENT': first.xPayment,
    },
    body: requestBody,
  });
  return { collar, idempotencyKey, retry };
}

test('crash after the provider returns leaves one unresolved attempt and never calls the provider again', async () => {
  let executions = 0;
  const prepared = await prepareReconciledRetry({
    executeSkill: async () => { executions += 1; return { output: 'completed but not journaled' }; },
    lifecycleFaults: { afterExecutorReturned: async () => { throw new Error('crash after provider return'); } },
  });
  try {
    assert.equal((await prepared.retry()).status, 500);
    assert.equal(executions, 1);
    assert.equal((await prepared.retry()).status, 503);
    assert.equal(executions, 1);
    const record = prepared.collar.journal.getByIdempotencyKey(prepared.idempotencyKey);
    assert.equal(record.execution.state, 'executing');
    assert.match(record.execution.executionAttemptId, /^attempt:/);
  } finally {
    prepared.collar.close();
  }
});

test('crash after finish but before receipt issuance replays the terminal receipt without another provider call', async () => {
  let executions = 0;
  let crash = true;
  const prepared = await prepareReconciledRetry({
    executeSkill: async () => { executions += 1; return { output: 'journaled output' }; },
    lifecycleFaults: { afterExecutionFinished: async () => {
      if (crash) { crash = false; throw new Error('crash before receipt append'); }
    } },
  });
  try {
    assert.equal((await prepared.retry()).status, 500);
    assert.equal(executions, 1);
    assert.equal(prepared.collar.journal.getByIdempotencyKey(prepared.idempotencyKey).receipt, null);
    const replay = await prepared.retry();
    assert.equal(replay.status, 200);
    const body = await replay.json();
    assert.equal(body.replayed, true);
    assert.equal(executions, 1);
    assert.equal(verifySignedReceipt(body.receipt, {
      publicKeyPem: prepared.collar.signingPublicKeyPem,
      keyId: prepared.collar.signingKeyId,
    }), true);
  } finally {
    prepared.collar.close();
  }
});

test('overlapping paid retries atomically claim one execution attempt and call the provider once', async () => {
  let executions = 0;
  let releaseExecution;
  let announceStarted;
  const started = new Promise((resolve) => { announceStarted = resolve; });
  const gate = new Promise((resolve) => { releaseExecution = resolve; });
  const prepared = await prepareReconciledRetry({
    executeSkill: async ({ executionAttemptId }) => {
      executions += 1;
      assert.match(executionAttemptId, /^attempt:/);
      announceStarted();
      await gate;
      return { output: 'one output' };
    },
  });
  try {
    const winner = prepared.retry();
    await started;
    const overlap = await prepared.retry();
    assert.equal(overlap.status, 503);
    assert.equal(executions, 1);
    releaseExecution();
    assert.equal((await winner).status, 200);
    assert.equal(executions, 1);
    assert.equal(prepared.collar.journal.events.filter((event) => event.type === 'execution.started').length, 1);
  } finally {
    releaseExecution();
    prepared.collar.close();
  }
});
```

- [ ] **Step 2: Run the test and verify the Collar does not expose a journal**

Run: `node --test spikes/pi-wielder/tests/collar-failure.test.mjs`

Expected: FAIL because `startCollar` does not return `journal`, injected execution is
not supported, and settled failures do not issue receipts.

- [ ] **Step 3: Replace the float settlement-engine imports with the atomic kernel and journal**

Replace the imports at the top of `spikes/pi-wielder/src/collar.mjs` with:

```js
import crypto from 'node:crypto';
import fs from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { allocateExternalGross } from '../../../prototype/atomic-money.mjs';
import {
  createLiveFacilitatorTransport,
  createMockFacilitatorTransport,
  x402Paywall,
  usdcToAtomic,
} from './x402-seller.mjs';
import {
  canonicalJson,
  createInvocationJournal,
} from './invocation-journal.mjs';
```

Add these helpers below `DEFAULT_PRICE_USDC`:

```js
const hash = (value) => `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;

const royaltyGraph = {
  [SKILL_ID]: {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: 'creator', bps: 10_000 }],
  },
};

function serializeAccounting(result) {
  return {
    grossAtomic: result.grossAtomic.toString(),
    executionCostAtomic: result.executionCostAtomic.toString(),
    settlementCostAtomic: result.settlementCostAtomic.toString(),
    protocolFeeAtomic: result.protocolFeeAtomic.toString(),
    royaltyPoolAtomic: result.royaltyPoolAtomic.toString(),
    refundReserveAtomic: result.refundReserveAtomic.toString(),
    holderCredits: result.holderCredits.map((credit) => ({
      ...credit,
      amountAtomic: credit.amountAtomic.toString(),
    })),
    ancestorCredits: result.ancestorCredits.map((credit) => ({
      ...credit,
      amountAtomic: credit.amountAtomic.toString(),
    })),
  };
}
```

- [ ] **Step 4: Replace `createCollar` with the authoritative lifecycle**

Replace the complete `createCollar` function with:

```js
export function createCollar({
  facilitatorTransport,
  payTo = process.env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dEaD',
  priceUsdc = process.env.SKILL_PRICE_USDC || String(DEFAULT_PRICE_USDC),
  mockLlm = process.env.MOCK_LLM === '1',
  journal = null,
  journalFile = process.env.COLLAR_JOURNAL_FILE || null,
  signingKeyFile = process.env.COLLAR_SIGNING_KEY_FILE || null,
  receiptSigner = null,
  executeSkill = null,
  lifecycleFaults = {}, // injected by offline crash-boundary tests only
  resolveSettlement = async () => ({ settled: false }),
} = {}) {
  if (!journal && Boolean(journalFile) !== Boolean(signingKeyFile)) {
    throw new Error('COLLAR_JOURNAL_FILE and COLLAR_SIGNING_KEY_FILE must be set together');
  }
  journal ??= createInvocationJournal({
    filePath: journalFile,
    signingKeyPath: signingKeyFile || undefined,
    signer: receiptSigner,
  });
  const skillContent = fs.readFileSync(SKILL_PATH, 'utf8');
  const skillVersionHash = hash(skillContent);
  const priceAtomic = usdcToAtomic(priceUsdc);
  const executor = executeSkill ?? (mockLlm
    ? async ({ input }) => ({ output: mockSkillOutput(input) })
    : async ({ input }) => ({ output: await runSkillViaAnthropic(skillContent, input) }));

  const lifecycle = {
    async onOffered({ idempotencyKey, requirements, expiresAt }) {
      journal.requestInvocation({
        idempotencyKey,
        mode: 'external',
        skillId: SKILL_ID,
        skillVersionHash,
        requestHash: requirements.extra.requestHash,
        creatorId: 'creator',
        beneficiaryId: null,
      });
      journal.offerExternalPayment(idempotencyKey, {
        quoteId: requirements.extra.quoteId,
        amountAtomic: requirements.maxAmountRequired,
        currency: 'USDC',
        network: requirements.network,
        asset: requirements.asset,
        payTo: requirements.payTo,
        resource: requirements.resource,
        requestHash: requirements.extra.requestHash,
        requirementsHash: hash(canonicalJson(requirements)),
        expiresAt,
        requirements,
      });
    },
    async loadFrozenOffer({ idempotencyKey }) {
      return journal.getByIdempotencyKey(idempotencyKey)?.quote?.requirements ?? null;
    },
    async onSigned({ idempotencyKey, settlementReference, payer, requirements }) {
      const existing = journal.getByIdempotencyKey(idempotencyKey);
      if (!existing?.quote) throw new Error('paid retry has no prior quoted Invocation');
      if (existing.quote.requirementsHash !== hash(canonicalJson(requirements))) {
        throw new Error('paid retry does not match the frozen x402 requirements');
      }
      if (existing.quote.requestHash !== requirements.extra.requestHash) {
        throw new Error('idempotency key already binds a different request payload');
      }
      const record = journal.markExternalPaymentSigned(idempotencyKey, { settlementReference, payer });
      if (['succeeded', 'failed', 'cancelled'].includes(record.execution.state)) {
        const receipt = record.receipt ?? journal.issueReceipt(idempotencyKey);
        return {
          kind: 'terminal',
          receipt,
          txHash: record.payment.txHash,
          payer: record.payment.payer,
        };
      }
      if (record.execution.state === 'executing') {
        return { kind: 'execution_unresolved', executionAttemptId: record.execution.executionAttemptId };
      }
      if (record.payment.state === 'settled' && record.execution.state === 'authorized') {
        return { kind: 'settled', txHash: record.payment.txHash, payer: record.payment.payer };
      }
      return null;
    },
    async onSettled({ idempotencyKey, settlementReference, txHash, payer }) {
      journal.markExternalPaymentSettled(idempotencyKey, { settlementReference, txHash, payer });
    },
    async onUnresolved({ idempotencyKey, reason }) {
      journal.markExternalPaymentUnresolved(idempotencyKey, { reason });
    },
    async onRejected({ idempotencyKey, reason }) {
      journal.rejectExternalPayment(idempotencyKey, { reason });
    },
  };

  const app = new Hono();
  app.get('/healthz', (c) => c.json({
    ok: true,
    skill: SKILL_ID,
    skillVersionHash,
    priceAtomic,
    currency: 'USDC',
    receiptAlgorithm: 'Ed25519',
    signingPublicKeyPem: journal.signingPublicKeyPem,
    signingKeyId: journal.signingKeyId,
  }));

  app.get('/receipts/by-settlement/:reference', (c) => {
    const record = journal.getBySettlementReference(c.req.param('reference'));
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (!record.receipt) {
      return c.json({
        invocationId: record.invocationId,
        paymentState: record.payment.state,
        executionState: record.execution.state,
      }, 202);
    }
    return c.json({ receipt: record.receipt });
  });

  app.post('/reconcile/by-settlement/:reference', async (c) => {
    const settlementReference = c.req.param('reference');
    const record = journal.getBySettlementReference(settlementReference);
    if (!record) return c.json({ error: 'unknown settlement reference' }, 404);
    if (record.payment.state === 'settled') {
      return c.json({ paymentState: 'settled', txHash: record.payment.txHash });
    }
    if (record.payment.state !== 'unresolved') {
      return c.json({ error: `payment state '${record.payment.state}' is not reconcilable` }, 409);
    }
    const resolution = await resolveSettlement({
      settlementReference,
      payer: record.payment.payer,
      amountAtomic: record.quote.amountAtomic,
      network: record.quote.network,
      asset: record.quote.asset,
      payTo: record.quote.payTo,
    });
    if (!resolution?.settled) {
      return c.json({ paymentState: 'unresolved', settlementReference }, 202);
    }
    if (resolution.settlementReference !== settlementReference
      || resolution.payer?.toLowerCase() !== record.payment.payer?.toLowerCase()
      || String(resolution.amountAtomic) !== record.quote.amountAtomic) {
      return c.json({ error: 'trusted settlement resolver returned a mismatched proof' }, 502);
    }
    const reconciled = journal.reconcileExternalSettlement({
      settlementReference,
      txHash: resolution.txHash,
      payer: resolution.payer,
    });
    return c.json({ paymentState: reconciled.payment.state, txHash: reconciled.payment.txHash });
  });

  app.post(
    '/invoke/:skillId',
    x402Paywall({
      price: priceUsdc,
      payTo,
      facilitatorTransport,
      description: `hosted-skill invocation: ${SKILL_ID}`,
      lifecycle,
    }),
    async (c) => {
      const payment = c.get('x402');
      const key = payment.idempotencyKey;
      const claim = journal.startExecution(key);
      if (!claim.started) {
        return c.json({
          error: 'execution outcome unresolved; trusted executor reconciliation is required',
          executionAttemptId: claim.record.execution.executionAttemptId,
        }, 503);
      }
      const executionAttemptId = claim.record.execution.executionAttemptId;

      const finishFailure = (failureClass, message, status) => {
        journal.finishExecution(key, {
          executionAttemptId,
          outcome: 'failed',
          failureClass,
          message,
          outcomeHash: null,
          accounting: null,
        });
        return c.json({ error: message, receipt: journal.issueReceipt(key) }, status);
      };

      if (c.req.param('skillId') !== SKILL_ID) {
        return finishFailure('UNKNOWN_SKILL', `unknown skill '${c.req.param('skillId')}'`, 404);
      }
      const body = await c.req.json().catch(() => null);
      if (!body?.input) {
        return finishFailure('INVALID_REQUEST', 'body must be JSON: { "input": "..." }', 400);
      }

      let execution;
      try {
        execution = await executor({
          skillId: SKILL_ID,
          skillVersionHash,
          skillContent,
          input: body.input,
          executionAttemptId,
        });
      } catch (error) {
        return finishFailure('UPSTREAM_500', error.message, 500);
      }
      if (!execution || typeof execution.output !== 'string') {
        return finishFailure('INVALID_EXECUTOR_RESULT', 'executor must return { output: string }', 500);
      }
      await lifecycleFaults.afterExecutorReturned?.({ idempotencyKey: key, executionAttemptId });

      const allocation = allocateExternalGross({
        grossAtomic: BigInt(payment.amountAtomic),
        executionCostAtomic: 0n,
        settlementCostAtomic: 0n,
        protocolFeeBps: 250,
        refundReserveAtomic: 0n,
        leafSkillId: SKILL_ID,
        skills: royaltyGraph,
      });
      journal.finishExecution(key, {
        executionAttemptId,
        outcome: 'succeeded',
        failureClass: null,
        message: null,
        outcomeHash: hash(execution.output),
        accounting: serializeAccounting(allocation),
      });
      await lifecycleFaults.afterExecutionFinished?.({ idempotencyKey: key, executionAttemptId });
      return c.json({ output: execution.output, receipt: journal.issueReceipt(key) });
    },
  );

  return { app, journal, skillVersionHash };
}
```

The zero execution-cost allocation is temporary and explicitly replaced by the
COGS-aware plan. It is accurate as a synthetic mock assumption and is never used to
claim live margin.

- [ ] **Step 5: Return the journal from the boot helper**

Replace `startCollar` with:

```js
export function startCollar({ port = 0, ...opts } = {}) {
  const { app, journal, skillVersionHash } = createCollar(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port }, (info) => {
      resolve({
        url: `http://127.0.0.1:${info.port}`,
        port: info.port,
        journal,
        skillVersionHash,
        signingPublicKeyPem: journal.signingPublicKeyPem,
        signingKeyId: journal.signingKeyId,
        close: () => server.close(),
      });
    });
  });
}
```

The standalone boot block may continue to consume only `startCollar(...).url`, but
startup now fails unless `COLLAR_JOURNAL_FILE` and `COLLAR_SIGNING_KEY_FILE` are both
absent (ephemeral mock) or both set to explicit absolute paths outside the checkout.

The atomic journal claim prevents duplicate calls by this Collar after the claim is
visible. `executionAttemptId` is also passed to the provider adapter as an idempotency
token where supported. This is not a categorical provider exactly-once guarantee: a
crash with state `executing` stays unresolved and returns 503 until a future trusted
executor-result resolver reconciles it.

- [ ] **Step 6: Run the failure test**

Run: `node --test spikes/pi-wielder/tests/collar-failure.test.mjs`

Expected: PASS, 6 tests and 0 failures. The fault cases contain one settled event per
Invocation, the atomic execution claim permits only one provider call, a crash after
provider return remains explicitly unresolved, and a crash after terminal persistence
issues the missing receipt on retry without re-execution.

- [ ] **Step 7: Commit authoritative Collar receipts**

```bash
git add spikes/pi-wielder/src/collar.mjs spikes/pi-wielder/tests/collar-failure.test.mjs
git commit -m "feat: issue authoritative Collar receipts"
```

### Task 4: Demote the Wielder ledger to a receipt view

**Files:**
- Modify: `spikes/pi-wielder/src/ledger.mjs:1-46`
- Modify: `spikes/pi-wielder/src/proxy.mjs:95-135`
- Modify: `spikes/pi-wielder/e2e.mjs:114-137`
- Create: `spikes/pi-wielder/tests/proxy-trust.test.mjs`

- [ ] **Step 1: Write failing receipt-view assertions in the e2e**

Add this import to `spikes/pi-wielder/e2e.mjs`:

```js
import { verifySignedReceipt } from './src/invocation-journal.mjs';
```

Pass the Collar trust anchor when starting the e2e proxy:

```js
  trustedCollarPublicKeyPem: collar.signingPublicKeyPem,
  trustedCollarKeyId: collar.signingKeyId,
```

In the direct unpaid-request loop, preserve the 402 contract by adding a unique key:

```js
headers: {
  'content-type': 'application/json',
  'Idempotency-Key': `unpaid-${name}`,
},
```

After the existing `eq(entries.map((e) => e.leg), ...)` assertion, add:

```js
  ok(entries.every((entry) => entry.view === 'wielder-receipt'), 'Wielder entries identify themselves as receipt views');
  ok(entries.every((entry) => entry.status === 'succeeded'), 'successful calls retain terminal status');
  ok(entries[2].receipt != null, 'Skill entry caches the signed Collar receipt');
  ok(verifySignedReceipt(entries[2].receipt, {
    publicKeyPem: collar.signingPublicKeyPem,
    keyId: collar.signingKeyId,
  }), 'cached Collar receipt verifies against the pinned Collar key');
  eq(
    entries[2].receipt.receipt.invocationId,
    collar.journal.getByTxHash(entries[2].txHash).invocationId,
    'Wielder view points to the authoritative Collar Invocation',
  );
```

Replace the old display-number amount assertion with:

```js
  eq(entries.map((entry) => entry.amountAtomic), [
    usdcToAtomic(MODEL_PRICES_USDC.claude),
    usdcToAtomic(MODEL_PRICES_USDC.gpt),
    usdcToAtomic('0.25'),
  ], 'atomic amounts match the quoted 402 offers');
```

Replace the old split-equivalence assertion with:

```js
  const receiptAccounting = entries[2].receipt.receipt.accounting;
  eq(entries[2].splits, [
    ...receiptAccounting.holderCredits.map((credit) => ({
      party: credit.recipientId,
      amountAtomic: credit.amountAtomic,
    })),
    { party: 'treasury', amountAtomic: receiptAccounting.protocolFeeAtomic },
  ], 'rendered splits are derived only from the signed Collar receipt');
  eq(entries[2].receipt, skill.json.receipt, 'response and Wielder cache contain the same signed receipt');
```

Remove imports and setup that recompute the split through
`prototype/settlement-engine.mjs`; the Collar receipt is now the authority.

- [ ] **Step 2: Run e2e and verify the proxy still drops failure receipts and old split fields differ**

Run: `npm run e2e --prefix spikes/pi-wielder`

Expected: FAIL on the new `view`, `status`, or signed-receipt assertions.

- [ ] **Step 3: Replace `ledger.mjs` with a receipt-view implementation**

Replace `spikes/pi-wielder/src/ledger.mjs` with:

```js
import fs from 'node:fs';
import { formatUsdc } from '../../../prototype/atomic-money.mjs';

export function createLedger(filePath = null) {
  const entries = [];
  return {
    entries,
    record(entry) {
      if (entry.view !== 'wielder-receipt') throw new Error("Wielder ledger entries must use view 'wielder-receipt'");
      const full = { ts: new Date().toISOString(), ...entry };
      entries.push(full);
      if (filePath) fs.appendFileSync(filePath, `${JSON.stringify(full)}\n`);
      return full;
    },
  };
}

const display = (amountAtomic) => `$${formatUsdc(BigInt(amountAtomic)).replace(/0+$/, '').replace(/\.$/, '')}`;

export function renderLedger(entries) {
  if (!entries.length) return '(empty Wielder receipt view)';
  const parts = entries.map((entry) => {
    let line = `${entry.label} ${display(entry.amountAtomic)} [${entry.status}]`;
    if (entry.splits?.length) {
      line += ` → ${entry.splits.map((split) => `${split.party} ${display(split.amountAtomic)}`).join(' / ')}`;
    }
    return line;
  });
  const totalAtomic = entries.reduce((sum, entry) => sum + BigInt(entry.amountAtomic), 0n);
  return `${parts.join(' · ')}\n  session receipt total ${display(totalAtomic)} across ${entries.length} settled calls, one wallet`;
}
```

- [ ] **Step 4: Record every settled response, including failures, from returned receipts**

Import receipt verification in `proxy.mjs`:

```js
import fs from 'node:fs';
import path from 'node:path';
import { verifySignedReceipt } from './invocation-journal.mjs';
```

Add this startup-only trust loader. It reads a configured public key; it never reads
trust material from an x402 challenge, response body, or receipt:

```js
export function loadPinnedCollarTrust(env = process.env) {
  const publicKeyFile = env.COLLAR_PUBLIC_KEY_FILE || null;
  const expectedKeyId = env.COLLAR_KEY_ID || null;
  if (!publicKeyFile || !expectedKeyId) {
    throw new Error('Skill routes require COLLAR_PUBLIC_KEY_FILE and COLLAR_KEY_ID');
  }
  if (!path.isAbsolute(publicKeyFile)) throw new Error('COLLAR_PUBLIC_KEY_FILE must be absolute');
  const publicKeyPem = fs.readFileSync(publicKeyFile, 'utf8');
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const actualKeyId = `sha256:${crypto.createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' })).digest('hex')}`;
  if (actualKeyId !== expectedKeyId) throw new Error('COLLAR_KEY_ID does not match COLLAR_PUBLIC_KEY_FILE');
  return { trustedCollarPublicKeyPem: publicKeyPem, trustedCollarKeyId: expectedKeyId };
}

export function assertReceiptMatchesPayment(bundle, expected) {
  const receipt = bundle?.receipt;
  const lower = (value) => String(value ?? '').toLowerCase();
  if (!receipt
    || receipt.idempotencyKey !== expected.idempotencyKey
    || receipt.requestHash !== expected.requestHash
    || receipt.quote?.requestHash !== expected.requestHash
    || receipt.quote?.quoteId !== expected.quoteId
    || receipt.quote?.amountAtomic !== expected.amountAtomic
    || lower(receipt.wielderId) !== lower(expected.payer)
    || lower(receipt.payment?.payer) !== lower(expected.payer)
    || lower(receipt.payment?.settlementReference) !== lower(expected.settlementReference)
    || lower(receipt.payment?.txHash) !== lower(expected.txHash)) {
    throw new Error('signed Collar receipt does not semantically match the current paid request');
  }
  return receipt;
}
```

Add `trustedCollarPublicKeyPem` and `trustedCollarKeyId` to `createProxy` options and
keep them in its closure. Put the first guard at the start of `createProxy`; this proxy
always exposes `/invoke/*` Skill routes. Put the second guard immediately after
`const receipt = parsed.receipt ?? null;` in the Skill response branch:

```js
  if (!trustedCollarPublicKeyPem || !trustedCollarKeyId) {
    throw new Error('Skill routes require a pinned Collar public key and key ID');
  }

      if (leg === 'skill') {
        if (!receipt || !trustedCollarPublicKeyPem || !trustedCollarKeyId) {
          throw new Error('Skill receipt requires a configured Collar trust anchor');
        }
        if (!verifySignedReceipt(receipt, {
          publicKeyPem: trustedCollarPublicKeyPem,
          keyId: trustedCollarKeyId,
        })) {
          throw new Error('Skill receipt signature does not match the pinned Collar key');
        }
        assertReceiptMatchesPayment(receipt, {
          idempotencyKey, requestHash, quoteId, amountAtomic,
          payer, settlementReference, txHash,
        });
      }
```

The receipt bundle's `keyId` is an identifier, not a trust anchor; the proxy never
uses a public key supplied inside the same response.

Replace the standalone boot call with:

```js
  const trust = loadPinnedCollarTrust(process.env);
  const { url, account } = await startProxy({
    port: Number(process.env.PROXY_PORT || 8402),
    ...trust,
  });
```

In the proxy `forward` handler, destructure these additional `payingFetch` fields:

```js
    const {
      res, paid, xPayment, idempotencyKey, amountAtomic, txHash, payer,
      requestHash, quoteId, settlementReference, timings,
    } = await payingFetch(account, `${upstreamBase}${path}`, {
```

Replace the `if (paid && res.ok) { ... }` block with:

```js
    if (paid && txHash) {
      let parsed = {};
      try { parsed = JSON.parse(resBody); } catch { /* SSE responses have no receipt body */ }
      const model = JSON.parse(bodyText || '{}').model ?? '';
      const label = leg === 'skill'
        ? `skill/${path.split('/').pop()}`
        : `${model.startsWith('claude') ? 'claude' : 'gpt'}/${c.req.header('x-session-label') || 'chat'}`;
      const receipt = parsed.receipt ?? null;
      const accounting = receipt?.receipt?.accounting ?? null;
      const splits = accounting ? [
        ...(accounting.holderCredits ?? []).map((credit) => ({
          party: credit.recipientId,
          amountAtomic: credit.amountAtomic,
        })),
        ...(accounting.ancestorCredits ?? []).map((credit) => ({
          party: credit.recipientId,
          amountAtomic: credit.amountAtomic,
        })),
        { party: 'treasury', amountAtomic: accounting.protocolFeeAtomic },
      ] : null;
      ledger.record({
        view: 'wielder-receipt',
        idempotencyKey,
        leg,
        label,
        amountAtomic,
        txHash,
        status: receipt?.receipt?.execution?.state ?? (res.ok ? 'succeeded' : 'failed'),
        receipt,
        splits,
      });
    }
```

Do not calculate or accept caller-supplied splits anywhere in the Wielder.

- [ ] **Step 5: Run the e2e and failure tests**

Create `spikes/pi-wielder/tests/proxy-trust.test.mjs`:

```js
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, createReceiptSigner, verifySignedReceipt } from '../src/invocation-journal.mjs';
import { assertReceiptMatchesPayment, createProxy, loadPinnedCollarTrust } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';

test('proxy startup accepts only an explicitly pinned public key and matching key ID', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'collar-public-'));
  const publicKeyFile = path.join(dir, 'collar-public.pem');
  const signer = createReceiptSigner();
  fs.writeFileSync(publicKeyFile, signer.publicKeyPem);
  const trust = loadPinnedCollarTrust({ COLLAR_PUBLIC_KEY_FILE: publicKeyFile, COLLAR_KEY_ID: signer.keyId });
  assert.equal(trust.trustedCollarKeyId, signer.keyId);
  assert.doesNotThrow(() => createProxy({ account: throwawayAccount(), ...trust }));
  assert.throws(() => loadPinnedCollarTrust({ COLLAR_PUBLIC_KEY_FILE: publicKeyFile }), /require/);
  assert.throws(() => loadPinnedCollarTrust({
    COLLAR_PUBLIC_KEY_FILE: publicKeyFile,
    COLLAR_KEY_ID: `sha256:${'0'.repeat(64)}`,
  }), /does not match/);
  assert.throws(() => createProxy({ account: throwawayAccount() }), /pinned Collar/);
});

test('a validly signed but stale receipt cannot be cached for a different paid request', () => {
  const signer = createReceiptSigner();
  const expected = {
    idempotencyKey: 'idem-current',
    requestHash: `sha256:${'1'.repeat(64)}`,
    quoteId: `sha256:${'2'.repeat(64)}`,
    amountAtomic: '250000',
    payer: `0x${'a'.repeat(40)}`,
    settlementReference: `0x${'b'.repeat(64)}`,
    txHash: `0x${'c'.repeat(64)}`,
  };
  const staleReceipt = {
    idempotencyKey: 'idem-previous',
    requestHash: expected.requestHash,
    quote: { requestHash: expected.requestHash, quoteId: expected.quoteId, amountAtomic: expected.amountAtomic },
    wielderId: expected.payer,
    payment: {
      payer: expected.payer,
      settlementReference: expected.settlementReference,
      txHash: expected.txHash,
    },
  };
  const receiptHash = crypto.createHash('sha256').update(canonicalJson(staleReceipt)).digest('hex');
  const bundle = {
    receipt: staleReceipt,
    receiptHash,
    signature: signer.signHash(receiptHash),
    algorithm: signer.algorithm,
    keyId: signer.keyId,
  };
  assert.equal(verifySignedReceipt(bundle, { publicKeyPem: signer.publicKeyPem, keyId: signer.keyId }), true);
  assert.throws(() => assertReceiptMatchesPayment(bundle, expected), /does not semantically match/);
});
```

Run: `npm run e2e --prefix spikes/pi-wielder && node --test spikes/pi-wielder/tests/collar-failure.test.mjs spikes/pi-wielder/tests/proxy-trust.test.mjs`

Expected: both commands PASS. The e2e prints a final green check count; the failure
test proves the signed failed receipt is preserved independently of HTTP success.

- [ ] **Step 6: Commit the receipt view**

```bash
git add spikes/pi-wielder/src/ledger.mjs spikes/pi-wielder/src/proxy.mjs spikes/pi-wielder/e2e.mjs spikes/pi-wielder/tests/proxy-trust.test.mjs
git commit -m "feat: make Wielder ledger a receipt view"
```

### Task 5: Verify persistence, reconciliation, and protected boundaries

**Files:**
- Modify: `spikes/pi-wielder/README.md:1-35`
- Modify: `spikes/pi-wielder/.env.example`
- Modify: `spikes/pi-wielder/RUNBOOK.md`

- [ ] **Step 1: Replace “unified ledger authority” wording**

Insert this section near the start of `spikes/pi-wielder/README.md` and remove any
sentence claiming the Wielder ledger is authoritative or that only successful calls
are paid:

```markdown
## Accounting authority

The Collar's append-only Invocation journal is authoritative. It records payment and
execution as independent state machines, so a settled Invocation remains recorded when
execution fails or the seller response is lost. The Wielder's `/ledger` endpoint is a
session receipt view: it caches Collar-signed receipts and renders their allocations,
but it does not calculate Royalty-claim splits.

Mock receipts use an ephemeral Ed25519 Collar key and deterministic mock settlement.
They are synthetic protocol evidence, not proof of live funds, mainnet readiness,
custody posture, or production key durability.
```

Append this safe-default configuration to `.env.example` (leave every path/identifier
blank in the tracked template):

```dotenv
# Offline mock settlement is the default. Set 1 only for an approved Base Sepolia run.
ALLOW_LIVE_X402=0
# Persistence is opt-in and paired. Both absolute paths must be outside the checkout.
COLLAR_JOURNAL_FILE=
COLLAR_SIGNING_KEY_FILE=
# Wielder trust is public-key-only and must match the expected key ID.
COLLAR_PUBLIC_KEY_FILE=
COLLAR_KEY_ID=
```

In `RUNBOOK.md`, document that a persistent Collar refuses to start unless the journal
and private signing-key paths are both explicit and absolute outside the checkout, the
proxy refuses Skill routes without the public key file plus expected key ID, and private
key material is never copied into the repository. Add this standalone selection helper
to `collar.mjs` and use it in the boot block:

```js
export async function chooseFacilitator({
  env = process.env,
  startMock = async () => (await import('./facilitator-mock.mjs')).createMockFacilitator(),
} = {}) {
  if (env.ALLOW_LIVE_X402 !== '1') {
    const app = await startMock();
    return {
      transport: createMockFacilitatorTransport((url, init) => app.request(url, init)),
      mode: 'mock',
    };
  }
  if (!env.FACILITATOR_URL) throw new Error('ALLOW_LIVE_X402=1 requires an explicit Base Sepolia FACILITATOR_URL');
  return {
    transport: createLiveFacilitatorTransport(env.FACILITATOR_URL),
    mode: 'approved-base-sepolia',
  };
}
```

The standalone block calls `chooseFacilitator()`; remove the old fallback to
`https://x402.org/facilitator`, passes only `selected.transport` into `createCollar`, and
never passes a URL from env directly. Add a focused test with an injected `startMock`
spy that proves empty/default env selects the injected app and never constructs a live
facilitator call. Live env succeeds only when `FACILITATOR_URL` equals
`APPROVED_LIVE_FACILITATOR_BASE` byte-for-byte.

- [ ] **Step 2: Run all focused tests**

Run: `npm test --prefix spikes/pi-wielder`

Expected: PASS for journal, x402 lifecycle, and Collar failure tests; 0 failures.

- [ ] **Step 3: Run the original offline proof**

Run: `npm run e2e --prefix spikes/pi-wielder`

Expected: PASS with three settled calls, one signed Skill receipt, exact atomic split
conservation, and no network/key/fund requirement.

- [ ] **Step 4: Prove a response lookup does not append or debit**

Run: `node --test --test-name-pattern="settled-then-500" spikes/pi-wielder/tests/collar-failure.test.mjs`

Expected: PASS; the assertion finds one and only one `payment.settled` event before
and after the receipt lookup.

- [ ] **Step 5: Confirm secrets and mainnet did not enter tracked files**

Run: `! git ls-files -z | xargs -0 rg -n --pcre2 '-----BEGIN (?:PRIVATE|ENCRYPTED PRIVATE) KEY-----|PRIVATE_KEY\s*=\s*(?:0x)?[0-9a-fA-F]{64}'`

Expected: no output. The existing ignored local `.env` remains untouched.

- [ ] **Step 6: Commit the authority documentation**

```bash
git add spikes/pi-wielder/README.md spikes/pi-wielder/RUNBOOK.md spikes/pi-wielder/.env.example spikes/pi-wielder/src/collar.mjs
git commit -m "docs: define Collar journal authority"
```

## Definition of done

- Every external Invocation uses one client-generated idempotency key from 402 challenge through retry and receipt.
- The Collar journal is durably appended under a same-host process lock/CAS, fsynced,
  hash-chained, signed per event, strict-transition replayed, and indexes settlement/tx references.
- A settled-then-500 record retains the transaction hash and terminal `failed` outcome.
- `GET /receipts/by-settlement/:reference` is read-only. An unresolved settlement advances only through `POST /reconcile/by-settlement/:reference`, whose injected trusted resolver verifies reference, payer, amount, and transaction evidence without accepting a client-supplied txHash.
- After trusted reconciliation, an exact retry reuses the settled credential once; later exact retries return the identical cached signed receipt without facilitator settlement or Skill execution.
- One atomic `executionAttemptId` claim permits one local provider call; overlapping
  retries and restart while `executing` return unresolved rather than re-executing.
- Method, resource URL, and exact body bytes are bound into `requestHash`; a conflicting body under the same idempotency key fails before settlement or execution.
- Exact duplicate operations are no-ops; conflicting reuse of an idempotency key, settlement reference, or transaction hash fails closed.
- The signed receipt binds Skill/version, quote, payer, payment, execution, accounting, timestamps, and terminal sequence.
- Receipt verification pins a separately configured Collar public key and key ID; a key named by the receipt cannot authenticate itself. Persistent journals require paired explicit absolute journal/private-key paths outside the checkout; ephemeral signing is in-memory mock-only.
- A confirmed refund carries its trusted reference and exact atomic amount in a new signed receipt revision that supersedes—but does not delete—the prior receipt.
- Refund v1 is serialized through the journal append lock and is legal only for a settled,
  terminal failed Invocation whose accounting contains one full-gross reconciliation hold
  and no finalized claims. The signed revision carries the exact balanced hold reversal
  and refund-disbursement entries; authorized, executing, succeeded, partial, and
  unresolved-payment refunds fail closed.
- Live facilitator traffic is restricted to the one byte-exact approved HTTPS base and
  `/verify`/`/settle` paths with redirects disabled. Offline mock settlement is reachable
  only through the injected-app transport constructor; arbitrary env URLs never enter fetch.
- The Wielder cache displays signed receipts and never supplies authoritative splits.
- All automated verification uses the mock facilitator, a throwaway wallet, and an ephemeral signing key. No mainnet or real funds are used.

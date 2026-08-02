import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { createReceiptSigner } from '../src/kernel/receipt-signing.mjs';
import {
  buildEvidenceBundle,
  verifyEvidenceBundle,
} from '../src/evidence-bundle.mjs';

const NODE = process.execPath;
const PACKAGE_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const NOW = '2026-07-31T12:00:01.000Z';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const FILES = ['README.md', 'events.jsonl', 'manifest.json', 'report.md', 'summary.json'];
const ENFORCED_PROBES = {
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
};

function temporaryDirectory(t, prefix = 'wallet-kernel-evidence-test-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return directory;
}

function signedReceipt(signer, {
  id = 'receipt-1',
  intentId = 'intent-1',
  revision = 1,
  supersedesReceiptHash = null,
  transactionId = `0x${'ab'.repeat(32)}`,
  sessionId = 'session-1',
  mutateReceipt = () => {},
} = {}) {
  const receipt = {
    schemaVersion: 1,
    receiptId: id,
    revision,
    issuedAt: NOW,
    intent: {
      id: intentId,
      requestId: `request-${intentId}`,
      intentHash: sha256(`intent:${intentId}`),
      sessionId,
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
      payTo: '0x2000000000000000000000000000000000000000',
      transactionId,
    },
    execution: {
      state: 'succeeded',
      httpStatus: 200,
      responseHash: sha256('sanitized-response'),
    },
    budget: { disposition: 'committed', amountAtomic: '50000' },
    reconciliation: null,
    refund: null,
    supersedesReceiptHash,
  };
  mutateReceipt(receipt);
  const receiptHash = crypto.createHash('sha256').update(canonicalJson(receipt)).digest('hex');
  return {
    id,
    intentId,
    revision,
    receipt,
    receiptHash,
    signature: signer.signHash(receiptHash),
    algorithm: 'Ed25519',
    keyId: signer.keyId,
    supersedesReceiptHash,
    createdAt: NOW,
  };
}

function signedProjection(signer, {
  authorityHead,
  policyHash,
  receipts,
  agentUid = '501',
  agentGid = '20',
  isolationStatus = 'simulated',
  preflightDigest = null,
  sessionId = 'session-1',
}) {
  const projection = {
    schemaVersion: 1,
    domain: 'wallet-kernel.sanitized-projection.v1',
    sessionHash: sha256(canonicalJson({
      domain: 'wallet-kernel.session-identity.v1',
      sessionId,
    })),
    wallet: { address: WALLET, adapterHash: sha256('adapter') },
    agentEnrollment: {
      enrollmentHash: sha256('enrollment'),
      identityHash: sha256(canonicalJson({
        domain: 'wallet-kernel.agent-identity.v1',
        agentUid,
        agentGid,
      })),
      state: 'active',
    },
    isolation: { status: isolationStatus, preflightDigest },
    policies: {
      activePolicyHash: policyHash,
      sessionPolicyHash: policyHash,
      historyHashes: [policyHash],
    },
    signedReceipts: receipts,
    eventHeadHash: authorityHead,
    issuedAt: NOW,
  };
  const unsigned = {
    schemaVersion: 1,
    domain: 'wallet-kernel.projection-export.v1',
    projection,
    algorithm: 'Ed25519',
    keyId: signer.keyId,
    publicKeyPem: signer.publicKeyPem,
  };
  const projectionHash = sha256(canonicalJson(unsigned));
  return {
    ...unsigned,
    projectionHash,
    signature: signer.signHash(projectionHash.slice('sha256:'.length)),
  };
}

function projectionSetHash(signedProjections) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.signed-projection-set.v1',
    signedProjections,
  }));
}

function fixture({
  signer = createReceiptSigner(),
  replacement = false,
  mode = 'offline-deterministic',
} = {}) {
  const testnet = mode === 'base-sepolia-testnet';
  const authorityHead = sha256(replacement ? 'replacement-authority-head' : 'authority-head');
  const policyHash = sha256(replacement ? 'replacement-policy' : 'policy');
  const receipt = signedReceipt(signer, {
    id: replacement ? 'receipt-replacement' : 'receipt-1',
    intentId: replacement ? 'intent-replacement' : 'intent-1',
    transactionId: `0x${(replacement ? 'cd' : 'ab').repeat(32)}`,
  });
  const kernelIdentity = testnet ? { uid: '991', gid: '991' } : { uid: '501', gid: '20' };
  const agentIdentity = testnet ? { uid: '992', gid: '992' } : { uid: '501', gid: '20' };
  const deployment = testnet ? {
    status: 'enforced',
    releaseManifestDigest: sha256('release-manifest'),
    releaseTreeHash: sha256('release-tree'),
    serviceArtifactsHash: sha256('service-artifacts'),
    systemdEffectiveConfigHash: sha256('systemd-effective'),
  } : {
    status: 'simulated',
    releaseManifestDigest: null,
    releaseTreeHash: null,
    serviceArtifactsHash: null,
    systemdEffectiveConfigHash: null,
  };
  const privilegedReport = testnet ? {
    schemaVersion: 1,
    enrollmentHash: sha256('enrollment'),
    kernelUid: kernelIdentity.uid,
    kernelGid: kernelIdentity.gid,
    agentUid: agentIdentity.uid,
    agentGid: agentIdentity.gid,
    authorityMetadataHash: sha256('authority-metadata'),
    credentialMetadataHash: sha256('credential-metadata'),
    releaseManifestHash: deployment.releaseManifestDigest,
    releaseTreeHash: deployment.releaseTreeHash,
    nodeExecutableHash: sha256('node-executable'),
    serviceArtifactsHash: deployment.serviceArtifactsHash,
    systemdEffectiveConfigHash: deployment.systemdEffectiveConfigHash,
    environmentMetadataHash: sha256('environment-metadata'),
    probeResults: ENFORCED_PROBES,
    probedAt: '2026-07-31T11:59:00.000Z',
    expiresAt: '2026-07-31T12:10:00.000Z',
  } : null;
  const preflightDigest = privilegedReport === null
    ? null
    : sha256(canonicalJson(privilegedReport));
  const projection = signedProjection(signer, {
    authorityHead,
    policyHash,
    receipts: [receipt],
    agentUid: agentIdentity.uid,
    agentGid: agentIdentity.gid,
    isolationStatus: testnet ? 'enforced' : 'simulated',
    preflightDigest,
  });
  const kernelIdentityHash = sha256(canonicalJson({
    domain: 'wallet-kernel.kernel-identity.v1',
    kernelUid: kernelIdentity.uid,
    kernelGid: kernelIdentity.gid,
  }));
  return {
    receipts: [receipt],
    events: [
      {
        sequence: 1,
        eventType: 'policy.decided',
        entityHash: sha256(replacement ? 'replacement-intent' : 'intent-1'),
        decision: 'allow',
        amountAtomic: null,
        transactionId: null,
        receiptHash: null,
        receiptSignature: null,
      },
      {
        sequence: 2,
        eventType: 'payment.settled',
        entityHash: sha256(replacement ? 'replacement-payment' : 'payment-1'),
        decision: null,
        amountAtomic: '50000',
        transactionId: receipt.receipt.payment.transactionId,
        receiptHash: null,
        receiptSignature: null,
      },
      {
        sequence: 3,
        eventType: 'receipt.issued',
        entityHash: sha256(receipt.id),
        decision: null,
        amountAtomic: null,
        transactionId: null,
        receiptHash: receipt.receiptHash,
        receiptSignature: receipt.signature,
      },
    ],
    manifestInput: {
      schemaVersion: 2,
      createdAt: NOW,
      mode,
      git: { commit: replacement ? 'b'.repeat(40) : 'a'.repeat(40), dirty: !testnet },
      runtime: { nodeVersion: testnet ? 'v24.18.1' : process.version, piVersion: '0.80.6' },
      protocol: { x402Version: 2, network: NETWORK, asset: ASSET },
      wallet: {
        provider: testnet ? 'cdp' : 'deterministic',
        walletIdHash: sha256(replacement ? 'wallet-replacement' : 'wallet-1'),
        address: WALLET,
      },
      isolation: {
        status: testnet ? 'enforced' : 'simulated',
        preflightDigest,
        kernelIdentityHash,
        agentIdentityHash: projection.projection.agentEnrollment.identityHash,
      },
      deployment,
      inputs: { policyHash, routeMapHash: sha256('routes'), configHash: sha256('config') },
      source: {
        authorityEventHeadHash: authorityHead,
        signedProjectionHash: projectionSetHash([projection]),
        receiptKeys: [{
          keyId: signer.keyId,
          algorithm: 'Ed25519',
          publicKeyPem: signer.publicKeyPem,
        }],
      },
      status: testnet
        ? { liveCdp: 'passed', walletFunded: 'sufficient', testnetTransaction: 'settled' }
        : { liveCdp: 'not-run', walletFunded: 'not-run', testnetTransaction: 'not-run' },
      identityBindings: {
        kernel: kernelIdentity,
        agent: agentIdentity,
      },
      privilegedReport,
      signedProjections: [projection],
    },
  };
}

function multiSessionFixture({ crossed = false } = {}) {
  const signer = createReceiptSigner();
  const input = fixture({ signer });
  const authorityHead = input.manifestInput.source.authorityEventHeadHash;
  const policyHash = input.manifestInput.inputs.policyHash;
  const first = input.receipts[0];
  const second = signedReceipt(signer, {
    id: 'receipt-2',
    intentId: 'intent-2',
    sessionId: 'session-2',
    transactionId: `0x${'cd'.repeat(32)}`,
  });
  const shared = {
    authorityHead,
    policyHash,
    agentUid: input.manifestInput.identityBindings.agent.uid,
    agentGid: input.manifestInput.identityBindings.agent.gid,
  };
  const firstProjection = signedProjection(signer, {
    ...shared,
    sessionId: 'session-1',
    receipts: [crossed ? second : first],
  });
  const secondProjection = signedProjection(signer, {
    ...shared,
    sessionId: 'session-2',
    receipts: [crossed ? first : second],
  });
  input.receipts = [first, second];
  input.events.push(
    {
      sequence: 4,
      eventType: 'payment.settled',
      entityHash: sha256('payment-2'),
      decision: null,
      amountAtomic: '50000',
      transactionId: second.receipt.payment.transactionId,
      receiptHash: null,
      receiptSignature: null,
    },
    {
      sequence: 5,
      eventType: 'receipt.issued',
      entityHash: sha256(second.id),
      decision: null,
      amountAtomic: null,
      transactionId: null,
      receiptHash: second.receiptHash,
      receiptSignature: second.signature,
    },
  );
  input.manifestInput.signedProjections = [firstProjection, secondProjection].sort(
    (left, right) => left.projection.sessionHash.localeCompare(right.projection.sessionHash),
  );
  input.manifestInput.source.signedProjectionHash = projectionSetHash(
    input.manifestInput.signedProjections,
  );
  return input;
}

function build(t, options = {}) {
  const parent = temporaryDirectory(t);
  const outputDirectory = path.join(parent, 'bundle');
  const input = fixture(options);
  const result = buildEvidenceBundle({ outputDirectory, ...input });
  return { ...input, ...result, outputDirectory, parent };
}

function rewriteManifest(directory, mutate) {
  const manifestPath = path.join(directory, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  mutate(manifest);
  const bytes = Buffer.from(`${canonicalJson(manifest)}\n`);
  fs.writeFileSync(manifestPath, bytes);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

function updateListedFile(directory, filename, bytes) {
  fs.writeFileSync(path.join(directory, filename), bytes);
  return rewriteManifest(directory, (manifest) => {
    const entry = manifest.files.find(({ path: entryPath }) => entryPath === filename);
    entry.bytes = bytes.length;
    entry.sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
  });
}

test('build writes exactly five canonical files and independent verification recomputes evidence', (t) => {
  const built = build(t);
  assert.deepEqual(fs.readdirSync(built.outputDirectory).sort(), FILES);
  assert.match(built.manifestSha256, /^[0-9a-f]{64}$/);

  const verified = verifyEvidenceBundle(built.outputDirectory, {
    expectedManifestSha256: built.manifestSha256,
  });
  assert.deepEqual(verified, {
    valid: true,
    mode: 'offline-deterministic',
    manifestSha256: built.manifestSha256,
    authorityEventHeadHash: built.manifestInput.source.authorityEventHeadHash,
    normalizedEvidenceHeadHash: verified.normalizedEvidenceHeadHash,
    eventCount: 3,
    decisionCount: 1,
    latestReceiptSettledGrossAtomic: '50000',
    latestReceiptConfirmedRefundAtomic: '0',
    latestReceiptUnresolvedExposureAtomic: '0',
    transactionCount: 1,
    receiptCount: 1,
    liveCdp: 'not-run',
    walletFunded: 'not-run',
    testnetTransaction: 'not-run',
  });
  assert.match(verified.normalizedEvidenceHeadHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(fs.readFileSync(path.join(built.outputDirectory, 'report.md'), 'utf8'),
    /does not recompute the private SQLite authority chain/i);
});

test('financial summary uses latest signed receipts instead of repeated lifecycle amounts', (t) => {
  const parent = temporaryDirectory(t);
  const outputDirectory = path.join(parent, 'bundle');
  const input = fixture();
  input.events[2].sequence = 4;
  input.events.splice(2, 0, {
    sequence: 3,
    eventType: 'budget.committed',
    entityHash: sha256('budget-1'),
    decision: null,
    amountAtomic: '50000',
    transactionId: null,
    receiptHash: null,
    receiptSignature: null,
  });
  const built = buildEvidenceBundle({ outputDirectory, ...input });
  const verified = verifyEvidenceBundle(outputDirectory, {
    expectedManifestSha256: built.manifestSha256,
  });
  assert.deepEqual({
    latestReceiptSettledGrossAtomic: verified.latestReceiptSettledGrossAtomic,
    latestReceiptConfirmedRefundAtomic: verified.latestReceiptConfirmedRefundAtomic,
    latestReceiptUnresolvedExposureAtomic: verified.latestReceiptUnresolvedExposureAtomic,
  }, {
    latestReceiptSettledGrossAtomic: '50000',
    latestReceiptConfirmedRefundAtomic: '0',
    latestReceiptUnresolvedExposureAtomic: '0',
  });
  const report = fs.readFileSync(path.join(outputDirectory, 'report.md'), 'utf8');
  assert.doesNotMatch(report, /atomic amount total/i);
  assert.match(report, /latest signed receipt revision for each intent/i);
});

test('financial summary separates settled gross, confirmed refunds, and unresolved exposure', (t) => {
  const signer = createReceiptSigner();
  const input = fixture({ signer });
  const first = input.receipts[0];
  const refundTransactionId = `0x${'cd'.repeat(32)}`;
  const refunded = signedReceipt(signer, {
    id: 'receipt-2',
    intentId: first.intentId,
    revision: 2,
    supersedesReceiptHash: first.receiptHash,
    transactionId: first.receipt.payment.transactionId,
    mutateReceipt: (receipt) => {
      receipt.outcome = { status: 'refunded', reasonCode: 'REFUND_CONFIRMED' };
      receipt.execution = {
        state: 'failed',
        httpStatus: 503,
        responseHash: null,
      };
      receipt.budget = { disposition: 'released', amountAtomic: '50000' };
      receipt.reconciliation = {
        kind: 'refund',
        outcome: 'refund_confirmed',
        operatorIdHash: sha256('refund-operator'),
        recordedAt: NOW,
      };
      receipt.refund = {
        state: 'confirmed',
        amountAtomic: '50000',
        transactionId: refundTransactionId,
      };
    },
  });
  const unresolved = signedReceipt(signer, {
    id: 'receipt-3',
    intentId: 'intent-2',
    transactionId: null,
    mutateReceipt: (receipt) => {
      receipt.outcome = { status: 'payment_unresolved', reasonCode: 'PAID_RESPONSE_AMBIGUOUS' };
      receipt.payment.state = 'unresolved';
      receipt.execution = { state: 'none', httpStatus: null, responseHash: null };
      receipt.budget = { disposition: 'unresolved', amountAtomic: '50000' };
    },
  });
  input.receipts = [first, refunded, unresolved];
  input.events = [
    input.events[0],
    input.events[1],
    input.events[2],
    {
      sequence: 4,
      eventType: 'refund.confirmed',
      entityHash: sha256('refund-1'),
      decision: null,
      amountAtomic: '50000',
      transactionId: refundTransactionId,
      receiptHash: null,
      receiptSignature: null,
    },
    ...[refunded, unresolved].map((receipt, index) => ({
      sequence: index + 5,
      eventType: 'receipt.issued',
      entityHash: sha256(receipt.id),
      decision: null,
      amountAtomic: null,
      transactionId: null,
      receiptHash: receipt.receiptHash,
      receiptSignature: receipt.signature,
    })),
  ];
  const projection = signedProjection(signer, {
    authorityHead: input.manifestInput.source.authorityEventHeadHash,
    policyHash: input.manifestInput.inputs.policyHash,
    receipts: input.receipts,
  });
  input.manifestInput.signedProjections = [projection];
  input.manifestInput.source.signedProjectionHash = projectionSetHash([projection]);
  const outputDirectory = path.join(temporaryDirectory(t), 'bundle');
  const built = buildEvidenceBundle({ outputDirectory, ...input });
  const verified = verifyEvidenceBundle(outputDirectory, {
    expectedManifestSha256: built.manifestSha256,
  });
  assert.deepEqual({
    latestReceiptSettledGrossAtomic: verified.latestReceiptSettledGrossAtomic,
    latestReceiptConfirmedRefundAtomic: verified.latestReceiptConfirmedRefundAtomic,
    latestReceiptUnresolvedExposureAtomic: verified.latestReceiptUnresolvedExposureAtomic,
  }, {
    latestReceiptSettledGrossAtomic: '50000',
    latestReceiptConfirmedRefundAtomic: '50000',
    latestReceiptUnresolvedExposureAtomic: '50000',
  });
});

test('normalized evidence rejects an omitted leading or interior authority event', (t) => {
  for (const omittedIndex of [0, 1]) {
    const input = fixture();
    input.events.splice(omittedIndex, 1);
    assert.throws(() => buildEvidenceBundle({
      outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
      ...input,
    }), { code: 'EVIDENCE_EVENT_SCHEMA' });
  }
});

test('v2 evidence authenticates a canonical multi-session projection partition', (t) => {
  const outputDirectory = path.join(temporaryDirectory(t), 'bundle');
  const input = multiSessionFixture();
  const built = buildEvidenceBundle({ outputDirectory, ...input });
  const verified = verifyEvidenceBundle(outputDirectory, {
    expectedManifestSha256: built.manifestSha256,
  });
  assert.equal(verified.receiptCount, 2);
  const summary = JSON.parse(fs.readFileSync(path.join(outputDirectory, 'summary.json')));
  assert.equal(summary.schemaVersion, 2);
  assert.equal(summary.signedProjections.length, 2);
  assert.equal(
    summary.signedProjections[0].projection.sessionHash
      .localeCompare(summary.signedProjections[1].projection.sessionHash) < 0,
    true,
  );
});

test('v2 evidence rejects projection omission, duplication, and cross-session receipts', (t) => {
  const variants = [
    (input) => {
      input.manifestInput.signedProjections.pop();
      input.manifestInput.source.signedProjectionHash = projectionSetHash(
        input.manifestInput.signedProjections,
      );
    },
    (input) => {
      input.manifestInput.signedProjections.push(input.manifestInput.signedProjections[0]);
      input.manifestInput.signedProjections.sort((left, right) => (
        left.projection.sessionHash.localeCompare(right.projection.sessionHash)
      ));
      input.manifestInput.source.signedProjectionHash = projectionSetHash(
        input.manifestInput.signedProjections,
      );
    },
  ];
  for (const mutate of variants) {
    const input = multiSessionFixture();
    mutate(input);
    assert.throws(() => buildEvidenceBundle({
      outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
      ...input,
    }), { code: 'EVIDENCE_PROJECTION_PARTITION' });
  }
  assert.throws(() => buildEvidenceBundle({
    outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
    ...multiSessionFixture({ crossed: true }),
  }), { code: 'EVIDENCE_PROJECTION_PARTITION' });
});

test('normalized evidence rejects transaction reuse instead of scrubbing a duplicate', (t) => {
  const input = fixture();
  input.events.push({
    sequence: 4,
    eventType: 'payment.settled',
    entityHash: sha256('duplicate-payment'),
    decision: null,
    amountAtomic: '50000',
    transactionId: input.events[1].transactionId,
    receiptHash: null,
    receiptSignature: null,
  });
  assert.throws(() => buildEvidenceBundle({
    outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
    ...input,
  }), { code: 'EVIDENCE_TRANSACTION_REUSE' });
});

test('verification requires the exact out-of-band manifest digest before trusting bundle bytes', (t) => {
  const built = build(t);
  for (const expectedManifestSha256 of [undefined, null, '', 'A'.repeat(64), '0'.repeat(63)]) {
    assert.throws(
      () => verifyEvidenceBundle(built.outputDirectory, { expectedManifestSha256 }),
      { code: 'EVIDENCE_EXTERNAL_ANCHOR' },
    );
  }
  assert.throws(
    () => verifyEvidenceBundle(built.outputDirectory, {
      expectedManifestSha256: '0'.repeat(64),
    }),
    { code: 'EVIDENCE_EXTERNAL_ANCHOR' },
  );

  const manifest = JSON.parse(fs.readFileSync(path.join(built.outputDirectory, 'manifest.json')));
  manifest.wallet.provider = 'substituted';
  fs.writeFileSync(
    path.join(built.outputDirectory, 'manifest.json'),
    `${canonicalJson(manifest)}\n`,
  );
  assert.throws(
    () => verifyEvidenceBundle(built.outputDirectory, {
      expectedManifestSha256: built.manifestSha256,
    }),
    { code: 'EVIDENCE_EXTERNAL_ANCHOR' },
  );
});

test('each non-manifest file fails verification when independently mutated', (t) => {
  for (const filename of FILES.filter((name) => name !== 'manifest.json')) {
    const built = build(t);
    fs.appendFileSync(path.join(built.outputDirectory, filename), 'tampered\n');
    assert.throws(
      () => verifyEvidenceBundle(built.outputDirectory, {
        expectedManifestSha256: built.manifestSha256,
      }),
      { code: 'EVIDENCE_FILE_HASH' },
      filename,
    );
  }
});

test('receipt, projection, and normalized-chain verification fail after internally re-anchored corruption', (t) => {
  {
    const built = build(t);
    const summaryPath = path.join(built.outputDirectory, 'summary.json');
    const summary = JSON.parse(fs.readFileSync(summaryPath));
    summary.receipts[0].signature = Buffer.alloc(64, 9).toString('base64');
    const anchor = updateListedFile(
      built.outputDirectory,
      'summary.json',
      Buffer.from(`${canonicalJson(summary)}\n`),
    );
    assert.throws(
      () => verifyEvidenceBundle(built.outputDirectory, { expectedManifestSha256: anchor }),
      { code: 'EVIDENCE_RECEIPT_SIGNATURE' },
    );
  }
  {
    const built = build(t);
    const summaryPath = path.join(built.outputDirectory, 'summary.json');
    const summary = JSON.parse(fs.readFileSync(summaryPath));
    summary.signedProjections[0].signature = Buffer.alloc(64, 7).toString('base64');
    const anchor = updateListedFile(
      built.outputDirectory,
      'summary.json',
      Buffer.from(`${canonicalJson(summary)}\n`),
    );
    assert.throws(
      () => verifyEvidenceBundle(built.outputDirectory, { expectedManifestSha256: anchor }),
      { code: 'EVIDENCE_PROJECTION_SIGNATURE' },
    );
  }
  {
    const built = build(t);
    const eventsPath = path.join(built.outputDirectory, 'events.jsonl');
    const events = fs.readFileSync(eventsPath, 'utf8').trimEnd().split('\n').map(JSON.parse);
    events[1].eventHash = sha256('forged-chain-head');
    const bytes = Buffer.from(`${events.map(canonicalJson).join('\n')}\n`);
    const anchor = updateListedFile(built.outputDirectory, 'events.jsonl', bytes);
    assert.throws(
      () => verifyEvidenceBundle(built.outputDirectory, { expectedManifestSha256: anchor }),
      { code: 'EVIDENCE_EVENT_CHAIN' },
    );
  }
});

test('receipt revisions require exact per-intent predecessor links', (t) => {
  const signer = createReceiptSigner();
  const input = fixture({ signer });
  const second = signedReceipt(signer, {
    id: 'receipt-2',
    revision: 2,
    supersedesReceiptHash: '0'.repeat(64),
  });
  input.receipts.push(second);
  input.manifestInput.signedProjections[0].projection.signedReceipts.push(second);
  assert.throws(
    () => buildEvidenceBundle({
      outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
      ...input,
    }),
    { code: 'EVIDENCE_RECEIPT_REVISION' },
  );
});

test('a substituted key pair or fully replaced bundle cannot satisfy the original trust anchor', (t) => {
  const original = build(t);
  const replacement = build(t, { signer: createReceiptSigner(), replacement: true });
  assert.notEqual(replacement.manifestSha256, original.manifestSha256);
  assert.throws(
    () => verifyEvidenceBundle(replacement.outputDirectory, {
      expectedManifestSha256: original.manifestSha256,
    }),
    { code: 'EVIDENCE_EXTERNAL_ANCHOR' },
  );
});

test('offline evidence rejects enforced isolation, deployment hashes, live status, and overwrite', (t) => {
  const variants = [
    (input) => { input.manifestInput.isolation.status = 'enforced'; },
    (input) => { input.manifestInput.isolation.preflightDigest = sha256('report'); },
    (input) => { input.manifestInput.deployment.releaseTreeHash = sha256('tree'); },
    (input) => { input.manifestInput.status.liveCdp = 'passed'; },
  ];
  for (const mutate of variants) {
    const input = fixture();
    mutate(input);
    assert.throws(
      () => buildEvidenceBundle({
        outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
        ...input,
      }),
      { code: 'EVIDENCE_MODE_GATE' },
    );
  }
  const built = build(t);
  assert.throws(
    () => buildEvidenceBundle({ outputDirectory: built.outputDirectory, ...fixture() }),
    { code: 'EVIDENCE_OUTPUT_EXISTS' },
  );
});

test('testnet evidence requires and re-verifies an unexpired deployment-bound privileged report', (t) => {
  const built = build(t, { mode: 'base-sepolia-testnet' });
  const verified = verifyEvidenceBundle(built.outputDirectory, {
    expectedManifestSha256: built.manifestSha256,
  });
  assert.equal(verified.mode, 'base-sepolia-testnet');
  assert.equal(verified.liveCdp, 'passed');
  assert.equal(verified.walletFunded, 'sufficient');
  assert.equal(verified.testnetTransaction, 'settled');

  const summaryPath = path.join(built.outputDirectory, 'summary.json');
  const summary = JSON.parse(fs.readFileSync(summaryPath));
  summary.isolationAttestation.expiresAt = NOW;
  const reanchored = updateListedFile(
    built.outputDirectory,
    'summary.json',
    Buffer.from(`${canonicalJson(summary)}\n`),
  );
  assert.throws(
    () => verifyEvidenceBundle(built.outputDirectory, {
      expectedManifestSha256: reanchored,
    }),
    { code: 'EVIDENCE_MODE_GATE' },
  );

  for (const mutate of [
    (input) => { input.manifestInput.privilegedReport.expiresAt = NOW; },
    (input) => { input.manifestInput.privilegedReport.releaseTreeHash = sha256('wrong-tree'); },
    (input) => { input.manifestInput.identityBindings.agent.uid = '993'; },
  ]) {
    const input = fixture({ mode: 'base-sepolia-testnet' });
    mutate(input);
    assert.throws(
      () => buildEvidenceBundle({
        outputDirectory: path.join(temporaryDirectory(t), 'bundle'),
        ...input,
      }),
      (error) => ['EVIDENCE_PREFLIGHT', 'EVIDENCE_IDENTITY'].includes(error.code),
    );
  }
});

test('raw content, credentials, provider failures, private keys, and local paths fail before write', (t) => {
  const mutations = [
    (input) => { input.manifestInput.signedProjections[0].projection.prompt = 'pay this'; },
    (input) => { input.manifestInput.signedProjections[0].projection.providerException = 'boom'; },
    (input) => { input.manifestInput.signedProjections[0].projection.agentUid = '501'; },
    (input) => {
      input.manifestInput.signedProjections[0].projection.payment = {
        signature: Buffer.alloc(64, 4).toString('base64'),
      };
    },
    (input) => {
      input.manifestInput.signedProjections[0].projection.note =
        'YWdlbnQtY3JlZGVudGlhbC1tYXJrZXI0MgYWdlbnQtY3JlZGVudGlhbA';
    },
    (input) => { input.manifestInput.signedProjections[0].projection.note = '/Users/alice/secret'; },
    (input) => { input.manifestInput.signedProjections[0].projection.note = '-----BEGIN PRIVATE KEY-----'; },
  ];
  for (const mutate of mutations) {
    const input = fixture();
    mutate(input);
    const outputDirectory = path.join(temporaryDirectory(t), 'bundle');
    assert.throws(
      () => buildEvidenceBundle({ outputDirectory, ...input }),
      { code: 'EVIDENCE_SANITIZATION' },
    );
    assert.equal(fs.existsSync(outputDirectory), false);
  }
});

test('verifier CLI requires the external anchor and prints canonical JSON only on success', (t) => {
  const built = build(t);
  const script = path.join(PACKAGE_ROOT, 'scripts/verify-evidence.mjs');
  const success = spawnSync(NODE, [
    script,
    built.outputDirectory,
    '--expect-manifest-sha256',
    built.manifestSha256,
  ], { cwd: PACKAGE_ROOT, encoding: 'utf8' });
  assert.equal(success.status, 0, success.stderr);
  const parsed = JSON.parse(success.stdout);
  assert.equal(success.stdout, `${canonicalJson(parsed)}\n`);
  assert.equal(parsed.valid, true);

  const missing = spawnSync(NODE, [script, built.outputDirectory], {
    cwd: PACKAGE_ROOT,
    encoding: 'utf8',
  });
  assert.equal(missing.status, 2);
  assert.equal(missing.stdout, '');
  assert.match(missing.stderr, /EVIDENCE_CLI_ARGUMENTS/);
});

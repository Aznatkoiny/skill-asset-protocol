import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  parseRunEvidenceArguments,
  runEvidence,
  runOfflineEvidence,
} from '../scripts/run-evidence.mjs';

const NOW = '2026-08-01T12:00:00.000Z';
const MANIFEST_HASH = 'a'.repeat(64);
const INVARIANT_IDS = Object.freeze([
  'allowed-payment-settles-once',
  'policy-denials-never-sign',
  'approval-survives-restart',
  'denial-and-expiry-never-sign',
  'changed-challenge-terminalizes-approval',
  'settled-http-failures-commit-and-block',
  'body-loss-execution-reconciliation',
  'pre-settlement-loss-holds-budget',
  'post-signature-ambiguity-is-unresolved',
  'trusted-settlement-needs-execution-evidence',
  'refund-releases-only-after-full-proof',
  'fresh-process-verifies-authority',
  'pi-carries-no-authority-headers',
  'all-egress-is-loopback',
  'unauthorized-calls-fail-before-body',
  'credential-reattaches-session',
  'tighter-policy-requires-guarded-transition',
  'revocation-recovery-and-replacement',
]);
const CHILD_NAMES = Object.freeze([
  'model', 'seller', 'bootstrap', 'control-initial', 'control-restarted',
  'pi-tool-approval', 'pi-model-approval', 'control-recovery',
  'bootstrap-replacement', 'control-replacement', 'control-verifier',
]);

function temporaryDirectory(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'evidence-runner-')));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function acceptanceResult(sequence, anchorOutput) {
  const eventHeadHash = sha256('authority-head');
  const projectionHash = sha256('projection');
  const receipt = {
    id: 'receipt-1',
    intentId: 'intent-1',
    revision: 1,
    receiptHash: 'a'.repeat(64),
    signature: 'receipt-signature',
  };
  const signedProjection = {
    projection: {
      eventHeadHash,
      sessionHash: sha256('session-1'),
      signedReceipts: [receipt],
    },
    projectionHash,
  };
  return {
    summary: {
      mode: 'offline-deterministic',
      piVersion: '0.80.6',
      x402Version: 2,
      network: 'eip155:84532',
      isolation: 'simulated',
      tests: INVARIANT_IDS.length,
      passed: INVARIANT_IDS.length,
      liveCdp: 'not-run',
      testnetTransaction: 'not-run',
    },
    evidenceInput: {
      acceptance: {
        invariants: INVARIANT_IDS.map((id) => ({
          id,
          passed: true,
          evidenceHash: sha256(`accepted:${id}`),
        })),
        processExitCodes: Object.fromEntries(CHILD_NAMES.map((name) => [name, 0])),
        transactionIds: [`0x${'ab'.repeat(32)}`],
        rawSettlementTransactionIds: [`0x${'ab'.repeat(32)}`],
        piApprovalResume: Object.fromEntries(['tool', 'model'].map((kind) => [kind, {
          pendingObserved: true,
          originalRequestHeld: true,
          operatorApprovalStatus: 200,
          signerDelta: 1,
          paidRequestDelta: 1,
          duplicatePaymentSignatureDelta: 0,
          outputObserved: 'PI_WALLET_OK',
          processExitCode: 0,
        }])),
      },
      sessionProjections: [signedProjection],
      authorityReceipts: [receipt],
      events: [{
        sequence: 1,
        eventType: 'receipt.issued',
        receiptHash: receipt.receiptHash,
        receiptSignature: receipt.signature,
      }],
      receiptPublicKeys: [{ keyId: 'key-1', algorithm: 'Ed25519', publicKeyPem: 'public' }],
      identityBindings: {
        kernel: { uid: '501', gid: '20' },
        agent: { uid: '501', gid: '20' },
      },
      privilegedReport: null,
      freshVerification: {
        authorityEventChain: true,
        projection: true,
        receipts: true,
      },
      policyHash: sha256('policy'),
      routeMapHash: sha256('routes'),
      configHash: sha256('config'),
      wallet: {
        provider: 'deterministic',
        walletIdHash: sha256('wallet'),
        address: '0x1000000000000000000000000000000000000000',
      },
    },
    cleanup: async () => {
      assert.equal(fs.existsSync(anchorOutput), true);
      sequence.push('cleanup');
    },
  };
}

test('offline evidence calls the production acceptance API once, verifies, anchors, then cleans', async (t) => {
  const parent = temporaryDirectory(t);
  const outputDirectory = path.join(parent, 'bundle');
  const anchorOutput = path.join(parent, 'manifest.sha256');
  const sequence = [];
  let calls = 0;
  let assembled;
  const verified = {
    valid: true,
    mode: 'offline-deterministic',
    manifestSha256: MANIFEST_HASH,
  };

  const result = await runOfflineEvidence({ outputDirectory, anchorOutput }, {
    runAcceptance: async ({ authorityDirectory, piExecutable, nodeExecutable }) => {
      calls += 1;
      sequence.push('acceptance');
      assert.equal(fs.statSync(authorityDirectory).mode & 0o777, 0o700);
      assert.equal(fs.readdirSync(authorityDirectory).length, 0);
      assert.equal(path.isAbsolute(piExecutable), true);
      assert.equal(path.isAbsolute(nodeExecutable), true);
      return acceptanceResult(sequence, anchorOutput);
    },
    buildBundle: (input) => {
      sequence.push('build');
      assembled = input;
      return { manifestSha256: MANIFEST_HASH };
    },
    verifyBundle: (directory, options) => {
      sequence.push('verify');
      assert.equal(directory, outputDirectory);
      assert.deepEqual(options, { expectedManifestSha256: MANIFEST_HASH });
      return verified;
    },
    gitState: () => ({ commit: 'b'.repeat(40), dirty: true }),
    now: () => NOW,
  });

  assert.equal(calls, 1);
  assert.deepEqual(result, verified);
  assert.deepEqual(sequence, ['acceptance', 'build', 'verify', 'cleanup']);
  assert.equal(fs.readFileSync(anchorOutput, 'utf8'), `${MANIFEST_HASH}\n`);
  assert.equal(fs.statSync(anchorOutput).mode & 0o777, 0o600);
  assert.equal(assembled.outputDirectory, outputDirectory);
  assert.deepEqual(assembled.events, acceptanceResult([], anchorOutput).evidenceInput.events);
  assert.deepEqual(
    assembled.receipts,
    acceptanceResult([], anchorOutput).evidenceInput.authorityReceipts,
  );
  const expectedProjections = acceptanceResult([], anchorOutput).evidenceInput.sessionProjections;
  assert.deepEqual(assembled.manifestInput, {
    schemaVersion: 2,
    createdAt: NOW,
    mode: 'offline-deterministic',
    git: { commit: 'b'.repeat(40), dirty: true },
    runtime: { nodeVersion: process.version, piVersion: '0.80.6' },
    protocol: {
      x402Version: 2,
      network: 'eip155:84532',
      asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
    },
    wallet: acceptanceResult([], anchorOutput).evidenceInput.wallet,
    isolation: {
      status: 'simulated',
      preflightDigest: null,
      kernelIdentityHash: sha256(JSON.stringify({
        domain: 'wallet-kernel.kernel-identity.v1',
        kernelGid: '20',
        kernelUid: '501',
      })),
      agentIdentityHash: sha256(JSON.stringify({
        agentGid: '20',
        agentUid: '501',
        domain: 'wallet-kernel.agent-identity.v1',
      })),
    },
    deployment: {
      status: 'simulated',
      releaseManifestDigest: null,
      releaseTreeHash: null,
      serviceArtifactsHash: null,
      systemdEffectiveConfigHash: null,
    },
    inputs: {
      policyHash: sha256('policy'),
      routeMapHash: sha256('routes'),
      configHash: sha256('config'),
    },
    source: {
      authorityEventHeadHash: sha256('authority-head'),
      signedProjectionHash: sha256(canonicalJson({
        schemaVersion: 1,
        domain: 'wallet-kernel.signed-projection-set.v1',
        signedProjections: expectedProjections,
      })),
      receiptKeys: [{ keyId: 'key-1', algorithm: 'Ed25519', publicKeyPem: 'public' }],
    },
    status: { liveCdp: 'not-run', walletFunded: 'not-run', testnetTransaction: 'not-run' },
    identityBindings: {
      kernel: { uid: '501', gid: '20' },
      agent: { uid: '501', gid: '20' },
    },
    privilegedReport: null,
    signedProjections: expectedProjections,
  });
});

test('offline evidence refuses an existing external anchor before running acceptance', async (t) => {
  const parent = temporaryDirectory(t);
  const anchorOutput = path.join(parent, 'manifest.sha256');
  fs.writeFileSync(anchorOutput, 'do-not-replace\n', { mode: 0o600 });
  let calls = 0;
  await assert.rejects(runOfflineEvidence({
    outputDirectory: path.join(parent, 'bundle'),
    anchorOutput,
  }, {
    runAcceptance: async () => { calls += 1; },
  }), { code: 'EVIDENCE_ANCHOR_EXISTS' });
  assert.equal(calls, 0);
  assert.equal(fs.readFileSync(anchorOutput, 'utf8'), 'do-not-replace\n');
});

test('offline evidence refuses dangling output or anchor symlinks before acceptance', async (t) => {
  const parent = temporaryDirectory(t);
  const dangling = path.join(parent, 'missing-target');
  const outputLink = path.join(parent, 'bundle');
  const anchorLink = path.join(parent, 'manifest.sha256');
  fs.symlinkSync(dangling, outputLink);
  let calls = 0;
  await assert.rejects(runOfflineEvidence({
    outputDirectory: outputLink,
    anchorOutput: path.join(parent, 'unused-anchor'),
  }, {
    runAcceptance: async () => { calls += 1; },
  }), { code: 'EVIDENCE_OUTPUT_EXISTS' });
  fs.unlinkSync(outputLink);
  fs.symlinkSync(dangling, anchorLink);
  await assert.rejects(runOfflineEvidence({
    outputDirectory: path.join(parent, 'unused-bundle'),
    anchorOutput: anchorLink,
  }, {
    runAcceptance: async () => { calls += 1; },
  }), { code: 'EVIDENCE_ANCHOR_EXISTS' });
  assert.equal(calls, 0);
});

test('offline evidence rejects a diluted self-consistent acceptance result', async (t) => {
  const parent = temporaryDirectory(t);
  const anchorOutput = path.join(parent, 'manifest.sha256');
  const diluted = acceptanceResult([], anchorOutput);
  diluted.summary.tests = 1;
  diluted.summary.passed = 1;
  diluted.evidenceInput.acceptance.invariants = diluted.evidenceInput.acceptance.invariants.slice(0, 1);
  let builds = 0;
  await assert.rejects(runOfflineEvidence({
    outputDirectory: path.join(parent, 'bundle'),
    anchorOutput,
  }, {
    runAcceptance: async () => diluted,
    buildBundle: () => { builds += 1; },
  }), { code: 'EVIDENCE_ACCEPTANCE_FAILED' });
  assert.equal(builds, 0);
});

test('offline evidence rejects nonzero or incomplete child-process authority before build', async (t) => {
  for (const mutate of [
    (result) => { result.evidenceInput.acceptance.processExitCodes.seller = 1; },
    (result) => { delete result.evidenceInput.acceptance.processExitCodes['control-verifier']; },
  ]) {
    const parent = temporaryDirectory(t);
    const anchorOutput = path.join(parent, 'manifest.sha256');
    const result = acceptanceResult([], anchorOutput);
    result.cleanup = async () => {};
    mutate(result);
    let builds = 0;
    await assert.rejects(runOfflineEvidence({
      outputDirectory: path.join(parent, 'bundle'),
      anchorOutput,
    }, {
      runAcceptance: async () => result,
      buildBundle: () => { builds += 1; },
    }), { code: 'EVIDENCE_ACCEPTANCE_RESULT' });
    assert.equal(builds, 0);
  }
});

test('offline evidence rejects raw transaction reuse and incomplete session partitions', async (t) => {
  const mutations = [
    (result) => {
      result.evidenceInput.acceptance.rawSettlementTransactionIds.push(
        result.evidenceInput.acceptance.rawSettlementTransactionIds[0],
      );
    },
    (result) => { result.evidenceInput.sessionProjections.length = 0; },
    (result) => { result.evidenceInput.authorityReceipts.length = 0; },
  ];
  for (const mutate of mutations) {
    const parent = temporaryDirectory(t);
    const anchorOutput = path.join(parent, 'manifest.sha256');
    const result = acceptanceResult([], anchorOutput);
    result.cleanup = async () => {};
    mutate(result);
    let builds = 0;
    await assert.rejects(runOfflineEvidence({
      outputDirectory: path.join(parent, 'bundle'),
      anchorOutput,
    }, {
      runAcceptance: async () => result,
      buildBundle: () => { builds += 1; },
    }), { code: 'EVIDENCE_ACCEPTANCE_RESULT' });
    assert.equal(builds, 0);
  }
});

test('offline evidence rejects missing or altered pinned Pi approval proof before build', async (t) => {
  const mutations = [
    (result) => { delete result.evidenceInput.acceptance.piApprovalResume.model; },
    (result) => {
      result.evidenceInput.acceptance.piApprovalResume.tool.originalRequestHeld = false;
    },
  ];
  for (const mutate of mutations) {
    const parent = temporaryDirectory(t);
    const anchorOutput = path.join(parent, 'manifest.sha256');
    const result = acceptanceResult([], anchorOutput);
    result.cleanup = async () => {};
    mutate(result);
    let builds = 0;
    await assert.rejects(runOfflineEvidence({
      outputDirectory: path.join(parent, 'bundle'),
      anchorOutput,
    }, {
      runAcceptance: async () => result,
      buildBundle: () => { builds += 1; },
    }), { code: 'EVIDENCE_ACCEPTANCE_RESULT' });
    assert.equal(builds, 0);
  }
});

test('CLI requires explicit offline paths and testnet remains honestly not-run', async () => {
  assert.deepEqual(parseRunEvidenceArguments([
    '--mode', 'offline-deterministic',
    '--output', '/tmp/evidence-bundle',
    '--anchor-output', '/tmp/evidence-manifest.sha256',
  ]), {
    mode: 'offline-deterministic',
    outputDirectory: '/tmp/evidence-bundle',
    anchorOutput: '/tmp/evidence-manifest.sha256',
  });
  assert.throws(
    () => parseRunEvidenceArguments(['--mode', 'offline-deterministic']),
    { code: 'EVIDENCE_RUN_ARGUMENTS' },
  );
  let acceptanceCalls = 0;
  await assert.rejects(runEvidence({ mode: 'base-sepolia-testnet' }, {
    runAcceptance: async () => { acceptanceCalls += 1; },
  }), { code: 'EVIDENCE_TESTNET_NOT_RUN' });
  assert.equal(acceptanceCalls, 0);
});

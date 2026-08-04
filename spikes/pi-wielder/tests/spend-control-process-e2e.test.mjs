import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import test from 'node:test';

import {
  runSpendControlProcessAcceptance,
  SPEND_CONTROL_PROCESS_CHILD_NAMES,
} from '../scripts/lib/spend-control-process-runner.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(import.meta.dirname, '..');
const NODE = process.execPath;
const PI = path.join(ROOT, 'node_modules', '.bin', 'pi');
const PRELOAD = path.join(import.meta.dirname, 'fixtures', 'loopback-only-preload.cjs');

const EXPECTED_INVARIANTS = Object.freeze([
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

const EXPECTED_CHILD_PROCESSES = Object.freeze([
  'model',
  'seller',
  'bootstrap',
  'control-initial',
  'control-restarted',
  'pi-tool-approval-first',
  'pi-tool-approval-second',
  'pi-model-approval-first',
  'pi-model-approval-second',
  'control-recovery',
  'bootstrap-replacement',
  'control-replacement',
  'control-verifier',
]);

test('process acceptance tracks both ordinary Pi attempts for each approval path', () => {
  assert.deepEqual(SPEND_CONTROL_PROCESS_CHILD_NAMES, EXPECTED_CHILD_PROCESSES);
});

async function supportsLoopbackListener() {
  const server = net.createServer();
  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
    return true;
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') return false;
    throw error;
  } finally {
    if (server.listening) {
      await new Promise((resolve) => server.close(resolve));
    }
  }
}

function assertNoSensitiveEvidence(value) {
  const serialized = JSON.stringify(value);
  const forbiddenFields = new Set([
    'authorization', 'cookie', 'paymentsignature', 'paymentpayload',
    'agentcredential', 'agenttoken', 'operatortoken', 'providererror',
    'providerexception', 'privatekey', 'requestbody', 'responsebody',
  ]);
  const visit = (item) => {
    if (!item || typeof item !== 'object') return;
    for (const [key, child] of Object.entries(item)) {
      const compact = key.toLowerCase().replaceAll(/[^a-z0-9]/gu, '');
      assert.equal(forbiddenFields.has(compact), false, key);
      visit(child);
    }
  };
  visit(value);
  for (const forbidden of ['payment-signature:', 'private key', 'bearer ']) {
    assert.equal(serialized.toLowerCase().includes(forbidden), false, forbidden);
  }
  assert.equal(/\/(?:Users|home|private|tmp|var)\//u.test(serialized), false);
}

test('repository-local Pi is pinned to exactly 0.80.6', async () => {
  const { stdout, stderr } = await execFileAsync(PI, ['--version'], {
    cwd: ROOT,
    env: { PATH: path.dirname(NODE) },
    timeout: 5_000,
  });
  assert.equal(stderr, '');
  assert.equal(stdout.trim(), '0.80.6');
});

test('loopback preload rejects external sockets and records only a sanitized destination', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-egress-test-'));
  fs.chmodSync(directory, 0o700);
  const logFile = path.join(directory, 'egress.jsonl');
  fs.writeFileSync(logFile, '', { mode: 0o600, flag: 'wx' });
  try {
    const script = [
      "const net = require('node:net');",
      "try { net.connect({ host: '203.0.113.7', port: 443 }); }",
      "catch (error) { process.stdout.write(error.code + '\\n'); }",
    ].join(' ');
    const { stdout, stderr } = await execFileAsync(NODE, ['-e', script], {
      cwd: ROOT,
      env: {
        NODE_OPTIONS: `--require=${PRELOAD}`,
        WALLET_KERNEL_EGRESS_LOG_FILE: logFile,
      },
      timeout: 5_000,
    });
    assert.equal(stderr, '');
    assert.equal(stdout, 'EXTERNAL_EGRESS_FORBIDDEN\n');
    const records = fs.readFileSync(logFile, 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(records, [{ destination: '203.0.113.7', operation: 'net.connect' }]);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test('real pinned-Pi process acceptance proves all eighteen invariants', async (t) => {
  if (!await supportsLoopbackListener()) {
    t.skip('loopback listener creation is denied by this sandbox (EPERM)');
    return;
  }

  const authorityDirectory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-process-authority-')),
  );
  fs.chmodSync(authorityDirectory, 0o700);
  let cleanup = async () => {};
  t.after(async () => {
    await cleanup();
    fs.rmSync(authorityDirectory, { recursive: true });
  });

  const result = await runSpendControlProcessAcceptance({
    authorityDirectory,
    piExecutable: PI,
    nodeExecutable: NODE,
  });
  cleanup = result.cleanup;

  assertNoSensitiveEvidence(result.evidenceInput);
  assert.deepEqual(
    result.evidenceInput.acceptance.invariants.map(({ id }) => id),
    EXPECTED_INVARIANTS,
  );
  const failedInvariants = result.evidenceInput.acceptance.invariants
    .filter(({ passed }) => passed !== true)
    .map(({ id, facts }) => ({ id, facts }));
  assert.deepEqual(failedInvariants, []);
  assert.deepEqual(result.summary, {
    mode: 'offline-deterministic',
    piVersion: '0.80.6',
    x402Version: 2,
    network: 'eip155:84532',
    isolation: 'simulated',
    tests: 18,
    passed: 18,
    liveCdp: 'not-run',
    testnetTransaction: 'not-run',
  });
  assert.deepEqual(result.evidenceInput.acceptance.processExitCodes, {
    model: 0,
    seller: 0,
    bootstrap: 0,
    'control-initial': 0,
    'control-restarted': 0,
    'pi-tool-approval-first': 0,
    'pi-tool-approval-second': 0,
    'pi-model-approval-first': 1,
    'pi-model-approval-second': 0,
    'control-recovery': 0,
    'bootstrap-replacement': 0,
    'control-replacement': 0,
    'control-verifier': 0,
  });
  assert.equal(new Set(result.evidenceInput.acceptance.transactionIds).size,
    result.evidenceInput.acceptance.transactionIds.length);
  assert.equal(result.evidenceInput.acceptance.rawSettlementTransactionIds.length > 1, true);
  assert.equal(
    result.evidenceInput.acceptance.rawSettlementTransactionIds.length,
    new Set(result.evidenceInput.acceptance.rawSettlementTransactionIds).size,
  );
  assert.equal(result.evidenceInput.acceptance.nonLoopbackEgressAttempts, 0);
  assert.equal(result.evidenceInput.acceptance.forbiddenPiAuthorityHeaderCount, 0);
  assert.equal(result.evidenceInput.acceptance.piOutputObserved, 'PI_WALLET_OK');
  for (const kind of ['tool', 'model']) {
    assert.deepEqual(result.evidenceInput.acceptance.piApprovalResume[kind], {
      firstAttempt: {
        pendingObserved: true,
        exitedBeforeOperatorApproval: true,
        signerDelta: 0,
        paidRequestDelta: 0,
        outputObserved: kind === 'tool' ? 'PI_APPROVAL_REQUIRED' : 'approval-required-error',
        processExitCode: kind === 'tool' ? 0 : 1,
      },
      operatorApprovalStatus: 200,
      secondAttempt: {
        sameRequestFingerprint: true,
        signerDelta: 1,
        paidRequestDelta: 1,
        duplicatePaymentSignatureDelta: 0,
        outputObserved: 'PI_WALLET_OK',
        processExitCode: 0,
      },
    });
  }
  assert.equal(result.evidenceInput.freshVerification.authorityEventChain, true);
  assert.equal(result.evidenceInput.freshVerification.projection, true);
  assert.equal(result.evidenceInput.freshVerification.receipts, true);
  assert.equal(result.evidenceInput.sessionProjections.length > 1, true);
  assert.equal(
    result.evidenceInput.sessionProjections.length,
    new Set(result.evidenceInput.sessionProjections.map((bundle) => (
      bundle.projection.sessionHash
    ))).size,
  );
  assert.equal(result.evidenceInput.authorityReceipts.length > Math.max(
    ...result.evidenceInput.sessionProjections.map((bundle) => (
      bundle.projection.signedReceipts.length
    )),
  ), true);
  assert.equal(
    result.evidenceInput.authorityReceipts.length,
    new Set(result.evidenceInput.authorityReceipts.map(({ receiptHash }) => receiptHash)).size,
  );
  const receiptEvents = result.evidenceInput.events.filter(
    ({ eventType }) => eventType === 'receipt.issued',
  );
  assert.equal(receiptEvents.length, result.evidenceInput.authorityReceipts.length);
  assert.equal(receiptEvents.every(({ receiptHash, receiptSignature }) => (
    typeof receiptHash === 'string' && typeof receiptSignature === 'string'
  )), true);
});

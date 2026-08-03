import fs from 'node:fs';
import path from 'node:path';

import { createAgentEnrollmentRepository } from '../../src/kernel/agent-enrollment.mjs';
import { createApprovalQueue } from '../../src/kernel/approval-queue.mjs';
import { acquireAuthorityLock } from '../../src/kernel/authority-lock.mjs';
import { createAuthorityMutationCoordinator } from '../../src/kernel/authority-mutation-coordinator.mjs';
import { createPermitAuthority } from '../../src/kernel/authorized-permit.mjs';
import { createBudgetLedger } from '../../src/kernel/budget-ledger.mjs';
import { canonicalJson, sha256 } from '../../src/kernel/canonical.mjs';
import { createIntentRepository } from '../../src/kernel/intent-builder.mjs';
import { createPolicyRepository } from '../../src/kernel/policy-repository.mjs';
import { loadOrCreateReceiptSigner } from '../../src/kernel/receipt-signing.mjs';
import { createSignedReceiptRepository } from '../../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';
import {
  createWalletKernel,
  KERNEL_FAULT_POINTS,
} from '../../src/kernel/wallet-kernel.mjs';

const NOW = '2026-08-01T12:00:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const SELLER = 'https://seller.example';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));
const PAYLOAD_FIELDS = Object.freeze([
  'databasePath',
  'directory',
  'receiptKeyPath',
  'signerCountPath',
  'transportCountPath',
  'faultPoint',
]);

function report(message) {
  if (typeof process.send === 'function' && process.connected) process.send(message);
  else process.stdout.write(`${JSON.stringify(message)}\n`);
}

function exactPayload(text) {
  const value = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== PAYLOAD_FIELDS.length
      || PAYLOAD_FIELDS.some((field) => !Object.hasOwn(value, field))
      || !KERNEL_FAULT_POINTS.includes(value.faultPoint)) {
    throw new Error('crash-worker payload does not match the closed fixture schema');
  }
  for (const field of PAYLOAD_FIELDS.filter((name) => name !== 'faultPoint')) {
    if (typeof value[field] !== 'string' || !path.isAbsolute(value[field])) {
      throw new Error(`crash-worker ${field} must be an absolute path`);
    }
  }
  const realDirectory = fs.realpathSync(value.directory);
  for (const field of PAYLOAD_FIELDS.filter(
    (name) => name !== 'directory' && name !== 'faultPoint',
  )) {
    if (fs.realpathSync(path.dirname(value[field])) !== realDirectory) {
      throw new Error(`crash-worker ${field} must be a direct child of the trusted directory`);
    }
  }
  return Object.freeze({ ...value });
}

function assertOwnerOnlyRegularFile(filePath) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile() || stat.isSymbolicLink()
      || stat.uid !== process.getuid() || (stat.mode & 0o777) !== 0o600) {
    throw new Error(`${filePath} must be an owner-only regular file`);
  }
}

function updateCounter(filePath, expectedFields, field) {
  assertOwnerOnlyRegularFile(filePath);
  const value = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== expectedFields.length
      || expectedFields.some((name) => !Object.hasOwn(value, name))
      || expectedFields.some((name) => !Number.isSafeInteger(value[name]) || value[name] < 0)) {
    throw new Error(`${filePath} counter schema is invalid`);
  }
  value[field] += 1;
  const descriptor = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW,
  );
  try {
    fs.writeFileSync(descriptor, `${JSON.stringify(value)}\n`, 'utf8');
    fs.fsyncSync(descriptor);
  } finally {
    fs.closeSync(descriptor);
  }
  return value[field];
}

function waitForRun(timeoutMilliseconds = 15_000) {
  return new Promise((resolve, reject) => {
    const onMessage = (message) => {
      if (!message || message.type !== 'run') return;
      clearTimeout(timer);
      process.off('message', onMessage);
      process.off('disconnect', onDisconnect);
      resolve();
    };
    const onDisconnect = () => {
      clearTimeout(timer);
      process.off('message', onMessage);
      reject(new Error('crash-worker parent disconnected before run authorization'));
    };
    const timer = setTimeout(() => {
      process.off('message', onMessage);
      process.off('disconnect', onDisconnect);
      reject(new Error('crash-worker timed out waiting for run authorization'));
    }, timeoutMilliseconds);
    process.on('message', onMessage);
    process.once('disconnect', onDisconnect);
  });
}

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function ordinaryRequest(faultPoint) {
  return {
    requestUrl: `${SELLER}/paid/infer`,
    method: 'POST',
    headers: { accept: 'application/json', 'content-type': 'application/json' },
    bodyBytes: Buffer.from(canonicalJson({ faultPoint })),
  };
}

function paymentRequired() {
  return Object.freeze({
    x402Version: 2,
    resource: Object.freeze({
      url: `${SELLER}/paid/infer`,
      description: 'offline fixture',
      mimeType: 'application/json',
    }),
    accepts: Object.freeze([Object.freeze({
      scheme: 'exact',
      network: NETWORK,
      asset: ASSET,
      amount: '50000',
      payTo: PAY_TO,
      maxTimeoutSeconds: 60,
      extra: Object.freeze({ name: 'USDC', version: '2' }),
    })]),
  });
}

function signedPaymentPayload(challenge) {
  return Object.freeze({
    x402Version: 2,
    resource: challenge.resource,
    accepted: challenge.accepts[0],
    payload: Object.freeze({
      signature: `0x${'11'.repeat(65)}`,
      authorization: Object.freeze({
        from: WALLET,
        to: PAY_TO,
        value: '50000',
        validAfter: '0',
        validBefore: String(Math.floor(Date.parse(NOW) / 1_000) + 60),
        nonce: `0x${'11'.repeat(32)}`,
      }),
    }),
  });
}

const payload = exactPayload(process.argv[2]);
const trust = Object.freeze({
  mode: 'deterministic',
  trustedAncestor: payload.directory,
  kernelUid: process.getuid(),
  agentUid: process.getuid(),
});
let authority;
let store;

try {
  authority = acquireAuthorityLock({
    databasePath: payload.databasePath,
    role: 'kernel',
    pathTrust: trust,
  });
  const signer = loadOrCreateReceiptSigner(payload.receiptKeyPath, { pathTrust: trust });
  store = openKernelStore({
    filePath: payload.databasePath,
    pathTrust: trust,
    now: () => NOW,
  });
  const ids = sequenceIds();
  const policies = createPolicyRepository(store);
  const policyVersion = policies.apply(structuredClone(BASE_POLICY), NOW).policyVersion;
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
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
  const intents = createIntentRepository({
    store,
    idFactory: ids,
    now: () => NOW,
    routeMetadata: Object.freeze({
      'paid-infer': Object.freeze({
        description: 'offline fixture',
        mimeType: 'application/json',
      }),
    }),
  });
  const budgets = createBudgetLedger({ store, now: () => NOW });
  const approvals = createApprovalQueue({ store, idFactory: ids, now: () => NOW });
  const receipts = createSignedReceiptRepository({
    store,
    signer,
    idFactory: ids,
    now: () => NOW,
  });
  let healthy = true;
  const markAuthorityUnhealthy = () => { healthy = false; };
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      if (!healthy) {
        const error = new Error('receipt parity is required');
        error.code = 'RECEIPT_PARITY_REQUIRED';
        throw error;
      }
    },
    markAuthorityUnhealthy,
  });
  const challenge = paymentRequired();
  const paymentPayload = signedPaymentPayload(challenge);
  const walletAdapter = Object.freeze({
    async walletIdentity() {
      updateCounter(
        payload.signerCountPath,
        ['walletIdentity', 'signX402Exact'],
        'walletIdentity',
      );
      return Object.freeze({
        provider: 'deterministic',
        walletId: 'wallet-1',
        address: WALLET,
        network: NETWORK,
      });
    },
    async signX402Exact() {
      updateCounter(
        payload.signerCountPath,
        ['walletIdentity', 'signX402Exact'],
        'signX402Exact',
      );
      return Object.freeze({ paymentPayload });
    },
  });
  const transport = Object.freeze({
    async probe() {
      updateCounter(
        payload.transportCountPath,
        ['probe', 'encodePayment', 'retryPaid'],
        'probe',
      );
      return Object.freeze({ kind: 'payment_required', paymentRequired: challenge });
    },
    encodePayment() {
      updateCounter(
        payload.transportCountPath,
        ['probe', 'encodePayment', 'retryPaid'],
        'encodePayment',
      );
      return 'restart-matrix-payment-header';
    },
    async retryPaid({ binding }) {
      updateCounter(
        payload.transportCountPath,
        ['probe', 'encodePayment', 'retryPaid'],
        'retryPaid',
      );
      return Object.freeze({
        kind: 'settled_response',
        settlement: Object.freeze({
          source: 'x402-payment-response',
          headerHash: sha256(Buffer.from('restart-matrix-settlement', 'ascii')),
          success: true,
          transaction: `0x${'ef'.repeat(32)}`,
          network: NETWORK,
          payer: WALLET,
          amountAtomic: '50000',
          paymentHash: binding.paymentHash,
        }),
        status: 200,
        body: Buffer.from('restart-matrix-ok'),
        executionState: 'succeeded',
      });
    },
  });
  const kernel = createWalletKernel({
    store,
    policies,
    enrollments,
    intents,
    budgets,
    approvals,
    receipts,
    permitAuthority: createPermitAuthority(),
    walletAdapter,
    transport,
    authorityMutationCoordinator: coordinator,
    markAuthorityUnhealthy,
    now: () => NOW,
    idFactory: ids,
    randomBytes: (size) => Buffer.alloc(size, 0x11),
    faultInjector(point) {
      if (point === payload.faultPoint) process.abort();
    },
  });
  const session = await kernel.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: policyVersion.id,
  });

  report({ type: 'ready', faultPoint: payload.faultPoint });
  await waitForRun();
  await kernel.execute({
    sessionId: session.id,
    routeId: 'paid-infer',
    request: ordinaryRequest(payload.faultPoint),
    purposeLabel: 'skill.invoke',
    correlationId: `restart-${payload.faultPoint}`,
  });
  throw new Error(`fault injector did not abort at ${payload.faultPoint}`);
} catch (error) {
  report({
    type: 'error',
    code: error?.code ?? null,
    name: error?.name ?? null,
    message: error?.message ?? String(error),
  });
  process.exitCode = 1;
} finally {
  store?.close();
  authority?.close();
}

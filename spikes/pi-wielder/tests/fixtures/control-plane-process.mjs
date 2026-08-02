import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';

import { serve } from '@hono/node-server';
import { keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { createDeterministicWalletAdapter } from '../../src/adapters/deterministic-wallet-adapter.mjs';
import { createSellerEvidenceResolver } from '../../src/adapters/seller-evidence-resolver.mjs';
import { createX402V2Transport } from '../../src/adapters/x402-v2-transport.mjs';
import { createAgentEnrollmentRepository } from '../../src/kernel/agent-enrollment.mjs';
import { createApprovalQueue } from '../../src/kernel/approval-queue.mjs';
import { acquireAuthorityLock } from '../../src/kernel/authority-lock.mjs';
import { createPermitAuthority } from '../../src/kernel/authorized-permit.mjs';
import { createBudgetLedger } from '../../src/kernel/budget-ledger.mjs';
import { canonicalJson, sha256 } from '../../src/kernel/canonical.mjs';
import { createIntentRepository } from '../../src/kernel/intent-builder.mjs';
import { validatePolicyDocument } from '../../src/kernel/policy-engine.mjs';
import { createPolicyRepository } from '../../src/kernel/policy-repository.mjs';
import { createProjectionExporter } from '../../src/kernel/projection-exporter.mjs';
import { loadOrCreateReceiptSigner } from '../../src/kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from '../../src/kernel/recovery.mjs';
import { createSignedReceiptRepository } from '../../src/kernel/signed-receipts.mjs';
import { openKernelStore } from '../../src/kernel/sqlite-store.mjs';
import { createOperatorAuth, loadOrCreateOperatorToken } from '../../src/operator/auth.mjs';
import { startControlPlane } from '../../src/control-plane.mjs';

const NETWORK = 'eip155:84532';
const HASH = /^sha256:[0-9a-f]{64}$/u;
const CONFIG_FIELDS = Object.freeze([
  'schemaVersion', 'authorityDirectory', 'databasePath', 'receiptKeyPath',
  'operatorTokenPath', 'policyPath', 'routePath', 'kernelStatePath',
  'expectedAgentUid', 'expectedAgentGid', 'sellerOrigin',
]);
const buyerAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-deterministic-adapter-test-only')),
);
const WALLET_ADDRESS = buyerAccount.address.toLowerCase();

function fixtureError(code, message) {
  return Object.assign(new Error(message), { code });
}

function exactRecord(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== fields.length
      || fields.some((field) => !Object.hasOwn(value, field))) {
    throw fixtureError('PROCESS_CONFIG_INVALID', `${label} is invalid`);
  }
  return Object.fromEntries(fields.map((field) => [field, value[field]]));
}

function absolutePath(value, authorityDirectory, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) {
    throw fixtureError('PROCESS_CONFIG_INVALID', `${label} is invalid`);
  }
  const relative = path.relative(authorityDirectory, value);
  if (relative === '' || relative === '..' || path.isAbsolute(relative)
      || relative.startsWith(`..${path.sep}`)) {
    throw fixtureError('PROCESS_CONFIG_INVALID', `${label} leaves authority directory`);
  }
  return value;
}

function loadFixtureConfig(filePath) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'fixture config path is invalid');
  }
  const stat = fs.lstatSync(filePath, { bigint: true });
  const uid = BigInt(process.getuid());
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== uid
      || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n || stat.size > 65_536n) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'fixture config authority is invalid');
  }
  const parsed = exactRecord(
    JSON.parse(fs.readFileSync(filePath, 'utf8')),
    CONFIG_FIELDS,
    'fixture config',
  );
  if (parsed.schemaVersion !== 1 || !Number.isSafeInteger(parsed.expectedAgentUid)
      || parsed.expectedAgentUid <= 0 || !Number.isSafeInteger(parsed.expectedAgentGid)
      || parsed.expectedAgentGid <= 0) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'fixture config values are invalid');
  }
  const authorityDirectory = parsed.authorityDirectory;
  if (typeof authorityDirectory !== 'string' || !path.isAbsolute(authorityDirectory)
      || path.resolve(authorityDirectory) !== authorityDirectory) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'authority directory is invalid');
  }
  const directoryStat = fs.lstatSync(authorityDirectory, { bigint: true });
  if (!directoryStat.isDirectory() || directoryStat.isSymbolicLink()
      || directoryStat.uid !== uid || (directoryStat.mode & 0o7777n) !== 0o700n) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'authority directory authority is invalid');
  }
  for (const field of [
    'databasePath', 'receiptKeyPath', 'operatorTokenPath', 'policyPath',
    'routePath', 'kernelStatePath',
  ]) absolutePath(parsed[field], authorityDirectory, field);
  const seller = new URL(parsed.sellerOrigin);
  if (seller.protocol !== 'http:' || seller.hostname !== '127.0.0.1'
      || seller.port === '' || seller.pathname !== '/' || seller.origin !== parsed.sellerOrigin) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'seller origin is invalid');
  }
  return Object.freeze(parsed);
}

function pathTrust(config) {
  return Object.freeze({
    mode: 'deterministic',
    trustedAncestor: config.authorityDirectory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
}

function readCanonicalFile(filePath, maximumBytes) {
  const bytes = fs.readFileSync(filePath);
  if (bytes.length === 0 || bytes.length > maximumBytes) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'canonical input size is invalid');
  }
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = JSON.parse(text);
  if (`${canonicalJson(value)}\n` !== text) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'input is not canonical JSON plus newline');
  }
  return value;
}

function readDescriptor(filePath) {
  const stat = fs.lstatSync(filePath, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(process.getuid())
      || (stat.mode & 0o7777n) !== 0o644n || stat.nlink !== 1n || stat.size > 4_096n) {
    throw fixtureError('AGENT_DESCRIPTOR_PATH', 'enrollment descriptor authority is invalid');
  }
  return readCanonicalFile(filePath, 4_096);
}

function currentTimestamp() {
  return new Date().toISOString();
}

function operatorHash(token) {
  return sha256(Buffer.concat([
    Buffer.from('wallet-kernel.fixture-bootstrap-operator.v1\0', 'utf8'),
    Buffer.from(token, 'ascii'),
  ]));
}

async function bootstrap(config, enrollmentPath) {
  const trust = pathTrust(config);
  const lock = acquireAuthorityLock({
    databasePath: config.databasePath,
    role: 'bootstrap',
    pathTrust: trust,
  });
  let store;
  try {
    const operatorToken = loadOrCreateOperatorToken({
      filePath: config.operatorTokenPath,
      pathTrust: trust,
    });
    loadOrCreateReceiptSigner(config.receiptKeyPath, { pathTrust: trust });
    store = openKernelStore({
      filePath: config.databasePath,
      pathTrust: trust,
      now: currentTimestamp,
    });
    const policy = validatePolicyDocument(readCanonicalFile(config.policyPath, 65_536));
    const policies = createPolicyRepository(store);
    const applied = policies.apply(policy, currentTimestamp()).policyVersion;
    const descriptor = readDescriptor(enrollmentPath);
    const enrollment = createAgentEnrollmentRepository({ store, now: currentTimestamp }).enroll({
      descriptor,
      expectedDescriptorHash: sha256(canonicalJson(descriptor)),
      operatorIdHash: operatorHash(operatorToken),
      mode: 'deterministic',
      kernelUid: process.getuid(),
      kernelGid: process.getgid(),
      expectedAgentUid: config.expectedAgentUid,
      expectedAgentGid: config.expectedAgentGid,
    });
    if (typeof process.send === 'function') {
      process.send({
        type: 'bootstrap-complete',
        descriptorHash: enrollment.enrollmentHash,
        policyHash: applied.hash,
      });
    }
  } finally {
    store?.close();
    lock.close();
  }
}

async function reservePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw fixtureError('PROCESS_LISTEN', 'port unavailable');
  const port = address.port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

function listener({ app, host, port }) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const server = serve({
      fetch: app.fetch,
      hostname: host,
      port,
      overrideGlobalObjects: false,
    }, () => {
      settled = true;
      resolve(Object.freeze({
        close: () => new Promise((done, failed) => server.close((error) => (
          error ? failed(error) : done()
        ))),
      }));
    });
    server.once('error', (error) => {
      if (!settled) reject(error);
    });
  });
}

function idFactory(store) {
  let sequence = Number(store.readOne('SELECT COALESCE(MAX(sequence), 0) AS value FROM events').value);
  return (kind) => `${kind}:${++sequence}`;
}

function routeMetadata(routes) {
  return Object.freeze(Object.fromEntries(routes.routes.map((route) => [
    route.id,
    Object.freeze({ description: route.resourceDescription, mimeType: route.resourceMimeType }),
  ])));
}

function bindingRows(store, intents, enrollment) {
  return store.readAll(`SELECT * FROM agent_session_bindings
    WHERE agent_instance_id = ? AND enrollment_hash = ? AND state = 'open'
    ORDER BY id`, [enrollment.agentInstanceId, enrollment.enrollmentHash]).map((row) => (
    Object.freeze({
      bindingId: row.id,
      agentInstanceId: row.agent_instance_id,
      credentialDigest: row.credential_digest,
      enrollmentHash: row.enrollment_hash,
      state: row.state,
      session: intents.getSession(row.session_id),
    })
  ));
}

function sessionRows(store, intents) {
  return store.readAll('SELECT id FROM spend_sessions ORDER BY created_at, id')
    .map((row) => intents.getSession(row.id));
}

function publicPolicy(version, activeId) {
  return Object.freeze({
    versionId: version.id,
    policy: version.policy,
    policyHash: version.hash,
    predecessorHash: version.predecessorHash,
    createdAt: version.appliedAt,
    active: version.id === activeId,
  });
}

function publicApproval(record) {
  return Object.freeze({
    approvalId: record.approvalId,
    intentId: record.intentId,
    decision: record.decision,
    intentHash: record.intentHash,
    challengeHash: record.challengeHash,
    quoteId: record.quoteId,
    acceptedIndex: record.acceptedIndex,
    amountAtomic: record.amountCeilingAtomic,
    walletAddress: record.walletAddress,
    policyVersionId: record.policyVersionId,
    expiresAt: record.expiresAt,
    reasonCode: record.reasonCode,
    recordedAt: record.decidedAt,
  });
}

function allReceipts(store, receipts) {
  const result = [];
  for (const row of store.readAll('SELECT DISTINCT intent_id FROM signed_receipts ORDER BY intent_id')) {
    const current = receipts.latest(row.intent_id);
    if (current) result.push(current);
  }
  return Object.freeze(result);
}

function normalizedEvents(store) {
  return Object.freeze(store.events().map((row) => {
    let data = {};
    try { data = JSON.parse(row.data_json); } catch {}
    const amountAtomic = [
      data.amountAtomic, data.amountCeilingAtomic, data.reservedAtomic,
      data.committedAtomic, data.releasedAtomic,
    ].find((value) => typeof value === 'string' && /^(?:0|[1-9][0-9]*)$/u.test(value)) ?? null;
    const transactionId = [
      data.transactionId, data.paymentTransactionId, data.refundTransactionId,
    ].find((value) => typeof value === 'string' && /^0x[0-9a-f]{64}$/u.test(value)) ?? null;
    return Object.freeze({
      id: String(row.sequence),
      kind: row.event_type,
      hash: sha256(canonicalJson({
        domain: 'wallet-kernel.normalized-entity.v1',
        entityType: row.entity_type,
        entityId: row.entity_id,
      })),
      decision: typeof data.decision === 'string' ? data.decision : null,
      amountAtomic,
      transactionId,
      receiptHash: typeof data.receiptHash === 'string' ? data.receiptHash : null,
      eventHash: row.event_hash,
      previousEventHash: row.previous_hash,
      createdAt: row.created_at,
    });
  }));
}

function persistedNumber(value, label) {
  const number = typeof value === 'bigint' ? Number(value) : value;
  if (!Number.isSafeInteger(number) || number < 0) {
    throw fixtureError('PROCESS_AUTHORITY', `${label} is invalid`);
  }
  return number;
}

function evidenceDigest(value) {
  return value === null ? null : sha256(value);
}

function paymentCaseHash(authority, candidates) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-reconciliation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    attemptState: authority.attempt.state,
    budgetState: authority.budget.state,
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
    history: candidates.map((row) => ({
      id: row.id,
      transactionId: row.transaction_id,
      state: row.state,
      evidenceHash: evidenceDigest(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function executionCaseHash(authority, execution, resolution) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.execution-reconciliation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    transactionId: authority.attempt.transaction_id,
    execution: {
      state: execution.state,
      httpStatus: execution.http_status === null
        ? null
        : persistedNumber(execution.http_status, 'execution HTTP status'),
      responseHash: execution.response_hash,
      metadataHash: sha256(execution.metadata_json),
      recordedAt: execution.recorded_at,
    },
    resolution: {
      state: resolution.state,
      reasonCode: resolution.reason_code,
      openedAt: resolution.opened_at,
    },
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
  }));
}

function refundCaseHash(authority, execution, resolution, refunds) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation-case.v1',
    intentId: authority.intent.id,
    intentHash: authority.intent.intent_hash,
    originalTransactionId: authority.attempt.transaction_id,
    executionState: execution.state,
    resolutionState: resolution.state,
    buyerOutcomeRevision: persistedNumber(authority.outcome.revision, 'buyer outcome revision'),
    history: refunds.map((row) => ({
      id: row.id,
      originalTransactionId: row.original_transaction_id,
      amountAtomic: row.amount_atomic,
      state: row.state,
      refundTransactionId: row.refund_transaction_id,
      evidenceHash: evidenceDigest(row.evidence_json),
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    })),
  }));
}

function reconciliationCases(store) {
  const result = [];
  const intents = store.readAll('SELECT * FROM spend_intents ORDER BY created_at, id');
  for (const intent of intents) {
    const attempt = store.readOne('SELECT * FROM payment_attempts WHERE intent_id = ?', [intent.id]);
    const budget = store.readOne('SELECT * FROM budget_reservations WHERE intent_id = ?', [intent.id]);
    const outcome = store.readOne('SELECT * FROM buyer_outcomes WHERE intent_id = ?', [intent.id]);
    if (!attempt || !budget || !outcome) continue;
    const authority = Object.freeze({ intent, attempt, budget, outcome });
    if (intent.state === 'unresolved' && attempt.state === 'unresolved'
        && budget.state === 'unresolved' && outcome.status === 'payment_unresolved') {
      const candidates = store.readAll(
        'SELECT * FROM payment_reconciliation_candidates WHERE intent_id = ? ORDER BY rowid',
        [intent.id],
      );
      result.push(Object.freeze({
        kind: 'payment',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: paymentCaseHash(authority, candidates),
        paymentTransactionId: candidates.find((row) => row.state === 'pending')?.transaction_id ?? null,
      }));
      continue;
    }
    const execution = store.readOne('SELECT * FROM execution_outcomes WHERE intent_id = ?', [intent.id]);
    const resolution = store.readOne(
      'SELECT * FROM execution_resolutions WHERE intent_id = ?',
      [intent.id],
    );
    if (!execution || !resolution) continue;
    if (outcome.status === 'execution_unknown' && execution.state === 'unknown'
        && resolution.state === 'reconciliation_required') {
      result.push(Object.freeze({
        kind: 'execution',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: executionCaseHash(authority, execution, resolution),
        transactionId: attempt.transaction_id,
      }));
      continue;
    }
    if (outcome.status === 'execution_failed' && execution.state === 'failed'
        && resolution.state === 'refund_pending') {
      const refunds = store.readAll('SELECT * FROM refunds WHERE intent_id = ? ORDER BY rowid', [intent.id]);
      const open = refunds.find((row) => row.state === 'pending' || row.state === 'unresolved');
      result.push(Object.freeze({
        kind: 'refund-observation',
        intentId: intent.id,
        intentHash: intent.intent_hash,
        caseHash: refundCaseHash(authority, execution, resolution, refunds),
        originalTransactionId: attempt.transaction_id,
        refundTransactionId: open?.refund_transaction_id ?? null,
      }));
    }
  }
  return Object.freeze(result);
}

async function rpcResult(url) {
  try {
    const response = await fetch(url, {
      method: 'GET',
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(2_000),
    });
    if (response.status !== 200
        || !response.headers.get('content-type')?.toLowerCase().startsWith('application/json')) {
      return null;
    }
    const bytes = Buffer.from(await response.arrayBuffer());
    if (bytes.length === 0 || bytes.length > 16_384) return null;
    try {
      const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      return value?.jsonrpc === '2.0' && value?.id === 1 ? value.result ?? null : null;
    } finally {
      bytes.fill(0);
    }
  } catch {
    return null;
  }
}

function rejectedRefundProof(proof) {
  if (!proof) return null;
  return Object.freeze({
    source: proof.source,
    network: proof.network,
    transactionId: proof.transactionId,
    blockHash: proof.blockHash,
    blockNumber: proof.blockNumber,
    transactionStatus: proof.transactionStatus,
    confirmations: proof.confirmations,
    reasonCode: proof.transactionStatus === 'reverted'
      ? 'TRANSACTION_REVERTED'
      : 'EXACT_TRANSFER_ABSENT',
    observedAt: proof.observedAt,
  });
}

function refundTransferProof(proof) {
  if (!proof) return null;
  return Object.freeze({
    source: proof.source,
    network: proof.network,
    transactionId: proof.transactionId,
    blockHash: proof.blockHash,
    blockNumber: proof.blockNumber,
    transactionStatus: proof.transactionStatus,
    confirmations: proof.confirmations,
    transferLogIndex: proof.transferLogIndex,
    tokenContract: proof.tokenContract,
    from: proof.from,
    to: proof.to,
    valueAtomic: proof.valueAtomic,
    observedAt: proof.observedAt,
  });
}

function isExactRefundTransfer(proof, binding) {
  return proof?.transactionStatus === 'success'
    && proof.network === binding.network
    && proof.transactionId === binding.refundTransactionId
    && proof.tokenContract === binding.asset
    && proof.from === binding.refundSource
    && proof.to === binding.originalPayer
    && proof.valueAtomic === binding.amountAtomic;
}

function kernelStateGuard(filePath) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDWR | fs.constants.O_NOFOLLOW);
  const stat = fs.fstatSync(descriptor, { bigint: true });
  if (!stat.isFile() || stat.uid !== BigInt(process.getuid())
      || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n) {
    fs.closeSync(descriptor);
    throw fixtureError('PROCESS_AUTHORITY', 'kernel fixture state is invalid');
  }
  let state;
  try {
    const bytes = fs.readFileSync(descriptor, { encoding: 'utf8' });
    state = bytes.length === 0 ? { signerCalls: 0, transportErrors: [] } : JSON.parse(bytes);
  } catch {
    fs.closeSync(descriptor);
    throw fixtureError('PROCESS_AUTHORITY', 'kernel fixture state is corrupt');
  }
  const incrementSigner = () => {
    state = { ...state, signerCalls: state.signerCalls + 1 };
    const bytes = Buffer.from(`${JSON.stringify(state)}\n`, 'utf8');
    fs.ftruncateSync(descriptor, 0);
    fs.writeSync(descriptor, bytes, 0, bytes.length, 0);
    fs.fsyncSync(descriptor);
    bytes.fill(0);
  };
  const recordTransportError = (operation, code) => {
    const safeCode = typeof code === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/u.test(code)
      ? code
      : 'TRANSPORT_INTERNAL';
    state = {
      ...state,
      transportErrors: [...(state.transportErrors ?? []), { operation, code: safeCode }].slice(-100),
    };
    const bytes = Buffer.from(`${JSON.stringify(state)}\n`, 'utf8');
    fs.ftruncateSync(descriptor, 0);
    fs.writeSync(descriptor, bytes, 0, bytes.length, 0);
    fs.fsyncSync(descriptor);
    bytes.fill(0);
  };
  return Object.freeze({
    incrementSigner,
    recordTransportError,
    close: () => fs.closeSync(descriptor),
  });
}

function observedTransport(kernelState) {
  const transport = createX402V2Transport({
    fetchImpl: fetch,
    mode: 'deterministic',
    limits: {
      requestTimeoutMs: 2_000,
      maximumResponseBytes: 1_048_576,
      maximumPaymentHeaderBytes: 16_384,
    },
  });
  const observed = (operation) => async (...args) => {
    try {
      return await transport[operation](...args);
    } catch (error) {
      kernelState.recordTransportError(operation, error?.code);
      throw error;
    }
  };
  return Object.freeze({
    probe: observed('probe'),
    encodePayment: (...args) => {
      try {
        return transport.encodePayment(...args);
      } catch (error) {
        kernelState.recordTransportError('encodePayment', error?.code);
        throw error;
      }
    },
    retryPaid: observed('retryPaid'),
  });
}

function unknownResolver() {
  return Object.freeze({ kind: 'unknown', reasonCode: 'SELLER_EVIDENCE_FETCH_FAILED' });
}

function buildDependencies(config, endpoints) {
  const trust = pathTrust(config);
  const origin = `http://127.0.0.1:${endpoints.operatorPort}`;
  return Object.freeze({
    deterministicEndpoints: Object.freeze(endpoints),
    loadConfig() {
      return Object.freeze({
        publicConfig: Object.freeze({
          mode: 'deterministic',
          agentHost: '127.0.0.1',
          agentPort: endpoints.agentPort,
          operatorAdminTransport: 'loopback-demo',
          operatorSocketPath: null,
          operatorConsoleTransport: 'loopback-demo',
          operatorConsoleActivationName: null,
          operatorHost: '127.0.0.1',
          operatorPort: endpoints.operatorPort,
          databasePath: config.databasePath,
          policyPath: config.policyPath,
          routePath: config.routePath,
          receiptKeyPath: config.receiptKeyPath,
          operatorTokenPath: config.operatorTokenPath,
          enrollmentInboxPath: null,
          agentRunOutboxPath: null,
          trustedAncestor: null,
          releaseRoot: null,
          releaseManifestPath: null,
          serviceDefinitionPath: null,
          socketDefinitionPath: null,
          environmentFilePath: null,
          evidenceRoot: null,
          isolationReportPath: null,
          expectedAgentUid: config.expectedAgentUid,
          expectedAgentGid: config.expectedAgentGid,
          cdpWalletName: null,
          network: NETWORK,
          observer: 'deterministic',
        }),
        assertCredentialPresence() {},
      });
    },
    readRouteDocument(filePath) {
      if (filePath !== config.routePath) throw fixtureError('PROCESS_CONFIG_INVALID', 'route path changed');
      return readCanonicalFile(filePath, 65_536);
    },
    acquireAuthorityLock({ config: publicConfig, role }) {
      return acquireAuthorityLock({
        databasePath: publicConfig.databasePath,
        role,
        pathTrust: trust,
      });
    },
    async openAuthority({ routes }) {
      const now = currentTimestamp;
      const store = openKernelStore({
        filePath: config.databasePath,
        pathTrust: trust,
        now,
      });
      const ids = idFactory(store);
      const policies = createPolicyRepository(store);
      const enrollments = createAgentEnrollmentRepository({ store, now });
      const intents = createIntentRepository({
        store,
        idFactory: ids,
        now,
        routeMetadata: routeMetadata(routes),
        allowLoopbackHttp: true,
      });
      const budgets = createBudgetLedger({ store, now });
      const approvals = createApprovalQueue({ store, idFactory: ids, now });
      const signer = loadOrCreateReceiptSigner(config.receiptKeyPath, { pathTrust: trust });
      const receipts = createSignedReceiptRepository({
        store,
        signer,
        idFactory: ids,
        now,
      });
      const exporter = createProjectionExporter({ store, receipts, signer, now });
      const token = loadOrCreateOperatorToken({
        filePath: config.operatorTokenPath,
        pathTrust: trust,
      });
      const operatorAuth = createOperatorAuth({ mode: 'deterministic', origin, token });
      const kernelState = kernelStateGuard(config.kernelStatePath);
      const sellerEvidence = createSellerEvidenceResolver({
        fetchImpl: fetch,
        mode: 'deterministic',
        now,
        limits: { requestTimeoutMs: 5_000, maximumResponseBytes: 16_384 },
      });
      const resolver = Object.freeze({
        async observePayment(binding) {
          if (binding.candidate === null) return unknownResolver();
          const proof = await rpcResult(
            `${config.sellerOrigin}/fixture/v1/payment-proof/${binding.candidate.transactionId}`,
          );
          return proof === null
            ? Object.freeze({ kind: 'unknown', reasonCode: 'RPC_PROVIDER_UNAVAILABLE' })
            : Object.freeze({ kind: 'settled_transfer', rpcTransferProof: proof });
        },
        observeExecution: (binding) => sellerEvidence.observeExecution(binding),
        async observeRefund(binding) {
          const proof = await rpcResult(
            `${config.sellerOrigin}/fixture/v1/refund-proof/${binding.refundTransactionId}`,
          );
          if (proof === null) {
            return Object.freeze({ kind: 'unknown', reasonCode: 'RPC_PROVIDER_UNAVAILABLE' });
          }
          if (!isExactRefundTransfer(proof, binding)) {
            return Object.freeze({
              kind: 'refund_candidate_rejected',
              rejectionProof: rejectedRefundProof(proof),
            });
          }
          const attested = await sellerEvidence.observeRefund(binding);
          if (attested.kind !== 'refund_attested') return attested;
          return Object.freeze({
            kind: 'refund_attested_and_confirmed',
            attestation: attested.attestation,
            attestationHash: attested.attestationHash,
            rpcTransferProof: refundTransferProof(proof),
          });
        },
      });
      const currentSessionId = () => store.readOne(`SELECT id FROM spend_sessions
        WHERE state IN ('open','policy_blocked') ORDER BY created_at DESC, id DESC LIMIT 1`)?.id ?? null;
      const receiptKey = () => Object.freeze({
        algorithm: signer.algorithm,
        keyId: signer.keyId,
        publicKeyPem: signer.publicKeyPem,
      });
      const operatorReads = Object.freeze({
        async overview() {
          const active = policies.active();
          const sessions = sessionRows(store, intents);
          const sessionId = currentSessionId();
          return Object.freeze({
            status: 'ready',
            deployment: 'simulated',
            isolation: 'simulated',
            wallet: Object.freeze({ address: WALLET_ADDRESS, network: NETWORK }),
            policyVersion: publicPolicy(active, active.id),
            sessions: Object.freeze(sessions),
            approvals: Object.freeze(approvals.list({ limit: 1_000 }).map(publicApproval)),
            receipts: allReceipts(store, receipts),
            reconciliations: reconciliationCases(store),
            events: normalizedEvents(store),
            projection: sessionId === null ? null : exporter.exportSigned({ sessionId }),
          });
        },
        async listPolicies() {
          const active = policies.active();
          return Object.freeze({ items: Object.freeze(policies.history().map(
            (version) => publicPolicy(version, active.id),
          )) });
        },
        async walletIdentity() { return Object.freeze({ address: WALLET_ADDRESS }); },
        async listApprovals({ state }) {
          return Object.freeze({
            items: Object.freeze(approvals.list({
              limit: 1_000,
              ...(state === null ? {} : { state }),
            }).map(publicApproval)),
          });
        },
        async listReceipts() { return Object.freeze({ items: allReceipts(store, receipts) }); },
        async getReceipt({ receiptId }) {
          const row = store.readOne(`SELECT spend_intents.session_id FROM signed_receipts
            JOIN spend_intents ON spend_intents.id = signed_receipts.intent_id
            WHERE signed_receipts.id = ?`, [receiptId]);
          if (!row) return null;
          return receipts.list({ sessionId: row.session_id, limit: 1_000 })
            .find((entry) => entry.id === receiptId) ?? null;
        },
        async exportSession({ sessionId }) {
          return exporter.exportSigned({ sessionId });
        },
        async receiptPublicKey() { return receiptKey(); },
      });
      const authority = {
        activePolicy: () => policies.active(),
        activeEnrollment: () => enrollments.active(),
        bindingsForEnrollment(input) {
          return bindingRows(store, intents, input);
        },
        walletIdentity: () => Object.freeze({
          provider: 'deterministic-test',
          walletId: 'wallet-process-fixture',
          address: WALLET_ADDRESS,
          network: NETWORK,
        }),
        operatorAuth,
        operatorReads,
        agentAuthDependencies: Object.freeze({ store, intents }),
        async createKernelDependencies() {
          const permitAuthority = createPermitAuthority();
          const walletAdapter = createDeterministicWalletAdapter({
            identity: {
              provider: 'deterministic-test',
              walletId: 'wallet-process-fixture',
              address: WALLET_ADDRESS,
              network: NETWORK,
            },
            verifyAndConsume: permitAuthority.verifyAndConsume,
            async signTypedData(typedData) {
              kernelState.incrementSigner();
              return await buyerAccount.signTypedData(typedData);
            },
            nowMs: Date.now,
          });
          return Object.freeze({
            store,
            policies,
            enrollments,
            intents,
            budgets,
            approvals,
            receipts,
            permitAuthority,
            walletAdapter,
            transport: observedTransport(kernelState),
            now,
            idFactory: ids,
            randomBytes: crypto.randomBytes,
            faultInjector() {},
          });
        },
        reconcilerDependencies: Object.freeze({
          store, budgets, receipts, resolver, now, idFactory: ids,
        }),
        recoveryDependencies: Object.freeze({ store, intents, budgets, approvals, receipts, now }),
        recoverySessionCloser(input) {
          return store.transaction((tokenValue) => intents.closeBoundSessionInTransaction(
            tokenValue,
            input,
          ));
        },
        async waitForUnsignedWork() {},
        async close() {
          kernelState.close();
          store.close();
        },
      };
      return Object.freeze(authority);
    },
    recoverAuthority: (dependencies) => recoverKernelAuthority(dependencies),
    listenOperatorConsole: listener,
    listenAgent: listener,
    async publishReady(message) {
      if (typeof process.send === 'function') process.send(message);
    },
  });
}

async function serveControlPlane(config) {
  const endpoints = Object.freeze({
    agentHost: '127.0.0.1',
    agentPort: await reservePort(),
    operatorHost: '127.0.0.1',
    operatorPort: await reservePort(),
  });
  if (endpoints.agentPort === endpoints.operatorPort) {
    throw fixtureError('PROCESS_LISTEN', 'ephemeral ports collided');
  }
  const env = Object.freeze({ WALLET_KERNEL_MODE: 'deterministic' });
  const plane = await startControlPlane({
    env,
    dependencies: buildDependencies(config, endpoints),
  });
  let closing = false;
  const close = async (code = 0) => {
    if (closing) return;
    closing = true;
    await plane.close();
    if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
    process.exitCode = code;
  };
  process.on('message', (message) => {
    if (message && typeof message === 'object' && message.type === 'shutdown') void close(0);
  });
  process.once('SIGINT', () => { void close(0); });
  process.once('SIGTERM', () => { void close(0); });
}

function parseArguments(argv) {
  if (argv.length === 3 && argv[0] === '--serve' && argv[1] === '--config') {
    return Object.freeze({ mode: 'serve', configPath: argv[2], enrollmentPath: null });
  }
  if (argv.length === 5 && argv[0] === '--bootstrap' && argv[1] === '--config'
      && argv[3] === '--enrollment') {
    return Object.freeze({ mode: 'bootstrap', configPath: argv[2], enrollmentPath: argv[4] });
  }
  throw fixtureError('PROCESS_USAGE', 'control-plane fixture usage is invalid');
}

try {
  const args = parseArguments(process.argv.slice(2));
  const config = loadFixtureConfig(args.configPath);
  if (config.sellerOrigin === null || config.sellerOrigin === undefined) {
    throw fixtureError('PROCESS_CONFIG_INVALID', 'seller origin is missing');
  }
  if (args.mode === 'bootstrap') {
    await bootstrap(config, args.enrollmentPath);
    if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
  } else {
    await serveControlPlane(config);
  }
} catch (error) {
  const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,127}$/u.test(error.code)
    ? error.code
    : 'CONTROL_PLANE_PROCESS_FAILED';
  if (typeof process.send === 'function') process.send({ type: 'fatal', code });
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
  if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
}

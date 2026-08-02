import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

import { keccak256, toBytes } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';

import { runAgentCredentialCli } from '../../src/agent/credential-cli.mjs';
import { canonicalJson, sha256 } from '../../src/kernel/canonical.mjs';
import { verifySignedReceipt } from '../../src/kernel/receipt-signing.mjs';

const ROOT = path.resolve(import.meta.dirname, '../..');
const FIXTURES = path.join(ROOT, 'tests', 'fixtures');
const PRELOAD = path.join(FIXTURES, 'loopback-only-preload.cjs');
const MODEL_PROCESS = path.join(FIXTURES, 'pi-model-process.mjs');
const SELLER_PROCESS = path.join(FIXTURES, 'x402-v2-seller-process.mjs');
const CONTROL_PROCESS = path.join(FIXTURES, 'control-plane-process.mjs');
const PI_PROCESS = path.join(FIXTURES, 'pi-client-process.mjs');
const REPOSITORY_PI = path.join(ROOT, 'node_modules', '.bin', 'pi');
const REPOSITORY_PI_TARGET = path.join(
  ROOT,
  'node_modules',
  '@earendil-works',
  'pi-coding-agent',
  'dist',
  'cli.js',
);

const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAY_TO = '0x2000000000000000000000000000000000000000';
const CHILD_DEADLINE_MS = 30_000;
const CHILD_GRACE_MS = 2_000;
const MAXIMUM_OUTPUT_BYTES = 1_048_576;

export const SPEND_CONTROL_PROCESS_INVARIANT_IDS = Object.freeze([
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
const INVARIANT_IDS = SPEND_CONTROL_PROCESS_INVARIANT_IDS;
export const SPEND_CONTROL_PROCESS_CHILD_NAMES = Object.freeze([
  'model',
  'seller',
  'bootstrap',
  'control-initial',
  'control-restarted',
  'pi-tool-approval',
  'pi-model-approval',
  'control-recovery',
  'bootstrap-replacement',
  'control-replacement',
  'control-verifier',
]);

const buyerAccount = privateKeyToAccount(
  keccak256(toBytes('wallet-kernel-deterministic-adapter-test-only')),
);
const WALLET_ADDRESS = buyerAccount.address.toLowerCase();

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function canonicalAbsolute(value, code, { file = false, directory = false } = {}) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) fail(code);
  const real = fs.realpathSync(value);
  if (real !== value) fail(code);
  const stat = fs.lstatSync(value, { bigint: true });
  if (stat.isSymbolicLink() || (file && !stat.isFile()) || (directory && !stat.isDirectory())) {
    fail(code);
  }
  return value;
}

function validateAuthorityDirectory(value) {
  const directory = canonicalAbsolute(value, 'PROCESS_AUTHORITY_INVALID', { directory: true });
  const stat = fs.lstatSync(directory, { bigint: true });
  if (stat.uid !== BigInt(process.getuid()) || (stat.mode & 0o7777n) !== 0o700n
      || fs.readdirSync(directory).length !== 0) {
    fail('PROCESS_AUTHORITY_INVALID');
  }
  return directory;
}

function validateNodeExecutable(value) {
  const executable = canonicalAbsolute(value, 'PROCESS_NODE_INVALID', { file: true });
  fs.accessSync(executable, fs.constants.X_OK);
  return executable;
}

function validatePiExecutable(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) fail('PROCESS_PI_INVALID');
  const link = fs.lstatSync(value, { bigint: true });
  if (!link.isSymbolicLink()
      || fs.realpathSync(value) !== fs.realpathSync(REPOSITORY_PI_TARGET)
      || value !== REPOSITORY_PI) {
    fail('PROCESS_PI_INVALID');
  }
  return value;
}

function createDirectory(filePath, mode) {
  fs.mkdirSync(filePath, { mode });
  fs.chmodSync(filePath, mode);
}

function createEmptyFile(filePath) {
  fs.writeFileSync(filePath, '', { flag: 'wx', mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function writeCanonicalFile(filePath, value) {
  fs.writeFileSync(filePath, `${canonicalJson(value)}\n`, { flag: 'wx', mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
}

function replaceCanonicalFile(filePath, value) {
  const descriptor = fs.openSync(filePath, fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isFile() || stat.uid !== BigInt(process.getuid())
        || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n) {
      fail('PROCESS_AUTHORITY_INVALID');
    }
    const bytes = Buffer.from(`${canonicalJson(value)}\n`, 'utf8');
    try {
      fs.ftruncateSync(descriptor, 0);
      fs.writeSync(descriptor, bytes, 0, bytes.length, 0);
      fs.fsyncSync(descriptor);
    } finally {
      bytes.fill(0);
    }
  } finally {
    fs.closeSync(descriptor);
  }
}

function delay(milliseconds) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, milliseconds);
    timer.unref();
  });
}

function readJsonFile(filePath, fallback = null) {
  const text = fs.readFileSync(filePath, 'utf8');
  if (text.length === 0) return fallback;
  try {
    return JSON.parse(text);
  } catch {
    fail('PROCESS_STATE_INVALID');
  }
}

function boundedOutput(stream, onOverflow) {
  const chunks = [];
  let length = 0;
  stream.on('data', (value) => {
    const bytes = Buffer.from(value);
    length += bytes.length;
    if (length > MAXIMUM_OUTPUT_BYTES) {
      onOverflow();
      return;
    }
    chunks.push(bytes);
  });
  return () => {
    const bytes = Buffer.concat(chunks);
    const hash = sha256(bytes);
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
    return hash;
  };
}

function killGroup(child, signal) {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }
}

function startChild({ name, nodeExecutable, script, argv = [], env }) {
  const child = spawn(nodeExecutable, [script, ...argv], {
    cwd: ROOT,
    detached: true,
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  const messages = [];
  const listeners = new Set();
  let deadlineExpired = false;
  let outputExceeded = false;
  let exitRecord = null;
  const notify = () => {
    for (const listener of [...listeners]) listener();
  };
  child.on('message', (message) => {
    if (message && typeof message === 'object') messages.push(message);
    notify();
  });
  const overflow = () => {
    if (outputExceeded) return;
    outputExceeded = true;
    killGroup(child, 'SIGTERM');
  };
  const stdoutHash = boundedOutput(child.stdout, overflow);
  const stderrHash = boundedOutput(child.stderr, overflow);
  const exited = new Promise((resolve) => {
    child.once('error', () => {
      exitRecord = Object.freeze({ code: 1, signal: null });
      notify();
      resolve(exitRecord);
    });
    child.once('exit', (code, signal) => {
      exitRecord = Object.freeze({ code: code ?? 1, signal });
      notify();
      resolve(exitRecord);
    });
  });
  let graceTimer = null;
  const deadlineTimer = setTimeout(() => {
    deadlineExpired = true;
    killGroup(child, 'SIGTERM');
    graceTimer = setTimeout(() => killGroup(child, 'SIGKILL'), CHILD_GRACE_MS);
    graceTimer.unref();
    notify();
  }, CHILD_DEADLINE_MS);
  deadlineTimer.unref();

  const waitMessage = (predicate) => new Promise((resolve, reject) => {
    let timer;
    const inspect = () => {
      const fatal = messages.find((message) => message.type === 'fatal');
      if (fatal) {
        cleanup();
        reject(Object.assign(new Error(fatal.code), { code: fatal.code }));
        return;
      }
      const found = messages.find(predicate);
      if (found) {
        cleanup();
        resolve(found);
        return;
      }
      if (deadlineExpired) {
        cleanup();
        reject(Object.assign(new Error('PROCESS_DEADLINE'), { code: 'PROCESS_DEADLINE' }));
        return;
      }
      if (outputExceeded || exitRecord !== null) {
        cleanup();
        reject(Object.assign(new Error('PROCESS_CHILD_FAILED'), { code: 'PROCESS_CHILD_FAILED' }));
      }
    };
    const cleanup = () => {
      clearTimeout(timer);
      listeners.delete(inspect);
    };
    listeners.add(inspect);
    timer = setTimeout(() => {
      cleanup();
      reject(Object.assign(new Error('PROCESS_DEADLINE'), { code: 'PROCESS_DEADLINE' }));
    }, CHILD_DEADLINE_MS);
    timer.unref();
    inspect();
  });

  const waitExit = async () => {
    const result = await exited;
    clearTimeout(deadlineTimer);
    clearTimeout(graceTimer);
    stdoutHash();
    stderrHash();
    return result;
  };

  const stop = async () => {
    if (exitRecord === null) {
      try {
        if (child.connected) child.send({ type: 'shutdown' });
        else killGroup(child, 'SIGTERM');
      } catch {
        killGroup(child, 'SIGTERM');
      }
    }
    const grace = setTimeout(() => killGroup(child, 'SIGKILL'), CHILD_GRACE_MS);
    grace.unref();
    const result = await waitExit();
    clearTimeout(grace);
    return result;
  };

  return Object.freeze({ name, child, waitMessage, waitExit, stop, exited });
}

function childEnvironment(nodeExecutable, preload, egressLog, additions = {}) {
  return Object.freeze({
    LANG: 'C.UTF-8',
    PATH: path.dirname(nodeExecutable),
    NODE_OPTIONS: `--require=${preload}`,
    WALLET_KERNEL_EGRESS_LOG_FILE: egressLog,
    ...additions,
  });
}

function route(id, kind, upstreamUrl, resourceDescription, purposeLabel) {
  return Object.freeze({
    id,
    kind,
    method: 'POST',
    upstreamUrl,
    resourceDescription,
    resourceMimeType: 'application/json',
    purposeLabel,
    requestContentTypes: Object.freeze(['application/json']),
    maximumRequestBytes: 262_144,
    maximumResponseBytes: 1_048_576,
  });
}

function routeDocument(sellerOrigin) {
  const scenarios = [
    'untrusted', 'over-budget', 'approval', 'changed-challenge', 'settled-302', 'settled-404',
    'settled-500', 'body-loss', 'pre-header-loss', 'trusted-settlement', 'delayed',
    'second-402', 'malformed-settlement', 'success-false', 'explicit-rejection',
  ];
  return Object.freeze({
    schemaVersion: 1,
    routes: Object.freeze([
      route(
        'example-model',
        'openai-chat',
        `${sellerOrigin}/paid/chat/completions`,
        'Wallet Kernel e2e model route',
        'model.infer',
      ),
      route(
        'free-model',
        'openai-chat',
        `${sellerOrigin}/paid/scenario/free-model`,
        'Wallet Kernel e2e free-model route',
        'model.infer',
      ),
      route(
        'approval-model',
        'openai-chat',
        `${sellerOrigin}/paid/scenario/approval-model`,
        'Wallet Kernel e2e approval-model route',
        'model.infer',
      ),
      route(
        'example-skill',
        'tool',
        `${sellerOrigin}/paid/skill`,
        'Wallet Kernel e2e Skill route',
        'skill.invoke',
      ),
      ...scenarios.map((scenario) => {
        const upstreamScenario = scenario === 'body-loss' ? 'delivery-loss' : scenario;
        return route(
          scenario,
          'tool',
          `${sellerOrigin}/paid/scenario/${upstreamScenario}`,
          `Wallet Kernel e2e ${upstreamScenario} route`,
          `scenario.${upstreamScenario.replaceAll('-', '_')}`,
        );
      }),
    ]),
  });
}

function policyDocument(seller) {
  return Object.freeze({
    schemaVersion: 1,
    network: NETWORK,
    asset: ASSET,
    wallet: WALLET_ADDRESS,
    methods: Object.freeze(['POST']),
    sellers: Object.freeze([Object.freeze({
      origin: seller.origin,
      pathPrefixes: Object.freeze(['/paid/']),
      payTo: PAY_TO,
      evidencePath: '/.well-known/wallet-kernel/evidence',
      executionSigner: seller.executionSigner,
      refundSigner: seller.refundSigner,
      refundSource: seller.refundSource,
      perRequestMaxAtomic: '500000',
      autoApproveAtomic: '100000',
      humanApproveAtomic: '500000',
      sellerSessionMaxAtomic: '5000000',
    })]),
    sessionMaxAtomic: '5000000',
    rolling24hMaxAtomic: '10000000',
    challengeMaxAgeMs: 60_000,
    approvalTtlMs: 1_500,
    maxPendingApprovals: 20,
    defaultAction: 'deny',
  });
}

async function responseProjection(response) {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > 2_097_152) fail('PROCESS_RESPONSE_TOO_LARGE');
  try {
    return Object.freeze({ status: response.status, value: JSON.parse(bytes.toString('utf8')) });
  } catch {
    return Object.freeze({ status: response.status, value: null });
  } finally {
    bytes.fill(0);
  }
}

async function boundedFetch(url, init = {}) {
  try {
    return await responseProjection(await fetch(url, {
      ...init,
      redirect: 'manual',
      credentials: 'omit',
      signal: AbortSignal.timeout(8_000),
    }));
  } catch (error) {
    if (error?.code === 'PROCESS_RESPONSE_TOO_LARGE') throw error;
    return Object.freeze({ status: 0, value: null });
  }
}

function newAgentCallId() {
  return crypto.randomBytes(32).toString('base64url');
}

function agentRequest(
  origin,
  token,
  routeId,
  value,
  headers = {},
  agentCallId = newAgentCallId(),
) {
  const body = canonicalJson(value);
  return boundedFetch(`${origin}/agent/v1/invoke/${routeId}`, {
    method: 'POST',
    headers: {
      authorization: `WalletKernelAgent ${token}`,
      'content-type': 'application/json',
      'x-agent-call-id': agentCallId,
      ...headers,
    },
    body,
  });
}

async function operatorRequest(origin, token, pathname, { method = 'GET', value } = {}) {
  const headers = { authorization: `Bearer ${token}` };
  const init = { method, headers };
  if (value !== undefined) {
    headers['content-type'] = 'application/json';
    init.body = canonicalJson(value);
  }
  return await boundedFetch(`${origin}${pathname}`, init);
}

function secureToken(filePath, field = null) {
  const stat = fs.lstatSync(filePath, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== BigInt(process.getuid())
      || (stat.mode & 0o7777n) !== 0o600n || stat.nlink !== 1n || stat.size > 4_096n) {
    fail('PROCESS_CREDENTIAL_INVALID');
  }
  const text = fs.readFileSync(filePath, 'utf8');
  const value = field === null ? text.trim() : JSON.parse(text)[field];
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)) {
    fail('PROCESS_CREDENTIAL_INVALID');
  }
  return value;
}

function signerCount(filePath) {
  return readJsonFile(filePath, { signerCalls: 0 })?.signerCalls ?? 0;
}

function sellerState(filePath) {
  return readJsonFile(filePath, {
    paidRequestCount: 0,
    paymentSignatureCount: 0,
    duplicatePaymentSignatureCount: 0,
    forbiddenForwardedHeaderCount: 0,
    transactionIds: [],
  });
}

function modelState(filePath) {
  return readJsonFile(filePath, {
    requestCount: 0,
    forbiddenAuthorityHeaderCount: 0,
    toolResultObserved: false,
  });
}

function verificationForProjection(bundle, receiptKey, receipts) {
  if (!bundle || typeof bundle !== 'object' || bundle.algorithm !== 'Ed25519'
      || bundle.keyId !== receiptKey?.keyId || bundle.publicKeyPem !== receiptKey?.publicKeyPem) {
    return false;
  }
  const unsigned = {
    schemaVersion: bundle.schemaVersion,
    domain: bundle.domain,
    projection: bundle.projection,
    algorithm: bundle.algorithm,
    keyId: bundle.keyId,
    publicKeyPem: bundle.publicKeyPem,
  };
  const expected = sha256(canonicalJson(unsigned));
  if (bundle.projectionHash !== expected) return false;
  let publicKey;
  let signature;
  try {
    publicKey = crypto.createPublicKey(bundle.publicKeyPem);
    signature = Buffer.from(bundle.signature, 'base64');
  } catch {
    return false;
  }
  return signature.length === 64
    && crypto.verify(null, Buffer.from(expected.slice(7), 'hex'), publicKey, signature)
    && receipts.every((receipt) => verifySignedReceipt(receipt, receiptKey));
}

function normalizedEvidenceEvents(events, receipts) {
  const receiptsByHash = new Map(receipts.map((receipt) => [receipt.receiptHash, receipt]));
  const canonicalTransactionEvents = new Set([
    'budget.committed',
    'budget.payment_resolved',
    'refund.confirmed',
  ]);
  const projectedTransactions = new Set();
  return events.map((event) => {
    const receipt = event.kind === 'receipt.issued'
      ? receiptsByHash.get(event.receiptHash) ?? null
      : null;
    const transactionId = canonicalTransactionEvents.has(event.kind)
      ? event.transactionId
      : null;
    if (transactionId !== null && projectedTransactions.has(transactionId)) {
      fail('PROCESS_TRANSACTION_REUSE');
    }
    if (transactionId !== null) projectedTransactions.add(transactionId);
    return Object.freeze({
      sequence: Number(event.id),
      eventType: event.kind,
      entityHash: event.hash,
      decision: new Set(['allow', 'approval_required', 'deny']).has(event.decision)
        ? event.decision
        : null,
      amountAtomic: event.amountAtomic,
      transactionId,
      receiptHash: receipt?.receiptHash ?? null,
      receiptSignature: receipt?.signature ?? null,
    });
  });
}

function egressAttempts(files) {
  let count = 0;
  for (const filePath of files) {
    const text = fs.readFileSync(filePath, 'utf8');
    if (text.length === 0) continue;
    const lines = text.trim().split('\n');
    for (const line of lines) {
      try {
        const record = JSON.parse(line);
        if (typeof record.destination !== 'string' || typeof record.operation !== 'string') {
          count += 1;
        } else {
          count += 1;
        }
      } catch {
        count += 1;
      }
    }
  }
  return count;
}

function observationHash(id, facts) {
  return sha256(canonicalJson({ domain: 'wallet-kernel.process-observation.v1', id, facts }));
}

function makeInvariantResults(observations) {
  return Object.freeze(INVARIANT_IDS.map((id) => {
    const entry = observations.get(id) ?? Object.freeze({ passed: false, facts: ['not_exercised'] });
    return Object.freeze({
      id,
      passed: entry.passed === true,
      facts: entry.facts,
      evidenceHash: observationHash(id, entry.facts),
    });
  }));
}

function recordObservation(observations, id, passed, facts) {
  observations.set(id, Object.freeze({ passed: passed === true, facts: Object.freeze(facts) }));
}

export async function runSpendControlProcessAcceptance({
  authorityDirectory,
  piExecutable,
  nodeExecutable = process.execPath,
}) {
  const authorityParent = validateAuthorityDirectory(authorityDirectory);
  const node = validateNodeExecutable(nodeExecutable);
  validatePiExecutable(piExecutable);
  canonicalAbsolute(PRELOAD, 'PROCESS_FIXTURE_INVALID', { file: true });
  for (const script of [MODEL_PROCESS, SELLER_PROCESS, CONTROL_PROCESS, PI_PROCESS]) {
    canonicalAbsolute(script, 'PROCESS_FIXTURE_INVALID', { file: true });
  }

  const artifacts = path.join(authorityParent, 'spend-control-process-artifacts');
  createDirectory(artifacts, 0o700);
  const privateDirectory = path.join(artifacts, 'agent-private');
  const enrollmentDirectory = path.join(artifacts, 'enrollment-handoff');
  const replacementPrivateDirectory = path.join(artifacts, 'replacement-agent-private');
  const replacementEnrollmentDirectory = path.join(
    artifacts,
    'replacement-enrollment-handoff',
  );
  const piDirectory = path.join(artifacts, 'pi-home');
  createDirectory(privateDirectory, 0o700);
  createDirectory(enrollmentDirectory, 0o755);
  createDirectory(replacementPrivateDirectory, 0o700);
  createDirectory(replacementEnrollmentDirectory, 0o755);
  createDirectory(piDirectory, 0o700);

  const credentialPath = path.join(privateDirectory, 'agent.json');
  const enrollmentPath = path.join(enrollmentDirectory, 'agent-enrollment.json');
  const replacementCredentialPath = path.join(replacementPrivateDirectory, 'agent.json');
  const replacementEnrollmentPath = path.join(
    replacementEnrollmentDirectory,
    'agent-enrollment.json',
  );
  const modelStatePath = path.join(artifacts, 'model-state.json');
  const sellerStatePath = path.join(artifacts, 'seller-state.json');
  const kernelStatePath = path.join(artifacts, 'kernel-state.json');
  const databasePath = path.join(artifacts, 'authority.sqlite');
  const receiptKeyPath = path.join(artifacts, 'receipt-key.pem');
  const operatorTokenPath = path.join(artifacts, 'operator-token');
  const policyPath = path.join(artifacts, 'policy.json');
  const routePath = path.join(artifacts, 'routes.json');
  const configPath = path.join(artifacts, 'process-config.json');
  for (const filePath of [modelStatePath, sellerStatePath, kernelStatePath]) {
    createEmptyFile(filePath);
  }

  const childNames = SPEND_CONTROL_PROCESS_CHILD_NAMES;
  const egressLogs = Object.fromEntries(childNames.map((name) => {
    const filePath = path.join(artifacts, `egress-${name}.jsonl`);
    createEmptyFile(filePath);
    return [name, filePath];
  }));
  const processExitCodes = Object.fromEntries(childNames.map((name) => [name, null]));
  const children = [];
  const observations = new Map();
  let activeControl = null;
  let finalOverview = null;
  let finalProjection = null;
  let sessionProjections = Object.freeze([]);
  let authorityReceipts = Object.freeze([]);
  let allSessionProjectionsVerified = false;
  let allAuthorityReceiptsVerified = false;
  let readyReceiptKey = null;
  let piResult = Object.freeze({
    exitCode: 1,
    piVersion: '0.80.6',
    outputObserved: 'missing',
  });
  let piApprovalResume = Object.freeze({
    tool: null,
    model: null,
  });

  const start = (options) => {
    const managed = startChild(options);
    children.push(managed);
    return managed;
  };
  const stopOne = async (managed) => {
    if (!managed) return;
    const exit = await managed.stop();
    processExitCodes[managed.name] = exit.code;
    if (activeControl === managed) activeControl = null;
  };
  const cleanup = async () => {
    fs.rmSync(artifacts, { recursive: true, force: true });
  };

  try {
    runAgentCredentialCli({
      argv: ['init', '--credential', credentialPath, '--enrollment', enrollmentPath],
      writeStdout() {},
      dependencies: {
        pathTrust: Object.freeze({
          mode: 'deterministic',
          trustedAncestor: artifacts,
          agentUid: process.getuid(),
        }),
      },
    });

    const model = start({
      name: 'model',
      nodeExecutable: node,
      script: MODEL_PROCESS,
      env: childEnvironment(node, PRELOAD, egressLogs.model, {
        WALLET_KERNEL_FIXTURE_STATE_FILE: modelStatePath,
      }),
    });
    const modelReady = await model.waitMessage((message) => message.type === 'ready');

    const seller = start({
      name: 'seller',
      nodeExecutable: node,
      script: SELLER_PROCESS,
      env: childEnvironment(node, PRELOAD, egressLogs.seller, {
        WALLET_KERNEL_FIXTURE_STATE_FILE: sellerStatePath,
        WALLET_KERNEL_FIXTURE_MODEL_ORIGIN: modelReady.origin,
      }),
    });
    const sellerReady = await seller.waitMessage((message) => message.type === 'ready');

    const policy = policyDocument(sellerReady);
    const routes = routeDocument(sellerReady.origin);
    writeCanonicalFile(policyPath, policy);
    writeCanonicalFile(routePath, routes);
    writeCanonicalFile(configPath, Object.freeze({
      schemaVersion: 1,
      authorityDirectory: artifacts,
      databasePath,
      receiptKeyPath,
      operatorTokenPath,
      policyPath,
      routePath,
      kernelStatePath,
      expectedAgentUid: process.getuid(),
      expectedAgentGid: process.getgid(),
      sellerOrigin: sellerReady.origin,
    }));

    const bootstrapChild = start({
      name: 'bootstrap',
      nodeExecutable: node,
      script: CONTROL_PROCESS,
      argv: ['--bootstrap', '--config', configPath, '--enrollment', enrollmentPath],
      env: childEnvironment(node, PRELOAD, egressLogs.bootstrap),
    });
    const bootstrapReady = await bootstrapChild.waitMessage(
      (message) => message.type === 'bootstrap-complete',
    );
    const bootstrapExit = await bootstrapChild.waitExit();
    processExitCodes.bootstrap = bootstrapExit.code;
    if (bootstrapExit.code !== 0) fail('PROCESS_BOOTSTRAP_FAILED');

    const agentToken = secureToken(credentialPath, 'token');
    const operatorToken = secureToken(operatorTokenPath);

    const launchControl = async (name) => {
      const child = start({
        name,
        nodeExecutable: node,
        script: CONTROL_PROCESS,
        argv: ['--serve', '--config', configPath],
        env: childEnvironment(node, PRELOAD, egressLogs[name]),
      });
      activeControl = child;
      const ready = await child.waitMessage((message) => message.type === 'ready');
      readyReceiptKey = ready.receiptPublicKey;
      return Object.freeze({ child, ready });
    };

    let running = await launchControl('control-initial');
    const initialSigner = signerCount(kernelStatePath);
    const initialSeller = sellerState(sellerStatePath);
    const noAuth = await boundedFetch(
      `${running.ready.agentOrigin}/agent/v1/invoke/example-skill`,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: canonicalJson({ input: 'unauthorized' }),
      },
    );
    const wrongAuth = await agentRequest(
      running.ready.agentOrigin,
      'A'.repeat(43),
      'example-skill',
      { input: 'wrong-agent' },
    );
    recordObservation(
      observations,
      'unauthorized-calls-fail-before-body',
      noAuth.status === 401 && wrongAuth.status === 401
        && signerCount(kernelStatePath) === initialSigner
        && sellerState(sellerStatePath).requestCount === initialSeller.requestCount,
      [noAuth.status, wrongAuth.status, signerCount(kernelStatePath) - initialSigner],
    );

    const denialSigner = signerCount(kernelStatePath);
    const untrusted = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'untrusted',
      { input: 'untrusted' },
    );
    const overBudget = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'over-budget',
      { input: 'over-budget' },
    );
    recordObservation(
      observations,
      'policy-denials-never-sign',
      untrusted.status === 403 && overBudget.status === 403
        && signerCount(kernelStatePath) === denialSigner,
      [untrusted.status, overBudget.status, signerCount(kernelStatePath) - denialSigner],
    );

    const allowedSigner = signerCount(kernelStatePath);
    const allowedSeller = sellerState(sellerStatePath);
    const allowed = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'allowed' },
    );
    const allowedSellerAfter = sellerState(sellerStatePath);
    const overviewAfterAllowed = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const allowedReceipts = overviewAfterAllowed.value?.data?.receipts ?? [];
    recordObservation(
      observations,
      'allowed-payment-settles-once',
      allowed.status === 200
        && signerCount(kernelStatePath) === allowedSigner + 1
        && allowedSellerAfter.paidRequestCount === allowedSeller.paidRequestCount + 1
        && allowedSellerAfter.paymentSignatureCount === allowedSeller.paymentSignatureCount + 1
        && allowedSellerAfter.duplicatePaymentSignatureCount
          === allowedSeller.duplicatePaymentSignatureCount
        && allowedReceipts.length >= 1
        && allowedReceipts.every((receipt) => verifySignedReceipt(receipt, readyReceiptKey)),
      [
        allowed.status,
        signerCount(kernelStatePath) - allowedSigner,
        allowedSellerAfter.paidRequestCount - allowedSeller.paidRequestCount,
        allowedReceipts.length,
        overviewAfterAllowed.status,
        overviewAfterAllowed.value?.error?.code ?? null,
      ],
    );

    const approvalPayload = Object.freeze({ input: 'approval' });
    const approvalCallId = newAgentCallId();
    const approvalSigner = signerCount(kernelStatePath);
    const approval = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'approval',
      approvalPayload,
      {},
      approvalCallId,
    );
    const overviewBeforeRestart = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const originalSession = overviewBeforeRestart.value?.data?.sessions?.[0] ?? null;
    const pendingBeforeRestart = overviewBeforeRestart.value?.data?.approvals?.find(
      (entry) => entry.decision === 'pending',
    ) ?? overviewBeforeRestart.value?.data?.approvals?.at(-1) ?? null;
    await stopOne(running.child);

    running = await launchControl('control-restarted');
    const overviewAfterRestart = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const restartedSession = overviewAfterRestart.value?.data?.sessions?.[0] ?? null;
    const pendingAfterRestart = overviewAfterRestart.value?.data?.approvals?.find(
      (entry) => entry.approvalId === pendingBeforeRestart?.approvalId,
    ) ?? null;
    recordObservation(
      observations,
      'credential-reattaches-session',
      approval.status === 409
        && typeof originalSession?.id === 'string'
        && typeof originalSession?.sessionHash === 'string'
        && originalSession.id === restartedSession?.id
        && originalSession?.sessionHash === restartedSession?.sessionHash,
      [approval.status,
        overviewBeforeRestart.status, overviewBeforeRestart.value?.error?.code ?? null,
        overviewAfterRestart.status, overviewAfterRestart.value?.error?.code ?? null,
        originalSession?.sessionHash ?? null, restartedSession?.sessionHash ?? null],
    );

    let approvedStatus = 0;
    let retryStatus = 0;
    if (pendingAfterRestart) {
      const approved = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/approvals/${pendingAfterRestart.approvalId}/approve`,
        {
          method: 'POST',
          value: { expectedIntentHash: pendingAfterRestart.intentHash },
        },
      );
      approvedStatus = approved.status;
      const retried = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        'approval',
        approvalPayload,
        {},
        approvalCallId,
      );
      retryStatus = retried.status;
    }
    recordObservation(
      observations,
      'approval-survives-restart',
      approval.status === 409 && pendingAfterRestart !== null
        && approvedStatus === 200 && retryStatus === 200
        && signerCount(kernelStatePath) === approvalSigner + 1,
      [approval.status, pendingAfterRestart !== null, approvedStatus, retryStatus,
        signerCount(kernelStatePath) - approvalSigner],
    );

    const pendingIds = async () => {
      const overview = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        '/operator/v1/overview',
      );
      const approvals = overview.value?.data?.approvals ?? [];
      return Object.freeze({
        overview,
        approvals,
        pending: approvals.filter((entry) => entry.decision === 'pending'),
      });
    };
    const newPendingApproval = async (beforeIds) => {
      const state = await pendingIds();
      return Object.freeze({
        ...state,
        approval: state.pending.find((entry) => !beforeIds.has(entry.approvalId)) ?? null,
      });
    };

    const denialBaseline = await pendingIds();
    const denialSignerCount = signerCount(kernelStatePath);
    const denialRequest = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'approval',
      { input: 'operator-denial' },
    );
    const denialPending = await newPendingApproval(
      new Set(denialBaseline.approvals.map((entry) => entry.approvalId)),
    );
    let denialResponse = Object.freeze({ status: 0, value: null });
    if (denialPending.approval) {
      denialResponse = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/approvals/${denialPending.approval.approvalId}/deny`,
        {
          method: 'POST',
          value: {
            expectedIntentHash: denialPending.approval.intentHash,
            reasonCode: 'OPERATOR_DENIED',
          },
        },
      );
    }

    const changedBaseline = await pendingIds();
    const changedSignerCount = signerCount(kernelStatePath);
    const changedPayload = Object.freeze({ input: 'changed-challenge' });
    const changedCallId = newAgentCallId();
    const changedRequest = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'changed-challenge',
      changedPayload,
      {},
      changedCallId,
    );
    const changedPending = await newPendingApproval(
      new Set(changedBaseline.approvals.map((entry) => entry.approvalId)),
    );
    let changedApprove = Object.freeze({ status: 0, value: null });
    let changedRetry = Object.freeze({ status: 0, value: null });
    if (changedPending.approval) {
      changedApprove = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/approvals/${changedPending.approval.approvalId}/approve`,
        {
          method: 'POST',
          value: { expectedIntentHash: changedPending.approval.intentHash },
        },
      );
      changedRetry = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        'changed-challenge',
        changedPayload,
        {},
        changedCallId,
      );
    }
    const changedAfter = await pendingIds();
    const oldChanged = changedAfter.approvals.find(
      (entry) => entry.approvalId === changedPending.approval?.approvalId,
    ) ?? null;
    const replacementApproval = changedAfter.pending.find(
      (entry) => entry.approvalId !== changedPending.approval?.approvalId,
    ) ?? null;
    recordObservation(
      observations,
      'changed-challenge-terminalizes-approval',
      changedRequest.status === 409 && changedApprove.status === 200
        && changedRetry.status === 403 && oldChanged?.decision === 'cancelled'
        && replacementApproval !== null
        && signerCount(kernelStatePath) === changedSignerCount,
      [changedRequest.status, changedApprove.status, changedRetry.status,
        oldChanged?.decision ?? null, replacementApproval !== null,
        signerCount(kernelStatePath) - changedSignerCount],
    );
    if (replacementApproval) {
      await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/approvals/${replacementApproval.approvalId}/deny`,
        {
          method: 'POST',
          value: {
            expectedIntentHash: replacementApproval.intentHash,
            reasonCode: 'OPERATOR_DENIED',
          },
        },
      );
    }

    const expiryBaseline = await pendingIds();
    const expirySignerCount = signerCount(kernelStatePath);
    const expiryPayload = Object.freeze({ input: 'approval-expiry' });
    const expiryCallId = newAgentCallId();
    const expiryRequest = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'approval',
      expiryPayload,
      {},
      expiryCallId,
    );
    const expiryPending = await newPendingApproval(
      new Set(expiryBaseline.approvals.map((entry) => entry.approvalId)),
    );
    await delay(policy.approvalTtlMs + 100);
    const expiryRetry = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'approval',
      expiryPayload,
      {},
      expiryCallId,
    );
    const decisionsAfterExpiry = await pendingIds();
    const expiredApproval = decisionsAfterExpiry.approvals.find(
      (entry) => entry.approvalId === expiryPending.approval?.approvalId,
    ) ?? null;
    recordObservation(
      observations,
      'denial-and-expiry-never-sign',
      denialRequest.status === 409 && denialResponse.status === 200
        && expiryRequest.status === 409 && expiryRetry.status >= 400
        && expiredApproval?.decision === 'expired'
        && signerCount(kernelStatePath) === denialSignerCount
        && signerCount(kernelStatePath) === expirySignerCount,
      [denialRequest.status, denialResponse.status, expiryRequest.status, expiryRetry.status,
        expiredApproval?.decision ?? null, signerCount(kernelStatePath) - denialSignerCount],
    );

    const policyBefore = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const sessionBeforePolicy = policyBefore.value?.data?.sessions?.find(
      (entry) => entry.state === 'open',
    ) ?? null;
    const tighterPolicy = Object.freeze({
      ...policy,
      sellers: Object.freeze(policy.sellers.map((entry) => Object.freeze({
        ...entry,
        sellerSessionMaxAtomic: '4500000',
      }))),
      sessionMaxAtomic: '4500000',
      rolling24hMaxAtomic: '9000000',
    });
    const tighterHash = sha256(canonicalJson(tighterPolicy));
    const policyApply = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/policies/apply',
      {
        method: 'POST',
        value: { document: tighterPolicy, expectedPolicyHash: tighterHash },
      },
    );
    const policyBlocked = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const blockedSession = policyBlocked.value?.data?.sessions?.find(
      (entry) => entry.id === sessionBeforePolicy?.id,
    ) ?? null;
    const blockedSigner = signerCount(kernelStatePath);
    const blockedAgentRequest = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'blocked-by-new-policy' },
    );
    let policyTransition = Object.freeze({ status: 0, value: null });
    if (blockedSession) {
      policyTransition = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/sessions/${blockedSession.id}/transition-policy`,
        {
          method: 'POST',
          value: {
            targetPolicyHash: tighterHash,
            expectedSessionHash: blockedSession.sessionHash,
          },
        },
      );
    }
    const policyAfter = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const transitionedSession = policyAfter.value?.data?.sessions?.find(
      (entry) => entry.id === sessionBeforePolicy?.id,
    ) ?? null;
    const replacementPolicySession = policyAfter.value?.data?.sessions?.find(
      (entry) => entry.id !== sessionBeforePolicy?.id && entry.state === 'open',
    ) ?? null;
    recordObservation(
      observations,
      'tighter-policy-requires-guarded-transition',
      policyApply.status === 200 && blockedSession?.state === 'policy_blocked'
        && blockedAgentRequest.status !== 200
        && signerCount(kernelStatePath) === blockedSigner
        && policyTransition.status === 200 && transitionedSession?.state === 'closed'
        && replacementPolicySession?.state === 'open'
        && replacementPolicySession?.policyVersionId !== sessionBeforePolicy?.policyVersionId
        && policyAfter.value?.data?.policyVersion?.policyHash === tighterHash,
      [policyApply.status, blockedSession?.state ?? null, blockedAgentRequest.status,
        signerCount(kernelStatePath) - blockedSigner, policyTransition.status,
        transitionedSession?.state ?? null, replacementPolicySession?.state ?? null,
        policyAfter.value?.data?.policyVersion?.policyHash ?? null],
    );
    if (policyApply.status === 200) replaceCanonicalFile(policyPath, tighterPolicy);

    const processOverview = async () => {
      const response = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        '/operator/v1/overview',
      );
      const data = response.value?.data ?? null;
      return Object.freeze({
        response,
        data,
        projection: data?.projection?.projection ?? null,
      });
    };
    const caseFor = (data, kind, intentId = null) => (
      (data?.reconciliations ?? []).findLast((entry) => (
        entry.kind === kind && (intentId === null || entry.intentId === intentId)
      )) ?? null
    );
    const receiptFor = (data, intentId) => (
      (data?.receipts ?? []).find((entry) => entry.intentId === intentId) ?? null
    );
    const reconcileExecutionCase = async (reconciliationCase) => {
      if (!reconciliationCase) {
        return Object.freeze({
          response: Object.freeze({ status: 0, value: null }),
          after: await processOverview(),
        });
      }
      const response = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/reconciliations/${reconciliationCase.intentId}/execution`,
        {
          method: 'POST',
          value: {
            expectedIntentHash: reconciliationCase.intentHash,
            expectedCaseHash: reconciliationCase.caseHash,
          },
        },
      );
      return Object.freeze({ response, after: await processOverview() });
    };
    const reconcilePaymentThenExecution = async (paymentCase, paymentTransactionId) => {
      if (!paymentCase) {
        return Object.freeze({
          payment: Object.freeze({ status: 0, value: null }),
          intermediate: await processOverview(),
          executionCase: null,
          execution: Object.freeze({ status: 0, value: null }),
          after: await processOverview(),
        });
      }
      const payment = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/reconciliations/${paymentCase.intentId}/payment`,
        {
          method: 'POST',
          value: {
            expectedIntentHash: paymentCase.intentHash,
            expectedCaseHash: paymentCase.caseHash,
            paymentTransactionId,
          },
        },
      );
      const intermediate = await processOverview();
      const executionCase = caseFor(intermediate.data, 'execution', paymentCase.intentId);
      const executionResult = await reconcileExecutionCase(executionCase);
      return Object.freeze({
        payment,
        intermediate,
        executionCase,
        execution: executionResult.response,
        after: executionResult.after,
      });
    };

    const publicTransactions = async () => await boundedFetch(
      `${sellerReady.origin}/fixture/v1/public-transactions`,
    );
    const reconcileRefundCase = async (reconciliationCase, refundTransactionId) => {
      if (!reconciliationCase) return Object.freeze({ status: 0, value: null });
      return await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/reconciliations/${reconciliationCase.intentId}/refund-observation`,
        {
          method: 'POST',
          value: {
            expectedIntentHash: reconciliationCase.intentHash,
            expectedCaseHash: reconciliationCase.caseHash,
            refundTransactionId,
          },
        },
      );
    };

    const httpFailureResults = [];
    let wrongRefundEvidence = null;
    for (const [routeId, expectedStatus] of [
      ['settled-302', 502],
      ['settled-404', 404],
      ['settled-500', 500],
    ]) {
      const beforeSigner = signerCount(kernelStatePath);
      const beforeSeller = sellerState(sellerStatePath);
      const response = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        routeId,
        { input: routeId },
      );
      const afterSeller = sellerState(sellerStatePath);
      const paymentTransactionId = afterSeller.transactionIds.at(-1) ?? null;
      const blocked = await processOverview();
      const refundCase = caseFor(blocked.data, 'refund-observation');
      const initialReceipt = receiptFor(blocked.data, refundCase?.intentId);
      const blockProbeSigner = signerCount(kernelStatePath);
      const blockProbe = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        'example-skill',
        { input: `blocked-${routeId}` },
      );
      const mappingResponse = await publicTransactions();
      const mapping = mappingResponse.value?.payments?.find(
        (entry) => entry.paymentTransactionId === paymentTransactionId,
      ) ?? null;
      let currentCase = refundCase;
      let wrong = Object.freeze({ status: 0, value: null });
      let afterWrong = null;
      let wrongReceipt = null;
      if (routeId === 'settled-302' && mappingResponse.value?.wrongRefundTransactionId) {
        wrong = await reconcileRefundCase(
          currentCase,
          mappingResponse.value.wrongRefundTransactionId,
        );
        afterWrong = await processOverview();
        wrongReceipt = receiptFor(afterWrong.data, refundCase?.intentId);
        currentCase = caseFor(afterWrong.data, 'refund-observation', refundCase?.intentId);
      }
      const correct = await reconcileRefundCase(currentCase, mapping?.refundTransactionId ?? null);
      const after = await processOverview();
      const finalReceipt = receiptFor(after.data, refundCase?.intentId);
      let exactReplay = Object.freeze({ status: 0, value: null });
      let afterExactReplay = null;
      let replayReceipt = null;
      if (routeId === 'settled-302') {
        exactReplay = await reconcileRefundCase(
          currentCase,
          mapping?.refundTransactionId ?? null,
        );
        afterExactReplay = await processOverview();
        replayReceipt = receiptFor(afterExactReplay.data, refundCase?.intentId);
      }
      const result = Object.freeze({
        routeId,
        expectedStatus,
        beforeSigner,
        beforeSeller,
        response,
        afterSeller,
        paymentTransactionId,
        blocked,
        refundCase,
        initialReceipt,
        blockProbeSigner,
        blockProbe,
        mappingResponse,
        mapping,
        wrong,
        afterWrong,
        wrongReceipt,
        correct,
        after,
        finalReceipt,
        exactReplay,
        afterExactReplay,
        replayReceipt,
      });
      if (routeId === 'settled-302') wrongRefundEvidence = result;
      httpFailureResults.push(result);
    }
    recordObservation(
      observations,
      'settled-http-failures-commit-and-block',
      httpFailureResults.length === 3 && httpFailureResults.every((entry) => (
        entry.response.status === entry.expectedStatus
          && entry.refundCase !== null
          && entry.initialReceipt?.receipt?.payment?.state === 'settled'
          && entry.initialReceipt?.receipt?.execution?.state === 'failed'
          && entry.initialReceipt?.receipt?.budget?.disposition === 'committed'
          && entry.initialReceipt?.receipt?.refund?.state === 'pending'
          && entry.blocked.projection?.blockers?.walletBlocked === true
          && entry.blockProbe.status !== 200
          && entry.blockProbeSigner === entry.beforeSigner + 1
          && entry.afterSeller.paidRequestCount === entry.beforeSeller.paidRequestCount + 1
          && entry.afterSeller.duplicatePaymentSignatureCount
            === entry.beforeSeller.duplicatePaymentSignatureCount
          && entry.correct.status === 200
          && entry.finalReceipt?.receipt?.outcome?.status === 'refunded'
          && entry.finalReceipt?.receipt?.budget?.disposition === 'released'
          && entry.after.projection?.blockers?.walletBlocked === false
      )),
      httpFailureResults.flatMap((entry) => [
        entry.routeId,
        entry.response.status,
        entry.refundCase !== null,
        entry.initialReceipt?.receipt?.budget?.disposition ?? null,
        entry.initialReceipt?.receipt?.refund?.state ?? null,
        entry.blockProbe.status,
        entry.afterSeller.duplicatePaymentSignatureCount
          - entry.beforeSeller.duplicatePaymentSignatureCount,
        entry.correct.status,
        entry.finalReceipt?.receipt?.budget?.disposition ?? null,
      ]),
    );
    recordObservation(
      observations,
      'refund-releases-only-after-full-proof',
      wrongRefundEvidence !== null
        && wrongRefundEvidence.wrong.status === 200
        && wrongRefundEvidence.wrongReceipt?.receipt?.refund?.state === 'rejected'
        && wrongRefundEvidence.wrongReceipt?.receipt?.budget?.disposition === 'committed'
        && wrongRefundEvidence.afterWrong?.projection?.blockers?.walletBlocked === true
        && wrongRefundEvidence.correct.status === 200
        && wrongRefundEvidence.finalReceipt?.receipt?.refund?.state === 'confirmed'
        && wrongRefundEvidence.finalReceipt?.receipt?.budget?.disposition === 'released'
        && wrongRefundEvidence.finalReceipt?.revision
          === wrongRefundEvidence.initialReceipt?.revision + 2
        && wrongRefundEvidence.finalReceipt?.supersedesReceiptHash
          === wrongRefundEvidence.wrongReceipt?.receiptHash
        && wrongRefundEvidence.after.projection?.blockers?.walletBlocked === false
        && wrongRefundEvidence.exactReplay.status === 200
        && wrongRefundEvidence.replayReceipt?.receiptHash
          === wrongRefundEvidence.finalReceipt?.receiptHash
        && wrongRefundEvidence.replayReceipt?.revision
          === wrongRefundEvidence.finalReceipt?.revision
        && wrongRefundEvidence.afterExactReplay?.data?.reconciliations?.length
          === wrongRefundEvidence.after?.data?.reconciliations?.length
        && wrongRefundEvidence.afterExactReplay?.projection?.blockers?.walletBlocked === false,
      [wrongRefundEvidence?.wrong.status ?? null,
        wrongRefundEvidence?.wrongReceipt?.receipt?.refund?.state ?? null,
        wrongRefundEvidence?.wrongReceipt?.receipt?.budget?.disposition ?? null,
        wrongRefundEvidence?.afterWrong?.projection?.blockers?.walletBlocked ?? null,
        wrongRefundEvidence?.correct.status ?? null,
        wrongRefundEvidence?.finalReceipt?.receipt?.refund?.state ?? null,
        wrongRefundEvidence?.finalReceipt?.receipt?.budget?.disposition ?? null,
        wrongRefundEvidence?.initialReceipt?.revision ?? null,
        wrongRefundEvidence?.wrongReceipt?.revision ?? null,
        wrongRefundEvidence?.finalReceipt?.revision ?? null,
        wrongRefundEvidence?.exactReplay.status ?? null,
        wrongRefundEvidence?.replayReceipt?.revision ?? null,
        wrongRefundEvidence?.replayReceipt?.receiptHash
          === wrongRefundEvidence?.finalReceipt?.receiptHash],
    );

    const bodyLossSigner = signerCount(kernelStatePath);
    const bodyLossSeller = sellerState(sellerStatePath);
    const bodyLoss = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'body-loss',
      { input: 'body-loss' },
    );
    const bodyLossBlocked = await processOverview();
    const bodyLossCase = caseFor(bodyLossBlocked.data, 'execution');
    const bodyLossReceipt = receiptFor(bodyLossBlocked.data, bodyLossCase?.intentId);
    const bodyLossBlockProbe = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'blocked-after-body-loss' },
    );
    const bodyLossResolved = await reconcileExecutionCase(bodyLossCase);
    const bodyLossRevised = receiptFor(bodyLossResolved.after.data, bodyLossCase?.intentId);
    recordObservation(
      observations,
      'body-loss-execution-reconciliation',
      bodyLoss.status === 502 && bodyLossCase !== null
        && bodyLossReceipt?.receipt?.payment?.state === 'settled'
        && bodyLossReceipt?.receipt?.execution?.state === 'unknown'
        && bodyLossReceipt?.receipt?.budget?.disposition === 'committed'
        && bodyLossBlocked.projection?.blockers?.walletBlocked === true
        && bodyLossBlockProbe.status !== 200
        && signerCount(kernelStatePath) === bodyLossSigner + 1
        && sellerState(sellerStatePath).paidRequestCount === bodyLossSeller.paidRequestCount + 1
        && bodyLossResolved.response.status === 200
        && bodyLossRevised?.revision === bodyLossReceipt.revision + 1
        && bodyLossRevised?.supersedesReceiptHash === bodyLossReceipt.receiptHash
        && caseFor(bodyLossResolved.after.data, 'execution', bodyLossCase.intentId) === null
        && bodyLossResolved.after.projection?.blockers?.walletBlocked === false,
      [bodyLoss.status, bodyLossCase !== null, bodyLossReceipt?.receipt?.payment?.state ?? null,
        bodyLossReceipt?.receipt?.execution?.state ?? null, bodyLossBlockProbe.status,
        signerCount(kernelStatePath) - bodyLossSigner, bodyLossResolved.response.status,
        bodyLossReceipt?.revision ?? null, bodyLossRevised?.revision ?? null,
        bodyLossResolved.after.projection?.blockers?.walletBlocked ?? null],
    );

    const runLostPaidResponse = async (routeId, label) => {
      const beforeSigner = signerCount(kernelStatePath);
      const beforeSeller = sellerState(sellerStatePath);
      const response = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        routeId,
        { input: label },
      );
      const afterSeller = sellerState(sellerStatePath);
      const transactionId = afterSeller.transactionIds.at(-1) ?? null;
      const blocked = await processOverview();
      const paymentCase = caseFor(blocked.data, 'payment');
      const initialReceipt = receiptFor(blocked.data, paymentCase?.intentId);
      const blockProbeSigner = signerCount(kernelStatePath);
      const blockProbe = await agentRequest(
        running.ready.agentOrigin,
        agentToken,
        'example-skill',
        { input: `blocked-${label}` },
      );
      const resolved = await reconcilePaymentThenExecution(paymentCase, transactionId);
      const intermediateReceipt = receiptFor(resolved.intermediate.data, paymentCase?.intentId);
      const finalReceipt = receiptFor(resolved.after.data, paymentCase?.intentId);
      return Object.freeze({
        beforeSigner,
        beforeSeller,
        response,
        afterSeller,
        transactionId,
        blocked,
        paymentCase,
        initialReceipt,
        blockProbeSigner,
        blockProbe,
        resolved,
        intermediateReceipt,
        finalReceipt,
      });
    };

    const preHeaderLoss = await runLostPaidResponse('pre-header-loss', 'pre-header-loss');
    recordObservation(
      observations,
      'pre-settlement-loss-holds-budget',
      preHeaderLoss.response.status === 503 && preHeaderLoss.paymentCase !== null
        && preHeaderLoss.initialReceipt?.receipt?.payment?.state === 'unresolved'
        && preHeaderLoss.initialReceipt?.receipt?.budget?.disposition === 'unresolved'
        && preHeaderLoss.blocked.projection?.blockers?.walletBlocked === true
        && preHeaderLoss.blockProbe.status !== 200
        && preHeaderLoss.blockProbeSigner === preHeaderLoss.beforeSigner + 1
        && signerCount(kernelStatePath) >= preHeaderLoss.blockProbeSigner
        && preHeaderLoss.afterSeller.duplicatePaymentSignatureCount
          === preHeaderLoss.beforeSeller.duplicatePaymentSignatureCount
        && preHeaderLoss.resolved.payment.status === 200
        && preHeaderLoss.resolved.execution.status === 200,
      [preHeaderLoss.response.status, preHeaderLoss.paymentCase !== null,
        preHeaderLoss.initialReceipt?.receipt?.payment?.state ?? null,
        preHeaderLoss.initialReceipt?.receipt?.budget?.disposition ?? null,
        preHeaderLoss.blockProbe.status,
        preHeaderLoss.afterSeller.duplicatePaymentSignatureCount
          - preHeaderLoss.beforeSeller.duplicatePaymentSignatureCount,
        preHeaderLoss.resolved.payment.status, preHeaderLoss.resolved.execution.status],
    );

    const ambiguousResults = [];
    for (const routeId of ['second-402', 'success-false']) {
      ambiguousResults.push(await runLostPaidResponse(routeId, routeId));
    }
    recordObservation(
      observations,
      'post-signature-ambiguity-is-unresolved',
      ambiguousResults.length === 2 && ambiguousResults.every((entry) => (
        entry.response.status === 503
          && entry.paymentCase !== null
          && entry.initialReceipt?.receipt?.outcome?.status === 'payment_unresolved'
          && entry.initialReceipt?.receipt?.payment?.state === 'unresolved'
          && entry.initialReceipt?.receipt?.budget?.disposition === 'unresolved'
          && entry.afterSeller.duplicatePaymentSignatureCount
            === entry.beforeSeller.duplicatePaymentSignatureCount
          && entry.resolved.payment.status === 200
          && entry.resolved.execution.status === 200
      )),
      ambiguousResults.flatMap((entry) => [
        entry.response.status,
        entry.initialReceipt?.receipt?.outcome?.status ?? null,
        entry.initialReceipt?.receipt?.payment?.state ?? null,
        entry.afterSeller.duplicatePaymentSignatureCount
          - entry.beforeSeller.duplicatePaymentSignatureCount,
        entry.resolved.payment.status,
        entry.resolved.execution.status,
      ]),
    );

    const trustedSettlement = await runLostPaidResponse(
      'trusted-settlement',
      'trusted-settlement',
    );
    recordObservation(
      observations,
      'trusted-settlement-needs-execution-evidence',
      trustedSettlement.response.status === 503 && trustedSettlement.paymentCase !== null
        && trustedSettlement.resolved.payment.status === 200
        && trustedSettlement.intermediateReceipt?.receipt?.payment?.state === 'settled'
        && trustedSettlement.intermediateReceipt?.receipt?.execution?.state === 'unknown'
        && trustedSettlement.intermediateReceipt?.receipt?.budget?.disposition === 'committed'
        && trustedSettlement.resolved.intermediate.projection?.blockers?.walletBlocked === true
        && trustedSettlement.resolved.execution.status === 200
        && trustedSettlement.finalReceipt?.receipt?.execution?.state === 'succeeded'
        && trustedSettlement.resolved.after.projection?.blockers?.walletBlocked === false
        && trustedSettlement.afterSeller.duplicatePaymentSignatureCount
          === trustedSettlement.beforeSeller.duplicatePaymentSignatureCount,
      [trustedSettlement.response.status, trustedSettlement.paymentCase !== null,
        trustedSettlement.resolved.payment.status,
        trustedSettlement.intermediateReceipt?.receipt?.payment?.state ?? null,
        trustedSettlement.intermediateReceipt?.receipt?.execution?.state ?? null,
        trustedSettlement.resolved.intermediate.projection?.blockers?.walletBlocked ?? null,
        trustedSettlement.resolved.execution.status,
        trustedSettlement.finalReceipt?.receipt?.execution?.state ?? null],
    );

    const waitForFreshPendingApproval = async (knownApprovalIds) => {
      const deadline = Date.now() + 8_000;
      while (Date.now() < deadline) {
        const overview = await processOverview();
        const pending = (overview.data?.approvals ?? []).find((entry) => (
          entry.decision === 'pending' && !knownApprovalIds.has(entry.approvalId)
        )) ?? null;
        if (pending !== null) return Object.freeze({ overview, pending });
        await delay(20);
      }
      return Object.freeze({ overview: null, pending: null });
    };
    const runPinnedPiApproval = async ({
      name,
      modelRoute,
      skillRoute,
      modelRequestsBeforeApproval,
      modelRequestsAfterCompletion,
    }) => {
      const baseline = await processOverview();
      const knownApprovalIds = new Set(
        (baseline.data?.approvals ?? []).map(({ approvalId }) => approvalId),
      );
      const beforeSigner = signerCount(kernelStatePath);
      const beforeSeller = sellerState(sellerStatePath);
      const beforeModel = modelState(modelStatePath);
      const pi = start({
        name,
        nodeExecutable: node,
        script: PI_PROCESS,
        env: childEnvironment(node, PRELOAD, egressLogs[name], {
          WALLET_KERNEL_FIXTURE_PI_DIRECTORY: piDirectory,
          WALLET_KERNEL_AGENT_CREDENTIAL_FILE: credentialPath,
          WALLET_KERNEL_FIXTURE_PRELOAD: PRELOAD,
          WALLET_KERNEL_ORIGIN: running.ready.agentOrigin,
          WALLET_KERNEL_PROVIDER_NAME: 'wallet-kernel-e2e',
          WALLET_KERNEL_MODEL_NAME: 'scripted-local',
          WALLET_KERNEL_MODEL_ROUTE: modelRoute,
          WALLET_KERNEL_SKILL_ROUTE: skillRoute,
        }),
      });
      let exited = false;
      void pi.exited.then(() => { exited = true; });
      const observed = await waitForFreshPendingApproval(knownApprovalIds);
      await delay(150);
      const modelWhilePending = modelState(modelStatePath);
      const originalRequestHeld = observed.pending !== null
        && exited === false
        && modelWhilePending.requestCount
          === beforeModel.requestCount + modelRequestsBeforeApproval;
      let operatorApprovalStatus = 0;
      if (observed.pending !== null) {
        const approved = await operatorRequest(
          running.ready.operatorOrigin,
          operatorToken,
          `/operator/v1/approvals/${observed.pending.approvalId}/approve`,
          {
            method: 'POST',
            value: { expectedIntentHash: observed.pending.intentHash },
          },
        );
        operatorApprovalStatus = approved.status;
      }
      let result;
      try {
        result = await pi.waitMessage((message) => message.type === 'result');
      } catch {
        result = Object.freeze({
          exitCode: 1,
          piVersion: '0.80.6',
          outputObserved: 'missing',
        });
      }
      const exit = await pi.waitExit();
      processExitCodes[name] = exit.code;
      const afterSeller = sellerState(sellerStatePath);
      const afterModel = modelState(modelStatePath);
      const publicResult = Object.freeze({
        pendingObserved: observed.pending !== null,
        originalRequestHeld,
        operatorApprovalStatus,
        signerDelta: signerCount(kernelStatePath) - beforeSigner,
        paidRequestDelta: afterSeller.paidRequestCount - beforeSeller.paidRequestCount,
        duplicatePaymentSignatureDelta: afterSeller.duplicatePaymentSignatureCount
          - beforeSeller.duplicatePaymentSignatureCount,
        outputObserved: result.outputObserved ?? 'missing',
        processExitCode: exit.code,
      });
      return Object.freeze({
        publicResult,
        modelRequestDelta: afterModel.requestCount - beforeModel.requestCount,
        expectedModelRequestDelta: modelRequestsAfterCompletion,
        result,
      });
    };

    const piToolApproval = await runPinnedPiApproval({
      name: 'pi-tool-approval',
      modelRoute: 'free-model',
      skillRoute: 'approval',
      modelRequestsBeforeApproval: 1,
      modelRequestsAfterCompletion: 2,
    });
    const piModelApproval = await runPinnedPiApproval({
      name: 'pi-model-approval',
      modelRoute: 'approval-model',
      skillRoute: 'example-skill',
      modelRequestsBeforeApproval: 0,
      modelRequestsAfterCompletion: 1,
    });
    piApprovalResume = Object.freeze({
      tool: piToolApproval.publicResult,
      model: piModelApproval.publicResult,
    });
    const piApprovalProved = [piToolApproval, piModelApproval].every((entry) => (
      entry.publicResult.pendingObserved === true
        && entry.publicResult.originalRequestHeld === true
        && entry.publicResult.operatorApprovalStatus === 200
        && entry.publicResult.signerDelta === 1
        && entry.publicResult.paidRequestDelta === 1
        && entry.publicResult.duplicatePaymentSignatureDelta === 0
        && entry.publicResult.outputObserved === 'PI_WALLET_OK'
        && entry.publicResult.processExitCode === 0
        && entry.modelRequestDelta === entry.expectedModelRequestDelta
    ));
    const approvalObservation = observations.get('approval-survives-restart');
    recordObservation(
      observations,
      'approval-survives-restart',
      approvalObservation?.passed === true && piApprovalProved,
      [
        ...(approvalObservation?.facts ?? ['not_exercised']),
        ...Object.values(piApprovalResume).flatMap((entry) => [
          entry.pendingObserved,
          entry.originalRequestHeld,
          entry.operatorApprovalStatus,
          entry.signerDelta,
          entry.paidRequestDelta,
          entry.duplicatePaymentSignatureDelta,
          entry.outputObserved,
          entry.processExitCode,
        ]),
        piToolApproval.modelRequestDelta,
        piModelApproval.modelRequestDelta,
      ],
    );
    piResult = Object.freeze({
      exitCode: piApprovalProved ? 0 : 1,
      piVersion: '0.80.6',
      outputObserved: piApprovalProved ? 'PI_WALLET_OK' : 'missing',
    });

    const historyOverview = await processOverview();
    const historicalReceipts = (historyOverview.data?.receipts ?? []).map((receipt) => (
      Object.freeze({
        intentId: receipt.intentId,
        receiptHash: receipt.receiptHash,
        disposition: receipt.receipt?.budget?.disposition ?? null,
      })
    ));
    const historicalEvents = (historyOverview.data?.events ?? []).map((event) => (
      Object.freeze({ id: event.id, hash: event.hash })
    ));
    const historySessionCount = historyOverview.data?.sessions?.length ?? 0;
    const originalDescriptor = readJsonFile(enrollmentPath);
    const originalDescriptorHash = sha256(canonicalJson(originalDescriptor));

    const recoveryAmbiguitySigner = signerCount(kernelStatePath);
    const recoveryAmbiguitySeller = sellerState(sellerStatePath);
    const recoveryAmbiguity = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'pre-header-loss',
      { input: 'retained-for-recovery' },
    );
    const recoveryAmbiguitySellerAfter = sellerState(sellerStatePath);
    const recoveryTransactionId = recoveryAmbiguitySellerAfter.transactionIds.at(-1) ?? null;
    const recoveryBlocked = await processOverview();
    const retainedSession = recoveryBlocked.data?.sessions?.find(
      (entry) => entry.state === 'open',
    ) ?? null;
    const retainedPaymentCase = caseFor(recoveryBlocked.data, 'payment');
    const retainedInitialReceipt = receiptFor(
      recoveryBlocked.data,
      retainedPaymentCase?.intentId,
    );
    const signerAfterAmbiguity = signerCount(kernelStatePath);

    const revoke = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      `/operator/v1/agents/${originalDescriptor?.agentInstanceId}/revoke`,
      {
        method: 'POST',
        value: { expectedEnrollmentHash: originalDescriptorHash },
      },
    );
    const signerAfterRevocation = signerCount(kernelStatePath);
    const sellerAfterRevocation = sellerState(sellerStatePath);
    const revokedOldToken = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'revoked-token' },
    );
    const signerAfterRevokedToken = signerCount(kernelStatePath);
    const sellerAfterRevokedToken = sellerState(sellerStatePath);

    await stopOne(running.child);
    running = await launchControl('control-recovery');
    const recoveryOverview = await processOverview();
    const recoverySession = recoveryOverview.data?.sessions?.find(
      (entry) => entry.id === retainedSession?.id,
    ) ?? null;
    const recoverySessionCount = recoveryOverview.data?.sessions?.length ?? 0;
    const recoverySignerBeforeWork = signerCount(kernelStatePath);
    const recoveryOldToken = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'recovery-only-token' },
    );
    const recoveryPaymentCase = caseFor(
      recoveryOverview.data,
      'payment',
      retainedPaymentCase?.intentId,
    );
    const recoveryResolved = await reconcilePaymentThenExecution(
      recoveryPaymentCase,
      recoveryTransactionId,
    );
    const recoveryIntermediateReceipt = receiptFor(
      recoveryResolved.intermediate.data,
      retainedPaymentCase?.intentId,
    );
    const recoveryFinalReceipt = receiptFor(
      recoveryResolved.after.data,
      retainedPaymentCase?.intentId,
    );
    const closableSession = recoveryResolved.after.data?.sessions?.find(
      (entry) => entry.id === retainedSession?.id,
    ) ?? null;
    const recoveryClose = closableSession === null
      ? Object.freeze({ status: 0, value: null })
      : await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/sessions/${closableSession.id}/close`,
        {
          method: 'POST',
          value: { expectedSessionHash: closableSession.sessionHash },
        },
      );
    const recoveryAfterClose = await processOverview();
    const closedRetainedSession = recoveryAfterClose.data?.sessions?.find(
      (entry) => entry.id === retainedSession?.id,
    ) ?? null;
    const recoverySignerAfterWork = signerCount(kernelStatePath);
    const recoverySellerAfterWork = sellerState(sellerStatePath);
    await stopOne(running.child);

    runAgentCredentialCli({
      argv: [
        'init',
        '--credential',
        replacementCredentialPath,
        '--enrollment',
        replacementEnrollmentPath,
      ],
      writeStdout() {},
      dependencies: {
        pathTrust: Object.freeze({
          mode: 'deterministic',
          trustedAncestor: artifacts,
          agentUid: process.getuid(),
        }),
      },
    });
    const replacementDescriptor = readJsonFile(replacementEnrollmentPath);
    const replacementDescriptorHash = sha256(canonicalJson(replacementDescriptor));
    const replacementToken = secureToken(replacementCredentialPath, 'token');
    const replacementBootstrap = start({
      name: 'bootstrap-replacement',
      nodeExecutable: node,
      script: CONTROL_PROCESS,
      argv: [
        '--bootstrap',
        '--config',
        configPath,
        '--enrollment',
        replacementEnrollmentPath,
      ],
      env: childEnvironment(node, PRELOAD, egressLogs['bootstrap-replacement']),
    });
    const replacementBootstrapReady = await replacementBootstrap.waitMessage(
      (message) => message.type === 'bootstrap-complete',
    );
    const replacementBootstrapExit = await replacementBootstrap.waitExit();
    processExitCodes['bootstrap-replacement'] = replacementBootstrapExit.code;
    if (replacementBootstrapExit.code !== 0) fail('PROCESS_REPLACEMENT_BOOTSTRAP_FAILED');

    running = await launchControl('control-replacement');
    const replacementBefore = await processOverview();
    const replacementSession = replacementBefore.data?.sessions?.find(
      (entry) => entry.state === 'open',
    ) ?? null;
    const replacementSignerBefore = signerCount(kernelStatePath);
    const replacementOldToken = await agentRequest(
      running.ready.agentOrigin,
      agentToken,
      'example-skill',
      { input: 'superseded-token' },
    );
    const replacementSignerAfterOldToken = signerCount(kernelStatePath);
    const replacementSellerBefore = sellerState(sellerStatePath);
    const replacementRequest = await agentRequest(
      running.ready.agentOrigin,
      replacementToken,
      'example-skill',
      { input: 'replacement-enrollment' },
    );
    const replacementAfter = await processOverview();
    const replacementSellerAfter = sellerState(sellerStatePath);
    const replacementSignerAfter = signerCount(kernelStatePath);

    await stopOne(running.child);
    running = await launchControl('control-verifier');
    finalOverview = await operatorRequest(
      running.ready.operatorOrigin,
      operatorToken,
      '/operator/v1/overview',
    );
    const finalData = finalOverview.value?.data ?? null;
    const finalSession = finalData?.sessions?.find((entry) => entry.state === 'open') ?? null;
    const finalSessions = Array.isArray(finalData?.sessions) ? finalData.sessions : [];
    const exportedSessions = [];
    for (const session of finalSessions) {
      const exported = await operatorRequest(
        running.ready.operatorOrigin,
        operatorToken,
        `/operator/v1/exports/${session.id}`,
      );
      exportedSessions.push(Object.freeze({
        sessionId: session.id,
        status: exported.status,
        bundle: exported.value?.data ?? null,
      }));
    }
    finalProjection = exportedSessions.find(({ sessionId }) => (
      sessionId === finalSession?.id
    ))?.bundle ?? null;
    sessionProjections = Object.freeze(exportedSessions
      .filter(({ status, bundle }) => status === 200 && bundle !== null)
      .map(({ bundle }) => bundle)
      .sort((left, right) => (
        left.projection.sessionHash.localeCompare(right.projection.sessionHash)
      )));
    const authorityReceiptByHash = new Map();
    for (const bundle of sessionProjections) {
      for (const receipt of bundle.projection?.signedReceipts ?? []) {
        authorityReceiptByHash.set(receipt.receiptHash, receipt);
      }
    }
    authorityReceipts = Object.freeze([...authorityReceiptByHash.values()].sort(
      (left, right) => left.intentId.localeCompare(right.intentId)
        || left.revision - right.revision
        || left.id.localeCompare(right.id),
    ));
    allSessionProjectionsVerified = finalSessions.length > 0
      && exportedSessions.length === finalSessions.length
      && exportedSessions.every(({ status, bundle }) => {
        const sessionReceipts = bundle?.projection?.signedReceipts ?? [];
        return status === 200
          && verificationForProjection(bundle, readyReceiptKey, sessionReceipts);
      });
    allAuthorityReceiptsVerified = authorityReceipts.length > 0
      && authorityReceipts.every((receipt) => verifySignedReceipt(receipt, readyReceiptKey));
    const receipts = finalProjection?.projection?.signedReceipts ?? [];
    const projectionVerified = verificationForProjection(
      finalProjection,
      readyReceiptKey,
      receipts,
    );
    const finalReceiptByIntent = new Map(
      (finalData?.receipts ?? []).map((receipt) => [receipt.intentId, receipt]),
    );
    const finalEventById = new Map(
      (finalData?.events ?? []).map((event) => [event.id, event]),
    );
    const historyPreserved = historicalReceipts.every((historical) => {
      const current = finalReceiptByIntent.get(historical.intentId);
      return current?.receiptHash === historical.receiptHash
        && (current.receipt?.budget?.disposition ?? null) === historical.disposition;
    }) && historicalEvents.every((historical) => (
      finalEventById.get(historical.id)?.hash === historical.hash
    ));
    const finalOpenSessions = (finalData?.sessions ?? []).filter(
      (entry) => entry.state === 'open',
    );
    const finalRetainedSession = finalData?.sessions?.find(
      (entry) => entry.id === retainedSession?.id,
    ) ?? null;
    recordObservation(
      observations,
      'revocation-recovery-and-replacement',
      historyOverview.response.status === 200
        && bootstrapReady.descriptorHash === originalDescriptorHash
        && recoveryAmbiguity.status === 503
        && retainedPaymentCase !== null
        && retainedInitialReceipt?.receipt?.payment?.state === 'unresolved'
        && retainedInitialReceipt?.receipt?.budget?.disposition === 'unresolved'
        && recoveryBlocked.projection?.blockers?.walletBlocked === true
        && signerAfterAmbiguity === recoveryAmbiguitySigner + 1
        && recoveryAmbiguitySellerAfter.paidRequestCount
          === recoveryAmbiguitySeller.paidRequestCount + 1
        && revoke.status === 200
        && signerAfterRevocation === signerAfterAmbiguity
        && revokedOldToken.status !== 200
        && signerAfterRevokedToken === signerAfterRevocation
        && sellerAfterRevokedToken.paidRequestCount === sellerAfterRevocation.paidRequestCount
        && recoveryOverview.response.status === 200
        && recoverySession?.state === 'open'
        && recoverySessionCount === historySessionCount
        && recoveryOldToken.status === 503
        && recoveryOldToken.value?.error?.code === 'AGENT_ENROLLMENT_REQUIRED'
        && recoveryResolved.payment.status === 200
        && recoveryIntermediateReceipt?.receipt?.payment?.state === 'settled'
        && recoveryIntermediateReceipt?.receipt?.execution?.state === 'unknown'
        && recoveryIntermediateReceipt?.receipt?.budget?.disposition === 'committed'
        && recoveryResolved.intermediate.projection?.blockers?.walletBlocked === true
        && recoveryResolved.execution.status === 200
        && recoveryFinalReceipt?.receipt?.execution?.state === 'succeeded'
        && recoveryResolved.after.projection?.blockers?.walletBlocked === false
        && recoveryClose.status === 200
        && closedRetainedSession?.state === 'closed'
        && recoverySignerAfterWork === recoverySignerBeforeWork
        && recoverySellerAfterWork.paidRequestCount === sellerAfterRevocation.paidRequestCount
        && replacementBootstrapReady.descriptorHash === replacementDescriptorHash
        && replacementBootstrapReady.policyHash === tighterHash
        && replacementDescriptor?.agentInstanceId !== originalDescriptor?.agentInstanceId
        && replacementDescriptorHash !== originalDescriptorHash
        && replacementBefore.response.status === 200
        && replacementSession?.state === 'open'
        && replacementSession?.policyVersionId === retainedSession?.policyVersionId
        && replacementBefore.data?.policyVersion?.policyHash === tighterHash
        && replacementBefore.projection?.agentEnrollment?.enrollmentHash
          === replacementDescriptorHash
        && replacementBefore.projection?.isolation?.status === 'simulated'
        && replacementBefore.projection?.isolation?.preflightDigest === null
        && replacementOldToken.status !== 200
        && replacementSignerAfterOldToken === replacementSignerBefore
        && replacementRequest.status === 200
        && replacementSignerAfter === replacementSignerBefore + 1
        && replacementSellerAfter.paidRequestCount
          === replacementSellerBefore.paidRequestCount + 1
        && finalOverview.status === 200
        && finalOpenSessions.length === 1
        && finalSession?.id === replacementSession?.id
        && finalSession?.sessionHash === replacementSession?.sessionHash
        && finalSession?.policyVersionId === retainedSession?.policyVersionId
        && finalRetainedSession?.state === 'closed'
        && (finalData?.sessions?.length ?? 0) === historySessionCount + 1
        && finalData?.policyVersion?.policyHash === tighterHash
        && historyPreserved,
      [recoveryAmbiguity.status, retainedPaymentCase !== null,
        retainedInitialReceipt?.receipt?.budget?.disposition ?? null,
        signerAfterAmbiguity - recoveryAmbiguitySigner,
        revoke.status, revokedOldToken.status,
        recoveryOverview.response.status, recoverySession?.state ?? null,
        recoverySessionCount - historySessionCount,
        recoveryOldToken.status, recoveryOldToken.value?.error?.code ?? null,
        recoveryResolved.payment.status, recoveryResolved.execution.status,
        recoveryFinalReceipt?.receipt?.execution?.state ?? null,
        recoveryClose.status, closedRetainedSession?.state ?? null,
        recoverySignerAfterWork - recoverySignerBeforeWork,
        replacementBootstrapReady.descriptorHash === replacementDescriptorHash,
        replacementDescriptorHash !== originalDescriptorHash,
        replacementSession?.state ?? null,
        replacementBefore.projection?.isolation?.status ?? null,
        replacementOldToken.status, replacementRequest.status,
        replacementSignerAfter - replacementSignerBefore,
        finalOpenSessions.length,
        finalSession?.id === replacementSession?.id,
        finalRetainedSession?.state ?? null,
        (finalData?.sessions?.length ?? 0) - historySessionCount,
        historyPreserved],
    );
    recordObservation(
      observations,
      'fresh-process-verifies-authority',
      finalOverview.status === 200
        && finalProjection !== null
        && projectionVerified
        && sessionProjections.length === finalSessions.length
        && allSessionProjectionsVerified
        && allAuthorityReceiptsVerified,
      [finalOverview.status, finalOverview.value?.error?.code ?? null,
        finalProjection !== null, projectionVerified,
        sessionProjections.length, finalSessions.length,
        allSessionProjectionsVerified, authorityReceipts.length,
        allAuthorityReceiptsVerified],
    );
  } finally {
    for (const managed of [...children].reverse()) {
      if (processExitCodes[managed.name] !== null) continue;
      try {
        const exit = await managed.stop();
        processExitCodes[managed.name] = exit.code;
      } catch {
        processExitCodes[managed.name] = 1;
      }
    }
  }

  const finalData = finalOverview?.value?.data ?? {};
  const receipts = Array.isArray(finalProjection?.projection?.signedReceipts)
    ? finalProjection.projection.signedReceipts
    : [];
  const events = Array.isArray(finalData.events)
    ? normalizedEvidenceEvents(finalData.events, authorityReceipts)
    : [];
  const finalSellerState = sellerState(sellerStatePath);
  const finalModelState = modelState(modelStatePath);
  const exactChildProcessSet = canonicalJson(Object.keys(processExitCodes))
    === canonicalJson(SPEND_CONTROL_PROCESS_CHILD_NAMES);
  const allChildProcessesExitedCleanly = exactChildProcessSet
    && SPEND_CONTROL_PROCESS_CHILD_NAMES.every((name) => processExitCodes[name] === 0);
  const freshProcessObservation = observations.get('fresh-process-verifies-authority');
  recordObservation(
    observations,
    'fresh-process-verifies-authority',
    freshProcessObservation?.passed === true && allChildProcessesExitedCleanly,
    [
      ...(freshProcessObservation?.facts ?? ['not_exercised']),
      exactChildProcessSet,
      ...SPEND_CONTROL_PROCESS_CHILD_NAMES.map((name) => processExitCodes[name]),
    ],
  );
  const rawSettlementTransactionIds = Object.freeze(
    Array.isArray(finalSellerState.transactionIds)
      ? [...finalSellerState.transactionIds]
      : [],
  );
  const uniqueSettlementTransactionCount = new Set(rawSettlementTransactionIds).size;
  const settlementTransactionsAreUnique = rawSettlementTransactionIds.length > 0
    && uniqueSettlementTransactionCount === rawSettlementTransactionIds.length;
  const allowedPaymentObservation = observations.get('allowed-payment-settles-once');
  recordObservation(
    observations,
    'allowed-payment-settles-once',
    allowedPaymentObservation?.passed === true
      && settlementTransactionsAreUnique
      && rawSettlementTransactionIds.length === finalSellerState.paidRequestCount
      && rawSettlementTransactionIds.length === finalSellerState.paymentSignatureCount
      && finalSellerState.duplicatePaymentSignatureCount === 0,
    [
      ...(allowedPaymentObservation?.facts ?? ['not_exercised']),
      rawSettlementTransactionIds.length,
      uniqueSettlementTransactionCount,
      finalSellerState.paidRequestCount,
      finalSellerState.paymentSignatureCount,
      finalSellerState.duplicatePaymentSignatureCount,
    ],
  );
  const nonLoopbackEgressAttempts = egressAttempts(Object.values(egressLogs));
  recordObservation(
    observations,
    'pi-carries-no-authority-headers',
    piResult.exitCode === 0
      && piResult.outputObserved === 'PI_WALLET_OK'
      && processExitCodes['pi-tool-approval'] === 0
      && processExitCodes['pi-model-approval'] === 0
      && finalModelState.forbiddenAuthorityHeaderCount === 0
      && finalSellerState.forbiddenForwardedHeaderCount === 0,
    [piResult.exitCode, piResult.outputObserved,
      processExitCodes['pi-tool-approval'], processExitCodes['pi-model-approval'],
      finalModelState.forbiddenAuthorityHeaderCount,
      finalSellerState.forbiddenForwardedHeaderCount],
  );
  recordObservation(
    observations,
    'all-egress-is-loopback',
    nonLoopbackEgressAttempts === 0,
    [nonLoopbackEgressAttempts],
  );

  const invariants = makeInvariantResults(observations);
  const passed = invariants.filter((entry) => entry.passed).length;
  const transactionIds = events
    .filter(({ transactionId }) => transactionId !== null)
    .map(({ transactionId }) => transactionId);
  const summary = Object.freeze({
    mode: 'offline-deterministic',
    piVersion: '0.80.6',
    x402Version: 2,
    network: NETWORK,
    isolation: 'simulated',
    tests: INVARIANT_IDS.length,
    passed,
    liveCdp: 'not-run',
    testnetTransaction: 'not-run',
  });
  const freshVerification = Object.freeze({
    authorityEventChain: finalOverview?.status === 200 && allSessionProjectionsVerified,
    projection: allSessionProjectionsVerified,
    receipts: allAuthorityReceiptsVerified,
  });
  return Object.freeze({
    summary,
    evidenceInput: Object.freeze({
      acceptance: Object.freeze({
        invariants,
        processExitCodes: Object.freeze({ ...processExitCodes }),
        transactionIds: Object.freeze(transactionIds),
        rawSettlementTransactionIds,
        nonLoopbackEgressAttempts,
        forbiddenPiAuthorityHeaderCount:
          finalModelState.forbiddenAuthorityHeaderCount
          + finalSellerState.forbiddenForwardedHeaderCount,
        piOutputObserved: piResult.outputObserved,
        piApprovalResume,
      }),
      sessionProjections,
      authorityReceipts,
      events: Object.freeze(events),
      receiptPublicKeys: Object.freeze(readyReceiptKey ? [readyReceiptKey] : []),
      identityBindings: Object.freeze({
        kernel: Object.freeze({ uid: String(process.getuid()), gid: String(process.getgid()) }),
        agent: Object.freeze({ uid: String(process.getuid()), gid: String(process.getgid()) }),
      }),
      privilegedReport: null,
      freshVerification,
      policyHash: sha256(canonicalJson(readJsonFile(policyPath))),
      routeMapHash: sha256(canonicalJson(readJsonFile(routePath))),
      configHash: sha256(canonicalJson({ mode: 'deterministic', network: NETWORK })),
      wallet: Object.freeze({
        provider: 'deterministic',
        walletIdHash: sha256('wallet-process-fixture'),
        address: WALLET_ADDRESS,
      }),
    }),
    cleanup: Object.freeze(cleanup),
  });
}

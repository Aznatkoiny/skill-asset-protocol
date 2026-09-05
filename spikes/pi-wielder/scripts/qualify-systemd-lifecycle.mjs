#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as pause } from 'node:timers/promises';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { captureDeploymentIsolationMetadata, deploymentRendererInput, validateDeploymentConfig } from '../src/kernel/deployment.mjs';
import { verifyReleaseIntegrity } from '../src/kernel/release-integrity.mjs';
import { assertServiceConfinement } from '../src/runtime/installed-service.mjs';
import { OFFLINE_QUALIFICATION } from '../src/runtime/qualification-clients.mjs';
import { inspectEffectiveSystemd, parseSystemctlShow, SERVICE_PROPERTIES, SOCKET_PROPERTIES } from './inspect-systemd-effective.mjs';
import { readManifestOnce } from './preflight-live-deployment.mjs';
import { runPrivilegedAgentIsolationPreflight } from './preflight-agent-isolation.mjs';
import { renderSystemdUnits } from './render-systemd-units.mjs';
import { LIFECYCLE_EXPECTATIONS, summarizeLifecycleEvents } from './verify-lifecycle-evidence.mjs';

const ROOT = '/opt/wallet-kernel-qualification';
const RELEASE_ROOT = fileURLToPath(new URL('../', import.meta.url)).replace(/\/$/, '');
const SERVICE = 'wallet-kernel.service';
const SOCKET = 'wallet-kernel-console.socket';
const CLEAN_ENV = Object.freeze({ PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' });
const events = [];
let stage = 'host';
let config;
let binding;
let ownsDeployment = false;
let output;

function command(binary, args, { input, timeout = 60_000, allowFailure = false } = {}) {
  try {
    return execFileSync(binary, args, { input, encoding: 'utf8', timeout,
      maxBuffer: 2 * 1024 * 1024, env: CLEAN_ENV, stdio: ['pipe', 'pipe', 'pipe'] });
  } catch (cause) {
    if (allowFailure) return null;
    const error = new Error('QUALIFICATION_COMMAND_FAILED');
    error.code = 'QUALIFICATION_COMMAND_FAILED';
    error.binary = path.basename(binary);
    error.status = Number.isInteger(cause.status) ? cause.status : null;
    // Child programs in this harness expose stable public codes only. Do not
    // export arbitrary stderr, credential bytes, or provider exception text.
    error.childCode = String(cause.stderr ?? '').match(/\b(?:LIVE|SYSTEMD|RELEASE|QUALIFICATION|RUNTIME|DEPLOYMENT|AGENT|AUTHORITY|KERNEL)_[A-Z_]{2,100}\b/)?.[0] ?? null;
    if (!error.childCode) {
      try {
        const value = JSON.parse(String(cause.stdout ?? ''));
        if (/^[A-Z][A-Z0-9_]{1,127}$/.test(value.code ?? '')) error.childCode = value.code;
      } catch {}
    }
    throw error;
  }
}
const ctl = (args, options) => command('/usr/bin/systemctl', args, options);
function capturePid1PropertyNames() {
  const publicFields = new Set(['User', 'Group', 'SupplementaryGroups', 'Restart', 'RestartUSec',
    'RestartPreventExitStatus', 'UMask', 'NoNewPrivileges', 'CapabilityBoundingSet', 'AmbientCapabilities',
    'ProtectSystem', 'ProtectHome', 'PrivateTmp', 'PrivateDevices', 'ProtectKernelTunables',
    'ProtectKernelModules', 'ProtectControlGroups', 'LockPersonality', 'RestrictAddressFamilies',
    'ReadWritePaths', 'IPAddressAllow', 'IPAddressDeny', 'Requires', 'After', 'LoadState', 'UnitFileState',
    'DropInPaths', 'NeedDaemonReload', 'Transient', 'Listen', 'Accept', 'Triggers', 'FileDescriptorName',
    'ReusePort', 'UnsetEnvironment']);
  for (const [unit, properties] of [[SERVICE, SERVICE_PROPERTIES], [SOCKET, SOCKET_PROPERTIES]]) {
    try {
      const raw = ctl(['show', '--all', '--no-pager', `--property=${properties.join(',')}`, unit]);
      const names = raw.split('\n').map((line) => line.match(/^([A-Za-z][A-Za-z0-9]*)=/)?.[1]).filter(Boolean);
      // Property names diagnose unsupported PID1 interfaces without exporting
      // environment values or arbitrary unit/drop-in content.
      process.stdout.write(`${canonicalJson({ diagnostic: 'pid1-property-names', unit,
        missing: properties.filter((name) => !names.includes(name)),
        duplicates: properties.filter((name) => names.filter((value) => value === name).length > 1),
        malformedLines: raw.split('\n').filter((line) => line && !/^[A-Za-z][A-Za-z0-9]*=/.test(line)).length })}\n`);
      const publicValues = Object.fromEntries(raw.split('\n').map((line) => {
        const split = line.indexOf('='); return [line.slice(0, split), line.slice(split + 1)];
      }).filter(([name, value]) => publicFields.has(name) && value.length <= 4096));
      process.stdout.write(`${canonicalJson({ diagnostic: 'pid1-public-properties-after-failure', unit, properties: publicValues })}\n`);
    } catch {}
  }
  try {
    const raw = command('/usr/bin/journalctl', ['--unit', SERVICE, '--no-pager', '--output=cat', '--lines=60']);
    const codes = [];
    for (const line of raw.split('\n')) {
      let candidate = line;
      try { candidate = JSON.parse(line)?.code; } catch {}
      if (typeof candidate === 'string' && /^(?:LIVE|SYSTEMD|RELEASE|RUNTIME|DEPLOYMENT|QUALIFICATION|AUTHORITY)_[A-Z_]{2,100}$/.test(candidate)) codes.push(candidate);
    }
    process.stdout.write(`${canonicalJson({ diagnostic: 'installed-service-codes', codes: [...new Set(codes)] })}\n`);
  } catch {}
}
function writePublic(location, value) {
  fs.writeFileSync(location, `${canonicalJson(value)}\n`, { mode: 0o644 });
}
function record(name, actual, details = null) {
  const body = { sequence: events.length + 1, name, actual, details,
    observedAt: new Date().toISOString(), previousHash: events.at(-1)?.eventHash ?? null };
  events.push({ ...body, eventHash: sha256(canonicalJson(body)) });
  process.stdout.write(`${canonicalJson({ check: name, passed: actual === LIFECYCLE_EXPECTATIONS[name] })}\n`);
  assert.deepEqual(actual, LIFECYCLE_EXPECTATIONS[name], name);
}
async function waitFor(label, operation, timeout = 45_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    try { const result = await operation(); if (result) return result; } catch {}
    await pause(250);
  }
  const error = new Error('QUALIFICATION_TIMEOUT'); error.code = 'QUALIFICATION_TIMEOUT'; error.label = label; throw error;
}
function listening(port) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    const finish = (value) => { socket.destroy(); resolve(value); };
    socket.setTimeout(500, () => finish(false));
    socket.once('connect', () => finish(true)); socket.once('error', () => finish(false));
  });
}
function unitState(unit) {
  const names = ['ActiveState', 'SubState', 'MainPID', 'NRestarts', 'Job', 'UnitFileState', 'Result'];
  const available = unit === SOCKET ? ['ActiveState', 'SubState', 'Job', 'UnitFileState'] : names;
  return parseSystemctlShow(ctl(['show', '--all', '--no-pager', `--property=${available.join(',')}`, unit]), available);
}
function stopped(state) {
  return ['inactive', 'failed'].includes(state.service.ActiveState)
    && state.service.MainPID === '0' && state.service.Job === ''
    && state.socket.ActiveState === 'inactive' && state.socket.Job === ''
    && state.socket.UnitFileState === 'disabled';
}
async function stopDeployment() {
  const failures = [];
  for (const args of [['stop', SOCKET], ['stop', SERVICE], ['disable', SOCKET]]) {
    try { ctl(args); } catch (error) { failures.push(error.code); }
  }
  const state = await waitFor('quiescent deployment', async () => {
    const state = { service: unitState(SERVICE), socket: unitState(SOCKET) };
    return stopped(state) && !await listening(8402) && !await listening(8405) ? state : false;
  });
  if (failures.length) throw Object.assign(new Error('QUALIFICATION_CLEANUP_FAILED'), { code: 'QUALIFICATION_CLEANUP_FAILED' });
  return state;
}
function roleCommand(role, action, mountPid) {
  const uid = role === 'agent' ? config.agentUid : config.kernelUid;
  const gid = role === 'agent' ? config.agentGid : config.kernelGid;
  const args = ['--bounding-set=-all', '--inh-caps=-all', '--ambient-caps=-all',
    '--reuid', uid, '--regid', gid, '--clear-groups', '--no-new-privs', '--',
    config.nodePath, path.join(RELEASE_ROOT, 'scripts/qualification-authority-worker.mjs'),
    '--deployment', path.join(RELEASE_ROOT, 'deployment.json'), '--action', action];
  return mountPid ? { binary: '/usr/bin/nsenter', args: [`--mount=/proc/${mountPid}/ns/mnt`, '--', '/usr/bin/setpriv', ...args] }
    : { binary: '/usr/bin/setpriv', args };
}
function worker(role, action, payload = {}, mountPid) {
  const selected = roleCommand(role, action, mountPid);
  const value = JSON.parse(command(selected.binary, selected.args, { input: `${canonicalJson(payload)}\n` }));
  assert.equal(value.profile, 'offline-qualification'); assert.equal(value.action, action); assert.equal(value.role, role);
  return ['agent-request', 'operator-request'].includes(action)
    ? { ...value.result, status: value.result.httpStatus } : value.result;
}
function backgroundWorker(role, action, payload) {
  const selected = roleCommand(role, action);
  const child = spawn(selected.binary, selected.args, { env: CLEAN_ENV, stdio: ['pipe', 'pipe', 'pipe'] });
  child.stdin.end(`${canonicalJson(payload)}\n`);
  let bytes = ''; child.stdout.on('data', (chunk) => { bytes += chunk; if (bytes.length > 2 * 1024 * 1024) child.kill('SIGKILL'); });
  child.stderr.resume();
  const done = new Promise((resolve) => {
    child.once('error', () => resolve({ exitCode: 1 }));
    child.once('exit', (exitCode) => {
      try { resolve({ exitCode, result: JSON.parse(bytes) }); } catch { resolve({ exitCode }); }
    });
  });
  return { child, done };
}
function privateDirectory(location, uid, gid, mode = 0o700) {
  fs.mkdirSync(location, { recursive: true, mode }); fs.chmodSync(location, mode); fs.chownSync(location, uid, gid);
}
function callPayload(scenario, suffix = '') {
  return { routeId: `qualification-${scenario}`,
    callId: Buffer.from(sha256(`${scenario}:${suffix}`).slice(7), 'hex').toString('base64url'),
    body: { qualification: true } };
}
const snapshot = () => {
  const value = worker('kernel', 'snapshot');
  return { ...value,
    approvals: value.approvals.map((item) => ({ ...item, approvalId: item.id })),
    receiptsVerified: value.receipts.length > 0 && value.receipts.every((item) => item.verified === true),
    signatureHashes: value.payments.map((item) => item.signatureHash).filter(Boolean).sort(),
    unresolvedAtomic: value.budgets.totals.unresolvedAtomic,
  };
};
function journalPair(before, after, additionalOpens = 0) {
  assert.deepEqual(after.journal.events.slice(0, before.journal.events.length), before.journal.events);
  assert.equal(after.journal.counters.providerOpens, before.journal.counters.providerOpens + additionalOpens);
  return { before: before.journal, after: after.journal };
}
function holdEvidence(scenario, before, after) {
  const routeId = `qualification-${scenario}`;
  assert.equal(after.intents.length, 1);
  const intent = after.intents[0]; assert.equal(intent.routeId, routeId);
  assert.equal(after.payments.length, 1); assert.equal(after.payments[0].intentId, intent.id);
  assert.equal(after.budgets.reservations.length, 1);
  assert.equal(after.budgets.reservations[0].intentId, intent.id);
  return { routeId, intents: after.intents, payments: after.payments,
    before: before.budgets, after: after.budgets };
}

function prepare(argv) {
  const names = ['--source-checkout', '--kernel-uid', '--kernel-gid', '--agent-uid', '--agent-gid', '--output'];
  assert.equal(argv.length, names.length * 2);
  const values = Object.fromEntries(names.map((name, index) => {
    assert.equal(argv[index * 2], name); return [name, argv[index * 2 + 1]];
  }));
  assert.equal(process.getuid(), 0); assert.equal(process.geteuid(), 0);
  assert.equal(RELEASE_ROOT, `${ROOT}/releases/${path.basename(RELEASE_ROOT)}`);
  assert.match(path.basename(RELEASE_ROOT), /^[0-9a-f]{40}$/);
  assert.equal(process.execPath, `${ROOT}/node/bin/node`);
  assert.equal(values['--source-checkout'], `${ROOT}/source`);
  assert.equal(values['--output'], `${ROOT}/report`);
  output = values['--output']; fs.mkdirSync(output, { mode: 0o755 });
  record('host.platform', process.platform);
  record('host.pid1', fs.readFileSync('/proc/1/comm', 'utf8').trim());
  record('host.node', process.version);
  const commit = command('/usr/bin/git', ['-C', values['--source-checkout'], 'rev-parse', 'HEAD']).trim();
  assert.equal(commit, path.basename(RELEASE_ROOT));
  for (const location of ['/etc/systemd/system/wallet-kernel.service', '/etc/systemd/system/wallet-kernel-console.socket',
    '/etc/wallet-kernel-qualification', '/var/lib/wallet-kernel-qualification', '/var/lib/wallet-agent-qualification',
    '/run/wallet-kernel-qualification']) assert.equal(fs.existsSync(location), false, 'disposable host must be clean');
  config = validateDeploymentConfig({ schemaVersion: 1, executionProfile: 'offline-qualification', commit,
    kernelUid: values['--kernel-uid'], kernelGid: values['--kernel-gid'],
    agentUid: values['--agent-uid'], agentGid: values['--agent-gid'],
    trustedAncestor: '/', releaseRoot: RELEASE_ROOT, nodePath: process.execPath,
    environmentPath: '/etc/wallet-kernel-qualification/kernel.env',
    authorityRoot: '/var/lib/wallet-kernel-qualification/authority',
    evidenceRoot: '/var/lib/wallet-kernel-qualification/evidence', runtimeRoot: '/run/wallet-kernel-qualification',
    agentRunOutboxPath: '/var/lib/wallet-kernel-qualification/agent-outbox',
    enrollmentInboxPath: '/var/lib/wallet-kernel-qualification/enrollment-inbox',
    serviceOutputPath: '/etc/systemd/system/wallet-kernel.service',
    socketOutputPath: '/etc/systemd/system/wallet-kernel-console.socket',
    databasePath: '/var/lib/wallet-kernel-qualification/authority/kernel.sqlite',
    receiptKeyPath: '/var/lib/wallet-kernel-qualification/authority/receipt.pem',
    operatorTokenPath: '/var/lib/wallet-kernel-qualification/authority/operator-token.json',
    operatorSocketPath: '/run/wallet-kernel-qualification/admin.sock',
    isolationReportPath: '/run/wallet-kernel-qualification/isolation.json',
    agentCredentialPath: '/var/lib/wallet-agent-qualification/credential.json',
    policyPath: `${RELEASE_ROOT}/qualification-policy.json`, routePath: `${RELEASE_ROOT}/qualification-routes.json`,
  });
  fs.mkdirSync('/var/lib/wallet-kernel-qualification', { mode: 0o755 });
  fs.mkdirSync('/etc/wallet-kernel-qualification', { mode: 0o755 });
  for (const root of [config.authorityRoot, config.evidenceRoot, config.runtimeRoot]) {
    privateDirectory(root, Number(config.kernelUid), Number(config.kernelGid));
  }
  privateDirectory(config.agentRunOutboxPath, Number(config.kernelUid), Number(config.kernelGid), 0o755);
  privateDirectory(config.enrollmentInboxPath, Number(config.agentUid), Number(config.agentGid), 0o755);
  privateDirectory(path.dirname(config.agentCredentialPath), Number(config.agentUid), Number(config.agentGid));
  const handoff = path.join(config.agentRunOutboxPath, 'qualification-public.json');
  writePublic(handoff, { qualification: true }); fs.chownSync(handoff, Number(config.kernelUid), Number(config.kernelGid));
  const policy = JSON.parse(fs.readFileSync(path.join(RELEASE_ROOT, 'policies/base-sepolia.example.json')));
  policy.wallet = OFFLINE_QUALIFICATION.walletAddress; policy.sellers[0].origin = OFFLINE_QUALIFICATION.sellerOrigin;
  policy.sellers[0].payTo = OFFLINE_QUALIFICATION.payTo;
  policy.sellers[0].sellerSessionMaxAtomic = '10000000'; policy.sessionMaxAtomic = '10000000'; policy.rolling24hMaxAtomic = '10000000';
  writePublic(config.policyPath, policy);
  writePublic(config.routePath, { schemaVersion: 1,
    routes: OFFLINE_QUALIFICATION.routes.map(({ scenario, amountAtomic, ...route }) => route) });
  writePublic(path.join(RELEASE_ROOT, 'deployment.json'), config);
  const environment = { ...OFFLINE_QUALIFICATION.environment,
    WALLET_KERNEL_MODE: 'cdp-testnet', WALLET_KERNEL_DB_FILE: config.databasePath,
    WALLET_KERNEL_RECEIPT_KEY_FILE: config.receiptKeyPath, WALLET_KERNEL_OPERATOR_TOKEN_FILE: config.operatorTokenPath,
    WALLET_KERNEL_TRUSTED_ANCESTOR: '/', WALLET_KERNEL_EXPECTED_AGENT_UID: config.agentUid,
    WALLET_KERNEL_EXPECTED_AGENT_GID: config.agentGid, WALLET_KERNEL_POLICY_FILE: config.policyPath,
    WALLET_KERNEL_ROUTE_FILE: config.routePath, WALLET_KERNEL_PORT: '8402', WALLET_KERNEL_OPERATOR_PORT: '8405',
    WALLET_KERNEL_OPERATOR_SOCKET_FILE: config.operatorSocketPath,
    WALLET_KERNEL_ENROLLMENT_INBOX: config.enrollmentInboxPath, WALLET_KERNEL_AGENT_RUN_OUTBOX: config.agentRunOutboxPath,
    WALLET_KERNEL_RELEASE_ROOT: config.releaseRoot, WALLET_KERNEL_RELEASE_MANIFEST: `${RELEASE_ROOT}/manifest.json`,
    WALLET_KERNEL_SERVICE_DEFINITION_FILE: config.serviceOutputPath,
    WALLET_KERNEL_SOCKET_DEFINITION_FILE: config.socketOutputPath, WALLET_KERNEL_ENV_FILE: config.environmentPath,
    WALLET_KERNEL_EVIDENCE_ROOT: config.evidenceRoot, WALLET_KERNEL_ISOLATION_REPORT_FILE: config.isolationReportPath };
  fs.writeFileSync(config.environmentPath, Object.entries(environment).map(([key, value]) => `${key}=${value}\n`).join(''), { mode: 0o600 });
  return values['--source-checkout'];
}

let descriptorHash;
let enrollmentHash;
function initializeAuthority() {
  worker('kernel', 'bootstrap');
  const enrolled = worker('kernel', 'enroll', { confirm: descriptorHash });
  enrollmentHash = enrolled.enrollmentHash;
}
async function refreshIsolation({ validForMs } = {}) {
  if (fs.existsSync(config.isolationReportPath)) fs.unlinkSync(config.isolationReportPath);
  const metadata = captureDeploymentIsolationMetadata(config);
  const probeName = `.qualification-probe-${process.pid}`;
  const result = await runPrivilegedAgentIsolationPreflight({ config: {
    schemaVersion: 1, enrollmentHash, kernelUid: config.kernelUid, kernelGid: config.kernelGid,
    agentUid: config.agentUid, agentGid: config.agentGid,
    authorityMetadataHash: metadata.authorityMetadataHash, credentialMetadataHash: metadata.credentialMetadataHash,
    ...Object.fromEntries(['releaseManifestHash', 'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
      'systemdEffectiveConfigHash', 'environmentMetadataHash'].map((key) => [key, binding[key]])),
    credentialPath: config.agentCredentialPath, reportPath: config.isolationReportPath,
    protectedReadPaths: { authorityDirectory: config.authorityRoot, database: config.databasePath,
      operatorToken: config.operatorTokenPath, receiptKey: config.receiptKeyPath, kernelEnvironment: config.environmentPath },
    writePaths: { releaseTreeWrite: path.join(RELEASE_ROOT, probeName),
      dependencyTreeWrite: path.join(RELEASE_ROOT, 'node_modules', probeName),
      serviceArtifactsWrite: path.join(path.dirname(config.serviceOutputPath), probeName),
      kernelEnvironmentParentWrite: path.join(path.dirname(config.environmentPath), probeName) },
  } });
  let report = JSON.parse(fs.readFileSync(config.isolationReportPath));
  let reportHash = result.reportHash;
  if (validForMs !== undefined) {
    // Shorten a freshly measured report and confirm those exact bytes while
    // valid. The later failed start can then demonstrate expiry, not tampering.
    report = { ...report, expiresAt: new Date(Date.now() + validForMs).toISOString() };
    reportHash = sha256(canonicalJson(report));
    fs.writeFileSync(config.isolationReportPath, `${canonicalJson(report)}\n`);
  }
  const imported = worker('kernel', 'import-isolation', { confirm: reportHash });
  return { reportHash, probedAt: report.probedAt, expiresAt: report.expiresAt, importedAt: imported.importedAt };
}
async function start() {
  ctl(['reset-failed', SERVICE, SOCKET], { allowFailure: true });
  ctl(['enable', SOCKET]); ctl(['start', SOCKET]); ctl(['start', SERVICE]);
  return waitFor('service ready', async () => {
    const state = unitState(SERVICE);
    return state.ActiveState === 'active' && Number(state.MainPID) > 0 && await listening(8402) ? state : false;
  });
}
async function killService() {
  ctl(['kill', '--kill-whom=main', '--signal=SIGKILL', SERVICE]);
  return waitFor('failed service cleanup', () => {
    const state = { service: unitState(SERVICE), socket: unitState(SOCKET) };
    return stopped(state) ? state : false;
  });
}
async function resetAuthority() {
  await stopDeployment();
  fs.rmSync(config.authorityRoot, { recursive: true });
  privateDirectory(config.authorityRoot, Number(config.kernelUid), Number(config.kernelGid));
  initializeAuthority(); await refreshIsolation(); await start();
}

async function rejection(name, mutate, restore, evidence = {}) {
  stage = name; await stopDeployment();
  const before = snapshot();
  try {
    await mutate(); ctl(['daemon-reload']);
    ctl(['reset-failed', SERVICE, SOCKET], { allowFailure: true });
    ctl(['enable', SOCKET]); ctl(['start', SOCKET]);
    const status = ctl(['start', SERVICE], { allowFailure: true });
    assert.equal(status, null, 'invalid deployment must fail its actual installed start');
    const state = await waitFor('rejected start cleanup', () => {
      const state = { service: unitState(SERVICE), socket: unitState(SOCKET) }; return stopped(state) ? state : false;
    });
    // Restore the sealed profile before using its strictly bound read-only
    // worker. Failure facts above were captured from the rejected invocation.
    await restore(); ctl(['daemon-reload']);
    const after = snapshot();
    record(name, stopped(state) && state.service.NRestarts === '0'
      && canonicalJson(before.journal) === canonicalJson(after.journal),
    { state, ...journalPair(before, after), ...evidence });
  } finally { await restore(); ctl(['daemon-reload']); }
}

async function exercise() {
  // Assertions below use only public worker projections. Authority mutations,
  // signatures, real HTTP listeners and all service lifecycle operations run in
  // the installed processes; only provider/chain outcomes are deterministic.
  stage = 'startup'; const initial = await start();
  record('startup.active', initial.ActiveState);
  const status = fs.readFileSync(`/proc/${initial.MainPID}/status`, 'utf8');
  assertServiceConfinement(status);
  for (const [field, expected] of [['Uid', config.kernelUid], ['Gid', config.kernelGid]]) {
    const values = status.match(new RegExp(`^${field}:\\s*(.+)$`, 'm'))?.[1].trim().split(/\s+/);
    assert.equal(values?.length, 4); assert.equal(values.every((value) => value === expected), true);
  }
  assert.equal(status.match(/^Groups:\s*(.*)$/m)?.[1].trim().split(/\s+/).filter(Boolean)
    .every((value) => value === config.kernelGid), true);
  assert.equal(fs.readlinkSync(`/proc/${initial.MainPID}/exe`), config.nodePath);
  record('startup.confinement', true, { uid: config.kernelUid, gid: config.kernelGid,
    status: status.split('\n').filter((line) => /^(Uid|Gid|Groups|Cap|NoNewPrivs)/.test(line)) });
  const inherited = fs.readlinkSync(`/proc/${initial.MainPID}/fd/3`);
  const inode = inherited.match(/^socket:\[([0-9]+)\]$/)?.[1];
  const socketRows = fs.readFileSync(`/proc/${initial.MainPID}/net/tcp`, 'utf8').trim().split('\n').slice(1)
    .map((line) => line.trim().split(/\s+/)).filter((columns) => columns[9] === inode);
  record('startup.inheritedSocket', socketRows.length === 1 && socketRows[0][1] === '0100007F:20D5'
    && socketRows[0][3] === '0A', { descriptor: inherited, rows: socketRows });
  const agent = worker('agent', 'boundary-probes');
  const delivered = worker('agent', 'delivered-credential-probe', {}, initial.MainPID);
  agent.probes.deliveredCredentialRead = delivered.probes.deliveredEnvironmentRead;
  agent.passed &&= delivered.passed;
  const kernel = worker('kernel', 'boundary-probes');
  record('isolation.agent', agent.passed, agent); record('isolation.kernel', kernel.passed, kernel);

  stage = 'automatic'; const allow = callPayload('allow');
  const paid = worker('agent', 'agent-request', allow); const paidSnapshot = snapshot();
  record('automatic.status', paid.status, paid);
  record('automatic.signerCalls', paidSnapshot.journal.counters.signerCalls, paidSnapshot.journal.counters);
  record('automatic.receiptVerified', paidSnapshot.receiptsVerified,
    { receiptPublicKey: paidSnapshot.receiptPublicKey, receipts: paidSnapshot.receipts });

  stage = 'approval'; const approvalCall = callPayload('approval');
  const pending = worker('agent', 'agent-request', approvalCall);
  const pendingSnapshot = snapshot();
  record('approval.pending', pendingSnapshot.approvals.some((item) => item.decision === 'pending')
    && pendingSnapshot.journal.counters.signerCalls === 1,
    { response: pending, approvals: pendingSnapshot.approvals, counters: pendingSnapshot.journal.counters });
  const approval = pendingSnapshot.approvals.find((item) => item.decision === 'pending');
  const approved = worker('kernel', 'operator-request', { method: 'POST',
    path: `/operator/v1/approvals/${approval.approvalId}/approve`,
    body: { expectedIntentHash: approval.intentHash } });
  const beforeRestart = snapshot();
  record('approval.approved', approved.status === 200 && beforeRestart.approvals.some((item) => item.decision === 'approved'),
    { response: approved, approvals: beforeRestart.approvals, counters: beforeRestart.journal.counters });
  stage = 'graceful restart'; ctl(['restart', SERVICE]);
  const restarted = await waitFor('restarted listener', async () => {
    const value = unitState(SERVICE); return value.ActiveState === 'active' && value.MainPID !== initial.MainPID && await listening(8402) ? value : false;
  });
  const afterRestart = snapshot();
  record('restart.changedPid', restarted.MainPID !== initial.MainPID, { before: initial.MainPID, after: restarted.MainPID });
  record('restart.approvalPreserved', canonicalJson(beforeRestart.approvals) === canonicalJson(afterRestart.approvals), { before: beforeRestart.approvals, after: afterRestart.approvals });
  record('restart.noSignature', beforeRestart.journal.counters.signerCalls === afterRestart.journal.counters.signerCalls,
    journalPair(beforeRestart, afterRestart, 1));
  const retry = worker('agent', 'agent-request', approvalCall); const completed = snapshot();
  record('approval.retryStatus', retry.status, retry); record('approval.receiptVerified', completed.receiptsVerified && completed.receipts.length === 2,
    { receiptPublicKey: completed.receiptPublicKey, receipts: completed.receipts });
  worker('agent', 'agent-request', allow);
  const replayed = snapshot();
  record('replay.noDoubleSigning', replayed.journal.counters.signerCalls === 2 && replayed.journal.counters.paidRequests === 2,
    journalPair(completed, replayed));

  stage = 'hard restart'; await killService();
  record('hardRestart.staleSocketPresent', fs.lstatSync(config.operatorSocketPath).isSocket());
  await refreshIsolation(); await start();
  const hardRestart = snapshot();
  record('hardRestart.socketRecovered', fs.lstatSync(config.operatorSocketPath).isSocket() && await listening(8402));
  record('hardRestart.receiptsPreserved', canonicalJson(replayed.receipts) === canonicalJson(hardRestart.receipts) && hardRestart.receiptsVerified,
    { receiptPublicKey: hardRestart.receiptPublicKey, before: replayed.receipts, after: hardRestart.receipts });
  record('hardRestart.noDoubleSigning', hardRestart.journal.counters.signerCalls === 2 && hardRestart.journal.counters.paidRequests === 2,
    journalPair(replayed, hardRestart, 1));

  await stopDeployment();
  const attestation = await refreshIsolation({ validForMs: 8_000 });
  assert.ok(Date.parse(attestation.importedAt) < Date.parse(attestation.expiresAt));
  await waitFor('attestation expiry', () => Date.now() >= Date.parse(attestation.expiresAt));
  attestation.rejectedAt = new Date().toISOString();
  await rejection('reject.staleAttestation', () => {}, () => {}, { attestation });
  await refreshIsolation();
  const sourcePath = path.join(RELEASE_ROOT, 'src/code-root.mjs'); const sourceBytes = fs.readFileSync(sourcePath);
  await rejection('reject.releaseChange', () => fs.appendFileSync(sourcePath, '\n// qualification mutation\n'), () => fs.writeFileSync(sourcePath, sourceBytes));
  const dropInRoot = `${config.serviceOutputPath}.d`;
  await rejection('reject.pid1Change', () => {
    fs.mkdirSync(dropInRoot, { mode: 0o755 }); fs.writeFileSync(path.join(dropInRoot, 'qualification.conf'), '[Service]\nEnvironment=WALLET_KERNEL_TAMPER=1\n');
  }, () => fs.rmSync(dropInRoot, { recursive: true, force: true }));
  const deploymentPath = path.join(RELEASE_ROOT, 'deployment.json'); const deploymentBytes = fs.readFileSync(deploymentPath);
  await rejection('reject.cdpProfile', () => writePublic(deploymentPath, { ...config, executionProfile: 'cdp-testnet' }), () => fs.writeFileSync(deploymentPath, deploymentBytes));

  // Monetary fault scenarios each use fresh synthetic authority. No production
  // database is selected or deleted: paths/profile and disposable-host checks
  // are fixed before this harness creates any authority.
  for (const [scenario, prefix, barrier] of [
    ['signing-interruption', 'signingInterruption', 'signer_blocked'],
    ['retry-interruption', 'retryInterruption', 'retry_blocked'],
  ]) {
    stage = scenario; await resetAuthority();
    const call = callPayload(scenario); const request = backgroundWorker('agent', 'agent-request', call);
    let before;
    try {
      before = await waitFor(barrier, () => { const state = snapshot(); return state.journal.lastEvent?.kind === barrier ? state : false; });
      await killService();
    } finally { request.child.kill('SIGKILL'); await request.done; }
    await refreshIsolation(); await start();
    worker('agent', 'agent-request', call);
    const after = snapshot();
    record(`${prefix}.holdPreserved`, after.unresolvedAtomic === OFFLINE_QUALIFICATION.routes.find((item) => item.scenario === scenario).amountAtomic,
      holdEvidence(scenario, before, after));
    if (prefix === 'retryInterruption') record(`${prefix}.signaturePreserved`, before.signatureHashes.length === 1
      && canonicalJson(before.signatureHashes) === canonicalJson(after.signatureHashes), { before: before.signatureHashes, after: after.signatureHashes });
    record(`${prefix}.noDoubleSigning`, after.journal.counters.signerCalls === 1
      && after.journal.counters.paidRequests === (prefix === 'retryInterruption' ? 1 : 0), journalPair(before, after, 1));
  }
  for (const [scenario, prefix] of [['payment-unresolved', 'unresolved'], ['charged-failure', 'chargedFailure']]) {
    stage = scenario; await resetAuthority(); const call = callPayload(scenario);
    const outcome = worker('agent', 'agent-request', call); const before = snapshot();
    assert.equal(outcome.status, prefix === 'unresolved' ? 503 : 500);
    assert.equal(outcome.response.status, prefix === 'unresolved' ? 'payment_unresolved' : 'execution_failed');
    const previousPid = unitState(SERVICE).MainPID;
    ctl(['restart', SERVICE]); await waitFor('post-outcome restart', async () => {
      const value = unitState(SERVICE); return value.ActiveState === 'active' && value.MainPID !== previousPid && await listening(8402);
    });
    worker('agent', 'agent-request', call); const after = snapshot();
    if (prefix === 'unresolved') record('unresolved.holdPreserved', after.unresolvedAtomic === '70000', holdEvidence(scenario, before, after));
    else {
      assert.equal(after.intents.length, 1); const intent = after.intents[0];
      assert.equal(intent.routeId, 'qualification-charged-failure');
      assert.equal(after.budgets.reservations.length, 1); const budget = after.budgets.reservations[0];
      assert.equal(budget.intentId, intent.id); assert.equal(budget.committedAtomic, '60000'); assert.equal(budget.unresolvedAtomic, '0');
      assert.equal(after.payments.length, 1); assert.equal(after.payments[0].intentId, intent.id);
      assert.equal(after.receipts.length, 1); assert.equal(after.receipts[0].intentId, intent.id);
      record('chargedFailure.receiptPreserved', after.receiptsVerified
        && canonicalJson(before.receipts) === canonicalJson(after.receipts)
        && after.receipts[0].receipt.outcome.status === 'execution_failed'
        && after.receipts[0].receipt.payment.amountAtomic === '60000'
        && after.receipts[0].receipt.budget.disposition === 'committed',
      { receiptPublicKey: after.receiptPublicKey, before: before.receipts, after: after.receipts });
    }
    record(`${prefix}.noDoubleSigning`, after.journal.counters.signerCalls === 1 && after.journal.counters.paidRequests === 1,
      journalPair(before, after, 1));
  }
}

async function main() {
  let failure = null;
  try {
    const sourceCheckoutPath = prepare(process.argv.slice(2));
    stage = 'authority bootstrap'; descriptorHash = worker('agent', 'agent-init').descriptorHash; initializeAuthority();
    stage = 'install'; ownsDeployment = true;
    const install = JSON.parse(command(config.nodePath, [path.join(RELEASE_ROOT, 'scripts/install-live-deployment.mjs'),
      '--deployment', path.join(RELEASE_ROOT, 'deployment.json'), '--source-checkout', sourceCheckoutPath]));
    record('install.execution', install.execution); record('install.status', install.status);
    record('install.serviceStopped', install.started === false && unitState(SERVICE).MainPID === '0');
    stage = 'installed manifest read';
    const manifest = readManifestOnce(path.join(RELEASE_ROOT, 'manifest.json'));
    stage = 'installed release verification';
    binding = verifyReleaseIntegrity({ mode: 'cdp-testnet', releaseRoot: RELEASE_ROOT, manifest,
      expectedOwnerUid: 0, expectedKernelUid: config.kernelUid, expectedKernelGid: config.kernelGid,
      nodePath: config.nodePath, nodeVersion: process.version, environmentPath: config.environmentPath,
      serviceArtifactPaths: { 'kernel-service': config.serviceOutputPath, 'console-socket': config.socketOutputPath } });
    stage = 'installed PID1 binding';
    const observed = await inspectEffectiveSystemd({ expected: renderSystemdUnits(deploymentRendererInput(config)).expectedEffectiveConfig });
    record('install.pid1Bound', Object.entries(manifest.systemd).every(([key, value]) => observed[key] === value), { systemd: observed, release: binding });
    stage = 'initial isolation attestation';
    await refreshIsolation(); await exercise();
  } catch (error) {
    failure = { stage, code: /^[A-Z_]{2,100}$/.test(error.code ?? '') ? error.code : 'QUALIFICATION_FAILED',
      childCode: error.childCode ?? null, binary: error.binary ?? null, status: error.status ?? null,
      label: error.label ?? null };
    process.stderr.write(`${canonicalJson(failure)}\n`);
    if (config && ownsDeployment) capturePid1PropertyNames();
  } finally {
    if (ownsDeployment) {
      try {
        const state = await stopDeployment();
        record('cleanup.serviceStopped', state.service.MainPID === '0' && ['inactive', 'failed'].includes(state.service.ActiveState), state.service);
        record('cleanup.socketDisabled', state.socket.UnitFileState === 'disabled' && state.socket.ActiveState === 'inactive', state.socket);
        record('cleanup.listenersClosed', !await listening(8402) && !await listening(8405));
      } catch (error) { failure ??= { stage: 'cleanup', code: error.code ?? 'QUALIFICATION_CLEANUP_FAILED' }; }
    }
    if (output) {
      const summary = summarizeLifecycleEvents(events);
      if (!summary.valid) failure ??= { stage, code: 'QUALIFICATION_INCOMPLETE' };
      const eventBytes = Buffer.from(events.map((event) => `${canonicalJson(event)}\n`).join(''));
      fs.writeFileSync(path.join(output, 'events.jsonl'), eventBytes, { mode: 0o644 });
      writePublic(path.join(output, 'summary.json'), summary);
      writePublic(path.join(output, 'manifest.json'), { schemaVersion: 1,
        scope: 'installed-offline-qualification', executionProfile: 'offline-qualification',
        commit: path.basename(RELEASE_ROOT), nodeVersion: process.version,
        nodeExecutableHash: sha256(fs.readFileSync(process.execPath)), hostKernel: os.release(),
        hostArchitecture: process.arch, release: binding ?? null, failure,
        eventsHash: sha256(eventBytes), summaryHash: sha256(fs.readFileSync(path.join(output, 'summary.json'))),
        liveCdp: 'not-run', testnetTransaction: 'not-run', publicRelease: 'not-qualified' });
    }
  }
  if (failure) process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();

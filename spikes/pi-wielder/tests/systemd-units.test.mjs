import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import {
  inspectEffectiveSystemd,
  parseSystemctlShow,
  validateEffectiveProjection,
} from '../scripts/inspect-systemd-effective.mjs';
import { LIVE_LAUNCH_GATE } from '../scripts/preflight-live-deployment.mjs';
import { renderSystemdUnits } from '../scripts/render-systemd-units.mjs';

function installFixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-systemd-'));
  const releaseRoot = path.join(root, 'release-aaaaaaaa');
  const dirs = {};
  for (const name of ['authority', 'evidence', 'runtime', 'outbox', 'inbox']) {
    dirs[name] = path.join(root, name);
    fs.mkdirSync(dirs[name], { mode: 0o700 });
  }
  fs.mkdirSync(path.join(releaseRoot, 'scripts'), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(releaseRoot, 'src'), { mode: 0o755 });
  const nodePath = path.join(root, 'node-v24.18.1');
  const environmentPath = path.join(root, 'kernel.env');
  fs.writeFileSync(nodePath, 'node', { mode: 0o755 });
  fs.writeFileSync(environmentPath, 'WALLET_KERNEL_MODE=cdp-testnet\n', { mode: 0o600 });
  return {
    root, releaseRoot, nodePath, environmentPath,
    serviceOutputPath: path.join(root, 'wallet-kernel.service'),
    socketOutputPath: path.join(root, 'wallet-kernel-console.socket'),
    authorityRoot: dirs.authority, evidenceRoot: dirs.evidence, runtimeRoot: dirs.runtime,
    agentRunOutboxPath: dirs.outbox, enrollmentInboxPath: dirs.inbox,
  };
}

function render(f, overrides = {}) {
  return renderSystemdUnits({
    schemaVersion: 1,
    kernelUid: '501', kernelGid: '20', agentUid: '502', agentGid: '20',
    releaseRoot: f.releaseRoot, nodePath: f.nodePath,
    environmentPath: f.environmentPath,
    authorityRoot: f.authorityRoot, evidenceRoot: f.evidenceRoot,
    runtimeRoot: f.runtimeRoot, agentRunOutboxPath: f.agentRunOutboxPath,
    enrollmentInboxPath: f.enrollmentInboxPath,
    serviceOutputPath: f.serviceOutputPath, socketOutputPath: f.socketOutputPath,
    ...overrides,
  });
}

test('renderer emits the exact hardened numeric-identity service and retained socket contract', () => {
  const f = installFixture();
  try {
    const result = render(f);
    const service = result.serviceBytes.toString('utf8');
    const socket = result.socketBytes.toString('utf8');
    for (const line of [
      'Requires=wallet-kernel-console.socket',
      'After=network-online.target wallet-kernel-console.socket',
      'User=501', 'Group=20', 'SupplementaryGroups=',
      `Environment=WALLET_KERNEL_ENV_FILE=${f.environmentPath}`,
      `LoadCredential=wallet-kernel-environment:${f.environmentPath}`,
      `ExecStartPre=+${f.nodePath} ${f.releaseRoot}/scripts/preflight-live-deployment.mjs --release-manifest ${f.releaseRoot}/manifest.json --kernel-uid 501 --kernel-gid 20`,
      `ExecStart=${f.nodePath} ${f.releaseRoot}/src/control-plane.mjs`,
      `ExecStopPost=+${f.nodePath} ${f.releaseRoot}/scripts/cleanup-live-deployment.mjs`,
      'Restart=no',
      'NoNewPrivileges=yes', 'CapabilityBoundingSet=', 'AmbientCapabilities=',
      'ProtectSystem=strict', 'ProtectHome=yes', 'PrivateTmp=yes', 'PrivateDevices=yes',
      'ProtectKernelTunables=yes', 'ProtectKernelModules=yes', 'ProtectControlGroups=yes',
      'LockPersonality=yes', 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6',
      `ReadWritePaths=${f.authorityRoot} ${f.evidenceRoot} ${f.runtimeRoot} ${f.agentRunOutboxPath}`,
      'UnsetEnvironment=NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE GLIBC_TUNABLES GCONV_PATH PRIVATE_KEY ANTHROPIC_API_KEY OPENAI_API_KEY CDP_API_KEY_ID CDP_API_KEY_SECRET CDP_WALLET_SECRET CDP_WALLET_NAME WALLET_KERNEL_BASE_SEPOLIA_RPC_URL CREDENTIALS_DIRECTORY HOME LOGNAME USER SHELL INVOCATION_ID JOURNAL_STREAM SYSTEMD_EXEC_PID MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC LISTEN_PIDFDID SGX_AESM_ADDR',
    ]) assert.equal(service.includes(`${line}\n`), true, line);
    assert.equal(service.includes('EnvironmentFile='), false,
      'the root-prefixed preflight must never inherit the secret environment file');
    assert.equal(socket.includes('ListenStream=127.0.0.1:8405\n'), true);
    assert.equal(socket.includes('Accept=no\n'), true);
    assert.equal(socket.includes('FileDescriptorName=wallet-kernel-console\n'), true);
    assert.equal(socket.includes('ReusePort=no\n'), true);
    assert.equal(socket.includes('WantedBy=sockets.target\n'), true);
    assert.equal(socket.includes('PartOf='), false);
    assert.equal(result.service.sha256.startsWith('sha256:'), true);
    assert.equal(result.socket.sha256.startsWith('sha256:'), true);
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('renderer rejects names, root/shared identities, whitespace, unknown fields, and overwrite', () => {
  const f = installFixture();
  try {
    for (const overrides of [
      { kernelUid: 'wallet-kernel' }, { kernelUid: '0' }, { agentUid: '501' },
      { nodePath: `${f.nodePath} bad` }, { releaseRoot: `${f.releaseRoot}\nBad=yes` },
      { surprise: true },
    ]) assert.throws(() => render(f, overrides));
    renderSystemdUnits({
      schemaVersion: 1, kernelUid: '501', kernelGid: '20', agentUid: '502', agentGid: '20',
      releaseRoot: f.releaseRoot, nodePath: f.nodePath, environmentPath: f.environmentPath,
      authorityRoot: f.authorityRoot, evidenceRoot: f.evidenceRoot, runtimeRoot: f.runtimeRoot,
      agentRunOutboxPath: f.agentRunOutboxPath, enrollmentInboxPath: f.enrollmentInboxPath,
      serviceOutputPath: f.serviceOutputPath, socketOutputPath: f.socketOutputPath,
      install: true, expectedOwnerUid: process.getuid(),
    });
    assert.throws(() => renderSystemdUnits({
      schemaVersion: 1, kernelUid: '501', kernelGid: '20', agentUid: '502', agentGid: '20',
      releaseRoot: f.releaseRoot, nodePath: f.nodePath, environmentPath: f.environmentPath,
      authorityRoot: f.authorityRoot, evidenceRoot: f.evidenceRoot, runtimeRoot: f.runtimeRoot,
      agentRunOutboxPath: f.agentRunOutboxPath, enrollmentInboxPath: f.enrollmentInboxPath,
      serviceOutputPath: f.serviceOutputPath, socketOutputPath: f.socketOutputPath,
      install: true, expectedOwnerUid: process.getuid(),
    }), /exist/);
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('systemctl show parser splits first equals and rejects duplicate, missing, and oversized data', () => {
  assert.deepEqual(parseSystemctlShow('Id=a.service\nEnvironmentFiles=/a=x (ignore_errors=no)\n',
    ['Id', 'EnvironmentFiles']), {
    Id: 'a.service', EnvironmentFiles: '/a=x (ignore_errors=no)',
  });
  assert.throws(() => parseSystemctlShow('Id=a\nId=b\n', ['Id']), /duplicate/);
  assert.throws(() => parseSystemctlShow('Id=a\n', ['Id', 'LoadState']), /missing/);
  assert.throws(() => parseSystemctlShow(`Id=${'x'.repeat(70_000)}\n`, ['Id']), /bounded/);
});

test('effective projection validates exact loaded static service and enabled socket', () => {
  const f = installFixture();
  try {
    const rendered = render(f);
    const projection = validateEffectiveProjection({
      service: {
        Id: 'wallet-kernel.service', LoadState: 'loaded', FragmentPath: f.serviceOutputPath,
        DropInPaths: '', NeedDaemonReload: 'no', Transient: 'no', UnitFileState: 'static',
        User: '501', Group: '20', SupplementaryGroups: '',
        Environment: `WALLET_KERNEL_ENV_FILE=${f.environmentPath}`,
        EnvironmentFiles: '', PassEnvironment: '',
        LoadCredential: `wallet-kernel-environment:${f.environmentPath}`,
        ExecStartPreEx: `{ path=${f.nodePath} ; argv[]=${f.nodePath} ${f.releaseRoot}/scripts/preflight-live-deployment.mjs --release-manifest ${f.releaseRoot}/manifest.json --kernel-uid 501 --kernel-gid 20 ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
        ExecStartEx: `{ path=${f.nodePath} ; argv[]=${f.nodePath} ${f.releaseRoot}/src/control-plane.mjs ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
        ExecStopPostEx: `{ path=${f.nodePath} ; argv[]=${f.nodePath} ${f.releaseRoot}/scripts/cleanup-live-deployment.mjs ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
        Restart: 'no', RestartUSec: '2s', RestartPreventExitStatus: '',
        UMask: '0077', NoNewPrivileges: 'yes',
        CapabilityBoundingSet: '', AmbientCapabilities: '', ProtectSystem: 'strict',
        ProtectHome: 'yes', PrivateTmp: 'yes', PrivateDevices: 'yes',
        ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes',
        ProtectControlGroups: 'yes', LockPersonality: 'yes',
        RestrictAddressFamilies: 'AF_UNIX AF_INET AF_INET6',
        ReadWritePaths: `${f.authorityRoot} ${f.evidenceRoot} ${f.runtimeRoot} ${f.agentRunOutboxPath}`,
        IPAddressAllow: '', IPAddressDeny: '',
        UnsetEnvironment: 'NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE GLIBC_TUNABLES GCONV_PATH PRIVATE_KEY ANTHROPIC_API_KEY OPENAI_API_KEY CDP_API_KEY_ID CDP_API_KEY_SECRET CDP_WALLET_SECRET CDP_WALLET_NAME WALLET_KERNEL_BASE_SEPOLIA_RPC_URL CREDENTIALS_DIRECTORY HOME LOGNAME USER SHELL INVOCATION_ID JOURNAL_STREAM SYSTEMD_EXEC_PID MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC LISTEN_PIDFDID SGX_AESM_ADDR',
        Requires: 'wallet-kernel-console.socket sysinit.target',
        After: 'network-online.target wallet-kernel-console.socket sysinit.target basic.target systemd-tmpfiles-setup.service systemd-journald.socket',
      },
      socket: {
        Id: 'wallet-kernel-console.socket', LoadState: 'loaded', FragmentPath: f.socketOutputPath,
        DropInPaths: '', NeedDaemonReload: 'no', Transient: 'no', UnitFileState: 'enabled',
        Listen: '127.0.0.1:8405 (Stream)', Accept: 'no', Triggers: 'wallet-kernel.service',
        FileDescriptorName: 'wallet-kernel-console', ReusePort: 'no',
      },
      expected: rendered.expectedEffectiveConfig,
    });
    assert.equal(projection.effectiveConfigHash.startsWith('sha256:'), true);
    for (const mutate of [
      (p) => { p.service.DropInPaths = '/etc/systemd/system/x.conf'; },
      (p) => { p.service.NeedDaemonReload = 'yes'; },
      (p) => { p.service.User = 'wallet-kernel'; },
      (p) => { p.service.CapabilityBoundingSet = 'CAP_NET_ADMIN'; },
      (p) => { p.service.Restart = 'on-failure'; },
      (p) => { p.service.RestartPreventExitStatus = '78'; },
      (p) => { p.service.EnvironmentFiles = f.environmentPath; },
      (p) => { p.service.LoadCredential = 'wallet-kernel-environment:/tmp/other'; },
      (p) => { p.service.LoadCredential += ' extra:/tmp/other'; },
      (p) => { p.service.Environment = `${p.service.Environment} CDP_API_KEY_SECRET=sentinel`; },
      (p) => { p.service.PassEnvironment = 'CDP_API_KEY_SECRET'; },
      (p) => { p.socket.Listen = '0.0.0.0:8405 (Stream)'; },
      (p) => { p.socket.ReusePort = 'yes'; },
    ]) {
      const candidate = structuredClone({ service: projection.service, socket: projection.socket });
      mutate(candidate);
      assert.throws(() => validateEffectiveProjection({ ...candidate, expected: rendered.expectedEffectiveConfig }));
    }
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

test('installed service remains blocked until Linux lifecycle evidence qualifies the composition', () => {
  assert.deepEqual(LIVE_LAUNCH_GATE, {
    schemaVersion: 1,
    status: 'blocked',
    code: 'LIVE_LAUNCH_NOT_READY',
    exitStatus: 78,
    blockers: [
      'LIVE_SYSTEMD_LIFECYCLE_EVIDENCE_REQUIRED',
    ],
  });

  const preflightPath = fileURLToPath(new URL('../scripts/preflight-live-deployment.mjs', import.meta.url));
  const preflight = spawnSync(process.execPath, [
    preflightPath,
    '--release-manifest', '/opt/wallet/releases/blocked/manifest.json',
    '--kernel-uid', '501', '--kernel-gid', '20',
  ], {
    encoding: 'utf8',
    env: {
      PATH: '/usr/bin:/bin',
      WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env',
    },
  });
  assert.equal(preflight.status, LIVE_LAUNCH_GATE.exitStatus);
  assert.equal(preflight.stdout, '');
  assert.equal(preflight.stderr, `${canonicalJson(LIVE_LAUNCH_GATE)}\n`);

  const controlPlanePath = fileURLToPath(new URL('../src/control-plane.mjs', import.meta.url));
  const controlPlane = spawnSync(process.execPath, [controlPlanePath], {
    encoding: 'utf8',
    env: { PATH: '/usr/bin:/bin' },
  });
  assert.equal(controlPlane.status, LIVE_LAUNCH_GATE.exitStatus);
  assert.equal(controlPlane.stdout, '');
  assert.equal(controlPlane.stderr, `${canonicalJson(LIVE_LAUNCH_GATE)}\n`);
});

test('live systemd static verification is explicit and never green on non-Linux', async (t) => {
  if (process.platform !== 'linux' || process.getuid?.() !== 0 || process.env.WALLET_KERNEL_SYSTEMD_INTEGRATION !== '1') {
    t.skip('requires Linux root and WALLET_KERNEL_SYSTEMD_INTEGRATION=1');
    return;
  }
  const f = installFixture();
  try {
    renderSystemdUnits({
      schemaVersion: 1,
      kernelUid: process.env.WALLET_KERNEL_TEST_KERNEL_UID,
      kernelGid: process.env.WALLET_KERNEL_TEST_KERNEL_GID,
      agentUid: process.env.WALLET_KERNEL_TEST_AGENT_UID,
      agentGid: process.env.WALLET_KERNEL_TEST_AGENT_GID,
      releaseRoot: f.releaseRoot, nodePath: f.nodePath,
      environmentPath: f.environmentPath,
      authorityRoot: f.authorityRoot, evidenceRoot: f.evidenceRoot,
      runtimeRoot: f.runtimeRoot, agentRunOutboxPath: f.agentRunOutboxPath,
      enrollmentInboxPath: f.enrollmentInboxPath,
      serviceOutputPath: f.serviceOutputPath, socketOutputPath: f.socketOutputPath,
      install: true, expectedOwnerUid: 0,
    });
    const verification = spawnSync('/usr/bin/systemd-analyze', [
      'verify', f.serviceOutputPath, f.socketOutputPath,
    ], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
    assert.equal(verification.status, 0, `${verification.stdout}\n${verification.stderr}`);
  } finally { fs.rmSync(f.root, { recursive: true, force: true }); }
});

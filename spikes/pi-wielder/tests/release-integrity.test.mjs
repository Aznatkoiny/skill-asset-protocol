import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertClosedLoaderEnvironment,
  buildReleaseManifest,
  captureInheritedConsoleSocket,
  computeServiceArtifactsHash,
  validateReleaseManifest,
  verifyReleaseIntegrity,
} from '../src/kernel/release-integrity.mjs';

const HASH = `sha256:${'a'.repeat(64)}`;

function fixture() {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-release-'));
  fs.chmodSync(parent, 0o700);
  const releaseRoot = path.join(parent, 'release');
  fs.mkdirSync(path.join(releaseRoot, 'src'), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(releaseRoot, 'scripts'), { mode: 0o755 });
  fs.writeFileSync(path.join(releaseRoot, 'src', 'control-plane.mjs'), 'export default 1;\n', {
    mode: 0o644,
  });
  fs.writeFileSync(path.join(releaseRoot, 'scripts', 'preflight-live-deployment.mjs'),
    '#!/usr/bin/env node\n', { mode: 0o755 });
  fs.writeFileSync(path.join(releaseRoot, 'package-lock.json'), '{"lockfileVersion":3}\n', {
    mode: 0o644,
  });
  fs.writeFileSync(path.join(releaseRoot, 'package.json'), '{"type":"module"}\n', {
    mode: 0o644,
  });
  const nodePath = path.join(parent, 'node');
  fs.writeFileSync(nodePath, 'synthetic-node\n', { mode: 0o755 });
  const environmentPath = path.join(parent, 'kernel.env');
  fs.writeFileSync(environmentPath, 'WALLET_KERNEL_MODE=cdp-testnet\n', { mode: 0o600 });
  const servicePath = path.join(parent, 'wallet-kernel.service');
  const socketPath = path.join(parent, 'wallet-kernel-console.socket');
  fs.writeFileSync(servicePath, '[Service]\n', { mode: 0o644 });
  fs.writeFileSync(socketPath, '[Socket]\n', { mode: 0o644 });
  return { parent, releaseRoot, nodePath, environmentPath, servicePath, socketPath };
}

function systemdFixture() {
  return {
    managerVersion: 'systemd 255 (255.4-1ubuntu8)',
    systemctlVersion: 'systemd 255 (255.4-1ubuntu8)',
    systemctlExecutablePathHash: HASH,
    systemctlExecutableSha256: HASH,
    effectiveConfigHash: HASH,
  };
}

test('builds and verifies a closed synthetic release manifest', () => {
  const f = fixture();
  try {
    const manifest = buildReleaseManifest({
      mode: 'deterministic',
      releaseRoot: f.releaseRoot,
      manifestPath: path.join(f.releaseRoot, 'manifest.json'),
      commit: '1'.repeat(40),
      createdAt: '2026-07-31T12:00:00.000Z',
      kernelUid: '501',
      kernelGid: '20',
      node: { path: f.nodePath, version: 'v24.18.1' },
      environmentPath: f.environmentPath,
      serviceArtifacts: [
        { role: 'kernel-service', path: f.servicePath },
        { role: 'console-socket', path: f.socketPath },
      ],
      systemd: systemdFixture(),
      expectedOwnerUid: process.getuid(),
    });
    assert.deepEqual(manifest.entries.map((entry) => entry.path), [
      'package-lock.json',
      'package.json',
      'scripts',
      'scripts/preflight-live-deployment.mjs',
      'src',
      'src/control-plane.mjs',
    ]);
    assert.equal(manifest.node.version, 'v24.18.1');
    assert.equal(manifest.serviceArtifacts.length, 2);
    assert.equal(validateReleaseManifest(manifest).commit, '1'.repeat(40));
    const verified = verifyReleaseIntegrity({
      mode: 'deterministic',
      releaseRoot: f.releaseRoot,
      manifest,
      expectedOwnerUid: process.getuid(),
      expectedKernelUid: '501',
      expectedKernelGid: '20',
      nodePath: f.nodePath,
      nodeVersion: 'v24.18.1',
      environmentPath: f.environmentPath,
      serviceArtifactPaths: {
        'kernel-service': f.servicePath,
        'console-socket': f.socketPath,
      },
    });
    assert.equal(verified.releaseManifestHash.startsWith('sha256:'), true);
  } finally {
    fs.rmSync(f.parent, { recursive: true, force: true });
  }
});

test('tree mutation, extra entries, mutable files, hardlinks, and escaping links fail closed', () => {
  const cases = [
    (f) => fs.appendFileSync(path.join(f.releaseRoot, 'package.json'), ' '),
    (f) => fs.writeFileSync(path.join(f.releaseRoot, 'extra'), 'x', { mode: 0o644 }),
    (f) => fs.chmodSync(path.join(f.releaseRoot, 'package.json'), 0o666),
    (f) => fs.linkSync(path.join(f.releaseRoot, 'package.json'), path.join(f.releaseRoot, 'alias')),
    (f) => fs.symlinkSync('../../escape', path.join(f.releaseRoot, 'escape')),
  ];
  for (const mutate of cases) {
    const f = fixture();
    try {
      const manifest = buildReleaseManifest({
        mode: 'deterministic', releaseRoot: f.releaseRoot,
        manifestPath: path.join(f.releaseRoot, 'manifest.json'), commit: '2'.repeat(40),
        createdAt: '2026-07-31T12:00:00.000Z', kernelUid: '501', kernelGid: '20',
        node: { path: f.nodePath, version: 'v24.18.1' }, environmentPath: f.environmentPath,
        serviceArtifacts: [
          { role: 'kernel-service', path: f.servicePath },
          { role: 'console-socket', path: f.socketPath },
        ], systemd: systemdFixture(), expectedOwnerUid: process.getuid(),
      });
      mutate(f);
      assert.throws(() => verifyReleaseIntegrity({
        mode: 'deterministic', releaseRoot: f.releaseRoot, manifest,
        expectedOwnerUid: process.getuid(), expectedKernelUid: '501', expectedKernelGid: '20',
        nodePath: f.nodePath, nodeVersion: 'v24.18.1', environmentPath: f.environmentPath,
        serviceArtifactPaths: {
          'kernel-service': f.servicePath, 'console-socket': f.socketPath,
        },
      }));
    } finally {
      fs.rmSync(f.parent, { recursive: true, force: true });
    }
  }
});

test('manifest rejects unknown fields, duplicate roles, and a non-pinned runtime', () => {
  const f = fixture();
  try {
    const common = {
      mode: 'deterministic', releaseRoot: f.releaseRoot,
      manifestPath: path.join(f.releaseRoot, 'manifest.json'), commit: '3'.repeat(40),
      createdAt: '2026-07-31T12:00:00.000Z', kernelUid: '501', kernelGid: '20',
      environmentPath: f.environmentPath, systemd: systemdFixture(),
      expectedOwnerUid: process.getuid(),
    };
    assert.throws(() => buildReleaseManifest({
      ...common, node: { path: f.nodePath, version: 'v24.18.0' },
      serviceArtifacts: [
        { role: 'kernel-service', path: f.servicePath },
        { role: 'console-socket', path: f.socketPath },
      ],
    }), /24\.18\.1/);
    assert.throws(() => buildReleaseManifest({
      ...common, node: { path: f.nodePath, version: 'v24.18.1' }, surprise: true,
      serviceArtifacts: [
        { role: 'kernel-service', path: f.servicePath },
        { role: 'console-socket', path: f.socketPath },
      ],
    }), /closed schema/);
    assert.throws(() => buildReleaseManifest({
      ...common, node: { path: f.nodePath, version: 'v24.18.1' },
      serviceArtifacts: [
        { role: 'kernel-service', path: f.servicePath },
        { role: 'kernel-service', path: f.socketPath },
      ],
    }), /roles/);
  } finally {
    fs.rmSync(f.parent, { recursive: true, force: true });
  }
});

test('service artifact aggregate is role ordered and domain separated', () => {
  const left = computeServiceArtifactsHash([
    { role: 'kernel-service', pathHash: HASH, sha256: HASH, uid: '0', gid: '0', mode: '644' },
    { role: 'console-socket', pathHash: HASH, sha256: HASH, uid: '0', gid: '0', mode: '644' },
  ]);
  const right = computeServiceArtifactsHash([
    { role: 'console-socket', pathHash: HASH, sha256: HASH, uid: '0', gid: '0', mode: '644' },
    { role: 'kernel-service', pathHash: HASH, sha256: HASH, uid: '0', gid: '0', mode: '644' },
  ]);
  assert.equal(left, right);
  assert.notEqual(left, HASH);
});

test('loader environment is a closed allowlist and rejects every loader-control family', () => {
  assert.deepEqual(assertClosedLoaderEnvironment({
    PATH: '/usr/bin:/bin', WALLET_KERNEL_MODE: 'cdp-testnet',
  }, { allowedWalletKernelFields: ['WALLET_KERNEL_MODE'] }), {
    PATH: '/usr/bin:/bin', WALLET_KERNEL_MODE: 'cdp-testnet',
  });
  for (const name of [
    'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_FOO', 'DYLD_INSERT_LIBRARIES',
    'GCONV_PATH', 'GLIBC_TUNABLES', 'WALLET_KERNEL_UNKNOWN',
  ]) {
    assert.throws(() => assertClosedLoaderEnvironment({ [name]: 'x' }, {
      allowedWalletKernelFields: ['WALLET_KERNEL_MODE'],
    }), /environment/);
  }
});

test('inherited console activation validates exact PID, count, name, descriptor, and clears variables', () => {
  const env = { LISTEN_PID: '123', LISTEN_FDS: '1', LISTEN_FDNAMES: 'wallet-kernel-console' };
  const result = captureInheritedConsoleSocket({
    env, processId: 123,
    inspectDescriptor: (fd) => ({
      fd, family: 'AF_INET', type: 'SOCK_STREAM', listening: true,
      address: '127.0.0.1', port: 8405,
    }),
  });
  assert.equal(result.fd, 3);
  assert.deepEqual(env, {});
  for (const changed of [
    { LISTEN_PID: '122' }, { LISTEN_FDS: '2' }, { LISTEN_FDNAMES: 'wrong' },
  ]) {
    assert.throws(() => captureInheritedConsoleSocket({
      env: { LISTEN_PID: '123', LISTEN_FDS: '1', LISTEN_FDNAMES: 'wallet-kernel-console', ...changed },
      processId: 123, inspectDescriptor: () => ({
        family: 'AF_INET', type: 'SOCK_STREAM', listening: true,
        address: '127.0.0.1', port: 8405,
      }),
    }), /activation/);
  }
  assert.throws(() => captureInheritedConsoleSocket({
    env: { LISTEN_PID: '123', LISTEN_FDS: '1', LISTEN_FDNAMES: 'wallet-kernel-console' },
    processId: 123, inspectDescriptor: () => ({
      family: 'AF_INET6', type: 'SOCK_STREAM', listening: true,
      address: '::1', port: 8405,
    }),
  }), /socket/);
});

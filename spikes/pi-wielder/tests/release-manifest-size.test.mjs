import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  buildReleaseManifest, MAXIMUM_RELEASE_MANIFEST_BYTES, serializeReleaseManifest,
  validateReleaseManifest,
} from '../src/kernel/release-integrity.mjs';
import { writeReleaseManifestExclusive } from '../scripts/build-release-manifest.mjs';
import { readManifestOnce } from '../scripts/preflight-live-deployment.mjs';

const HASH = `sha256:${'a'.repeat(64)}`;

function fixture(t) {
  const base = process.platform === 'linux' && process.getuid() === 0 ? '/run' : os.tmpdir();
  const root = fs.mkdtempSync(path.join(base, 'release-manifest-size-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const releaseRoot = path.join(root, 'release');
  fs.mkdirSync(path.join(releaseRoot, 'src'), { recursive: true, mode: 0o755 });
  fs.writeFileSync(path.join(releaseRoot, 'src/control-plane.mjs'), 'export default 1;\n', { mode: 0o644 });
  fs.writeFileSync(path.join(releaseRoot, 'package-lock.json'), '{"lockfileVersion":3}\n', { mode: 0o644 });
  const nodePath = path.join(root, 'node');
  const environmentPath = path.join(root, 'kernel.env');
  const servicePath = path.join(root, 'wallet-kernel.service');
  const socketPath = path.join(root, 'wallet-kernel-console.socket');
  fs.writeFileSync(nodePath, 'synthetic-node\n', { mode: 0o755 });
  fs.writeFileSync(environmentPath, 'WALLET_KERNEL_MODE=cdp-testnet\n', { mode: 0o600 });
  fs.writeFileSync(servicePath, '[Service]\n', { mode: 0o644 });
  fs.writeFileSync(socketPath, '[Socket]\n', { mode: 0o644 });
  const manifestPath = path.join(releaseRoot, 'manifest.json');
  const input = {
    mode: 'deterministic', releaseRoot, manifestPath, commit: '1'.repeat(40),
    createdAt: '2026-09-05T12:00:00.000Z', kernelUid: '501', kernelGid: '502',
    node: { path: nodePath, version: 'v24.18.1' }, environmentPath,
    serviceArtifacts: [{ role: 'kernel-service', path: servicePath }, { role: 'console-socket', path: socketPath }],
    systemd: { managerVersion: '255', systemctlVersion: 'systemd 255',
      systemctlExecutablePathHash: HASH, systemctlExecutableSha256: HASH, effectiveConfigHash: HASH },
    expectedOwnerUid: process.getuid(),
  };
  return { root, manifestPath, manifest: buildReleaseManifest(input) };
}

function dependencyManifest(base, count) {
  // Generate a structurally valid dependency-sized manifest without copying
  // tens of thousands of fixture files or requiring installed dependencies.
  const entries = [...base.entries];
  for (const relative of ['node_modules', 'node_modules/qualification-package', 'node_modules/qualification-package/dist']) {
    entries.push({ path: relative, kind: 'directory', uid: '0', gid: '0', mode: '755',
      bytes: null, sha256: null, target: null });
  }
  for (let index = 0; index < count; index += 1) entries.push({
    path: `node_modules/qualification-package/dist/entry-${String(index).padStart(6, '0')}.mjs`,
    kind: 'file', uid: '0', gid: '0', mode: '644', bytes: '18', sha256: HASH, target: null,
  });
  entries.sort((a, b) => Buffer.from(a.path).compare(Buffer.from(b.path)));
  return { ...base, entries,
    releaseTreeHash: sha256(`wallet-kernel/release-tree/v1\0${canonicalJson(entries)}`) };
}

function rootMetadataOnly(t) {
  // File I/O, inode, mode, link count, contents and size remain real. Only the
  // root-owner observation is simulated on non-root local test runners.
  if (process.getuid() === 0) return;
  const fstat = fs.fstatSync;
  t.mock.method(fs, 'fstatSync', (descriptor, options) => {
    const stat = fstat(descriptor, options);
    stat.uid = options?.bigint ? 0n : 0;
    return stat;
  });
}

test('dependency-sized canonical release manifest above 4 MiB round-trips through the exclusive writer and installed reader', t => {
  const f = fixture(t);
  const manifest = dependencyManifest(f.manifest, 40000);
  const bytes = serializeReleaseManifest(manifest);
  assert.ok(bytes.length > 4 * 1024 * 1024);
  assert.ok(bytes.length < MAXIMUM_RELEASE_MANIFEST_BYTES);
  assert.equal(writeReleaseManifestExclusive({ manifestPath: f.manifestPath, manifest }), bytes.length);
  assert.deepEqual(fs.readFileSync(f.manifestPath), bytes);
  rootMetadataOnly(t);
  const read = readManifestOnce(f.manifestPath);
  assert.equal(read.releaseTreeHash, manifest.releaseTreeHash);
  assert.equal(read.entries.length, manifest.entries.length);
  assert.throws(() => writeReleaseManifestExclusive({ manifestPath: f.manifestPath, manifest }), { code: 'EEXIST' });
});

test('oversized canonical release manifests fail shared validation and cannot create a sealed output', t => {
  const f = fixture(t);
  const manifest = dependencyManifest(f.manifest, 80000);
  assert.ok(Buffer.byteLength(`${canonicalJson(manifest)}\n`) > MAXIMUM_RELEASE_MANIFEST_BYTES);
  for (const operation of [
    () => serializeReleaseManifest(manifest),
    () => validateReleaseManifest(manifest),
    () => writeReleaseManifestExclusive({ manifestPath: f.manifestPath, manifest }),
  ]) assert.throws(operation, { code: 'RELEASE_MANIFEST_SIZE' });
  assert.equal(fs.existsSync(f.manifestPath), false);
});

test('installed manifest reader rejects an oversized sparse file before reading any bytes', t => {
  const f = fixture(t);
  const descriptor = fs.openSync(f.manifestPath, 'wx', 0o644);
  try { fs.ftruncateSync(descriptor, MAXIMUM_RELEASE_MANIFEST_BYTES + 1); }
  finally { fs.closeSync(descriptor); }
  rootMetadataOnly(t);
  let reads = 0;
  t.mock.method(fs, 'readSync', () => { reads += 1; throw new Error('oversized input must not be read'); });
  assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_SIZE' });
  assert.equal(reads, 0);
});

test('larger manifest allowance preserves ownership, link, direct-file, canonical-byte and inode-stability checks', t => {
  const f = fixture(t);
  writeReleaseManifestExclusive({ manifestPath: f.manifestPath, manifest: f.manifest });
  if (process.getuid() !== 0) assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_FILE' });
  rootMetadataOnly(t);
  fs.chmodSync(f.manifestPath, 0o666);
  assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_FILE' });
  fs.chmodSync(f.manifestPath, 0o644);
  const alias = path.join(f.root, 'alias.json');
  fs.linkSync(f.manifestPath, alias);
  assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_FILE' });
  fs.unlinkSync(alias);
  fs.symlinkSync(f.manifestPath, alias);
  assert.throws(() => readManifestOnce(alias), { code: 'RELEASE_MANIFEST_FILE' });
  if (process.platform === 'linux') {
    const fifo = path.join(f.root, 'manifest.fifo');
    execFileSync('/usr/bin/mkfifo', [fifo], { env: { PATH: '/usr/bin:/bin' }, timeout: 5000 });
    assert.throws(() => readManifestOnce(fifo), { code: 'RELEASE_MANIFEST_FILE' });
  }
  fs.appendFileSync(f.manifestPath, '\n');
  assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_CANONICAL' });
  fs.writeFileSync(f.manifestPath, serializeReleaseManifest(f.manifest));
  const read = fs.readSync;
  let modified = false;
  t.mock.method(fs, 'readSync', (...args) => {
    const count = read(...args);
    if (!modified) { modified = true; fs.appendFileSync(f.manifestPath, ' '); }
    return count;
  });
  assert.throws(() => readManifestOnce(f.manifestPath), { code: 'RELEASE_MANIFEST_RACE' });
});

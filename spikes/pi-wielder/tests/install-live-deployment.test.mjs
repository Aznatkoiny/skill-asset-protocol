import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, KernelError } from '../src/kernel/canonical.mjs';
import { readDeploymentConfig } from '../src/kernel/deployment.mjs';
import { buildReleaseManifest, verifyReleaseIntegrity } from '../src/kernel/release-integrity.mjs';
import { writeReleaseManifestExclusive } from '../scripts/build-release-manifest.mjs';
import {
  assertLiveInstallHost, installLiveDeployment, runInstallLiveDeployment, verifyPreparedRelease,
} from '../scripts/install-live-deployment.mjs';
import { renderSystemdUnits } from '../scripts/render-systemd-units.mjs';

const HASH = `sha256:${'a'.repeat(64)}`;
const UID = process.getuid();

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-install-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const sourceCheckoutPath = path.join(root, 'source');
  fs.mkdirSync(sourceCheckoutPath, { mode: 0o755 });
  const runGit = (directory, args) => execFileSync('/usr/bin/git', [
    '--no-optional-locks', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
    '-c', 'core.pager=cat', '-c', 'commit.gpgSign=false', '-C', directory, ...args,
  ], { encoding: 'utf8', timeout: 10_000, maxBuffer: 4 * 1024 * 1024,
    env: { PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null',
      GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '',
      GIT_AUTHOR_NAME: 'Offline fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid',
      GIT_COMMITTER_NAME: 'Offline fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
    stdio: ['ignore', 'pipe', 'pipe'] });
  runGit(sourceCheckoutPath, ['init', '--quiet']);
  const packageRoot = path.join(sourceCheckoutPath, 'spikes/pi-wielder');
  fs.mkdirSync(path.join(packageRoot, 'src'), { recursive: true, mode: 0o755 });
  fs.mkdirSync(path.join(packageRoot, 'scripts'), { mode: 0o755 });
  const packageJson = { name: 'fixture-kernel', version: '0.1.0', dependencies: { example: '1.0.0' } };
  const dependency = { version: '1.0.0', resolved: 'https://example.invalid/example.tgz', integrity: 'sha512-fixture' };
  const lock = { name: 'fixture-kernel', version: '0.1.0', lockfileVersion: 3,
    packages: { '': packageJson, 'node_modules/example': dependency } };
  const write = (location, value, mode = 0o644) => fs.writeFileSync(location, value, { mode });
  write(path.join(sourceCheckoutPath, '.gitignore'), 'node_modules/\n');
  write(path.join(sourceCheckoutPath, 'README.md'), 'Source outside the package must also be clean.\n');
  write(path.join(packageRoot, 'package.json'), `${JSON.stringify(packageJson)}\n`);
  write(path.join(packageRoot, 'package-lock.json'), `${JSON.stringify(lock)}\n`);
  write(path.join(packageRoot, 'src/control-plane.mjs'), 'export const fixture = true;\n');
  write(path.join(packageRoot, 'scripts/preflight-live-deployment.mjs'), 'process.exitCode = 78;\n', 0o755);
  write(path.join(packageRoot, 'scripts/install-live-deployment.mjs'), '// fixture installer graph, never executed\n');
  fs.mkdirSync(path.join(packageRoot, 'src/kernel'), { mode: 0o755 });
  fs.mkdirSync(path.join(packageRoot, 'deploy/systemd'), { recursive: true, mode: 0o755 });
  for (const name of ['src/kernel/canonical.mjs', 'src/kernel/deployment.mjs', 'src/kernel/release-integrity.mjs',
    'scripts/render-systemd-units.mjs', 'scripts/inspect-systemd-effective.mjs', 'scripts/build-release-manifest.mjs',
    'deploy/systemd/wallet-kernel.service', 'deploy/systemd/wallet-kernel-console.socket']) {
    write(path.join(packageRoot, name), 'fixture privileged helper bytes; never executed\n');
  }
  runGit(sourceCheckoutPath, ['add', '--all']);
  runGit(sourceCheckoutPath, ['commit', '--quiet', '-m', 'Offline install fixture']);
  const commit = runGit(sourceCheckoutPath, ['rev-parse', 'HEAD']).trim();
  const releaseRoot = path.join(root, 'releases', commit);
  fs.mkdirSync(path.dirname(releaseRoot), { mode: 0o755 });
  fs.cpSync(packageRoot, releaseRoot, { recursive: true });
  fs.mkdirSync(path.join(releaseRoot, 'node_modules/example'), { recursive: true, mode: 0o755 });
  write(path.join(releaseRoot, 'node_modules/.package-lock.json'), `${JSON.stringify({
    lockfileVersion: 3, packages: { 'node_modules/example': dependency },
  })}\n`);
  write(path.join(releaseRoot, 'node_modules/example/package.json'), '{"name":"example","version":"1.0.0"}\n');
  write(path.join(releaseRoot, 'node_modules/example/index.js'), 'export default 1;\n');
  for (const name of ['authority', 'evidence', 'runtime', 'outbox', 'inbox', 'units', 'credentials']) {
    fs.mkdirSync(path.join(root, name), { mode: 0o700 });
  }
  fs.mkdirSync(path.join(releaseRoot, 'config'), { mode: 0o755 });
  write(path.join(releaseRoot, 'config/policy.json'), '{}\n');
  write(path.join(releaseRoot, 'config/routes.json'), '{}\n');
  const config = {
    schemaVersion: 1, commit, trustedAncestor: root, kernelUid: '1001', kernelGid: '1001',
    agentUid: '1002', agentGid: '1002', releaseRoot, nodePath: path.join(root, 'node'),
    environmentPath: path.join(root, 'kernel.env'), authorityRoot: path.join(root, 'authority'),
    evidenceRoot: path.join(root, 'evidence'), runtimeRoot: path.join(root, 'runtime'),
    agentRunOutboxPath: path.join(root, 'outbox'), enrollmentInboxPath: path.join(root, 'inbox'),
    serviceOutputPath: path.join(root, 'units/wallet-kernel.service'),
    socketOutputPath: path.join(root, 'units/wallet-kernel-console.socket'),
    databasePath: path.join(root, 'authority/kernel.sqlite'),
    receiptKeyPath: path.join(root, 'authority/receipt.key'),
    operatorTokenPath: path.join(root, 'authority/operator.token'),
    isolationReportPath: path.join(root, 'runtime/isolation.json'),
    agentCredentialPath: path.join(root, 'credentials/agent.token'),
    policyPath: path.join(releaseRoot, 'config/policy.json'), routePath: path.join(releaseRoot, 'config/routes.json'),
    operatorSocketPath: path.join(root, 'runtime/operator.sock'),
  };
  write(config.nodePath, 'synthetic Node bytes; never executed\n', 0o755);
  write(config.environmentPath, 'SYNTHETIC_SECRET_MUST_NOT_APPEAR_IN_OUTPUT=1\n', 0o600);
  const deploymentPath = path.join(releaseRoot, 'deployment.json');
  write(deploymentPath, `${canonicalJson(config)}\n`);
  // Git and recursive copies can inherit the test host's group-writable umask.
  // Model an operator-prepared immutable tree before exercising its validation.
  const removeSharedWrite = (directory) => {
    const stat = fs.lstatSync(directory);
    fs.chmodSync(directory, stat.mode & 0o7755);
    if (stat.isDirectory()) for (const name of fs.readdirSync(directory)) removeSharedWrite(path.join(directory, name));
  };
  removeSharedWrite(root);
  return { root, config, sourceCheckoutPath, packageRoot, deploymentPath, runGit, write, lock, removeSharedWrite };
}

function harness(f) {
  const calls = [];
  const effects = {
    assertHost: () => ({ nodePath: f.config.nodePath, nodeVersion: 'v24.18.1', unitDirectory: path.join(f.root, 'units'),
      installerPath: path.join(f.packageRoot, 'scripts/install-live-deployment.mjs') }),
    readConfig: (file) => readDeploymentConfig(file, { expectedOwnerUid: UID }),
    verifyPrepared: (input) => {
      calls.push('provenance');
      return verifyPreparedRelease(input, { expectedOwnerUid: UID, runGit: f.runGit });
    },
    render: (input) => {
      calls.push('render');
      return renderSystemdUnits({ ...input, expectedOwnerUid: UID });
    },
    systemctl: (args) => {
      calls.push(args.join(' '));
      if (args[0] === 'show') return 'ActiveState=inactive\n';
      return '';
    },
    inspect: () => {
      calls.push('inspect');
      return { platform: 'linux', managerVersion: '255', systemctlVersion: 'systemd 255',
        systemctlExecutablePathHash: HASH, systemctlExecutableSha256: HASH, effectiveConfigHash: HASH };
    },
    build: (input) => {
      calls.push('build');
      return buildReleaseManifest({ ...input, mode: 'deterministic', expectedOwnerUid: UID });
    },
    write: (input) => { calls.push('write'); return writeReleaseManifestExclusive(input); },
    verify: (input) => {
      calls.push('verify');
      return verifyReleaseIntegrity({ ...input, mode: 'deterministic', expectedOwnerUid: UID });
    },
    now: () => '2026-09-05T12:00:00.000Z',
  };
  const install = () => installLiveDeployment({ deploymentPath: f.deploymentPath,
    sourceCheckoutPath: f.sourceCheckoutPath }, effects);
  return { calls, effects, install };
}

test('seals a clean prepared release in order, without starting or claiming qualification', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const result = await h.install();
  assert.equal(result.status, 'sealed_not_started');
  assert.equal(result.started, false);
  assert.equal(result.execution, 'simulated');
  assert.equal(result.qualification, 'not_performed');
  assert.deepEqual(h.calls.filter((item) => !item.startsWith('show ')), [
    'provenance', 'render', 'daemon-reload', 'enable wallet-kernel-console.socket',
    'inspect', 'build', 'write', 'verify',
  ]);
  assert.equal(h.calls.some((item) => /\b(start|restart|--now)\b/.test(item)), false);
  const bytes = fs.readFileSync(path.join(f.config.releaseRoot, 'manifest.json'), 'utf8');
  const manifest = JSON.parse(bytes);
  assert.equal(bytes, `${canonicalJson(manifest)}\n`);
  assert.equal(manifest.commit, f.config.commit);
  assert.equal(manifest.entries.some((entry) => entry.path === 'deployment.json'), true);
  assert.equal(bytes.includes('SYNTHETIC_SECRET_MUST_NOT_APPEAR'), false);
  await assert.rejects(h.install(), { code: 'LIVE_INSTALL_EXISTS' });
});

test('cleanup attempts all steps after partial enablement, preserving the original failure code', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const run = h.effects.systemctl;
  h.effects.systemctl = (args) => {
    const result = run(args);
    if (args[0] === 'enable') throw new KernelError('ENABLE_RESPONSE_LOST', 'sensitive host detail');
    if (args[0] === 'stop') throw new KernelError('STOP_FAILED', 'another sensitive detail');
    return result;
  };
  await assert.rejects(h.install(), (error) => {
    assert.equal(error.code, 'ENABLE_RESPONSE_LOST');
    assert.deepEqual(error.cleanup.map((item) => item.status), ['attempt_failed', 'attempt_failed', 'attempt_succeeded']);
    assert.equal(JSON.stringify(error.cleanup).includes('sensitive'), false);
    return true;
  });
  assert.deepEqual(h.calls.slice(-3), [
    'stop wallet-kernel.service', 'stop wallet-kernel-console.socket', 'disable wallet-kernel-console.socket',
  ]);
  assert.equal(fs.existsSync(path.join(f.config.releaseRoot, 'manifest.json')), false);
});

for (const stage of ['inspect', 'build', 'write', 'verify']) {
  test(`failure during ${stage} cleans up enabled units without masking the cause`, async (t) => {
    const f = fixture(t);
    const h = harness(f);
    h.effects[stage] = () => { throw new KernelError('ORIGINAL_FAILURE', 'private implementation detail'); };
    await assert.rejects(h.install(), { code: 'ORIGINAL_FAILURE' });
    assert.deepEqual(h.calls.slice(-3), [
      'stop wallet-kernel.service', 'stop wallet-kernel-console.socket', 'disable wallet-kernel-console.socket',
    ]);
  });
}

test('daemon reload failure cannot enable or start the socket', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const run = h.effects.systemctl;
  h.effects.systemctl = (args) => {
    run(args);
    if (args[0] === 'daemon-reload') throw new KernelError('RELOAD_FAILED', 'reload failed');
    return 'ActiveState=inactive\n';
  };
  await assert.rejects(h.install(), { code: 'RELOAD_FAILED' });
  assert.equal(h.calls.some((item) => item.startsWith('enable') || item.startsWith('stop')), false);
});

test('an already active unit blocks installation, and activation during sealing forces cleanup', async (t) => {
  for (const activateAt of ['before', 'after']) {
    await t.test(activateAt, async (t) => {
      const f = fixture(t);
      const h = harness(f);
      const run = h.effects.systemctl;
      h.effects.systemctl = (args) => {
        const result = run(args);
        if (args[0] === 'show' && (activateAt === 'before' || h.calls.includes('verify'))) return 'ActiveState=active\n';
        return result;
      };
      await assert.rejects(h.install(), { code: 'LIVE_INSTALL_ACTIVE' });
      if (activateAt === 'before') assert.equal(h.calls.includes('render'), false);
      else assert.equal(h.calls.at(-1), 'disable wallet-kernel-console.socket');
    });
  }
});

test('real temporary Git provenance accepts the exact clean source and installed lock', (t) => {
  const f = fixture(t);
  const result = verifyPreparedRelease({ config: f.config, sourceCheckoutPath: f.sourceCheckoutPath },
    { expectedOwnerUid: UID, runGit: f.runGit });
  assert.equal(result.commit, f.config.commit);
  assert.equal(result.sourceFiles, 13);
  assert.equal(result.installedPackages, 1);
});

for (const [name, mutate, code] of [
  ['dirty tracked source', (f) => fs.appendFileSync(path.join(f.sourceCheckoutPath, 'README.md'), 'changed\n'), 'LIVE_INSTALL_SOURCE'],
  ['staged source change', (f) => { fs.appendFileSync(path.join(f.sourceCheckoutPath, 'README.md'), 'changed\n'); f.runGit(f.sourceCheckoutPath, ['add', 'README.md']); f.removeSharedWrite(path.join(f.sourceCheckoutPath, '.git')); }, 'LIVE_INSTALL_SOURCE'],
  ['untracked source', (f) => f.write(path.join(f.sourceCheckoutPath, 'unexpected.txt'), 'extra'), 'LIVE_INSTALL_SOURCE'],
  ['prepared source change', (f) => fs.appendFileSync(path.join(f.config.releaseRoot, 'src/control-plane.mjs'), '// changed\n'), 'LIVE_INSTALL_SOURCE'],
  ['prepared privileged helper change', (f) => fs.appendFileSync(path.join(f.config.releaseRoot, 'scripts/render-systemd-units.mjs'), '// changed\n'), 'LIVE_INSTALL_SOURCE'],
  ['changed executable mode', (f) => fs.chmodSync(path.join(f.config.releaseRoot, 'src/control-plane.mjs'), 0o755), 'LIVE_INSTALL_SOURCE'],
  ['extra prepared file', (f) => f.write(path.join(f.config.releaseRoot, 'surprise.mjs'), 'extra'), 'LIVE_INSTALL_SOURCE'],
  ['writable release', (f) => fs.chmodSync(f.config.releaseRoot, 0o777), 'LIVE_INSTALL_OWNERSHIP'],
  ['Git include', (f) => fs.appendFileSync(path.join(f.sourceCheckoutPath, '.git/config'), '\n[include]\npath=/untrusted\n'), 'LIVE_INSTALL_SOURCE'],
  ['Git filter', (f) => fs.appendFileSync(path.join(f.sourceCheckoutPath, '.git/config'), '\n[filter "unsafe"]\nclean=arbitrary-command\n'), 'LIVE_INSTALL_SOURCE'],
  ['Git extension', (f) => fs.appendFileSync(path.join(f.sourceCheckoutPath, '.git/config'), '\n[extensions]\nworktreeConfig=true\n'), 'LIVE_INSTALL_SOURCE'],
  ['Git partial clone', (f) => fs.appendFileSync(path.join(f.sourceCheckoutPath, '.git/config'), '\n[remote "origin"]\npromisor=true\n'), 'LIVE_INSTALL_SOURCE'],
  ['mutable Git object directory', (f) => fs.chmodSync(path.join(f.sourceCheckoutPath, '.git/objects'), 0o777), 'LIVE_INSTALL_OWNERSHIP'],
  ['mutable source ancestor', (f) => fs.chmodSync(path.join(f.sourceCheckoutPath, 'spikes'), 0o777), 'LIVE_INSTALL_OWNERSHIP'],
  ['wrong package version', (f) => f.write(path.join(f.config.releaseRoot, 'node_modules/example/package.json'), '{"name":"example","version":"9.0.0"}\n'), 'LIVE_INSTALL_LOCK'],
  ['wrong installed integrity', (f) => f.write(path.join(f.config.releaseRoot, 'node_modules/.package-lock.json'), JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/example': { version: '1.0.0', integrity: 'wrong' } } })), 'LIVE_INSTALL_LOCK'],
  ['missing locked package', (f) => f.write(path.join(f.config.releaseRoot, 'node_modules/.package-lock.json'), '{"lockfileVersion":3,"packages":{}}\n'), 'LIVE_INSTALL_LOCK'],
  ['unlocked installed package', (f) => { fs.mkdirSync(path.join(f.config.releaseRoot, 'node_modules/unlocked'), { mode: 0o755 }); f.write(path.join(f.config.releaseRoot, 'node_modules/unlocked/package.json'), '{}'); }, 'LIVE_INSTALL_LOCK'],
  ['external prepared symlink', (f) => fs.symlinkSync(f.config.nodePath, path.join(f.config.releaseRoot, 'node_modules/outside')), 'LIVE_INSTALL_SOURCE'],
]) {
  test(`rejects ${name} before changing systemd`, async (t) => {
    const f = fixture(t);
    mutate(f);
    const h = harness(f);
    await assert.rejects(h.install(), { code });
    assert.deepEqual(h.calls, ['provenance']);
  });
}

test('loader/config and existing-unit failures do not create new installation artifacts', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const host = h.effects.assertHost();
  h.effects.assertHost = () => ({ ...host, nodePath: '/wrong/node' });
  await assert.rejects(h.install(), { code: 'LIVE_INSTALL_INPUT' });
  assert.deepEqual(h.calls, []);
  h.effects.assertHost = () => host;
  f.write(f.config.serviceOutputPath, 'pre-existing unit');
  await assert.rejects(h.install(), { code: 'LIVE_INSTALL_EXISTS' });
  assert.equal(fs.readFileSync(f.config.serviceOutputPath, 'utf8'), 'pre-existing unit');
});

test('production unit-directory binding rejects units that systemd would not load by name', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const host = h.effects.assertHost();
  h.effects.assertHost = () => ({ ...host, unitDirectory: '/etc/systemd/system' });
  await assert.rejects(h.install(), { code: 'LIVE_INSTALL_INPUT' });
  assert.deepEqual(h.calls, []);
});

test('installer entrypoint must be in the verified source or release graph', async (t) => {
  const f = fixture(t);
  const h = harness(f);
  const host = h.effects.assertHost();
  h.effects.assertHost = () => ({ ...host, installerPath: '/unrelated/scripts/install-live-deployment.mjs' });
  await assert.rejects(h.install(), { code: 'LIVE_INSTALL_INPUT' });
  assert.deepEqual(h.calls, []);
  h.effects.assertHost = () => ({ ...host, installerPath: path.join(f.config.releaseRoot, 'scripts/install-live-deployment.mjs') });
  assert.equal((await h.install()).status, 'sealed_not_started');
});

test('an internal npm bin symlink remains a valid sealed dependency entry', async (t) => {
  const f = fixture(t);
  fs.mkdirSync(path.join(f.config.releaseRoot, 'node_modules/.bin'), { mode: 0o755 });
  fs.symlinkSync('../example/index.js', path.join(f.config.releaseRoot, 'node_modules/.bin/example'));
  const result = await harness(f).install();
  assert.equal(result.status, 'sealed_not_started');
  const manifest = JSON.parse(fs.readFileSync(path.join(f.config.releaseRoot, 'manifest.json'), 'utf8'));
  assert.equal(manifest.entries.find((entry) => entry.path === 'node_modules/.bin/example').target, 'node_modules/example/index.js');
});

for (const [name, mutate] of [
  ['committed source', (f) => fs.appendFileSync(path.join(f.config.releaseRoot, 'src/control-plane.mjs'), '// late change\n')],
  ['extra source', (f) => f.write(path.join(f.config.releaseRoot, 'late.mjs'), 'export default 1;\n')],
  ['dependency inventory', (f) => fs.appendFileSync(path.join(f.config.releaseRoot, 'node_modules/.package-lock.json'), '\n')],
  ['deployment binding', (f) => fs.appendFileSync(f.deploymentPath, '\n')],
]) {
  test(`a late change to ${name} is rejected before the manifest is written`, async (t) => {
    const f = fixture(t);
    const h = harness(f);
    const inspect = h.effects.inspect;
    h.effects.inspect = () => { const result = inspect(); mutate(f); return result; };
    await assert.rejects(h.install(), { code: 'LIVE_INSTALL_CHANGED' });
    assert.equal(fs.existsSync(path.join(f.config.releaseRoot, 'manifest.json')), false);
    assert.equal(h.calls.at(-1), 'disable wallet-kernel-console.socket');
  });
}

test('CLI has no start or deterministic host-bypass flag and reports bounded codes only', async () => {
  const stdout = [];
  const stderr = [];
  const code = await runInstallLiveDeployment({ argv: ['--start'],
    stdout: { write: (value) => stdout.push(value) }, stderr: { write: (value) => stderr.push(value) } });
  assert.equal(code, 1);
  assert.deepEqual(stdout, []);
  assert.deepEqual(JSON.parse(stderr[0]), { code: 'LIVE_INSTALL_ARGUMENTS', cleanup: [] });
  if (process.getuid() !== 0 || process.platform !== 'linux' || process.version !== 'v24.18.1') {
    assert.throws(() => assertLiveInstallHost(), { code: 'LIVE_INSTALL_HOST' });
  }
});

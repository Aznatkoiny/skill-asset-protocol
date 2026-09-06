import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import { deploymentRendererInput, readDeploymentConfig } from '../src/kernel/deployment.mjs';
import { cleanupSystemdQualification, runCleanupSystemdQualification } from '../scripts/cleanup-systemd-qualification.mjs';
import { renderSystemdUnits } from '../scripts/render-systemd-units.mjs';

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'qualification-teardown-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const commit = 'a'.repeat(40);
  const releaseRoot = path.join(root, 'releases', commit);
  for (const name of [`releases/${commit}`, 'node/bin', 'config', 'authority', 'runtime', 'evidence', 'outbox', 'inbox', 'agent-private', 'units']) {
    fs.mkdirSync(path.join(root, name), { recursive: true, mode: 0o755 });
  }
  const config = { schemaVersion: 1, commit, executionProfile: 'offline-qualification',
    kernelUid: '1001', kernelGid: '1001', agentUid: '1002', agentGid: '1002', trustedAncestor: root,
    releaseRoot, nodePath: path.join(root, 'node/bin/node'), environmentPath: path.join(root, 'config/kernel.env'),
    authorityRoot: path.join(root, 'authority'), runtimeRoot: path.join(root, 'runtime'), evidenceRoot: path.join(root, 'evidence'),
    agentRunOutboxPath: path.join(root, 'outbox'), enrollmentInboxPath: path.join(root, 'inbox'),
    serviceOutputPath: path.join(root, 'units/wallet-kernel.service'), socketOutputPath: path.join(root, 'units/wallet-kernel-console.socket'),
    databasePath: path.join(root, 'authority/kernel.sqlite'), receiptKeyPath: path.join(root, 'authority/receipt-key.json'),
    operatorTokenPath: path.join(root, 'authority/operator-token.json'), isolationReportPath: path.join(root, 'runtime/isolation.json'),
    operatorSocketPath: path.join(root, 'runtime/admin.sock'), agentCredentialPath: path.join(root, 'agent-private/credential.json'),
    policyPath: path.join(releaseRoot, 'policy.json'), routePath: path.join(releaseRoot, 'routes.json'),
  };
  fs.writeFileSync(config.nodePath, 'fixture bytes; never executed\n', { mode: 0o755 });
  fs.writeFileSync(config.environmentPath, 'SYNTHETIC_SECRET_NOT_READ_OR_LOGGED=1\n', { mode: 0o600 });
  const deploymentPath = path.join(releaseRoot, 'deployment.json');
  fs.writeFileSync(deploymentPath, `${canonicalJson(config)}\n`, { mode: 0o644 });
  renderSystemdUnits({ ...deploymentRendererInput(config), install: true, expectedOwnerUid: process.getuid() });
  const exec = (relative, privileged = false) => `{ path=${config.nodePath} ; argv[]=${config.nodePath} ${releaseRoot}/${relative} ; flags=${privileged ? 'privileged' : ''} ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`;
  const state = {
    service: { Id: 'wallet-kernel.service', LoadState: 'loaded', FragmentPath: config.serviceOutputPath,
      ExecStartEx: exec('src/control-plane.mjs'), ExecStopPostEx: exec('scripts/cleanup-live-deployment.mjs', true),
      ActiveState: 'active', MainPID: '1234', Job: '' },
    socket: { Id: 'wallet-kernel-console.socket', LoadState: 'loaded', FragmentPath: config.socketOutputPath,
      UnitFileState: 'enabled', ActiveState: 'active', Job: '' },
  };
  const calls = [];
  let time = 0;
  const effects = {
    assertHost: () => ({ qualificationRoot: root, nodePath: config.nodePath, expectedOwnerUid: process.getuid(),
      unitDirectory: path.join(root, 'units'), scriptPath: path.join(releaseRoot, 'scripts/cleanup-systemd-qualification.mjs') }),
    readDeployment: (location) => readDeploymentConfig(location, { expectedOwnerUid: process.getuid() }),
    runSystemctl: (args) => {
      calls.push(args.join(' '));
      if (args[0] === 'show') {
        const unit = args.at(-1).endsWith('.socket') ? state.socket : state.service;
        return `${args[3].slice('--property='.length).split(',').map((name) => `${name}=${unit[name]}`).join('\n')}\n`;
      }
      if (args[0] === 'stop' && args[1].endsWith('.socket')) state.socket.ActiveState = 'inactive';
      if (args[0] === 'stop' && args[1].endsWith('.service')) { state.service.ActiveState = 'inactive'; state.service.MainPID = '0'; }
      if (args[0] === 'disable') state.socket.UnitFileState = 'disabled';
      return '';
    },
    listenersClosed: () => true,
    now: () => time,
    sleep: async (ms) => { time += ms; },
  };
  return { root, config, deploymentPath, state, calls, effects,
    clean: () => cleanupSystemdQualification({ deploymentPath }, effects) };
}

test('owned disposable units are removed only after all stop/disable requests and observed quiescence', async (t) => {
  const f = fixture(t);
  const result = await f.clean();
  assert.equal(result.status, 'removed_after_quiescence');
  assert.equal(result.execution, 'simulated');
  assert.equal(result.qualification, 'not_performed');
  assert.deepEqual(f.calls.filter((call) => !call.startsWith('show ')), [
    'stop wallet-kernel-console.socket', 'stop wallet-kernel.service', 'disable wallet-kernel-console.socket', 'daemon-reload',
  ]);
  assert.equal(fs.existsSync(f.config.serviceOutputPath), false);
  assert.equal(fs.existsSync(f.config.socketOutputPath), false);
  assert.equal(fs.readFileSync(f.config.environmentPath, 'utf8'), 'SYNTHETIC_SECRET_NOT_READ_OR_LOGGED=1\n');
});

test('failed stop requests cannot mask their errors or prevent remaining cleanup attempts', async (t) => {
  const f = fixture(t);
  const run = f.effects.runSystemctl;
  f.effects.runSystemctl = (args) => {
    const result = run(args);
    if (args[0] === 'stop') { const error = new Error('private host response'); error.code = 'STOP_REQUEST_FAILED'; throw error; }
    return result;
  };
  await assert.rejects(f.clean(), (error) => {
    assert.equal(error.code, 'STOP_REQUEST_FAILED');
    assert.equal(JSON.stringify(error).includes('private'), false);
    assert.equal(error.attempts.length, 3);
    return true;
  });
  assert.equal(f.calls.includes('disable wallet-kernel-console.socket'), true);
  assert.equal(f.calls.includes('daemon-reload'), false);
  assert.equal(fs.existsSync(f.config.serviceOutputPath), true);
  assert.equal(fs.existsSync(f.config.socketOutputPath), true);
});

for (const reason of ['live profile', 'foreign fragment', 'foreign executable', 'changed unit bytes']) {
  test(`refuses ${reason} before any mutation`, async (t) => {
    const f = fixture(t);
    let code = 'QUALIFICATION_CLEANUP_OWNER';
    if (reason === 'live profile') {
      f.effects.readDeployment = () => ({ ...f.config, executionProfile: 'cdp-testnet' });
      code = 'QUALIFICATION_CLEANUP_SCOPE';
    } else if (reason === 'foreign fragment') f.state.service.FragmentPath = '/etc/systemd/system/unrelated.service';
    else if (reason === 'foreign executable') f.state.service.ExecStartEx = f.state.service.ExecStartEx.replace('/src/control-plane.mjs', '/src/other.mjs');
    else fs.appendFileSync(f.config.serviceOutputPath, '# unexpected modification\n');
    await assert.rejects(f.clean(), { code });
    assert.deepEqual(f.calls.filter((call) => !call.startsWith('show ')), []);
    assert.equal(fs.existsSync(f.config.serviceOutputPath), true);
  });
}

for (const reason of ['listener remains', 'job remains', 'MainPID remains']) {
  test(`bounded quiescence refuses deletion when ${reason}`, async (t) => {
    const f = fixture(t);
    const run = f.effects.runSystemctl;
    if (reason === 'listener remains') f.effects.listenersClosed = () => false;
    else f.effects.runSystemctl = (args) => {
      if (args[0] === 'show') {
        if (reason === 'job remains') f.state.service.Job = '42';
        else f.state.service.MainPID = '1234';
      }
      return run(args);
    };
    await assert.rejects(f.clean(), { code: 'QUALIFICATION_CLEANUP_NOT_QUIESCENT' });
    assert.equal(f.calls.includes('daemon-reload'), false);
    assert.equal(fs.existsSync(f.config.serviceOutputPath), true);
  });
}

test('a stopped failed service is acceptable, but replacing an owned unit during the wait is not', async (t) => {
  const f = fixture(t);
  const run = f.effects.runSystemctl;
  f.effects.runSystemctl = (args) => {
    if (args[0] === 'show' && f.state.service.MainPID === '0') f.state.service.ActiveState = 'failed';
    return run(args);
  };
  assert.equal((await f.clean()).status, 'removed_after_quiescence');
  const replaced = fixture(t);
  replaced.effects.listenersClosed = () => { fs.appendFileSync(replaced.config.socketOutputPath, '# replacement\n'); return true; };
  await assert.rejects(replaced.clean(), { code: 'QUALIFICATION_CLEANUP_OWNER' });
  assert.equal(fs.existsSync(replaced.config.serviceOutputPath), true);
  assert.equal(fs.existsSync(replaced.config.socketOutputPath), true);
});

test('the command line has no scope or simulation override and emits stable diagnostics', async () => {
  const errors = [];
  const status = await runCleanupSystemdQualification({ argv: ['--simulate'],
    stdout: { write() { assert.fail('unexpected success'); } }, stderr: { write(value) { errors.push(value); } } });
  assert.equal(status, 1);
  assert.deepEqual(JSON.parse(errors[0]), { code: 'QUALIFICATION_CLEANUP_ARGUMENTS', attempts: [] });
});

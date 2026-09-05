import assert from 'node:assert/strict';
import test from 'node:test';
import { canonicalJson } from '../src/kernel/canonical.mjs';
import { REQUIRED_ISOLATION_PROBE_RESULTS } from '../src/agent/isolation-preflight.mjs';
import { composeInstalledService } from '../src/runtime/installed-service.mjs';

const H = `sha256:${'a'.repeat(64)}`;
const commit = 'a'.repeat(40);
const root = `/srv/wallet/releases/${commit}`;
const config = {
  schemaVersion: 1, commit, kernelUid: '501', kernelGid: '501', agentUid: '502', agentGid: '502',
  trustedAncestor: '/srv/wallet', releaseRoot: root, nodePath: process.execPath,
  environmentPath: '/srv/wallet/config/kernel.env', authorityRoot: '/srv/wallet/authority',
  runtimeRoot: '/srv/wallet/runtime', evidenceRoot: '/srv/wallet/evidence',
  agentRunOutboxPath: '/srv/wallet/outbox', enrollmentInboxPath: '/srv/wallet/inbox',
  serviceOutputPath: '/srv/wallet/systemd/wallet-kernel.service',
  socketOutputPath: '/srv/wallet/systemd/wallet-kernel-console.socket',
  databasePath: '/srv/wallet/authority/db', receiptKeyPath: '/srv/wallet/authority/key',
  operatorTokenPath: '/srv/wallet/authority/token', isolationReportPath: '/srv/wallet/runtime/isolation.json',
  operatorSocketPath: '/srv/wallet/runtime/admin.sock', agentCredentialPath: '/srv/wallet/agent-private/credential',
  policyPath: `${root}/policy.json`, routePath: `${root}/routes.json`,
};
const release = {
  releaseManifestHash: H, releaseTreeHash: H, nodeExecutableHash: H,
  serviceArtifactsHash: H, systemdEffectiveConfigHash: H, environmentMetadataHash: H,
};
const report = {
  schemaVersion: 1, enrollmentHash: H, kernelUid: '501', kernelGid: '501', agentUid: '502', agentGid: '502',
  authorityMetadataHash: H, credentialMetadataHash: H, ...release,
  probeResults: REQUIRED_ISOLATION_PROBE_RESULTS,
  probedAt: '2026-09-05T12:00:00.000Z', expiresAt: '2026-09-05T12:15:00.000Z',
};

function fixture(changes = {}) {
  const events = [];
  const input = { releaseRoot: root, environment: {
    WALLET_KERNEL_ENV_FILE: config.environmentPath,
    LISTEN_PID: '12345', LISTEN_FDS: '1', LISTEN_FDNAMES: 'wallet-kernel-console',
  } };
  const effects = {
    processApi: { platform: 'linux', pid: 12345, version: 'v24.18.1', execPath: process.execPath,
      getuid: () => 501, geteuid: () => 501, getgid: () => 501, getegid: () => 501, getgroups: () => [501] },
    readDeployment: () => config,
    inspectDescriptor: (fd) => {
      events.push('activation');
      return { fd, family: 'AF_INET', type: 'SOCK_STREAM', listening: true, address: '127.0.0.1', port: 8405 };
    },
    readManifest: () => ({ commit, systemd: { effectiveConfigHash: H } }),
    verifyRelease: (request) => { events.push('release'); assert.equal(request.expectedOwnerUid, 0); return release; },
    renderUnits: () => ({ expectedEffectiveConfig: {} }),
    inspectSystemd: async () => { events.push('pid1'); return { effectiveConfigHash: H }; },
    captureAuthorityMetadata: () => H,
    readReport: () => Buffer.from(`${canonicalJson(report)}\n`),
    now: () => '2026-09-05T12:05:00.000Z',
    startRuntime: async (options) => {
      events.push('runtime');
      assert.equal(options.kernelUid, 501);
      assert.equal(options.kernelGid, 501);
      assert.equal(options.environmentFilePath, config.environmentPath);
      assert.equal(options.credentialFilePath, '/run/credentials/wallet-kernel.service/wallet-kernel-environment');
      assert.equal(options.deployment, config);
      assert.equal(options.consoleActivation.fd, 3);
      const admission = options.assertLiveAdmission({ enrollment: { enrollmentHash: H } });
      assert.equal(admission.isolation, 'verified');
      assert.deepEqual(admission.report, report);
      return { close: async () => {} };
    },
    ...changes,
  };
  return { input, effects, events };
}

test('installed bootstrap verifies process, socket, release, and PID1 before runtime secret delivery', async () => {
  const f = fixture();
  const plane = await composeInstalledService(f.input, f.effects);
  assert.equal(typeof plane.close, 'function');
  assert.deepEqual(f.events, ['activation', 'release', 'pid1', 'runtime']);
});

test('root, extra groups, wrong socket, and inherited secrets cannot reach the runtime', async () => {
  for (const mutate of [
    (f) => { f.effects.processApi.getuid = () => 0; },
    (f) => { f.effects.processApi.getgroups = () => [501, 502]; },
    (f) => { f.input.environment.LISTEN_PID = '999'; },
    (f) => { f.input.environment.CDP_API_KEY_SECRET = 'sentinel'; },
  ]) {
    const f = fixture(); mutate(f);
    await assert.rejects(composeInstalledService(f.input, f.effects));
    assert.equal(f.events.includes('runtime'), false);
  }
});

test('late PID1 drift and stale or differently bound attestations refuse installed startup', async () => {
  const drift = fixture({ inspectSystemd: async () => ({ effectiveConfigHash: `sha256:${'b'.repeat(64)}` }) });
  await assert.rejects(composeInstalledService(drift.input, drift.effects), /PID1/);
  assert.equal(drift.events.includes('runtime'), false);
  for (const changes of [
    { now: () => '2026-09-05T12:15:00.000Z' },
    { captureAuthorityMetadata: () => `sha256:${'b'.repeat(64)}` },
    { readReport: () => Buffer.from(`${canonicalJson({ ...report, nodeExecutableHash: `sha256:${'b'.repeat(64)}` })}\n`) },
    { readReport: () => Buffer.from(`${canonicalJson({ ...report, agentUid: '503' })}\n`) },
  ]) {
    const f = fixture(changes);
    await assert.rejects(composeInstalledService(f.input, f.effects));
  }
});

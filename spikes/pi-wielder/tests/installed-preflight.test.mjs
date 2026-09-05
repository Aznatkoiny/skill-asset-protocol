import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { canonicalJson } from '../src/kernel/canonical.mjs';
import { deploymentRendererInput, isInstalledQualificationRelease, readDeploymentConfig, validateDeploymentConfig } from '../src/kernel/deployment.mjs';
import { REQUIRED_ISOLATION_PROBE_RESULTS } from '../src/agent/isolation-preflight.mjs';
import { runInstalledLivePreflight } from '../scripts/preflight-live-deployment.mjs';

const HASH = `sha256:${'a'.repeat(64)}`;
function configuration(root = '/srv/wallet') {
  const commit = 'a'.repeat(40);
  const releaseRoot = `${root}/releases/${commit}`;
  return {
    schemaVersion: 1, commit, kernelUid: '501', kernelGid: '501', agentUid: '502', agentGid: '502',
    trustedAncestor: root, releaseRoot, nodePath: process.execPath,
    environmentPath: `${root}/config/kernel.env`, authorityRoot: `${root}/authority`,
    runtimeRoot: `${root}/runtime`, evidenceRoot: `${root}/evidence`,
    agentRunOutboxPath: `${root}/outbox`, enrollmentInboxPath: `${root}/inbox`,
    serviceOutputPath: `${root}/systemd/wallet-kernel.service`,
    socketOutputPath: `${root}/systemd/wallet-kernel-console.socket`,
    databasePath: `${root}/authority/kernel.sqlite`, receiptKeyPath: `${root}/authority/receipt-key.json`,
    operatorTokenPath: `${root}/authority/operator-token.json`,
    isolationReportPath: `${root}/runtime/isolation.json`, operatorSocketPath: `${root}/runtime/admin.sock`,
    agentCredentialPath: `${root}/agent-private/credential.json`,
    policyPath: `${releaseRoot}/policy.json`, routePath: `${releaseRoot}/routes.json`,
  };
}

test('public deployment rejects mixed releases, authority overlap, aliases, and secret fields', () => {
  assert.equal(validateDeploymentConfig(configuration()).commit, 'a'.repeat(40));
  for (const change of [
    { commit: 'b'.repeat(40) }, { kernelUid: '0' }, { agentUid: '501' }, { agentGid: '501' },
    { evidenceRoot: '/srv/wallet/authority/evidence' },
    { policyPath: '/srv/wallet/config/policy.json' },
    { environmentPath: '/srv/wallet/authority/kernel.env' },
    { databasePath: '/srv/wallet/authority/../kernel.sqlite' },
    { CDP_API_KEY_SECRET: 'never-public' },
    { executionProfile: 'live-override' }, { executionProfile: true },
  ]) assert.throws(() => validateDeploymentConfig({ ...configuration(), ...change }));
});

test('qualification is an explicit sealed deployment profile, never selected by caller environment', () => {
  const config = validateDeploymentConfig({ ...configuration(), executionProfile: 'offline-qualification' });
  assert.equal(deploymentRendererInput(config).executionProfile, 'offline-qualification');
  assert.equal(deploymentRendererInput(configuration()).executionProfile, undefined);
  assert.equal(isInstalledQualificationRelease('/does/not/exist'), false);
});

test('deployment input is canonical, bounded, immutable, and bound to its release directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'installed-deployment-'));
  try {
    const config = configuration(root);
    fs.mkdirSync(config.releaseRoot, { recursive: true });
    const filePath = path.join(config.releaseRoot, 'deployment.json');
    fs.writeFileSync(filePath, `${canonicalJson(config)}\n`, { mode: 0o644 });
    assert.deepEqual(readDeploymentConfig(filePath, { expectedOwnerUid: process.getuid() }), config);
    fs.chmodSync(filePath, 0o666);
    assert.throws(() => readDeploymentConfig(filePath, { expectedOwnerUid: process.getuid() }));
    fs.chmodSync(filePath, 0o644);
    fs.appendFileSync(filePath, '\n');
    assert.throws(() => readDeploymentConfig(filePath, { expectedOwnerUid: process.getuid() }));
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

function preflightFixture(overrides = {}) {
  const config = validateDeploymentConfig(configuration());
  const events = [];
  const input = {
    argv: ['--release-manifest', `${config.releaseRoot}/manifest.json`, '--kernel-uid', '501', '--kernel-gid', '501'],
    environment: { WALLET_KERNEL_ENV_FILE: config.environmentPath },
  };
  const effects = {
    assertRoot: () => { events.push('root'); },
    readDeployment: () => config,
    readManifest: () => ({ commit: config.commit, systemd: { effectiveConfigHash: HASH } }),
    verifyRelease: (request) => {
      assert.equal(request.mode, 'cdp-testnet');
      assert.equal(request.expectedOwnerUid, 0);
      events.push('release');
      return { releaseManifestHash: HASH };
    },
    renderUnits: (request) => {
      assert.equal(request.environmentPath, config.environmentPath);
      assert.equal(request.install, undefined);
      return { expectedEffectiveConfig: { releaseRoot: config.releaseRoot } };
    },
    inspectSystemd: async () => { events.push('pid1'); return { effectiveConfigHash: HASH }; },
    captureAuthorityMetadata: () => { events.push('authority'); return HASH; },
    captureMetadata: () => { events.push('metadata'); return { authorityMetadataHash: HASH, credentialMetadataHash: HASH }; },
    probeAgent: async (request) => {
      events.push('probe');
      assert.equal(request.agentUid, '502');
      assert.equal(request.protectedReadPaths.kernelEnvironment, config.environmentPath);
      assert.equal(request.protectedReadPaths.database, config.databasePath);
      assert.equal(path.dirname(request.writePaths.dependencyTreeWrite), `${config.releaseRoot}/node_modules`);
      return REQUIRED_ISOLATION_PROBE_RESULTS;
    },
    auditReader: async (request) => {
      if (request.readerRequest.phase === 'inspect') {
        events.push('inspection');
        assert.equal(request.readerRequest.probeResults, null);
        assert.equal(request.readerRequest.credentialMetadataHash, null);
        return { status: 'enrolled', preflightDigest: HASH };
      }
      events.push('reader');
      assert.deepEqual(request.environment, input.environment);
      assert.deepEqual(request.readerRequest.probeResults, REQUIRED_ISOLATION_PROBE_RESULTS);
      assert.equal(request.readerRequest.authorityMetadataHash, HASH);
      assert.equal(request.readerRequest.credentialMetadataHash, HASH);
      assert.equal(request.readerRequest.databasePath, config.databasePath);
      assert.equal(request.readerRequest.pathTrust.kernelUid, 501);
      return { status: 'verified', preflightDigest: HASH };
    },
    now: () => '2026-09-05T12:00:00.000Z',
    ...overrides,
  };
  return { input, effects, events };
}

test('installed preflight binds verified release and actual probes to the dropped reader', async () => {
  const f = preflightFixture();
  const result = await runInstalledLivePreflight(f.input, f.effects);
  assert.equal(result.status, 'verified');
  assert.deepEqual(f.events, ['root', 'release', 'pid1', 'authority', 'inspection', 'metadata', 'probe', 'metadata', 'reader']);
});

test('preflight refuses secret inheritance, release drift, and PID1 drift before private probes', async () => {
  const inherited = preflightFixture();
  inherited.input.environment.CDP_API_KEY_SECRET = 'sentinel';
  await assert.rejects(runInstalledLivePreflight(inherited.input, inherited.effects), /environment/);
  assert.deepEqual(inherited.events, ['root']);
  const drift = preflightFixture({ inspectSystemd: async () => ({ effectiveConfigHash: `sha256:${'b'.repeat(64)}` }) });
  await assert.rejects(runInstalledLivePreflight(drift.input, drift.effects), /PID1/);
  assert.deepEqual(drift.events, ['root', 'release']);
  const release = preflightFixture({ verifyRelease: () => { throw new Error('release drift'); } });
  await assert.rejects(runInstalledLivePreflight(release.input, release.effects), /release drift/);
  assert.deepEqual(release.events, ['root']);
});

test('failed isolation and invalid reader outcomes never authorize service startup', async () => {
  const probe = preflightFixture({ probeAgent: async () => { throw new Error('isolation refused'); } });
  await assert.rejects(runInstalledLivePreflight(probe.input, probe.effects), /isolation refused/);
  assert.equal(probe.events.includes('reader'), false);
  const reader = preflightFixture({ auditReader: async () => ({ status: 'unknown', preflightDigest: HASH }) });
  await assert.rejects(runInstalledLivePreflight(reader.input, reader.effects), /invalid inspection/);
});

test('recovery-only startup does not require a retained Agent credential or fabricated probes', async () => {
  const f = preflightFixture({
    auditReader: async (request) => {
      assert.equal(request.readerRequest.phase, 'inspect');
      assert.equal(request.readerRequest.probeResults, null);
      return { status: 'recovery_only', preflightDigest: HASH };
    },
    captureMetadata: () => { throw new Error('must not inspect Agent credentials'); },
    probeAgent: () => { throw new Error('must not fabricate isolation probes'); },
  });
  assert.equal((await runInstalledLivePreflight(f.input, f.effects)).status, 'recovery_only');
});

test('a credential metadata change during probing requires a fresh attestation', async () => {
  let captures = 0;
  const f = preflightFixture({ captureMetadata: () => ({ authorityMetadataHash: HASH,
    credentialMetadataHash: ++captures === 1 ? HASH : `sha256:${'b'.repeat(64)}` }) });
  await assert.rejects(runInstalledLivePreflight(f.input, f.effects), /metadata changed/);
  assert.equal(f.events.includes('reader'), false);
});

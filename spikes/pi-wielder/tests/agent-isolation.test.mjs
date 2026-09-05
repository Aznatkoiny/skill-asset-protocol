import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import {
  REQUIRED_ISOLATION_PROBE_RESULTS,
  createIsolationAttestationRepository,
  hashIsolationMetadata,
  validateIsolationMetadata,
  validateIsolationReportBytes,
} from '../src/agent/isolation-preflight.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  buildIsolationReport,
  runPrivilegedAgentIsolationPreflight,
} from '../scripts/preflight-agent-isolation.mjs';
import { dropToAgentIdentity } from '../scripts/agent-isolation-probe-worker.mjs';
import {
  assertReaderEnvironment,
  dropToKernelIdentity,
  parseReaderArguments,
  runDroppedReader,
  validateReaderRequest,
} from '../scripts/prelaunch-kernel-reader.mjs';
import {
  assertRootPreflightEnvironment,
  parsePreflightArguments,
} from '../scripts/preflight-live-deployment.mjs';

const H = (character) => `sha256:${character.repeat(64)}`;
const ENROLLMENT_HASH = H('1');
const OPERATOR_HASH = H('2');

function report(overrides = {}) {
  return {
    schemaVersion: 1,
    enrollmentHash: ENROLLMENT_HASH,
    kernelUid: '501', kernelGid: '20', agentUid: '502', agentGid: '20',
    authorityMetadataHash: H('3'), credentialMetadataHash: H('4'),
    releaseManifestHash: H('5'), releaseTreeHash: H('6'), nodeExecutableHash: H('7'),
    serviceArtifactsHash: H('8'), systemdEffectiveConfigHash: H('9'),
    environmentMetadataHash: H('a'),
    probeResults: {
      authorityDirectory: 'EACCES', database: 'EACCES', operatorToken: 'EACCES',
      receiptKey: 'EACCES', kernelEnvironment: 'EACCES', agentCredential: 'READABLE',
      releaseTreeWrite: 'EACCES', dependencyTreeWrite: 'EACCES',
      serviceArtifactsWrite: 'EACCES', kernelEnvironmentParentWrite: 'EACCES',
    },
    probedAt: '2026-07-31T12:00:00.000Z',
    expiresAt: '2026-07-31T12:15:00.000Z',
    ...overrides,
  };
}

test('pure isolation metadata requires distinct non-root identities and private directions', () => {
  const authority = {
    role: 'authority', chain: [{ role: 'authority', depth: 0, device: '1', inode: '2', uid: 501, gid: 20, mode: 0o700 }],
    leaf: { role: 'authority-leaf', depth: 1, device: '1', inode: '3', uid: 501, gid: 20, mode: 0o600 },
  };
  const credential = {
    role: 'credential', chain: [{ role: 'credential', depth: 0, device: '2', inode: '4', uid: 502, gid: 20, mode: 0o700 }],
    leaf: { role: 'credential-leaf', depth: 1, device: '2', inode: '5', uid: 502, gid: 20, mode: 0o600 },
  };
  const result = validateIsolationMetadata({
    kernelUid: 501, kernelGid: 20, agentUid: 502, agentGid: 20,
    authority, credential, authorityInsideCredential: false, credentialInsideAuthority: false,
  });
  assert.equal(result.authorityMetadataHash, hashIsolationMetadata(authority));
  assert.equal(result.credentialMetadataHash, hashIsolationMetadata(credential));
  for (const bad of [
    { kernelUid: 0 }, { agentUid: 0 }, { agentUid: 501 },
    { authorityInsideCredential: true }, { credentialInsideAuthority: true },
  ]) assert.throws(() => validateIsolationMetadata({
    kernelUid: 501, kernelGid: 20, agentUid: 502, agentGid: 20,
    authority, credential, authorityInsideCredential: false, credentialInsideAuthority: false,
    ...bad,
  }));
  assert.throws(() => validateIsolationMetadata({
    kernelUid: 501, kernelGid: 20, agentUid: 502, agentGid: 20,
    authority: { ...authority, leaf: { ...authority.leaf, mode: 0o640 } },
    credential, authorityInsideCredential: false, credentialInsideAuthority: false,
  }), /mode/);
});

test('report parser enforces canonical bytes, exact result codes, identity, hash, and half-open expiry', () => {
  const bytes = Buffer.from(`${canonicalJson(report())}\n`);
  const expectedReportHash = sha256(canonicalJson(report()));
  const valid = validateIsolationReportBytes(bytes, {
    expectedReportHash, expectedEnrollmentHash: ENROLLMENT_HASH,
    expectedKernelUid: '501', expectedKernelGid: '20',
    expectedReleaseManifestHash: H('5'), now: () => '2026-07-31T12:14:59.999Z',
  });
  assert.equal(valid.reportHash, expectedReportHash);
  assert.throws(() => validateIsolationReportBytes(Buffer.from(JSON.stringify(report())), {
    expectedReportHash, expectedEnrollmentHash: ENROLLMENT_HASH,
    expectedKernelUid: '501', expectedKernelGid: '20',
    expectedReleaseManifestHash: H('5'), now: () => '2026-07-31T12:10:00.000Z',
  }), /canonical/);
  for (const broken of [
    report({ kernelUid: '0' }), report({ agentUid: '501' }), report({ expiresAt: '2026-07-31T12:15:00.001Z' }),
    report({ probeResults: { ...report().probeResults, database: 'ENOENT' } }),
  ]) assert.throws(() => validateIsolationReportBytes(Buffer.from(`${canonicalJson(broken)}\n`), {
    expectedReportHash: sha256(canonicalJson(broken)), expectedEnrollmentHash: ENROLLMENT_HASH,
    expectedKernelUid: broken.kernelUid, expectedKernelGid: broken.kernelGid,
    expectedReleaseManifestHash: H('5'), now: () => '2026-07-31T12:10:00.000Z',
  }));
  assert.throws(() => validateIsolationReportBytes(bytes, {
    expectedReportHash, expectedEnrollmentHash: ENROLLMENT_HASH,
    expectedKernelUid: '501', expectedKernelGid: '20',
    expectedReleaseManifestHash: H('5'), now: () => '2026-07-31T12:15:00.000Z',
  }), /expired/);
});

test('privileged report builder binds deployment hashes and emits only the public report hash', () => {
  const value = report();
  const built = buildIsolationReport({
    config: {
      schemaVersion: 1,
      enrollmentHash: value.enrollmentHash,
      kernelUid: value.kernelUid, kernelGid: value.kernelGid,
      agentUid: value.agentUid, agentGid: value.agentGid,
      authorityMetadataHash: value.authorityMetadataHash,
      credentialMetadataHash: value.credentialMetadataHash,
      releaseManifestHash: value.releaseManifestHash,
      releaseTreeHash: value.releaseTreeHash,
      nodeExecutableHash: value.nodeExecutableHash,
      serviceArtifactsHash: value.serviceArtifactsHash,
      systemdEffectiveConfigHash: value.systemdEffectiveConfigHash,
      environmentMetadataHash: value.environmentMetadataHash,
      credentialPath: '/private/agent/credential',
      protectedReadPaths: {}, writePaths: {}, reportPath: '/private/kernel/report',
    },
    probeResults: value.probeResults,
    now: () => value.probedAt,
  });
  assert.equal(built.reportHash, sha256(canonicalJson(value)));
  assert.equal(built.reportBytes.equals(Buffer.from(`${canonicalJson(value)}\n`)), true);
});

test('identity-drop helpers clear groups before gid/uid and verify the final identity', () => {
  for (const drop of [dropToAgentIdentity, dropToKernelIdentity]) {
    const calls = [];
    const fake = {
      setgroups: (groups) => calls.push(['groups', groups]),
      setgid: (gid) => calls.push(['gid', gid]),
      setuid: (uid) => calls.push(['uid', uid]),
      getuid: () => 501, geteuid: () => 501,
      getgid: () => 20, getegid: () => 20, getgroups: () => [20],
    };
    drop({ uid: 501, gid: 20, processApi: fake });
    assert.deepEqual(calls, [['groups', []], ['gid', 20], ['uid', 501]]);
  }
});

test('prelaunch helper executes the dynamic audit only after the exact identity drop', async () => {
  const calls = [];
  const fake = {
    setgroups: (groups) => calls.push(['groups', groups]),
    setgid: (gid) => calls.push(['gid', gid]),
    setuid: (uid) => calls.push(['uid', uid]),
    getuid: () => 501, geteuid: () => 501,
    getgid: () => 20, getegid: () => 20, getgroups: () => [20],
  };
  const result = await runDroppedReader({
    argv: ['--kernel-uid', '501', '--kernel-gid', '20'],
    environment: { NODE_CHANNEL_FD: '3' },
    processApi: fake,
    dynamicAudit: async () => {
      calls.push(['audit']);
      return Object.freeze({ status: 'ready' });
    },
  });
  assert.deepEqual(calls, [
    ['groups', []], ['gid', 20], ['uid', 501], ['audit'],
  ]);
  assert.deepEqual(result, { status: 'ready' });
});

test('prelaunch protocols reject argument, environment, identity, nonce, and secret-shaped IPC drift', () => {
  assert.deepEqual(parseReaderArguments(['--kernel-uid', '501', '--kernel-gid', '20']), {
    kernelUid: 501, kernelGid: 20,
  });
  assertReaderEnvironment({ NODE_CHANNEL_FD: '3' });
  assert.throws(() => assertReaderEnvironment({ NODE_OPTIONS: '--import=x' }), /environment/);
  assert.deepEqual(parsePreflightArguments([
    '--release-manifest', '/opt/wallet/releases/a/manifest.json',
    '--kernel-uid', '501', '--kernel-gid', '20',
  ]), {
    manifestPath: '/opt/wallet/releases/a/manifest.json', kernelUid: '501', kernelGid: '20',
  });
  const request = {
    nonce: 'n', parentPid: 7, kernelUid: '501', kernelGid: '20',
    releaseRoot: '/opt/wallet/releases/a', releaseManifestHash: H('5'),
    authorityMetadataHash: H('3'), credentialMetadataHash: H('4'),
    probeResults: { ...REQUIRED_ISOLATION_PROBE_RESULTS },
    databasePath: '/private/kernel/kernel.sqlite',
    pathTrust: { mode: 'cdp-testnet', trustedAncestor: '/private', kernelUid: 501, agentUid: 502 },
    isolationReportPath: '/private/kernel/report.json', now: '2026-07-31T12:00:00.000Z',
  };
  assert.equal(validateReaderRequest(request, { nonce: 'n', parentPid: 7, uid: 501, gid: 20 }), request);
  assert.throws(() => validateReaderRequest({
    ...request, probeResults: { receiptKeyPath: '/private/key' },
  }, { nonce: 'n', parentPid: 7, uid: 501, gid: 20 }), /probe results/);
  assert.throws(() => validateReaderRequest({ ...request, nonce: 'wrong' }, {
    nonce: 'n', parentPid: 7, uid: 501, gid: 20,
  }), /binding/);
});

test('root live preflight receives only a safe environment-file pointer, never wallet secrets', () => {
  const environmentPath = '/etc/wallet-kernel/kernel.env';
  assert.deepEqual(assertRootPreflightEnvironment({
    PATH: '/usr/bin:/bin',
    LANG: 'C.UTF-8',
    WALLET_KERNEL_ENV_FILE: environmentPath,
  }), {
    PATH: '/usr/bin:/bin',
    LANG: 'C.UTF-8',
    WALLET_KERNEL_ENV_FILE: environmentPath,
  });

  for (const environment of [
    { WALLET_KERNEL_ENV_FILE: environmentPath, CDP_API_KEY_SECRET: 'sentinel' },
    { WALLET_KERNEL_ENV_FILE: environmentPath, CDP_WALLET_SECRET: 'sentinel' },
    { WALLET_KERNEL_ENV_FILE: environmentPath,
      WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: 'https://rpc.example/?key=sentinel' },
    { WALLET_KERNEL_ENV_FILE: environmentPath,
      WALLET_KERNEL_OPERATOR_TOKEN_FILE: '/private/token' },
    { WALLET_KERNEL_ENV_FILE: environmentPath, NODE_OPTIONS: '--import=/tmp/hook.mjs' },
  ]) assert.throws(() => assertRootPreflightEnvironment(environment), /environment/);

  assert.throws(() => assertRootPreflightEnvironment({ PATH: '/usr/bin:/bin' }),
    /environment file pointer/);
  assert.throws(() => assertRootPreflightEnvironment({
    WALLET_KERNEL_ENV_FILE: 'relative/kernel.env',
  }), /environment file pointer/);
});

function repositoryFixture() {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  store.execForTest(`INSERT INTO agent_enrollments
    (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
     state, enrolled_by_operator_hash, enrolled_at, revoked_by_operator_hash, revoked_at)
    VALUES ('AAAAAAAAAAAAAAAAAAAAAA', '${H('b')}', '${ENROLLMENT_HASH}', '502', '20',
      'active', '${OPERATOR_HASH}', '2026-07-31T11:00:00.000Z', NULL, NULL)`);
  return store;
}

test('repository atomically imports, replays, supersedes, and resolves only the exact current binding', () => {
  const store = repositoryFixture();
  let id = 0;
  let now = '2026-07-31T12:05:00.000Z';
  const repository = createIsolationAttestationRepository({
    store, now: () => now, idFactory: () => `isolation-${++id}`,
  });
  const firstReport = report();
  const firstBytes = Buffer.from(`${canonicalJson(firstReport)}\n`);
  const firstHash = sha256(canonicalJson(firstReport));
  const first = repository.importCurrent({
    reportBytes: firstBytes, expectedReportHash: firstHash, operatorIdHash: OPERATOR_HASH,
  });
  assert.equal(first.reportHash, firstHash);
  assert.deepEqual(repository.importCurrent({
    reportBytes: firstBytes, expectedReportHash: firstHash, operatorIdHash: OPERATOR_HASH,
  }), first);
  assert.equal(repository.currentFor({
    enrollmentHash: ENROLLMENT_HASH, authorityMetadataHash: H('3'),
    releaseManifestHash: H('5'), expectedReportHash: firstHash,
  }).reportHash, firstHash);
  const secondReport = report({
    authorityMetadataHash: H('c'), probedAt: '2026-07-31T12:06:00.000Z',
    expiresAt: '2026-07-31T12:14:00.000Z',
  });
  now = '2026-07-31T12:07:00.000Z';
  const secondHash = sha256(canonicalJson(secondReport));
  const second = repository.importCurrent({
    reportBytes: Buffer.from(`${canonicalJson(secondReport)}\n`),
    expectedReportHash: secondHash, operatorIdHash: OPERATOR_HASH,
  });
  assert.equal(second.reportHash, secondHash);
  assert.equal(store.readOne('SELECT state FROM isolation_attestations WHERE report_hash = ?', [firstHash]).state, 'superseded');
  assert.equal(repository.currentFor({
    enrollmentHash: ENROLLMENT_HASH, authorityMetadataHash: H('3'),
    releaseManifestHash: H('5'), expectedReportHash: firstHash,
  }), null);
  now = '2026-07-31T12:14:00.000Z';
  assert.equal(repository.currentFor({
    enrollmentHash: ENROLLMENT_HASH, authorityMetadataHash: H('c'),
    releaseManifestHash: H('5'), expectedReportHash: secondHash,
  }), null);
  store.close();
});

test('repository rejects inactive/mismatched enrollment and rolls back supersession on insert failure', () => {
  const store = repositoryFixture();
  const repository = createIsolationAttestationRepository({
    store, now: () => '2026-07-31T12:05:00.000Z', idFactory: () => 'duplicate-id',
  });
  const bytes = Buffer.from(`${canonicalJson(report())}\n`);
  const hash = sha256(canonicalJson(report()));
  repository.importCurrent({ reportBytes: bytes, expectedReportHash: hash, operatorIdHash: OPERATOR_HASH });
  const other = report({ authorityMetadataHash: H('d'), probedAt: '2026-07-31T12:06:00.000Z' });
  assert.throws(() => repository.importCurrent({
    reportBytes: Buffer.from(`${canonicalJson(other)}\n`),
    expectedReportHash: sha256(canonicalJson(other)), operatorIdHash: OPERATOR_HASH,
  }));
  assert.equal(store.readOne('SELECT state FROM isolation_attestations WHERE report_hash = ?', [hash]).state, 'current');
  store.execForTest(`UPDATE agent_enrollments SET state='revoked',
    revoked_by_operator_hash='${OPERATOR_HASH}', revoked_at='2026-07-31T12:07:00.000Z'`);
  assert.throws(() => repository.importCurrent({
    reportBytes: bytes, expectedReportHash: hash, operatorIdHash: OPERATOR_HASH,
  }), /active enrollment/);
  store.close();
});

test('real dropped-UID isolation probe is explicit and skipped without safe fixture identities', async (t) => {
  if (process.platform === 'win32' || process.getuid?.() !== 0
      || !process.env.WALLET_KERNEL_TEST_AGENT_UID || !process.env.WALLET_KERNEL_TEST_AGENT_GID) {
    t.skip('requires root and explicit disposable WALLET_KERNEL_TEST_AGENT_UID/GID');
    return;
  }
  const agentUid = Number(process.env.WALLET_KERNEL_TEST_AGENT_UID);
  const agentGid = Number(process.env.WALLET_KERNEL_TEST_AGENT_GID);
  const kernelUid = Number(process.env.WALLET_KERNEL_TEST_KERNEL_UID);
  const kernelGid = Number(process.env.WALLET_KERNEL_TEST_KERNEL_GID);
  assert.equal([agentUid, agentGid, kernelUid, kernelGid].every((id) => Number.isSafeInteger(id) && id > 0), true);
  assert.notEqual(agentUid, kernelUid);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-real-isolation-'));
  try {
    fs.chmodSync(root, 0o755);
    const authority = path.join(root, 'authority');
    const agentPrivate = path.join(root, 'agent-private');
    const reportParent = path.join(root, 'reports');
    const writeParents = {};
    fs.mkdirSync(authority, { mode: 0o700 });
    fs.chownSync(authority, kernelUid, kernelGid);
    fs.mkdirSync(agentPrivate, { mode: 0o700 });
    fs.chownSync(agentPrivate, agentUid, agentGid);
    fs.mkdirSync(reportParent, { mode: 0o700 });
    fs.chownSync(reportParent, kernelUid, kernelGid);
    const protectedReadPaths = { authorityDirectory: authority };
    for (const name of ['database', 'operatorToken', 'receiptKey', 'kernelEnvironment']) {
      const target = path.join(authority, name);
      fs.writeFileSync(target, name, { mode: 0o600 });
      fs.chownSync(target, kernelUid, kernelGid);
      protectedReadPaths[name] = target;
    }
    const credentialPath = path.join(agentPrivate, 'credential');
    fs.writeFileSync(credentialPath, 'fixture-credential', { mode: 0o600 });
    fs.chownSync(credentialPath, agentUid, agentGid);
    for (const name of [
      'releaseTreeWrite', 'dependencyTreeWrite', 'serviceArtifactsWrite',
      'kernelEnvironmentParentWrite',
    ]) {
      const parent = path.join(root, name);
      fs.mkdirSync(parent, { mode: 0o555 });
      writeParents[name] = path.join(parent, 'must-not-exist');
    }
    const config = {
      schemaVersion: 1, enrollmentHash: ENROLLMENT_HASH,
      kernelUid: String(kernelUid), kernelGid: String(kernelGid),
      agentUid: String(agentUid), agentGid: String(agentGid),
      authorityMetadataHash: H('3'), credentialMetadataHash: H('4'),
      releaseManifestHash: H('5'), releaseTreeHash: H('6'), nodeExecutableHash: H('7'),
      serviceArtifactsHash: H('8'), systemdEffectiveConfigHash: H('9'),
      environmentMetadataHash: H('a'), credentialPath, protectedReadPaths,
      writePaths: writeParents, reportPath: path.join(reportParent, 'isolation-report.json'),
    };
    const result = await runPrivilegedAgentIsolationPreflight({
      config, now: () => '2026-07-31T12:00:00.000Z',
    });
    assert.equal(result.reportHash.startsWith('sha256:'), true);
    const stat = fs.lstatSync(config.reportPath);
    assert.equal(stat.uid, kernelUid);
    assert.equal(stat.gid, kernelGid);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(Object.values(writeParents).every((target) => !fs.existsSync(target)), true);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

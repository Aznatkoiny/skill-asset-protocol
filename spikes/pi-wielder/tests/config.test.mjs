import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  CONTROL_PLANE_MODES,
  loadControlPlaneConfig,
  readBoundedRouteDocument,
  validateRouteMap,
} from '../src/config.mjs';
import { KernelError } from '../src/kernel/canonical.mjs';

const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
const CURRENT_UID = typeof process.getuid === 'function' ? process.getuid() : 501;
const CURRENT_GID = typeof process.getgid === 'function' ? process.getgid() : 20;

function writeFixtureFile(filePath, contents = 'fixture\n', mode = 0o600) {
  fs.writeFileSync(filePath, contents, { mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

function makeFixture(t) {
  const lexicalRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-config-'));
  const root = fs.realpathSync(lexicalRoot);
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));

  const authority = path.join(root, 'authority');
  const release = path.join(root, 'release');
  const socketParent = path.join(root, 'operator');
  const enrollmentInbox = path.join(root, 'enrollment-inbox');
  const agentRunOutbox = path.join(root, 'agent-run-outbox');
  const evidenceRoot = path.join(root, 'evidence');
  for (const directory of [authority, release, socketParent, evidenceRoot]) {
    fs.mkdirSync(directory, { mode: 0o700 });
    fs.chmodSync(directory, 0o700);
  }
  for (const directory of [enrollmentInbox, agentRunOutbox]) {
    fs.mkdirSync(directory, { mode: 0o755 });
    fs.chmodSync(directory, 0o755);
  }

  const paths = {
    database: writeFixtureFile(path.join(authority, 'kernel.sqlite')),
    receiptKey: writeFixtureFile(path.join(authority, 'receipt.key')),
    operatorToken: writeFixtureFile(path.join(authority, 'operator.token')),
    policy: writeFixtureFile(path.join(release, 'policy.json'), '{}\n', 0o600),
    route: writeFixtureFile(path.join(release, 'routes.json'), '{}\n', 0o600),
    operatorSocket: path.join(socketParent, 'admin.sock'),
    enrollmentInbox,
    agentRunOutbox,
    releaseRoot: release,
    releaseManifest: writeFixtureFile(path.join(release, 'manifest.json'), '{}\n', 0o600),
    serviceDefinition: writeFixtureFile(path.join(release, 'wallet-kernel.service'), 'fixture\n', 0o600),
    socketDefinition: writeFixtureFile(path.join(release, 'wallet-kernel-console.socket'), 'fixture\n', 0o600),
    environmentFile: writeFixtureFile(path.join(release, 'wallet-kernel.env'), 'fixture\n', 0o600),
    evidenceRoot,
    isolationReport: writeFixtureFile(path.join(evidenceRoot, 'isolation.json'), '{}\n', 0o600),
  };

  const env = {
    WALLET_KERNEL_MODE: 'deterministic',
    WALLET_KERNEL_DB_FILE: paths.database,
    WALLET_KERNEL_RECEIPT_KEY_FILE: paths.receiptKey,
    WALLET_KERNEL_OPERATOR_TOKEN_FILE: paths.operatorToken,
    WALLET_KERNEL_TRUSTED_ANCESTOR: root,
    WALLET_KERNEL_EXPECTED_AGENT_UID: '1001',
    WALLET_KERNEL_EXPECTED_AGENT_GID: '1002',
    WALLET_KERNEL_POLICY_FILE: paths.policy,
    WALLET_KERNEL_ROUTE_FILE: paths.route,
    WALLET_KERNEL_PORT: '8402',
    WALLET_KERNEL_OPERATOR_PORT: '8405',
    WALLET_KERNEL_OPERATOR_SOCKET_FILE: paths.operatorSocket,
    WALLET_KERNEL_ENROLLMENT_INBOX: paths.enrollmentInbox,
    WALLET_KERNEL_AGENT_RUN_OUTBOX: paths.agentRunOutbox,
    WALLET_KERNEL_RELEASE_ROOT: paths.releaseRoot,
    WALLET_KERNEL_RELEASE_MANIFEST: paths.releaseManifest,
    WALLET_KERNEL_SERVICE_DEFINITION_FILE: paths.serviceDefinition,
    WALLET_KERNEL_SOCKET_DEFINITION_FILE: paths.socketDefinition,
    WALLET_KERNEL_ENV_FILE: paths.environmentFile,
    WALLET_KERNEL_EVIDENCE_ROOT: paths.evidenceRoot,
    WALLET_KERNEL_ISOLATION_REPORT_FILE: paths.isolationReport,
  };
  return { root, paths, env };
}

function safeRootOwnedFiles() {
  const candidates = [
    '/private/etc/hosts',
    '/private/etc/services',
    '/private/etc/protocols',
    '/private/etc/shells',
    '/private/etc/paths',
    '/private/etc/passwd',
    '/private/etc/group',
    '/etc/hosts',
    '/etc/services',
    '/etc/protocols',
    '/etc/shells',
    '/etc/paths',
    '/etc/passwd',
    '/etc/group',
  ];
  const files = [];
  for (const candidate of candidates) {
    try {
      const resolved = fs.realpathSync(candidate);
      const stat = fs.lstatSync(resolved);
      if (!stat.isFile() || stat.uid !== 0 || (stat.mode & 0o022) !== 0) continue;
      const descriptor = fs.openSync(resolved, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
      fs.closeSync(descriptor);
      if (!files.includes(resolved)) files.push(resolved);
    } catch {}
  }
  return files;
}

function everyAncestorIsLiveSafe(targetPath, allowedUids) {
  let current = path.parse(targetPath).root;
  for (const part of targetPath.slice(current.length).split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || (stat.mode & 0o022) !== 0 || !allowedUids.has(stat.uid)) {
      return false;
    }
  }
  return true;
}

function makeLiveFixture(t) {
  if (CURRENT_UID === 0 || CURRENT_GID === 0) return null;
  const fixture = makeFixture(t);
  const rootFiles = safeRootOwnedFiles();
  if (rootFiles.length < 6
      || !everyAncestorIsLiveSafe(fixture.root, new Set([0, CURRENT_UID]))) {
    return null;
  }
  const expectedAgentUid = CURRENT_UID === 65_534 ? CURRENT_UID - 1 : CURRENT_UID + 1;
  const expectedAgentGid = CURRENT_GID === 65_534 ? CURRENT_GID - 1 : CURRENT_GID + 1;
  const releaseRoot = path.dirname(rootFiles[0]);
  if (!rootFiles.slice(0, 4).every((file) => path.dirname(file) === releaseRoot)) return null;
  return {
    ...fixture,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    env: {
      ...fixture.env,
      WALLET_KERNEL_MODE: 'cdp-testnet',
      WALLET_KERNEL_TRUSTED_ANCESTOR: path.parse(fixture.root).root,
      WALLET_KERNEL_EXPECTED_AGENT_UID: String(expectedAgentUid),
      WALLET_KERNEL_EXPECTED_AGENT_GID: String(expectedAgentGid),
      WALLET_KERNEL_RELEASE_ROOT: releaseRoot,
      WALLET_KERNEL_RELEASE_MANIFEST: rootFiles[0],
      WALLET_KERNEL_SERVICE_DEFINITION_FILE: rootFiles[1],
      WALLET_KERNEL_SOCKET_DEFINITION_FILE: rootFiles[2],
      WALLET_KERNEL_ENV_FILE: rootFiles[3],
      WALLET_KERNEL_POLICY_FILE: rootFiles[4],
      WALLET_KERNEL_ROUTE_FILE: rootFiles[5],
      CDP_API_KEY_ID: 'key-id-sentinel',
      CDP_API_KEY_SECRET: 'api-secret-sentinel',
      CDP_WALLET_SECRET: 'wallet-secret-sentinel',
      CDP_WALLET_NAME: 'pilot-wallet',
      WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: 'https://rpc.example/v1/provider-secret?key=query-secret',
    },
  };
}

test('route documents are read once through a bounded regular-file descriptor', (t) => {
  const fixture = makeFixture(t);
  const document = routeDocument();
  fs.writeFileSync(fixture.paths.route, JSON.stringify(document));
  assert.deepEqual(readBoundedRouteDocument(fixture.paths.route), document);

  const empty = writeFixtureFile(path.join(fixture.root, 'empty-routes.json'), '');
  assertKernelError(() => readBoundedRouteDocument(empty), 'ROUTE_FILE');

  const oversized = writeFixtureFile(
    path.join(fixture.root, 'oversized-routes.json'),
    `{"padding":"${'x'.repeat(65_536)}"}`,
  );
  assertKernelError(() => readBoundedRouteDocument(oversized), 'ROUTE_FILE');

  const hardlink = path.join(fixture.root, 'hardlinked-routes.json');
  fs.linkSync(fixture.paths.route, hardlink);
  assertKernelError(() => readBoundedRouteDocument(hardlink), 'ROUTE_FILE');

  const symlink = path.join(fixture.root, 'symlinked-routes.json');
  fs.symlinkSync(fixture.paths.route, symlink);
  assertKernelError(() => readBoundedRouteDocument(symlink), 'ROUTE_FILE');
});

function assertKernelError(action, code) {
  assert.throws(action, (error) => (
    error instanceof KernelError && (code === undefined || error.code === code)
  ));
}

test('control-plane modes are closed and frozen', () => {
  assert.deepEqual(CONTROL_PLANE_MODES, ['deterministic', 'cdp-testnet']);
  assert.equal(Object.isFrozen(CONTROL_PLANE_MODES), true);
});

test('deterministic configuration is exact, frozen, and ignores all CDP secrets', (t) => {
  const fixture = makeFixture(t);
  const secretValues = {
    CDP_API_KEY_ID: 'ignored-key-id',
    CDP_API_KEY_SECRET: 'ignored-api-secret',
    CDP_WALLET_SECRET: 'ignored-wallet-secret',
    CDP_WALLET_NAME: 'ignored-wallet-name',
    WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: 'not even a URL secret',
  };
  const config = loadControlPlaneConfig({
    env: { ...fixture.env, ...secretValues },
    checkoutRoot: CHECKOUT_ROOT,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    platform: 'darwin',
  });

  assert.deepEqual(config.publicConfig, {
    mode: 'deterministic',
    agentHost: '127.0.0.1',
    agentPort: 8402,
    operatorAdminTransport: 'loopback-demo',
    operatorSocketPath: null,
    operatorConsoleTransport: 'loopback-demo',
    operatorConsoleActivationName: null,
    operatorHost: '127.0.0.1',
    operatorPort: 8405,
    databasePath: fixture.env.WALLET_KERNEL_DB_FILE,
    policyPath: fixture.env.WALLET_KERNEL_POLICY_FILE,
    routePath: fixture.env.WALLET_KERNEL_ROUTE_FILE,
    receiptKeyPath: fixture.env.WALLET_KERNEL_RECEIPT_KEY_FILE,
    operatorTokenPath: fixture.env.WALLET_KERNEL_OPERATOR_TOKEN_FILE,
    enrollmentInboxPath: fixture.env.WALLET_KERNEL_ENROLLMENT_INBOX,
    agentRunOutboxPath: fixture.env.WALLET_KERNEL_AGENT_RUN_OUTBOX,
    trustedAncestor: null,
    releaseRoot: null,
    releaseManifestPath: null,
    serviceDefinitionPath: null,
    socketDefinitionPath: null,
    environmentFilePath: null,
    evidenceRoot: null,
    isolationReportPath: null,
    expectedAgentUid: 1001,
    expectedAgentGid: 1002,
    cdpWalletName: null,
    network: 'eip155:84532',
    observer: 'deterministic',
  });
  assert.equal(Object.isFrozen(config), true);
  assert.equal(Object.isFrozen(config.publicConfig), true);
  assert.equal(config.assertCredentialPresence(), undefined);
  const serialized = JSON.stringify(config);
  for (const value of Object.values(secretValues)) assert.equal(serialized.includes(value), false);
});

test('cdp-testnet exposes only the exact live public projection', (t) => {
  const fixture = makeLiveFixture(t);
  if (!fixture) {
    t.skip('requires non-root POSIX fixtures below a root-owned non-writable ancestor');
    return;
  }
  const config = loadControlPlaneConfig({
    env: fixture.env,
    checkoutRoot: CHECKOUT_ROOT,
    uid: fixture.uid,
    gid: fixture.gid,
    platform: 'linux',
  });
  assert.deepEqual(config.publicConfig, {
    mode: 'cdp-testnet',
    agentHost: '127.0.0.1',
    agentPort: 8402,
    operatorAdminTransport: 'unix',
    operatorSocketPath: fixture.env.WALLET_KERNEL_OPERATOR_SOCKET_FILE,
    operatorConsoleTransport: 'socket-activated-loopback',
    operatorConsoleActivationName: 'wallet-kernel-console',
    operatorHost: '127.0.0.1',
    operatorPort: 8405,
    databasePath: fixture.env.WALLET_KERNEL_DB_FILE,
    policyPath: fixture.env.WALLET_KERNEL_POLICY_FILE,
    routePath: fixture.env.WALLET_KERNEL_ROUTE_FILE,
    receiptKeyPath: fixture.env.WALLET_KERNEL_RECEIPT_KEY_FILE,
    operatorTokenPath: fixture.env.WALLET_KERNEL_OPERATOR_TOKEN_FILE,
    enrollmentInboxPath: fixture.env.WALLET_KERNEL_ENROLLMENT_INBOX,
    agentRunOutboxPath: fixture.env.WALLET_KERNEL_AGENT_RUN_OUTBOX,
    trustedAncestor: fixture.env.WALLET_KERNEL_TRUSTED_ANCESTOR,
    releaseRoot: fixture.env.WALLET_KERNEL_RELEASE_ROOT,
    releaseManifestPath: fixture.env.WALLET_KERNEL_RELEASE_MANIFEST,
    serviceDefinitionPath: fixture.env.WALLET_KERNEL_SERVICE_DEFINITION_FILE,
    socketDefinitionPath: fixture.env.WALLET_KERNEL_SOCKET_DEFINITION_FILE,
    environmentFilePath: fixture.env.WALLET_KERNEL_ENV_FILE,
    evidenceRoot: fixture.env.WALLET_KERNEL_EVIDENCE_ROOT,
    isolationReportPath: fixture.env.WALLET_KERNEL_ISOLATION_REPORT_FILE,
    expectedAgentUid: Number(fixture.env.WALLET_KERNEL_EXPECTED_AGENT_UID),
    expectedAgentGid: Number(fixture.env.WALLET_KERNEL_EXPECTED_AGENT_GID),
    cdpWalletName: 'pilot-wallet',
    network: 'eip155:84532',
    observer: 'base-sepolia-read-only',
  });
  assert.equal(config.assertCredentialPresence(), undefined);
  const serialized = JSON.stringify(config);
  for (const field of [
    'CDP_API_KEY_ID',
    'CDP_API_KEY_SECRET',
    'CDP_WALLET_SECRET',
    'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
  ]) {
    assert.equal(serialized.includes(fixture.env[field]), false);
  }
});

test('modes, identities, ports, and the Kernel environment namespace fail closed', (t) => {
  const fixture = makeFixture(t);
  const invoke = (overrides = {}, options = {}) => () => loadControlPlaneConfig({
    env: { ...fixture.env, ...overrides },
    checkoutRoot: CHECKOUT_ROOT,
    uid: options.uid ?? CURRENT_UID,
    gid: options.gid ?? CURRENT_GID,
    platform: options.platform ?? 'darwin',
  });

  for (const mode of ['', 'production', 'mainnet', 'eip155:8453', 'CDP-TESTNET']) {
    assertKernelError(invoke({ WALLET_KERNEL_MODE: mode }), 'CONFIG_MODE');
  }
  for (const [field, value] of [
    ['WALLET_KERNEL_EXPECTED_AGENT_UID', ''],
    ['WALLET_KERNEL_EXPECTED_AGENT_UID', '0'],
    ['WALLET_KERNEL_EXPECTED_AGENT_UID', '01'],
    ['WALLET_KERNEL_EXPECTED_AGENT_UID', '+1'],
    ['WALLET_KERNEL_EXPECTED_AGENT_UID', '1.0'],
    ['WALLET_KERNEL_EXPECTED_AGENT_GID', '0'],
    ['WALLET_KERNEL_EXPECTED_AGENT_GID', '9007199254740992'],
    ['WALLET_KERNEL_PORT', '0'],
    ['WALLET_KERNEL_PORT', '08042'],
    ['WALLET_KERNEL_PORT', '65536'],
    ['WALLET_KERNEL_OPERATOR_PORT', '8402'],
    ['WALLET_KERNEL_NETWORK', 'eip155:8453'],
    ['WALLET_KERNEL_ASSET', '0x0000000000000000000000000000000000000000'],
    ['WALLET_KERNEL_AGENT_CREDENTIAL_FILE', '/tmp/forbidden'],
    ['WALLET_KERNEL_UNRECOGNIZED', '1'],
  ]) {
    assertKernelError(invoke({ [field]: value }));
  }
  assertKernelError(() => loadControlPlaneConfig({
    env: fixture.env,
    checkoutRoot: CHECKOUT_ROOT,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    platform: 'unknown-platform',
  }), 'CONFIG_PLATFORM');
  assertKernelError(() => loadControlPlaneConfig({
    env: fixture.env,
    checkoutRoot: CHECKOUT_ROOT,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    platform: 'darwin',
    network: 'eip155:8453',
  }), 'CONFIG_SCHEMA');
  assertKernelError(() => loadControlPlaneConfig(null), 'CONFIG_SCHEMA');
});

test('live identity, Linux, activation, credential, and loader gates precede composition', (t) => {
  const fixture = makeLiveFixture(t);
  if (!fixture) {
    t.skip('requires non-root POSIX fixtures below a root-owned non-writable ancestor');
    return;
  }
  const invoke = (env = fixture.env, options = {}) => () => loadControlPlaneConfig({
    env,
    checkoutRoot: CHECKOUT_ROOT,
    uid: options.uid ?? fixture.uid,
    gid: options.gid ?? fixture.gid,
    platform: options.platform ?? 'linux',
  });

  assertKernelError(invoke(fixture.env, { platform: 'darwin' }), 'CONFIG_PLATFORM');
  assertKernelError(invoke(fixture.env, { platform: 'win32' }), 'CONFIG_PLATFORM');
  assertKernelError(invoke(fixture.env, { uid: 0 }), 'CONFIG_IDENTITY');
  assertKernelError(invoke(fixture.env, { gid: 0 }), 'CONFIG_IDENTITY');
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_EXPECTED_AGENT_UID: String(fixture.uid),
  }), 'CONFIG_IDENTITY');

  for (const field of ['CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET']) {
    const missing = { ...fixture.env };
    delete missing[field];
    assertKernelError(invoke(missing), 'CONFIG_CREDENTIALS');
    assertKernelError(invoke({ ...fixture.env, [field]: '' }), 'CONFIG_CREDENTIALS');
  }
  assertKernelError(invoke({ ...fixture.env, CDP_WALLET_NAME: '' }), 'CONFIG_WALLET');
  assertKernelError(invoke({ ...fixture.env, WALLET_KERNEL_OPERATOR_PORT: '8406' }), 'CONFIG_ACTIVATION');
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_OPERATOR_HOST: '127.0.0.1',
  }), 'CONFIG_ENV_UNKNOWN');

  for (const loaderKey of [
    'NODE_OPTIONS',
    'NODE_PATH',
    'LD_PRELOAD',
    'LD_AUDIT',
    'DYLD_INSERT_LIBRARIES',
    'GCONV_PATH',
    'GLIBC_TUNABLES',
  ]) {
    assertKernelError(invoke({ ...fixture.env, [loaderKey]: '' }), 'CONFIG_LOADER_ENV');
  }
});

test('deterministic mode ignores loader and CDP-only values instead of serializing them', (t) => {
  const fixture = makeFixture(t);
  const config = loadControlPlaneConfig({
    env: {
      ...fixture.env,
      NODE_OPTIONS: '--import=/credential-bearing/path',
      LD_PRELOAD: '/credential-bearing/library',
      CDP_API_KEY_SECRET: 'deterministic-secret',
      CDP_WALLET_SECRET: 'deterministic-wallet-secret',
      WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: 'https://user:pass@rpc.example/secret',
    },
    checkoutRoot: CHECKOUT_ROOT,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    platform: 'darwin',
  });
  const serialized = JSON.stringify(config);
  assert.equal(serialized.includes('credential-bearing'), false);
  assert.equal(serialized.includes('deterministic-secret'), false);
  assert.equal(serialized.includes('deterministic-wallet-secret'), false);
  assert.equal(serialized.includes('user:pass'), false);
});

test('live RPC validation is HTTPS and credential-free without exposing its secret URL', (t) => {
  const fixture = makeLiveFixture(t);
  if (!fixture) {
    t.skip('requires non-root POSIX fixtures below a root-owned non-writable ancestor');
    return;
  }
  for (const rpcUrl of [
    '',
    'http://rpc.example/v1/key',
    'https://user@rpc.example/v1/key',
    'https://:password@rpc.example/v1/key',
    'not-a-url',
  ]) {
    let caught;
    try {
      loadControlPlaneConfig({
        env: { ...fixture.env, WALLET_KERNEL_BASE_SEPOLIA_RPC_URL: rpcUrl },
        checkoutRoot: CHECKOUT_ROOT,
        uid: fixture.uid,
        gid: fixture.gid,
        platform: 'linux',
      });
    } catch (error) {
      caught = error;
    }
    assert.equal(caught instanceof KernelError, true);
    assert.equal(caught.code, 'CONFIG_RPC');
    if (rpcUrl !== '') assert.equal(String(caught).includes(rpcUrl), false);
  }
});

test('configuration paths are canonical, external, non-symlinked, and non-writable', (t) => {
  const fixture = makeFixture(t);
  const invoke = (overrides) => () => loadControlPlaneConfig({
    env: { ...fixture.env, ...overrides },
    checkoutRoot: CHECKOUT_ROOT,
    uid: CURRENT_UID,
    gid: CURRENT_GID,
    platform: 'darwin',
  });

  assertKernelError(invoke({ WALLET_KERNEL_DB_FILE: 'relative/kernel.sqlite' }), 'CONFIG_PATH');
  assertKernelError(invoke({
    WALLET_KERNEL_POLICY_FILE: path.join(CHECKOUT_ROOT, 'spikes/pi-wielder/package.json'),
  }), 'CONFIG_PATH');
  assertKernelError(invoke({
    WALLET_KERNEL_ROUTE_FILE: `${fixture.root}/release/./routes.json`,
  }), 'CONFIG_PATH');
  assertKernelError(invoke({
    WALLET_KERNEL_EVIDENCE_ROOT: fixture.root,
  }), 'CONFIG_PATH');

  const symlink = path.join(fixture.root, 'route-link.json');
  fs.symlinkSync(fixture.paths.route, symlink);
  assertKernelError(invoke({ WALLET_KERNEL_ROUTE_FILE: symlink }), 'CONFIG_PATH');

  const brokenPrivateSymlink = path.join(fixture.root, 'broken-private-link');
  fs.symlinkSync(path.join(fixture.root, 'missing-private-target'), brokenPrivateSymlink);
  assertKernelError(invoke({ WALLET_KERNEL_DB_FILE: brokenPrivateSymlink }), 'CONFIG_PATH');

  const permissive = path.join(fixture.root, 'permissive');
  fs.mkdirSync(permissive, { mode: 0o777 });
  fs.chmodSync(permissive, 0o777);
  const permissivePolicy = writeFixtureFile(path.join(permissive, 'policy.json'));
  assertKernelError(invoke({ WALLET_KERNEL_POLICY_FILE: permissivePolicy }), 'CONFIG_PATH_MODE');

  assertKernelError(invoke({
    WALLET_KERNEL_OPERATOR_TOKEN_FILE: fixture.env.WALLET_KERNEL_DB_FILE,
  }), 'CONFIG_PATH_COLLISION');
});

test('live requires every deployment path and rejects sticky or non-root trust', (t) => {
  const fixture = makeLiveFixture(t);
  if (!fixture) {
    t.skip('requires non-root POSIX fixtures below a root-owned non-writable ancestor');
    return;
  }
  const invoke = (env) => () => loadControlPlaneConfig({
    env,
    checkoutRoot: CHECKOUT_ROOT,
    uid: fixture.uid,
    gid: fixture.gid,
    platform: 'linux',
  });
  for (const field of [
    'WALLET_KERNEL_OPERATOR_SOCKET_FILE',
    'WALLET_KERNEL_ENROLLMENT_INBOX',
    'WALLET_KERNEL_AGENT_RUN_OUTBOX',
    'WALLET_KERNEL_RELEASE_ROOT',
    'WALLET_KERNEL_RELEASE_MANIFEST',
    'WALLET_KERNEL_SERVICE_DEFINITION_FILE',
    'WALLET_KERNEL_SOCKET_DEFINITION_FILE',
    'WALLET_KERNEL_ENV_FILE',
    'WALLET_KERNEL_EVIDENCE_ROOT',
    'WALLET_KERNEL_ISOLATION_REPORT_FILE',
  ]) {
    assertKernelError(invoke({ ...fixture.env, [field]: '' }), 'CONFIG_PATH');
  }
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_TRUSTED_ANCESTOR: fixture.root,
  }), 'CONFIG_PATH_OWNER');
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_TRUSTED_ANCESTOR: fs.realpathSync('/tmp'),
  }), 'CONFIG_PATH_MODE');
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_SERVICE_DEFINITION_FILE: fixture.env.WALLET_KERNEL_SOCKET_DEFINITION_FILE,
  }), 'CONFIG_PATH_COLLISION');
  assertKernelError(invoke({
    ...fixture.env,
    WALLET_KERNEL_ROUTE_FILE: fixture.paths.route,
  }), 'CONFIG_PATH_OWNER');

  const outsideRelease = fs.realpathSync('/usr/bin/true');
  const outsideStat = fs.statSync(outsideRelease);
  if (outsideStat.uid === 0 && outsideStat.isFile() && (outsideStat.mode & 0o022) === 0) {
    assertKernelError(invoke({
      ...fixture.env,
      WALLET_KERNEL_ROUTE_FILE: outsideRelease,
    }), 'CONFIG_RELEASE_BOUNDARY');
  }

  fs.chmodSync(path.dirname(fixture.env.WALLET_KERNEL_OPERATOR_SOCKET_FILE), 0o755);
  assertKernelError(invoke(fixture.env), 'CONFIG_PATH_MODE');
});

function route(overrides = {}) {
  return {
    id: 'example-skill',
    kind: 'tool',
    method: 'POST',
    upstreamUrl: 'https://seller.example/paid/skill',
    resourceDescription: 'Wallet Kernel example Skill route',
    resourceMimeType: 'application/json',
    purposeLabel: 'skill.invoke',
    requestContentTypes: ['application/json'],
    maximumRequestBytes: 262_144,
    maximumResponseBytes: 1_048_576,
    ...overrides,
  };
}

test('installed release configuration excludes private state and inspects the closed source by metadata only', (t) => {
  const fixture = makeFixture(t);
  const source = writeFixtureFile(path.join(fixture.root, 'kernel.env'), 'synthetic-source-never-opened\n');
  const env = {...fixture.env, WALLET_KERNEL_MODE:'cdp-testnet', WALLET_KERNEL_ENV_FILE:source,
    WALLET_KERNEL_EXPECTED_AGENT_UID:String(CURRENT_UID + 1),
    WALLET_KERNEL_EXPECTED_AGENT_GID:String(CURRENT_GID + 1),
    CDP_API_KEY_ID:'synthetic-id', CDP_API_KEY_SECRET:'synthetic-secret',
    CDP_WALLET_SECRET:'synthetic-wallet-secret', CDP_WALLET_NAME:'pilot-wallet',
    WALLET_KERNEL_BASE_SEPOLIA_RPC_URL:'https://rpc.example'};
  // Model only immutable ownership metadata. No host chown or secret reads.
  const rootOwned = (location) => location === fixture.root || location === source
    || location === fixture.paths.releaseRoot || location.startsWith(`${fixture.paths.releaseRoot}/`);
  const originalOpen = fs.openSync;
  const originalLstat = fs.lstatSync;
  const originalFstat = fs.fstatSync;
  const descriptors = new Map();
  let sourceOpens = 0;
  let policyOpens = 0;
  const project = (stat, location) => {
    if (rootOwned(location)) stat.uid = typeof stat.uid === 'bigint' ? 0n : 0;
    return stat;
  };
  t.mock.method(fs, 'openSync', (location, ...args) => {
    if (location === source) {sourceOpens++; throw Error('root source cannot be opened');}
    if (location === fixture.paths.policy) policyOpens++;
    const descriptor = originalOpen(location, ...args);
    descriptors.set(descriptor, location);
    return descriptor;
  });
  t.mock.method(fs, 'lstatSync', (location, ...args) => project(originalLstat(location, ...args), location));
  t.mock.method(fs, 'fstatSync', (descriptor, ...args) => project(originalFstat(descriptor, ...args), descriptors.get(descriptor)));
  const input = {env, checkoutRoot:fixture.paths.releaseRoot, uid:CURRENT_UID, gid:CURRENT_GID, platform:'linux'};
  assertKernelError(() => loadControlPlaneConfig(input), 'CONFIG_PATH');
  const installed = {...input, verifiedReleaseRoot:fixture.paths.releaseRoot};
  assert.equal(loadControlPlaneConfig(installed).publicConfig.environmentFilePath, source);
  assert.equal(sourceOpens, 0);
  assert.ok(policyOpens > 0, 'immutable public files retain descriptor checks');
  assertKernelError(() => loadControlPlaneConfig({...installed, env:{...env,
    WALLET_KERNEL_DB_FILE:path.join(fixture.paths.releaseRoot, 'private.sqlite')}}), 'CONFIG_PATH');
  assertKernelError(() => loadControlPlaneConfig({...installed, env:{...env,
    WALLET_KERNEL_ENV_FILE:fixture.paths.environmentFile}}), 'CONFIG_PATH');
  fs.unlinkSync(fixture.paths.isolationReport);
  assert.equal(loadControlPlaneConfig(installed).publicConfig.isolationReportPath, fixture.paths.isolationReport);
  writeFixtureFile(fixture.paths.isolationReport, '{}\n', 0o644);
  assertKernelError(() => loadControlPlaneConfig(installed), 'CONFIG_PATH_MODE');
});

function routeDocument(routes = [route()]) {
  return { schemaVersion: 1, routes };
}

test('route-map validation returns a detached deeply frozen exact-ID registry', () => {
  const source = routeDocument([
    route(),
    route({
      id: 'example-model',
      kind: 'openai-chat',
      upstreamUrl: 'https://seller.example/paid/chat/completions',
      resourceDescription: 'Wallet Kernel example model route',
      purposeLabel: 'model.infer',
    }),
  ]);
  const registry = validateRouteMap({ document: source, mode: 'cdp-testnet' });
  assert.equal(Object.isFrozen(registry), true);
  assert.equal(Object.isFrozen(registry.routes), true);
  assert.equal(Object.isFrozen(registry.routes[0]), true);
  assert.equal(Object.isFrozen(registry.routes[0].requestContentTypes), true);
  assert.equal(Object.isFrozen(registry.get), true);
  assert.equal(registry.schemaVersion, 1);
  assert.equal(registry.get('example-skill'), registry.routes[0]);
  assert.equal(registry.get('EXAMPLE-SKILL'), null);
  assert.equal(registry.get('https://attacker.example'), null);
  source.routes[0].upstreamUrl = 'https://attacker.example/replace';
  source.routes[0].requestContentTypes[0] = 'text/plain';
  assert.equal(registry.get('example-skill').upstreamUrl, 'https://seller.example/paid/skill');
  assert.deepEqual(registry.get('example-skill').requestContentTypes, ['application/json']);
  assertKernelError(() => registry.get('example-skill', 'https://attacker.example'), 'ROUTE_LOOKUP');
});

test('deterministic routes permit only literal canonical loopback HTTP', () => {
  for (const upstreamUrl of [
    'http://127.0.0.1:8403/paid/skill',
    'http://[::1]:8403/paid/skill',
    'https://seller.example/paid/skill',
  ]) {
    assert.doesNotThrow(() => validateRouteMap({
      document: routeDocument([route({ upstreamUrl })]),
      mode: 'deterministic',
    }));
  }
  for (const upstreamUrl of [
    'http://localhost:8403/paid/skill',
    'http://127.0.0.2:8403/paid/skill',
    'http://2130706433:8403/paid/skill',
    'http://127.0.0.01:8403/paid/skill',
    'http://[0:0:0:0:0:0:0:1]:8403/paid/skill',
  ]) {
    assertKernelError(() => validateRouteMap({
      document: routeDocument([route({ upstreamUrl })]),
      mode: 'deterministic',
    }), 'ROUTE_URL');
  }
});

test('cdp-testnet routes require canonical credential-free queryless HTTPS', () => {
  for (const upstreamUrl of [
    'http://127.0.0.1:8403/paid/skill',
    'https://user@seller.example/paid/skill',
    'https://:password@seller.example/paid/skill',
    'https://seller.example/paid/skill?target=https://attacker.example',
    'https://seller.example/paid/skill#fragment',
    'https://seller.example/paid/%2fescape',
    'https://SELLER.example/paid/skill',
    'https://seller.example:443/paid/skill',
  ]) {
    assertKernelError(() => validateRouteMap({
      document: routeDocument([route({ upstreamUrl })]),
      mode: 'cdp-testnet',
    }), 'ROUTE_URL');
  }
});

test('route maps are closed, unique, canonical, and bounded', () => {
  assertKernelError(() => validateRouteMap({
    document: routeDocument(),
    mode: 'cdp-testnet',
    upstreamUrl: 'https://attacker.example/override',
  }), 'ROUTE_SCHEMA');
  assertKernelError(() => validateRouteMap({
    document: { ...routeDocument(), unknown: true },
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
  assertKernelError(() => validateRouteMap({
    document: { schemaVersion: 2, routes: [route()] },
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
  assertKernelError(() => validateRouteMap({
    document: { schemaVersion: 1, routes: [] },
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
  assertKernelError(() => validateRouteMap({
    document: routeDocument([route(), route()]),
    mode: 'cdp-testnet',
  }), 'ROUTE_DUPLICATE');

  for (const id of ['', 'not a route', '../escape', 'A'.repeat(65)]) {
    assertKernelError(() => validateRouteMap({
      document: routeDocument([route({ id })]),
      mode: 'cdp-testnet',
    }), 'ROUTE_ID');
  }
  assertKernelError(() => validateRouteMap({
    document: routeDocument(Array.from({ length: 65 }, (_, index) => route({ id: `route-${index}` }))),
    mode: 'cdp-testnet',
  }), 'ROUTE_LIMIT');
  assertKernelError(() => validateRouteMap({
    document: routeDocument([{ ...route(), unknown: true }]),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
});

test('route methods, kinds, content types, metadata, and byte limits are closed', () => {
  const invalidRoutes = [
    [route({ method: 'GET' }), 'ROUTE_METHOD'],
    [route({ method: 'post' }), 'ROUTE_METHOD'],
    [route({ kind: 'arbitrary-fetch' }), 'ROUTE_KIND'],
    [route({ resourceMimeType: 'text/html' }), 'ROUTE_CONTENT_TYPE'],
    [route({ requestContentTypes: ['application/json', 'text/plain'] }), 'ROUTE_CONTENT_TYPE'],
    [route({ requestContentTypes: [] }), 'ROUTE_CONTENT_TYPE'],
    [route({ resourceDescription: '' }), 'ROUTE_METADATA'],
    [route({ resourceDescription: 'x'.repeat(257) }), 'ROUTE_METADATA'],
    [route({ purposeLabel: 'not a label' }), 'ROUTE_METADATA'],
    [route({ maximumRequestBytes: 0 }), 'ROUTE_BYTES'],
    [route({ maximumRequestBytes: 262_145 }), 'ROUTE_BYTES'],
    [route({ maximumResponseBytes: 1_048_577 }), 'ROUTE_BYTES'],
    [route({ maximumResponseBytes: 1.5 }), 'ROUTE_BYTES'],
  ];
  for (const [entry, code] of invalidRoutes) {
    assertKernelError(() => validateRouteMap({
      document: routeDocument([entry]),
      mode: 'cdp-testnet',
    }), code);
  }
});

test('route-map input rejects proxies, accessors, sparse arrays, and oversized documents', () => {
  assertKernelError(() => validateRouteMap({
    document: new Proxy(routeDocument(), {}),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');

  const accessor = route();
  Object.defineProperty(accessor, 'id', { enumerable: true, get: () => 'example-skill' });
  assertKernelError(() => validateRouteMap({
    document: routeDocument([accessor]),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');

  let nestedProxyCalls = 0;
  const proxiedRoutes = new Proxy([route()], {
    get(target, property, receiver) {
      nestedProxyCalls += 1;
      return Reflect.get(target, property, receiver);
    },
  });
  assertKernelError(() => validateRouteMap({
    document: routeDocument(proxiedRoutes),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
  assert.equal(nestedProxyCalls, 0);

  const contentTypes = [];
  let nestedGetterCalls = 0;
  Object.defineProperty(contentTypes, '0', {
    enumerable: true,
    get() {
      nestedGetterCalls += 1;
      return 'application/json';
    },
  });
  Object.defineProperty(contentTypes, 'length', { value: 1 });
  assertKernelError(() => validateRouteMap({
    document: routeDocument([route({ requestContentTypes: contentTypes })]),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');
  assert.equal(nestedGetterCalls, 0);

  const sparse = new Array(2);
  sparse[0] = route();
  assertKernelError(() => validateRouteMap({
    document: routeDocument(sparse),
    mode: 'cdp-testnet',
  }), 'ROUTE_SCHEMA');

  assertKernelError(() => validateRouteMap({
    document: routeDocument(Array.from({ length: 64 }, (_, index) => route({
      id: `route-${index}`,
      resourceDescription: 'x'.repeat(256),
      upstreamUrl: `https://seller.example/${'x'.repeat(700)}-${index}`,
    }))),
    mode: 'cdp-testnet',
  }), 'ROUTE_LIMIT');
});

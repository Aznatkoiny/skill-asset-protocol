import fs from 'node:fs';
import path from 'node:path';

import {
  canonicalJson,
  canonicalTimestamp,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const NONNEGATIVE_DECIMAL = /^(0|[1-9][0-9]*)$/;
const OCTAL = /^(0|[1-7][0-7]{0,3})$/;
const RELEASE_ENTRY_KINDS = new Set(['directory', 'file', 'symlink']);
const SERVICE_ROLES = Object.freeze(['console-socket', 'kernel-service']);
const MANIFEST_FIELDS = Object.freeze([
  'schemaVersion', 'commit', 'createdAt', 'entrypoint', 'packageLockHash',
  'releaseTreeHash', 'kernelIdentity', 'node', 'environment', 'serviceArtifacts',
  'systemd', 'entries',
]);
const LOADER_EXACT = new Set([
  'NODE_OPTIONS', 'NODE_PATH', 'GCONV_PATH', 'GLIBC_TUNABLES',
]);
const BASE_ENVIRONMENT = new Set(['PATH', 'LANG', 'LC_ALL', 'TZ']);
const TREE_DOMAIN = 'wallet-kernel/release-tree/v1\0';
const SERVICE_DOMAIN = 'wallet-kernel/service-artifacts/v1\0';
const ENVIRONMENT_DOMAIN = 'wallet-kernel/environment-metadata/v1\0';
const PATH_DOMAIN = 'wallet-kernel/absolute-path/v1\0';

function fail(code, message, cause) {
  throw new KernelError(code, message, cause ? { cause } : undefined);
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('RELEASE_MANIFEST_SCHEMA', `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalIdentity(value, label, { positive = true } = {}) {
  const pattern = positive ? POSITIVE_DECIMAL : NONNEGATIVE_DECIMAL;
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail('RELEASE_MANIFEST_SCHEMA', `${label} must be canonical ${positive ? 'positive' : 'nonnegative'} decimal text`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || String(parsed) !== value) {
    fail('RELEASE_MANIFEST_SCHEMA', `${label} must round-trip through a safe integer`);
  }
  return value;
}

function canonicalMode(value, label) {
  if (typeof value !== 'string' || !OCTAL.test(value)
      || Number.parseInt(value, 8) > 0o7777
      || Number.parseInt(value, 8).toString(8) !== value) {
    fail('RELEASE_MANIFEST_SCHEMA', `${label} must be canonical octal text`);
  }
  return value;
}

function assertAbsolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value
      || value.includes('\0')) {
    fail('RELEASE_PATH', `${label} must be one canonical absolute path`);
  }
  return value;
}

function assertNoMutableBits(stat, label, expectedOwnerUid) {
  const mode = Number(stat.mode & 0o7777n);
  if (Number(stat.uid) !== expectedOwnerUid || (mode & 0o022) !== 0) {
    fail('RELEASE_OWNERSHIP', `${label} must have the expected owner and no group/other write bit`);
  }
  return mode;
}

function metadata(stat, expectedOwnerUid, label) {
  const mode = assertNoMutableBits(stat, label, expectedOwnerUid);
  return Object.freeze({
    uid: String(Number(stat.uid)),
    gid: String(Number(stat.gid)),
    mode: mode.toString(8),
  });
}

function readRegularFile(filePath, expectedOwnerUid, label) {
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n) {
      fail('RELEASE_FILE', `${label} must be one regular file with link count one`);
    }
    const meta = metadata(before, expectedOwnerUid, label);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
        || before.mtimeNs !== after.mtimeNs || before.mode !== after.mode
        || before.uid !== after.uid || before.gid !== after.gid) {
      fail('RELEASE_RACE', `${label} changed while it was being hashed`);
    }
    return Object.freeze({ bytes, ...meta });
  } finally {
    fs.closeSync(descriptor);
  }
}

// The source file is root-only. PID1 delivers a separate read-only credential
// copy to the Kernel; neither release building nor verification opens its bytes.
function environmentMetadata(filePath, expectedOwnerUid) {
  assertAbsolute(filePath, 'environment file');
  let parent = path.dirname(filePath);
  for (;;) {
    const stat = fs.lstatSync(parent, { bigint: true });
    if (!stat.isDirectory() || stat.isSymbolicLink()) {
      fail('RELEASE_ENVIRONMENT', 'environment ancestors must be direct directories');
    }
    if (expectedOwnerUid === 0) assertNoMutableBits(stat, 'environment ancestor', 0);
    if (parent === path.dirname(parent)) break;
    parent = path.dirname(parent);
  }
  const stat = fs.lstatSync(filePath, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n) {
    fail('RELEASE_ENVIRONMENT', 'environment must be one direct single-link regular file');
  }
  const meta = metadata(stat, expectedOwnerUid, 'environment file');
  if (meta.mode !== '600') fail('RELEASE_ENVIRONMENT', 'environment file must have mode 0600');
  return Object.freeze({ device: stat.dev.toString(10), inode: stat.ino.toString(10), ...meta });
}

function canonicalRelative(relativePath) {
  if (typeof relativePath !== 'string' || relativePath === '' || path.isAbsolute(relativePath)
      || relativePath.includes('\\') || relativePath.includes('\0')) {
    fail('RELEASE_ENTRY', 'release entry path must be a canonical relative POSIX path');
  }
  const parts = relativePath.split('/');
  if (parts.some((part) => part === '' || part === '.' || part === '..')
      || parts.join('/') !== relativePath) {
    fail('RELEASE_ENTRY', 'release entry path must be a canonical relative POSIX path');
  }
  return relativePath;
}

function inside(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`)
    && !path.isAbsolute(relative));
}

function collectEntries({ releaseRoot, manifestPath, expectedOwnerUid }) {
  const root = assertAbsolute(releaseRoot, 'release root');
  const rootStat = fs.lstatSync(root, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink()) {
    fail('RELEASE_ROOT', 'release root must be one direct directory');
  }
  assertNoMutableBits(rootStat, 'release root', expectedOwnerUid);
  const excluded = manifestPath === undefined ? null : path.relative(root, manifestPath).split(path.sep).join('/');
  const entries = [];

  const walk = (directory, prefix = '') => {
    const names = fs.readdirSync(directory);
    names.sort((left, right) => Buffer.from(left).compare(Buffer.from(right)));
    for (const name of names) {
      if (name === '.' || name === '..' || name.includes('/') || name.includes('\0')) {
        fail('RELEASE_ENTRY', 'release contains an invalid entry name');
      }
      const relative = canonicalRelative(prefix ? `${prefix}/${name}` : name);
      if (relative === excluded) continue;
      const absolute = path.join(directory, name);
      const stat = fs.lstatSync(absolute, { bigint: true });
      // Symlink permission bits are conventionally 0777 and do not grant
      // mutation. Its owner, containing directories and resolved target do.
      if (stat.isSymbolicLink() && Number(stat.uid) !== expectedOwnerUid) {
        fail('RELEASE_OWNERSHIP', 'release symlink must have the expected owner');
      }
      const meta = stat.isSymbolicLink()
        ? { uid: stat.uid.toString(), gid: stat.gid.toString(), mode: (stat.mode & 0o7777n).toString(8) }
        : metadata(stat, expectedOwnerUid, `release entry ${relative}`);
      if (stat.isDirectory()) {
        entries.push({ path: relative, kind: 'directory', ...meta, bytes: null, sha256: null, target: null });
        walk(absolute, relative);
      } else if (stat.isFile()) {
        if (stat.nlink !== 1n) fail('RELEASE_HARDLINK', 'release regular files must have link count one');
        const file = readRegularFile(absolute, expectedOwnerUid, `release entry ${relative}`);
        entries.push({
          path: relative, kind: 'file', uid: file.uid, gid: file.gid, mode: file.mode,
          bytes: String(file.bytes.length), sha256: sha256(file.bytes), target: null,
        });
      } else if (stat.isSymbolicLink()) {
        const rawTarget = fs.readlinkSync(absolute);
        const resolved = path.resolve(path.dirname(absolute), rawTarget);
        if (!inside(root, resolved) || !fs.existsSync(resolved)) {
          fail('RELEASE_SYMLINK', 'release symlink must resolve to an existing in-root target');
        }
        const target = path.relative(root, resolved).split(path.sep).join('/');
        canonicalRelative(target);
        entries.push({ path: relative, kind: 'symlink', ...meta, bytes: null, sha256: null, target });
      } else {
        fail('RELEASE_ENTRY', 'release may contain only directories, files, and in-root symlinks');
      }
    }
  };
  walk(root);
  entries.sort((left, right) => Buffer.from(left.path).compare(Buffer.from(right.path)));
  return entries;
}

function validateEntry(value) {
  const entry = exactRecord(value, [
    'path', 'kind', 'uid', 'gid', 'mode', 'bytes', 'sha256', 'target',
  ], [], 'RELEASE_MANIFEST_SCHEMA', 'release entry');
  canonicalRelative(entry.path);
  if (!RELEASE_ENTRY_KINDS.has(entry.kind)) fail('RELEASE_MANIFEST_SCHEMA', 'release entry kind is invalid');
  canonicalIdentity(entry.uid, 'release entry UID', { positive: false });
  canonicalIdentity(entry.gid, 'release entry GID', { positive: false });
  canonicalMode(entry.mode, 'release entry mode');
  if (entry.kind === 'file') {
    canonicalIdentity(entry.bytes, 'release entry byte count', { positive: false });
    canonicalHash(entry.sha256, 'release entry content hash');
    if (entry.target !== null) fail('RELEASE_MANIFEST_SCHEMA', 'file target must be null');
  } else if (entry.kind === 'directory') {
    if (entry.bytes !== null || entry.sha256 !== null || entry.target !== null) {
      fail('RELEASE_MANIFEST_SCHEMA', 'directory content fields must be null');
    }
  } else {
    if (entry.bytes !== null || entry.sha256 !== null) {
      fail('RELEASE_MANIFEST_SCHEMA', 'symlink content fields must be null');
    }
    canonicalRelative(entry.target);
  }
  return Object.freeze(entry);
}

function validateServiceArtifact(value) {
  const artifact = exactRecord(value, [
    'role', 'pathHash', 'sha256', 'uid', 'gid', 'mode',
  ], [], 'RELEASE_MANIFEST_SCHEMA', 'service artifact');
  if (!SERVICE_ROLES.includes(artifact.role)) fail('RELEASE_MANIFEST_SCHEMA', 'service artifact role is invalid');
  canonicalHash(artifact.pathHash, 'service artifact path hash');
  canonicalHash(artifact.sha256, 'service artifact hash');
  canonicalIdentity(artifact.uid, 'service artifact UID', { positive: false });
  canonicalIdentity(artifact.gid, 'service artifact GID', { positive: false });
  canonicalMode(artifact.mode, 'service artifact mode');
  return Object.freeze(artifact);
}

function validateSystemd(value) {
  const systemd = exactRecord(value, [
    'managerVersion', 'systemctlVersion', 'systemctlExecutablePathHash',
    'systemctlExecutableSha256', 'effectiveConfigHash',
  ], [], 'RELEASE_MANIFEST_SCHEMA', 'systemd manifest');
  for (const field of ['managerVersion', 'systemctlVersion']) {
    if (typeof systemd[field] !== 'string' || systemd[field].length < 1
        || systemd[field].length > 256 || /[\r\n\0]/.test(systemd[field])) {
      fail('RELEASE_MANIFEST_SCHEMA', `${field} must be bounded canonical text`);
    }
  }
  for (const field of [
    'systemctlExecutablePathHash', 'systemctlExecutableSha256', 'effectiveConfigHash',
  ]) canonicalHash(systemd[field], field);
  return Object.freeze(systemd);
}

export function computeServiceArtifactsHash(value) {
  if (!Array.isArray(value) || value.length !== 2) {
    fail('RELEASE_MANIFEST_SCHEMA', 'service artifacts must contain exactly two roles');
  }
  const artifacts = value.map(validateServiceArtifact)
    .sort((left, right) => left.role.localeCompare(right.role));
  if (artifacts.map(({ role }) => role).join(',') !== SERVICE_ROLES.join(',')) {
    fail('RELEASE_MANIFEST_SCHEMA', 'service artifacts must contain the exact roles');
  }
  return sha256(`${SERVICE_DOMAIN}${canonicalJson(artifacts)}`);
}

export function validateReleaseManifest(value) {
  const manifest = exactRecord(value, MANIFEST_FIELDS, [],
    'RELEASE_MANIFEST_SCHEMA', 'release manifest');
  if (manifest.schemaVersion !== 1) fail('RELEASE_MANIFEST_SCHEMA', 'release manifest schemaVersion must equal 1');
  if (typeof manifest.commit !== 'string' || !COMMIT.test(manifest.commit)) {
    fail('RELEASE_MANIFEST_SCHEMA', 'release commit must be one full lowercase hash');
  }
  canonicalTimestamp(manifest.createdAt, 'release createdAt');
  if (manifest.entrypoint !== 'src/control-plane.mjs') {
    fail('RELEASE_MANIFEST_SCHEMA', 'release entrypoint is not the pinned control plane');
  }
  canonicalHash(manifest.packageLockHash, 'package-lock hash');
  canonicalHash(manifest.releaseTreeHash, 'release tree hash');
  const kernelIdentity = exactRecord(manifest.kernelIdentity, ['uid', 'gid'], [],
    'RELEASE_MANIFEST_SCHEMA', 'Kernel identity');
  canonicalIdentity(kernelIdentity.uid, 'Kernel UID');
  canonicalIdentity(kernelIdentity.gid, 'Kernel GID');
  const node = exactRecord(manifest.node, [
    'version', 'executablePathHash', 'executableSha256', 'uid', 'gid', 'mode',
  ], [], 'RELEASE_MANIFEST_SCHEMA', 'Node runtime');
  if (node.version !== 'v24.18.1') fail('RELEASE_NODE_VERSION', 'Node runtime must equal v24.18.1');
  canonicalHash(node.executablePathHash, 'Node path hash');
  canonicalHash(node.executableSha256, 'Node executable hash');
  if (node.uid !== '0') fail('RELEASE_MANIFEST_SCHEMA', 'Node executable must be root owned');
  canonicalIdentity(node.gid, 'Node executable GID', { positive: false });
  canonicalMode(node.mode, 'Node executable mode');
  const environment = exactRecord(manifest.environment, ['environmentMetadataHash'], [],
    'RELEASE_MANIFEST_SCHEMA', 'environment metadata');
  canonicalHash(environment.environmentMetadataHash, 'environment metadata hash');
  const serviceArtifacts = manifest.serviceArtifacts.map(validateServiceArtifact)
    .sort((left, right) => left.role.localeCompare(right.role));
  computeServiceArtifactsHash(serviceArtifacts);
  if (!Array.isArray(manifest.entries) || manifest.entries.length === 0) {
    fail('RELEASE_MANIFEST_SCHEMA', 'release manifest entries must be nonempty');
  }
  const entries = manifest.entries.map(validateEntry);
  const paths = entries.map((entry) => entry.path);
  if (new Set(paths).size !== paths.length
      || paths.some((entryPath, index) => index > 0 && Buffer.from(paths[index - 1]).compare(Buffer.from(entryPath)) >= 0)) {
    fail('RELEASE_MANIFEST_SCHEMA', 'release entries must be unique and canonically sorted');
  }
  const calculatedTreeHash = sha256(`${TREE_DOMAIN}${canonicalJson(entries)}`);
  if (calculatedTreeHash !== manifest.releaseTreeHash) {
    fail('RELEASE_MANIFEST_HASH', 'release tree aggregate hash does not match its entries');
  }
  const packageEntry = entries.find((entry) => entry.path === 'package-lock.json');
  if (!packageEntry || packageEntry.sha256 !== manifest.packageLockHash) {
    fail('RELEASE_MANIFEST_HASH', 'package-lock hash does not match its tree entry');
  }
  if (!entries.some((entry) => entry.path === manifest.entrypoint && entry.kind === 'file')) {
    fail('RELEASE_MANIFEST_SCHEMA', 'release entrypoint is missing from the tree');
  }
  validateSystemd(manifest.systemd);
  return frozenCopy({ ...manifest, kernelIdentity, node, environment, serviceArtifacts, entries });
}

function captureBuildInput(input) {
  return exactRecord(input, [
    'mode', 'releaseRoot', 'manifestPath', 'commit', 'createdAt', 'kernelUid', 'kernelGid',
    'node', 'environmentPath', 'serviceArtifacts', 'systemd', 'expectedOwnerUid',
  ], [], 'RELEASE_BUILD_INPUT', 'release manifest build input');
}

export function buildReleaseManifest(input) {
  const options = captureBuildInput(input);
  if (options.mode !== 'deterministic' && options.mode !== 'cdp-testnet') {
    fail('RELEASE_BUILD_INPUT', 'release manifest mode is invalid');
  }
  if (!Number.isSafeInteger(options.expectedOwnerUid) || options.expectedOwnerUid < 0
      || (options.mode === 'cdp-testnet' && options.expectedOwnerUid !== 0)) {
    fail('RELEASE_BUILD_INPUT', 'release expected owner is invalid');
  }
  const releaseRoot = assertAbsolute(options.releaseRoot, 'release root');
  const manifestPath = assertAbsolute(options.manifestPath, 'release manifest path');
  if (!inside(releaseRoot, manifestPath) || path.dirname(manifestPath) !== releaseRoot) {
    fail('RELEASE_BUILD_INPUT', 'release manifest must be a direct child of the release root');
  }
  if (typeof options.commit !== 'string' || !COMMIT.test(options.commit)) {
    fail('RELEASE_BUILD_INPUT', 'release commit must be one full lowercase hash');
  }
  canonicalTimestamp(options.createdAt, 'release createdAt');
  canonicalIdentity(options.kernelUid, 'Kernel UID');
  canonicalIdentity(options.kernelGid, 'Kernel GID');
  const nodeInput = exactRecord(options.node, ['path', 'version'], [],
    'RELEASE_BUILD_INPUT', 'Node build input');
  if (nodeInput.version !== 'v24.18.1') fail('RELEASE_NODE_VERSION', 'Node runtime must equal v24.18.1');
  const nodePath = assertAbsolute(nodeInput.path, 'Node executable');
  const nodeFile = readRegularFile(nodePath, options.expectedOwnerUid, 'Node executable');
  const environmentPath = assertAbsolute(options.environmentPath, 'environment file');
  const environmentFile = environmentMetadata(environmentPath, options.expectedOwnerUid);
  if (!Array.isArray(options.serviceArtifacts) || options.serviceArtifacts.length !== 2) {
    fail('RELEASE_BUILD_INPUT', 'service artifact inputs must contain exactly two roles');
  }
  const artifactPaths = new Set();
  const serviceArtifacts = options.serviceArtifacts.map((candidate) => {
    const item = exactRecord(candidate, ['role', 'path'], [],
      'RELEASE_BUILD_INPUT', 'service artifact input');
    if (!SERVICE_ROLES.includes(item.role)) fail('RELEASE_BUILD_INPUT', 'service artifact roles are invalid');
    const artifactPath = assertAbsolute(item.path, 'service artifact path');
    if (artifactPaths.has(artifactPath)) fail('RELEASE_BUILD_INPUT', 'service artifact path reuse is forbidden');
    artifactPaths.add(artifactPath);
    const file = readRegularFile(artifactPath, options.expectedOwnerUid, `service artifact ${item.role}`);
    return {
      role: item.role,
      pathHash: sha256(`${PATH_DOMAIN}${artifactPath}`),
      sha256: sha256(file.bytes), uid: file.uid, gid: file.gid, mode: file.mode,
    };
  }).sort((left, right) => left.role.localeCompare(right.role));
  computeServiceArtifactsHash(serviceArtifacts);
  const entries = collectEntries({ releaseRoot, manifestPath, expectedOwnerUid: options.expectedOwnerUid });
  const packageLock = entries.find((entry) => entry.path === 'package-lock.json');
  if (!packageLock || packageLock.kind !== 'file') fail('RELEASE_BUILD_INPUT', 'package-lock.json is required');
  const nodeMode = Number.parseInt(nodeFile.mode, 8);
  const manifest = {
    schemaVersion: 1,
    commit: options.commit,
    createdAt: options.createdAt,
    entrypoint: 'src/control-plane.mjs',
    packageLockHash: packageLock.sha256,
    releaseTreeHash: sha256(`${TREE_DOMAIN}${canonicalJson(entries)}`),
    kernelIdentity: { uid: options.kernelUid, gid: options.kernelGid },
    node: {
      version: nodeInput.version,
      executablePathHash: sha256(`${PATH_DOMAIN}${nodePath}`),
      executableSha256: sha256(nodeFile.bytes),
      uid: options.mode === 'cdp-testnet' ? nodeFile.uid : '0',
      gid: nodeFile.gid,
      mode: nodeMode.toString(8),
    },
    environment: {
      environmentMetadataHash: sha256(`${ENVIRONMENT_DOMAIN}${canonicalJson(environmentFile)}`),
    },
    serviceArtifacts,
    systemd: validateSystemd(options.systemd),
    entries,
  };
  return validateReleaseManifest(manifest);
}

export function verifyReleaseIntegrity(input) {
  const options = exactRecord(input, [
    'mode', 'releaseRoot', 'manifest', 'expectedOwnerUid', 'expectedKernelUid',
    'expectedKernelGid', 'nodePath', 'nodeVersion', 'environmentPath', 'serviceArtifactPaths',
  ], [], 'RELEASE_VERIFY_INPUT', 'release verification input');
  const manifest = validateReleaseManifest(options.manifest);
  if (options.mode !== 'deterministic' && options.mode !== 'cdp-testnet') fail('RELEASE_VERIFY_INPUT', 'release verification mode is invalid');
  if (!Number.isSafeInteger(options.expectedOwnerUid) || options.expectedOwnerUid < 0
      || (options.mode === 'cdp-testnet' && options.expectedOwnerUid !== 0)) {
    fail('RELEASE_VERIFY_INPUT', 'release verification owner is invalid');
  }
  if (manifest.kernelIdentity.uid !== options.expectedKernelUid
      || manifest.kernelIdentity.gid !== options.expectedKernelGid) {
    fail('RELEASE_IDENTITY_MISMATCH', 'runtime Kernel identity differs from the manifest');
  }
  const entries = collectEntries({
    releaseRoot: assertAbsolute(options.releaseRoot, 'release root'),
    manifestPath: path.join(options.releaseRoot, 'manifest.json'),
    expectedOwnerUid: options.expectedOwnerUid,
  });
  if (canonicalJson(entries) !== canonicalJson(manifest.entries)
      || sha256(`${TREE_DOMAIN}${canonicalJson(entries)}`) !== manifest.releaseTreeHash) {
    fail('RELEASE_TREE_CHANGED', 'installed release tree differs from its manifest');
  }
  if (options.nodeVersion !== manifest.node.version) fail('RELEASE_NODE_VERSION', 'running Node version differs from the manifest');
  const nodePath = assertAbsolute(options.nodePath, 'Node executable');
  const nodeFile = readRegularFile(nodePath, options.expectedOwnerUid, 'Node executable');
  if (sha256(`${PATH_DOMAIN}${nodePath}`) !== manifest.node.executablePathHash
      || sha256(nodeFile.bytes) !== manifest.node.executableSha256) {
    fail('RELEASE_NODE_CHANGED', 'Node executable differs from the manifest');
  }
  const environmentPath = assertAbsolute(options.environmentPath, 'environment file');
  const environmentMetadataHash = sha256(`${ENVIRONMENT_DOMAIN}${canonicalJson(
    environmentMetadata(environmentPath, options.expectedOwnerUid),
  )}`);
  if (environmentMetadataHash !== manifest.environment.environmentMetadataHash) {
    fail('RELEASE_ENVIRONMENT_CHANGED', 'environment metadata differs from the manifest');
  }
  const paths = exactRecord(options.serviceArtifactPaths, SERVICE_ROLES, [],
    'RELEASE_VERIFY_INPUT', 'service artifact paths');
  for (const artifact of manifest.serviceArtifacts) {
    const artifactPath = assertAbsolute(paths[artifact.role], `${artifact.role} path`);
    const file = readRegularFile(artifactPath, options.expectedOwnerUid, artifact.role);
    if (sha256(`${PATH_DOMAIN}${artifactPath}`) !== artifact.pathHash
        || sha256(file.bytes) !== artifact.sha256
        || file.uid !== artifact.uid || file.gid !== artifact.gid || file.mode !== artifact.mode) {
      fail('RELEASE_SERVICE_CHANGED', 'service artifact differs from the manifest');
    }
  }
  return Object.freeze({
    releaseManifestHash: sha256(canonicalJson(manifest)),
    releaseTreeHash: manifest.releaseTreeHash,
    nodeExecutableHash: manifest.node.executableSha256,
    serviceArtifactsHash: computeServiceArtifactsHash(manifest.serviceArtifacts),
    systemdEffectiveConfigHash: manifest.systemd.effectiveConfigHash,
    environmentMetadataHash,
  });
}

export function assertClosedLoaderEnvironment(environment, { allowedWalletKernelFields = [] } = {}) {
  const captured = exactRecord({ environment, allowedWalletKernelFields },
    ['environment', 'allowedWalletKernelFields'], [], 'RELEASE_ENVIRONMENT', 'loader environment input');
  if (!Array.isArray(captured.allowedWalletKernelFields)
      || captured.allowedWalletKernelFields.some((name) => typeof name !== 'string'
        || !/^WALLET_KERNEL_[A-Z0-9_]+$/.test(name))) {
    fail('RELEASE_ENVIRONMENT', 'allowed Wallet Kernel environment fields are invalid');
  }
  const allowed = new Set([...BASE_ENVIRONMENT, ...captured.allowedWalletKernelFields]);
  const result = {};
  for (const name of Reflect.ownKeys(captured.environment)) {
    if (typeof name !== 'string' || !/^[A-Z][A-Z0-9_]*$/.test(name)
        || LOADER_EXACT.has(name) || name.startsWith('LD_') || name.startsWith('DYLD_')
        || (name.startsWith('WALLET_KERNEL_') && !allowed.has(name)) || !allowed.has(name)) {
      fail('RELEASE_ENVIRONMENT', 'process environment contains an unrecognized or loader-control field');
    }
    const value = captured.environment[name];
    if (typeof value !== 'string' || value.includes('\0') || value.length > 4096) {
      fail('RELEASE_ENVIRONMENT', 'process environment contains an invalid value');
    }
    result[name] = value;
  }
  return Object.freeze(result);
}

export function captureInheritedConsoleSocket(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || Object.getPrototypeOf(input) !== Object.prototype
      || Reflect.ownKeys(input).length !== 3
      || !['env', 'processId', 'inspectDescriptor'].every((field) => Object.hasOwn(input, field))) {
    fail('SOCKET_ACTIVATION', 'socket activation input fields do not match the closed schema');
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  if (Object.values(descriptors).some((descriptor) => !descriptor.enumerable
      || !Object.hasOwn(descriptor, 'value'))) {
    fail('SOCKET_ACTIVATION', 'socket activation input must use enumerable data fields');
  }
  const options = Object.freeze({
    env: descriptors.env.value,
    processId: descriptors.processId.value,
    inspectDescriptor: descriptors.inspectDescriptor.value,
  });
  if (!Number.isSafeInteger(options.processId) || options.processId <= 0
      || typeof options.inspectDescriptor !== 'function') {
    fail('SOCKET_ACTIVATION', 'socket activation dependencies are invalid');
  }
  const env = options.env;
  if (!env || typeof env !== 'object'
      || env.LISTEN_PID !== String(options.processId)
      || env.LISTEN_FDS !== '1'
      || env.LISTEN_FDNAMES !== 'wallet-kernel-console') {
    fail('SOCKET_ACTIVATION', 'socket activation metadata is missing or inconsistent');
  }
  const details = options.inspectDescriptor(3);
  const socket = exactRecord(details, [
    'family', 'type', 'listening', 'address', 'port',
  ], ['fd'], 'SOCKET_ACTIVATION', 'inherited socket descriptor');
  if (socket.family !== 'AF_INET' || socket.type !== 'SOCK_STREAM' || socket.listening !== true
      || socket.address !== '127.0.0.1' || socket.port !== 8405
      || (Object.hasOwn(socket, 'fd') && socket.fd !== 3)) {
    fail('SOCKET_ACTIVATION', 'inherited socket does not match the reserved console socket');
  }
  delete env.LISTEN_PID;
  delete env.LISTEN_FDS;
  delete env.LISTEN_FDNAMES;
  return Object.freeze({ fd: 3, name: 'wallet-kernel-console', address: '127.0.0.1', port: 8405 });
}

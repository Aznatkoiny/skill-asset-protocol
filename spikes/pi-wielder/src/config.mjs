import fs from 'node:fs';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  KernelError,
  canonicalJson,
  exactRecord,
  frozenCopy,
} from './kernel/canonical.mjs';

export const CONTROL_PLANE_MODES = Object.freeze(['deterministic', 'cdp-testnet']);

const MODE_SET = new Set(CONTROL_PLANE_MODES);
const KNOWN_PLATFORMS = new Set([
  'aix',
  'android',
  'cygwin',
  'darwin',
  'freebsd',
  'haiku',
  'linux',
  'netbsd',
  'openbsd',
  'sunos',
  'win32',
]);

const WALLET_KERNEL_ENVIRONMENT = new Set([
  'WALLET_KERNEL_MODE',
  'WALLET_KERNEL_DB_FILE',
  'WALLET_KERNEL_RECEIPT_KEY_FILE',
  'WALLET_KERNEL_OPERATOR_TOKEN_FILE',
  'WALLET_KERNEL_TRUSTED_ANCESTOR',
  'WALLET_KERNEL_EXPECTED_AGENT_UID',
  'WALLET_KERNEL_EXPECTED_AGENT_GID',
  'WALLET_KERNEL_POLICY_FILE',
  'WALLET_KERNEL_ROUTE_FILE',
  'WALLET_KERNEL_PORT',
  'WALLET_KERNEL_OPERATOR_PORT',
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
  'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
]);

const LIVE_LOADER_KEYS = new Set([
  'NODE_OPTIONS',
  'NODE_PATH',
  'GCONV_PATH',
  'GLIBC_TUNABLES',
]);

const REQUIRED_CORE_PATHS = Object.freeze([
  'WALLET_KERNEL_DB_FILE',
  'WALLET_KERNEL_RECEIPT_KEY_FILE',
  'WALLET_KERNEL_OPERATOR_TOKEN_FILE',
  'WALLET_KERNEL_POLICY_FILE',
  'WALLET_KERNEL_ROUTE_FILE',
]);

const LIVE_PATHS = Object.freeze([
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
]);

const ROUTE_FIELDS = Object.freeze([
  'id',
  'kind',
  'method',
  'upstreamUrl',
  'resourceDescription',
  'resourceMimeType',
  'purposeLabel',
  'requestContentTypes',
  'maximumRequestBytes',
  'maximumResponseBytes',
]);
const ROUTE_KINDS = new Set(['openai-chat', 'tool']);
const MAXIMUM_ROUTES = 64;
const MAXIMUM_ROUTE_DOCUMENT_BYTES = 65_536;
const MAXIMUM_ROUTE_ID_BYTES = 64;
const MAXIMUM_ROUTE_URL_BYTES = 2_048;
const MAXIMUM_ROUTE_DESCRIPTION_BYTES = 256;
const MAXIMUM_PURPOSE_LABEL_BYTES = 64;
const MAXIMUM_REQUEST_BYTES = 262_144;
const MAXIMUM_RESPONSE_BYTES = 1_048_576;

function fail(code, message) {
  throw new KernelError(code, message);
}

function isOwnDataDescriptor(descriptor) {
  return descriptor?.enumerable === true && Object.hasOwn(descriptor, 'value');
}

function captureClosedCall(input, required, optional, code, label) {
  if (!input || typeof input !== 'object' || utilTypes.isProxy(input)
      || Array.isArray(input)
      || (Object.getPrototypeOf(input) !== Object.prototype
        && Object.getPrototypeOf(input) !== null)) {
    fail(code, `${label} must be one plain object`);
  }
  const descriptors = Object.getOwnPropertyDescriptors(input);
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(input);
  if (required.some((key) => !Object.hasOwn(descriptors, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))
      || keys.some((key) => !isOwnDataDescriptor(descriptors[key]))) {
    fail(code, `${label} fields do not match the closed schema`);
  }
  return Object.fromEntries(keys.map((key) => [key, descriptors[key].value]));
}

function captureEnvironment(env) {
  if (!env || typeof env !== 'object' || utilTypes.isProxy(env)) {
    fail('CONFIG_ENV', 'configuration environment must be an explicit non-proxy object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(env);
  const keys = Reflect.ownKeys(env);
  if (keys.some((key) => typeof key !== 'string')) {
    fail('CONFIG_ENV', 'configuration environment may contain only string keys');
  }
  for (const key of keys) {
    if (!isOwnDataDescriptor(descriptors[key])) {
      fail('CONFIG_ENV', 'configuration environment fields must be enumerable data properties');
    }
    if (key.startsWith('WALLET_KERNEL_') && !WALLET_KERNEL_ENVIRONMENT.has(key)) {
      fail('CONFIG_ENV_UNKNOWN', 'configuration environment contains an unknown WALLET_KERNEL field');
    }
  }
  return descriptors;
}

function capturedValue(descriptors, key) {
  return descriptors[key]?.value;
}

function requireString(descriptors, key, code = 'CONFIG_VALUE') {
  const value = capturedValue(descriptors, key);
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    fail(code, `${key} must be one non-empty string`);
  }
  return value;
}

function optionalString(descriptors, key) {
  const value = capturedValue(descriptors, key);
  if (value === undefined || value === '') return null;
  if (typeof value !== 'string' || value.includes('\0')) {
    fail('CONFIG_VALUE', `${key} must be one string when present`);
  }
  return value;
}

function canonicalPositiveInteger(value, label, code = 'CONFIG_IDENTITY') {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    fail(code, `${label} must be one canonical positive decimal integer`);
  }
  const number = Number(value);
  if (!Number.isSafeInteger(number) || String(number) !== value) {
    fail(code, `${label} must be one canonical positive safe integer`);
  }
  return number;
}

function injectedIdentity(value, label, { positive }) {
  if (!Number.isSafeInteger(value) || value < (positive ? 1 : 0)) {
    fail('CONFIG_IDENTITY', `${label} must be a ${positive ? 'positive' : 'non-negative'} safe integer`);
  }
  return value;
}

function port(descriptors, key, fallback) {
  const value = capturedValue(descriptors, key) ?? fallback;
  return canonicalPositiveInteger(value, key, 'CONFIG_PORT') <= 65_535
    ? Number(value)
    : fail('CONFIG_PORT', `${key} must be at most 65535`);
}

function canonicalAbsolutePath(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
      || !path.isAbsolute(value) || path.resolve(value) !== value) {
    fail('CONFIG_PATH', `${label} must be one canonical absolute path`);
  }
  if (value !== path.parse(value).root && value.endsWith(path.sep)) {
    fail('CONFIG_PATH', `${label} must not contain an empty trailing component`);
  }
  return value;
}

function isInside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === ''
    || (relative !== '..' && !path.isAbsolute(relative) && !relative.startsWith(`..${path.sep}`));
}

function statMode(stat) {
  return Number(stat.mode & 0o7777n);
}

function descriptorStat(location, expectedType, label, { metadataOnly = false } = {}) {
  let descriptor;
  try {
    if (metadataOnly) {
      // PID1 delivers the source's private contents separately with LoadCredential.
      // A Kernel UID may inspect this root-owned 0600 inode but may not open it.
      const before = fs.lstatSync(location, { bigint: true });
      const after = fs.lstatSync(location, { bigint: true });
      if (!before.isFile() || before.isSymbolicLink()
          || ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']
            .some(field => before[field] !== after[field])) {
        fail('CONFIG_PATH', `${label} metadata changed or is not a regular file`);
      }
      return Object.freeze({uid: Number(before.uid), gid: Number(before.gid),
        mode: statMode(before), nlink: Number(before.nlink)});
    }
    const directoryFlag = expectedType === 'directory' ? fs.constants.O_DIRECTORY : 0;
    descriptor = fs.openSync(
      location,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | directoryFlag,
    );
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (expectedType === 'directory' && !stat.isDirectory()) {
      fail('CONFIG_PATH', `${label} must be a directory`);
    }
    if (expectedType === 'file' && !stat.isFile()) {
      fail('CONFIG_PATH', `${label} must be a regular file`);
    }
    const pathStat = fs.lstatSync(location, { bigint: true });
    if (pathStat.isSymbolicLink() || pathStat.dev !== stat.dev || pathStat.ino !== stat.ino) {
      fail('CONFIG_PATH', `${label} may not be a symlink or change during inspection`);
    }
    return Object.freeze({
      uid: Number(stat.uid),
      gid: Number(stat.gid),
      mode: statMode(stat),
      nlink: Number(stat.nlink),
    });
  } catch (error) {
    if (error instanceof KernelError) throw error;
    const code = error?.code === 'ELOOP' || error?.code === 'ENOTDIR'
      ? 'CONFIG_PATH'
      : 'CONFIG_PATH_IO';
    fail(code, `${label} failed read-only descriptor inspection`);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function pathChain(ancestor, target) {
  if (!isInside(ancestor, target)) {
    fail('CONFIG_PATH', 'every configured live path must be beneath the trusted ancestor');
  }
  const relative = path.relative(ancestor, target);
  const chain = [ancestor];
  if (relative !== '') {
    for (const component of relative.split(path.sep)) {
      chain.push(path.join(chain.at(-1), component));
    }
  }
  return chain;
}

function inspectPath({
  value,
  label,
  trustedAncestor,
  checkoutRoot,
  mode,
  kernelUid,
  expectedAgentUid,
  type,
  requireLeaf,
  terminalOwner,
  exactTerminalMode,
  exactTerminalLinks,
  parentOwner,
  exactParentMode,
  metadataOnly = false,
  verifiedReleaseRoot = null,
}) {
  const target = canonicalAbsolutePath(value, label);
  if (target === trustedAncestor) {
    fail('CONFIG_PATH', `${label} must name a descendant below the trusted ancestor`);
  }
  const immutableReleaseRole = new Set([
    'WALLET_KERNEL_RELEASE_ROOT', 'WALLET_KERNEL_RELEASE_MANIFEST',
    'WALLET_KERNEL_POLICY_FILE', 'WALLET_KERNEL_ROUTE_FILE',
    'WALLET_KERNEL_SERVICE_DEFINITION_FILE', 'WALLET_KERNEL_SOCKET_DEFINITION_FILE',
  ]).has(label);
  if (isInside(checkoutRoot, target)
      && !(verifiedReleaseRoot && immutableReleaseRole && isInside(verifiedReleaseRoot, target))) {
    fail('CONFIG_PATH', `${label} must be outside the checkout`);
  }
  const chain = pathChain(trustedAncestor, target);
  let terminalExists = false;
  let terminalPathStat;
  try {
    terminalPathStat = fs.lstatSync(target, { bigint: true });
    if (terminalPathStat.isSymbolicLink()) {
      fail('CONFIG_PATH', `${label} may not be a symlink`);
    }
    terminalExists = true;
  } catch (error) {
    if (error instanceof KernelError) throw error;
    if (error?.code !== 'ENOENT') {
      fail('CONFIG_PATH_IO', `${label} failed read-only metadata inspection`);
    }
  }
  if (requireLeaf && !terminalExists) {
    fail('CONFIG_PATH_IO', `${label} must already exist`);
  }
  const socketPath = type === 'socket-path';
  const inspectThrough = terminalExists && !socketPath ? chain.length : chain.length - 1;
  if (inspectThrough < 1) {
    fail('CONFIG_PATH', `${label} must name a child below the trusted ancestor`);
  }

  for (let index = 0; index < inspectThrough; index += 1) {
    const location = chain[index];
    const terminal = terminalExists && index === chain.length - 1;
    const expectedType = terminal ? type : 'directory';
    const metadata = descriptorStat(location, expectedType, label, {
      metadataOnly: terminal && metadataOnly,
    });
    if ((metadata.mode & 0o022) !== 0) {
      fail('CONFIG_PATH_MODE', `${label} has a group/other-writable path component`);
    }
    if (mode === 'cdp-testnet') {
      if (![0, kernelUid, expectedAgentUid].includes(metadata.uid)) {
        fail('CONFIG_PATH_OWNER', `${label} has a path component outside the pinned identities`);
      }
      if (index === 0 && metadata.uid !== 0) {
        fail('CONFIG_PATH_OWNER', 'live trusted ancestor must be root-owned');
      }
    }
    const targetParent = index === chain.length - 2;
    if (targetParent) {
      if (parentOwner === 'kernel' && mode === 'cdp-testnet' && metadata.uid !== kernelUid) {
        fail('CONFIG_PATH_OWNER', `${label} parent must be Kernel-owned`);
      }
      if (parentOwner === 'root' && metadata.uid !== 0) {
        fail('CONFIG_PATH_OWNER', `${label} parent must be root-owned`);
      }
      if (exactParentMode !== undefined && metadata.mode !== exactParentMode) {
        fail('CONFIG_PATH_MODE', `${label} parent does not have its exact required mode`);
      }
    }
    if (terminal) {
      if (terminalOwner === 'root' && metadata.uid !== 0) {
        fail('CONFIG_PATH_OWNER', `${label} must be root-owned`);
      }
      if (terminalOwner === 'kernel' && mode === 'cdp-testnet' && metadata.uid !== kernelUid) {
        fail('CONFIG_PATH_OWNER', `${label} must be Kernel-owned`);
      }
      if (terminalOwner === 'agent' && mode === 'cdp-testnet' && metadata.uid !== expectedAgentUid) {
        fail('CONFIG_PATH_OWNER', `${label} must be agent-owned`);
      }
      if (exactTerminalMode !== undefined && metadata.mode !== exactTerminalMode) {
        fail('CONFIG_PATH_MODE', `${label} does not have its exact required mode`);
      }
      if (exactTerminalLinks !== undefined && metadata.nlink !== exactTerminalLinks) {
        fail('CONFIG_PATH', `${label} does not have its exact required link count`);
      }
    }
  }
  if (socketPath && terminalExists) {
    const metadata = {
      uid: Number(terminalPathStat.uid),
      mode: statMode(terminalPathStat),
    };
    if (!terminalPathStat.isSocket()) {
      fail('CONFIG_PATH', `${label} must be a Unix-domain socket when it exists`);
    }
    if ((metadata.mode & 0o177) !== 0) {
      fail('CONFIG_PATH_MODE', `${label} must be owner-only when it exists`);
    }
    if (mode === 'cdp-testnet' && metadata.uid !== kernelUid) {
      fail('CONFIG_PATH_OWNER', `${label} must be Kernel-owned when it exists`);
    }
  }
  return target;
}

function validateCheckoutRoot(value) {
  const checkoutRoot = canonicalAbsolutePath(value, 'checkout root');
  let real;
  try {
    real = fs.realpathSync(checkoutRoot);
  } catch {
    fail('CONFIG_PATH_IO', 'checkout root must be an existing directory');
  }
  if (real !== checkoutRoot) {
    fail('CONFIG_PATH', 'checkout root must be its canonical non-symlink path');
  }
  descriptorStat(checkoutRoot, 'directory', 'checkout root');
  return checkoutRoot;
}

function validateRpcPresence(descriptors) {
  const raw = requireString(descriptors, 'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL', 'CONFIG_RPC');
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    fail('CONFIG_RPC', 'Base Sepolia observation endpoint must be one valid HTTPS URL');
  }
  if (parsed.protocol !== 'https:' || parsed.hostname.length === 0
      || parsed.username !== '' || parsed.password !== '') {
    fail('CONFIG_RPC', 'Base Sepolia observation endpoint must be HTTPS and credential-free');
  }
  return true;
}

function validateCredentialPresence(descriptors) {
  for (const key of ['CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET']) {
    const value = capturedValue(descriptors, key);
    if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
      fail('CONFIG_CREDENTIALS', 'all three CDP credential variables must be present in cdp-testnet mode');
    }
  }
  return true;
}

function validateWalletName(descriptors) {
  const value = capturedValue(descriptors, 'CDP_WALLET_NAME');
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    fail('CONFIG_WALLET', 'CDP wallet name must be one bounded canonical public name');
  }
  return value;
}

function validateMode(value, code = 'CONFIG_MODE') {
  if (!MODE_SET.has(value)) fail(code, 'mode must be deterministic or cdp-testnet');
  return value;
}

function liveLoaderPreflight(descriptors) {
  for (const key of Object.keys(descriptors)) {
    if (LIVE_LOADER_KEYS.has(key) || key.startsWith('LD_') || key.startsWith('DYLD_')) {
      fail('CONFIG_LOADER_ENV', 'live environment contains a forbidden loader control');
    }
  }
}

function pathValue(descriptors, key, required) {
  return required
    ? requireString(descriptors, key, 'CONFIG_PATH')
    : optionalString(descriptors, key);
}

export function loadControlPlaneConfig(input) {
  const request = captureClosedCall(
    input,
    ['env', 'checkoutRoot'],
    ['uid', 'gid', 'platform', 'verifiedReleaseRoot'],
    'CONFIG_SCHEMA',
    'configuration request',
  );
  const env = request.env;
  const checkoutRootInput = request.checkoutRoot;
  const uid = request.uid === undefined
    ? (typeof process.getuid === 'function' ? process.getuid() : undefined)
    : request.uid;
  const gid = request.gid === undefined
    ? (typeof process.getgid === 'function' ? process.getgid() : undefined)
    : request.gid;
  const platform = request.platform === undefined ? process.platform : request.platform;
  const descriptors = captureEnvironment(env);
  const mode = validateMode(capturedValue(descriptors, 'WALLET_KERNEL_MODE'));
  if (!KNOWN_PLATFORMS.has(platform) || (mode === 'cdp-testnet' && platform !== 'linux')) {
    fail('CONFIG_PLATFORM', 'platform must be a known Node platform and cdp-testnet requires Linux');
  }

  const live = mode === 'cdp-testnet';
  const verifiedReleaseRoot = request.verifiedReleaseRoot === undefined ? null
    : canonicalAbsolutePath(request.verifiedReleaseRoot, 'verified release root');
  if (verifiedReleaseRoot !== null && (!live
      || verifiedReleaseRoot !== capturedValue(descriptors, 'WALLET_KERNEL_RELEASE_ROOT'))) {
    fail('CONFIG_RELEASE_BOUNDARY', 'verified release root must match the live release exactly');
  }
  const kernelUid = injectedIdentity(uid, 'Kernel UID', { positive: live });
  injectedIdentity(gid, 'Kernel GID', { positive: live });
  const expectedAgentUid = canonicalPositiveInteger(
    requireString(descriptors, 'WALLET_KERNEL_EXPECTED_AGENT_UID', 'CONFIG_IDENTITY'),
    'expected Agent UID',
  );
  const expectedAgentGid = canonicalPositiveInteger(
    requireString(descriptors, 'WALLET_KERNEL_EXPECTED_AGENT_GID', 'CONFIG_IDENTITY'),
    'expected Agent GID',
  );
  if (live && expectedAgentUid === kernelUid) {
    fail('CONFIG_IDENTITY', 'live Agent UID must differ from the Kernel UID');
  }
  if (live) liveLoaderPreflight(descriptors);

  const agentPort = port(descriptors, 'WALLET_KERNEL_PORT', '8402');
  const operatorPort = port(descriptors, 'WALLET_KERNEL_OPERATOR_PORT', '8405');
  if (agentPort === operatorPort) {
    fail('CONFIG_PORT', 'agent and operator ports must be distinct');
  }
  if (live && operatorPort !== 8405) {
    fail('CONFIG_ACTIVATION', 'live operator console requires exact socket activation on port 8405');
  }

  const checkoutRoot = validateCheckoutRoot(checkoutRootInput);
  const trustedAncestor = canonicalAbsolutePath(
    requireString(descriptors, 'WALLET_KERNEL_TRUSTED_ANCESTOR', 'CONFIG_PATH'),
    'WALLET_KERNEL_TRUSTED_ANCESTOR',
  );
  if (isInside(checkoutRoot, trustedAncestor)) {
    fail('CONFIG_PATH', 'trusted ancestor must be outside the checkout');
  }
  const trustedMetadata = descriptorStat(
    trustedAncestor,
    'directory',
    'WALLET_KERNEL_TRUSTED_ANCESTOR',
  );
  if ((trustedMetadata.mode & 0o022) !== 0) {
    fail('CONFIG_PATH_MODE', 'trusted ancestor may not be group/other writable, including sticky roots');
  }
  if (live && trustedMetadata.uid !== 0) {
    fail('CONFIG_PATH_OWNER', 'live trusted ancestor must be root-owned');
  }

  const rawPaths = Object.fromEntries(REQUIRED_CORE_PATHS.map((key) => [
    key,
    pathValue(descriptors, key, true),
  ]));
  for (const key of LIVE_PATHS) {
    rawPaths[key] = pathValue(descriptors, key, live);
  }

  const common = {
    trustedAncestor,
    checkoutRoot,
    mode,
    kernelUid,
    expectedAgentUid,
    verifiedReleaseRoot,
  };
  const inspect = (key, options) => {
    const value = rawPaths[key];
    if (value === null) return null;
    return inspectPath({ value, label: key, ...common, ...options });
  };

  const databasePath = inspect('WALLET_KERNEL_DB_FILE', {
    type: 'file', requireLeaf: false, terminalOwner: 'kernel', exactTerminalMode: 0o600,
  });
  const receiptKeyPath = inspect('WALLET_KERNEL_RECEIPT_KEY_FILE', {
    type: 'file', requireLeaf: false, terminalOwner: 'kernel', exactTerminalMode: 0o600,
  });
  const operatorTokenPath = inspect('WALLET_KERNEL_OPERATOR_TOKEN_FILE', {
    type: 'file', requireLeaf: false, terminalOwner: 'kernel', exactTerminalMode: 0o600,
  });
  const policyPath = inspect('WALLET_KERNEL_POLICY_FILE', {
    type: 'file', requireLeaf: true,
    terminalOwner: live ? 'root' : undefined,
    exactTerminalLinks: live ? 1 : undefined,
  });
  const routePath = inspect('WALLET_KERNEL_ROUTE_FILE', {
    type: 'file', requireLeaf: true,
    terminalOwner: live ? 'root' : undefined,
    exactTerminalLinks: live ? 1 : undefined,
  });
  const operatorSocketPath = inspect('WALLET_KERNEL_OPERATOR_SOCKET_FILE', {
    type: 'socket-path',
    requireLeaf: false,
    parentOwner: live ? 'kernel' : undefined,
    exactParentMode: live ? 0o700 : undefined,
  });
  const enrollmentInboxPath = inspect('WALLET_KERNEL_ENROLLMENT_INBOX', {
    type: 'directory', requireLeaf: live, exactTerminalMode: live ? 0o755 : undefined,
  });
  const agentRunOutboxPath = inspect('WALLET_KERNEL_AGENT_RUN_OUTBOX', {
    type: 'directory', requireLeaf: live, exactTerminalMode: live ? 0o755 : undefined,
  });
  const releaseRoot = inspect('WALLET_KERNEL_RELEASE_ROOT', {
    type: 'directory', requireLeaf: live, terminalOwner: live ? 'root' : undefined,
  });
  const releaseManifestPath = inspect('WALLET_KERNEL_RELEASE_MANIFEST', {
    type: 'file', requireLeaf: live, terminalOwner: live ? 'root' : undefined,
  });
  const serviceDefinitionPath = inspect('WALLET_KERNEL_SERVICE_DEFINITION_FILE', {
    type: 'file', requireLeaf: live, terminalOwner: live ? 'root' : undefined,
  });
  const socketDefinitionPath = inspect('WALLET_KERNEL_SOCKET_DEFINITION_FILE', {
    type: 'file', requireLeaf: live, terminalOwner: live ? 'root' : undefined,
  });
  const environmentFilePath = inspect('WALLET_KERNEL_ENV_FILE', {
    type: 'file', requireLeaf: live, terminalOwner: live ? 'root' : undefined,
    metadataOnly: true,
  });
  const evidenceRoot = inspect('WALLET_KERNEL_EVIDENCE_ROOT', {
    type: 'directory', requireLeaf: live,
  });
  const isolationReportPath = inspect('WALLET_KERNEL_ISOLATION_REPORT_FILE', {
    // Recovery-only startup has no enrolled Agent to attest. Enrolled admission
    // must subsequently read this report and match the authoritative stored row.
    type: 'file', requireLeaf: false, exactTerminalMode: live ? 0o600 : undefined,
  });

  if (live && (!isInside(releaseRoot, policyPath) || policyPath === releaseRoot
      || !isInside(releaseRoot, routePath) || routePath === releaseRoot)) {
    fail(
      'CONFIG_RELEASE_BOUNDARY',
      'live PolicyVersion seed and route authority must be files inside the verified release root',
    );
  }

  const configuredPaths = [
    databasePath,
    receiptKeyPath,
    operatorTokenPath,
    policyPath,
    routePath,
    operatorSocketPath,
    enrollmentInboxPath,
    agentRunOutboxPath,
    releaseRoot,
    releaseManifestPath,
    serviceDefinitionPath,
    socketDefinitionPath,
    environmentFilePath,
    evidenceRoot,
    isolationReportPath,
  ].filter((value) => value !== null);
  if (new Set(configuredPaths).size !== configuredPaths.length) {
    fail('CONFIG_PATH_COLLISION', 'configured filesystem roles must use distinct paths');
  }

  let cdpWalletName = null;
  let credentialsPresent = false;
  if (live) {
    credentialsPresent = validateCredentialPresence(descriptors);
    cdpWalletName = validateWalletName(descriptors);
    validateRpcPresence(descriptors);
  }
  const assertCredentialPresence = Object.freeze(function assertCredentialPresence() {
    if (live && !credentialsPresent) {
      fail('CONFIG_CREDENTIALS', 'all three CDP credential variables must be present in cdp-testnet mode');
    }
    return undefined;
  });

  const publicConfig = Object.freeze({
    mode,
    agentHost: '127.0.0.1',
    agentPort,
    operatorAdminTransport: live ? 'unix' : 'loopback-demo',
    operatorSocketPath: live ? operatorSocketPath : null,
    operatorConsoleTransport: live ? 'socket-activated-loopback' : 'loopback-demo',
    operatorConsoleActivationName: live ? 'wallet-kernel-console' : null,
    operatorHost: '127.0.0.1',
    operatorPort,
    databasePath,
    policyPath,
    routePath,
    receiptKeyPath,
    operatorTokenPath,
    enrollmentInboxPath,
    agentRunOutboxPath,
    trustedAncestor: live ? trustedAncestor : null,
    releaseRoot: live ? releaseRoot : null,
    releaseManifestPath: live ? releaseManifestPath : null,
    serviceDefinitionPath: live ? serviceDefinitionPath : null,
    socketDefinitionPath: live ? socketDefinitionPath : null,
    environmentFilePath: live ? environmentFilePath : null,
    evidenceRoot: live ? evidenceRoot : null,
    isolationReportPath: live ? isolationReportPath : null,
    expectedAgentUid,
    expectedAgentGid,
    cdpWalletName,
    network: 'eip155:84532',
    observer: live ? 'base-sepolia-read-only' : 'deterministic',
  });
  return Object.freeze({ publicConfig, assertCredentialPresence });
}

export function readBoundedRouteDocument(filePath) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath || filePath.includes('\0')) {
    fail('ROUTE_FILE', 'route document path must be one canonical absolute path');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(
      filePath,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
    );
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size < 1n
        || before.size > BigInt(MAXIMUM_ROUTE_DOCUMENT_BYTES)) {
      fail('ROUTE_FILE', 'route document must be one bounded single-link regular file');
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of [
      'dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs',
    ]) {
      if (before[field] !== after[field]) {
        fail('ROUTE_FILE', 'route document changed while it was being read');
      }
    }
    if (BigInt(bytes.length) !== before.size) {
      fail('ROUTE_FILE', 'route document length changed while it was being read');
    }
    try {
      return JSON.parse(bytes.toString('utf8'));
    } catch {
      fail('ROUTE_FILE', 'route document is not valid JSON');
    }
  } catch (error) {
    if (error instanceof KernelError) throw error;
    fail('ROUTE_FILE', 'route document failed descriptor-safe reading');
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function canonicalRouteUrl(value, mode) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > MAXIMUM_ROUTE_URL_BYTES
      || value.includes('?') || value.includes('#')) {
    fail('ROUTE_URL', 'route upstream URL must be bounded, queryless, and fragment-free');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('ROUTE_URL', 'route upstream URL must be absolute');
  }
  if (parsed.toString() !== value || parsed.username !== '' || parsed.password !== ''
      || parsed.pathname.length === 0 || parsed.pathname.startsWith('//')
      || /%2f|%5c/i.test(parsed.pathname) || parsed.pathname.includes('\\')) {
    fail('ROUTE_URL', 'route upstream URL must be canonical and credential-free');
  }
  if (parsed.protocol === 'https:') return value;
  const literalLoopback = parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
  if (mode !== 'deterministic' || parsed.protocol !== 'http:' || !literalLoopback) {
    fail('ROUTE_URL', 'route upstream URL must be HTTPS or deterministic literal loopback HTTP');
  }
  return value;
}

function validateRouteId(value) {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') > MAXIMUM_ROUTE_ID_BYTES
      || !/^[a-z0-9][a-z0-9._-]*$/.test(value)) {
    fail('ROUTE_ID', 'route ID must be one bounded canonical lower-case token');
  }
  return value;
}

function boundedPublicText(value, maximumBytes, label) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > maximumBytes
      || /[\u0000-\u001f\u007f]/u.test(value)
      || value.trim() !== value) {
    fail('ROUTE_METADATA', `${label} must be bounded public text`);
  }
  return value;
}

function boundedRouteBytes(value, maximum, label) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail('ROUTE_BYTES', `${label} must be a positive safe integer within the hard ceiling`);
  }
  return value;
}

export function validateRouteMap(input) {
  const request = exactRecord(
    input,
    ['document', 'mode'],
    [],
    'ROUTE_SCHEMA',
    'route-map validation request',
  );
  const { document, mode } = request;
  validateMode(mode, 'ROUTE_MODE');
  let captured;
  try {
    captured = exactRecord(
      document,
      ['schemaVersion', 'routes'],
      [],
      'ROUTE_SCHEMA',
      'route map',
    );
  } catch (error) {
    if (error instanceof KernelError && error.code === 'ROUTE_SCHEMA') throw error;
    throw new KernelError('ROUTE_SCHEMA', 'route map must contain only closed canonical data');
  }
  if (captured.schemaVersion !== 1 || !Array.isArray(captured.routes)
      || captured.routes.length < 1) {
    fail('ROUTE_SCHEMA', 'route map must have schemaVersion 1 and at least one route');
  }
  if (captured.routes.length > MAXIMUM_ROUTES) {
    fail('ROUTE_LIMIT', 'route map exceeds the maximum route count');
  }
  const ids = new Set();
  const normalized = captured.routes.map((input, index) => {
    const entry = exactRecord(
      input,
      ROUTE_FIELDS,
      [],
      'ROUTE_SCHEMA',
      `route ${index}`,
    );
    const id = validateRouteId(entry.id);
    if (ids.has(id)) fail('ROUTE_DUPLICATE', 'route IDs must be unique');
    ids.add(id);
    if (!ROUTE_KINDS.has(entry.kind)) {
      fail('ROUTE_KIND', 'route kind must be openai-chat or tool');
    }
    if (entry.method !== 'POST') fail('ROUTE_METHOD', 'route method must be exact POST');
    if (entry.resourceMimeType !== 'application/json'
        || !Array.isArray(entry.requestContentTypes)
        || entry.requestContentTypes.length !== 1
        || entry.requestContentTypes[0] !== 'application/json') {
      fail('ROUTE_CONTENT_TYPE', 'route content types must be exact application/json');
    }
    const purposeLabel = boundedPublicText(
      entry.purposeLabel,
      MAXIMUM_PURPOSE_LABEL_BYTES,
      'route purpose label',
    );
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(purposeLabel)) {
      fail('ROUTE_METADATA', 'route purpose label must be one canonical token');
    }
    return frozenCopy({
      id,
      kind: entry.kind,
      method: entry.method,
      upstreamUrl: canonicalRouteUrl(entry.upstreamUrl, mode),
      resourceDescription: boundedPublicText(
        entry.resourceDescription,
        MAXIMUM_ROUTE_DESCRIPTION_BYTES,
        'route resource description',
      ),
      resourceMimeType: entry.resourceMimeType,
      purposeLabel,
      requestContentTypes: ['application/json'],
      maximumRequestBytes: boundedRouteBytes(
        entry.maximumRequestBytes,
        MAXIMUM_REQUEST_BYTES,
        'route maximum request bytes',
      ),
      maximumResponseBytes: boundedRouteBytes(
        entry.maximumResponseBytes,
        MAXIMUM_RESPONSE_BYTES,
        'route maximum response bytes',
      ),
    });
  });

  try {
    const normalizedDocument = { schemaVersion: 1, routes: normalized };
    if (Buffer.byteLength(canonicalJson(normalizedDocument), 'utf8')
        > MAXIMUM_ROUTE_DOCUMENT_BYTES) {
      fail('ROUTE_LIMIT', 'route map exceeds the canonical document byte ceiling');
    }
  } catch (error) {
    if (error instanceof KernelError && error.code === 'ROUTE_LIMIT') throw error;
    fail('ROUTE_SCHEMA', 'route map must contain only canonical JSON data');
  }

  const byId = new Map(normalized.map((entry) => [entry.id, entry]));
  const get = Object.freeze(function get(routeId) {
    if (arguments.length !== 1) {
      fail('ROUTE_LOOKUP', 'route lookup accepts exactly one route ID');
    }
    if (typeof routeId !== 'string') return null;
    return byId.get(routeId) ?? null;
  });
  return Object.freeze({
    schemaVersion: 1,
    routes: Object.freeze(normalized),
    get,
  });
}

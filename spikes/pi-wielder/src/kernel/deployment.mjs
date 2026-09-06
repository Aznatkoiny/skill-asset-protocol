import fs from 'node:fs';
import path from 'node:path';
import { canonicalJson, exactRecord, frozenCopy, KernelError } from './canonical.mjs';
import { hashIsolationMetadata, validateIsolationMetadata } from '../agent/isolation-preflight.mjs';

const RENDER_FIELDS = Object.freeze([
  'schemaVersion', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid', 'releaseRoot',
  'nodePath', 'environmentPath', 'authorityRoot', 'evidenceRoot', 'runtimeRoot',
  'agentRunOutboxPath', 'enrollmentInboxPath', 'serviceOutputPath', 'socketOutputPath',
]);
const FIELDS = Object.freeze([...RENDER_FIELDS, 'commit', 'trustedAncestor',
  'databasePath', 'receiptKeyPath', 'operatorTokenPath', 'isolationReportPath',
  'agentCredentialPath', 'policyPath', 'routePath', 'operatorSocketPath']);
const IDENTITIES = ['kernelUid', 'kernelGid', 'agentUid', 'agentGid'];
const PATH_FIELDS = FIELDS.filter((key) => !['schemaVersion', 'commit', ...IDENTITIES].includes(key));

function fail(message) { throw new KernelError('DEPLOYMENT_CONFIG', message); }
function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === '' || (!path.isAbsolute(relative) && relative !== '..'
    && !relative.startsWith(`..${path.sep}`));
}

export function validateDeploymentConfig(value) {
  const config = exactRecord(value, FIELDS, ['executionProfile'], 'DEPLOYMENT_CONFIG', 'public deployment');
  if (config.schemaVersion !== 1 || !/^[0-9a-f]{40}$/.test(config.commit)) fail('invalid deployment version or commit');
  if (config.executionProfile !== undefined
      && !['cdp-testnet', 'offline-qualification'].includes(config.executionProfile)) {
    fail('unsupported installed execution profile');
  }
  for (const field of IDENTITIES) {
    if (typeof config[field] !== 'string' || !/^[1-9][0-9]*$/.test(config[field])
        || !Number.isSafeInteger(Number(config[field]))) fail('deployment identities must be positive numeric text');
  }
  if (config.kernelUid === config.agentUid || config.kernelGid === config.agentGid) fail('installed Kernel and Agent UIDs and GIDs must differ');
  for (const field of PATH_FIELDS) {
    const value = config[field];
    if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value
        || /[\s\0'"`$;&|<>\\]/.test(value)) fail('deployment paths must be canonical absolute tokens');
  }
  if (path.basename(config.releaseRoot) !== config.commit) fail('release path must be addressed by its full commit');
  const roots = ['releaseRoot', 'authorityRoot', 'evidenceRoot', 'runtimeRoot',
    'agentRunOutboxPath', 'enrollmentInboxPath'].map((name) => config[name]);
  for (let i = 0; i < roots.length; i += 1) {
    if (!inside(config.trustedAncestor, roots[i]) || roots[i] === config.trustedAncestor) {
      fail('deployment roots must be below the trusted ancestor');
    }
    if (roots.some((other, j) => i !== j && inside(roots[i], other))) fail('deployment roots must be disjoint');
  }
  for (const field of ['databasePath', 'receiptKeyPath', 'operatorTokenPath']) {
    if (path.dirname(config[field]) !== config.authorityRoot) fail('authority files must be direct children of the authority root');
  }
  if (path.dirname(config.operatorSocketPath) !== config.runtimeRoot
      || path.dirname(config.isolationReportPath) !== config.runtimeRoot) fail('runtime files must be in the runtime root');
  for (const field of ['policyPath', 'routePath']) {
    if (!inside(config.releaseRoot, config[field]) || config[field] === config.releaseRoot) fail('policy and routes must belong to the immutable release');
  }
  for (const field of ['environmentPath', 'serviceOutputPath', 'socketOutputPath', 'agentCredentialPath']) {
    if (roots.some((root) => inside(root, config[field]))) fail('environment, unit artifacts, and Agent credentials need separate paths');
    if (!inside(config.trustedAncestor, config[field])) fail('deployment files must be below the trusted ancestor');
  }
  if (path.dirname(config.serviceOutputPath) !== path.dirname(config.socketOutputPath)
      || config.serviceOutputPath === config.socketOutputPath
      || new Set(['databasePath', 'receiptKeyPath', 'operatorTokenPath', 'policyPath', 'routePath',
        'operatorSocketPath', 'isolationReportPath', 'environmentPath', 'agentCredentialPath']
        .map((key) => config[key])).size !== 9) fail('deployment file roles must be distinct');
  return frozenCopy(config);
}

export function deploymentRendererInput(value) {
  const config = validateDeploymentConfig(value);
  return Object.freeze({ ...Object.fromEntries(RENDER_FIELDS.map((field) => [field, config[field]])),
    ...(config.executionProfile === undefined ? {} : { executionProfile: config.executionProfile }) });
}

// Selection is sealed into deployment.json and the release manifest. Neither an
// environment variable nor command-line input selects a qualification adapter.
export function isInstalledQualificationRelease(releaseRoot) {
  try {
    const config = readDeploymentConfig(path.join(releaseRoot, 'deployment.json'));
    return config.releaseRoot === releaseRoot && config.executionProfile === 'offline-qualification';
  } catch { return false; }
}

export function readDeploymentConfig(filePath, { expectedOwnerUid = 0 } = {}) {
  if (typeof filePath !== 'string' || path.resolve(filePath) !== filePath
      || path.basename(filePath) !== 'deployment.json') fail('expected an absolute deployment.json path');
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedOwnerUid)
        || (before.mode & 0o022n) !== 0n || before.size < 1n || before.size > 32_768n) fail('deployment input must be one immutable bounded file');
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ['dev', 'ino', 'uid', 'gid', 'mode', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[field] !== after[field]) fail('deployment input changed while being read');
    }
    const config = validateDeploymentConfig(JSON.parse(bytes.toString('utf8')));
    if (!bytes.equals(Buffer.from(`${canonicalJson(config)}\n`))
        || path.dirname(filePath) !== config.releaseRoot) fail('deployment input must be canonical and inside its release');
    return config;
  } finally { fs.closeSync(descriptor); }
}

function privateProjection(root, leaf, role, uid) {
  const item = (location, depth, label, directory) => {
    const stat = fs.lstatSync(location, { bigint: true });
    if (stat.isSymbolicLink() || (directory ? !stat.isDirectory() : !stat.isFile())
        || stat.uid !== BigInt(uid) || (stat.mode & 0o7777n) !== (directory ? 0o700n : 0o600n)
        || (!directory && stat.nlink !== 1n)) fail('private path metadata does not match the assigned identity');
    return { role: label, depth, device: stat.dev.toString(), inode: stat.ino.toString(),
      uid: Number(stat.uid), gid: Number(stat.gid), mode: Number(stat.mode & 0o7777n) };
  };
  return { role, chain: [item(root, 0, `${role}-parent`, true)],
    leaf: item(leaf, 1, `${role}-file`, false) };
}

export function captureDeploymentIsolationMetadata(value) {
  const config = validateDeploymentConfig(value);
  const credentialRoot = path.dirname(config.agentCredentialPath);
  return validateIsolationMetadata({
    kernelUid: Number(config.kernelUid), kernelGid: Number(config.kernelGid),
    agentUid: Number(config.agentUid), agentGid: Number(config.agentGid),
    authority: privateProjection(config.authorityRoot, config.databasePath, 'authority', config.kernelUid),
    credential: privateProjection(credentialRoot, config.agentCredentialPath, 'credential', config.agentUid),
    authorityInsideCredential: inside(credentialRoot, config.authorityRoot),
    credentialInsideAuthority: inside(config.authorityRoot, credentialRoot),
  });
}

export function captureDeploymentAuthorityMetadata(value) {
  const config = validateDeploymentConfig(value);
  return hashIsolationMetadata(privateProjection(
    config.authorityRoot, config.databasePath, 'authority', config.kernelUid,
  ));
}

export function assertRuntimeDeploymentBindings(value, publicConfig) {
  const deployment = validateDeploymentConfig(value);
  const mapping = {
    databasePath: 'databasePath', receiptKeyPath: 'receiptKeyPath', operatorTokenPath: 'operatorTokenPath',
    policyPath: 'policyPath', routePath: 'routePath', operatorSocketPath: 'operatorSocketPath',
    enrollmentInboxPath: 'enrollmentInboxPath', agentRunOutboxPath: 'agentRunOutboxPath',
    trustedAncestor: 'trustedAncestor', releaseRoot: 'releaseRoot', environmentFilePath: 'environmentPath',
    evidenceRoot: 'evidenceRoot', isolationReportPath: 'isolationReportPath',
    serviceDefinitionPath: 'serviceOutputPath', socketDefinitionPath: 'socketOutputPath',
  };
  if (publicConfig.mode !== 'cdp-testnet' || publicConfig.releaseManifestPath !== path.join(deployment.releaseRoot, 'manifest.json')
      || publicConfig.expectedAgentUid !== Number(deployment.agentUid)
      || publicConfig.expectedAgentGid !== Number(deployment.agentGid)) fail('runtime identity differs from public deployment');
  for (const [field, source] of Object.entries(mapping)) {
    if (publicConfig[field] !== deployment[source]) fail('runtime paths differ from public deployment');
  }
  return deployment;
}

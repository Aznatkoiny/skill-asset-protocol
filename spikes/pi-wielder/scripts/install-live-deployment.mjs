#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, exactRecord, frozenCopy, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { deploymentRendererInput, readDeploymentConfig, validateDeploymentConfig } from '../src/kernel/deployment.mjs';
import { buildReleaseManifest, verifyReleaseIntegrity } from '../src/kernel/release-integrity.mjs';
import { writeReleaseManifestExclusive } from './build-release-manifest.mjs';
import { inspectEffectiveSystemd, parseSystemctlShow } from './inspect-systemd-effective.mjs';
import { renderSystemdUnits } from './render-systemd-units.mjs';

const SERVICE = 'wallet-kernel.service';
const SOCKET = 'wallet-kernel-console.socket';
const PACKAGE_PREFIX = 'spikes/pi-wielder/';
const REQUIRED_SOURCE_FILES = Object.freeze([
  'package.json', 'package-lock.json', 'src/control-plane.mjs',
  'src/kernel/canonical.mjs', 'src/kernel/deployment.mjs', 'src/kernel/release-integrity.mjs',
  'scripts/install-live-deployment.mjs', 'scripts/preflight-live-deployment.mjs',
  'scripts/cleanup-live-deployment.mjs',
  'scripts/render-systemd-units.mjs', 'scripts/inspect-systemd-effective.mjs', 'scripts/build-release-manifest.mjs',
  'deploy/systemd/wallet-kernel.service', 'deploy/systemd/wallet-kernel-console.socket',
]);
const MAXIMUM_FILES = 100_000;
const MAXIMUM_FILE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_SOURCE_BYTES = 256 * 1024 * 1024;
const GIT_OPTIONS = Object.freeze([
  '--no-optional-locks', '--no-replace-objects', '-c', 'core.hooksPath=/dev/null', '-c', 'core.fsmonitor=false',
  '-c', 'core.pager=cat', '-c', 'core.untrackedCache=false',
]);

function fail(code, message, cause) {
  throw new KernelError(code, message, cause ? { cause } : undefined);
}

function absolute(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value
      || /[\s\0'"`$;&|<>\\]/.test(value)) fail('LIVE_INSTALL_PATH', `${label} must be a canonical absolute path`);
  return value;
}

function relative(value) {
  if (typeof value !== 'string' || !value || path.posix.normalize(value) !== value
      || value.startsWith('/') || value.split('/').includes('..') || /[\x00-\x1f\x7f\\]/.test(value)) {
    fail('LIVE_INSTALL_SOURCE', 'source paths must be canonical repository-relative paths');
  }
  return value;
}

function immutableStat(location, expectedOwnerUid, { directory = false } = {}) {
  const stat = fs.lstatSync(location, { bigint: true });
  if (stat.uid !== BigInt(expectedOwnerUid)
      || (!stat.isSymbolicLink() && (stat.mode & 0o7022n) !== 0n)
      || (directory && (!stat.isDirectory() || stat.isSymbolicLink()))) {
    fail('LIVE_INSTALL_OWNERSHIP', 'installation paths must be direct and immutable to other identities');
  }
  return stat;
}

function immutableChain(location, trustedAncestor, expectedOwnerUid) {
  const anchor = expectedOwnerUid === 0 ? path.parse(location).root : trustedAncestor;
  const tail = path.relative(anchor, location);
  if (tail === '..' || tail.startsWith(`..${path.sep}`) || path.isAbsolute(tail)) {
    fail('LIVE_INSTALL_PATH', 'installation path is outside its trusted ancestor');
  }
  let current = anchor;
  immutableStat(current, expectedOwnerUid, { directory: true });
  for (const part of tail.split(path.sep).filter(Boolean)) {
    current = path.join(current, part);
    immutableStat(current, expectedOwnerUid, { directory: true });
  }
}

function readBoundedFile(location, expectedOwnerUid, maximumBytes = MAXIMUM_FILE_BYTES) {
  const descriptor = fs.openSync(location, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(expectedOwnerUid)
        || (before.mode & 0o7022n) !== 0n || before.size > BigInt(maximumBytes)) {
      fail('LIVE_INSTALL_FILE', 'installation input must be a bounded immutable single-link file');
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    for (const field of ['dev', 'ino', 'uid', 'gid', 'mode', 'size', 'mtimeNs', 'ctimeNs']) {
      if (before[field] !== after[field]) fail('LIVE_INSTALL_CHANGED', 'installation input changed while reading');
    }
    return { bytes, mode: Number(before.mode & 0o7777n) };
  } finally { fs.closeSync(descriptor); }
}

function assertAbsent(location) {
  try { fs.lstatSync(location); } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  fail('LIVE_INSTALL_EXISTS', 'installation artifacts already exist; installation never overwrites them');
}

function assertFixedBinary(location) {
  immutableChain(path.dirname(location), '/', 0);
  const stat = immutableStat(location, 0);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1n
      || (stat.mode & 0o111n) === 0n) fail('LIVE_INSTALL_BINARY', 'host utility must be an immutable root-owned executable');
}

function gitRead(sourceCheckoutPath, args) {
  assertFixedBinary('/usr/bin/git');
  return execFileSync('/usr/bin/git', [...GIT_OPTIONS, '-C', sourceCheckoutPath, ...args], {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 16 * 1024 * 1024,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C',
      GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0',
      GIT_NO_LAZY_FETCH: '1', GIT_ALLOW_PROTOCOL: '' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function gitRows(output, kind) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > 16 * 1024 * 1024
      || !output.endsWith('\0')) fail('LIVE_INSTALL_SOURCE', 'Git records must be bounded NUL-terminated text');
  const rows = new Map();
  const expression = kind === 'tree'
    ? /^(100644|100755|120000) blob ([0-9a-f]{40})\t(.+)$/s
    : /^(100644|100755|120000) ([0-9a-f]{40}) 0\t(.+)$/s;
  for (const row of output.slice(0, -1).split('\0')) {
    const match = expression.exec(row);
    if (!match) fail('LIVE_INSTALL_SOURCE', 'Git source must contain ordinary files and in-tree links, without submodules or conflicts');
    const name = relative(match[3]);
    if (rows.has(name) || rows.size >= MAXIMUM_FILES) fail('LIVE_INSTALL_SOURCE', 'Git source contains duplicate or excessive records');
    rows.set(name, { mode: match[1], object: match[2] });
  }
  return rows;
}

function blobHash(bytes) {
  return crypto.createHash('sha1').update(`blob ${bytes.length}\0`).update(bytes).digest('hex');
}

function committedBytes(root, name, entry, expectedOwnerUid) {
  const location = path.join(root, name);
  immutableChain(path.dirname(location), root, expectedOwnerUid);
  const stat = immutableStat(location, expectedOwnerUid);
  let bytes;
  let target = null;
  if (entry.mode === '120000') {
    if (!stat.isSymbolicLink()) fail('LIVE_INSTALL_SOURCE', 'committed symlink type differs from prepared input');
    const rawTarget = fs.readlinkSync(location);
    const resolved = fs.realpathSync(location);
    if (!resolved.startsWith(`${root}${path.sep}`)) fail('LIVE_INSTALL_SOURCE', 'source link escapes its tree');
    target = path.relative(root, path.resolve(path.dirname(location), rawTarget)).split(path.sep).join('/');
    relative(target);
    bytes = Buffer.from(rawTarget);
  } else {
    const file = readBoundedFile(location, expectedOwnerUid);
    if (file.mode !== (entry.mode === '100755' ? 0o755 : 0o644)) {
      fail('LIVE_INSTALL_SOURCE', 'source file mode differs from its committed mode');
    }
    bytes = file.bytes;
  }
  if (blobHash(bytes) !== entry.object) fail('LIVE_INSTALL_SOURCE', 'prepared source bytes differ from the committed object');
  return { byteLength: bytes.length, kind: target === null ? 'file' : 'symlink',
    mode: (Number(stat.mode) & 0o7777).toString(8), sha256: target === null ? sha256(bytes) : null, target };
}

function verifyGitMetadata(sourceCheckoutPath, expectedOwnerUid) {
  const gitRoot = path.join(sourceCheckoutPath, '.git');
  immutableStat(gitRoot, expectedOwnerUid, { directory: true });
  let count = 0;
  const walk = (directory) => {
    for (const name of fs.readdirSync(directory)) {
      if (++count > MAXIMUM_FILES) fail('LIVE_INSTALL_SOURCE', 'Git metadata inventory is too large');
      const location = path.join(directory, name);
      const stat = immutableStat(location, expectedOwnerUid);
      if (stat.isDirectory()) walk(location);
      else if (!stat.isFile() || stat.nlink !== 1n) fail('LIVE_INSTALL_SOURCE', 'Git metadata must be direct single-link files');
    }
  };
  walk(gitRoot);
  const gitConfig = readBoundedFile(path.join(gitRoot, 'config'), expectedOwnerUid, 64 * 1024).bytes.toString('utf8');
  // Full standalone clones only: no includes, filters, alternate worktrees,
  // replace refs, or partial-clone transports. Root never fetches source objects.
  if (/^\s*\[\s*(?:include(?:if)?|filter|extensions)(?:\s|\])/im.test(gitConfig)
      || /^\s*(?:promisor|partialclonefilter|worktree)\s*=/im.test(gitConfig)) {
    fail('LIVE_INSTALL_SOURCE', 'source Git configuration must be self-contained without executable helpers');
  }
  for (const name of ['commondir', 'config.worktree', 'objects/info/alternates', 'objects/info/http-alternates', 'refs/replace']) {
    if (fs.existsSync(path.join(gitRoot, name))) fail('LIVE_INSTALL_SOURCE', 'source Git metadata must be self-contained');
  }
}

function readJson(location, expectedOwnerUid) {
  try { return JSON.parse(readBoundedFile(location, expectedOwnerUid, 4 * 1024 * 1024).bytes.toString('utf8')); }
  catch (cause) { fail('LIVE_INSTALL_LOCK', 'locked package metadata is invalid', cause); }
}

function verifyLockedPackages(releaseRoot, expectedOwnerUid) {
  const lock = readJson(path.join(releaseRoot, 'package-lock.json'), expectedOwnerUid);
  const installed = readJson(path.join(releaseRoot, 'node_modules/.package-lock.json'), expectedOwnerUid);
  const pkg = readJson(path.join(releaseRoot, 'package.json'), expectedOwnerUid);
  if (lock.lockfileVersion !== 3 || installed.lockfileVersion !== 3
      || !lock.packages || !installed.packages || !lock.packages['']) {
    fail('LIVE_INSTALL_LOCK', 'a v3 source lock and installed-package lock are required');
  }
  for (const field of ['name', 'version', 'dependencies', 'devDependencies', 'optionalDependencies']) {
    if (canonicalJson(pkg[field] ?? null) !== canonicalJson(lock.packages[''][field] ?? null)) {
      fail('LIVE_INSTALL_LOCK', 'package metadata differs from the committed dependency lock');
    }
  }
  const installedNames = Object.keys(installed.packages);
  if (installedNames.length > MAXIMUM_FILES) fail('LIVE_INSTALL_LOCK', 'installed dependency inventory is too large');
  for (const name of installedNames) {
    relative(name);
    const expected = lock.packages[name];
    const actual = installed.packages[name];
    if (!name.startsWith('node_modules/') || !expected || expected.link || actual?.link
        || !actual || ['version', 'resolved', 'integrity'].some((field) => actual[field] !== expected[field])) {
      fail('LIVE_INSTALL_LOCK', 'installed dependency differs from the committed lock');
    }
    immutableStat(path.join(releaseRoot, name), expectedOwnerUid, { directory: true });
    const packageJson = readJson(path.join(releaseRoot, name, 'package.json'), expectedOwnerUid);
    const expectedName = expected.name ?? name.split('node_modules/').at(-1);
    if (packageJson.name !== expectedName || packageJson.version !== expected.version) {
      fail('LIVE_INSTALL_LOCK', 'installed package identity differs from the committed lock');
    }
  }
  for (const [name, metadata] of Object.entries(lock.packages)) {
    if (name && !Object.hasOwn(installed.packages, name) && metadata.optional !== true) {
      fail('LIVE_INSTALL_LOCK', 'a required locked dependency is missing');
    }
  }
  const inspectModules = (directory, prefix = 'node_modules') => {
    for (const name of fs.readdirSync(directory)) {
      if (name === '.bin' || (prefix === 'node_modules' && name === '.package-lock.json')) continue;
      const candidates = name.startsWith('@')
        ? fs.readdirSync(path.join(directory, name)).map((child) => `${name}/${child}`) : [name];
      for (const candidate of candidates) {
        const entry = `${prefix}/${candidate}`;
        if (!Object.hasOwn(installed.packages, entry)) fail('LIVE_INSTALL_LOCK', 'unlocked package exists in the installed dependency tree');
        const nested = path.join(directory, candidate, 'node_modules');
        if (fs.existsSync(nested)) inspectModules(nested, `${entry}/node_modules`);
      }
    }
  };
  inspectModules(path.join(releaseRoot, 'node_modules'));
  return installedNames.length;
}

// This verifies a prepared snapshot. It neither runs npm nor claims to have
// reproduced registry tarballs: the privileged preparer supplies the installed
// dependency bytes, which the release manifest subsequently hashes in full.
export function verifyPreparedRelease({ config: value, sourceCheckoutPath }, {
  expectedOwnerUid = 0, runGit = gitRead,
} = {}) {
  const config = validateDeploymentConfig(value);
  absolute(sourceCheckoutPath, 'source checkout');
  if (!Number.isSafeInteger(expectedOwnerUid) || expectedOwnerUid < 0) fail('LIVE_INSTALL_INPUT', 'invalid expected owner');
  immutableChain(config.releaseRoot, config.trustedAncestor, expectedOwnerUid);
  immutableChain(sourceCheckoutPath, config.trustedAncestor, expectedOwnerUid);
  verifyGitMetadata(sourceCheckoutPath, expectedOwnerUid);
  assertAbsent(path.join(config.releaseRoot, 'manifest.json'));
  const head = () => runGit(sourceCheckoutPath, ['rev-parse', '--verify', 'HEAD^{commit}']).trim();
  if (head() !== config.commit) fail('LIVE_INSTALL_SOURCE', 'clean source HEAD must equal the configured release commit');
  const tree = gitRows(runGit(sourceCheckoutPath, ['ls-tree', '-r', '-z', '--full-tree', config.commit]), 'tree');
  const index = gitRows(runGit(sourceCheckoutPath, ['ls-files', '--stage', '-z']), 'index');
  if (canonicalJson([...tree]) !== canonicalJson([...index])
      || runGit(sourceCheckoutPath, ['ls-files', '--others', '--exclude-standard', '-z']) !== '') {
    fail('LIVE_INSTALL_SOURCE', 'source index and working tree must be clean');
  }
  let sourceBytes = 0;
  const packageFiles = new Set();
  const sourceEntries = [];
  for (const [name, entry] of tree) {
    sourceBytes += committedBytes(sourceCheckoutPath, name, entry, expectedOwnerUid).byteLength;
    if (sourceBytes > MAXIMUM_SOURCE_BYTES) fail('LIVE_INSTALL_SOURCE', 'source verification byte limit exceeded');
    if (name.startsWith(PACKAGE_PREFIX)) {
      const packageName = name.slice(PACKAGE_PREFIX.length);
      const { byteLength, ...projection } = committedBytes(config.releaseRoot, packageName, entry, expectedOwnerUid);
      sourceEntries.push({ path: packageName, ...projection });
      packageFiles.add(packageName);
    }
  }
  if (!REQUIRED_SOURCE_FILES.every((name) => packageFiles.has(name))) {
    fail('LIVE_INSTALL_SOURCE', 'committed Wallet Kernel package and privileged installer graph must be complete');
  }
  const publicFiles = new Set(['deployment.json',
    path.relative(config.releaseRoot, config.policyPath).split(path.sep).join('/'),
    path.relative(config.releaseRoot, config.routePath).split(path.sep).join('/')]);
  let visited = 0;
  const walk = (directory, prefix = '') => {
    for (const name of fs.readdirSync(directory)) {
      if (++visited > MAXIMUM_FILES) fail('LIVE_INSTALL_SOURCE', 'prepared tree exceeds file limit');
      const entry = relative(prefix ? `${prefix}/${name}` : name);
      const location = path.join(directory, name);
      const stat = immutableStat(location, expectedOwnerUid);
      if (stat.isDirectory()) walk(location, entry);
      else if (stat.isFile() || stat.isSymbolicLink()) {
        if (stat.isFile() && stat.nlink !== 1n) fail('LIVE_INSTALL_FILE', 'prepared files must have one link');
        if (stat.isSymbolicLink() && !fs.realpathSync(location).startsWith(`${config.releaseRoot}${path.sep}`)) {
          fail('LIVE_INSTALL_SOURCE', 'prepared link escapes the release');
        }
        if (!packageFiles.has(entry) && !publicFiles.has(entry) && !entry.startsWith('node_modules/')) {
          fail('LIVE_INSTALL_SOURCE', 'prepared release contains uncommitted executable or data files');
        }
      } else fail('LIVE_INSTALL_FILE', 'prepared release contains a special file');
    }
  };
  walk(config.releaseRoot);
  const installedPackages = verifyLockedPackages(config.releaseRoot, expectedOwnerUid);
  if (head() !== config.commit) fail('LIVE_INSTALL_CHANGED', 'source HEAD changed during verification');
  return frozenCopy({ commit: config.commit, sourceFiles: packageFiles.size, sourceEntries,
    publicFiles: [...publicFiles], installedPackages,
    packageLockHash: sha256(readBoundedFile(path.join(config.releaseRoot, 'package-lock.json'), expectedOwnerUid).bytes),
    installedLockHash: sha256(readBoundedFile(path.join(config.releaseRoot, 'node_modules/.package-lock.json'), expectedOwnerUid).bytes) });
}

function bindManifestProvenance(manifest, provenance, config) {
  const entries = new Map(manifest.entries.map((entry) => [entry.path, entry]));
  for (const expected of provenance.sourceEntries) {
    const entry = entries.get(expected.path);
    if (!entry || ['kind', 'mode', 'sha256', 'target'].some((field) => entry[field] !== expected[field])) {
      fail('LIVE_INSTALL_CHANGED', 'source changed after committed provenance verification');
    }
  }
  const permitted = new Set([...provenance.sourceEntries.map((entry) => entry.path), ...provenance.publicFiles]);
  for (const entry of manifest.entries) {
    if (entry.kind !== 'directory' && !permitted.has(entry.path) && !entry.path.startsWith('node_modules/')) {
      fail('LIVE_INSTALL_CHANGED', 'uncommitted source appeared after provenance verification');
    }
  }
  if (manifest.packageLockHash !== provenance.packageLockHash
      || entries.get('node_modules/.package-lock.json')?.sha256 !== provenance.installedLockHash
      || entries.get('deployment.json')?.sha256 !== sha256(`${canonicalJson(config)}\n`)) {
    fail('LIVE_INSTALL_CHANGED', 'dependency or deployment bindings changed after provenance verification');
  }
}

export function assertLiveInstallHost() {
  if (process.platform !== 'linux' || process.getuid?.() !== 0 || process.version !== 'v24.18.1') {
    fail('LIVE_INSTALL_HOST', 'installation requires root on Linux with exact Node v24.18.1');
  }
  assertFixedBinary(process.execPath);
  immutableChain('/etc/systemd/system', '/', 0);
  return { nodePath: process.execPath, nodeVersion: process.version, unitDirectory: '/etc/systemd/system',
    installerPath: fileURLToPath(import.meta.url) };
}

function systemctl(args) {
  const allowed = [
    ['daemon-reload'], ['enable', SOCKET], ['stop', SERVICE], ['stop', SOCKET], ['disable', SOCKET],
    ['show', '--all', '--no-pager', '--property=ActiveState', SERVICE],
    ['show', '--all', '--no-pager', '--property=ActiveState', SOCKET],
  ];
  if (!allowed.some((candidate) => canonicalJson(candidate) === canonicalJson(args))) {
    fail('LIVE_INSTALL_COMMAND', 'systemctl command is outside the installer contract');
  }
  assertFixedBinary('/usr/bin/systemctl');
  return execFileSync('/usr/bin/systemctl', args, {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 64 * 1024,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
}

async function requireInactive(runSystemctl) {
  for (const unit of [SERVICE, SOCKET]) {
    const output = await runSystemctl(['show', '--all', '--no-pager', '--property=ActiveState', unit]);
    if (parseSystemctlShow(output, ['ActiveState']).ActiveState !== 'inactive') {
      fail('LIVE_INSTALL_ACTIVE', 'installation requires both service and socket to remain inactive');
    }
  }
}

function publicCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,100}$/.test(error.code)
    ? error.code : 'LIVE_INSTALL_FAILED';
}

// Effects are an in-process test seam, never selectable through CLI or environment.
// An injected result is always labeled simulated and never host qualification.
export async function installLiveDeployment(input, injectedEffects) {
  const options = exactRecord(input, ['deploymentPath', 'sourceCheckoutPath'], [], 'LIVE_INSTALL_INPUT', 'installer input');
  const defaults = { assertHost: assertLiveInstallHost, readConfig: readDeploymentConfig,
    verifyPrepared: verifyPreparedRelease, render: renderSystemdUnits, systemctl,
    inspect: inspectEffectiveSystemd, build: buildReleaseManifest,
    write: writeReleaseManifestExclusive, verify: verifyReleaseIntegrity,
    now: () => new Date().toISOString() };
  if (injectedEffects !== undefined && (injectedEffects === null || typeof injectedEffects !== 'object'
      || Reflect.ownKeys(injectedEffects).some((name) => !Object.hasOwn(defaults, name)
        || typeof injectedEffects[name] !== 'function'))) fail('LIVE_INSTALL_INPUT', 'invalid installer effects');
  const effects = { ...defaults, ...injectedEffects };
  const host = effects.assertHost();
  const unitDirectory = absolute(host.unitDirectory, 'host systemd unit directory');
  const sourceCheckoutPath = absolute(options.sourceCheckoutPath, 'source checkout');
  const config = validateDeploymentConfig(effects.readConfig(absolute(options.deploymentPath, 'deployment config')));
  if (options.deploymentPath !== path.join(config.releaseRoot, 'deployment.json')
      || host.nodePath !== config.nodePath || host.nodeVersion !== 'v24.18.1'
      || config.serviceOutputPath !== path.join(unitDirectory, SERVICE)
      || config.socketOutputPath !== path.join(unitDirectory, SOCKET)
      || ![path.join(config.releaseRoot, 'scripts/install-live-deployment.mjs'),
        path.join(sourceCheckoutPath, PACKAGE_PREFIX, 'scripts/install-live-deployment.mjs')].includes(host.installerPath)) {
    fail('LIVE_INSTALL_INPUT', 'deployment bindings differ from the runtime, source graph, or fixed systemd unit directory');
  }
  const provenance = effects.verifyPrepared({ config, sourceCheckoutPath });
  assertAbsent(config.serviceOutputPath);
  assertAbsent(config.socketOutputPath);
  await requireInactive(effects.systemctl);
  let enablementAttempted = false;
  try {
    const rendered = effects.render({ ...deploymentRendererInput(config), install: true, expectedOwnerUid: 0 });
    await effects.systemctl(['daemon-reload']);
    // A failed enable command can still have created links before failing.
    enablementAttempted = true;
    await effects.systemctl(['enable', SOCKET]);
    const observed = await effects.inspect({ expected: rendered.expectedEffectiveConfig });
    if (observed.platform !== 'linux') fail('LIVE_INSTALL_SYSTEMD', 'effective systemd observation must come from Linux');
    const systemd = Object.fromEntries(['managerVersion', 'systemctlVersion',
      'systemctlExecutablePathHash', 'systemctlExecutableSha256', 'effectiveConfigHash']
      .map((field) => [field, observed[field]]));
    const manifestPath = path.join(config.releaseRoot, 'manifest.json');
    const manifest = effects.build({ mode: 'cdp-testnet', releaseRoot: config.releaseRoot,
      manifestPath, commit: config.commit, createdAt: effects.now(), kernelUid: config.kernelUid,
      kernelGid: config.kernelGid, node: { path: config.nodePath, version: host.nodeVersion },
      environmentPath: config.environmentPath, serviceArtifacts: [
        { role: 'kernel-service', path: config.serviceOutputPath },
        { role: 'console-socket', path: config.socketOutputPath },
      ], systemd, expectedOwnerUid: 0 });
    bindManifestProvenance(manifest, provenance, config);
    effects.write({ manifestPath, manifest });
    const verified = effects.verify({ mode: 'cdp-testnet', releaseRoot: config.releaseRoot, manifest,
      expectedOwnerUid: 0, expectedKernelUid: config.kernelUid, expectedKernelGid: config.kernelGid,
      nodePath: config.nodePath, nodeVersion: host.nodeVersion, environmentPath: config.environmentPath,
      serviceArtifactPaths: { 'kernel-service': config.serviceOutputPath, 'console-socket': config.socketOutputPath } });
    await requireInactive(effects.systemctl);
    return frozenCopy({ schemaVersion: 1, status: 'sealed_not_started',
      execution: injectedEffects === undefined ? 'installed' : 'simulated',
      qualification: 'not_performed', started: false, commit: config.commit,
      releaseManifestHash: verified.releaseManifestHash, releaseTreeHash: verified.releaseTreeHash });
  } catch (cause) {
    const cleanup = [];
    if (enablementAttempted) {
      for (const args of [['stop', SERVICE], ['stop', SOCKET], ['disable', SOCKET]]) {
        try { await effects.systemctl(args); cleanup.push({ action: args.join(' '), status: 'attempt_succeeded' }); }
        catch (error) { cleanup.push({ action: args.join(' '), status: 'attempt_failed', code: publicCode(error) }); }
      }
    }
    const error = new KernelError(publicCode(cause), 'live installation failed; no start was requested', { cause });
    error.cleanup = frozenCopy(cleanup);
    throw error;
  }
}

export async function runInstallLiveDeployment({ argv, stdout = process.stdout, stderr = process.stderr }) {
  try {
    if (!Array.isArray(argv) || argv.length !== 4 || argv[0] !== '--deployment' || argv[2] !== '--source-checkout') {
      fail('LIVE_INSTALL_ARGUMENTS', 'expected --deployment ABSOLUTE_JSON --source-checkout ABSOLUTE_REPOSITORY');
    }
    const result = await installLiveDeployment({ deploymentPath: argv[1], sourceCheckoutPath: argv[3] });
    stdout.write(`${canonicalJson(result)}\n`);
    return 0;
  } catch (error) {
    stderr.write(`${canonicalJson({ code: publicCode(error), cleanup: error.cleanup ?? [] })}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runInstallLiveDeployment({ argv: process.argv.slice(2) });
}

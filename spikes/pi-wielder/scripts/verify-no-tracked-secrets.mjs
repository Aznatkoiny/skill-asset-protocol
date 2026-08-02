#!/usr/bin/env node

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';

const MAXIMUM_TRACKED_FILE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_SECRET_FILE_BYTES = 256 * 1024;
const SECRET_NAME = /(?:SECRET|TOKEN|PASSWORD|PASSPHRASE|PRIVATE_KEY|API_KEY|CREDENTIAL)/i;
const NON_VALUE_NAME = /(?:_FILE|_PATH|_DIRECTORY|_DIR|_ROOT|_URL|_ENDPOINT)$/i;
const PRIVATE_KEY_ENCODING = /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,262144}-----END (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/;
const CONTEXTUAL_HEX_PRIVATE_KEY = /(?:private[_-]?key|wallet[_-]?secret)[^\r\n]{0,64}(?:0x)?[0-9a-fA-F]{64}/i;
const SECRET_FILE_ENVIRONMENT = Object.freeze([
  ['WALLET_KERNEL_RECEIPT_KEY_FILE', 'WALLET_KERNEL_RECEIPT_KEY_FILE'],
  ['WALLET_KERNEL_OPERATOR_TOKEN_FILE', 'WALLET_KERNEL_OPERATOR_TOKEN_FILE'],
]);

class SecretScanError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'SecretScanError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new SecretScanError(code, message, cause ? { cause } : undefined);
}

function parseArguments(argv) {
  if (!Array.isArray(argv)) fail('SECRET_SCAN_ARGUMENTS', 'arguments must be one array');
  if (argv.length === 0) return Object.freeze({ agentCredential: null });
  if (argv.length !== 2 || argv[0] !== '--agent-credential'
      || typeof argv[1] !== 'string' || argv[1].length === 0) {
    fail('SECRET_SCAN_ARGUMENTS', 'usage: verify-no-tracked-secrets.mjs [--agent-credential FILE]');
  }
  if (!path.isAbsolute(argv[1]) || path.resolve(argv[1]) !== argv[1]) {
    fail('SECRET_SCAN_ARGUMENTS', 'agent credential path must be canonical and absolute');
  }
  return Object.freeze({ agentCredential: argv[1] });
}

function gitTrackedPaths(cwd) {
  const result = spawnSync('git', ['ls-files', '-z'], {
    cwd,
    encoding: null,
    maxBuffer: 16 * 1024 * 1024,
    env: { PATH: process.env.PATH ?? '' },
  });
  if (result.status !== 0 || !Buffer.isBuffer(result.stdout)) {
    fail('SECRET_SCAN_GIT', 'git ls-files -z failed');
  }
  const bytes = result.stdout;
  if (bytes.length === 0) return [];
  if (bytes.at(-1) !== 0) fail('SECRET_SCAN_GIT', 'git ls-files output was not NUL terminated');
  const paths = bytes.subarray(0, -1).toString('utf8').split('\0');
  if (paths.some((item) => item.length === 0 || item.includes('\0') || path.isAbsolute(item)
      || item.split(/[\\/]/).includes('..'))) {
    fail('SECRET_SCAN_GIT', 'git returned a noncanonical tracked path');
  }
  return paths;
}

function gitRepositoryRoot(cwd) {
  const result = spawnSync('git', ['rev-parse', '--show-toplevel'], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 4096,
    env: { PATH: process.env.PATH ?? '' },
  });
  if (result.status !== 0 || typeof result.stdout !== 'string'
      || !result.stdout.endsWith('\n') || result.stdout.slice(0, -1).includes('\n')
      || result.stdout.includes('\0')) {
    fail('SECRET_SCAN_GIT', 'git repository root discovery failed');
  }
  const root = result.stdout.slice(0, -1);
  if (!path.isAbsolute(root) || path.resolve(root) !== root) {
    fail('SECRET_SCAN_GIT', 'git repository root is not canonical');
  }
  let actual;
  try { actual = fs.realpathSync(root); } catch (cause) {
    fail('SECRET_SCAN_GIT', 'git repository root does not exist', cause);
  }
  if (actual !== root || !fs.lstatSync(root).isDirectory()) {
    fail('SECRET_SCAN_GIT', 'git repository root is not one direct directory');
  }
  return root;
}

function trackedFilenameIsSecret(relativePath) {
  const basename = path.posix.basename(relativePath.replaceAll('\\', '/')).toLowerCase();
  if (basename.startsWith('.env') && !/(?:example|sample|template)$/.test(basename)) return true;
  if (/\.(?:pem|key|p12|pfx|sqlite|sqlite3|db)$/.test(basename)) return true;
  return /^(?:operator[-_.]?token|receipt[-_.]?key|agent[-_.]?credential|local[-_.]?enrollment)(?:\.(?:json|txt|secret|token|key|pem))?$/.test(basename)
    || /^(?:kernel|authority|wallet-kernel)(?:[-_.][a-z0-9-]+)*\.(?:sqlite|sqlite3|db)$/.test(basename);
}

function readTrackedBytes(cwd, relativePath) {
  const destination = path.resolve(cwd, relativePath);
  const prefix = `${path.resolve(cwd)}${path.sep}`;
  if (!destination.startsWith(prefix)) fail('SECRET_SCAN_PATH', 'tracked path escaped the repository');
  let stat;
  try { stat = fs.lstatSync(destination); } catch (cause) {
    fail('SECRET_SCAN_PATH', `tracked path could not be inspected: ${relativePath}`, cause);
  }
  if (stat.isSymbolicLink()) {
    return Buffer.from(fs.readlinkSync(destination), 'utf8');
  }
  if (!stat.isFile() || stat.size > MAXIMUM_TRACKED_FILE_BYTES) {
    fail('SECRET_SCAN_PATH', `tracked path is not a bounded regular file: ${relativePath}`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(destination, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (!before.isFile() || before.nlink !== 1 || before.size !== bytes.length
        || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
      fail('SECRET_SCAN_PATH', `tracked path changed while read: ${relativePath}`);
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof SecretScanError) throw cause;
    fail('SECRET_SCAN_PATH', `tracked path could not be read safely: ${relativePath}`, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function readOwnerOnlySecret(filePath, label) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath || filePath.includes('\0')) {
    fail('SECRET_SCAN_AUTHORITY', `${label} must be one canonical absolute path`);
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    const before = fs.fstatSync(descriptor);
    const currentUid = typeof process.getuid === 'function' ? process.getuid() : before.uid;
    if (!before.isFile() || before.nlink !== 1 || before.uid !== currentUid
        || (before.mode & 0o777) !== 0o600 || before.size < 8
        || before.size > MAXIMUM_SECRET_FILE_BYTES) {
      fail('SECRET_SCAN_AUTHORITY', `${label} is not an owner-only bounded regular file`);
    }
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor);
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size) {
      fail('SECRET_SCAN_AUTHORITY', `${label} changed while read`);
    }
    return bytes;
  } catch (cause) {
    if (cause instanceof SecretScanError) throw cause;
    fail('SECRET_SCAN_AUTHORITY', `${label} could not be read safely`, cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
}

function candidateVariants(bytes) {
  const variants = [Buffer.from(bytes)];
  if (bytes.at(-1) === 0x0a) {
    const withoutLf = bytes.subarray(0, -1);
    const trimmed = withoutLf.at(-1) === 0x0d ? withoutLf.subarray(0, -1) : withoutLf;
    if (trimmed.length >= 8) variants.push(Buffer.from(trimmed));
  }
  const unique = new Map(variants.filter((item) => item.length >= 8)
    .map((item) => [item.toString('base64'), item]));
  return [...unique.values()];
}

function environmentCandidates(environment) {
  const candidates = [];
  for (const name of Object.keys(environment).sort()) {
    const value = environment[name];
    if (!SECRET_NAME.test(name) || NON_VALUE_NAME.test(name)
        || typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 8) continue;
    candidates.push({ name, values: [Buffer.from(value, 'utf8')] });
  }
  return candidates;
}

function fileCandidates(environment, agentCredential) {
  const candidates = [];
  for (const [name, environmentName] of SECRET_FILE_ENVIRONMENT) {
    const configured = environment[environmentName];
    if (configured === undefined || configured === '') continue;
    candidates.push({
      name,
      values: candidateVariants(readOwnerOnlySecret(configured, name)),
    });
  }
  if (agentCredential !== null) {
    candidates.push({
      name: 'AGENT_CREDENTIAL_FILE',
      values: candidateVariants(readOwnerOnlySecret(agentCredential, 'AGENT_CREDENTIAL_FILE')),
    });
  }
  return candidates;
}

function scanPrivateKeyEncoding(bytes) {
  const text = bytes.toString('utf8');
  return PRIVATE_KEY_ENCODING.test(text) || CONTEXTUAL_HEX_PRIVATE_KEY.test(text);
}

export function scanTrackedSecrets({ cwd, environment, agentCredential = null }) {
  if (typeof cwd !== 'string' || !path.isAbsolute(cwd)
      || !environment || typeof environment !== 'object' || Array.isArray(environment)) {
    fail('SECRET_SCAN_INPUT', 'secret scan requires an absolute repository and explicit environment');
  }
  const trackedPaths = gitTrackedPaths(cwd);
  const tracked = trackedPaths.map((relativePath) => ({
    path: relativePath,
    bytes: readTrackedBytes(cwd, relativePath),
  }));
  const findings = [];
  for (const file of tracked) {
    if (trackedFilenameIsSecret(file.path)) {
      findings.push({ name: 'TRACKED_SECRET_FILENAME', path: file.path });
    }
    if (scanPrivateKeyEncoding(file.bytes)) {
      findings.push({ name: 'PRIVATE_KEY_ENCODING', path: file.path });
    }
  }
  const candidates = [
    ...environmentCandidates(environment),
    ...fileCandidates(environment, agentCredential),
  ];
  for (const candidate of candidates) {
    for (const file of tracked) {
      if (candidate.values.some((value) => file.bytes.indexOf(value) !== -1)) {
        findings.push({ name: candidate.name, path: file.path });
      }
    }
  }
  const unique = [...new Map(findings.map((finding) => [
    `${finding.name}\0${finding.path}`,
    finding,
  ])).values()].sort((left, right) => left.name.localeCompare(right.name)
    || left.path.localeCompare(right.path));
  return Object.freeze({ scannedFiles: tracked.length, findings: Object.freeze(unique) });
}

export function main(argv = process.argv.slice(2)) {
  let options;
  try {
    options = parseArguments(argv);
    const repositoryRoot = gitRepositoryRoot(fs.realpathSync(process.cwd()));
    const result = scanTrackedSecrets({
      cwd: repositoryRoot,
      environment: process.env,
      agentCredential: options.agentCredential,
    });
    if (result.findings.length === 0) {
      process.stdout.write(`${canonicalJson({ scannedFiles: result.scannedFiles, valid: true })}\n`);
      return 0;
    }
    for (const finding of result.findings) {
      process.stderr.write(`${canonicalJson(finding)}\n`);
    }
    return 1;
  } catch (error) {
    const code = error instanceof SecretScanError ? error.code : 'SECRET_SCAN_INTERNAL';
    process.stderr.write(`${canonicalJson({ valid: false, code })}\n`);
    return 2;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) process.exitCode = main();

#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { exactRecord, frozenCopy, KernelError, sha256 } from '../src/kernel/canonical.mjs';

const SERVICE_TEMPLATE = fileURLToPath(new URL('../deploy/systemd/wallet-kernel.service', import.meta.url));
const SOCKET_TEMPLATE = fileURLToPath(new URL('../deploy/systemd/wallet-kernel-console.socket', import.meta.url));
const POSITIVE = /^[1-9][0-9]*$/;
const INPUT_FIELDS = Object.freeze([
  'schemaVersion', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid', 'releaseRoot',
  'nodePath', 'environmentPath', 'authorityRoot', 'evidenceRoot', 'runtimeRoot',
  'agentRunOutboxPath', 'enrollmentInboxPath', 'serviceOutputPath', 'socketOutputPath',
]);

function fail(code, message, cause) {
  throw new KernelError(code, message, cause ? { cause } : undefined);
}

function identity(value, label) {
  if (typeof value !== 'string' || !POSITIVE.test(value)
      || !Number.isSafeInteger(Number(value)) || String(Number(value)) !== value) {
    fail('SYSTEMD_RENDER_IDENTITY', `${label} must be canonical positive numeric text`);
  }
  return value;
}

function absoluteToken(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || path.resolve(value) !== value
      || /[\s\0'"`$;&|<>\\]/.test(value)) {
    fail('SYSTEMD_RENDER_PATH', `${label} must be one canonical absolute systemd token`);
  }
  return value;
}

function assertDirectPath(value, label, { directory = false, regular = false } = {}) {
  absoluteToken(value, label);
  let stat;
  try {
    stat = fs.lstatSync(value);
  } catch (cause) {
    fail('SYSTEMD_RENDER_PATH', `${label} must already exist`, cause);
  }
  if (stat.isSymbolicLink() || (directory && !stat.isDirectory()) || (regular && !stat.isFile())) {
    fail('SYSTEMD_RENDER_PATH', `${label} has the wrong filesystem type`);
  }
  return value;
}

function closedInput(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    fail('SYSTEMD_RENDER_INPUT', 'systemd render input must be one plain object');
  }
  const allowed = new Set([...INPUT_FIELDS, 'install', 'expectedOwnerUid', 'executionProfile']);
  const keys = Reflect.ownKeys(value);
  if (INPUT_FIELDS.some((field) => !Object.hasOwn(value, field))
      || keys.some((field) => typeof field !== 'string' || !allowed.has(field))) {
    fail('SYSTEMD_RENDER_INPUT', 'systemd render input fields do not match the closed schema');
  }
  const base = exactRecord(Object.fromEntries(INPUT_FIELDS.map((field) => [field, value[field]])),
    INPUT_FIELDS, [], 'SYSTEMD_RENDER_INPUT', 'systemd render input');
  if (Object.hasOwn(value, 'executionProfile') && !['cdp-testnet', 'offline-qualification'].includes(value.executionProfile)) {
    fail('SYSTEMD_RENDER_INPUT', 'execution profile must be absent, cdp-testnet, or offline-qualification');
  }
  return Object.freeze({
    ...base,
    ...(value.executionProfile === 'offline-qualification' ? { executionProfile: value.executionProfile } : {}),
    install: value.install === undefined ? false : value.install,
    expectedOwnerUid: value.expectedOwnerUid === undefined ? 0 : value.expectedOwnerUid,
  });
}

function substitute(template, replacements) {
  let output = template;
  for (const [marker, value] of Object.entries(replacements)) {
    output = output.replaceAll(`{{${marker}}}`, value);
  }
  if (/\{\{[A-Z0-9_]+\}\}/.test(output)) {
    fail('SYSTEMD_RENDER_TEMPLATE', 'systemd template contains an unresolved marker');
  }
  return Buffer.from(output, 'utf8');
}

function exclusiveInstall(filePath, bytes, expectedOwnerUid) {
  const parent = path.dirname(filePath);
  const parentStat = fs.lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()
      || parentStat.uid !== expectedOwnerUid || (parentStat.mode & 0o022) !== 0) {
    fail('SYSTEMD_INSTALL_PATH', 'unit install parent must be expected-owner and immutable to group/other');
  }
  let descriptor;
  try {
    descriptor = fs.openSync(filePath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o644);
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } catch (cause) {
    fail('SYSTEMD_INSTALL_FAILED', 'unit output already exists or could not be installed', cause);
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
  }
  const directory = fs.openSync(parent, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

export function renderSystemdUnits(value) {
  const input = closedInput(value);
  if (input.schemaVersion !== 1 || typeof input.install !== 'boolean'
      || !Number.isSafeInteger(input.expectedOwnerUid) || input.expectedOwnerUid < 0) {
    fail('SYSTEMD_RENDER_INPUT', 'systemd render input values are invalid');
  }
  for (const [field, label] of [
    ['kernelUid', 'Kernel UID'], ['kernelGid', 'Kernel GID'],
    ['agentUid', 'Agent UID'], ['agentGid', 'Agent GID'],
  ]) identity(input[field], label);
  if (input.kernelUid === input.agentUid) fail('SYSTEMD_RENDER_IDENTITY', 'Kernel and Agent UIDs must differ');
  assertDirectPath(input.releaseRoot, 'release root', { directory: true });
  if (path.basename(input.releaseRoot) === 'current') {
    fail('SYSTEMD_RENDER_PATH', 'release root must be immutable and version-addressed');
  }
  assertDirectPath(input.nodePath, 'Node executable', { regular: true });
  assertDirectPath(input.environmentPath, 'environment file', { regular: true });
  // Only the Kernel parses PID1's delivered credential copy. The privileged
  // renderer checks source-file metadata and never loads secret values.
  const environmentStat = fs.lstatSync(input.environmentPath);
  if (environmentStat.nlink !== 1 || (environmentStat.mode & 0o7777) !== 0o600
      || environmentStat.size > 64 * 1024) {
    fail('SYSTEMD_RENDER_ENVIRONMENT', 'Kernel environment source must be a bounded single-link 0600 file');
  }
  for (const field of [
    'authorityRoot', 'evidenceRoot', 'runtimeRoot', 'agentRunOutboxPath', 'enrollmentInboxPath',
  ]) assertDirectPath(input[field], field, { directory: true });
  for (const field of ['serviceOutputPath', 'socketOutputPath']) {
    absoluteToken(input[field], field);
    assertDirectPath(path.dirname(input[field]), `${field} parent`, { directory: true });
  }
  const directional = [input.authorityRoot, input.evidenceRoot, input.runtimeRoot,
    input.agentRunOutboxPath, input.enrollmentInboxPath];
  if (new Set(directional).size !== directional.length
      || directional.some((candidate) => candidate === input.releaseRoot
        || candidate.startsWith(`${input.releaseRoot}${path.sep}`))) {
    fail('SYSTEMD_RENDER_PATH', 'writable and directional roots must be distinct and outside the release');
  }
  const replacements = {
    KERNEL_UID: input.kernelUid, KERNEL_GID: input.kernelGid,
    RELEASE_ROOT: input.releaseRoot, NODE_PATH: input.nodePath,
    ENVIRONMENT_PATH: input.environmentPath, AUTHORITY_ROOT: input.authorityRoot,
    EVIDENCE_ROOT: input.evidenceRoot, RUNTIME_ROOT: input.runtimeRoot,
    AGENT_RUN_OUTBOX_PATH: input.agentRunOutboxPath,
    EXECUTION_PROFILE: input.executionProfile === 'offline-qualification'
      ? 'IPAddressDeny=any\nIPAddressAllow=localhost' : '',
  };
  const serviceBytes = substitute(fs.readFileSync(SERVICE_TEMPLATE, 'utf8'), replacements);
  const socketBytes = substitute(fs.readFileSync(SOCKET_TEMPLATE, 'utf8'), replacements);
  if (input.install) {
    exclusiveInstall(input.serviceOutputPath, serviceBytes, input.expectedOwnerUid);
    try {
      exclusiveInstall(input.socketOutputPath, socketBytes, input.expectedOwnerUid);
    } catch (cause) {
      // The first file remains visible and auditable; privileged install cleanup owns removal.
      throw cause;
    }
  }
  const expectedEffectiveConfig = frozenCopy({
    kernelUid: input.kernelUid, kernelGid: input.kernelGid,
    releaseRoot: input.releaseRoot, nodePath: input.nodePath,
    environmentPath: input.environmentPath,
    servicePath: input.serviceOutputPath, socketPath: input.socketOutputPath,
    readWritePaths: [input.authorityRoot, input.evidenceRoot, input.runtimeRoot,
      input.agentRunOutboxPath],
    ...(input.executionProfile ? { executionProfile: input.executionProfile } : {}),
  });
  return Object.freeze({
    serviceBytes, socketBytes,
    service: Object.freeze({ path: input.serviceOutputPath, sha256: sha256(serviceBytes) }),
    socket: Object.freeze({ path: input.socketOutputPath, sha256: sha256(socketBytes) }),
    expectedEffectiveConfig,
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write('render-systemd-units.mjs is a library entrypoint; invoke it through the privileged installer\n');
  process.exitCode = 2;
}

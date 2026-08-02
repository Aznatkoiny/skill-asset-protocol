#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const PROTECTED_READ_FIELDS = Object.freeze([
  'authorityDirectory', 'database', 'operatorToken', 'receiptKey', 'kernelEnvironment',
]);
const WRITE_FIELDS = Object.freeze([
  'releaseTreeWrite', 'dependencyTreeWrite', 'serviceArtifactsWrite',
  'kernelEnvironmentParentWrite',
]);

function fail(message) { throw new Error(message); }

function positive(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)
      || !Number.isSafeInteger(Number(value)) || String(Number(value)) !== value) {
    fail(`${label} is invalid`);
  }
  return Number(value);
}

export function dropToAgentIdentity({ uid, gid, processApi = process }) {
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0) {
    fail('Agent identity is invalid');
  }
  processApi.setgroups([]);
  processApi.setgid(gid);
  processApi.setuid(uid);
  if (processApi.getuid() !== uid || processApi.geteuid?.() !== uid
      || processApi.getgid() !== gid || processApi.getegid?.() !== gid
      || processApi.getgroups().some((group) => group !== gid)) {
    fail('Agent identity drop did not remove privilege and supplementary groups');
  }
}

function denialCode(operation) {
  try {
    operation();
    return 'UNEXPECTED_SUCCESS';
  } catch (error) {
    return error?.code === 'EPERM' ? 'EPERM' : error?.code === 'EACCES' ? 'EACCES' : 'UNEXPECTED_ERROR';
  }
}

function readProbe(target) {
  let descriptor;
  try {
    descriptor = fs.openSync(target, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    fs.readSync(descriptor, Buffer.alloc(1), 0, 1, 0);
    return 'READABLE';
  } catch (error) {
    if (error?.code === 'EPERM') return 'EPERM';
    if (error?.code === 'EACCES') return 'EACCES';
    return 'UNEXPECTED_ERROR';
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}

export function runProbeRequest(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)
      || Reflect.ownKeys(request).length !== 3
      || !['credentialPath', 'protectedReadPaths', 'writePaths'].every((key) => Object.hasOwn(request, key))) {
    fail('isolation worker request fields are invalid');
  }
  if (typeof request.credentialPath !== 'string' || !path.isAbsolute(request.credentialPath)) {
    fail('credential path is invalid');
  }
  const protectedPaths = request.protectedReadPaths;
  const writePaths = request.writePaths;
  if (!protectedPaths || !writePaths || typeof protectedPaths !== 'object'
      || typeof writePaths !== 'object'
      || Reflect.ownKeys(protectedPaths).length !== PROTECTED_READ_FIELDS.length
      || Reflect.ownKeys(writePaths).length !== WRITE_FIELDS.length) {
    fail('isolation worker probe maps are invalid');
  }
  const result = {};
  for (const field of PROTECTED_READ_FIELDS) {
    if (!Object.hasOwn(protectedPaths, field) || typeof protectedPaths[field] !== 'string'
        || !path.isAbsolute(protectedPaths[field])) fail('protected read path is invalid');
    result[field] = readProbe(protectedPaths[field]);
  }
  result.agentCredential = readProbe(request.credentialPath);
  for (const field of WRITE_FIELDS) {
    if (!Object.hasOwn(writePaths, field) || typeof writePaths[field] !== 'string'
        || !path.isAbsolute(writePaths[field])) fail('write probe path is invalid');
    const target = writePaths[field];
    result[field] = denialCode(() => {
      const descriptor = fs.openSync(target,
        fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
        0o600);
      fs.closeSync(descriptor);
    });
  }
  return Object.freeze(result);
}

async function direct() {
  const argv = process.argv.slice(2);
  if (argv.length !== 4 || argv[0] !== '--agent-uid' || argv[2] !== '--agent-gid') {
    fail('isolation worker arguments are invalid');
  }
  const uid = positive(argv[1], 'Agent UID');
  const gid = positive(argv[3], 'Agent GID');
  if (Reflect.ownKeys(process.env).some((name) => name !== 'NODE_CHANNEL_FD')) {
    fail('isolation worker inherited an unrecognized environment field');
  }
  dropToAgentIdentity({ uid, gid });
  process.send?.({ type: 'ready', pid: process.pid });
  let handled = false;
  process.on('message', (request) => {
    if (handled) process.exit(1);
    handled = true;
    try {
      process.send?.({ type: 'result', probeResults: runProbeRequest(request) });
      process.exit(0);
    } catch {
      process.send?.({ type: 'failed', code: 'ISOLATION_PROBE_FAILED' });
      process.exit(1);
    }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  direct().catch(() => { process.exitCode = 1; });
}

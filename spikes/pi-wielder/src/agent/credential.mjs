import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  canonicalJson,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { loadOrInitializeAgentPrivateFile } from '../kernel/secure-storage.mjs';
import { openAgentTrustedParent } from '../kernel/trusted-path.mjs';

const INSTANCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const NOFOLLOW = fs.constants.O_NOFOLLOW;

function fail(code, message) {
  throw new KernelError(code, message);
}

function opaque(value, bytes, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    fail('AGENT_CREDENTIAL_SCHEMA', `${label} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.length !== bytes || decoded.toString('base64url') !== value) {
    decoded.fill(0);
    fail('AGENT_CREDENTIAL_SCHEMA', `${label} is not canonical base64url`);
  }
  return decoded;
}

function randomOpaque(randomBytes, bytes, pattern, label, maximumAttempts = 1) {
  for (let attempt = 0; attempt < maximumAttempts; attempt += 1) {
    let value;
    try {
      value = Buffer.from(randomBytes(bytes));
    } catch {
      fail('AGENT_CREDENTIAL_RANDOMNESS', `${label} randomness failed`);
    }
    if (value.length !== bytes) {
      value.fill(0);
      fail('AGENT_CREDENTIAL_RANDOMNESS', `${label} randomness returned the wrong size`);
    }
    const encoded = value.toString('base64url');
    value.fill(0);
    if (pattern.test(encoded)) return encoded;
  }
  fail('AGENT_CREDENTIAL_RANDOMNESS', `${label} could not satisfy its durable token grammar`);
}

function validateCredential(value) {
  const credential = exactRecord(
    value,
    ['schemaVersion', 'agentInstanceId', 'token'],
    [],
    'AGENT_CREDENTIAL_SCHEMA',
    'agent credential',
  );
  if (credential.schemaVersion !== 1) {
    fail('AGENT_CREDENTIAL_SCHEMA', 'agent credential schemaVersion must equal 1');
  }
  const instanceBytes = opaque(
    credential.agentInstanceId,
    16,
    INSTANCE_PATTERN,
    'agent instance ID',
  );
  const tokenBytes = opaque(credential.token, 32, TOKEN_PATTERN, 'agent token');
  instanceBytes.fill(0);
  tokenBytes.fill(0);
  return frozenCopy(credential);
}

function parseCredentialBytes(bytes) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('AGENT_CREDENTIAL_SCHEMA', 'agent credential bytes are not canonical UTF-8');
  }
  if (!text.endsWith('\n') || text.slice(0, -1).includes('\n')) {
    fail('AGENT_CREDENTIAL_SCHEMA', 'agent credential must contain one canonical line');
  }
  let parsed;
  try {
    parsed = JSON.parse(text.slice(0, -1));
  } catch {
    fail('AGENT_CREDENTIAL_SCHEMA', 'agent credential is not canonical JSON');
  }
  const credential = validateCredential(parsed);
  if (`${canonicalJson(credential)}\n` !== text) {
    fail('AGENT_CREDENTIAL_SCHEMA', 'agent credential bytes are not canonical JSON');
  }
  return credential;
}

function positiveIdentity(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail('AGENT_IDENTITY', `${label} must be one positive safe integer`);
  }
  return String(value);
}

function exactOptions(value, fields, label, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('AGENT_CREDENTIAL_SCHEMA', `${label} must be one plain object`);
  }
  const keys = Reflect.ownKeys(value);
  const allowed = [...fields, ...optional];
  if (keys.length < fields.length || keys.length > allowed.length
      || fields.some((field) => !Object.hasOwn(value, field))
      || keys.some((key) => typeof key !== 'string' || !allowed.includes(key))) {
    fail('AGENT_CREDENTIAL_SCHEMA', `${label} fields do not match the closed schema`);
  }
  const captured = {};
  for (const field of allowed) {
    if (!Object.hasOwn(value, field)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('AGENT_CREDENTIAL_SCHEMA', `${label} must contain only data fields`);
    }
    captured[field] = descriptor.value;
  }
  return captured;
}

function derivedAgentPathTrust(filePath) {
  if (process.platform !== 'linux' || typeof process.getuid !== 'function'
      || process.getuid() <= 0) {
    fail(
      'AGENT_CREDENTIAL_PATH',
      'live Agent authority derivation requires a non-root Linux Agent identity',
    );
  }
  return Object.freeze({
    mode: 'cdp-testnet',
    trustedAncestor: path.parse(filePath).root,
    agentUid: process.getuid(),
  });
}

function selectedPathTrust(filePath, supplied) {
  return supplied === undefined ? derivedAgentPathTrust(filePath) : supplied;
}

export function loadOrCreateAgentCredential(value = {}) {
  const captured = exactOptions(
    value,
    ['filePath'],
    'agent credential initialization',
    ['pathTrust', 'randomBytes'],
  );
  const randomBytes = captured.randomBytes ?? crypto.randomBytes;
  if (typeof randomBytes !== 'function' || utilTypes.isProxy(randomBytes)) {
    fail('AGENT_CREDENTIAL_RANDOMNESS', 'agent credential randomness must be one function');
  }
  return loadOrInitializeAgentPrivateFile({
    filePath: captured.filePath,
    pathTrust: selectedPathTrust(captured.filePath, captured.pathTrust),
    label: 'Agent credential',
    createBytes: () => {
      const credential = Object.freeze({
        schemaVersion: 1,
        agentInstanceId: randomOpaque(
          randomBytes,
          16,
          INSTANCE_PATTERN,
          'agent instance ID',
          128,
        ),
        token: randomOpaque(randomBytes, 32, TOKEN_PATTERN, 'agent token'),
      });
      return Buffer.from(`${canonicalJson(credential)}\n`, 'utf8');
    },
    validateBytes: parseCredentialBytes,
    randomBytes,
  });
}

export function createAgentEnrollmentDescriptor(value) {
  const captured = exactOptions(
    value,
    ['credential'],
    'agent descriptor input',
  );
  const credential = validateCredential(captured.credential);
  const tokenBytes = opaque(credential.token, 32, TOKEN_PATTERN, 'agent token');
  let credentialDigest;
  try {
    credentialDigest = sha256(tokenBytes);
  } finally {
    tokenBytes.fill(0);
  }
  return frozenCopy({
    schemaVersion: 1,
    agentInstanceId: credential.agentInstanceId,
    credentialDigest,
    agentUid: positiveIdentity(process.getuid?.(), 'agent UID'),
    agentGid: positiveIdentity(process.getgid?.(), 'agent GID'),
  });
}

function validateDescriptor(value) {
  const descriptor = exactRecord(
    value,
    ['schemaVersion', 'agentInstanceId', 'credentialDigest', 'agentUid', 'agentGid'],
    [],
    'AGENT_DESCRIPTOR_SCHEMA',
    'agent enrollment descriptor',
  );
  if (descriptor.schemaVersion !== 1 || !HASH_PATTERN.test(descriptor.credentialDigest)) {
    fail('AGENT_DESCRIPTOR_SCHEMA', 'agent descriptor version or digest is invalid');
  }
  const instanceBytes = opaque(
    descriptor.agentInstanceId,
    16,
    INSTANCE_PATTERN,
    'agent instance ID',
  );
  instanceBytes.fill(0);
  if (!/^[1-9][0-9]*$/.test(descriptor.agentUid)
      || !/^[1-9][0-9]*$/.test(descriptor.agentGid)
      || !Number.isSafeInteger(Number(descriptor.agentUid))
      || !Number.isSafeInteger(Number(descriptor.agentGid))) {
    fail('AGENT_DESCRIPTOR_SCHEMA', 'agent descriptor identity is invalid');
  }
  return frozenCopy(descriptor);
}

function fileIdentity(stat) {
  return Object.freeze({
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    mode: Number(stat.mode & 0o7777n),
    nlink: stat.nlink.toString(10),
    size: stat.size.toString(10),
  });
}

function sameFileIdentity(left, right) {
  return Object.keys(left).every((field) => left[field] === right[field]);
}

function assertPublishedFile(stat, expectedBytes, descriptor) {
  const expectedUid = process.getuid?.();
  const expectedGid = process.getgid?.();
  if (!stat.isFile() || Number(stat.uid) !== expectedUid || Number(stat.gid) !== expectedGid
      || Number(stat.mode & 0o7777n) !== 0o644 || stat.nlink !== 1n
      || stat.size !== BigInt(expectedBytes.length)) {
    fail('AGENT_DESCRIPTOR_PATH', 'published enrollment descriptor authority changed');
  }
  const observed = Buffer.alloc(expectedBytes.length);
  try {
    let offset = 0;
    while (offset < observed.length) {
      const count = fs.readSync(descriptor, observed, offset, observed.length - offset, offset);
      if (count === 0) break;
      offset += count;
    }
    if (offset !== observed.length || !observed.equals(expectedBytes)) {
      fail('AGENT_DESCRIPTOR_PATH', 'published enrollment descriptor bytes changed');
    }
  } finally {
    observed.fill(0);
  }
}

export function publishAgentEnrollmentDescriptor(value) {
  const captured = exactOptions(
    value,
    ['filePath', 'credentialPath', 'descriptor'],
    'agent descriptor publication',
    ['pathTrust'],
  );
  if (typeof captured.filePath !== 'string' || typeof captured.credentialPath !== 'string'
      || !path.isAbsolute(captured.filePath) || !path.isAbsolute(captured.credentialPath)
      || path.resolve(captured.filePath) !== captured.filePath
      || path.resolve(captured.credentialPath) !== captured.credentialPath) {
    fail('AGENT_DESCRIPTOR_PATH', 'agent handoff paths must be canonical and absolute');
  }
  const targetParent = path.dirname(captured.filePath);
  const credentialParent = path.dirname(captured.credentialPath);
  if (targetParent === credentialParent
      || targetParent.startsWith(`${credentialParent}${path.sep}`)
      || credentialParent.startsWith(`${targetParent}${path.sep}`)) {
    fail('AGENT_DESCRIPTOR_PATH', 'credential and enrollment parents must be distinct');
  }
  const descriptor = validateDescriptor(captured.descriptor);
  if (descriptor.agentUid !== String(process.getuid?.())
      || descriptor.agentGid !== String(process.getgid?.())) {
    fail('AGENT_DESCRIPTOR_PATH', 'agent descriptor identity must equal the running Agent');
  }
  const bytes = Buffer.from(`${canonicalJson(descriptor)}\n`, 'utf8');
  const credentialTrust = selectedPathTrust(captured.credentialPath, captured.pathTrust);
  const enrollmentTrust = selectedPathTrust(captured.filePath, captured.pathTrust);
  let credentialGuard;
  let enrollmentGuard;
  let descriptorFd;
  try {
    credentialGuard = openAgentTrustedParent({
      ...credentialTrust,
      targetFile: captured.credentialPath,
      terminalOwnerUid: process.getuid(),
      terminalMode: 0o700,
      role: 'agent-private',
    });
    enrollmentGuard = openAgentTrustedParent({
      ...enrollmentTrust,
      targetFile: captured.filePath,
      terminalOwnerUid: process.getuid(),
      terminalMode: 0o755,
      role: 'agent-handoff',
    });
    credentialGuard.revalidate();
    descriptorFd = enrollmentGuard.openLeaf(
      fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      0o644,
    );
    fs.writeFileSync(descriptorFd, bytes);
    fs.fsyncSync(descriptorFd);
    const createdIdentity = fileIdentity(fs.fstatSync(descriptorFd, { bigint: true }));
    assertPublishedFile(fs.fstatSync(descriptorFd, { bigint: true }), bytes, descriptorFd);
    enrollmentGuard.revalidate();
    enrollmentGuard.fsyncParent();
    fs.closeSync(descriptorFd);
    descriptorFd = undefined;
    descriptorFd = enrollmentGuard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    const reopened = fs.fstatSync(descriptorFd, { bigint: true });
    assertPublishedFile(reopened, bytes, descriptorFd);
    if (!sameFileIdentity(createdIdentity, fileIdentity(reopened))) {
      fail('AGENT_DESCRIPTOR_PATH', 'published enrollment descriptor inode changed');
    }
    credentialGuard.revalidate();
  } finally {
    bytes.fill(0);
    if (descriptorFd !== undefined) fs.closeSync(descriptorFd);
    if (enrollmentGuard) enrollmentGuard.close();
    if (credentialGuard) credentialGuard.close();
  }
  return Object.freeze({
    descriptor,
    descriptorHash: sha256(canonicalJson(descriptor)),
  });
}

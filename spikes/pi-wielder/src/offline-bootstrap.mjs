import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { types as utilTypes } from 'node:util';

import {
  createIsolationAttestationRepository,
  validateIsolationReportBytes,
} from './agent/isolation-preflight.mjs';
import { createAgentEnrollmentRepository } from './kernel/agent-enrollment.mjs';
import { createApprovalQueue } from './kernel/approval-queue.mjs';
import { acquireAuthorityLock } from './kernel/authority-lock.mjs';
import { createBudgetLedger } from './kernel/budget-ledger.mjs';
import {
  canonicalJson,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './kernel/canonical.mjs';
import { createIntentRepository } from './kernel/intent-builder.mjs';
import { validatePolicyDocument } from './kernel/policy-engine.mjs';
import { createPolicyRepository } from './kernel/policy-repository.mjs';
import { loadOrCreateReceiptSigner } from './kernel/receipt-signing.mjs';
import { recoverKernelAuthority } from './kernel/recovery.mjs';
import { readPrivateInputFile } from './kernel/secure-storage.mjs';
import { createSignedReceiptRepository } from './kernel/signed-receipts.mjs';
import { openKernelStore } from './kernel/sqlite-store.mjs';

const ORIGIN = 'http://127.0.0.1:8405';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const MAXIMUM_POLICY_BYTES = 65_536;
const MAXIMUM_DESCRIPTOR_BYTES = 1_024;
const MAXIMUM_REPORT_BYTES = 16_384;
const CONFIG_FIELDS = Object.freeze([
  'mode',
  'databasePath',
  'receiptKeyPath',
  'operatorTokenPath',
  'operatorSocketPath',
  'origin',
  'trustedAncestor',
  'enrollmentInboxPath',
  'expectedAgentUid',
  'expectedAgentGid',
  'kernelUid',
  'kernelGid',
]);
const COMMAND_FIELDS = Object.freeze({
  preflight: Object.freeze([]),
  'agent-enroll': Object.freeze(['descriptorPath', 'expectedDescriptorHash']),
  'policy-validate': Object.freeze(['policyPath']),
  'policy-apply': Object.freeze(['policyPath', 'expectedPolicyHash']),
  'isolation-attest': Object.freeze(['reportPath', 'expectedReportHash']),
});

function fail(code, message, cause) {
  throw new KernelError(code, message, cause === undefined ? undefined : { cause });
}

function canonicalPath(value, label, { nullable = false } = {}) {
  if (nullable && value === null) return null;
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
      || !path.isAbsolute(value) || path.resolve(value) !== value
      || (value !== path.parse(value).root && value.endsWith(path.sep))) {
    fail('BOOTSTRAP_CONFIG_INVALID', `${label} must be one canonical absolute path`);
  }
  return value;
}

function positiveIdentity(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail('BOOTSTRAP_CONFIG_INVALID', `${label} must be one positive safe integer`);
  }
  return value;
}

function captureConfig(value) {
  const config = exactRecord(
    value,
    CONFIG_FIELDS,
    [],
    'BOOTSTRAP_CONFIG_SCHEMA',
    'offline bootstrap configuration',
  );
  if (config.mode !== 'deterministic' && config.mode !== 'cdp-testnet') {
    fail('BOOTSTRAP_CONFIG_INVALID', 'offline bootstrap mode is invalid');
  }
  if (config.origin !== ORIGIN) {
    fail('BOOTSTRAP_CONFIG_INVALID', 'offline bootstrap origin must be exact loopback');
  }
  const databasePath = canonicalPath(config.databasePath, 'database path');
  const receiptKeyPath = canonicalPath(
    config.receiptKeyPath,
    'receipt key path',
    { nullable: true },
  );
  const operatorTokenPath = canonicalPath(config.operatorTokenPath, 'operator token path');
  const operatorSocketPath = canonicalPath(
    config.operatorSocketPath,
    'operator socket path',
    { nullable: true },
  );
  const enrollmentInboxPath = canonicalPath(
    config.enrollmentInboxPath,
    'enrollment inbox path',
    { nullable: true },
  );
  const kernelUid = positiveIdentity(config.kernelUid, 'Kernel UID');
  const kernelGid = positiveIdentity(config.kernelGid, 'Kernel GID');
  const expectedAgentUid = positiveIdentity(config.expectedAgentUid, 'Agent UID');
  const expectedAgentGid = positiveIdentity(config.expectedAgentGid, 'Agent GID');
  if (typeof process.getuid !== 'function' || typeof process.getgid !== 'function'
      || process.getuid() !== kernelUid || process.getgid() !== kernelGid) {
    fail('BOOTSTRAP_IDENTITY_INVALID', 'offline bootstrap must run as the configured Kernel identity');
  }
  if (config.mode === 'deterministic') {
    if (operatorSocketPath !== null
        || expectedAgentUid !== kernelUid || expectedAgentGid !== kernelGid) {
      fail(
        'BOOTSTRAP_CONFIG_INVALID',
        'deterministic bootstrap requires one explicit same-identity fixture and no Unix socket',
      );
    }
  } else if (process.platform !== 'linux' || kernelUid === 0
      || expectedAgentUid === kernelUid || operatorSocketPath === null) {
    fail(
      'BOOTSTRAP_CONFIG_INVALID',
      'cdp-testnet bootstrap requires Linux, non-root distinct identities, and a Unix socket path',
    );
  }
  const trustedAncestor = canonicalPath(
    config.trustedAncestor ?? (config.mode === 'deterministic'
      ? path.dirname(databasePath)
      : null),
    'trusted ancestor',
  );
  if (new Set([
    databasePath,
    receiptKeyPath,
    operatorTokenPath,
    operatorSocketPath,
    enrollmentInboxPath,
  ].filter((item) => item !== null)).size
      !== [
        databasePath,
        receiptKeyPath,
        operatorTokenPath,
        operatorSocketPath,
        enrollmentInboxPath,
      ].filter((item) => item !== null).length) {
    fail('BOOTSTRAP_CONFIG_INVALID', 'offline bootstrap filesystem roles must be distinct');
  }
  const sqliteAuthorityPaths = new Set([
    databasePath,
    `${databasePath}-wal`,
    `${databasePath}-shm`,
    `${databasePath}.authority-lock.sqlite`,
  ]);
  if ([receiptKeyPath, operatorTokenPath, operatorSocketPath, enrollmentInboxPath]
    .some((item) => item !== null && sqliteAuthorityPaths.has(item))) {
    fail('BOOTSTRAP_CONFIG_INVALID', 'offline bootstrap path collides with SQLite authority');
  }
  return Object.freeze({
    mode: config.mode,
    databasePath,
    receiptKeyPath,
    operatorTokenPath,
    operatorSocketPath,
    origin: ORIGIN,
    trustedAncestor,
    enrollmentInboxPath,
    expectedAgentUid,
    expectedAgentGid,
    kernelUid,
    kernelGid,
  });
}

function captureCommand(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('BOOTSTRAP_COMMAND_SCHEMA', 'offline bootstrap command must be one plain object');
  }
  const descriptor = Object.getOwnPropertyDescriptor(value, 'name');
  if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')
      || typeof descriptor.value !== 'string'
      || !Object.hasOwn(COMMAND_FIELDS, descriptor.value)) {
    fail('BOOTSTRAP_COMMAND_SCHEMA', 'offline bootstrap command name is invalid');
  }
  const name = descriptor.value;
  return Object.freeze(exactRecord(
    value,
    ['name', ...COMMAND_FIELDS[name]],
    [],
    'BOOTSTRAP_COMMAND_SCHEMA',
    `${name} command`,
  ));
}

function validateOperatorToken(value) {
  if (typeof value !== 'string' || !TOKEN_PATTERN.test(value)) {
    fail('OPERATOR_TOKEN_INVALID', 'operator token is invalid');
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) {
    bytes.fill(0);
    fail('OPERATOR_TOKEN_INVALID', 'operator token is invalid');
  }
  return bytes;
}

function operatorIdentityHash(token) {
  const bytes = validateOperatorToken(token);
  try {
    return sha256(Buffer.concat([
      Buffer.from('wallet-kernel.operator-id.v1\0', 'utf8'),
      bytes,
    ]));
  } finally {
    bytes.fill(0);
  }
}

function validateOwnerAuthority(token, config) {
  const suppliedDecoded = validateOperatorToken(token);
  suppliedDecoded.fill(0);
  const supplied = Buffer.from(token, 'ascii');
  const pathTrust = Object.freeze({
    mode: config.mode,
    trustedAncestor: config.trustedAncestor,
    kernelUid: config.kernelUid,
    agentUid: config.expectedAgentUid,
  });
  let persisted;
  try {
    persisted = readPrivateInputFile(
      config.operatorTokenPath,
      'Operator token',
      { maximumBytes: 43, pathTrust },
    );
  } catch (cause) {
    supplied.fill(0);
    fail('OPERATOR_TOKEN_INVALID', 'operator token is invalid', cause);
  }
  let persistedText = '';
  let suppliedDigest;
  let persistedDigest;
  try {
    if (persisted.some((byte) => byte > 0x7f)) {
      fail('OPERATOR_TOKEN_INVALID', 'operator token is invalid');
    }
    persistedText = persisted.toString('ascii');
    const persistedBytes = validateOperatorToken(persistedText);
    persistedBytes.fill(0);
    suppliedDigest = crypto.createHash('sha256')
      .update('wallet-kernel.operator-bearer.v1\0', 'utf8')
      .update(supplied)
      .digest();
    persistedDigest = crypto.createHash('sha256')
      .update('wallet-kernel.operator-bearer.v1\0', 'utf8')
      .update(persisted)
      .digest();
    if (!crypto.timingSafeEqual(suppliedDigest, persistedDigest)) {
      fail('OPERATOR_TOKEN_INVALID', 'operator token is invalid');
    }
  } finally {
    supplied.fill(0);
    persisted.fill(0);
    suppliedDigest?.fill(0);
    persistedDigest?.fill(0);
    persistedText = '';
  }
}

function identity(stat) {
  return Object.freeze({
    dev: stat.dev,
    ino: stat.ino,
    uid: stat.uid,
    gid: stat.gid,
    mode: stat.mode & 0o7777n,
    nlink: stat.nlink,
    size: stat.size,
    mtimeNs: stat.mtimeNs,
  });
}

function sameIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs;
}

function readBoundedFile(filePath, {
  code,
  maximumBytes,
  expectedUid,
  expectedGid,
  expectedMode,
  expectedParentUid,
  expectedParentGid,
  expectedParentMode,
  live,
}) {
  const canonical = canonicalPath(filePath, 'bootstrap input path');
  const parentPath = path.dirname(canonical);
  const leafName = path.basename(canonical);
  let parentDescriptor;
  let descriptor;
  let bytes;
  const reject = (message, cause) => fail(code, message, cause);
  try {
    parentDescriptor = fs.openSync(
      parentPath,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
    );
    const parentBeforeStat = fs.fstatSync(parentDescriptor, { bigint: true });
    const parentPathStat = fs.lstatSync(parentPath, { bigint: true });
    const parentBefore = identity(parentBeforeStat);
    if (!parentBeforeStat.isDirectory() || parentPathStat.isSymbolicLink()
        || !parentPathStat.isDirectory()
        || parentBefore.dev !== parentPathStat.dev || parentBefore.ino !== parentPathStat.ino
        || (expectedParentUid !== undefined && Number(parentBefore.uid) !== expectedParentUid)
        || (expectedParentGid !== undefined && Number(parentBefore.gid) !== expectedParentGid)
        || (expectedParentMode !== undefined && Number(parentBefore.mode) !== expectedParentMode)) {
      reject('bootstrap input parent authority is invalid');
    }
    const childLocation = live ? `/proc/self/fd/${parentDescriptor}/${leafName}` : canonical;
    descriptor = fs.openSync(childLocation, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const beforeStat = fs.fstatSync(descriptor, { bigint: true });
    const pathStat = fs.lstatSync(canonical, { bigint: true });
    const before = identity(beforeStat);
    if (!beforeStat.isFile() || pathStat.isSymbolicLink() || !pathStat.isFile()
        || before.dev !== pathStat.dev || before.ino !== pathStat.ino
        || before.nlink !== 1n || before.size < 1n || before.size > BigInt(maximumBytes)
        || (expectedUid !== undefined && Number(before.uid) !== expectedUid)
        || (expectedGid !== undefined && Number(before.gid) !== expectedGid)
        || (expectedMode !== undefined && Number(before.mode) !== expectedMode)) {
      reject('bootstrap input file authority is invalid');
    }
    bytes = Buffer.alloc(Number(before.size));
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) reject('bootstrap input was truncated during its single read');
      offset += count;
    }
    const overflow = Buffer.alloc(1);
    if (fs.readSync(descriptor, overflow, 0, 1, offset) !== 0) {
      reject('bootstrap input exceeded its captured size');
    }
    const after = identity(fs.fstatSync(descriptor, { bigint: true }));
    const afterPath = fs.lstatSync(canonical, { bigint: true });
    const parentAfter = identity(fs.fstatSync(parentDescriptor, { bigint: true }));
    const parentAfterPath = fs.lstatSync(parentPath, { bigint: true });
    if (!sameIdentity(before, after)
        || afterPath.isSymbolicLink() || afterPath.dev !== after.dev || afterPath.ino !== after.ino
        || !sameIdentity(parentBefore, parentAfter)
        || parentAfterPath.isSymbolicLink()
        || parentAfterPath.dev !== parentAfter.dev || parentAfterPath.ino !== parentAfter.ino) {
      reject('bootstrap input authority changed during its single read');
    }
    return bytes;
  } catch (error) {
    if (error instanceof KernelError && error.code === code) throw error;
    reject('bootstrap input could not be read safely', error);
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (parentDescriptor !== undefined) {
      try { fs.closeSync(parentDescriptor); } catch {}
    }
  }
}

function parseJsonBytes(bytes, code, label, { canonicalLine = false } = {}) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (cause) {
    fail(code, `${label} is not valid UTF-8`, cause);
  }
  if (text.includes('\0')) fail(code, `${label} contains a NUL byte`);
  let source = text;
  if (canonicalLine) {
    if (!text.endsWith('\n') || text.slice(0, -1).includes('\n')) {
      fail(code, `${label} must be canonical JSON plus one newline`);
    }
    source = text.slice(0, -1);
  }
  let parsed;
  try {
    parsed = JSON.parse(source);
  } catch (cause) {
    fail(code, `${label} is not valid JSON`, cause);
  }
  if (canonicalLine && `${canonicalJson(parsed)}\n` !== text) {
    fail(code, `${label} bytes are not canonical JSON plus one newline`);
  }
  return parsed;
}

function readPolicy(command, config) {
  const bytes = readBoundedFile(command.policyPath, {
    code: 'POLICY_FILE_UNSAFE',
    maximumBytes: MAXIMUM_POLICY_BYTES,
    live: config.mode === 'cdp-testnet',
  });
  try {
    const policy = validatePolicyDocument(parseJsonBytes(bytes, 'POLICY_FILE_INVALID', 'policy'));
    const policyHash = sha256(canonicalJson(policy));
    if (command.name === 'policy-apply') {
      if (typeof command.expectedPolicyHash !== 'string'
          || !HASH_PATTERN.test(command.expectedPolicyHash)
          || command.expectedPolicyHash !== policyHash) {
        fail('POLICY_HASH_MISMATCH', 'policy hash does not match the confirmed canonical policy');
      }
    }
    return Object.freeze({ policy, policyHash });
  } finally {
    bytes.fill(0);
  }
}

function validateEnrollmentInbox(config) {
  const relative = path.relative(config.trustedAncestor, config.enrollmentInboxPath);
  if (relative === '' || path.isAbsolute(relative) || relative === '..'
      || relative.startsWith(`..${path.sep}`)) {
    fail('AGENT_DESCRIPTOR_PATH', 'enrollment inbox must be beneath the trusted ancestor');
  }
  const paths = [config.trustedAncestor];
  for (const component of relative.split(path.sep)) {
    if (component.length === 0 || component === '.' || component === '..') {
      fail('AGENT_DESCRIPTOR_PATH', 'enrollment inbox path is not canonical');
    }
    paths.push(path.join(paths.at(-1), component));
  }
  for (let index = 0; index < paths.length; index += 1) {
    let stat;
    try {
      stat = fs.lstatSync(paths[index], { bigint: true });
    } catch (cause) {
      fail('AGENT_DESCRIPTOR_PATH', 'enrollment inbox path cannot be inspected', cause);
    }
    const terminal = index === paths.length - 1;
    const uid = Number(stat.uid);
    const gid = Number(stat.gid);
    const mode = Number(stat.mode & 0o7777n);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      fail('AGENT_DESCRIPTOR_PATH', 'enrollment inbox chain must contain only directories');
    }
    if (terminal) {
      if (uid !== config.expectedAgentUid || gid !== config.expectedAgentGid || mode !== 0o755) {
        fail('AGENT_DESCRIPTOR_PATH', 'enrollment inbox must have exact Pi ownership and mode');
      }
    } else if (config.mode === 'deterministic') {
      if (uid !== config.kernelUid || mode !== 0o700) {
        fail('AGENT_DESCRIPTOR_PATH', 'deterministic inbox ancestors must be owner-only');
      }
    } else if ((index === 0 && uid !== 0)
        || (index > 0 && uid !== 0 && uid !== config.kernelUid)
        || (mode & 0o022) !== 0) {
      fail('AGENT_DESCRIPTOR_PATH', 'live inbox ancestors must not be Pi-writable');
    }
  }
}

function readEnrollmentDescriptor(command, config) {
  if (config.enrollmentInboxPath === null
      || path.dirname(command.descriptorPath) !== config.enrollmentInboxPath) {
    fail('AGENT_DESCRIPTOR_PATH', 'enrollment descriptor must be in the configured Pi inbox');
  }
  validateEnrollmentInbox(config);
  const bytes = readBoundedFile(command.descriptorPath, {
    code: 'AGENT_DESCRIPTOR_PATH',
    maximumBytes: MAXIMUM_DESCRIPTOR_BYTES,
    expectedUid: config.expectedAgentUid,
    expectedGid: config.expectedAgentGid,
    expectedMode: 0o644,
    expectedParentUid: config.expectedAgentUid,
    expectedParentGid: config.expectedAgentGid,
    expectedParentMode: 0o755,
    live: config.mode === 'cdp-testnet',
  });
  try {
    const descriptor = exactRecord(
      parseJsonBytes(bytes, 'AGENT_DESCRIPTOR_BYTES', 'agent descriptor', {
        canonicalLine: true,
      }),
      ['schemaVersion', 'agentInstanceId', 'credentialDigest', 'agentUid', 'agentGid'],
      [],
      'AGENT_DESCRIPTOR_BYTES',
      'agent descriptor',
    );
    const descriptorHash = sha256(canonicalJson(descriptor));
    if (typeof command.expectedDescriptorHash !== 'string'
        || !HASH_PATTERN.test(command.expectedDescriptorHash)
        || descriptorHash !== command.expectedDescriptorHash) {
      fail('AGENT_DESCRIPTOR_HASH', 'agent descriptor hash differs from the confirmation');
    }
    return Object.freeze({ descriptor: Object.freeze(descriptor), descriptorHash });
  } finally {
    bytes.fill(0);
  }
}

function readIsolationReport(command, config, now) {
  if (config.mode !== 'cdp-testnet') {
    fail('ISOLATION_MODE_INVALID', 'privileged isolation attestation exists only in cdp-testnet mode');
  }
  const bytes = readBoundedFile(command.reportPath, {
    code: 'ISOLATION_REPORT_PATH',
    maximumBytes: MAXIMUM_REPORT_BYTES,
    expectedUid: config.kernelUid,
    expectedGid: config.kernelGid,
    expectedMode: 0o600,
    expectedParentUid: config.kernelUid,
    expectedParentGid: config.kernelGid,
    expectedParentMode: 0o700,
    live: true,
  });
  try {
    const validated = validateIsolationReportBytes(bytes, {
      expectedReportHash: command.expectedReportHash,
      expectedKernelUid: String(config.kernelUid),
      expectedKernelGid: String(config.kernelGid),
      now,
    });
    return Object.freeze({
      bytes: Buffer.from(bytes),
      report: validated.report,
      reportHash: validated.reportHash,
    });
  } finally {
    bytes.fill(0);
  }
}

function sequenceFactory(randomBytes = crypto.randomBytes) {
  return (kind) => `${kind}-${randomBytes(16).toString('base64url')}`;
}

function openRecoveryContext(config, now) {
  if (config.receiptKeyPath === null) {
    fail('BOOTSTRAP_CONFIG_INVALID', 'receipt key path is required for authority recovery');
  }
  const pathTrust = Object.freeze({
    mode: config.mode,
    trustedAncestor: config.trustedAncestor,
    kernelUid: config.kernelUid,
    agentUid: config.expectedAgentUid,
  });
  const signer = loadOrCreateReceiptSigner(config.receiptKeyPath, { pathTrust });
  const store = openKernelStore({
    filePath: config.databasePath,
    pathTrust,
    now,
  });
  try {
    const idFactory = sequenceFactory();
    const intents = createIntentRepository({
      store,
      idFactory,
      now,
      allowLoopbackHttp: config.mode === 'deterministic',
      routeMetadata: {},
    });
    const budgets = createBudgetLedger({ store, now });
    const approvals = createApprovalQueue({ store, idFactory, now });
    const receipts = createSignedReceiptRepository({ store, signer, idFactory, now });
    return Object.freeze({
      store,
      intents,
      budgets,
      approvals,
      receipts,
      policies: createPolicyRepository(store),
      enrollments: createAgentEnrollmentRepository({ store, now }),
      attestations: createIsolationAttestationRepository({
        store,
        now,
        idFactory: () => idFactory('isolation'),
      }),
      recoveryDependencies: Object.freeze({ store, intents, budgets, approvals, receipts, now }),
      close: () => store.close(),
    });
  } catch (error) {
    try { store.close(); } catch {}
    throw error;
  }
}

function projectEnrollment(value) {
  return frozenCopy({
    agentInstanceId: value.agentInstanceId,
    credentialDigest: value.credentialDigest,
    enrollmentHash: value.enrollmentHash,
    agentUid: value.agentUid,
    agentGid: value.agentGid,
    state: value.state,
    isolation: value.isolation,
    enrolledAt: value.enrolledAt,
  });
}

function recoveryRequired(cause) {
  if (cause instanceof KernelError && cause.code === 'AUTHORITY_BUSY') throw cause;
  fail(
    'AUTHORITY_RECOVERY_REQUIRED',
    'offline bootstrap could not prove healthy Wallet authority',
    cause,
  );
}

export async function runOfflineBootstrap(value) {
  const input = exactRecord(
    value,
    ['command', 'config', 'operatorToken'],
    [],
    'BOOTSTRAP_SCHEMA',
    'offline bootstrap request',
  );
  const command = captureCommand(input.command);
  const config = captureConfig(input.config);
  validateOwnerAuthority(input.operatorToken, config);
  const operatorIdHash = operatorIdentityHash(input.operatorToken);
  const now = () => new Date().toISOString();
  const pathTrust = Object.freeze({
    mode: config.mode,
    trustedAncestor: config.trustedAncestor,
    kernelUid: config.kernelUid,
    agentUid: config.expectedAgentUid,
  });

  let lock;
  let context;
  let prepared = null;
  let operationSucceeded = false;
  let cleanupFailure = null;
  let result;
  try {
    try {
      lock = acquireAuthorityLock({
        databasePath: config.databasePath,
        role: 'bootstrap',
        pathTrust,
      });
    } catch (cause) {
      recoveryRequired(cause);
    }

    if (command.name === 'policy-validate' || command.name === 'policy-apply') {
      prepared = readPolicy(command, config);
    } else if (command.name === 'agent-enroll') {
      prepared = readEnrollmentDescriptor(command, config);
    } else if (command.name === 'isolation-attest') {
      prepared = readIsolationReport(command, config, now);
    }

    if (command.name === 'policy-validate') {
      result = frozenCopy({ policy: prepared.policy, policyHash: prepared.policyHash });
      operationSucceeded = true;
    } else {
      try {
        context = openRecoveryContext(config, now);
      } catch (cause) {
        recoveryRequired(cause);
      }
      let recovery;
      try {
        recovery = recoverKernelAuthority(context.recoveryDependencies);
      } catch (cause) {
        recoveryRequired(cause);
      }

      if (command.name === 'preflight') {
        result = frozenCopy({ state: 'healthy', recovery });
      } else if (command.name === 'policy-apply') {
        result = context.policies.apply(prepared.policy, now());
      } else if (command.name === 'agent-enroll') {
        result = projectEnrollment(context.enrollments.enroll({
          descriptor: prepared.descriptor,
          expectedDescriptorHash: prepared.descriptorHash,
          operatorIdHash,
          mode: config.mode,
          kernelUid: config.kernelUid,
          kernelGid: config.kernelGid,
          expectedAgentUid: config.expectedAgentUid,
          expectedAgentGid: config.expectedAgentGid,
        }));
      } else if (command.name === 'isolation-attest') {
        const active = context.enrollments.active();
        if (active === null || active.enrollmentHash !== prepared.report.enrollmentHash) {
          fail('ISOLATION_ENROLLMENT', 'isolation report does not bind the active enrollment');
        }
        result = context.attestations.importCurrent({
          reportBytes: prepared.bytes,
          expectedReportHash: prepared.reportHash,
          operatorIdHash,
        });
      }
      operationSucceeded = true;
    }
  } finally {
    if (context) {
      try {
        context.close();
      } catch (cause) {
        cleanupFailure ??= cause;
      }
    }
    if (lock) {
      try {
        lock.close();
      } catch (cause) {
        cleanupFailure ??= cause;
      }
    }
    if (prepared?.bytes && Buffer.isBuffer(prepared.bytes)) prepared.bytes.fill(0);
    if (operationSucceeded && cleanupFailure !== null) recoveryRequired(cleanupFailure);
  }
  return result;
}

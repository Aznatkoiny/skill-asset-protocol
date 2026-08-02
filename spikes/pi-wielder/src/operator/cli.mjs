import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { types as utilTypes } from 'node:util';

import { canonicalJson } from '../kernel/canonical.mjs';
import { runOfflineBootstrap } from '../offline-bootstrap.mjs';
import { projectOperatorPublicResult } from './api.mjs';

const ORIGIN = 'http://127.0.0.1:8405';
const MAXIMUM_ARGUMENTS = 64;
const MAXIMUM_ARGUMENT_BYTES = 4_096;
const MAXIMUM_RESPONSE_BYTES = 1_048_576;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const SIGNED_RECEIPT_HASH_PATTERN = /^[0-9a-f]{64}$/;
const TRANSACTION_PATTERN = /^0x[0-9a-f]{64}$/;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const ERROR_CODE_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const USAGE = 'usage: wallet-kernel <command> [options]';
const FORBIDDEN_OUTPUT_KEY_FRAGMENT = /raw|secret|credential|privatekey|seedphrase|mnemonic|password|token|bearer|authorization|prompt|body|content|evidence|payload|exception|stack|paymentpayload|paymentheader|apikey|signature/;
const PUBLIC_HASH_KEYS = new Set([
  'ancestorMetadataHash', 'authorityMetadataHash', 'caseHash', 'closedSessionHash',
  'correlationHash', 'credentialDigest', 'credentialHash', 'credentialMetadataHash', 'enrollmentHash',
  'environmentMetadataHash', 'eventHash', 'eventHeadHash', 'executionCaseHash',
  'expectedCaseHash', 'expectedEnrollmentHash', 'expectedIntentHash',
  'expectedPolicyHash', 'expectedReportHash', 'expectedSessionHash', 'intentHash',
  'keyId', 'metadataHash', 'nodeExecutableHash', 'paymentCaseHash', 'policyHash',
  'previousEventHash', 'projectionHash', 'receiptHash', 'refundCaseHash',
  'releaseManifestHash', 'releaseTreeHash', 'replacementSessionHash', 'requestHash',
  'requestUrlHash', 'resourceHash', 'responseHash', 'serviceArtifactsHash',
  'sessionHash', 'supersedesReceiptHash', 'systemdEffectiveConfigHash',
  'transactionHash',
]);
const CANONICAL_SIGNATURE_PATTERN = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/][AQgw]==$/;

const KNOWN_WALLET_KERNEL_ENVIRONMENT = new Set([
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

class CliError extends Error {
  constructor(code, { usage = false } = {}) {
    super(code);
    this.name = 'CliError';
    this.code = code;
    this.usage = usage;
  }
}

function fail(code, options) {
  throw new CliError(code, options);
}

function usage() {
  fail('CLI_USAGE', { usage: true });
}

function isPlainDataObject(value) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && !utilTypes.isProxy(value)
    && (Object.getPrototypeOf(value) === Object.prototype
      || Object.getPrototypeOf(value) === null);
}

function ownDataDescriptors(value, code) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) fail(code);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(value).some((key) => typeof key !== 'string'
      || !descriptors[key]?.enumerable
      || !Object.hasOwn(descriptors[key], 'value'))) {
    fail(code);
  }
  return descriptors;
}

function captureArgv(argv) {
  if (utilTypes.isProxy(argv) || !Array.isArray(argv)
      || Object.getPrototypeOf(argv) !== Array.prototype
      || argv.length > MAXIMUM_ARGUMENTS) usage();
  const descriptors = Object.getOwnPropertyDescriptors(argv);
  const keys = Reflect.ownKeys(argv);
  const length = descriptors.length?.value;
  if (!Number.isSafeInteger(length) || keys.length !== length + 1) usage();
  const captured = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = descriptors[String(index)];
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) usage();
    const value = descriptor.value;
    if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
        || Buffer.byteLength(value, 'utf8') > MAXIMUM_ARGUMENT_BYTES) usage();
    captured.push(value);
  }
  return captured;
}

function captureEnvironment(env) {
  const descriptors = ownDataDescriptors(env, 'CLI_CONFIG_INVALID');
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (key.startsWith('WALLET_KERNEL_') && !KNOWN_WALLET_KERNEL_ENVIRONMENT.has(key)) {
      fail('CLI_CONFIG_INVALID');
    }
    if (typeof descriptor.value !== 'string') fail('CLI_CONFIG_INVALID');
  }
  return descriptors;
}

function environmentValue(descriptors, key, { required = false } = {}) {
  const value = descriptors[key]?.value;
  if (value === undefined || value === '') {
    if (required) fail('CLI_CONFIG_INVALID');
    return null;
  }
  if (value.includes('\0')) fail('CLI_CONFIG_INVALID');
  return value;
}

function canonicalAbsolutePath(value, code) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
      || !path.isAbsolute(value) || path.resolve(value) !== value
      || (value !== path.parse(value).root && value.endsWith(path.sep))) {
    fail(code);
  }
  return value;
}

function captureConfig(env) {
  const descriptors = captureEnvironment(env);
  const mode = environmentValue(descriptors, 'WALLET_KERNEL_MODE', { required: true });
  if (mode !== 'deterministic' && mode !== 'cdp-testnet') fail('CLI_CONFIG_INVALID');
  const tokenPath = canonicalAbsolutePath(
    environmentValue(descriptors, 'WALLET_KERNEL_OPERATOR_TOKEN_FILE', { required: true }),
    'CLI_CONFIG_INVALID',
  );
  const databaseValue = environmentValue(descriptors, 'WALLET_KERNEL_DB_FILE');
  const databasePath = databaseValue === null
    ? null
    : canonicalAbsolutePath(databaseValue, 'CLI_CONFIG_INVALID');
  const receiptKeyValue = environmentValue(descriptors, 'WALLET_KERNEL_RECEIPT_KEY_FILE');
  const receiptKeyPath = receiptKeyValue === null
    ? null
    : canonicalAbsolutePath(receiptKeyValue, 'CLI_CONFIG_INVALID');
  const trustedAncestorValue = environmentValue(descriptors, 'WALLET_KERNEL_TRUSTED_ANCESTOR');
  const trustedAncestor = trustedAncestorValue === null
    ? null
    : canonicalAbsolutePath(trustedAncestorValue, 'CLI_CONFIG_INVALID');
  const enrollmentInboxValue = environmentValue(descriptors, 'WALLET_KERNEL_ENROLLMENT_INBOX');
  const enrollmentInboxPath = enrollmentInboxValue === null
    ? null
    : canonicalAbsolutePath(enrollmentInboxValue, 'CLI_CONFIG_INVALID');
  const socketValue = environmentValue(descriptors, 'WALLET_KERNEL_OPERATOR_SOCKET_FILE');
  const operatorSocketPath = socketValue === null
    ? null
    : canonicalAbsolutePath(socketValue, 'CLI_CONFIG_INVALID');
  const operatorPort = environmentValue(descriptors, 'WALLET_KERNEL_OPERATOR_PORT') ?? '8405';
  if (operatorPort !== '8405') fail('CLI_CONFIG_INVALID');
  if ((mode === 'cdp-testnet') !== (operatorSocketPath !== null)) {
    fail('CLI_CONFIG_INVALID');
  }
  const parseIdentity = (key, fallback) => {
    const value = environmentValue(descriptors, key);
    if (value === null) return fallback;
    if (!/^[1-9][0-9]*$/.test(value)) fail('CLI_CONFIG_INVALID');
    const numeric = Number(value);
    if (!Number.isSafeInteger(numeric) || String(numeric) !== value) {
      fail('CLI_CONFIG_INVALID');
    }
    return numeric;
  };
  const kernelUid = currentUid();
  if (typeof process.getgid !== 'function') fail('CLI_CONFIG_INVALID');
  const kernelGid = process.getgid();
  if (!Number.isSafeInteger(kernelGid) || kernelGid <= 0) fail('CLI_CONFIG_INVALID');
  const expectedAgentUid = parseIdentity('WALLET_KERNEL_EXPECTED_AGENT_UID', kernelUid);
  const expectedAgentGid = parseIdentity('WALLET_KERNEL_EXPECTED_AGENT_GID', kernelGid);
  return Object.freeze({
    mode,
    databasePath,
    receiptKeyPath,
    operatorTokenPath: tokenPath,
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

function currentUid() {
  if (typeof process.getuid !== 'function') fail('OPERATOR_CHANNEL_INVALID');
  return process.getuid();
}

function statIdentity(stat) {
  return Object.freeze({ dev: stat.dev, ino: stat.ino });
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino;
}

function openPrivateParent(filePath, code) {
  const parentPath = path.dirname(filePath);
  let descriptor;
  try {
    descriptor = fs.openSync(
      parentPath,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW,
    );
    const descriptorStat = fs.fstatSync(descriptor, { bigint: true });
    const pathStat = fs.lstatSync(parentPath, { bigint: true });
    if (!descriptorStat.isDirectory() || pathStat.isSymbolicLink()
        || !pathStat.isDirectory()
        || !sameIdentity(statIdentity(descriptorStat), statIdentity(pathStat))
        || Number(descriptorStat.uid) !== currentUid()
        || Number(descriptorStat.mode & 0o777n) !== 0o700) {
      fail(code);
    }
    const identity = statIdentity(descriptorStat);
    const revalidate = () => {
      const held = fs.fstatSync(descriptor, { bigint: true });
      const current = fs.lstatSync(parentPath, { bigint: true });
      if (!held.isDirectory() || current.isSymbolicLink() || !current.isDirectory()
          || !sameIdentity(identity, statIdentity(held))
          || !sameIdentity(identity, statIdentity(current))
          || Number(held.uid) !== currentUid()
          || Number(held.mode & 0o777n) !== 0o700) {
        fail(code);
      }
    };
    revalidate();
    return Object.freeze({ parentPath, descriptor, revalidate });
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (error instanceof CliError) throw error;
    fail(code);
  }
}

function readOperatorToken(filePath) {
  const guard = openPrivateParent(filePath, 'OPERATOR_TOKEN_INVALID');
  let descriptor;
  let bytes;
  try {
    descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    let stat = fs.fstatSync(descriptor, { bigint: true });
    const pathStat = fs.lstatSync(filePath, { bigint: true });
    if (!stat.isFile() || pathStat.isSymbolicLink() || !pathStat.isFile()
        || !sameIdentity(statIdentity(stat), statIdentity(pathStat))
        || Number(stat.uid) !== currentUid()
        || Number(stat.mode & 0o777n) !== 0o600
        || stat.size !== 43n) {
      fail('OPERATOR_TOKEN_INVALID');
    }
    bytes = Buffer.alloc(43);
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count === 0) fail('OPERATOR_TOKEN_INVALID');
      offset += count;
    }
    const overflow = Buffer.alloc(1);
    if (fs.readSync(descriptor, overflow, 0, 1, offset) !== 0) {
      fail('OPERATOR_TOKEN_INVALID');
    }
    stat = fs.fstatSync(descriptor, { bigint: true });
    const finalPathStat = fs.lstatSync(filePath, { bigint: true });
    guard.revalidate();
    if (!sameIdentity(statIdentity(stat), statIdentity(pathStat))
        || !sameIdentity(statIdentity(stat), statIdentity(finalPathStat))
        || Number(stat.mode & 0o777n) !== 0o600) {
      fail('OPERATOR_TOKEN_INVALID');
    }
    if (bytes.some((byte) => byte > 0x7f)) fail('OPERATOR_TOKEN_INVALID');
    const token = bytes.toString('ascii');
    if (!TOKEN_PATTERN.test(token)) fail('OPERATOR_TOKEN_INVALID');
    const decoded = Buffer.from(token, 'base64url');
    try {
      if (decoded.length !== 32 || decoded.toString('base64url') !== token) {
        fail('OPERATOR_TOKEN_INVALID');
      }
    } finally {
      decoded.fill(0);
    }
    return token;
  } catch (error) {
    if (error instanceof CliError) throw error;
    fail('OPERATOR_TOKEN_INVALID');
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (bytes) bytes.fill(0);
    try { fs.closeSync(guard.descriptor); } catch {}
  }
}

function inspectAdminSocket(socketPath) {
  const guard = openPrivateParent(socketPath, 'OPERATOR_CHANNEL_INVALID');
  let socketIdentity;
  const revalidate = () => {
    guard.revalidate();
    let stat;
    try {
      stat = fs.lstatSync(socketPath, { bigint: true });
    } catch {
      fail('OPERATOR_CHANNEL_INVALID');
    }
    if (stat.isSymbolicLink() || !stat.isSocket()
        || Number(stat.uid) !== currentUid()
        || Number(stat.mode & 0o777n) !== 0o600) {
      fail('OPERATOR_CHANNEL_INVALID');
    }
    const identity = statIdentity(stat);
    if (socketIdentity && !sameIdentity(socketIdentity, identity)) {
      fail('OPERATOR_CHANNEL_INVALID');
    }
    socketIdentity ??= identity;
    guard.revalidate();
  };
  try {
    revalidate();
    return Object.freeze({
      revalidate,
      close() { fs.closeSync(guard.descriptor); },
    });
  } catch (error) {
    try { fs.closeSync(guard.descriptor); } catch {}
    throw error;
  }
}

function parseFlags(tokens, start, allowed, required = []) {
  const result = {};
  for (let index = start; index < tokens.length; index += 2) {
    const flag = tokens[index];
    const value = tokens[index + 1];
    if (!Object.hasOwn(allowed, flag) || value === undefined || value.startsWith('--')
        || Object.hasOwn(result, flag)) {
      usage();
    }
    result[flag] = allowed[flag](value);
  }
  if (required.some((flag) => !Object.hasOwn(result, flag))) usage();
  return result;
}

function exactId(value) {
  if (!ID_PATTERN.test(value)) usage();
  return value;
}

function exactHash(value) {
  if (!HASH_PATTERN.test(value)) usage();
  return value;
}

function exactTransaction(value) {
  if (!TRANSACTION_PATTERN.test(value)) usage();
  return value;
}

function inputPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')
      || /[\u0000-\u001f\u007f]/u.test(value)
      || Buffer.byteLength(value, 'utf8') > MAXIMUM_ARGUMENT_BYTES
      || value.startsWith('--') || !path.isAbsolute(value) || path.resolve(value) !== value
      || (value !== path.parse(value).root && value.endsWith(path.sep))) {
    usage();
  }
  return value;
}

function freezeCommand(value) {
  if (value.body && typeof value.body === 'object') Object.freeze(value.body);
  if (value.bootstrap && typeof value.bootstrap === 'object') Object.freeze(value.bootstrap);
  return Object.freeze(value);
}

function parseCommand(rawArgv) {
  const argv = captureArgv(rawArgv);
  const jsonCount = argv.filter((value) => value === '--json').length;
  if (jsonCount > 1) usage();
  const json = jsonCount === 1;
  const tokens = argv.filter((value) => value !== '--json');
  const [scope, action] = tokens;
  let command;

  if (scope === 'preflight' && tokens.length === 1) {
    command = { name: 'preflight', offline: true, bootstrap: { name: 'preflight' } };
  } else if (scope === 'agent' && action === 'enroll' && tokens.length >= 3) {
    const descriptorPath = inputPath(tokens[2]);
    const flags = parseFlags(tokens, 3, { '--confirm': exactHash }, ['--confirm']);
    command = {
      name: 'agent-enroll', offline: true,
      bootstrap: { name: 'agent-enroll', descriptorPath, expectedDescriptorHash: flags['--confirm'] },
    };
  } else if (scope === 'isolation' && action === 'attest' && tokens.length >= 3) {
    const reportPath = inputPath(tokens[2]);
    const flags = parseFlags(tokens, 3, { '--confirm': exactHash }, ['--confirm']);
    command = {
      name: 'isolation-attest', offline: true,
      bootstrap: { name: 'isolation-attest', reportPath, expectedReportHash: flags['--confirm'] },
    };
  } else if (scope === 'policy' && action === 'validate' && tokens.length === 3) {
    command = {
      name: 'policy-validate', offline: true,
      bootstrap: { name: 'policy-validate', policyPath: inputPath(tokens[2]) },
    };
  } else if (scope === 'policy' && action === 'apply' && tokens.length >= 3) {
    const policyPath = inputPath(tokens[2]);
    const flags = parseFlags(tokens, 3, { '--confirm': exactHash }, ['--confirm']);
    command = {
      name: 'policy-apply', offline: true,
      bootstrap: { name: 'policy-apply', policyPath, expectedPolicyHash: flags['--confirm'] },
    };
  } else if (scope === 'agent' && action === 'revoke' && tokens.length >= 3) {
    const agentInstanceId = exactId(tokens[2]);
    const flags = parseFlags(tokens, 3, { '--confirm': exactHash }, ['--confirm']);
    command = {
      name: 'agent-revoke', method: 'POST',
      path: `/operator/v1/agents/${agentInstanceId}/revoke`,
      body: { expectedEnrollmentHash: flags['--confirm'] },
    };
  } else if (scope === 'console' && action === 'launch' && tokens.length === 2) {
    command = {
      name: 'console-launch', method: 'POST', path: '/operator/v1/browser-launch', body: null,
      consoleLaunch: true,
    };
  } else if (scope === 'sessions' && action === 'transition' && tokens.length >= 3) {
    const sessionId = exactId(tokens[2]);
    const flags = parseFlags(
      tokens,
      3,
      { '--to-policy': exactHash, '--confirm': exactHash },
      ['--to-policy', '--confirm'],
    );
    command = {
      name: 'sessions-transition', method: 'POST',
      path: `/operator/v1/sessions/${sessionId}/transition-policy`,
      body: { targetPolicyHash: flags['--to-policy'], expectedSessionHash: flags['--confirm'] },
    };
  } else if (scope === 'sessions' && action === 'close' && tokens.length >= 3) {
    const sessionId = exactId(tokens[2]);
    const flags = parseFlags(tokens, 3, { '--confirm': exactHash }, ['--confirm']);
    command = {
      name: 'sessions-close', method: 'POST',
      path: `/operator/v1/sessions/${sessionId}/close`,
      body: { expectedSessionHash: flags['--confirm'] },
    };
  } else if (scope === 'approvals' && action === 'list' && tokens.length >= 2) {
    const flags = parseFlags(tokens, 2, { '--state': (value) => {
      if (value !== 'pending') usage();
      return value;
    } });
    command = {
      name: 'approvals-list', method: 'GET',
      path: Object.hasOwn(flags, '--state')
        ? '/operator/v1/approvals?state=pending'
        : '/operator/v1/approvals',
      body: null,
    };
  } else if (scope === 'approvals'
      && (action === 'approve' || action === 'deny') && tokens.length >= 3) {
    const approvalId = exactId(tokens[2]);
    const allowed = { '--confirm': exactHash };
    if (action === 'deny') {
      allowed['--reason'] = (value) => {
        if (value !== 'OPERATOR_DENIED') usage();
        return value;
      };
    }
    const required = action === 'deny' ? ['--confirm', '--reason'] : ['--confirm'];
    const flags = parseFlags(tokens, 3, allowed, required);
    command = {
      name: `approvals-${action}`, method: 'POST',
      path: `/operator/v1/approvals/${approvalId}/${action}`,
      body: {
        expectedIntentHash: flags['--confirm'],
        ...(action === 'deny' ? { reasonCode: flags['--reason'] } : {}),
      },
    };
  } else if (scope === 'receipts' && action === 'list' && tokens.length === 2) {
    command = {
      name: 'receipts-list', method: 'GET', path: '/operator/v1/receipts', body: null,
    };
  } else if (scope === 'receipts' && action === 'verify' && tokens.length === 3) {
    const receiptId = exactId(tokens[2]);
    command = {
      name: 'receipts-verify', method: 'GET',
      path: `/operator/v1/receipts/${receiptId}`, body: null,
    };
  } else if (scope === 'reconcile'
      && ['payment', 'execution', 'refund-observation'].includes(action)
      && tokens.length >= 3) {
    const intentId = exactId(tokens[2]);
    const allowed = { '--confirm': exactHash, '--confirm-case': exactHash };
    const required = ['--confirm', '--confirm-case'];
    if (action === 'payment') allowed['--payment-transaction'] = exactTransaction;
    if (action === 'refund-observation') {
      allowed['--refund-transaction'] = exactTransaction;
      required.push('--refund-transaction');
    }
    const flags = parseFlags(tokens, 3, allowed, required);
    command = {
      name: `reconcile-${action}`, method: 'POST',
      path: `/operator/v1/reconciliations/${intentId}/${action}`,
      body: {
        expectedIntentHash: flags['--confirm'],
        expectedCaseHash: flags['--confirm-case'],
        ...(Object.hasOwn(flags, '--payment-transaction')
          ? { paymentTransactionId: flags['--payment-transaction'] }
          : {}),
        ...(Object.hasOwn(flags, '--refund-transaction')
          ? { refundTransactionId: flags['--refund-transaction'] }
          : {}),
      },
    };
  } else if (scope === 'reconcile' && action === 'abandon-candidate' && tokens.length >= 3) {
    const intentId = exactId(tokens[2]);
    const flags = parseFlags(tokens, 3, {
      '--kind': (value) => {
        if (value !== 'payment' && value !== 'refund-observation') usage();
        return value;
      },
      '--confirm': exactHash,
      '--confirm-case': exactHash,
    }, ['--kind', '--confirm', '--confirm-case']);
    command = {
      name: 'reconcile-abandon-candidate', method: 'POST',
      path: `/operator/v1/reconciliations/${intentId}/${flags['--kind']}/abandon-candidate`,
      body: { expectedIntentHash: flags['--confirm'], expectedCaseHash: flags['--confirm-case'] },
    };
  } else if (scope === 'export' && tokens.length >= 2) {
    const sessionId = exactId(tokens[1]);
    const flags = parseFlags(tokens, 2, { '--output': (value) => canonicalAbsolutePath(value, 'CLI_USAGE') }, ['--output']);
    command = {
      name: 'export', method: 'GET', path: `/operator/v1/exports/${sessionId}`, body: null,
      exportOutputPath: flags['--output'],
    };
  } else {
    usage();
  }

  return Object.freeze({ command: freezeCommand(command), json });
}

function assertSafeData(
  value,
  ownerToken,
  ancestors = new Set(),
  state = { nodes: 0 },
  depth = 0,
  location = [],
) {
  state.nodes += 1;
  if (state.nodes > 20_000 || depth > 64) fail('OPERATOR_RESPONSE_UNSAFE');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (value.includes(ownerToken)) fail('OPERATOR_RESPONSE_UNSAFE');
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) fail('OPERATOR_RESPONSE_UNSAFE');
    return;
  }
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || ancestors.has(value)) {
    fail('OPERATOR_RESPONSE_UNSAFE');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) fail('OPERATOR_RESPONSE_UNSAFE');
      const descriptors = Object.getOwnPropertyDescriptors(value);
      if (Reflect.ownKeys(value).length !== value.length + 1) fail('OPERATOR_RESPONSE_UNSAFE');
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
          fail('OPERATOR_RESPONSE_UNSAFE');
        }
        assertSafeData(descriptor.value, ownerToken, ancestors, state, depth + 1, location);
      }
      return;
    }
    if (!isPlainDataObject(value)) fail('OPERATOR_RESPONSE_UNSAFE');
    const descriptors = ownDataDescriptors(value, 'OPERATOR_RESPONSE_UNSAFE');
    const descriptorKeys = Object.keys(descriptors).sort();
    const exactKeys = (required, optional = []) => {
      const allowed = new Set([...required, ...optional]);
      return required.every((key) => Object.hasOwn(descriptors, key))
        && descriptorKeys.every((key) => allowed.has(key));
    };
    const signatureValue = descriptors.signature?.value;
    const canonicalSignature = typeof signatureValue === 'string'
      && CANONICAL_SIGNATURE_PATTERN.test(signatureValue)
      && Buffer.from(signatureValue, 'base64').length === 64
      && Buffer.from(signatureValue, 'base64').toString('base64') === signatureValue;
    const projectionBundle = exactKeys([
      'schemaVersion', 'domain', 'projection', 'projectionHash',
      'algorithm', 'keyId', 'publicKeyPem', 'signature',
    ])
      && descriptors.schemaVersion.value === 1
      && descriptors.domain.value === 'wallet-kernel.projection-export.v1'
      && descriptors.algorithm.value === 'Ed25519'
      && HASH_PATTERN.test(descriptors.projectionHash.value)
      && HASH_PATTERN.test(descriptors.keyId.value)
      && typeof descriptors.publicKeyPem.value === 'string'
      && canonicalSignature;
    const receiptBundle = exactKeys(
      ['receipt', 'receiptHash', 'algorithm', 'keyId', 'signature'],
      ['id', 'intentId', 'revision', 'supersedesReceiptHash', 'createdAt'],
    )
      && descriptors.algorithm?.value === 'Ed25519'
      && typeof descriptors.receiptHash?.value === 'string'
      && SIGNED_RECEIPT_HASH_PATTERN.test(descriptors.receiptHash.value)
      && typeof descriptors.keyId?.value === 'string'
      && HASH_PATTERN.test(descriptors.keyId.value)
      && canonicalSignature;
    for (const [key, descriptor] of Object.entries(descriptors)) {
      const normalizedKey = key.replaceAll(/[-_]/g, '').toLowerCase();
      const hashProjection = PUBLIC_HASH_KEYS.has(key)
        && typeof descriptor.value === 'string'
        && ((key === 'receiptHash' || key === 'supersedesReceiptHash')
          ? SIGNED_RECEIPT_HASH_PATTERN.test(descriptor.value)
          : HASH_PATTERN.test(descriptor.value));
      const allowedPublicField = (key === 'tokenContract'
          && typeof descriptor.value === 'string'
          && /^0x[0-9a-f]{40}$/.test(descriptor.value))
        || (key === 'authorizationState' && typeof descriptor.value === 'boolean')
        || (key === 'evidencePath'
          && typeof descriptor.value === 'string'
          && /^\/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{1,2047}$/.test(descriptor.value))
        || hashProjection;
      const projectionSignature = key === 'signature' && projectionBundle;
      const receiptSignature = key === 'signature' && receiptBundle;
      if ((!allowedPublicField && !projectionSignature && !receiptSignature
            && FORBIDDEN_OUTPUT_KEY_FRAGMENT.test(normalizedKey))
          || (normalizedKey === 'signature' && !projectionSignature && !receiptSignature)) {
        fail('OPERATOR_RESPONSE_UNSAFE');
      }
      assertSafeData(
        descriptor.value,
        ownerToken,
        ancestors,
        state,
        depth + 1,
        [...location, key],
      );
    }
  } finally {
    ancestors.delete(value);
  }
}

function captureResponse(response, ownerToken) {
  if (!isPlainDataObject(response)) fail('OPERATOR_RESPONSE_INVALID');
  const descriptors = ownDataDescriptors(response, 'OPERATOR_RESPONSE_INVALID');
  const keys = Object.keys(descriptors).sort();
  if (canonicalJson(keys) !== canonicalJson(['body', 'headers', 'status'])) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  const status = descriptors.status.value;
  const body = descriptors.body.value;
  const headers = descriptors.headers.value;
  if (!Number.isSafeInteger(status) || status < 100 || status > 599
      || typeof body !== 'string' || Buffer.byteLength(body, 'utf8') > MAXIMUM_RESPONSE_BYTES
      || !isPlainDataObject(headers)) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  const headerDescriptors = ownDataDescriptors(headers, 'OPERATOR_RESPONSE_INVALID');
  if (canonicalJson(Object.keys(headerDescriptors).sort())
        !== canonicalJson(['cache-control', 'content-type'])
      || headerDescriptors['cache-control'].value !== 'no-store'
      || headerDescriptors['content-type'].value !== 'application/json') {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  let parsed;
  try {
    parsed = body === '' ? null : JSON.parse(body);
  } catch {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  if (status < 200 || status >= 300) {
    if (!isPlainDataObject(parsed)) fail('OPERATOR_RESPONSE_INVALID');
    const envelope = ownDataDescriptors(parsed, 'OPERATOR_RESPONSE_INVALID');
    if (canonicalJson(Object.keys(envelope).sort()) !== canonicalJson(['error', 'ok'])
        || envelope.ok.value !== false || !isPlainDataObject(envelope.error.value)) {
      fail('OPERATOR_RESPONSE_INVALID');
    }
    const error = ownDataDescriptors(envelope.error.value, 'OPERATOR_RESPONSE_INVALID');
    if (canonicalJson(Object.keys(error).sort()) !== canonicalJson(['code', 'message'])
        || typeof error.code.value !== 'string'
        || !ERROR_CODE_PATTERN.test(error.code.value)
        || typeof error.message.value !== 'string'
        || Buffer.byteLength(error.message.value, 'utf8') > 512
        || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(error.message.value)) {
      fail('OPERATOR_RESPONSE_INVALID');
    }
    fail(error.code.value);
  }
  if (!isPlainDataObject(parsed)) fail('OPERATOR_RESPONSE_INVALID');
  const envelope = ownDataDescriptors(parsed, 'OPERATOR_RESPONSE_INVALID');
  if (canonicalJson(Object.keys(envelope).sort()) !== canonicalJson(['data', 'ok'])
      || envelope.ok.value !== true) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  let data;
  try {
    data = projectOperatorPublicResult(envelope.data.value);
  } catch {
    fail('OPERATOR_RESPONSE_UNSAFE');
  }
  assertSafeData(data, ownerToken);
  canonicalJson(data);
  return data;
}

function validateConsoleLaunch(value, ownerToken) {
  if (!isPlainDataObject(value)) fail('OPERATOR_RESPONSE_INVALID');
  const descriptors = ownDataDescriptors(value, 'OPERATOR_RESPONSE_INVALID');
  if (canonicalJson(Object.keys(descriptors).sort()) !== canonicalJson(['expiresAt', 'url'])) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  const url = descriptors.url.value;
  const expiresAt = descriptors.expiresAt.value;
  if (typeof url !== 'string' || typeof expiresAt !== 'string'
      || new Date(Date.parse(expiresAt)).toISOString() !== expiresAt) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  let parsed;
  try { parsed = new URL(url); } catch { fail('OPERATOR_RESPONSE_INVALID'); }
  if (parsed.origin !== ORIGIN || parsed.pathname !== '/operator/'
      || parsed.search !== '' || parsed.username !== '' || parsed.password !== ''
      || !/^#launch=[A-Za-z0-9_-]{43}$/.test(parsed.hash)) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  const launchToken = parsed.hash.slice('#launch='.length);
  const decoded = Buffer.from(launchToken, 'base64url');
  if (decoded.length !== 32 || decoded.toString('base64url') !== launchToken
      || launchToken === ownerToken) {
    fail('OPERATOR_RESPONSE_INVALID');
  }
  return Object.freeze({ url, expiresAt });
}

function extractErrorCode(error, fallback = 'OPERATOR_REQUEST_FAILED') {
  if (error instanceof CliError && ERROR_CODE_PATTERN.test(error.code)) return error.code;
  if (typeof error?.code === 'string' && ERROR_CODE_PATTERN.test(error.code)
      && !/^E[A-Z0-9]+$/.test(error.code)) {
    return error.code;
  }
  return fallback;
}

function emitFailure(stderr, json, code, withUsage = false) {
  if (json) {
    stderr.write(`${canonicalJson({ error: { code }, ok: false })}\n`);
  } else {
    stderr.write(`error: ${code}\n`);
    if (withUsage) stderr.write(`${USAGE}\n`);
  }
}

function emitSuccess(stdout, json, command, result) {
  if (command.consoleLaunch) {
    const launch = result;
    if (json) {
      stdout.write(`${canonicalJson({ command: command.name, expiresAt: launch.expiresAt, ok: true, url: launch.url })}\n`);
    } else {
      stdout.write(`${launch.url}\n`);
    }
    return;
  }
  if (command.exportOutputPath) {
    if (json) {
      stdout.write(`${canonicalJson({ command: command.name, ok: true, written: true })}\n`);
    } else {
      stdout.write('export: written\n');
    }
    return;
  }
  if (json) {
    stdout.write(`${canonicalJson({ command: command.name, ok: true, result })}\n`);
  } else {
    stdout.write(`${command.name}: ${canonicalJson(result)}\n`);
  }
}

function preflightExport(outputPath) {
  const guard = openPrivateParent(outputPath, 'EXPORT_OUTPUT_UNSAFE');
  try {
    try {
      fs.lstatSync(outputPath, { bigint: true });
      fail('EXPORT_OUTPUT_UNSAFE');
    } catch (error) {
      if (error instanceof CliError) throw error;
      if (error?.code !== 'ENOENT') fail('EXPORT_OUTPUT_UNSAFE');
    }
    guard.revalidate();
    return Object.freeze({
      revalidate: guard.revalidate,
      close() { fs.closeSync(guard.descriptor); },
    });
  } catch (error) {
    try { fs.closeSync(guard.descriptor); } catch {}
    throw error;
  }
}

function writeExclusiveExport(outputPath, value, guard) {
  const bytes = Buffer.from(canonicalJson(value), 'utf8');
  let descriptor;
  let createdIdentity = null;
  try {
    guard.revalidate();
    descriptor = fs.openSync(
      outputPath,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
      0o600,
    );
    fs.fchmodSync(descriptor, 0o600);
    let stat = fs.fstatSync(descriptor, { bigint: true });
    createdIdentity = statIdentity(stat);
    if (!stat.isFile() || Number(stat.uid) !== currentUid()
        || Number(stat.mode & 0o777n) !== 0o600) {
      fail('EXPORT_OUTPUT_UNSAFE');
    }
    let offset = 0;
    while (offset < bytes.length) {
      const count = fs.writeSync(descriptor, bytes, offset, bytes.length - offset, offset);
      if (count <= 0) fail('EXPORT_OUTPUT_UNSAFE');
      offset += count;
    }
    fs.fsyncSync(descriptor);
    stat = fs.fstatSync(descriptor, { bigint: true });
    const pathStat = fs.lstatSync(outputPath, { bigint: true });
    guard.revalidate();
    if (!sameIdentity(createdIdentity, statIdentity(stat))
        || pathStat.isSymbolicLink() || !pathStat.isFile()
        || !sameIdentity(createdIdentity, statIdentity(pathStat))
        || stat.size !== BigInt(bytes.length)) {
      fail('EXPORT_OUTPUT_UNSAFE');
    }
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
      descriptor = undefined;
    }
    if (createdIdentity !== null) {
      try {
        const stat = fs.lstatSync(outputPath, { bigint: true });
        if (!stat.isSymbolicLink() && sameIdentity(createdIdentity, statIdentity(stat))) {
          fs.unlinkSync(outputPath);
        }
      } catch {}
    }
    if (error instanceof CliError) throw error;
    fail('EXPORT_OUTPUT_UNSAFE');
  } finally {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
  }
}

async function nodeHttpRequest({ socketPath, origin, method, path: requestPath, headers, body }) {
  return new Promise((resolve, reject) => {
    const parsedOrigin = new URL(origin);
    const options = socketPath === null
      ? {
        hostname: parsedOrigin.hostname,
        port: Number(parsedOrigin.port),
        method,
        path: requestPath,
        headers,
      }
      : {
        socketPath,
        method,
        path: requestPath,
        headers: { ...headers, host: parsedOrigin.host },
      };
    const request = http.request(options, (response) => {
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > MAXIMUM_RESPONSE_BYTES) {
          request.destroy(new Error('bounded operator response exceeded'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => resolve(Object.freeze({
        status: response.statusCode,
        headers: Object.freeze({
          'cache-control': response.headers['cache-control'],
          'content-type': response.headers['content-type'],
        }),
        body: Buffer.concat(chunks).toString('utf8'),
      })));
    });
    request.once('error', reject);
    if (body !== null) request.write(body);
    request.end();
  });
}

export async function runOperatorCli({
  argv,
  env,
  requestImpl = nodeHttpRequest,
  stdout = process.stdout,
  stderr = process.stderr,
  offlineBootstrap = runOfflineBootstrap,
}) {
  let json = false;
  let parsed;
  let exportGuard = null;
  let socketGuard = null;
  try {
    try {
      parsed = parseCommand(argv);
      json = parsed.json;
    } catch (error) {
      json = !utilTypes.isProxy(argv)
        && Array.isArray(argv)
        && argv.filter((value) => value === '--json').length === 1;
      throw error;
    }
    if (!stdout || typeof stdout.write !== 'function'
        || !stderr || typeof stderr.write !== 'function'
        || typeof requestImpl !== 'function') {
      fail('CLI_CONFIG_INVALID');
    }
    const config = captureConfig(env);
    if (parsed.command.offline && config.databasePath === null) fail('CLI_CONFIG_INVALID');
    if (parsed.command.exportOutputPath) {
      exportGuard = preflightExport(parsed.command.exportOutputPath);
    }
    const operatorToken = readOperatorToken(config.operatorTokenPath);

    let result;
    if (parsed.command.offline) {
      if (typeof offlineBootstrap !== 'function') fail('OFFLINE_BOOTSTRAP_UNAVAILABLE');
      result = await offlineBootstrap(Object.freeze({
        command: parsed.command.bootstrap,
        config,
        operatorToken,
      }));
      assertSafeData(result, operatorToken);
      canonicalJson(result);
    } else {
      if (config.mode === 'cdp-testnet') {
        socketGuard = inspectAdminSocket(config.operatorSocketPath);
        socketGuard.revalidate();
      }
      const body = parsed.command.body === null ? null : canonicalJson(parsed.command.body);
      const headers = Object.freeze({
        accept: 'application/json',
        authorization: `Bearer ${operatorToken}`,
        ...(body === null ? {} : { 'content-type': 'application/json' }),
      });
      const request = Object.freeze({
        socketPath: config.mode === 'cdp-testnet' ? config.operatorSocketPath : null,
        origin: config.origin,
        method: parsed.command.method,
        path: parsed.command.path,
        headers,
        body,
      });
      let rawResponse;
      try {
        rawResponse = await requestImpl(request);
      } catch {
        fail('OPERATOR_REQUEST_FAILED');
      }
      if (socketGuard) socketGuard.revalidate();
      result = captureResponse(rawResponse, operatorToken);
    }

    if (parsed.command.consoleLaunch) {
      result = validateConsoleLaunch(result, operatorToken);
    }
    if (parsed.command.exportOutputPath) {
      writeExclusiveExport(parsed.command.exportOutputPath, result, exportGuard);
    }
    emitSuccess(stdout, json, parsed.command, result);
    return 0;
  } catch (error) {
    const code = extractErrorCode(error);
    const withUsage = error instanceof CliError && error.usage;
    emitFailure(stderr, json, code, withUsage);
    return withUsage ? 2 : 1;
  } finally {
    if (socketGuard) {
      try { socketGuard.close(); } catch {}
    }
    if (exportGuard) {
      try { exportGuard.close(); } catch {}
    }
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const exitCode = await runOperatorCli({ argv: process.argv.slice(2), env: process.env });
  process.exitCode = exitCode;
}

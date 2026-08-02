#!/usr/bin/env node

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalTimestamp,
  exactRecord,
  frozenCopy,
  sha256,
} from '../src/kernel/canonical.mjs';

const DOMAIN = 'wallet-kernel.testnet-agent-run.v1';
const AGENT_CALL_DOMAIN = 'wallet-kernel.testnet-agent-call.v1\0';
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const HASH = /^sha256:[0-9a-f]{64}$/u;
const COMMIT = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const ADDRESS = /^0x[0-9a-f]{40}$/u;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const ROUTE_PATH = /^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@%-]+\/?)*$/u;
const MAXIMUM_INTENT_LIFETIME_MS = 15 * 60 * 1_000;
const MAXIMUM_INTENT_BYTES = 65_536;
const MAXIMUM_CREDENTIAL_BYTES = 256;
const MAXIMUM_RESPONSE_BYTES = 1_048_576;
const REQUEST_TIMEOUT_MS = 30_000;
const INSTANCE = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/u;
const CREDENTIAL_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const FORBIDDEN_AGENT_ENVIRONMENT = Object.freeze([
  'CDP_API_KEY_ID',
  'CDP_API_KEY_SECRET',
  'CDP_WALLET_SECRET',
  'CDP_WALLET_NAME',
  'PRIVATE_KEY',
  'WALLET_PRIVATE_KEY',
  'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
  'WALLET_KERNEL_OPERATOR_TOKEN_FILE',
  'WALLET_KERNEL_RECEIPT_KEY_FILE',
]);

const INTENT_FIELDS = Object.freeze([
  'schemaVersion', 'domain', 'runId', 'createdAt', 'expiresAt', 'network', 'asset',
  'gitCommit', 'deployment', 'walletAddress', 'policyHash', 'routeMapHash',
  'maximumTotalAtomic', 'kernelOrigin', 'kernelIdentity', 'agentIdentity',
  'credentialDigest', 'sellerRoutes',
]);
const DEPLOYMENT_FIELDS = Object.freeze([
  'releaseManifestDigest', 'releaseTreeHash', 'serviceArtifactsHash',
  'systemdEffectiveConfigHash',
]);

export class TestnetAgentRunnerError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'TestnetAgentRunnerError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new TestnetAgentRunnerError(code, message, cause ? { cause } : undefined);
}

function record(value, fields, code, label) {
  try {
    return exactRecord(value, fields, [], code, label);
  } catch (cause) {
    if (cause?.code === code) throw new TestnetAgentRunnerError(code, cause.message, { cause });
    return fail(code, `${label} fields do not match the closed schema`, cause);
  }
}

function canonicalIdentity(value, label) {
  const identity = record(value, ['uid', 'gid'], 'TESTNET_RUN_INTENT_SCHEMA', label);
  for (const field of ['uid', 'gid']) {
    if (typeof identity[field] !== 'string' || !/^[1-9][0-9]*$/u.test(identity[field])
        || !Number.isSafeInteger(Number(identity[field]))) {
      fail('TESTNET_RUN_INTENT_IDENTITY', `${label} must contain positive decimal identity text`);
    }
  }
  return identity;
}

function canonicalLoopbackOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch {
    return fail('TESTNET_RUN_INTENT_ORIGIN', 'Kernel origin must be one exact loopback origin');
  }
  if (typeof value !== 'string' || parsed.protocol !== 'http:'
      || parsed.hostname !== '127.0.0.1' || parsed.port === ''
      || parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== ''
      || parsed.username !== '' || parsed.password !== '' || parsed.origin !== value) {
    fail('TESTNET_RUN_INTENT_ORIGIN', 'Kernel origin must be one exact loopback origin');
  }
  return value;
}

function canonicalSellerOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch {
    return fail('TESTNET_RUN_INTENT_ROUTE', 'seller origin is invalid');
  }
  if (typeof value !== 'string' || parsed.protocol !== 'https:'
      || parsed.username !== '' || parsed.password !== '' || parsed.port !== ''
      || parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== ''
      || parsed.origin !== value) {
    fail('TESTNET_RUN_INTENT_ROUTE', 'seller origin must be one exact HTTPS origin');
  }
  return value;
}

function validateRoute(value, index) {
  const route = record(
    value,
    ['routeId', 'kind', 'sellerOrigin', 'resourcePath', 'model'],
    'TESTNET_RUN_INTENT_SCHEMA',
    `seller route ${index}`,
  );
  if (typeof route.routeId !== 'string' || !TOKEN.test(route.routeId)
      || !['openai-chat', 'tool'].includes(route.kind)
      || typeof route.resourcePath !== 'string' || !ROUTE_PATH.test(route.resourcePath)
      || route.resourcePath.includes('//') || route.resourcePath.includes('?')
      || route.resourcePath.includes('#')
      || ((route.kind === 'openai-chat') !== (typeof route.model === 'string'))
      || (route.model !== null && !TOKEN.test(route.model))) {
    fail('TESTNET_RUN_INTENT_ROUTE', 'seller route fields are invalid');
  }
  canonicalSellerOrigin(route.sellerOrigin);
  return route;
}

export function validateTestnetRunIntent(value, { now = new Date().toISOString() } = {}) {
  const intent = record(
    value,
    INTENT_FIELDS,
    'TESTNET_RUN_INTENT_SCHEMA',
    'testnet run intent',
  );
  if (intent.schemaVersion !== 1 || intent.domain !== DOMAIN
      || typeof intent.runId !== 'string' || !TOKEN.test(intent.runId)
      || typeof intent.gitCommit !== 'string' || !COMMIT.test(intent.gitCommit)
      || typeof intent.walletAddress !== 'string' || !ADDRESS.test(intent.walletAddress)) {
    fail('TESTNET_RUN_INTENT_SCHEMA', 'testnet run intent fields are invalid');
  }
  if (intent.network !== NETWORK || intent.asset !== ASSET) {
    fail('TESTNET_RUN_INTENT_NETWORK', 'only canonical Base Sepolia USDC is permitted');
  }
  try {
    canonicalTimestamp(intent.createdAt, 'run intent createdAt');
    canonicalTimestamp(intent.expiresAt, 'run intent expiresAt');
    canonicalTimestamp(now, 'run intent validation time');
  } catch (cause) {
    fail('TESTNET_RUN_INTENT_TIME', 'run intent timestamps are invalid', cause);
  }
  const created = Date.parse(intent.createdAt);
  const expires = Date.parse(intent.expiresAt);
  const observed = Date.parse(now);
  if (expires <= created || expires - created > MAXIMUM_INTENT_LIFETIME_MS
      || observed < created || observed >= expires) {
    fail('TESTNET_RUN_INTENT_TIME', 'run intent is not currently valid');
  }
  const deployment = record(
    intent.deployment,
    DEPLOYMENT_FIELDS,
    'TESTNET_RUN_INTENT_SCHEMA',
    'testnet deployment binding',
  );
  for (const [label, hash] of Object.entries({
    ...deployment,
    policyHash: intent.policyHash,
    routeMapHash: intent.routeMapHash,
    credentialDigest: intent.credentialDigest,
  })) {
    if (typeof hash !== 'string' || !HASH.test(hash)) {
      fail('TESTNET_RUN_INTENT_SCHEMA', `${label} must be one canonical SHA-256 digest`);
    }
  }
  let maximum;
  try { maximum = canonicalAtomic(intent.maximumTotalAtomic, 'run maximum'); } catch (cause) {
    fail('TESTNET_RUN_INTENT_SCHEMA', 'maximum total must be canonical atomic text', cause);
  }
  if (maximum.value <= 0n || intent.maximumTotalAtomic.length > 78) {
    fail('TESTNET_RUN_INTENT_SCHEMA', 'maximum total must be positive bounded atomic text');
  }
  canonicalLoopbackOrigin(intent.kernelOrigin);
  const kernelIdentity = canonicalIdentity(intent.kernelIdentity, 'Kernel identity');
  const agentIdentity = canonicalIdentity(intent.agentIdentity, 'Agent identity');
  if (kernelIdentity.uid === agentIdentity.uid) {
    fail('TESTNET_RUN_INTENT_IDENTITY', 'Kernel and Agent UIDs must be distinct');
  }
  if (!Array.isArray(intent.sellerRoutes) || intent.sellerRoutes.length < 1
      || intent.sellerRoutes.length > 16) {
    fail('TESTNET_RUN_INTENT_ROUTE', 'run intent must contain one bounded route list');
  }
  const routes = intent.sellerRoutes.map(validateRoute);
  if (new Set(routes.map(({ routeId }) => routeId)).size !== routes.length) {
    fail('TESTNET_RUN_INTENT_ROUTE', 'run intent route IDs must be unique');
  }
  return frozenCopy({
    ...intent,
    deployment,
    kernelIdentity,
    agentIdentity,
    sellerRoutes: routes,
  });
}

export function testnetRunIntentDigest(intent) {
  return sha256(canonicalJson(intent));
}

export function testnetAgentCallId(intentDigest, routeId) {
  if (typeof intentDigest !== 'string' || !HASH.test(intentDigest)
      || typeof routeId !== 'string' || !TOKEN.test(routeId)) {
    fail('TESTNET_AGENT_REQUEST', 'Agent logical call binding is invalid');
  }
  return crypto.createHash('sha256')
    .update(AGENT_CALL_DOMAIN, 'utf8')
    .update(intentDigest, 'utf8')
    .update('\0', 'utf8')
    .update(routeId, 'utf8')
    .digest('base64url');
}

function canonicalAbsolute(value, code, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) {
    fail(code, `${label} must be one canonical absolute path`);
  }
  return value;
}

function fileIdentity(stat) {
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

function sameFileIdentity(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function readExactBytes(descriptor, size) {
  const bytes = Buffer.alloc(Number(size));
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
    if (count <= 0) fail('TESTNET_RUN_INTENT_FILE', 'run intent was truncated during read');
    offset += count;
  }
  const overflow = Buffer.alloc(1);
  try {
    if (fs.readSync(descriptor, overflow, 0, 1, offset) !== 0) {
      fail('TESTNET_RUN_INTENT_FILE', 'run intent grew during read');
    }
  } finally {
    overflow.fill(0);
  }
  return bytes;
}

function parseCanonicalIntent(bytes, now) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (cause) {
    fail('TESTNET_RUN_INTENT_FILE', 'run intent is not canonical UTF-8', cause);
  }
  if (!text.endsWith('\n') || text.slice(0, -1).includes('\n') || text.includes('\0')) {
    fail('TESTNET_RUN_INTENT_FILE', 'run intent must contain canonical JSON plus one newline');
  }
  let value;
  try { value = JSON.parse(text.slice(0, -1)); } catch (cause) {
    fail('TESTNET_RUN_INTENT_FILE', 'run intent is not JSON', cause);
  }
  const intent = validateTestnetRunIntent(value, { now });
  if (text !== `${canonicalJson(intent)}\n`) {
    fail('TESTNET_RUN_INTENT_FILE', 'run intent bytes are not canonical JSON');
  }
  return intent;
}

export function readTestnetRunIntent({
  filePath,
  outboxPath,
  expectedDigest,
  now = new Date().toISOString(),
}) {
  const destination = canonicalAbsolute(
    filePath,
    'TESTNET_RUN_INTENT_PATH',
    'run intent path',
  );
  const outbox = canonicalAbsolute(
    outboxPath,
    'TESTNET_RUN_INTENT_PATH',
    'Agent run outbox',
  );
  if (path.dirname(destination) !== outbox || path.basename(destination) === '') {
    fail('TESTNET_RUN_INTENT_PATH', 'run intent must be one direct child of the configured outbox');
  }
  let actualOutbox;
  try { actualOutbox = fs.realpathSync(outbox); } catch (cause) {
    fail('TESTNET_RUN_INTENT_PATH', 'Agent run outbox does not exist', cause);
  }
  if (actualOutbox !== outbox || typeof expectedDigest !== 'string' || !HASH.test(expectedDigest)) {
    fail('TESTNET_RUN_INTENT_PATH', 'run intent path or confirmation digest is invalid');
  }

  let parentDescriptor;
  let descriptor;
  let bytes;
  try {
    parentDescriptor = fs.openSync(
      outbox,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const parentBeforeStat = fs.fstatSync(parentDescriptor, { bigint: true });
    const parentBefore = fileIdentity(parentBeforeStat);
    if (!parentBeforeStat.isDirectory() || parentBefore.mode !== 0o755n) {
      fail('TESTNET_RUN_INTENT_AUTHORITY', 'Agent run outbox authority is invalid');
    }

    descriptor = fs.openSync(
      destination,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const beforeStat = fs.fstatSync(descriptor, { bigint: true });
    const before = fileIdentity(beforeStat);
    if (!beforeStat.isFile() || before.mode !== 0o644n || before.nlink !== 1n
        || before.size < 1n || before.size > BigInt(MAXIMUM_INTENT_BYTES)) {
      fail('TESTNET_RUN_INTENT_AUTHORITY', 'run intent file authority is invalid');
    }
    bytes = readExactBytes(descriptor, before.size);
    const after = fileIdentity(fs.fstatSync(descriptor, { bigint: true }));
    const pathStat = fs.lstatSync(destination, { bigint: true });
    const parentAfter = fileIdentity(fs.fstatSync(parentDescriptor, { bigint: true }));
    const parentPathStat = fs.lstatSync(outbox, { bigint: true });
    if (!sameFileIdentity(before, after) || pathStat.isSymbolicLink()
        || !sameFileIdentity(before, fileIdentity(pathStat))
        || parentPathStat.isSymbolicLink() || !parentPathStat.isDirectory()
        || !sameFileIdentity(parentBefore, parentAfter)
        || !sameFileIdentity(parentBefore, fileIdentity(parentPathStat))) {
      fail('TESTNET_RUN_INTENT_AUTHORITY', 'run intent authority changed during read');
    }
    const intent = parseCanonicalIntent(bytes, now);
    // The declared Kernel owner is not self-authenticating: expectedDigest is the
    // separately confirmed trust anchor over these exact canonical intent bytes.
    // Only after that binding is checked do we accept the declaration as the UID/GID
    // authority against which the already-open file and parent are compared.
    const intentDigest = testnetRunIntentDigest(intent);
    if (intentDigest !== expectedDigest) {
      fail('TESTNET_RUN_INTENT_CONFIRMATION', 'run intent confirmation does not match');
    }
    const kernelUid = BigInt(intent.kernelIdentity.uid);
    const kernelGid = BigInt(intent.kernelIdentity.gid);
    if (before.uid !== kernelUid || before.gid !== kernelGid
        || parentBefore.uid !== kernelUid || parentBefore.gid !== kernelGid) {
      fail('TESTNET_RUN_INTENT_AUTHORITY', 'run intent is not owned by the declared Kernel');
    }
    return frozenCopy({ intent, intentDigest });
  } catch (cause) {
    if (cause instanceof TestnetAgentRunnerError) throw cause;
    fail('TESTNET_RUN_INTENT_FILE', 'run intent could not be read safely', cause);
  } finally {
    bytes?.fill(0);
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (parentDescriptor !== undefined) fs.closeSync(parentDescriptor);
  }
}

function parseCredential(bytes) {
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch (cause) {
    fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential is not canonical UTF-8', cause);
  }
  if (!text.endsWith('\n') || text.slice(0, -1).includes('\n') || text.includes('\0')) {
    fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential must contain one canonical line');
  }
  let value;
  try { value = JSON.parse(text.slice(0, -1)); } catch (cause) {
    fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential is not JSON', cause);
  }
  const credential = record(
    value,
    ['agentInstanceId', 'schemaVersion', 'token'],
    'TESTNET_AGENT_CREDENTIAL',
    'Agent credential',
  );
  if (credential.schemaVersion !== 1 || !INSTANCE.test(credential.agentInstanceId)
      || !CREDENTIAL_TOKEN.test(credential.token)
      || `${canonicalJson(credential)}\n` !== text) {
    fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential schema or encoding is invalid');
  }
  const instanceBytes = Buffer.from(credential.agentInstanceId, 'base64url');
  const tokenBytes = Buffer.from(credential.token, 'base64url');
  try {
    if (instanceBytes.length !== 16
        || instanceBytes.toString('base64url') !== credential.agentInstanceId
        || tokenBytes.length !== 32
        || tokenBytes.toString('base64url') !== credential.token) {
      fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential opaque values are invalid');
    }
    return { credential: frozenCopy(credential), credentialDigest: sha256(tokenBytes) };
  } finally {
    instanceBytes.fill(0);
    tokenBytes.fill(0);
  }
}

export function readTestnetAgentCredential({
  filePath,
  expectedDigest,
  expectedAgentUid,
  expectedAgentGid,
}) {
  const destination = canonicalAbsolute(
    filePath,
    'TESTNET_AGENT_CREDENTIAL_PATH',
    'Agent credential path',
  );
  if (typeof expectedDigest !== 'string' || !HASH.test(expectedDigest)
      || !Number.isSafeInteger(expectedAgentUid) || expectedAgentUid <= 0
      || !Number.isSafeInteger(expectedAgentGid) || expectedAgentGid <= 0) {
    fail('TESTNET_AGENT_CREDENTIAL_PATH', 'Agent credential authority input is invalid');
  }
  const parent = path.dirname(destination);
  let actualParent;
  try { actualParent = fs.realpathSync(parent); } catch (cause) {
    fail('TESTNET_AGENT_CREDENTIAL_PATH', 'Agent credential parent does not exist', cause);
  }
  if (actualParent !== parent) {
    fail('TESTNET_AGENT_CREDENTIAL_PATH', 'Agent credential parent must not traverse symlinks');
  }

  let parentDescriptor;
  let descriptor;
  let bytes;
  try {
    parentDescriptor = fs.openSync(
      parent,
      fs.constants.O_RDONLY | (fs.constants.O_DIRECTORY ?? 0) | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const parentBeforeStat = fs.fstatSync(parentDescriptor, { bigint: true });
    const parentBefore = fileIdentity(parentBeforeStat);
    if (!parentBeforeStat.isDirectory() || parentBefore.uid !== BigInt(expectedAgentUid)
        || parentBefore.gid !== BigInt(expectedAgentGid) || parentBefore.mode !== 0o700n) {
      fail('TESTNET_AGENT_CREDENTIAL_AUTHORITY', 'Agent credential parent authority is invalid');
    }
    descriptor = fs.openSync(
      destination,
      fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
    );
    const beforeStat = fs.fstatSync(descriptor, { bigint: true });
    const before = fileIdentity(beforeStat);
    if (!beforeStat.isFile() || before.uid !== BigInt(expectedAgentUid)
        || before.gid !== BigInt(expectedAgentGid) || before.mode !== 0o600n
        || before.nlink !== 1n || before.size < 1n
        || before.size > BigInt(MAXIMUM_CREDENTIAL_BYTES)) {
      fail('TESTNET_AGENT_CREDENTIAL_AUTHORITY', 'Agent credential file authority is invalid');
    }
    bytes = readExactBytes(descriptor, before.size);
    const after = fileIdentity(fs.fstatSync(descriptor, { bigint: true }));
    const pathStat = fs.lstatSync(destination, { bigint: true });
    const parentAfter = fileIdentity(fs.fstatSync(parentDescriptor, { bigint: true }));
    const parentPathStat = fs.lstatSync(parent, { bigint: true });
    if (!sameFileIdentity(before, after) || pathStat.isSymbolicLink()
        || !sameFileIdentity(before, fileIdentity(pathStat))
        || parentPathStat.isSymbolicLink() || !parentPathStat.isDirectory()
        || !sameFileIdentity(parentBefore, parentAfter)
        || !sameFileIdentity(parentBefore, fileIdentity(parentPathStat))) {
      fail('TESTNET_AGENT_CREDENTIAL_AUTHORITY', 'Agent credential authority changed during read');
    }
    const parsed = parseCredential(bytes);
    if (parsed.credentialDigest !== expectedDigest) {
      fail('TESTNET_AGENT_CREDENTIAL_BINDING', 'Agent credential does not match the run intent');
    }
    return parsed.credential;
  } catch (cause) {
    if (cause instanceof TestnetAgentRunnerError) throw cause;
    fail('TESTNET_AGENT_CREDENTIAL', 'Agent credential could not be read safely', cause);
  } finally {
    bytes?.fill(0);
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (parentDescriptor !== undefined) fs.closeSync(parentDescriptor);
  }
}

export function parseTestnetAgentArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 4
      || argv[0] !== '--run-intent' || argv[2] !== '--confirm-sha256') {
    fail(
      'TESTNET_AGENT_ARGUMENTS',
      'usage: run-testnet-agent --run-intent ABSOLUTE_PATH --confirm-sha256 sha256:HEX',
    );
  }
  const runIntentPath = canonicalAbsolute(
    argv[1],
    'TESTNET_AGENT_ARGUMENTS',
    'run intent argument',
  );
  if (typeof argv[3] !== 'string' || !HASH.test(argv[3])) {
    fail('TESTNET_AGENT_ARGUMENTS', 'confirmation must be one canonical SHA-256 digest');
  }
  return Object.freeze({ runIntentPath, confirmationDigest: argv[3] });
}

function environmentPath(environment, name) {
  const value = environment?.[name];
  return canonicalAbsolute(value, 'TESTNET_AGENT_ENVIRONMENT', name);
}

function assertAgentEnvironment(environment) {
  for (const name of FORBIDDEN_AGENT_ENVIRONMENT) {
    if (typeof environment?.[name] === 'string' && environment[name] !== '') {
      fail('TESTNET_AGENT_ENVIRONMENT', `Agent process must not receive ${name}`);
    }
  }
}

function assertSeparatedAuthorityPaths(outboxPath, credentialPath) {
  const credentialParent = path.dirname(credentialPath);
  const relativeCredential = path.relative(outboxPath, credentialParent);
  const relativeOutbox = path.relative(credentialParent, outboxPath);
  if (outboxPath === credentialParent
      || (!relativeCredential.startsWith('..') && !path.isAbsolute(relativeCredential))
      || (!relativeOutbox.startsWith('..') && !path.isAbsolute(relativeOutbox))) {
    fail(
      'TESTNET_AGENT_ENVIRONMENT',
      'run-intent outbox and Agent credential authority must be separate',
    );
  }
}

function assertAgentIdentity({ intent, platform, getuid, getgid, getgroups }) {
  if (platform !== 'linux' || typeof getuid !== 'function' || typeof getgid !== 'function'
      || typeof getgroups !== 'function') {
    fail('TESTNET_AGENT_IDENTITY', 'testnet Agent must run under one dedicated Linux identity');
  }
  const uid = getuid();
  const gid = getgid();
  const groups = getgroups();
  const expectedUid = Number(intent.agentIdentity.uid);
  const expectedGid = Number(intent.agentIdentity.gid);
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0
      || uid !== expectedUid || gid !== expectedGid
      || uid === Number(intent.kernelIdentity.uid)
      || !Array.isArray(groups) || groups.some((group) => group !== gid)) {
    fail('TESTNET_AGENT_IDENTITY', 'running process does not match the isolated Agent identity');
  }
  return Object.freeze({ uid, gid });
}

async function boundedResponseBytes(response) {
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > MAXIMUM_RESPONSE_BYTES) {
    bytes.fill(0);
    fail('TESTNET_AGENT_RESPONSE', 'Kernel response exceeded the public response limit');
  }
  return bytes;
}

export async function requestTestnetAgentRoute({
  origin,
  token,
  route,
  agentCallId,
  fetchFn = globalThis.fetch,
}) {
  canonicalLoopbackOrigin(origin);
  validateRoute(route, 0);
  if (typeof token !== 'string' || !CREDENTIAL_TOKEN.test(token)
      || typeof agentCallId !== 'string' || !CREDENTIAL_TOKEN.test(agentCallId)
      || typeof fetchFn !== 'function') {
    fail('TESTNET_AGENT_REQUEST', 'Agent route request inputs are invalid');
  }
  const routeSegment = encodeURIComponent(route.routeId);
  const pathname = route.kind === 'openai-chat'
    ? `/agent/v1/openai/${routeSegment}/chat/completions`
    : `/agent/v1/invoke/${routeSegment}`;
  const value = route.kind === 'openai-chat'
    ? {
        messages: [{ content: 'Reply exactly WALLET_KERNEL_TESTNET_OK.', role: 'user' }],
        model: route.model,
        stream: false,
      }
    : { input: 'wallet-kernel-testnet-acceptance' };

  let response;
  try {
    response = await fetchFn(`${origin}${pathname}`, {
      method: 'POST',
      headers: {
        authorization: `WalletKernelAgent ${token}`,
        'content-type': 'application/json',
        'x-agent-call-id': agentCallId,
      },
      body: canonicalJson(value),
      credentials: 'omit',
      redirect: 'manual',
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (cause) {
    fail('TESTNET_AGENT_REQUEST', 'Kernel route request failed', cause);
  }

  if (response.status !== 200
      || response.headers.get('content-type')?.toLowerCase() !== 'application/json') {
    fail('TESTNET_AGENT_RESPONSE', 'Kernel route response was not canonical JSON success');
  }
  let bytes;
  try {
    bytes = await boundedResponseBytes(response);
    let value;
    try { value = JSON.parse(bytes.toString('utf8')); } catch (cause) {
      fail('TESTNET_AGENT_RESPONSE', 'Kernel route response body was not JSON', cause);
    }
    if (value === null || typeof value !== 'object' || Array.isArray(value)
        || value.status !== 'completed') {
      fail('TESTNET_AGENT_RESPONSE', 'Kernel route did not complete');
    }
    return Object.freeze({ httpStatus: 200, outcome: 'completed' });
  } finally {
    bytes?.fill(0);
  }
}

export async function runTestnetAgent({
  argv = process.argv.slice(2),
  environment = process.env,
  now = () => new Date().toISOString(),
  platform = process.platform,
  getuid = process.getuid,
  getgid = process.getgid,
  getgroups = process.getgroups,
  readRunIntent = readTestnetRunIntent,
  readCredential = readTestnetAgentCredential,
  requestRoute = requestTestnetAgentRoute,
} = {}) {
  assertAgentEnvironment(environment);
  const { runIntentPath, confirmationDigest } = parseTestnetAgentArguments(argv);
  const outboxPath = environmentPath(
    environment,
    'WALLET_KERNEL_AGENT_RUN_OUTBOX',
  );
  const credentialPath = environmentPath(
    environment,
    'WALLET_KERNEL_AGENT_CREDENTIAL_FILE',
  );
  assertSeparatedAuthorityPaths(outboxPath, credentialPath);
  const { intent, intentDigest } = readRunIntent({
    filePath: runIntentPath,
    outboxPath,
    expectedDigest: confirmationDigest,
    now: now(),
  });
  const { uid, gid } = assertAgentIdentity({ intent, platform, getuid, getgid, getgroups });
  const credential = readCredential({
    filePath: credentialPath,
    expectedDigest: intent.credentialDigest,
    expectedAgentUid: uid,
    expectedAgentGid: gid,
  });

  const routes = [];
  for (const route of intent.sellerRoutes) {
    const outcome = await requestRoute({
      origin: intent.kernelOrigin,
      route,
      token: credential.token,
      agentCallId: testnetAgentCallId(intentDigest, route.routeId),
    });
    routes.push(Object.freeze({
      routeId: route.routeId,
      kind: route.kind,
      httpStatus: outcome.httpStatus,
      outcome: outcome.outcome,
    }));
  }
  return frozenCopy({
    status: 'completed',
    mode: 'base-sepolia-testnet',
    runId: intent.runId,
    intentDigest,
    routeCount: routes.length,
    routes,
  });
}

function publicFailure(error) {
  const code = error instanceof TestnetAgentRunnerError
    ? error.code
    : 'TESTNET_AGENT_UNEXPECTED';
  return canonicalJson({ code, mode: 'base-sepolia-testnet', status: 'not-run' });
}

export async function main() {
  try {
    process.stdout.write(`${canonicalJson(await runTestnetAgent())}\n`);
    return 0;
  } catch (error) {
    process.stderr.write(`${publicFailure(error)}\n`);
    return 2;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) process.exitCode = await main();

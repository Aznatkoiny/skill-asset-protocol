import fs from 'node:fs';
import path from 'node:path';

import { KernelError } from '../kernel/canonical.mjs';

export const INSTALLED_CREDENTIAL_PATH =
  '/run/credentials/wallet-kernel.service/wallet-kernel-environment';
const MAXIMUM_ENVIRONMENT_BYTES = 65_536;
const FIELDS = new Set([
  'WALLET_KERNEL_MODE', 'WALLET_KERNEL_DB_FILE', 'WALLET_KERNEL_RECEIPT_KEY_FILE',
  'WALLET_KERNEL_OPERATOR_TOKEN_FILE', 'WALLET_KERNEL_TRUSTED_ANCESTOR',
  'WALLET_KERNEL_EXPECTED_AGENT_UID', 'WALLET_KERNEL_EXPECTED_AGENT_GID',
  'WALLET_KERNEL_POLICY_FILE', 'WALLET_KERNEL_ROUTE_FILE', 'WALLET_KERNEL_PORT',
  'WALLET_KERNEL_OPERATOR_PORT', 'WALLET_KERNEL_OPERATOR_SOCKET_FILE',
  'WALLET_KERNEL_ENROLLMENT_INBOX', 'WALLET_KERNEL_AGENT_RUN_OUTBOX',
  'WALLET_KERNEL_RELEASE_ROOT', 'WALLET_KERNEL_RELEASE_MANIFEST',
  'WALLET_KERNEL_SERVICE_DEFINITION_FILE', 'WALLET_KERNEL_SOCKET_DEFINITION_FILE',
  'WALLET_KERNEL_ENV_FILE', 'WALLET_KERNEL_EVIDENCE_ROOT',
  'WALLET_KERNEL_ISOLATION_REPORT_FILE', 'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
  'CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET', 'CDP_WALLET_NAME',
]);
const REQUIRED_SECRETS = Object.freeze([
  'CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET',
  'CDP_WALLET_NAME', 'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
]);

function fail(code = 'RUNTIME_CREDENTIAL_INVALID') {
  // File paths, parser input, provider messages, and secret values are never diagnostics.
  throw new KernelError(code, 'Installed Wallet Kernel credential delivery refused');
}

export function assertKernelProcessIdentity({ kernelUid, kernelGid }) {
  if (process.platform !== 'linux'
      || !Number.isSafeInteger(kernelUid) || kernelUid <= 0
      || !Number.isSafeInteger(kernelGid) || kernelGid <= 0
      || process.getuid() !== kernelUid || process.geteuid() !== kernelUid
      || process.getgid() !== kernelGid || process.getegid() !== kernelGid
      || process.getgroups().some((gid) => gid !== kernelGid)) {
    fail('RUNTIME_KERNEL_IDENTITY');
  }
}

/** An inert, closed environment document, never a shell script or dotenv expansion. */
export function parseDeliveredEnvironment(bytes, environmentFilePath) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0
      || bytes.length > MAXIMUM_ENVIRONMENT_BYTES
      || typeof environmentFilePath !== 'string'
      || !path.isAbsolute(environmentFilePath)
      || path.resolve(environmentFilePath) !== environmentFilePath) fail();
  let text;
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes); } catch { fail(); }
  if (text.includes('\0') || text.includes('\r') || !text.endsWith('\n')) fail();
  const environment = {};
  for (const line of text.split('\n')) {
    if (line === '' || line.startsWith('#')) continue;
    const equals = line.indexOf('=');
    if (equals < 1) fail();
    const key = line.slice(0, equals);
    const value = line.slice(equals + 1);
    if (!FIELDS.has(key) || Object.hasOwn(environment, key)
        || value.length === 0 || Buffer.byteLength(value, 'utf8') > 8_192
        || /[\u0000-\u001f\u007f]/u.test(value)) fail();
    environment[key] = value;
  }
  if (environment.WALLET_KERNEL_MODE !== 'cdp-testnet'
      || environment.WALLET_KERNEL_ENV_FILE !== environmentFilePath
      || REQUIRED_SECRETS.some((key) => !Object.hasOwn(environment, key))) fail();
  return Object.freeze(environment);
}

function sameIdentity(before, after) {
  return ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
    .every((field) => before[field] === after[field]);
}

/** Validate the kernel-reported mount envelope, never an environment-supplied path. */
export function validatePid1CredentialMount(mountInfo, directoryMountId, fileMountId) {
  if (typeof mountInfo !== 'string' || Buffer.byteLength(mountInfo) > 1_048_576
      || !/^[1-9][0-9]*$/u.test(directoryMountId) || directoryMountId !== fileMountId) fail();
  const rows = mountInfo.split('\n').filter(Boolean).map((line) => line.split(' '));
  const matches = rows.filter((fields) => fields[0] === directoryMountId);
  if (matches.length !== 1) fail();
  const fields = matches[0];
  const separator = fields.indexOf('-');
  const mountOptions = fields[5]?.split(',') ?? [];
  if (separator < 6 || fields.length !== separator + 4
      || fields[4] !== path.dirname(INSTALLED_CREDENTIAL_PATH)
      || !['tmpfs', 'ramfs'].includes(fields[separator + 1])
      || !mountOptions.includes('ro') || mountOptions.includes('rw')) fail();
  return directoryMountId;
}

function credentialMountId(descriptor) {
  const info = fs.readFileSync(`/proc/self/fdinfo/${descriptor}`, 'utf8');
  const matches = [...info.matchAll(/^mnt_id:\s*([1-9][0-9]*)$/gmu)];
  if (matches.length !== 1) fail();
  return matches[0][1];
}

function assertPid1CredentialMount(parent, descriptor) {
  return validatePid1CredentialMount(fs.readFileSync('/proc/self/mountinfo', 'utf8'),
    credentialMountId(parent), credentialMountId(descriptor));
}

/** Read PID1's private copy only after privilege drop; the root-owned source is never opened. */
export function loadDeliveredEnvironment({
  credentialFilePath = INSTALLED_CREDENTIAL_PATH,
  environmentFilePath,
  kernelUid,
  kernelGid,
}) {
  assertKernelProcessIdentity({ kernelUid, kernelGid });
  if (typeof credentialFilePath !== 'string' || !path.isAbsolute(credentialFilePath)
      || credentialFilePath !== path.resolve(credentialFilePath)
      || credentialFilePath.includes('\0') || credentialFilePath === environmentFilePath) fail();
  const parts = credentialFilePath.slice(1).split('/');
  const descriptors = [];
  let bytes;
  try {
    let parent = fs.openSync('/', fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
    descriptors.push(parent);
    for (const component of parts.slice(0, -1)) {
      parent = fs.openSync(`/proc/self/fd/${parent}/${component}`,
        fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
      descriptors.push(parent);
      const stat = fs.fstatSync(parent, { bigint: true });
      const mode = Number(stat.mode & 0o7777n);
      // A root-owned sticky ancestor (e.g. a test's /tmp) cannot rename this
      // identity's private child. Every opened descriptor pins its own inode.
      if (!stat.isDirectory() || ![0n, BigInt(kernelUid)].includes(stat.uid)
          || ((mode & 0o022) !== 0 && !(stat.uid === 0n && (mode & 0o1000) !== 0))) fail();
    }
    const parentStat = fs.fstatSync(parent, { bigint: true });
    const descriptor = fs.openSync(`/proc/self/fd/${parent}/${parts.at(-1)}`,
      fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
    descriptors.push(descriptor);
    const before = fs.fstatSync(descriptor, { bigint: true });
    const installed = credentialFilePath === INSTALLED_CREDENTIAL_PATH;
    // PID1 normally retains root ownership and adds only this UID's read ACL;
    // stat exposes the ACL mask as group bits. Accept that representation only
    // on the fixed, read-only credential mount. An arbitrary test copy must
    // instead be Kernel-owned and private. No plain-directory PID1 fallback.
    const rootAcl = installed && parentStat.uid === 0n && parentStat.gid === 0n
      && (parentStat.mode & 0o7777n) === 0o550n && before.uid === 0n && before.gid === 0n
      && (before.mode & 0o7777n) === 0o440n;
    const kernelOwned = parentStat.uid === BigInt(kernelUid)
      && parentStat.gid === BigInt(kernelGid) && (parentStat.mode & 0o077n) === 0n
      && before.uid === BigInt(kernelUid) && before.gid === BigInt(kernelGid)
      && (installed ? (before.mode & 0o7777n) === 0o400n
        : [0o400n, 0o600n].includes(before.mode & 0o7777n));
    if ((!rootAcl && !kernelOwned) || !before.isFile() || before.nlink !== 1n
        || before.size <= 0n || before.size > BigInt(MAXIMUM_ENVIRONMENT_BYTES)) fail();
    const mountId = installed ? assertPid1CredentialMount(parent, descriptor) : null;
    bytes = Buffer.alloc(Number(before.size) + 1);
    let read = 0;
    while (read < bytes.length) {
      const count = fs.readSync(descriptor, bytes, read, bytes.length - read, read);
      if (count === 0) break;
      read += count;
    }
    if (read !== Number(before.size)
        || !sameIdentity(before, fs.fstatSync(descriptor, { bigint: true }))
        || !sameIdentity(parentStat, fs.fstatSync(parent, { bigint: true }))
        || (installed && mountId !== assertPid1CredentialMount(parent, descriptor))) fail();
    return parseDeliveredEnvironment(bytes.subarray(0, read), environmentFilePath);
  } catch (error) {
    if (error instanceof KernelError) throw error;
    fail();
  } finally {
    bytes?.fill(0);
    for (const descriptor of descriptors.reverse()) fs.closeSync(descriptor);
  }
}

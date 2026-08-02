import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { openAgentTrustedParent, openTrustedParent } from './trusted-path.mjs';

const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../../', import.meta.url)));
const MAXIMUM_PRIVATE_BYTES = 1_048_576;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const PRIVATE_TEMP_LIST = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.private-temp-list.v1',
);
const STAT_SQLITE_SIBLING = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.sqlite-sibling-stat.v1',
);
const OPEN_SQLITE_SIBLING_HELD = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.sqlite-sibling-held-open.v1',
);
const SQLITE_SUFFIXES = Object.freeze(['', '-wal', '-shm']);
const PATH_TRUST_FIELDS = Object.freeze([
  'mode',
  'trustedAncestor',
  'kernelUid',
  'agentUid',
]);
const AGENT_PATH_TRUST_FIELDS = Object.freeze([
  'mode',
  'trustedAncestor',
  'agentUid',
]);
const ABSENT = Symbol('absent-private-file');
const SQLITE_PREFLIGHTS = new WeakMap();

function assertSecurePlatform() {
  if (typeof process.getuid !== 'function' || !Number.isInteger(NOFOLLOW)) {
    throw new Error('Wallet Kernel pilot requires POSIX owner and O_NOFOLLOW semantics');
  }
}

function capturePathTrust(pathTrust) {
  if (pathTrust === null
      || typeof pathTrust !== 'object'
      || !Object.isFrozen(pathTrust)) {
    throw new Error('Wallet Kernel file access requires an explicit frozen pathTrust object');
  }
  const prototype = Object.getPrototypeOf(pathTrust);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error('pathTrust must be a plain object with exact fields');
  }
  if (Object.getOwnPropertySymbols(pathTrust).length !== 0) {
    throw new Error('pathTrust must not contain symbols');
  }
  const descriptors = Object.getOwnPropertyDescriptors(pathTrust);
  const keys = Object.keys(descriptors);
  if (keys.length !== PATH_TRUST_FIELDS.length
      || PATH_TRUST_FIELDS.some((field) => !Object.hasOwn(descriptors, field))) {
    throw new Error('pathTrust must contain the exact fields');
  }
  for (const field of PATH_TRUST_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new Error('pathTrust fields must be own enumerable data fields');
    }
  }
  return Object.freeze({
    mode: descriptors.mode.value,
    trustedAncestor: descriptors.trustedAncestor.value,
    kernelUid: descriptors.kernelUid.value,
    agentUid: descriptors.agentUid.value,
  });
}

function captureAgentPathTrust(pathTrust) {
  if (pathTrust === null
      || typeof pathTrust !== 'object'
      || !Object.isFrozen(pathTrust)
      || Object.getPrototypeOf(pathTrust) !== Object.prototype
      || Object.getOwnPropertySymbols(pathTrust).length !== 0) {
    throw new Error('Agent pathTrust must be one frozen plain object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(pathTrust);
  const keys = Object.keys(descriptors);
  if (keys.length !== AGENT_PATH_TRUST_FIELDS.length
      || AGENT_PATH_TRUST_FIELDS.some((field) => !Object.hasOwn(descriptors, field))) {
    throw new Error('Agent pathTrust must contain the exact fields');
  }
  const captured = {};
  for (const field of AGENT_PATH_TRUST_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new Error('Agent pathTrust fields must be own enumerable data fields');
    }
    captured[field] = descriptor.value;
  }
  return Object.freeze(captured);
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..');
}

function assertOwner(stat, label) {
  assertSecurePlatform();
  if (Number(stat.uid) !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
}

function assertOwnerOnlyRegular(stat, label) {
  assertOwner(stat, label);
  if (!stat.isFile()) throw new Error(`${label} must be a regular file`);
  const mode = typeof stat.mode === 'bigint'
    ? Number(stat.mode & 0o777n)
    : stat.mode & 0o777;
  if (mode !== 0o600) {
    throw new Error(`${label} must be an owner-only regular file`);
  }
}

function fileIdentityFor(stat) {
  const mode = typeof stat.mode === 'bigint'
    ? Number(stat.mode & 0o7777n)
    : stat.mode & 0o7777;
  const modificationTime = typeof stat.mtimeNs === 'bigint'
    ? stat.mtimeNs.toString(10)
    : String(Math.trunc(stat.mtimeMs * 1_000_000));
  return Object.freeze({
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    mode,
    size: stat.size.toString(10),
    modificationTime,
  });
}

function sameFileIdentity(left, right) {
  return left.device === right.device
    && left.inode === right.inode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mode === right.mode
    && left.size === right.size
    && left.modificationTime === right.modificationTime;
}

function sqliteIdentityFor(stat) {
  const mode = typeof stat.mode === 'bigint'
    ? Number(stat.mode & 0o7777n)
    : stat.mode & 0o7777;
  return Object.freeze({
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    mode,
  });
}

function sameSqliteFile(left, right) {
  return left?.device === right.device && left?.inode === right.inode;
}

function sameSqliteIdentity(left, right) {
  return sameSqliteFile(left, right)
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mode === right.mode;
}

function privateParent(filePath, label, checkoutRoot, pathTrust) {
  assertSecurePlatform();
  const trust = capturePathTrust(pathTrust);
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) {
    throw new Error(`${label} path must be absolute`);
  }
  const lexicalParent = path.resolve(path.dirname(filePath));
  if (inside(checkoutRoot, lexicalParent)) {
    throw new Error(`${label} must be outside the checkout`);
  }
  return openTrustedParent({
    ...trust,
    targetFile: filePath,
    terminalOwnerUid: process.getuid(),
    terminalMode: 0o700,
    role: 'kernel-private',
  });
}

function agentPrivateParent(filePath, label, checkoutRoot, pathTrust) {
  assertSecurePlatform();
  const trust = captureAgentPathTrust(pathTrust);
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath)) {
    throw new Error(`${label} path must be absolute`);
  }
  const lexicalParent = path.resolve(path.dirname(filePath));
  if (inside(checkoutRoot, lexicalParent)) {
    throw new Error(`${label} must be outside the checkout`);
  }
  return openAgentTrustedParent({
    ...trust,
    targetFile: filePath,
    terminalOwnerUid: process.getuid(),
    terminalMode: 0o700,
    role: 'agent-private',
  });
}

function readBoundedDescriptor(descriptor, maximumBytes, label) {
  const scratch = Buffer.allocUnsafe(maximumBytes + 1);
  let total = 0;
  try {
    while (total < scratch.length) {
      const read = fs.readSync(descriptor, scratch, total, scratch.length - total, null);
      if (read === 0) break;
      total += read;
    }
    if (total > maximumBytes) {
      throw new Error(`${label} size is outside the allowed boundary`);
    }
    return Buffer.from(scratch.subarray(0, total));
  } finally {
    scratch.fill(0);
  }
}

function detachAliasedValidatorResult(result, bytes, label) {
  if (result instanceof ArrayBuffer && result === bytes.buffer) {
    throw new Error(`${label} validator must not return the input ArrayBuffer`);
  }
  if (!ArrayBuffer.isView(result) || result.buffer !== bytes.buffer) return result;
  const inputStart = bytes.byteOffset;
  const inputEnd = inputStart + bytes.byteLength;
  const resultStart = result.byteOffset;
  const resultEnd = resultStart + result.byteLength;
  if (resultStart < inputStart || resultEnd > inputEnd) {
    throw new Error(`${label} validator must not expose memory outside its input bytes`);
  }
  if (Buffer.isBuffer(result)) return Buffer.from(result);
  if (result instanceof DataView) {
    const copy = Buffer.from(new Uint8Array(result.buffer, result.byteOffset, result.byteLength));
    return new DataView(copy.buffer, copy.byteOffset, copy.byteLength);
  }
  return new result.constructor(result);
}

function readValidatedDescriptor(descriptor, label, validateBytes, { includeIdentity = false } = {}) {
  const before = fs.fstatSync(descriptor, { bigint: true });
  assertOwnerOnlyRegular(before, label);
  if (before.size <= 0n || before.size > BigInt(MAXIMUM_PRIVATE_BYTES)) {
    throw new Error(`${label} must not be empty and must remain within the size boundary`);
  }
  const identity = fileIdentityFor(before);

  const bytes = readBoundedDescriptor(descriptor, MAXIMUM_PRIVATE_BYTES, label);
  try {
    if (bytes.length <= 0) {
      throw new Error(`${label} must not be empty and must remain within the size boundary`);
    }
    const value = detachAliasedValidatorResult(validateBytes(bytes), bytes, label);
    const after = fileIdentityFor(fs.fstatSync(descriptor, { bigint: true }));
    if (!sameFileIdentity(identity, after)) {
      throw new Error(`${label} file identity changed during validation`);
    }
    return includeIdentity ? { identity, value } : value;
  } finally {
    bytes.fill(0);
  }
}

export function preparePrivateFile(filePath, label, {
  checkoutRoot = CHECKOUT_ROOT,
  pathTrust,
} = {}) {
  const guard = privateParent(filePath, label, checkoutRoot, pathTrust);
  try {
    try {
      const created = guard.openLeaf(
        fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
        0o600,
      );
      fs.closeSync(created);
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }

    const descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    try {
      assertOwnerOnlyRegular(fs.fstatSync(descriptor), label);
      guard.revalidate();
    } finally {
      fs.closeSync(descriptor);
    }
    return filePath;
  } finally {
    guard.close();
  }
}

export function readPrivateInputFile(filePath, label, {
  checkoutRoot = CHECKOUT_ROOT,
  maximumBytes = MAXIMUM_PRIVATE_BYTES,
  pathTrust,
} = {}) {
  if (!Number.isSafeInteger(maximumBytes)
      || maximumBytes <= 0
      || maximumBytes > MAXIMUM_PRIVATE_BYTES) {
    throw new Error(`${label} maximum size must be a positive safe integer within the hard ceiling`);
  }
  const guard = privateParent(filePath, label, checkoutRoot, pathTrust);
  let descriptor;
  try {
    descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    const stat = fs.fstatSync(descriptor);
    assertOwnerOnlyRegular(stat, label);
    if (stat.size <= 0 || stat.size > maximumBytes) {
      throw new Error(`${label} size is outside the allowed boundary`);
    }
    const bytes = readBoundedDescriptor(descriptor, maximumBytes, label);
    if (bytes.length <= 0) {
      bytes.fill(0);
      throw new Error(`${label} size is outside the allowed boundary`);
    }
    guard.revalidate();
    return bytes;
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    guard.close();
  }
}

export function preflightSqliteFiles(databasePath, { pathTrust } = {}) {
  // Call only before SQLite opens this path in the current process. POSIX
  // record locks are process-associated and closing any descriptor for a
  // locked inode can release SQLite's locks on its separate descriptor.
  const guard = privateParent(
    databasePath,
    'Wallet Kernel database',
    CHECKOUT_ROOT,
    pathTrust,
  );
  const existingFiles = new Map();
  try {
    for (const suffix of SQLITE_SUFFIXES) {
      let descriptor;
      try {
        descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY | NOFOLLOW);
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
      try {
        const label = `SQLite ${suffix || 'database'}`;
        const stat = fs.fstatSync(descriptor, { bigint: true });
        assertOwnerOnlyRegular(stat, label);
        existingFiles.set(suffix, sqliteIdentityFor(stat));
      } finally {
        fs.closeSync(descriptor);
      }
    }
    guard.revalidate();
    const capability = Object.freeze(Object.create(null));
    SQLITE_PREFLIGHTS.set(capability, Object.freeze({
      ancestorMetadataHash: guard.ancestorMetadataHash,
      databasePath,
      existingFiles,
    }));
    return capability;
  } finally {
    guard.close();
  }
}

export function secureNewSqliteSideFiles(databasePath, existing, {
  pathTrust,
  onAcquisitionFailure,
} = {}) {
  const guard = privateParent(
    databasePath,
    'Wallet Kernel database',
    CHECKOUT_ROOT,
    pathTrust,
  );
  const heldFiles = new Map();
  // These proof descriptors deliberately remain open for the SQLite
  // connection's lifetime. Revalidation uses fstat/lstat only; close() must
  // run after DatabaseSync.close() so it cannot tear down SQLite's locks.
  let guardClosed = false;
  let state = 'acquiring';
  const closeHeldFiles = () => {
    if (state === 'closed') return;
    state = 'closing';
    let firstError;
    for (const [suffix, held] of [...heldFiles.entries()].reverse()) {
      if (!held) {
        heldFiles.delete(suffix);
        continue;
      }
      try {
        fs.closeSync(held.descriptor);
        heldFiles.delete(suffix);
      } catch (error) {
        firstError ??= error;
      }
    }
    if (heldFiles.size === 0 && !guardClosed) {
      try {
        guard.close();
        guardClosed = true;
      } catch (error) {
        firstError ??= error;
      }
    }
    if (heldFiles.size === 0 && guardClosed) state = 'closed';
    if (firstError) throw firstError;
  };

  try {
    const preflight = SQLITE_PREFLIGHTS.get(existing);
    if (!preflight) throw new Error('SQLite repair requires an opaque preflight capability');
    SQLITE_PREFLIGHTS.delete(existing);
    if (preflight.databasePath !== databasePath) {
      throw new Error('SQLite preflight capability belongs to a different database path');
    }
    if (preflight.ancestorMetadataHash !== guard.ancestorMetadataHash) {
      throw new Error('SQLite preflight capability belongs to a different trusted parent');
    }
    const openSqliteSiblingHeld = guard[OPEN_SQLITE_SIBLING_HELD];
    if (typeof openSqliteSiblingHeld !== 'function') {
      throw new Error('trusted parent does not expose held-open SQLite acquisition');
    }
    for (const suffix of SQLITE_SUFFIXES) {
      let descriptor;
      try {
        descriptor = openSqliteSiblingHeld(suffix, fs.constants.O_RDONLY);
      } catch (error) {
        if (error.code === 'ENOENT') {
          heldFiles.set(suffix, null);
          continue;
        }
        throw error;
      }
      heldFiles.set(suffix, Object.freeze({ descriptor, identity: null }));
      const label = `SQLite ${suffix || 'database'}`;
      let stat = fs.fstatSync(descriptor, { bigint: true });
      assertOwner(stat, label);
      if (!stat.isFile()) throw new Error(`${label} must be regular`);
      const currentIdentity = sqliteIdentityFor(stat);
      const existedAtPreflight = preflight.existingFiles.has(suffix);
      const preflightIdentity = preflight.existingFiles.get(suffix);
      if (existedAtPreflight) {
        if (!sameSqliteIdentity(preflightIdentity, currentIdentity)) {
          throw new Error(`${label} identity changed after preflight`);
        }
        if (currentIdentity.mode !== 0o600) {
          throw new Error(`${label} must be owner-only`);
        }
      } else {
        fs.fchmodSync(descriptor, 0o600);
      }
      stat = fs.fstatSync(descriptor, { bigint: true });
      assertOwnerOnlyRegular(stat, label);
      heldFiles.set(suffix, Object.freeze({
        descriptor,
        identity: sqliteIdentityFor(stat),
      }));
    }
    guard.revalidate();

    const revalidate = () => {
      if (state !== 'open') throw new Error('SQLite lifetime proof is closing or closed');
      guard.revalidate();
      const statSibling = guard[STAT_SQLITE_SIBLING];
      if (typeof statSibling !== 'function') {
        throw new Error('trusted parent does not expose SQLite namespace stat');
      }
      for (const suffix of SQLITE_SUFFIXES) {
        const held = heldFiles.get(suffix);
        let namespaceStat;
        try {
          namespaceStat = statSibling(suffix);
        } catch (error) {
          if (error.code === 'ENOENT' && held === null) continue;
          if (error.code === 'ENOENT') {
            throw new Error(`SQLite ${suffix || 'database'} namespace identity changed`);
          }
          throw error;
        }
        if (held === null) {
          throw new Error(`SQLite ${suffix || 'database'} namespace identity changed`);
        }
        const descriptorStat = fs.fstatSync(held.descriptor, { bigint: true });
        const label = `SQLite ${suffix || 'database'}`;
        assertOwnerOnlyRegular(descriptorStat, label);
        const descriptorIdentity = sqliteIdentityFor(descriptorStat);
        const namespaceIdentity = sqliteIdentityFor(namespaceStat);
        if (!namespaceStat.isFile()
            || !sameSqliteIdentity(descriptorIdentity, held.identity)
            || !sameSqliteIdentity(namespaceIdentity, held.identity)) {
          throw new Error(`${label} namespace identity changed`);
        }
      }
      guard.revalidate();
    };

    state = 'open';
    revalidate();
    return Object.freeze({
      revalidate,
      close: closeHeldFiles,
    });
  } catch (error) {
    const cleanup = Object.freeze({ close: closeHeldFiles });
    if (typeof onAcquisitionFailure === 'function') {
      try { onAcquisitionFailure(cleanup); } catch {}
    } else {
      try { cleanup.close(); } catch {}
    }
    throw error;
  }
}

function candidateError(label, error) {
  const wrapped = new Error(`${label} candidate ${error.message}`);
  if (error.code) wrapped.code = error.code;
  return wrapped;
}

function validateCandidate(guard, name, label, validateBytes) {
  let descriptor;
  try {
    descriptor = guard.openNamedLeaf(name, fs.constants.O_RDONLY | NOFOLLOW);
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw candidateError(label, error);
  }

  try {
    let validated;
    try {
      validated = readValidatedDescriptor(
        descriptor,
        `${label} candidate`,
        validateBytes,
        { includeIdentity: true },
      );
    } catch (error) {
      if (/owned by|owner-only|regular file|empty|size boundary|identity changed/.test(error.message)) {
        throw error;
      }
      throw new Error(`${label} candidate is invalid: ${error.message}`);
    }
    guard.revalidate();
    return Object.freeze({ descriptor, identity: validated.identity, name });
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

function unlinkCandidate(guard, candidate) {
  try {
    guard.unlinkNamed(candidate.name, candidate.identity);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  guard.fsyncParent();
}

function loadOrInitializePrivateFileInternal({
  filePath,
  label,
  createBytes,
  validateBytes,
  randomBytes = crypto.randomBytes,
  faultInjector = () => {},
  pathTrust,
}, role) {
  if (typeof createBytes !== 'function' || typeof validateBytes !== 'function') {
    throw new Error(`${label} initializer and validator must be functions`);
  }
  if (typeof randomBytes !== 'function' || typeof faultInjector !== 'function') {
    throw new Error(`${label} randomness and fault injector must be functions`);
  }

  const guard = role === 'agent-private'
    ? agentPrivateParent(filePath, label, CHECKOUT_ROOT, pathTrust)
    : privateParent(filePath, label, CHECKOUT_ROOT, pathTrust);
  const readExisting = () => {
    const descriptor = guard.openLeaf(fs.constants.O_RDONLY | NOFOLLOW);
    try {
      const value = readValidatedDescriptor(descriptor, label, validateBytes);
      guard.revalidate();
      return value;
    } finally {
      fs.closeSync(descriptor);
    }
  };

  const readExistingOrAbsent = () => {
    try {
      return readExisting();
    } catch (error) {
      if (error.code === 'ENOENT') return ABSENT;
      throw error;
    }
  };

  const recover = () => {
    const listPrivateNames = guard[PRIVATE_TEMP_LIST];
    if (typeof listPrivateNames !== 'function') {
      throw new Error('trusted parent does not expose private recovery enumeration');
    }
    const names = listPrivateNames();
    const validated = [];
    try {
      for (const name of names) {
        const candidate = validateCandidate(guard, name, label, validateBytes);
        if (candidate) validated.push(candidate);
      }

      let existing = readExistingOrAbsent();
      if (existing === ABSENT && validated.length > 0) {
        let namespaceChanged = false;
        for (const candidate of validated) {
          try {
            guard.linkNamedToLeaf(candidate.name, candidate.identity);
            namespaceChanged = true;
            break;
          } catch (error) {
            if (error.code === 'EEXIST') {
              namespaceChanged = true;
              break;
            }
            if (error.code !== 'ENOENT') throw error;
          }
        }
        if (namespaceChanged) guard.fsyncParent();
        existing = readExistingOrAbsent();
      }

      if (existing !== ABSENT) {
        for (const candidate of validated) unlinkCandidate(guard, candidate);
      }
      return existing;
    } finally {
      for (const candidate of validated) fs.closeSync(candidate.descriptor);
    }
  };

  let bytes;
  let temporaryCreated = false;
  let temporaryIdentity;
  let temporaryName;
  try {
    const recovered = recover();
    if (recovered !== ABSENT) return recovered;

    bytes = Buffer.from(createBytes());
    if (bytes.length === 0) throw new Error(`${label} initializer returned empty content`);
    if (bytes.length > MAXIMUM_PRIVATE_BYTES) {
      throw new Error(`${label} initializer exceeded the size boundary`);
    }
    validateBytes(bytes);

    const random = Buffer.from(randomBytes(16));
    if (random.length !== 16) throw new Error(`${label} initializer requires 16 random bytes`);
    const suffix = random.toString('hex');
    random.fill(0);
    temporaryName = `.${path.basename(filePath)}.tmp-${process.pid}-${suffix}`;
    const descriptor = guard.openNamedLeaf(
      temporaryName,
      fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | NOFOLLOW,
      0o600,
    );
    temporaryCreated = true;
    try {
      fs.writeFileSync(descriptor, bytes);
      faultInjector('after_private_temp_write');
      fs.fsyncSync(descriptor);
      faultInjector('after_private_temp_fsync');
    } finally {
      try {
        temporaryIdentity = fileIdentityFor(fs.fstatSync(descriptor, { bigint: true }));
      } finally {
        fs.closeSync(descriptor);
      }
    }

    try {
      guard.linkNamedToLeaf(temporaryName, temporaryIdentity);
      faultInjector('after_private_publish');
    } catch (error) {
      if (error.code !== 'EEXIST') throw error;
    }
    guard.fsyncParent();
    faultInjector('after_private_directory_fsync');
    return readExisting();
  } finally {
    try {
      if (bytes) bytes.fill(0);
      if (temporaryCreated && temporaryIdentity) {
        unlinkCandidate(guard, Object.freeze({
          identity: temporaryIdentity,
          name: temporaryName,
        }));
      }
      guard.revalidate();
    } finally {
      guard.close();
    }
  }
}

export function loadOrInitializePrivateFile(options) {
  return loadOrInitializePrivateFileInternal(options, 'kernel-private');
}

export function loadOrInitializeAgentPrivateFile(options) {
  return loadOrInitializePrivateFileInternal(options, 'agent-private');
}

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { openTrustedParent } from './trusted-path.mjs';

const CHECKOUT_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../../', import.meta.url)));
const MAXIMUM_PRIVATE_BYTES = 1_048_576;
const NOFOLLOW = fs.constants.O_NOFOLLOW;
const PRIVATE_TEMP_LIST = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.private-temp-list.v1',
);
const SQLITE_SUFFIXES = Object.freeze(['', '-wal', '-shm']);
const ABSENT = Symbol('absent-private-file');

function assertSecurePlatform() {
  if (typeof process.getuid !== 'function' || !Number.isInteger(NOFOLLOW)) {
    throw new Error('Wallet Kernel pilot requires POSIX owner and O_NOFOLLOW semantics');
  }
}

function assertPathTrust(pathTrust) {
  if (pathTrust === null
      || typeof pathTrust !== 'object'
      || !Object.isFrozen(pathTrust)) {
    throw new Error('Wallet Kernel file access requires an explicit frozen pathTrust object');
  }
  return pathTrust;
}

function inside(parent, child) {
  const relative = path.relative(parent, child);
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..');
}

function assertOwner(stat, label) {
  assertSecurePlatform();
  if (stat.uid !== process.getuid()) {
    throw new Error(`${label} must be owned by the current user`);
  }
}

function assertOwnerOnlyRegular(stat, label) {
  assertOwner(stat, label);
  if (!stat.isFile()) throw new Error(`${label} must be a regular file`);
  if ((stat.mode & 0o777) !== 0o600) {
    throw new Error(`${label} must be an owner-only regular file`);
  }
}

function privateParent(filePath, label, checkoutRoot, pathTrust) {
  assertSecurePlatform();
  const trust = assertPathTrust(pathTrust);
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

function readValidatedDescriptor(descriptor, label, validateBytes) {
  const stat = fs.fstatSync(descriptor);
  assertOwnerOnlyRegular(stat, label);
  if (stat.size <= 0 || stat.size > MAXIMUM_PRIVATE_BYTES) {
    throw new Error(`${label} must not be empty and must remain within the size boundary`);
  }

  const bytes = fs.readFileSync(descriptor);
  try {
    if (bytes.length <= 0 || bytes.length > MAXIMUM_PRIVATE_BYTES) {
      throw new Error(`${label} must not be empty and must remain within the size boundary`);
    }
    return validateBytes(bytes);
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
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes <= 0) {
    throw new Error(`${label} maximum size must be a positive safe integer`);
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
    const bytes = fs.readFileSync(descriptor);
    if (bytes.length <= 0 || bytes.length > maximumBytes) {
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
  const guard = privateParent(
    databasePath,
    'Wallet Kernel database',
    CHECKOUT_ROOT,
    pathTrust,
  );
  const existing = new Set();
  try {
    for (const suffix of SQLITE_SUFFIXES) {
      const target = `${databasePath}${suffix}`;
      let descriptor;
      try {
        descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY | NOFOLLOW);
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
      try {
        const label = `SQLite ${suffix || 'database'}`;
        assertOwnerOnlyRegular(fs.fstatSync(descriptor), label);
        existing.add(target);
      } finally {
        fs.closeSync(descriptor);
      }
    }
    guard.revalidate();
    return existing;
  } finally {
    guard.close();
  }
}

export function secureNewSqliteSideFiles(databasePath, existing, { pathTrust } = {}) {
  if (!(existing instanceof Set)) {
    throw new Error('SQLite preflight state must be a Set');
  }
  const guard = privateParent(
    databasePath,
    'Wallet Kernel database',
    CHECKOUT_ROOT,
    pathTrust,
  );
  try {
    for (const suffix of SQLITE_SUFFIXES) {
      const target = `${databasePath}${suffix}`;
      let descriptor;
      try {
        descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY | NOFOLLOW);
      } catch (error) {
        if (error.code === 'ENOENT') continue;
        throw error;
      }
      try {
        const label = `SQLite ${suffix || 'database'}`;
        const stat = fs.fstatSync(descriptor);
        assertOwner(stat, label);
        if (!stat.isFile()) throw new Error(`${label} must be regular`);
        if (existing.has(target)) {
          if ((stat.mode & 0o777) !== 0o600) {
            throw new Error(`${label} must be owner-only`);
          }
        } else {
          fs.fchmodSync(descriptor, 0o600);
        }
      } finally {
        fs.closeSync(descriptor);
      }
    }
    guard.revalidate();
  } finally {
    guard.close();
  }
  preflightSqliteFiles(databasePath, { pathTrust });
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
    try {
      readValidatedDescriptor(descriptor, `${label} candidate`, validateBytes);
    } catch (error) {
      if (/owned by|owner-only|regular file|empty|size boundary/.test(error.message)) throw error;
      throw new Error(`${label} candidate is invalid: ${error.message}`);
    }
    guard.revalidate();
    return true;
  } finally {
    fs.closeSync(descriptor);
  }
}

function unlinkCandidate(guard, name) {
  try {
    guard.unlinkNamed(name);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  guard.fsyncParent();
}

export function loadOrInitializePrivateFile({
  filePath,
  label,
  createBytes,
  validateBytes,
  randomBytes = crypto.randomBytes,
  faultInjector = () => {},
  pathTrust,
}) {
  if (typeof createBytes !== 'function' || typeof validateBytes !== 'function') {
    throw new Error(`${label} initializer and validator must be functions`);
  }
  if (typeof randomBytes !== 'function' || typeof faultInjector !== 'function') {
    throw new Error(`${label} randomness and fault injector must be functions`);
  }

  const guard = privateParent(filePath, label, CHECKOUT_ROOT, pathTrust);
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
    for (const name of names) {
      if (validateCandidate(guard, name, label, validateBytes)) validated.push(name);
    }

    let existing = readExistingOrAbsent();
    if (existing === ABSENT && validated.length > 0) {
      try {
        guard.linkNamedToLeaf(validated[0]);
      } catch (error) {
        if (error.code !== 'EEXIST') throw error;
      }
      guard.fsyncParent();
      existing = readExisting();
    }

    if (existing !== ABSENT) {
      for (const name of validated) unlinkCandidate(guard, name);
    }
    return existing;
  };

  let bytes;
  let temporaryCreated = false;
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
      fs.closeSync(descriptor);
    }

    try {
      guard.linkNamedToLeaf(temporaryName);
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
      if (temporaryCreated) unlinkCandidate(guard, temporaryName);
      guard.revalidate();
    } finally {
      guard.close();
    }
  }
}

import fs from 'node:fs';
import path from 'node:path';

import { canonicalJson, sha256 } from './canonical.mjs';

const MODES = new Set(['deterministic', 'cdp-testnet']);
const KERNEL_ROLES = new Set(['kernel-private', 'root-only']);
const AGENT_ROLES = new Set(['agent-private', 'agent-handoff']);
const ROLES = new Set([...KERNEL_ROLES, ...AGENT_ROLES]);
const SQLITE_SUFFIXES = new Set(['', '-wal', '-shm']);
const METADATA_DOMAIN = 'wallet-kernel/trusted-parent-metadata/v1\0';
const FILE_IDENTITY_FIELDS = Object.freeze([
  'device',
  'inode',
  'uid',
  'gid',
  'mode',
  'size',
  'modificationTime',
]);
const LIST_PRIVATE_NAMES = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.private-temp-list.v1',
);
const STAT_SQLITE_SIBLING = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.sqlite-sibling-stat.v1',
);
const OPEN_SQLITE_SIBLING_HELD = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.sqlite-sibling-held-open.v1',
);
const DIRECTORY_FLAGS = fs.constants.O_RDONLY
  | fs.constants.O_DIRECTORY
  | fs.constants.O_NOFOLLOW;

function fail(message, code) {
  const error = new Error(message);
  if (code) error.code = code;
  throw error;
}

function assertPlatformBoundary() {
  if (typeof process.getuid !== 'function'
      || !Number.isInteger(fs.constants.O_DIRECTORY)
      || !Number.isInteger(fs.constants.O_NOFOLLOW)) {
    fail('trusted authority paths require POSIX descriptor and O_NOFOLLOW semantics');
  }
}

function assertUid(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail(`${label} UID must be a nonnegative safe integer`);
  }
}

function assertMode(value, label) {
  if (!Number.isInteger(value) || value < 0 || value > 0o7777) {
    fail(`${label} mode must be a bounded POSIX mode`);
  }
}

function pathComponents(value, label) {
  if (typeof value !== 'string' || !path.isAbsolute(value)) {
    fail(`${label} must be absolute`);
  }
  if (value.includes('\0') || value !== path.resolve(value)) {
    fail(`${label} must be a direct canonical path without dot or empty components`);
  }
  const root = path.parse(value).root;
  if (value === root) return [];
  const components = value.slice(root.length).split(path.sep);
  if (components.some((component) => component === '' || component === '.' || component === '..')) {
    fail(`${label} must be a direct canonical path without dot or empty components`);
  }
  return components;
}

function descendantComponents(trustedAncestor, parentPath) {
  const relative = path.relative(trustedAncestor, parentPath);
  if (relative === '') return [];
  if (path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
    fail('target parent must be beneath the trusted ancestor');
  }
  const components = relative.split(path.sep);
  if (components.some((component) => component === '' || component === '.' || component === '..')) {
    fail('target parent must be directly beneath the trusted ancestor');
  }
  return components;
}

function assertLeafName(name) {
  if (typeof name !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(name)
      || Buffer.byteLength(name, 'utf8') > 128) {
    fail('target leaf must be one bounded canonical name');
  }
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function wrapFileError(error, label) {
  if (error?.code === 'ELOOP' || error?.code === 'ENOTDIR') {
    const wrapped = new Error(`${label} rejected a symlink or non-directory`);
    wrapped.code = error.code;
    return wrapped;
  }
  const code = typeof error?.code === 'string' ? error.code : 'FILESYSTEM_ERROR';
  const wrapped = new Error(`${label} failed (${code})`);
  wrapped.code = code;
  return wrapped;
}

function modeOf(stat) {
  return Number(stat.mode & 0o7777n);
}

function projectionFor(stat, role, depth) {
  if (!stat.isDirectory()) fail('trusted path component must be a directory');
  const uid = Number(stat.uid);
  const gid = Number(stat.gid);
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(gid)) {
    fail('trusted path metadata contains an unsupported owner identifier');
  }
  return {
    role,
    depth,
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid,
    gid,
    mode: modeOf(stat),
  };
}

function fileIdentityFor(stat) {
  return {
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    mode: modeOf(stat),
    size: stat.size.toString(10),
    modificationTime: stat.mtimeNs.toString(10),
  };
}

function captureExpectedFileIdentity(value) {
  if (value === undefined) return undefined;
  if (value === null
      || typeof value !== 'object'
      || !Object.isFrozen(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Object.getOwnPropertySymbols(value).length !== 0) {
    fail('expected private file identity must be one frozen plain data object');
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const keys = Object.keys(descriptors);
  if (keys.length !== FILE_IDENTITY_FIELDS.length
      || FILE_IDENTITY_FIELDS.some((field) => !Object.hasOwn(descriptors, field))) {
    fail('expected private file identity must contain exact fields');
  }
  const captured = {};
  for (const field of FILE_IDENTITY_FIELDS) {
    const descriptor = descriptors[field];
    if (!descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('expected private file identity fields must be enumerable data');
    }
    captured[field] = descriptor.value;
  }
  return captured;
}

function assertExpectedFileIdentity(stat, expected) {
  if (!expected) return;
  const actual = fileIdentityFor(stat);
  if (FILE_IDENTITY_FIELDS.some((field) => actual[field] !== expected[field])) {
    fail('private temporary file identity changed');
  }
}

function sameProjection(left, right) {
  return left.role === right.role
    && left.depth === right.depth
    && left.device === right.device
    && left.inode === right.inode
    && left.uid === right.uid
    && left.gid === right.gid
    && left.mode === right.mode;
}

function validatePolicy(projection, {
  mode,
  role,
  kernelUid,
  agentUid,
  terminalOwnerUid,
  terminalMode,
}) {
  const terminal = projection.at(-1);
  if (mode === 'deterministic') {
    const currentUid = process.getuid();
    const deterministicChain = KERNEL_ROLES.has(role)
      ? projection
      : projection.slice(0, -1);
    for (const component of deterministicChain) {
      if (component.uid !== currentUid || component.mode !== 0o700) {
        fail('deterministic trusted path components must be current-UID owner-only directories');
      }
    }
  } else if (role === 'root-only') {
    for (const component of projection) {
      if (component.uid !== 0 || (component.mode & 0o022) !== 0) {
        fail('root-only trusted path components must be root-owned and not group/other writable');
      }
    }
  } else if (role === 'kernel-private') {
    const ancestor = projection[0];
    if (ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) {
      fail('live trusted ancestor must be root-owned and not group/other writable');
    }
    for (const component of projection.slice(1, -1)) {
      if ((component.uid !== 0 && component.uid !== kernelUid)
          || (component.mode & 0o022) !== 0) {
        fail('Kernel-private intermediate must be root/Kernel-owned and not group/other writable');
      }
    }
  } else {
    const ancestor = projection[0];
    if (ancestor.uid !== 0 || (ancestor.mode & 0o022) !== 0) {
      fail('live Agent trusted ancestor must be root-owned and not group/other writable');
    }
    for (const component of projection.slice(1, -1)) {
      if (component.uid !== 0 || (component.mode & 0o022) !== 0) {
        fail('Agent path intermediate must be root-owned and not group/other writable');
      }
    }
  }

  if (terminal.uid !== terminalOwnerUid) {
    fail('trusted terminal owner does not match the required terminal owner');
  }
  if (terminal.mode !== terminalMode) {
    fail('trusted terminal mode does not match the required terminal mode');
  }
}

function procChild(parentDescriptor, name) {
  return `/proc/self/fd/${parentDescriptor}/${name}`;
}

function closeDescriptors(descriptors) {
  let firstError;
  for (let index = descriptors.length - 1; index >= 0; index -= 1) {
    try {
      fs.closeSync(descriptors[index]);
      descriptors.splice(index, 1);
    } catch (error) {
      firstError ??= error;
    }
  }
  if (firstError) throw firstError;
}

function openDirectory(location, label) {
  let descriptor;
  try {
    descriptor = fs.openSync(location, DIRECTORY_FLAGS);
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (!stat.isDirectory()) fail(`${label} must be a directory`);
    return descriptor;
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (error?.message === `${label} must be a directory`) throw error;
    throw wrapFileError(error, label);
  }
}

function openTrustedParentInternal({
  mode,
  trustedAncestor,
  targetFile,
  kernelUid,
  agentUid,
  terminalOwnerUid,
  terminalMode,
  role,
}) {
  assertPlatformBoundary();
  if (!MODES.has(mode)) fail('trusted path mode must be deterministic or cdp-testnet');
  if (!ROLES.has(role)) fail('trusted path role is outside the closed role set');
  if (KERNEL_ROLES.has(role)) assertUid(kernelUid, 'Kernel');
  assertUid(agentUid, 'Agent');
  assertUid(terminalOwnerUid, 'terminal owner');
  assertMode(terminalMode, 'terminal');
  pathComponents(trustedAncestor, 'trusted ancestor');
  pathComponents(targetFile, 'target file');

  if (mode === 'deterministic') {
    if (agentUid !== process.getuid()
        || (KERNEL_ROLES.has(role) && kernelUid !== process.getuid())) {
      fail('deterministic path identities must equal the current UID');
    }
  } else {
    if (KERNEL_ROLES.has(role)) {
      if (kernelUid === 0 || agentUid === 0) {
        fail('live Kernel and Pi UIDs must be nonzero');
      }
      if (kernelUid === agentUid) fail('live Kernel and Pi UIDs must be distinct');
      if (role === 'kernel-private' && terminalOwnerUid !== kernelUid) {
        fail('Kernel-private terminal owner must be the Kernel UID');
      }
      if (role === 'root-only' && terminalOwnerUid !== 0) {
        fail('root-only terminal owner must be root');
      }
    } else {
      if (agentUid === 0 || process.getuid() !== agentUid) {
        fail('live Agent path must run as the configured non-root Agent UID');
      }
      if (terminalOwnerUid !== agentUid) {
        fail('Agent path terminal owner must be the Agent UID');
      }
    }
    if (process.platform !== 'linux') {
      fail('cdp-testnet trusted paths require Linux');
    }
    try {
      if (!fs.statSync('/proc/self/fd').isDirectory()) throw new Error('not a directory');
    } catch {
      fail('cdp-testnet trusted paths require the Linux /proc/self/fd boundary');
    }
  }

  const canonicalParentPath = path.dirname(targetFile);
  const leafName = path.basename(targetFile);
  assertLeafName(leafName);
  const descendants = descendantComponents(trustedAncestor, canonicalParentPath);
  const chainPaths = [trustedAncestor];
  for (const component of descendants) {
    chainPaths.push(path.join(chainPaths.at(-1), component));
  }

  const descriptors = [];
  let state = 'open';
  try {
    descriptors.push(openDirectory(trustedAncestor, 'trusted ancestor'));
    for (let index = 0; index < descendants.length; index += 1) {
      const location = mode === 'cdp-testnet'
        ? procChild(descriptors.at(-1), descendants[index])
        : chainPaths[index + 1];
      descriptors.push(openDirectory(location, 'trusted descendant'));
    }

    const originalProjection = descriptors.map((descriptor, depth) => projectionFor(
      fs.fstatSync(descriptor, { bigint: true }),
      role,
      depth,
    ));
    validatePolicy(originalProjection, {
      mode,
      role,
      kernelUid,
      agentUid,
      terminalOwnerUid,
      terminalMode,
    });
    const ancestorMetadataHash = sha256(
      `${METADATA_DOMAIN}${canonicalJson(originalProjection)}`,
    );
    const parentDescriptor = descriptors.at(-1);

    const assertOpen = () => {
      if (state !== 'open') fail('trusted parent guard is closing or closed');
    };

    const verifyProjection = (actual, expected) => {
      if (!sameProjection(actual, expected)) {
        fail('trusted path descriptor or namespace metadata changed');
      }
    };

    const revalidate = () => {
      assertOpen();
      for (let index = 0; index < descriptors.length; index += 1) {
        const actual = projectionFor(
          fs.fstatSync(descriptors[index], { bigint: true }),
          role,
          index,
        );
        verifyProjection(actual, originalProjection[index]);
      }

      for (let index = mode === 'cdp-testnet' ? 1 : 0;
        index < descriptors.length;
        index += 1) {
        const location = mode === 'cdp-testnet'
          ? procChild(descriptors[index - 1], descendants[index - 1])
          : chainPaths[index];
        const probe = openDirectory(location, 'trusted namespace');
        try {
          const actual = projectionFor(
            fs.fstatSync(probe, { bigint: true }),
            role,
            index,
          );
          verifyProjection(actual, originalProjection[index]);
        } finally {
          fs.closeSync(probe);
        }
      }
      return ancestorMetadataHash;
    };

    const childLocation = (name) => mode === 'cdp-testnet'
      ? procChild(parentDescriptor, name)
      : path.join(canonicalParentPath, name);

    const openBounded = (name, flags, creationMode, label) => {
      assertOpen();
      if (!Number.isInteger(flags) || flags < 0) fail(`${label} flags must be an integer`);
      if (creationMode !== undefined) assertMode(creationMode, label);
      revalidate();
      let descriptor;
      try {
        const safeFlags = flags | fs.constants.O_NOFOLLOW;
        descriptor = creationMode === undefined
          ? fs.openSync(childLocation(name), safeFlags)
          : fs.openSync(childLocation(name), safeFlags, creationMode);
        revalidate();
        return descriptor;
      } catch (error) {
        if (descriptor !== undefined) {
          try { fs.closeSync(descriptor); } catch {}
        }
        if (error?.message === 'trusted path descriptor or namespace metadata changed'
            || error?.message === 'trusted parent guard is closing or closed') {
          throw error;
        }
        throw wrapFileError(error, label);
      }
    };

    const assertSuffix = (suffix) => {
      if (!SQLITE_SUFFIXES.has(suffix)) {
        fail('SQLite sibling suffix is outside the closed suffix set');
      }
    };

    const privateNamePattern = new RegExp(
      `^\\.${escapeRegExp(leafName)}\\.tmp-[1-9][0-9]*-[0-9a-f]{32}$`,
    );
    const assertPrivateName = (name) => {
      if (typeof name !== 'string'
          || Buffer.byteLength(name, 'utf8') > 255
          || !privateNamePattern.test(name)) {
        fail('name must match the exact private temporary name grammar');
      }
    };
    const listPrivateNames = () => {
      assertOpen();
      revalidate();
      let names;
      try {
        const parentLocation = mode === 'cdp-testnet'
          ? `/proc/self/fd/${parentDescriptor}`
          : canonicalParentPath;
        names = fs.readdirSync(parentLocation, { encoding: 'utf8' });
      } catch (error) {
        throw wrapFileError(error, 'private temporary listing');
      }
      revalidate();
      return Object.freeze(names.filter((name) => privateNamePattern.test(name)).sort());
    };

    const openLeaf = (flags, creationMode) => openBounded(
      leafName,
      flags,
      creationMode,
      'trusted leaf open',
    );
    const openSibling = (suffix, flags) => {
      assertSuffix(suffix);
      return openBounded(`${leafName}${suffix}`, flags, undefined, 'SQLite sibling open');
    };
    const openSqliteSiblingHeld = (suffix, flags) => {
      assertOpen();
      assertSuffix(suffix);
      if (flags !== fs.constants.O_RDONLY) {
        fail('SQLite held-open flags must be read-only');
      }
      revalidate();
      try {
        // Ownership transfers to the SQLite lifetime proof as soon as openSync
        // returns. No fallible validation or cleanup may run in this layer
        // after acquisition because closing this descriptor could release
        // process-associated SQLite locks before DatabaseSync closes.
        return fs.openSync(
          childLocation(`${leafName}${suffix}`),
          fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW,
        );
      } catch (error) {
        throw wrapFileError(error, 'SQLite held-open sibling');
      }
    };
    const statSibling = (suffix) => {
      assertOpen();
      assertSuffix(suffix);
      revalidate();
      let stat;
      try {
        stat = fs.lstatSync(childLocation(`${leafName}${suffix}`), { bigint: true });
      } catch (error) {
        throw wrapFileError(error, 'SQLite sibling stat');
      }
      revalidate();
      return stat;
    };
    const openNamedLeaf = (name, flags, creationMode) => {
      assertPrivateName(name);
      return openBounded(name, flags, creationMode, 'private temporary open');
    };

    const linkNamedToLeaf = (name, expectedIdentityValue) => {
      assertOpen();
      assertPrivateName(name);
      const expectedIdentity = captureExpectedFileIdentity(expectedIdentityValue);
      revalidate();
      let sourceDescriptor;
      try {
        sourceDescriptor = openBounded(name, fs.constants.O_RDONLY, undefined, 'private temporary open');
        const source = fs.fstatSync(sourceDescriptor, { bigint: true });
        if (!source.isFile()) fail('private temporary link source must be a regular file');
        assertExpectedFileIdentity(source, expectedIdentity);
        try {
          fs.linkSync(childLocation(name), childLocation(leafName));
        } catch (error) {
          throw wrapFileError(error, 'private temporary publish');
        }
        let publishedDescriptor;
        try {
          publishedDescriptor = openBounded(
            leafName,
            fs.constants.O_RDONLY,
            undefined,
            'published private leaf open',
          );
          const published = fs.fstatSync(publishedDescriptor, { bigint: true });
          if (!published.isFile() || published.dev !== source.dev || published.ino !== source.ino) {
            fail('private temporary publish did not preserve the held regular file');
          }
          if (expectedIdentity) {
            const publishedIdentity = fileIdentityFor(published);
            for (const field of FILE_IDENTITY_FIELDS) {
              if (field !== 'modificationTime'
                  && publishedIdentity[field] !== expectedIdentity[field]) {
                fail('private temporary publish did not preserve validated identity');
              }
            }
            if (publishedIdentity.modificationTime !== expectedIdentity.modificationTime) {
              fail('private temporary publish did not preserve validated identity');
            }
          }
        } finally {
          if (publishedDescriptor !== undefined) fs.closeSync(publishedDescriptor);
        }
        revalidate();
      } finally {
        if (sourceDescriptor !== undefined) fs.closeSync(sourceDescriptor);
      }
    };

    const unlinkNamed = (name, expectedIdentityValue) => {
      assertOpen();
      assertPrivateName(name);
      const expectedIdentity = captureExpectedFileIdentity(expectedIdentityValue);
      revalidate();
      let descriptor;
      let linkCountBefore;
      try {
        if (expectedIdentity) {
          descriptor = openBounded(
            name,
            fs.constants.O_RDONLY,
            undefined,
            'private temporary cleanup open',
          );
          const before = fs.fstatSync(descriptor, { bigint: true });
          if (!before.isFile()) fail('private temporary cleanup source must be regular');
          assertExpectedFileIdentity(before, expectedIdentity);
          linkCountBefore = before.nlink;
        }
        // POSIX has no unlink-if-inode primitive. Live callers rely on the held
        // Kernel-owned 0700 chain, a distinct Pi UID, and the authority lock;
        // the checks here detect faults inside that explicit trust boundary.
        fs.unlinkSync(childLocation(name));
        if (descriptor !== undefined) {
          const after = fs.fstatSync(descriptor, { bigint: true });
          if (after.dev !== BigInt(expectedIdentity.device)
              || after.ino !== BigInt(expectedIdentity.inode)
              || after.nlink >= linkCountBefore) {
            fail('private temporary cleanup descriptor identity changed');
          }
        }
      } catch (error) {
        if (error?.message === 'private temporary file identity changed'
            || error?.message === 'private temporary cleanup source must be regular'
            || error?.message === 'private temporary cleanup descriptor identity changed') {
          throw error;
        }
        throw wrapFileError(error, 'private temporary unlink');
      } finally {
        if (descriptor !== undefined) fs.closeSync(descriptor);
      }
      revalidate();
    };

    const fsyncParent = () => {
      assertOpen();
      revalidate();
      fs.fsyncSync(parentDescriptor);
      revalidate();
    };

    const close = () => {
      if (state === 'closed') return;
      state = 'closing';
      closeDescriptors(descriptors);
      state = 'closed';
    };

    revalidate();
    const guard = {
      canonicalParentPath,
      ancestorMetadataHash,
      status: mode === 'deterministic' ? 'simulated' : 'enforced',
      openLeaf,
      openSibling,
      openNamedLeaf,
      linkNamedToLeaf,
      unlinkNamed,
      fsyncParent,
      revalidate,
      close,
    };
    Object.defineProperty(guard, LIST_PRIVATE_NAMES, {
      configurable: false,
      enumerable: false,
      value: listPrivateNames,
      writable: false,
    });
    Object.defineProperty(guard, STAT_SQLITE_SIBLING, {
      configurable: false,
      enumerable: false,
      value: statSibling,
      writable: false,
    });
    Object.defineProperty(guard, OPEN_SQLITE_SIBLING_HELD, {
      configurable: false,
      enumerable: false,
      value: openSqliteSiblingHeld,
      writable: false,
    });
    return Object.freeze(guard);
  } catch (error) {
    state = 'closing';
    try {
      closeDescriptors(descriptors);
    } catch {}
    if (descriptors.length === 0) state = 'closed';
    throw error;
  }
}

export function openTrustedParent(options) {
  if (!options || typeof options !== 'object' || !KERNEL_ROLES.has(options.role)) {
    fail('Kernel trusted parent requires a kernel-private or root-only role');
  }
  return openTrustedParentInternal(options);
}

export function openAgentTrustedParent(options) {
  if (!options || typeof options !== 'object' || !AGENT_ROLES.has(options.role)
      || Object.hasOwn(options, 'kernelUid')) {
    fail('Agent trusted parent requires a scoped Agent role without Kernel identity');
  }
  const requiredMode = options.role === 'agent-private' ? 0o700 : 0o755;
  if (options.terminalMode !== requiredMode
      || options.terminalOwnerUid !== options.agentUid) {
    fail('Agent trusted parent role requires its exact terminal owner and mode');
  }
  return openTrustedParentInternal(options);
}

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { openAgentTrustedParent, openTrustedParent } from '../src/kernel/trusted-path.mjs';

test('exports the trusted parent opener', () => {
  assert.equal(typeof openTrustedParent, 'function');
  assert.equal(typeof openAgentTrustedParent, 'function');
});

test('Agent trusted roles bind their exact terminal owner and mode', (t) => {
  const privateFixture = makeFixture(t);
  for (const [role, terminalMode, wrongMode] of [
    ['agent-private', 0o700, 0o755],
    ['agent-handoff', 0o755, 0o700],
  ]) {
    const fixture = role === 'agent-private'
      ? privateFixture
      : makeFixture(t, { terminalMode: 0o755 });
    const base = {
      mode: 'deterministic',
      trustedAncestor: fixture.trustedAncestor,
      targetFile: fixture.targetFile,
      agentUid: CURRENT_UID,
      terminalOwnerUid: CURRENT_UID,
      terminalMode,
      role,
    };
    assert.throws(
      () => openAgentTrustedParent({ ...base, terminalMode: wrongMode }),
      /exact terminal owner and mode/,
    );
    assert.throws(
      () => openAgentTrustedParent({ ...base, terminalOwnerUid: CURRENT_UID + 1 }),
      /exact terminal owner and mode/,
    );
    const guard = openAgentTrustedParent(base);
    guard.close();
  }
});

const CURRENT_UID = process.getuid();
const METADATA_DOMAIN = 'wallet-kernel/trusted-parent-metadata/v1\0';
const LIST_PRIVATE_NAMES = Symbol.for(
  'skill-asset-protocol.wallet-kernel.trusted-parent.private-temp-list.v1',
);

function makeFixture(t, {
  ancestorMode = 0o700,
  intermediateMode = 0o700,
  terminalMode = 0o700,
} = {}) {
  const trustedAncestor = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-parent-'));
  fs.chmodSync(trustedAncestor, ancestorMode);
  const intermediate = path.join(trustedAncestor, 'kernel');
  const terminal = path.join(intermediate, 'authority');
  fs.mkdirSync(intermediate, { mode: intermediateMode });
  fs.chmodSync(intermediate, intermediateMode);
  fs.mkdirSync(terminal, { mode: terminalMode });
  fs.chmodSync(terminal, terminalMode);
  const targetFile = path.join(terminal, 'kernel.sqlite');
  t.after(() => fs.rmSync(trustedAncestor, { force: true, recursive: true }));
  return { trustedAncestor, intermediate, terminal, targetFile };
}

function deterministicOptions(fixture, overrides = {}) {
  return {
    mode: 'deterministic',
    trustedAncestor: fixture.trustedAncestor,
    targetFile: fixture.targetFile,
    kernelUid: CURRENT_UID,
    agentUid: CURRENT_UID,
    terminalOwnerUid: CURRENT_UID,
    terminalMode: 0o700,
    role: 'kernel-private',
    ...overrides,
  };
}

function statProjection(role, paths) {
  return paths.map((entry, depth) => {
    const stat = fs.statSync(entry, { bigint: true });
    return {
      role,
      depth,
      device: stat.dev.toString(10),
      inode: stat.ino.toString(10),
      uid: Number(stat.uid),
      gid: Number(stat.gid),
      mode: Number(stat.mode & 0o7777n),
    };
  });
}

function privateFileIdentity(filePath) {
  const stat = fs.statSync(filePath, { bigint: true });
  return Object.freeze({
    device: stat.dev.toString(10),
    inode: stat.ino.toString(10),
    uid: Number(stat.uid),
    gid: Number(stat.gid),
    mode: Number(stat.mode & 0o7777n),
    size: stat.size.toString(10),
    modificationTime: stat.mtimeNs.toString(10),
  });
}

test('deterministic guard holds an owner-only chain and exposes only the frozen boundary', (t) => {
  const fixture = makeFixture(t);
  fs.writeFileSync(fixture.targetFile, 'database', { mode: 0o600 });
  fs.writeFileSync(`${fixture.targetFile}-wal`, 'wal', { mode: 0o600 });
  fs.writeFileSync(`${fixture.targetFile}-shm`, 'shm', { mode: 0o600 });

  const guard = openTrustedParent(deterministicOptions(fixture));

  assert.equal(Object.isFrozen(guard), true);
  assert.deepEqual(Object.keys(guard), [
    'canonicalParentPath',
    'ancestorMetadataHash',
    'status',
    'openLeaf',
    'openSibling',
    'openNamedLeaf',
    'linkNamedToLeaf',
    'unlinkNamed',
    'fsyncParent',
    'revalidate',
    'close',
  ]);
  assert.equal(guard.canonicalParentPath, fixture.terminal);
  assert.equal(guard.status, 'simulated');

  const leaf = guard.openLeaf(fs.constants.O_RDONLY);
  try {
    assert.equal(fs.readFileSync(leaf, 'utf8'), 'database');
  } finally {
    fs.closeSync(leaf);
  }
  for (const [suffix, expected] of [['-wal', 'wal'], ['-shm', 'shm']]) {
    const descriptor = guard.openSibling(suffix, fs.constants.O_RDONLY);
    try {
      assert.equal(fs.readFileSync(descriptor, 'utf8'), expected);
    } finally {
      fs.closeSync(descriptor);
    }
  }

  guard.fsyncParent();
  guard.revalidate();
  guard.close();
  guard.close();
});

test('private temporary names publish by no-replace link and unlink only the exact name', (t) => {
  const fixture = makeFixture(t);
  const guard = openTrustedParent(deterministicOptions(fixture));
  const name = `.kernel.sqlite.tmp-${process.pid}-${'ab'.repeat(16)}`;
  const descriptor = guard.openNamedLeaf(
    name,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600,
  );
  fs.writeFileSync(descriptor, 'candidate');
  fs.fsyncSync(descriptor);
  fs.closeSync(descriptor);

  guard.linkNamedToLeaf(name);
  assert.equal(fs.readFileSync(fixture.targetFile, 'utf8'), 'candidate');
  assert.throws(() => guard.linkNamedToLeaf(name), (error) => error.code === 'EEXIST');
  guard.unlinkNamed(name);
  assert.equal(fs.existsSync(path.join(fixture.terminal, name)), false);
  assert.equal(fs.readFileSync(fixture.targetFile, 'utf8'), 'candidate');
  guard.close();
});

test('publish mismatch fails closed without unlinking a replacement leaf by pathname', (t) => {
  const fixture = makeFixture(t);
  const guard = openTrustedParent(deterministicOptions(fixture));
  const name = `.kernel.sqlite.tmp-${process.pid}-${'ef'.repeat(16)}`;
  const descriptor = guard.openNamedLeaf(
    name,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600,
  );
  fs.writeFileSync(descriptor, 'candidate');
  fs.closeSync(descriptor);

  const originalFstat = fs.fstatSync;
  let regularFileFstats = 0;
  let replacementInstalled = false;
  fs.fstatSync = function replacePublishedLeaf(descriptorToInspect, options) {
    const stat = originalFstat.call(fs, descriptorToInspect, options);
    if (options?.bigint === true && stat.isFile()) {
      regularFileFstats += 1;
      if (regularFileFstats === 2) {
        fs.unlinkSync(fixture.targetFile);
        fs.writeFileSync(fixture.targetFile, 'replacement', { mode: 0o600 });
        replacementInstalled = true;
        return new Proxy(stat, {
          get(target, property, receiver) {
            if (property === 'ino') return target.ino + 1n;
            return Reflect.get(target, property, receiver);
          },
        });
      }
    }
    return stat;
  };

  try {
    assert.throws(
      () => guard.linkNamedToLeaf(name),
      /private temporary publish did not preserve the held regular file/,
    );
  } finally {
    fs.fstatSync = originalFstat;
    guard.close();
  }

  assert.equal(replacementInstalled, true);
  assert.equal(fs.existsSync(fixture.targetFile), true);
  assert.equal(fs.readFileSync(fixture.targetFile, 'utf8'), 'replacement');
});

test('validated private-temp identity gates publish and cleanup before pathname mutation', (t) => {
  const fixture = makeFixture(t);
  const guard = openTrustedParent(deterministicOptions(fixture));
  const name = `.kernel.sqlite.tmp-${process.pid}-${'fa'.repeat(16)}`;
  const candidate = path.join(fixture.terminal, name);
  fs.writeFileSync(candidate, 'validated', { mode: 0o600 });
  const identity = privateFileIdentity(candidate);
  fs.renameSync(candidate, `${candidate}.moved`);
  fs.writeFileSync(candidate, 'replacement', { mode: 0o600 });

  assert.throws(() => guard.linkNamedToLeaf(name, identity), /identity changed/);
  assert.equal(fs.existsSync(fixture.targetFile), false);
  assert.throws(() => guard.unlinkNamed(name, identity), /identity changed/);
  assert.equal(fs.readFileSync(candidate, 'utf8'), 'replacement');
  guard.close();
});

test('sibling and private-temp namespaces are closed and bounded', (t) => {
  const fixture = makeFixture(t);
  fs.writeFileSync(fixture.targetFile, 'database', { mode: 0o600 });
  const guard = openTrustedParent(deterministicOptions(fixture));

  for (const suffix of ['-journal', '../escape', '/absolute', '-wal/escape', null]) {
    assert.throws(() => guard.openSibling(suffix, fs.constants.O_RDONLY), /SQLite sibling suffix/);
  }
  for (const name of [
    `.kernel.sqlite.tmp-0-${'ab'.repeat(16)}`,
    `.kernel.sqlite.tmp--1-${'ab'.repeat(16)}`,
    `.kernel.sqlite.tmp-${process.pid}-${'AB'.repeat(16)}`,
    `.kernelXsqlite.tmp-${process.pid}-${'ab'.repeat(16)}`,
    `.other.tmp-${process.pid}-${'ab'.repeat(16)}`,
    `.kernel.sqlite.tmp-${process.pid}-${'ab'.repeat(15)}`,
    `../.kernel.sqlite.tmp-${process.pid}-${'ab'.repeat(16)}`,
  ]) {
    assert.throws(
      () => guard.openNamedLeaf(name, fs.constants.O_RDONLY),
      /private temporary name/,
    );
    assert.throws(() => guard.linkNamedToLeaf(name), /private temporary name/);
    assert.throws(() => guard.unlinkNamed(name), /private temporary name/);
  }
  guard.close();
});

test('internal private-temp listing is descriptor-bound, exact, sorted, and revalidated', (t) => {
  const fixture = makeFixture(t);
  const guard = openTrustedParent(deterministicOptions(fixture));
  const first = `.kernel.sqlite.tmp-101-${'11'.repeat(16)}`;
  const second = `.kernel.sqlite.tmp-202-${'22'.repeat(16)}`;
  for (const name of [
    second,
    first,
    `.kernel.sqlite.tmp-0-${'33'.repeat(16)}`,
    `.kernel.sqlite.tmp-303-${'AA'.repeat(16)}`,
    'unrelated',
  ]) {
    fs.writeFileSync(path.join(fixture.terminal, name), 'candidate', { mode: 0o600 });
  }

  assert.equal(Object.keys(guard).includes(String(LIST_PRIVATE_NAMES)), false);
  const descriptor = Object.getOwnPropertyDescriptor(guard, LIST_PRIVATE_NAMES);
  assert.equal(descriptor?.enumerable, false);
  assert.equal(typeof descriptor?.value, 'function');
  const names = guard[LIST_PRIVATE_NAMES]();
  assert.deepEqual(names, [first, second]);
  assert.equal(Object.isFrozen(names), true);
  assert.equal(names.some((name) => name.includes(fixture.terminal)), false);

  const originalReaddir = fs.readdirSync;
  fs.readdirSync = function mutateAfterListing(location, options) {
    const result = originalReaddir.call(fs, location, options);
    fs.chmodSync(fixture.terminal, 0o755);
    return result;
  };
  try {
    assert.throws(() => guard[LIST_PRIVATE_NAMES](), /changed/);
  } finally {
    fs.readdirSync = originalReaddir;
    guard.close();
  }
  assert.throws(() => guard[LIST_PRIVATE_NAMES](), /closed/);
});

test('leaf opens are no-follow even when the caller omits O_NOFOLLOW', (t) => {
  const fixture = makeFixture(t);
  const outside = path.join(fixture.trustedAncestor, 'outside-file');
  fs.writeFileSync(outside, 'outside', { mode: 0o600 });
  fs.symlinkSync(outside, fixture.targetFile);
  const guard = openTrustedParent(deterministicOptions(fixture));

  assert.throws(() => guard.openLeaf(fs.constants.O_RDONLY), /symlink/);
  guard.close();
});

test('every operation rejects use after close while close remains idempotent', (t) => {
  const fixture = makeFixture(t);
  fs.writeFileSync(fixture.targetFile, 'database', { mode: 0o600 });
  const guard = openTrustedParent(deterministicOptions(fixture));
  const name = `.kernel.sqlite.tmp-${process.pid}-${'cd'.repeat(16)}`;
  guard.close();

  const actions = [
    () => guard.openLeaf(fs.constants.O_RDONLY),
    () => guard.openSibling('', fs.constants.O_RDONLY),
    () => guard.openNamedLeaf(name, fs.constants.O_RDONLY),
    () => guard.linkNamedToLeaf(name),
    () => guard.unlinkNamed(name),
    () => guard.fsyncParent(),
    () => guard.revalidate(),
  ];
  for (const action of actions) assert.throws(action, /closed/);
  assert.doesNotThrow(() => guard.close());
});

test('trusted parent close retains a failed descriptor for one bounded retry', (t) => {
  const fixture = makeFixture(t);
  fs.writeFileSync(fixture.targetFile, 'database', { mode: 0o600 });
  const terminalIdentity = fs.statSync(fixture.terminal, { bigint: true });
  const guard = openTrustedParent(deterministicOptions(fixture));
  const originalClose = fs.closeSync;
  let terminalDescriptor;
  let terminalCloseCalls = 0;

  fs.closeSync = function failFirstTerminalClose(descriptor) {
    const stat = fs.fstatSync(descriptor, { bigint: true });
    if (stat.isDirectory()
        && stat.dev === terminalIdentity.dev
        && stat.ino === terminalIdentity.ino) {
      terminalDescriptor = descriptor;
      terminalCloseCalls += 1;
      if (terminalCloseCalls === 1) {
        throw new Error('injected trusted parent close fault');
      }
    }
    return originalClose.call(fs, descriptor);
  };

  try {
    assert.throws(() => guard.close(), /injected trusted parent close fault/);
    assert.throws(() => guard.revalidate(), /closing|closed/);
    assert.doesNotThrow(() => guard.close());
    assert.doesNotThrow(() => guard.close());
  } finally {
    fs.closeSync = originalClose;
    if (terminalDescriptor !== undefined) {
      try {
        fs.fstatSync(terminalDescriptor);
        originalClose.call(fs, terminalDescriptor);
      } catch {}
    }
  }

  assert.equal(terminalCloseCalls, 2);
});

test('mode, role, UID, path, and canonical-component inputs fail closed', (t) => {
  const fixture = makeFixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-outside-'));
  fs.chmodSync(outside, 0o700);
  t.after(() => fs.rmSync(outside, { force: true, recursive: true }));

  const cases = [
    [deterministicOptions(fixture, { mode: 'live' }), /mode/],
    [deterministicOptions(fixture, { role: 'other' }), /role/],
    [deterministicOptions(fixture, { trustedAncestor: 'relative' }), /absolute/],
    [deterministicOptions(fixture, { targetFile: 'relative' }), /absolute/],
    [deterministicOptions(fixture, { targetFile: path.join(outside, 'file') }), /beneath/],
    [deterministicOptions(fixture, {
      targetFile: `${fixture.trustedAncestor}/./kernel/authority/kernel.sqlite`,
    }), /canonical|dot/],
    [deterministicOptions(fixture, {
      targetFile: `${fixture.trustedAncestor}/kernel//authority/kernel.sqlite`,
    }), /canonical|empty/],
    [deterministicOptions(fixture, { trustedAncestor: `${fixture.trustedAncestor}/` }), /canonical/],
    [deterministicOptions(fixture, { kernelUid: -1 }), /UID/],
    [deterministicOptions(fixture, { agentUid: 1.5 }), /UID/],
    [deterministicOptions(fixture, {
      kernelUid: CURRENT_UID + 1,
      agentUid: CURRENT_UID + 1,
    }), /current UID/],
    [deterministicOptions(fixture, { terminalMode: 0o10000 }), /mode/],
  ];
  for (const [options, pattern] of cases) {
    assert.throws(() => openTrustedParent(options), pattern);
  }
});

test('deterministic chains reject symlink and non-directory components', (t) => {
  const target = fs.mkdtempSync(path.join(os.tmpdir(), 'trusted-target-'));
  fs.chmodSync(target, 0o700);
  t.after(() => fs.rmSync(target, { force: true, recursive: true }));

  {
    const fixture = makeFixture(t);
    const trustedLink = path.join(path.dirname(fixture.trustedAncestor), `trusted-link-${process.pid}`);
    fs.symlinkSync(fixture.trustedAncestor, trustedLink);
    t.after(() => fs.rmSync(trustedLink, { force: true }));
    assert.throws(
      () => openTrustedParent(deterministicOptions(fixture, {
        trustedAncestor: trustedLink,
        targetFile: path.join(trustedLink, 'kernel', 'authority', 'kernel.sqlite'),
      })),
      /symlink|directory/,
    );
  }
  {
    const fixture = makeFixture(t);
    fs.rmSync(fixture.intermediate, { recursive: true });
    fs.symlinkSync(target, fixture.intermediate);
    assert.throws(() => openTrustedParent(deterministicOptions(fixture)), /symlink|directory/);
  }
  {
    const fixture = makeFixture(t);
    fs.rmSync(fixture.terminal, { recursive: true });
    fs.symlinkSync(target, fixture.terminal);
    assert.throws(() => openTrustedParent(deterministicOptions(fixture)), /symlink|directory/);
  }
  {
    const fixture = makeFixture(t);
    fs.rmSync(fixture.intermediate, { recursive: true });
    fs.writeFileSync(fixture.intermediate, 'not a directory', { mode: 0o600 });
    assert.throws(() => openTrustedParent(deterministicOptions(fixture)), /directory/);
  }
});

test('deterministic chains reject permissive ancestors, intermediates, and terminal parents', (t) => {
  for (const key of ['ancestorMode', 'intermediateMode', 'terminalMode']) {
    const fixture = makeFixture(t, { [key]: 0o755 });
    assert.throws(() => openTrustedParent(deterministicOptions(fixture)), /owner-only|mode/);
  }
});

test('terminal owner and exact mode are authoritative', (t) => {
  const fixture = makeFixture(t);
  assert.throws(
    () => openTrustedParent(deterministicOptions(fixture, { terminalOwnerUid: CURRENT_UID + 1 })),
    /terminal owner/,
  );
  assert.throws(
    () => openTrustedParent(deterministicOptions(fixture, { terminalMode: 0o750 })),
    /terminal mode/,
  );
});

test('metadata hash is domain-separated over the ordered path-free projection', (t) => {
  const fixture = makeFixture(t);
  const projection = statProjection('kernel-private', [
    fixture.trustedAncestor,
    fixture.intermediate,
    fixture.terminal,
  ]);
  const expected = sha256(`${METADATA_DOMAIN}${canonicalJson(projection)}`);
  const guard = openTrustedParent(deterministicOptions(fixture));

  assert.equal(guard.ancestorMetadataHash, expected);
  assert.match(guard.ancestorMetadataHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(guard.ancestorMetadataHash.includes(fixture.trustedAncestor), false);
  assert.equal(guard.ancestorMetadataHash.includes(fixture.terminal), false);
  guard.revalidate();
  assert.equal(guard.ancestorMetadataHash, expected);
  guard.close();
});

test('descriptor mode drift and namespace replacement are detected before reuse', (t) => {
  {
    const fixture = makeFixture(t);
    const guard = openTrustedParent(deterministicOptions(fixture));
    fs.chmodSync(fixture.terminal, 0o755);
    assert.throws(() => guard.revalidate(), /changed/);
    guard.close();
  }
  {
    const fixture = makeFixture(t);
    fs.writeFileSync(fixture.targetFile, 'old namespace', { mode: 0o600 });
    const guard = openTrustedParent(deterministicOptions(fixture));
    const moved = `${fixture.terminal}-moved`;
    fs.renameSync(fixture.terminal, moved);
    fs.mkdirSync(fixture.terminal, { mode: 0o700 });
    fs.writeFileSync(fixture.targetFile, 'replacement namespace', { mode: 0o600 });
    assert.throws(() => guard.openLeaf(fs.constants.O_RDONLY), /changed/);
    guard.close();
  }
});

test('injected descriptor inode drift is detected by full-chain revalidation', (t) => {
  const fixture = makeFixture(t);
  const terminalStat = fs.statSync(fixture.terminal, { bigint: true });
  const guard = openTrustedParent(deterministicOptions(fixture));
  const original = fs.fstatSync;
  fs.fstatSync = function injectedFstat(descriptor, options) {
    const stat = original.call(fs, descriptor, options);
    if (options?.bigint === true && stat.dev === terminalStat.dev && stat.ino === terminalStat.ino) {
      return new Proxy(stat, {
        get(target, property, receiver) {
          if (property === 'ino') return target.ino + 1n;
          return Reflect.get(target, property, receiver);
        },
      });
    }
    return stat;
  };
  try {
    assert.throws(() => guard.revalidate(), /changed/);
  } finally {
    fs.fstatSync = original;
    guard.close();
  }
});

test('cdp-testnet rejects zero or equal Kernel and Pi UIDs before platform admission', (t) => {
  const fixture = makeFixture(t);
  assert.throws(
    () => openTrustedParent(deterministicOptions(fixture, {
      mode: 'cdp-testnet', kernelUid: 0, agentUid: 501,
    })),
    /nonzero/,
  );
  assert.throws(
    () => openTrustedParent(deterministicOptions(fixture, {
      mode: 'cdp-testnet', kernelUid: 501, agentUid: 501,
    })),
    /distinct/,
  );
});

test('cdp-testnet fails closed on non-Linux and never returns simulated proof', {
  skip: process.platform === 'linux' ? 'this negative admission test requires a non-Linux host' : false,
}, (t) => {
  const fixture = makeFixture(t);
  assert.throws(
    () => openTrustedParent(deterministicOptions(fixture, {
      mode: 'cdp-testnet', kernelUid: 501, agentUid: 502,
    })),
    /Linux/,
  );
});

test('real Linux root-owned and dropped-UID path integration', {
  skip: process.platform !== 'linux'
    ? 'requires Linux /proc/self/fd, root-owned fixtures, and disposable distinct UIDs'
    : 'requires a separately provisioned privileged integration fixture',
}, () => {});

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  loadOrInitializePrivateFile,
  preflightSqliteFiles,
  preparePrivateFile,
  readPrivateInputFile,
  secureNewSqliteSideFiles,
} from '../src/kernel/secure-storage.mjs';

const CURRENT_UID = process.getuid();
const REPOSITORY_ROOT = fs.realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
const SECURE_STORAGE_URL = new URL('../src/kernel/secure-storage.mjs', import.meta.url).href;
const PRIVATE_VALUE_PATTERN = /^secret:[0-9a-f]{32}\n$/;

function authority(t, prefix = 'wallet-kernel-storage-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(directory, 0o700);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: CURRENT_UID,
    agentUid: CURRENT_UID,
  });
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  return {
    directory,
    databasePath: path.join(directory, 'kernel.sqlite'),
    privatePath: path.join(directory, 'receipt.receipt-key'),
    pathTrust,
  };
}

function secret(pair) {
  return `secret:${pair.repeat(16)}\n`;
}

function validatePrivateValue(bytes) {
  const value = Buffer.from(bytes).toString('utf8');
  if (!PRIVATE_VALUE_PATTERN.test(value)) throw new Error('invalid private value');
  return value;
}

function privateCandidateNames(directory, basename) {
  const escaped = basename.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const pattern = new RegExp(`^\\.${escaped}\\.tmp-[1-9][0-9]*-[0-9a-f]{32}$`);
  return fs.readdirSync(directory).filter((name) => pattern.test(name)).sort();
}

async function storageChildMain() {
  const fsModule = (await import('node:fs')).default;
  const [moduleUrl, payloadText] = process.argv.slice(1);
  const payload = JSON.parse(payloadText);
  const storage = await import(moduleUrl);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: payload.directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  const validateBytes = (bytes) => {
    const value = Buffer.from(bytes).toString('utf8');
    if (!/^secret:[0-9a-f]{32}\n$/.test(value)) throw new Error('invalid private value');
    return value;
  };

  if (payload.readyFile) {
    fsModule.writeFileSync(payload.readyFile, 'ready', { mode: 0o600 });
    while (!fsModule.existsSync(payload.releaseFile)) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  }

  const result = storage.loadOrInitializePrivateFile({
    filePath: payload.filePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(payload.value, 'utf8'),
    validateBytes,
    faultInjector: (point) => {
      if (point === payload.faultPoint) process.abort();
    },
    pathTrust,
  });
  process.stdout.write(JSON.stringify({ result }));
}

const STORAGE_CHILD_SCRIPT = `(${storageChildMain.toString()})().catch((error) => {
  process.stderr.write(String(error && error.message ? error.message : error));
  process.exitCode = 1;
})`;

function runStorageChild(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [
      '--input-type=module',
      '-e',
      STORAGE_CHILD_SCRIPT,
      SECURE_STORAGE_URL,
      JSON.stringify(payload),
    ], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.once('error', reject);
    child.once('close', (code, signal) => resolve({ code, signal, stderr, stdout }));
  });
}

async function waitForFiles(files, timeoutMilliseconds = 5_000) {
  const deadline = Date.now() + timeoutMilliseconds;
  while (!files.every((file) => fs.existsSync(file))) {
    if (Date.now() >= deadline) throw new Error('timed out waiting for child readiness');
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

test('exports the secure storage boundary', () => {
  for (const value of [
    preparePrivateFile,
    readPrivateInputFile,
    preflightSqliteFiles,
    secureNewSqliteSideFiles,
    loadOrInitializePrivateFile,
  ]) {
    assert.equal(typeof value, 'function');
  }
});

test('local authority artifacts are ignored and the environment template stays nonsecret', () => {
  const gitignore = fs.readFileSync(path.join(REPOSITORY_ROOT, '.gitignore'), 'utf8');
  const expectedIgnoreBlock = `# Agent Spend Control Plane local authority
spikes/pi-wielder/**/*.sqlite
spikes/pi-wielder/**/*.sqlite-wal
spikes/pi-wielder/**/*.sqlite-shm
spikes/pi-wielder/**/*.operator-token
spikes/pi-wielder/**/*.receipt-key
spikes/pi-wielder/**/*.agent-credential
spikes/pi-wielder/**/*.agent-enrollment
spikes/pi-wielder/**/*.authority-lock.sqlite*`;
  assert.equal(gitignore.includes(expectedIgnoreBlock), true);

  const environment = fs.readFileSync(
    path.join(REPOSITORY_ROOT, 'spikes/pi-wielder/.env.example'),
    'utf8',
  );
  const expectedEnvironmentBlock = `# --- Agent Spend Control Plane local authority (absolute, outside checkout) --
WALLET_KERNEL_DB_FILE=
WALLET_KERNEL_RECEIPT_KEY_FILE=
WALLET_KERNEL_OPERATOR_TOKEN_FILE=
WALLET_KERNEL_TRUSTED_ANCESTOR=
WALLET_KERNEL_EXPECTED_AGENT_UID=
WALLET_KERNEL_EXPECTED_AGENT_GID=
WALLET_KERNEL_POLICY_FILE=
WALLET_KERNEL_ROUTE_FILE=
WALLET_KERNEL_PORT=8402
WALLET_KERNEL_OPERATOR_PORT=8405`;
  assert.equal(environment.includes(expectedEnvironmentBlock), true);
});

test('every file-backed boundary requires an explicit frozen pathTrust object', (t) => {
  const fixture = authority(t);
  fs.writeFileSync(fixture.privatePath, secret('11'), { mode: 0o600 });
  const initializer = (pathTrust) => () => loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(secret('22')),
    validateBytes: validatePrivateValue,
    pathTrust,
  });
  const calls = (pathTrust) => [
    () => preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust }),
    () => readPrivateInputFile(fixture.privatePath, 'Receipt key', { pathTrust }),
    () => preflightSqliteFiles(fixture.databasePath, { pathTrust }),
    () => secureNewSqliteSideFiles(fixture.databasePath, new Set(), { pathTrust }),
    initializer(pathTrust),
  ];

  for (const action of calls(undefined)) assert.throws(action, /frozen pathTrust/);
  const mutableTrust = { ...fixture.pathTrust };
  for (const action of calls(mutableTrust)) assert.throws(action, /frozen pathTrust/);
});

test('private files must use absolute paths outside the checkout', (t) => {
  const fixture = authority(t);
  assert.throws(
    () => preparePrivateFile('relative.receipt-key', 'Receipt key', {
      pathTrust: fixture.pathTrust,
    }),
    /absolute/,
  );
  assert.throws(
    () => preparePrivateFile(
      path.join(REPOSITORY_ROOT, 'spikes/pi-wielder/forbidden.receipt-key'),
      'Receipt key',
      { pathTrust: fixture.pathTrust },
    ),
    /outside the checkout/,
  );
});

test('preparePrivateFile creates or reuses only a current-owner 0600 regular file', (t) => {
  const fixture = authority(t);
  assert.equal(
    preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: fixture.pathTrust }),
    fixture.privatePath,
  );
  let stat = fs.lstatSync(fixture.privatePath);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.uid, CURRENT_UID);
  assert.equal(stat.mode & 0o777, 0o600);

  fs.writeFileSync(fixture.privatePath, secret('11'));
  assert.equal(
    preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: fixture.pathTrust }),
    fixture.privatePath,
  );
  stat = fs.lstatSync(fixture.privatePath);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('11'));
});

test('prepare and read never chmod-repair permissive, symlinked, or nonfile inputs', (t) => {
  {
    const fixture = authority(t);
    fs.writeFileSync(fixture.privatePath, secret('11'), { mode: 0o644 });
    assert.throws(
      () => preparePrivateFile(fixture.privatePath, 'Receipt key', {
        pathTrust: fixture.pathTrust,
      }),
      /owner-only/,
    );
    assert.equal(fs.statSync(fixture.privatePath).mode & 0o777, 0o644);
  }
  {
    const fixture = authority(t);
    const target = path.join(fixture.directory, 'symlink-target');
    fs.writeFileSync(target, secret('22'), { mode: 0o600 });
    fs.symlinkSync(target, fixture.privatePath);
    assert.throws(
      () => readPrivateInputFile(fixture.privatePath, 'Receipt key', {
        pathTrust: fixture.pathTrust,
      }),
      /symlink/,
    );
    assert.equal(fs.lstatSync(fixture.privatePath).isSymbolicLink(), true);
    assert.equal(fs.readFileSync(target, 'utf8'), secret('22'));
  }
  {
    const fixture = authority(t);
    fs.mkdirSync(fixture.privatePath, { mode: 0o700 });
    assert.throws(
      () => preparePrivateFile(fixture.privatePath, 'Receipt key', {
        pathTrust: fixture.pathTrust,
      }),
      /regular file/,
    );
    assert.equal(fs.statSync(fixture.privatePath).isDirectory(), true);
  }
});

test('readPrivateInputFile reads one held descriptor and enforces nonempty bounded bytes', (t) => {
  const fixture = authority(t);
  const originalValue = secret('33');
  fs.writeFileSync(fixture.privatePath, originalValue, { mode: 0o600 });
  const moved = path.join(fixture.directory, 'original-held-value');
  const originalReadFile = fs.readFileSync;
  let descriptorReads = 0;
  fs.readFileSync = function swapPathBeforeDescriptorRead(input, ...rest) {
    if (typeof input === 'number') {
      descriptorReads += 1;
      fs.renameSync(fixture.privatePath, moved);
      fs.writeFileSync(fixture.privatePath, secret('44'), { mode: 0o600 });
    }
    return originalReadFile.call(fs, input, ...rest);
  };
  let bytes;
  try {
    bytes = readPrivateInputFile(fixture.privatePath, 'Policy file', {
      maximumBytes: Buffer.byteLength(originalValue),
      pathTrust: fixture.pathTrust,
    });
  } finally {
    fs.readFileSync = originalReadFile;
  }
  assert.equal(descriptorReads, 1);
  assert.equal(bytes.toString('utf8'), originalValue);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('44'));

  fs.writeFileSync(fixture.privatePath, '', { mode: 0o600 });
  assert.throws(
    () => readPrivateInputFile(fixture.privatePath, 'Policy file', {
      pathTrust: fixture.pathTrust,
    }),
    /size/,
  );
  fs.writeFileSync(fixture.privatePath, '12345', { mode: 0o600 });
  assert.throws(
    () => readPrivateInputFile(fixture.privatePath, 'Policy file', {
      maximumBytes: 4,
      pathTrust: fixture.pathTrust,
    }),
    /size/,
  );
});

test('SQLite preflight accepts absent or exact 0600 current-owner regular files', (t) => {
  const fixture = authority(t);
  assert.deepEqual([...preflightSqliteFiles(fixture.databasePath, {
    pathTrust: fixture.pathTrust,
  })], []);

  const expected = ['', '-wal', '-shm'].map((suffix) => `${fixture.databasePath}${suffix}`);
  for (const target of expected) fs.writeFileSync(target, '', { mode: 0o600 });
  const existing = preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust });
  assert.equal(existing instanceof Set, true);
  assert.deepEqual([...existing], expected);
});

test('SQLite preflight rejects permissive, symlinked, and nonfile database siblings', (t) => {
  for (const suffix of ['', '-wal', '-shm']) {
    {
      const fixture = authority(t);
      const target = `${fixture.databasePath}${suffix}`;
      fs.writeFileSync(target, '', { mode: 0o644 });
      assert.throws(
        () => preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust }),
        /owner-only/,
      );
      assert.equal(fs.statSync(target).mode & 0o777, 0o644);
    }
    {
      const fixture = authority(t);
      const target = `${fixture.databasePath}${suffix}`;
      const symlinkTarget = path.join(fixture.directory, `target${suffix || '-database'}`);
      fs.writeFileSync(symlinkTarget, '', { mode: 0o600 });
      fs.symlinkSync(symlinkTarget, target);
      assert.throws(
        () => preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust }),
        /symlink/,
      );
      assert.equal(fs.lstatSync(target).isSymbolicLink(), true);
    }
    {
      const fixture = authority(t);
      const target = `${fixture.databasePath}${suffix}`;
      fs.mkdirSync(target, { mode: 0o700 });
      assert.throws(
        () => preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust }),
        /regular/,
      );
      assert.equal(fs.statSync(target).isDirectory(), true);
    }
  }
});

test('only SQLite files absent at preflight may be tightened to 0600', (t) => {
  const fixture = authority(t);
  fs.writeFileSync(fixture.databasePath, '', { mode: 0o600 });
  const existing = preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust });
  fs.writeFileSync(`${fixture.databasePath}-wal`, '', { mode: 0o644 });
  fs.writeFileSync(`${fixture.databasePath}-shm`, '', { mode: 0o666 });

  secureNewSqliteSideFiles(fixture.databasePath, existing, { pathTrust: fixture.pathTrust });
  assert.equal(fs.statSync(fixture.databasePath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(`${fixture.databasePath}-wal`).mode & 0o777, 0o600);
  assert.equal(fs.statSync(`${fixture.databasePath}-shm`).mode & 0o777, 0o600);

  fs.chmodSync(fixture.databasePath, 0o644);
  assert.throws(
    () => secureNewSqliteSideFiles(fixture.databasePath, existing, {
      pathTrust: fixture.pathTrust,
    }),
    /owner-only/,
  );
  assert.equal(fs.statSync(fixture.databasePath).mode & 0o777, 0o644);
});

test('new SQLite symlinks and nonfiles fail closed instead of being repaired', (t) => {
  for (const kind of ['symlink', 'directory']) {
    const fixture = authority(t);
    const existing = preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust });
    const wal = `${fixture.databasePath}-wal`;
    if (kind === 'symlink') {
      const target = path.join(fixture.directory, 'wal-target');
      fs.writeFileSync(target, '', { mode: 0o600 });
      fs.symlinkSync(target, wal);
    } else {
      fs.mkdirSync(wal, { mode: 0o700 });
    }
    assert.throws(
      () => secureNewSqliteSideFiles(fixture.databasePath, existing, {
        pathTrust: fixture.pathTrust,
      }),
      /symlink|regular/,
    );
    assert.equal(
      kind === 'symlink' ? fs.lstatSync(wal).isSymbolicLink() : fs.statSync(wal).isDirectory(),
      true,
    );
  }
});

test('private initializer atomically creates one value and reuses it without overwrite', (t) => {
  const fixture = authority(t);
  let createCalls = 0;
  const firstValue = secret('55');
  const first = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => {
      createCalls += 1;
      return Buffer.from(firstValue);
    },
    validateBytes: validatePrivateValue,
    randomBytes: () => Buffer.from('01'.repeat(16), 'hex'),
    pathTrust: fixture.pathTrust,
  });
  assert.equal(first, firstValue);
  assert.equal(createCalls, 1);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), firstValue);
  assert.equal(fs.statSync(fixture.privatePath).mode & 0o777, 0o600);
  assert.deepEqual(privateCandidateNames(fixture.directory, path.basename(fixture.privatePath)), []);

  const reused = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => {
      createCalls += 1;
      return Buffer.from(secret('66'));
    },
    validateBytes: validatePrivateValue,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(reused, firstValue);
  assert.equal(createCalls, 1);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), firstValue);
});

test('existing empty, truncated, invalid, symlinked, permissive, and nonfile values fail closed', (t) => {
  const cases = [
    ['empty', (fixture) => fs.writeFileSync(fixture.privatePath, '', { mode: 0o600 })],
    ['truncated', (fixture) => fs.writeFileSync(fixture.privatePath, 'secret:aa\n', { mode: 0o600 })],
    ['invalid', (fixture) => fs.writeFileSync(fixture.privatePath, 'not-secret\n', { mode: 0o600 })],
    ['permissive', (fixture) => fs.writeFileSync(fixture.privatePath, secret('11'), { mode: 0o644 })],
    ['directory', (fixture) => fs.mkdirSync(fixture.privatePath, { mode: 0o700 })],
    ['symlink', (fixture) => {
      const target = path.join(fixture.directory, 'existing-target');
      fs.writeFileSync(target, secret('11'), { mode: 0o600 });
      fs.symlinkSync(target, fixture.privatePath);
    }],
  ];

  for (const [name, arrange] of cases) {
    const fixture = authority(t, `wallet-kernel-${name}-`);
    arrange(fixture);
    let createCalls = 0;
    assert.throws(
      () => loadOrInitializePrivateFile({
        filePath: fixture.privatePath,
        label: 'Receipt key',
        createBytes: () => {
          createCalls += 1;
          return Buffer.from(secret('22'));
        },
        validateBytes: validatePrivateValue,
        pathTrust: fixture.pathTrust,
      }),
      /empty|invalid|owner-only|regular file|symlink/,
    );
    assert.equal(createCalls, 0);
    if (name === 'permissive') {
      assert.equal(fs.statSync(fixture.privatePath).mode & 0o777, 0o644);
    }
    if (name === 'symlink') assert.equal(fs.lstatSync(fixture.privatePath).isSymbolicLink(), true);
  }
});

test('empty or invalid generated values fail before publishing and leave no candidate', (t) => {
  for (const value of [Buffer.alloc(0), Buffer.from('invalid\n')]) {
    const fixture = authority(t);
    assert.throws(
      () => loadOrInitializePrivateFile({
        filePath: fixture.privatePath,
        label: 'Receipt key',
        createBytes: () => value,
        validateBytes: validatePrivateValue,
        randomBytes: () => Buffer.from('02'.repeat(16), 'hex'),
        pathTrust: fixture.pathTrust,
      }),
      /empty|invalid/,
    );
    assert.equal(fs.existsSync(fixture.privatePath), false);
    assert.deepEqual(privateCandidateNames(fixture.directory, path.basename(fixture.privatePath)), []);
  }
});

test('initializer never removes a colliding temp name it did not create', (t) => {
  const fixture = authority(t);
  const random = Buffer.from('03'.repeat(16), 'hex');
  const candidateName = `.${path.basename(fixture.privatePath)}.tmp-${process.pid}-${random.toString('hex')}`;
  const candidatePath = path.join(fixture.directory, candidateName);

  assert.throws(
    () => loadOrInitializePrivateFile({
      filePath: fixture.privatePath,
      label: 'Receipt key',
      createBytes: () => Buffer.from(secret('33')),
      validateBytes: validatePrivateValue,
      randomBytes: () => {
        fs.writeFileSync(candidatePath, secret('44'), { mode: 0o600 });
        return random;
      },
      pathTrust: fixture.pathTrust,
    }),
    (error) => error.code === 'EEXIST',
  );
  assert.equal(fs.existsSync(candidatePath), true);
  assert.equal(fs.readFileSync(candidatePath, 'utf8'), secret('44'));
  assert.equal(fs.existsSync(fixture.privatePath), false);
});

test('recovery publishes the lexicographically first valid candidate and ignores decoys', (t) => {
  const fixture = authority(t);
  const basename = path.basename(fixture.privatePath);
  const first = `.${basename}.tmp-101-${'11'.repeat(16)}`;
  const second = `.${basename}.tmp-202-${'22'.repeat(16)}`;
  const decoys = [
    `.${basename}.tmp-0-${'33'.repeat(16)}`,
    `.${basename}.tmp-303-${'AA'.repeat(16)}`,
    `.other.tmp-404-${'44'.repeat(16)}`,
  ];
  fs.writeFileSync(path.join(fixture.directory, second), secret('22'), { mode: 0o600 });
  fs.writeFileSync(path.join(fixture.directory, first), secret('11'), { mode: 0o600 });
  for (const name of decoys) {
    fs.writeFileSync(path.join(fixture.directory, name), 'decoy', { mode: 0o644 });
  }

  const recovered = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(secret('55')),
    validateBytes: validatePrivateValue,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(recovered, secret('11'));
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('11'));
  assert.deepEqual(privateCandidateNames(fixture.directory, basename), []);
  for (const name of decoys) assert.equal(fs.existsSync(path.join(fixture.directory, name)), true);
});

test('valid final value wins recovery and validated candidates are removed', (t) => {
  const fixture = authority(t);
  const basename = path.basename(fixture.privatePath);
  const candidate = `.${basename}.tmp-505-${'55'.repeat(16)}`;
  fs.writeFileSync(fixture.privatePath, secret('11'), { mode: 0o600 });
  fs.writeFileSync(path.join(fixture.directory, candidate), secret('22'), { mode: 0o600 });

  const recovered = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(secret('33')),
    validateBytes: validatePrivateValue,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(recovered, secret('11'));
  assert.equal(fs.existsSync(path.join(fixture.directory, candidate)), false);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('11'));
});

test('unsafe exact-namespace recovery candidates fail closed and are never deleted', (t) => {
  const cases = [
    ['invalid', (candidate) => fs.writeFileSync(candidate, 'invalid\n', { mode: 0o600 })],
    ['permissive', (candidate) => fs.writeFileSync(candidate, secret('11'), { mode: 0o644 })],
    ['directory', (candidate) => fs.mkdirSync(candidate, { mode: 0o700 })],
    ['symlink', (candidate, fixture) => {
      const target = path.join(fixture.directory, 'candidate-target');
      fs.writeFileSync(target, secret('11'), { mode: 0o600 });
      fs.symlinkSync(target, candidate);
    }],
  ];
  for (const [kind, arrange] of cases) {
    const fixture = authority(t, `wallet-kernel-candidate-${kind}-`);
    const name = `.${path.basename(fixture.privatePath)}.tmp-606-${'66'.repeat(16)}`;
    const candidate = path.join(fixture.directory, name);
    arrange(candidate, fixture);
    assert.throws(
      () => loadOrInitializePrivateFile({
        filePath: fixture.privatePath,
        label: 'Receipt key',
        createBytes: () => Buffer.from(secret('22')),
        validateBytes: validatePrivateValue,
        pathTrust: fixture.pathTrust,
      }),
      /candidate.*invalid|candidate.*owner-only|candidate.*regular|candidate.*symlink/,
    );
    assert.doesNotThrow(() => fs.lstatSync(candidate));
    assert.equal(fs.existsSync(fixture.privatePath), false);
  }
});

test('wrong-owner-like recovery candidate metadata fails closed without chown privileges', (t) => {
  const fixture = authority(t, 'wallet-kernel-candidate-owner-');
  const name = `.${path.basename(fixture.privatePath)}.tmp-707-${'77'.repeat(16)}`;
  const candidate = path.join(fixture.directory, name);
  fs.writeFileSync(candidate, secret('11'), { mode: 0o600 });
  const candidateStat = fs.statSync(candidate);
  const originalFstat = fs.fstatSync;
  fs.fstatSync = function injectWrongOwner(descriptor, options) {
    const stat = originalFstat.call(fs, descriptor, options);
    if (options === undefined && stat.isFile() && stat.ino === candidateStat.ino) {
      return new Proxy(stat, {
        get(target, property, receiver) {
          if (property === 'uid') return target.uid + 1;
          return Reflect.get(target, property, receiver);
        },
      });
    }
    return stat;
  };
  try {
    assert.throws(
      () => loadOrInitializePrivateFile({
        filePath: fixture.privatePath,
        label: 'Receipt key',
        createBytes: () => Buffer.from(secret('22')),
        validateBytes: validatePrivateValue,
        pathTrust: fixture.pathTrust,
      }),
      /candidate.*owned by the current user/,
    );
  } finally {
    fs.fstatSync = originalFstat;
  }
  assert.doesNotThrow(() => fs.lstatSync(candidate));
  assert.equal(fs.existsSync(fixture.privatePath), false);
});

test('two fresh processes racing initialization converge on one value without overwrite', async (t) => {
  const fixture = authority(t, 'wallet-kernel-race-');
  const coordination = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-race-gate-'));
  fs.chmodSync(coordination, 0o700);
  t.after(() => fs.rmSync(coordination, { force: true, recursive: true }));
  const releaseFile = path.join(coordination, 'release');
  const readyFiles = [path.join(coordination, 'ready-one'), path.join(coordination, 'ready-two')];
  const values = [secret('77'), secret('88')];
  const children = values.map((value, index) => runStorageChild({
    directory: fixture.directory,
    filePath: fixture.privatePath,
    readyFile: readyFiles[index],
    releaseFile,
    value,
  }));

  try {
    await waitForFiles(readyFiles);
  } finally {
    fs.writeFileSync(releaseFile, 'release', { mode: 0o600 });
  }
  const results = await Promise.all(children);
  for (const result of results) {
    assert.equal(result.code, 0, result.stderr);
    assert.equal(result.signal, null);
  }
  const returned = results.map((result) => JSON.parse(result.stdout).result);
  assert.equal(returned[0], returned[1]);
  assert.equal(values.includes(returned[0]), true);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), returned[0]);
  assert.equal(fs.statSync(fixture.privatePath).mode & 0o777, 0o600);
  assert.deepEqual(privateCandidateNames(fixture.directory, path.basename(fixture.privatePath)), []);
});

test('fresh processes recover one reusable value after every private-file crash boundary', async (t) => {
  const faultPoints = [
    'after_private_temp_write',
    'after_private_temp_fsync',
    'after_private_publish',
    'after_private_directory_fsync',
  ];
  for (const [index, faultPoint] of faultPoints.entries()) {
    const fixture = authority(t, `wallet-kernel-crash-${index}-`);
    const original = secret('99');
    const crash = await runStorageChild({
      directory: fixture.directory,
      faultPoint,
      filePath: fixture.privatePath,
      value: original,
    });
    assert.equal(crash.code, null, `${faultPoint}: ${crash.stderr}`);
    assert.equal(crash.signal, 'SIGABRT', `${faultPoint}: ${crash.stderr}`);

    const recovery = await runStorageChild({
      directory: fixture.directory,
      filePath: fixture.privatePath,
      value: secret('aa'),
    });
    assert.equal(recovery.code, 0, `${faultPoint}: ${recovery.stderr}`);
    assert.equal(JSON.parse(recovery.stdout).result, original);
    assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), original);
    assert.equal(fs.statSync(fixture.privatePath).mode & 0o777, 0o600);
    assert.deepEqual(
      privateCandidateNames(fixture.directory, path.basename(fixture.privatePath)),
      [],
    );
  }
});

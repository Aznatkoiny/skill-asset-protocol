import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
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

function childResult(child) {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    child.on('error', reject);
    child.on('exit', (code) => code === 0
      ? resolve(stdout.trim())
      : reject(new Error(`writer exited ${code}: ${stderr}`)));
  });
}

function memoryStore() {
  return openKernelStore({ filePath: ':memory:', allowMemory: true });
}

function sqlText(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function seedSchemaDependencies(store) {
  store.execForTest(`
    INSERT INTO policy_versions
      (id, schema_version, canonical_json, policy_hash, applied_at)
      VALUES ('policy-1', 1, '{}', 'policy-hash-1', '2026-08-01T00:00:00.000Z');
    INSERT INTO agent_enrollments
      (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
       state, enrolled_by_operator_hash, enrolled_at)
      VALUES ('agent-1', 'credential-1', 'enrollment-1', '1000', '1000',
       'active', 'operator-1', '2026-08-01T00:00:00.000Z');
    INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES ('session-1', 'adapter-1', '0xwallet', 'policy-1', 'open',
       '2026-08-01T00:00:00.000Z');
    INSERT INTO spend_intents
      (id, request_id, session_id, enrollment_hash, route_id, method,
       request_url_hash, seller_origin, resource_path, body_hash,
       header_allowlist_hash, ordinary_fingerprint, purpose_label,
       correlation_id, idempotency_key, wallet_address, intent_hash,
       state, created_at, updated_at)
      VALUES ('intent-1', 'request-1', 'session-1', 'enrollment-1', 'route-1', 'POST',
       'url-hash-1', 'https://seller.example', '/resource', 'body-hash-1',
       'headers-hash-1', 'fingerprint-1', 'inference', 'correlation-1',
       'idempotency-1', '0xwallet', 'intent-hash-1', 'captured',
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z');
  `);
}

function withSeededStore(operation) {
  const store = memoryStore();
  try {
    seedSchemaDependencies(store);
    return operation(store);
  } finally {
    store.close();
  }
}

function assertAccepted(sql) {
  withSeededStore((store) => assert.doesNotThrow(() => store.execForTest(sql)));
}

function assertRejected(sql) {
  withSeededStore((store) => assert.throws(() => store.execForTest(sql), /constraint/i));
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

test('frozen pathTrust accepts only exact own enumerable data fields without invoking accessors', (t) => {
  const fixture = authority(t);
  let getterCalls = 0;
  const accessorTrust = {
    mode: 'deterministic',
    kernelUid: CURRENT_UID,
    agentUid: CURRENT_UID,
  };
  Object.defineProperty(accessorTrust, 'trustedAncestor', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return fixture.directory;
    },
  });
  Object.freeze(accessorTrust);
  assert.throws(
    () => preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: accessorTrust }),
    /data fields/,
  );
  assert.equal(getterCalls, 0);

  const symbolTrust = { ...fixture.pathTrust };
  symbolTrust[Symbol('hidden')] = 'value';
  Object.freeze(symbolTrust);
  assert.throws(
    () => preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: symbolTrust }),
    /symbols/,
  );

  const unknownTrust = Object.freeze({ ...fixture.pathTrust, extra: true });
  assert.throws(
    () => preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: unknownTrust }),
    /exact fields/,
  );

  const inheritedTrust = Object.freeze(Object.assign(
    Object.create({ mode: 'deterministic' }),
    {
      trustedAncestor: fixture.directory,
      kernelUid: CURRENT_UID,
      agentUid: CURRENT_UID,
    },
  ));
  assert.throws(
    () => preparePrivateFile(fixture.privatePath, 'Receipt key', { pathTrust: inheritedTrust }),
    /plain object|exact fields/,
  );
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
  const originalRead = fs.readSync;
  const descriptorsRead = new Set();
  let swapped = false;
  fs.readSync = function swapPathBeforeDescriptorRead(descriptor, ...rest) {
    descriptorsRead.add(descriptor);
    if (!swapped) {
      swapped = true;
      fs.renameSync(fixture.privatePath, moved);
      fs.writeFileSync(fixture.privatePath, secret('44'), { mode: 0o600 });
    }
    return originalRead.call(fs, descriptor, ...rest);
  };
  let bytes;
  try {
    bytes = readPrivateInputFile(fixture.privatePath, 'Policy file', {
      maximumBytes: Buffer.byteLength(originalValue),
      pathTrust: fixture.pathTrust,
    });
  } finally {
    fs.readSync = originalRead;
  }
  assert.equal(descriptorsRead.size, 1);
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
  assert.throws(
    () => readPrivateInputFile(fixture.privatePath, 'Policy file', {
      maximumBytes: 1_048_577,
      pathTrust: fixture.pathTrust,
    }),
    /hard ceiling/,
  );
});

test('bounded descriptor reads reject growth without reading beyond limit plus one', (t) => {
  const fixture = authority(t);
  fs.writeFileSync(fixture.privatePath, '1', { mode: 0o600 });
  const originalRead = fs.readSync;
  let maximumRequested = 0;
  let grew = false;
  fs.readSync = function growHeldInode(descriptor, buffer, offset, length, position) {
    maximumRequested = Math.max(maximumRequested, length);
    if (!grew) {
      grew = true;
      fs.appendFileSync(fixture.privatePath, '23456789');
    }
    return originalRead.call(fs, descriptor, buffer, offset, length, position);
  };
  try {
    assert.throws(
      () => readPrivateInputFile(fixture.privatePath, 'Policy file', {
        maximumBytes: 4,
        pathTrust: fixture.pathTrust,
      }),
      /size/,
    );
  } finally {
    fs.readSync = originalRead;
  }
  assert.equal(maximumRequested <= 5, true);
});

test('SQLite preflight accepts absent or exact 0600 current-owner regular files', (t) => {
  const fixture = authority(t);
  const absent = preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust });
  assert.equal(Object.isFrozen(absent), true);
  assert.deepEqual(Object.keys(absent), []);
  assert.equal(absent instanceof Set, false);

  for (const suffix of ['', '-wal', '-shm']) {
    fs.writeFileSync(`${fixture.databasePath}${suffix}`, '', { mode: 0o600 });
  }
  const existing = preflightSqliteFiles(fixture.databasePath, { pathTrust: fixture.pathTrust });
  assert.equal(Object.isFrozen(existing), true);
  assert.deepEqual(Object.keys(existing), []);
  assert.equal(existing instanceof Set, false);
});

test('SQLite repair requires its opaque one-use path-bound preflight capability', (t) => {
  const first = authority(t, 'wallet-kernel-preflight-one-');
  const second = authority(t, 'wallet-kernel-preflight-two-');
  const capability = preflightSqliteFiles(first.databasePath, { pathTrust: first.pathTrust });
  fs.writeFileSync(`${first.databasePath}-wal`, '', { mode: 0o644 });

  assert.throws(
    () => secureNewSqliteSideFiles(first.databasePath, Object.freeze({}), {
      pathTrust: first.pathTrust,
    }),
    /opaque preflight capability/,
  );
  assert.equal(fs.statSync(`${first.databasePath}-wal`).mode & 0o777, 0o644);
  assert.throws(
    () => secureNewSqliteSideFiles(second.databasePath, capability, {
      pathTrust: second.pathTrust,
    }),
    /different database path/,
  );
  assert.equal(fs.statSync(`${first.databasePath}-wal`).mode & 0o777, 0o644);
  assert.throws(
    () => secureNewSqliteSideFiles(first.databasePath, capability, {
      pathTrust: first.pathTrust,
    }),
    /consumed|opaque preflight capability/,
  );
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
  const secondPreflight = preflightSqliteFiles(fixture.databasePath, {
    pathTrust: fixture.pathTrust,
  });
  fs.writeFileSync(`${fixture.databasePath}-wal`, '', { mode: 0o644 });
  fs.writeFileSync(`${fixture.databasePath}-shm`, '', { mode: 0o666 });

  secureNewSqliteSideFiles(fixture.databasePath, existing, { pathTrust: fixture.pathTrust });
  assert.equal(fs.statSync(fixture.databasePath).mode & 0o777, 0o600);
  assert.equal(fs.statSync(`${fixture.databasePath}-wal`).mode & 0o777, 0o600);
  assert.equal(fs.statSync(`${fixture.databasePath}-shm`).mode & 0o777, 0o600);

  fs.chmodSync(fixture.databasePath, 0o644);
  assert.throws(
    () => secureNewSqliteSideFiles(fixture.databasePath, secondPreflight, {
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

test('private validator results are detached before input bytes are zeroed', (t) => {
  const fixture = authority(t);
  const value = secret('5a');
  fs.writeFileSync(fixture.privatePath, value, { mode: 0o600 });

  const whole = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(secret('5b')),
    validateBytes: (bytes) => bytes,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(Buffer.isBuffer(whole), true);
  assert.equal(whole.toString('utf8'), value);

  const view = loadOrInitializePrivateFile({
    filePath: fixture.privatePath,
    label: 'Receipt key',
    createBytes: () => Buffer.from(secret('5c')),
    validateBytes: (bytes) => bytes.subarray(0, 6),
    pathTrust: fixture.pathTrust,
  });
  assert.equal(Buffer.isBuffer(view), true);
  assert.equal(view.toString('utf8'), 'secret');

  assert.throws(
    () => loadOrInitializePrivateFile({
      filePath: fixture.privatePath,
      label: 'Receipt key',
      createBytes: () => Buffer.from(secret('5d')),
      validateBytes: (bytes) => {
        const inputEnd = bytes.byteOffset + bytes.byteLength;
        if (bytes.byteOffset > 0) return new Uint8Array(bytes.buffer, 0, 1);
        if (inputEnd < bytes.buffer.byteLength) {
          return new Uint8Array(bytes.buffer, inputEnd, 1);
        }
        return bytes.buffer;
      },
      pathTrust: fixture.pathTrust,
    }),
    /outside its input bytes|input ArrayBuffer/,
  );
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

test('recovery never publishes or removes a temp name whose validated inode was replaced', (t) => {
  for (const finalExists of [false, true]) {
    const fixture = authority(t, `wallet-kernel-identity-${finalExists ? 'unlink' : 'publish'}-`);
    const basename = path.basename(fixture.privatePath);
    const name = `.${basename}.tmp-808-${'88'.repeat(16)}`;
    const candidate = path.join(fixture.directory, name);
    const moved = `${candidate}.validated-inode`;
    fs.writeFileSync(candidate, secret('88'), { mode: 0o600 });
    if (finalExists) fs.writeFileSync(fixture.privatePath, secret('11'), { mode: 0o600 });
    const candidateInode = fs.statSync(candidate).ino;
    const originalRead = fs.readSync;
    let swapped = false;
    fs.readSync = function swapAfterValidatedRead(descriptor, ...rest) {
      const inode = fs.fstatSync(descriptor).ino;
      const read = originalRead.call(fs, descriptor, ...rest);
      if (!swapped && inode === candidateInode && read > 0) {
        fs.renameSync(candidate, moved);
        fs.writeFileSync(candidate, 'unvalidated replacement\n', { mode: 0o600 });
        swapped = true;
      }
      return read;
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
        /identity changed/,
      );
    } finally {
      fs.readSync = originalRead;
    }
    assert.equal(swapped, true);
    assert.equal(fs.readFileSync(candidate, 'utf8'), 'unvalidated replacement\n');
    if (finalExists) {
      assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('11'));
    } else {
      assert.equal(fs.existsSync(fixture.privatePath), false);
    }
  }
});

test('initializer cleanup leaves a replacement of its own validated temp name untouched', (t) => {
  const fixture = authority(t, 'wallet-kernel-own-cleanup-');
  const random = Buffer.from('09'.repeat(16), 'hex');
  const name = `.${path.basename(fixture.privatePath)}.tmp-${process.pid}-${random.toString('hex')}`;
  const candidate = path.join(fixture.directory, name);
  const moved = `${candidate}.published-inode`;
  let swapped = false;
  assert.throws(
    () => loadOrInitializePrivateFile({
      filePath: fixture.privatePath,
      label: 'Receipt key',
      createBytes: () => Buffer.from(secret('99')),
      validateBytes: validatePrivateValue,
      randomBytes: () => random,
      faultInjector: (point) => {
        if (point === 'after_private_directory_fsync') {
          fs.renameSync(candidate, moved);
          fs.writeFileSync(candidate, 'replacement cleanup target\n', { mode: 0o600 });
          swapped = true;
        }
      },
      pathTrust: fixture.pathTrust,
    }),
    /identity changed/,
  );
  assert.equal(swapped, true);
  assert.equal(fs.readFileSync(fixture.privatePath, 'utf8'), secret('99'));
  assert.equal(fs.readFileSync(candidate, 'utf8'), 'replacement cleanup target\n');
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
  const candidateStat = fs.statSync(candidate, { bigint: true });
  const originalFstat = fs.fstatSync;
  fs.fstatSync = function injectWrongOwner(descriptor, options) {
    const stat = originalFstat.call(fs, descriptor, options);
    if (options?.bigint === true && stat.isFile() && stat.ino === candidateStat.ino) {
      return new Proxy(stat, {
        get(target, property, receiver) {
          if (property === 'uid') return target.uid + 1n;
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

test('in-memory authority requires explicit injection and exposes test SQL only there', (t) => {
  assert.throws(
    () => openKernelStore({ filePath: ':memory:' }),
    /explicit test injection/,
  );
  const memory = memoryStore();
  assert.equal(typeof memory.execForTest, 'function');
  memory.close();

  const fixture = authority(t, 'wallet-kernel-store-surface-');
  const persistent = openKernelStore({
    filePath: fixture.databasePath,
    allowMemory: true,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(persistent.execForTest, undefined);
  assert.equal(persistent.rawForModules, undefined);
  assert.equal(persistent.appendEvent, undefined);
  assert.equal(Object.isFrozen(persistent), true);
  persistent.close();
});

test('persistent store enables WAL, FULL sync, foreign keys, and schema v1', (t) => {
  const fixture = authority(t, 'wallet-kernel-store-pragmas-');
  const store = openKernelStore({
    filePath: fixture.databasePath,
    pathTrust: fixture.pathTrust,
  });
  assert.equal(store.pragma('journal_mode'), 'wal');
  assert.equal(store.pragma('synchronous'), 2);
  assert.equal(store.pragma('foreign_keys'), 1);
  assert.equal(store.pragma('user_version'), 1);
  assert.equal(store.integrityCheck(), 'ok');
  assert.throws(() => store.pragma('trusted_schema'), /not exposed/);
  store.close();
  for (const suffix of ['', '-wal', '-shm']) {
    const target = `${fixture.databasePath}${suffix}`;
    if (fs.existsSync(target)) assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  }
});

test('persistent store rejects checkout, symlink, permissive, and wrong-owner-like paths', (t) => {
  const fixture = authority(t, 'wallet-kernel-store-paths-');
  assert.throws(() => openKernelStore({
    filePath: path.join(REPOSITORY_ROOT, 'spikes/pi-wielder/kernel.sqlite'),
    pathTrust: fixture.pathTrust,
  }), /outside the checkout/);

  const target = path.join(fixture.directory, 'target.sqlite');
  fs.writeFileSync(target, '', { mode: 0o600 });
  fs.symlinkSync(target, fixture.databasePath);
  assert.throws(
    () => openKernelStore({ filePath: fixture.databasePath, pathTrust: fixture.pathTrust }),
    /symlink|ELOOP/,
  );
  fs.unlinkSync(fixture.databasePath);
  fs.chmodSync(fixture.directory, 0o755);
  assert.throws(
    () => openKernelStore({ filePath: fixture.databasePath, pathTrust: fixture.pathTrust }),
    /owner-only/,
  );

  const ownerFixture = authority(t, 'wallet-kernel-store-owner-');
  fs.writeFileSync(ownerFixture.databasePath, '', { mode: 0o600 });
  const databaseStat = fs.statSync(ownerFixture.databasePath, { bigint: true });
  const originalFstat = fs.fstatSync;
  fs.fstatSync = function injectWrongOwner(descriptor, options) {
    const stat = originalFstat.call(fs, descriptor, options);
    if (stat.isFile() && BigInt(stat.ino) === databaseStat.ino) {
      return new Proxy(stat, {
        get(targetStat, property, receiver) {
          if (property === 'uid') {
            return typeof targetStat.uid === 'bigint' ? targetStat.uid + 1n : targetStat.uid + 1;
          }
          return Reflect.get(targetStat, property, receiver);
        },
      });
    }
    return stat;
  };
  try {
    assert.throws(
      () => openKernelStore({
        filePath: ownerFixture.databasePath,
        pathTrust: ownerFixture.pathTrust,
      }),
      /owned by the current user/,
    );
  } finally {
    fs.fstatSync = originalFstat;
  }
});

test('persistent store rejects insecure pre-existing SQLite sidecars', (t) => {
  for (const suffix of ['-wal', '-shm']) {
    const permissive = authority(t, `wallet-kernel-store-sidecar-${suffix.slice(1)}-`);
    fs.writeFileSync(`${permissive.databasePath}${suffix}`, '', { mode: 0o644 });
    assert.throws(
      () => openKernelStore({
        filePath: permissive.databasePath,
        pathTrust: permissive.pathTrust,
      }),
      /owner-only/,
    );

    const symlinked = authority(t, `wallet-kernel-store-sidecar-link-${suffix.slice(1)}-`);
    fs.symlinkSync(path.join(symlinked.directory, 'missing'), `${symlinked.databasePath}${suffix}`);
    assert.throws(
      () => openKernelStore({
        filePath: symlinked.databasePath,
        pathTrust: symlinked.pathTrust,
      }),
      /symlink|ELOOP/,
    );
  }
});

test('domain mutation and event append commit or roll back together', () => {
  const store = memoryStore();
  try {
    store.mutate({
      entityType: 'test', entityId: 'one', eventType: 'test.created', data: { value: 1 },
    }, ({ db }) => db.prepare(
      'INSERT INTO metadata(key, value) VALUES (?, ?)',
    ).run('sample', 'one'));
    assert.equal(store.events().length, 1);
    assert.equal(store.verifyEventChain(), true);

    assert.throws(() => store.mutate({
      entityType: 'test', entityId: 'two', eventType: 'test.failed', data: { value: 2 },
    }, ({ db }) => {
      db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('rolled-back', 'yes');
      throw new Error('fault');
    }), /fault/);
    assert.equal(store.events().length, 1);
    assert.equal(store.getMetadata('sample'), 'one');
    assert.equal(store.getMetadata('rolled-back'), null);
  } finally {
    store.close();
  }
});

test('transaction tokens are live, synchronous, unforgeable, and non-nestable', () => {
  const store = memoryStore();
  let stale;
  try {
    assert.equal(store.transaction((token) => store.within(token, ({ db }) => {
      stale = token;
      db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('valid', 'yes');
      return 'committed';
    })), 'committed');
    assert.equal(store.getMetadata('valid'), 'yes');
    assert.throws(() => store.within(stale, () => undefined), /invalid authority transaction/);
    assert.throws(
      () => store.within(Object.freeze(Object.create(null)), () => undefined),
      /invalid authority transaction/,
    );

    assert.throws(() => store.transaction((token) => {
      store.within(token, ({ db }) => {
        db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('nested', 'no');
      });
      return store.transaction(() => 'forbidden');
    }), /nested authority transaction/);
    assert.equal(store.getMetadata('nested'), null);

    assert.throws(() => store.transaction((token) => {
      store.within(token, ({ db }) => {
        db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('async', 'no');
      });
      return Promise.resolve('forbidden');
    }), /must be synchronous/);
    assert.equal(store.getMetadata('async'), null);

    assert.throws(() => store.transaction((token) => {
      store.within(token, ({ db }) => {
        db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('wrapper', 'no');
      });
      return store.mutate({
        entityType: 'test', entityId: 'nested', eventType: 'test.nested', data: {},
      }, () => undefined);
    }), /nested authority transaction/);
    assert.equal(store.getMetadata('wrapper'), null);
    assert.equal(store.events().length, 0);

    assert.throws(() => store.transaction((token) => token), /transaction token.*return/);

    assert.throws(() => store.transaction((token) => ({ nested: [token] })),
      /transaction token.*return/);
    assert.throws(() => store.transaction((token) => ({ [Symbol('hidden')]: token })),
      /transaction token.*return/);

    assert.throws(() => store.transaction((token) => {
      store.within(token, async ({ db }) => {
        db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('awaited', 'no');
      });
      return undefined;
    }), /must be synchronous/);
    assert.equal(store.getMetadata('awaited'), null);

    for (const operation of [
      function* generatorBoundary({ db }) { yield db; },
      async function* asyncGeneratorBoundary({ db }) { yield db; },
    ]) {
      assert.throws(() => store.transaction((token) => {
        store.within(token, operation);
        return undefined;
      }), /ordinary synchronous functions/);
    }
  } finally {
    store.close();
  }
});

test('read boundary is one parameterized SELECT and persistent writes require a live token', (t) => {
  const fixture = authority(t, 'wallet-kernel-store-reads-');
  const store = openKernelStore({ filePath: fixture.databasePath, pathTrust: fixture.pathTrust });
  try {
    store.transaction((token) => store.within(token, ({ db }) => {
      db.prepare('INSERT INTO metadata(key, value) VALUES (?, ?)').run('sample', 'one');
    }));
    assert.deepEqual({ ...store.readOne(
      'SELECT value FROM metadata WHERE key = ?', ['sample'],
    ) }, { value: 'one' });
    assert.deepEqual(store.readAll(
      'SELECT value FROM metadata WHERE key = ?', ['missing'],
    ), []);
    for (const sql of [
      'INSERT INTO metadata(key, value) VALUES (?, ?)',
      'PRAGMA user_version',
      'SELECT 1; SELECT 2',
      'WITH row(value) AS (SELECT 1) SELECT value FROM row',
    ]) {
      assert.throws(() => store.readAll(sql), /only one parameterized SELECT/);
    }
    assert.equal(store.execForTest, undefined);
    assert.throws(
      () => store.within(Object.freeze(Object.create(null)), () => undefined),
      /invalid authority transaction/,
    );
  } finally {
    store.close();
  }
});

test('event verification detects row tampering', () => {
  const store = memoryStore();
  try {
    store.mutate({
      entityType: 'test', entityId: 'one', eventType: 'test.created', data: { value: 1 },
    }, ({ db }) => db.prepare(
      'INSERT INTO metadata(key, value) VALUES (?, ?)',
    ).run('sample', 'one'));
    assert.equal(store.verifyEventChain(), true);
    store.execForTest("UPDATE events SET data_json = '{\"value\":2}' WHERE sequence = 1");
    assert.equal(store.verifyEventChain(), false);
  } finally {
    store.close();
  }
});

test('event append validates one closed data-only envelope without invoking accessors', () => {
  const store = memoryStore();
  let getterCalls = 0;
  const event = {
    entityId: 'one',
    eventType: 'test.created',
    data: { value: 1 },
  };
  Object.defineProperty(event, 'entityType', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'test';
    },
  });
  try {
    assert.throws(() => store.mutate(event, ({ db }) => db.prepare(
      'INSERT INTO metadata(key, value) VALUES (?, ?)',
    ).run('accessor', 'no')), /closed schema/);
    assert.equal(getterCalls, 0);
    assert.equal(store.getMetadata('accessor'), null);
    assert.equal(store.events().length, 0);
  } finally {
    store.close();
  }
});

test('a newer schema and initialization faults close the database without masking the error', (t) => {
  const fixture = authority(t, 'wallet-kernel-store-newer-');
  const first = openKernelStore({ filePath: fixture.databasePath, pathTrust: fixture.pathTrust });
  first.close();
  const raw = new DatabaseSync(fixture.databasePath);
  raw.exec('PRAGMA user_version = 99');
  raw.close();
  assert.throws(
    () => openKernelStore({ filePath: fixture.databasePath, pathTrust: fixture.pathTrust }),
    /newer schema/,
  );
  const reusable = new DatabaseSync(fixture.databasePath, { timeout: 0 });
  reusable.exec('BEGIN EXCLUSIVE; ROLLBACK');
  reusable.close();

  const sentinel = new Error('injected initialization fault');
  const originalPrepare = DatabaseSync.prototype.prepare;
  const originalClose = DatabaseSync.prototype.close;
  let closeCalls = 0;
  DatabaseSync.prototype.prepare = function injectPrepare(sql) {
    if (sql === 'PRAGMA user_version') throw sentinel;
    return originalPrepare.call(this, sql);
  };
  DatabaseSync.prototype.close = function countClose() {
    closeCalls += 1;
    return originalClose.call(this);
  };
  try {
    assert.throws(
      () => openKernelStore({ filePath: ':memory:', allowMemory: true }),
      (error) => error === sentinel,
    );
    assert.equal(closeCalls, 1);
  } finally {
    DatabaseSync.prototype.prepare = originalPrepare;
    DatabaseSync.prototype.close = originalClose;
  }
});

const enumCases = [
  {
    name: 'spend_sessions.state',
    valid: ['open', 'policy_blocked', 'closed'],
    insert: (value) => `INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES ('session-extra', 'adapter-extra', 'wallet-extra', 'policy-1',
       ${sqlText(value)}, '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'agent_enrollments.state',
    valid: ['active', 'revoked'],
    insert: (value) => `DELETE FROM spend_intents; DELETE FROM spend_sessions;
      DELETE FROM agent_enrollments;
      INSERT INTO agent_enrollments
      (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid, state,
       enrolled_by_operator_hash, enrolled_at, revoked_by_operator_hash, revoked_at)
      VALUES ('agent-extra', 'credential-extra', 'enrollment-extra', '1000', '1000',
       ${sqlText(value)}, 'operator-1', '2026-08-01T00:00:00.000Z',
       ${value === 'revoked' ? "'operator-2'" : 'NULL'},
       ${value === 'revoked' ? "'2026-08-01T01:00:00.000Z'" : 'NULL'})`,
  },
  {
    name: 'isolation_attestations.state',
    valid: ['current', 'superseded'],
    insert: (value) => `INSERT INTO isolation_attestations
      (id, report_hash, enrollment_hash, report_json, state, imported_by_operator_hash,
       probed_at, expires_at, imported_at, superseded_at)
      VALUES ('attestation-1', 'report-1', 'enrollment-1', '{}', ${sqlText(value)},
       'operator-1', '2026-08-01T00:00:00.000Z', '2026-08-02T00:00:00.000Z',
       '2026-08-01T00:00:00.000Z',
       ${value === 'superseded' ? "'2026-08-01T01:00:00.000Z'" : 'NULL'})`,
  },
  {
    name: 'agent_session_bindings.state',
    valid: ['open', 'closed'],
    insert: (value) => `INSERT INTO agent_session_bindings
      (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
       state, created_at, last_seen_at)
      VALUES ('binding-1', 'agent-1', 'credential-1', 'enrollment-1', 'session-1',
       ${sqlText(value)}, '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'spend_intents.state',
    valid: [
      'captured', 'challenged', 'approval_pending', 'authorized', 'reserved', 'signing',
      'signed', 'retrying', 'unresolved', 'terminal',
    ],
    insert: (value) => `UPDATE spend_intents SET state = ${sqlText(value)} WHERE id = 'intent-1'`,
  },
  {
    name: 'policy_decisions.decision',
    valid: ['allow', 'approval_required', 'deny'],
    insert: (value) => `INSERT INTO policy_decisions
      (intent_id, policy_version_id, decision, reason_code, challenge_hash,
       amount_ceiling_atomic, decided_at)
      VALUES ('intent-1', 'policy-1', ${sqlText(value)}, 'reason-1', 'challenge-1', '0',
       '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'budget_reservations.state',
    valid: ['reserved', 'committed', 'released', 'unresolved'],
    insert: (value) => `INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, updated_at)
      VALUES ('intent-1', 'session-1', 'https://seller.example', '1', '0', '0', '0',
       ${sqlText(value)}, '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'approvals.decision',
    valid: ['pending', 'approved', 'denied', 'expired', 'cancelled', 'consumed'],
    insert: (value) => `INSERT INTO approvals
      (id, intent_id, decision, intent_hash, challenge_hash, quote_id, accepted_index,
       amount_ceiling_atomic, wallet_address, policy_version_id, expires_at)
      VALUES ('approval-1', 'intent-1', ${sqlText(value)}, 'intent-hash-1', 'challenge-1',
       'quote-1', 0, '0', '0xwallet', 'policy-1', '2026-08-02T00:00:00.000Z')`,
  },
  {
    name: 'payment_attempts.state',
    valid: ['reserved', 'signing', 'signed', 'retrying', 'unresolved', 'settled', 'rejected'],
    insert: (value) => `INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index, quote_id,
       created_at, updated_at)
      VALUES ('payment-1', 'intent-1', ${sqlText(value)}, '{}', 0, 'quote-1',
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'payment_reconciliation_candidates.state',
    valid: ['pending', 'abandoned', 'rejected', 'confirmed'],
    insert: (value) => `INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index, quote_id,
       created_at, updated_at)
      VALUES ('payment-1', 'intent-1', 'unresolved', '{}', 0, 'quote-1',
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z');
      INSERT INTO payment_reconciliation_candidates
      (id, intent_id, transaction_id, state, created_at, updated_at)
      VALUES ('candidate-1', 'intent-1', 'transaction-1', ${sqlText(value)},
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'execution_outcomes.state',
    valid: ['succeeded', 'failed', 'unknown'],
    insert: (value) => `INSERT INTO execution_outcomes
      (intent_id, state, metadata_json, recorded_at)
      VALUES ('intent-1', ${sqlText(value)}, '{}', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'execution_resolutions.state',
    valid: ['refund_pending', 'reconciliation_required', 'resolved'],
    insert: (value) => `INSERT INTO execution_outcomes
      (intent_id, state, metadata_json, recorded_at)
      VALUES ('intent-1', 'unknown', '{}', '2026-08-01T00:00:00.000Z');
      INSERT INTO execution_resolutions
      (intent_id, state, reason_code, blocks_wallet, opened_at, resolved_at)
      VALUES ('intent-1', ${sqlText(value)}, 'reason-1',
       ${value === 'resolved' ? 0 : 1}, '2026-08-01T00:00:00.000Z',
       ${value === 'resolved' ? "'2026-08-01T01:00:00.000Z'" : 'NULL'})`,
  },
  {
    name: 'refunds.state',
    valid: ['pending', 'unresolved', 'abandoned', 'confirmed', 'rejected'],
    insert: (value) => `INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state, created_at, updated_at)
      VALUES ('refund-1', 'intent-1', 'transaction-1', '0', ${sqlText(value)},
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'reconciliations.kind',
    valid: ['payment', 'execution', 'refund'],
    insert: (value) => `INSERT INTO reconciliations
      (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
      VALUES ('reconciliation-1', 'intent-1', ${sqlText(value)}, 'unresolved', '{}',
       'operator-1', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'reconciliations.outcome',
    valid: [
      'settled', 'rejected', 'execution_succeeded', 'execution_failed',
      'execution_unknown', 'refund_confirmed', 'refund_rejected', 'unresolved',
    ],
    insert: (value) => `INSERT INTO reconciliations
      (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
      VALUES ('reconciliation-1', 'intent-1', 'payment', ${sqlText(value)}, '{}',
       'operator-1', '2026-08-01T00:00:00.000Z')`,
  },
  {
    name: 'buyer_outcomes.status',
    valid: [
      'completed', 'upstream_failed', 'payment_denied', 'payment_failed',
      'payment_unresolved', 'payment_rejected', 'execution_failed',
      'execution_unknown', 'refunded',
    ],
    insert: (value) => `INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES ('intent-1', ${sqlText(value)}, 'reason-1', 1,
       '2026-08-01T00:00:00.000Z')`,
  },
];

for (const enumCase of enumCases) {
  test(`${enumCase.name} accepts every declared value and rejects undeclared values`, () => {
    for (const value of enumCase.valid) assertAccepted(enumCase.insert(value));
    assertRejected(enumCase.insert('not-declared'));
  });
}

test('canonical atomic columns reject negatives, leading zeroes, non-digits, and empty text', () => {
  const invalid = ['-1', '01', '1x', ''];
  const cases = [
    (value) => `INSERT INTO policy_decisions
      (intent_id, policy_version_id, decision, reason_code, challenge_hash,
       amount_ceiling_atomic, decided_at)
      VALUES ('intent-1', 'policy-1', 'allow', 'reason-1', 'challenge-1',
       ${sqlText(value)}, '2026-08-01T00:00:00.000Z')`,
    (value) => `INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, updated_at)
      VALUES ('intent-1', 'session-1', 'https://seller.example', ${sqlText(value)},
       '0', '0', '0', 'reserved', '2026-08-01T00:00:00.000Z')`,
    (value) => `INSERT INTO approvals
      (id, intent_id, decision, intent_hash, challenge_hash, quote_id, accepted_index,
       amount_ceiling_atomic, wallet_address, policy_version_id, expires_at)
      VALUES ('approval-1', 'intent-1', 'pending', 'intent-hash-1', 'challenge-1',
       'quote-1', 0, ${sqlText(value)}, '0xwallet', 'policy-1',
       '2026-08-02T00:00:00.000Z')`,
    (value) => `INSERT INTO refunds
      (id, intent_id, original_transaction_id, amount_atomic, state, created_at, updated_at)
      VALUES ('refund-1', 'intent-1', 'transaction-1', ${sqlText(value)}, 'pending',
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  ];
  for (const makeSql of cases) {
    for (const value of ['0', '1']) assertAccepted(makeSql(value));
    for (const value of invalid) assertRejected(makeSql(value));
  }

  for (const column of ['committed_atomic', 'released_atomic', 'unresolved_atomic']) {
    for (const value of invalid) {
      assertRejected(`INSERT INTO budget_reservations
        (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
         released_atomic, unresolved_atomic, state, updated_at)
        VALUES ('intent-1', 'session-1', 'https://seller.example', '0',
         ${column === 'committed_atomic' ? sqlText(value) : "'0'"},
         ${column === 'released_atomic' ? sqlText(value) : "'0'"},
         ${column === 'unresolved_atomic' ? sqlText(value) : "'0'"},
         'reserved', '2026-08-01T00:00:00.000Z')`);
    }
  }
});

test('UID, validity-window, index, HTTP, and revision boundaries are enforced', () => {
  for (const column of ['agent_uid', 'agent_gid']) {
    for (const value of ['-1', '0', '01', '1x', '']) {
      assertRejected(`DELETE FROM spend_intents; DELETE FROM spend_sessions;
        DELETE FROM agent_enrollments;
        INSERT INTO agent_enrollments
        (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
         state, enrolled_by_operator_hash, enrolled_at)
        VALUES ('agent-extra', 'credential-extra', 'enrollment-extra',
         ${column === 'agent_uid' ? sqlText(value) : "'1000'"},
         ${column === 'agent_gid' ? sqlText(value) : "'1000'"},
         'active', 'operator-1', '2026-08-01T00:00:00.000Z')`);
    }
  }

  for (const column of ['valid_after', 'valid_before']) {
    for (const value of ['0', '1']) {
      assertAccepted(`INSERT INTO payment_attempts
        (id, intent_id, state, payment_required_projection_json, accepted_index,
         quote_id, ${column}, created_at, updated_at)
        VALUES ('payment-1', 'intent-1', 'reserved', '{}', 0, 'quote-1',
         ${sqlText(value)}, '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`);
    }
    for (const value of ['-1', '01', '1x', '']) {
      assertRejected(`INSERT INTO payment_attempts
        (id, intent_id, state, payment_required_projection_json, accepted_index,
         quote_id, ${column}, created_at, updated_at)
        VALUES ('payment-1', 'intent-1', 'reserved', '{}', 0, 'quote-1',
         ${sqlText(value)}, '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`);
    }
  }

  const acceptedIndexStatements = [
    `INSERT INTO policy_decisions
      (intent_id, policy_version_id, decision, reason_code, challenge_hash,
       accepted_index, quote_id, amount_ceiling_atomic, decided_at)
      VALUES ('intent-1', 'policy-1', 'allow', 'reason-1', 'challenge-1', -1,
       'quote-1', '0', '2026-08-01T00:00:00.000Z')`,
    `INSERT INTO approvals
      (id, intent_id, decision, intent_hash, challenge_hash, quote_id, accepted_index,
       amount_ceiling_atomic, wallet_address, policy_version_id, expires_at)
      VALUES ('approval-1', 'intent-1', 'pending', 'intent-hash-1', 'challenge-1',
       'quote-1', -1, '0', '0xwallet', 'policy-1', '2026-08-02T00:00:00.000Z')`,
    `INSERT INTO payment_attempts
      (id, intent_id, state, payment_required_projection_json, accepted_index, quote_id,
       created_at, updated_at)
      VALUES ('payment-1', 'intent-1', 'reserved', '{}', -1, 'quote-1',
       '2026-08-01T00:00:00.000Z', '2026-08-01T00:00:00.000Z')`,
  ];
  for (const sql of acceptedIndexStatements) assertRejected(sql);

  for (const status of [100, 599]) {
    assertAccepted(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, metadata_json, recorded_at)
      VALUES ('intent-1', 'succeeded', ${status}, '{}', '2026-08-01T00:00:00.000Z')`);
  }
  for (const status of [99, 600]) {
    assertRejected(`INSERT INTO execution_outcomes
      (intent_id, state, http_status, metadata_json, recorded_at)
      VALUES ('intent-1', 'succeeded', ${status}, '{}', '2026-08-01T00:00:00.000Z')`);
  }

  for (const revision of [0, -1]) {
    assertRejected(`INSERT INTO signed_receipts
      (id, intent_id, revision, receipt_json, receipt_hash, signature, algorithm,
       key_id, created_at)
      VALUES ('receipt-1', 'intent-1', ${revision}, '{}', 'receipt-hash-1',
       'signature-1', 'Ed25519', 'key-1', '2026-08-01T00:00:00.000Z')`);
    assertRejected(`INSERT INTO buyer_outcomes
      (intent_id, status, reason_code, revision, recorded_at)
      VALUES ('intent-1', 'completed', 'reason-1', ${revision},
       '2026-08-01T00:00:00.000Z')`);
  }
  assertAccepted(`INSERT INTO signed_receipts
    (id, intent_id, revision, receipt_json, receipt_hash, signature, algorithm,
     key_id, created_at)
    VALUES ('receipt-1', 'intent-1', 1, '{}', 'receipt-hash-1',
     'signature-1', 'Ed25519', 'key-1', '2026-08-01T00:00:00.000Z')`);
  assertRejected(`INSERT INTO signed_receipts
    (id, intent_id, revision, receipt_json, receipt_hash, signature, algorithm,
     key_id, created_at)
    VALUES ('receipt-1', 'intent-1', 1, '{}', 'receipt-hash-1',
     'signature-1', 'RSA', 'key-1', '2026-08-01T00:00:00.000Z')`);
});

test('boolean and paired-index CHECK boundaries accept only their declared forms', () => {
  for (const value of [0, 1]) {
    assertAccepted(`UPDATE spend_intents SET retry_matchable = ${value}
      WHERE id = 'intent-1'`);
  }
  for (const value of [-1, 2]) {
    assertRejected(`UPDATE spend_intents SET retry_matchable = ${value}
      WHERE id = 'intent-1'`);
  }

  assertAccepted(`INSERT INTO policy_decisions
    (intent_id, policy_version_id, decision, reason_code, challenge_hash,
     accepted_index, quote_id, amount_ceiling_atomic, decided_at)
    VALUES ('intent-1', 'policy-1', 'allow', 'reason-1', 'challenge-1', 0,
     'quote-1', '0', '2026-08-01T00:00:00.000Z')`);
  assertRejected(`INSERT INTO policy_decisions
    (intent_id, policy_version_id, decision, reason_code, challenge_hash,
     accepted_index, amount_ceiling_atomic, decided_at)
    VALUES ('intent-1', 'policy-1', 'allow', 'reason-1', 'challenge-1', 0,
     '0', '2026-08-01T00:00:00.000Z')`);

  assertRejected(`INSERT INTO execution_outcomes
    (intent_id, state, metadata_json, recorded_at)
    VALUES ('intent-1', 'unknown', '{}', '2026-08-01T00:00:00.000Z');
    INSERT INTO execution_resolutions
    (intent_id, state, reason_code, blocks_wallet, opened_at)
    VALUES ('intent-1', 'refund_pending', 'reason-1', 2,
     '2026-08-01T00:00:00.000Z')`);
});

test('two processes serialize one conditional claim and one hash-chain event', async (t) => {
  const fixtureAuthority = authority(t, 'wallet-kernel-store-writers-');
  const initial = openKernelStore({
    filePath: fixtureAuthority.databasePath,
    pathTrust: fixtureAuthority.pathTrust,
  });
  initial.close();
  const fixture = fileURLToPath(new URL('./fixtures/kernel-db-writer.mjs', import.meta.url));
  const children = ['a', 'b'].map((claimId) => spawn(
    process.execPath,
    [fixture, fixtureAuthority.databasePath, fixtureAuthority.directory, claimId],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  ));
  assert.deepEqual(
    (await Promise.all(children.map(childResult))).sort(),
    ['already_claimed', 'claimed'],
  );
  const reopened = openKernelStore({
    filePath: fixtureAuthority.databasePath,
    pathTrust: fixtureAuthority.pathTrust,
  });
  assert.equal(reopened.verifyEventChain(), true);
  assert.equal(
    reopened.events().filter((event) => event.event_type === 'test.claimed').length,
    1,
  );
  reopened.close();
});

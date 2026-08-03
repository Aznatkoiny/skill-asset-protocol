import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import { acquireAuthorityLock } from '../src/kernel/authority-lock.mjs';
import { createIntentRepository } from '../src/kernel/intent-builder.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';
import { runOfflineBootstrap } from '../src/offline-bootstrap.mjs';
import { runOperatorCli } from '../src/operator/cli.mjs';

const TOKEN = Buffer.alloc(32, 0x41).toString('base64url');
const BASE_POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-offline-'));
  fs.chmodSync(root, 0o700);
  const authority = path.join(root, 'authority');
  const inputs = path.join(root, 'inputs');
  const enrollmentInbox = path.join(root, 'enrollment-inbox');
  fs.mkdirSync(authority, { mode: 0o700 });
  fs.mkdirSync(inputs, { mode: 0o700 });
  fs.mkdirSync(enrollmentInbox, { mode: 0o755 });
  fs.chmodSync(authority, 0o700);
  fs.chmodSync(inputs, 0o700);
  fs.chmodSync(enrollmentInbox, 0o755);
  const databasePath = path.join(authority, 'kernel.sqlite');
  const receiptKeyPath = path.join(authority, 'receipt-key.pem');
  const operatorTokenPath = path.join(authority, 'operator.token');
  fs.writeFileSync(operatorTokenPath, TOKEN, { flag: 'wx', mode: 0o600 });
  fs.chmodSync(operatorTokenPath, 0o600);
  const config = Object.freeze({
    mode: 'deterministic',
    databasePath,
    receiptKeyPath,
    operatorTokenPath,
    operatorSocketPath: null,
    origin: 'http://127.0.0.1:8405',
    trustedAncestor: root,
    enrollmentInboxPath: enrollmentInbox,
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
    kernelUid: process.getuid(),
    kernelGid: process.getgid(),
  });
  const env = Object.freeze({
    WALLET_KERNEL_MODE: 'deterministic',
    WALLET_KERNEL_DB_FILE: databasePath,
    WALLET_KERNEL_RECEIPT_KEY_FILE: receiptKeyPath,
    WALLET_KERNEL_OPERATOR_TOKEN_FILE: operatorTokenPath,
    WALLET_KERNEL_TRUSTED_ANCESTOR: root,
    WALLET_KERNEL_EXPECTED_AGENT_UID: String(process.getuid()),
    WALLET_KERNEL_EXPECTED_AGENT_GID: String(process.getgid()),
    WALLET_KERNEL_ENROLLMENT_INBOX: enrollmentInbox,
    WALLET_KERNEL_OPERATOR_PORT: '8405',
  });
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return Object.freeze({
    root,
    authority,
    inputs,
    enrollmentInbox,
    databasePath,
    receiptKeyPath,
    operatorTokenPath,
    config,
    env,
  });
}

function writeJson(directory, name, value, { mode = 0o600, canonicalLine = false } = {}) {
  const filePath = path.join(directory, name);
  const bytes = canonicalLine ? `${canonicalJson(value)}\n` : JSON.stringify(value, null, 2);
  fs.writeFileSync(filePath, bytes, { flag: 'wx', mode });
  fs.chmodSync(filePath, mode);
  return filePath;
}

function policyFile(value, policy = BASE_POLICY, name = 'policy.json') {
  const filePath = writeJson(value.inputs, name, policy);
  return Object.freeze({ filePath, hash: sha256(canonicalJson(policy)) });
}

function descriptorForCurrentIdentity() {
  return Object.freeze({
    schemaVersion: 1,
    agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
    credentialDigest: `sha256:${'ab'.repeat(32)}`,
    agentUid: String(process.getuid()),
    agentGid: String(process.getgid()),
  });
}

function capture() {
  let value = '';
  return Object.freeze({
    stream: Object.freeze({ write(chunk) { value += String(chunk); return true; } }),
    read() { return value; },
  });
}

function query(databasePath, sql, ...parameters) {
  const database = new DatabaseSync(databasePath, { readBigInts: true });
  try {
    return database.prepare(sql).all(...parameters);
  } finally {
    database.close();
  }
}

test('bootstrap entrypoint accepts only the exact closed command and configuration schemas', async (t) => {
  const value = fixture(t);
  await assert.rejects(
    runOfflineBootstrap({
      command: { name: 'preflight', extra: true },
      config: value.config,
      operatorToken: TOKEN,
    }),
    (error) => error.code === 'BOOTSTRAP_COMMAND_SCHEMA',
  );
  await assert.rejects(
    runOfflineBootstrap({
      command: { name: 'preflight' },
      config: { ...value.config, surprise: true },
      operatorToken: TOKEN,
    }),
    (error) => error.code === 'BOOTSTRAP_CONFIG_SCHEMA',
  );
  await assert.rejects(
    runOfflineBootstrap({
      command: { name: 'preflight' },
      config: value.config,
      operatorToken: `${TOKEN}\n`,
    }),
    (error) => error.code === 'OPERATOR_TOKEN_INVALID',
  );
  await assert.rejects(
    runOfflineBootstrap({
      command: { name: 'preflight' },
      config: value.config,
      operatorToken: Buffer.alloc(32, 0x42).toString('base64url'),
    }),
    (error) => error.code === 'OPERATOR_TOKEN_INVALID',
  );
  let trapped = false;
  const command = new Proxy({ name: 'preflight' }, {
    getOwnPropertyDescriptor() {
      trapped = true;
      throw new Error(`must stay inert ${TOKEN}`);
    },
  });
  await assert.rejects(
    runOfflineBootstrap({ command, config: value.config, operatorToken: TOKEN }),
    (error) => error.code === 'BOOTSTRAP_SCHEMA',
  );
  assert.equal(trapped, false);
  assert.equal(fs.existsSync(value.databasePath), false);
  assert.equal(fs.existsSync(value.receiptKeyPath), false);
});

test('policy validation is bounded, offline, lock-owning, and does not open authority SQLite', async (t) => {
  const value = fixture(t);
  const policy = policyFile(value);
  const result = await runOfflineBootstrap({
    command: { name: 'policy-validate', policyPath: policy.filePath },
    config: value.config,
    operatorToken: TOKEN,
  });
  assert.deepEqual(result, Object.freeze({
    policy: structuredClone(BASE_POLICY),
    policyHash: policy.hash,
  }));
  assert.equal(fs.existsSync(value.databasePath), false);
  assert.equal(fs.existsSync(value.receiptKeyPath), false);
  assert.equal(fs.existsSync(`${value.databasePath}.authority-lock.sqlite`), true);
});

test('direct CLI uses the real offline bootstrap for policy apply and preflight', async (t) => {
  const value = fixture(t);
  const policy = policyFile(value);
  for (const argv of [
    ['policy', 'apply', policy.filePath, '--confirm', policy.hash],
    ['preflight'],
  ]) {
    const stdout = capture();
    const stderr = capture();
    const exitCode = await runOperatorCli({
      argv,
      env: value.env,
      requestImpl: async () => { throw new Error('offline bootstrap must not use HTTP'); },
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    assert.equal(exitCode, 0, `${argv.join(' ')}: ${stderr.read()}`);
    assert.equal(stderr.read(), '');
    assert.doesNotMatch(stdout.read(), /OFFLINE_BOOTSTRAP_UNAVAILABLE/);
    assert.equal(stdout.read().includes(TOKEN), false);
  }
  assert.equal(query(value.databasePath, 'SELECT id FROM policy_versions').length, 1);
  assert.equal(fs.readFileSync(value.databasePath).includes(Buffer.from(TOKEN)), false);
});

test('agent enrollment single-FD reads one canonical public descriptor and persists no raw token', async (t) => {
  const value = fixture(t);
  const descriptor = descriptorForCurrentIdentity();
  const descriptorPath = writeJson(
    value.enrollmentInbox,
    'agent-enrollment.json',
    descriptor,
    { mode: 0o644, canonicalLine: true },
  );
  const expectedDescriptorHash = sha256(canonicalJson(descriptor));
  const result = await runOfflineBootstrap({
    command: { name: 'agent-enroll', descriptorPath, expectedDescriptorHash },
    config: value.config,
    operatorToken: TOKEN,
  });
  assert.deepEqual(Object.keys(result), [
    'agentInstanceId', 'credentialDigest', 'enrollmentHash', 'agentUid', 'agentGid',
    'state', 'isolation', 'enrolledAt',
  ]);
  assert.equal(result.enrollmentHash, expectedDescriptorHash);
  assert.equal(result.state, 'active');
  assert.equal(result.isolation, 'simulated');
  const rows = query(value.databasePath, 'SELECT * FROM agent_enrollments');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].enrollment_hash, expectedDescriptorHash);
  assert.equal(fs.readFileSync(value.databasePath).includes(Buffer.from(TOKEN)), false);
});

test('direct CLI performs offline agent enrollment without an HTTP or listener dependency', async (t) => {
  const value = fixture(t);
  const descriptor = descriptorForCurrentIdentity();
  const descriptorPath = writeJson(
    value.enrollmentInbox,
    'agent-enrollment.json',
    descriptor,
    { mode: 0o644, canonicalLine: true },
  );
  const stdout = capture();
  const stderr = capture();
  const exitCode = await runOperatorCli({
    argv: [
      'agent', 'enroll', descriptorPath,
      '--confirm', sha256(canonicalJson(descriptor)),
    ],
    env: value.env,
    requestImpl: async () => { throw new Error('offline enrollment must not use HTTP'); },
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  assert.equal(exitCode, 0, stderr.read());
  assert.equal(stderr.read(), '');
  assert.match(stdout.read(), /^agent-enroll: \{/);
  assert.equal(stdout.read().includes(TOKEN), false);
  assert.equal(query(value.databasePath, 'SELECT * FROM agent_enrollments').length, 1);
});

test('descriptor symlinks, hardlinks, permissive paths, and noncanonical bytes fail without enrollment', async (t) => {
  for (const kind of ['symlink', 'hardlink', 'permissive', 'permissive-parent', 'noncanonical']) {
    await t.test(kind, async (t) => {
      const value = fixture(t);
      const descriptor = descriptorForCurrentIdentity();
      const original = writeJson(
        value.enrollmentInbox,
        'original.json',
        descriptor,
        { mode: 0o644, canonicalLine: kind !== 'noncanonical' },
      );
      let descriptorPath = original;
      if (kind === 'symlink') {
        descriptorPath = path.join(value.enrollmentInbox, 'linked.json');
        fs.symlinkSync(original, descriptorPath);
      } else if (kind === 'hardlink') {
        descriptorPath = path.join(value.enrollmentInbox, 'linked.json');
        fs.linkSync(original, descriptorPath);
      } else if (kind === 'permissive') {
        fs.chmodSync(original, 0o666);
      } else if (kind === 'permissive-parent') {
        fs.chmodSync(value.enrollmentInbox, 0o775);
      }
      await assert.rejects(
        runOfflineBootstrap({
          command: {
            name: 'agent-enroll',
            descriptorPath,
            expectedDescriptorHash: sha256(canonicalJson(descriptor)),
          },
          config: value.config,
          operatorToken: TOKEN,
        }),
        (error) => error.code === 'AGENT_DESCRIPTOR_PATH'
          || error.code === 'AGENT_DESCRIPTOR_BYTES',
      );
      if (fs.existsSync(value.databasePath)) {
        assert.equal(query(value.databasePath, 'SELECT id FROM agent_enrollments').length, 0);
      }
    });
  }
});

test('a competing Kernel or bootstrap owner returns AUTHORITY_BUSY before any authority write', async (t) => {
  const value = fixture(t);
  const policy = policyFile(value);
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: value.root,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  const owner = acquireAuthorityLock({
    databasePath: value.databasePath,
    role: 'kernel',
    pathTrust,
  });
  try {
    await assert.rejects(
      runOfflineBootstrap({
        command: {
          name: 'policy-apply',
          policyPath: policy.filePath,
          expectedPolicyHash: policy.hash,
        },
        config: value.config,
        operatorToken: TOKEN,
      }),
      (error) => error.code === 'AUTHORITY_BUSY',
    );
    assert.equal(fs.existsSync(value.databasePath), false);
    assert.equal(fs.existsSync(value.receiptKeyPath), false);
  } finally {
    owner.close();
  }
});

test('semantic or event-chain corruption becomes AUTHORITY_RECOVERY_REQUIRED before requested mutation', async (t) => {
  const value = fixture(t);
  const initial = policyFile(value);
  await runOfflineBootstrap({
    command: {
      name: 'policy-apply',
      policyPath: initial.filePath,
      expectedPolicyHash: initial.hash,
    },
    config: value.config,
    operatorToken: TOKEN,
  });

  const corruptor = new DatabaseSync(value.databasePath);
  try {
    corruptor.prepare("UPDATE events SET event_hash = ? WHERE event_type = 'policy.applied'")
      .run(`sha256:${'ff'.repeat(32)}`);
  } finally {
    corruptor.close();
  }
  const replacementPolicy = structuredClone(BASE_POLICY);
  replacementPolicy.sessionMaxAtomic = '1900000';
  const replacement = policyFile(value, replacementPolicy, 'replacement.json');

  await assert.rejects(
    runOfflineBootstrap({
      command: {
        name: 'policy-apply',
        policyPath: replacement.filePath,
        expectedPolicyHash: replacement.hash,
      },
      config: value.config,
      operatorToken: TOKEN,
    }),
    (error) => error.code === 'AUTHORITY_RECOVERY_REQUIRED',
  );
  assert.equal(query(value.databasePath, 'SELECT id FROM policy_versions').length, 1);
});

test('a domain-commit receipt gap is repaired to exact parity before policy mutation', async (t) => {
  const value = fixture(t);
  const initial = policyFile(value);
  await runOfflineBootstrap({
    command: {
      name: 'policy-apply',
      policyPath: initial.filePath,
      expectedPolicyHash: initial.hash,
    },
    config: value.config,
    operatorToken: TOKEN,
  });
  const descriptor = descriptorForCurrentIdentity();
  const descriptorPath = writeJson(
    value.enrollmentInbox,
    'agent-enrollment.json',
    descriptor,
    { mode: 0o644, canonicalLine: true },
  );
  await runOfflineBootstrap({
    command: {
      name: 'agent-enroll',
      descriptorPath,
      expectedDescriptorHash: sha256(canonicalJson(descriptor)),
    },
    config: value.config,
    operatorToken: TOKEN,
  });

  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: value.root,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  const owner = acquireAuthorityLock({
    databasePath: value.databasePath,
    role: 'kernel',
    pathTrust,
  });
  const store = openKernelStore({
    filePath: value.databasePath,
    pathTrust,
    now: () => new Date().toISOString(),
  });
  try {
    let sequence = 0;
    const intents = createIntentRepository({
      store,
      idFactory: (kind) => `${kind}-offline-gap-${++sequence}`,
      now: () => new Date().toISOString(),
      allowLoopbackHttp: true,
      routeMetadata: {},
    });
    const policy = store.readOne('SELECT id FROM policy_versions WHERE policy_hash = ?', [initial.hash]);
    const session = intents.openOrResumeSession({
      agentInstanceId: descriptor.agentInstanceId,
      walletAddress: BASE_POLICY.wallet,
      policyVersionId: policy.id,
    });
    intents.captureIntent({
      sessionId: session.id,
      routeId: 'paid-infer',
      method: 'POST',
      requestUrl: 'https://seller.example/paid/infer',
      headers: { accept: 'application/json', 'content-type': 'application/json' },
      bodyBytes: Buffer.from('{}'),
      purposeLabel: 'skill.invoke',
      correlationId: 'offline-receipt-gap',
    });
  } finally {
    store.close();
    owner.close();
  }

  await runOfflineBootstrap({
    command: { name: 'preflight' },
    config: value.config,
    operatorToken: TOKEN,
  });
  assert.equal(query(value.databasePath, 'SELECT id FROM signed_receipts').length, 1);

  const crashGap = new DatabaseSync(value.databasePath);
  try {
    const receiptEvent = crashGap.prepare(`SELECT sequence FROM events
      WHERE entity_type = 'signed_receipt' AND event_type = 'receipt.issued'`).get();
    const tail = crashGap.prepare('SELECT MAX(sequence) AS sequence FROM events').get();
    assert.equal(receiptEvent.sequence, tail.sequence, 'receipt issuance must be the removable tail');
    crashGap.exec('BEGIN IMMEDIATE');
    crashGap.prepare("DELETE FROM events WHERE entity_type = 'signed_receipt'").run();
    crashGap.prepare('DELETE FROM signed_receipts').run();
    crashGap.exec('COMMIT');
  } finally {
    crashGap.close();
  }

  const replacementPolicy = structuredClone(BASE_POLICY);
  replacementPolicy.sessionMaxAtomic = '1900000';
  const replacement = policyFile(value, replacementPolicy, 'replacement-after-gap.json');
  const applied = await runOfflineBootstrap({
    command: {
      name: 'policy-apply',
      policyPath: replacement.filePath,
      expectedPolicyHash: replacement.hash,
    },
    config: value.config,
    operatorToken: TOKEN,
  });
  assert.equal(applied.policyVersion.hash, replacement.hash);
  assert.equal(query(value.databasePath, 'SELECT id FROM signed_receipts').length, 1);
  assert.equal(query(value.databasePath, `SELECT sequence FROM events
    WHERE entity_type = 'signed_receipt' AND event_type = 'receipt.issued'`).length, 1);
  assert.equal(query(value.databasePath, 'SELECT id FROM policy_versions').length, 2);
});

test('input confirmation is canonical and stale policy confirmation cannot mutate authority', async (t) => {
  const value = fixture(t);
  const policy = policyFile(value);
  await assert.rejects(
    runOfflineBootstrap({
      command: {
        name: 'policy-apply',
        policyPath: policy.filePath,
        expectedPolicyHash: `sha256:${'00'.repeat(32)}`,
      },
      config: value.config,
      operatorToken: TOKEN,
    }),
    (error) => error.code === 'POLICY_HASH_MISMATCH',
  );
  assert.equal(fs.existsSync(value.databasePath), false);
  assert.equal(fs.existsSync(value.receiptKeyPath), false);
});

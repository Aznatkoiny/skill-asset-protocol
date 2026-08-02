import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createAgentEnrollmentDescriptor,
  loadOrCreateAgentCredential,
  publishAgentEnrollmentDescriptor,
} from '../src/agent/credential.mjs';
import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';

const CURRENT_UID = process.getuid();
const CURRENT_GID = process.getgid();

function fixture(t) {
  const root = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-agent-credential-')),
  );
  fs.chmodSync(root, 0o700);
  const privateParent = path.join(root, 'private');
  const enrollmentInbox = path.join(root, 'enrollment-inbox');
  fs.mkdirSync(privateParent, { mode: 0o700 });
  fs.mkdirSync(enrollmentInbox, { mode: 0o755 });
  fs.chmodSync(privateParent, 0o700);
  fs.chmodSync(enrollmentInbox, 0o755);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return Object.freeze({
    root,
    credentialPath: path.join(privateParent, 'agent.json'),
    enrollmentPath: path.join(enrollmentInbox, 'agent-enrollment.json'),
    pathTrust: Object.freeze({
      mode: 'deterministic',
      trustedAncestor: root,
      agentUid: CURRENT_UID,
    }),
  });
}

function deterministicRandom(sequence = [0x11, 0x22, 0x33, 0x44]) {
  let index = 0;
  return (size) => Buffer.alloc(size, sequence[index++] ?? 0x55);
}

test('Pi credential initializes exact canonical private authority and reuses it unchanged', (t) => {
  const value = fixture(t);
  const calls = [];
  const randomBytes = deterministicRandom();
  const credential = loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: value.pathTrust,
    randomBytes(size) {
      calls.push(size);
      return randomBytes(size);
    },
  });
  assert.deepEqual(Object.keys(credential), ['agentInstanceId', 'schemaVersion', 'token']);
  assert.equal(credential.schemaVersion, 1);
  assert.match(credential.agentInstanceId, /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/);
  assert.match(credential.token, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(Buffer.from(credential.agentInstanceId, 'base64url').length, 16);
  assert.equal(Buffer.from(credential.token, 'base64url').length, 32);
  assert.equal(Buffer.from(credential.agentInstanceId, 'base64url').toString('base64url'), credential.agentInstanceId);
  assert.equal(Buffer.from(credential.token, 'base64url').toString('base64url'), credential.token);
  assert.equal(
    fs.readFileSync(value.credentialPath, 'utf8'),
    `${canonicalJson(credential)}\n`,
  );
  const stat = fs.lstatSync(value.credentialPath);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.uid, CURRENT_UID);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.deepEqual(calls, [16, 32, 16]);

  const before = fs.statSync(value.credentialPath, { bigint: true });
  const reused = loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: value.pathTrust,
    randomBytes() { throw new Error('must not rotate an existing Pi credential'); },
  });
  const after = fs.statSync(value.credentialPath, { bigint: true });
  assert.deepEqual(reused, credential);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mtimeNs, before.mtimeNs);
});

test('agent instance generation rejects a base64url-leading authority delimiter', (t) => {
  const value = fixture(t);
  const calls = [];
  const outputs = [
    Buffer.from([0xf8, ...new Array(15).fill(0)]),
    Buffer.alloc(16, 0x11),
    Buffer.alloc(32, 0x22),
    Buffer.alloc(16, 0x33),
  ];
  const credential = loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: value.pathTrust,
    randomBytes(size) {
      calls.push(size);
      return outputs.shift();
    },
  });

  assert.match(Buffer.from([0xf8, ...new Array(15).fill(0)]).toString('base64url'), /^-/);
  assert.match(credential.agentInstanceId, /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/);
  assert.deepEqual(calls, [16, 16, 32, 16]);

  const exhausted = fixture(t);
  let attempts = 0;
  assert.throws(() => loadOrCreateAgentCredential({
    filePath: exhausted.credentialPath,
    pathTrust: exhausted.pathTrust,
    randomBytes(size) {
      attempts += 1;
      return Buffer.from([0xf8, ...new Array(size - 1).fill(0)]);
    },
  }), (error) => error?.code === 'AGENT_CREDENTIAL_RANDOMNESS');
  assert.equal(attempts, 128);
  assert.equal(fs.existsSync(exhausted.credentialPath), false);
});

test('Pi credential rejects noncanonical bytes and authority metadata without repair', (t) => {
  for (const bytes of [
    '{}\n',
    `${JSON.stringify({ schemaVersion: 1, agentInstanceId: 'A'.repeat(22), token: 'A'.repeat(43), extra: true })}\n`,
    `${canonicalJson({ schemaVersion: 1, agentInstanceId: 'A'.repeat(22), token: `${'A'.repeat(42)}B` })}\n`,
    `${canonicalJson({
      schemaVersion: 1,
      agentInstanceId: Buffer.from([0xf8, ...new Array(15).fill(0)]).toString('base64url'),
      token: 'A'.repeat(43),
    })}\n`,
    canonicalJson({ schemaVersion: 1, agentInstanceId: 'A'.repeat(22), token: 'A'.repeat(43) }),
    ` ${canonicalJson({ schemaVersion: 1, agentInstanceId: 'A'.repeat(22), token: 'A'.repeat(43) })}\n`,
  ]) {
    const value = fixture(t);
    fs.writeFileSync(value.credentialPath, bytes, { mode: 0o600 });
    fs.chmodSync(value.credentialPath, 0o600);
    assert.throws(() => loadOrCreateAgentCredential({
      filePath: value.credentialPath,
      pathTrust: value.pathTrust,
      randomBytes() { throw new Error('must not repair'); },
    }));
    assert.equal(fs.readFileSync(value.credentialPath, 'utf8'), bytes);
  }

  const permissive = fixture(t);
  fs.writeFileSync(permissive.credentialPath, `${canonicalJson({
    schemaVersion: 1,
    agentInstanceId: Buffer.alloc(16, 1).toString('base64url'),
    token: Buffer.alloc(32, 2).toString('base64url'),
  })}\n`, { mode: 0o644 });
  fs.chmodSync(permissive.credentialPath, 0o644);
  assert.throws(() => loadOrCreateAgentCredential({
    filePath: permissive.credentialPath,
    pathTrust: permissive.pathTrust,
  }));

  const symlink = fixture(t);
  const target = path.join(symlink.root, 'target.json');
  fs.writeFileSync(target, '{}\n', { mode: 0o600 });
  fs.symlinkSync(target, symlink.credentialPath);
  assert.throws(() => loadOrCreateAgentCredential({
    filePath: symlink.credentialPath,
    pathTrust: symlink.pathTrust,
  }));
});

test('enrollment descriptor is public, secret-free, and hashes raw credential bytes once', (t) => {
  const value = fixture(t);
  const credential = loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: value.pathTrust,
    randomBytes: deterministicRandom(),
  });
  const descriptor = createAgentEnrollmentDescriptor({
    credential,
  });
  assert.deepEqual(Object.keys(descriptor), [
    'schemaVersion',
    'agentInstanceId',
    'credentialDigest',
    'agentUid',
    'agentGid',
  ]);
  assert.equal(descriptor.agentInstanceId, credential.agentInstanceId);
  const rawToken = Buffer.from(credential.token, 'base64url');
  assert.equal(descriptor.credentialDigest, sha256(rawToken));
  assert.notEqual(descriptor.credentialDigest, sha256(credential.token));
  assert.equal(JSON.stringify(descriptor).includes(credential.token), false);
  assert.equal(JSON.stringify(descriptor).includes('token'), false);

  const published = publishAgentEnrollmentDescriptor({
    filePath: value.enrollmentPath,
    credentialPath: value.credentialPath,
    descriptor,
    pathTrust: value.pathTrust,
  });
  const bytes = `${canonicalJson(descriptor)}\n`;
  assert.deepEqual(published, Object.freeze({
    descriptor,
    descriptorHash: sha256(canonicalJson(descriptor)),
  }));
  assert.equal(fs.readFileSync(value.enrollmentPath, 'utf8'), bytes);
  const stat = fs.lstatSync(value.enrollmentPath);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.nlink, 1);
  assert.equal(stat.uid, CURRENT_UID);
  assert.equal(stat.mode & 0o777, 0o644);
  assert.equal(fs.readFileSync(value.enrollmentPath, 'utf8').includes(credential.token), false);
  assert.throws(() => publishAgentEnrollmentDescriptor({
    filePath: value.enrollmentPath,
    credentialPath: value.credentialPath,
    descriptor,
    pathTrust: value.pathTrust,
  }), (error) => error.code === 'EEXIST');
  assert.equal(fs.readFileSync(value.enrollmentPath, 'utf8'), bytes);
});

test('descriptor publication rejects same-parent, extension, noncanonical identity, and hostile shapes', (t) => {
  const value = fixture(t);
  const credential = loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: value.pathTrust,
    randomBytes: deterministicRandom(),
  });
  const descriptor = createAgentEnrollmentDescriptor({
    credential,
  });
  assert.throws(() => publishAgentEnrollmentDescriptor({
    filePath: path.join(path.dirname(value.credentialPath), 'descriptor.json'),
    credentialPath: value.credentialPath,
    descriptor,
    pathTrust: value.pathTrust,
  }));
  assert.throws(() => publishAgentEnrollmentDescriptor({
    filePath: value.enrollmentPath,
    credentialPath: value.credentialPath,
    descriptor: { ...descriptor, token: credential.token },
    pathTrust: value.pathTrust,
  }));
  assert.throws(() => createAgentEnrollmentDescriptor({
    credential,
    agentUid: String(CURRENT_UID),
  }));
  assert.throws(() => createAgentEnrollmentDescriptor(new Proxy({
    credential,
  }, {})));
});

test('Pi credential and handoff use their distinct live authority roles', (t) => {
  if (process.platform === 'linux') {
    t.skip('the live-role wiring assertion is exercised by Linux isolation tests');
    return;
  }
  const value = fixture(t);
  const livePathTrust = Object.freeze({
    mode: 'cdp-testnet',
    trustedAncestor: value.root,
    agentUid: CURRENT_UID,
  });
  assert.throws(() => loadOrCreateAgentCredential({
    filePath: value.credentialPath,
    pathTrust: livePathTrust,
    randomBytes: deterministicRandom(),
  }), /cdp-testnet trusted paths require Linux/);

  const credential = Object.freeze({
    schemaVersion: 1,
    agentInstanceId: Buffer.alloc(16, 0x31).toString('base64url'),
    token: Buffer.alloc(32, 0x32).toString('base64url'),
  });
  const descriptor = createAgentEnrollmentDescriptor({ credential });
  assert.throws(() => publishAgentEnrollmentDescriptor({
    filePath: value.enrollmentPath,
    credentialPath: value.credentialPath,
    descriptor,
    pathTrust: livePathTrust,
  }), /cdp-testnet trusted paths require Linux/);
});

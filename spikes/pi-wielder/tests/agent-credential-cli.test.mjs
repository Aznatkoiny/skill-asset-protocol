import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { runAgentCredentialCli } from '../src/agent/credential-cli.mjs';

const CURRENT_UID = process.getuid();

function fixture(t) {
  const root = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-agent-cli-')),
  );
  const privateDirectory = path.join(root, 'private');
  const enrollmentDirectory = path.join(root, 'enrollment');
  fs.mkdirSync(privateDirectory, { mode: 0o700 });
  fs.mkdirSync(enrollmentDirectory, { mode: 0o755 });
  fs.chmodSync(root, 0o700);
  fs.chmodSync(privateDirectory, 0o700);
  fs.chmodSync(enrollmentDirectory, 0o755);
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  return Object.freeze({
    credentialPath: path.join(privateDirectory, 'agent.json'),
    enrollmentPath: path.join(enrollmentDirectory, 'agent-enrollment.json'),
    pathTrust: Object.freeze({
      mode: 'deterministic',
      trustedAncestor: root,
      agentUid: CURRENT_UID,
    }),
  });
}

function deterministicRandom() {
  const values = [0x11, 0x22, 0x33];
  let index = 0;
  return (size) => Buffer.alloc(size, values[index++] ?? 0x44);
}

test('credential init prints only one descriptor SHA-256 and never publishes the token', (t) => {
  const value = fixture(t);
  const output = [];
  const result = runAgentCredentialCli({
    argv: [
      'init',
      '--credential', value.credentialPath,
      '--enrollment', value.enrollmentPath,
    ],
    writeStdout(bytes) { output.push(bytes); },
    dependencies: {
      pathTrust: value.pathTrust,
      randomBytes: deterministicRandom(),
    },
  });

  assert.equal(result, 0);
  assert.equal(output.length, 1);
  assert.match(output[0], /^sha256:[0-9a-f]{64}\n$/);
  assert.doesNotMatch(output[0], /^sha256:sha256:/);

  const credentialText = fs.readFileSync(value.credentialPath, 'utf8');
  const enrollmentText = fs.readFileSync(value.enrollmentPath, 'utf8');
  const credential = JSON.parse(credentialText);
  assert.equal(enrollmentText.includes(credential.token), false);
  assert.equal(output[0].includes(credential.token), false);
});

test('credential init refuses enrollment overwrite without rotating the existing credential', (t) => {
  const value = fixture(t);
  const argv = [
    'init',
    '--credential', value.credentialPath,
    '--enrollment', value.enrollmentPath,
  ];
  runAgentCredentialCli({
    argv,
    writeStdout() {},
    dependencies: {
      pathTrust: value.pathTrust,
      randomBytes: deterministicRandom(),
    },
  });
  const credentialBefore = fs.readFileSync(value.credentialPath);
  const enrollmentBefore = fs.readFileSync(value.enrollmentPath);
  const output = [];

  assert.throws(() => runAgentCredentialCli({
    argv,
    writeStdout(bytes) { output.push(bytes); },
    dependencies: {
      pathTrust: value.pathTrust,
      randomBytes() { throw new Error('must not rotate'); },
    },
  }), (error) => error?.code === 'EEXIST');

  assert.deepEqual(output, []);
  assert.deepEqual(fs.readFileSync(value.credentialPath), credentialBefore);
  assert.deepEqual(fs.readFileSync(value.enrollmentPath), enrollmentBefore);
});

test('credential CLI accepts only the exact init grammar before touching authority', () => {
  const attempts = [];
  for (const argv of [
    [],
    ['help'],
    ['init'],
    ['init', '--credential', '/a', '--enrollment', '/b', '--extra', 'x'],
    ['init', '--enrollment', '/b', '--credential', '/a'],
    ['init', '--credential=/a', '--enrollment=/b'],
    ['init', '--credential', '/a', '--credential', '/b', '--enrollment', '/c'],
  ]) {
    assert.throws(() => runAgentCredentialCli({
      argv,
      writeStdout() { attempts.push('stdout'); },
      dependencies: {
        pathTrust: Object.freeze({}),
        randomBytes() { attempts.push('random'); },
      },
    }), (error) => error?.code === 'AGENT_CREDENTIAL_CLI_USAGE');
  }
  assert.deepEqual(attempts, []);
});

test('credential CLI source has no Kernel authority, environment, database, or listener path', () => {
  const source = fs.readFileSync(
    new URL('../src/agent/credential-cli.mjs', import.meta.url),
    'utf8',
  );
  assert.match(source, /from '\.\/credential\.mjs'/);
  assert.doesNotMatch(source, /process\.env|WALLET_KERNEL_OPERATOR|sqlite|listen\(|createServer|kernel\/wallet-kernel|operator/i);
});

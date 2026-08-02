import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const NODE = process.execPath;
const PACKAGE_ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const SCRIPT = path.join(PACKAGE_ROOT, 'scripts/verify-no-tracked-secrets.mjs');

function repository(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'no-secrets-test-')));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { force: true, recursive: true }));
  const initialized = spawnSync('git', ['init', '-q'], { cwd: directory, encoding: 'utf8' });
  assert.equal(initialized.status, 0, initialized.stderr);
  return directory;
}

function track(directory, relativePath, contents) {
  const destination = path.join(directory, relativePath);
  fs.mkdirSync(path.dirname(destination), { recursive: true });
  fs.writeFileSync(destination, contents);
  const added = spawnSync('git', ['add', '--', relativePath], { cwd: directory, encoding: 'utf8' });
  assert.equal(added.status, 0, added.stderr);
}

function run(directory, { env = {}, args = [], cwd = directory } = {}) {
  return spawnSync(NODE, [SCRIPT, ...args], {
    cwd,
    env: {
      PATH: process.env.PATH,
      ...env,
    },
    encoding: 'utf8',
  });
}

test('CLI scans the whole repository when invoked from a nested package directory', (t) => {
  const directory = repository(t);
  const nested = path.join(directory, 'packages', 'wallet');
  fs.mkdirSync(nested, { recursive: true });
  track(directory, 'operator-token', 'placeholder-only');
  track(directory, 'packages/wallet/safe.txt', 'safe\n');
  const result = run(directory, { cwd: nested });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /TRACKED_SECRET_FILENAME/);
  assert.match(result.stderr, /operator-token/);
});

test('tracked-secret scan permits variable names and placeholders in example files', (t) => {
  const directory = repository(t);
  track(directory, '.env.example', [
    'CDP_API_KEY_SECRET=replace-me',
    'WALLET_KERNEL_OPERATOR_TOKEN_FILE=/path/set/at/install',
    'WALLET_KERNEL_RECEIPT_KEY_FILE=/path/set/at/install',
    '',
  ].join('\n'));
  track(directory, 'src/config.mjs', "export const name = 'CDP_API_KEY_SECRET';\n");
  const result = run(directory, { env: { CDP_API_KEY_SECRET: 'actual-secret-marker' } });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), { scannedFiles: 2, valid: true });
  assert.doesNotMatch(result.stdout + result.stderr, /actual-secret-marker/);
});

test('exact, multiline, and base64-like configured secret values fail without disclosure', (t) => {
  const cases = [
    ['CDP_API_KEY_SECRET', 'exact-secret-marker', 'prefix exact-secret-marker suffix'],
    ['CDP_WALLET_SECRET', 'line-one\nline-two', 'before\nline-one\nline-two\nafter'],
    ['SERVICE_AUTH_TOKEN', 'YWdlbnQtc2VjcmV0LXZhbHVl', 'YWdlbnQtc2VjcmV0LXZhbHVl'],
  ];
  for (const [name, secret, tracked] of cases) {
    const directory = repository(t);
    track(directory, 'tracked.txt', tracked);
    const result = run(directory, { env: { [name]: secret } });
    assert.equal(result.status, 1);
    assert.match(result.stderr, new RegExp(name));
    assert.match(result.stderr, /tracked\.txt/);
    assert.doesNotMatch(result.stdout + result.stderr, new RegExp(secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  }
});

test('owner-only Kernel secret files are scanned while Pi credential is untouched by default', (t) => {
  const directory = repository(t);
  const privateDirectory = path.join(directory, 'private-authority');
  fs.mkdirSync(privateDirectory, { mode: 0o700 });
  const operatorToken = path.join(privateDirectory, 'operator-token');
  const receiptKey = path.join(privateDirectory, 'receipt-key.pem');
  const agentCredential = path.join(privateDirectory, 'agent-credential.json');
  fs.writeFileSync(operatorToken, 'operator-token-marker\n', { mode: 0o600 });
  fs.writeFileSync(receiptKey, 'receipt-key-marker\n', { mode: 0o600 });
  fs.writeFileSync(agentCredential, 'agent-credential-marker\n', { mode: 0o000 });
  track(directory, 'safe.txt', 'nothing sensitive here\n');

  const result = run(directory, {
    env: {
      WALLET_KERNEL_OPERATOR_TOKEN_FILE: operatorToken,
      WALLET_KERNEL_RECEIPT_KEY_FILE: receiptKey,
    },
  });
  assert.equal(result.status, 0, result.stderr);

  fs.chmodSync(agentCredential, 0o600);
  track(directory, 'leak.txt', 'agent-credential-marker');
  const piSide = run(directory, { args: ['--agent-credential', agentCredential] });
  assert.equal(piSide.status, 1);
  assert.match(piSide.stderr, /AGENT_CREDENTIAL_FILE/);
  assert.doesNotMatch(piSide.stdout + piSide.stderr, /agent-credential-marker/);
});

test('secret-bearing filenames and complete private-key encodings fail closed', (t) => {
  {
    const directory = repository(t);
    track(directory, 'operator-token', 'placeholder-only');
    const result = run(directory);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /TRACKED_SECRET_FILENAME/);
  }
  {
    const directory = repository(t);
    const begin = ['-----BEGIN ', 'PRIVATE KEY-----'].join('');
    const end = ['-----END ', 'PRIVATE KEY-----'].join('');
    track(directory, 'source.txt', `${begin}\nQUJDREVGR0g=\n${end}\n`);
    const result = run(directory);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /PRIVATE_KEY_ENCODING/);
    assert.doesNotMatch(result.stdout + result.stderr, /QUJDREVGR0g/);
  }
});

test('agent credential option rejects missing value, symlink, permissive mode, and extra arguments', (t) => {
  const directory = repository(t);
  track(directory, 'safe.txt', 'safe\n');
  const credential = path.join(directory, 'credential');
  fs.writeFileSync(credential, 'credential-marker\n', { mode: 0o600 });
  const link = path.join(directory, 'credential-link');
  fs.symlinkSync(credential, link);

  assert.equal(run(directory, { args: ['--agent-credential'] }).status, 2);
  assert.equal(run(directory, { args: ['--agent-credential', credential, 'extra'] }).status, 2);
  assert.equal(run(directory, { args: ['--agent-credential', link] }).status, 2);
  fs.chmodSync(credential, 0o644);
  assert.equal(run(directory, { args: ['--agent-credential', credential] }).status, 2);
});

import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import { runOperatorCli } from '../src/operator/cli.mjs';

const ORIGIN = 'http://127.0.0.1:8405';
const TOKEN = Buffer.alloc(32, 0x41).toString('base64url');
const LAUNCH_TOKEN = Buffer.alloc(32, 0x22).toString('base64url');
const SHA_A = `sha256:${'a1'.repeat(32)}`;
const SHA_B = `sha256:${'b2'.repeat(32)}`;
const TX_A = `0x${'ab'.repeat(32)}`;
const TX_B = `0x${'cd'.repeat(32)}`;

function makeFixture(t, { mode = 'deterministic' } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-cli-'));
  fs.chmodSync(directory, 0o700);
  const tokenPath = path.join(directory, 'operator.token');
  fs.writeFileSync(tokenPath, TOKEN, { mode: 0o600, flag: 'wx' });
  fs.chmodSync(tokenPath, 0o600);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return Object.freeze({
    directory,
    tokenPath,
    socketPath: path.join(directory, 'operator.sock'),
    env: Object.freeze({
      WALLET_KERNEL_MODE: mode,
      WALLET_KERNEL_DB_FILE: path.join(directory, 'authority.sqlite'),
      WALLET_KERNEL_OPERATOR_TOKEN_FILE: tokenPath,
      WALLET_KERNEL_OPERATOR_PORT: '8405',
      ...(mode === 'cdp-testnet'
        ? { WALLET_KERNEL_OPERATOR_SOCKET_FILE: path.join(directory, 'operator.sock') }
        : {}),
    }),
  });
}

function capture() {
  let value = '';
  return Object.freeze({
    stream: Object.freeze({ write(chunk) { value += String(chunk); return true; } }),
    read() { return value; },
  });
}

function response(body = { state: 'ok' }, status = 200, headers = {}) {
  const payload = status >= 200 && status < 300 ? { ok: true, data: body } : body;
  return Object.freeze({
    status,
    headers: Object.freeze({
      'cache-control': 'no-store',
      'content-type': 'application/json',
      ...headers,
    }),
    body: canonicalJson(payload),
  });
}

function fakeSocketMetadata(t, socketPath) {
  const realLstatSync = fs.lstatSync.bind(fs);
  t.mock.method(fs, 'lstatSync', (location, options) => {
    const stat = realLstatSync(location, options);
    if (location !== socketPath) return stat;
    return new Proxy(stat, {
      get(target, property, receiver) {
        if (property === 'isSocket') return () => true;
        if (property === 'isFile' || property === 'isSymbolicLink') return () => false;
        return Reflect.get(target, property, receiver);
      },
    });
  });
}

async function invoke(t, argv, {
  mode = 'deterministic',
  requestImpl = async () => response(),
  offlineBootstrap,
  env: envOverrides = {},
} = {}) {
  const fixture = makeFixture(t, { mode });
  const stdout = capture();
  const stderr = capture();
  const exitCode = await runOperatorCli({
    argv,
    env: { ...fixture.env, ...envOverrides },
    requestImpl,
    offlineBootstrap,
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  return Object.freeze({ exitCode, stdout: stdout.read(), stderr: stderr.read(), fixture });
}

test('online commands map to the exact closed operator API request contract', async (t) => {
  const cases = [
    {
      argv: ['agent', 'revoke', 'agent-1', '--confirm', SHA_A],
      method: 'POST', path: '/operator/v1/agents/agent-1/revoke',
      body: { expectedEnrollmentHash: SHA_A },
    },
    {
      argv: ['console', 'launch'], method: 'POST', path: '/operator/v1/browser-launch', body: null,
      result: { url: `${ORIGIN}/operator/#launch=${LAUNCH_TOKEN}`, expiresAt: '2026-08-02T00:01:00.000Z' },
    },
    {
      argv: ['sessions', 'transition', 'session-1', '--to-policy', SHA_B, '--confirm', SHA_A],
      method: 'POST', path: '/operator/v1/sessions/session-1/transition-policy',
      body: { targetPolicyHash: SHA_B, expectedSessionHash: SHA_A },
    },
    {
      argv: ['sessions', 'close', 'session-1', '--confirm', SHA_A],
      method: 'POST', path: '/operator/v1/sessions/session-1/close',
      body: { expectedSessionHash: SHA_A },
    },
    {
      argv: ['approvals', 'list'], method: 'GET', path: '/operator/v1/approvals', body: null,
    },
    {
      argv: ['approvals', 'list', '--state', 'pending'],
      method: 'GET', path: '/operator/v1/approvals?state=pending', body: null,
    },
    {
      argv: ['approvals', 'approve', 'approval-1', '--confirm', SHA_A],
      method: 'POST', path: '/operator/v1/approvals/approval-1/approve',
      body: { expectedIntentHash: SHA_A },
    },
    {
      argv: ['approvals', 'deny', 'approval-1', '--confirm', SHA_A, '--reason', 'OPERATOR_DENIED'],
      method: 'POST', path: '/operator/v1/approvals/approval-1/deny',
      body: { expectedIntentHash: SHA_A, reasonCode: 'OPERATOR_DENIED' },
    },
    {
      argv: ['receipts', 'list'], method: 'GET', path: '/operator/v1/receipts', body: null,
    },
    {
      argv: ['receipts', 'verify', 'receipt-1'],
      method: 'GET', path: '/operator/v1/receipts/receipt-1', body: null,
    },
    {
      argv: ['reconcile', 'payment', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/payment',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B },
    },
    {
      argv: ['reconcile', 'payment', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B,
        '--payment-transaction', TX_A],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/payment',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B, paymentTransactionId: TX_A },
    },
    {
      argv: ['reconcile', 'execution', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/execution',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B },
    },
    {
      argv: ['reconcile', 'refund-observation', 'intent-1', '--confirm', SHA_A,
        '--confirm-case', SHA_B, '--refund-transaction', TX_B],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/refund-observation',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B, refundTransactionId: TX_B },
    },
    {
      argv: ['reconcile', 'abandon-candidate', 'intent-1', '--kind', 'payment',
        '--confirm', SHA_A, '--confirm-case', SHA_B],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/payment/abandon-candidate',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B },
    },
    {
      argv: ['reconcile', 'abandon-candidate', 'intent-1', '--kind', 'refund-observation',
        '--confirm', SHA_A, '--confirm-case', SHA_B],
      method: 'POST', path: '/operator/v1/reconciliations/intent-1/refund-observation/abandon-candidate',
      body: { expectedIntentHash: SHA_A, expectedCaseHash: SHA_B },
    },
  ];

  for (const value of cases) {
    let captured;
    const result = await invoke(t, value.argv, {
      requestImpl: async (input) => {
        captured = input;
        return response(value.result ?? { commandState: 'ok' });
      },
    });
    assert.equal(result.exitCode, 0, `${value.argv.join(' ')}: ${result.stderr}`);
    assert.equal(result.stderr, '');
    assert.deepEqual(Object.keys(captured), [
      'socketPath', 'origin', 'method', 'path', 'headers', 'body',
    ]);
    assert.equal(captured.socketPath, null);
    assert.equal(captured.origin, ORIGIN);
    assert.equal(captured.method, value.method);
    assert.equal(captured.path, value.path);
    assert.deepEqual(captured.body, value.body === null ? null : canonicalJson(value.body));
    assert.deepEqual(captured.headers, Object.freeze({
      accept: 'application/json',
      authorization: `Bearer ${TOKEN}`,
      ...(value.body === null ? {} : { 'content-type': 'application/json' }),
    }));
    assert.equal(`${result.stdout}${result.stderr}`.includes(TOKEN), false);
  }
});

test('offline commands dispatch only through the narrow bootstrap capability', async (t) => {
  const cases = [
    { argv: ['preflight'], command: { name: 'preflight' } },
    {
      argv: ['agent', 'enroll', '/input/agent.json', '--confirm', SHA_A],
      command: { name: 'agent-enroll', descriptorPath: '/input/agent.json', expectedDescriptorHash: SHA_A },
    },
    {
      argv: ['isolation', 'attest', '/input/report.json', '--confirm', SHA_A],
      command: { name: 'isolation-attest', reportPath: '/input/report.json', expectedReportHash: SHA_A },
    },
    {
      argv: ['policy', 'validate', '/input/policy.json'],
      command: { name: 'policy-validate', policyPath: '/input/policy.json' },
    },
    {
      argv: ['policy', 'apply', '/input/policy.json', '--confirm', SHA_A],
      command: { name: 'policy-apply', policyPath: '/input/policy.json', expectedPolicyHash: SHA_A },
    },
  ];

  for (const value of cases) {
    let captured;
    const result = await invoke(t, value.argv, {
      requestImpl: async () => { throw new Error('offline command must not use HTTP'); },
      offlineBootstrap: async (input) => {
        captured = input;
        return Object.freeze({ state: 'ok' });
      },
    });
    assert.equal(result.exitCode, 0, `${value.argv.join(' ')}: ${result.stderr}`);
    assert.deepEqual(captured.command, value.command);
    assert.equal(captured.operatorToken, TOKEN);
    assert.deepEqual(captured.config, Object.freeze({
      mode: 'deterministic',
      databasePath: result.fixture.env.WALLET_KERNEL_DB_FILE,
      receiptKeyPath: null,
      operatorTokenPath: result.fixture.tokenPath,
      operatorSocketPath: null,
      origin: ORIGIN,
      trustedAncestor: null,
      enrollmentInboxPath: null,
      expectedAgentUid: process.getuid(),
      expectedAgentGid: process.getgid(),
      kernelUid: process.getuid(),
      kernelGid: process.getgid(),
    }));
    assert.equal(Object.isFrozen(captured), true);
    assert.equal(Object.isFrozen(captured.command), true);
    assert.equal(Object.isFrozen(captured.config), true);
    assert.equal(`${result.stdout}${result.stderr}`.includes(TOKEN), false);
  }
});

test('parser rejects missing operands, unknown or duplicate flags, and noncanonical values with exit 2', async (t) => {
  const invalid = [
    [],
    ['unknown'],
    ['agent', 'revoke'],
    ['agent', 'revoke', 'agent-1', '--confirm', SHA_A, '--surprise'],
    ['agent', 'revoke', 'agent-1', '--confirm', SHA_A, '--confirm', SHA_A],
    ['agent', 'revoke', '../agent', '--confirm', SHA_A],
    ['policy', 'validate', 'relative-policy.json'],
    ['policy', 'apply', '/input/policy.json'],
    ['approvals', 'list', '--state', 'approved'],
    ['approvals', 'deny', 'approval-1', '--confirm', SHA_A, '--reason', 'anything'],
    ['reconcile', 'payment', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B,
      '--payment-transaction', TX_A.toUpperCase()],
    ['reconcile', 'execution', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B,
      '--payment-transaction', TX_A],
    ['reconcile', 'refund-observation', 'intent-1', '--confirm', SHA_A, '--confirm-case', SHA_B],
    ['reconcile', 'abandon-candidate', 'intent-1', '--kind', 'execution',
      '--confirm', SHA_A, '--confirm-case', SHA_B],
    ['receipts', 'list', '--json', '--json'],
    ['export', 'session-1'],
  ];
  for (const argv of invalid) {
    let calls = 0;
    const result = await invoke(t, argv, {
      requestImpl: async () => { calls += 1; return response(); },
      offlineBootstrap: async () => { calls += 1; return {}; },
    });
    assert.equal(result.exitCode, 2, `${argv.join(' ')}: ${result.stderr}`);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /^error: CLI_USAGE\nusage: wallet-kernel /);
    assert.equal(calls, 0);
  }
});

test('parser rejects proxy argv without invoking its traps', async (t) => {
  const fixture = makeFixture(t);
  let trapped = false;
  const argv = new Proxy(['receipts', 'list'], {
    getPrototypeOf() {
      trapped = true;
      throw new Error(`must stay inert ${TOKEN}`);
    },
  });
  const stdout = capture();
  const stderr = capture();
  let calls = 0;
  const exitCode = await runOperatorCli({
    argv,
    env: fixture.env,
    requestImpl: async () => { calls += 1; return response(); },
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  assert.equal(exitCode, 2);
  assert.equal(trapped, false);
  assert.equal(calls, 0);
  assert.equal(stdout.read(), '');
  assert.equal(stderr.read(), `error: CLI_USAGE\nusage: wallet-kernel <command> [options]\n`);
  assert.equal(stderr.read().includes(TOKEN), false);
});

test('--json returns one closed success or usage object', async (t) => {
  const success = await invoke(t, ['receipts', 'list', '--json'], {
    requestImpl: async () => response({ receipts: [] }),
  });
  assert.equal(success.exitCode, 0);
  assert.deepEqual(JSON.parse(success.stdout), {
    command: 'receipts-list',
    ok: true,
    result: { receipts: [] },
  });
  assert.equal(success.stdout.trimEnd().split('\n').length, 1);
  assert.equal(success.stderr, '');

  const usage = await invoke(t, ['receipts', 'list', '--bogus', '--json']);
  assert.equal(usage.exitCode, 2);
  assert.equal(usage.stdout, '');
  assert.deepEqual(JSON.parse(usage.stderr), {
    error: { code: 'CLI_USAGE' },
    ok: false,
  });
});

test('authenticated API failures and transport exceptions are stable, bounded, and redacted', async (t) => {
  for (const [label, requestImpl, expected] of [
    ['api', async () => response({ ok: false, error: { code: 'APPROVAL_STALE', message: TOKEN } }, 409), 'APPROVAL_STALE'],
    ['transport', async () => { const error = new Error(`provider ${TOKEN}`); error.code = 'ECONNREFUSED'; throw error; }, 'OPERATOR_REQUEST_FAILED'],
    ['malformed', async () => ({ status: 500, headers: {}, body: `{\"error\":\"${TOKEN}` }), 'OPERATOR_RESPONSE_INVALID'],
  ]) {
    const result = await invoke(t, ['receipts', 'list'], { requestImpl });
    assert.equal(result.exitCode, 1, label);
    assert.equal(result.stdout, '', label);
    assert.equal(result.stderr, `error: ${expected}\n`, label);
    assert.equal(result.stderr.includes(TOKEN), false, label);
  }
});

test('successful response projections are bounded and fail closed on secret-bearing fields', async (t) => {
  for (const body of [
    { operatorToken: TOKEN },
    { nested: { paymentSignature: '0x1234' } },
    { rows: [{ credential: 'agent-secret' }] },
    { value: TOKEN },
    { nested: { rawEvidence: 'provider material' } },
    { nested: { rawPrompt: 'private prompt' } },
    { nested: { providerSecretValue: 'provider secret' } },
    { nested: { privateKeyHex: '0x1234' } },
    { nested: { accessToken: 'opaque access' } },
    { nested: { seedPhrase: 'wallet words' } },
    { nested: { signature: 'unbound signature' } },
    { tokenContract: 'provider secret' },
    { authorizationState: 'provider secret' },
    { privateKeyHash: SHA_A },
    { operatorTokenHash: SHA_A },
    { content: 'RAW_PRIVATE_PROVIDER_RESPONSE' },
    {
      domain: 'wallet-kernel.projection-export.v1',
      algorithm: 'Ed25519',
      projectionHash: SHA_A,
      signature: Buffer.alloc(64, 0x41).toString('base64'),
    },
  ]) {
    const result = await invoke(t, ['receipts', 'list'], {
      requestImpl: async () => response(body),
    });
    assert.equal(result.exitCode, 1, JSON.stringify(body));
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'error: OPERATOR_RESPONSE_UNSAFE\n');
    assert.equal(`${result.stdout}${result.stderr}`.includes(TOKEN), false);
  }

  const oversized = await invoke(t, ['receipts', 'list'], {
    requestImpl: async () => ({
      status: 200,
      headers: { 'cache-control': 'no-store', 'content-type': 'application/json' },
      body: `{"ok":true,"data":{"value":"${'a'.repeat(1_048_577)}"}}`,
    }),
  });
  assert.equal(oversized.exitCode, 1);
  assert.equal(oversized.stdout, '');
  assert.equal(oversized.stderr, 'error: OPERATOR_RESPONSE_INVALID\n');

  let tooDeep = { leaf: true };
  for (let index = 0; index < 80; index += 1) tooDeep = { nested: tooDeep };
  const deep = await invoke(t, ['receipts', 'list'], {
    requestImpl: async () => response(tooDeep),
  });
  assert.equal(deep.exitCode, 1);
  assert.equal(deep.stdout, '');
  assert.equal(deep.stderr, 'error: OPERATOR_RESPONSE_UNSAFE\n');

  const publicProof = {
    authorizationState: false,
    credentialHash: SHA_A,
    tokenContract: `0x${'12'.repeat(20)}`,
  };
  const publicResult = await invoke(t, ['receipts', 'list', '--json'], {
    requestImpl: async () => response(publicProof),
  });
  assert.equal(publicResult.exitCode, 0, publicResult.stderr);
  assert.deepEqual(JSON.parse(publicResult.stdout).result, publicProof);
});

test('console launch prints only a validated one-time fragment URL', async (t) => {
  const launch = {
    url: `${ORIGIN}/operator/#launch=${Buffer.alloc(32, 0x22).toString('base64url')}`,
    expiresAt: '2026-08-02T00:01:00.000Z',
  };
  const textResult = await invoke(t, ['console', 'launch'], {
    requestImpl: async () => response(launch),
  });
  assert.equal(textResult.exitCode, 0);
  assert.equal(textResult.stdout, `${launch.url}\n`);
  assert.equal(textResult.stderr, '');

  const jsonResult = await invoke(t, ['console', 'launch', '--json'], {
    requestImpl: async () => response(launch),
  });
  assert.deepEqual(JSON.parse(jsonResult.stdout), {
    command: 'console-launch',
    expiresAt: launch.expiresAt,
    ok: true,
    url: launch.url,
  });

  const hostile = await invoke(t, ['console', 'launch'], {
    requestImpl: async () => response({ ...launch, url: `https://evil.example/#launch=${LAUNCH_TOKEN}` }),
  });
  assert.equal(hostile.exitCode, 1);
  assert.equal(hostile.stdout, '');
  assert.equal(hostile.stderr, 'error: OPERATOR_RESPONSE_INVALID\n');
  assert.equal(hostile.stderr.includes(TOKEN), false);
});

test('live mode sends bearer only through a validated owner-only Unix socket', async (t) => {
  const fixture = makeFixture(t, { mode: 'cdp-testnet' });
  fs.writeFileSync(fixture.socketPath, '', { mode: 0o600, flag: 'wx' });
  fs.chmodSync(fixture.socketPath, 0o600);
  fakeSocketMetadata(t, fixture.socketPath);

  const stdout = capture();
  const stderr = capture();
  let captured;
  const exitCode = await runOperatorCli({
    argv: ['receipts', 'list'],
    env: fixture.env,
    requestImpl: async (input) => { captured = input; return response({ receipts: [] }); },
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  assert.equal(exitCode, 0, stderr.read());
  assert.equal(captured.socketPath, fixture.socketPath);
  assert.equal(captured.origin, ORIGIN);
  assert.equal(captured.headers.authorization, `Bearer ${TOKEN}`);
  assert.deepEqual(Object.keys(captured), [
    'socketPath', 'origin', 'method', 'path', 'headers', 'body',
  ]);
});

test('built-in live HTTP adapter pins Host to the authenticated loopback origin over UDS', async (t) => {
  const fixture = makeFixture(t, { mode: 'cdp-testnet' });
  fs.writeFileSync(fixture.socketPath, '', { mode: 0o600, flag: 'wx' });
  fs.chmodSync(fixture.socketPath, 0o600);
  fakeSocketMetadata(t, fixture.socketPath);
  let requestOptions;
  t.mock.method(http, 'request', (options, onResponse) => {
    requestOptions = options;
    const request = new EventEmitter();
    request.write = () => { throw new Error('GET must not have a body'); };
    request.destroy = (error) => request.emit('error', error);
    request.end = () => {
      const result = response({ receipts: [] });
      const incoming = new EventEmitter();
      incoming.statusCode = result.status;
      incoming.headers = result.headers;
      queueMicrotask(() => {
        onResponse(incoming);
        incoming.emit('data', Buffer.from(result.body));
        incoming.emit('end');
      });
    };
    return request;
  });
  const stdout = capture();
  const stderr = capture();
  const exitCode = await runOperatorCli({
    argv: ['receipts', 'list'],
    env: fixture.env,
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  assert.equal(exitCode, 0, stderr.read());
  assert.equal(requestOptions.socketPath, fixture.socketPath);
  assert.equal(requestOptions.hostname, undefined);
  assert.equal(requestOptions.port, undefined);
  assert.equal(requestOptions.headers.host, '127.0.0.1:8405');
  assert.equal(requestOptions.headers.authorization, `Bearer ${TOKEN}`);
});

test('live mode rejects missing, regular, symlink, and permissive socket paths before request', async (t) => {
  for (const socketCase of ['missing', 'regular', 'symlink']) {
    const fixture = makeFixture(t, { mode: 'cdp-testnet' });
    if (socketCase === 'regular') {
      fs.writeFileSync(fixture.socketPath, 'not-a-socket', { mode: 0o600 });
    } else if (socketCase === 'symlink') {
      const target = path.join(fixture.directory, 'target');
      fs.writeFileSync(target, 'not-a-socket', { mode: 0o600 });
      fs.symlinkSync(target, fixture.socketPath);
    }
    let calls = 0;
    const stdout = capture();
    const stderr = capture();
    const exitCode = await runOperatorCli({
      argv: ['receipts', 'list'],
      env: fixture.env,
      requestImpl: async () => { calls += 1; return response(); },
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    assert.equal(exitCode, 1, socketCase);
    assert.equal(stdout.read(), '', socketCase);
    assert.equal(stderr.read(), 'error: OPERATOR_CHANNEL_INVALID\n', socketCase);
    assert.equal(calls, 0, socketCase);
  }

  await t.test('permissive socket metadata', async (t) => {
    const fixture = makeFixture(t, { mode: 'cdp-testnet' });
    fs.writeFileSync(fixture.socketPath, '', { mode: 0o600, flag: 'wx' });
    fs.chmodSync(fixture.socketPath, 0o666);
    fakeSocketMetadata(t, fixture.socketPath);
    let calls = 0;
    const stdout = capture();
    const stderr = capture();
    const exitCode = await runOperatorCli({
      argv: ['receipts', 'list'],
      env: fixture.env,
      requestImpl: async () => { calls += 1; return response(); },
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    assert.equal(exitCode, 1);
    assert.equal(stdout.read(), '');
    assert.equal(stderr.read(), 'error: OPERATOR_CHANNEL_INVALID\n');
    assert.equal(calls, 0);
  });
});

test('owner token authority is strict and never repaired or disclosed', async (t) => {
  for (const [label, mutate] of [
    ['newline', (fixture) => fs.writeFileSync(fixture.tokenPath, `${TOKEN}\n`, { mode: 0o600 })],
    ['non-ASCII alias', (fixture) => {
      const bytes = Buffer.from(TOKEN, 'ascii');
      bytes[0] |= 0x80;
      fs.writeFileSync(fixture.tokenPath, bytes, { mode: 0o600 });
    }],
    ['permissive', (fixture) => fs.chmodSync(fixture.tokenPath, 0o644)],
    ['symlink', (fixture) => {
      fs.unlinkSync(fixture.tokenPath);
      const target = path.join(fixture.directory, 'target-token');
      fs.writeFileSync(target, TOKEN, { mode: 0o600 });
      fs.symlinkSync(target, fixture.tokenPath);
    }],
  ]) {
    const fixture = makeFixture(t);
    mutate(fixture);
    const stdout = capture();
    const stderr = capture();
    let calls = 0;
    const exitCode = await runOperatorCli({
      argv: ['receipts', 'list'],
      env: fixture.env,
      requestImpl: async () => { calls += 1; return response(); },
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    assert.equal(exitCode, 1, label);
    assert.equal(stdout.read(), '', label);
    assert.equal(stderr.read(), 'error: OPERATOR_TOKEN_INVALID\n', label);
    assert.equal(`${stdout.read()}${stderr.read()}`.includes(TOKEN), false, label);
    assert.equal(calls, 0, label);
  }
});

test('export exclusive-creates one owner-only canonical file and never overwrites or follows symlinks', async (t) => {
  const projection = Object.freeze({
    schemaVersion: 1,
    domain: 'wallet-kernel.projection-export.v1',
    projection: Object.freeze({ sessionId: 'session-1', eventHeadHash: SHA_A }),
    projectionHash: SHA_B,
    algorithm: 'Ed25519',
    keyId: SHA_A,
    publicKeyPem: 'PUBLIC KEY',
    signature: Buffer.alloc(64, 0x41).toString('base64'),
  });
  const fixture = makeFixture(t);
  const outputPath = path.join(fixture.directory, 'projection.json');
  const stdout = capture();
  const stderr = capture();
  let calls = 0;
  const run = () => runOperatorCli({
    argv: ['export', 'session-1', '--output', outputPath],
    env: fixture.env,
    requestImpl: async (input) => {
      calls += 1;
      assert.equal(input.path, '/operator/v1/exports/session-1');
      return response(projection);
    },
    stdout: stdout.stream,
    stderr: stderr.stream,
  });
  assert.equal(await run(), 0, stderr.read());
  assert.equal(fs.readFileSync(outputPath, 'utf8'), canonicalJson(projection));
  const stat = fs.lstatSync(outputPath);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.equal(calls, 1);

  const secondOut = capture();
  const secondErr = capture();
  const second = await runOperatorCli({
    argv: ['export', 'session-1', '--output', outputPath],
    env: fixture.env,
    requestImpl: async () => { calls += 1; return response({ changed: true }); },
    stdout: secondOut.stream,
    stderr: secondErr.stream,
  });
  assert.equal(second, 1);
  assert.equal(secondOut.read(), '');
  assert.equal(secondErr.read(), 'error: EXPORT_OUTPUT_UNSAFE\n');
  assert.equal(calls, 1, 'overwrite refusal happens before requesting the export');
  assert.equal(fs.readFileSync(outputPath, 'utf8'), canonicalJson(projection));

  const target = path.join(fixture.directory, 'target.json');
  const symlink = path.join(fixture.directory, 'symlink.json');
  fs.writeFileSync(target, 'unchanged', { mode: 0o600 });
  fs.symlinkSync(target, symlink);
  const symlinkOut = capture();
  const symlinkErr = capture();
  const symlinkExit = await runOperatorCli({
    argv: ['export', 'session-1', '--output', symlink],
    env: fixture.env,
    requestImpl: async () => { calls += 1; return response(projection); },
    stdout: symlinkOut.stream,
    stderr: symlinkErr.stream,
  });
  assert.equal(symlinkExit, 1);
  assert.equal(symlinkErr.read(), 'error: EXPORT_OUTPUT_UNSAFE\n');
  assert.equal(fs.readFileSync(target, 'utf8'), 'unchanged');
  assert.equal(calls, 1);
});

test('offline bootstrap and API failures share stable exit 1 without leaking authority', async (t) => {
  const result = await invoke(t, ['policy', 'apply', '/input/policy.json', '--confirm', SHA_A], {
    offlineBootstrap: async ({ operatorToken }) => {
      const error = new Error(`busy ${operatorToken}`);
      error.code = 'AUTHORITY_BUSY';
      throw error;
    },
  });
  assert.equal(result.exitCode, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, 'error: AUTHORITY_BUSY\n');
  assert.equal(result.stderr.includes(TOKEN), false);
});

test('environment capture accepts known fields but rejects accessors and unknown wallet-kernel fields', async (t) => {
  const fixture = makeFixture(t);
  const unknown = await runWithEnvironment(
    ['receipts', 'list'],
    { ...fixture.env, WALLET_KERNEL_SURPRISE: 'value' },
  );
  assert.equal(unknown.exitCode, 1);
  assert.equal(unknown.stderr, 'error: CLI_CONFIG_INVALID\n');

  const accessor = { ...fixture.env };
  Object.defineProperty(accessor, 'WALLET_KERNEL_MODE', {
    enumerable: true,
    get() { throw new Error(`do not execute ${TOKEN}`); },
  });
  const captured = await runWithEnvironment(['receipts', 'list'], accessor);
  assert.equal(captured.exitCode, 1);
  assert.equal(captured.stderr, 'error: CLI_CONFIG_INVALID\n');
  assert.equal(captured.stderr.includes(TOKEN), false);

  async function runWithEnvironment(argv, env) {
    const stdout = capture();
    const stderr = capture();
    let calls = 0;
    const exitCode = await runOperatorCli({
      argv,
      env,
      requestImpl: async () => { calls += 1; return response(); },
      stdout: stdout.stream,
      stderr: stderr.stream,
    });
    assert.equal(calls, 0);
    return { exitCode, stdout: stdout.read(), stderr: stderr.read() };
  }
});

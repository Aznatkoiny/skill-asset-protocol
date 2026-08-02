import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';
import {
  readTestnetAgentCredential,
  readTestnetRunIntent,
  requestTestnetAgentRoute,
  runTestnetAgent,
  testnetAgentCallId,
  testnetRunIntentDigest,
  validateTestnetRunIntent,
} from '../scripts/run-testnet-agent.mjs';

const NOW = '2026-08-01T12:00:00.000Z';
const AGENT_CALL_ID = Buffer.alloc(32, 0x63).toString('base64url');
const INTENT = Object.freeze({
  schemaVersion: 1,
  domain: 'wallet-kernel.testnet-agent-run.v1',
  runId: 'acceptance-20260801-a',
  createdAt: NOW,
  expiresAt: '2026-08-01T12:10:00.000Z',
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  gitCommit: 'a'.repeat(40),
  deployment: Object.freeze({
    releaseManifestDigest: `sha256:${'1'.repeat(64)}`,
    releaseTreeHash: `sha256:${'2'.repeat(64)}`,
    serviceArtifactsHash: `sha256:${'3'.repeat(64)}`,
    systemdEffectiveConfigHash: `sha256:${'4'.repeat(64)}`,
  }),
  walletAddress: '0x1000000000000000000000000000000000000000',
  policyHash: `sha256:${'5'.repeat(64)}`,
  routeMapHash: `sha256:${'6'.repeat(64)}`,
  maximumTotalAtomic: '100000',
  kernelOrigin: 'http://127.0.0.1:8402',
  kernelIdentity: Object.freeze({ uid: '991', gid: '991' }),
  agentIdentity: Object.freeze({ uid: '992', gid: '992' }),
  credentialDigest: `sha256:${'7'.repeat(64)}`,
  sellerRoutes: Object.freeze([
    Object.freeze({
      routeId: 'example-model',
      kind: 'openai-chat',
      sellerOrigin: 'https://seller.example',
      resourcePath: '/paid/chat/completions',
      model: 'scripted-testnet',
    }),
    Object.freeze({
      routeId: 'example-skill',
      kind: 'tool',
      sellerOrigin: 'https://seller.example',
      resourcePath: '/paid/skill',
      model: null,
    }),
  ]),
});

function temporaryDirectory(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'testnet-agent-runner-')));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeIntent(t) {
  const root = temporaryDirectory(t);
  const outbox = path.join(root, 'agent-run-outbox');
  fs.mkdirSync(outbox, { mode: 0o755 });
  fs.chmodSync(outbox, 0o755);
  const intent = {
    ...INTENT,
    kernelIdentity: { uid: String(process.getuid()), gid: String(process.getgid()) },
    agentIdentity: { uid: String(process.getuid() + 1), gid: String(process.getgid() + 1) },
  };
  const filePath = path.join(outbox, 'acceptance-20260801-a.json');
  fs.writeFileSync(filePath, `${canonicalJson(intent)}\n`, { flag: 'wx', mode: 0o644 });
  fs.chmodSync(filePath, 0o644);
  return { root, outbox, filePath, intent };
}

function writeCredential(t) {
  const root = temporaryDirectory(t);
  const privateDirectory = path.join(root, 'agent-private');
  fs.mkdirSync(privateDirectory, { mode: 0o700 });
  fs.chmodSync(privateDirectory, 0o700);
  const tokenBytes = Buffer.alloc(32, 0x42);
  const credential = {
    agentInstanceId: Buffer.alloc(16, 0x24).toString('base64url'),
    schemaVersion: 1,
    token: tokenBytes.toString('base64url'),
  };
  const credentialDigest = sha256(tokenBytes);
  tokenBytes.fill(0);
  const filePath = path.join(privateDirectory, 'agent-credential.json');
  fs.writeFileSync(filePath, `${canonicalJson(credential)}\n`, { flag: 'wx', mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
  return { privateDirectory, filePath, credential, credentialDigest };
}

test('testnet run intent is closed, Base Sepolia-only, and bound to canonical confirmation', () => {
  const validated = validateTestnetRunIntent(INTENT, { now: NOW });
  assert.deepEqual(validated, INTENT);
  assert.equal(testnetRunIntentDigest(validated), sha256(canonicalJson(INTENT)));

  assert.throws(
    () => validateTestnetRunIntent({ ...INTENT, network: 'eip155:8453' }, { now: NOW }),
    { code: 'TESTNET_RUN_INTENT_NETWORK' },
  );
  assert.throws(
    () => validateTestnetRunIntent({ ...INTENT, unexpected: true }, { now: NOW }),
    { code: 'TESTNET_RUN_INTENT_SCHEMA' },
  );
});

test('testnet route call IDs are stable per confirmed run and distinct per route', () => {
  const digest = testnetRunIntentDigest(INTENT);
  const model = testnetAgentCallId(digest, 'example-model');
  assert.match(model, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(testnetAgentCallId(digest, 'example-model'), model);
  assert.notEqual(testnetAgentCallId(digest, 'example-skill'), model);
  assert.throws(() => testnetAgentCallId(digest, '../escape'), {
    code: 'TESTNET_AGENT_REQUEST',
  });
});

test('Agent reads one canonical Kernel-owned run intent from the exact public outbox', (t) => {
  const fixture = writeIntent(t);
  const result = readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(fixture.intent),
    now: NOW,
  });
  assert.deepEqual(result, {
    intent: fixture.intent,
    intentDigest: testnetRunIntentDigest(fixture.intent),
  });
});

test('Agent rejects a stale human confirmation before using a run intent', (t) => {
  const fixture = writeIntent(t);
  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: `sha256:${'0'.repeat(64)}`,
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_CONFIRMATION' });
});

test('external confirmation authenticates the declared Kernel owner before it is trusted', (t) => {
  const fixture = writeIntent(t);
  const substituted = {
    ...fixture.intent,
    kernelIdentity: {
      uid: String(process.getuid() + 100),
      gid: String(process.getgid() + 100),
    },
  };
  fs.writeFileSync(fixture.filePath, `${canonicalJson(substituted)}\n`, { mode: 0o644 });

  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(fixture.intent),
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_CONFIRMATION' });
  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(substituted),
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_AUTHORITY' });
});

test('Agent rejects a writable run-intent outbox', (t) => {
  const fixture = writeIntent(t);
  fs.chmodSync(fixture.outbox, 0o775);
  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(fixture.intent),
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_AUTHORITY' });
});

test('Agent rejects a run-intent file with private or mutable publication mode', (t) => {
  const fixture = writeIntent(t);
  fs.chmodSync(fixture.filePath, 0o600);
  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(fixture.intent),
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_AUTHORITY' });
});

test('Agent rejects a symlink in place of the Kernel run-intent file', (t) => {
  const fixture = writeIntent(t);
  const backing = path.join(fixture.root, 'backing-intent.json');
  fs.renameSync(fixture.filePath, backing);
  fs.symlinkSync(backing, fixture.filePath);
  assert.throws(() => readTestnetRunIntent({
    filePath: fixture.filePath,
    outboxPath: fixture.outbox,
    expectedDigest: testnetRunIntentDigest(fixture.intent),
    now: NOW,
  }), { code: 'TESTNET_RUN_INTENT_FILE' });
});

test('Agent reads only its own bound credential from a separate private parent', (t) => {
  const fixture = writeCredential(t);
  const result = readTestnetAgentCredential({
    filePath: fixture.filePath,
    expectedDigest: fixture.credentialDigest,
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
  });
  assert.deepEqual(result, fixture.credential);
});

test('Agent rejects a persisted credential instance ID beginning with punctuation', (t) => {
  const fixture = writeCredential(t);
  const credential = {
    ...fixture.credential,
    agentInstanceId: `_${fixture.credential.agentInstanceId.slice(1)}`,
  };
  fs.writeFileSync(fixture.filePath, `${canonicalJson(credential)}\n`, { mode: 0o600 });
  assert.throws(() => readTestnetAgentCredential({
    filePath: fixture.filePath,
    expectedDigest: fixture.credentialDigest,
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
  }), { code: 'TESTNET_AGENT_CREDENTIAL' });
});

test('enrolled Agent drives only confirmed ordinary routes and returns no credential', async () => {
  const credential = {
    agentInstanceId: Buffer.alloc(16, 0x24).toString('base64url'),
    schemaVersion: 1,
    token: Buffer.alloc(32, 0x42).toString('base64url'),
  };
  const observed = [];
  const result = await runTestnetAgent({
    argv: ['--run-intent', '/kernel-outbox/run.json', '--confirm-sha256',
      testnetRunIntentDigest(INTENT)],
    environment: {
      WALLET_KERNEL_AGENT_RUN_OUTBOX: '/kernel-outbox',
      WALLET_KERNEL_AGENT_CREDENTIAL_FILE: '/agent-private/credential.json',
    },
    now: () => NOW,
    platform: 'linux',
    getuid: () => 992,
    getgid: () => 992,
    getgroups: () => [992],
    readRunIntent: () => ({ intent: INTENT, intentDigest: testnetRunIntentDigest(INTENT) }),
    readCredential: () => credential,
    requestRoute: async (request) => {
      observed.push(request);
      return { httpStatus: 200, outcome: 'completed' };
    },
  });

  assert.deepEqual(result, {
    status: 'completed',
    mode: 'base-sepolia-testnet',
    runId: INTENT.runId,
    intentDigest: testnetRunIntentDigest(INTENT),
    routeCount: 2,
    routes: [
      { routeId: 'example-model', kind: 'openai-chat', httpStatus: 200, outcome: 'completed' },
      { routeId: 'example-skill', kind: 'tool', httpStatus: 200, outcome: 'completed' },
    ],
  });
  assert.deepEqual(observed.map(({ origin, route, token }) => ({
    origin,
    routeId: route.routeId,
    tokenMatches: token === credential.token,
  })), [
    { origin: INTENT.kernelOrigin, routeId: 'example-model', tokenMatches: true },
    { origin: INTENT.kernelOrigin, routeId: 'example-skill', tokenMatches: true },
  ]);
  assert.deepEqual(observed.map(({ route, agentCallId }) => ({
    routeId: route.routeId,
    agentCallId,
  })), INTENT.sellerRoutes.map((route) => ({
    routeId: route.routeId,
    agentCallId: testnetAgentCallId(testnetRunIntentDigest(INTENT), route.routeId),
  })));
  assert.equal(JSON.stringify(result).includes(credential.token), false);
});

test('Agent identity mismatch fails before credential access or route execution', async () => {
  let credentialReads = 0;
  let routeRequests = 0;
  await assert.rejects(runTestnetAgent({
    argv: ['--run-intent', '/kernel-outbox/run.json', '--confirm-sha256',
      testnetRunIntentDigest(INTENT)],
    environment: {
      WALLET_KERNEL_AGENT_RUN_OUTBOX: '/kernel-outbox',
      WALLET_KERNEL_AGENT_CREDENTIAL_FILE: '/agent-private/credential.json',
    },
    now: () => NOW,
    platform: 'linux',
    getuid: () => 993,
    getgid: () => 992,
    getgroups: () => [992],
    readRunIntent: () => ({ intent: INTENT, intentDigest: testnetRunIntentDigest(INTENT) }),
    readCredential: () => { credentialReads += 1; },
    requestRoute: async () => { routeRequests += 1; },
  }), { code: 'TESTNET_AGENT_IDENTITY' });
  assert.equal(credentialReads, 0);
  assert.equal(routeRequests, 0);
});

test('Agent refuses wallet authority material in its environment before reading files', async () => {
  let runIntentReads = 0;
  await assert.rejects(runTestnetAgent({
    argv: ['--run-intent', '/kernel-outbox/run.json', '--confirm-sha256',
      testnetRunIntentDigest(INTENT)],
    environment: {
      CDP_API_KEY_SECRET: 'must-not-cross-the-Agent-boundary',
      WALLET_KERNEL_AGENT_RUN_OUTBOX: '/kernel-outbox',
      WALLET_KERNEL_AGENT_CREDENTIAL_FILE: '/agent-private/credential.json',
    },
    readRunIntent: () => { runIntentReads += 1; },
  }), { code: 'TESTNET_AGENT_ENVIRONMENT' });
  assert.equal(runIntentReads, 0);
});

test('ordinary Agent route calls only the loopback Kernel once with a bounded fixed request', async () => {
  const requests = [];
  const token = Buffer.alloc(32, 0x42).toString('base64url');
  const outcome = await requestTestnetAgentRoute({
    origin: INTENT.kernelOrigin,
    token,
    route: INTENT.sellerRoutes[0],
    agentCallId: AGENT_CALL_ID,
    fetchFn: async (url, options) => {
      requests.push({ url, options });
      return new Response(canonicalJson({ status: 'completed' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  assert.deepEqual(outcome, { httpStatus: 200, outcome: 'completed' });
  assert.equal(requests.length, 1);
  assert.equal(
    requests[0].url,
    'http://127.0.0.1:8402/agent/v1/openai/example-model/chat/completions',
  );
  assert.equal(requests[0].url.includes(INTENT.sellerRoutes[0].sellerOrigin), false);
  assert.equal(requests[0].options.redirect, 'manual');
  assert.equal(requests[0].options.credentials, 'omit');
  assert.deepEqual(JSON.parse(requests[0].options.body), {
    messages: [{ content: 'Reply exactly WALLET_KERNEL_TESTNET_OK.', role: 'user' }],
    model: 'scripted-testnet',
    stream: false,
  });
  assert.equal(requests[0].options.headers.authorization, `WalletKernelAgent ${token}`);
  assert.equal(requests[0].options.headers['x-agent-call-id'], AGENT_CALL_ID);
});

test('Agent route failure is returned after one attempt and never retried', async () => {
  let requests = 0;
  await assert.rejects(requestTestnetAgentRoute({
    origin: INTENT.kernelOrigin,
    token: Buffer.alloc(32, 0x42).toString('base64url'),
    route: INTENT.sellerRoutes[1],
    agentCallId: AGENT_CALL_ID,
    fetchFn: async () => {
      requests += 1;
      return new Response(canonicalJson({ status: 'payment_failed' }), {
        status: 502,
        headers: { 'content-type': 'application/json' },
      });
    },
  }), { code: 'TESTNET_AGENT_RESPONSE' });
  assert.equal(requests, 1);
});

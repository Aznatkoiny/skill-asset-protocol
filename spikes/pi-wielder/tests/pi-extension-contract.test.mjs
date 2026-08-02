import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import activate, {
  loadPiExtensionConfiguration,
  readPiAgentCredential,
  renderWalletKernelOutcome,
} from '../pi-extension/x402.ts';

const RAW_PROMPT_SENTINEL = 'RAW_PROMPT_SENTINEL';
const PROVIDER_EXCEPTION_SENTINEL = 'PROVIDER_EXCEPTION_SENTINEL';
const HASH = 'a'.repeat(64);
const TOKEN = Buffer.alloc(32, 0x22).toString('base64url');
const CREDENTIAL = Object.freeze({
  agentInstanceId: Buffer.alloc(16, 0x11).toString('base64url'),
  schemaVersion: 1,
  token: TOKEN,
});
const CREDENTIAL_TEXT = `{"agentInstanceId":"${CREDENTIAL.agentInstanceId}","schemaVersion":1,"token":"${TOKEN}"}\n`;

function toolAgentCallId(toolCallId) {
  return crypto.createHash('sha256')
    .update('wallet-kernel.pi-tool-call.v1\0', 'utf8')
    .update(toolCallId, 'utf8')
    .digest('base64url');
}

function temporaryCredential(t) {
  const directory = fs.realpathSync(
    fs.mkdtempSync(path.join(os.tmpdir(), 'pi-agent-extension-')),
  );
  fs.chmodSync(directory, 0o700);
  const filePath = path.join(directory, 'agent.json');
  fs.writeFileSync(filePath, CREDENTIAL_TEXT, { mode: 0o600 });
  fs.chmodSync(filePath, 0o600);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return filePath;
}

function environment(credentialPath, overrides = {}) {
  return Object.freeze({
    WALLET_KERNEL_ORIGIN: 'http://127.0.0.1:8402',
    WALLET_KERNEL_AGENT_CREDENTIAL_FILE: credentialPath,
    WALLET_KERNEL_PROVIDER_NAME: 'wallet-kernel-e2e',
    WALLET_KERNEL_MODEL_NAME: 'scripted-local',
    WALLET_KERNEL_MODEL_ROUTE: 'example-model',
    WALLET_KERNEL_SKILL_ROUTE: 'example-skill',
    ...overrides,
  });
}

function receipt(overrides = {}) {
  return Object.freeze({
    id: 'receipt_public_1',
    hash: HASH,
    sellerOrigin: 'https://seller.example',
    chargedAtomic: '1200',
    remainingSessionAtomic: '8800',
    terminalState: 'completed',
    transactionPrefix: '0x1234567890',
    ...overrides,
  });
}

test('Pi extension statically exposes only fixed Wallet Kernel routes and ordinary auth', () => {
  const source = fs.readFileSync(new URL('../pi-extension/x402.ts', import.meta.url), 'utf8');
  assert.match(source, /\/agent\/v1\/openai\//);
  assert.match(source, /\/agent\/v1\/invoke\//);
  assert.match(source, /WalletKernelAgent/);
  assert.match(source, /O_NOFOLLOW/);
  assert.doesNotMatch(source, /@coinbase|@x402|awal|src\/proxy|src\/gateway/i);
  for (const forbiddenHeader of [
    'x-payment',
    'payment-signature',
    'x-idempotency-key',
    'idempotency-key',
    'x-session-id',
    'x-approval-id',
    'x-wallet-address',
    'x-payee',
  ]) {
    assert.equal(source.toLowerCase().includes(`"${forbiddenHeader}"`), false);
  }
  assert.doesNotMatch(
    source,
    /setInterval|window\.open|\/operator\/|\/ledger|appendEntry|registerCommand/,
  );

  const envSource = fs.readFileSync(
    new URL('../pi-extension/agent.env.example', import.meta.url),
    'utf8',
  );
  assert.equal(envSource, [
    'WALLET_KERNEL_ORIGIN=',
    'WALLET_KERNEL_AGENT_CREDENTIAL_FILE=',
    'WALLET_KERNEL_PROVIDER_NAME=',
    'WALLET_KERNEL_MODEL_NAME=',
    'WALLET_KERNEL_MODEL_ROUTE=',
    'WALLET_KERNEL_SKILL_ROUTE=',
    '',
  ].join('\n'));
});

test('hostile or noncanonical origins fail before credential authority is read', () => {
  let reads = 0;
  for (const origin of [
    'https://127.0.0.1:8402',
    'http://localhost:8402',
    'http://127.0.0.2:8402',
    'http://user:password@127.0.0.1:8402',
    'http://127.0.0.1:8402/path',
    'http://127.0.0.1:8402?query=1',
    'http://127.0.0.1:8402#fragment',
    'http://127.0.0.1',
    'http://127.0.0.1:080',
  ]) {
    assert.throws(() => loadPiExtensionConfiguration({
      env: environment('/private/credential.json', { WALLET_KERNEL_ORIGIN: origin }),
      readCredential() {
        reads += 1;
        return CREDENTIAL;
      },
    }), (error) => error?.code === 'PI_KERNEL_ORIGIN_INVALID');
  }
  assert.equal(reads, 0);

  for (const origin of ['http://127.0.0.1:8402', 'http://[::1]:8402']) {
    const config = loadPiExtensionConfiguration({
      env: environment('/private/credential.json', { WALLET_KERNEL_ORIGIN: origin }),
      readCredential() {
        reads += 1;
        return CREDENTIAL;
      },
    });
    assert.equal(config.origin, origin);
  }
  assert.equal(reads, 2);
});

test('route, provider, and model names are bounded tokens and never URLs', () => {
  let reads = 0;
  for (const [field, invalid] of [
    ['WALLET_KERNEL_PROVIDER_NAME', 'https://provider.example'],
    ['WALLET_KERNEL_MODEL_NAME', '../model'],
    ['WALLET_KERNEL_MODEL_ROUTE', 'example-model/path'],
    ['WALLET_KERNEL_SKILL_ROUTE', 'example-skill?target=https://seller.example'],
    ['WALLET_KERNEL_SKILL_ROUTE', 'x'.repeat(65)],
  ]) {
    assert.throws(() => loadPiExtensionConfiguration({
      env: environment('/private/credential.json', { [field]: invalid }),
      readCredential() {
        reads += 1;
        return CREDENTIAL;
      },
    }), (error) => error?.code === 'PI_KERNEL_TOKEN_INVALID');
  }
  assert.equal(reads, 0);
});

test('credential is opened once with NOFOLLOW and parsed from the held owner-only inode', (t) => {
  const filePath = temporaryCredential(t);
  const calls = [];
  const fileSystem = Object.freeze({
    constants: fs.constants,
    openSync(target, flags) {
      calls.push({ operation: 'open', target, flags });
      return fs.openSync(target, flags);
    },
    fstatSync(descriptor, options) {
      calls.push({ operation: 'fstat', descriptor });
      return fs.fstatSync(descriptor, options);
    },
    readSync(...args) {
      calls.push({ operation: 'read', descriptor: args[0] });
      return fs.readSync(...args);
    },
    closeSync(descriptor) {
      calls.push({ operation: 'close', descriptor });
      return fs.closeSync(descriptor);
    },
  });

  const credential = readPiAgentCredential({
    filePath,
    fileSystem,
    getuid: () => process.getuid(),
  });
  assert.deepEqual(credential, CREDENTIAL);
  const opens = calls.filter((call) => call.operation === 'open');
  assert.equal(opens.length, 1);
  assert.equal(opens[0].target, filePath);
  assert.notEqual(opens[0].flags & fs.constants.O_NOFOLLOW, 0);
  const descriptors = new Set(
    calls.filter((call) => ['fstat', 'read', 'close'].includes(call.operation))
      .map((call) => call.descriptor),
  );
  assert.equal(descriptors.size, 1);
});

test('credential reader rejects root, wrong owner, permissive files, symlinks, and noncanonical bytes', (t) => {
  const filePath = temporaryCredential(t);
  assert.throws(() => readPiAgentCredential({
    filePath,
    getuid: () => 0,
  }), (error) => error?.code === 'PI_AGENT_IDENTITY_INVALID');
  assert.throws(() => readPiAgentCredential({
    filePath,
    getuid: () => process.getuid() + 1,
  }), (error) => error?.code === 'PI_AGENT_CREDENTIAL_AUTHORITY');

  fs.chmodSync(filePath, 0o640);
  assert.throws(() => readPiAgentCredential({ filePath }),
    (error) => error?.code === 'PI_AGENT_CREDENTIAL_AUTHORITY');
  fs.chmodSync(filePath, 0o600);

  const linkPath = `${filePath}.link`;
  fs.symlinkSync(filePath, linkPath);
  assert.throws(() => readPiAgentCredential({ filePath: linkPath }),
    (error) => error?.code === 'PI_AGENT_CREDENTIAL_OPEN');

  fs.writeFileSync(filePath, `${JSON.stringify({
    schemaVersion: 1,
    agentInstanceId: CREDENTIAL.agentInstanceId,
    token: CREDENTIAL.token,
  })}\n`, { mode: 0o600 });
  assert.throws(() => readPiAgentCredential({ filePath }),
    (error) => error?.code === 'PI_AGENT_CREDENTIAL_SCHEMA');
});

test('activation registers one fixed provider and one fixed Skill route with only ordinary headers', async (t) => {
  const credentialPath = temporaryCredential(t);
  const providers = [];
  const tools = [];
  const commands = [];
  const requests = [];
  const handlers = new Map();
  const pi = {
    registerProvider(name, config) { providers.push({ name, config }); },
    registerTool(tool) { tools.push(tool); },
    registerCommand(name, command) { commands.push({ name, command }); },
    on(name, handler) { handlers.set(name, handler); },
  };
  const completed = {
    status: 'completed',
    requestId: 'request_public_1',
    resource: {
      httpStatus: 200,
      contentType: 'application/json',
      body: { output: 'optimized' },
    },
    receipt: receipt(),
  };

  activate(pi, {
    env: environment(credentialPath),
    fetchFn: async (url, options) => {
      requests.push({ url, options });
      return new Response(JSON.stringify(completed), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  assert.equal(providers.length, 1);
  assert.equal(providers[0].name, 'wallet-kernel-e2e');
  assert.equal(providers[0].config.baseUrl, 'http://127.0.0.1:8402/agent/v1/openai/example-model');
  assert.equal(providers[0].config.api, 'openai-completions');
  assert.equal(providers[0].config.authHeader, false);
  assert.deepEqual(providers[0].config.headers, {
    Authorization: `WalletKernelAgent ${TOKEN}`,
    'Content-Type': 'application/json',
  });
  assert.equal(providers[0].config.models.length, 1);
  assert.equal(providers[0].config.models[0].id, 'scripted-local');
  assert.deepEqual(providers[0].config.models[0].compat, {
    sendSessionAffinityHeaders: false,
  });
  assert.equal(tools.length, 1);
  assert.equal(commands.length, 0);
  assert.deepEqual([...handlers.keys()].sort(), [
    'agent_settled', 'before_provider_headers', 'message_end',
  ]);
  assert.equal(/\bskillId\b/.test(tools[0].execute.toString()), false);
  assert.equal(tools[0].execute.length, 5);

  const controller = new AbortController();
  const toolCallId = 'call_invoke_skill_1';
  const output = await tools[0].execute(
    toolCallId,
    { input: 'ordinary input' },
    controller.signal,
    undefined,
    Object.freeze({}),
  );
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, 'http://127.0.0.1:8402/agent/v1/invoke/example-skill');
  assert.equal(requests[0].options.method, 'POST');
  assert.deepEqual(requests[0].options.headers, {
    Authorization: `WalletKernelAgent ${TOKEN}`,
    'Content-Type': 'application/json',
    'x-agent-call-id': toolAgentCallId(toolCallId),
  });
  assert.equal(requests[0].options.signal, controller.signal);
  assert.deepEqual(JSON.parse(requests[0].options.body), { input: 'ordinary input' });
  assert.deepEqual(output, {
    content: [{
      type: 'text',
      text: `optimized\n\n[completed · receipt receipt_public_1 · sha256:${'a'.repeat(12)}… · charged 1200 atomic · remaining 8800 atomic · tx 0x1234567890]`,
    }],
    details: { boundaryStatus: 'returned' },
  });
});

test('model request keys survive transient retry and rotate only on success or final failure', (t) => {
  const credentialPath = temporaryCredential(t);
  const handlers = new Map();
  activate({
    registerProvider() {},
    registerTool() {},
    on(name, handler) { handlers.set(name, handler); },
  }, { env: environment(credentialPath) });

  const providerHeaders = () => ({
    type: 'before_provider_headers',
    headers: {
      Authorization: `WalletKernelAgent ${TOKEN}`,
      Prefer: 'wait=999',
    },
  });
  const first = providerHeaders();
  handlers.get('before_provider_headers')(first, Object.freeze({}));
  const firstId = first.headers['x-agent-call-id'];
  assert.match(firstId, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(Buffer.from(firstId, 'base64url').length, 32);
  assert.equal(Object.hasOwn(first.headers, 'Prefer'), false);

  handlers.get('message_end')({
    type: 'message_end',
    message: {
      role: 'assistant',
      provider: 'wallet-kernel-e2e',
      model: 'scripted-local',
      stopReason: 'error',
    },
  }, Object.freeze({}));
  const transientRetry = providerHeaders();
  handlers.get('before_provider_headers')(transientRetry, Object.freeze({}));
  assert.equal(transientRetry.headers['x-agent-call-id'], firstId);

  handlers.get('message_end')({
    type: 'message_end',
    message: {
      role: 'assistant',
      provider: 'another-provider',
      model: 'scripted-local',
      stopReason: 'stop',
    },
  }, Object.freeze({}));
  const afterUnrelatedSuccess = providerHeaders();
  handlers.get('before_provider_headers')(afterUnrelatedSuccess, Object.freeze({}));
  assert.equal(afterUnrelatedSuccess.headers['x-agent-call-id'], firstId);

  handlers.get('message_end')({
    type: 'message_end',
    message: {
      role: 'assistant',
      provider: 'wallet-kernel-e2e',
      model: 'scripted-local',
      stopReason: 'toolUse',
    },
  }, Object.freeze({}));
  const afterSuccess = providerHeaders();
  handlers.get('before_provider_headers')(afterSuccess, Object.freeze({}));
  const secondId = afterSuccess.headers['x-agent-call-id'];
  assert.notEqual(secondId, firstId);

  handlers.get('agent_settled')({ type: 'agent_settled' }, Object.freeze({}));
  const afterFinalFailure = providerHeaders();
  handlers.get('before_provider_headers')(afterFinalFailure, Object.freeze({}));
  assert.notEqual(afterFinalFailure.headers['x-agent-call-id'], secondId);

  const unrelated = {
    type: 'before_provider_headers',
    headers: { Authorization: 'Bearer external-provider-secret' },
  };
  handlers.get('before_provider_headers')(unrelated, Object.freeze({}));
  assert.equal(Object.hasOwn(unrelated.headers, 'x-agent-call-id'), false);
});

test('tool call IDs are validated before fetch and cancellation propagates through the real ABI', async (t) => {
  const credentialPath = temporaryCredential(t);
  const tools = [];
  let fetchCalls = 0;
  activate({
    registerProvider() {},
    registerTool(tool) { tools.push(tool); },
    on() {},
  }, {
    env: environment(credentialPath),
    fetchFn: async () => {
      fetchCalls += 1;
      throw new Error('fetch must not run');
    },
  });

  const rejected = await tools[0].execute(
    'duplicate,call-id',
    { input: 'ordinary input' },
    undefined,
    undefined,
    Object.freeze({}),
  );
  assert.deepEqual(rejected, {
    content: [{ type: 'text', text: 'invoke_skill call rejected.' }],
    details: { boundaryStatus: 'rejected' },
  });
  assert.equal(fetchCalls, 0);

  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    tools[0].execute(
      'call_invoke_skill_aborted',
      { input: 'ordinary input' },
      controller.signal,
      undefined,
      Object.freeze({}),
    ),
    (error) => error?.name === 'AbortError',
  );
  assert.equal(fetchCalls, 0);
});

test('one controlled tool retry reuses its call key and renders terminal replay without spending again', async (t) => {
  const credentialPath = temporaryCredential(t);
  const tools = [];
  const requests = [];
  const replay = {
    status: 'completed_replay',
    terminalStatus: 'completed',
    requestId: 'request_public_1',
    reasonCode: 'PAYMENT_SETTLED',
    projections: {
      request: '/agent/v1/intents/request_public_1',
      receipt: '/agent/v1/receipts/receipt_public_1',
    },
    receipt: receipt(),
  };
  activate({
    registerProvider() {},
    registerTool(tool) { tools.push(tool); },
    on() {},
  }, {
    env: environment(credentialPath),
    fetchFn: async (url, options) => {
      requests.push({ url, options });
      if (requests.length === 1) {
        throw new TypeError('simulated response transport loss');
      }
      return new Response(JSON.stringify(replay), {
        status: 409,
        headers: { 'content-type': 'application/json' },
      });
    },
  });
  const output = await tools[0].execute(
    'call_paid_response_lost',
    { input: 'ordinary input' },
    undefined,
    undefined,
    Object.freeze({}),
  );

  assert.equal(requests.length, 2);
  assert.equal(
    requests[0].options.headers['x-agent-call-id'],
    requests[1].options.headers['x-agent-call-id'],
  );
  assert.equal(
    requests[0].options.headers['x-agent-call-id'],
    toolAgentCallId('call_paid_response_lost'),
  );
  assert.deepEqual(output, {
    content: [{
      type: 'text',
      text: `Completed replay: the charge is already recorded, provider output was not retained, and retrying this same call key will not spend again. Inspect /agent/v1/intents/request_public_1 and /agent/v1/receipts/receipt_public_1. receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`,
    }],
    details: { boundaryStatus: 'returned' },
  });
});

test('returned invalid Kernel content is never retried as a transport loss', async (t) => {
  for (const fixture of [
    {
      label: 'invalid content type',
      response: () => new Response('not-json', {
        status: 502,
        headers: { 'content-type': 'text/plain' },
      }),
    },
    {
      label: 'malformed JSON',
      response: () => new Response('not-json', {
        status: 502,
        headers: { 'content-type': 'application/json' },
      }),
    },
  ]) {
    await t.test(fixture.label, async (st) => {
      const credentialPath = temporaryCredential(st);
      const tools = [];
      let fetchCalls = 0;
      activate({
        registerProvider() {},
        registerTool(tool) { tools.push(tool); },
        on() {},
      }, {
        env: environment(credentialPath),
        fetchFn: async () => {
          fetchCalls += 1;
          return fixture.response();
        },
      });

      await assert.rejects(
        tools[0].execute(
          `call_invalid_kernel_response_${fetchCalls}`,
          { input: 'ordinary input' },
          undefined,
          undefined,
          Object.freeze({}),
        ),
        (error) => error?.code === 'PI_KERNEL_RESPONSE_INVALID',
      );
      assert.equal(fetchCalls, 1);
    });
  }
});

test('a Kernel response-body transport loss receives one same-key retry', async (t) => {
  const credentialPath = temporaryCredential(t);
  const tools = [];
  const requests = [];
  const replay = {
    status: 'completed_replay',
    terminalStatus: 'completed',
    requestId: 'request_public_1',
    reasonCode: 'PAYMENT_SETTLED',
    projections: {
      request: '/agent/v1/intents/request_public_1',
      receipt: '/agent/v1/receipts/receipt_public_1',
    },
    receipt: receipt(),
  };
  activate({
    registerProvider() {},
    registerTool(tool) { tools.push(tool); },
    on() {},
  }, {
    env: environment(credentialPath),
    fetchFn: async (url, options) => {
      requests.push({ url, options });
      if (requests.length === 1) {
        return {
          headers: new Headers({ 'content-type': 'application/json' }),
          async text() { throw new TypeError('simulated body transport loss'); },
        };
      }
      return new Response(JSON.stringify(replay), {
        status: 409,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const output = await tools[0].execute(
    'call_paid_body_lost',
    { input: 'ordinary input' },
    undefined,
    undefined,
    Object.freeze({}),
  );

  assert.equal(requests.length, 2);
  assert.equal(
    requests[0].options.headers['x-agent-call-id'],
    requests[1].options.headers['x-agent-call-id'],
  );
  assert.deepEqual(output.details, { boundaryStatus: 'returned' });
  assert.match(output.content[0].text, /^Completed replay:/u);
});

test('application approval and denial responses never trigger a Skill transport retry', async (t) => {
  for (const fixture of [
    {
      label: 'approval',
      httpStatus: 409,
      outcome: {
        status: 'payment_approval_required',
        requestId: 'request_public_1',
        approval: {
          expiresAt: '2026-08-01T12:00:00.000Z',
          amountAtomic: '1200',
          sellerOrigin: 'https://seller.example',
          purposeLabel: 'skill.invoke',
        },
      },
      output: /^Approval required:/u,
    },
    {
      label: 'denial',
      httpStatus: 403,
      outcome: {
        status: 'payment_denied',
        requestId: 'request_public_1',
        reasonCode: 'OPERATOR_DENIED',
        receipt: receipt(),
      },
      output: /^Payment denied:/u,
    },
  ]) {
    await t.test(fixture.label, async (st) => {
      const credentialPath = temporaryCredential(st);
      const tools = [];
      let fetchCalls = 0;
      activate({
        registerProvider() {},
        registerTool(tool) { tools.push(tool); },
        on() {},
      }, {
        env: environment(credentialPath),
        fetchFn: async () => {
          fetchCalls += 1;
          return new Response(JSON.stringify(fixture.outcome), {
            status: fixture.httpStatus,
            headers: { 'content-type': 'application/json' },
          });
        },
      });

      const output = await tools[0].execute(
        `call_application_${fixture.label}`,
        { input: 'ordinary input' },
        undefined,
        undefined,
        Object.freeze({}),
      );
      assert.equal(fetchCalls, 1);
      assert.deepEqual(output.details, { boundaryStatus: 'returned' });
      assert.match(output.content[0].text, fixture.output);
    });
  }
});

test('stable outcome rendering separates approval, denial, expiry, failure, refund, and uncertainty', () => {
  const publicReceipt = receipt();
  const cases = [
    [{
      status: 'payment_approval_required',
      requestId: 'request_public_1',
      approval: {
        expiresAt: '2026-08-01T12:00:00.000Z',
        amountAtomic: '1200',
        sellerOrigin: 'https://seller.example',
        purposeLabel: 'skill.invoke',
      },
    }, 'Approval required: https://seller.example · 1200 atomic · skill.invoke · expires 2026-08-01T12:00:00.000Z. Retry the same tool call after an operator decision.'],
    [{ status: 'payment_denied', requestId: 'request_public_1', reasonCode: 'POLICY_DENIED', receipt: publicReceipt }, `Payment denied: POLICY_DENIED · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'payment_rejected', requestId: 'request_public_1', reasonCode: 'APPROVAL_EXPIRED', receipt: publicReceipt }, `Payment rejected or expired: APPROVAL_EXPIRED · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'payment_failed', requestId: 'request_public_1', reasonCode: 'SIGNER_FAILED', receipt: publicReceipt }, `Payment failed before settlement: SIGNER_FAILED · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'upstream_failed', requestId: 'request_public_1', reasonCode: 'SELLER_UNAVAILABLE', receipt: publicReceipt }, `Upstream failed before payment: SELLER_UNAVAILABLE · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'execution_failed', requestId: 'request_public_1', reasonCode: 'UPSTREAM_HTTP_500', receipt: publicReceipt }, `Execution failed after settlement: UPSTREAM_HTTP_500 · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'execution_unknown', requestId: 'request_public_1', reasonCode: 'RESPONSE_BODY_LOST', receipt: publicReceipt }, `Execution outcome unknown after settlement: RESPONSE_BODY_LOST · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'payment_unresolved', requestId: 'request_public_1', reasonCode: 'SETTLEMENT_UNRESOLVED', receipt: publicReceipt }, `Payment unresolved: SETTLEMENT_UNRESOLVED · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{ status: 'refunded', requestId: 'request_public_1', reasonCode: 'REFUND_CONFIRMED', receipt: publicReceipt }, `Refunded: REFUND_CONFIRMED · receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
    [{
      status: 'completed_replay',
      terminalStatus: 'completed',
      requestId: 'request_public_1',
      reasonCode: 'PAYMENT_SETTLED',
      projections: {
        request: '/agent/v1/intents/request_public_1',
        receipt: '/agent/v1/receipts/receipt_public_1',
      },
      receipt: publicReceipt,
    }, `Completed replay: the charge is already recorded, provider output was not retained, and retrying this same call key will not spend again. Inspect /agent/v1/intents/request_public_1 and /agent/v1/receipts/receipt_public_1. receipt receipt_public_1 · sha256:${'a'.repeat(12)}…`],
  ];
  for (const [outcome, expected] of cases) {
    assert.equal(renderWalletKernelOutcome(outcome), expected);
  }
});

test('credential and provider exception sentinels never reach output or diagnostics', async (t) => {
  const credentialPath = temporaryCredential(t);
  const outputs = [];
  const diagnostics = [];
  const tools = [];
  let kernelRequests = 0;
  const pi = {
    registerProvider() {},
    registerTool(tool) { tools.push(tool); },
    registerCommand() { throw new Error('must not register console access'); },
    on() {},
  };
  const originalError = console.error;
  const originalWarn = console.warn;
  console.error = (...values) => diagnostics.push(values.join(' '));
  console.warn = (...values) => diagnostics.push(values.join(' '));
  t.after(() => {
    console.error = originalError;
    console.warn = originalWarn;
  });

  activate(pi, {
    env: environment(credentialPath),
    fetchFn: async () => {
      kernelRequests += 1;
      return new Response(JSON.stringify({
        status: 'payment_unresolved',
        requestId: 'request_public_1',
        reasonCode: 'SETTLEMENT_UNRESOLVED',
        receipt: receipt(),
        challengeFreeText: PROVIDER_EXCEPTION_SENTINEL,
      }), { status: 503, headers: { 'content-type': 'application/json' } });
    },
  });
  outputs.push(await tools[0].execute(
    'call_sentinel_1',
    { input: RAW_PROMPT_SENTINEL },
    undefined,
    undefined,
    Object.freeze({}),
  ));
  assert.equal(kernelRequests, 1);

  const throwingTools = [];
  activate({
    registerProvider() {},
    registerTool(tool) { throwingTools.push(tool); },
    registerCommand() { throw new Error('must not register console access'); },
    on() {},
  }, {
    env: environment(credentialPath),
    fetchFn: async () => {
      kernelRequests += 1;
      throw new Error(PROVIDER_EXCEPTION_SENTINEL);
    },
  });
  outputs.push(await throwingTools[0].execute(
    'call_sentinel_2',
    { input: RAW_PROMPT_SENTINEL },
    undefined,
    undefined,
    Object.freeze({}),
  ));
  assert.equal(kernelRequests, 3);

  const rendered = JSON.stringify({ outputs, diagnostics });
  assert.equal(rendered.includes(TOKEN), false);
  assert.equal(rendered.includes(RAW_PROMPT_SENTINEL), false);
  assert.equal(rendered.includes(PROVIDER_EXCEPTION_SENTINEL), false);
  assert.deepEqual(outputs[1], {
    content: [{
      type: 'text',
      text: 'Wallet Kernel unavailable after one same-key retry.',
    }],
    details: { boundaryStatus: 'unavailable' },
  });
});

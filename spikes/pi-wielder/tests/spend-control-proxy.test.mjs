import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import test from 'node:test';

import { validateRouteMap } from '../src/config.mjs';
import { createSpendControlProxy } from '../src/spend-control-proxy.mjs';
import { canonicalJson, KernelError } from '../src/kernel/canonical.mjs';

const ORIGIN = 'http://127.0.0.1:8505';
const TOKEN = Buffer.alloc(32, 0x41).toString('base64url');
const AGENT_CALL_ID = Buffer.alloc(32, 0x42).toString('base64url');
const TRANSACTION = `0x${'ab'.repeat(32)}`;
const RECEIPT_HASH = 'cd'.repeat(32);

function correlationForAgentCall(agentCallId) {
  return `agent-call:${crypto.createHash('sha256')
    .update('wallet-kernel.agent-call.v1\0', 'utf8')
    .update(agentCallId, 'ascii')
    .digest('base64url')}`;
}

function signedReceipt({
  status = 'completed',
  reasonCode = 'PAYMENT_SETTLED',
  paymentState = 'settled',
  amountAtomic = '100000',
  transactionId = TRANSACTION,
  budgetDisposition = 'committed',
  revision = 1,
  receiptId = 'receipt-1',
  requestId = 'request-1',
  resourcePath = '/paid/chat/completions',
  purposeLabel = 'model.infer',
  executionState = 'succeeded',
  httpStatus = 200,
} = {}) {
  return Object.freeze({
    id: receiptId,
    intentId: 'internal-intent-1',
    revision,
    receipt: Object.freeze({
      schemaVersion: 1,
      receiptId,
      revision,
      issuedAt: '2026-08-01T12:00:00.000Z',
      intent: Object.freeze({
        id: 'internal-intent-1',
        requestId,
        intentHash: `sha256:${'11'.repeat(32)}`,
        sessionId: 'session-1',
        sellerOrigin: 'https://seller.example',
        resourcePath,
        purposeLabel,
      }),
      outcome: Object.freeze({ status, reasonCode }),
      policy: Object.freeze({
        versionId: 'policy-1', decision: 'allow', reasonCode: 'WITHIN_AUTO_LIMIT',
      }),
      approval: Object.freeze({ state: 'not_required', operatorIdHash: null }),
      payment: paymentState === 'none'
        ? Object.freeze({ state: 'none' })
        : Object.freeze({
          state: paymentState,
          amountAtomic,
          network: 'eip155:84532',
          asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
          payTo: '0x2000000000000000000000000000000000000000',
          transactionId,
        }),
      execution: Object.freeze({
        state: executionState,
        httpStatus,
        responseHash: executionState === 'none' ? null : `sha256:${'22'.repeat(32)}`,
      }),
      budget: paymentState === 'none'
        ? null
        : Object.freeze({ disposition: budgetDisposition, amountAtomic }),
      reconciliation: null,
      refund: null,
      supersedesReceiptHash: revision === 1 ? null : 'ef'.repeat(32),
    }),
    receiptHash: RECEIPT_HASH,
    signature: Buffer.alloc(64, 0x55).toString('base64'),
    algorithm: 'Ed25519',
    keyId: `sha256:${'33'.repeat(32)}`,
    supersedesReceiptHash: revision === 1 ? null : 'ef'.repeat(32),
    createdAt: '2026-08-01T12:00:00.000Z',
  });
}

function statusView(receipt, {
  requestId = 'request-1',
  approval = null,
  outcome = receipt === null ? null : {
    status: receipt.receipt.outcome.status,
    reasonCode: receipt.receipt.outcome.reasonCode,
    revision: receipt.receipt.revision,
  },
  intentState = outcome === null ? 'approval_pending' : 'terminal',
  remainingSessionAtomic = '1900000',
  sellerOrigin = 'https://seller.example',
  purposeLabel = receipt?.receipt.intent.purposeLabel ?? 'skill.invoke',
} = {}) {
  return Object.freeze({
    requestId,
    sellerOrigin,
    purposeLabel,
    intentState,
    approval: approval === null ? null : Object.freeze(approval),
    outcome: outcome === null ? null : Object.freeze(outcome),
    receipt,
    remainingSessionAtomic,
  });
}

const ROUTE_DOCUMENT = JSON.parse(fs.readFileSync(
  new URL('../routes/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function dependencies({ auth = {}, kernel = {}, maximumRequestBytes = 262_144 } = {}) {
  const calls = [];
  return {
    calls,
    agentAuth: Object.freeze({
      authenticate(request) {
        calls.push({ name: 'authenticate', request });
        return Object.freeze({ agentInstanceId: 'agent-1' });
      },
      resolveBoundSession(principal) {
        calls.push({ name: 'resolveBoundSession', principal });
        return Object.freeze({ id: 'session-1' });
      },
      ...auth,
    }),
    kernel: Object.freeze({
      async execute(input) {
        calls.push({ name: 'execute', input });
        throw new Error('not used by construction test');
      },
      statusByRequestId(input) {
        calls.push({ name: 'statusByRequestId', input });
        return null;
      },
      receiptById(input) {
        calls.push({ name: 'receiptById', input });
        return null;
      },
      ...kernel,
    }),
    routes: validateRouteMap({ document: ROUTE_DOCUMENT, mode: 'cdp-testnet' }),
    maximumRequestBytes,
  };
}

function create(overrides) {
  const value = dependencies(overrides);
  return {
    ...value,
    app: createSpendControlProxy({
      agentAuth: value.agentAuth,
      kernel: value.kernel,
      routes: value.routes,
      maximumRequestBytes: value.maximumRequestBytes,
    }),
  };
}

function agentHeaders(extra = {}) {
  return {
    authorization: `WalletKernelAgent ${TOKEN}`,
    'content-type': 'application/json',
    accept: 'application/json',
    'user-agent': 'pi-agent/1',
    'x-agent-call-id': AGENT_CALL_ID,
    ...extra,
  };
}

async function json(response) {
  return await response.json();
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((onResolve, onReject) => {
    resolve = onResolve;
    reject = onReject;
  });
  return Object.freeze({ promise, resolve, reject });
}

test('proxy construction exposes only the four agent route capabilities', () => {
  const { app, calls } = create();

  assert.deepEqual(app.routes.map(({ method, path }) => `${method} ${path}`).sort(), [
    'GET /agent/v1/intents/:requestId',
    'GET /agent/v1/receipts/:receiptId',
    'POST /agent/v1/invoke/:routeId',
    'POST /agent/v1/openai/:routeId/chat/completions',
  ].sort());
  assert.deepEqual(calls, []);
});

test('proxy construction rejects ambient, mutable, accessor, and incomplete authority', () => {
  const value = dependencies();
  const valid = {
    agentAuth: value.agentAuth,
    kernel: value.kernel,
    routes: value.routes,
    maximumRequestBytes: value.maximumRequestBytes,
  };
  const getter = {};
  Object.defineProperty(getter, 'authenticate', { enumerable: true, get() { return () => {}; } });
  Object.defineProperty(getter, 'resolveBoundSession', {
    enumerable: true, value() {},
  });
  for (const invalid of [
    { ...valid, environment: process.env },
    { ...valid, maximumRequestBytes: 0 },
    { ...valid, maximumRequestBytes: 1_048_577 },
    { ...valid, agentAuth: getter },
    { ...valid, kernel: { execute() {}, statusByRequestId() {} } },
    { ...valid, routes: ROUTE_DOCUMENT },
    new Proxy(valid, {}),
  ]) {
    assert.throws(() => createSpendControlProxy(invalid), TypeError);
  }
});

test('agent authentication fails before session resolution, route authority, or body parsing', async () => {
  let bodyReaderCalls = 0;
  const { app, calls } = create({
    auth: {
      authenticate(request) {
        calls.push({ name: 'authenticate', request });
        throw new KernelError('AGENT_UNAUTHORIZED', 'private authentication detail');
      },
    },
  });
  const body = new ReadableStream({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(canonicalJson({ prompt: 'secret' })));
      controller.close();
    },
  });
  const getReader = body.getReader.bind(body);
  Object.defineProperty(body, 'getReader', {
    value(...args) {
      bodyReaderCalls += 1;
      return getReader(...args);
    },
  });
  const response = await app.request(new Request(
    `${ORIGIN}/agent/v1/openai/example-model/chat/completions`,
    { method: 'POST', headers: agentHeaders(), body, duplex: 'half' },
  ));

  assert.equal(response.status, 401);
  assert.deepEqual(await json(response), {
    error: { code: 'AGENT_UNAUTHORIZED', message: 'Agent authentication failed' },
  });
  assert.equal(bodyReaderCalls, 0);
  assert.deepEqual(calls.map(({ name }) => name), ['authenticate']);
});

test('OpenAI route executes only the immutable route and returns a compact receipt header projection', async () => {
  const receipt = signedReceipt();
  const upstreamBody = Buffer.from(canonicalJson({
    choices: [{ message: { role: 'assistant', content: 'hello' } }],
    id: 'completion-1',
    object: 'chat.completion',
  }));
  const { app, calls } = create({
    kernel: {
      async execute(input) {
        calls.push({ name: 'execute', input });
        return Object.freeze({
          requestId: 'request-1',
          status: 'completed',
          reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200,
          body: upstreamBody,
          receipt,
        });
      },
      statusByRequestId(input) {
        calls.push({ name: 'statusByRequestId', input });
        return Object.freeze({
          requestId: 'request-1',
          sellerOrigin: 'https://seller.example',
          purposeLabel: 'model.infer',
          intentState: 'terminal',
          approval: null,
          outcome: Object.freeze({
            status: 'completed', reasonCode: 'PAYMENT_SETTLED', revision: 1,
          }),
          receipt,
          remainingSessionAtomic: '1900000',
        });
      },
    },
  });
  const requestBody = canonicalJson({ messages: [{ role: 'user', content: 'hello' }] });
  const response = await app.request(`${ORIGIN}/agent/v1/openai/example-model/chat/completions`, {
    method: 'POST',
    headers: agentHeaders({
      cookie: 'must-not-reach-seller',
      connection: 'keep-alive',
      host: 'attacker.example',
      'x-custom-secret': 'must-not-reach-seller',
    }),
    body: requestBody,
  });

  assert.equal(response.status, 200, await response.clone().text());
  assert.deepEqual(await json(response), JSON.parse(upstreamBody));
  assert.equal(response.headers.get('content-type'), 'application/json');
  assert.equal(response.headers.get('x-wallet-receipt-id'), 'receipt-1');
  assert.equal(response.headers.get('x-wallet-terminal-state'), 'completed');
  assert.equal(response.headers.get('x-wallet-charged-atomic'), '100000');
  assert.equal(response.headers.get('x-wallet-session-remaining-atomic'), '1900000');
  assert.equal(response.headers.get('x-wallet-transaction-prefix'), '0xabababab');
  assert.equal(response.headers.has('set-cookie'), false);
  assert.equal(response.headers.has('location'), false);

  assert.deepEqual(calls.map(({ name }) => name), [
    'authenticate', 'resolveBoundSession', 'execute', 'statusByRequestId',
  ]);
  const execution = calls.find(({ name }) => name === 'execute').input;
  assert.equal(execution.sessionId, 'session-1');
  assert.equal(execution.routeId, 'example-model');
  assert.equal(execution.purposeLabel, 'model.infer');
  assert.equal(execution.correlationId, correlationForAgentCall(AGENT_CALL_ID));
  assert.deepEqual(execution.request, {
    requestUrl: 'https://seller.example/paid/chat/completions',
    method: 'POST',
    headers: {
      accept: 'application/json',
      'content-type': 'application/json',
      'user-agent': 'pi-agent/1',
    },
    bodyBytes: Buffer.from(requestBody),
  });
  assert.equal(JSON.stringify(execution).includes(TOKEN), false);
  assert.equal(JSON.stringify(execution).includes('must-not-reach-seller'), false);
  assert.deepEqual(calls.find(({ name }) => name === 'statusByRequestId').input, {
    sessionId: 'session-1', requestId: 'request-1',
  });
});

test('Pi streaming completions cross the agent boundary only as bounded OpenAI SSE', async () => {
  const receipt = signedReceipt();
  const upstreamBody = Buffer.from([
    'data: {"id":"completion-1","object":"chat.completion.chunk","choices":[]}',
    '',
    'data: [DONE]',
    '',
    '',
  ].join('\n'));
  const { app } = create({
    kernel: {
      async execute() {
        return Object.freeze({
          requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200, body: upstreamBody, receipt,
        });
      },
      statusByRequestId() { return statusView(receipt); },
    },
  });

  const response = await app.request(
    `${ORIGIN}/agent/v1/openai/example-model/chat/completions`,
    { method: 'POST', headers: agentHeaders(), body: '{"messages":[],"stream":true}' },
  );

  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get('content-type'), 'text/event-stream; charset=utf-8');
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), upstreamBody);
  assert.equal(response.headers.get('x-wallet-receipt-id'), 'receipt-1');
});

test('streaming completion responses reject malformed SSE and format confusion', async (t) => {
  const cases = [
    ['JSON for stream request', Buffer.from('{"choices":[]}'), true],
    ['SSE for buffered request', Buffer.from('data: {"choices":[]}\n\ndata: [DONE]\n\n'), false],
    ['missing done', Buffer.from('data: {"choices":[]}\n\n'), true],
    ['array event', Buffer.from('data: []\n\ndata: [DONE]\n\n'), true],
    ['invalid event JSON', Buffer.from('data: PROVIDER_EXCEPTION_SENTINEL\n\ndata: [DONE]\n\n'), true],
    ['unsupported SSE field', Buffer.from('event: message\ndata: {"choices":[]}\n\ndata: [DONE]\n\n'), true],
    ['bytes after done', Buffer.from('data: {"choices":[]}\n\ndata: [DONE]\n\ndata: {"private":true}\n\n'), true],
    ['invalid UTF-8', Buffer.from([0xff]), true],
  ];
  for (const [label, body, stream] of cases) {
    await t.test(label, async () => {
      const receipt = signedReceipt();
      const { app } = create({
        kernel: {
          async execute() {
            return Object.freeze({
              requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
              upstreamStatus: 200, body, receipt,
            });
          },
          statusByRequestId() { return statusView(receipt); },
        },
      });
      const response = await app.request(
        `${ORIGIN}/agent/v1/openai/example-model/chat/completions`,
        {
          method: 'POST',
          headers: agentHeaders(),
          body: JSON.stringify({ messages: [], stream }),
        },
      );
      assert.equal(response.status, 502);
      const serialized = JSON.stringify(await json(response));
      assert.equal(serialized.includes('PROVIDER_EXCEPTION_SENTINEL'), false);
      assert.equal(serialized.includes(receipt.signature), false);
    });
  }
});

test('tool completion returns the stable resource envelope without signed receipt bytes', async () => {
  const receipt = signedReceipt({
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
    httpStatus: 201,
  });
  const { app } = create({
    kernel: {
      async execute() {
        return Object.freeze({
          requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 201, body: Buffer.from('{"answer":42}'), receipt,
        });
      },
      statusByRequestId() { return statusView(receipt); },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
  });

  assert.equal(response.status, 200);
  const value = await json(response);
  assert.deepEqual(value, {
    status: 'completed',
    requestId: 'request-1',
    resource: { httpStatus: 201, contentType: 'application/json', body: { answer: 42 } },
    receipt: {
      id: 'receipt-1',
      hash: RECEIPT_HASH,
      sellerOrigin: 'https://seller.example',
      chargedAtomic: '100000',
      remainingSessionAtomic: '1900000',
      terminalState: 'completed',
      transactionPrefix: '0xabababab',
    },
  });
  const serialized = JSON.stringify(value);
  assert.equal(serialized.includes(receipt.signature), false);
  assert.equal(serialized.includes('internal-intent-1'), false);
  assert.equal(serialized.includes('session-1'), false);
});

test('one Agent call ID replays the persisted terminal result without another payment', async () => {
  const receipt = signedReceipt({
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
  });
  const executions = new Map();
  let paymentAttempts = 0;
  const { app, calls } = create({
    kernel: {
      async execute(input) {
        calls.push({ name: 'execute', input });
        const prior = executions.get(input.correlationId);
        if (prior !== undefined) {
          return Object.freeze({
            requestId: prior.requestId,
            status: prior.status,
            reasonCode: prior.reasonCode,
            receipt: prior.receipt,
          });
        }
        paymentAttempts += 1;
        const result = Object.freeze({
          requestId: 'request-1',
          status: 'completed',
          reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200,
          body: Buffer.from('{"answer":42}'),
          receipt,
        });
        executions.set(input.correlationId, result);
        return result;
      },
      statusByRequestId(input) {
        calls.push({ name: 'statusByRequestId', input });
        return statusView(receipt);
      },
    },
  });
  const request = () => app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST',
    headers: agentHeaders(),
    body: '{"input":"hello"}',
  });

  const first = await request();
  assert.equal(first.status, 200);
  assert.equal((await json(first)).status, 'completed');

  const replay = await request();
  assert.equal(replay.status, 409);
  assert.deepEqual(await json(replay), {
    status: 'completed_replay',
    terminalStatus: 'completed',
    requestId: 'request-1',
    reasonCode: 'PAYMENT_SETTLED',
    projections: {
      request: '/agent/v1/intents/request-1',
      receipt: '/agent/v1/receipts/receipt-1',
    },
    receipt: {
      id: 'receipt-1',
      hash: RECEIPT_HASH,
      sellerOrigin: 'https://seller.example',
      chargedAtomic: '100000',
      remainingSessionAtomic: '1900000',
      terminalState: 'completed',
      transactionPrefix: '0xabababab',
    },
  });
  assert.equal(paymentAttempts, 1);
  const correlations = calls
    .filter(({ name }) => name === 'execute')
    .map(({ input }) => input.correlationId);
  assert.deepEqual(correlations, [
    correlationForAgentCall(AGENT_CALL_ID),
    correlationForAgentCall(AGENT_CALL_ID),
  ]);
});

test('streaming completion replay is explicit bounded JSON with a non-success status', async () => {
  const receipt = signedReceipt();
  const completed = Object.freeze({
    requestId: 'request-1',
    status: 'completed',
    reasonCode: 'PAYMENT_SETTLED',
    upstreamStatus: 200,
    body: Buffer.from('data: {"choices":[]}\n\ndata: [DONE]\n\n'),
    receipt,
  });
  let executions = 0;
  const { app } = create({
    kernel: {
      async execute() {
        executions += 1;
        return executions === 1
          ? completed
          : Object.freeze({
            requestId: completed.requestId,
            status: completed.status,
            reasonCode: completed.reasonCode,
            receipt: completed.receipt,
          });
      },
      statusByRequestId() {
        return statusView(receipt, { purposeLabel: 'model.infer' });
      },
    },
  });
  const request = () => app.request(
    `${ORIGIN}/agent/v1/openai/example-model/chat/completions`,
    {
      method: 'POST',
      headers: agentHeaders(),
      body: '{"messages":[],"stream":true}',
    },
  );

  const first = await request();
  assert.equal(first.status, 200);
  assert.equal(first.headers.get('content-type'), 'text/event-stream; charset=utf-8');
  const replay = await request();
  assert.equal(replay.status, 409);
  assert.match(replay.headers.get('content-type') ?? '', /^application\/json\b/u);
  const value = await json(replay);
  assert.equal(value.status, 'completed_replay');
  assert.equal(Object.hasOwn(value, 'resource'), false);
  assert.equal(Object.hasOwn(value, 'body'), false);
  assert.deepEqual(value.projections, {
    request: '/agent/v1/intents/request-1',
    receipt: '/agent/v1/receipts/receipt-1',
  });
});

test('one Agent call ID cannot be rebound to a different canonical request', async () => {
  const receipt = signedReceipt({
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
  });
  const executions = new Map();
  let paymentAttempts = 0;
  const { app, calls } = create({
    kernel: {
      async execute(input) {
        calls.push({ name: 'execute', input });
        const fingerprint = input.request.bodyBytes.toString('base64url');
        const prior = executions.get(input.correlationId);
        if (prior !== undefined && prior.fingerprint !== fingerprint) {
          throw new KernelError(
            'CORRELATION_CONFLICT',
            'private canonical request mismatch detail',
          );
        }
        if (prior !== undefined) return prior.result;
        paymentAttempts += 1;
        const result = Object.freeze({
          requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200, body: Buffer.from('{"answer":42}'), receipt,
        });
        executions.set(input.correlationId, { fingerprint, result });
        return result;
      },
      statusByRequestId() { return statusView(receipt); },
    },
  });

  const first = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"first"}',
  });
  assert.equal(first.status, 200);
  const mismatch = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"different"}',
  });

  assert.equal(mismatch.status, 409);
  assert.deepEqual(await json(mismatch), {
    error: {
      code: 'CORRELATION_CONFLICT',
      message: 'Agent call ID is already bound to a different request',
    },
  });
  assert.equal(paymentAttempts, 1);
});

test('completed output requires one signed bounded upstream status', async (t) => {
  for (const upstreamStatus of ['PROVIDER_EXCEPTION_SENTINEL', 202]) {
    await t.test(String(upstreamStatus), async () => {
      const receipt = signedReceipt({
        resourcePath: '/paid/skill',
        purposeLabel: 'skill.invoke',
        httpStatus: 201,
      });
      const { app } = create({
        kernel: {
          async execute() {
            return Object.freeze({
              requestId: 'request-1',
              status: 'completed',
              reasonCode: 'PAYMENT_SETTLED',
              upstreamStatus,
              body: Buffer.from('{"answer":42}'),
              receipt,
            });
          },
          statusByRequestId() { return statusView(receipt); },
        },
      });
      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
      });
      assert.equal(response.status, 502);
      const serialized = JSON.stringify(await json(response));
      assert.equal(serialized.includes('PROVIDER_EXCEPTION_SENTINEL'), false);
      assert.equal(serialized.includes('202'), false);
      assert.equal(serialized.includes('201'), false);
    });
  }
});

test('model and Skill approvals return immediately and resume only on a later same-key request', async (t) => {
  for (const fixture of [
    {
      label: 'model',
      path: '/agent/v1/openai/example-model/chat/completions',
      body: '{"messages":[{"role":"user","content":"hello"}]}',
      resourcePath: '/paid/chat/completions',
      purposeLabel: 'model.infer',
      upstreamBody: Buffer.from('{"choices":[{"message":{"role":"assistant","content":"ok"}}]}'),
    },
    {
      label: 'Skill',
      path: '/agent/v1/invoke/example-skill',
      body: '{"input":"hello"}',
      resourcePath: '/paid/skill',
      purposeLabel: 'skill.invoke',
      upstreamBody: Buffer.from('{"output":"ok"}'),
    },
  ]) {
    await t.test(fixture.label, async () => {
      const approval = Object.freeze({
        state: 'pending',
        expiresAt: new Date(Date.now() + 5_000).toISOString(),
        amountAtomic: '250000',
      });
      const receipt = signedReceipt({
        resourcePath: fixture.resourcePath,
        purposeLabel: fixture.purposeLabel,
        amountAtomic: approval.amountAtomic,
      });
      const executions = [];
      let statusReads = 0;
      let signerCalls = 0;
      let approved = false;
      const { app } = create({
        kernel: {
          async execute(input) {
            executions.push(input);
            if (!approved) {
              return Object.freeze({
                requestId: 'request-1',
                status: 'payment_approval_required',
                reasonCode: 'HUMAN_APPROVAL_REQUIRED',
                expiresAt: approval.expiresAt,
                receipt: null,
              });
            }
            signerCalls += 1;
            return Object.freeze({
              requestId: 'request-1',
              status: 'completed',
              reasonCode: 'PAYMENT_SETTLED',
              upstreamStatus: 200,
              body: fixture.upstreamBody,
              receipt,
            });
          },
          statusByRequestId() {
            statusReads += 1;
            if (approved) {
              return statusView(receipt, { purposeLabel: fixture.purposeLabel });
            }
            return statusView(null, {
              approval,
              purposeLabel: fixture.purposeLabel,
            });
          },
        },
      });

      const request = () => app.request(`${ORIGIN}${fixture.path}`, {
        method: 'POST', headers: agentHeaders(), body: fixture.body,
      });

      const first = await request();
      assert.equal(first.status, 409, await first.clone().text());
      assert.equal((await json(first)).status, 'payment_approval_required');
      assert.equal(executions.length, 1);
      assert.equal(signerCalls, 0);
      assert.equal(statusReads, 1);

      approved = true;
      const second = await request();
      assert.equal(second.status, 200, await second.clone().text());
      assert.equal(executions.length, 2);
      assert.equal(signerCalls, 1);
      assert.equal(statusReads, 2);
      assert.deepEqual(executions[1], executions[0]);
      assert.notEqual(executions[1], executions[0]);
      assert.notEqual(executions[1].request.bodyBytes, executions[0].request.bodyBytes);
      assert.equal(Object.isFrozen(executions[0]), true);
      assert.equal(Object.isFrozen(executions[0].request), true);
      assert.equal(executions[0].correlationId, correlationForAgentCall(AGENT_CALL_ID));
      assert.equal(Object.hasOwn(executions[0].request.headers, 'prefer'), false);
    });
  }
});

test('approval-required is bounded after one Kernel execution and one status read', async () => {
  const approval = {
    state: 'pending',
    expiresAt: new Date(Date.now() + 20).toISOString(),
    amountAtomic: '250000',
  };
  let executeCalls = 0;
  let statusReads = 0;
  const { app } = create({
    kernel: {
      async execute() {
        executeCalls += 1;
        return Object.freeze({
          requestId: 'request-1',
          status: 'payment_approval_required',
          reasonCode: 'HUMAN_APPROVAL_REQUIRED',
          expiresAt: approval.expiresAt,
          receipt: null,
        });
      },
      statusByRequestId() {
        statusReads += 1;
        return statusView(null, { approval });
      },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
  });

  assert.equal(response.status, 409);
  assert.deepEqual(await json(response), {
    status: 'payment_approval_required',
    requestId: 'request-1',
    approval: {
      expiresAt: approval.expiresAt,
      amountAtomic: '250000',
      sellerOrigin: 'https://seller.example',
      purposeLabel: 'skill.invoke',
    },
  });
  assert.equal(executeCalls, 1);
  assert.equal(statusReads, 1);
});

test('every approval wait preference is forbidden before Kernel execution', async (t) => {
  for (const preference of [
    'wait=1',
    'wait=300',
    'wait=0',
    'wait=01',
    'wait=301',
    'wait=1.5',
    'wait=1, respond-async',
    'respond-async',
  ]) {
    await t.test(preference, async () => {
      const { app, calls } = create();
      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST',
        headers: agentHeaders({ Prefer: preference }),
        body: '{"input":"hello"}',
      });
      assert.equal(response.status, 400);
      assert.equal((await json(response)).error.code, 'AGENT_PREFER_INVALID');
      assert.equal(calls.some(({ name }) => name === 'execute'), false);
    });
  }
});

test('denial and expiry races return the signed terminal projection without another execute', async (t) => {
  for (const reasonCode of ['OPERATOR_DENIED', 'APPROVAL_EXPIRED']) {
    await t.test(reasonCode, async () => {
      const approval = Object.freeze({
        state: 'pending',
        expiresAt: new Date(Date.now() + 5_000).toISOString(),
        amountAtomic: '250000',
      });
      const receipt = signedReceipt({
        status: 'payment_denied',
        reasonCode,
        paymentState: 'none',
        transactionId: null,
        budgetDisposition: 'released',
        resourcePath: '/paid/skill',
        purposeLabel: 'skill.invoke',
        executionState: 'none',
        httpStatus: null,
      });
      let executeCalls = 0;
      let statusReads = 0;
      const { app } = create({
        kernel: {
          async execute() {
            executeCalls += 1;
            return Object.freeze({
              requestId: 'request-1',
              status: 'payment_approval_required',
              reasonCode: 'HUMAN_APPROVAL_REQUIRED',
              expiresAt: approval.expiresAt,
              receipt: null,
            });
          },
          statusByRequestId() {
            statusReads += 1;
            return statusView(receipt, { purposeLabel: 'skill.invoke' });
          },
        },
      });

      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
      });

      assert.equal(response.status, 403, await response.clone().text());
      const outcome = await json(response);
      assert.equal(outcome.status, 'payment_denied');
      assert.equal(outcome.reasonCode, reasonCode);
      assert.equal(outcome.receipt.id, 'receipt-1');
      assert.equal(executeCalls, 1);
      assert.equal(statusReads, 1);
    });
  }
});

test('a raced terminal approval rejects an outcome that disagrees with its signed receipt state', async () => {
  const approval = Object.freeze({
    state: 'pending',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
    amountAtomic: '250000',
  });
  const receipt = signedReceipt({
    status: 'payment_denied',
    reasonCode: 'OPERATOR_DENIED',
    paymentState: 'none',
    transactionId: null,
    budgetDisposition: 'released',
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
    executionState: 'none',
    httpStatus: null,
  });
  const { app } = create({
    kernel: {
      async execute() {
        return Object.freeze({
          requestId: 'request-1',
          status: 'payment_approval_required',
          reasonCode: 'HUMAN_APPROVAL_REQUIRED',
          expiresAt: approval.expiresAt,
          receipt: null,
        });
      },
      statusByRequestId() {
        return statusView(receipt, {
          purposeLabel: 'skill.invoke',
          outcome: {
            status: 'payment_failed',
            reasonCode: 'OPERATOR_DENIED',
            revision: 1,
          },
        });
      },
    },
  });

  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
  });

  assert.equal(response.status, 502);
  assert.equal((await json(response)).error.code, 'AGENT_RESPONSE_INVALID');
});

test('an approval decision racing the first status read cannot trigger connected replay', async () => {
  const approval = Object.freeze({
    state: 'approved',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
    amountAtomic: '250000',
  });
  let executeCalls = 0;
  let signerCalls = 0;
  const { app } = create({
    kernel: {
      async execute() {
        executeCalls += 1;
        if (executeCalls > 1) signerCalls += 1;
        return Object.freeze({
          requestId: 'request-1',
          status: 'payment_approval_required',
          reasonCode: 'HUMAN_APPROVAL_REQUIRED',
          expiresAt: approval.expiresAt,
          receipt: null,
        });
      },
      statusByRequestId() {
        return statusView(null, { approval, purposeLabel: 'skill.invoke' });
      },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST',
    headers: agentHeaders(),
    body: '{"input":"hello"}',
  });

  assert.equal(response.status, 409, await response.clone().text());
  assert.equal((await json(response)).status, 'payment_approval_required');
  assert.equal(executeCalls, 1);
  assert.equal(signerCalls, 0);
});

test('concurrent fresh-call retries remain separate requests and one alias replays terminal state', async () => {
  const callB = Buffer.alloc(32, 0x43).toString('base64url');
  const callC = Buffer.alloc(32, 0x44).toString('base64url');
  const approval = Object.freeze({
    state: 'pending',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
    amountAtomic: '250000',
  });
  const approvedApproval = Object.freeze({ ...approval, state: 'approved' });
  const receipt = signedReceipt({
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
    amountAtomic: approval.amountAtomic,
  });
  const leaderStarted = deferred();
  const leaderRelease = deferred();
  const correlations = [];
  let approved = false;
  let leaderInFlight = false;
  let completed = false;
  let signerCalls = 0;
  const { app } = create({
    kernel: {
      async execute(input) {
        correlations.push(input.correlationId);
        if (completed) {
          return Object.freeze({
            requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED', receipt,
          });
        }
        if (!approved) {
          return Object.freeze({
            requestId: 'request-1',
            status: 'payment_approval_required',
            reasonCode: 'HUMAN_APPROVAL_REQUIRED',
            expiresAt: approval.expiresAt,
            receipt: null,
          });
        }
        if (leaderInFlight) {
          return Object.freeze({
            requestId: 'request-1',
            status: 'request_in_flight',
            reasonCode: 'REQUEST_IN_FLIGHT',
            receipt: null,
          });
        }
        leaderInFlight = true;
        signerCalls += 1;
        leaderStarted.resolve();
        await leaderRelease.promise;
        completed = true;
        return Object.freeze({
          requestId: 'request-1',
          status: 'completed',
          reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200,
          body: Buffer.from('{"output":"ok"}'),
          receipt,
        });
      },
      statusByRequestId() {
        if (completed) return statusView(receipt, { purposeLabel: 'skill.invoke' });
        return statusView(null, {
          approval: approved ? approvedApproval : approval,
          purposeLabel: 'skill.invoke',
        });
      },
    },
  });
  const request = (agentCallId) => app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST',
    headers: agentHeaders({ 'x-agent-call-id': agentCallId }),
    body: '{"input":"hello"}',
  });

  const pending = await request(AGENT_CALL_ID);
  assert.equal(pending.status, 409);
  approved = true;
  const leader = request(callB);
  await leaderStarted.promise;
  const follower = await request(callC);
  assert.equal(follower.status, 409);
  assert.equal((await json(follower)).status, 'request_in_flight');
  leaderRelease.resolve();
  assert.equal((await leader).status, 200);
  const replay = await request(callC);
  assert.equal(replay.status, 409);
  assert.equal((await json(replay)).status, 'completed_replay');
  assert.equal(signerCalls, 1);
  assert.deepEqual(correlations, [
    correlationForAgentCall(AGENT_CALL_ID),
    correlationForAgentCall(callB),
    correlationForAgentCall(callC),
    correlationForAgentCall(callC),
  ]);
});

test('a changed challenge requires separate ordinary requests for replacement approval', async () => {
  const callB = Buffer.alloc(32, 0x45).toString('base64url');
  const callC = Buffer.alloc(32, 0x46).toString('base64url');
  const firstApproval = Object.freeze({
    state: 'pending',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
    amountAtomic: '250000',
  });
  const replacementApproval = Object.freeze({
    state: 'pending',
    expiresAt: new Date(Date.now() + 5_000).toISOString(),
    amountAtomic: '260000',
  });
  const changedReceipt = signedReceipt({
    status: 'payment_denied',
    reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
    paymentState: 'none',
    transactionId: null,
    budgetDisposition: 'released',
    resourcePath: '/paid/skill',
    purposeLabel: 'skill.invoke',
    executionState: 'none',
    httpStatus: null,
  });
  let executeCalls = 0;
  const { app } = create({
    kernel: {
      async execute() {
        executeCalls += 1;
        if (executeCalls === 1) {
          return Object.freeze({
            requestId: 'request-1',
            status: 'payment_approval_required',
            reasonCode: 'HUMAN_APPROVAL_REQUIRED',
            expiresAt: firstApproval.expiresAt,
            receipt: null,
          });
        }
        if (executeCalls === 2) {
          return Object.freeze({
            requestId: 'request-1',
            status: 'payment_denied',
            reasonCode: 'APPROVAL_CHALLENGE_CHANGED',
            receipt: changedReceipt,
            replacementRequestId: 'request-2',
            replacementExpiresAt: replacementApproval.expiresAt,
          });
        }
        return Object.freeze({
          requestId: 'request-2',
          status: 'payment_approval_required',
          reasonCode: 'HUMAN_APPROVAL_REQUIRED',
          expiresAt: replacementApproval.expiresAt,
          receipt: null,
        });
      },
      statusByRequestId({ requestId }) {
        if (requestId === 'request-2') {
          return statusView(null, { requestId, approval: replacementApproval });
        }
        return executeCalls === 1
          ? statusView(null, { approval: firstApproval })
          : statusView(changedReceipt, { purposeLabel: 'skill.invoke' });
      },
    },
  });
  const request = (agentCallId) => app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST',
    headers: agentHeaders({ 'x-agent-call-id': agentCallId }),
    body: '{"input":"hello"}',
  });

  const first = await request(AGENT_CALL_ID);
  const changed = await request(callB);
  const replacement = await request(callC);

  assert.equal(first.status, 409);
  assert.equal((await json(first)).status, 'payment_approval_required');
  assert.equal(changed.status, 403);
  assert.equal((await json(changed)).reasonCode, 'APPROVAL_CHALLENGE_CHANGED');
  assert.equal(replacement.status, 409);
  const replacementOutcome = await json(replacement);
  assert.equal(replacementOutcome.status, 'payment_approval_required');
  assert.equal(replacementOutcome.requestId, 'request-2');
  assert.equal(replacementOutcome.approval.amountAtomic, '260000');
  assert.equal(executeCalls, 3);
});

test('terminal buyer outcomes use the fixed public HTTP mapping and never return seller bodies', async (t) => {
  const cases = [
    ['payment_denied', 'PER_REQUEST_LIMIT', 403, 'none', null, 'released', null],
    ['payment_failed', 'WALLET_PRE_SIGN_REJECTED', 502, 'not_signed', null, 'released', null],
    ['payment_unresolved', 'PAID_RESPONSE_AMBIGUOUS', 503, 'unresolved', null, 'unresolved', null],
    ['payment_rejected', 'AUTHORIZATION_UNUSED_AFTER_EXPIRY', 402, 'rejected', null, 'released', null],
    ['upstream_failed', 'UPSTREAM_TRANSPORT_FAILURE', 502, 'none', null, 'released', null],
    ['execution_failed', 'UPSTREAM_HTTP_FAILURE', 429, 'settled', TRANSACTION, 'committed', 429],
    ['execution_failed', 'UPSTREAM_HTTP_FAILURE', 502, 'settled', TRANSACTION, 'committed', 302],
    ['execution_unknown', 'PAID_RESPONSE_AMBIGUOUS', 502, 'settled', TRANSACTION, 'committed', null],
    ['refunded', 'REFUND_CONFIRMED', 200, 'settled', TRANSACTION, 'released', 500],
  ];
  for (const [status, reasonCode, expectedHttp, paymentState, transactionId,
    budgetDisposition, upstreamStatus] of cases) {
    await t.test(`${status} maps to ${expectedHttp}`, async () => {
      const receipt = signedReceipt({
        status,
        reasonCode,
        paymentState,
        transactionId,
        budgetDisposition,
        resourcePath: '/paid/skill',
        purposeLabel: 'skill.invoke',
        executionState: status === 'execution_failed' || status === 'refunded'
          ? 'failed'
          : (status === 'execution_unknown' ? 'unknown' : 'none'),
        httpStatus: upstreamStatus,
      });
      const { app } = create({
        kernel: {
          async execute() {
            return Object.freeze({
              requestId: 'request-1', status, reasonCode, receipt,
              ...(upstreamStatus === undefined ? {} : { upstreamStatus }),
              body: Buffer.from('PROVIDER_EXCEPTION_SENTINEL'),
            });
          },
          statusByRequestId() { return statusView(receipt); },
        },
      });
      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
      });
      const value = await json(response);

      assert.equal(response.status, expectedHttp);
      assert.equal(value.status, status);
      assert.equal(value.requestId, 'request-1');
      assert.equal(value.reasonCode, reasonCode);
      assert.equal(value.receipt.terminalState, status);
      assert.equal(Object.hasOwn(value, 'resource'), false);
      assert.equal(JSON.stringify(value).includes('PROVIDER_EXCEPTION_SENTINEL'), false);
      assert.equal(JSON.stringify(value).includes(receipt.signature), false);
    });
  }
});

test('agent intent and receipt reads are session-scoped compact projections', async () => {
  const receipt = signedReceipt({
    status: 'payment_rejected',
    reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
    paymentState: 'rejected',
    transactionId: null,
    budgetDisposition: 'released',
    revision: 2,
    receiptId: 'receipt-2',
    executionState: 'none',
    httpStatus: null,
  });
  const view = statusView(receipt, {
    outcome: {
      status: 'payment_rejected',
      reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      revision: 2,
    },
    remainingSessionAtomic: '2000000',
  });
  const { app, calls } = create({
    kernel: {
      statusByRequestId(input) {
        calls.push({ name: 'statusByRequestId', input });
        return input.requestId === 'request-1' ? view : null;
      },
      receiptById(input) {
        calls.push({ name: 'receiptById', input });
        return input.receiptId === 'receipt-2' ? view : null;
      },
    },
  });

  for (const path of [
    '/agent/v1/intents/request-1',
    '/agent/v1/receipts/receipt-2',
  ]) {
    const response = await app.request(`${ORIGIN}${path}`, {
      headers: { authorization: `WalletKernelAgent ${TOKEN}` },
    });
    assert.equal(response.status, 200);
    assert.deepEqual(await json(response), {
      status: 'payment_rejected',
      requestId: 'request-1',
      reasonCode: 'AUTHORIZATION_UNUSED_AFTER_EXPIRY',
      receipt: {
        id: 'receipt-2',
        hash: RECEIPT_HASH,
        sellerOrigin: 'https://seller.example',
        chargedAtomic: '0',
        remainingSessionAtomic: '2000000',
        terminalState: 'payment_rejected',
        transactionPrefix: null,
      },
    });
  }
  assert.deepEqual(
    calls.filter(({ name }) => name === 'statusByRequestId').at(-1).input,
    { sessionId: 'session-1', requestId: 'request-1' },
  );
  assert.deepEqual(
    calls.find(({ name }) => name === 'receiptById').input,
    { sessionId: 'session-1', receiptId: 'receipt-2' },
  );
});

test('agent reads hide guessed identifiers from other sessions and reject noncanonical paths', async () => {
  const { app, calls } = create({
    kernel: {
      statusByRequestId(input) {
        calls.push({ name: 'statusByRequestId', input });
        return null;
      },
      receiptById(input) {
        calls.push({ name: 'receiptById', input });
        throw new KernelError('RECEIPT_SESSION_MISMATCH', 'private cross-session detail');
      },
    },
  });
  for (const path of [
    '/agent/v1/intents/request-other',
    '/agent/v1/receipts/receipt-other',
    '/agent/v1/intents/request-1?sessionId=session-other',
    '/agent/v1/receipts/https%3A%2F%2Fattacker.example',
  ]) {
    const response = await app.request(`${ORIGIN}${path}`, {
      headers: { authorization: `WalletKernelAgent ${TOKEN}` },
    });
    assert.equal([400, 404].includes(response.status), true);
    const serialized = JSON.stringify(await json(response));
    assert.equal(serialized.includes('session-other'), false);
    assert.equal(serialized.includes('private cross-session detail'), false);
  }
  assert.equal(calls.some(({ name }) => name === 'execute'), false);
});

test('pending intent lookup returns the same bounded approval projection', async () => {
  const approval = {
    state: 'pending',
    expiresAt: '2026-08-01T12:05:00.000Z',
    amountAtomic: '250000',
  };
  const { app } = create({
    kernel: {
      statusByRequestId() { return statusView(null, { approval }); },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/intents/request-1`, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await json(response), {
    status: 'payment_approval_required',
    requestId: 'request-1',
    approval: {
      expiresAt: approval.expiresAt,
      amountAtomic: approval.amountAtomic,
      sellerOrigin: 'https://seller.example',
      purposeLabel: 'skill.invoke',
    },
  });
});

test('approved intent lookup tells the agent to retry without exposing approval authority', async () => {
  const approval = {
    state: 'approved',
    expiresAt: '2026-08-01T12:05:00.000Z',
    amountAtomic: '250000',
  };
  const { app } = create({
    kernel: {
      statusByRequestId() { return statusView(null, { approval }); },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/intents/request-1`, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  });

  assert.equal(response.status, 200);
  assert.deepEqual(await json(response), {
    status: 'request_in_flight',
    requestId: 'request-1',
    reasonCode: 'APPROVAL_GRANTED_RETRY_REQUIRED',
  });
});

test('fixed route file is accepted only through the shared validator in both modes', () => {
  const cdp = validateRouteMap({ document: ROUTE_DOCUMENT, mode: 'cdp-testnet' });
  const deterministic = validateRouteMap({ document: ROUTE_DOCUMENT, mode: 'deterministic' });
  assert.deepEqual(cdp.routes, deterministic.routes);
  assert.deepEqual(cdp.routes.map(({ id, kind, method, upstreamUrl }) => ({
    id, kind, method, upstreamUrl,
  })), [
    {
      id: 'example-model',
      kind: 'openai-chat',
      method: 'POST',
      upstreamUrl: 'https://seller.example/paid/chat/completions',
    },
    {
      id: 'example-skill',
      kind: 'tool',
      method: 'POST',
      upstreamUrl: 'https://seller.example/paid/skill',
    },
  ]);
});

test('unknown, cross-kind, URL-like, extended, queried, wrong-method, and operator paths never execute', async (t) => {
  const cases = [
    ['POST', '/agent/v1/invoke/unknown', 404],
    ['POST', '/agent/v1/invoke/example-model', 404],
    ['POST', '/agent/v1/openai/example-skill/chat/completions', 404],
    ['POST', '/agent/v1/invoke/https%3A%2F%2Fattacker.example', 400],
    ['POST', '/agent/v1/invoke/example-skill/extra', 404],
    ['POST', '/agent/v1/invoke/example-skill?target=https://attacker.example', 400],
    ['GET', '/agent/v1/invoke/example-skill', 404],
    ['HEAD', '/agent/v1/intents/request-1', 404],
    ['POST', '/operator/v1/approvals/approval-1/approve', 404],
  ];
  for (const [method, path, expectedStatus] of cases) {
    await t.test(`${method} ${path}`, async () => {
      const { app, calls } = create();
      const response = await app.request(`${ORIGIN}${path}`, {
        method,
        headers: method === 'POST' ? agentHeaders() : {
          authorization: `WalletKernelAgent ${TOKEN}`,
        },
        ...(method === 'POST' ? { body: '{"input":"hello"}' } : {}),
      });
      assert.equal(response.status, expectedStatus);
      assert.equal(calls.some(({ name }) => name === 'execute'), false);
      assert.equal(calls.some(({ name }) => name === 'statusByRequestId'), false);
      assert.equal(calls.some(({ name }) => name === 'receiptById'), false);
    });
  }
});

test('payment, policy, session, target, and idempotency headers are rejected before Kernel execution', async (t) => {
  const forbidden = [
    'payment-required', 'payment-signature', 'payment-response',
    'x-payment', 'x-payment-required', 'x-payment-response',
    'idempotency-key', 'x-idempotency-key', 'x-approval-id', 'x-spend-session',
    'x-session-id', 'x-wallet-address', 'x-wallet-policy', 'x-wallet-payee',
    'x-wallet-amount', 'x-target-url', 'x-http-method', 'x-correlation-id', 'x-request-id',
  ];
  assert.equal(forbidden.includes('x-agent-call-id'), false);
  for (const name of forbidden) {
    await t.test(name, async () => {
      const { app, calls } = create();
      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST', headers: agentHeaders({ [name]: 'attacker-choice' }),
        body: '{"input":"hello"}',
      });
      assert.equal(response.status, 400);
      assert.equal((await json(response)).error.code, 'AGENT_FORBIDDEN_HEADER');
      assert.equal(calls.some(({ name: callName }) => callName === 'execute'), false);
    });
  }
});

test('missing, malformed, and duplicate-ish Agent call IDs fail before body read or execution', async (t) => {
  const validHeaders = agentHeaders();
  const missingHeaders = { ...validHeaders };
  delete missingHeaders['x-agent-call-id'];
  const duplicateHeaders = new Headers(validHeaders);
  duplicateHeaders.append('x-agent-call-id', Buffer.alloc(32, 0x43).toString('base64url'));
  const cases = [
    ['missing', missingHeaders],
    ['empty', agentHeaders({ 'x-agent-call-id': '' })],
    ['noncanonical', agentHeaders({ 'x-agent-call-id': `${AGENT_CALL_ID}=` })],
    ['wrong length', agentHeaders({ 'x-agent-call-id': AGENT_CALL_ID.slice(1) })],
    ['duplicate-ish', duplicateHeaders],
  ];
  for (const [label, headers] of cases) {
    await t.test(label, async () => {
      let bodyReaderCalls = 0;
      const { app, calls } = create();
      const body = new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode('{"input":"hello"}'));
          controller.close();
        },
      });
      const getReader = body.getReader.bind(body);
      Object.defineProperty(body, 'getReader', {
        value(...args) {
          bodyReaderCalls += 1;
          return getReader(...args);
        },
      });
      const response = await app.request(new Request(
        `${ORIGIN}/agent/v1/invoke/example-skill`,
        { method: 'POST', headers, body, duplex: 'half' },
      ));

      assert.equal(response.status, 400);
      assert.deepEqual(await json(response), {
        error: {
          code: 'AGENT_CALL_ID_INVALID',
          message: 'Agent call ID must be one canonical 32-byte token',
        },
      });
      assert.equal(bodyReaderCalls, 0);
      assert.equal(calls.some(({ name }) => name === 'execute'), false);
    });
  }
});

test('only normalized accept, content-type, and user-agent reach the Kernel ordinary request', async () => {
  const receipt = signedReceipt({ resourcePath: '/paid/skill', purposeLabel: 'skill.invoke' });
  const { app, calls } = create({
    kernel: {
      async execute(input) {
        calls.push({ name: 'execute', input });
        return Object.freeze({
          requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200, body: Buffer.from('{"ok":true}'), receipt,
        });
      },
      statusByRequestId() { return statusView(receipt); },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST',
    headers: agentHeaders({
      host: 'attacker.example',
      connection: 'keep-alive',
      cookie: 'secret-cookie',
      forwarded: 'for=attacker',
      'x-forwarded-for': '203.0.113.8',
      'proxy-authorization': 'Basic secret',
      'x-api-key': 'provider-secret',
    }),
    body: '{"input":"hello"}',
  });
  assert.equal(response.status, 200);
  const headers = calls.find(({ name }) => name === 'execute').input.request.headers;
  assert.deepEqual(headers, {
    accept: 'application/json',
    'content-type': 'application/json',
    'user-agent': 'pi-agent/1',
  });
  assert.equal(JSON.stringify(headers).includes('secret'), false);
  assert.equal(JSON.stringify(headers).includes('attacker'), false);
});

test('request bodies are bounded duplicate-free JSON objects and validation occurs before execution', async (t) => {
  const cases = [
    ['wrong content type', { headers: agentHeaders({ 'content-type': 'application/json; charset=utf-8' }), body: '{"a":1}' }, 415, 'AGENT_CONTENT_TYPE'],
    ['missing body', { headers: agentHeaders() }, 400, 'AGENT_BODY_REQUIRED'],
    ['duplicate top-level key', { headers: agentHeaders(), body: '{"a":1,"a":2}' }, 400, 'AGENT_BODY_SCHEMA'],
    ['duplicate decoded nested key', { headers: agentHeaders(), body: '{"nested":{"a":1,"\\u0061":2}}' }, 400, 'AGENT_BODY_SCHEMA'],
    ['array body', { headers: agentHeaders(), body: '[1,2,3]' }, 400, 'AGENT_BODY_SCHEMA'],
    ['oversized declared body', { headers: agentHeaders({ 'content-length': '100' }), body: '{"a":1}' }, 413, 'AGENT_BODY_TOO_LARGE'],
  ];
  for (const [label, init, expectedStatus, expectedCode] of cases) {
    await t.test(label, async () => {
      const { app, calls } = create({ maximumRequestBytes: 32 });
      const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
        method: 'POST', ...init,
      });
      assert.equal(response.status, expectedStatus);
      assert.equal((await json(response)).error.code, expectedCode);
      assert.equal(calls.some(({ name }) => name === 'execute'), false);
    });
  }

  await t.test('streamed overflow', async () => {
    const { app, calls } = create({ maximumRequestBytes: 16 });
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(10).fill(0x20));
        controller.enqueue(new Uint8Array(10).fill(0x20));
        controller.close();
      },
    });
    const response = await app.request(new Request(
      `${ORIGIN}/agent/v1/invoke/example-skill`,
      { method: 'POST', headers: agentHeaders(), body, duplex: 'half' },
    ));
    assert.equal(response.status, 413);
    assert.equal((await json(response)).error.code, 'AGENT_BODY_TOO_LARGE');
    assert.equal(calls.some(({ name }) => name === 'execute'), false);
  });
});

test('ordinary Pi JSON is canonicalized once before intent hashing and upstream forwarding', async (t) => {
  for (const body of [
    '{"stream":true,"model":"scripted-local","messages":[{"role":"user","content":"hello"}]}',
    ' { "stream": true, "model": "scripted-local", "messages": [ { "role": "user", "content": "hello" } ] }\n',
  ]) {
    await t.test(body.startsWith(' ') ? 'whitespace' : 'Pi key order', async () => {
      const receipt = signedReceipt();
      let execution;
      const { app } = create({
        kernel: {
          async execute(input) {
            execution = input;
            return Object.freeze({
              requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
              upstreamStatus: 200,
              body: Buffer.from([
                'data: {"choices":[],"id":"completion-1","object":"chat.completion.chunk"}',
                '',
                'data: [DONE]',
                '',
                '',
              ].join('\n')),
              receipt,
            });
          },
          statusByRequestId() {
            return statusView(receipt, { purposeLabel: 'model.infer' });
          },
        },
      });
      const response = await app.request(`${ORIGIN}/agent/v1/openai/example-model/chat/completions`, {
        method: 'POST', headers: agentHeaders(), body,
      });
      assert.equal(response.status, 200, await response.clone().text());
      assert.deepEqual(
        execution.request.bodyBytes,
        Buffer.from(canonicalJson(JSON.parse(body))),
      );
    });
  }
});

test('closed or policy-blocked session fails before route and body parsing', async () => {
  let bodyReaderCalls = 0;
  const { app, calls } = create({
    auth: {
      resolveBoundSession(principal) {
        calls.push({ name: 'resolveBoundSession', principal });
        throw new KernelError('POLICY_TRANSITION_REQUIRED', 'private policy detail');
      },
    },
  });
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array([0x7b])); controller.close(); },
  });
  const getReader = body.getReader.bind(body);
  Object.defineProperty(body, 'getReader', {
    value(...args) { bodyReaderCalls += 1; return getReader(...args); },
  });
  const response = await app.request(new Request(
    `${ORIGIN}/agent/v1/invoke/unknown?target=https://attacker.example`,
    { method: 'POST', headers: agentHeaders(), body, duplex: 'half' },
  ));
  assert.equal(response.status, 409);
  assert.equal((await json(response)).error.code, 'POLICY_TRANSITION_REQUIRED');
  assert.equal(bodyReaderCalls, 0);
  assert.deepEqual(calls.map(({ name }) => name), ['authenticate', 'resolveBoundSession']);
});

test('request body authority-like names cannot alter the fixed Kernel invocation', async () => {
  const receipt = signedReceipt({ resourcePath: '/paid/skill', purposeLabel: 'skill.invoke' });
  const { app, calls } = create({
    kernel: {
      async execute(input) {
        calls.push({ name: 'execute', input });
        return Object.freeze({
          requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
          upstreamStatus: 200, body: Buffer.from('{"ok":true}'), receipt,
        });
      },
      statusByRequestId() { return statusView(receipt); },
    },
  });
  const body = canonicalJson({
    amount: '999999999',
    approvalId: 'approval-attacker',
    headers: { 'payment-signature': 'forged' },
    idempotencyKey: 'attacker-key',
    method: 'DELETE',
    payee: '0x9999999999999999999999999999999999999999',
    policy: 'allow-all',
    sessionId: 'session-attacker',
    targetUrl: 'https://attacker.example/drain',
    wallet: '0x9999999999999999999999999999999999999999',
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body,
  });
  assert.equal(response.status, 200);
  const execution = calls.find(({ name }) => name === 'execute').input;
  assert.deepEqual(Object.keys(execution).sort(), [
    'correlationId', 'purposeLabel', 'request', 'routeId', 'sessionId',
  ]);
  assert.equal(execution.sessionId, 'session-1');
  assert.equal(execution.routeId, 'example-skill');
  assert.equal(execution.request.method, 'POST');
  assert.equal(execution.request.requestUrl, 'https://seller.example/paid/skill');
  assert.deepEqual(execution.request.headers, {
    accept: 'application/json',
    'content-type': 'application/json',
    'user-agent': 'pi-agent/1',
  });
  assert.deepEqual(execution.request.bodyBytes, Buffer.from(body));
});

test('invalid or oversized upstream JSON never crosses the agent response boundary', async (t) => {
  for (const [label, body] of [
    ['invalid JSON', Buffer.from('PROVIDER_EXCEPTION_SENTINEL')],
    ['JSON array', Buffer.from('["private"]')],
    ['oversized JSON', Buffer.from(`{"value":"${'x'.repeat(1_048_577)}"}`)],
  ]) {
    await t.test(label, async () => {
      const receipt = signedReceipt();
      const { app } = create({
        kernel: {
          async execute() {
            return Object.freeze({
              requestId: 'request-1', status: 'completed', reasonCode: 'PAYMENT_SETTLED',
              upstreamStatus: 200, body, receipt,
            });
          },
          statusByRequestId() { return statusView(receipt); },
        },
      });
      const response = await app.request(
        `${ORIGIN}/agent/v1/openai/example-model/chat/completions`,
        { method: 'POST', headers: agentHeaders(), body: '{"messages":[]}' },
      );
      assert.equal(response.status, 502);
      const serialized = JSON.stringify(await json(response));
      assert.equal(serialized.includes('PROVIDER_EXCEPTION_SENTINEL'), false);
      assert.equal(serialized.includes(receipt.signature), false);
    });
  }
});

test('arbitrary Kernel exceptions are redacted to one stable internal failure', async () => {
  const { app } = create({
    kernel: {
      async execute() {
        const error = new KernelError('PROVIDER_PRIVATE_FAILURE', 'provider-secret-value');
        error.privateResponse = 'PROVIDER_EXCEPTION_SENTINEL';
        throw error;
      },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/invoke/example-skill`, {
    method: 'POST', headers: agentHeaders(), body: '{"input":"hello"}',
  });
  assert.equal(response.status, 500);
  const serialized = JSON.stringify(await json(response));
  assert.equal(serialized, JSON.stringify({
    error: { code: 'AGENT_INTERNAL', message: 'Agent request failed' },
  }));
  assert.equal(serialized.includes('provider-secret-value'), false);
  assert.equal(serialized.includes('PROVIDER_EXCEPTION_SENTINEL'), false);
});

test('receipt route rejects a signed projection that is not bound to the current session', async () => {
  const receipt = signedReceipt();
  const forged = structuredClone(receipt);
  forged.receipt.intent.sessionId = 'session-other';
  const { app } = create({
    kernel: {
      receiptById() { return statusView(Object.freeze(forged)); },
    },
  });
  const response = await app.request(`${ORIGIN}/agent/v1/receipts/receipt-1`, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  });
  assert.equal(response.status, 502);
  assert.equal((await json(response)).error.code, 'AGENT_RESPONSE_INVALID');
});

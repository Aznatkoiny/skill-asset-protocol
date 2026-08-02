import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { Worker } from 'node:worker_threads';

import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import {
  canonicalIntentFingerprint,
  FORBIDDEN_AGENT_HEADERS,
  createIntentRepository,
} from '../src/kernel/intent-builder.mjs';
import { createPolicyRepository } from '../src/kernel/policy-repository.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:00.000Z';
const WALLET = '0x1000000000000000000000000000000000000000';
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;
const ROUTE_METADATA = Object.freeze({
  'example-skill': Object.freeze({
    description: 'offline fixture',
    mimeType: 'application/json',
  }),
});
const POLICY = JSON.parse(fs.readFileSync(
  new URL('../policies/base-sepolia.example.json', import.meta.url),
  'utf8',
));

function sequenceIds() {
  const counts = new Map();
  return (kind) => {
    const next = (counts.get(kind) ?? 0) + 1;
    counts.set(kind, next);
    return `${kind}-${next}`;
  };
}

function trackedIds() {
  const calls = [];
  const factory = (kind) => {
    calls.push(kind);
    return `${kind}-${calls.filter((entry) => entry === kind).length}`;
  };
  factory.calls = calls;
  return factory;
}

function setup(t, {
  idFactory = sequenceIds(),
  allowLoopbackHttp = false,
  now = () => NOW,
} = {}) {
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now,
  });
  t.after(() => store.close());
  const activePolicy = createPolicyRepository(store).apply(POLICY, NOW).policyVersion;
  const enrolled = createAgentEnrollmentRepository({ store, now }).enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const intents = createIntentRepository({
    store,
    idFactory,
    now,
    allowLoopbackHttp,
    routeMetadata: ROUTE_METADATA,
  });
  return { activePolicy, enrolled, intents, store };
}

function ordinaryRequest(overrides = {}) {
  return {
    routeId: 'example-skill',
    method: 'POST',
    requestUrl: 'https://seller.example/paid/infer',
    headers: { 'content-type': 'application/json', accept: 'application/json' },
    bodyBytes: Buffer.from('{"prompt":"redacted after hashing"}'),
    purposeLabel: 'skill.invoke',
    correlationId: 'pi-call-001',
    ...overrides,
  };
}

function requestWithoutCorrelation(overrides = {}) {
  const request = ordinaryRequest(overrides);
  delete request.correlationId;
  return request;
}

function assertKernelError(operation, expectedCode) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

function openSession(context) {
  return context.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
}

function paymentRequired(overrides = {}) {
  return {
    x402Version: 2,
    error: 'seller prose',
    resource: {
      url: 'https://seller.example/paid/infer',
      description: 'offline fixture',
      mimeType: 'application/json',
    },
    accepts: [{
      scheme: 'exact',
      network: 'eip155:84532',
      asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
      amount: '50000',
      payTo: '0x2000000000000000000000000000000000000000',
      maxTimeoutSeconds: 60,
      extra: { name: 'USDC', version: '2' },
    }],
    ...overrides,
  };
}

function capturedContext(t, request = ordinaryRequest()) {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...request });
  return { ...context, session, intent, request };
}

function terminalCloseContext(t) {
  const context = capturedContext(t);
  context.intents.transition({
    intentId: context.intent.id,
    expectedState: 'captured',
    nextState: 'terminal',
    reasonCode: 'TEST_TERMINAL',
  });
  context.store.execForTest(`INSERT INTO buyer_outcomes(
      intent_id, status, reason_code, revision, recorded_at
    )
      VALUES ('${context.intent.id}', 'payment_denied', 'TEST_TERMINAL', 1, '${NOW}');
  `);
  return context;
}

function blockedSessionContext(t) {
  const context = setup(t);
  const session = openSession(context);
  const nextPolicy = structuredClone(POLICY);
  nextPolicy.sellers[0].autoApproveAtomic = '50000';
  const targetPolicy = createPolicyRepository(context.store).apply(
    nextPolicy,
    '2026-07-31T12:01:00.000Z',
  ).policyVersion;
  const blockedSession = context.intents.getSession(session.id);
  assert.equal(blockedSession.state, 'policy_blocked');
  return { ...context, session, blockedSession, targetPolicy };
}

function sqlText(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function nextWorkerMessage(worker) {
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      worker.off('message', onMessage);
      worker.off('error', onError);
      worker.off('exit', onExit);
    };
    const onMessage = (message) => {
      cleanup();
      resolve(message);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onExit = (code) => {
      cleanup();
      reject(new Error(`capture worker exited before replying with code ${code}`));
    };
    worker.once('message', onMessage);
    worker.once('error', onError);
    worker.once('exit', onExit);
  });
}

test('opens a wallet-bound Spend Session and persists an exact privacy-safe Spend Intent', (t) => {
  const { activePolicy, enrolled, intents, store } = setup(t);

  const session = intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  const intent = intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });

  assert.equal(session.id, 'session-1');
  assert.match(session.sessionHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(intent.id, 'intent-1');
  assert.equal(intent.requestId, 'request-1');
  assert.equal(intent.enrollmentHash, enrolled.enrollmentHash);
  assert.equal(intent.routeId, 'example-skill');
  assert.equal(intent.sellerOrigin, 'https://seller.example');
  assert.equal(intent.resourcePath, '/paid/infer');
  assert.match(intent.requestUrlHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(intent.bodyHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(intent.headerAllowlistHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(intent.intentHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(intent.idempotencyKey, /^wk_[0-9a-f]{64}$/);
  assert.equal(intent.intentHash, sha256(canonicalJson({
    requestId: intent.requestId,
    sessionId: intent.sessionId,
    enrollmentHash: intent.enrollmentHash,
    routeId: intent.routeId,
    method: intent.method,
    requestUrlHash: intent.requestUrlHash,
    sellerOrigin: intent.sellerOrigin,
    resourcePath: intent.resourcePath,
    bodyHash: intent.bodyHash,
    headerAllowlistHash: intent.headerAllowlistHash,
    purposeLabel: intent.purposeLabel,
    correlationId: intent.correlationId,
    walletAddress: intent.walletAddress,
    policyVersionId: activePolicy.id,
  })));
  const captureEvent = store.events().find((row) => row.event_type === 'intent.captured');
  assert.equal(JSON.parse(captureEvent.data_json).sellerOrigin, intent.sellerOrigin);
  assert.equal(JSON.parse(captureEvent.data_json).resourcePath, intent.resourcePath);
  const persisted = store.readOne('SELECT * FROM spend_intents WHERE id = ?', [intent.id]);
  assert.equal(Object.values(persisted).map(String).join('\n').includes('redacted after hashing'), false);
});

test('Spend Session admission rejects base64url instance IDs that are not canonical tokens', (t) => {
  const { activePolicy, intents } = setup(t);
  for (const agentInstanceId of [
    `_${'A'.repeat(21)}`,
    `-${'A'.repeat(21)}`,
  ]) {
    assertKernelError(() => intents.openOrResumeSession({
      agentInstanceId,
      walletAddress: WALLET,
      policyVersionId: activePolicy.id,
    }), 'AGENT_INSTANCE_ID');
  }
});

test('agent-controlled payment headers and hostile header shapes never create an intent', (t) => {
  const context = setup(t);
  const session = openSession(context);
  for (const header of FORBIDDEN_AGENT_HEADERS) {
    for (const suppliedName of [header, header.toUpperCase()]) {
      assertKernelError(() => context.intents.captureIntent({
        sessionId: session.id,
        ...ordinaryRequest({
          headers: { [suppliedName]: 'forbidden' },
          correlationId: `header-${header.replaceAll('-', '_')}`,
        }),
      }), 'AGENT_HEADER_FORBIDDEN');
    }
  }
  for (const headers of [
    { Accept: 'application/json', accept: 'application/json' },
    { 'accept\r\nx-injected': 'application/json' },
    { accept: 'application/json\r\nx-injected: yes' },
    { accept: 'application/json\nx-injected: yes' },
    { 'x-not-allowlisted': 'value' },
    { accept: ['application/json'] },
  ]) {
    assertKernelError(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ headers, correlationId: 'hostile-header' }),
    }), headers['x-not-allowlisted'] ? 'AGENT_HEADER_UNSUPPORTED' : 'AGENT_HEADER_SCHEMA');
  }
  let getterCalls = 0;
  const accessorHeaders = {};
  Object.defineProperty(accessorHeaders, 'accept', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'application/json';
    },
  });
  assertKernelError(() => context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ headers: accessorHeaders }),
  }), 'AGENT_HEADER_SCHEMA');
  assert.equal(getterCalls, 0);
  assertKernelError(() => context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({
      headers: new Proxy({ accept: 'application/json' }, {}),
    }),
  }), 'AGENT_HEADER_SCHEMA');

  const canonical = canonicalIntentFingerprint(requestWithoutCorrelation({
    headers: { Accept: ' application/json ', 'Content-Type': ' application/json ' },
  }));
  const reordered = canonicalIntentFingerprint(requestWithoutCorrelation({
    headers: { 'content-type': 'application/json', accept: 'application/json' },
  }));
  assert.equal(canonical.headerAllowlistHash, reordered.headerAllowlistHash);
  assert.equal(canonical.ordinaryFingerprint, reordered.ordinaryFingerprint);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 0n);
});

test('session and request schemas reject caller authority and unsafe URLs without sentinel persistence', (t) => {
  const context = setup(t);
  assertKernelError(() => context.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
    sessionId: 'caller-session',
  }), 'SESSION_SCHEMA');
  const session = openSession(context);
  const unsafeUrls = [
    'https://user:pass@seller.example/paid/infer',
    'http://seller.example/paid/infer',
    'http://localhost:8787/paid/infer',
    'http://2130706433:8787/paid/infer',
    'http://127.0.0.1:8787/paid/infer',
    'https://seller.example/paid/infer#fragment',
    'https://seller.example/paid/infer#',
    'https://seller.example/paid/infer?prompt=RAW_PROMPT_SENTINEL',
    'https://seller.example/paid/infer?',
  ];
  for (const requestUrl of unsafeUrls) {
    assertKernelError(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ requestUrl }),
    }), 'REQUEST_URL');
  }
  for (const routeId of ['', 'not a token']) {
    assertKernelError(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ routeId }),
    }), 'ROUTE_ID');
  }
  assertKernelError(() => context.intents.captureIntent({
    sessionId: 'unknown-session',
    ...ordinaryRequest(),
  }), 'SESSION_UNKNOWN');
  const serialized = canonicalJson({
    rows: context.store.readAll('SELECT * FROM spend_intents'),
    events: context.store.events().map((row) => JSON.parse(row.data_json)),
  });
  assert.equal(serialized.includes('RAW_PROMPT_SENTINEL'), false);
});

test('loopback HTTP is explicit and accepts only canonical literal addresses', (t) => {
  const context = setup(t, { allowLoopbackHttp: true });
  const session = openSession(context);
  for (const [index, requestUrl] of [
    'http://127.0.0.1:8787/paid/infer',
    'http://[::1]:8787/paid/infer',
  ].entries()) {
    const captured = context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ requestUrl, correlationId: `loopback-${index}` }),
    });
    assert.equal(captured.requestUrlHash, sha256(requestUrl));
  }
  for (const requestUrl of [
    'http://localhost:8787/paid/infer',
    'http://127.1:8787/paid/infer',
    'http://2130706433:8787/paid/infer',
    'http://0177.0.0.1:8787/paid/infer',
    'http://[0:0:0:0:0:0:0:1]:8787/paid/infer',
    'http://192.168.1.1:8787/paid/infer',
    'http://user:pass@127.0.0.1:8787/paid/infer',
    'http://127.0.0.1:8787/paid/infer?raw=1',
    'http://[::1]:8787/paid/infer#fragment',
  ]) {
    assertKernelError(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ requestUrl, correlationId: 'bad-loopback' }),
    }), 'REQUEST_URL');
  }
});

test('correlation and active fingerprint layers collapse retries without aliasing mutations', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const originalRequest = ordinaryRequest();
  const first = context.intents.captureIntent({ sessionId: session.id, ...originalRequest });
  const exact = context.intents.captureIntent({ sessionId: session.id, ...originalRequest });
  const otherCorrelation = context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ correlationId: 'pi-call-002' }),
  });
  assert.deepEqual(exact, first);
  assert.deepEqual(otherCorrelation, first);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 1);
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: originalRequest,
  }), first.id);
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: ordinaryRequest({
      bodyBytes: Buffer.from('changed'),
      correlationId: 'changed-body',
    }),
  }), null);
  assertKernelError(() => context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ bodyBytes: Buffer.from('changed') }),
  }), 'CORRELATION_CONFLICT');

  context.intents.transition({
    intentId: first.id,
    expectedState: 'captured',
    nextState: 'terminal',
    reasonCode: 'TEST_TERMINAL',
  });
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: originalRequest,
  }), first.id);
  assertKernelError(() => context.intents.matchRetry({
    sessionId: session.id,
    request: ordinaryRequest({
      correlationId: originalRequest.correlationId,
      purposeLabel: 'different.purpose',
    }),
  }), 'CORRELATION_CONFLICT');
});

test('correlation-less fingerprint replay does not resample Kernel-issued IDs', (t) => {
  const idFactory = trackedIds();
  const context = setup(t, { idFactory });
  const session = openSession(context);
  const request = requestWithoutCorrelation();
  const first = context.intents.captureIntent({ sessionId: session.id, ...request });
  const callsAfterFirst = [...idFactory.calls];
  const replay = context.intents.captureIntent({ sessionId: session.id, ...request });

  assert.equal(replay.id, first.id);
  assert.equal(replay.requestId, first.requestId);
  assert.deepEqual(idFactory.calls, callsAfterFirst);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 1n);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 1);
  assert.equal(context.intents.matchRetry({ sessionId: session.id, request }), first.id);
  assert.equal(context.intents.matchRetry({ sessionId: 'another-session', request }), null);
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: requestWithoutCorrelation({ bodyBytes: Buffer.from('changed') }),
  }), null);
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: requestWithoutCorrelation({ purposeLabel: 'inference.invoke' }),
  }), null);
});

test('an ordinary follower correlation remains durably bound after terminal release', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const first = context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ correlationId: 'pi-call-primary' }),
  });
  const followerRequest = ordinaryRequest({ correlationId: 'pi-call-follower' });
  const follower = context.intents.captureIntent({ sessionId: session.id, ...followerRequest });
  assert.equal(follower.id, first.id);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.correlation_bound',
  ).length, 1);

  context.intents.transition({
    intentId: first.id,
    expectedState: 'captured',
    nextState: 'terminal',
    reasonCode: 'TEST_TERMINAL',
  });
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: followerRequest,
  }), first.id);
  assert.equal(context.intents.captureIntent({
    sessionId: session.id,
    ...followerRequest,
  }).id, first.id);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 1n);

  const later = context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ correlationId: 'pi-call-later' }),
  });
  assert.notEqual(later.id, first.id);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 2n);
});

test('capture owns its byte snapshot and simultaneous ordinary followers share one intent', async (t) => {
  const context = setup(t);
  const session = openSession(context);
  const body = Buffer.from('{"prompt":"owned snapshot"}');
  const original = Buffer.from(body);
  const first = context.intents.captureIntent({
    sessionId: session.id,
    ...requestWithoutCorrelation({ bodyBytes: body }),
  });
  body.fill(0x78);
  assert.equal(context.intents.matchRetry({
    sessionId: session.id,
    request: requestWithoutCorrelation({ bodyBytes: original }),
  }), first.id);

  const [left, right] = await Promise.all([
    Promise.resolve().then(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ correlationId: 'parallel-left' }),
    })),
    Promise.resolve().then(() => context.intents.captureIntent({
      sessionId: session.id,
      ...ordinaryRequest({ correlationId: 'parallel-right' }),
    })),
  ]);
  assert.equal(left.id, right.id);
  assert.equal(left.requestId, right.requestId);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 2n);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 2);
});

test('captureIntentInTransaction succeeds only inside its live authority scope', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const captured = context.store.transaction((token) => (
    context.intents.captureIntentInTransaction(token, {
      sessionId: session.id,
      ...ordinaryRequest({ correlationId: 'scoped-capture' }),
    })
  ));

  assert.equal(context.intents.getIntent(captured.id).id, captured.id);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 1n);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 1);

  let staleToken;
  context.store.transaction((token) => {
    staleToken = token;
  });
  for (const token of [Object.freeze(Object.create(null)), staleToken]) {
    assert.throws(() => context.intents.captureIntentInTransaction(token, {
      sessionId: session.id,
      ...ordinaryRequest({ correlationId: 'invalid-scope-capture' }),
    }), /invalid authority transaction/);
  }
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 1n);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 1);
});

test('captureIntentInTransaction rolls intent, request authority, and event back with its owner', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const eventsBefore = context.store.events().length;

  assert.throws(() => context.store.transaction((token) => {
    const captured = context.intents.captureIntentInTransaction(token, {
      sessionId: session.id,
      ...ordinaryRequest({ correlationId: 'rolled-back-capture' }),
    });
    assert.equal(captured.state, 'captured');
    throw new Error('outer aggregate fault');
  }), /outer aggregate fault/);

  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 0n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(DISTINCT request_id) AS count FROM spend_intents',
  ).count, 0n);
  assert.equal(context.store.events().length, eventsBefore);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 0);
});

test('challenge attachment is canonical, one-way, active-epoch bound, and transaction scoped', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  const challenge = paymentRequired();
  const attached = context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: challenge,
    challengeReceivedAt: NOW,
  });
  assert.equal(attached.state, 'challenged');
  assert.match(attached.challengeHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(attached.challengeProjectionJson.includes(challenge.resource.url), false);
  assert.equal(attached.challengeProjectionJson.includes(challenge.error), false);
  assert.equal(JSON.parse(attached.challengeProjectionJson).resource.urlHash,
    sha256(challenge.resource.url));
  const events = context.store.events().filter(
    (row) => row.event_type === 'intent.challenge_attached',
  );
  const replay = context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: { ...challenge, error: 'different unbound seller prose' },
    challengeReceivedAt: NOW,
  });
  assert.deepEqual(replay, attached);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'intent.challenge_attached',
  ).length, events.length);

  const changed = paymentRequired({
    accepts: [{ ...challenge.accepts[0], amount: '50001' }],
  });
  assertKernelError(() => context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: changed,
    challengeReceivedAt: NOW,
  }), 'CHALLENGE_CHANGED');
  assert.throws(() => context.intents.attachChallengeInTransaction(
    Object.freeze(Object.create(null)),
    { intentId: intent.id, paymentRequired: challenge, challengeReceivedAt: NOW },
  ), /invalid authority transaction/);

  const second = context.intents.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({ correlationId: 'challenge-rollback', bodyBytes: Buffer.from('two') }),
  });
  assert.throws(() => context.store.transaction((token) => {
    context.intents.attachChallengeInTransaction(token, {
      intentId: second.id,
      paymentRequired: challenge,
      challengeReceivedAt: NOW,
    });
    throw new Error('aggregate fault');
  }), /aggregate fault/);
  assert.equal(context.intents.getIntent(second.id).state, 'captured');
  assert.equal(context.intents.getIntent(second.id).challengeHash, null);
});

test('challenge attachment binds the intent URL and rejects a revoked enrollment even on replay', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  assertKernelError(() => context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: paymentRequired({
      resource: {
        url: 'https://seller.example/paid/other',
        description: 'offline fixture',
        mimeType: 'application/json',
      },
    }),
    challengeReceivedAt: NOW,
  }), 'CHALLENGE_RESOURCE_MISMATCH');
  context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: paymentRequired(),
    challengeReceivedAt: NOW,
  });
  createAgentEnrollmentRepository({ store: context.store, now: () => NOW }).revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  assertKernelError(() => context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: paymentRequired(),
    challengeReceivedAt: NOW,
  }), 'AGENT_REVOKED');
});

test('challenge persistence requires exact operator-owned route metadata', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  for (const resource of [
    {
      url: 'https://seller.example/paid/infer',
      description: 'RAW_PROMPT_SENTINEL',
      mimeType: 'application/json',
    },
    {
      url: 'https://seller.example/paid/infer',
      description: 'offline fixture',
      mimeType: 'text/plain',
    },
  ]) {
    assertKernelError(() => context.intents.attachChallenge({
      intentId: intent.id,
      paymentRequired: paymentRequired({ resource }),
      challengeReceivedAt: NOW,
    }), 'CHALLENGE_RESOURCE_METADATA_MISMATCH');
  }
  assert.equal(context.intents.getIntent(intent.id).state, 'captured');
  const persistedText = [
    ...context.store.readAll('SELECT * FROM spend_intents')
      .flatMap((row) => Object.values(row).map(String)),
    ...context.store.events().map((event) => event.data_json),
  ].join('\n');
  assert.equal(persistedText.includes('RAW_PROMPT_SENTINEL'), false);

  const repositoryWithoutRouteMap = createIntentRepository({
    store: context.store,
    idFactory: sequenceIds(),
    now: () => NOW,
  });
  assertKernelError(() => repositoryWithoutRouteMap.attachChallenge({
    intentId: intent.id,
    paymentRequired: paymentRequired(),
    challengeReceivedAt: NOW,
  }), 'ROUTE_METADATA_REQUIRED');
});

test('intent transitions enforce the strict graph and terminal retry release', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  context.intents.attachChallenge({
    intentId: intent.id,
    paymentRequired: paymentRequired(),
    challengeReceivedAt: NOW,
  });
  assertKernelError(() => context.intents.transition({
    intentId: intent.id,
    expectedState: 'challenged',
    nextState: 'signed',
    reasonCode: 'ILLEGAL_TEST',
  }), 'INTENT_TRANSITION');
  let current = context.intents.transition({
    intentId: intent.id,
    expectedState: 'challenged',
    nextState: 'authorized',
    reasonCode: 'POLICY_ALLOWED',
  });
  for (const [expectedState, nextState] of [
    ['authorized', 'reserved'],
    ['reserved', 'signing'],
    ['signing', 'signed'],
    ['signed', 'retrying'],
    ['retrying', 'unresolved'],
    ['unresolved', 'terminal'],
  ]) {
    current = context.intents.transition({
      intentId: intent.id,
      expectedState,
      nextState,
      reasonCode: `TO_${nextState.toUpperCase()}`,
    });
    assert.equal(current.state, nextState);
  }
  assert.equal(current.retryMatchable, false);
  assertKernelError(() => context.intents.transition({
    intentId: intent.id,
    expectedState: 'unresolved',
    nextState: 'terminal',
    reasonCode: 'STALE_REPLAY',
  }), 'INTENT_STATE_CONFLICT');
  assert.throws(() => context.intents.transitionInTransaction(
    Object.freeze(Object.create(null)),
    {
      intentId: intent.id,
      expectedState: 'terminal',
      nextState: 'terminal',
      reasonCode: 'FORGED',
    },
  ), /invalid authority transaction/);
});

test('guarded session close is hash-bound, atomic, replayable, and supports revoked cleanup', (t) => {
  const context = setup(t);
  const session = openSession(context);
  assertKernelError(() => context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: `sha256:${'00'.repeat(32)}`,
    })
  )), 'SESSION_CONFIRMATION_STALE');
  createAgentEnrollmentRepository({ store: context.store, now: () => NOW }).revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  const closed = context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  ));
  assert.equal(closed.closedSession.state, 'closed');
  const replay = context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  ));
  assert.deepEqual(replay, closed);
  assert.throws(() => context.intents.closeBoundSessionInTransaction(
    Object.freeze(Object.create(null)),
    { sessionId: session.id, expectedSessionHash: session.sessionHash },
  ), /invalid authority transaction/);
});

test('policy-blocked session transition closes the old pair and opens one active replacement', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const nextPolicy = structuredClone(POLICY);
  nextPolicy.sellers[0].autoApproveAtomic = '50000';
  const applied = createPolicyRepository(context.store).apply(
    nextPolicy,
    '2026-07-31T12:01:00.000Z',
  );
  const blocked = context.intents.getSession(session.id);
  assert.equal(blocked.state, 'policy_blocked');
  const transitioned = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: session.id,
      targetPolicyVersionId: applied.policyVersion.id,
      expectedSessionHash: blocked.sessionHash,
    })
  ));
  assert.equal(transitioned.previousSession.state, 'closed');
  assert.equal(transitioned.replacementSession.state, 'open');
  assert.equal(transitioned.replacementSession.policyVersionId, applied.policyVersion.id);
  const replay = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: session.id,
      targetPolicyVersionId: applied.policyVersion.id,
      expectedSessionHash: blocked.sessionHash,
    })
  ));
  assert.deepEqual(replay, transitioned);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'session.policy_transitioned',
  ).length, 1);
});

test('policy transition rejects stale confirmation and fake or stale transaction scopes', (t) => {
  const context = blockedSessionContext(t);
  const eventsBefore = context.store.events().length;
  const transition = (token, expectedSessionHash = context.blockedSession.sessionHash) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash,
    })
  );

  assertKernelError(() => context.store.transaction((token) => (
    transition(token, sha256('stale policy transition confirmation'))
  )), 'SESSION_CONFIRMATION_STALE');

  let staleToken;
  context.store.transaction((token) => {
    staleToken = token;
  });
  for (const token of [Object.freeze(Object.create(null)), staleToken]) {
    assert.throws(() => transition(token), /invalid authority transaction/);
  }

  assert.equal(context.intents.getSession(context.session.id).state, 'policy_blocked');
  const unchangedPair = context.store.readOne(`SELECT spend_sessions.state AS session_state,
      agent_session_bindings.state AS binding_state
    FROM spend_sessions JOIN agent_session_bindings
      ON agent_session_bindings.session_id = spend_sessions.id
    WHERE spend_sessions.id = ?`, [context.session.id]);
  assert.equal(unchangedPair.session_state, 'policy_blocked');
  assert.equal(unchangedPair.binding_state, 'open');
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 1n);
  assert.equal(context.store.events().length, eventsBefore);
  assert.equal(context.store.events().filter((row) => [
    'session.binding_closed',
    'session.policy_transitioned',
  ].includes(row.event_type)).length, 0);
});

test('policy transition rolls the old close, replacement pair, and events back with its owner', (t) => {
  const context = blockedSessionContext(t);
  const eventsBefore = context.store.events().length;

  assert.throws(() => context.store.transaction((token) => {
    const provisional = context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    });
    assert.equal(provisional.previousSession.state, 'closed');
    assert.equal(provisional.replacementSession.state, 'open');
    throw new Error('outer aggregate fault');
  }), /outer aggregate fault/);

  assert.equal(context.intents.getSession(context.session.id).state, 'policy_blocked');
  const restoredPair = context.store.readOne(`SELECT spend_sessions.state AS session_state,
      agent_session_bindings.state AS binding_state
    FROM spend_sessions JOIN agent_session_bindings
      ON agent_session_bindings.session_id = spend_sessions.id
    WHERE spend_sessions.id = ?`, [context.session.id]);
  assert.equal(restoredPair.session_state, 'policy_blocked');
  assert.equal(restoredPair.binding_state, 'open');
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 1n);
  assert.equal(context.store.readOne(
    'SELECT COUNT(*) AS count FROM agent_session_bindings',
  ).count, 1n);
  assert.equal(context.store.events().length, eventsBefore);
  assert.equal(context.store.events().filter((row) => [
    'session.binding_closed',
    'session.policy_transitioned',
  ].includes(row.event_type)).length, 0);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'session.started',
  ).length, 1);
});

test('policy transition exact replay retains the original replacement after a later policy blocks it', (t) => {
  const context = blockedSessionContext(t);
  const transitioned = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  ));
  const laterPolicy = structuredClone(POLICY);
  laterPolicy.sellers[0].autoApproveAtomic = '40000';
  createPolicyRepository(context.store).apply(
    laterPolicy,
    '2026-07-31T12:02:00.000Z',
  );
  assert.equal(
    context.intents.getSession(transitioned.replacementSession.id).state,
    'policy_blocked',
  );

  const replay = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  ));
  assert.deepEqual(replay, transitioned);
  assert.equal(replay.replacementSession.state, 'open');
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'session.policy_transitioned',
  ).length, 1);
});

test('policy transition exact replay retains the original replacement after enrollment revocation', (t) => {
  const context = blockedSessionContext(t);
  const transitioned = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  ));
  createAgentEnrollmentRepository({ store: context.store, now: () => NOW }).revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: context.enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });

  const replay = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  ));
  assert.deepEqual(replay, transitioned);
  assert.equal(context.store.events().filter(
    (row) => row.event_type === 'session.policy_transitioned',
  ).length, 1);
});

test('session close refuses nonterminal intent ambiguity and rolls back with its owner', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const intent = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  assertKernelError(() => context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  )), 'SESSION_MONETARY_AMBIGUITY');

  context.intents.transition({
    intentId: intent.id,
    expectedState: 'captured',
    nextState: 'terminal',
    reasonCode: 'TEST_TERMINAL',
  });
  context.store.execForTest(`INSERT INTO buyer_outcomes(
      intent_id, status, reason_code, revision, recorded_at
    ) VALUES ('${intent.id}', 'payment_denied', 'TEST_TERMINAL', 1, '${NOW}')`);
  assert.throws(() => context.store.transaction((token) => {
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    });
    throw new Error('aggregate fault');
  }), /aggregate fault/);
  assert.equal(context.intents.getSession(session.id).state, 'open');
});

test('capture commits before any injected transport probe', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const callerBody = Buffer.from('{"prompt":"owned outbound snapshot"}');
  const originalBody = Buffer.from(callerBody);
  let observed;
  const transport = {
    probe({ intent, bodyBytes }) {
      callerBody.fill(0x78);
      observed = context.store.readOne(
        'SELECT state FROM spend_intents WHERE id = ?', [intent.id],
      )?.state;
      assert.deepEqual(bodyBytes, originalBody);
      assert.equal(sha256(bodyBytes), intent.bodyHash);
      return 'unpaid';
    },
  };
  const captureThenProbe = (request) => {
    const bodyBytes = Buffer.from(request.bodyBytes);
    const intent = context.intents.captureIntent({
      sessionId: session.id,
      ...request,
      bodyBytes,
    });
    return transport.probe({ intent, bodyBytes });
  };
  assert.equal(captureThenProbe(ordinaryRequest({ bodyBytes: callerBody })), 'unpaid');
  assert.equal(observed, 'captured');
});

test('file-backed reopen resumes one exact authority and retains only request hashes', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-intent-reopen-'));
  fs.chmodSync(directory, 0o700);
  const databasePath = path.join(directory, 'kernel.sqlite');
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  let store;
  t.after(() => {
    try { store?.close(); } catch {}
    fs.rmSync(directory, { force: true, recursive: true });
  });
  store = openKernelStore({ filePath: databasePath, pathTrust, now: () => NOW });
  const activePolicy = createPolicyRepository(store).apply(POLICY, NOW).policyVersion;
  createAgentEnrollmentRepository({ store, now: () => NOW }).enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const firstRepository = createIntentRepository({
    store,
    idFactory: sequenceIds(),
    now: () => NOW,
  });
  const firstSession = firstRepository.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  const firstIntent = firstRepository.captureIntent({
    sessionId: firstSession.id,
    ...ordinaryRequest({
      bodyBytes: Buffer.from('{"prompt":"RAW_PROMPT_SENTINEL"}'),
    }),
  });
  store.close();

  let clockCalls = 0;
  const reopenedIds = trackedIds();
  store = openKernelStore({ filePath: databasePath, pathTrust, now: () => NOW });
  const reopened = createIntentRepository({
    store,
    idFactory: reopenedIds,
    now: () => {
      clockCalls += 1;
      return 'not-a-timestamp';
    },
  });
  const resumed = reopened.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  const retained = reopened.getIntent(firstIntent.id);

  assert.deepEqual(resumed, firstSession);
  assert.equal(retained.requestUrlHash, firstIntent.requestUrlHash);
  assert.equal(retained.bodyHash, firstIntent.bodyHash);
  assert.equal(retained.headerAllowlistHash, firstIntent.headerAllowlistHash);
  assert.deepEqual(reopenedIds.calls, []);
  assert.equal(clockCalls, 0);
  assert.equal(store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 1n);
  assert.equal(store.events().filter((row) => row.event_type === 'session.started').length, 1);
  assert.equal(store.readOne('SELECT COUNT(*) AS count FROM budget_reservations').count, 0n);
  const persistedText = [
    ...store.readAll('SELECT * FROM spend_intents'),
    ...store.events(),
  ].flatMap((row) => Object.values(row).map(String)).join('\n');
  assert.equal(persistedText.includes('RAW_PROMPT_SENTINEL'), false);
  store.close();
  store = null;
  for (const name of fs.readdirSync(directory)) {
    assert.equal(fs.readFileSync(path.join(directory, name)).includes('RAW_PROMPT_SENTINEL'), false);
  }
});

test('two file-backed worker stores race one initial capture to one durable winner', async (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-intent-race-'));
  fs.chmodSync(directory, 0o700);
  const databasePath = path.join(directory, 'kernel.sqlite');
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  const workers = [];
  let verifier;
  t.after(async () => {
    try { verifier?.close(); } catch {}
    await Promise.all(workers.map(async (worker) => {
      try { await worker.terminate(); } catch {}
    }));
    fs.rmSync(directory, { force: true, recursive: true });
  });

  let initializer = openKernelStore({ filePath: databasePath, pathTrust, now: () => NOW });
  const activePolicy = createPolicyRepository(initializer).apply(POLICY, NOW).policyVersion;
  createAgentEnrollmentRepository({ store: initializer, now: () => NOW }).enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });
  const session = createIntentRepository({
    store: initializer,
    idFactory: sequenceIds(),
    now: () => NOW,
  }).openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: activePolicy.id,
  });
  initializer.close();
  initializer = null;

  const gate = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT);
  const workerSource = `
    import { parentPort, threadId, workerData } from 'node:worker_threads';

    const { openKernelStore } = await import(workerData.storeModule);
    const { createIntentRepository } = await import(workerData.intentModule);
    const counts = new Map();
    const idFactory = (kind) => {
      const next = (counts.get(kind) ?? 0) + 1;
      counts.set(kind, next);
      return kind + '-' + next;
    };
    const store = openKernelStore({
      filePath: workerData.databasePath,
      pathTrust: Object.freeze(workerData.pathTrust),
      now: () => workerData.now,
    });
    const repository = createIntentRepository({
      store,
      idFactory,
      now: () => workerData.now,
    });
    parentPort.postMessage({ type: 'ready', threadId });
    parentPort.once('message', () => {
      let reply;
      try {
        const barrier = new Int32Array(workerData.gate);
        Atomics.add(barrier, 0, 1);
        Atomics.notify(barrier, 0);
        while (Atomics.load(barrier, 0) < 2) {
          if (Atomics.wait(barrier, 0, 1, 5000) === 'timed-out') {
            throw new Error('initial-capture race barrier timed out');
          }
        }
        const intent = repository.captureIntent({
          sessionId: workerData.sessionId,
          routeId: workerData.request.routeId,
          method: workerData.request.method,
          requestUrl: workerData.request.requestUrl,
          headers: workerData.request.headers,
          bodyBytes: Buffer.from(workerData.bodyBase64, 'base64'),
          purposeLabel: workerData.request.purposeLabel,
        });
        reply = {
          type: 'result',
          ok: true,
          threadId,
          id: intent.id,
          requestId: intent.requestId,
          intentHash: intent.intentHash,
        };
      } catch (error) {
        reply = {
          type: 'result',
          ok: false,
          threadId,
          errorCode: error?.code ?? null,
          errorMessage: error?.message ?? String(error),
          errorStack: error?.stack ?? null,
        };
      } finally {
        store.close();
      }
      parentPort.postMessage(reply);
      parentPort.close();
    });
  `;
  const workerUrl = new URL(
    `data:text/javascript;charset=utf-8,${encodeURIComponent(workerSource)}`,
  );
  const workerData = {
    storeModule: new URL('../src/kernel/sqlite-store.mjs', import.meta.url).href,
    intentModule: new URL('../src/kernel/intent-builder.mjs', import.meta.url).href,
    databasePath,
    pathTrust,
    now: NOW,
    gate,
    sessionId: session.id,
    request: requestWithoutCorrelation(),
    bodyBase64: ordinaryRequest().bodyBytes.toString('base64'),
  };
  delete workerData.request.bodyBytes;
  workers.push(
    new Worker(workerUrl, { workerData }),
    new Worker(workerUrl, { workerData }),
  );

  const ready = await Promise.all(workers.map((worker) => nextWorkerMessage(worker)));
  assert.deepEqual(ready.map((message) => message.type), ['ready', 'ready']);
  const resultPromises = workers.map((worker) => nextWorkerMessage(worker));
  for (const worker of workers) worker.postMessage('capture');
  const results = await Promise.all(resultPromises);
  for (const result of results) {
    assert.equal(result.ok, true, result.errorStack ?? result.errorMessage);
  }
  assert.notEqual(results[0].threadId, results[1].threadId);
  assert.equal(results[0].id, results[1].id);
  assert.equal(results[0].requestId, results[1].requestId);
  assert.equal(results[0].intentHash, results[1].intentHash);

  verifier = openKernelStore({ filePath: databasePath, pathTrust, now: () => NOW });
  assert.equal(verifier.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 1n);
  assert.equal(verifier.readOne(
    'SELECT COUNT(DISTINCT request_id) AS count FROM spend_intents',
  ).count, 1n);
  assert.equal(verifier.events().filter(
    (row) => row.event_type === 'intent.captured',
  ).length, 1);
});

test('changed wallet, policy, or enrollment epoch never resumes an existing session', (t) => {
  const walletContext = setup(t);
  const walletSession = openSession(walletContext);
  assertKernelError(() => walletContext.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: '0x4000000000000000000000000000000000000000',
    policyVersionId: walletContext.activePolicy.id,
  }), 'POLICY_WALLET_MISMATCH');
  assert.equal(walletContext.store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 1n);
  assert.equal(walletContext.intents.getSession(walletSession.id).id, walletSession.id);

  const policyContext = setup(t);
  const policySession = openSession(policyContext);
  const nextPolicy = structuredClone(POLICY);
  nextPolicy.sellers[0].autoApproveAtomic = '50000';
  const nextVersion = createPolicyRepository(policyContext.store).apply(
    nextPolicy,
    '2026-07-31T12:01:00.000Z',
  ).policyVersion;
  assertKernelError(() => policyContext.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: nextVersion.id,
  }), 'AGENT_SESSION_UNAVAILABLE');
  assert.equal(policyContext.intents.getSession(policySession.id).state, 'policy_blocked');

  const enrollmentContext = setup(t);
  const enrollmentSession = openSession(enrollmentContext);
  createAgentEnrollmentRepository({
    store: enrollmentContext.store,
    now: () => NOW,
  }).revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrollmentContext.enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  assertKernelError(() => enrollmentContext.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: enrollmentContext.activePolicy.id,
  }), 'AGENT_REVOKED');
  assert.equal(enrollmentContext.intents.getSession(enrollmentSession.id).id, enrollmentSession.id);
});

for (const scenario of [
  {
    name: 'closed session',
    code: 'SESSION_CLOSED',
    mutate(context, session) {
      const intentId = context.store.readOne(
        'SELECT id FROM spend_intents WHERE session_id = ?',
        [session.id],
      ).id;
      context.intents.transition({
        intentId,
        expectedState: 'captured',
        nextState: 'terminal',
        reasonCode: 'TEST_TERMINAL',
      });
      context.store.execForTest(`INSERT INTO buyer_outcomes
        (intent_id, status, reason_code, revision, recorded_at)
        VALUES ('${intentId}', 'payment_denied', 'TEST_TERMINAL', 1, '${NOW}')`);
      context.store.transaction((token) => context.intents.closeBoundSessionInTransaction(token, {
        sessionId: session.id,
        expectedSessionHash: session.sessionHash,
      }));
    },
  },
  {
    name: 'policy-blocked session',
    code: 'SESSION_POLICY_BLOCKED',
    mutate(context) {
      const nextPolicy = structuredClone(POLICY);
      nextPolicy.sellers[0].autoApproveAtomic = '50000';
      createPolicyRepository(context.store).apply(nextPolicy, '2026-07-31T12:01:00.000Z');
    },
  },
  {
    name: 'revoked enrollment',
    code: 'AGENT_REVOKED',
    mutate(context) {
      createAgentEnrollmentRepository({ store: context.store, now: () => NOW }).revoke({
        agentInstanceId: DESCRIPTOR.agentInstanceId,
        expectedEnrollmentHash: context.enrolled.enrollmentHash,
        operatorIdHash: OPERATOR_HASH,
      });
    },
  },
  {
    name: 'corrupted session pair',
    code: 'SESSION_AUTHORITY_AMBIGUOUS',
    mutate(context, session) {
      context.store.execForTest(`UPDATE spend_sessions
        SET adapter_id = 'pi:BBBBBBBBBBBBBBBBBBBBBB' WHERE id = '${session.id}'`);
    },
  },
]) {
  test(`matchRetry rejects ${scenario.name}`, (t) => {
    const context = setup(t);
    const session = openSession(context);
    const request = ordinaryRequest();
    context.intents.captureIntent({ sessionId: session.id, ...request });
    scenario.mutate(context, session);
    assertKernelError(() => context.intents.matchRetry({
      sessionId: session.id,
      request,
    }), scenario.code);
  });
}

test('matchRetry performs its authority check and lookup in one transaction', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const request = ordinaryRequest();
  const intent = context.intents.captureIntent({ sessionId: session.id, ...request });
  let transactionCount = 0;
  let transactionDepth = 0;
  const guardedStore = Object.freeze({
    transaction(operation) {
      transactionCount += 1;
      return context.store.transaction((token) => {
        transactionDepth += 1;
        try {
          return operation(token);
        } finally {
          transactionDepth -= 1;
        }
      });
    },
    within: context.store.within,
    readOne(...args) {
      if (transactionDepth === 0) throw new Error('read escaped authoritative transaction');
      return context.store.readOne(...args);
    },
    readAll(...args) {
      if (transactionDepth === 0) throw new Error('read escaped authoritative transaction');
      return context.store.readAll(...args);
    },
  });
  const repository = createIntentRepository({
    store: guardedStore,
    idFactory: sequenceIds(),
    now: () => NOW,
  });

  assert.equal(repository.matchRetry({ sessionId: session.id, request }), intent.id);
  assert.equal(transactionCount, 1);
});

for (const corruption of [
  {
    name: 'request/body hashes',
    sql: `body_hash = 'sha256:${'00'.repeat(32)}'`,
  },
  {
    name: 'intent hash',
    sql: `intent_hash = 'sha256:${'01'.repeat(32)}'`,
  },
  {
    name: 'idempotency binding',
    sql: `idempotency_key = 'wk_${'02'.repeat(32)}'`,
  },
  {
    name: 'state/challenge tuple',
    sql: "state = 'challenged'",
  },
  {
    name: 'partial challenge columns',
    sql: "state = 'challenged', challenge_projection_json = '{}'",
  },
  {
    name: 'canonical timestamps',
    sql: "updated_at = 'not-a-timestamp'",
  },
  {
    name: 'monotonic timestamps',
    sql: "created_at = '2026-07-31T12:01:00.000Z', updated_at = '2026-07-31T12:00:00.000Z'",
  },
]) {
  test(`getIntent fails closed on persisted ${corruption.name} corruption`, (t) => {
    const context = capturedContext(t);
    context.store.execForTest(`UPDATE spend_intents SET ${corruption.sql}
      WHERE id = '${context.intent.id}'`);
    assertKernelError(() => context.intents.getIntent(context.intent.id), 'INTENT_CORRUPTION');
  });
}

for (const operation of [
  {
    name: 'getIntent',
    invoke(context) {
      return context.intents.getIntent(context.intent.id);
    },
  },
  {
    name: 'captureIntent replay',
    invoke(context) {
      return context.intents.captureIntent({
        sessionId: context.session.id,
        ...context.request,
      });
    },
  },
  {
    name: 'matchRetry',
    invoke(context) {
      return context.intents.matchRetry({
        sessionId: context.session.id,
        request: context.request,
      });
    },
  },
  {
    name: 'attachChallenge',
    invoke(context) {
      return context.intents.attachChallenge({
        intentId: context.intent.id,
        paymentRequired: paymentRequired(),
        challengeReceivedAt: NOW,
      });
    },
  },
  {
    name: 'transition',
    invoke(context) {
      return context.intents.transition({
        intentId: context.intent.id,
        expectedState: 'captured',
        nextState: 'terminal',
        reasonCode: 'CORRUPTION_TEST',
      });
    },
  },
]) {
  test(`${operation.name} validates the complete persisted intent binding`, (t) => {
    const context = capturedContext(t);
    context.store.execForTest(`UPDATE spend_intents
      SET intent_hash = 'sha256:${'03'.repeat(32)}'
      WHERE id = '${context.intent.id}'`);
    assertKernelError(() => operation.invoke(context), 'INTENT_CORRUPTION');
  });
}

test('openOrResume rejects an open session paired to a closed binding before ID allocation', (t) => {
  const idFactory = trackedIds();
  const context = setup(t, { idFactory });
  const session = openSession(context);
  context.store.execForTest(`UPDATE agent_session_bindings
    SET state = 'closed', closed_at = '${NOW}' WHERE session_id = '${session.id}'`);
  const callsBeforeReplay = [...idFactory.calls];

  assertKernelError(() => context.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  }), 'SESSION_AUTHORITY_AMBIGUOUS');
  assert.deepEqual(idFactory.calls, callsBeforeReplay);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 1n);
});

test('openOrResume rejects an extra malformed live-adapter session pair', (t) => {
  const context = setup(t);
  const session = openSession(context);
  context.store.execForTest(`
    INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      SELECT 'session-extra', adapter_id, wallet_address, policy_version_id,
        'policy_blocked', created_at
      FROM spend_sessions WHERE id = '${session.id}';
    INSERT INTO agent_session_bindings
      (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
       state, created_at, last_seen_at, closed_at)
      VALUES ('binding-extra', '${DESCRIPTOR.agentInstanceId}',
       '${DESCRIPTOR.credentialDigest}', '${context.enrolled.enrollmentHash}',
       'session-extra', 'closed', '${NOW}', '${NOW}', '${NOW}');
  `);

  assertKernelError(() => context.intents.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  }), 'SESSION_AUTHORITY_AMBIGUOUS');
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_sessions').count, 2n);
});

test('Kernel-issued session ID collisions retry without reopening a historical authority', (t) => {
  const context = setup(t);
  const first = openSession(context);
  context.store.transaction((token) => context.intents.closeBoundSessionInTransaction(token, {
    sessionId: first.id,
    expectedSessionHash: first.sessionHash,
  }));
  const candidates = ['session-1', 'session-2'];
  const collisionRepository = createIntentRepository({
    store: context.store,
    idFactory: (kind) => (kind === 'session' ? candidates.shift() : `${kind}-collision`),
    now: () => '2026-07-31T12:02:00.000Z',
  });

  const replacement = collisionRepository.openOrResumeSession({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    walletAddress: WALLET,
    policyVersionId: context.activePolicy.id,
  });
  assert.equal(replacement.id, 'session-2');
  assert.equal(context.intents.getSession(first.id).state, 'closed');
  assert.equal(replacement.state, 'open');
});

test('Kernel-issued intent/request ID collisions retry without aliasing another request', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const first = context.intents.captureIntent({ sessionId: session.id, ...ordinaryRequest() });
  const candidates = {
    intent: ['intent-1', 'intent-2'],
    request: ['request-1', 'request-2'],
  };
  const collisionRepository = createIntentRepository({
    store: context.store,
    idFactory: (kind) => candidates[kind]?.shift() ?? `${kind}-collision`,
    now: () => '2026-07-31T12:02:00.000Z',
  });
  const second = collisionRepository.captureIntent({
    sessionId: session.id,
    ...ordinaryRequest({
      bodyBytes: Buffer.from('{"different":true}'),
      correlationId: 'pi-call-collision',
    }),
  });

  assert.equal(second.id, 'intent-2');
  assert.equal(second.requestId, 'request-2');
  assert.notEqual(second.intentHash, first.intentHash);
  assert.equal(context.store.readOne('SELECT COUNT(*) AS count FROM spend_intents').count, 2n);
  assert.equal(context.intents.getIntent(first.id).correlationId, 'pi-call-001');
});

const CLOSE_BLOCKERS = [
  ...['pending'].map((state) => ({
    name: `${state} approval`,
    insert(context) {
      context.store.execForTest(`INSERT INTO approvals
        (id, intent_id, decision, intent_hash, challenge_hash, quote_id,
         accepted_index, amount_ceiling_atomic, wallet_address, policy_version_id,
         expires_at)
        VALUES ('approval-${state}', '${context.intent.id}', '${state}',
         '${context.intent.intentHash}', 'sha256:${'11'.repeat(32)}',
         'sha256:${'12'.repeat(32)}', 0, '50000', '${WALLET}',
         '${context.activePolicy.id}', '2026-07-31T12:05:00.000Z')`);
    },
  })),
  ...['reserved', 'unresolved'].map((state) => ({
    name: `${state} budget reservation`,
    insert(context) {
      context.store.execForTest(`INSERT INTO budget_reservations
        (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
         released_atomic, unresolved_atomic, state, updated_at)
        VALUES ('${context.intent.id}', '${context.session.id}', 'https://seller.example',
         '${state === 'reserved' ? '50000' : '0'}', '0', '0',
         '${state === 'unresolved' ? '50000' : '0'}', '${state}', '${NOW}')`);
    },
  })),
  ...['reserved', 'signing', 'signed', 'retrying', 'unresolved'].map((state) => ({
    name: `${state} payment attempt`,
    insert(context) {
      context.store.execForTest(`INSERT INTO payment_attempts
        (id, intent_id, state, payment_required_projection_json, accepted_index,
         quote_id, created_at, updated_at)
        VALUES ('payment-${state}', '${context.intent.id}', '${state}', '{}', 0,
         'sha256:${'13'.repeat(32)}', '${NOW}', '${NOW}')`);
    },
  })),
  {
    name: 'pending payment reconciliation candidate',
    insert(context) {
      context.store.execForTest(`
        INSERT INTO payment_attempts
          (id, intent_id, state, payment_required_projection_json, accepted_index,
           quote_id, created_at, updated_at)
          VALUES ('payment-rejected', '${context.intent.id}', 'rejected', '{}', 0,
           'sha256:${'14'.repeat(32)}', '${NOW}', '${NOW}');
        INSERT INTO payment_reconciliation_candidates
          (id, intent_id, transaction_id, state, created_at, updated_at)
          VALUES ('candidate-1', '${context.intent.id}',
           '0x${'15'.repeat(32)}', 'pending', '${NOW}', '${NOW}');
      `);
    },
  },
  ...['refund_pending', 'reconciliation_required'].map((state) => ({
    name: `${state} execution resolution`,
    insert(context) {
      context.store.execForTest(`
        INSERT INTO execution_outcomes
          (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
          VALUES ('${context.intent.id}', 'failed', 500,
           'sha256:${'16'.repeat(32)}', '{}', '${NOW}');
        INSERT INTO execution_resolutions
          (intent_id, state, reason_code, blocks_wallet, opened_at)
          VALUES ('${context.intent.id}', '${state}', 'TEST_OPEN_CASE', 1, '${NOW}');
      `);
    },
  })),
  {
    name: 'unresolved execution outcome without a resolution row',
    insert(context) {
      context.store.execForTest(`INSERT INTO budget_reservations
        (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
         released_atomic, unresolved_atomic, state, committed_at, updated_at)
        VALUES ('${context.intent.id}', '${context.session.id}', 'https://seller.example',
         '0', '50000', '0', '0', 'committed', '${NOW}', '${NOW}');
        INSERT INTO execution_outcomes
          (intent_id, state, metadata_json, recorded_at)
          VALUES ('${context.intent.id}', 'unknown', '{}', '${NOW}')`);
    },
  },
  {
    name: 'latest unresolved reconciliation',
    insert(context) {
      context.store.execForTest(`INSERT INTO reconciliations
        (id, intent_id, kind, outcome, evidence_json, operator_id_hash, recorded_at)
        VALUES ('reconciliation-unresolved', '${context.intent.id}', 'payment',
         'unresolved', '{}', '${OPERATOR_HASH}', '${NOW}')`);
    },
  },
  ...['pending', 'unresolved'].map((state) => ({
    name: `${state} refund`,
    insert(context) {
      context.store.execForTest(`INSERT INTO refunds
        (id, intent_id, original_transaction_id, amount_atomic, state,
         created_at, updated_at)
        VALUES ('refund-${state}', '${context.intent.id}',
         '0x${'17'.repeat(32)}', '50000', '${state}', '${NOW}', '${NOW}')`);
    },
  })),
];

for (const blocker of CLOSE_BLOCKERS) {
  test(`guarded close rejects ${blocker.name}`, (t) => {
    const context = terminalCloseContext(t);
    blocker.insert(context);
    assertKernelError(() => context.store.transaction((token) => (
      context.intents.closeBoundSessionInTransaction(token, {
        sessionId: context.session.id,
        expectedSessionHash: context.session.sessionHash,
      })
    )), 'SESSION_MONETARY_AMBIGUITY');
    assert.equal(context.intents.getSession(context.session.id).state, 'open');
  });
}

test('guarded close ignores an approved row retained behind a terminal non-matchable intent', (t) => {
  const context = terminalCloseContext(t);
  context.store.execForTest(`INSERT INTO execution_outcomes
    (intent_id, state, http_status, response_hash, metadata_json, recorded_at)
    VALUES ('${context.intent.id}', 'unknown', NULL, NULL,
      '{"reasonCode":"UPSTREAM_TRANSPORT_FAILURE"}', '${NOW}');
    INSERT INTO approvals
    (id, intent_id, decision, operator_id_hash, intent_hash, challenge_hash, quote_id,
     accepted_index, amount_ceiling_atomic, wallet_address, policy_version_id,
     expires_at, decided_at)
    VALUES ('approval-approved-history', '${context.intent.id}', 'approved',
     '${OPERATOR_HASH}', '${context.intent.intentHash}', 'sha256:${'11'.repeat(32)}',
     'sha256:${'12'.repeat(32)}', 0, '50000', '${WALLET}',
     '${context.activePolicy.id}', '2026-07-31T12:05:00.000Z', '${NOW}')`);

  const closed = context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: context.session.id,
      expectedSessionHash: context.session.sessionHash,
    })
  ));

  assert.equal(closed.closedSession.state, 'closed');
  assert.equal(context.store.readOne(
    "SELECT decision FROM approvals WHERE id = 'approval-approved-history'",
  ).decision, 'approved');
});

test('exact close replay is event-bound and never consults a now-invalid clock', (t) => {
  let clockValue = NOW;
  const context = setup(t, { now: () => clockValue });
  const session = openSession(context);
  const closed = context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  ));
  clockValue = 'not-a-timestamp';
  const replay = context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  ));
  assert.deepEqual(replay, closed);
  assert.equal(context.store.events().filter((row) => row.event_type === 'session.closed').length, 1);
});

test('close replay rejects a canonical command event with unknown fields', (t) => {
  const context = setup(t);
  const session = openSession(context);
  context.store.transaction((token) => context.intents.closeBoundSessionInTransaction(token, {
    sessionId: session.id,
    expectedSessionHash: session.sessionHash,
  }));
  const event = context.store.readOne(`SELECT sequence, data_json FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?`, [
    'spend_session',
    session.id,
    'session.closed',
  ]);
  const tampered = canonicalJson({ ...JSON.parse(event.data_json), injected: true });
  context.store.execForTest(`UPDATE events SET data_json = '${tampered}'
    WHERE sequence = ${event.sequence}`);

  assertKernelError(() => context.store.transaction((token) => (
    context.intents.closeBoundSessionInTransaction(token, {
      sessionId: session.id,
      expectedSessionHash: session.sessionHash,
    })
  )), 'SESSION_AUTHORITY_AMBIGUOUS');
});

test('policy-transition replay rejects a canonical command event with unknown fields', (t) => {
  const context = setup(t);
  const session = openSession(context);
  const nextPolicy = structuredClone(POLICY);
  nextPolicy.sellers[0].autoApproveAtomic = '50000';
  const target = createPolicyRepository(context.store).apply(
    nextPolicy,
    '2026-07-31T12:01:00.000Z',
  ).policyVersion;
  const blocked = context.intents.getSession(session.id);
  context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: session.id,
      targetPolicyVersionId: target.id,
      expectedSessionHash: blocked.sessionHash,
    })
  ));
  const event = context.store.readOne(`SELECT sequence, data_json FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?`, [
    'spend_session',
    session.id,
    'session.policy_transitioned',
  ]);
  const tampered = canonicalJson({ ...JSON.parse(event.data_json), injected: true });
  context.store.execForTest(`UPDATE events SET data_json = '${tampered}'
    WHERE sequence = ${event.sequence}`);

  assertKernelError(() => context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: session.id,
      targetPolicyVersionId: target.id,
      expectedSessionHash: blocked.sessionHash,
    })
  )), 'SESSION_AUTHORITY_AMBIGUOUS');
});

function mutateLifecycleEvent(context, eventSpec, mutation) {
  const event = context.store.readOne(`SELECT sequence, entity_type, entity_id,
      event_type, data_json, previous_hash, event_hash, created_at
    FROM events WHERE entity_type = ? AND entity_id = ? AND event_type = ?`, [
    eventSpec.entityType,
    eventSpec.entityId,
    eventSpec.eventType,
  ]);
  assert.ok(event, `${eventSpec.eventType} fixture event must exist`);
  if (mutation === 'deleted') {
    context.store.execForTest(`DELETE FROM events WHERE sequence = ${event.sequence}`);
    return;
  }
  if (mutation === 'extra') {
    const extraHash = sha256(canonicalJson({
      domain: 'wallet-kernel.test.extra-lifecycle-event',
      eventType: event.event_type,
      sequence: String(event.sequence),
    }));
    context.store.execForTest(`INSERT INTO events(
        entity_type, entity_id, event_type, data_json, previous_hash, event_hash, created_at
      ) VALUES (
        ${sqlText(event.entity_type)},
        ${sqlText(event.entity_id)},
        ${sqlText(event.event_type)},
        ${sqlText(event.data_json)},
        ${event.previous_hash === null ? 'NULL' : sqlText(event.previous_hash)},
        ${sqlText(extraHash)},
        ${sqlText(event.created_at)}
      )`);
    return;
  }
  const data = JSON.parse(event.data_json);
  if (event.event_type === 'session.binding_closed') {
    data.reasonCode = 'FORGED_CLOSE_REASON';
  } else if (event.event_type === 'session.closed') {
    data.closedAt = '2026-07-31T12:00:01.000Z';
  } else {
    data.replacementSessionHash = sha256('forged replacement relationship');
  }
  context.store.execForTest(`UPDATE events
    SET data_json = ${sqlText(canonicalJson(data))}
    WHERE sequence = ${event.sequence}`);
}

for (const eventName of ['session.binding_closed', 'session.closed']) {
  for (const mutation of ['deleted', 'extra', 'tampered']) {
    test(`getSession and close replay reject ${mutation} ${eventName} lifecycle evidence`, (t) => {
      const context = setup(t);
      const session = openSession(context);
      context.store.transaction((token) => (
        context.intents.closeBoundSessionInTransaction(token, {
          sessionId: session.id,
          expectedSessionHash: session.sessionHash,
        })
      ));
      const bindingId = context.store.readOne(
        'SELECT id FROM agent_session_bindings WHERE session_id = ?',
        [session.id],
      ).id;
      mutateLifecycleEvent(context, {
        entityType: eventName === 'session.binding_closed'
          ? 'session_binding'
          : 'spend_session',
        entityId: eventName === 'session.binding_closed' ? bindingId : session.id,
        eventType: eventName,
      }, mutation);

      assertKernelError(() => context.intents.getSession(session.id),
        'SESSION_AUTHORITY_AMBIGUOUS');
      assertKernelError(() => context.store.transaction((token) => (
        context.intents.closeBoundSessionInTransaction(token, {
          sessionId: session.id,
          expectedSessionHash: session.sessionHash,
        })
      )), 'SESSION_AUTHORITY_AMBIGUOUS');
    });
  }
}

for (const eventName of ['session.binding_closed', 'session.policy_transitioned']) {
  for (const mutation of ['deleted', 'extra', 'tampered']) {
    test(`getSession and policy replay reject ${mutation} ${eventName} lifecycle evidence`, (t) => {
      const context = blockedSessionContext(t);
      context.store.transaction((token) => (
        context.intents.transitionBlockedSessionInTransaction(token, {
          sessionId: context.session.id,
          targetPolicyVersionId: context.targetPolicy.id,
          expectedSessionHash: context.blockedSession.sessionHash,
        })
      ));
      const bindingId = context.store.readOne(
        'SELECT id FROM agent_session_bindings WHERE session_id = ?',
        [context.session.id],
      ).id;
      mutateLifecycleEvent(context, {
        entityType: eventName === 'session.binding_closed'
          ? 'session_binding'
          : 'spend_session',
        entityId: eventName === 'session.binding_closed' ? bindingId : context.session.id,
        eventType: eventName,
      }, mutation);

      assertKernelError(() => context.intents.getSession(context.session.id),
        'SESSION_AUTHORITY_AMBIGUOUS');
      assertKernelError(() => context.store.transaction((token) => (
        context.intents.transitionBlockedSessionInTransaction(token, {
          sessionId: context.session.id,
          targetPolicyVersionId: context.targetPolicy.id,
          expectedSessionHash: context.blockedSession.sessionHash,
        })
      )), 'SESSION_AUTHORITY_AMBIGUOUS');
    });
  }
}

test('policy replay rejects an internally valid replacement forged outside its transition', (t) => {
  const context = blockedSessionContext(t);
  const transitioned = context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  ));
  const replacement = transitioned.replacementSession;
  const binding = context.store.readOne(
    'SELECT * FROM agent_session_bindings WHERE session_id = ?',
    [replacement.id],
  );
  const forgedCreatedAt = '2026-07-31T12:00:01.000Z';
  const forgedHash = sha256(canonicalJson({
    session: {
      id: replacement.id,
      adapterId: replacement.adapterId,
      walletAddress: replacement.walletAddress,
      policyVersionId: replacement.policyVersionId,
      state: 'open',
      createdAt: forgedCreatedAt,
      closedAt: null,
    },
    binding: {
      id: binding.id,
      agentInstanceId: binding.agent_instance_id,
      credentialDigest: binding.credential_digest,
      enrollmentHash: binding.enrollment_hash,
      sessionId: replacement.id,
      state: 'open',
      createdAt: forgedCreatedAt,
      lastSeenAt: forgedCreatedAt,
      closedAt: null,
    },
  }));
  const startedEvent = context.store.readOne(`SELECT sequence, data_json FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?`, [
    'spend_session',
    replacement.id,
    'session.started',
  ]);
  const openedEvent = context.store.readOne(`SELECT sequence, data_json FROM events
    WHERE entity_type = ? AND entity_id = ? AND event_type = ?`, [
    'session_binding',
    binding.id,
    'session.binding_opened',
  ]);
  const forgedStarted = {
    ...JSON.parse(startedEvent.data_json),
    createdAt: forgedCreatedAt,
    sessionHash: forgedHash,
  };
  const forgedOpened = {
    ...JSON.parse(openedEvent.data_json),
    createdAt: forgedCreatedAt,
  };
  context.store.execForTest(`
    UPDATE spend_sessions SET created_at = ${sqlText(forgedCreatedAt)}
      WHERE id = ${sqlText(replacement.id)};
    UPDATE agent_session_bindings
      SET created_at = ${sqlText(forgedCreatedAt)},
          last_seen_at = ${sqlText(forgedCreatedAt)}
      WHERE id = ${sqlText(binding.id)};
    UPDATE events SET data_json = ${sqlText(canonicalJson(forgedStarted))}
      WHERE sequence = ${startedEvent.sequence};
    UPDATE events SET data_json = ${sqlText(canonicalJson(forgedOpened))}
      WHERE sequence = ${openedEvent.sequence};
  `);

  assert.equal(context.intents.getSession(replacement.id).sessionHash, forgedHash);
  assertKernelError(() => context.intents.getSession(context.session.id),
    'SESSION_AUTHORITY_AMBIGUOUS');
  assertKernelError(() => context.store.transaction((token) => (
    context.intents.transitionBlockedSessionInTransaction(token, {
      sessionId: context.session.id,
      targetPolicyVersionId: context.targetPolicy.id,
      expectedSessionHash: context.blockedSession.sessionHash,
    })
  )), 'SESSION_AUTHORITY_AMBIGUOUS');
});

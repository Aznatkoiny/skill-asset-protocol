import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import { createAgentAuth } from '../src/agent/auth.mjs';
import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { validatePolicyDocument } from '../src/kernel/policy-engine.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const ORIGIN = 'http://127.0.0.1:8505';
const TOKEN = Buffer.alloc(32, 0x41).toString('base64url');
const WRONG_TOKEN = Buffer.alloc(32, 0x42).toString('base64url');
const INSTANCE_ID = Buffer.alloc(16, 0x31).toString('base64url');
const CREDENTIAL_DIGEST = sha256(Buffer.from(TOKEN, 'base64url'));
const WALLET = '0x1000000000000000000000000000000000000000';
const POLICY = validatePolicyDocument({
  schemaVersion: 1,
  network: 'eip155:84532',
  asset: '0x036cbd53842c5426634e7929541ec2318f3dcf7e',
  wallet: WALLET,
  methods: ['POST'],
  sellers: [{
    origin: 'https://seller.example',
    pathPrefixes: ['/paid/'],
    payTo: '0x2000000000000000000000000000000000000000',
    evidencePath: '/.well-known/wallet-kernel/evidence',
    executionSigner: '0x3000000000000000000000000000000000000000',
    refundSigner: '0x4000000000000000000000000000000000000000',
    refundSource: '0x5000000000000000000000000000000000000000',
    perRequestMaxAtomic: '500000',
    autoApproveAtomic: '100000',
    humanApproveAtomic: '500000',
    sellerSessionMaxAtomic: '1000000',
  }],
  sessionMaxAtomic: '2000000',
  rolling24hMaxAtomic: '5000000',
  challengeMaxAgeMs: 60000,
  approvalTtlMs: 300000,
  maxPendingApprovals: 20,
  defaultAction: 'deny',
});
const POLICY_VERSION = Object.freeze({
  id: 'policy-1',
  hash: sha256(canonicalJson(POLICY)),
  policy: POLICY,
});
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: INSTANCE_ID,
  credentialDigest: CREDENTIAL_DIGEST,
  agentUid: String(process.getuid()),
  agentGid: String(process.getgid()),
});
const ENROLLMENT_HASH = sha256(canonicalJson(DESCRIPTOR));

function activeRow(overrides = {}) {
  return {
    agent_instance_id: INSTANCE_ID,
    credential_digest: CREDENTIAL_DIGEST,
    enrollment_hash: ENROLLMENT_HASH,
    agent_uid: String(process.getuid()),
    agent_gid: String(process.getgid()),
    state: 'active',
    ...overrides,
  };
}

function bindingRow(overrides = {}) {
  return {
    binding_id: 'binding-1',
    agent_instance_id: INSTANCE_ID,
    credential_digest: CREDENTIAL_DIGEST,
    enrollment_hash: ENROLLMENT_HASH,
    session_id: 'session-1',
    binding_state: 'open',
    session_state: 'open',
    ...overrides,
  };
}

function dependencies({ enrollments = [activeRow()], bindings = [bindingRow()], session } = {}) {
  const calls = [];
  const state = { enrollments, bindings, session };
  return {
    calls,
    state,
    store: Object.freeze({
      readAll(sql, params = []) {
        calls.push({ kind: 'readAll', sql, params });
        if (sql.includes('FROM agent_enrollments')) return state.enrollments;
        if (sql.includes('FROM agent_session_bindings')) return state.bindings;
        throw new Error('unexpected read query');
      },
    }),
    intents: Object.freeze({
      getSession(sessionId) {
        calls.push({ kind: 'getSession', sessionId });
        return state.session ?? Object.freeze({
          id: 'session-1',
          adapterId: `pi:${INSTANCE_ID}`,
          agentInstanceId: INSTANCE_ID,
          enrollmentHash: ENROLLMENT_HASH,
          walletAddress: WALLET,
          policyVersionId: POLICY_VERSION.id,
          state: 'open',
          createdAt: '2026-08-01T12:00:00.000Z',
          closedAt: null,
          sessionHash: `sha256:${'66'.repeat(32)}`,
        });
      },
    }),
  };
}

function create(overrides = {}) {
  const deps = dependencies(overrides);
  const auth = createAgentAuth({
    store: deps.store,
    intents: deps.intents,
    walletIdentity: Object.freeze({
      network: POLICY.network,
      address: WALLET,
    }),
    activePolicy: POLICY_VERSION,
    kernelUid: process.getuid(),
    kernelGid: process.getgid(),
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
    mode: 'deterministic',
  });
  return { auth, ...deps };
}

function request(pathname = '/agent/v1/openai/example-model/chat/completions', options = {}) {
  return new Request(`${ORIGIN}${pathname}`, options);
}

function assertCode(action, code, forbidden = []) {
  assert.throws(action, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, code);
    assert.equal(error.cause, undefined);
    const serialized = `${String(error)} ${JSON.stringify(error)}`;
    for (const value of forbidden) assert.equal(serialized.includes(value), false);
    return true;
  });
}

test('agent auth returns only frozen enrolled public authority and never reads the body', () => {
  const { auth } = create();
  assert.deepEqual(Object.keys(auth).sort(), ['authenticate', 'resolveBoundSession']);
  let bodyReads = 0;
  const body = new ReadableStream({
    pull(controller) {
      bodyReads += 1;
      controller.enqueue(new TextEncoder().encode('RAW_PROMPT_SENTINEL'));
      controller.close();
    },
  });
  const principal = auth.authenticate(request(undefined, {
    method: 'POST',
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
    body,
    duplex: 'half',
  }));
  assert.equal(bodyReads, 0);
  assert.equal(Object.isFrozen(principal), true);
  assert.deepEqual(principal, {
    agentInstanceId: INSTANCE_ID,
    credentialDigest: CREDENTIAL_DIGEST,
    enrollmentHash: ENROLLMENT_HASH,
    agentUid: String(process.getuid()),
    agentGid: String(process.getgid()),
  });
  assert.equal(JSON.stringify(principal).includes(TOKEN), false);
  assert.equal(Object.hasOwn(principal, 'sessionId'), false);
});

test('real SQLite null-prototype rows cross only the closed authentication row boundary', (t) => {
  const store = openKernelStore({ filePath: ':memory:', allowMemory: true });
  t.after(() => store.close());
  const quoted = (value) => `'${String(value).replaceAll("'", "''")}'`;
  store.execForTest(`INSERT INTO policy_versions
    (id, schema_version, canonical_json, policy_hash, predecessor_hash, applied_at)
    VALUES (${quoted(POLICY_VERSION.id)}, 1, ${quoted(canonicalJson(POLICY))},
      ${quoted(POLICY_VERSION.hash)}, NULL, '2026-08-01T12:00:00.000Z');
    INSERT INTO spend_sessions
    (id, adapter_id, wallet_address, policy_version_id, state, created_at, closed_at)
    VALUES ('session-1', ${quoted(`pi:${INSTANCE_ID}`)}, ${quoted(WALLET)},
      ${quoted(POLICY_VERSION.id)}, 'open', '2026-08-01T12:00:00.000Z', NULL);
    INSERT INTO agent_enrollments
    (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
      state, enrolled_by_operator_hash, enrolled_at, revoked_by_operator_hash, revoked_at)
    VALUES (${quoted(INSTANCE_ID)}, ${quoted(CREDENTIAL_DIGEST)}, ${quoted(ENROLLMENT_HASH)},
      ${quoted(String(process.getuid()))}, ${quoted(String(process.getgid()))}, 'active',
      ${quoted(`sha256:${'77'.repeat(32)}`)}, '2026-08-01T12:00:00.000Z', NULL, NULL);
    INSERT INTO agent_session_bindings
    (id, agent_instance_id, credential_digest, enrollment_hash, session_id, state,
      created_at, last_seen_at, closed_at)
    VALUES ('binding-1', ${quoted(INSTANCE_ID)}, ${quoted(CREDENTIAL_DIGEST)},
      ${quoted(ENROLLMENT_HASH)}, 'session-1', 'open',
      '2026-08-01T12:00:00.000Z', '2026-08-01T12:00:00.000Z', NULL);`);

  assert.equal(Object.getPrototypeOf(store.readAll(
    "SELECT agent_instance_id FROM agent_enrollments WHERE state = 'active'",
  )[0]), null);
  const auth = createAgentAuth({
    store,
    intents: Object.freeze({
      getSession() {
        return Object.freeze({
          id: 'session-1', adapterId: `pi:${INSTANCE_ID}`, agentInstanceId: INSTANCE_ID,
          enrollmentHash: ENROLLMENT_HASH, walletAddress: WALLET,
          policyVersionId: POLICY_VERSION.id, state: 'open',
          createdAt: '2026-08-01T12:00:00.000Z', closedAt: null,
          sessionHash: `sha256:${'66'.repeat(32)}`,
        });
      },
    }),
    walletIdentity: Object.freeze({ network: POLICY.network, address: WALLET }),
    activePolicy: POLICY_VERSION,
    kernelUid: process.getuid(),
    kernelGid: process.getgid(),
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
    mode: 'deterministic',
  });
  const principal = auth.authenticate(request(undefined, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  }));
  assert.equal(auth.resolveBoundSession(principal).id, 'session-1');
});

test('agent credential grammar, channel, query, cookie, and forwarding fail redacted', () => {
  const { auth } = create();
  for (const authorization of [
    undefined,
    '',
    `Bearer ${TOKEN}`,
    `WalletKernelAgent  ${TOKEN}`,
    `WalletKernelAgent ${TOKEN}, WalletKernelAgent ${TOKEN}`,
    `WalletKernelAgent ${TOKEN.slice(1)}`,
    `WalletKernelAgent ${WRONG_TOKEN}`,
  ]) {
    assertCode(() => auth.authenticate(request(undefined, {
      headers: authorization === undefined ? {} : { authorization },
    })), 'AGENT_UNAUTHORIZED', [TOKEN, WRONG_TOKEN]);
  }
  for (const [pathname, headers] of [
    [`/agent/v1/intents/value?token=${TOKEN}`, { authorization: `WalletKernelAgent ${TOKEN}` }],
    ['/agent/v1/intents/value', { authorization: `WalletKernelAgent ${TOKEN}`, cookie: `agent=${TOKEN}` }],
    ['/agent/v1/intents/value', { authorization: `WalletKernelAgent ${TOKEN}`, forwarded: 'for=unix' }],
    ['/agent/v1/intents/value', { authorization: `WalletKernelAgent ${TOKEN}`, 'x-forwarded-for': '127.0.0.1' }],
  ]) {
    assertCode(() => auth.authenticate(request(pathname, { headers })), 'AGENT_UNAUTHORIZED', [TOKEN]);
  }
});

test('revocation and zero-active recovery state reject before route or body authority', () => {
  const value = create();
  value.state.enrollments = [];
  assertCode(() => value.auth.authenticate(request('/agent/v1/unknown', {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  })), 'AGENT_ENROLLMENT_REQUIRED', [TOKEN]);

  value.state.enrollments = [activeRow(), activeRow({
    agent_instance_id: Buffer.alloc(16, 0x39).toString('base64url'),
    credential_digest: sha256(Buffer.alloc(32, 0x39)),
    enrollment_hash: `sha256:${'99'.repeat(32)}`,
  })];
  assertCode(() => value.auth.authenticate(request(undefined, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  })), 'AGENT_ENROLLMENT_AMBIGUOUS', [TOKEN]);
});

test('startup identity and policy authority fail closed', () => {
  const deps = dependencies();
  const base = {
    store: deps.store,
    intents: deps.intents,
    walletIdentity: Object.freeze({ network: POLICY.network, address: WALLET }),
    activePolicy: POLICY_VERSION,
    kernelUid: process.getuid(),
    kernelGid: process.getgid(),
    expectedAgentUid: process.getuid(),
    expectedAgentGid: process.getgid(),
    mode: 'deterministic',
  };
  for (const mutation of [
    { expectedAgentUid: process.getuid() + 1 },
    { walletIdentity: Object.freeze({ network: POLICY.network, address: POLICY.sellers[0].payTo }) },
    { activePolicy: Object.freeze({ ...POLICY_VERSION, hash: `sha256:${'99'.repeat(32)}` }) },
    { mode: 'cdp-testnet' },
    { mode: 'unknown' },
    { walletAdapter: {} },
  ]) {
    assert.throws(() => createAgentAuth({ ...base, ...mutation }));
  }
});

test('session resolution is read-only, exact, and immediately revocation-aware', () => {
  const value = create();
  const principal = value.auth.authenticate(request(undefined, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  }));
  const session = value.auth.resolveBoundSession(principal);
  assert.equal(Object.isFrozen(session), true);
  assert.equal(session.id, 'session-1');
  assert.equal(session.enrollmentHash, ENROLLMENT_HASH);
  assert.equal(value.calls.filter((call) => call.kind === 'getSession').length, 1);

  value.state.enrollments = [];
  assertCode(() => value.auth.resolveBoundSession(principal), 'AGENT_ENROLLMENT_REQUIRED');
});

test('closed, ambiguous, mismatched, and policy-blocked bindings cannot silently spend', () => {
  const scenarios = [
    { bindings: [], code: 'AGENT_SESSION_UNAVAILABLE' },
    { bindings: [bindingRow(), bindingRow({ binding_id: 'binding-2', session_id: 'session-2' })], code: 'SESSION_AUTHORITY_AMBIGUOUS' },
    { bindings: [bindingRow({ credential_digest: `sha256:${'77'.repeat(32)}` })], code: 'SESSION_AUTHORITY_AMBIGUOUS' },
    { bindings: [bindingRow({ binding_state: 'closed', session_state: 'closed' })], code: 'AGENT_SESSION_UNAVAILABLE' },
    {
      bindings: [bindingRow({ session_state: 'policy_blocked' })],
      session: Object.freeze({
        id: 'session-1', adapterId: `pi:${INSTANCE_ID}`, agentInstanceId: INSTANCE_ID,
        enrollmentHash: ENROLLMENT_HASH, walletAddress: WALLET,
        policyVersionId: 'policy-old', state: 'policy_blocked',
        createdAt: '2026-08-01T12:00:00.000Z', closedAt: null,
        sessionHash: `sha256:${'66'.repeat(32)}`,
      }),
      code: 'POLICY_TRANSITION_REQUIRED',
    },
  ];
  for (const scenario of scenarios) {
    const value = create(scenario);
    const principal = value.auth.authenticate(request(undefined, {
      headers: { authorization: `WalletKernelAgent ${TOKEN}` },
    }));
    assertCode(() => value.auth.resolveBoundSession(principal), scenario.code);
  }
});

test('the same auth instance resolves a guarded replacement on the repository-current policy', () => {
  const value = create({
    bindings: [bindingRow({ session_state: 'policy_blocked' })],
    session: Object.freeze({
      id: 'session-1', adapterId: `pi:${INSTANCE_ID}`, agentInstanceId: INSTANCE_ID,
      enrollmentHash: ENROLLMENT_HASH, walletAddress: WALLET,
      policyVersionId: POLICY_VERSION.id, state: 'policy_blocked',
      createdAt: '2026-08-01T12:00:00.000Z', closedAt: null,
      sessionHash: `sha256:${'66'.repeat(32)}`,
    }),
  });
  const principal = value.auth.authenticate(request(undefined, {
    headers: { authorization: `WalletKernelAgent ${TOKEN}` },
  }));
  assertCode(() => value.auth.resolveBoundSession(principal), 'POLICY_TRANSITION_REQUIRED');

  value.state.bindings = [bindingRow({
    binding_id: 'binding-2',
    session_id: 'session-2',
  })];
  value.state.session = Object.freeze({
    id: 'session-2', adapterId: `pi:${INSTANCE_ID}`, agentInstanceId: INSTANCE_ID,
    enrollmentHash: ENROLLMENT_HASH, walletAddress: WALLET,
    policyVersionId: 'policy-2', state: 'open',
    createdAt: '2026-08-01T12:05:00.000Z', closedAt: null,
    sessionHash: `sha256:${'77'.repeat(32)}`,
  });
  const replacement = value.auth.resolveBoundSession(principal);
  assert.equal(replacement.id, 'session-2');
  assert.equal(replacement.policyVersionId, 'policy-2');
});

test('source uses fixed-length comparison and zeroes decoded credential bytes', () => {
  const source = fs.readFileSync(new URL('../src/agent/auth.mjs', import.meta.url), 'utf8');
  assert.match(source, /timingSafeEqual/);
  assert.match(source, /\.fill\(0\)/);
  assert.doesNotMatch(source, /console\.|process\.env|localStorage|sessionStorage/);
});

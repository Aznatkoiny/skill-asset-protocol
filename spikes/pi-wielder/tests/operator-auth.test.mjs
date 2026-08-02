import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  createOperatorAuth,
  loadOrCreateOperatorToken,
} from '../src/operator/auth.mjs';
import { KernelError } from '../src/kernel/canonical.mjs';

const CURRENT_UID = process.getuid();
const ORIGIN = 'http://127.0.0.1:8405';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-operator-auth-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return Object.freeze({
    directory,
    filePath: path.join(directory, 'operator.token'),
    pathTrust: Object.freeze({
      mode: 'deterministic',
      trustedAncestor: directory,
      kernelUid: CURRENT_UID,
      agentUid: CURRENT_UID,
    }),
  });
}

function tokenValue(byte = 0x11) {
  return Buffer.alloc(32, byte).toString('base64url');
}

function deterministicRandom(sequence = [0x21, 0x22, 0x23, 0x24]) {
  let index = 0;
  return (size) => {
    const value = sequence[index] ?? (0x40 + index);
    index += 1;
    return Buffer.alloc(size, value);
  };
}

function assertUnauthorized(action, forbidden = []) {
  return assert.rejects(action, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, 'OPERATOR_UNAUTHORIZED');
    assert.equal(error.cause, undefined);
    const serialized = `${String(error)} ${JSON.stringify(error)}`;
    for (const value of forbidden.filter((candidate) => candidate !== '')) {
      assert.equal(serialized.includes(value), false);
    }
    return true;
  });
}

function request(pathname, { method = 'GET', headers = {}, body } = {}) {
  return new Request(`${ORIGIN}${pathname}`, { method, headers, body });
}

function launchToken(result) {
  const url = new URL(result.url);
  assert.equal(url.origin, ORIGIN);
  assert.equal(url.pathname, '/operator/');
  assert.match(url.hash, /^#launch=[A-Za-z0-9_-]{43}$/);
  return url.hash.slice('#launch='.length);
}

function sessionExchange(auth, value, origin = ORIGIN) {
  return auth.exchangeBrowserSession(request('/operator/v1/session', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin },
    body: JSON.stringify({ launchToken: value }),
  }));
}

function sessionHeaders(response) {
  const setCookie = response.headers.get('set-cookie');
  assert.match(
    setCookie,
    /^wallet_kernel_session=[A-Za-z0-9_-]{43}; HttpOnly; SameSite=Strict; Path=\/operator(?:; Secure)?$/,
  );
  return Object.freeze({
    cookie: setCookie.split(';', 1)[0],
    csrf: response.headers.get('x-csrf-token'),
  });
}

test('operator token initializes once as exact owner-only base64url bytes', (t) => {
  const value = fixture(t);
  const calls = [];
  const token = loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: value.pathTrust,
    randomBytes(size) {
      calls.push(size);
      return Buffer.alloc(size, size === 32 ? 0x11 : 0x22);
    },
  });

  assert.equal(token, tokenValue(0x11));
  assert.match(token, TOKEN_PATTERN);
  assert.equal(Buffer.from(token, 'base64url').length, 32);
  assert.equal(Buffer.from(token, 'base64url').toString('base64url'), token);
  assert.equal(fs.readFileSync(value.filePath, 'ascii'), token);
  const stat = fs.lstatSync(value.filePath);
  assert.equal(stat.isFile(), true);
  assert.equal(stat.isSymbolicLink(), false);
  assert.equal(stat.uid, CURRENT_UID);
  assert.equal(stat.mode & 0o777, 0o600);
  assert.deepEqual(calls, [32, 16]);

  const before = fs.statSync(value.filePath, { bigint: true });
  const reused = loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: value.pathTrust,
    randomBytes() {
      throw new Error('existing owner token must not be replaced');
    },
  });
  const after = fs.statSync(value.filePath, { bigint: true });
  assert.equal(reused, token);
  assert.equal(after.ino, before.ino);
  assert.equal(after.mtimeNs, before.mtimeNs);
});

test('operator token rejects malformed existing bytes without trimming or repair', (t) => {
  for (const [label, contents] of [
    ['short', 'abc'],
    ['newline', `${tokenValue()}\n`],
    ['padding', `${tokenValue()}=`],
    ['standard base64', `${tokenValue().slice(0, -1)}+`],
    ['non-roundtrip', `${'A'.repeat(42)}B`],
  ]) {
    const value = fixture(t);
    fs.writeFileSync(value.filePath, contents, { mode: 0o600 });
    fs.chmodSync(value.filePath, 0o600);
    assert.throws(
      () => loadOrCreateOperatorToken({
        filePath: value.filePath,
        pathTrust: value.pathTrust,
        randomBytes() { throw new Error('must not repair'); },
      }),
      undefined,
      label,
    );
    assert.equal(fs.readFileSync(value.filePath, 'ascii'), contents, label);
  }

  const value = fixture(t);
  const highBitBytes = Buffer.alloc(43, 0xc1);
  fs.writeFileSync(value.filePath, highBitBytes, { mode: 0o600 });
  fs.chmodSync(value.filePath, 0o600);
  assert.throws(() => loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: value.pathTrust,
  }));
  assert.deepEqual(fs.readFileSync(value.filePath), highBitBytes);
});

test('operator token rejects symlink, permissive, and wrong-identity-like authority', (t) => {
  const value = fixture(t);
  const target = path.join(value.directory, 'target.token');
  fs.writeFileSync(target, tokenValue(), { mode: 0o600 });
  fs.symlinkSync(target, value.filePath);
  assert.throws(() => loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: value.pathTrust,
  }));
  fs.unlinkSync(value.filePath);

  fs.writeFileSync(value.filePath, tokenValue(), { mode: 0o644 });
  fs.chmodSync(value.filePath, 0o644);
  assert.throws(() => loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: value.pathTrust,
  }));
  fs.chmodSync(value.filePath, 0o600);

  const wrongIdentity = Object.freeze({
    ...value.pathTrust,
    kernelUid: CURRENT_UID + 1,
  });
  assert.throws(() => loadOrCreateOperatorToken({
    filePath: value.filePath,
    pathTrust: wrongIdentity,
  }));
});

test('owner bearer is exact, constant-shape, channel-bound, and redacted', async () => {
  const token = tokenValue();
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  assert.deepEqual(Object.keys(auth).sort(), [
    'authenticateBearer',
    'authenticateBrowser',
    'exchangeBrowserSession',
    'issueBrowserLaunch',
    'revokeBrowserSession',
  ]);

  const principal = auth.authenticateBearer(request('/operator/v1/overview', {
    headers: { authorization: `Bearer ${token}` },
  }), { transport: 'loopback-demo' });
  assert.match(principal.operatorIdHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(principal).includes(token), false);

  for (const authorization of [
    undefined,
    '',
    'bearer value',
    `Basic ${token}`,
    `Bearer ${token.slice(1)}`,
    `Bearer  ${token}`,
    `Bearer ${token}, Bearer ${token}`,
    `Bearer ${tokenValue(0x12)}`,
  ]) {
    const headers = authorization === undefined ? {} : { authorization };
    await assertUnauthorized(
      async () => auth.authenticateBearer(request('/operator/v1/overview', { headers }), {
        transport: 'loopback-demo',
      }),
      [token, authorization ?? ''],
    );
  }
  await assertUnauthorized(
    async () => auth.authenticateBearer(request(`/operator/v1/overview?token=${token}`, {
      headers: { authorization: `Bearer ${token}` },
    }), { transport: 'loopback-demo' }),
    [token],
  );
  await assertUnauthorized(
    async () => auth.authenticateBearer(request(`/operator/v1/overview?state=${token}`, {
      headers: { authorization: `Bearer ${token}` },
    }), { transport: 'loopback-demo' }),
    [token],
  );
  await assertUnauthorized(
    async () => auth.authenticateBearer(request('/operator/v1/overview', {
      headers: { authorization: `Bearer ${token}`, cookie: `owner=${token}` },
    }), { transport: 'loopback-demo' }),
    [token],
  );
  for (const forwarded of ['forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-proto']) {
    await assertUnauthorized(
      async () => auth.authenticateBearer(request('/operator/v1/overview', {
        headers: { authorization: `Bearer ${token}`, [forwarded]: 'unix' },
      }), { transport: 'loopback-demo' }),
      [token],
    );
  }

  const live = createOperatorAuth({
    token,
    mode: 'cdp-testnet',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  assert.equal(live.authenticateBearer(request('/operator/v1/overview', {
    headers: { authorization: `Bearer ${token}` },
  }), { transport: 'unix' }).operatorIdHash, principal.operatorIdHash);
  await assertUnauthorized(
    async () => live.authenticateBearer(request('/operator/v1/overview', {
      headers: { authorization: `Bearer ${token}` },
    }), { transport: 'loopback-demo' }),
    [token],
  );
});

test('browser launch is single-use, origin-bound, and restart-invalidated', async () => {
  let nowMs = 1_785_585_600_000;
  const token = tokenValue();
  const options = {
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => nowMs,
    randomBytes: deterministicRandom(),
  };
  const auth = createOperatorAuth(options);
  const launch = auth.issueBrowserLaunch({ transport: 'loopback-demo' });
  const capability = launchToken(launch);
  assert.equal(JSON.stringify(auth).includes(capability), false);
  assert.equal(launch.expiresAt, '2026-08-01T12:01:00.000Z');

  const exchange = await sessionExchange(auth, capability);
  assert.equal(exchange.status, 204);
  assert.equal(exchange.headers.get('cache-control'), 'no-store');
  const browser = sessionHeaders(exchange);
  assert.match(browser.csrf, TOKEN_PATTERN);
  assert.equal(browser.cookie.includes(token), false);

  await assertUnauthorized(() => sessionExchange(auth, capability), [capability, token]);
  const restarted = createOperatorAuth(options);
  await assertUnauthorized(() => sessionExchange(restarted, capability), [capability, token]);

  const changedOriginLaunch = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  await assertUnauthorized(
    () => sessionExchange(auth, changedOriginLaunch, 'http://127.0.0.1:8406'),
    [changedOriginLaunch, token],
  );

  const expired = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  nowMs += 60_000;
  await assertUnauthorized(() => sessionExchange(auth, expired), [expired, token]);
});

test('browser capabilities reject a regressing authentication clock', async () => {
  let nowMs = 1_785_585_600_000;
  const token = tokenValue();
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => nowMs,
    randomBytes: deterministicRandom(),
  });
  const capability = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  nowMs -= 1;
  await assert.rejects(
    () => sessionExchange(auth, capability),
    (error) => error instanceof KernelError
      && error.code === 'OPERATOR_CONFIGURATION_INVALID',
  );
});

test('browser session requires exact cookie, Origin, and CSRF for mutations', async () => {
  let nowMs = 1_785_585_600_000;
  const token = tokenValue();
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => nowMs,
    randomBytes: deterministicRandom(),
    sessionTtlMs: 900_000,
  });
  const capability = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  const session = sessionHeaders(await sessionExchange(auth, capability));

  const readPrincipal = auth.authenticateBrowser(request('/operator/v1/overview', {
    headers: { cookie: session.cookie },
  }), { mutation: false });
  assert.match(readPrincipal.operatorIdHash, /^sha256:[0-9a-f]{64}$/);

  const mutationRequest = () => request('/operator/v1/policies/apply', {
    method: 'POST',
    headers: {
      cookie: session.cookie,
      origin: ORIGIN,
      'x-csrf-token': session.csrf,
    },
  });
  assert.equal(
    auth.authenticateBrowser(mutationRequest(), { mutation: true }).operatorIdHash,
    readPrincipal.operatorIdHash,
  );

  for (const headers of [
    {},
    { cookie: session.cookie, origin: ORIGIN },
    { cookie: session.cookie, origin: ORIGIN, 'x-csrf-token': tokenValue(0x44) },
    { cookie: session.cookie, origin: 'http://127.0.0.1:8406', 'x-csrf-token': session.csrf },
    { cookie: `${session.cookie}; wallet_kernel_session=${tokenValue(0x45)}`,
      origin: ORIGIN, 'x-csrf-token': session.csrf },
    { cookie: session.cookie, origin: ORIGIN, 'x-csrf-token': session.csrf,
      authorization: `Bearer ${token}` },
  ]) {
    await assertUnauthorized(
      async () => auth.authenticateBrowser(request('/operator/v1/policies/apply', {
        method: 'POST', headers,
      }), { mutation: true }),
      [token, session.csrf],
    );
  }

  nowMs += 900_000;
  await assertUnauthorized(
    async () => auth.authenticateBrowser(request('/operator/v1/overview', {
      headers: { cookie: session.cookie },
    }), { mutation: false }),
    [token],
  );
});

test('browser session exchange accepts only the exact bounded canonical body', async () => {
  const token = tokenValue();
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  const bodies = [
    '{}',
    '{"launchToken":"value","unknown":true}',
    '{"launchToken":"first","launchToken":"second"}',
    ` {"launchToken":"${tokenValue(0x51)}"}`,
    'not-json',
    JSON.stringify({ launchToken: 'short' }),
    JSON.stringify({ launchToken: tokenValue(0x52), padding: 'x'.repeat(1_024) }),
  ];
  for (const body of bodies) {
    await assertUnauthorized(
      () => auth.exchangeBrowserSession(request('/operator/v1/session', {
        method: 'POST',
        headers: { origin: ORIGIN, 'content-type': 'application/json' },
        body,
      })),
      [token],
    );
  }
  const capability = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  await assertUnauthorized(
    () => auth.exchangeBrowserSession(request('/operator/v1/session', {
      method: 'POST',
      headers: { origin: ORIGIN, 'content-type': 'text/plain' },
      body: JSON.stringify({ launchToken: capability }),
    })),
    [capability, token],
  );
});

test('browser logout invalidates server state and clears the cookie', async () => {
  const token = tokenValue();
  const auth = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  const capability = launchToken(auth.issueBrowserLaunch({ transport: 'loopback-demo' }));
  const session = sessionHeaders(await sessionExchange(auth, capability));
  const logoutRequest = request('/operator/v1/session', {
    method: 'DELETE',
    headers: {
      cookie: session.cookie,
      origin: ORIGIN,
      'x-csrf-token': session.csrf,
    },
  });
  const response = auth.revokeBrowserSession(logoutRequest);
  assert.equal(response.status, 204);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.match(response.headers.get('set-cookie'), /^wallet_kernel_session=;.*Max-Age=0/);
  await assertUnauthorized(
    async () => auth.authenticateBrowser(request('/operator/v1/overview', {
      headers: { cookie: session.cookie },
    }), { mutation: false }),
    [token],
  );
});

test('live browser launch is Unix-admin-only and secure cookies follow TLS origin', async () => {
  const token = tokenValue();
  const live = createOperatorAuth({
    token,
    mode: 'cdp-testnet',
    origin: ORIGIN,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  assert.throws(
    () => live.issueBrowserLaunch({ transport: 'loopback-demo' }),
    (error) => error.code === 'OPERATOR_UNAUTHORIZED',
  );
  const capability = launchToken(live.issueBrowserLaunch({ transport: 'unix' }));
  const response = await sessionExchange(live, capability);
  assert.doesNotMatch(response.headers.get('set-cookie'), /; Secure$/);

  const tlsOrigin = 'https://127.0.0.1:8405';
  const tls = createOperatorAuth({
    token,
    mode: 'deterministic',
    origin: tlsOrigin,
    now: () => 1_785_585_600_000,
    randomBytes: deterministicRandom(),
  });
  const tlsLaunch = tls.issueBrowserLaunch({ transport: 'loopback-demo' });
  const tlsCapability = new URL(tlsLaunch.url).hash.slice('#launch='.length);
  const tlsResponse = await tls.exchangeBrowserSession(new Request(
    `${tlsOrigin}/operator/v1/session`,
    {
      method: 'POST',
      headers: { origin: tlsOrigin, 'content-type': 'application/json' },
      body: JSON.stringify({ launchToken: tlsCapability }),
    },
  ));
  assert.match(tlsResponse.headers.get('set-cookie'), /; Secure$/);
});

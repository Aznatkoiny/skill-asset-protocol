import crypto from 'node:crypto';

import {
  canonicalJson,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { loadOrInitializePrivateFile } from '../kernel/secure-storage.mjs';

const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const FORWARDED_HEADERS = Object.freeze([
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-proto',
]);
const COOKIE_NAME = 'wallet_kernel_session';
const LAUNCH_TTL_MS = 60_000;
const DEFAULT_SESSION_TTL_MS = 900_000;
const MAX_LAUNCHES = 128;
const MAX_SESSIONS = 128;
const MAX_EXCHANGE_BYTES = 512;
const AUTH_OPTION_FIELDS = Object.freeze([
  'token',
  'mode',
  'origin',
  'now',
  'randomBytes',
  'sessionTtlMs',
]);

function unauthorized() {
  throw new KernelError('OPERATOR_UNAUTHORIZED', 'Operator authentication failed');
}

function configuration(message) {
  throw new KernelError('OPERATOR_CONFIGURATION_INVALID', message);
}

function captureOptions(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    configuration('Operator authentication options must be one plain object');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.some((key) => typeof key !== 'string' || !AUTH_OPTION_FIELDS.includes(key))) {
    configuration('Operator authentication options contain an unknown field');
  }
  const captured = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      configuration('Operator authentication options must contain only data fields');
    }
    captured[key] = descriptor.value;
  }
  return captured;
}

function decodeToken(value, label = 'operator credential') {
  if (typeof value !== 'string' || !TOKEN_PATTERN.test(value)) {
    throw new Error(`${label} must be exactly 32 canonical base64url bytes`);
  }
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length !== 32 || bytes.toString('base64url') !== value) {
    bytes.fill(0);
    throw new Error(`${label} must be exactly 32 canonical base64url bytes`);
  }
  return bytes;
}

function opaqueValue(randomBytes, label) {
  let bytes;
  try {
    bytes = Buffer.from(randomBytes(32));
  } catch {
    configuration(`${label} randomness failed`);
  }
  if (bytes.length !== 32) {
    bytes.fill(0);
    configuration(`${label} requires exactly 32 random bytes`);
  }
  const value = bytes.toString('base64url');
  bytes.fill(0);
  if (!TOKEN_PATTERN.test(value)) configuration(`${label} encoding failed`);
  return value;
}

function digestBytes(domain, value) {
  return crypto.createHash('sha256')
    .update(domain, 'utf8')
    .update(Buffer.from([0]))
    .update(value, 'utf8')
    .digest();
}

function digestKey(domain, value) {
  const digest = digestBytes(domain, value);
  try {
    return digest.toString('hex');
  } finally {
    digest.fill(0);
  }
}

function constantDigestMatch(domain, candidate, expected) {
  const actual = digestBytes(domain, candidate);
  try {
    return crypto.timingSafeEqual(actual, expected);
  } finally {
    actual.fill(0);
  }
}

function validateOrigin(value) {
  if (typeof value !== 'string') configuration('Operator origin must be canonical');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    configuration('Operator origin must be canonical');
  }
  if ((parsed.protocol !== 'http:' && parsed.protocol !== 'https:')
      || parsed.username !== '' || parsed.password !== ''
      || parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== ''
      || parsed.origin !== value) {
    configuration('Operator origin must be one canonical HTTP origin');
  }
  return parsed.origin;
}

function nowValue(now) {
  let value;
  try {
    value = now();
  } catch {
    configuration('Operator clock failed');
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    configuration('Operator clock must return nonnegative integer milliseconds');
  }
  return value;
}

function assertTransport(mode, transport) {
  const expected = mode === 'cdp-testnet' ? 'unix' : 'loopback-demo';
  if (transport !== expected) unauthorized();
}

function rejectForwarding(headers) {
  if (FORWARDED_HEADERS.some((name) => headers.has(name))) unauthorized();
}

function requestUrl(request, origin, pathname) {
  let parsed;
  try {
    parsed = new URL(request.url);
  } catch {
    unauthorized();
  }
  if (parsed.origin !== origin || parsed.pathname !== pathname
      || parsed.search !== '' || parsed.hash !== '') {
    unauthorized();
  }
}

function suspiciousBearerQuery(request, ownerDigest) {
  let parsed;
  try {
    parsed = new URL(request.url);
  } catch {
    return true;
  }
  const forbidden = new Set(['access_token', 'authorization', 'bearer', 'owner', 'token']);
  for (const [key, value] of parsed.searchParams) {
    if (forbidden.has(key.toLowerCase())) return true;
    if (constantDigestMatch('wallet-kernel.operator-bearer.v1', value, ownerDigest)) return true;
  }
  return false;
}

function pruneExpired(records, nowMs) {
  for (const [key, value] of records) {
    if (nowMs >= value.expiresAtMs) {
      value.csrfDigest?.fill(0);
      records.delete(key);
    }
  }
}

async function boundedRequestText(request) {
  const declared = request.headers.get('content-length');
  if (declared !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(declared)
        || Number(declared) > MAX_EXCHANGE_BYTES) unauthorized();
  }
  if (!request.body) unauthorized();
  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      const bytes = Buffer.from(value);
      length += bytes.length;
      if (length > MAX_EXCHANGE_BYTES) unauthorized();
      chunks.push(bytes);
    }
  } catch (error) {
    if (error instanceof KernelError) throw error;
    unauthorized();
  }
  let bytes = Buffer.concat(chunks, length);
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    unauthorized();
  } finally {
    bytes.fill(0);
    for (const chunk of chunks) chunk.fill(0);
  }
}

function exactSessionCookie(headers) {
  const cookie = headers.get('cookie');
  if (cookie === null) unauthorized();
  const match = /^wallet_kernel_session=([A-Za-z0-9_-]{43})$/.exec(cookie);
  if (!match) unauthorized();
  try {
    const bytes = decodeToken(match[1], 'browser session');
    bytes.fill(0);
  } catch {
    unauthorized();
  }
  return match[1];
}

function sessionCookie(value, secure) {
  return `${COOKIE_NAME}=${value}; HttpOnly; SameSite=Strict; Path=/operator${
    secure ? '; Secure' : ''
  }`;
}

function clearedSessionCookie(secure) {
  return `${COOKIE_NAME}=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/operator${
    secure ? '; Secure' : ''
  }`;
}

export function loadOrCreateOperatorToken({
  filePath,
  pathTrust,
  randomBytes = crypto.randomBytes,
} = {}) {
  if (typeof randomBytes !== 'function') {
    throw new Error('Operator token randomness must be a function');
  }
  return loadOrInitializePrivateFile({
    filePath,
    label: 'Operator token',
    createBytes: () => Buffer.from(opaqueValue(randomBytes, 'Operator token'), 'ascii'),
    validateBytes(bytes) {
      if (bytes.length !== 43 || bytes.some((byte) => byte > 0x7f)) {
        throw new Error('Operator token must be exactly 43 ASCII bytes');
      }
      const value = bytes.toString('ascii');
      const decoded = decodeToken(value, 'Operator token');
      decoded.fill(0);
      return value;
    },
    randomBytes,
    pathTrust,
  });
}

export function createOperatorAuth(options) {
  const captured = captureOptions(options);
  const mode = captured.mode;
  if (mode !== 'deterministic' && mode !== 'cdp-testnet') {
    configuration('Operator mode must be deterministic or cdp-testnet');
  }
  const origin = validateOrigin(captured.origin);
  const now = captured.now ?? Date.now;
  const randomBytes = captured.randomBytes ?? crypto.randomBytes;
  const sessionTtlMs = captured.sessionTtlMs ?? DEFAULT_SESSION_TTL_MS;
  if (typeof now !== 'function' || typeof randomBytes !== 'function'
      || !Number.isSafeInteger(sessionTtlMs) || sessionTtlMs < 1
      || sessionTtlMs > 86_400_000) {
    configuration('Operator runtime options are invalid');
  }

  let ownerBytes;
  try {
    ownerBytes = decodeToken(captured.token);
  } catch {
    configuration('Operator credential is invalid');
  }
  const ownerDigest = digestBytes('wallet-kernel.operator-bearer.v1', captured.token);
  const operatorIdHash = sha256(Buffer.concat([
    Buffer.from('wallet-kernel.operator-id.v1\0', 'utf8'),
    ownerBytes,
  ]));
  ownerBytes.fill(0);
  const principal = Object.freeze({ operatorIdHash });
  const launches = new Map();
  const sessions = new Map();
  const secure = origin.startsWith('https://');
  let lastNowMs = -1;

  function currentTime() {
    const value = nowValue(now);
    if (value < lastNowMs) configuration('Operator clock regressed');
    lastNowMs = value;
    return value;
  }

  function authenticateBearer(request, { transport } = {}) {
    assertTransport(mode, transport);
    if (!(request instanceof Request)) unauthorized();
    rejectForwarding(request.headers);
    if (request.headers.has('cookie') || suspiciousBearerQuery(request, ownerDigest)) unauthorized();
    const authorization = request.headers.get('authorization');
    const match = typeof authorization === 'string'
      ? /^Bearer ([A-Za-z0-9_-]{43})$/.exec(authorization)
      : null;
    const candidate = match?.[1] ?? '';
    const valid = constantDigestMatch(
      'wallet-kernel.operator-bearer.v1',
      candidate,
      ownerDigest,
    );
    if (!match || !valid) unauthorized();
    return principal;
  }

  function issueBrowserLaunch({ transport } = {}) {
    assertTransport(mode, transport);
    const nowMs = currentTime();
    pruneExpired(launches, nowMs);
    if (launches.size >= MAX_LAUNCHES) {
      throw new KernelError('OPERATOR_CAPACITY', 'Browser launch capacity is full');
    }
    const capability = opaqueValue(randomBytes, 'Browser launch');
    const key = digestKey('wallet-kernel.browser-launch.v1', capability);
    if (launches.has(key)) configuration('Browser launch randomness collided');
    const expiresAtMs = nowMs + LAUNCH_TTL_MS;
    if (!Number.isSafeInteger(expiresAtMs)) configuration('Browser launch expiry overflowed');
    launches.set(key, Object.freeze({ expiresAtMs, origin }));
    return Object.freeze({
      url: `${origin}/operator/#launch=${capability}`,
      expiresAt: new Date(expiresAtMs).toISOString(),
    });
  }

  async function exchangeBrowserSession(request) {
    if (!(request instanceof Request) || request.method !== 'POST') unauthorized();
    requestUrl(request, origin, '/operator/v1/session');
    rejectForwarding(request.headers);
    if (request.headers.has('authorization') || request.headers.has('cookie')
        || request.headers.get('origin') !== origin
        || request.headers.get('content-type') !== 'application/json') {
      unauthorized();
    }
    const body = await boundedRequestText(request);
    let value;
    try {
      value = JSON.parse(body);
      if (!value || typeof value !== 'object' || Array.isArray(value)
          || Object.getPrototypeOf(value) !== Object.prototype
          || Reflect.ownKeys(value).length !== 1
          || !Object.hasOwn(value, 'launchToken')
          || canonicalJson(value) !== body) {
        unauthorized();
      }
    } catch (error) {
      if (error instanceof KernelError) throw error;
      unauthorized();
    }
    let launchBytes;
    try {
      launchBytes = decodeToken(value.launchToken, 'browser launch');
    } catch {
      unauthorized();
    } finally {
      launchBytes?.fill(0);
    }
    const nowMs = currentTime();
    pruneExpired(launches, nowMs);
    pruneExpired(sessions, nowMs);
    const launchKey = digestKey('wallet-kernel.browser-launch.v1', value.launchToken);
    const launch = launches.get(launchKey);
    if (!launch) unauthorized();
    launches.delete(launchKey);
    if (nowMs >= launch.expiresAtMs || launch.origin !== origin) unauthorized();
    if (sessions.size >= MAX_SESSIONS) {
      throw new KernelError('OPERATOR_CAPACITY', 'Browser session capacity is full');
    }

    const sessionValue = opaqueValue(randomBytes, 'Browser session');
    const csrfValue = opaqueValue(randomBytes, 'Browser CSRF');
    const sessionKey = digestKey('wallet-kernel.browser-session.v1', sessionValue);
    if (sessions.has(sessionKey)) configuration('Browser session randomness collided');
    const csrfDigest = digestBytes('wallet-kernel.browser-csrf.v1', csrfValue);
    const expiresAtMs = nowMs + sessionTtlMs;
    if (!Number.isSafeInteger(expiresAtMs)) configuration('Browser session expiry overflowed');
    sessions.set(sessionKey, Object.freeze({ csrfDigest, expiresAtMs, origin }));
    return new Response(null, {
      status: 204,
      headers: {
        'cache-control': 'no-store',
        'set-cookie': sessionCookie(sessionValue, secure),
        'x-csrf-token': csrfValue,
      },
    });
  }

  function authenticateBrowser(request, { mutation } = {}) {
    if (!(request instanceof Request) || typeof mutation !== 'boolean') unauthorized();
    rejectForwarding(request.headers);
    if (request.headers.has('authorization')) unauthorized();
    const sessionValue = exactSessionCookie(request.headers);
    const nowMs = currentTime();
    pruneExpired(sessions, nowMs);
    const sessionKey = digestKey('wallet-kernel.browser-session.v1', sessionValue);
    const session = sessions.get(sessionKey);
    if (!session || nowMs >= session.expiresAtMs || session.origin !== origin) unauthorized();
    if (mutation) {
      const csrf = request.headers.get('x-csrf-token') ?? '';
      const csrfValid = constantDigestMatch(
        'wallet-kernel.browser-csrf.v1',
        csrf,
        session.csrfDigest,
      );
      if (request.headers.get('origin') !== origin || !TOKEN_PATTERN.test(csrf) || !csrfValid) {
        unauthorized();
      }
    } else if (request.headers.has('origin') && request.headers.get('origin') !== origin) {
      unauthorized();
    }
    return principal;
  }

  function revokeBrowserSession(request) {
    authenticateBrowser(request, { mutation: true });
    const sessionValue = exactSessionCookie(request.headers);
    const key = digestKey('wallet-kernel.browser-session.v1', sessionValue);
    const session = sessions.get(key);
    sessions.delete(key);
    session?.csrfDigest.fill(0);
    return new Response(null, {
      status: 204,
      headers: {
        'cache-control': 'no-store',
        'set-cookie': clearedSessionCookie(secure),
      },
    });
  }

  return Object.freeze({
    authenticateBearer,
    authenticateBrowser,
    exchangeBrowserSession,
    issueBrowserLaunch,
    revokeBrowserSession,
  });
}

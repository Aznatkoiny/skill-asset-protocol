'use strict';

const dns = require('node:dns');
const dnsPromises = require('node:dns/promises');
const fs = require('node:fs');
const net = require('node:net');
const path = require('node:path');
const tls = require('node:tls');

const LOOPBACK = new Set(['127.0.0.1', '::1', '[::1]', 'localhost']);
const LOG_PATH = process.env.WALLET_KERNEL_EGRESS_LOG_FILE;

function fixtureError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function openLog() {
  if (typeof LOG_PATH !== 'string' || LOG_PATH.length === 0
      || !path.isAbsolute(LOG_PATH) || path.resolve(LOG_PATH) !== LOG_PATH) {
    throw fixtureError('EGRESS_LOG_INVALID', 'egress log path must be canonical and absolute');
  }
  const descriptor = fs.openSync(
    LOG_PATH,
    fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW,
  );
  try {
    const stat = fs.fstatSync(descriptor, { bigint: true });
    const uid = typeof process.getuid === 'function' ? BigInt(process.getuid()) : stat.uid;
    if (!stat.isFile() || stat.uid !== uid || (stat.mode & 0o7777n) !== 0o600n
        || stat.nlink !== 1n) {
      throw fixtureError('EGRESS_LOG_INVALID', 'egress log authority is invalid');
    }
    return descriptor;
  } catch (error) {
    fs.closeSync(descriptor);
    throw error;
  }
}

const logDescriptor = openLog();

function sanitizedDestination(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 255) return 'invalid';
  const lowered = value.toLowerCase();
  if (!/^[a-z0-9.:[\]_-]+$/u.test(lowered)) return 'invalid';
  return lowered;
}

function hostnameFromConnectArguments(args) {
  const first = args[0];
  if (first && typeof first === 'object') {
    if (typeof first.path === 'string') return 'unix-socket';
    return first.host ?? first.hostname ?? 'localhost';
  }
  if (typeof first === 'string') return 'unix-socket';
  return typeof args[1] === 'string' ? args[1] : 'localhost';
}

function recordAndThrow(operation, destination) {
  const record = JSON.stringify({
    destination: sanitizedDestination(destination),
    operation,
  });
  fs.writeSync(logDescriptor, `${record}\n`, null, 'utf8');
  throw fixtureError(
    'EXTERNAL_EGRESS_FORBIDDEN',
    'fixture processes may connect only to literal loopback destinations',
  );
}

function assertLoopback(operation, destination) {
  const normalized = sanitizedDestination(destination);
  if (!LOOPBACK.has(normalized)) recordAndThrow(operation, normalized);
}

function wrapConnect(target, name, operation) {
  const original = target[name];
  Object.defineProperty(target, name, {
    configurable: true,
    enumerable: true,
    writable: true,
    value: function loopbackOnlyConnect(...args) {
      assertLoopback(operation, hostnameFromConnectArguments(args));
      return Reflect.apply(original, this, args);
    },
  });
}

wrapConnect(net, 'connect', 'net.connect');
wrapConnect(net, 'createConnection', 'net.createConnection');
wrapConnect(tls, 'connect', 'tls.connect');

for (const name of [
  'lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa',
  'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr',
  'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse',
]) {
  if (typeof dns[name] !== 'function') continue;
  const original = dns[name];
  Object.defineProperty(dns, name, {
    configurable: true,
    enumerable: true,
    writable: true,
    value: function loopbackOnlyDns(destination, ...args) {
      assertLoopback(`dns.${name}`, destination);
      return Reflect.apply(original, this, [destination, ...args]);
    },
  });
}

for (const name of [
  'lookup', 'resolve', 'resolve4', 'resolve6', 'resolveAny', 'resolveCaa',
  'resolveCname', 'resolveMx', 'resolveNaptr', 'resolveNs', 'resolvePtr',
  'resolveSoa', 'resolveSrv', 'resolveTxt', 'reverse',
]) {
  if (typeof dnsPromises[name] !== 'function') continue;
  const original = dnsPromises[name];
  Object.defineProperty(dnsPromises, name, {
    configurable: true,
    enumerable: true,
    writable: true,
    value: function loopbackOnlyDnsPromise(destination, ...args) {
      assertLoopback(`dns.promises.${name}`, destination);
      return Reflect.apply(original, this, [destination, ...args]);
    },
  });
}

process.once('exit', () => {
  try {
    fs.closeSync(logDescriptor);
  } catch {
    // Process teardown is already terminal and the log never carries credentials.
  }
});

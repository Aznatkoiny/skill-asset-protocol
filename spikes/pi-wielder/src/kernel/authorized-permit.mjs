import { types as utilTypes } from 'node:util';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';

const BASE_SEPOLIA_CAIP2 = 'eip155:84532';
const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const NONCE_PATTERN = /^0x[0-9a-f]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const PristineWeakMap = WeakMap;
const PristineWeakSet = WeakSet;
const reflectApply = Reflect.apply;
const weakMapDelete = WeakMap.prototype.delete;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetAdd = WeakSet.prototype.add;
const weakSetHas = WeakSet.prototype.has;
const BINDING_FIELDS = Object.freeze([
  'intentId',
  'intentHash',
  'challengeHash',
  'quoteId',
  'acceptedIndex',
  'requestUrl',
  'resourceDescription',
  'resourceMimeType',
  'scheme',
  'network',
  'asset',
  'walletAddress',
  'payTo',
  'amountAtomic',
  'validAfter',
  'validBefore',
  'nonce',
  'policyVersionId',
]);
const WINDOW_FIELDS = Object.freeze([
  'nowMs',
  'challengeReceivedAtMs',
  'challengeMaxAgeMs',
  'approvalExpiresAt',
  'maxTimeoutSeconds',
  'randomBytes',
]);

function fail(code, message) {
  throw new KernelError(code, message);
}

function permitBindingError(message) {
  fail('PERMIT_BINDING', message);
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    permitBindingError(`${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalAddress(value, label) {
  if (typeof value !== 'string' || !ADDRESS_PATTERN.test(value)) {
    permitBindingError(`${label} must be one canonical lowercase EVM address`);
  }
  return value;
}

function canonicalUint256(value, label, { positive = false } = {}) {
  let atomic;
  try {
    atomic = canonicalAtomic(value, label);
  } catch (error) {
    if (error instanceof KernelError) {
      return permitBindingError(`${label} must be canonical uint256 text`);
    }
    throw error;
  }
  if ((positive && atomic.value === 0n) || atomic.value > MAX_UINT256) {
    permitBindingError(`${label} is outside the permitted uint256 range`);
  }
  return atomic.text;
}

function isCanonicalLiteralLoopbackHttp(value, parsed) {
  if (parsed.protocol !== 'http:' || !value.startsWith('http://')) return false;
  const authority = value.slice('http://'.length).split(/[/?#]/u, 1)[0];
  return /^(?:127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(authority)
    && parsed.origin === `http://${authority}`;
}

function canonicalRequestUrl(value) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > 4_096) {
    permitBindingError('request URL must be one bounded canonical URL');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return permitBindingError('request URL must be one absolute canonical URL');
  }
  if ((parsed.protocol !== 'https:' && !isCanonicalLiteralLoopbackHttp(value, parsed))
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.hash !== ''
      || parsed.origin === 'null'
      || parsed.href !== value) {
    permitBindingError('request URL must preserve one exact HTTPS or literal-loopback URL');
  }
  return value;
}

function canonicalIntentId(value) {
  try {
    return canonicalToken(value, 'permit intent ID');
  } catch (error) {
    if (error instanceof KernelError) {
      return permitBindingError('intent ID must be one bounded canonical token');
    }
    throw error;
  }
}

function canonicalPolicyVersionId(value) {
  try {
    return canonicalToken(value, 'permit policy version ID');
  } catch (error) {
    if (error instanceof KernelError) {
      return permitBindingError('policy version ID must be one bounded canonical token');
    }
    throw error;
  }
}

function boundedResourceDescription(value) {
  if (typeof value !== 'string'
      || value.length === 0
      || Buffer.byteLength(value, 'utf8') > 1_024
      || /[\x00-\x1f\x7f]/.test(value)) {
    permitBindingError('resource description must be bounded canonical public text');
  }
  return value;
}

function canonicalResourceMimeType(value) {
  if (typeof value !== 'string'
      || Buffer.byteLength(value, 'utf8') > 200
      || !/^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/.test(
        value,
      )) {
    permitBindingError('resource MIME type must be bounded and canonical');
  }
  return value;
}

function validatePermitBinding(value) {
  let binding;
  try {
    binding = exactRecord(
      value,
      BINDING_FIELDS,
      [],
      'PERMIT_BINDING',
      'AuthorizedPermit binding',
    );
  } catch (error) {
    if (error instanceof KernelError) permitBindingError(error.message);
    throw error;
  }

  if (!Number.isSafeInteger(binding.acceptedIndex) || binding.acceptedIndex < 0) {
    permitBindingError('accepted index must be one nonnegative safe integer');
  }
  if (binding.scheme !== 'exact') {
    permitBindingError('permit scheme must be exact');
  }
  if (binding.network !== BASE_SEPOLIA_CAIP2) {
    permitBindingError('permit network must be Base Sepolia');
  }
  if (binding.asset !== BASE_SEPOLIA_USDC) {
    permitBindingError('permit asset must be Base Sepolia test USDC');
  }
  if (binding.validAfter !== '0') {
    permitBindingError('authorization validAfter must be exactly zero');
  }
  if (typeof binding.nonce !== 'string' || !NONCE_PATTERN.test(binding.nonce)) {
    permitBindingError('authorization nonce must be one canonical lowercase bytes32 value');
  }

  const challengeHash = canonicalHash(binding.challengeHash, 'challenge hash');
  const quoteId = canonicalHash(binding.quoteId, 'quote ID');
  if (quoteId !== sha256(canonicalJson({
    challengeHash,
    acceptedIndex: binding.acceptedIndex,
  }))) {
    permitBindingError('quote ID does not match the challenge selection');
  }

  return frozenCopy({
    intentId: canonicalIntentId(binding.intentId),
    intentHash: canonicalHash(binding.intentHash, 'intent hash'),
    challengeHash,
    quoteId,
    acceptedIndex: binding.acceptedIndex,
    requestUrl: canonicalRequestUrl(binding.requestUrl),
    resourceDescription: boundedResourceDescription(binding.resourceDescription),
    resourceMimeType: canonicalResourceMimeType(binding.resourceMimeType),
    scheme: 'exact',
    network: BASE_SEPOLIA_CAIP2,
    asset: BASE_SEPOLIA_USDC,
    walletAddress: canonicalAddress(binding.walletAddress, 'wallet address'),
    payTo: canonicalAddress(binding.payTo, 'payee address'),
    amountAtomic: canonicalUint256(binding.amountAtomic, 'authorization amount', {
      positive: true,
    }),
    validAfter: '0',
    validBefore: canonicalUint256(binding.validBefore, 'authorization validBefore', {
      positive: true,
    }),
    nonce: binding.nonce,
    policyVersionId: canonicalPolicyVersionId(binding.policyVersionId),
  });
}

function closedWindowInput(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('AUTHORIZATION_WINDOW', 'authorization-window input must be one plain object');
  }
  const keys = Reflect.ownKeys(value);
  const allowed = new Set(WINDOW_FIELDS);
  if (WINDOW_FIELDS.some((field) => !Object.hasOwn(value, field))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    fail('AUTHORIZATION_WINDOW', 'authorization-window input fields do not match the closed schema');
  }
  const copy = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('AUTHORIZATION_WINDOW', 'authorization-window fields must be enumerable data');
    }
    copy[key] = descriptor.value;
  }
  return copy;
}

function nonnegativeSafeMilliseconds(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('AUTHORIZATION_WINDOW', `${label} must be nonnegative safe-integer milliseconds`);
  }
  return value;
}

function positiveSafeInteger(value, label, maximum = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    fail('AUTHORIZATION_WINDOW', `${label} must be one positive bounded safe integer`);
  }
  return value;
}

function canonicalApprovalExpiry(value) {
  if (value === null) return null;
  try {
    return canonicalTimestamp(value, 'approval expiry');
  } catch (error) {
    if (error instanceof KernelError) {
      return fail('AUTHORIZATION_WINDOW', 'approval expiry must be null or a canonical timestamp');
    }
    throw error;
  }
}

function randomNonce(randomBytes) {
  if (typeof randomBytes !== 'function') {
    fail('AUTHORIZATION_WINDOW', 'randomBytes must be one injected function');
  }
  const bytes = randomBytes(32);
  if (utilTypes.isProxy(bytes)) {
    fail('AUTHORIZATION_RANDOMNESS', 'randomBytes must return exactly 32 inert bytes');
  }
  const isBuffer = Buffer.isBuffer(bytes) && Object.getPrototypeOf(bytes) === Buffer.prototype;
  const isUint8 = bytes instanceof Uint8Array
    && Object.getPrototypeOf(bytes) === Uint8Array.prototype;
  if ((!isBuffer && !isUint8)
      || bytes.buffer instanceof SharedArrayBuffer
      || bytes.byteLength !== 32) {
    fail('AUTHORIZATION_RANDOMNESS', 'randomBytes must return exactly 32 inert bytes');
  }
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

export function deriveAuthorizationWindow(value) {
  const input = closedWindowInput(value);
  const nowMs = nonnegativeSafeMilliseconds(input.nowMs, 'current time');
  const challengeReceivedAtMs = nonnegativeSafeMilliseconds(
    input.challengeReceivedAtMs,
    'challenge receipt time',
  );
  const challengeMaxAgeMs = positiveSafeInteger(
    input.challengeMaxAgeMs,
    'challenge maximum age',
  );
  const maxTimeoutSeconds = positiveSafeInteger(
    input.maxTimeoutSeconds,
    'protocol maximum timeout',
    3_600,
  );
  const approvalExpiresAt = canonicalApprovalExpiry(input.approvalExpiresAt);
  if (challengeReceivedAtMs > nowMs
      || challengeReceivedAtMs > Number.MAX_SAFE_INTEGER - challengeMaxAgeMs) {
    fail('AUTHORIZATION_WINDOW', 'challenge timing is not one safe elapsed window');
  }

  const nowSeconds = Math.floor(nowMs / 1_000);
  const challengeDeadlineSeconds = Math.floor(
    (challengeReceivedAtMs + challengeMaxAgeMs) / 1_000,
  );
  const approvalDeadlineSeconds = approvalExpiresAt === null
    ? challengeDeadlineSeconds
    : Math.floor(Date.parse(approvalExpiresAt) / 1_000);
  const validBefore = Math.min(
    nowSeconds + maxTimeoutSeconds,
    challengeDeadlineSeconds,
    approvalDeadlineSeconds,
  );
  if (!Number.isSafeInteger(validBefore) || validBefore <= nowSeconds) {
    fail('AUTHORIZATION_WINDOW', 'authorization validity window is exhausted');
  }

  const nonce = randomNonce(input.randomBytes);
  return frozenCopy({
    nonce,
    validAfter: '0',
    validBefore: String(validBefore),
  });
}

export function createPermitAuthority() {
  const live = new PristineWeakMap();
  const consumed = new PristineWeakSet();
  return Object.freeze({
    issue(binding) {
      const validated = validatePermitBinding(binding);
      const permit = Object.freeze({
        kind: 'AuthorizedPermit',
        intentId: validated.intentId,
      });
      reflectApply(weakMapSet, live, [permit, validated]);
      return permit;
    },
    verifyAndConsume(permit) {
      if (reflectApply(weakSetHas, consumed, [permit])) {
        throw new Error('AuthorizedPermit already consumed');
      }
      const binding = reflectApply(weakMapGet, live, [permit]);
      if (!binding) throw new Error('AuthorizedPermit is forged');
      reflectApply(weakMapDelete, live, [permit]);
      reflectApply(weakSetAdd, consumed, [permit]);
      return binding;
    },
  });
}

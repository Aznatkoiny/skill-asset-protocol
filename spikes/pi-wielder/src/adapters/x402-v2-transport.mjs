import { types as utilTypes } from 'node:util';

import {
  decodePaymentRequiredHeader,
  decodePaymentResponseHeader,
  encodePaymentSignatureHeader,
} from '@x402/core/http';

import {
  canonicalAtomic,
  canonicalEvmHash,
  canonicalJson,
  frozenCopy,
  sha256,
} from '../kernel/canonical.mjs';
import {
  cancelResponseBody,
  readBodyBytes,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from '../runtime-boundaries.mjs';

const MODES = new Set(['cdp-testnet', 'deterministic']);
const BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;
const ASCII = /^[\x00-\x7f]*$/;
const HASH = /^sha256:[0-9a-f]{64}$/;
const LOWERCASE_ADDRESS = /^0x[0-9a-f]{40}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const HTTP_METHOD = /^[A-Z][A-Z0-9-]{0,31}$/;
const PROTOCOL_TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/;
const MIME_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]*$/;
const MAX_REQUEST_BODY_BYTES = 1_048_576;
const MAX_HEADER_COUNT = 100;
const MAX_HEADER_VALUE_BYTES = 8_192;
const MAX_TEXT_BYTES = 2_048;
const MAX_ACCEPTS = 100;
const MAX_CLASSIFIER_HEADER_BYTES = 16_384;
const FORBIDDEN_REQUEST_HEADERS = new Set([
  'authorization',
  'connection',
  'content-length',
  'cookie',
  'cookie2',
  'host',
  'payment-required',
  'payment-response',
  'payment-signature',
  'proxy-authorization',
  'proxy-connection',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'x-payment',
  'x-payment-required',
  'x-payment-response',
]);

export class X402TransportError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'X402TransportError';
    this.code = code;
  }
}

function fail(code, message, cause) {
  throw new X402TransportError(code, message, cause === undefined ? undefined : { cause });
}

function plainFunction(value, code, label) {
  if (typeof value !== 'function' || utilTypes.isProxy(value)) {
    fail(code, `${label} must be one non-proxy function`);
  }
  return value;
}

function closedRecord(value, required, optional, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, `${label} must be one plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    fail(code, `${label} fields do not match the closed schema`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(code, `${label} must contain only enumerable data fields`);
    }
    result[key] = descriptor.value;
  }
  return result;
}

function positiveSafeInteger(value, code, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    fail(code, `${label} must be one positive safe integer`);
  }
  return value;
}

function boundedText(value, code, label, maximum = MAX_TEXT_BYTES) {
  if (typeof value !== 'string' || value.length === 0
      || Buffer.byteLength(value, 'utf8') > maximum
      || /[\x00-\x1f\x7f]/.test(value)) {
    fail(code, `${label} must be one nonempty bounded string`);
  }
  return value;
}

function protocolToken(value, code, label) {
  if (typeof value !== 'string' || !PROTOCOL_TOKEN.test(value)) {
    fail(code, `${label} must be one bounded protocol token`);
  }
  return value;
}

function safeFrozenCopy(value, code, label) {
  try {
    canonicalJson(value);
    return frozenCopy(value);
  } catch (error) {
    fail(code, `${label} must contain only inert canonical data`, error);
  }
}

function canonicalUrl(value, mode, code = 'REQUEST_SCHEMA') {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8_192) {
    fail(code, 'request URL must be one bounded absolute URL');
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch (error) {
    fail(code, 'request URL must be one bounded absolute URL', error);
  }
  const loopback = parsed.protocol === 'http:'
    && (parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]');
  if ((parsed.protocol !== 'https:' && !(mode === 'deterministic' && loopback))
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.hash !== ''
      || parsed.href !== value) {
    fail(code, 'request URL is outside the selected transport mode');
  }
  return Object.freeze({ href: parsed.href, origin: parsed.origin });
}

function copyBody(value) {
  if (utilTypes.isProxy(value)) fail('REQUEST_SCHEMA', 'request body must be inert bytes');
  const buffer = Buffer.isBuffer(value) && Object.getPrototypeOf(value) === Buffer.prototype;
  const uint8 = value instanceof Uint8Array
    && Object.getPrototypeOf(value) === Uint8Array.prototype;
  if ((!buffer && !uint8) || value.buffer instanceof SharedArrayBuffer
      || value.byteLength > MAX_REQUEST_BODY_BYTES) {
    fail('REQUEST_SCHEMA', 'request body must be bounded inert bytes');
  }
  return Buffer.from(value);
}

function canonicalRequestHeaders(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail('REQUEST_SCHEMA', 'request headers must be one plain object');
  }
  const keys = Reflect.ownKeys(value);
  if (keys.length > MAX_HEADER_COUNT) fail('REQUEST_SCHEMA', 'too many request headers');
  const normalized = new Map();
  for (const key of keys) {
    if (typeof key !== 'string' || !HEADER_NAME.test(key)) {
      fail('REQUEST_SCHEMA', 'request header name is invalid');
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('REQUEST_SCHEMA', 'request headers must contain only data fields');
    }
    const name = key.toLowerCase();
    if (normalized.has(name) || FORBIDDEN_REQUEST_HEADERS.has(name)) {
      fail('REQUEST_SCHEMA', 'request header is duplicate, credential-bearing, or reserved');
    }
    const headerValue = descriptor.value;
    if (typeof headerValue !== 'string' || headerValue.length === 0
        || Buffer.byteLength(headerValue, 'utf8') > MAX_HEADER_VALUE_BYTES
        || /[\x00-\x08\x0a-\x1f\x7f]/.test(headerValue)) {
      fail('REQUEST_SCHEMA', 'request header value is invalid');
    }
    normalized.set(name, headerValue);
  }
  return Object.freeze(Object.fromEntries([...normalized.entries()].sort(([left], [right]) => (
    left < right ? -1 : left > right ? 1 : 0
  ))));
}

function captureRequest(value, mode) {
  const request = closedRecord(
    value,
    ['requestUrl', 'method', 'headers', 'bodyBytes'],
    [],
    'REQUEST_SCHEMA',
    'transport request',
  );
  if (typeof request.method !== 'string' || !HTTP_METHOD.test(request.method)) {
    fail('REQUEST_SCHEMA', 'request method must be one canonical uppercase HTTP token');
  }
  const url = canonicalUrl(request.requestUrl, mode);
  return Object.freeze({
    requestUrl: url.href,
    method: request.method,
    headers: canonicalRequestHeaders(request.headers),
    bodyBytes: copyBody(request.bodyBytes),
  });
}

function fetchInit(snapshot, signal, paymentHeader = null) {
  const headers = new Headers(snapshot.headers);
  if (paymentHeader !== null) headers.set('PAYMENT-SIGNATURE', paymentHeader);
  const init = {
    method: snapshot.method,
    headers,
    redirect: 'manual',
    credentials: 'omit',
    signal,
  };
  if (snapshot.method !== 'GET' && snapshot.method !== 'HEAD') {
    init.body = Buffer.from(snapshot.bodyBytes);
  } else if (snapshot.bodyBytes.byteLength !== 0) {
    fail('REQUEST_SCHEMA', `${snapshot.method} requests may not carry a body`);
  }
  return init;
}

function assertResponse(value, code) {
  if (!(value instanceof Response)) fail(code, 'fetch must return one real Response');
  return value;
}

function isRedirect(status) {
  return status >= 300 && status <= 399;
}

function headerValue(response, name, maximumBytes, prefix) {
  const value = response.headers.get(name);
  if (value === null) fail(`${prefix}_MISSING`, `${name} header is required`);
  if (typeof value !== 'string') {
    fail(`${prefix}_MALFORMED`, `${name} must be one primitive string`);
  }
  if (value.length > maximumBytes) {
    fail(`${prefix}_TOO_LARGE`, `${name} exceeds its byte ceiling`);
  }
  if (!ASCII.test(value)) {
    fail(`${prefix}_MALFORMED`, `${name} must contain only ASCII bytes`);
  }
  if (Buffer.byteLength(value, 'ascii') > maximumBytes) {
    fail(`${prefix}_TOO_LARGE`, `${name} exceeds its byte ceiling`);
  }
  if (value.includes(',')) fail(`${prefix}_DUPLICATE`, `${name} header must occur exactly once`);
  return value;
}

function base64HeaderStatus(value, maximumBytes) {
  if (typeof value !== 'string') return 'invalid';
  if (value.length > maximumBytes) return 'too_large';
  if (!ASCII.test(value)) return 'invalid';
  if (Buffer.byteLength(value, 'ascii') > maximumBytes) return 'too_large';
  if (value.length === 0 || !BASE64.test(value)) return 'invalid';
  try {
    return Buffer.from(value, 'base64').toString('base64') === value
      ? 'canonical'
      : 'invalid';
  } catch {
    return 'invalid';
  }
}

function validateExtra(value, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    fail(code, `${label} must be one plain object`);
  }
  return safeFrozenCopy(value, code, label);
}

function validatePaymentRequired(value, expectedUrl, mode) {
  const payment = closedRecord(
    value,
    ['x402Version', 'resource', 'accepts'],
    ['error'],
    'PAYMENT_REQUIRED_SCHEMA',
    'PAYMENT-REQUIRED value',
  );
  if (payment.x402Version !== 2) {
    fail('PAYMENT_REQUIRED_SCHEMA', 'only x402Version 2 is accepted');
  }
  if (Object.hasOwn(payment, 'error')) {
    boundedText(payment.error, 'PAYMENT_REQUIRED_SCHEMA', 'payment error');
  }
  const resource = closedRecord(
    payment.resource,
    ['url', 'description', 'mimeType'],
    [],
    'PAYMENT_REQUIRED_SCHEMA',
    'payment resource',
  );
  const resourceUrl = canonicalUrl(resource.url, mode, 'PAYMENT_REQUIRED_SCHEMA');
  boundedText(resource.description, 'PAYMENT_REQUIRED_SCHEMA', 'resource description', 1_024);
  boundedText(resource.mimeType, 'PAYMENT_REQUIRED_SCHEMA', 'resource MIME type', 200);
  if (!MIME_TYPE.test(resource.mimeType)) {
    fail('PAYMENT_REQUIRED_SCHEMA', 'resource MIME type is not canonical');
  }
  if (resourceUrl.href !== expectedUrl) {
    fail('RESOURCE_URL_MISMATCH', 'payment resource URL differs from the unpaid request');
  }
  if (!Array.isArray(payment.accepts) || Object.getPrototypeOf(payment.accepts) !== Array.prototype
      || payment.accepts.length < 1 || payment.accepts.length > MAX_ACCEPTS) {
    fail('PAYMENT_REQUIRED_SCHEMA', 'accepts must be one nonempty bounded array');
  }
  const accepts = payment.accepts.map((candidateValue) => {
    const candidate = closedRecord(candidateValue, [
      'scheme',
      'network',
      'asset',
      'amount',
      'payTo',
      'maxTimeoutSeconds',
      'extra',
    ], [], 'PAYMENT_REQUIRED_SCHEMA', 'payment requirement');
    protocolToken(candidate.scheme, 'PAYMENT_REQUIRED_SCHEMA', 'payment requirement scheme');
    protocolToken(candidate.network, 'PAYMENT_REQUIRED_SCHEMA', 'payment requirement network');
    for (const [key, maximum] of [['asset', 1_024], ['payTo', 1_024]]) {
      boundedText(candidate[key], 'PAYMENT_REQUIRED_SCHEMA', `payment requirement ${key}`, maximum);
    }
    if (typeof candidate.amount !== 'string' || candidate.amount.length > 100) {
      fail('PAYMENT_REQUIRED_SCHEMA', 'payment requirement amount must be bounded text');
    }
    let amount;
    try {
      amount = canonicalAtomic(candidate.amount, 'payment requirement amount');
    } catch (error) {
      fail('PAYMENT_REQUIRED_SCHEMA', 'payment requirement amount must be canonical atomic text', error);
    }
    if (amount.value <= 0n) {
      fail('PAYMENT_REQUIRED_SCHEMA', 'payment requirement amount must be positive and bounded');
    }
    positiveSafeInteger(
      candidate.maxTimeoutSeconds,
      'PAYMENT_REQUIRED_SCHEMA',
      'payment requirement maxTimeoutSeconds',
    );
    return {
      scheme: candidate.scheme,
      network: candidate.network,
      asset: candidate.asset,
      amount: amount.text,
      payTo: candidate.payTo,
      maxTimeoutSeconds: candidate.maxTimeoutSeconds,
      extra: validateExtra(candidate.extra, 'PAYMENT_REQUIRED_SCHEMA', 'payment requirement extra'),
    };
  });
  return frozenCopy({
    x402Version: 2,
    ...(Object.hasOwn(payment, 'error') ? { error: payment.error } : {}),
    resource: {
      url: resourceUrl.href,
      description: resource.description,
      mimeType: resource.mimeType,
    },
    accepts,
  });
}

function decodeChallenge(rawHeader, expectedUrl, mode, maximumBytes) {
  const status = base64HeaderStatus(rawHeader, maximumBytes);
  if (status === 'too_large') {
    fail('PAYMENT_REQUIRED_TOO_LARGE', 'PAYMENT-REQUIRED exceeds its byte ceiling');
  }
  if (status !== 'canonical') {
    fail('PAYMENT_REQUIRED_MALFORMED', 'PAYMENT-REQUIRED is not canonical base64 JSON');
  }
  let decoded;
  try {
    decoded = decodePaymentRequiredHeader(rawHeader);
  } catch (error) {
    fail('PAYMENT_REQUIRED_MALFORMED', 'PAYMENT-REQUIRED is not canonical base64 JSON', error);
  }
  return validatePaymentRequired(decoded, expectedUrl, mode);
}

function validateBinding(value) {
  const binding = closedRecord(value, [
    'network',
    'walletAddress',
    'amountAtomic',
    'paymentHash',
  ], [], 'SETTLEMENT_BINDING', 'settlement binding');
  protocolToken(binding.network, 'SETTLEMENT_BINDING', 'settlement network');
  if (typeof binding.walletAddress !== 'string'
      || !LOWERCASE_ADDRESS.test(binding.walletAddress)) {
    fail('SETTLEMENT_BINDING', 'settlement wallet must be one canonical lowercase EVM address');
  }
  if (typeof binding.amountAtomic !== 'string' || binding.amountAtomic.length > 100) {
    fail('SETTLEMENT_BINDING', 'settlement amount must be bounded canonical text');
  }
  let amount;
  try {
    amount = canonicalAtomic(binding.amountAtomic, 'settlement amount');
  } catch (error) {
    fail('SETTLEMENT_BINDING', 'settlement amount must be canonical atomic text', error);
  }
  if (amount.value <= 0n || typeof binding.paymentHash !== 'string'
      || !HASH.test(binding.paymentHash)) {
    fail('SETTLEMENT_BINDING', 'settlement binding amount or payment hash is invalid');
  }
  return Object.freeze({
    network: binding.network,
    walletAddress: binding.walletAddress,
    amountAtomic: amount.text,
    paymentHash: binding.paymentHash,
  });
}

function unresolved(reasonCode) {
  return Object.freeze({ kind: 'unresolved', reasonCode });
}

function normalizePayer(value) {
  if (typeof value !== 'string' || !ADDRESS.test(value)) return null;
  return value.toLowerCase();
}

export function classifyX402PaymentResponse(value) {
  let input;
  let binding;
  try {
    input = closedRecord(
      value,
      ['rawHeader', 'decoded', 'binding'],
      [],
      'SETTLEMENT_CLASSIFIER',
      'settlement classifier input',
    );
    binding = validateBinding(input.binding);
  } catch {
    return unresolved('SETTLEMENT_BINDING_INVALID');
  }
  if (base64HeaderStatus(input.rawHeader, MAX_CLASSIFIER_HEADER_BYTES) !== 'canonical') {
    return unresolved('SETTLEMENT_HEADER_INVALID');
  }
  let headerDecoded;
  try {
    headerDecoded = decodePaymentResponseHeader(input.rawHeader);
  } catch {
    return unresolved('SETTLEMENT_HEADER_INVALID');
  }
  try {
    if (canonicalJson(headerDecoded) !== canonicalJson(input.decoded)) {
      return unresolved('SETTLEMENT_DECODE_MISMATCH');
    }
  } catch {
    return unresolved('SETTLEMENT_SCHEMA_INVALID');
  }

  let decoded;
  try {
    decoded = closedRecord(input.decoded, [
      'success',
      'transaction',
      'network',
    ], [
      'payer',
      'amount',
      'errorReason',
      'errorMessage',
      'extensions',
      'extra',
    ], 'SETTLEMENT_SCHEMA', 'PAYMENT-RESPONSE value');
  } catch {
    return unresolved('SETTLEMENT_SCHEMA_INVALID');
  }
  if (typeof decoded.success !== 'boolean'
      || typeof decoded.transaction !== 'string'
      || typeof decoded.network !== 'string'
      || decoded.network.length === 0
      || Buffer.byteLength(decoded.network, 'utf8') > 200) {
    return unresolved('SETTLEMENT_SCHEMA_INVALID');
  }
  for (const field of ['payer', 'amount', 'errorReason', 'errorMessage']) {
    if (Object.hasOwn(decoded, field) && typeof decoded[field] !== 'string') {
      return unresolved('SETTLEMENT_SCHEMA_INVALID');
    }
  }
  for (const field of ['extensions', 'extra']) {
    if (Object.hasOwn(decoded, field)) {
      try {
        validateExtra(decoded[field], 'SETTLEMENT_SCHEMA', `settlement ${field}`);
      } catch {
        return unresolved('SETTLEMENT_SCHEMA_INVALID');
      }
    }
  }
  if (!decoded.success) return unresolved('SETTLEMENT_REPORTED_FAILURE');
  if (Object.hasOwn(decoded, 'errorReason') || Object.hasOwn(decoded, 'errorMessage')) {
    return unresolved('SETTLEMENT_SUCCESS_HAS_ERROR');
  }
  if (decoded.network !== binding.network) return unresolved('SETTLEMENT_NETWORK_MISMATCH');
  if (!Object.hasOwn(decoded, 'payer')) return unresolved('SETTLEMENT_PAYER_MISSING');
  const payer = normalizePayer(decoded.payer);
  if (payer === null) return unresolved('SETTLEMENT_PAYER_INVALID');
  if (payer !== binding.walletAddress) return unresolved('SETTLEMENT_PAYER_MISMATCH');
  let transaction;
  try {
    transaction = canonicalEvmHash(decoded.transaction, 'settlement transaction');
  } catch {
    return unresolved('SETTLEMENT_TRANSACTION_INVALID');
  }
  let amountAtomic;
  if (Object.hasOwn(decoded, 'amount')) {
    try {
      amountAtomic = canonicalAtomic(decoded.amount, 'settlement amount').text;
    } catch {
      return unresolved('SETTLEMENT_AMOUNT_INVALID');
    }
    if (amountAtomic !== binding.amountAtomic) return unresolved('SETTLEMENT_AMOUNT_MISMATCH');
  }
  const settlement = frozenCopy({
    source: 'x402-payment-response',
    headerHash: sha256(Buffer.from(input.rawHeader, 'ascii')),
    success: true,
    transaction,
    network: decoded.network,
    payer,
    ...(amountAtomic === undefined ? {} : { amountAtomic }),
    paymentHash: binding.paymentHash,
  });
  return Object.freeze({ kind: 'settled', settlement });
}

function ambiguous(reasonCode) {
  return Object.freeze({ kind: 'paid_response_ambiguous', reasonCode });
}

function settledResult(settlement, status, body, executionState, deliveryReason) {
  return Object.freeze({
    kind: 'settled_response',
    settlement,
    status,
    body,
    executionState,
    ...(deliveryReason === undefined ? {} : { deliveryReason }),
  });
}

function decodeSettlementHeader(response, maximumBytes, binding) {
  let rawHeader;
  try {
    rawHeader = headerValue(
      response,
      'PAYMENT-RESPONSE',
      maximumBytes,
      'PAYMENT_RESPONSE',
    );
  } catch (error) {
    if (error instanceof X402TransportError) return ambiguous(error.code);
    return ambiguous('PAYMENT_RESPONSE_MALFORMED');
  }
  const status = base64HeaderStatus(rawHeader, maximumBytes);
  if (status === 'too_large') return ambiguous('PAYMENT_RESPONSE_TOO_LARGE');
  if (status !== 'canonical') return ambiguous('PAYMENT_RESPONSE_MALFORMED');
  let decoded;
  try {
    decoded = decodePaymentResponseHeader(rawHeader);
  } catch {
    return ambiguous('PAYMENT_RESPONSE_MALFORMED');
  }
  const classified = classifyX402PaymentResponse({ rawHeader, decoded, binding });
  return classified.kind === 'settled'
    ? classified
    : ambiguous(classified.reasonCode);
}

function boundaryOptions(requestTimeoutMs, prefix) {
  return {
    timeoutMs: requestTimeoutMs,
    timeoutCode: `${prefix}_TIMEOUT`,
    timeoutMessage: `${prefix.toLowerCase().replaceAll('_', ' ')} timed out`,
    abortedCode: `${prefix}_ABORTED`,
    abortedMessage: `${prefix.toLowerCase().replaceAll('_', ' ')} was aborted`,
  };
}

function bodyOptions(maximumResponseBytes, signal) {
  return {
    maxBytes: maximumResponseBytes,
    tooLargeCode: 'BODY_TOO_LARGE',
    tooLargeMessage: 'response body exceeds its byte ceiling',
    readErrorCode: 'BODY_READ_FAILED',
    readErrorMessage: 'response body could not be delivered',
    signal,
  };
}

function mapUnpaidFailure(error) {
  if (error instanceof X402TransportError) return error;
  if (error instanceof RuntimeBoundaryError) {
    return new X402TransportError(error.code, error.message, { cause: error });
  }
  return new X402TransportError('UNPAID_FETCH_FAILED', 'unpaid request failed', { cause: error });
}

function mapPaidFailure(error, trustedSettlement, status) {
  if (trustedSettlement !== null && status >= 200 && status <= 299) {
    if (error instanceof RuntimeBoundaryError && error.code === 'PAID_RESPONSE_TIMEOUT') {
      return settledResult(trustedSettlement, status, null, 'unknown', 'BODY_TIMEOUT');
    }
    if (error instanceof RuntimeBoundaryError && error.code === 'BODY_TOO_LARGE') {
      return settledResult(trustedSettlement, status, null, 'unknown', 'BODY_TOO_LARGE');
    }
    return settledResult(trustedSettlement, status, null, 'unknown', 'BODY_READ_FAILED');
  }
  if (error instanceof RuntimeBoundaryError && error.code === 'PAID_RESPONSE_TIMEOUT') {
    return ambiguous('PAID_RESPONSE_TIMEOUT');
  }
  return ambiguous('PAID_FETCH_FAILED');
}

export function createX402V2Transport(value) {
  const config = closedRecord(
    value,
    ['fetchImpl', 'mode', 'limits'],
    [],
    'TRANSPORT_CONFIG',
    'x402 transport configuration',
  );
  const fetchImpl = plainFunction(config.fetchImpl, 'TRANSPORT_CONFIG', 'fetchImpl');
  if (!MODES.has(config.mode)) fail('TRANSPORT_CONFIG', 'transport mode is unsupported');
  const rawLimits = closedRecord(config.limits, [
    'requestTimeoutMs',
    'maximumResponseBytes',
    'maximumPaymentHeaderBytes',
  ], [], 'TRANSPORT_CONFIG', 'x402 transport limits');
  const limits = Object.freeze({
    requestTimeoutMs: positiveSafeInteger(
      rawLimits.requestTimeoutMs,
      'TRANSPORT_CONFIG',
      'requestTimeoutMs',
    ),
    maximumResponseBytes: positiveSafeInteger(
      rawLimits.maximumResponseBytes,
      'TRANSPORT_CONFIG',
      'maximumResponseBytes',
    ),
    maximumPaymentHeaderBytes: positiveSafeInteger(
      rawLimits.maximumPaymentHeaderBytes,
      'TRANSPORT_CONFIG',
      'maximumPaymentHeaderBytes',
    ),
  });
  const requests = new WeakMap();

  const probe = async (request) => {
    if (!request || typeof request !== 'object' || utilTypes.isProxy(request)) {
      fail('REQUEST_SCHEMA', 'transport request must be one plain object');
    }
    const previous = requests.get(request);
    if (previous?.phase === 'probing' || previous?.phase === 'retrying') {
      fail('REQUEST_IN_FLIGHT', 'request already has a transport call in flight');
    }
    const snapshot = captureRequest(request, config.mode);
    const state = { snapshot, phase: 'probing' };
    requests.set(request, state);
    try {
      const result = await withWallClockDeadline(
        boundaryOptions(limits.requestTimeoutMs, 'UNPAID_RESPONSE'),
        async (signal) => {
          const response = assertResponse(
            await fetchImpl(snapshot.requestUrl, fetchInit(snapshot, signal)),
            'UNPAID_RESPONSE_SHAPE',
          );
          if (isRedirect(response.status)) {
            cancelResponseBody(response, new Error('redirect forbidden'));
            fail('REDIRECT_FORBIDDEN', 'unpaid redirect responses are forbidden');
          }
          if (response.status === 402) {
            let rawHeader;
            try {
              rawHeader = headerValue(
                response,
                'PAYMENT-REQUIRED',
                limits.maximumPaymentHeaderBytes,
                'PAYMENT_REQUIRED',
              );
            } catch (error) {
              cancelResponseBody(response, error);
              throw error;
            }
            await readBodyBytes(response, {
              ...bodyOptions(limits.maximumResponseBytes, signal),
              tooLargeCode: 'RESPONSE_TOO_LARGE',
              tooLargeMessage: '402 response body exceeds its byte ceiling',
              readErrorCode: 'RESPONSE_READ_FAILED',
              readErrorMessage: '402 response body could not be read',
            });
            const paymentRequired = decodeChallenge(
              rawHeader,
              snapshot.requestUrl,
              config.mode,
              limits.maximumPaymentHeaderBytes,
            );
            return Object.freeze({ kind: 'payment_required', paymentRequired });
          }
          const body = await readBodyBytes(
            response,
            bodyOptions(limits.maximumResponseBytes, signal),
          );
          return Object.freeze({ kind: 'response', status: response.status, body });
        },
      );
      state.phase = result.kind === 'payment_required' ? 'challenged' : 'complete';
      return result;
    } catch (error) {
      state.phase = 'failed';
      throw mapUnpaidFailure(error);
    }
  };

  const encodePayment = (paymentPayload) => {
    try {
      canonicalJson(paymentPayload);
    } catch (error) {
      fail('PAYMENT_PAYLOAD_SCHEMA', 'payment payload must be inert canonical data', error);
    }
    let encoded;
    try {
      encoded = encodePaymentSignatureHeader(paymentPayload);
    } catch (error) {
      fail('PAYMENT_PAYLOAD_SCHEMA', 'payment payload cannot be encoded', error);
    }
    const status = base64HeaderStatus(encoded, limits.maximumPaymentHeaderBytes);
    if (status === 'too_large') {
      fail('PAYMENT_SIGNATURE_TOO_LARGE', 'PAYMENT-SIGNATURE exceeds byte ceiling');
    }
    if (status !== 'canonical') {
      fail('PAYMENT_PAYLOAD_SCHEMA', 'official payment codec produced a noncanonical header');
    }
    return encoded;
  };

  const retryPaid = async (valueForRetry) => {
    const retry = closedRecord(
      valueForRetry,
      ['request', 'paymentHeader', 'binding'],
      [],
      'PAID_RETRY_SCHEMA',
      'paid retry request',
    );
    const state = retry.request && typeof retry.request === 'object'
      ? requests.get(retry.request)
      : undefined;
    if (!state) fail('REQUEST_NOT_PROBED', 'paid retry requires the exact probed request');
    if (state.phase === 'retrying' || state.phase === 'retried') {
      fail('REQUEST_ALREADY_RETRIED', 'paid retry already ran');
    }
    if (state.phase !== 'challenged') {
      fail('REQUEST_NOT_PROBED', 'paid retry requires a successful payment challenge');
    }
    if (base64HeaderStatus(
      retry.paymentHeader,
      limits.maximumPaymentHeaderBytes,
    ) !== 'canonical') {
      fail('PAYMENT_HEADER_SCHEMA', 'paid retry header must be bounded canonical base64');
    }
    const normalizedBinding = validateBinding(retry.binding);
    if (sha256(Buffer.from(retry.paymentHeader, 'ascii')) !== normalizedBinding.paymentHash) {
      fail('PAYMENT_HASH_MISMATCH', 'paid retry header differs from the persisted payment hash');
    }
    state.phase = 'retrying';
    let trustedSettlement = null;
    let status = null;
    try {
      const result = await withWallClockDeadline(
        boundaryOptions(limits.requestTimeoutMs, 'PAID_RESPONSE'),
        async (signal) => {
          const response = assertResponse(
            await fetchImpl(
              state.snapshot.requestUrl,
              fetchInit(state.snapshot, signal, retry.paymentHeader),
            ),
            'PAID_RESPONSE_SHAPE',
          );
          status = response.status;
          if (response.status === 402) {
            cancelResponseBody(response, new Error('second 402 retains the payment hold'));
            return ambiguous('SECOND_PAYMENT_REQUIRED');
          }
          const classified = decodeSettlementHeader(
            response,
            limits.maximumPaymentHeaderBytes,
            normalizedBinding,
          );
          if (classified.kind !== 'settled') {
            cancelResponseBody(response, new Error(classified.reasonCode));
            return classified;
          }
          trustedSettlement = classified.settlement;
          if (response.status < 200 || response.status > 299) {
            cancelResponseBody(response, new Error('settled non-2xx response'));
            return settledResult(
              trustedSettlement,
              response.status,
              null,
              'failed',
              'HTTP_STATUS_FAILURE',
            );
          }
          const body = await readBodyBytes(
            response,
            bodyOptions(limits.maximumResponseBytes, signal),
          );
          return settledResult(trustedSettlement, response.status, body, 'succeeded');
        },
      );
      state.phase = 'retried';
      return result;
    } catch (error) {
      state.phase = 'retried';
      return mapPaidFailure(error, trustedSettlement, status);
    }
  };

  return Object.freeze({ probe, encodePayment, retryPaid });
}

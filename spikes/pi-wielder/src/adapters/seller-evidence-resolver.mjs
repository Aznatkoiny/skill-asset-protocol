import { types as utilTypes } from 'node:util';

import { recoverMessageAddress } from 'viem';

import {
  canonicalAtomic,
  canonicalEvmHash,
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { validatePolicyDocument } from '../kernel/policy-engine.mjs';
import {
  cancelResponseBody,
  readBodyBytes,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from '../runtime-boundaries.mjs';

const MODES = new Set(['deterministic', 'cdp-testnet']);
const HASH = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const REASON = /^[A-Z][A-Z0-9_]{0,79}$/;
const SIGNATURE = /^0x[0-9a-f]{130}$/;
const ENCODED_PATH_SEPARATOR = /%(?:2f|5c)/i;
const MAX_TIMEOUT_MS = 5_000;
const MAX_RESPONSE_BYTES = 16_384;
const MAX_ATTESTATION_LIFETIME_MS = 15 * 60 * 1_000;

const UNKNOWN_REASONS = new Set([
  'SELLER_EVIDENCE_BINDING_INVALID',
  'SELLER_EVIDENCE_ENDPOINT_INVALID',
  'SELLER_EVIDENCE_FETCH_FAILED',
  'SELLER_EVIDENCE_TIMEOUT',
  'SELLER_EVIDENCE_REDIRECT',
  'SELLER_EVIDENCE_HTTP_STATUS',
  'SELLER_EVIDENCE_CONTENT_TYPE',
  'SELLER_EVIDENCE_TOO_LARGE',
  'SELLER_EVIDENCE_RESPONSE_INVALID',
  'SELLER_EVIDENCE_JSON_INVALID',
  'SELLER_EVIDENCE_ATTESTATION_INVALID',
  'SELLER_EVIDENCE_ATTESTATION_MISMATCH',
  'SELLER_EVIDENCE_TIME_INVALID',
  'SELLER_EVIDENCE_SIGNATURE_INVALID',
]);

const EXECUTION_BINDING_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'intentId',
  'intentHash',
  'policyVersion',
  'seller',
  'resourcePath',
  'network',
  'sellerOrigin',
  'transactionId',
  'executionSigner',
  'persistedHttpStatus',
  'persistedResponseHash',
  'resolutionReasonCode',
  'caseHash',
]);
const REFUND_BINDING_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'intentId',
  'intentHash',
  'policyVersion',
  'seller',
  'resourcePath',
  'network',
  'sellerOrigin',
  'originalTransactionId',
  'refundTransactionId',
  'asset',
  'originalPayer',
  'originalPayee',
  'refundSource',
  'refundSigner',
  'amountAtomic',
  'localRefundBindingHash',
  'refundId',
  'caseHash',
]);
const EXECUTION_ATTESTATION_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'network',
  'sellerOrigin',
  'intentHash',
  'transactionId',
  'outcome',
  'httpStatus',
  'responseHash',
  'issuedAt',
  'expiresAt',
  'signer',
  'signature',
]);
const REFUND_ATTESTATION_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'network',
  'sellerOrigin',
  'intentHash',
  'originalTransactionId',
  'refundTransactionId',
  'asset',
  'originalPayer',
  'originalPayee',
  'refundSource',
  'amountAtomic',
  'issuedAt',
  'expiresAt',
  'signer',
  'signature',
]);

class SellerEvidenceFault extends Error {
  constructor(reasonCode) {
    super('seller evidence is unavailable');
    this.name = 'SellerEvidenceFault';
    this.reasonCode = reasonCode;
  }
}

function fault(reasonCode) {
  if (!UNKNOWN_REASONS.has(reasonCode)) {
    throw new TypeError('seller evidence fault reason is not allowlisted');
  }
  throw new SellerEvidenceFault(reasonCode);
}

function configError() {
  throw new KernelError(
    'SELLER_EVIDENCE_CONFIG',
    'seller evidence resolver configuration is invalid',
  );
}

function closedShallowRecord(value, required) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return configError();
  }
  const keys = Reflect.ownKeys(value);
  const allowed = new Set(required);
  if (keys.length !== required.length
      || required.some((field) => !Object.hasOwn(value, field))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    return configError();
  }
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) return configError();
    result[key] = descriptor.value;
  }
  return result;
}

function positiveLimit(value, maximum) {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) return configError();
  return value;
}

function unknown(reasonCode) {
  if (!UNKNOWN_REASONS.has(reasonCode)) {
    throw new TypeError('unknown seller evidence reason is not allowlisted');
  }
  return Object.freeze({ kind: 'unknown', reasonCode });
}

function canonicalHash(value) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  return value;
}

function canonicalAddress(value) {
  if (typeof value !== 'string' || !ADDRESS.test(value)) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  return value;
}

function canonicalTransaction(value) {
  let normalized;
  try {
    normalized = canonicalEvmHash(value, 'transaction ID');
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (normalized !== value) fault('SELLER_EVIDENCE_BINDING_INVALID');
  return value;
}

function canonicalResourcePath(value, origin) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') > 2_048
      || !value.startsWith('/') || value.startsWith('//')
      || value.includes('?') || value.includes('#') || value.includes('\\')
      || ENCODED_PATH_SEPARATOR.test(value)) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  let parsed;
  try {
    parsed = new URL(value, `${origin}/`);
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (parsed.origin !== origin || parsed.pathname !== value
      || parsed.search !== '' || parsed.hash !== '') {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  return value;
}

function closedBinding(value, fields, label) {
  try {
    return exactRecord(value, fields, [], 'SELLER_EVIDENCE_BINDING_INVALID', label);
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
}

function policyAuthority(binding) {
  let version;
  try {
    version = exactRecord(
      binding.policyVersion,
      ['id', 'hash', 'policy'],
      [],
      'SELLER_EVIDENCE_BINDING_INVALID',
      'policy version',
    );
    canonicalToken(version.id, 'policy version ID');
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  canonicalHash(version.hash);

  let policy;
  let policyMatches;
  try {
    policy = validatePolicyDocument(version.policy);
    policyMatches = canonicalJson(version.policy) === canonicalJson(policy);
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (!policyMatches || sha256(canonicalJson(policy)) !== version.hash) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  canonicalResourcePath(binding.resourcePath, binding.sellerOrigin);
  const seller = policy.sellers.find((candidate) => (
    candidate.origin === binding.sellerOrigin
      && candidate.pathPrefixes.some((prefix) => binding.resourcePath.startsWith(prefix))
  ));
  if (!seller) fault('SELLER_EVIDENCE_BINDING_INVALID');
  let sellerMatches = false;
  try {
    sellerMatches = canonicalJson(seller) === canonicalJson(binding.seller);
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (!sellerMatches) fault('SELLER_EVIDENCE_BINDING_INVALID');
  return Object.freeze({ policy, seller });
}

function executionAuthority(value) {
  const binding = closedBinding(value, EXECUTION_BINDING_FIELDS, 'execution binding');
  const { policy, seller } = policyAuthority(binding);
  if (binding.schemaVersion !== 1
      || binding.domain !== 'wallet-kernel.execution-observation.v1'
      || binding.network !== policy.network
      || binding.sellerOrigin !== seller.origin
      || binding.executionSigner !== seller.executionSigner
      || typeof binding.resolutionReasonCode !== 'string'
      || !REASON.test(binding.resolutionReasonCode)) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  try {
    canonicalToken(binding.intentId, 'intent ID');
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  canonicalHash(binding.intentHash);
  canonicalTransaction(binding.transactionId);
  canonicalAddress(binding.executionSigner);
  canonicalHash(binding.caseHash);
  if (binding.persistedHttpStatus !== null
      && (!Number.isSafeInteger(binding.persistedHttpStatus)
        || binding.persistedHttpStatus < 100
        || binding.persistedHttpStatus > 599)) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (binding.persistedResponseHash !== null) canonicalHash(binding.persistedResponseHash);
  return Object.freeze({ binding, seller });
}

function refundBindingHash(binding) {
  return sha256(canonicalJson({
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-binding.v1',
    intentHash: binding.intentHash,
    originalTransactionId: binding.originalTransactionId,
    refundTransactionId: binding.refundTransactionId,
    network: binding.network,
    sellerOrigin: binding.sellerOrigin,
    asset: binding.asset,
    originalPayer: binding.originalPayer,
    originalPayee: binding.originalPayee,
    refundSource: binding.refundSource,
    refundSigner: binding.refundSigner,
    amountAtomic: binding.amountAtomic,
  }));
}

function refundAuthority(value) {
  const binding = closedBinding(value, REFUND_BINDING_FIELDS, 'refund binding');
  const { policy, seller } = policyAuthority(binding);
  if (binding.schemaVersion !== 1
      || binding.domain !== 'wallet-kernel.refund-observation.v1'
      || binding.network !== policy.network
      || binding.asset !== policy.asset
      || binding.sellerOrigin !== seller.origin
      || binding.originalPayer !== policy.wallet
      || binding.originalPayee !== seller.payTo
      || binding.refundSource !== seller.refundSource
      || binding.refundSigner !== seller.refundSigner) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  try {
    canonicalToken(binding.intentId, 'intent ID');
    canonicalToken(binding.refundId, 'refund ID');
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  canonicalHash(binding.intentHash);
  canonicalTransaction(binding.originalTransactionId);
  canonicalTransaction(binding.refundTransactionId);
  canonicalAddress(binding.originalPayer);
  canonicalAddress(binding.originalPayee);
  canonicalAddress(binding.refundSource);
  canonicalAddress(binding.refundSigner);
  let amount;
  try {
    amount = canonicalAtomic(binding.amountAtomic, 'refund amount');
  } catch {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  if (amount.value < 1n
      || amount.value > canonicalAtomic(seller.perRequestMaxAtomic, 'seller limit').value) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  canonicalHash(binding.localRefundBindingHash);
  canonicalHash(binding.caseHash);
  if (refundBindingHash(binding) !== binding.localRefundBindingHash) {
    fault('SELLER_EVIDENCE_BINDING_INVALID');
  }
  return Object.freeze({ binding, seller });
}

function literalLoopbackHttp(origin, parsed) {
  if (parsed.protocol !== 'http:' || !origin.startsWith('http://')) return false;
  const authority = origin.slice('http://'.length);
  return /^(?:127\.0\.0\.1|\[::1\])(?::[1-9][0-9]{0,4})?$/.test(authority)
    && parsed.origin === origin;
}

function endpointFor(seller, mode) {
  let origin;
  try {
    origin = new URL(seller.origin);
  } catch {
    fault('SELLER_EVIDENCE_ENDPOINT_INVALID');
  }
  if (origin.origin !== seller.origin || origin.username !== '' || origin.password !== ''
      || origin.pathname !== '/' || origin.search !== '' || origin.hash !== ''
      || (mode === 'cdp-testnet' && origin.protocol !== 'https:')
      || (mode === 'deterministic' && origin.protocol !== 'https:'
        && !literalLoopbackHttp(seller.origin, origin))) {
    fault('SELLER_EVIDENCE_ENDPOINT_INVALID');
  }
  let endpoint;
  try {
    endpoint = new URL(seller.evidencePath, `${seller.origin}/`);
  } catch {
    fault('SELLER_EVIDENCE_ENDPOINT_INVALID');
  }
  const expected = `${seller.origin}${seller.evidencePath}`;
  if (endpoint.href !== expected || endpoint.origin !== seller.origin
      || endpoint.pathname !== seller.evidencePath
      || endpoint.search !== '' || endpoint.hash !== '') {
    fault('SELLER_EVIDENCE_ENDPOINT_INVALID');
  }
  return expected;
}

function closedAttestation(value, fields, label) {
  try {
    return exactRecord(
      value,
      fields,
      [],
      'SELLER_EVIDENCE_ATTESTATION_INVALID',
      label,
    );
  } catch {
    fault('SELLER_EVIDENCE_ATTESTATION_INVALID');
  }
}

function validateWindow(attestation, now) {
  let issuedAt;
  let expiresAt;
  let observedAt;
  try {
    issuedAt = canonicalTimestamp(attestation.issuedAt, 'attestation issuedAt');
    expiresAt = canonicalTimestamp(attestation.expiresAt, 'attestation expiresAt');
    observedAt = canonicalTimestamp(now(), 'attestation observation time');
  } catch {
    fault('SELLER_EVIDENCE_TIME_INVALID');
  }
  if (Date.parse(expiresAt) <= Date.parse(issuedAt)
      || Date.parse(expiresAt) - Date.parse(issuedAt) > MAX_ATTESTATION_LIFETIME_MS
      || Date.parse(observedAt) < Date.parse(issuedAt)
      || Date.parse(observedAt) >= Date.parse(expiresAt)) {
    fault('SELLER_EVIDENCE_TIME_INVALID');
  }
}

async function verifySignature(attestation, policySigner) {
  if (typeof attestation.signer !== 'string' || !ADDRESS.test(attestation.signer)
      || attestation.signer !== policySigner
      || typeof attestation.signature !== 'string'
      || !SIGNATURE.test(attestation.signature)) {
    fault('SELLER_EVIDENCE_SIGNATURE_INVALID');
  }
  const { signature, ...unsigned } = attestation;
  let recovered;
  try {
    recovered = await recoverMessageAddress({
      message: { raw: Buffer.from(canonicalJson(unsigned), 'utf8') },
      signature,
    });
  } catch {
    fault('SELLER_EVIDENCE_SIGNATURE_INVALID');
  }
  if (recovered.toLowerCase() !== policySigner) {
    fault('SELLER_EVIDENCE_SIGNATURE_INVALID');
  }
  return frozenCopy(unsigned);
}

function canonicalAttestationHash(value) {
  if (value !== null && (typeof value !== 'string' || !HASH.test(value))) {
    fault('SELLER_EVIDENCE_ATTESTATION_INVALID');
  }
  return value;
}

async function executionAttestation(value, binding, now) {
  const attestation = closedAttestation(
    value,
    EXECUTION_ATTESTATION_FIELDS,
    'execution attestation',
  );
  if (attestation.schemaVersion !== 1) fault('SELLER_EVIDENCE_ATTESTATION_INVALID');
  if (attestation.domain !== 'wallet-kernel.execution.v1'
      || attestation.network !== binding.network
      || attestation.sellerOrigin !== binding.sellerOrigin
      || attestation.intentHash !== binding.intentHash
      || attestation.transactionId !== binding.transactionId) {
    fault('SELLER_EVIDENCE_ATTESTATION_MISMATCH');
  }
  if (!new Set(['succeeded', 'failed']).has(attestation.outcome)
      || !Number.isSafeInteger(attestation.httpStatus)
      || attestation.httpStatus < 100 || attestation.httpStatus > 599
      || (attestation.outcome === 'succeeded'
        && (attestation.httpStatus < 200 || attestation.httpStatus > 299))
      || (attestation.outcome === 'failed' && attestation.httpStatus < 400)) {
    fault('SELLER_EVIDENCE_ATTESTATION_INVALID');
  }
  canonicalAttestationHash(attestation.responseHash);
  if ((binding.persistedHttpStatus !== null
        && attestation.httpStatus !== binding.persistedHttpStatus)
      || (binding.persistedResponseHash !== null
        && attestation.responseHash !== binding.persistedResponseHash)) {
    fault('SELLER_EVIDENCE_ATTESTATION_MISMATCH');
  }
  validateWindow(attestation, now);
  return await verifySignature(attestation, binding.executionSigner);
}

async function refundAttestation(value, binding, now) {
  const attestation = closedAttestation(
    value,
    REFUND_ATTESTATION_FIELDS,
    'refund attestation',
  );
  if (attestation.schemaVersion !== 1) fault('SELLER_EVIDENCE_ATTESTATION_INVALID');
  if (attestation.domain !== 'wallet-kernel.refund.v1'
      || attestation.network !== binding.network
      || attestation.sellerOrigin !== binding.sellerOrigin
      || attestation.intentHash !== binding.intentHash
      || attestation.originalTransactionId !== binding.originalTransactionId
      || attestation.refundTransactionId !== binding.refundTransactionId
      || attestation.asset !== binding.asset
      || attestation.originalPayer !== binding.originalPayer
      || attestation.originalPayee !== binding.originalPayee
      || attestation.refundSource !== binding.refundSource
      || attestation.amountAtomic !== binding.amountAtomic) {
    fault('SELLER_EVIDENCE_ATTESTATION_MISMATCH');
  }
  validateWindow(attestation, now);
  return await verifySignature(attestation, binding.refundSigner);
}

function validateResponseSurface(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Response.prototype
      || Reflect.ownKeys(value).length !== 0) {
    fault('SELLER_EVIDENCE_RESPONSE_INVALID');
  }
  if (value.redirected || (value.status >= 300 && value.status <= 399)) {
    cancelResponseBody(value, new Error('seller evidence redirect rejected'));
    fault('SELLER_EVIDENCE_REDIRECT');
  }
  if (value.status !== 200) {
    cancelResponseBody(value, new Error('seller evidence HTTP status rejected'));
    fault('SELLER_EVIDENCE_HTTP_STATUS');
  }
  const contentType = value.headers.get('content-type')?.toLowerCase();
  if (contentType !== 'application/json'
      && contentType !== 'application/json; charset=utf-8') {
    cancelResponseBody(value, new Error('seller evidence content type rejected'));
    fault('SELLER_EVIDENCE_CONTENT_TYPE');
  }
  return value;
}

function parseJson(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    fault('SELLER_EVIDENCE_JSON_INVALID');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fault('SELLER_EVIDENCE_JSON_INVALID');
  }
  try {
    return JSON.parse(text);
  } catch {
    fault('SELLER_EVIDENCE_JSON_INVALID');
  }
}

function mapBoundaryError(error) {
  if (error instanceof SellerEvidenceFault) return unknown(error.reasonCode);
  if (error instanceof RuntimeBoundaryError) {
    if (error.code === 'SELLER_EVIDENCE_TIMEOUT') {
      return unknown('SELLER_EVIDENCE_TIMEOUT');
    }
    if (error.code === 'SELLER_EVIDENCE_TOO_LARGE') {
      return unknown('SELLER_EVIDENCE_TOO_LARGE');
    }
    if (error.code === 'SELLER_EVIDENCE_RESPONSE_INVALID') {
      return unknown('SELLER_EVIDENCE_RESPONSE_INVALID');
    }
  }
  return unknown('SELLER_EVIDENCE_FETCH_FAILED');
}

export function createSellerEvidenceResolver(value) {
  const config = closedShallowRecord(value, ['fetchImpl', 'mode', 'now', 'limits']);
  if (typeof config.fetchImpl !== 'function' || utilTypes.isProxy(config.fetchImpl)
      || typeof config.now !== 'function' || utilTypes.isProxy(config.now)
      || !MODES.has(config.mode)) {
    return configError();
  }
  const rawLimits = closedShallowRecord(
    config.limits,
    ['requestTimeoutMs', 'maximumResponseBytes'],
  );
  const limits = Object.freeze({
    requestTimeoutMs: positiveLimit(rawLimits.requestTimeoutMs, MAX_TIMEOUT_MS),
    maximumResponseBytes: positiveLimit(rawLimits.maximumResponseBytes, MAX_RESPONSE_BYTES),
  });
  const fetchImpl = config.fetchImpl;
  const mode = config.mode;
  const now = config.now;

  const request = async ({ authority, kind, body, endpoint }) => {
    try {
      return await withWallClockDeadline({
        timeoutMs: limits.requestTimeoutMs,
        timeoutCode: 'SELLER_EVIDENCE_TIMEOUT',
        timeoutMessage: 'seller evidence request timed out',
        abortedCode: 'SELLER_EVIDENCE_TIMEOUT',
        abortedMessage: 'seller evidence request was aborted',
      }, async (signal) => {
        let response;
        try {
          response = await fetchImpl(endpoint, {
            method: 'POST',
            redirect: 'manual',
            credentials: 'omit',
            cache: 'no-store',
            referrerPolicy: 'no-referrer',
            signal,
            headers: {
              accept: 'application/json',
              'content-type': 'application/json',
            },
            body: canonicalJson(body),
          });
        } catch {
          if (signal.aborted) fault('SELLER_EVIDENCE_TIMEOUT');
          fault('SELLER_EVIDENCE_FETCH_FAILED');
        }
        validateResponseSurface(response);
        const bytes = await readBodyBytes(response, {
          maxBytes: limits.maximumResponseBytes,
          tooLargeCode: 'SELLER_EVIDENCE_TOO_LARGE',
          tooLargeMessage: 'seller evidence response is too large',
          readErrorCode: 'SELLER_EVIDENCE_RESPONSE_INVALID',
          readErrorMessage: 'seller evidence response body is invalid',
          signal,
        });
        const parsed = parseJson(bytes);
        const attestation = kind === 'execution'
          ? await executionAttestation(parsed, authority.binding, now)
          : await refundAttestation(parsed, authority.binding, now);
        return frozenCopy({
          kind: kind === 'execution' ? 'execution_attested' : 'refund_attested',
          attestation,
          attestationHash: sha256(canonicalJson(attestation)),
        });
      });
    } catch (error) {
      return mapBoundaryError(error);
    }
  };

  return Object.freeze({
    async observeExecution(persistedBinding) {
      let authority;
      let endpoint;
      try {
        authority = executionAuthority(persistedBinding);
        endpoint = endpointFor(authority.seller, mode);
      } catch (error) {
        if (error instanceof SellerEvidenceFault) return unknown(error.reasonCode);
        return unknown('SELLER_EVIDENCE_BINDING_INVALID');
      }
      return await request({
        authority,
        endpoint,
        kind: 'execution',
        body: {
          schemaVersion: 1,
          kind: 'execution',
          sellerOrigin: authority.binding.sellerOrigin,
          intentHash: authority.binding.intentHash,
          transactionId: authority.binding.transactionId,
        },
      });
    },
    async observeRefund(persistedBinding) {
      let authority;
      let endpoint;
      try {
        authority = refundAuthority(persistedBinding);
        endpoint = endpointFor(authority.seller, mode);
      } catch (error) {
        if (error instanceof SellerEvidenceFault) return unknown(error.reasonCode);
        return unknown('SELLER_EVIDENCE_BINDING_INVALID');
      }
      return await request({
        authority,
        endpoint,
        kind: 'refund',
        body: {
          schemaVersion: 1,
          kind: 'refund',
          sellerOrigin: authority.binding.sellerOrigin,
          intentHash: authority.binding.intentHash,
          originalTransactionId: authority.binding.originalTransactionId,
          refundTransactionId: authority.binding.refundTransactionId,
        },
      });
    },
  });
}

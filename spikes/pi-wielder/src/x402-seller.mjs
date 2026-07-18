// Seller-side x402 v1 boundary for the offline/testnet spike.
//
// A client-generated Idempotency-Key binds method, resource URL, and exact body
// bytes to one frozen PaymentRequirements envelope. The Collar persists that
// envelope and owns payment/execution lifecycle state; this middleware never
// rebuilds an offer after restart and never treats a quote as authorization.

import crypto from 'node:crypto';

import { formatUsdc, parseUsdc } from '../../../prototype/atomic-money.mjs';
import {
  cancelResponseBody,
  readBodyBytes,
  readJsonBody,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from './runtime-boundaries.mjs';

export const X402_VERSION = 1;
export const NETWORK = 'base-sepolia';
export const CHAIN_ID = 84532;
export const USDC_ADDRESS = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
export const USDC_EIP712 = Object.freeze({ name: 'USDC', version: '2' });
export const APPROVED_LIVE_FACILITATOR_BASE = 'https://x402.org/facilitator';
export const DEFAULT_X402_REQUEST_BODY_BYTES = 4096;
// The generic x402 default stays at the Collar's 4 KiB contract. The fixed
// model-gateway route is the only current consumer of the larger hard ceiling.
export const MAX_X402_REQUEST_BODY_BYTES = 1024 * 1024;
export const DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS = 5_000;
export const DEFAULT_FACILITATOR_TIMEOUT_MS = 10_000;
export const DEFAULT_FACILITATOR_RESPONSE_BYTES = 64 * 1024;
export const MAX_IDEMPOTENCY_KEY_CHARACTERS = 128;
export const DEFAULT_PENDING_OFFER_LIMIT = 128;
export const DEFAULT_PENDING_OFFER_TTL_MS = 60_000;

export const usdcToAtomic = (display) => parseUsdc(display).toString();
export const atomicToUsdc = (atomic) => formatUsdc(BigInt(atomic));

const b64ToJson = (value) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error('payment header is not canonical base64');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) throw new Error('payment header is not canonical base64');
  return JSON.parse(bytes.toString('utf8'));
};
const jsonToB64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64');
const authorizedTransports = new WeakSet();

function authorizeTransport(transport) {
  const frozen = Object.freeze(transport);
  authorizedTransports.add(frozen);
  return frozen;
}

export function createMockFacilitatorTransport(fetchImpl) {
  if (typeof fetchImpl !== 'function') throw new TypeError('mock facilitator requires an injected fetch/app');
  return authorizeTransport({
    mode: 'mock',
    baseUrl: 'http://facilitator.invalid',
    fetchImpl,
  });
}

export function createLiveFacilitatorTransport(rawBaseUrl, fetchImpl = fetch) {
  if (rawBaseUrl !== APPROVED_LIVE_FACILITATOR_BASE) {
    const error = new Error('live facilitator is not the pinned approved endpoint');
    error.code = 'FACILITATOR_NOT_APPROVED';
    throw error;
  }
  const parsed = new URL(rawBaseUrl);
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password
      || parsed.port || parsed.search || parsed.hash || parsed.pathname !== '/facilitator') {
    const error = new Error('live facilitator endpoint violates the approved HTTPS contract');
    error.code = 'FACILITATOR_NOT_APPROVED';
    throw error;
  }
  if (typeof fetchImpl !== 'function') throw new TypeError('live facilitator requires fetch');
  return authorizeTransport({ mode: 'live', baseUrl: rawBaseUrl, fetchImpl });
}

function requireFacilitatorTransport(transport) {
  if (!transport || !authorizedTransports.has(transport)) {
    throw new Error('facilitatorTransport must come from an approved live or injected-mock constructor');
  }
  return transport;
}

function canonicalAddress(value) {
  const text = String(value ?? '');
  if (!/^0x[0-9a-fA-F]{40}$/.test(text)) throw new Error('payTo must be a 20-byte hex address');
  return text.toLowerCase();
}

function validTxHash(value) {
  return /^0x[0-9a-fA-F]{64}$/.test(String(value ?? ''));
}

function exactPlainObject(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length
    && actual.every((key, index) => key === expected[index]);
}

function positiveLimit(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }
  return value;
}

function cappedLimit(value, label, ceiling) {
  positiveLimit(value, label);
  if (value > ceiling) throw new TypeError(`${label} cannot exceed ${ceiling}`);
  return value;
}

const X402_BODY_TEXT_KEY = 'x402RequestBodyText';
const X402_BODY_BYTES_KEY = 'x402RequestBodyBytes';

export function x402RequestBodyText(c) {
  const value = c.get(X402_BODY_TEXT_KEY);
  if (typeof value !== 'string') throw new Error('x402 request body was not captured');
  return value;
}

export function x402RequestBodyBytes(c) {
  const value = c.get(X402_BODY_BYTES_KEY);
  if (!(value instanceof Uint8Array)) throw new Error('x402 request body was not captured');
  return Buffer.from(value);
}

function terminalReplayIsTrusted(decision, payer) {
  return decision?.kind === 'terminal'
    && ['settled', 'refunded'].includes(decision.paymentState)
    && validTxHash(decision.txHash)
    && String(decision.payer ?? '').toLowerCase() === String(payer).toLowerCase()
    && decision.receipt
    && Number.isSafeInteger(decision.httpStatus)
    && decision.httpStatus >= 100
    && decision.httpStatus <= 599;
}

function paymentResponseEvidence({
  idempotencyKey,
  requirements,
  payer,
  settlementReference,
  transaction,
}) {
  return {
    success: true,
    authorizationId: idempotencyKey,
    idempotencyKey,
    network: NETWORK,
    chainId: CHAIN_ID,
    asset: requirements.asset,
    payTo: requirements.payTo,
    payer: String(payer).toLowerCase(),
    value: requirements.maxAmountRequired,
    nonce: settlementReference,
    settlementReference,
    requestHash: requirements.extra.requestHash,
    quoteId: requirements.extra.quoteId,
    transaction: String(transaction).toLowerCase(),
  };
}

function validateAuthorizationEnvelope(paymentPayload, requirements) {
  if (!exactPlainObject(paymentPayload, ['x402Version', 'scheme', 'network', 'payload'])
      || !exactPlainObject(paymentPayload.payload, ['signature', 'authorization'])
      || paymentPayload?.x402Version !== X402_VERSION
      || paymentPayload?.scheme !== requirements.scheme
      || paymentPayload?.network !== requirements.network) {
    throw new Error('payment envelope does not exactly match the frozen x402 offer');
  }
  const authorization = paymentPayload?.payload?.authorization;
  const signature = paymentPayload?.payload?.signature;
  if (!exactPlainObject(authorization, [
    'from', 'to', 'value', 'validAfter', 'validBefore', 'nonce',
  ]) || typeof signature !== 'string' || !/^0x[0-9a-f]{130}$/.test(signature)) {
    throw new Error('payment authorization lacks authorization or signature');
  }
  if (!/^0x[0-9a-f]{40}$/.test(authorization.from)
      || !/^0x[0-9a-f]{40}$/.test(authorization.to)
      || typeof authorization.value !== 'string'
      || !/^(0|[1-9]\d*)$/.test(authorization.value)
      || typeof authorization.validAfter !== 'string'
      || !/^(0|[1-9]\d*)$/.test(authorization.validAfter)
      || typeof authorization.validBefore !== 'string'
      || !/^(0|[1-9]\d*)$/.test(authorization.validBefore)
      || authorization.to !== requirements.payTo
      || authorization.value !== requirements.maxAmountRequired) {
    throw new Error('payment authorization must exactly match payee and quoted amount');
  }
  if (!/^0x[0-9a-f]{64}$/.test(authorization.nonce)) {
    throw new Error('payment authorization lacks a valid nonce or payer');
  }
  return authorization;
}

export function x402Paywall({
  price,
  payTo,
  facilitatorTransport,
  description = '',
  lifecycle = {},
  quote = null,
  maxRequestBodyBytes = DEFAULT_X402_REQUEST_BODY_BYTES,
  requestBodyTimeoutMs = DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS,
  facilitatorTimeoutMs = DEFAULT_FACILITATOR_TIMEOUT_MS,
  facilitatorResponseMaxBytes = DEFAULT_FACILITATOR_RESPONSE_BYTES,
  maxPendingOffers = DEFAULT_PENDING_OFFER_LIMIT,
  pendingOfferTtlMs = DEFAULT_PENDING_OFFER_TTL_MS,
  now = Date.now,
}) {
  const transport = requireFacilitatorTransport(facilitatorTransport);
  const canonicalPayTo = canonicalAddress(payTo);
  if (quote !== null && typeof quote !== 'function') {
    throw new TypeError('quote must be an injected function or null');
  }
  cappedLimit(maxRequestBodyBytes, 'maxRequestBodyBytes', MAX_X402_REQUEST_BODY_BYTES);
  cappedLimit(requestBodyTimeoutMs, 'requestBodyTimeoutMs', DEFAULT_X402_REQUEST_BODY_TIMEOUT_MS);
  cappedLimit(facilitatorTimeoutMs, 'facilitatorTimeoutMs', DEFAULT_FACILITATOR_TIMEOUT_MS);
  cappedLimit(
    facilitatorResponseMaxBytes,
    'facilitatorResponseMaxBytes',
    DEFAULT_FACILITATOR_RESPONSE_BYTES,
  );
  cappedLimit(maxPendingOffers, 'maxPendingOffers', DEFAULT_PENDING_OFFER_LIMIT);
  cappedLimit(pendingOfferTtlMs, 'pendingOfferTtlMs', DEFAULT_PENDING_OFFER_TTL_MS);
  if (typeof now !== 'function') throw new TypeError('now must be a trusted clock function');
  const pendingOffers = new Map();
  const authorizationClaims = new Map();
  const authorizationClaimByIdempotencyKey = new Map();
  const locallyUnresolvedSettlements = new Set();
  const transientAdmissions = new Set();

  const activeKeyCount = () => new Set([
    ...pendingOffers.keys(),
    ...authorizationClaimByIdempotencyKey.keys(),
    ...locallyUnresolvedSettlements,
    ...transientAdmissions,
  ]).size;

  const releaseAuthorizationClaim = (authorizationIdentity, claim) => {
    if (authorizationClaims.get(authorizationIdentity) === claim) {
      authorizationClaims.delete(authorizationIdentity);
    }
    if (authorizationClaimByIdempotencyKey.get(claim.idempotencyKey)
        === authorizationIdentity) {
      authorizationClaimByIdempotencyKey.delete(claim.idempotencyKey);
    }
  };

  const claimForIdempotencyKey = (idempotencyKey) => {
    const authorizationIdentity = authorizationClaimByIdempotencyKey.get(idempotencyKey);
    if (!authorizationIdentity) return null;
    const claim = authorizationClaims.get(authorizationIdentity);
    return claim ? { authorizationIdentity, claim } : null;
  };

  const reserveTransientAdmission = (idempotencyKey) => {
    if (transientAdmissions.has(idempotencyKey)) return false;
    const alreadyTracked = pendingOffers.has(idempotencyKey)
      || authorizationClaimByIdempotencyKey.has(idempotencyKey)
      || locallyUnresolvedSettlements.has(idempotencyKey);
    if (!alreadyTracked && activeKeyCount() >= maxPendingOffers) return false;
    transientAdmissions.add(idempotencyKey);
    return true;
  };

  return async (c, next) => {
    const notifyUnresolved = async (payload) => {
      try {
        await lifecycle.onUnresolved?.(payload);
      } catch {
        // A settlement append can win and then report a lease-release error.
        // The next retry re-reads authority through onSigned; never turn this
        // ambiguity into a second settlement attempt or an unstructured 500.
      }
    };
    const idempotencyKey = c.req.header('Idempotency-Key');
    if (!idempotencyKey) return c.json({ error: 'Idempotency-Key header is required' }, 400);
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(idempotencyKey)) {
      return c.json({
        error: `Idempotency-Key must be 1-${MAX_IDEMPOTENCY_KEY_CHARACTERS} canonical ASCII characters`,
        code: 'IDEMPOTENCY_KEY_INVALID',
      }, 400);
    }
    const requestNowMs = now();
    if (!Number.isSafeInteger(requestNowMs) || requestNowMs < 0) {
      return c.json({ error: 'trusted offer clock returned an invalid time' }, 503);
    }
    for (const [key, offer] of pendingOffers) {
      if (offer.expiresAtMs <= requestNowMs) pendingOffers.delete(key);
    }
    for (const [authorizationIdentity, claim] of authorizationClaims) {
      if (claim.state === 'consumed' && claim.expiresAtMs <= requestNowMs) {
        releaseAuthorizationClaim(authorizationIdentity, claim);
      }
    }
    const paymentHeader = c.req.header('X-PAYMENT');
    let requestBodyBytes;
    try {
      requestBodyBytes = await withWallClockDeadline({
        signal: c.req.raw.signal,
        timeoutMs: requestBodyTimeoutMs,
        timeoutCode: 'REQUEST_BODY_TIMEOUT',
        timeoutMessage: 'x402 request body timed out',
        abortedCode: 'REQUEST_BODY_ABORTED',
        abortedMessage: 'x402 request body was aborted',
      }, (signal) => readBodyBytes(c.req.raw, {
        maxBytes: maxRequestBodyBytes,
        tooLargeCode: 'REQUEST_BODY_TOO_LARGE',
        tooLargeMessage: `request body exceeds the ${maxRequestBodyBytes}-byte x402 limit`,
        readErrorCode: 'REQUEST_BODY_READ_FAILED',
        readErrorMessage: 'x402 request body could not be read',
        signal,
      }));
    } catch (error) {
      const code = error instanceof RuntimeBoundaryError ? error.code : 'REQUEST_BODY_READ_FAILED';
      const status = code === 'REQUEST_BODY_TOO_LARGE' ? 413
        : code === 'REQUEST_BODY_TIMEOUT' ? 408
        : 400;
      const message = error instanceof RuntimeBoundaryError
        ? error.message
        : 'x402 request body could not be read';
      return c.json({ error: message, code }, status);
    }
    const requestBody = requestBodyBytes.toString('utf8');
    c.set(X402_BODY_BYTES_KEY, Buffer.from(requestBodyBytes));
    c.set(X402_BODY_TEXT_KEY, requestBody);
    const requestHash = `sha256:${crypto.createHash('sha256')
      .update(Buffer.from(`${c.req.method}\n${c.req.url}\n`, 'utf8'))
      .update(requestBodyBytes)
      .digest('hex')}`;

    let transientAdmission = false;
    let activeAuthorizationClaim = null;
    const capacityResponse = () => {
      const response = c.json({
        error: 'pending x402 offer capacity is exhausted',
        code: 'PENDING_OFFER_CAPACITY',
      }, 503);
      response.headers.set('Retry-After', '1');
      return response;
    };
    const unresolvedResponse = (settlementReference = null) => c.json({
      error: 'payment settlement unresolved; trusted reconciliation is required',
      settlementReference,
    }, 503);

    try {

    let frozen = pendingOffers.get(idempotencyKey) ?? null;
    if (!frozen) {
      let recovered = null;
      try {
        recovered = await lifecycle.loadFrozenOffer?.({
          idempotencyKey,
          paymentHeaderPresent: Boolean(paymentHeader),
        });
      } catch {
        return c.json({ error: 'frozen offer recovery conflicts with authoritative state' }, 409);
      }
      if (recovered) {
        if (!exactPlainObject(recovered, [
          'requirements', 'executionQuote', 'verificationRequired', 'verifiedPaymentHash',
        ]) || typeof recovered.verificationRequired !== 'boolean'
          || (recovered.verifiedPaymentHash !== null
            && !/^sha256:[0-9a-f]{64}$/.test(recovered.verifiedPaymentHash))
          || recovered.verificationRequired !== (recovered.verifiedPaymentHash === null)) {
          return c.json({ error: 'persisted frozen offer has an unsupported schema' }, 409);
        }
        frozen = structuredClone(recovered);
      }
    }
    if (frozen && (paymentHeader || !pendingOffers.has(idempotencyKey))) {
      if (!reserveTransientAdmission(idempotencyKey)) return capacityResponse();
      transientAdmission = true;
    }
    let requirements = frozen?.requirements ?? null;
    let executionQuote = frozen?.executionQuote ?? null;
    if (requirements) {
      if (requirements.extra?.requestHash !== requestHash) {
        return c.json({ error: 'Idempotency-Key already binds a different request' }, 409);
      }
    } else {
      if (locallyUnresolvedSettlements.has(idempotencyKey)) return unresolvedResponse();
      if (paymentHeader) return c.json({ error: 'paid retry has no prior frozen x402 offer' }, 409);
      const outstandingAuthorization = claimForIdempotencyKey(idempotencyKey);
      if (outstandingAuthorization) {
        if (outstandingAuthorization.claim.state === 'consumed') {
          return c.json({
            error: 'payment authorization was already consumed; response replay is unavailable',
            code: 'PAYMENT_AUTHORIZATION_CONSUMED',
          }, 409);
        }
        return unresolvedResponse();
      }
      if (!reserveTransientAdmission(idempotencyKey)) return capacityResponse();
      transientAdmission = true;
      try {
        executionQuote = quote ? structuredClone(await quote(c)) : null;
      } catch (error) {
        const code = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,63}$/.test(error.code)
          ? error.code
          : 'QUOTE_REJECTED';
        const status = code === 'REQUEST_BODY_TOO_LARGE' ? 413 : 400;
        const message = error?.name === 'ExecutionEconomicsError'
          ? error.message
          : 'execution quote rejected';
        return c.json({ error: message, code }, status);
      }
      if (executionQuote !== null
          && (!exactPlainObject(executionQuote, Object.keys(executionQuote))
            || executionQuote.schemaVersion !== 2
            || typeof executionQuote.quoteId !== 'string'
            || !/^sha256:[0-9a-f]{64}$/.test(executionQuote.quoteId)
            || typeof executionQuote.grossAtomic !== 'string'
            || !/^[1-9]\d*$/.test(executionQuote.grossAtomic))) {
        return c.json({ error: 'execution quote rejected', code: 'QUOTE_SCHEMA' }, 400);
      }
      const priceUsdc = executionQuote == null
        ? (typeof price === 'function' ? await price(c) : price)
        : null;
      const amountAtomic = executionQuote == null
        ? usdcToAtomic(priceUsdc)
        : executionQuote.grossAtomic;
      const issuedAt = new Date(requestNowMs).toISOString();
      const expiresAtMs = requestNowMs + pendingOfferTtlMs;
      const expiresAt = new Date(expiresAtMs).toISOString();
      const base = {
        scheme: 'exact',
        network: NETWORK,
        maxAmountRequired: amountAtomic,
        resource: c.req.url,
        description,
        mimeType: 'application/json',
        payTo: canonicalPayTo,
        maxTimeoutSeconds: 60,
        asset: USDC_ADDRESS,
      };
      const quoteId = executionQuote?.quoteId ?? `sha256:${crypto.createHash('sha256')
        .update(JSON.stringify({ ...base, requestHash, issuedAt, expiresAt }))
        .digest('hex')}`;
      requirements = {
        ...base,
        extra: {
          name: USDC_EIP712.name,
          version: USDC_EIP712.version,
          requestHash,
          quoteId,
          issuedAt,
          expiresAt,
        },
      };
      frozen = {
        requirements,
        executionQuote,
        expiresAtMs,
        verificationRequired: true,
        verifiedPaymentHash: null,
      };
      pendingOffers.set(idempotencyKey, structuredClone(frozen));
    }

    if (!paymentHeader) {
      if (locallyUnresolvedSettlements.has(idempotencyKey)) return unresolvedResponse();
      try {
        await lifecycle.onOffered?.({
          idempotencyKey,
          requirements: structuredClone(requirements),
          expiresAt: requirements.extra.expiresAt,
          executionQuote: structuredClone(executionQuote),
        });
      } catch {
        return c.json({ error: 'Invocation offer conflicts with authoritative state' }, 409);
      }
      return c.json({
        x402Version: X402_VERSION,
        error: 'X-PAYMENT header is required',
        accepts: [requirements],
      }, 402);
    }

    let paymentPayload;
    try {
      paymentPayload = b64ToJson(paymentHeader);
    } catch {
      return c.json({
        x402Version: X402_VERSION,
        error: 'malformed X-PAYMENT header',
        accepts: [requirements],
      }, 402);
    }

    let authorization;
    try {
      authorization = validateAuthorizationEnvelope(paymentPayload, requirements);
    } catch (error) {
      return c.json({
        x402Version: X402_VERSION,
        error: error.message,
        accepts: [requirements],
      }, 402);
    }
    const settlementReference = authorization.nonce.toLowerCase();
    const payer = authorization.from.toLowerCase();
    const paymentHash = `sha256:${crypto.createHash('sha256').update(paymentHeader).digest('hex')}`;
    const facilitatorBody = {
      x402Version: X402_VERSION,
      paymentPayload,
      paymentRequirements: requirements,
    };
    let facilitatorStarted = null;
    if (frozen.verifiedPaymentHash !== null && frozen.verifiedPaymentHash !== paymentHash) {
      return c.json({
        error: 'paid retry does not match the facilitator-verified payment authorization',
        code: 'VERIFIED_PAYMENT_MISMATCH',
      }, 409);
    }
    const authorizationIdentity = [
      NETWORK, USDC_ADDRESS, payer, settlementReference,
    ].join(':');
    const ownerAuthorizationIdentity = authorizationClaimByIdempotencyKey.get(idempotencyKey);
    let authorizationClaim = authorizationClaims.get(authorizationIdentity) ?? null;
    if (authorizationClaim && authorizationClaim.idempotencyKey !== idempotencyKey) {
      return c.json({
        error: 'payment authorization is already claimed by a different Idempotency-Key',
        code: 'PAYMENT_AUTHORIZATION_CLAIMED',
      }, 409);
    }
    if ((ownerAuthorizationIdentity && ownerAuthorizationIdentity !== authorizationIdentity)
        || (authorizationClaim && authorizationClaim.paymentHash !== paymentHash)) {
      return c.json({
        error: 'Idempotency-Key already binds a different payment authorization',
        code: 'PAYMENT_AUTHORIZATION_MISMATCH',
      }, 409);
    }
    if (authorizationClaim?.state === 'consumed' && !authorizationClaim.authoritative) {
      return c.json({
        error: 'payment authorization was already consumed; response replay is unavailable',
        code: 'PAYMENT_AUTHORIZATION_CONSUMED',
      }, 409);
    }
    if (!authorizationClaim) {
      authorizationClaim = {
        idempotencyKey,
        paymentHash,
        state: 'processing',
        phase: 'verification',
        authoritative: false,
        expiresAtMs: null,
      };
      // Both indexes are populated synchronously before the first facilitator
      // await. One authorization cannot race under another key, and one key
      // cannot accumulate many ambiguous authorization identities.
      authorizationClaims.set(authorizationIdentity, authorizationClaim);
      authorizationClaimByIdempotencyKey.set(idempotencyKey, authorizationIdentity);
      activeAuthorizationClaim = {
        authorizationIdentity,
        claim: authorizationClaim,
        priorState: null,
      };
    } else {
      if (authorizationClaim.state === 'processing') {
        return c.json({
          error: 'payment authorization is already being processed',
          code: 'PAYMENT_AUTHORIZATION_IN_PROGRESS',
        }, 409);
      }
      activeAuthorizationClaim = {
        authorizationIdentity,
        claim: authorizationClaim,
        priorState: authorizationClaim.state,
      };
      authorizationClaim.state = 'processing';
    }

    const retainAuthorizationClaim = (phase) => {
      authorizationClaim.state = 'unresolved';
      authorizationClaim.phase = phase;
    };
    const beginAuthorizationExecution = () => {
      authorizationClaim.state = 'executing';
      authorizationClaim.phase = 'execution';
      authorizationClaim.expiresAtMs = null;
    };
    const consumeAuthorizationClaim = () => {
      let completionNowMs = requestNowMs;
      try {
        const candidateNowMs = now();
        if (Number.isSafeInteger(candidateNowMs) && candidateNowMs >= requestNowMs) {
          completionNowMs = candidateNowMs;
        }
      } catch {
        // The validated request clock remains the conservative fallback.
      }
      authorizationClaim.state = 'consumed';
      authorizationClaim.phase = 'consumed';
      authorizationClaim.expiresAtMs = completionNowMs
        <= Number.MAX_SAFE_INTEGER - pendingOfferTtlMs
        ? completionNowMs + pendingOfferTtlMs
        : Number.MAX_SAFE_INTEGER;
    };
    const rejectAndReleaseAuthorization = async (reason) => {
      try {
        await lifecycle.onRejected?.({ idempotencyKey, reason, settlementReference, payer });
      } catch {
        retainAuthorizationClaim('rejection_persistence');
        return false;
      }
      releaseAuthorizationClaim(authorizationIdentity, authorizationClaim);
      return true;
    };
    let paymentVerified = frozen.verifiedPaymentHash === paymentHash;
    const verifyPayment = async () => {
      facilitatorStarted ??= performance.now();
      try {
        return await postJson(transport, 'verify', facilitatorBody, {
          signal: c.req.raw.signal,
          timeoutMs: facilitatorTimeoutMs,
          maxResponseBytes: facilitatorResponseMaxBytes,
        });
      } catch {
        return null;
      }
    };
    if (frozen.verificationRequired && !paymentVerified) {
      const verify = await verifyPayment();
      if (verify === null) {
        retainAuthorizationClaim('verification');
        return c.json({ error: 'payment verification unresolved', settlementReference }, 503);
      }
      if (verify?.isValid !== true) {
        const reason = 'payment verification failed';
        // Verification precedes onSigned and therefore precedes durable
        // Invocation authority. An explicit facilitator rejection proves that
        // settlement did not begin, so this process-local claim is safe to
        // release without asking a journal to reject a record that does not
        // exist yet.
        releaseAuthorizationClaim(authorizationIdentity, authorizationClaim);
        return c.json({
          x402Version: X402_VERSION,
          error: reason,
          accepts: [requirements],
        }, 402);
      }
      paymentVerified = true;
      authorizationClaim.phase = 'verified';
      const pendingOffer = pendingOffers.get(idempotencyKey);
      if (pendingOffer) {
        pendingOffer.verifiedPaymentHash = paymentHash;
        pendingOffer.verificationRequired = false;
      }
    }
    if (paymentVerified) authorizationClaim.phase = 'verified';
    let priorDecision = null;
    try {
      priorDecision = await lifecycle.onSigned?.({
        idempotencyKey,
        settlementReference,
        payer,
        requirements: structuredClone(requirements),
        executionQuote: structuredClone(executionQuote),
        verifiedPaymentHash: paymentHash,
      });
    } catch {
      retainAuthorizationClaim('signed_authority');
      return c.json({ error: 'paid retry conflicts with authoritative Invocation state' }, 409);
    }
    const authoritativeSigned = priorDecision?.kind === 'signed';
    if (priorDecision?.kind) authorizationClaim.authoritative = true;
    const retainLocalUnresolved = () => {
      // This key already owns either a pending or transient admission, so
      // converting it to unresolved cannot raise the hard unique-key count.
      locallyUnresolvedSettlements.add(idempotencyKey);
      retainAuthorizationClaim('settlement');
      if (authoritativeSigned) pendingOffers.delete(idempotencyKey);
    };

    if (activeAuthorizationClaim.priorState === 'consumed'
        && !['terminal', 'settled', 'payment_unresolved', 'execution_unresolved']
          .includes(priorDecision?.kind)) {
      retainAuthorizationClaim('execution_authority');
      return c.json({
        error: 'consumed payment requires trusted terminal replay authority',
      }, 503);
    }

    if (locallyUnresolvedSettlements.has(idempotencyKey)
        && !['terminal', 'settled'].includes(priorDecision?.kind)) {
      retainAuthorizationClaim('settlement');
      return unresolvedResponse(settlementReference);
    }

    if (priorDecision?.kind === 'terminal') {
      if (!terminalReplayIsTrusted(priorDecision, payer)) {
        retainAuthorizationClaim('terminal_authority');
        return c.json({ error: 'terminal replay lacks a settled or refunded transaction' }, 503);
      }
      locallyUnresolvedSettlements.delete(idempotencyKey);
      pendingOffers.delete(idempotencyKey);
      consumeAuthorizationClaim();
      const body = {
        replayed: true,
        receipt: priorDecision.receipt,
        ...(priorDecision.httpStatus >= 400
          ? { error: 'terminal execution failed' }
          : {}),
      };
      const replay = c.json(body, priorDecision.httpStatus);
      replay.headers.set('X-PAYMENT-RESPONSE', jsonToB64(paymentResponseEvidence({
        idempotencyKey,
        requirements,
        transaction: priorDecision.txHash,
        payer: priorDecision.payer,
        settlementReference,
      })));
      return replay;
    }
    if (priorDecision?.kind === 'payment_unresolved') {
      retainAuthorizationClaim('settlement');
      return c.json({
        error: 'payment settlement unresolved; trusted reconciliation is required',
        settlementReference,
      }, 503);
    }
    if (priorDecision?.kind === 'execution_unresolved') {
      retainAuthorizationClaim('execution');
      return c.json({
        error: 'execution outcome unresolved; trusted executor reconciliation is required',
        executionAttemptId: priorDecision.executionAttemptId,
      }, 503);
    }

    authorizationClaim.phase = 'pre_settlement';
    try {
      await lifecycle.beforeSettlement?.({
        context: c,
        idempotencyKey,
        settlementReference,
        payer,
        requirements: structuredClone(requirements),
        executionQuote: structuredClone(executionQuote),
        verifiedPaymentHash: paymentHash,
      });
    } catch (error) {
      retainAuthorizationClaim('pre_settlement');
      const known = ['PROVIDER_SPEND_CAP', 'PROVIDER_ATTEMPT_IN_PROGRESS'].includes(error?.code);
      return c.json({
        error: known ? error.message : 'pre-settlement authorization failed',
        code: known ? error.code : 'PRE_SETTLEMENT_AUTHORIZATION',
      }, 503);
    }

    let settle;
    let facilitatorMs = 0;
    if (priorDecision?.kind === 'settled') {
      if (!validTxHash(priorDecision.txHash)
          || String(priorDecision.payer ?? '').toLowerCase() !== payer) {
        retainAuthorizationClaim('settlement_authority');
        return c.json({ error: 'persisted settlement proof does not match the signed payer' }, 503);
      }
      locallyUnresolvedSettlements.delete(idempotencyKey);
      pendingOffers.delete(idempotencyKey);
      settle = {
        success: true,
        transaction: priorDecision.txHash,
        payer: priorDecision.payer,
        network: NETWORK,
      };
    } else {
      if (!paymentVerified) {
        const verify = await verifyPayment();
        if (verify === null) {
          retainLocalUnresolved();
          await notifyUnresolved({
            idempotencyKey,
            settlementReference,
            payer,
            reason: 'facilitator verification unresolved',
          });
          return c.json({ error: 'payment verification unresolved', settlementReference }, 503);
        }
        if (verify?.isValid !== true) {
          const reason = 'payment verification failed';
          if (!await rejectAndReleaseAuthorization(reason)) {
            return c.json({
              error: 'payment rejection conflicts with authoritative Invocation state',
            }, 409);
          }
          return c.json({
            x402Version: X402_VERSION,
            error: reason,
            accepts: [requirements],
          }, 402);
        }
        paymentVerified = true;
      }
      authorizationClaim.phase = 'settlement';
      try {
        facilitatorStarted ??= performance.now();
        settle = await postJson(transport, 'settle', facilitatorBody, {
          signal: c.req.raw.signal,
          timeoutMs: facilitatorTimeoutMs,
          maxResponseBytes: facilitatorResponseMaxBytes,
        });
      } catch {
        retainLocalUnresolved();
        await notifyUnresolved({
          idempotencyKey,
          settlementReference,
          payer,
          reason: 'facilitator response unresolved',
        });
        return c.json({ error: 'payment settlement unresolved', settlementReference }, 503);
      }
      facilitatorMs = performance.now() - facilitatorStarted;
    }
    if (settle?.success !== true) {
      if (settle?.success !== false) {
        retainLocalUnresolved();
        await notifyUnresolved({
          idempotencyKey,
          settlementReference,
          payer,
          reason: 'facilitator returned an ambiguous settlement result',
        });
        return c.json({ error: 'payment settlement unresolved', settlementReference }, 503);
      }
      const reason = 'payment settlement failed';
      if (!await rejectAndReleaseAuthorization(reason)) {
        return c.json({
          error: 'payment rejection conflicts with authoritative Invocation state',
        }, 409);
      }
      locallyUnresolvedSettlements.delete(idempotencyKey);
      if (authoritativeSigned) pendingOffers.delete(idempotencyKey);
      return c.json({
        x402Version: X402_VERSION,
        error: reason,
        accepts: [requirements],
      }, 402);
    }
    const settledPayer = String(settle.payer ?? '').toLowerCase();
    const settledTxHash = String(settle.transaction ?? '').toLowerCase();
    if (!validTxHash(settledTxHash)
        || settledPayer !== payer
        || settle.network !== NETWORK) {
      retainLocalUnresolved();
      await notifyUnresolved({
        idempotencyKey,
        settlementReference,
        payer,
        reason: 'facilitator returned malformed settlement evidence',
      });
      return c.json({
        error: 'payment settlement unresolved: facilitator evidence is invalid',
        settlementReference,
      }, 503);
    }
    if (priorDecision?.kind !== 'settled') {
      try {
        await lifecycle.onSettled?.({
          idempotencyKey,
          settlementReference,
          txHash: settledTxHash,
          payer: settledPayer,
          amountAtomic: requirements.maxAmountRequired,
          requirements: structuredClone(requirements),
          executionQuote: structuredClone(executionQuote),
        });
      } catch {
        retainLocalUnresolved();
        await notifyUnresolved({
          idempotencyKey,
          settlementReference,
          payer,
          reason: 'settlement confirmed but journal persistence unresolved',
        });
        return c.json({
          error: 'payment settlement unresolved: authoritative persistence requires reconciliation',
          settlementReference,
        }, 503);
      }
      if (authoritativeSigned) pendingOffers.delete(idempotencyKey);
    }

    if (['signed', 'settled'].includes(priorDecision?.kind)) {
      authorizationClaim.authoritative = true;
    }
    // Claim consumption precedes the handler. A provider or response failure
    // can never reopen the same monetary authorization for another execution.
    beginAuthorizationExecution();

    c.set('x402', {
      idempotencyKey,
      settlementReference,
      txHash: settledTxHash,
      payer: settledPayer,
      amountAtomic: requirements.maxAmountRequired,
      requirements: structuredClone(requirements),
      executionQuote: structuredClone(executionQuote),
      legacySchemaVersion: priorDecision?.legacySchemaVersion ?? null,
    });
    await next();
    consumeAuthorizationClaim();
    c.res.headers.set('X-PAYMENT-RESPONSE', jsonToB64(paymentResponseEvidence({
      idempotencyKey,
      requirements,
      transaction: settledTxHash,
      payer: settledPayer,
      settlementReference,
    })));
    c.res.headers.set('X-402-FACILITATOR-MS', facilitatorMs.toFixed(1));
    } finally {
      if (activeAuthorizationClaim
          && authorizationClaims.get(activeAuthorizationClaim.authorizationIdentity)
            === activeAuthorizationClaim.claim
          && ['processing', 'executing'].includes(activeAuthorizationClaim.claim.state)) {
        if (activeAuthorizationClaim.claim.state === 'executing') {
          consumeAuthorizationClaim();
        } else {
          activeAuthorizationClaim.claim.state = 'unresolved';
          activeAuthorizationClaim.claim.phase = 'unexpected_failure';
        }
      }
      if (transientAdmission) transientAdmissions.delete(idempotencyKey);
    }
  };
}

async function postJson(transport, operation, body, {
  signal,
  timeoutMs,
  maxResponseBytes,
}) {
  if (!['verify', 'settle'].includes(operation)) throw new Error('invalid facilitator operation');
  return withWallClockDeadline({
    signal,
    timeoutMs,
    timeoutCode: 'FACILITATOR_TIMEOUT',
    timeoutMessage: `facilitator ${operation} timed out`,
    abortedCode: 'FACILITATOR_ABORTED',
    abortedMessage: `facilitator ${operation} was aborted`,
  }, async (composedSignal) => {
    const response = await transport.fetchImpl(`${transport.baseUrl}/${operation}`, {
      method: 'POST',
      redirect: 'error',
      signal: composedSignal,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response?.ok) {
      const error = new RuntimeBoundaryError(
        'FACILITATOR_HTTP',
        'facilitator returned an unsuccessful status',
      );
      cancelResponseBody(response, error);
      throw error;
    }
    return readJsonBody(response, {
      maxBytes: maxResponseBytes,
      tooLargeCode: 'FACILITATOR_RESPONSE_TOO_LARGE',
      tooLargeMessage: 'facilitator response exceeds the JSON byte limit',
      readErrorCode: 'FACILITATOR_RESPONSE_READ_FAILED',
      readErrorMessage: 'facilitator response could not be read',
      jsonErrorCode: 'FACILITATOR_RESPONSE_JSON',
      jsonErrorMessage: 'facilitator response was not JSON',
      signal: composedSignal,
    });
  });
}

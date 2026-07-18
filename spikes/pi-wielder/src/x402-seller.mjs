// Seller-side x402 v1 boundary for the offline/testnet spike.
//
// A client-generated Idempotency-Key binds method, resource URL, and exact body
// bytes to one frozen PaymentRequirements envelope. The Collar persists that
// envelope and owns payment/execution lifecycle state; this middleware never
// rebuilds an offer after restart and never treats a quote as authorization.

import crypto from 'node:crypto';

import { formatUsdc, parseUsdc } from '../../../prototype/atomic-money.mjs';

export const X402_VERSION = 1;
export const NETWORK = 'base-sepolia';
export const CHAIN_ID = 84532;
export const USDC_ADDRESS = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
export const USDC_EIP712 = Object.freeze({ name: 'USDC', version: '2' });
export const APPROVED_LIVE_FACILITATOR_BASE = 'https://x402.org/facilitator';

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
}) {
  const transport = requireFacilitatorTransport(facilitatorTransport);
  const canonicalPayTo = canonicalAddress(payTo);
  if (quote !== null && typeof quote !== 'function') {
    throw new TypeError('quote must be an injected function or null');
  }
  const frozenOffers = new Map();
  const locallyUnresolvedSettlements = new Set();

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
    const idempotencyKey = c.req.header('Idempotency-Key')?.trim();
    if (!idempotencyKey) return c.json({ error: 'Idempotency-Key header is required' }, 400);
    const paymentHeader = c.req.header('X-PAYMENT');
    const requestBody = await c.req.text();
    const requestHash = `sha256:${crypto.createHash('sha256')
      .update(`${c.req.method}\n${c.req.url}\n${requestBody}`)
      .digest('hex')}`;

    let frozen = frozenOffers.get(idempotencyKey) ?? null;
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
        if (!exactPlainObject(recovered, ['requirements', 'executionQuote'])) {
          return c.json({ error: 'persisted frozen offer has an unsupported schema' }, 409);
        }
        frozen = structuredClone(recovered);
        frozenOffers.set(idempotencyKey, frozen);
      }
    }
    let requirements = frozen?.requirements ?? null;
    let executionQuote = frozen?.executionQuote ?? null;
    if (requirements) {
      if (requirements.extra?.requestHash !== requestHash) {
        return c.json({ error: 'Idempotency-Key already binds a different request' }, 409);
      }
    } else {
      if (paymentHeader) return c.json({ error: 'paid retry has no prior frozen x402 offer' }, 409);
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
      const issuedAt = new Date().toISOString();
      const expiresAt = new Date(Date.now() + 60_000).toISOString();
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
      frozen = { requirements, executionQuote };
      frozenOffers.set(idempotencyKey, structuredClone(frozen));
    }

    if (!paymentHeader) {
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
      await lifecycle.onRejected?.({ idempotencyKey, reason: error.message });
      return c.json({
        x402Version: X402_VERSION,
        error: error.message,
        accepts: [requirements],
      }, 402);
    }
    const settlementReference = authorization.nonce.toLowerCase();
    const payer = authorization.from.toLowerCase();
    let priorDecision = null;
    try {
      priorDecision = await lifecycle.onSigned?.({
        idempotencyKey,
        settlementReference,
        payer,
        requirements: structuredClone(requirements),
        executionQuote: structuredClone(executionQuote),
      });
    } catch {
      return c.json({ error: 'paid retry conflicts with authoritative Invocation state' }, 409);
    }

    if (locallyUnresolvedSettlements.has(idempotencyKey)
        && !['terminal', 'settled'].includes(priorDecision?.kind)) {
      return c.json({
        error: 'payment settlement unresolved; trusted reconciliation is required',
        settlementReference,
      }, 503);
    }

    if (priorDecision?.kind === 'terminal') {
      if (!terminalReplayIsTrusted(priorDecision, payer)) {
        return c.json({ error: 'terminal replay lacks a settled or refunded transaction' }, 503);
      }
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
      return c.json({
        error: 'payment settlement unresolved; trusted reconciliation is required',
        settlementReference,
      }, 503);
    }
    if (priorDecision?.kind === 'execution_unresolved') {
      return c.json({
        error: 'execution outcome unresolved; trusted executor reconciliation is required',
        executionAttemptId: priorDecision.executionAttemptId,
      }, 503);
    }

    const facilitatorBody = {
      x402Version: X402_VERSION,
      paymentPayload,
      paymentRequirements: requirements,
    };
    let settle;
    let facilitatorMs = 0;
    if (priorDecision?.kind === 'settled') {
      if (!validTxHash(priorDecision.txHash)
          || String(priorDecision.payer ?? '').toLowerCase() !== payer) {
        return c.json({ error: 'persisted settlement proof does not match the signed payer' }, 503);
      }
      settle = {
        success: true,
        transaction: priorDecision.txHash,
        payer: priorDecision.payer,
        network: NETWORK,
      };
    } else {
      const started = performance.now();
      try {
        const verify = await postJson(transport, 'verify', facilitatorBody);
        if (!verify?.isValid) {
          const reason = 'payment verification failed';
          await lifecycle.onRejected?.({ idempotencyKey, reason, settlementReference, payer });
          return c.json({
            x402Version: X402_VERSION,
            error: reason,
            accepts: [requirements],
          }, 402);
        }
        settle = await postJson(transport, 'settle', facilitatorBody);
      } catch {
        locallyUnresolvedSettlements.add(idempotencyKey);
        await notifyUnresolved({
          idempotencyKey,
          settlementReference,
          payer,
          reason: 'facilitator response unresolved',
        });
        return c.json({ error: 'payment settlement unresolved', settlementReference }, 503);
      }
      facilitatorMs = performance.now() - started;
    }
    if (settle?.success !== true) {
      if (settle?.success !== false) {
        locallyUnresolvedSettlements.add(idempotencyKey);
        await notifyUnresolved({
          idempotencyKey,
          settlementReference,
          payer,
          reason: 'facilitator returned an ambiguous settlement result',
        });
        return c.json({ error: 'payment settlement unresolved', settlementReference }, 503);
      }
      const reason = 'payment settlement failed';
      await lifecycle.onRejected?.({ idempotencyKey, reason, settlementReference, payer });
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
      locallyUnresolvedSettlements.add(idempotencyKey);
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
        locallyUnresolvedSettlements.add(idempotencyKey);
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
    }

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
    c.res.headers.set('X-PAYMENT-RESPONSE', jsonToB64(paymentResponseEvidence({
      idempotencyKey,
      requirements,
      transaction: settledTxHash,
      payer: settledPayer,
      settlementReference,
    })));
    c.res.headers.set('X-402-FACILITATOR-MS', facilitatorMs.toFixed(1));
  };
}

async function postJson(transport, operation, body) {
  if (!['verify', 'settle'].includes(operation)) throw new Error('invalid facilitator operation');
  const response = await transport.fetchImpl(`${transport.baseUrl}/${operation}`, {
    method: 'POST',
    redirect: 'error',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error(`facilitator HTTP ${response.status}`);
  const json = await response.json().catch(() => null);
  if (!json) throw new Error('facilitator returned no JSON result');
  return json;
}

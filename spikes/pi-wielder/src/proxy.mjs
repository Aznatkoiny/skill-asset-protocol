// proxy.mjs — Wielder-side payment transport skeleton for this spike.
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ THIS FILE COVERS THE SPIKE'S X402 CHALLENGE, SIGN, AND RETRY TRANSPORT.    ║
// ║                                                                          ║
// ║ It also verifies pinned Collar receipts and maintains a payer-local      ║
// ║ receipt view. It is not the complete protocol, accounting authority,     ║
// ║ custody design, durable cross-process budget enforcement, or proof that  ║
// ║ ADR-0008 is production-ready.                                            ║
// ╚══════════════════════════════════════════════════════════════════════════╝

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { formatUsdc, parseUsdc } from '../../../prototype/atomic-money.mjs';
import { loadAccount } from './wallet.mjs';
import { createLedger, renderLedger } from './ledger.mjs';
import { receiptKeyId, verifySignedReceipt } from './invocation-journal.mjs';
import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  createPaymentPolicy,
  PaymentPolicyError,
} from './payment-policy.mjs';

// EIP-712 typed data for EIP-3009 transferWithAuthorization — the single
// signature that IS the payment. (Constants restated here on purpose: the
// Wielder must be self-contained, importing nothing from the seller side.)
const CHAIN_ID = BASE_SEPOLIA_CHAIN_ID;
const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
  ],
};
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');

const payingFetchOptionKeys = new Set([
  'fetchImpl', 'idempotencyKey', 'paymentPolicy', 'onSignedAuthorizationPersisted', 'nonceFactory',
]);
const requestInitKeys = Object.freeze([
  'body', 'cache', 'credentials', 'dispatcher', 'duplex', 'headers', 'integrity', 'keepalive',
  'method', 'mode', 'priority', 'redirect', 'referrer', 'referrerPolicy', 'signal', 'window',
]);
const requestInitKeySet = new Set(requestInitKeys);

function paymentError(code, message) {
  return new PaymentPolicyError(code, message);
}

function validatePayingFetchOptions(options) {
  if (!options || typeof options !== 'object' || Array.isArray(options)
      || Object.getPrototypeOf(options) !== Object.prototype
      || Object.keys(options).some((key) => !payingFetchOptionKeys.has(key))) {
    throw paymentError('PAYING_FETCH_OPTIONS', 'payingFetch options contain an unknown or invalid field');
  }
}

function ownedRequestHeaders(input) {
  const forbidden = new Set(['x-payment', 'idempotency-key']);
  const names = [];
  if (input == null) {
    // no caller headers
  } else if (input instanceof Headers) {
    for (const [name] of input.entries()) names.push(name);
  } else if (Array.isArray(input)) {
    for (const entry of input) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') {
        throw paymentError('REQUEST_HEADERS', 'request header tuples must be exact name/value pairs');
      }
      names.push(entry[0]);
    }
  } else if (typeof input === 'object' && Object.getPrototypeOf(input) === Object.prototype) {
    names.push(...Object.keys(input));
  } else {
    throw paymentError('REQUEST_HEADERS', 'request headers must use a standard HeadersInit shape');
  }
  if (names.some((name) => forbidden.has(name.toLowerCase()))) {
    throw paymentError(
      'CALLER_PAYMENT_HEADER',
      'the Wielder exclusively owns Idempotency-Key and X-PAYMENT headers',
    );
  }
  let normalized;
  try {
    normalized = new Headers(input ?? undefined);
  } catch {
    throw paymentError('REQUEST_HEADERS', 'request headers are malformed');
  }
  return Object.fromEntries(normalized.entries());
}

function captureRequestInitDictionary(input) {
  if (input == null) return {};
  const source = Object(input);
  const captured = {};
  for (const key of requestInitKeys) {
    const value = source[key];
    if (value !== undefined) captured[key] = value;
  }
  for (const key of Reflect.ownKeys(source)) {
    if (typeof key === 'string' && requestInitKeySet.has(key)) continue;
    const descriptor = Object.getOwnPropertyDescriptor(source, key);
    if (descriptor?.enumerable) captured[key] = source[key];
  }
  return captured;
}

function capturePayingRequestInit(init, idempotencyKey) {
  // Materialize caller-owned accessors exactly once. Every transport request is
  // rebuilt from this private snapshot, never by re-spreading the caller object.
  const captured = captureRequestInitDictionary(init);
  const method = captured.method ?? 'GET';
  if (typeof method !== 'string' || method !== method.toUpperCase()) {
    throw paymentError('REQUEST_METHOD', 'request method must be uppercase');
  }

  const callerBody = captured.body;
  let bodyBytes;
  let transportBody;
  if (callerBody == null) {
    bodyBytes = null;
    transportBody = callerBody;
  } else if (typeof callerBody === 'string') {
    bodyBytes = callerBody;
    transportBody = callerBody;
  } else if (callerBody instanceof Uint8Array) {
    bodyBytes = Buffer.from(callerBody);
    transportBody = bodyBytes;
  } else {
    throw paymentError(
      'REQUEST_BODY',
      'payingFetch requires a replayable string, Uint8Array, or null request body',
    );
  }

  const requestHeaders = Object.freeze({
    ...ownedRequestHeaders(captured.headers),
    'Idempotency-Key': idempotencyKey,
  });
  const hasBody = Object.hasOwn(captured, 'body');
  const baseInit = { ...captured, method };
  delete baseInit.headers;
  delete baseInit.body;
  delete baseInit.redirect;
  Object.freeze(baseInit);

  function transportInit(xPayment = null) {
    const request = {
      ...baseInit,
      method,
      redirect: 'error',
      headers: {
        ...requestHeaders,
        ...(xPayment === null ? {} : { 'X-PAYMENT': xPayment }),
      },
    };
    if (hasBody) {
      request.body = transportBody instanceof Uint8Array
        ? Buffer.from(transportBody)
        : transportBody;
    }
    return request;
  }

  function policyBodyBytes() {
    return bodyBytes instanceof Uint8Array ? Buffer.from(bodyBytes) : bodyBytes;
  }

  return Object.freeze({
    method,
    policyBodyBytes,
    transportInit,
  });
}

function decodeSettlementHeader(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw paymentError('SETTLEMENT_EVIDENCE', 'settlement evidence is missing or malformed');
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) {
    throw paymentError('SETTLEMENT_EVIDENCE', 'settlement evidence is missing or malformed');
  }
  try {
    const decoded = JSON.parse(bytes.toString('utf8'));
    if (!decoded || typeof decoded !== 'object' || Array.isArray(decoded)) throw new Error('shape');
    return decoded;
  } catch {
    throw paymentError('SETTLEMENT_EVIDENCE', 'settlement evidence is missing or malformed');
  }
}

// Buyer transport loop used by this spike: request -> 402 -> sign EIP-3009 -> retry once.
// Returns the accepted quote/authorization identity with the response. Timings are the spike's
// payment-overhead measurement (402 roundtrip + sign + facilitator).
export async function payingFetch(account, url, init, options = {}) {
  validatePayingFetchOptions(options);
  const {
    fetchImpl = fetch,
    idempotencyKey = crypto.randomUUID(),
    paymentPolicy,
    onSignedAuthorizationPersisted = null,
    nonceFactory = () => `0x${crypto.randomBytes(32).toString('hex')}`,
  } = options;
  if (typeof fetchImpl !== 'function') throw paymentError('FETCH_CAPABILITY', 'fetchImpl must be a function');
  if (!paymentPolicy) throw paymentError('PAYMENT_POLICY_REQUIRED', 'paymentPolicy is required before any x402 signature');
  if (onSignedAuthorizationPersisted !== null
      && typeof onSignedAuthorizationPersisted !== 'function') {
    throw paymentError('PERSISTENCE_HOOK', 'onSignedAuthorizationPersisted must be a function');
  }
  if (typeof nonceFactory !== 'function') {
    throw paymentError('NONCE_CAPABILITY', 'nonceFactory must be a synchronous function');
  }
  if (typeof idempotencyKey !== 'string' || !/^[A-Za-z0-9._:-]{1,200}$/.test(idempotencyKey)) {
    throw paymentError('AUTHORIZATION_ID', 'idempotencyKey must be a bounded canonical token');
  }
  const request = capturePayingRequestInit(init, idempotencyKey);
  const { method } = request;
  const t0 = performance.now();
  const first = await fetchImpl(url, request.transportInit());
  if (first.status !== 402) return { res: first, paid: false, idempotencyKey };
  const receivedAt = paymentPolicy.captureReceivedAt();
  const ms402 = performance.now() - t0;

  let firstChallenge;
  try {
    firstChallenge = await first.json();
  } catch {
    throw paymentError('CHALLENGE_SCHEMA', '402 response does not contain strict x402 JSON');
  }
  const authorizationRecord = paymentPolicy.reserveAuthorization({
    authorizationId: idempotencyKey,
    requestUrl: url,
    method,
    bodyBytes: request.policyBodyBytes(),
    challenge: firstChallenge,
    receivedAt,
  });
  const req = authorizationRecord.offer;

  let signedRecord;
  let msSign = 0;
  if (authorizationRecord.state === 'reserved') {
    const claim = paymentPolicy.claimSignature(idempotencyKey, {
      offerFingerprint: authorizationRecord.offerFingerprint,
    });
    if (!claim.claimed) {
      throw paymentError('AUTHORIZATION_ALREADY_USED', 'idempotency key already has a signature claim');
    }
    let payer;
    let signTypedData;
    let authorization;
    let preSignFailureReason = 'LOCAL_AUTHORIZATION_FAILURE';
    try {
      const address = account?.address;
      const signer = account?.signTypedData;
      payer = typeof address === 'string' ? address.toLowerCase() : '';
      if (!/^0x[0-9a-f]{40}$/.test(payer) || typeof signer !== 'function') {
        preSignFailureReason = 'INVALID_WALLET_CAPABILITY';
        throw paymentError(
          'WALLET_CAPABILITY',
          'wallet must expose a canonical address and signTypedData capability',
        );
      }
      signTypedData = signer;
      const nonce = nonceFactory();
      if (nonce && typeof nonce.then === 'function') {
        throw paymentError('NONCE_CAPABILITY', 'nonceFactory must be synchronous');
      }
      if (typeof nonce !== 'string' || !/^0x[0-9a-f]{64}$/.test(nonce)) {
        throw paymentError('NONCE_FORMAT', 'nonceFactory must return one canonical lowercase bytes32');
      }
      authorization = {
        from: payer,
        to: req.payTo,
        value: authorizationRecord.amountAtomic,
        validAfter: authorizationRecord.validAfter,
        validBefore: authorizationRecord.validBefore,
        nonce,
      };
    } catch (error) {
      paymentPolicy.releaseUnsigned(idempotencyKey, {
        reasonCode: preSignFailureReason,
      });
      throw error;
    }
    const tSign = performance.now();
    let signatureReturned = false;
    let signature;
    try {
      signature = await Reflect.apply(signTypedData, account, [{
        domain: {
          name: req.extra.name,
          version: req.extra.version,
          chainId: CHAIN_ID,
          verifyingContract: req.asset,
        },
        types: EIP3009_TYPES,
        primaryType: 'TransferWithAuthorization',
        message: {
          ...authorization,
          value: BigInt(authorization.value),
          validAfter: BigInt(authorization.validAfter),
          validBefore: BigInt(authorization.validBefore),
        },
      }]);
      signatureReturned = true;
      msSign = performance.now() - tSign;
      const xPayment = b64({
        x402Version: 1,
        scheme: 'exact',
        network: req.network,
        payload: { signature, authorization },
      });
      // Same-process durability boundary: no await occurs between signer return
      // and storing the exact authorization, signature, and X-PAYMENT bytes.
      signedRecord = paymentPolicy.persistSignedAuthorization(idempotencyKey, {
        authorization,
        signature,
        xPayment,
      });
    } catch (error) {
      if (!signatureReturned) {
        paymentPolicy.releaseUnsigned(idempotencyKey, { reasonCode: 'SIGNER_REJECTED' });
      } else {
        paymentPolicy.markPotentiallySigned(idempotencyKey, {
          reasonCode: 'SIGNATURE_PERSISTENCE_UNCERTAIN',
        });
      }
      throw error;
    }
    if (onSignedAuthorizationPersisted) {
      await onSignedAuthorizationPersisted({ authorization: signedRecord });
    }
  } else if (authorizationRecord.state === 'signed') {
    signedRecord = paymentPolicy.recoverSignedAuthorization({
      authorizationId: idempotencyKey,
      requestUrl: url,
      method,
      bodyBytes: request.policyBodyBytes(),
    });
  } else {
    throw paymentError(
      'AUTHORIZATION_ALREADY_USED',
      'idempotency key already has a signing, retrying, unresolved, or terminal authorization',
    );
  }

  try {
    signedRecord = paymentPolicy.assertAuthorizationFresh(idempotencyKey);
  } catch (error) {
    paymentPolicy.markUnresolved(idempotencyKey, {
      reasonCode: 'AUTHORIZATION_EXPIRED_BEFORE_RETRY',
    });
    throw error;
  }
  const { authorization, xPayment } = signedRecord;
  paymentPolicy.beginRetry(idempotencyKey);
  const tRetry = performance.now();
  let res;
  try {
    res = await fetchImpl(url, request.transportInit(xPayment));
  } catch (error) {
    paymentPolicy.markUnresolved(idempotencyKey, { reasonCode: 'RETRY_RESPONSE_LOST' });
    throw error;
  }
  const msPaidRoundtrip = performance.now() - tRetry;

  if (res.status === 402) {
    let secondChallenge = null;
    try { secondChallenge = await res.clone().json(); } catch { /* stable changed-quote error below */ }
    let secondError;
    try {
      paymentPolicy.assertRetryChallenge(idempotencyKey, secondChallenge);
      secondError = paymentError(
        'SECOND_PAYMENT_REQUIRED',
        'seller requested a second payment after the only permitted retry',
      );
    } catch (error) {
      secondError = error;
    }
    paymentPolicy.markUnresolved(idempotencyKey, { reasonCode: 'SECOND_PAYMENT_REQUIRED' });
    throw secondError;
  }

  let settlement;
  try {
    settlement = decodeSettlementHeader(res.headers.get('X-PAYMENT-RESPONSE'));
    paymentPolicy.acceptSettlement(idempotencyKey, settlement);
  } catch {
    paymentPolicy.markUnresolved(idempotencyKey, { reasonCode: 'SETTLEMENT_EVIDENCE_INVALID' });
    throw paymentError(
      'SETTLEMENT_EVIDENCE',
      'retry settlement evidence is missing, malformed, or mismatched; upstream output withheld',
    );
  }
  const reportedFacilitatorMs = Number(res.headers.get('X-402-FACILITATOR-MS'));
  const msFacilitator = Number.isFinite(reportedFacilitatorMs) && reportedFacilitatorMs >= 0
    ? reportedFacilitatorMs
    : null;
  return {
    res,
    paid: true,
    xPayment,
    idempotencyKey,
    settlementReference: authorization.nonce,
    txHash: settlement.transaction,
    payer: authorization.from,
    requestHash: signedRecord.requestHash,
    quoteId: signedRecord.quoteId,
    amountAtomic: signedRecord.amountAtomic,
    amountDisplay: formatUsdc(BigInt(signedRecord.amountAtomic)),
    timings: {
      ms402,
      msSign,
      msFacilitator,
      msPaidRoundtrip,
      msOverhead: ms402 + msSign + (msFacilitator ?? 0),
    },
  };
}

export function createDefaultPaymentPolicy({ gatewayUrl, collarUrl, env = process.env, now } = {}) {
  const payTo = env.PAY_TO_ADDRESS || '0x000000000000000000000000000000000000dead';
  return createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: parseUsdc(env.WIELDER_SESSION_BUDGET_USDC || '1.00').toString(),
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    ...(now ? { now } : {}),
    sellers: [
      {
        origin: new URL(gatewayUrl).origin,
        pathPrefix: '/v1/',
        payTo,
        maxPerCallAtomic: parseUsdc(env.WIELDER_MODEL_MAX_USDC || '0.10').toString(),
      },
      {
        origin: new URL(collarUrl).origin,
        pathPrefix: '/invoke/',
        payTo,
        maxPerCallAtomic: parseUsdc(env.WIELDER_SKILL_MAX_USDC || '0.50').toString(),
      },
    ],
  });
}

export function loadPinnedCollarTrust(env = process.env) {
  const publicKeyFile = env.COLLAR_PUBLIC_KEY_FILE || null;
  const expectedKeyId = env.COLLAR_KEY_ID || null;
  if (!publicKeyFile || !expectedKeyId) {
    throw new Error('Skill routes require COLLAR_PUBLIC_KEY_FILE and COLLAR_KEY_ID');
  }
  if (!path.isAbsolute(publicKeyFile)) throw new Error('COLLAR_PUBLIC_KEY_FILE must be absolute');
  const stat = fs.lstatSync(publicKeyFile);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error('COLLAR_PUBLIC_KEY_FILE must be a regular non-symlink file');
  }
  const descriptor = fs.openSync(
    publicKeyFile,
    fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0),
  );
  let publicKeyPem;
  try {
    if (!fs.fstatSync(descriptor).isFile()) {
      throw new Error('COLLAR_PUBLIC_KEY_FILE must remain a regular file');
    }
    publicKeyPem = fs.readFileSync(descriptor, 'utf8');
  } finally {
    fs.closeSync(descriptor);
  }
  const actualKeyId = receiptKeyId(publicKeyPem);
  if (actualKeyId !== expectedKeyId) {
    throw new Error('COLLAR_KEY_ID does not match COLLAR_PUBLIC_KEY_FILE');
  }
  return { trustedCollarPublicKeyPem: publicKeyPem, trustedCollarKeyId: expectedKeyId };
}

export function assertReceiptMatchesPayment(bundle, expected) {
  const receipt = bundle?.receipt;
  const lower = (value) => String(value ?? '').toLowerCase();
  const terminal = new Set(['succeeded', 'failed', 'cancelled']);
  const paymentTerminal = new Set(['settled', 'refunded']);
  const executionState = receipt?.execution?.state;
  const httpStatus = receipt?.execution?.httpStatus;
  const statusSemanticsMatch = executionState === 'succeeded'
    ? httpStatus >= 200 && httpStatus < 400
    : Number.isSafeInteger(httpStatus) && httpStatus >= 400 && httpStatus <= 599;
  const legacyReceipt = receipt?.schemaVersion === 1
    && receipt.quote?.schemaVersion === undefined
    && receipt.quote?.executionQuote === undefined;
  const cogsAwareReceipt = receipt?.schemaVersion === 2
    && receipt.quote?.schemaVersion === 2
    && receipt.quote?.executionQuote?.schemaVersion === 2
    && receipt.quote.executionQuote.quoteId === expected.quoteId
    && receipt.quote.executionQuote.grossAtomic === expected.amountAtomic
    && receipt.accounting?.schemaVersion === 2
    && receipt.accounting?.quoteId === expected.quoteId;
  if (!receipt
      || !(legacyReceipt || cogsAwareReceipt)
      || receipt.mode !== 'external'
      || receipt.idempotencyKey !== expected.idempotencyKey
      || receipt.requestHash !== expected.requestHash
      || receipt.skill?.id !== expected.skillId
      || receipt.quote?.requestHash !== expected.requestHash
      || receipt.quote?.quoteId !== expected.quoteId
      || receipt.quote?.amountAtomic !== expected.amountAtomic
      || receipt.quote?.currency !== 'USDC'
      || receipt.quote?.network !== 'base-sepolia'
      || receipt.quote?.resource !== expected.resource
      || lower(receipt.wielderId) !== lower(expected.payer)
      || !paymentTerminal.has(receipt.payment?.state)
      || lower(receipt.payment?.payer) !== lower(expected.payer)
      || lower(receipt.payment?.settlementReference) !== lower(expected.settlementReference)
      || lower(receipt.payment?.txHash) !== lower(expected.txHash)
      || (receipt.payment?.state === 'refunded'
        && receipt.payment.refundAmountAtomic !== expected.amountAtomic)
      || !terminal.has(executionState)
      || httpStatus !== expected.httpStatus
      || !statusSemanticsMatch
      || receipt.accounting?.grossAtomic !== expected.amountAtomic) {
    throw new Error('signed Collar receipt does not semantically match the current paid request');
  }
  return receipt;
}

export function createProxy({
  account = loadAccount(),
  gatewayUrl = process.env.GATEWAY_URL || 'http://127.0.0.1:8403',
  collarUrl = process.env.COLLAR_URL || 'http://127.0.0.1:8404',
  ledgerFile = process.env.LEDGER_FILE ?? null,
  gatewayFetch = fetch,
  collarFetch = fetch,
  trustedCollarPublicKeyPem = null,
  trustedCollarKeyId = null,
  paymentPolicy = null,
} = {}) {
  if (!trustedCollarPublicKeyPem || !trustedCollarKeyId) {
    throw new Error('Skill routes require a pinned Collar public key and key ID');
  }
  if (receiptKeyId(trustedCollarPublicKeyPem) !== trustedCollarKeyId) {
    throw new Error('pinned Collar public key and key ID do not match');
  }
  const ledger = createLedger(ledgerFile);
  const sessionPaymentPolicy = paymentPolicy ?? createDefaultPaymentPolicy({ gatewayUrl, collarUrl });
  const app = new Hono();

  // One handler for both asset classes: /v1/* -> inference gateway (leg:
  // "model"), /invoke/* -> collar (leg: "skill"). Same wallet, one local view.
  const forward = (upstreamBase, leg, fetchImpl) => async (c) => {
    const path = c.req.path;
    const bodyText = await c.req.text();
    const {
      res, paid, xPayment, idempotencyKey, amountAtomic, txHash, payer,
      requestHash, quoteId, settlementReference, timings,
    } = await payingFetch(account, `${upstreamBase}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: bodyText,
    }, { fetchImpl, paymentPolicy: sessionPaymentPolicy });
    const resBody = await res.text();

    if (paid && txHash) {
      let parsed = {};
      try { parsed = JSON.parse(resBody); } catch { /* SSE bodies are not JSON */ }
      let requestBody = {};
      try { requestBody = JSON.parse(bodyText || '{}'); } catch { /* seller owns request validation */ }
      const model = requestBody.model ?? '';
      const label = leg === 'skill'
        ? `skill/${path.split('/').pop()}`
        : `${model.startsWith('claude') ? 'claude' : 'gpt'}/${c.req.header('x-session-label') || 'chat'}`;
      const receipt = parsed.receipt ?? null;
      if (leg === 'skill') {
        if (!receipt || !verifySignedReceipt(receipt, {
          publicKeyPem: trustedCollarPublicKeyPem,
          keyId: trustedCollarKeyId,
        })) {
          throw new Error('Skill receipt signature does not match the pinned Collar key');
        }
        assertReceiptMatchesPayment(receipt, {
          idempotencyKey,
          requestHash,
          quoteId,
          amountAtomic,
          payer,
          settlementReference,
          txHash,
          httpStatus: res.status,
          skillId: path.split('/').pop(),
          resource: `${upstreamBase}${path}`,
        });
      }
      const accounting = receipt?.receipt?.accounting ?? null;
      const finalizedAccounting = accounting?.allocationState === 'finalized'
        && typeof accounting.protocolFeeAtomic === 'string';
      const splits = finalizedAccounting ? [
        ...(accounting.holderCredits ?? []).map((credit) => ({
          party: credit.recipientId,
          amountAtomic: credit.amountAtomic,
        })),
        ...(accounting.ancestorCredits ?? []).map((credit) => ({
          party: credit.recipientId,
          amountAtomic: credit.amountAtomic,
        })),
        { party: 'treasury', amountAtomic: accounting.protocolFeeAtomic },
      ] : null;
      ledger.record({
        view: 'wielder-receipt',
        idempotencyKey,
        leg,
        label,
        amountAtomic,
        txHash,
        status: receipt?.receipt?.execution?.state ?? (res.ok ? 'succeeded' : 'failed'),
        receipt,
        splits,
      });
    }

    // Spike-only debug headers: proof-of-402 + overhead for e2e, and the raw
    // X-PAYMENT so the e2e can attempt (and be refused) a credential replay.
    const headers = { 'content-type': res.headers.get('content-type') ?? 'application/json' };
    if (paid) {
      headers['x-wielder-402'] = '1';
      headers['x-wielder-overhead'] = JSON.stringify(timings);
      headers['x-wielder-payment'] = xPayment; // testnet-only; never expose a mainnet authorization like this
    }
    return c.newResponse(resBody, res.status, headers);
  };

  app.post('/v1/*', forward(gatewayUrl, 'model', gatewayFetch));
  app.post('/invoke/*', forward(collarUrl, 'skill', collarFetch));

  // The payer's session-local receipt view — what Pi's /ledger command renders.
  app.get('/ledger', (c) =>
    c.req.query('format') === 'json' ? c.json(ledger.entries) : c.text(renderLedger(ledger.entries)));

  return { app, ledger, account, paymentPolicy: sessionPaymentPolicy };
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startProxy({ port = 0, ...opts } = {}) {
  const { app, ledger, account, paymentPolicy } = createProxy(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port, hostname: '127.0.0.1' }, (info) => {
      let closePromise = null;
      const close = () => {
        closePromise ??= new Promise((closeResolve, closeReject) => {
          server.close((error) => (error ? closeReject(error) : closeResolve()));
        });
        return closePromise;
      };
      resolve({
        url: `http://127.0.0.1:${info.port}`,
        port: info.port,
        address: info.address,
        ledger,
        account,
        paymentPolicy,
        close,
      });
    });
  });
}

// Standalone: `npm run proxy`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const trust = loadPinnedCollarTrust(process.env);
  const { url, account } = await startProxy({
    port: Number(process.env.PROXY_PORT || 8402),
    ...trust,
  });
  console.log(`[proxy] Wielder wallet ${account.address} paying at ${url} (/v1/* -> gateway, /invoke/* -> collar, /ledger)`);
}

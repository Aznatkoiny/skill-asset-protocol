// proxy.mjs — Wielder-side payment transport skeleton for this spike.
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ THIS FILE COVERS THE SPIKE'S X402 CHALLENGE, SIGN, AND RETRY TRANSPORT.    ║
// ║                                                                          ║
// ║ It also verifies pinned Collar receipts and maintains a payer-local      ║
// ║ receipt view. It is not the complete protocol, accounting authority,     ║
// ║ custody design, or proof that ADR-0008 is production-ready. Plan 6       ║
// ║ payment policy is not implemented here.                                  ║
// ╚══════════════════════════════════════════════════════════════════════════╝

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { formatUsdc } from '../../../prototype/atomic-money.mjs';
import { loadAccount } from './wallet.mjs';
import { createLedger, renderLedger } from './ledger.mjs';
import { receiptKeyId, verifySignedReceipt } from './invocation-journal.mjs';

// EIP-712 typed data for EIP-3009 transferWithAuthorization — the single
// signature that IS the payment. (Constants restated here on purpose: the
// Wielder must be self-contained, importing nothing from the seller side.)
const CHAIN_ID = 84532; // Base Sepolia
const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' }, { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
  ],
};
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const unb64 = (s) => JSON.parse(Buffer.from(s, 'base64').toString('utf8'));

// Buyer transport loop used by this spike: request -> 402 -> sign EIP-3009 -> retry once.
// Returns the accepted quote/authorization identity with the response. Timings are the spike's
// payment-overhead measurement (402 roundtrip + sign + facilitator).
export async function payingFetch(account, url, init, {
  fetchImpl = fetch,
  idempotencyKey = crypto.randomUUID(),
} = {}) {
  const requestHeaders = { ...init.headers, 'Idempotency-Key': idempotencyKey };
  const t0 = performance.now();
  const first = await fetchImpl(url, { ...init, headers: requestHeaders });
  if (first.status !== 402) return { res: first, paid: false, idempotencyKey };
  const ms402 = performance.now() - t0;

  // The 402 body carries PaymentRequirements; we accept the first offer.
  const { accepts } = await first.json();
  const req = accepts?.[0];
  if (!req || req.scheme !== 'exact') throw new Error('402 without a usable "exact" payment offer');

  // Sign the USDC transfer authorization. Pure local cryptography — this is
  // the only "wallet" action the Wielder ever performs.
  const tSign = performance.now();
  const now = Math.floor(Date.now() / 1000);
  const authorization = {
    from: account.address,
    to: req.payTo,
    value: req.maxAmountRequired,                       // atomic USDC
    validAfter: String(now - 60),                       // clock-skew slack
    validBefore: String(now + (req.maxTimeoutSeconds ?? 60)),
    nonce: `0x${crypto.randomBytes(32).toString('hex')}`, // random EIP-3009 nonce = replay protection
  };
  const signature = await account.signTypedData({
    domain: { name: req.extra?.name, version: req.extra?.version, chainId: CHAIN_ID, verifyingContract: req.asset },
    types: EIP3009_TYPES,
    primaryType: 'TransferWithAuthorization',
    message: { ...authorization, value: BigInt(authorization.value), validAfter: BigInt(authorization.validAfter), validBefore: BigInt(authorization.validBefore) },
  });
  const msSign = performance.now() - tSign;

  // Retry with X-PAYMENT. The seller verifies + settles via its facilitator.
  const xPayment = b64({ x402Version: 1, scheme: 'exact', network: req.network, payload: { signature, authorization } });
  const tRetry = performance.now();
  const res = await fetchImpl(url, {
    ...init,
    headers: { ...requestHeaders, 'X-PAYMENT': xPayment },
  });
  const msPaidRoundtrip = performance.now() - tRetry;
  const msFacilitator = Number(res.headers.get('X-402-FACILITATOR-MS') ?? NaN); // seller-reported verify+settle
  const paymentResponse = res.headers.get('X-PAYMENT-RESPONSE');
  const settlement = paymentResponse ? unb64(paymentResponse) : null;
  return {
    res,
    paid: true,
    xPayment,
    idempotencyKey,
    settlementReference: authorization.nonce.toLowerCase(),
    txHash: settlement?.transaction ?? null,
    payer: account.address.toLowerCase(),
    requestHash: req.extra.requestHash,
    quoteId: req.extra.quoteId,
    amountAtomic: String(req.maxAmountRequired),
    amountDisplay: formatUsdc(BigInt(req.maxAmountRequired)),
    timings: { ms402, msSign, msFacilitator, msPaidRoundtrip, msOverhead: ms402 + msSign + (msFacilitator || 0) },
  };
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
  if (!receipt
      || receipt.schemaVersion !== 1
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
} = {}) {
  if (!trustedCollarPublicKeyPem || !trustedCollarKeyId) {
    throw new Error('Skill routes require a pinned Collar public key and key ID');
  }
  if (receiptKeyId(trustedCollarPublicKeyPem) !== trustedCollarKeyId) {
    throw new Error('pinned Collar public key and key ID do not match');
  }
  const ledger = createLedger(ledgerFile);
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
    }, { fetchImpl });
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

  return { app, ledger, account };
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startProxy({ port = 0, ...opts } = {}) {
  const { app, ledger, account } = createProxy(opts);
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

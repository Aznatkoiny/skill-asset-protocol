// proxy.mjs — THE WIELDER.
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ THIS FILE IS THE ENTIRE WIELDER-SIDE PROTOCOL FOOTPRINT.                  ║
// ║                                                                          ║
// ║ Everything a client needs in order to consume BOTH asset classes         ║
// ║ (per-call model inference AND hosted-skill invocations) is below:        ║
// ║ answer HTTP 402 with a signed USDC payment and retry. No Story SDK,      ║
// ║ no token custody, no chain reads. The harness (Pi) never sees any of     ║
// ║ it — it just talks OpenAI-compatible HTTP to localhost. That is          ║
// ║ ADR-0008 ("the Wielder is a wallet, not a harness") proved by            ║
// ║ construction. Precedent: BlockRun's ClawRouter runs the same paying-     ║
// ║ proxy pattern for OpenClaw on port 8402.                                 ║
// ╚══════════════════════════════════════════════════════════════════════════╝

import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { formatUsdc } from '../../../prototype/atomic-money.mjs';
import { loadAccount } from './wallet.mjs';
import { createLedger, renderLedger } from './ledger.mjs';

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

// The whole buyer protocol: request -> 402 -> sign EIP-3009 -> retry once.
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

export function createProxy({
  account = loadAccount(),
  gatewayUrl = process.env.GATEWAY_URL || 'http://127.0.0.1:8403',
  collarUrl = process.env.COLLAR_URL || 'http://127.0.0.1:8404',
  ledgerFile = process.env.LEDGER_FILE ?? null,
} = {}) {
  const ledger = createLedger(ledgerFile);
  const app = new Hono();

  // One handler for both asset classes: /v1/* -> inference gateway (leg:
  // "model"), /invoke/* -> collar (leg: "skill"). Same wallet, same ledger.
  const forward = (upstreamBase, leg) => async (c) => {
    const path = c.req.path;
    const bodyText = await c.req.text();
    const { res, paid, xPayment, amountUSDC, timings } = await payingFetch(account, `${upstreamBase}${path}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: bodyText,
    });
    const resBody = await res.text();

    if (paid && res.ok) {
      let parsed = {};
      try { parsed = JSON.parse(resBody); } catch { /* SSE bodies are not JSON */ }
      const model = JSON.parse(bodyText || '{}').model ?? '';
      const label = leg === 'skill'
        ? `skill/${path.split('/').pop()}`
        : `${model.startsWith('claude') ? 'claude' : 'gpt'}/${c.req.header('x-session-label') || 'chat'}`;
      ledger.record({
        leg, label, amountUSDC,
        txHash: unb64(res.headers.get('X-PAYMENT-RESPONSE')).transaction,
        splits: parsed.receipt?.splits ?? null, // royalty breakdown rides back on the skill leg only
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

  app.post('/v1/*', forward(gatewayUrl, 'model'));
  app.post('/invoke/*', forward(collarUrl, 'skill'));

  // The unified session ledger — what Pi's /ledger command renders.
  app.get('/ledger', (c) =>
    c.req.query('format') === 'json' ? c.json(ledger.entries) : c.text(renderLedger(ledger.entries)));

  return { app, ledger, account };
}

/** Boot helper shared by the standalone script and e2e.mjs. */
export function startProxy({ port = 0, ...opts } = {}) {
  const { app, ledger, account } = createProxy(opts);
  return new Promise((resolve) => {
    const server = serve({ fetch: app.fetch, port }, (info) => {
      resolve({ url: `http://127.0.0.1:${info.port}`, port: info.port, ledger, account, close: () => server.close() });
    });
  });
}

// Standalone: `npm run proxy`
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { url, account } = await startProxy({ port: Number(process.env.PROXY_PORT || 8402) });
  console.log(`[proxy] Wielder wallet ${account.address} paying at ${url} (/v1/* -> gateway, /invoke/* -> collar, /ledger)`);
}

// x402-seller.mjs — the SELLER half of the x402 protocol, written out by hand.
//
// Both paid services in this spike (collar.mjs, gateway.mjs) gate their routes
// with the `x402Paywall` Hono middleware below. We deliberately implement the
// x402 v1 "exact" scheme manually instead of pulling in `@x402/hono`:
// the published 2.x packages implement protocol v2 (class-based scheme
// registries, facilitator sync-on-start) while the free no-auth testnet
// facilitator at https://x402.org/facilitator speaks v1 — and, for a spike,
// spelling the handshake out is the argument. The whole protocol is ~100
// commented lines.
//
// The seller flow (this file), per the x402 v1 spec:
//   1. Request arrives without an X-PAYMENT header
//        -> respond 402 with { x402Version: 1, accepts: [PaymentRequirements] }.
//   2. Client retries with X-PAYMENT: base64(JSON payment payload)
//        -> POST facilitator /verify  (checks the EIP-3009 signature + funds)
//        -> POST facilitator /settle  (broadcasts transferWithAuthorization;
//                                      the settled txHash is the receipt)
//   3. The settled txHash is treated as a SINGLE-USE EXECUTION CREDENTIAL:
//      it goes into an in-memory consumed-set and any replay of the same
//      payment is rejected. (On a real chain the EIP-3009 nonce makes the
//      replayed /settle fail anyway; the consumed-set makes the same property
//      hold under the mock facilitator, and models the protocol's
//      "no credential, no run" rule explicitly.)
//   4. Only then does the resource handler run. Success responses carry an
//      X-PAYMENT-RESPONSE header (base64 settlement receipt) so the buyer
//      learns the txHash.
//
// NOTE we settle BEFORE executing the resource. Production middleware usually
// executes first and settles after (so a crashed handler doesn't charge the
// buyer); the collar wants the opposite order because the txHash *is* the
// execution credential — pay -> mint -> consume -> execute, exactly the
// sequence in prototype/settlement-engine.mjs.

// --- x402 v1 / Base Sepolia constants -------------------------------------
export const X402_VERSION = 1;
export const NETWORK = 'base-sepolia';
export const CHAIN_ID = 84532;
// Circle's canonical USDC deployment on Base Sepolia (6 decimals).
export const USDC_ADDRESS = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
// EIP-712 domain values USDC uses for EIP-3009 signatures.
export const USDC_EIP712 = { name: 'USDC', version: '2' };
export const USDC_DECIMALS = 6;

export const usdcToAtomic = (usdc) => String(Math.round(Number(usdc) * 10 ** USDC_DECIMALS));
export const atomicToUsdc = (atomic) => Number(atomic) / 10 ** USDC_DECIMALS;

const b64ToJson = (s) => JSON.parse(Buffer.from(s, 'base64').toString('utf8'));
const jsonToB64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');

/**
 * Hono middleware that 402-gates a route.
 *
 * @param {object} opts
 * @param {number|function} opts.price   price in USDC (e.g. 0.25), or an async
 *                                       (honoContext) => number for per-request pricing
 * @param {string}  opts.payTo           address the USDC authorization must pay
 * @param {string}  opts.facilitatorUrl  x402 facilitator base URL (/verify, /settle)
 * @param {string}  opts.description     human-readable description in the 402 offer
 *
 * On success, the settlement receipt is exposed to the downstream handler as
 * c.get('x402') = { txHash, payer, amountUsdc, requirements }.
 */
export function x402Paywall({ price, payTo, facilitatorUrl, description = '' }) {
  const consumed = new Set(); // settled txHash -> already-used execution credentials

  return async (c, next) => {
    const priceUsdc = typeof price === 'function' ? await price(c) : price;
    const requirements = {
      scheme: 'exact',
      network: NETWORK,
      maxAmountRequired: usdcToAtomic(priceUsdc), // atomic USDC (6 decimals)
      resource: c.req.url,
      description,
      mimeType: 'application/json',
      payTo,
      maxTimeoutSeconds: 60,
      asset: USDC_ADDRESS,
      // The buyer needs these to build the EIP-712 domain it signs against.
      extra: { name: USDC_EIP712.name, version: USDC_EIP712.version },
    };

    // -- step 1: no payment attached -> challenge with 402 ------------------
    const paymentHeader = c.req.header('X-PAYMENT');
    if (!paymentHeader) {
      return c.json(
        { x402Version: X402_VERSION, error: 'X-PAYMENT header is required', accepts: [requirements] },
        402,
      );
    }

    // -- step 2: decode + verify + settle through the facilitator -----------
    let paymentPayload;
    try {
      paymentPayload = b64ToJson(paymentHeader);
    } catch {
      return c.json({ x402Version: X402_VERSION, error: 'malformed X-PAYMENT header', accepts: [requirements] }, 402);
    }

    const facilitatorBody = { x402Version: X402_VERSION, paymentPayload, paymentRequirements: requirements };
    const tFacilitator = performance.now(); // measured so the buyer can report verify+settle overhead
    const verify = await postJson(`${facilitatorUrl}/verify`, facilitatorBody);
    if (!verify?.isValid) {
      return c.json(
        { x402Version: X402_VERSION, error: `payment verification failed: ${verify?.invalidReason ?? 'unknown'}`, accepts: [requirements] },
        402,
      );
    }

    const settle = await postJson(`${facilitatorUrl}/settle`, facilitatorBody);
    const facilitatorMs = performance.now() - tFacilitator;
    if (!settle?.success) {
      return c.json(
        { x402Version: X402_VERSION, error: `payment settlement failed: ${settle?.errorReason ?? 'unknown'}`, accepts: [requirements] },
        402,
      );
    }

    // -- step 3: the settled txHash is a single-use credential --------------
    if (consumed.has(settle.transaction)) {
      // "NO CREDENTIAL, NO RUN" — a credential spends exactly once.
      return c.json({ error: 'replayed payment: credential already consumed', txHash: settle.transaction }, 409);
    }
    consumed.add(settle.transaction);

    // -- step 4: run the resource with the receipt in scope -----------------
    c.set('x402', {
      txHash: settle.transaction,
      payer: settle.payer ?? paymentPayload?.payload?.authorization?.from,
      amountUsdc: atomicToUsdc(requirements.maxAmountRequired),
      requirements,
    });
    await next();

    // Buyer-visible settlement receipt (standard x402 response header) plus a
    // spike-only timing header so the buyer can attribute verify+settle cost.
    c.res.headers.set(
      'X-PAYMENT-RESPONSE',
      jsonToB64({ success: true, transaction: settle.transaction, network: NETWORK, payer: settle.payer }),
    );
    c.res.headers.set('X-402-FACILITATOR-MS', facilitatorMs.toFixed(1));
  };
}

async function postJson(url, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return res.json().catch(() => null);
}

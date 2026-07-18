// facilitator-mock.mjs — an in-process stand-in for https://x402.org/facilitator
// (MOCK_FACILITATOR=1). Zero network, zero keys, zero funds.
//
// It is deliberately NOT a rubber stamp:
//   /verify  really recovers the EIP-712 signer of the EIP-3009
//            TransferWithAuthorization (pure secp256k1 — no chain needed) and
//            checks it against `authorization.from`, the payee, the amount and
//            the validity window. So even offline, a forged or mis-signed
//            payment is rejected and the buyer-side signing code is genuinely
//            exercised. The only thing we cannot check offline is whether the
//            payer actually holds USDC.
//   /settle  fakes the on-chain broadcast. The fake txHash is a DETERMINISTIC
//            hash of the payment payload, which preserves the real chain's
//            replay property: re-settling the same authorization yields the
//            same txHash, so the seller's consumed-set rejects it (on the real
//            chain the reused EIP-3009 nonce would make /settle revert).

import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { recoverTypedDataAddress, keccak256, toHex } from 'viem';
import { X402_VERSION, NETWORK, CHAIN_ID } from './x402-seller.mjs';

// Identical types/domain to what the buyer signs in proxy.mjs.
const EIP3009_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
};

export function createMockFacilitator() {
  const app = new Hono();

  app.post('/verify', async (c) => {
    const { paymentPayload, paymentRequirements: req } = await c.req.json();
    const auth = paymentPayload?.payload?.authorization;
    const signature = paymentPayload?.payload?.signature;
    const fail = (reason) => c.json({ isValid: false, invalidReason: reason });

    if (paymentPayload?.x402Version !== X402_VERSION) return fail('unsupported x402Version');
    if (paymentPayload?.scheme !== 'exact' || paymentPayload?.network !== NETWORK) return fail('scheme/network mismatch');
    if (!auth || !signature) return fail('missing authorization or signature');
    if (auth.to?.toLowerCase() !== req?.payTo?.toLowerCase()) return fail('authorization pays the wrong address');
    if (String(auth.value) !== String(req.maxAmountRequired)) return fail('authorization amount must equal price');
    const now = Math.floor(Date.now() / 1000);
    if (now <= Number(auth.validAfter) || now >= Number(auth.validBefore)) return fail('authorization outside validity window');

    // The real check: who signed this? (pure crypto, no chain access)
    const signer = await recoverTypedDataAddress({
      domain: { name: req.extra.name, version: req.extra.version, chainId: CHAIN_ID, verifyingContract: req.asset },
      types: EIP3009_TYPES,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: auth.from,
        to: auth.to,
        value: BigInt(auth.value),
        validAfter: BigInt(auth.validAfter),
        validBefore: BigInt(auth.validBefore),
        nonce: auth.nonce,
      },
      signature,
    });
    if (signer.toLowerCase() !== auth.from.toLowerCase()) return fail('signature does not match payer');

    return c.json({ isValid: true, payer: auth.from });
  });

  app.post('/settle', async (c) => {
    const { paymentPayload } = await c.req.json();
    const auth = paymentPayload?.payload?.authorization;
    if (!auth) return c.json({ success: false, errorReason: 'missing authorization' });
    // Deterministic fake txHash: same authorization -> same "transaction",
    // which is what makes replay detection meaningful in mock mode.
    const txHash = keccak256(toHex(JSON.stringify(auth) + (paymentPayload.payload.signature ?? '')));
    return c.json({ success: true, transaction: txHash, network: NETWORK, payer: auth.from });
  });

  return app;
}

/** Boot on an ephemeral (or given) port; resolves to { url, close }. */
export function startMockFacilitator(port = 0) {
  return new Promise((resolve) => {
    const server = serve({ fetch: createMockFacilitator().fetch, port }, (info) => {
      resolve({ url: `http://127.0.0.1:${info.port}`, close: () => server.close() });
    });
  });
}

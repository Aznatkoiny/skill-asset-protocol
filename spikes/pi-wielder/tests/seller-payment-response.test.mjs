import assert from 'node:assert/strict';
import test from 'node:test';

import { Hono } from 'hono';
import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  createPaymentPolicy,
} from '../src/payment-policy.mjs';
import { payingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport, x402Paywall } from '../src/x402-seller.mjs';

const URL = 'http://seller.test/resource';
const PAYEE = '0x000000000000000000000000000000000000dead';

test('seller settlement response binds the complete signed authorization and quote identity', async () => {
  const facilitator = createMockFacilitator();
  const app = new Hono();
  app.post('/resource', x402Paywall({
    price: '0.25',
    payTo: PAYEE,
    facilitatorTransport: createMockFacilitatorTransport(
      (url, init) => facilitator.request(url, init),
    ),
  }), (c) => c.json({ output: 'released only after exact settlement validation' }));
  const paymentPolicy = createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '250000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    sellers: [{
      origin: 'http://seller.test',
      pathPrefix: '/resource',
      payTo: PAYEE,
      maxPerCallAtomic: '250000',
    }],
  });
  const result = await payingFetch(throwawayAccount(), URL, {
    method: 'POST', body: '{}',
  }, {
    idempotencyKey: 'idem-complete-settlement',
    paymentPolicy,
    fetchImpl: (url, init) => app.request(url, init),
  });
  const evidence = JSON.parse(Buffer.from(
    result.res.headers.get('X-PAYMENT-RESPONSE'), 'base64',
  ).toString('utf8'));
  assert.deepEqual(Object.keys(evidence).sort(), [
    'asset', 'authorizationId', 'chainId', 'idempotencyKey', 'network', 'nonce', 'payTo',
    'payer', 'quoteId', 'requestHash', 'settlementReference', 'success', 'transaction', 'value',
  ].sort());
  assert.equal(evidence.authorizationId, 'idem-complete-settlement');
  assert.equal(evidence.idempotencyKey, 'idem-complete-settlement');
  assert.equal(evidence.chainId, 84532);
  assert.equal(evidence.asset, BASE_SEPOLIA_USDC);
  assert.equal(evidence.payTo, PAYEE);
  assert.equal(evidence.value, '250000');
  assert.equal(evidence.requestHash, result.requestHash);
  assert.equal(evidence.quoteId, result.quoteId);
  assert.equal(evidence.nonce, result.settlementReference);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { createGateway, MODEL_PRICES_USDC } from '../src/gateway.mjs';
import { payingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';

test('gateway prices are decimal strings and the injected transport stays in process', async () => {
  assert.ok(Object.values(MODEL_PRICES_USDC).every((price) => typeof price === 'string'));
  const facilitator = createMockFacilitator();
  const facilitatorTransport = createMockFacilitatorTransport((url, init) => facilitator.request(url, init));
  const gateway = createGateway({ facilitatorTransport, mockLlm: true });
  const paid = await payingFetch(throwawayAccount(), 'http://gateway.test/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: 'claude-sonnet-4-6', messages: [] }),
  }, {
    fetchImpl: (url, init) => gateway.request(url, init),
    idempotencyKey: 'idem-gateway',
  });
  assert.equal(paid.res.status, 200);
  assert.equal(paid.amountAtomic, '41000');
  assert.equal(paid.amountDisplay, '0.041000');
});

test('gateway rejects an unapproved structural transport or legacy facilitator URL', () => {
  assert.throws(() => createGateway({
    facilitatorTransport: { mode: 'mock', baseUrl: 'http://facilitator.invalid', fetchImpl: fetch },
    mockLlm: true,
  }), /approved live or injected-mock/);
  assert.throws(() => createGateway({ facilitatorUrl: 'https://evil.test', mockLlm: true }), /facilitatorTransport/);
});

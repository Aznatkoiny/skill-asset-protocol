import assert from 'node:assert/strict';
import test from 'node:test';

import { createMockFacilitator } from '../src/facilitator-mock.mjs';
import { createGateway, MODEL_PRICES_USDC, startGateway } from '../src/gateway.mjs';
import { payingFetch as policyPayingFetch } from '../src/proxy.mjs';
import { throwawayAccount } from '../src/wallet.mjs';
import { createMockFacilitatorTransport } from '../src/x402-seller.mjs';
import { paymentPolicyFor } from './payment-policy-fixture.mjs';

const payingFetch = (account, url, init, options = {}) => policyPayingFetch(account, url, init, {
  paymentPolicy: paymentPolicyFor(url),
  ...options,
});

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

test('gateway listener binds only IPv4 loopback and closes cleanly', async () => {
  const facilitator = createMockFacilitator();
  const gateway = await startGateway({
    facilitatorTransport: createMockFacilitatorTransport(
      (url, init) => facilitator.request(url, init),
    ),
    mockLlm: true,
  });
  try {
    assert.equal(gateway.address, '127.0.0.1');
    assert.equal(new URL(gateway.url).hostname, '127.0.0.1');
    assert.equal((await fetch(`${gateway.url}/healthz`)).status, 200);
  } finally {
    await gateway.close();
  }
});

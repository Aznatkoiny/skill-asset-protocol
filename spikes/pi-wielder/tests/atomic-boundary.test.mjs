import assert from 'node:assert/strict';
import test from 'node:test';

import { atomicToUsdc, usdcToAtomic } from '../src/x402-seller.mjs';

test('x402 monetary conversion accepts decimal strings and returns canonical strings only', () => {
  assert.equal(usdcToAtomic('0.25'), '250000');
  assert.equal(usdcToAtomic('0.000001'), '1');
  assert.equal(atomicToUsdc('250000'), '0.250000');
  assert.throws(() => usdcToAtomic(0.25), /decimal string|must be a string/);
  assert.throws(() => usdcToAtomic('0.0000001'), /six fractional digits/);
});

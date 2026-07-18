import {
  BASE_SEPOLIA_CHAIN_ID,
  BASE_SEPOLIA_NETWORK,
  BASE_SEPOLIA_USDC,
  createPaymentPolicy,
} from '../src/payment-policy.mjs';

export const DEFAULT_TEST_PAYEE = '0x000000000000000000000000000000000000dead';

export function paymentPolicyFor(requestUrl, payTo = DEFAULT_TEST_PAYEE) {
  const parsed = new URL(requestUrl);
  const pathPrefix = parsed.pathname.startsWith('/invoke/') ? '/invoke/'
    : parsed.pathname.startsWith('/v1/') ? '/v1/'
    : parsed.pathname;
  return createPaymentPolicy({
    network: BASE_SEPOLIA_NETWORK,
    chainId: BASE_SEPOLIA_CHAIN_ID,
    asset: BASE_SEPOLIA_USDC,
    sessionBudgetAtomic: '1000000000',
    maxQuoteAgeMs: 5_000,
    maxAuthorizationSeconds: 60,
    sellers: [{
      origin: parsed.origin,
      pathPrefix,
      payTo,
      maxPerCallAtomic: '1000000000',
    }],
  });
}

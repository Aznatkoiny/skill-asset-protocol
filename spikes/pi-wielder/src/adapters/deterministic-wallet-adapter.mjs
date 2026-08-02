import { getAddress } from 'viem';

import {
  assertPermitMatchesPayment,
  createDeadlineRunner,
  executeAuthorizedSigning,
  validateWalletIdentity,
} from './wallet-adapter-contract.mjs';
import { buildEip3009Exact } from './eip3009-exact.mjs';

/**
 * Offline Wallet Adapter used only by deterministic tests and evidence runs.
 * Mode selection belongs to the process composition root; this adapter has no
 * environment, provider SDK, transport, or network surface.
 */
export function createDeterministicWalletAdapter({
  identity,
  verifyAndConsume,
  signTypedData,
  runWithDeadline = createDeadlineRunner(),
  preSignTimeoutMs = 5_000,
  signerTimeoutMs = 15_000,
  nowMs = Date.now,
}) {
  const normalizedIdentity = validateWalletIdentity(identity);

  return Object.freeze({
    async walletIdentity() {
      return structuredClone(normalizedIdentity);
    },

    async signX402Exact(authorizedPermit, paymentRequired) {
      return await executeAuthorizedSigning({
        runWithDeadline,
        preSignTimeoutMs,
        signerTimeoutMs,
        prepare: async () => {
          if (typeof nowMs !== 'function') throw new Error('wallet signing clock is invalid');
          const signingNowMs = nowMs();
          if (!Number.isSafeInteger(signingNowMs) || signingNowMs < 0) {
            throw new Error('wallet signing clock returned an invalid value');
          }
          const issuedBinding = verifyAndConsume(authorizedPermit);
          const binding = assertPermitMatchesPayment(
            issuedBinding,
            paymentRequired,
            undefined,
          );
          if (getAddress(normalizedIdentity.address) !== getAddress(binding.walletAddress)) {
            throw new Error('wallet identity mismatch');
          }
          return Object.freeze({
            exact: buildEip3009Exact({ binding, paymentRequired, nowMs: signingNowMs }),
          });
        },
        invokeSigner: ({ exact }) => signTypedData(exact.typedData),
        finalize: async ({ exact }, signature) => Object.freeze({
          paymentPayload: await exact.assemble(signature),
        }),
      });
    },
  });
}

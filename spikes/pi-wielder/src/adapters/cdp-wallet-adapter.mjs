import { getAddress } from 'viem';

import {
  assertPermitMatchesPayment,
  createDeadlineRunner,
  executeAuthorizedSigning,
  validateWalletIdentity,
} from './wallet-adapter-contract.mjs';
import { buildEip3009Exact } from './eip3009-exact.mjs';
import { canonicalToken, KernelError } from '../kernel/canonical.mjs';

const BASE_SEPOLIA_CAIP2 = 'eip155:84532';

function configurationFailure() {
  throw new KernelError(
    'CDP_WALLET_ADAPTER_CONFIG',
    'CDP wallet adapter configuration is invalid',
  );
}

function captureClient(cdpClient) {
  try {
    if (!cdpClient || (typeof cdpClient !== 'object' && typeof cdpClient !== 'function')) {
      return configurationFailure();
    }
    const evm = cdpClient.evm;
    if (!evm || (typeof evm !== 'object' && typeof evm !== 'function')) {
      return configurationFailure();
    }
    const getAccount = evm.getAccount;
    if (typeof getAccount !== 'function') return configurationFailure();
    return Object.freeze({ evm, getAccount });
  } catch {
    return configurationFailure();
  }
}

function callable(value) {
  if (typeof value !== 'function') return configurationFailure();
  return value;
}

function positiveMilliseconds(value) {
  if (!Number.isSafeInteger(value) || value < 1) return configurationFailure();
  return value;
}

/**
 * Live-shaped CDP Wallet Adapter.
 *
 * The adapter can retrieve only an already-provisioned named account and can
 * sign only the Kernel-constructed EIP-3009 authorization. Account creation,
 * arbitrary signing, transaction sending, and provider handles are absent from
 * its public surface.
 */
export function createCdpWalletAdapter({
  cdpClient,
  walletName,
  verifyAndConsume,
  runWithDeadline = createDeadlineRunner(),
  preSignTimeoutMs = 5_000,
  signerTimeoutMs = 15_000,
  nowMs = Date.now,
}) {
  const client = captureClient(cdpClient);
  let normalizedWalletName;
  try {
    normalizedWalletName = canonicalToken(walletName, 'CDP wallet name');
  } catch {
    return configurationFailure();
  }
  const consumePermit = callable(verifyAndConsume);
  const deadline = callable(runWithDeadline);
  const signingClock = callable(nowMs);
  const identityTimeoutMs = positiveMilliseconds(preSignTimeoutMs);
  const signingTimeoutMs = positiveMilliseconds(signerTimeoutMs);

  let accountPromise;
  const account = () => {
    accountPromise ??= Promise.resolve().then(() => Reflect.apply(
      client.getAccount,
      client.evm,
      [{ name: normalizedWalletName }],
    ));
    return accountPromise;
  };

  const publicIdentity = async () => {
    const value = await account();
    return validateWalletIdentity({
      provider: 'coinbase-cdp',
      walletId: normalizedWalletName,
      address: value.address,
      network: BASE_SEPOLIA_CAIP2,
    });
  };

  return Object.freeze({
    async walletIdentity() {
      const identity = await deadline({
        phase: 'wallet_identity',
        timeoutMs: identityTimeoutMs,
        operation: publicIdentity,
      });
      return structuredClone(identity);
    },

    async signX402Exact(authorizedPermit, paymentRequired) {
      return await executeAuthorizedSigning({
        runWithDeadline: deadline,
        preSignTimeoutMs: identityTimeoutMs,
        signerTimeoutMs: signingTimeoutMs,
        prepare: async () => {
          const sampledNowMs = signingClock();
          if (!Number.isSafeInteger(sampledNowMs) || sampledNowMs < 0) {
            throw new KernelError(
              'CDP_WALLET_CLOCK',
              'CDP wallet signing clock returned an invalid value',
            );
          }
          const issuedBinding = consumePermit(authorizedPermit);
          const binding = assertPermitMatchesPayment(
            issuedBinding,
            paymentRequired,
            undefined,
            sampledNowMs,
          );
          const value = await account();
          const identity = validateWalletIdentity({
            provider: 'coinbase-cdp',
            walletId: normalizedWalletName,
            address: value.address,
            network: BASE_SEPOLIA_CAIP2,
          });
          if (getAddress(identity.address) !== getAddress(binding.walletAddress)) {
            throw new KernelError(
              'CDP_WALLET_IDENTITY_MISMATCH',
              'CDP wallet identity does not match the AuthorizedPermit',
            );
          }
          const signTypedData = value.signTypedData;
          if (typeof signTypedData !== 'function') {
            throw new KernelError(
              'CDP_WALLET_SIGNER',
              'CDP wallet account does not expose typed-data signing',
            );
          }
          return Object.freeze({
            exact: buildEip3009Exact({
              binding,
              paymentRequired,
              nowMs: sampledNowMs,
            }),
            invoke: (typedData) => Reflect.apply(signTypedData, value, [typedData]),
          });
        },
        invokeSigner: ({ exact, invoke }) => invoke(exact.typedData),
        finalize: async ({ exact }, signature) => Object.freeze({
          paymentPayload: await exact.assemble(signature),
        }),
      });
    },
  });
}

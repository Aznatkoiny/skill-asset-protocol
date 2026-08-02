import { authorizationTypes } from '@x402/evm';
import { getAddress } from 'viem';

import { exactRecord, frozenCopy } from '../kernel/canonical.mjs';
import { projectPaymentRequired } from '../kernel/policy-engine.mjs';
import {
  assertPermitMatchesPayment,
  validatePaymentPayload,
} from './wallet-adapter-contract.mjs';

export const BASE_SEPOLIA_CAIP2 = 'eip155:84532';
export const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
export const BASE_SEPOLIA_USDC_EIP712_NAME = 'USDC';
export const BASE_SEPOLIA_USDC_EIP712_VERSION = '2';

const BASE_SEPOLIA_CHAIN_ID = 84532;

export function buildEip3009Exact(value) {
  const request = exactRecord(
    value,
    ['binding', 'paymentRequired', 'nowMs'],
    [],
    'WALLET_BINDING',
    'EIP-3009 construction request',
  );
  const binding = assertPermitMatchesPayment(
    request.binding,
    request.paymentRequired,
    request.binding.acceptedIndex,
    request.nowMs,
  );
  const projection = projectPaymentRequired(request.paymentRequired);
  const accepted = projection.accepts[binding.acceptedIndex];
  const normalizedPaymentRequired = frozenCopy({
    x402Version: 2,
    resource: {
      url: binding.requestUrl,
      description: binding.resourceDescription,
      mimeType: binding.resourceMimeType,
    },
    accepts: projection.accepts,
  });
  const authorization = frozenCopy({
    from: binding.walletAddress,
    to: binding.payTo,
    value: binding.amountAtomic,
    validAfter: binding.validAfter,
    validBefore: binding.validBefore,
    nonce: binding.nonce,
  });
  const typedData = frozenCopy({
    domain: {
      name: BASE_SEPOLIA_USDC_EIP712_NAME,
      version: BASE_SEPOLIA_USDC_EIP712_VERSION,
      chainId: BASE_SEPOLIA_CHAIN_ID,
      verifyingContract: getAddress(BASE_SEPOLIA_USDC),
    },
    types: authorizationTypes,
    primaryType: 'TransferWithAuthorization',
    message: {
      from: getAddress(authorization.from),
      to: getAddress(authorization.to),
      value: BigInt(authorization.value),
      validAfter: BigInt(authorization.validAfter),
      validBefore: BigInt(authorization.validBefore),
      nonce: authorization.nonce,
    },
  });

  return Object.freeze({
    typedData,
    async assemble(signature) {
      return await validatePaymentPayload({
        paymentPayload: {
          x402Version: 2,
          resource: {
            url: binding.requestUrl,
            description: binding.resourceDescription,
            mimeType: binding.resourceMimeType,
          },
          accepted,
          payload: { signature, authorization },
        },
        binding,
        paymentRequired: normalizedPaymentRequired,
        typedData,
        nowMs: request.nowMs,
      });
    },
  });
}

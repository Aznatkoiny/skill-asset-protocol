import { authorizationTypes } from '@x402/evm';
import { getAddress, recoverTypedDataAddress } from 'viem';
import { types as utilTypes } from 'node:util';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { projectPaymentRequired } from '../kernel/policy-engine.mjs';

const DEADLINE_CODES = Object.freeze({
  wallet_identity: 'WALLET_IDENTITY_TIMEOUT',
  'pre-sign': 'WALLET_PRE_SIGN_TIMEOUT',
  signer: 'WALLET_SIGNER_TIMEOUT',
});
const OPERATION_FAILURE_CODES = Object.freeze({
  wallet_identity: 'WALLET_IDENTITY_OPERATION_FAILED',
  'pre-sign': 'WALLET_PRE_SIGN_OPERATION_FAILED',
  signer: 'WALLET_SIGNER_OPERATION_FAILED',
});
const BASE_SEPOLIA_CAIP2 = 'eip155:84532';
const BASE_SEPOLIA_USDC = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const LOWERCASE_ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const NONCE_PATTERN = /^0x[0-9a-f]{64}$/;
const MAX_UINT256 = (1n << 256n) - 1n;
const SECP256K1_N = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141');
const SECP256K1_HALF_N = BigInt(
  '0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0',
);
const SIGNING_BINDING_FIELDS = Object.freeze([
  'intentId',
  'intentHash',
  'challengeHash',
  'quoteId',
  'acceptedIndex',
  'requestUrl',
  'resourceDescription',
  'resourceMimeType',
  'scheme',
  'network',
  'asset',
  'walletAddress',
  'payTo',
  'amountAtomic',
  'validAfter',
  'validBefore',
  'nonce',
  'policyVersionId',
]);

function identityFailure(message) {
  throw new KernelError('WALLET_IDENTITY', message);
}

function bindingFailure(message) {
  throw new KernelError('WALLET_BINDING', message);
}

function paymentPayloadFailure(message) {
  throw new KernelError('WALLET_PAYMENT_PAYLOAD', message);
}

function inertRecord(value, required, optional, code, label) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value) || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new KernelError(code, `${label} must be one plain object`);
  }
  const allowed = new Set([...required, ...optional]);
  const keys = Reflect.ownKeys(value);
  if (required.some((key) => !Object.hasOwn(value, key))
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new KernelError(code, `${label} fields do not match the closed schema`);
  }
  const result = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new KernelError(code, `${label} fields must be enumerable data properties`);
    }
    result[key] = descriptor.value;
  }
  return Object.freeze(result);
}

function plainCallable(value, code, label) {
  if (typeof value !== 'function' || utilTypes.isProxy(value)) {
    throw new KernelError(code, `${label} must be one non-proxy function`);
  }
  return value;
}

function positiveDeadline(value, code, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new KernelError(code, `${label} must be positive safe-integer milliseconds`);
  }
  return value;
}

function signingHash(value) {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    bindingFailure('wallet signing hashes must be canonical SHA-256 values');
  }
  return value;
}

function signingAddress(value, label) {
  if (typeof value !== 'string' || !LOWERCASE_ADDRESS_PATTERN.test(value)
      || value === ZERO_ADDRESS) {
    bindingFailure(`${label} must be one nonzero canonical lowercase EVM address`);
  }
  return value;
}

function signingUint256(value, label, { positive = false } = {}) {
  let atomic;
  try {
    atomic = canonicalAtomic(value, label);
  } catch {
    return bindingFailure(`${label} must be canonical uint256 text`);
  }
  if (atomic.value > MAX_UINT256 || (positive && atomic.value === 0n)) {
    bindingFailure(`${label} is outside the permitted uint256 range`);
  }
  return atomic.text;
}

function canonicalEoaSignature(value) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{130}$/.test(value)) {
    paymentPayloadFailure('signed payment requires one canonical EOA signature');
  }
  const r = BigInt(`0x${value.slice(2, 66)}`);
  const s = BigInt(`0x${value.slice(66, 130)}`);
  const v = Number.parseInt(value.slice(130, 132), 16);
  if (r === 0n || r >= SECP256K1_N
      || s === 0n || s > SECP256K1_HALF_N
      || (v !== 27 && v !== 28)) {
    paymentPayloadFailure('signed payment requires one canonical EOA signature');
  }
  return value;
}

export function assertPermitMatchesPayment(value, paymentRequired, acceptedIndex, nowMs) {
  try {
    const binding = exactRecord(
      value,
      SIGNING_BINDING_FIELDS,
      [],
      'WALLET_BINDING',
      'wallet signing binding',
    );
    if (!Number.isSafeInteger(binding.acceptedIndex) || binding.acceptedIndex < 0
        || (acceptedIndex !== undefined && acceptedIndex !== binding.acceptedIndex)) {
      bindingFailure('accepted index does not match the AuthorizedPermit');
    }
    const selectedIndex = binding.acceptedIndex;

    const projection = projectPaymentRequired(paymentRequired);
    if (projection.x402Version !== 2 || selectedIndex >= projection.accepts.length) {
      bindingFailure('AuthorizedPermit does not select one x402 v2 payment requirement');
    }
    const accepted = projection.accepts[selectedIndex];
    const challengeHash = signingHash(binding.challengeHash);
    const quoteId = signingHash(binding.quoteId);
    if (challengeHash !== sha256(canonicalJson(projection))
        || quoteId !== sha256(canonicalJson({ challengeHash, acceptedIndex: selectedIndex }))) {
      bindingFailure('AuthorizedPermit does not match the canonical payment challenge');
    }

    let intentId;
    let policyVersionId;
    try {
      intentId = canonicalToken(binding.intentId, 'wallet signing intent ID');
      policyVersionId = canonicalToken(binding.policyVersionId, 'wallet signing policy version ID');
    } catch {
      return bindingFailure('AuthorizedPermit identity fields are not canonical tokens');
    }
    const amountAtomic = signingUint256(binding.amountAtomic, 'wallet signing amount', {
      positive: true,
    });
    const validBefore = signingUint256(binding.validBefore, 'authorization validBefore', {
      positive: true,
    });
    const walletAddress = signingAddress(binding.walletAddress, 'wallet address');
    const payTo = signingAddress(binding.payTo, 'payment recipient');
    const asset = signingAddress(binding.asset, 'payment asset');
    if (typeof binding.nonce !== 'string' || !NONCE_PATTERN.test(binding.nonce)) {
      bindingFailure('authorization nonce must be one canonical lowercase bytes32 value');
    }

    if (accepted.scheme !== 'exact'
        || accepted.network !== BASE_SEPOLIA_CAIP2
        || accepted.asset !== BASE_SEPOLIA_USDC
        || accepted.extra.name !== 'USDC'
        || accepted.extra.version !== '2'
        || (Object.hasOwn(accepted.extra, 'assetTransferMethod')
          && accepted.extra.assetTransferMethod !== 'eip3009')
        || binding.scheme !== accepted.scheme
        || binding.network !== accepted.network
        || asset !== accepted.asset
        || payTo !== accepted.payTo
        || amountAtomic !== accepted.amount
        || binding.requestUrl === ''
        || sha256(binding.requestUrl) !== projection.resource.urlHash
        || binding.resourceDescription !== projection.resource.description
        || binding.resourceMimeType !== projection.resource.mimeType
        || binding.validAfter !== '0') {
      bindingFailure('AuthorizedPermit fields do not exactly match the selected payment');
    }
    if (nowMs !== undefined) {
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
        bindingFailure('wallet signing time must be nonnegative safe-integer milliseconds');
      }
      const nowSeconds = BigInt(Math.floor(nowMs / 1_000));
      const validBeforeSeconds = BigInt(validBefore);
      const protocolDeadlineSeconds = nowSeconds + BigInt(accepted.maxTimeoutSeconds);
      if (validBeforeSeconds <= nowSeconds || validBeforeSeconds > protocolDeadlineSeconds) {
        bindingFailure('authorization validity is expired or exceeds the selected payment timeout');
      }
    }

    return frozenCopy({
      intentId,
      intentHash: signingHash(binding.intentHash),
      challengeHash,
      quoteId,
      acceptedIndex: selectedIndex,
      requestUrl: binding.requestUrl,
      resourceDescription: binding.resourceDescription,
      resourceMimeType: binding.resourceMimeType,
      scheme: 'exact',
      network: BASE_SEPOLIA_CAIP2,
      asset,
      walletAddress,
      payTo,
      amountAtomic,
      validAfter: '0',
      validBefore,
      nonce: binding.nonce,
      policyVersionId,
    });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'WALLET_BINDING') throw error;
    return bindingFailure('AuthorizedPermit or payment challenge failed closed validation');
  }
}

function validateTypedData(value, binding) {
  const typedData = exactRecord(
    value,
    ['domain', 'types', 'primaryType', 'message'],
    [],
    'WALLET_PAYMENT_PAYLOAD',
    'EIP-3009 typed data',
  );
  const domain = exactRecord(
    typedData.domain,
    ['name', 'version', 'chainId', 'verifyingContract'],
    [],
    'WALLET_PAYMENT_PAYLOAD',
    'EIP-712 domain',
  );
  const message = exactRecord(
    typedData.message,
    ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'],
    [],
    'WALLET_PAYMENT_PAYLOAD',
    'EIP-3009 message',
  );
  const types = exactRecord(
    typedData.types,
    ['TransferWithAuthorization'],
    [],
    'WALLET_PAYMENT_PAYLOAD',
    'EIP-3009 authorization types',
  );
  if (JSON.stringify(types) !== JSON.stringify(authorizationTypes)
      || typedData.primaryType !== 'TransferWithAuthorization'
      || domain.name !== 'USDC'
      || domain.version !== '2'
      || domain.chainId !== 84532
      || domain.verifyingContract !== getAddress(binding.asset)
      || message.from !== getAddress(binding.walletAddress)
      || message.to !== getAddress(binding.payTo)
      || message.value !== BigInt(binding.amountAtomic)
      || message.validAfter !== BigInt(binding.validAfter)
      || message.validBefore !== BigInt(binding.validBefore)
      || message.nonce !== binding.nonce) {
    paymentPayloadFailure('typed data does not exactly encode the AuthorizedPermit');
  }
  return frozenCopy({ domain, types, primaryType: typedData.primaryType, message });
}

function validateAcceptedPayload(value, expected) {
  const accepted = exactRecord(
    value,
    ['scheme', 'network', 'asset', 'amount', 'payTo', 'maxTimeoutSeconds', 'extra'],
    [],
    'WALLET_PAYMENT_PAYLOAD',
    'x402 accepted requirement',
  );
  const extra = exactRecord(
    accepted.extra,
    ['name', 'version'],
    ['assetTransferMethod'],
    'WALLET_PAYMENT_PAYLOAD',
    'x402 accepted requirement extra',
  );
  const normalized = { ...accepted, extra };
  if (canonicalJson(normalized) !== canonicalJson(expected)) {
    paymentPayloadFailure('signed payment changed the selected accepted requirement');
  }
  return normalized;
}

export async function validatePaymentPayload(value) {
  try {
    const request = exactRecord(
      value,
      ['paymentPayload', 'binding', 'paymentRequired', 'typedData'],
      ['nowMs'],
      'WALLET_PAYMENT_PAYLOAD',
      'payment-payload validation request',
    );
    const paymentPayload = request.paymentPayload;
    const bindingValue = request.binding;
    const paymentRequired = request.paymentRequired;
    const typedDataValue = request.typedData;
    const binding = assertPermitMatchesPayment(
      bindingValue,
      paymentRequired,
      undefined,
      request.nowMs,
    );
    const projection = projectPaymentRequired(paymentRequired);
    const expectedAccepted = projection.accepts[binding.acceptedIndex];
    const payment = exactRecord(
      paymentPayload,
      ['x402Version', 'resource', 'accepted', 'payload'],
      [],
      'WALLET_PAYMENT_PAYLOAD',
      'x402 payment payload',
    );
    const resource = exactRecord(
      payment.resource,
      ['url', 'description', 'mimeType'],
      [],
      'WALLET_PAYMENT_PAYLOAD',
      'x402 payment resource',
    );
    const accepted = validateAcceptedPayload(payment.accepted, expectedAccepted);
    const payload = exactRecord(
      payment.payload,
      ['signature', 'authorization'],
      [],
      'WALLET_PAYMENT_PAYLOAD',
      'x402 exact payload',
    );
    const authorization = exactRecord(
      payload.authorization,
      ['from', 'to', 'value', 'validAfter', 'validBefore', 'nonce'],
      [],
      'WALLET_PAYMENT_PAYLOAD',
      'EIP-3009 authorization',
    );
    const typedData = validateTypedData(typedDataValue, binding);

    if (payment.x402Version !== 2
        || resource.url !== binding.requestUrl
        || resource.description !== binding.resourceDescription
        || resource.mimeType !== binding.resourceMimeType
        || authorization.from !== binding.walletAddress
        || authorization.to !== binding.payTo
        || authorization.value !== binding.amountAtomic
        || authorization.validAfter !== binding.validAfter
        || authorization.validBefore !== binding.validBefore
        || authorization.nonce !== binding.nonce
        || typeof payload.signature !== 'string') {
      paymentPayloadFailure('signed payment does not exactly match the AuthorizedPermit');
    }
    const signature = canonicalEoaSignature(payload.signature);

    let recovered;
    try {
      recovered = await recoverTypedDataAddress({ ...typedData, signature });
    } catch {
      return paymentPayloadFailure('signed payment contains an invalid EIP-3009 signature');
    }
    if (getAddress(recovered) !== getAddress(binding.walletAddress)) {
      paymentPayloadFailure('signed payment was not produced by the authorized wallet');
    }

    return frozenCopy({
      x402Version: 2,
      resource,
      accepted,
      payload: { signature, authorization },
    });
  } catch (error) {
    if (error instanceof KernelError && error.code === 'WALLET_PAYMENT_PAYLOAD') throw error;
    return paymentPayloadFailure('signed payment failed closed validation');
  }
}

export function validateWalletIdentity(value) {
  let identity;
  try {
    identity = exactRecord(
      value,
      ['provider', 'walletId', 'address', 'network'],
      [],
      'WALLET_IDENTITY',
      'wallet identity',
    );
  } catch (error) {
    if (error instanceof KernelError) identityFailure(error.message);
    throw error;
  }

  let provider;
  let walletId;
  let normalizedAddress;
  try {
    provider = canonicalToken(identity.provider, 'wallet provider');
    walletId = canonicalToken(identity.walletId, 'wallet ID');
    normalizedAddress = getAddress(identity.address);
  } catch {
    return identityFailure('wallet identity contains invalid provider, wallet ID, or address');
  }
  if (normalizedAddress.toLowerCase() === ZERO_ADDRESS || identity.network !== BASE_SEPOLIA_CAIP2) {
    identityFailure('wallet identity must name one nonzero Base Sepolia account');
  }
  return frozenCopy({
    provider,
    walletId,
    address: normalizedAddress.toLowerCase(),
    network: BASE_SEPOLIA_CAIP2,
  });
}

export class WalletSigningError extends KernelError {
  #exactConstruction;

  #stableCode;

  #stableSignatureMayExist;

  constructor(code, message, { signatureMayExist }) {
    super(code, message);
    this.#exactConstruction = new.target === WalletSigningError;
    this.#stableCode = code;
    this.#stableSignatureMayExist = signatureMayExist;
    this.name = 'WalletSigningError';
    this.signatureMayExist = signatureMayExist;
  }

  static isExact(value, code, signatureMayExist) {
    if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) return false;
    try {
      return Object.getPrototypeOf(value) === WalletSigningError.prototype
        && value.#exactConstruction
        && value.#stableCode === code
        && value.#stableSignatureMayExist === signatureMayExist;
    } catch {
      return false;
    }
  }
}

Object.freeze(WalletSigningError);

export function createDeadlineRunner(options = {}) {
  const config = inertRecord(
    options,
    [],
    ['setTimeoutImpl', 'clearTimeoutImpl'],
    'WALLET_DEADLINE_CONFIG',
    'wallet deadline configuration',
  );
  const setTimeoutImpl = plainCallable(
    Object.hasOwn(config, 'setTimeoutImpl') ? config.setTimeoutImpl : setTimeout,
    'WALLET_DEADLINE_CONFIG',
    'setTimeout implementation',
  );
  const clearTimeoutImpl = plainCallable(
    Object.hasOwn(config, 'clearTimeoutImpl') ? config.clearTimeoutImpl : clearTimeout,
    'WALLET_DEADLINE_CONFIG',
    'clearTimeout implementation',
  );

  return async function runWithDeadline(value) {
    const request = inertRecord(
      value,
      ['phase', 'timeoutMs', 'operation'],
      [],
      'WALLET_DEADLINE_REQUEST',
      'wallet deadline request',
    );
    const phase = request.phase;
    const timeoutMs = request.timeoutMs;
    const operation = plainCallable(
      request.operation,
      'WALLET_DEADLINE_REQUEST',
      'wallet deadline operation',
    );
    if (!Object.hasOwn(DEADLINE_CODES, phase)
        || !Object.hasOwn(OPERATION_FAILURE_CODES, phase)) {
      throw new KernelError('WALLET_DEADLINE_PHASE', 'unknown wallet deadline phase');
    }
    const timeoutCode = DEADLINE_CODES[phase];
    positiveDeadline(timeoutMs, 'WALLET_DEADLINE_TIMEOUT', 'wallet deadline');

    let timer;
    let deadlineFired = false;
    let deadlineError;
    const deadline = new Promise((_, reject) => {
      const rejectOnce = (error) => {
        if (deadlineFired) return;
        deadlineFired = true;
        deadlineError = error;
        reject(error);
      };
      const expire = () => {
        rejectOnce(new KernelError(
          timeoutCode,
          `${phase} wallet operation exceeded its deadline`,
        ));
      };
      try {
        timer = setTimeoutImpl(expire, timeoutMs);
      } catch {
        rejectOnce(new KernelError(
          'WALLET_DEADLINE_SETUP_FAILED',
          'wallet deadline could not be armed',
        ));
      }
    });
    const operationResult = Promise.resolve().then(() => (
      deadlineFired ? new Promise(() => {}) : operation()
    ));

    try {
      return await Promise.race([operationResult, deadline]);
    } catch (error) {
      if (error === deadlineError) throw error;
      throw new KernelError(
        OPERATION_FAILURE_CODES[phase],
        `${phase} wallet operation failed`,
      );
    } finally {
      try {
        clearTimeoutImpl(timer);
      } catch {
        // Timer cleanup cannot be allowed to suppress the operation's settled outcome.
      }
    }
  };
}

export async function executeAuthorizedSigning(value) {
  let request;
  let prepared;
  try {
    request = inertRecord(
      value,
      ['prepare', 'invokeSigner', 'finalize'],
      ['runWithDeadline', 'preSignTimeoutMs', 'signerTimeoutMs'],
      'WALLET_SIGNING_REQUEST',
      'authorized-signing request',
    );
    const prepare = plainCallable(request.prepare, 'WALLET_SIGNING_REQUEST', 'prepare callback');
    plainCallable(request.invokeSigner, 'WALLET_SIGNING_REQUEST', 'signer callback');
    plainCallable(request.finalize, 'WALLET_SIGNING_REQUEST', 'finalize callback');
    const runWithDeadline = plainCallable(
      Object.hasOwn(request, 'runWithDeadline')
        ? request.runWithDeadline
        : createDeadlineRunner(),
      'WALLET_SIGNING_REQUEST',
      'deadline runner',
    );
    const preSignTimeoutMs = positiveDeadline(
      Object.hasOwn(request, 'preSignTimeoutMs') ? request.preSignTimeoutMs : 5_000,
      'WALLET_SIGNING_REQUEST',
      'pre-sign timeout',
    );
    positiveDeadline(
      Object.hasOwn(request, 'signerTimeoutMs') ? request.signerTimeoutMs : 15_000,
      'WALLET_SIGNING_REQUEST',
      'signer timeout',
    );
    request = Object.freeze({
      ...request,
      prepare,
      runWithDeadline,
      preSignTimeoutMs,
      signerTimeoutMs: Object.hasOwn(request, 'signerTimeoutMs')
        ? request.signerTimeoutMs
        : 15_000,
    });
    prepared = await runWithDeadline({
      phase: 'pre-sign',
      timeoutMs: preSignTimeoutMs,
      operation: prepare,
    });
  } catch {
    throw new WalletSigningError(
      'WALLET_PRE_SIGN_REJECTED',
      'wallet request was rejected before signing',
      { signatureMayExist: false },
    );
  }

  try {
    let signerEntered = false;
    return await request.runWithDeadline({
      phase: 'signer',
      timeoutMs: request.signerTimeoutMs,
      operation: async () => {
        if (signerEntered) {
          throw new KernelError(
            'WALLET_SIGNER_REENTRY',
            'wallet signer operation is strictly one-shot',
          );
        }
        signerEntered = true;
        const signature = await request.invokeSigner(prepared);
        return await request.finalize(prepared, signature);
      },
    });
  } catch {
    throw new WalletSigningError(
      'WALLET_SIGNATURE_AMBIGUOUS',
      'wallet signing outcome is ambiguous',
      { signatureMayExist: true },
    );
  }
}

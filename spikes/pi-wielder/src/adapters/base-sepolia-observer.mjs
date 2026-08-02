import { types as utilTypes } from 'node:util';

import {
  decodeEventLog,
  encodeEventTopics,
  parseAbi,
} from 'viem';

import {
  canonicalAtomic,
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';
import { validatePolicyDocument } from '../kernel/policy-engine.mjs';

const CHAIN_ID = 84_532;
const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const MAX_UINT256 = (1n << 256n) - 1n;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-f]{40}$/;
const PROVIDER_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const EVM_WORD = /^0x[0-9a-f]{64}$/;
const PROVIDER_WORD = /^0x[0-9a-fA-F]{64}$/;
const HEX_BYTES = /^0x(?:[0-9a-fA-F]{2})*$/;
const ENCODED_PATH_SEPARATOR = /%(?:2f|5c)/i;

const PAYMENT_BINDING_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'intentId',
  'intentHash',
  'challengeHash',
  'quoteId',
  'network',
  'asset',
  'payer',
  'payee',
  'amountAtomic',
  'nonce',
  'validAfter',
  'validBefore',
  'paymentPayloadHash',
  'paymentHeaderHash',
  'localAttemptHash',
  'caseHash',
  'candidate',
]);
const REFUND_BINDING_FIELDS = Object.freeze([
  'schemaVersion',
  'domain',
  'intentId',
  'intentHash',
  'policyVersion',
  'seller',
  'resourcePath',
  'network',
  'sellerOrigin',
  'originalTransactionId',
  'refundTransactionId',
  'asset',
  'originalPayer',
  'originalPayee',
  'refundSource',
  'refundSigner',
  'amountAtomic',
  'localRefundBindingHash',
  'refundId',
  'caseHash',
]);
const CLIENT_METHODS = Object.freeze([
  'getChainId',
  'getBlockNumber',
  'getBlock',
  'getTransactionReceipt',
  'readContract',
]);
const PAYMENT_UNKNOWN_REASONS = new Set([
  'RPC_RECEIPT_MISSING',
  'RPC_CONFIRMATIONS_INSUFFICIENT',
  'RPC_PROVIDER_UNAVAILABLE',
  'RPC_REORG_DETECTED',
  'RPC_EVIDENCE_INVALID',
  'AUTHORIZATION_ALREADY_USED',
  'AUTHORIZATION_NOT_EXPIRED',
]);
const REFUND_UNKNOWN_REASONS = new Set([
  'RPC_RECEIPT_MISSING',
  'RPC_CONFIRMATIONS_INSUFFICIENT',
  'RPC_PROVIDER_UNAVAILABLE',
  'RPC_REORG_DETECTED',
  'RPC_EVIDENCE_INVALID',
]);

const USDC_ABI = frozenCopy(parseAbi([
  'function name() view returns (string)',
  'function version() view returns (string)',
  'function decimals() view returns (uint8)',
  'function balanceOf(address owner) view returns (uint256)',
  'function authorizationState(address authorizer, bytes32 nonce) view returns (bool)',
  'event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]));
const [AUTHORIZATION_USED_TOPIC] = encodeEventTopics({
  abi: USDC_ABI,
  eventName: 'AuthorizationUsed',
});
const [TRANSFER_TOPIC] = encodeEventTopics({
  abi: USDC_ABI,
  eventName: 'Transfer',
});

class EvidenceFault extends Error {
  constructor(reasonCode) {
    super(reasonCode);
    this.name = 'EvidenceFault';
    this.reasonCode = reasonCode;
  }
}

function failBinding() {
  throw new KernelError(
    'OBSERVER_BINDING',
    'observer input must be one valid persisted Kernel binding',
  );
}

function evidenceFault(reasonCode) {
  throw new EvidenceFault(reasonCode);
}

function exactFunctionConfiguration(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)
      || utilTypes.isProxy(input) || Object.getPrototypeOf(input) !== Object.prototype) {
    throw new KernelError('OBSERVER_CONFIG', 'observer configuration is invalid');
  }
  const allowed = new Set(['publicClient', 'now', 'minimumConfirmations']);
  const keys = Reflect.ownKeys(input);
  if (!Object.hasOwn(input, 'publicClient')
      || !Object.hasOwn(input, 'now')
      || keys.some((key) => typeof key !== 'string' || !allowed.has(key))) {
    throw new KernelError('OBSERVER_CONFIG', 'observer configuration is invalid');
  }
  const values = {};
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(input, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      throw new KernelError('OBSERVER_CONFIG', 'observer configuration is invalid');
    }
    values[key] = descriptor.value;
  }
  return values;
}

function captureClient(value) {
  if (!value || typeof value !== 'object' || utilTypes.isProxy(value)) {
    throw new KernelError('OBSERVER_CONFIG', 'read-only public client is invalid');
  }
  const captured = {};
  for (const name of CLIENT_METHODS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'function'
        || utilTypes.isProxy(descriptor.value)) {
      throw new KernelError('OBSERVER_CONFIG', 'read-only public client is invalid');
    }
    const method = descriptor.value;
    captured[name] = (...args) => Reflect.apply(method, value, args);
  }
  return Object.freeze(captured);
}

function captureClock(value) {
  if (typeof value !== 'function' || utilTypes.isProxy(value)) {
    throw new KernelError('OBSERVER_CONFIG', 'observer clock is invalid');
  }
  return () => Reflect.apply(value, undefined, []);
}

function canonicalClock(clock) {
  try {
    return canonicalTimestamp(clock(), 'observer clock');
  } catch {
    return evidenceFault('RPC_PROVIDER_UNAVAILABLE');
  }
}

function hash(value) {
  if (typeof value !== 'string' || !SHA256.test(value)) failBinding();
  return value;
}

function address(value) {
  if (typeof value !== 'string' || !ADDRESS.test(value)) failBinding();
  return value;
}

function transactionId(value) {
  if (typeof value !== 'string' || !EVM_WORD.test(value)) failBinding();
  return value;
}

function atomic(value, { positive = false } = {}) {
  let parsed;
  try {
    if (typeof value !== 'string' || value.length > 78) failBinding();
    parsed = canonicalAtomic(value, 'observer atomic value');
  } catch {
    return failBinding();
  }
  if (parsed.value > MAX_UINT256 || (positive && parsed.value === 0n)) failBinding();
  return parsed;
}

function token(value) {
  try {
    return canonicalToken(value, 'observer token');
  } catch {
    return failBinding();
  }
}

function timestamp(value) {
  try {
    return canonicalTimestamp(value, 'observer timestamp');
  } catch {
    return failBinding();
  }
}

function validatePaymentBinding(value) {
  try {
    const binding = exactRecord(
      value,
      PAYMENT_BINDING_FIELDS,
      [],
      'OBSERVER_BINDING',
      'payment observation binding',
    );
    if (binding.schemaVersion !== 1
        || binding.domain !== 'wallet-kernel.payment-observation.v1'
        || binding.network !== NETWORK
        || binding.asset !== ASSET) failBinding();
    token(binding.intentId);
    hash(binding.intentHash);
    hash(binding.challengeHash);
    hash(binding.quoteId);
    address(binding.payer);
    address(binding.payee);
    const amount = atomic(binding.amountAtomic, { positive: true });
    transactionId(binding.nonce);
    const validAfter = atomic(binding.validAfter);
    const validBefore = atomic(binding.validBefore);
    if (validBefore.value <= validAfter.value) failBinding();
    hash(binding.paymentPayloadHash);
    hash(binding.paymentHeaderHash);
    hash(binding.localAttemptHash);
    hash(binding.caseHash);

    if (binding.candidate !== null) {
      const candidate = exactRecord(
        binding.candidate,
        ['id', 'transactionId', 'state', 'createdAt'],
        [],
        'OBSERVER_BINDING',
        'payment candidate',
      );
      token(candidate.id);
      transactionId(candidate.transactionId);
      timestamp(candidate.createdAt);
      if (candidate.state !== 'pending') failBinding();
      binding.candidate = candidate;
    }

    const expectedAttemptHash = sha256(canonicalJson({
      schemaVersion: 1,
      domain: 'wallet-kernel.payment-attempt-binding.v1',
      intentHash: binding.intentHash,
      challengeHash: binding.challengeHash,
      quoteId: binding.quoteId,
      paymentPayloadHash: binding.paymentPayloadHash,
      paymentHeaderHash: binding.paymentHeaderHash,
      network: binding.network,
      payer: binding.payer,
      payee: binding.payee,
      asset: binding.asset,
      amountAtomic: amount.text,
      nonce: binding.nonce,
      validAfter: validAfter.text,
      validBefore: validBefore.text,
    }));
    if (binding.localAttemptHash !== expectedAttemptHash) failBinding();
    return frozenCopy(binding);
  } catch {
    return failBinding();
  }
}

function canonicalResourcePath(value, origin) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 2_048
      || !value.startsWith('/') || value.startsWith('//')
      || value.includes('?') || value.includes('#') || value.includes('\\')
      || ENCODED_PATH_SEPARATOR.test(value)) failBinding();
  let parsed;
  try {
    parsed = new URL(value, `${origin}/`);
  } catch {
    return failBinding();
  }
  if (parsed.origin !== origin || parsed.pathname !== value
      || parsed.search !== '' || parsed.hash !== '') failBinding();
  return value;
}

function validateRefundBinding(value) {
  try {
    const binding = exactRecord(
      value,
      REFUND_BINDING_FIELDS,
      [],
      'OBSERVER_BINDING',
      'refund observation binding',
    );
    if (binding.schemaVersion !== 1
        || binding.domain !== 'wallet-kernel.refund-observation.v1'
        || binding.network !== NETWORK
        || binding.asset !== ASSET) failBinding();
    token(binding.intentId);
    hash(binding.intentHash);
    const version = exactRecord(
      binding.policyVersion,
      ['id', 'hash', 'policy'],
      [],
      'OBSERVER_BINDING',
      'refund policy version',
    );
    token(version.id);
    hash(version.hash);
    const policy = validatePolicyDocument(version.policy);
    if (canonicalJson(policy) !== canonicalJson(version.policy)
        || sha256(canonicalJson(policy)) !== version.hash) failBinding();

    if (typeof binding.sellerOrigin !== 'string') failBinding();
    const selectedSeller = policy.sellers.find((entry) => entry.origin === binding.sellerOrigin);
    canonicalResourcePath(binding.resourcePath, binding.sellerOrigin);
    if (!selectedSeller
        || !selectedSeller.pathPrefixes.some((prefix) => binding.resourcePath.startsWith(prefix))
        || canonicalJson(selectedSeller) !== canonicalJson(binding.seller)) failBinding();

    transactionId(binding.originalTransactionId);
    transactionId(binding.refundTransactionId);
    if (binding.originalTransactionId === binding.refundTransactionId) failBinding();
    address(binding.originalPayer);
    address(binding.originalPayee);
    address(binding.refundSource);
    address(binding.refundSigner);
    const amount = atomic(binding.amountAtomic, { positive: true });
    if (binding.network !== policy.network
        || binding.asset !== policy.asset
        || binding.originalPayer !== policy.wallet
        || binding.sellerOrigin !== selectedSeller.origin
        || binding.originalPayee !== selectedSeller.payTo
        || binding.refundSource !== selectedSeller.refundSource
        || binding.refundSigner !== selectedSeller.refundSigner
        || amount.value > BigInt(selectedSeller.perRequestMaxAtomic)) failBinding();
    hash(binding.localRefundBindingHash);
    token(binding.refundId);
    hash(binding.caseHash);

    const expectedRefundHash = sha256(canonicalJson({
      schemaVersion: 1,
      domain: 'wallet-kernel.refund-binding.v1',
      intentHash: binding.intentHash,
      originalTransactionId: binding.originalTransactionId,
      refundTransactionId: binding.refundTransactionId,
      network: binding.network,
      sellerOrigin: binding.sellerOrigin,
      asset: binding.asset,
      originalPayer: binding.originalPayer,
      originalPayee: binding.originalPayee,
      refundSource: binding.refundSource,
      refundSigner: binding.refundSigner,
      amountAtomic: amount.text,
    }));
    if (binding.localRefundBindingHash !== expectedRefundHash) failBinding();
    binding.policyVersion = version;
    return frozenCopy(binding);
  } catch {
    return failBinding();
  }
}

function ordinaryDataRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || utilTypes.isProxy(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (typeof key !== 'string' || !descriptor?.enumerable
        || !Object.hasOwn(descriptor, 'value')) {
      return evidenceFault('RPC_EVIDENCE_INVALID');
    }
  }
  return value;
}

function own(value, name, optional = false) {
  const descriptor = Object.getOwnPropertyDescriptor(value, name);
  if (!descriptor || !Object.hasOwn(descriptor, 'value')) {
    if (optional) return undefined;
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return descriptor.value;
}

function denseArray(value, maximum = 10_000) {
  if (!Array.isArray(value) || utilTypes.isProxy(value)
      || Object.getPrototypeOf(value) !== Array.prototype) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  const length = Object.getOwnPropertyDescriptor(value, 'length');
  if (!length || length.enumerable || !Object.hasOwn(length, 'value')
      || !Number.isSafeInteger(length.value) || length.value > maximum
      || Reflect.ownKeys(value).length !== length.value + 1) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  const result = [];
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      return evidenceFault('RPC_EVIDENCE_INVALID');
    }
    result.push(descriptor.value);
  }
  return result;
}

function uint256(value) {
  if (typeof value !== 'bigint' || value < 0n || value > MAX_UINT256) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return value;
}

function blockNumber(value) {
  return uint256(value);
}

function providerWord(value) {
  if (typeof value !== 'string' || !PROVIDER_WORD.test(value)) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return value.toLowerCase();
}

function providerAddress(value) {
  if (typeof value !== 'string' || !PROVIDER_ADDRESS.test(value)) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return value.toLowerCase();
}

function parseBlock(value) {
  const record = ordinaryDataRecord(value);
  return Object.freeze({
    number: blockNumber(own(record, 'number')),
    hash: providerWord(own(record, 'hash')),
    timestamp: uint256(own(record, 'timestamp')),
  });
}

function sameBlock(left, right) {
  return left.number === right.number
    && left.hash === right.hash
    && left.timestamp === right.timestamp;
}

function parseHead(value) {
  return blockNumber(value);
}

function parseReceipt(value, expectedTransactionId) {
  const record = ordinaryDataRecord(value);
  const parsed = Object.freeze({
    transactionId: providerWord(own(record, 'transactionHash')),
    blockHash: providerWord(own(record, 'blockHash')),
    blockNumber: blockNumber(own(record, 'blockNumber')),
    status: own(record, 'status'),
    logs: denseArray(own(record, 'logs'), 10_000),
  });
  if (parsed.transactionId !== expectedTransactionId
      || !new Set(['success', 'reverted']).has(parsed.status)) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return parsed;
}

function parseLog(value, receipt, seenIndexes) {
  const record = ordinaryDataRecord(value);
  const topics = denseArray(own(record, 'topics'), 4);
  const parsed = {
    address: providerAddress(own(record, 'address')),
    blockHash: providerWord(own(record, 'blockHash')),
    blockNumber: blockNumber(own(record, 'blockNumber')),
    data: own(record, 'data'),
    logIndex: own(record, 'logIndex'),
    removed: own(record, 'removed', true),
    topics,
    transactionId: providerWord(own(record, 'transactionHash')),
  };
  if (!Number.isSafeInteger(parsed.logIndex) || parsed.logIndex < 0
      || (parsed.removed !== undefined && parsed.removed !== false)
      || typeof parsed.data !== 'string' || !HEX_BYTES.test(parsed.data)
      || topics.some((topic) => typeof topic !== 'string' || !PROVIDER_WORD.test(topic))) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  if (parsed.blockHash !== receipt.blockHash
      || parsed.blockNumber !== receipt.blockNumber) {
    return evidenceFault('RPC_REORG_DETECTED');
  }
  if (parsed.transactionId !== receipt.transactionId || seenIndexes.has(parsed.logIndex)) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  seenIndexes.add(parsed.logIndex);
  return parsed;
}

function decodeRelevantLog(log, eventName) {
  try {
    if ((eventName === 'AuthorizationUsed' && log.data !== '0x')
        || (eventName === 'Transfer' && !/^0x[0-9a-fA-F]{64}$/.test(log.data))) {
      evidenceFault('RPC_EVIDENCE_INVALID');
    }
    return decodeEventLog({
      abi: USDC_ABI,
      eventName,
      data: log.data,
      topics: log.topics,
      strict: true,
    });
  } catch {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
}

function matchingPaymentLogs(receipt, binding) {
  const seenIndexes = new Set();
  const transfers = [];
  const authorizations = [];
  for (const value of receipt.logs) {
    const log = parseLog(value, receipt, seenIndexes);
    if (log.address !== ASSET || log.topics.length === 0) continue;
    const topic = log.topics[0].toLowerCase();
    if (topic === TRANSFER_TOPIC) {
      const decoded = decodeRelevantLog(log, 'Transfer');
      if (providerAddress(decoded.args.from) === binding.payer
          && providerAddress(decoded.args.to) === binding.payee
          && uint256(decoded.args.value).toString() === binding.amountAtomic) {
        transfers.push(log);
      }
    } else if (topic === AUTHORIZATION_USED_TOPIC) {
      const decoded = decodeRelevantLog(log, 'AuthorizationUsed');
      if (providerAddress(decoded.args.authorizer) === binding.payer
          && providerWord(decoded.args.nonce) === binding.nonce) {
        authorizations.push(log);
      }
    }
  }
  if (transfers.length > 1 || authorizations.length > 1) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return Object.freeze({
    transfer: transfers[0] ?? null,
    authorization: authorizations[0] ?? null,
  });
}

function matchingRefundLog(receipt, binding) {
  const seenIndexes = new Set();
  const transfers = [];
  for (const value of receipt.logs) {
    const log = parseLog(value, receipt, seenIndexes);
    if (log.address !== ASSET || log.topics.length === 0
        || log.topics[0].toLowerCase() !== TRANSFER_TOPIC) continue;
    const decoded = decodeRelevantLog(log, 'Transfer');
    if (providerAddress(decoded.args.from) === binding.refundSource
        && providerAddress(decoded.args.to) === binding.originalPayer
        && uint256(decoded.args.value).toString() === binding.amountAtomic) {
      transfers.push(log);
    }
  }
  if (transfers.length > 1) return evidenceFault('RPC_EVIDENCE_INVALID');
  return transfers[0] ?? null;
}

function confirmations(head, includedAt) {
  if (head < includedAt) return evidenceFault('RPC_EVIDENCE_INVALID');
  const value = head - includedAt + 1n;
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
  return Number(value);
}

function blockNotFuture(value, observedAt) {
  if (value.timestamp * 1_000n > BigInt(Date.parse(observedAt))) {
    return evidenceFault('RPC_EVIDENCE_INVALID');
  }
}

function isMissingReceiptError(error) {
  try {
    return error?.name === 'TransactionReceiptNotFoundError'
      || error?.name === 'TransactionNotFoundError';
  } catch {
    return false;
  }
}

function unknown(reasonCode, allowed) {
  if (!allowed.has(reasonCode)) {
    throw new KernelError('OBSERVER_INTERNAL', 'observer unknown reason is not allowlisted');
  }
  return frozenCopy({ kind: 'unknown', reasonCode });
}

function rejection(kind, binding, confirmed, reasonCode, observedAt) {
  return frozenCopy({
    kind: `${kind}_candidate_rejected`,
    rejectionProof: {
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: kind === 'payment'
        ? binding.candidate.transactionId
        : binding.refundTransactionId,
      blockHash: confirmed.receipt.blockHash,
      blockNumber: confirmed.receipt.blockNumber.toString(),
      transactionStatus: confirmed.receipt.status,
      confirmations: confirmed.confirmations,
      reasonCode,
      observedAt,
    },
  });
}

export function createBaseSepoliaObserver(input) {
  if (arguments.length !== 1) {
    throw new KernelError('OBSERVER_CONFIG', 'observer configuration is invalid');
  }
  const configuration = exactFunctionConfiguration(input);
  const client = captureClient(configuration.publicClient);
  const clock = captureClock(configuration.now);
  const minimumConfirmations = Object.hasOwn(configuration, 'minimumConfirmations')
    ? configuration.minimumConfirmations
    : 2;
  if (!Number.isSafeInteger(minimumConfirmations)
      || minimumConfirmations < 1 || minimumConfirmations > 1_000) {
    throw new KernelError('OBSERVER_CONFIG', 'minimum confirmation depth is invalid');
  }

  const loadConfirmedReceipt = async (candidateTransactionId, observedAt) => {
    let rawReceipt;
    try {
      rawReceipt = await client.getTransactionReceipt({ hash: candidateTransactionId });
    } catch (error) {
      if (isMissingReceiptError(error)) return Object.freeze({ state: 'missing' });
      return evidenceFault('RPC_PROVIDER_UNAVAILABLE');
    }
    if (rawReceipt === null || rawReceipt === undefined) {
      return Object.freeze({ state: 'missing' });
    }
    const receipt = parseReceipt(rawReceipt, candidateTransactionId);
    let head;
    try {
      head = parseHead(await client.getBlockNumber());
    } catch (error) {
      if (error instanceof EvidenceFault) throw error;
      return evidenceFault('RPC_PROVIDER_UNAVAILABLE');
    }
    const depth = confirmations(head, receipt.blockNumber);
    if (depth < minimumConfirmations) {
      return Object.freeze({ state: 'insufficient', head });
    }
    let includedBlock;
    try {
      includedBlock = parseBlock(await client.getBlock({ blockNumber: receipt.blockNumber }));
    } catch (error) {
      if (error instanceof EvidenceFault) throw error;
      return evidenceFault('RPC_PROVIDER_UNAVAILABLE');
    }
    if (includedBlock.number !== receipt.blockNumber
        || includedBlock.hash !== receipt.blockHash) {
      return evidenceFault('RPC_REORG_DETECTED');
    }
    blockNotFuture(includedBlock, observedAt);
    return Object.freeze({
      state: 'confirmed',
      receipt,
      confirmations: depth,
    });
  };

  const observeUnusedAuthorization = async (binding, observedAt, fallbackReason, knownHead) => {
    let head = knownHead;
    if (head === undefined) {
      try {
        head = parseHead(await client.getBlockNumber());
      } catch (error) {
        return unknown(
          error instanceof EvidenceFault ? error.reasonCode : 'RPC_PROVIDER_UNAVAILABLE',
          PAYMENT_UNKNOWN_REASONS,
        );
      }
    }
    const offset = BigInt(minimumConfirmations - 1);
    if (head < offset) {
      return unknown(
        fallbackReason ?? 'RPC_CONFIRMATIONS_INSUFFICIENT',
        PAYMENT_UNKNOWN_REASONS,
      );
    }
    const safeNumber = head - offset;
    let firstRaw;
    try {
      firstRaw = await client.getBlock({ blockNumber: safeNumber });
    } catch {
      return unknown('RPC_PROVIDER_UNAVAILABLE', PAYMENT_UNKNOWN_REASONS);
    }
    if (firstRaw === null || firstRaw === undefined) {
      return unknown(fallbackReason ?? 'RPC_EVIDENCE_INVALID', PAYMENT_UNKNOWN_REASONS);
    }
    let first;
    try {
      first = parseBlock(firstRaw);
      if (first.number !== safeNumber) evidenceFault('RPC_EVIDENCE_INVALID');
      blockNotFuture(first, observedAt);
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_EVIDENCE_INVALID',
        PAYMENT_UNKNOWN_REASONS,
      );
    }
    if (first.timestamp < BigInt(binding.validBefore)) {
      return unknown('AUTHORIZATION_NOT_EXPIRED', PAYMENT_UNKNOWN_REASONS);
    }

    let state;
    try {
      state = await client.readContract({
        address: ASSET,
        abi: USDC_ABI,
        functionName: 'authorizationState',
        args: [binding.payer, binding.nonce],
        blockNumber: safeNumber,
      });
    } catch {
      return unknown('RPC_PROVIDER_UNAVAILABLE', PAYMENT_UNKNOWN_REASONS);
    }
    if (typeof state !== 'boolean') {
      return unknown('RPC_EVIDENCE_INVALID', PAYMENT_UNKNOWN_REASONS);
    }

    let second;
    try {
      second = parseBlock(await client.getBlock({ blockNumber: safeNumber }));
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_PROVIDER_UNAVAILABLE',
        PAYMENT_UNKNOWN_REASONS,
      );
    }
    if (!sameBlock(first, second)) {
      return unknown('RPC_REORG_DETECTED', PAYMENT_UNKNOWN_REASONS);
    }
    if (state === true) {
      return unknown('AUTHORIZATION_ALREADY_USED', PAYMENT_UNKNOWN_REASONS);
    }
    return frozenCopy({
      kind: 'authorization_unused_after_expiry',
      network: NETWORK,
      asset: ASSET,
      payer: binding.payer,
      nonce: binding.nonce,
      validBefore: binding.validBefore,
      authorizationState: false,
      observedBlockNumber: first.number.toString(),
      observedBlockHash: first.hash,
      observedBlockTimestamp: first.timestamp.toString(),
      confirmations: minimumConfirmations,
    });
  };

  const preflight = async function preflight() {
    if (arguments.length !== 0) {
      throw new KernelError('OBSERVER_INPUT', 'preflight accepts no caller input');
    }
    try {
      if (await client.getChainId() !== CHAIN_ID) evidenceFault('RPC_EVIDENCE_INVALID');
      const head = parseHead(await client.getBlockNumber());
      const first = parseBlock(await client.getBlock({ blockNumber: head }));
      if (first.number !== head) evidenceFault('RPC_EVIDENCE_INVALID');
      const name = await client.readContract({
        address: ASSET,
        abi: USDC_ABI,
        functionName: 'name',
        blockNumber: head,
      });
      const version = await client.readContract({
        address: ASSET,
        abi: USDC_ABI,
        functionName: 'version',
        blockNumber: head,
      });
      const decimals = await client.readContract({
        address: ASSET,
        abi: USDC_ABI,
        functionName: 'decimals',
        blockNumber: head,
      });
      const second = parseBlock(await client.getBlock({ blockNumber: head }));
      if (!sameBlock(first, second)
          || name !== 'USDC' || version !== '2' || decimals !== 6) {
        evidenceFault('RPC_EVIDENCE_INVALID');
      }
      return frozenCopy({
        network: NETWORK,
        asset: ASSET,
        eip712Name: name,
        eip712Version: version,
        decimals,
        blockNumber: first.number.toString(),
        blockHash: first.hash,
      });
    } catch {
      throw new KernelError('OBSERVER_PREFLIGHT', 'Base Sepolia observer preflight failed');
    }
  };

  const fundingStatus = async function fundingStatus(value) {
    if (arguments.length !== 1) {
      throw new KernelError('OBSERVER_INPUT', 'funding status input is invalid');
    }
    let request;
    try {
      request = exactRecord(
        value,
        ['walletAddress', 'requiredAtomic'],
        [],
        'OBSERVER_INPUT',
        'funding status request',
      );
      if (typeof request.walletAddress !== 'string' || !ADDRESS.test(request.walletAddress)) {
        throw new KernelError('OBSERVER_INPUT', 'funding wallet address is invalid');
      }
      if (typeof request.requiredAtomic !== 'string' || request.requiredAtomic.length > 78) {
        throw new KernelError('OBSERVER_INPUT', 'required funding is invalid');
      }
      const required = canonicalAtomic(request.requiredAtomic, 'required funding');
      if (required.value === 0n || required.value > MAX_UINT256) {
        throw new KernelError('OBSERVER_INPUT', 'required funding is invalid');
      }
      request.requiredAtomic = required.text;
    } catch {
      throw new KernelError('OBSERVER_INPUT', 'funding status input is invalid');
    }

    try {
      const observedAt = canonicalClock(clock);
      const head = parseHead(await client.getBlockNumber());
      const first = parseBlock(await client.getBlock({ blockNumber: head }));
      if (first.number !== head) evidenceFault('RPC_EVIDENCE_INVALID');
      const rawBalance = await client.readContract({
        address: ASSET,
        abi: USDC_ABI,
        functionName: 'balanceOf',
        args: [request.walletAddress],
        blockNumber: head,
      });
      const balance = uint256(rawBalance);
      const second = parseBlock(await client.getBlock({ blockNumber: head }));
      if (!sameBlock(first, second)) evidenceFault('RPC_REORG_DETECTED');
      blockNotFuture(first, observedAt);
      return frozenCopy({
        walletAddress: request.walletAddress,
        asset: ASSET,
        balanceAtomic: balance.toString(),
        requiredAtomic: request.requiredAtomic,
        status: balance >= BigInt(request.requiredAtomic) ? 'sufficient' : 'insufficient',
        blockNumber: head.toString(),
        blockHash: first.hash,
        observedAt,
      });
    } catch {
      throw new KernelError('OBSERVER_UNAVAILABLE', 'funding status is unavailable');
    }
  };

  const observePayment = async function observePayment(value) {
    if (arguments.length !== 1) failBinding();
    const binding = validatePaymentBinding(value);
    let observedAt;
    try {
      observedAt = canonicalClock(clock);
    } catch (error) {
      return unknown(error.reasonCode, PAYMENT_UNKNOWN_REASONS);
    }

    if (binding.candidate === null) {
      return observeUnusedAuthorization(binding, observedAt, undefined, undefined);
    }

    let candidate;
    try {
      candidate = await loadConfirmedReceipt(binding.candidate.transactionId, observedAt);
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_PROVIDER_UNAVAILABLE',
        PAYMENT_UNKNOWN_REASONS,
      );
    }
    if (candidate.state === 'missing') {
      return observeUnusedAuthorization(
        binding,
        observedAt,
        'RPC_RECEIPT_MISSING',
        undefined,
      );
    }
    if (candidate.state === 'insufficient') {
      return observeUnusedAuthorization(
        binding,
        observedAt,
        'RPC_CONFIRMATIONS_INSUFFICIENT',
        candidate.head,
      );
    }
    if (candidate.receipt.status === 'reverted') {
      return rejection('payment', binding, candidate, 'TRANSACTION_REVERTED', observedAt);
    }

    let logs;
    try {
      logs = matchingPaymentLogs(candidate.receipt, binding);
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_EVIDENCE_INVALID',
        PAYMENT_UNKNOWN_REASONS,
      );
    }
    if (!logs.transfer || !logs.authorization) {
      return rejection('payment', binding, candidate, 'EXACT_TRANSFER_ABSENT', observedAt);
    }
    return frozenCopy({
      kind: 'settled_transfer',
      rpcTransferProof: {
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.candidate.transactionId,
        blockHash: candidate.receipt.blockHash,
        blockNumber: candidate.receipt.blockNumber.toString(),
        transactionStatus: 'success',
        confirmations: candidate.confirmations,
        transferLogIndex: logs.transfer.logIndex,
        authorizationLogIndex: logs.authorization.logIndex,
        tokenContract: ASSET,
        from: binding.payer,
        to: binding.payee,
        valueAtomic: binding.amountAtomic,
        authorizationNonce: binding.nonce,
        observedAt,
      },
    });
  };

  const observeRefund = async function observeRefund(value) {
    if (arguments.length !== 1) failBinding();
    const binding = validateRefundBinding(value);
    let observedAt;
    try {
      observedAt = canonicalClock(clock);
    } catch (error) {
      return unknown(error.reasonCode, REFUND_UNKNOWN_REASONS);
    }
    let candidate;
    try {
      candidate = await loadConfirmedReceipt(binding.refundTransactionId, observedAt);
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_PROVIDER_UNAVAILABLE',
        REFUND_UNKNOWN_REASONS,
      );
    }
    if (candidate.state === 'missing') {
      return unknown('RPC_RECEIPT_MISSING', REFUND_UNKNOWN_REASONS);
    }
    if (candidate.state === 'insufficient') {
      return unknown('RPC_CONFIRMATIONS_INSUFFICIENT', REFUND_UNKNOWN_REASONS);
    }
    if (candidate.receipt.status === 'reverted') {
      return rejection('refund', binding, candidate, 'TRANSACTION_REVERTED', observedAt);
    }

    let transfer;
    try {
      transfer = matchingRefundLog(candidate.receipt, binding);
    } catch (error) {
      return unknown(
        error instanceof EvidenceFault ? error.reasonCode : 'RPC_EVIDENCE_INVALID',
        REFUND_UNKNOWN_REASONS,
      );
    }
    if (!transfer) {
      return rejection('refund', binding, candidate, 'EXACT_TRANSFER_ABSENT', observedAt);
    }
    return frozenCopy({
      kind: 'refund_transfer_confirmed',
      rpcTransferProof: {
        source: 'base-sepolia-rpc',
        network: NETWORK,
        transactionId: binding.refundTransactionId,
        blockHash: candidate.receipt.blockHash,
        blockNumber: candidate.receipt.blockNumber.toString(),
        transactionStatus: 'success',
        confirmations: candidate.confirmations,
        transferLogIndex: transfer.logIndex,
        tokenContract: ASSET,
        from: binding.refundSource,
        to: binding.originalPayer,
        valueAtomic: binding.amountAtomic,
        observedAt,
      },
    });
  };

  return Object.freeze({
    preflight,
    fundingStatus,
    observePayment,
    observeRefund,
  });
}

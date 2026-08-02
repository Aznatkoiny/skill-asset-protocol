import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

import {
  encodeAbiParameters,
  encodeEventTopics,
  parseAbi,
} from 'viem';

import { createBaseSepoliaObserver } from '../src/adapters/base-sepolia-observer.mjs';
import {
  canonicalJson,
  frozenCopy,
  KernelError,
  sha256,
} from '../src/kernel/canonical.mjs';
import { validatePolicyDocument } from '../src/kernel/policy-engine.mjs';

const NETWORK = 'eip155:84532';
const ASSET = '0x036cbd53842c5426634e7929541ec2318f3dcf7e';
const PAYER = '0x1000000000000000000000000000000000000000';
const PAYEE = '0x2000000000000000000000000000000000000000';
const REFUND_SOURCE = '0x3000000000000000000000000000000000000000';
const SIGNER = '0x4000000000000000000000000000000000000000';
const TX = `0x${'ab'.repeat(32)}`;
const REFUND_TX = `0x${'de'.repeat(32)}`;
const BLOCK_HASH = `0x${'cd'.repeat(32)}`;
const HEAD_HASH = `0x${'ef'.repeat(32)}`;
const NONCE = `0x${'11'.repeat(32)}`;
const AMOUNT = '50000';
const RECEIPT_BLOCK = 100n;
const HEAD_BLOCK = 101n;
const VALID_BEFORE = 1_785_502_860n;
const NOW = new Date(Number((VALID_BEFORE + 120n) * 1_000n)).toISOString();
const CREATED_AT = new Date(Number((VALID_BEFORE - 120n) * 1_000n)).toISOString();

const USDC_EVENTS = parseAbi([
  'event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)',
  'event Transfer(address indexed from, address indexed to, uint256 value)',
]);

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function block({
  number = RECEIPT_BLOCK,
  hash = BLOCK_HASH,
  timestamp = VALID_BEFORE - 10n,
} = {}) {
  return { number, hash, timestamp };
}

function eventLog({
  eventName,
  args,
  logIndex,
  transactionHash = TX,
  blockHash = BLOCK_HASH,
  blockNumber = RECEIPT_BLOCK,
  address = ASSET,
  removed = false,
  data,
  topics,
} = {}) {
  const encodedTopics = topics ?? encodeEventTopics({ abi: USDC_EVENTS, eventName, args });
  const encodedData = data ?? (eventName === 'Transfer'
    ? encodeAbiParameters([{ type: 'uint256' }], [BigInt(args.value)])
    : '0x');
  return {
    address,
    blockHash,
    blockNumber,
    data: encodedData,
    logIndex,
    removed,
    topics: encodedTopics,
    transactionHash,
    transactionIndex: 0,
  };
}

function authorizationLog(overrides = {}) {
  return eventLog({
    eventName: 'AuthorizationUsed',
    args: { authorizer: PAYER, nonce: NONCE },
    logIndex: 5,
    ...overrides,
  });
}

function transferLog(overrides = {}) {
  return eventLog({
    eventName: 'Transfer',
    args: { from: PAYER, to: PAYEE, value: BigInt(AMOUNT) },
    logIndex: 4,
    ...overrides,
  });
}

function receipt(overrides = {}) {
  return {
    blockHash: BLOCK_HASH,
    blockNumber: RECEIPT_BLOCK,
    contractAddress: null,
    cumulativeGasUsed: 1n,
    effectiveGasPrice: 1n,
    from: PAYER,
    gasUsed: 1n,
    logs: [transferLog(), authorizationLog()],
    logsBloom: `0x${'00'.repeat(256)}`,
    status: 'success',
    to: ASSET,
    transactionHash: TX,
    transactionIndex: 0,
    type: 'eip1559',
    ...overrides,
  };
}

function makeClient({
  chainId = 84_532,
  head = HEAD_BLOCK,
  blocks,
  transactionReceipt = receipt(),
  receiptError = null,
  balance = 75_000n,
  authorizationState = false,
  name = 'USDC',
  version = '2',
  decimals = 6,
  readError = null,
} = {}) {
  const calls = [];
  const blockCalls = new Map();
  const blockSource = blocks ?? new Map([
    [RECEIPT_BLOCK.toString(), block()],
    [HEAD_BLOCK.toString(), block({ number: HEAD_BLOCK, hash: HEAD_HASH })],
  ]);
  const publicClient = Object.freeze({
    async getChainId(...args) {
      calls.push({ method: 'getChainId', args });
      return chainId;
    },
    async getBlockNumber(...args) {
      calls.push({ method: 'getBlockNumber', args });
      return head;
    },
    async getBlock(request) {
      calls.push({ method: 'getBlock', request });
      const key = request?.blockNumber?.toString();
      const seen = blockCalls.get(key) ?? 0;
      blockCalls.set(key, seen + 1);
      const configured = blockSource instanceof Map ? blockSource.get(key) : blockSource[key];
      if (Array.isArray(configured)) return configured[Math.min(seen, configured.length - 1)];
      if (configured instanceof Error) throw configured;
      return configured;
    },
    async getTransactionReceipt(request) {
      calls.push({ method: 'getTransactionReceipt', request });
      if (receiptError) throw receiptError;
      return transactionReceipt;
    },
    async readContract(request) {
      calls.push({
        method: 'readContract',
        request: {
          address: request?.address,
          functionName: request?.functionName,
          args: request?.args,
          blockNumber: request?.blockNumber,
        },
      });
      if (readError) throw readError;
      if (request.functionName === 'balanceOf') return balance;
      if (request.functionName === 'authorizationState') return authorizationState;
      if (request.functionName === 'name') return name;
      if (request.functionName === 'version') return version;
      if (request.functionName === 'decimals') return decimals;
      throw new Error('unexpected fake read');
    },
  });
  return { calls, publicClient };
}

function localAttemptHash(binding) {
  return sha256(canonicalJson({
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
    amountAtomic: binding.amountAtomic,
    nonce: binding.nonce,
    validAfter: binding.validAfter,
    validBefore: binding.validBefore,
  }));
}

function paymentBinding({ candidate = true, ...overrides } = {}) {
  const base = {
    schemaVersion: 1,
    domain: 'wallet-kernel.payment-observation.v1',
    intentId: 'intent-1',
    intentHash: `sha256:${'01'.repeat(32)}`,
    challengeHash: `sha256:${'02'.repeat(32)}`,
    quoteId: `sha256:${'03'.repeat(32)}`,
    network: NETWORK,
    asset: ASSET,
    payer: PAYER,
    payee: PAYEE,
    amountAtomic: AMOUNT,
    nonce: NONCE,
    validAfter: '0',
    validBefore: VALID_BEFORE.toString(),
    paymentPayloadHash: `sha256:${'04'.repeat(32)}`,
    paymentHeaderHash: `sha256:${'05'.repeat(32)}`,
    caseHash: `sha256:${'06'.repeat(32)}`,
    candidate: candidate === false ? null : {
      id: 'payment-candidate-1',
      transactionId: TX,
      state: 'pending',
      createdAt: CREATED_AT,
    },
    ...overrides,
  };
  base.localAttemptHash ??= localAttemptHash(base);
  return deepFreeze(base);
}

function policy() {
  return validatePolicyDocument({
    schemaVersion: 1,
    network: NETWORK,
    asset: ASSET,
    wallet: PAYER,
    methods: ['POST'],
    sellers: [{
      origin: 'https://seller.example',
      pathPrefixes: ['/paid/'],
      payTo: PAYEE,
      evidencePath: '/.well-known/wallet-kernel/evidence',
      executionSigner: SIGNER,
      refundSigner: SIGNER,
      refundSource: REFUND_SOURCE,
      perRequestMaxAtomic: '500000',
      autoApproveAtomic: '100000',
      humanApproveAtomic: '500000',
      sellerSessionMaxAtomic: '1000000',
    }],
    sessionMaxAtomic: '2000000',
    rolling24hMaxAtomic: '5000000',
    challengeMaxAgeMs: 60_000,
    approvalTtlMs: 300_000,
    maxPendingApprovals: 20,
    defaultAction: 'deny',
  });
}

function localRefundHash(binding) {
  return sha256(canonicalJson({
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
    amountAtomic: binding.amountAtomic,
  }));
}

function refundBinding(overrides = {}) {
  const validatedPolicy = policy();
  const base = {
    schemaVersion: 1,
    domain: 'wallet-kernel.refund-observation.v1',
    intentId: 'intent-1',
    intentHash: `sha256:${'01'.repeat(32)}`,
    policyVersion: {
      id: 'policy-1',
      hash: sha256(canonicalJson(validatedPolicy)),
      policy: validatedPolicy,
    },
    seller: validatedPolicy.sellers[0],
    resourcePath: '/paid/infer',
    network: NETWORK,
    sellerOrigin: 'https://seller.example',
    originalTransactionId: TX,
    refundTransactionId: REFUND_TX,
    asset: ASSET,
    originalPayer: PAYER,
    originalPayee: PAYEE,
    refundSource: REFUND_SOURCE,
    refundSigner: SIGNER,
    amountAtomic: AMOUNT,
    refundId: 'refund-1',
    caseHash: `sha256:${'07'.repeat(32)}`,
    ...overrides,
  };
  base.localRefundBindingHash ??= localRefundHash(base);
  return deepFreeze(base);
}

function observer(client, overrides = {}) {
  return createBaseSepoliaObserver({
    publicClient: client.publicClient,
    now: () => NOW,
    ...overrides,
  });
}

function assertKernelError(error, code) {
  assert.equal(error instanceof KernelError, true);
  assert.equal(error.code, code);
  return true;
}

function assertUnknown(value, reasonCode) {
  assert.deepEqual(value, { kind: 'unknown', reasonCode });
  assert.equal(Object.isFrozen(value), true);
  for (const forbidden of ['error', 'message', 'stack', 'cause', 'response']) {
    assert.equal(Object.hasOwn(value, forbidden), false);
  }
}

test('observer exposes only the frozen read-only surface and preflights the exact token domain', async () => {
  const client = makeClient();
  const value = observer(client);
  assert.equal(Object.isFrozen(value), true);
  assert.deepEqual(Object.keys(value), ['preflight', 'fundingStatus', 'observePayment', 'observeRefund']);
  for (const forbidden of [
    'client', 'request', 'wallet', 'signer', 'faucet', 'transfer',
    'sendTransaction', 'writeContract', 'getLogs',
  ]) assert.equal(Object.hasOwn(value, forbidden), false);

  assert.deepEqual(await value.preflight(), {
    network: NETWORK,
    asset: ASSET,
    eip712Name: 'USDC',
    eip712Version: '2',
    decimals: 6,
    blockNumber: HEAD_BLOCK.toString(),
    blockHash: HEAD_HASH,
  });
  assert.equal(Object.isFrozen(await value.preflight()), true);
  const reads = client.calls.filter((call) => call.method === 'readContract');
  assert.deepEqual(reads.slice(0, 3).map((call) => ({
    address: call.request.address,
    functionName: call.request.functionName,
    blockNumber: call.request.blockNumber,
  })), [
    { address: ASSET, functionName: 'name', blockNumber: HEAD_BLOCK },
    { address: ASSET, functionName: 'version', blockNumber: HEAD_BLOCK },
    { address: ASSET, functionName: 'decimals', blockNumber: HEAD_BLOCK },
  ]);
});

test('preflight rejects wrong chain, token domain, reorg, and provider failures without leakage', async () => {
  {
    const client = makeClient({ chainId: 1 });
    await assert.rejects(observer(client).preflight(), (error) => (
      assertKernelError(error, 'OBSERVER_PREFLIGHT')
      && client.calls.length === 1
    ));
  }
  for (const options of [
    { name: 'USD Coin' },
    { version: '1' },
    { decimals: 18 },
    { readError: new Error('RPC_SECRET_SENTINEL') },
    { blocks: new Map([[HEAD_BLOCK.toString(), [
      block({ number: HEAD_BLOCK, hash: HEAD_HASH }),
      block({ number: HEAD_BLOCK, hash: `0x${'99'.repeat(32)}` }),
    ]]]) },
  ]) {
    let caught;
    try { await observer(makeClient(options)).preflight(); } catch (error) { caught = error; }
    assertKernelError(caught, 'OBSERVER_PREFLIGHT');
    assert.equal(String(caught).includes('RPC_SECRET_SENTINEL'), false);
  }
});

test('constructor validates the injected client, clock, and bounded confirmation depth', () => {
  const client = makeClient();
  for (const minimumConfirmations of [0, -1, 1.5, 1_001, '2']) {
    assert.throws(
      () => observer(client, { minimumConfirmations }),
      (error) => assertKernelError(error, 'OBSERVER_CONFIG'),
    );
  }
  assert.throws(
    () => createBaseSepoliaObserver({ publicClient: {}, now: () => NOW }),
    (error) => assertKernelError(error, 'OBSERVER_CONFIG'),
  );
  assert.throws(
    () => createBaseSepoliaObserver({ publicClient: client.publicClient, now: 'clock' }),
    (error) => assertKernelError(error, 'OBSERVER_CONFIG'),
  );
});

test('factory and observer methods reject argument extension before provider access', async () => {
  const client = makeClient({ transactionReceipt: refundReceipt() });
  assert.throws(
    () => createBaseSepoliaObserver({ publicClient: client.publicClient, now: () => NOW }, null),
    (error) => assertKernelError(error, 'OBSERVER_CONFIG'),
  );
  const value = observer(client);
  await assert.rejects(value.preflight(null), (error) => assertKernelError(error, 'OBSERVER_INPUT'));
  await assert.rejects(
    value.fundingStatus({ walletAddress: PAYER, requiredAtomic: AMOUNT }, null),
    (error) => assertKernelError(error, 'OBSERVER_INPUT'),
  );
  await assert.rejects(
    value.observePayment(paymentBinding(), null),
    (error) => assertKernelError(error, 'OBSERVER_BINDING'),
  );
  await assert.rejects(
    value.observeRefund(refundBinding(), null),
    (error) => assertKernelError(error, 'OBSERVER_BINDING'),
  );
  assert.equal(client.calls.length, 0);
});

test('configured confirmation depth governs candidate and expiry observations', async () => {
  const confirmed = await observer(makeClient({ head: HEAD_BLOCK + 1n }), {
    minimumConfirmations: 3,
  }).observePayment(paymentBinding());
  assert.equal(confirmed.kind, 'settled_transfer');
  assert.equal(confirmed.rpcTransferProof.confirmations, 3);

  const insufficient = await observer(makeClient({ transactionReceipt: refundReceipt() }), {
    minimumConfirmations: 3,
  }).observeRefund(refundBinding());
  assertUnknown(insufficient, 'RPC_CONFIRMATIONS_INSUFFICIENT');
});

test('funding status reads one stable captured block and returns only canonical public facts', async () => {
  const sufficientClient = makeClient({ balance: 50_000n });
  const sufficient = await observer(sufficientClient).fundingStatus({
    walletAddress: PAYER,
    requiredAtomic: AMOUNT,
  });
  assert.deepEqual(sufficient, {
    walletAddress: PAYER,
    asset: ASSET,
    balanceAtomic: AMOUNT,
    requiredAtomic: AMOUNT,
    status: 'sufficient',
    blockNumber: HEAD_BLOCK.toString(),
    blockHash: HEAD_HASH,
    observedAt: NOW,
  });
  assert.equal(Object.isFrozen(sufficient), true);
  assert.deepEqual(
    sufficientClient.calls.filter((call) => call.method === 'readContract')[0].request,
    { address: ASSET, functionName: 'balanceOf', args: [PAYER], blockNumber: HEAD_BLOCK },
  );

  const insufficient = await observer(makeClient({ balance: 49_999n })).fundingStatus({
    walletAddress: PAYER,
    requiredAtomic: AMOUNT,
  });
  assert.equal(insufficient.status, 'insufficient');
  assert.equal(insufficient.balanceAtomic, '49999');
});

test('funding rejects hostile input, precision loss, reorg, future blocks, and provider leakage', async () => {
  const cases = [
    { walletAddress: `0x${'AB'.repeat(20)}`, requiredAtomic: AMOUNT },
    { walletAddress: PAYER, requiredAtomic: '050000' },
    { walletAddress: PAYER, requiredAtomic: AMOUNT, upstreamUrl: 'https://attacker.example' },
  ];
  for (const input of cases) {
    const client = makeClient();
    await assert.rejects(observer(client).fundingStatus(input), (error) => (
      assertKernelError(error, 'OBSERVER_INPUT') && client.calls.length === 0
    ));
  }
  for (const client of [
    makeClient({ balance: Number.MAX_SAFE_INTEGER }),
    makeClient({ readError: new Error('PROVIDER_SECRET_SENTINEL') }),
    makeClient({ blocks: new Map([[HEAD_BLOCK.toString(), [
      block({ number: HEAD_BLOCK, hash: HEAD_HASH }),
      block({ number: HEAD_BLOCK, hash: `0x${'98'.repeat(32)}` }),
    ]]]) }),
    makeClient({ blocks: new Map([[HEAD_BLOCK.toString(), block({
      number: HEAD_BLOCK,
      hash: HEAD_HASH,
      timestamp: VALID_BEFORE + 10_000n,
    })]]) }),
  ]) {
    let caught;
    try {
      await observer(client).fundingStatus({ walletAddress: PAYER, requiredAtomic: AMOUNT });
    } catch (error) { caught = error; }
    assertKernelError(caught, 'OBSERVER_UNAVAILABLE');
    assert.equal(String(caught).includes('PROVIDER_SECRET_SENTINEL'), false);
  }
});

test('payment observation proves exactly one confirmed authorization and transfer', async () => {
  const client = makeClient();
  const result = await observer(client).observePayment(paymentBinding());
  assert.deepEqual(result, {
    kind: 'settled_transfer',
    rpcTransferProof: {
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: TX,
      blockHash: BLOCK_HASH,
      blockNumber: RECEIPT_BLOCK.toString(),
      transactionStatus: 'success',
      confirmations: 2,
      transferLogIndex: 4,
      authorizationLogIndex: 5,
      tokenContract: ASSET,
      from: PAYER,
      to: PAYEE,
      valueAtomic: AMOUNT,
      authorizationNonce: NONCE,
      observedAt: NOW,
    },
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.isFrozen(result.rpcTransferProof), true);
  assert.deepEqual(client.calls.map((call) => call.method), [
    'getTransactionReceipt', 'getBlockNumber', 'getBlock',
  ]);
  assert.deepEqual(client.calls[0].request, { hash: TX });
});

test('confirmed reverted payment remains a rejected candidate while authorization is still valid', async () => {
  const client = makeClient({ transactionReceipt: receipt({ status: 'reverted', logs: [] }) });
  const result = await observer(client).observePayment(paymentBinding());
  assert.deepEqual(result, {
    kind: 'payment_candidate_rejected',
    rejectionProof: {
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: TX,
      blockHash: BLOCK_HASH,
      blockNumber: RECEIPT_BLOCK.toString(),
      transactionStatus: 'reverted',
      confirmations: 2,
      reasonCode: 'TRANSACTION_REVERTED',
      observedAt: NOW,
    },
  });
  assert.equal(client.calls.some((call) => call.request?.functionName === 'authorizationState'), false);
});

test('confirmed successful payment candidates with mismatched exact logs are rejected', async () => {
  const receipts = [
    receipt({ logs: [transferLog(), authorizationLog({
      args: { authorizer: PAYER, nonce: `0x${'12'.repeat(32)}` },
    })] }),
    receipt({ logs: [authorizationLog(), transferLog({
      args: { from: PAYER, to: REFUND_SOURCE, value: BigInt(AMOUNT) },
    })] }),
    receipt({ logs: [authorizationLog(), transferLog({
      args: { from: PAYER, to: PAYEE, value: 49_999n },
    })] }),
    receipt({ logs: [authorizationLog()] }),
  ];
  for (const transactionReceipt of receipts) {
    const result = await observer(makeClient({ transactionReceipt })).observePayment(paymentBinding());
    assert.equal(result.kind, 'payment_candidate_rejected');
    assert.equal(result.rejectionProof.reasonCode, 'EXACT_TRANSFER_ABSENT');
    assert.equal(result.rejectionProof.transactionStatus, 'success');
  }
});

test('post-expiry false authorization state is the only release-grade no-use observation', async () => {
  const expiryBlock = block({
    number: RECEIPT_BLOCK,
    hash: BLOCK_HASH,
    timestamp: VALID_BEFORE,
  });
  const client = makeClient({
    transactionReceipt: null,
    authorizationState: false,
    blocks: new Map([
      [RECEIPT_BLOCK.toString(), expiryBlock],
      [HEAD_BLOCK.toString(), block({ number: HEAD_BLOCK, hash: HEAD_HASH })],
    ]),
  });
  const result = await observer(client).observePayment(paymentBinding({ candidate: false }));
  assert.deepEqual(result, {
    kind: 'authorization_unused_after_expiry',
    network: NETWORK,
    asset: ASSET,
    payer: PAYER,
    nonce: NONCE,
    validBefore: VALID_BEFORE.toString(),
    authorizationState: false,
    observedBlockNumber: RECEIPT_BLOCK.toString(),
    observedBlockHash: BLOCK_HASH,
    observedBlockTimestamp: VALID_BEFORE.toString(),
    confirmations: 2,
  });
  assert.equal(Object.isFrozen(result), true);
  const read = client.calls.find((call) => call.request?.functionName === 'authorizationState');
  assert.deepEqual(read.request, {
    address: ASSET,
    functionName: 'authorizationState',
    args: [PAYER, NONCE],
    blockNumber: RECEIPT_BLOCK,
  });
});

test('used, pre-expiry, missing, and insufficient payment evidence stays unknown', async () => {
  const beforeExpiry = block({
    number: RECEIPT_BLOCK,
    hash: BLOCK_HASH,
    timestamp: VALID_BEFORE - 1n,
  });
  for (const { client, reasonCode } of [
    { client: makeClient({ transactionReceipt: null, authorizationState: true, blocks: new Map([
      [RECEIPT_BLOCK.toString(), block({
        number: RECEIPT_BLOCK, hash: BLOCK_HASH, timestamp: VALID_BEFORE,
      })],
    ]) }), reasonCode: 'AUTHORIZATION_ALREADY_USED' },
    { client: makeClient({ transactionReceipt: null, blocks: new Map([
      [RECEIPT_BLOCK.toString(), beforeExpiry],
    ]) }), reasonCode: 'AUTHORIZATION_NOT_EXPIRED' },
    { client: makeClient({
      head: RECEIPT_BLOCK,
      transactionReceipt: receipt(),
      blocks: new Map([[RECEIPT_BLOCK.toString(), block()]]),
    }), reasonCode: 'RPC_CONFIRMATIONS_INSUFFICIENT' },
    { client: makeClient({
      head: RECEIPT_BLOCK - 1n,
      transactionReceipt: receipt(),
      blocks: new Map(),
    }), reasonCode: 'RPC_EVIDENCE_INVALID' },
  ]) {
    assertUnknown(await observer(client).observePayment(paymentBinding()), reasonCode);
  }
});

test('insufficient candidate evidence may still prove unused after an already-expired stable block', async () => {
  const client = makeClient({
    head: RECEIPT_BLOCK,
    transactionReceipt: receipt(),
    authorizationState: false,
    blocks: new Map([
      [(RECEIPT_BLOCK - 1n).toString(), block({
        number: RECEIPT_BLOCK - 1n,
        hash: `0x${'88'.repeat(32)}`,
        timestamp: VALID_BEFORE,
      })],
    ]),
  });
  const result = await observer(client).observePayment(paymentBinding());
  assert.equal(result.kind, 'authorization_unused_after_expiry');
  assert.equal(result.observedBlockNumber, (RECEIPT_BLOCK - 1n).toString());
});

test('payment reorgs, duplicate proof logs, malformed relevant logs, and provider errors are unknown', async () => {
  const malformed = authorizationLog();
  malformed.data = '0x12';
  for (const { client, reasonCode } of [
    { client: makeClient({ transactionReceipt: receipt({
      blockHash: `0x${'90'.repeat(32)}`,
    }) }), reasonCode: 'RPC_REORG_DETECTED' },
    { client: makeClient({ transactionReceipt: receipt({
      logs: [transferLog(), transferLog({ logIndex: 6 }), authorizationLog()],
    }) }), reasonCode: 'RPC_EVIDENCE_INVALID' },
    { client: makeClient({ transactionReceipt: receipt({
      logs: [transferLog(), malformed],
    }) }), reasonCode: 'RPC_EVIDENCE_INVALID' },
    { client: makeClient({
      receiptError: new Error('PRIVATE_PROVIDER_RESPONSE'),
    }), reasonCode: 'RPC_PROVIDER_UNAVAILABLE' },
  ]) {
    const result = await observer(client).observePayment(paymentBinding());
    assertUnknown(result, reasonCode);
    assert.equal(JSON.stringify(result).includes('PRIVATE_PROVIDER_RESPONSE'), false);
  }
});

test('payment bindings are closed, internally hashed, and lowercase before any RPC call', async () => {
  const variants = [
    { ...paymentBinding(), candidate: { ...paymentBinding().candidate, transactionId: TX.toUpperCase().replace('0X', '0x') } },
    { ...paymentBinding(), localAttemptHash: `sha256:${'99'.repeat(32)}` },
    { ...paymentBinding(), evidence: { status: 'success' } },
  ];
  for (const binding of variants) {
    const client = makeClient();
    await assert.rejects(observer(client).observePayment(binding), (error) => (
      assertKernelError(error, 'OBSERVER_BINDING') && client.calls.length === 0
    ));
  }
});

function refundTransferLog(overrides = {}) {
  return transferLog({
    transactionHash: REFUND_TX,
    args: { from: REFUND_SOURCE, to: PAYER, value: BigInt(AMOUNT) },
    ...overrides,
  });
}

function refundReceipt(overrides = {}) {
  return receipt({
    transactionHash: REFUND_TX,
    logs: [refundTransferLog()],
    ...overrides,
  });
}

test('refund observation returns only the confirmed independent chain half', async () => {
  const client = makeClient({ transactionReceipt: refundReceipt() });
  const result = await observer(client).observeRefund(refundBinding());
  assert.deepEqual(result, {
    kind: 'refund_transfer_confirmed',
    rpcTransferProof: {
      source: 'base-sepolia-rpc',
      network: NETWORK,
      transactionId: REFUND_TX,
      blockHash: BLOCK_HASH,
      blockNumber: RECEIPT_BLOCK.toString(),
      transactionStatus: 'success',
      confirmations: 2,
      transferLogIndex: 4,
      tokenContract: ASSET,
      from: REFUND_SOURCE,
      to: PAYER,
      valueAtomic: AMOUNT,
      observedAt: NOW,
    },
  });
  assert.equal(Object.isFrozen(result), true);
  assert.equal(Object.hasOwn(result, 'attestation'), false);
  assert.equal(Object.hasOwn(result, 'refundConfirmed'), false);
  assert.deepEqual(client.calls[0], {
    method: 'getTransactionReceipt', request: { hash: REFUND_TX },
  });
});

test('confirmed reverted or exact-transfer-mismatched refund candidates are rejected only', async () => {
  for (const transactionReceipt of [
    refundReceipt({ status: 'reverted', logs: [] }),
    refundReceipt({ logs: [refundTransferLog({
      args: { from: PAYEE, to: PAYER, value: BigInt(AMOUNT) },
    })] }),
    refundReceipt({ logs: [refundTransferLog({
      args: { from: REFUND_SOURCE, to: PAYER, value: 49_999n },
    })] }),
  ]) {
    const result = await observer(makeClient({ transactionReceipt })).observeRefund(refundBinding());
    assert.equal(result.kind, 'refund_candidate_rejected');
    assert.equal(result.rejectionProof.reasonCode,
      transactionReceipt.status === 'reverted' ? 'TRANSACTION_REVERTED' : 'EXACT_TRANSFER_ABSENT');
    assert.equal(Object.hasOwn(result, 'attestation'), false);
  }
});

test('missing, insufficient, duplicate, malformed, reorged, or uncertain refund proof stays unknown', async () => {
  const malformed = refundTransferLog();
  malformed.data = '0x12';
  for (const { client, reasonCode } of [
    { client: makeClient({ transactionReceipt: null }), reasonCode: 'RPC_RECEIPT_MISSING' },
    { client: makeClient({
      head: RECEIPT_BLOCK,
      transactionReceipt: refundReceipt(),
    }), reasonCode: 'RPC_CONFIRMATIONS_INSUFFICIENT' },
    { client: makeClient({ transactionReceipt: refundReceipt({
      blockHash: `0x${'90'.repeat(32)}`,
    }) }), reasonCode: 'RPC_REORG_DETECTED' },
    { client: makeClient({ transactionReceipt: refundReceipt({
      logs: [refundTransferLog(), refundTransferLog({ logIndex: 6 })],
    }) }), reasonCode: 'RPC_EVIDENCE_INVALID' },
    { client: makeClient({ transactionReceipt: refundReceipt({
      logs: [malformed],
    }) }), reasonCode: 'RPC_EVIDENCE_INVALID' },
    { client: makeClient({
      receiptError: new Error('REFUND_PROVIDER_SECRET'),
    }), reasonCode: 'RPC_PROVIDER_UNAVAILABLE' },
  ]) {
    const result = await observer(client).observeRefund(refundBinding());
    assertUnknown(result, reasonCode);
    assert.equal(JSON.stringify(result).includes('REFUND_PROVIDER_SECRET'), false);
  }
});

test('refund binding is closed and revalidates immutable PolicyVersion seller authority', async () => {
  const valid = refundBinding();
  const changedSeller = { ...valid.seller, refundSource: PAYEE };
  const variants = [
    { ...valid, seller: changedSeller },
    { ...valid, refundSource: PAYEE },
    { ...valid, resourcePath: '/untrusted/infer' },
    { ...valid, policyVersion: { ...valid.policyVersion, hash: `sha256:${'99'.repeat(32)}` } },
    { ...valid, refundTransactionId: REFUND_TX.toUpperCase().replace('0X', '0x') },
    { ...valid, localRefundBindingHash: `sha256:${'98'.repeat(32)}` },
    { ...valid, rpcEvidence: { transfer: true } },
  ];
  for (const binding of variants) {
    const client = makeClient({ transactionReceipt: refundReceipt() });
    await assert.rejects(observer(client).observeRefund(binding), (error) => (
      assertKernelError(error, 'OBSERVER_BINDING') && client.calls.length === 0
    ));
  }
});

test('observer source has no network construction, write, wallet, key, or environment capability', () => {
  const source = fs.readFileSync(new URL('../src/adapters/base-sepolia-observer.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /process\.env|\bfetch\s*\(|\bhttp\s*\(|createPublicClient|sendTransaction|writeContract|signTypedData|faucet|privateKey/i);
});

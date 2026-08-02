import assert from "node:assert/strict";
import test from "node:test";

import { WIP_TOKEN_ADDRESS } from "@story-protocol/core-sdk";
import {
  TransactionNotFoundError,
  TransactionReceiptNotFoundError,
} from "viem";
import {
  encodeAbiParameters,
  encodeEventTopics,
  keccak256,
  parseAbiItem,
  type Log,
} from "viem";

import {
  StoryChain,
  type StoryPublicClientBoundary,
  type StorySdkBoundary,
  type StoryWalletBoundary,
} from "../src/story";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const SPG = "0x00000000000000000000000000000000000000bb" as const;
const LICENSE_TEMPLATE = "0x00000000000000000000000000000000000000cc" as const;
const DERIVATIVE_WORKFLOWS = "0x00000000000000000000000000000000000000dd" as const;
const PARENT = "0x0000000000000000000000000000000000000001" as const;
const CHILD = "0x0000000000000000000000000000000000000002" as const;
const CALLER = "0x00000000000000000000000000000000000000ee" as const;
const HASH = `0x${"1".repeat(64)}` as const;
const ENCODED = { to: SPG, data: "0x1234" as const };
const SERIALIZED = `0x${"ab".repeat(64)}` as const;
const TX_HASH = keccak256(SERIALIZED);
const METADATA = {
  ipMetadataURI: "https://example.test/ip",
  ipMetadataHash: HASH,
  nftMetadataURI: "https://example.test/nft",
  nftMetadataHash: HASH,
};

const COLLECTION_CREATED = parseAbiItem("event CollectionCreated(address indexed spgNftContract)");
const IP_REGISTERED = parseAbiItem("event IPRegistered(address ipId, uint256 indexed chainId, address indexed tokenContract, uint256 indexed tokenId, string name, string uri, uint256 registrationDate)");
const LICENSE_TERMS_ATTACHED = parseAbiItem("event LicenseTermsAttached(address indexed caller, address indexed ipId, address licenseTemplate, uint256 licenseTermsId)");
const DERIVATIVE_REGISTERED = parseAbiItem("event DerivativeRegistered(address indexed caller, address indexed childIpId, uint256[] licenseTokenIds, address[] parentIpIds, uint256[] licenseTermsIds, address licenseTemplate)");

function collectionLog(spgNftContract = SPG): Log {
  return {
    topics: encodeEventTopics({
      abi: [COLLECTION_CREATED],
      eventName: "CollectionCreated",
      args: { spgNftContract },
    }),
    data: "0x",
  } as unknown as Log;
}

function ipRegisteredLog(input: {
  ipId?: `0x${string}`;
  chainId?: bigint;
  tokenContract?: `0x${string}`;
  tokenId?: bigint;
} = {}): Log {
  const ipId = input.ipId ?? CHILD;
  const chainId = input.chainId ?? 1315n;
  const tokenContract = input.tokenContract ?? SPG;
  const tokenId = input.tokenId ?? 2n;
  return {
    topics: encodeEventTopics({
      abi: [IP_REGISTERED],
      eventName: "IPRegistered",
      args: { chainId, tokenContract, tokenId },
    }),
    data: encodeAbiParameters(
      [
        { type: "address" },
        { type: "string" },
        { type: "string" },
        { type: "uint256" },
      ],
      [ipId, "registered", "ipfs://registered", 1n],
    ),
  } as Log;
}

function licenseTermsAttachedLog(input: {
  ipId?: `0x${string}`;
  licenseTemplate?: `0x${string}`;
  licenseTermsId?: bigint;
} = {}): Log {
  const ipId = input.ipId ?? PARENT;
  return {
    topics: encodeEventTopics({
      abi: [LICENSE_TERMS_ATTACHED],
      eventName: "LicenseTermsAttached",
      args: { caller: CALLER, ipId },
    }),
    data: encodeAbiParameters(
      [{ type: "address" }, { type: "uint256" }],
      [input.licenseTemplate ?? LICENSE_TEMPLATE, input.licenseTermsId ?? 7n],
    ),
  } as Log;
}

function derivativeRegisteredLog(input: {
  childIpId?: `0x${string}`;
  parentIpIds?: readonly `0x${string}`[];
  licenseTermsIds?: readonly bigint[];
  licenseTemplate?: `0x${string}`;
} = {}): Log {
  const childIpId = input.childIpId ?? CHILD;
  return {
    topics: encodeEventTopics({
      abi: [DERIVATIVE_REGISTERED],
      eventName: "DerivativeRegistered",
      args: { caller: CALLER, childIpId },
    }),
    data: encodeAbiParameters(
      [
        { type: "uint256[]" },
        { type: "address[]" },
        { type: "uint256[]" },
        { type: "address" },
      ],
      [[], input.parentIpIds ?? [PARENT], input.licenseTermsIds ?? [7n], input.licenseTemplate ?? LICENSE_TEMPLATE],
    ),
  } as Log;
}

function receipt(logs: Log[], status: "success" | "reverted" = "success") {
  return { status, transactionHash: TX_HASH, logs } as const;
}

function sdk(overrides: Partial<StorySdkBoundary> = {}): StorySdkBoundary {
  const base: StorySdkBoundary = {
    nftClient: {
      createNFTCollection: async () => ({ encodedTxData: ENCODED }),
    },
    ipAsset: {
      mintAndRegisterIpAssetWithPilTerms: async () => ({ encodedTxData: ENCODED }),
      mintAndRegisterIpAndMakeDerivative: async () => ({ encodedTxData: ENCODED }),
      wipClient: {
        address: WIP_TOKEN_ADDRESS,
        balanceOf: async () => ({ result: 123n }),
        allowance: async () => ({ result: 123n }),
      },
      derivativeWorkflowsClient: { address: DERIVATIVE_WORKFLOWS },
    },
    license: {
      predictMintingLicenseFee: async () => ({ currencyToken: WIP_TOKEN_ADDRESS, tokenAmount: 123n }),
    },
  };
  return {
    ...base,
    ...overrides,
    nftClient: { ...base.nftClient, ...overrides.nftClient },
    ipAsset: { ...base.ipAsset, ...overrides.ipAsset },
    license: { ...base.license, ...overrides.license },
  };
}

function boundaries(input: {
  sdk?: StorySdkBoundary;
  receipt?: ReturnType<typeof receipt>;
  sendRawTransaction?: StoryPublicClientBoundary["sendRawTransaction"];
  getTransaction?: StoryPublicClientBoundary["getTransaction"];
  getTransactionReceipt?: StoryPublicClientBoundary["getTransactionReceipt"];
} = {}) {
  const sent: `0x${string}`[] = [];
  const preparedRequests: unknown[] = [];
  const signedRequests: unknown[] = [];
  const wallet: StoryWalletBoundary = {
    account: { address: WALLET },
    chain: { id: 1315 },
    prepareTransactionRequest: async (request) => {
      preparedRequests.push(request);
      return { ...request, nonce: 1 };
    },
    signTransaction: async (request) => {
      signedRequests.push(request);
      return SERIALIZED;
    },
  };
  const publicClient: StoryPublicClientBoundary = {
    getChainId: async () => 1315,
    getBalance: async () => 1n,
    getGasPrice: async () => 2n,
    sendRawTransaction: input.sendRawTransaction ?? (async ({ serializedTransaction }) => {
      sent.push(serializedTransaction);
      return TX_HASH;
    }),
    getTransaction: input.getTransaction ?? (async () => ({ hash: TX_HASH })),
    getTransactionReceipt: input.getTransactionReceipt ?? (async () => ({ transactionHash: TX_HASH })),
    waitForTransactionReceipt: async () => input.receipt ?? receipt([]),
  };
  return {
    story: new StoryChain({ sdk: input.sdk ?? sdk(), wallet, publicClient }),
    sent,
    preparedRequests,
    signedRequests,
  };
}

test("prepareCollection encodes, signs, and hashes without broadcasting", async () => {
  let observedInput: Record<string, unknown> | undefined;
  const chain = boundaries({
    sdk: sdk({
      nftClient: {
        createNFTCollection: async (input) => {
          observedInput = input as unknown as Record<string, unknown>;
          return { encodedTxData: ENCODED };
        },
      },
    }),
  });

  const prepared = await chain.story.prepareCollection({
    name: "Skills",
    symbol: "SKILL",
    mintFeeRecipient: WALLET,
  });

  assert.deepEqual(observedInput?.txOptions, { encodedTxDataOnly: true });
  assert.equal(observedInput?.isPublicMinting, true);
  assert.equal(observedInput?.mintOpen, true);
  assert.deepEqual(chain.preparedRequests[0], {
    account: { address: WALLET },
    chain: { id: 1315 },
    to: ENCODED.to,
    data: ENCODED.data,
  });
  assert.equal(chain.signedRequests.length, 1);
  assert.deepEqual(prepared, { serializedTransaction: SERIALIZED, transactionHash: TX_HASH });
  assert.deepEqual(chain.sent, []);
});

test("Skill and Derivative prepare calls preserve terms and fee caps at the encoded boundary", async () => {
  let rootInput: Record<string, unknown> | undefined;
  let derivativeInput: Record<string, unknown> | undefined;
  const chain = boundaries({
    sdk: sdk({
      ipAsset: {
        ...sdk().ipAsset,
        mintAndRegisterIpAssetWithPilTerms: async (input) => {
          rootInput = input as unknown as Record<string, unknown>;
          return { encodedTxData: ENCODED };
        },
        mintAndRegisterIpAndMakeDerivative: async (input) => {
          derivativeInput = input as unknown as Record<string, unknown>;
          return { encodedTxData: ENCODED };
        },
      },
    }),
  });

  await chain.story.prepareSkill({
    spgNftContract: SPG,
    metadata: METADATA,
    defaultMintingFee: 1n,
  });
  await chain.story.prepareDerivative({
    spgNftContract: SPG,
    parentIpId: PARENT,
    licenseTermsId: 7n,
    maxMintingFee: 123n,
    metadata: METADATA,
  });

  assert.deepEqual(rootInput?.txOptions, { encodedTxDataOnly: true });
  assert.equal(Array.isArray(rootInput?.licenseTermsData), true);
  assert.deepEqual(derivativeInput?.txOptions, { encodedTxDataOnly: true });
  assert.deepEqual((derivativeInput?.derivData as Record<string, unknown>).parentIpIds, [PARENT]);
  assert.equal((derivativeInput?.derivData as Record<string, unknown>).maxMintingFee, 123n);
  assert.deepEqual(chain.sent, []);
});

test("missing encoded SDK data fails before signing", async () => {
  const chain = boundaries({
    sdk: sdk({ nftClient: { createNFTCollection: async () => ({}) } }),
  });
  await assert.rejects(
    chain.story.prepareCollection({ name: "Skills", symbol: "SKILL", mintFeeRecipient: WALLET }),
    /missing encoded collection transaction/i,
  );
  assert.equal(chain.signedRequests.length, 0);
});

test("broadcastPrepared sends exact bytes and requires the exact local hash", async () => {
  const exact = boundaries();
  await exact.story.broadcastPrepared({ serializedTransaction: SERIALIZED, transactionHash: TX_HASH });
  assert.deepEqual(exact.sent, [SERIALIZED]);

  const mismatch = boundaries({ sendRawTransaction: async () => `0x${"9".repeat(64)}` });
  await assert.rejects(
    mismatch.story.broadcastPrepared({ serializedTransaction: SERIALIZED, transactionHash: TX_HASH }),
    /RPC returned.*expected/i,
  );
});

test("known or consumed nonce reconciles only when the exact hash is queryable", async () => {
  let transactionQueries = 0;
  let receiptQueries = 0;
  const reconciled = boundaries({
    sendRawTransaction: async () => { throw new Error("nonce too low"); },
    getTransaction: async ({ hash }) => {
      transactionQueries += 1;
      return { hash };
    },
    getTransactionReceipt: async ({ hash }) => {
      receiptQueries += 1;
      throw new TransactionReceiptNotFoundError({ hash });
    },
  });
  await reconciled.story.broadcastPrepared({ serializedTransaction: SERIALIZED, transactionHash: TX_HASH });
  assert.equal(transactionQueries, 1);
  assert.equal(receiptQueries, 1);

  const absent = boundaries({
    sendRawTransaction: async () => { throw new Error("already known transaction"); },
    getTransaction: async ({ hash }) => { throw new TransactionNotFoundError({ hash }); },
    getTransactionReceipt: async ({ hash }) => { throw new TransactionReceiptNotFoundError({ hash }); },
  });
  await assert.rejects(
    absent.story.broadcastPrepared({ serializedTransaction: SERIALIZED, transactionHash: TX_HASH }),
    /unresolved.*replaced/i,
  );
});

test("known or consumed nonce reconciles from an exact receipt when the transaction lookup is absent", async () => {
  let transactionQueries = 0;
  let receiptQueries = 0;
  const reconciled = boundaries({
    sendRawTransaction: async () => { throw new Error("already known transaction"); },
    getTransaction: async ({ hash }) => {
      transactionQueries += 1;
      throw new TransactionNotFoundError({ hash });
    },
    getTransactionReceipt: async ({ hash }) => {
      receiptQueries += 1;
      return { transactionHash: hash };
    },
  });

  await reconciled.story.broadcastPrepared({
    serializedTransaction: SERIALIZED,
    transactionHash: TX_HASH,
  });
  assert.equal(transactionQueries, 1);
  assert.equal(receiptQueries, 1);
});

test("reconciliation propagates unrelated RPC failures", async () => {
  const reconciled = boundaries({
    sendRawTransaction: async () => { throw new Error("nonce too low"); },
    getTransaction: async () => { throw new Error("RPC authorization failed"); },
    getTransactionReceipt: async ({ hash }) => ({ transactionHash: hash }),
  });

  await assert.rejects(
    reconciled.story.broadcastPrepared({
      serializedTransaction: SERIALIZED,
      transactionHash: TX_HASH,
    }),
    /RPC authorization failed/,
  );
});

test("confirmCollection decodes one successful CollectionCreated event", async () => {
  const chain = boundaries({ receipt: receipt([collectionLog()]) });
  assert.deepEqual(await chain.story.confirmCollection(TX_HASH), {
    spgNftContract: SPG,
    txHash: TX_HASH,
  });
});

test("confirmSkill binds IP registration and attached license terms to the expected collection", async () => {
  const chain = boundaries({
    receipt: receipt([
      ipRegisteredLog({ ipId: PARENT, tokenId: 1n }),
      licenseTermsAttachedLog({ ipId: PARENT }),
    ]),
  });
  assert.deepEqual(await chain.story.confirmSkill({
    transactionHash: TX_HASH,
    expectedCollection: SPG,
  }), {
    ipId: PARENT,
    tokenId: 1n,
    txHash: TX_HASH,
    licenseTermsId: 7n,
    licenseTemplate: LICENSE_TEMPLATE,
  });
});

test("confirmDerivative returns only event-derived matching ancestry", async () => {
  const chain = boundaries({
    receipt: receipt([ipRegisteredLog(), derivativeRegisteredLog()]),
  });
  assert.deepEqual(await chain.story.confirmDerivative({
    transactionHash: TX_HASH,
    expectedCollection: SPG,
    expectedParentIpId: PARENT,
    expectedLicenseTermsId: 7n,
    expectedLicenseTemplate: LICENSE_TEMPLATE,
  }), {
    ipId: CHILD,
    tokenId: 2n,
    txHash: TX_HASH,
    licenseTermsId: 7n,
    licenseTemplate: LICENSE_TEMPLATE,
  });
});

for (const scenario of [
  { name: "child", logs: [ipRegisteredLog(), derivativeRegisteredLog({ childIpId: PARENT })] },
  { name: "parent", logs: [ipRegisteredLog(), derivativeRegisteredLog({ parentIpIds: [CHILD] })] },
  { name: "terms", logs: [ipRegisteredLog(), derivativeRegisteredLog({ licenseTermsIds: [8n] })] },
  { name: "template", logs: [ipRegisteredLog(), derivativeRegisteredLog({ licenseTemplate: SPG })] },
  { name: "duplicate", logs: [ipRegisteredLog(), ipRegisteredLog(), derivativeRegisteredLog()] },
  {
    name: "mixed matching and foreign DerivativeRegistered",
    logs: [
      ipRegisteredLog(),
      derivativeRegisteredLog(),
      derivativeRegisteredLog({ childIpId: PARENT }),
    ],
  },
  { name: "missing", logs: [ipRegisteredLog()] },
] as const) {
  test(`confirmDerivative rejects ${scenario.name} event evidence`, async () => {
    const chain = boundaries({ receipt: receipt([...scenario.logs]) });
    await assert.rejects(
      chain.story.confirmDerivative({
        transactionHash: TX_HASH,
        expectedCollection: SPG,
        expectedParentIpId: PARENT,
        expectedLicenseTermsId: 7n,
        expectedLicenseTemplate: LICENSE_TEMPLATE,
      }),
      /Derivative|event|parent|terms|template|exactly one/i,
    );
  });
}

test("confirmation rejects a reverted receipt or a receipt for another hash", async () => {
  const reverted = boundaries({ receipt: receipt([collectionLog()], "reverted") });
  await assert.rejects(reverted.story.confirmCollection(TX_HASH), /reverted|successful/i);

  const wrongHashReceipt = {
    ...receipt([collectionLog()]),
    transactionHash: `0x${"8".repeat(64)}` as const,
  };
  const wrongHash = boundaries({ receipt: wrongHashReceipt });
  await assert.rejects(wrongHash.story.confirmCollection(TX_HASH), /receipt.*expected hash/i);
});

test("Derivative fee readiness reads WIP balance and allowance for the SDK spender", async () => {
  const calls: unknown[] = [];
  const chain = boundaries({
    sdk: sdk({
      ipAsset: {
        ...sdk().ipAsset,
        wipClient: {
          address: WIP_TOKEN_ADDRESS,
          balanceOf: async (input) => {
            calls.push(["balance", input]);
            return { result: 11n };
          },
          allowance: async (input) => {
            calls.push(["allowance", input]);
            return { result: 12n };
          },
        },
        derivativeWorkflowsClient: { address: DERIVATIVE_WORKFLOWS },
      },
    }),
  });
  assert.deepEqual(await chain.story.getDerivativeFeeReadiness({
    wallet: WALLET,
    currencyToken: WIP_TOKEN_ADDRESS,
    requiredAmount: 10n,
  }), {
    currencyToken: WIP_TOKEN_ADDRESS,
    spender: DERIVATIVE_WORKFLOWS,
    requiredAmount: 10n,
    balance: 11n,
    allowance: 12n,
  });
  assert.deepEqual(calls, [
    ["balance", { owner: WALLET }],
    ["allowance", { owner: WALLET, spender: DERIVATIVE_WORKFLOWS }],
  ]);
});

test("unsupported predicted currency rejects before any WIP read", async () => {
  let reads = 0;
  const chain = boundaries({
    sdk: sdk({
      ipAsset: {
        ...sdk().ipAsset,
        wipClient: {
          address: WIP_TOKEN_ADDRESS,
          balanceOf: async () => { reads += 1; return { result: 1n }; },
          allowance: async () => { reads += 1; return { result: 1n }; },
        },
      },
    }),
  });
  await assert.rejects(
    chain.story.getDerivativeFeeReadiness({
      wallet: WALLET,
      currencyToken: SPG,
      requiredAmount: 1n,
    }),
    /not supported WIP/i,
  );
  assert.equal(reads, 0);
});

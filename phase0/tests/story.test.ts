import assert from "node:assert/strict";
import test from "node:test";

import { StoryChain, type StorySdkBoundary } from "../src/story";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const SPG = "0x00000000000000000000000000000000000000bb" as const;
const PARENT = "0x0000000000000000000000000000000000000001" as const;
const HASH = `0x${"1".repeat(64)}` as const;
const METADATA = {
  ipMetadataURI: "https://example.test/ip",
  ipMetadataHash: HASH,
  nftMetadataURI: "https://example.test/nft",
  nftMetadataHash: HASH,
};

function sdk(overrides: Partial<StorySdkBoundary> = {}): StorySdkBoundary {
  return {
    nftClient: {
      createNFTCollection: async () => ({ spgNftContract: SPG, txHash: "0xcollection" }),
    },
    ipAsset: {
      mintAndRegisterIpAssetWithPilTerms: async () => ({
        ipId: PARENT,
        tokenId: 1n,
        txHash: "0xroot",
        licenseTermsIds: [7n],
      }),
      mintAndRegisterIpAndMakeDerivative: async () => ({
        ipId: "0x0000000000000000000000000000000000000002",
        tokenId: 2n,
        txHash: "0xchild",
      }),
    },
    license: {
      predictMintingLicenseFee: async () => ({ currencyToken: SPG, tokenAmount: 123n }),
    },
    ...overrides,
  };
}

function chain(boundary = sdk()) {
  return new StoryChain({
    sdk: boundary,
    publicClient: {
      getChainId: async () => 1315,
      getBalance: async () => 1n,
      getGasPrice: async () => 2n,
    },
  });
}

test("SDK optional proof fields are guarded before the workflow can advance", async () => {
  const missingCollection = sdk({
    nftClient: { createNFTCollection: async () => ({ txHash: "0xcollection" }) },
  });
  await assert.rejects(
    chain(missingCollection).createCollection({ name: "Skills", symbol: "SKILL", mintFeeRecipient: WALLET }),
    /missing spgNftContract/i,
  );

  const missingRootTerms = sdk({
    ipAsset: {
      mintAndRegisterIpAssetWithPilTerms: async () => ({ ipId: PARENT, tokenId: 1n, txHash: "0xroot" }),
      mintAndRegisterIpAndMakeDerivative: async () => ({
        ipId: "0x0000000000000000000000000000000000000002",
        tokenId: 2n,
        txHash: "0xchild",
      }),
    },
  });
  await assert.rejects(
    chain(missingRootTerms).registerSkill({
      spgNftContract: SPG,
      metadata: METADATA,
      defaultMintingFee: 1n,
    }),
    /missing licenseTermsId/i,
  );
});

test("predicted fee is passed as the standalone Derivative maxMintingFee cap", async () => {
  let observedCap: bigint | undefined;
  const boundary = sdk({
    ipAsset: {
      mintAndRegisterIpAssetWithPilTerms: async () => ({
        ipId: PARENT,
        tokenId: 1n,
        txHash: "0xroot",
        licenseTermsIds: [7n],
      }),
      mintAndRegisterIpAndMakeDerivative: async (input) => {
        const cap = input.derivData.maxMintingFee;
        if (typeof cap !== "bigint") throw new Error("expected a bigint cap");
        observedCap = cap;
        return {
          ipId: "0x0000000000000000000000000000000000000002",
          tokenId: 2n,
          txHash: "0xchild",
        };
      },
    },
  });
  const story = chain(boundary);
  const prediction = await story.predictMintingLicenseFee({
    licensorIpId: PARENT,
    licenseTermsId: 7n,
    amount: 1,
  });

  await story.registerDerivative({
    spgNftContract: SPG,
    parentIpId: PARENT,
    licenseTermsId: 7n,
    maxMintingFee: prediction.tokenAmount,
    metadata: METADATA,
  });

  assert.equal(prediction.tokenAmount, 123n);
  assert.equal(observedCap, 123n);
});

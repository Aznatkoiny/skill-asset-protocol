import {
  NativeRoyaltyPolicy,
  PILFlavor,
  type StoryClient,
  WIP_TOKEN_ADDRESS,
} from "@story-protocol/core-sdk";

import type { DemoChain, PreparedMetadata } from "./demo";

type Address = `0x${string}`;

export type StorySdkBoundary = {
  nftClient: Pick<StoryClient["nftClient"], "createNFTCollection">;
  ipAsset: Pick<
    StoryClient["ipAsset"],
    "mintAndRegisterIpAssetWithPilTerms" | "mintAndRegisterIpAndMakeDerivative"
  >;
  license: Pick<StoryClient["license"], "predictMintingLicenseFee">;
};

export interface StoryPublicClientBoundary {
  getChainId(): Promise<number>;
  getBalance(input: { address: Address }): Promise<bigint>;
  getGasPrice(): Promise<bigint>;
}

function required<T>(value: T | undefined, label: string): T {
  if (value === undefined) throw new Error(`Story SDK response is missing ${label}`);
  return value;
}

function validateRevShare(value: number): number {
  if (!Number.isFinite(value) || value < 0 || value > 100) {
    throw new Error("rev-share must be a finite number from 0 to 100");
  }
  return value;
}

export class StoryChain implements DemoChain {
  private readonly sdk: StorySdkBoundary;
  private readonly publicClient: StoryPublicClientBoundary;

  constructor(input: { sdk: StorySdkBoundary; publicClient: StoryPublicClientBoundary }) {
    this.sdk = input.sdk;
    this.publicClient = input.publicClient;
  }

  getChainId(): Promise<number> {
    return this.publicClient.getChainId();
  }

  getBalance(address: Address): Promise<bigint> {
    return this.publicClient.getBalance({ address });
  }

  getGasPrice(): Promise<bigint> {
    return this.publicClient.getGasPrice();
  }

  async createCollection(input: {
    name: string;
    symbol: string;
    mintFeeRecipient: Address;
  }) {
    const response = await this.sdk.nftClient.createNFTCollection({
      ...input,
      isPublicMinting: true,
      mintOpen: true,
      contractURI: "",
    });
    return {
      spgNftContract: required(response.spgNftContract, "spgNftContract"),
      txHash: required(response.txHash, "collection txHash"),
    };
  }

  async registerSkill(input: {
    spgNftContract: Address;
    metadata: PreparedMetadata["onchain"];
    defaultMintingFee: bigint;
    revShare?: number;
    policy?: "LAP" | "LRP";
  }) {
    const revShare = validateRevShare(input.revShare ?? 25);
    const policy = input.policy ?? "LAP";
    const terms = PILFlavor.commercialRemix({
      defaultMintingFee: input.defaultMintingFee,
      commercialRevShare: revShare,
      currency: WIP_TOKEN_ADDRESS,
      royaltyPolicy: policy === "LRP" ? NativeRoyaltyPolicy.LRP : NativeRoyaltyPolicy.LAP,
    });
    const response = await this.sdk.ipAsset.mintAndRegisterIpAssetWithPilTerms({
      spgNftContract: input.spgNftContract,
      licenseTermsData: [{ terms }],
      ipMetadata: input.metadata,
    });
    return {
      ipId: required(response.ipId, "ipId"),
      tokenId: required(response.tokenId, "tokenId"),
      txHash: required(response.txHash, "registration txHash"),
      licenseTermsId: required(response.licenseTermsIds?.[0], "licenseTermsId"),
    };
  }

  async predictMintingLicenseFee(input: {
    licensorIpId: Address;
    licenseTermsId: bigint;
    amount: number;
  }) {
    const response = await this.sdk.license.predictMintingLicenseFee(input);
    return { tokenAmount: required(response.tokenAmount, "predicted tokenAmount") };
  }

  async registerDerivative(input: {
    spgNftContract: Address;
    parentIpId: Address;
    licenseTermsId: bigint;
    maxMintingFee: bigint;
    metadata: PreparedMetadata["onchain"];
  }) {
    const response = await this.sdk.ipAsset.mintAndRegisterIpAndMakeDerivative({
      spgNftContract: input.spgNftContract,
      derivData: {
        parentIpIds: [input.parentIpId],
        licenseTermsIds: [input.licenseTermsId],
        maxMintingFee: input.maxMintingFee,
        maxRts: 100_000_000,
        maxRevenueShare: 100,
      },
      ipMetadata: input.metadata,
    });
    return {
      ipId: required(response.ipId, "ipId"),
      tokenId: required(response.tokenId, "tokenId"),
      txHash: required(response.txHash, "registration txHash"),
    };
  }
}

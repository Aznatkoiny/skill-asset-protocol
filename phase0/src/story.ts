import {
  NativeRoyaltyPolicy,
  PILFlavor,
  type StoryClient,
  WIP_TOKEN_ADDRESS,
} from "@story-protocol/core-sdk";
import {
  keccak256,
  parseAbiItem,
  parseEventLogs,
  TransactionNotFoundError,
  TransactionReceiptNotFoundError,
  type Hash,
  type Hex,
  type Log,
} from "viem";

import {
  AENEID_CHAIN_ID,
  type CollectionInput,
  type CollectionResult,
  type DemoChain,
  type DerivativeInput,
  type DerivativeResult,
  type PreparedChainTransaction,
  type PredictFeeInput,
  type SkillInput,
  type SkillResult,
} from "./demo";

type Address = `0x${string}`;

export type StorySdkBoundary = {
  nftClient: Pick<StoryClient["nftClient"], "createNFTCollection">;
  ipAsset: Pick<
    StoryClient["ipAsset"],
    "mintAndRegisterIpAssetWithPilTerms" | "mintAndRegisterIpAndMakeDerivative"
  > & {
    wipClient: {
      address: Address;
      balanceOf(input: { owner: Address }): Promise<{ result: bigint }>;
      allowance(input: { owner: Address; spender: Address }): Promise<{ result: bigint }>;
    };
    derivativeWorkflowsClient: { address: Address };
  };
  license: Pick<StoryClient["license"], "predictMintingLicenseFee">;
};

export interface StoryWalletBoundary {
  account: unknown;
  chain: unknown;
  prepareTransactionRequest(input: {
    account: unknown;
    chain: unknown;
    to: Address;
    data: Hex;
  }): Promise<unknown>;
  signTransaction(request: unknown): Promise<Hex>;
}

export interface StoryReceiptBoundary {
  status: "success" | "reverted";
  transactionHash: Hash;
  logs: Log[];
}

export interface StoryPublicClientBoundary {
  getChainId(): Promise<number>;
  getBalance(input: { address: Address }): Promise<bigint>;
  getGasPrice(): Promise<bigint>;
  sendRawTransaction(input: { serializedTransaction: Hex }): Promise<Hash>;
  getTransaction(input: { hash: Hash }): Promise<{ hash: Hash }>;
  getTransactionReceipt(input: { hash: Hash }): Promise<{ transactionHash: Hash }>;
  waitForTransactionReceipt(input: { hash: Hash }): Promise<StoryReceiptBoundary>;
}

const COLLECTION_CREATED = parseAbiItem("event CollectionCreated(address indexed spgNftContract)");
const IP_REGISTERED = parseAbiItem("event IPRegistered(address ipId, uint256 indexed chainId, address indexed tokenContract, uint256 indexed tokenId, string name, string uri, uint256 registrationDate)");
const LICENSE_TERMS_ATTACHED = parseAbiItem("event LicenseTermsAttached(address indexed caller, address indexed ipId, address licenseTemplate, uint256 licenseTermsId)");
const DERIVATIVE_REGISTERED = parseAbiItem("event DerivativeRegistered(address indexed caller, address indexed childIpId, uint256[] licenseTokenIds, address[] parentIpIds, uint256[] licenseTermsIds, address licenseTemplate)");

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

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function exactlyOne<T>(items: readonly T[], label: string): T {
  if (items.length !== 1) throw new Error(`Expected exactly one ${label} event; received ${items.length}`);
  return items[0];
}

export class StoryChain implements DemoChain {
  constructor(private readonly input: {
    sdk: StorySdkBoundary;
    wallet: StoryWalletBoundary;
    publicClient: StoryPublicClientBoundary;
  }) {}

  getChainId(): Promise<number> {
    return this.input.publicClient.getChainId();
  }

  getBalance(address: Address): Promise<bigint> {
    return this.input.publicClient.getBalance({ address });
  }

  getGasPrice(): Promise<bigint> {
    return this.input.publicClient.getGasPrice();
  }

  async prepareCollection(input: CollectionInput): Promise<PreparedChainTransaction> {
    const response = await this.input.sdk.nftClient.createNFTCollection({
      ...input,
      isPublicMinting: true,
      mintOpen: true,
      contractURI: "",
      txOptions: { encodedTxDataOnly: true },
    });
    return this.signEncoded(required(response.encodedTxData, "encoded collection transaction"));
  }

  async prepareSkill(input: SkillInput): Promise<PreparedChainTransaction> {
    const revShare = validateRevShare(input.revShare ?? 25);
    const policy = input.policy ?? "LAP";
    const terms = PILFlavor.commercialRemix({
      defaultMintingFee: input.defaultMintingFee,
      commercialRevShare: revShare,
      currency: WIP_TOKEN_ADDRESS,
      royaltyPolicy: policy === "LRP" ? NativeRoyaltyPolicy.LRP : NativeRoyaltyPolicy.LAP,
    });
    const response = await this.input.sdk.ipAsset.mintAndRegisterIpAssetWithPilTerms({
      spgNftContract: input.spgNftContract,
      licenseTermsData: [{ terms }],
      ipMetadata: input.metadata,
      txOptions: { encodedTxDataOnly: true },
    });
    return this.signEncoded(required(response.encodedTxData, "encoded Skill transaction"));
  }

  async prepareDerivative(input: DerivativeInput): Promise<PreparedChainTransaction> {
    const response = await this.input.sdk.ipAsset.mintAndRegisterIpAndMakeDerivative({
      spgNftContract: input.spgNftContract,
      derivData: {
        parentIpIds: [input.parentIpId],
        licenseTermsIds: [input.licenseTermsId],
        maxMintingFee: input.maxMintingFee,
        maxRts: 100_000_000,
        maxRevenueShare: 100,
      },
      ipMetadata: input.metadata,
      txOptions: { encodedTxDataOnly: true },
    });
    return this.signEncoded(required(response.encodedTxData, "encoded Derivative transaction"));
  }

  async broadcastPrepared(input: PreparedChainTransaction): Promise<void> {
    try {
      const observed = await this.input.publicClient.sendRawTransaction({
        serializedTransaction: input.serializedTransaction,
      });
      if (!sameHex(observed, input.transactionHash)) {
        throw new Error(`RPC returned ${observed}; expected ${input.transactionHash}`);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (!/already known|known transaction|nonce too low/i.test(message)) throw error;
      if (!await this.findExactTransaction(input.transactionHash)) {
        throw new Error(
          `Prepared transaction ${input.transactionHash} is unresolved; its nonce may have been replaced`,
          { cause: error },
        );
      }
    }
  }

  async confirmCollection(transactionHash: Hash): Promise<CollectionResult> {
    const receipt = await this.successfulReceipt(transactionHash);
    const events = parseEventLogs({ abi: [COLLECTION_CREATED], logs: receipt.logs, strict: true });
    const event = exactlyOne(events, "CollectionCreated");
    return { spgNftContract: event.args.spgNftContract, txHash: transactionHash };
  }

  async confirmSkill(input: {
    transactionHash: Hash;
    expectedCollection: Address;
  }): Promise<SkillResult> {
    const receipt = await this.successfulReceipt(input.transactionHash);
    const registrations = parseEventLogs({ abi: [IP_REGISTERED], logs: receipt.logs, strict: true })
      .filter((event) => event.args.chainId === BigInt(AENEID_CHAIN_ID)
        && sameHex(event.args.tokenContract, input.expectedCollection));
    const registration = exactlyOne(registrations, "matching IPRegistered");
    const licenses = parseEventLogs({ abi: [LICENSE_TERMS_ATTACHED], logs: receipt.logs, strict: true })
      .filter((event) => sameHex(event.args.ipId, registration.args.ipId));
    const license = exactlyOne(licenses, "matching LicenseTermsAttached");
    return {
      ipId: registration.args.ipId,
      tokenId: registration.args.tokenId,
      txHash: input.transactionHash,
      licenseTermsId: license.args.licenseTermsId,
      licenseTemplate: license.args.licenseTemplate,
    };
  }

  async confirmDerivative(input: {
    transactionHash: Hash;
    expectedCollection: Address;
    expectedParentIpId: Address;
    expectedLicenseTermsId: bigint;
    expectedLicenseTemplate: Address;
  }): Promise<DerivativeResult> {
    const receipt = await this.successfulReceipt(input.transactionHash);
    const registrations = parseEventLogs({ abi: [IP_REGISTERED], logs: receipt.logs, strict: true })
      .filter((event) => event.args.chainId === BigInt(AENEID_CHAIN_ID)
        && sameHex(event.args.tokenContract, input.expectedCollection));
    const registration = exactlyOne(registrations, "matching IPRegistered");
    const derivatives = parseEventLogs({ abi: [DERIVATIVE_REGISTERED], logs: receipt.logs, strict: true });
    const derivative = exactlyOne(derivatives, "DerivativeRegistered");
    if (!sameHex(derivative.args.childIpId, registration.args.ipId)) {
      throw new Error("DerivativeRegistered child IP does not match the registered IP");
    }
    if (derivative.args.parentIpIds.length !== 1
        || !sameHex(derivative.args.parentIpIds[0], input.expectedParentIpId)) {
      throw new Error("DerivativeRegistered parent IP does not match the journal-bound parent");
    }
    if (derivative.args.licenseTermsIds.length !== 1
        || derivative.args.licenseTermsIds[0] !== input.expectedLicenseTermsId) {
      throw new Error("DerivativeRegistered license terms do not match the journal-bound terms");
    }
    if (!sameHex(derivative.args.licenseTemplate, input.expectedLicenseTemplate)) {
      throw new Error("DerivativeRegistered license template does not match the journal-bound template");
    }
    return {
      ipId: registration.args.ipId,
      tokenId: registration.args.tokenId,
      txHash: input.transactionHash,
      licenseTermsId: derivative.args.licenseTermsIds[0],
      licenseTemplate: derivative.args.licenseTemplate,
    };
  }

  async predictMintingLicenseFee(input: PredictFeeInput) {
    const response = await this.input.sdk.license.predictMintingLicenseFee(input);
    return {
      currencyToken: required(response.currencyToken, "predicted currencyToken"),
      tokenAmount: required(response.tokenAmount, "predicted tokenAmount"),
    };
  }

  async getDerivativeFeeReadiness(input: {
    wallet: Address;
    currencyToken: Address;
    requiredAmount: bigint;
  }) {
    const wip = this.input.sdk.ipAsset.wipClient;
    const spender = this.input.sdk.ipAsset.derivativeWorkflowsClient.address;
    if (!sameHex(input.currencyToken, WIP_TOKEN_ADDRESS)
        || !sameHex(wip.address, WIP_TOKEN_ADDRESS)) {
      throw new Error(
        `Derivative fee currency ${input.currencyToken} is not supported WIP ${WIP_TOKEN_ADDRESS}`,
      );
    }
    const [balanceResult, allowanceResult] = await Promise.all([
      wip.balanceOf({ owner: input.wallet }),
      wip.allowance({ owner: input.wallet, spender }),
    ]);
    return {
      currencyToken: wip.address,
      spender,
      requiredAmount: input.requiredAmount,
      balance: balanceResult.result,
      allowance: allowanceResult.result,
    };
  }

  private async signEncoded(encoded: { to: Address; data: Hex }): Promise<PreparedChainTransaction> {
    const request = await this.input.wallet.prepareTransactionRequest({
      account: this.input.wallet.account,
      chain: this.input.wallet.chain,
      to: encoded.to,
      data: encoded.data,
    });
    const serializedTransaction = await this.input.wallet.signTransaction(request);
    return { serializedTransaction, transactionHash: keccak256(serializedTransaction) };
  }

  private async findExactTransaction(expected: Hash): Promise<boolean> {
    const [transaction, receipt] = await Promise.all([
      this.input.publicClient.getTransaction({ hash: expected }).catch((error: unknown) => {
        if (error instanceof TransactionNotFoundError) return null;
        throw error;
      }),
      this.input.publicClient.getTransactionReceipt({ hash: expected }).catch((error: unknown) => {
        if (error instanceof TransactionReceiptNotFoundError) return null;
        throw error;
      }),
    ]);
    return Boolean(
      (transaction && sameHex(transaction.hash, expected))
      || (receipt && sameHex(receipt.transactionHash, expected)),
    );
  }

  private async successfulReceipt(expected: Hash): Promise<StoryReceiptBoundary> {
    const receipt = await this.input.publicClient.waitForTransactionReceipt({ hash: expected });
    if (!sameHex(receipt.transactionHash, expected)) {
      throw new Error(`Transaction receipt ${receipt.transactionHash} does not match expected hash ${expected}`);
    }
    if (receipt.status !== "success") {
      throw new Error(`Transaction ${expected} did not produce a successful receipt (status: ${receipt.status})`);
    }
    return receipt;
  }
}

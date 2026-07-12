import { fileURLToPath } from "node:url";
import { parseEther } from "viem";

import {
  AENEID_NETWORK,
  type DemoStage,
  type MetadataProof,
  type RegistrationManifest,
  type RegistrationProof,
  type RegistrationStore,
} from "./registrations";

export const AENEID_CHAIN_ID = AENEID_NETWORK.chainId;
export const AENEID_FAUCET_URL = "https://aeneid.faucet.story.foundation/";
export const DEMO_ROOT_MINTING_FEE = parseEther("0.001");

export interface DemoSkillDefinition {
  stage: DemoStage;
  name: string;
  description: string;
  artifactPath: string;
}

export interface PreparedMetadata {
  onchain: {
    ipMetadataURI: string;
    ipMetadataHash: `0x${string}`;
    nftMetadataURI: string;
    nftMetadataHash: `0x${string}`;
  };
  proof: MetadataProof;
}

export interface DemoMetadataProvider {
  prepare(input: DemoSkillDefinition & { creatorAddress: `0x${string}` }): Promise<PreparedMetadata>;
}

export interface DemoChain {
  getChainId(): Promise<number>;
  getBalance(address: `0x${string}`): Promise<bigint>;
  createCollection(input: {
    name: string;
    symbol: string;
    mintFeeRecipient: `0x${string}`;
  }): Promise<{ spgNftContract: `0x${string}`; txHash: `0x${string}` }>;
  registerSkill(input: {
    spgNftContract: `0x${string}`;
    metadata: PreparedMetadata["onchain"];
    defaultMintingFee: bigint;
    revShare?: number;
    policy?: "LAP" | "LRP";
  }): Promise<{
    ipId: `0x${string}`;
    tokenId: bigint;
    txHash: `0x${string}`;
    licenseTermsId: bigint;
  }>;
  predictMintingLicenseFee(input: {
    licensorIpId: `0x${string}`;
    licenseTermsId: bigint;
    amount: number;
  }): Promise<{ tokenAmount: bigint }>;
  registerDerivative(input: {
    spgNftContract: `0x${string}`;
    parentIpId: `0x${string}`;
    licenseTermsId: bigint;
    maxMintingFee: bigint;
    metadata: PreparedMetadata["onchain"];
  }): Promise<{ ipId: `0x${string}`; tokenId: bigint; txHash: `0x${string}` }>;
}

export interface RunDemoInput {
  wallet: `0x${string}`;
  chain: DemoChain;
  metadata: DemoMetadataProvider;
  store: RegistrationStore;
  skills?: readonly DemoSkillDefinition[];
}

export const DEMO_SKILLS: readonly DemoSkillDefinition[] = [
  {
    stage: "root",
    name: "demo-research-skill",
    description: "A tiny research Skill used to prove Story provenance on Aeneid.",
    artifactPath: fileURLToPath(new URL("../fixtures/demo-base/SKILL.md", import.meta.url)),
  },
  {
    stage: "child",
    name: "demo-research-derivative",
    description: "A declared Derivative that adds source comparison.",
    artifactPath: fileURLToPath(new URL("../fixtures/demo-child/SKILL.md", import.meta.url)),
  },
  {
    stage: "grandchild",
    name: "demo-research-grandchild",
    description: "A second-level Derivative that adds concise synthesis.",
    artifactPath: fileURLToPath(new URL("../fixtures/demo-grandchild/SKILL.md", import.meta.url)),
  },
] as const;

function definitionFor(skills: readonly DemoSkillDefinition[], stage: DemoStage) {
  const definition = skills.find((skill) => skill.stage === stage);
  if (!definition) throw new Error(`Missing demo Skill definition for ${stage}`);
  return definition;
}

function ensureResumableManifest(manifest: RegistrationManifest, wallet: `0x${string}`) {
  if (manifest.schemaVersion !== 1) {
    throw new Error(`Unsupported registrations schema version: ${manifest.schemaVersion}`);
  }
  if (manifest.network.chainId !== AENEID_CHAIN_ID) {
    throw new Error(
      `registrations.json targets chain ${manifest.network.chainId}; expected Story Aeneid (${AENEID_CHAIN_ID})`,
    );
  }
  if (manifest.wallet && manifest.wallet.toLowerCase() !== wallet.toLowerCase()) {
    throw new Error(`registrations.json belongs to wallet ${manifest.wallet}; current wallet is ${wallet}`);
  }
  if (manifest.registrations.root === null && (manifest.registrations.child || manifest.registrations.grandchild)) {
    throw new Error("registrations.json is inconsistent: a Derivative exists without the root Skill");
  }
  if (manifest.registrations.child === null && manifest.registrations.grandchild) {
    throw new Error("registrations.json is inconsistent: the grandchild exists without its parent Derivative");
  }
}

function metadataProofMatches(stored: MetadataProof, current: MetadataProof): boolean {
  return (
    stored.ip.uri === current.ip.uri
    && stored.ip.hash === current.ip.hash
    && stored.nft.uri === current.nft.uri
    && stored.nft.hash === current.nft.hash
    && stored.artifact.mediaHash === current.artifact.mediaHash
    && stored.artifact.mediaType === current.artifact.mediaType
  );
}

function proof(input: {
  definition: DemoSkillDefinition;
  result: { ipId: `0x${string}`; tokenId: bigint; txHash: `0x${string}` };
  licenseTermsId: bigint;
  parentIpIds: `0x${string}`[];
  defaultMintingFee?: bigint;
  maxMintingFee?: bigint;
  metadata: PreparedMetadata;
}): RegistrationProof {
  return {
    stage: input.definition.stage,
    kind: input.definition.stage === "root" ? "Skill" : "Derivative",
    name: input.definition.name,
    ipId: input.result.ipId,
    tokenId: input.result.tokenId.toString(),
    txHash: input.result.txHash,
    licenseTermsId: input.licenseTermsId.toString(),
    parentIpIds: input.parentIpIds,
    defaultMintingFee: input.defaultMintingFee?.toString() ?? null,
    maxMintingFee: input.maxMintingFee?.toString() ?? null,
    metadata: input.metadata.proof,
  };
}

export async function runDemo(input: RunDemoInput): Promise<RegistrationManifest> {
  const chainId = await input.chain.getChainId();
  if (chainId !== AENEID_CHAIN_ID) {
    throw new Error(`Wrong network: expected Story Aeneid (${AENEID_CHAIN_ID}), received chain ${chainId}`);
  }

  const balance = await input.chain.getBalance(input.wallet);
  if (balance === 0n) {
    throw new Error(
      `Wallet ${input.wallet} on Story Aeneid (${AENEID_CHAIN_ID}) has exactly 0 IP. Fund it manually at ${AENEID_FAUCET_URL}`,
    );
  }

  const manifest = await input.store.load();
  ensureResumableManifest(manifest, input.wallet);
  const skills = input.skills ?? DEMO_SKILLS;
  const metadata = new Map<DemoStage, PreparedMetadata>();

  for (const stage of ["root", "child", "grandchild"] as const) {
    const definition = definitionFor(skills, stage);
    metadata.set(stage, await input.metadata.prepare({ ...definition, creatorAddress: input.wallet }));
  }

  for (const stage of ["root", "child", "grandchild"] as const) {
    const stored = manifest.registrations[stage];
    if (stored) {
      const current = metadata.get(stage);
      if (!current) throw new Error(`${stage} metadata was not prepared`);
      if (!metadataProofMatches(stored.metadata, current.proof)) {
        throw new Error(
          `${stage} metadata proof drift detected: the current artifact or metadata no longer matches registrations.json. Restore the recorded inputs or start a separate proof artifact before resuming.`,
        );
      }
    }
  }

  if (!manifest.spgNftContract) {
    const collection = await input.chain.createCollection({
      name: "Skill Asset Protocol Demo",
      symbol: "SKILL",
      mintFeeRecipient: input.wallet,
    });
    manifest.wallet = input.wallet;
    manifest.spgNftContract = collection.spgNftContract;
    manifest.collectionTxHash = collection.txHash;
    manifest.status = "partial";
    await input.store.save(manifest);
  }

  const spgNftContract = manifest.spgNftContract;
  if (!spgNftContract) throw new Error("Collection transaction confirmed without an SPG NFT contract");

  if (!manifest.registrations.root) {
    const definition = definitionFor(skills, "root");
    const prepared = metadata.get("root");
    if (!prepared) throw new Error("Root Skill metadata was not prepared");
    const result = await input.chain.registerSkill({
      spgNftContract,
      metadata: prepared.onchain,
      defaultMintingFee: DEMO_ROOT_MINTING_FEE,
    });
    manifest.registrations.root = proof({
      definition,
      result,
      licenseTermsId: result.licenseTermsId,
      parentIpIds: [],
      defaultMintingFee: DEMO_ROOT_MINTING_FEE,
      metadata: prepared,
    });
    manifest.status = "partial";
    await input.store.save(manifest);
  }

  const root = manifest.registrations.root;
  if (!root) throw new Error("Root Skill transaction confirmed without a persisted proof");

  if (!manifest.registrations.child) {
    const definition = definitionFor(skills, "child");
    const prepared = metadata.get("child");
    if (!prepared) throw new Error("Child Derivative metadata was not prepared");
    const licenseTermsId = BigInt(root.licenseTermsId);
    const predicted = await input.chain.predictMintingLicenseFee({
      licensorIpId: root.ipId,
      licenseTermsId,
      amount: 1,
    });
    const result = await input.chain.registerDerivative({
      spgNftContract,
      parentIpId: root.ipId,
      licenseTermsId,
      maxMintingFee: predicted.tokenAmount,
      metadata: prepared.onchain,
    });
    manifest.registrations.child = proof({
      definition,
      result,
      licenseTermsId,
      parentIpIds: [root.ipId],
      maxMintingFee: predicted.tokenAmount,
      metadata: prepared,
    });
    manifest.status = "partial";
    await input.store.save(manifest);
  }

  const child = manifest.registrations.child;
  if (!child) throw new Error("Child Derivative transaction confirmed without a persisted proof");

  if (!manifest.registrations.grandchild) {
    const definition = definitionFor(skills, "grandchild");
    const prepared = metadata.get("grandchild");
    if (!prepared) throw new Error("Grandchild Derivative metadata was not prepared");
    const licenseTermsId = BigInt(child.licenseTermsId);
    const predicted = await input.chain.predictMintingLicenseFee({
      licensorIpId: child.ipId,
      licenseTermsId,
      amount: 1,
    });
    const result = await input.chain.registerDerivative({
      spgNftContract,
      parentIpId: child.ipId,
      licenseTermsId,
      maxMintingFee: predicted.tokenAmount,
      metadata: prepared.onchain,
    });
    manifest.registrations.grandchild = proof({
      definition,
      result,
      licenseTermsId,
      parentIpIds: [child.ipId],
      maxMintingFee: predicted.tokenAmount,
      metadata: prepared,
    });
    manifest.status = "complete";
    await input.store.save(manifest);
  }

  return manifest;
}

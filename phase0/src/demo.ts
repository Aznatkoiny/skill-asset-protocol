import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { formatEther, keccak256, parseEther } from "viem";

import { estimateRemainingDemoGasMinimum } from "./funding";
import {
  AENEID_NETWORK,
  parseRegistrationManifest,
  type DemoStage,
  type MetadataProof,
  type RegistrationManifest,
  type RegistrationProof,
  type RegistrationStore,
} from "./registrations";
import {
  operationIntentHash,
  runConfigHash,
  type CanonicalOperationIntent,
  type LeasedOperationJournal,
  type OperationStage,
  type PendingOperation,
} from "./transactions";

export const AENEID_CHAIN_ID = AENEID_NETWORK.chainId;
export const AENEID_FAUCET_URL = "https://aeneid.faucet.story.foundation/";
export const DEMO_ROOT_MINTING_FEE = parseEther("0.001");

const OPERATION_STAGES = ["collection", "root", "child", "grandchild"] as const;
const REGISTRATION_STAGES = ["root", "child", "grandchild"] as const;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const SERIALIZED_TRANSACTION = /^0x(?:[0-9a-fA-F]{2})+$/;

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

export interface PreparedChainTransaction {
  transactionHash: `0x${string}`;
  serializedTransaction: `0x${string}`;
}

export interface CollectionInput {
  name: string;
  symbol: string;
  mintFeeRecipient: `0x${string}`;
}

export interface CollectionResult {
  spgNftContract: `0x${string}`;
  txHash: `0x${string}`;
}

export interface SkillInput {
  spgNftContract: `0x${string}`;
  metadata: PreparedMetadata["onchain"];
  defaultMintingFee: bigint;
  revShare?: number;
  policy?: "LAP" | "LRP";
}

export interface SkillResult {
  ipId: `0x${string}`;
  tokenId: bigint;
  txHash: `0x${string}`;
  licenseTermsId: bigint;
  licenseTemplate: `0x${string}`;
}

export interface PredictFeeInput {
  licensorIpId: `0x${string}`;
  licenseTermsId: bigint;
  amount: number;
}

export interface DerivativeInput {
  spgNftContract: `0x${string}`;
  parentIpId: `0x${string}`;
  licenseTermsId: bigint;
  maxMintingFee: bigint;
  metadata: PreparedMetadata["onchain"];
}

export interface DerivativeResult {
  ipId: `0x${string}`;
  tokenId: bigint;
  txHash: `0x${string}`;
  licenseTermsId: bigint;
  licenseTemplate: `0x${string}`;
}

export interface DerivativeFeeReadiness {
  currencyToken: `0x${string}`;
  spender: `0x${string}`;
  requiredAmount: bigint;
  balance: bigint;
  allowance: bigint;
}

export interface DemoChain {
  getChainId(): Promise<number>;
  getBalance(address: `0x${string}`): Promise<bigint>;
  getGasPrice(): Promise<bigint>;
  prepareCollection(input: CollectionInput): Promise<PreparedChainTransaction>;
  prepareSkill(input: SkillInput): Promise<PreparedChainTransaction>;
  prepareDerivative(input: DerivativeInput): Promise<PreparedChainTransaction>;
  broadcastPrepared(input: PreparedChainTransaction): Promise<void>;
  confirmCollection(txHash: `0x${string}`): Promise<CollectionResult>;
  confirmSkill(input: {
    transactionHash: `0x${string}`;
    expectedCollection: `0x${string}`;
  }): Promise<SkillResult>;
  confirmDerivative(input: {
    transactionHash: `0x${string}`;
    expectedCollection: `0x${string}`;
    expectedParentIpId: `0x${string}`;
    expectedLicenseTermsId: bigint;
    expectedLicenseTemplate: `0x${string}`;
  }): Promise<DerivativeResult>;
  predictMintingLicenseFee(input: PredictFeeInput): Promise<{
    currencyToken: `0x${string}`;
    tokenAmount: bigint;
  }>;
  getDerivativeFeeReadiness(input: {
    wallet: `0x${string}`;
    currencyToken: `0x${string}`;
    requiredAmount: bigint;
  }): Promise<DerivativeFeeReadiness>;
}

export interface RunDemoInput {
  wallet: `0x${string}`;
  chain: DemoChain;
  metadata: DemoMetadataProvider;
  store: RegistrationStore;
  journal: LeasedOperationJournal;
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

interface ResolvedRunConfig {
  readonly hash: `0x${string}`;
  readonly artifactHashes: ReadonlyMap<DemoStage, `0x${string}`>;
  readonly definitions: ReadonlyMap<DemoStage, Readonly<DemoSkillDefinition>>;
}

interface ExecutedOperation<T> {
  result: T;
  operation: PendingOperation;
  journalRevision: number;
}

function sameHex(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}

function definitionFor(skills: readonly DemoSkillDefinition[], stage: DemoStage): DemoSkillDefinition {
  const matches = skills.filter((skill) => skill.stage === stage);
  if (matches.length !== 1) {
    throw new Error(`Expected exactly one demo Skill definition for ${stage}; received ${matches.length}`);
  }
  const definition = matches[0];
  if (!definition.name.trim() || !definition.description.trim() || !definition.artifactPath.trim()) {
    throw new Error(`${stage} definition must contain name, description, and artifact path`);
  }
  return definition;
}

function requiredAddress(value: `0x${string}` | null, label: string): `0x${string}` {
  if (!value || !ADDRESS.test(value)) throw new Error(`Pending intent is missing ${label}`);
  return value;
}

function requiredString(value: string | null, label: string): string {
  if (!value) throw new Error(`Pending intent is missing ${label}`);
  return value;
}

function operationId(wallet: `0x${string}`, stage: OperationStage): string {
  return `phase0:${wallet}:${stage}`;
}

function updateStatus(manifest: RegistrationManifest): void {
  if (!manifest.spgNftContract) {
    manifest.status = "not-run";
    return;
  }
  manifest.status = REGISTRATION_STAGES.every((stage) => manifest.registrations[stage] !== null)
    ? "complete"
    : "partial";
}

export function missingOperationStages(manifest: RegistrationManifest): OperationStage[] {
  const missing: OperationStage[] = [];
  if (!manifest.spgNftContract) missing.push("collection");
  for (const stage of REGISTRATION_STAGES) {
    if (!manifest.registrations[stage]) missing.push(stage);
  }
  return missing;
}

function ensureCurrentWallet(manifest: RegistrationManifest, wallet: `0x${string}`): void {
  if (manifest.wallet && !sameHex(manifest.wallet, wallet)) {
    throw new Error(`registrations.json belongs to wallet ${manifest.wallet}; current wallet is ${wallet}`);
  }
}

async function resolveRunConfig(
  wallet: `0x${string}`,
  skills: readonly DemoSkillDefinition[],
): Promise<ResolvedRunConfig> {
  if (skills.length !== REGISTRATION_STAGES.length) {
    throw new Error("Demo run configuration must contain exactly root, child, and grandchild definitions");
  }
  const artifactHashes = new Map<DemoStage, `0x${string}`>();
  const definitions = new Map<DemoStage, Readonly<DemoSkillDefinition>>();
  const stages = [];
  for (const stage of REGISTRATION_STAGES) {
    const definition = Object.freeze({ ...definitionFor(skills, stage) });
    const artifactSha256 = `0x${createHash("sha256")
      .update(await readFile(definition.artifactPath))
      .digest("hex")}` as const;
    artifactHashes.set(stage, artifactSha256);
    definitions.set(stage, definition);
    stages.push({
      stage,
      name: definition.name,
      description: definition.description,
      artifactPath: definition.artifactPath,
      artifactSha256,
    });
  }
  return {
    hash: runConfigHash({ chainId: AENEID_CHAIN_ID, wallet, stages }),
    artifactHashes,
    definitions,
  };
}

function resolvedDefinitionFor(
  resolved: ResolvedRunConfig,
  stage: DemoStage,
): Readonly<DemoSkillDefinition> {
  const definition = resolved.definitions.get(stage);
  if (!definition) throw new Error(`Resolved run configuration is missing the ${stage} definition`);
  return definition;
}

function verifyConfirmedArtifactHashes(
  manifest: RegistrationManifest,
  resolved: ResolvedRunConfig,
): void {
  for (const stage of REGISTRATION_STAGES) {
    const stored = manifest.registrations[stage];
    if (!stored) continue;
    const current = resolved.artifactHashes.get(stage);
    if (!current || !sameHex(stored.metadata.artifact.mediaHash, current)) {
      throw new Error(
        `${stage} artifact hash drift detected: restore the recorded local artifact before preparing a new transaction`,
      );
    }
  }
}

function metadataForIntent(input: {
  definition: DemoSkillDefinition;
  prepared: PreparedMetadata;
  artifactHash: `0x${string}`;
}): NonNullable<CanonicalOperationIntent["metadata"]> {
  const { definition, prepared, artifactHash } = input;
  if (prepared.proof.ip.uri !== prepared.onchain.ipMetadataURI
      || !sameHex(prepared.proof.ip.hash, prepared.onchain.ipMetadataHash)
      || prepared.proof.nft.uri !== prepared.onchain.nftMetadataURI
      || !sameHex(prepared.proof.nft.hash, prepared.onchain.nftMetadataHash)) {
    throw new Error(`${definition.stage} metadata proof does not match its on-chain URI/hash fields`);
  }
  if (resolve(prepared.proof.artifact.path) !== resolve(definition.artifactPath)
      || !sameHex(prepared.proof.artifact.mediaHash, artifactHash)) {
    throw new Error(`${definition.stage} metadata artifact proof does not match the current local artifact`);
  }
  if (prepared.proof.artifact.mediaType !== "text/markdown") {
    throw new Error(`${definition.stage} artifact media type must be text/markdown`);
  }
  return {
    ipMetadataURI: prepared.onchain.ipMetadataURI,
    ipMetadataHash: prepared.onchain.ipMetadataHash,
    nftMetadataURI: prepared.onchain.nftMetadataURI,
    nftMetadataHash: prepared.onchain.nftMetadataHash,
    artifactMediaHash: prepared.proof.artifact.mediaHash,
    artifactMediaType: prepared.proof.artifact.mediaType,
  };
}

function registrationProof(
  operation: PendingOperation,
  confirmed: SkillResult | DerivativeResult,
): RegistrationProof {
  const intent = operation.intent;
  if (operation.stage === "collection" || !intent.metadata) {
    throw new Error("A registration proof requires journal-bound metadata");
  }
  if (!sameHex(confirmed.txHash, operation.transactionHash)) {
    throw new Error(`Confirmed ${operation.stage} result does not match the journal transaction hash`);
  }
  const registrationName = requiredString(intent.registrationName, "registration name");
  const artifactPath = requiredString(intent.artifactPath, "artifact path");
  return {
    stage: operation.stage,
    kind: operation.stage === "root" ? "Skill" : "Derivative",
    name: registrationName,
    ipId: confirmed.ipId,
    tokenId: confirmed.tokenId.toString(),
    txHash: operation.transactionHash,
    licenseTermsId: confirmed.licenseTermsId.toString(),
    licenseTemplate: confirmed.licenseTemplate,
    parentIpIds: operation.stage === "root"
      ? []
      : [requiredAddress(intent.parentIpId, "parent IP")],
    defaultMintingFee: intent.defaultMintingFee,
    maxMintingFee: intent.maxMintingFee,
    metadata: {
      ip: { uri: intent.metadata.ipMetadataURI, hash: intent.metadata.ipMetadataHash },
      nft: { uri: intent.metadata.nftMetadataURI, hash: intent.metadata.nftMetadataHash },
      artifact: {
        path: artifactPath,
        mediaHash: intent.metadata.artifactMediaHash,
        mediaType: intent.metadata.artifactMediaType,
      },
    },
  };
}

function assertPendingIntegrity(operation: PendingOperation): void {
  if (operation.intent.stage !== operation.stage) {
    throw new Error("Pending operation stage does not match its intent stage");
  }
  const expectedIntentHash = operationIntentHash(operation.intent);
  if (operation.intentHash !== expectedIntentHash) {
    throw new Error("Pending operation intent hash does not match its canonical intent");
  }
  if (!HASH.test(operation.transactionHash)
      || !SERIALIZED_TRANSACTION.test(operation.serializedTransaction)
      || keccak256(operation.serializedTransaction) !== operation.transactionHash) {
    throw new Error("Pending operation transaction hash does not match its serialized transaction");
  }
  const expectedOperationId = operationId(operation.intent.wallet, operation.stage);
  if (operation.operationId !== expectedOperationId) {
    throw new Error(`Pending operation ID ${operation.operationId} does not match ${expectedOperationId}`);
  }
}

function confirmedHash(manifest: RegistrationManifest, pending: PendingOperation): `0x${string}` | null {
  return pending.stage === "collection"
    ? manifest.collectionTxHash
    : manifest.registrations[pending.stage]?.txHash ?? null;
}

function validatePendingPrerequisites(
  manifest: RegistrationManifest,
  pending: PendingOperation,
): void {
  const intent = pending.intent;
  if (intent.chainId !== AENEID_CHAIN_ID) {
    throw new Error(`Pending transaction targets chain ${intent.chainId}; expected Story Aeneid (${AENEID_CHAIN_ID})`);
  }
  if (manifest.wallet && !sameHex(manifest.wallet, intent.wallet)) {
    throw new Error("Pending transaction wallet does not match the persisted manifest wallet");
  }
  if (pending.stage === "collection") {
    if (manifest.spgNftContract || manifest.registrations.root
        || manifest.registrations.child || manifest.registrations.grandchild) {
      throw new Error("Pending collection transaction conflicts with later persisted proof");
    }
    return;
  }
  const collection = requiredAddress(intent.spgNftContract, "SPG collection");
  if (!manifest.spgNftContract || !sameHex(manifest.spgNftContract, collection)) {
    throw new Error(`Pending ${pending.stage} transaction does not match the persisted SPG collection`);
  }
  if (pending.stage === "root") {
    if (manifest.registrations.child || manifest.registrations.grandchild) {
      throw new Error("Pending root transaction conflicts with persisted Derivative proof");
    }
    return;
  }
  const parent = pending.stage === "child"
    ? manifest.registrations.root
    : manifest.registrations.child;
  if (!parent) throw new Error(`Pending ${pending.stage} transaction is missing its persisted parent proof`);
  if (!sameHex(parent.ipId, requiredAddress(intent.parentIpId, "parent IP"))) {
    throw new Error(`Pending ${pending.stage} parent IP does not match the persisted parent proof`);
  }
  if (parent.licenseTermsId !== requiredString(intent.licenseTermsId, "license terms ID")) {
    throw new Error(`Pending ${pending.stage} license terms do not match the persisted parent proof`);
  }
  if (!sameHex(parent.licenseTemplate, requiredAddress(intent.licenseTemplate, "license template"))) {
    throw new Error(`Pending ${pending.stage} license template does not match the persisted parent proof`);
  }
  if (pending.stage === "child" && manifest.registrations.grandchild) {
    throw new Error("Pending child transaction conflicts with a persisted grandchild proof");
  }
}

async function executeOrResume<T>(input: {
  journal: LeasedOperationJournal;
  operationId: string;
  stage: OperationStage;
  intent: CanonicalOperationIntent;
  prepare(): Promise<PreparedChainTransaction>;
  broadcast(tx: PreparedChainTransaction): Promise<void>;
  confirm(operation: PendingOperation): Promise<T>;
}): Promise<ExecutedOperation<T>> {
  const intentHash = operationIntentHash(input.intent);
  let snapshot = await input.journal.load();
  let pending = snapshot.operation;
  if (pending) {
    assertPendingIntegrity(pending);
    if (pending.operationId !== input.operationId
        || pending.stage !== input.stage
        || pending.intentHash !== intentHash) {
      throw new Error(`Pending ${pending.stage} transaction does not match the current ${input.stage} intent`);
    }
  } else {
    const prepared = await input.prepare();
    if (!HASH.test(prepared.transactionHash)
        || !SERIALIZED_TRANSACTION.test(prepared.serializedTransaction)
        || keccak256(prepared.serializedTransaction) !== prepared.transactionHash) {
      throw new Error("Prepared transaction hash does not match its serialized transaction");
    }
    pending = {
      schemaVersion: 1,
      operationId: input.operationId,
      stage: input.stage,
      intent: input.intent,
      intentHash,
      transactionHash: prepared.transactionHash,
      serializedTransaction: prepared.serializedTransaction,
      state: "prepared",
    };
    snapshot = await input.journal.save(pending, snapshot.revision);
  }
  await input.broadcast({
    transactionHash: pending.transactionHash,
    serializedTransaction: pending.serializedTransaction,
  });
  if (pending.state !== "broadcast") {
    pending = { ...pending, state: "broadcast" };
    snapshot = await input.journal.save(pending, snapshot.revision);
  }
  const result = await input.confirm(pending);
  return { result, operation: pending, journalRevision: snapshot.revision };
}

async function requireDerivativeFeeReadiness(input: {
  chain: DemoChain;
  wallet: `0x${string}`;
  predicted: { currencyToken: `0x${string}`; tokenAmount: bigint };
}): Promise<DerivativeFeeReadiness> {
  if (input.predicted.tokenAmount < 0n) throw new Error("Predicted Derivative fee cannot be negative");
  const readiness = await input.chain.getDerivativeFeeReadiness({
    wallet: input.wallet,
    currencyToken: input.predicted.currencyToken,
    requiredAmount: input.predicted.tokenAmount,
  });
  if (!sameHex(readiness.currencyToken, input.predicted.currencyToken)
      || readiness.requiredAmount !== input.predicted.tokenAmount) {
    throw new Error("Derivative WIP readiness response does not match the predicted fee");
  }
  if (!ADDRESS.test(readiness.spender)) {
    throw new Error("Derivative WIP readiness response has an invalid spender");
  }
  if (readiness.balance < input.predicted.tokenAmount) {
    throw new Error(
      `WIP balance ${readiness.balance} is below required ${input.predicted.tokenAmount} `
      + `for Derivative fee token ${readiness.currencyToken}`,
    );
  }
  if (readiness.allowance < input.predicted.tokenAmount) {
    throw new Error(
      `WIP allowance ${readiness.allowance} is below required ${input.predicted.tokenAmount} `
      + `for DerivativeWorkflows spender ${readiness.spender}`,
    );
  }
  return readiness;
}

async function persistExecuted<T>(input: {
  executed: ExecutedOperation<T>;
  manifest: RegistrationManifest;
  store: RegistrationStore;
  journal: LeasedOperationJournal;
  apply(result: T, operation: PendingOperation): void;
}): Promise<void> {
  input.apply(input.executed.result, input.executed.operation);
  updateStatus(input.manifest);
  await input.store.save(input.manifest);
  await input.journal.clear(
    input.executed.operation.operationId,
    input.executed.journalRevision,
  );
}

async function recoverPending(input: {
  pending: PendingOperation;
  manifest: RegistrationManifest;
  chain: DemoChain;
  store: RegistrationStore;
  journal: LeasedOperationJournal;
}): Promise<void> {
  const pending = input.pending;
  const executed = await executeOrResume({
    journal: input.journal,
    operationId: pending.operationId,
    stage: pending.stage,
    intent: pending.intent,
    prepare: async () => {
      throw new Error("Recovery must never prepare a replacement transaction");
    },
    broadcast: (transaction) => input.chain.broadcastPrepared(transaction),
    confirm: async (operation) => {
      if (operation.stage === "collection") {
        return input.chain.confirmCollection(operation.transactionHash);
      }
      if (operation.stage === "root") {
        return input.chain.confirmSkill({
          transactionHash: operation.transactionHash,
          expectedCollection: requiredAddress(operation.intent.spgNftContract, "SPG collection"),
        });
      }
      return input.chain.confirmDerivative({
        transactionHash: operation.transactionHash,
        expectedCollection: requiredAddress(operation.intent.spgNftContract, "SPG collection"),
        expectedParentIpId: requiredAddress(operation.intent.parentIpId, "parent IP"),
        expectedLicenseTermsId: BigInt(requiredString(operation.intent.licenseTermsId, "license terms ID")),
        expectedLicenseTemplate: requiredAddress(operation.intent.licenseTemplate, "license template"),
      });
    },
  });
  await persistExecuted({
    executed,
    manifest: input.manifest,
    store: input.store,
    journal: input.journal,
    apply: (result, operation) => {
      if (operation.stage === "collection") {
        const collection = result as CollectionResult;
        if (!sameHex(collection.txHash, operation.transactionHash)) {
          throw new Error("Confirmed collection result does not match the journal transaction hash");
        }
        input.manifest.wallet = operation.intent.wallet;
        input.manifest.spgNftContract = collection.spgNftContract;
        input.manifest.collectionTxHash = operation.transactionHash;
      } else {
        input.manifest.registrations[operation.stage] = registrationProof(
          operation,
          result as SkillResult | DerivativeResult,
        );
      }
    },
  });
}

function collectionIntent(input: {
  wallet: `0x${string}`;
  runConfigHash: `0x${string}`;
}): CanonicalOperationIntent {
  return {
    stage: "collection",
    chainId: AENEID_CHAIN_ID,
    wallet: input.wallet,
    registrationName: null,
    artifactPath: null,
    spgNftContract: null,
    parentIpId: null,
    licenseTermsId: null,
    licenseTemplate: null,
    currencyToken: null,
    defaultMintingFee: null,
    maxMintingFee: null,
    metadata: null,
    runConfigHash: input.runConfigHash,
  };
}

export async function runDemo(input: RunDemoInput): Promise<RegistrationManifest> {
  const chainId = await input.chain.getChainId();
  if (chainId !== AENEID_CHAIN_ID) {
    throw new Error(`Wrong network: expected Story Aeneid (${AENEID_CHAIN_ID}), received chain ${chainId}`);
  }

  const manifest = parseRegistrationManifest(await input.store.load());
  const skills = input.skills ?? DEMO_SKILLS;
  const initialSnapshot = await input.journal.load();
  const initialPending = initialSnapshot.operation;
  let recoveredRunConfigHash: `0x${string}` | null = null;
  let resolved: ResolvedRunConfig | null = null;

  if (initialPending) {
    assertPendingIntegrity(initialPending);
    recoveredRunConfigHash = initialPending.intent.runConfigHash;
    const persistedHash = confirmedHash(manifest, initialPending);
    if (persistedHash) {
      if (!sameHex(persistedHash, initialPending.transactionHash)) {
        throw new Error(`Confirmed ${initialPending.stage} proof does not match the pending transaction hash`);
      }
      await input.journal.clear(initialPending.operationId, initialSnapshot.revision);
    } else {
      validatePendingPrerequisites(manifest, initialPending);
      await recoverPending({
        pending: initialPending,
        manifest,
        chain: input.chain,
        store: input.store,
        journal: input.journal,
      });
    }

    resolved = await resolveRunConfig(input.wallet, skills);
    if (resolved.hash !== recoveredRunConfigHash) {
      throw new Error("Recovered pending transaction, but current run configuration differs");
    }
  }

  ensureCurrentWallet(manifest, input.wallet);
  const remainingStages = missingOperationStages(manifest);
  if (remainingStages.length === 0) return manifest;

  const [balance, gasPrice] = await Promise.all([
    input.chain.getBalance(input.wallet),
    input.chain.getGasPrice(),
  ]);
  const requiredMinimum = estimateRemainingDemoGasMinimum({
    gasPrice,
    remainingNewWrites: remainingStages.length,
  });
  if (balance < requiredMinimum) {
    throw new Error(
      `Wallet ${input.wallet} has ${formatEther(balance)} IP; `
      + `estimated native-gas minimum for ${remainingStages.join(",")} is `
      + `${formatEther(requiredMinimum)} IP. Fund it manually at ${AENEID_FAUCET_URL}`,
    );
  }

  resolved ??= await resolveRunConfig(input.wallet, skills);
  verifyConfirmedArtifactHashes(manifest, resolved);

  if (!manifest.spgNftContract) {
    const intent = collectionIntent({ wallet: input.wallet, runConfigHash: resolved.hash });
    const executed = await executeOrResume({
      journal: input.journal,
      operationId: operationId(input.wallet, "collection"),
      stage: "collection",
      intent,
      prepare: () => input.chain.prepareCollection({
        name: "Skill Asset Protocol Demo",
        symbol: "SKILL",
        mintFeeRecipient: input.wallet,
      }),
      broadcast: (transaction) => input.chain.broadcastPrepared(transaction),
      confirm: (operation) => input.chain.confirmCollection(operation.transactionHash),
    });
    await persistExecuted({
      executed,
      manifest,
      store: input.store,
      journal: input.journal,
      apply: (collection, operation) => {
        if (!sameHex(collection.txHash, operation.transactionHash)) {
          throw new Error("Confirmed collection result does not match the journal transaction hash");
        }
        manifest.wallet = operation.intent.wallet;
        manifest.spgNftContract = collection.spgNftContract;
        manifest.collectionTxHash = operation.transactionHash;
      },
    });
  }

  const spgNftContract = manifest.spgNftContract;
  if (!spgNftContract) throw new Error("Collection transaction confirmed without an SPG NFT contract");

  if (!manifest.registrations.root) {
    const definition = resolvedDefinitionFor(resolved, "root");
    const prepared = await input.metadata.prepare({ ...definition, creatorAddress: input.wallet });
    const artifactHash = resolved.artifactHashes.get("root");
    if (!artifactHash) throw new Error("Root artifact hash was not resolved");
    const intent: CanonicalOperationIntent = {
      stage: "root",
      chainId: AENEID_CHAIN_ID,
      wallet: input.wallet,
      registrationName: definition.name,
      artifactPath: definition.artifactPath,
      spgNftContract,
      parentIpId: null,
      licenseTermsId: null,
      licenseTemplate: null,
      currencyToken: null,
      defaultMintingFee: DEMO_ROOT_MINTING_FEE.toString(),
      maxMintingFee: null,
      metadata: metadataForIntent({ definition, prepared, artifactHash }),
      runConfigHash: resolved.hash,
    };
    const executed = await executeOrResume({
      journal: input.journal,
      operationId: operationId(input.wallet, "root"),
      stage: "root",
      intent,
      prepare: () => input.chain.prepareSkill({
        spgNftContract,
        metadata: prepared.onchain,
        defaultMintingFee: DEMO_ROOT_MINTING_FEE,
      }),
      broadcast: (transaction) => input.chain.broadcastPrepared(transaction),
      confirm: (operation) => input.chain.confirmSkill({
        transactionHash: operation.transactionHash,
        expectedCollection: requiredAddress(operation.intent.spgNftContract, "SPG collection"),
      }),
    });
    await persistExecuted({
      executed,
      manifest,
      store: input.store,
      journal: input.journal,
      apply: (result, operation) => {
        manifest.registrations.root = registrationProof(operation, result);
      },
    });
  }

  for (const stage of ["child", "grandchild"] as const) {
    if (manifest.registrations[stage]) continue;
    const parent = stage === "child" ? manifest.registrations.root : manifest.registrations.child;
    if (!parent) throw new Error(`${stage} Derivative is missing its persisted parent proof`);
    const definition = resolvedDefinitionFor(resolved, stage);
    const predicted = await input.chain.predictMintingLicenseFee({
      licensorIpId: parent.ipId,
      licenseTermsId: BigInt(parent.licenseTermsId),
      amount: 1,
    });
    if (!ADDRESS.test(predicted.currencyToken)) {
      throw new Error("Predicted Derivative fee currency is not an address");
    }
    const prepared = await input.metadata.prepare({ ...definition, creatorAddress: input.wallet });
    const artifactHash = resolved.artifactHashes.get(stage);
    if (!artifactHash) throw new Error(`${stage} artifact hash was not resolved`);
    const intent: CanonicalOperationIntent = {
      stage,
      chainId: AENEID_CHAIN_ID,
      wallet: input.wallet,
      registrationName: definition.name,
      artifactPath: definition.artifactPath,
      spgNftContract,
      parentIpId: parent.ipId,
      licenseTermsId: parent.licenseTermsId,
      licenseTemplate: parent.licenseTemplate,
      currencyToken: predicted.currencyToken,
      defaultMintingFee: null,
      maxMintingFee: predicted.tokenAmount.toString(),
      metadata: metadataForIntent({ definition, prepared, artifactHash }),
      runConfigHash: resolved.hash,
    };
    const derivativeInput: DerivativeInput = {
      spgNftContract,
      parentIpId: parent.ipId,
      licenseTermsId: BigInt(parent.licenseTermsId),
      maxMintingFee: predicted.tokenAmount,
      metadata: prepared.onchain,
    };
    const executed = await executeOrResume({
      journal: input.journal,
      operationId: operationId(input.wallet, stage),
      stage,
      intent,
      prepare: async () => {
        await requireDerivativeFeeReadiness({ chain: input.chain, wallet: input.wallet, predicted });
        return input.chain.prepareDerivative(derivativeInput);
      },
      broadcast: (transaction) => input.chain.broadcastPrepared(transaction),
      confirm: (operation) => input.chain.confirmDerivative({
        transactionHash: operation.transactionHash,
        expectedCollection: requiredAddress(operation.intent.spgNftContract, "SPG collection"),
        expectedParentIpId: requiredAddress(operation.intent.parentIpId, "parent IP"),
        expectedLicenseTermsId: BigInt(requiredString(operation.intent.licenseTermsId, "license terms ID")),
        expectedLicenseTemplate: requiredAddress(operation.intent.licenseTemplate, "license template"),
      }),
    });
    await persistExecuted({
      executed,
      manifest,
      store: input.store,
      journal: input.journal,
      apply: (result, operation) => {
        manifest.registrations[stage] = registrationProof(operation, result);
      },
    });
  }

  return manifest;
}

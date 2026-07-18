import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { WIP_TOKEN_ADDRESS } from "@story-protocol/core-sdk";
import { keccak256 } from "viem";

import {
  AENEID_CHAIN_ID,
  AENEID_FAUCET_URL,
  DEMO_ROOT_MINTING_FEE,
  DEMO_SKILLS,
  runDemo,
  type CollectionInput,
  type DemoChain,
  type DemoMetadataProvider,
  type DemoSkillDefinition,
  type DerivativeInput,
  type PreparedChainTransaction,
  type SkillInput,
} from "../src/demo";
import { HttpMetadataProvider } from "../src/metadata";
import {
  FileRegistrationStore,
  createEmptyRegistrationManifest,
  type RegistrationManifest,
  type RegistrationProof,
  type RegistrationStore,
} from "../src/registrations";
import {
  operationIntentHash,
  runConfigHash,
  type CanonicalOperationIntent,
  type JournalSnapshot,
  type LeasedOperationJournal,
  type OperationState,
  type OperationStage,
  type PendingOperation,
} from "../src/transactions";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const OTHER_WALLET = "0x00000000000000000000000000000000000000ff" as const;
const COLLECTION = "0x00000000000000000000000000000000000000bb" as const;
const LICENSE_TEMPLATE = "0x00000000000000000000000000000000000000cc" as const;
const DERIVATIVE_FEE_SPENDER = "0x00000000000000000000000000000000000000dd" as const;
const ROOT = "0x0000000000000000000000000000000000000001" as const;
const CHILD = "0x0000000000000000000000000000000000000002" as const;
const GRANDCHILD = "0x0000000000000000000000000000000000000003" as const;
const GAS_PRICE = 2n;
const FUNDED_BALANCE = 20_000_000n;

const SERIALIZED: Record<OperationStage, `0x${string}`> = {
  collection: `0x${"11".repeat(64)}`,
  root: `0x${"22".repeat(64)}`,
  child: `0x${"33".repeat(64)}`,
  grandchild: `0x${"44".repeat(64)}`,
};

const TRANSACTION_HASH: Record<OperationStage, `0x${string}`> = {
  collection: keccak256(SERIALIZED.collection),
  root: keccak256(SERIALIZED.root),
  child: keccak256(SERIALIZED.child),
  grandchild: keccak256(SERIALIZED.grandchild),
};

function clone<T>(value: T): T {
  return structuredClone(value);
}

function fakePinataFetcher(): typeof fetch {
  const pinned = new Map<string, Buffer>();
  let uploadCount = 0;
  return async (input, init) => {
    const url = String(input);
    if (init?.method === "POST") {
      assert.equal(url, "https://uploads.pinata.cloud/v3/files");
      assert.ok(init.body instanceof FormData);
      const file = init.body.get("file");
      assert.ok(file instanceof Blob);
      uploadCount += 1;
      const cid = `bafyabsolute${uploadCount}`;
      pinned.set(`https://gateway.pinata.cloud/ipfs/${cid}`, Buffer.from(await file.arrayBuffer()));
      return Response.json({ data: { cid } });
    }
    const bytes = pinned.get(url);
    assert.ok(bytes, `unexpected metadata fetch ${url}`);
    return new Response(bytes.toString("utf8"));
  };
}

async function sha256(path: string): Promise<`0x${string}`> {
  return `0x${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

function definition(stage: "root" | "child" | "grandchild", skills = DEMO_SKILLS) {
  const found = skills.find((value) => value.stage === stage);
  if (!found) throw new Error(`missing ${stage} definition`);
  return found;
}

async function configHash(wallet = WALLET, skills = DEMO_SKILLS) {
  return runConfigHash({
    chainId: AENEID_CHAIN_ID,
    wallet,
    stages: await Promise.all((["root", "child", "grandchild"] as const).map(async (stage) => {
      const value = definition(stage, skills);
      return {
        stage,
        name: value.name,
        description: value.description,
        artifactPath: value.artifactPath,
        artifactSha256: await sha256(value.artifactPath),
      };
    })),
  });
}

class MemoryStore implements RegistrationStore {
  saveCalls = 0;
  snapshots: RegistrationManifest[] = [];
  throwAfterSavingStage: "root" | "child" | "grandchild" | null = null;

  constructor(public manifest = createEmptyRegistrationManifest()) {}

  async load(): Promise<RegistrationManifest> {
    return clone(this.manifest);
  }

  async save(manifest: RegistrationManifest): Promise<void> {
    this.saveCalls += 1;
    this.manifest = clone(manifest);
    this.snapshots.push(clone(manifest));
    const stage = this.throwAfterSavingStage;
    if (stage && manifest.registrations[stage]) {
      this.throwAfterSavingStage = null;
      throw new Error(`simulated crash after ${stage} manifest rename`);
    }
  }
}

class MemoryJournal implements LeasedOperationJournal {
  revision = 0;
  operation: PendingOperation | null = null;
  saveCalls = 0;
  clearCalls = 0;
  crashAfterNextSave = false;

  constructor(snapshot?: JournalSnapshot) {
    if (snapshot) {
      this.revision = snapshot.revision;
      this.operation = clone(snapshot.operation);
    }
  }

  async load(): Promise<JournalSnapshot> {
    return { revision: this.revision, operation: clone(this.operation) };
  }

  async save(operation: PendingOperation, expectedRevision: number): Promise<JournalSnapshot> {
    assert.equal(expectedRevision, this.revision, "test journal CAS revision");
    this.revision += 1;
    this.operation = clone(operation);
    this.saveCalls += 1;
    if (this.crashAfterNextSave) {
      this.crashAfterNextSave = false;
      throw new Error("simulated crash after journal save");
    }
    return this.load();
  }

  async clear(operationId: string, expectedRevision: number): Promise<JournalSnapshot> {
    assert.equal(expectedRevision, this.revision, "test journal clear CAS revision");
    assert.equal(this.operation?.operationId, operationId, "test journal clear operation");
    this.revision += 1;
    this.operation = null;
    this.clearCalls += 1;
    return this.load();
  }
}

class FakeMetadata implements DemoMetadataProvider {
  calls = 0;
  stages: string[] = [];
  failWith: string | null = null;

  async prepare(input: DemoSkillDefinition) {
    this.calls += 1;
    this.stages.push(input.stage);
    if (this.failWith) throw new Error(this.failWith);
    const digit = input.stage === "root" ? "1" : input.stage === "child" ? "2" : "3";
    const metadataHash = `0x${digit.repeat(64)}` as const;
    const artifactHash = await sha256(input.artifactPath);
    return {
      onchain: {
        ipMetadataURI: `https://example.test/${input.stage}/ip`,
        ipMetadataHash: metadataHash,
        nftMetadataURI: `https://example.test/${input.stage}/nft`,
        nftMetadataHash: metadataHash,
      },
      proof: {
        ip: { uri: `https://example.test/${input.stage}/ip`, hash: metadataHash },
        nft: { uri: `https://example.test/${input.stage}/nft`, hash: metadataHash },
        artifact: {
          path: input.artifactPath,
          mediaHash: artifactHash,
          mediaType: "text/markdown",
        },
      },
    };
  }
}

type CrashPoint = "broadcast" | "confirm" | null;

class CrashableChain implements DemoChain {
  chainId: number = AENEID_CHAIN_ID;
  balance = FUNDED_BALANCE;
  gasPrice = GAS_PRICE;
  predictedCurrencyToken = WIP_TOKEN_ADDRESS;
  predictedFee = 123n;
  wipBalance = 1_000_000_000_000_000_000n;
  wipAllowance = 1_000_000_000_000_000_000n;
  derivativeFeeSpender = DERIVATIVE_FEE_SPENDER;
  balanceReads = 0;
  gasPriceReads = 0;
  predictionCalls = 0;
  feeReadinessCalls = 0;
  prepareCounts: Record<OperationStage, number> = {
    collection: 0,
    root: 0,
    child: 0,
    grandchild: 0,
  };
  preparedHashes: `0x${string}`[] = [];
  broadcastTransactions: PreparedChainTransaction[] = [];
  confirmHashes: `0x${string}`[] = [];
  stopAfterRoot = false;
  consumeBalancesOnBroadcast = false;
  private crashed = false;

  constructor(
    public crashAfter: CrashPoint = null,
    public crashStage: OperationStage = "root",
  ) {}

  resumedWithoutCrash(): CrashableChain {
    const next = new CrashableChain(null, this.crashStage);
    next.chainId = this.chainId;
    next.balance = this.balance;
    next.gasPrice = this.gasPrice;
    next.predictedCurrencyToken = this.predictedCurrencyToken;
    next.predictedFee = this.predictedFee;
    next.wipBalance = this.wipBalance;
    next.wipAllowance = this.wipAllowance;
    next.derivativeFeeSpender = this.derivativeFeeSpender;
    return next;
  }

  async getChainId() {
    return this.chainId;
  }

  async getBalance() {
    this.balanceReads += 1;
    return this.balance;
  }

  async getGasPrice() {
    this.gasPriceReads += 1;
    return this.gasPrice;
  }

  async prepareCollection(_input: CollectionInput) {
    return this.prepare("collection");
  }

  async prepareSkill(_input: SkillInput) {
    return this.prepare("root");
  }

  async prepareDerivative(input: DerivativeInput) {
    return this.prepare(input.parentIpId.toLowerCase() === ROOT.toLowerCase() ? "child" : "grandchild");
  }

  async broadcastPrepared(input: PreparedChainTransaction) {
    assert.equal(keccak256(input.serializedTransaction), input.transactionHash);
    this.broadcastTransactions.push(clone(input));
    const stage = this.stageForHash(input.transactionHash);
    if (this.consumeBalancesOnBroadcast && (stage === "child" || stage === "grandchild")) {
      this.balance = 0n;
      this.wipBalance = 0n;
      this.wipAllowance = 0n;
    }
    this.maybeCrash("broadcast", stage);
  }

  async confirmCollection(transactionHash: `0x${string}`) {
    this.confirm("collection", transactionHash);
    return { spgNftContract: COLLECTION, txHash: transactionHash };
  }

  async confirmSkill(input: { transactionHash: `0x${string}`; expectedCollection: `0x${string}` }) {
    assert.equal(input.expectedCollection.toLowerCase(), COLLECTION.toLowerCase());
    this.confirm("root", input.transactionHash);
    return {
      ipId: ROOT,
      tokenId: 1n,
      txHash: input.transactionHash,
      licenseTermsId: 7n,
      licenseTemplate: LICENSE_TEMPLATE,
    };
  }

  async confirmDerivative(input: {
    transactionHash: `0x${string}`;
    expectedCollection: `0x${string}`;
    expectedParentIpId: `0x${string}`;
    expectedLicenseTermsId: bigint;
    expectedLicenseTemplate: `0x${string}`;
  }) {
    assert.equal(input.expectedCollection.toLowerCase(), COLLECTION.toLowerCase());
    assert.equal(input.expectedLicenseTermsId, 7n);
    assert.equal(input.expectedLicenseTemplate.toLowerCase(), LICENSE_TEMPLATE.toLowerCase());
    const stage = input.expectedParentIpId.toLowerCase() === ROOT.toLowerCase() ? "child" : "grandchild";
    this.confirm(stage, input.transactionHash);
    return {
      ipId: stage === "child" ? CHILD : GRANDCHILD,
      tokenId: stage === "child" ? 2n : 3n,
      txHash: input.transactionHash,
      licenseTermsId: 7n,
      licenseTemplate: LICENSE_TEMPLATE,
    };
  }

  async predictMintingLicenseFee() {
    this.predictionCalls += 1;
    if (this.stopAfterRoot) throw new Error("stop after recovered root");
    return { currencyToken: this.predictedCurrencyToken, tokenAmount: this.predictedFee };
  }

  async getDerivativeFeeReadiness(input: {
    currencyToken: `0x${string}`;
    requiredAmount: bigint;
  }) {
    this.feeReadinessCalls += 1;
    return {
      currencyToken: input.currencyToken,
      spender: this.derivativeFeeSpender,
      requiredAmount: input.requiredAmount,
      balance: this.wipBalance,
      allowance: this.wipAllowance,
    };
  }

  private prepare(stage: OperationStage): PreparedChainTransaction {
    this.prepareCounts[stage] += 1;
    this.preparedHashes.push(TRANSACTION_HASH[stage]);
    return { serializedTransaction: SERIALIZED[stage], transactionHash: TRANSACTION_HASH[stage] };
  }

  private confirm(stage: OperationStage, transactionHash: `0x${string}`) {
    assert.equal(transactionHash, TRANSACTION_HASH[stage]);
    this.confirmHashes.push(transactionHash);
    this.maybeCrash("confirm", stage);
  }

  private maybeCrash(point: Exclude<CrashPoint, null>, stage: OperationStage) {
    if (!this.crashed && this.crashAfter === point && this.crashStage === stage) {
      this.crashed = true;
      throw new Error(`simulated crash after ${stage} ${point}`);
    }
  }

  private stageForHash(hash: `0x${string}`): OperationStage {
    const found = (Object.entries(TRANSACTION_HASH) as Array<[OperationStage, `0x${string}`]>)
      .find(([, candidate]) => candidate === hash)?.[0];
    if (!found) throw new Error(`unknown transaction ${hash}`);
    return found;
  }
}

async function proof(
  stage: "root" | "child" | "grandchild",
  input: { ipId: `0x${string}`; parentIpIds: `0x${string}`[] },
): Promise<RegistrationProof> {
  const value = definition(stage);
  const digit = stage === "root" ? "1" : stage === "child" ? "2" : "3";
  const metadataHash = `0x${digit.repeat(64)}` as const;
  return {
    stage,
    kind: stage === "root" ? "Skill" : "Derivative",
    name: value.name,
    ipId: input.ipId,
    tokenId: stage === "root" ? "1" : stage === "child" ? "2" : "3",
    txHash: TRANSACTION_HASH[stage],
    licenseTermsId: "7",
    licenseTemplate: LICENSE_TEMPLATE,
    parentIpIds: input.parentIpIds,
    defaultMintingFee: stage === "root" ? DEMO_ROOT_MINTING_FEE.toString() : null,
    maxMintingFee: stage === "root" ? null : "123",
    metadata: {
      ip: { uri: `https://example.test/${stage}/ip`, hash: metadataHash },
      nft: { uri: `https://example.test/${stage}/nft`, hash: metadataHash },
      artifact: {
        path: value.artifactPath,
        mediaHash: await sha256(value.artifactPath),
        mediaType: "text/markdown",
      },
    },
  };
}

function collectionOnlyStore() {
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = WALLET;
  manifest.spgNftContract = COLLECTION;
  manifest.collectionTxHash = TRANSACTION_HASH.collection;
  return new MemoryStore(manifest);
}

async function rootOnlyStore() {
  const store = collectionOnlyStore();
  store.manifest.registrations.root = await proof("root", { ipId: ROOT, parentIpIds: [] });
  return store;
}

async function throughChildStore() {
  const store = await rootOnlyStore();
  store.manifest.registrations.child = await proof("child", { ipId: CHILD, parentIpIds: [ROOT] });
  return store;
}

async function completeStore() {
  const store = await throughChildStore();
  store.manifest.registrations.grandchild = await proof("grandchild", {
    ipId: GRANDCHILD,
    parentIpIds: [CHILD],
  });
  store.manifest.status = "complete";
  return store;
}

function intentMetadata(prepared: Awaited<ReturnType<FakeMetadata["prepare"]>>) {
  return {
    ipMetadataURI: prepared.onchain.ipMetadataURI,
    ipMetadataHash: prepared.onchain.ipMetadataHash,
    nftMetadataURI: prepared.onchain.nftMetadataURI,
    nftMetadataHash: prepared.onchain.nftMetadataHash,
    artifactMediaHash: prepared.proof.artifact.mediaHash,
    artifactMediaType: prepared.proof.artifact.mediaType,
  };
}

function pendingOperation(input: {
  stage: "child" | "grandchild";
  intent: CanonicalOperationIntent;
  state?: OperationState;
}): PendingOperation {
  return {
    schemaVersion: 1,
    operationId: `phase0:${input.intent.wallet}:${input.stage}`,
    stage: input.stage,
    intent: input.intent,
    intentHash: operationIntentHash(input.intent),
    transactionHash: TRANSACTION_HASH[input.stage],
    serializedTransaction: SERIALIZED[input.stage],
    state: input.state ?? "prepared",
  };
}

async function derivativeIntent(input: {
  stage: "child" | "grandchild";
  parentIpId: `0x${string}`;
  registrationName?: string;
  artifactPath?: string;
  persistedRunConfigHash?: `0x${string}`;
}) {
  const value = definition(input.stage);
  const prepared = await new FakeMetadata().prepare({
    ...value,
    artifactPath: input.artifactPath ?? value.artifactPath,
  });
  return {
    stage: input.stage,
    chainId: AENEID_CHAIN_ID,
    wallet: WALLET,
    registrationName: input.registrationName ?? value.name,
    artifactPath: input.artifactPath ?? value.artifactPath,
    spgNftContract: COLLECTION,
    parentIpId: input.parentIpId,
    licenseTermsId: "7",
    licenseTemplate: LICENSE_TEMPLATE,
    currencyToken: WIP_TOKEN_ADDRESS,
    defaultMintingFee: null,
    maxMintingFee: "123",
    metadata: intentMetadata(prepared),
    runConfigHash: input.persistedRunConfigHash ?? await configHash(),
  } satisfies CanonicalOperationIntent;
}

test("a funded demo journals and confirms one collection, Skill, child, and grandchild", async () => {
  const chain = new CrashableChain();
  const metadata = new FakeMetadata();
  const store = new MemoryStore();
  const journal = new MemoryJournal();

  const result = await runDemo({ wallet: WALLET, chain, metadata, store, journal });

  assert.equal(result.status, "complete");
  assert.deepEqual(chain.prepareCounts, { collection: 1, root: 1, child: 1, grandchild: 1 });
  assert.equal(chain.broadcastTransactions.length, 4);
  assert.equal(chain.confirmHashes.length, 4);
  assert.deepEqual(metadata.stages, ["root", "child", "grandchild"]);
  assert.equal(chain.balanceReads, 1);
  assert.equal(chain.gasPriceReads, 1);
  assert.equal(chain.feeReadinessCalls, 2);
  assert.equal(journal.operation, null);
  assert.equal(journal.revision, 12);
  assert.equal(store.saveCalls, 4);
  assert.equal(result.registrations.root?.licenseTemplate, LICENSE_TEMPLATE);
  assert.equal(result.registrations.child?.licenseTemplate, LICENSE_TEMPLATE);
  assert.equal(result.registrations.grandchild?.licenseTemplate, LICENSE_TEMPLATE);
});

test("the real metadata provider accepts an absolute demo artifact path at the journal boundary", async () => {
  const chain = new CrashableChain();
  chain.stopAfterRoot = true;
  const store = collectionOnlyStore();
  const metadata = new HttpMetadataProvider({
    fetcher: fakePinataFetcher(),
    pinataJwt: "fixture-token",
  });

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store, journal: new MemoryJournal() }),
    /stop after recovered root/,
  );

  assert.equal(store.manifest.registrations.root?.txHash, TRANSACTION_HASH.root);
  assert.equal(
    store.manifest.registrations.root?.metadata.artifact.path,
    definition("root").artifactPath,
  );
});

test("a nonzero but insufficient native balance stops before metadata or prepare", async () => {
  const chain = new CrashableChain();
  chain.balance = 1n;
  const metadata = new FakeMetadata();
  const journal = new MemoryJournal();

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store: new MemoryStore(), journal }),
    /estimated native-gas minimum.*Fund it manually/i,
  );

  assert.equal(metadata.calls, 0);
  assert.deepEqual(chain.prepareCounts, { collection: 0, root: 0, child: 0, grandchild: 0 });
  assert.equal(chain.broadcastTransactions.length, 0);
  assert.equal(journal.operation, null);
});

test("zero native balance reports the Aeneid faucet before metadata or prepare", async () => {
  const chain = new CrashableChain();
  chain.balance = 0n;
  const metadata = new FakeMetadata();
  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store: new MemoryStore(), journal: new MemoryJournal() }),
    new RegExp(AENEID_FAUCET_URL.replaceAll(".", "\\.")),
  );
  assert.equal(metadata.calls, 0);
  assert.equal(chain.prepareCounts.collection, 0);
});

test("wrong chain exits before manifest, journal, balances, or metadata", async () => {
  const chain = new CrashableChain();
  chain.chainId = 1514;
  const metadata = new FakeMetadata();
  const store = new MemoryStore();
  let journalLoads = 0;
  const journal = new MemoryJournal();
  const originalLoad = journal.load.bind(journal);
  journal.load = async () => { journalLoads += 1; return originalLoad(); };

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store, journal }),
    /expected Story Aeneid \(1315\).*1514/i,
  );
  assert.equal(journalLoads, 0);
  assert.equal(chain.balanceReads, 0);
  assert.equal(metadata.calls, 0);
});

for (const crashAfter of ["journal", "broadcast", "confirm", "manifest-save"] as const) {
  test(`resume after ${crashAfter} reuses the exact root transaction bytes and hash`, async () => {
    const store = collectionOnlyStore();
    const journal = new MemoryJournal();
    const first = new CrashableChain(
      crashAfter === "broadcast" || crashAfter === "confirm" ? crashAfter : null,
      "root",
    );
    if (crashAfter === "journal") journal.crashAfterNextSave = true;
    if (crashAfter === "manifest-save") store.throwAfterSavingStage = "root";

    await assert.rejects(
      runDemo({ wallet: WALLET, chain: first, metadata: new FakeMetadata(), store, journal }),
      /simulated crash/,
    );
    const pending = clone(journal.operation);
    assert.equal(pending?.stage, "root");
    assert.equal(pending?.transactionHash, TRANSACTION_HASH.root);
    assert.equal(pending?.serializedTransaction, SERIALIZED.root);

    const resumed = first.resumedWithoutCrash();
    resumed.stopAfterRoot = true;
    await assert.rejects(
      runDemo({ wallet: WALLET, chain: resumed, metadata: new FakeMetadata(), store, journal }),
      /stop after recovered root/,
    );

    assert.equal(resumed.prepareCounts.root, 0);
    assert.equal(
      resumed.broadcastTransactions.every((value) =>
        value.transactionHash === pending?.transactionHash
        && value.serializedTransaction === pending.serializedTransaction),
      true,
    );
    assert.equal(store.manifest.registrations.root?.txHash, pending?.transactionHash);
    assert.equal(journal.operation, null);
  });
}

test("manifest rename crash retains the exact root journal until durable recovery", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-manifest-resume-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const stableStore = new FileRegistrationStore(path);
  await stableStore.save(collectionOnlyStore().manifest);

  const journal = new MemoryJournal();
  const first = new CrashableChain();
  const crashingStore = new FileRegistrationStore(path, {
    afterRename: () => { throw new Error("simulated crash after root manifest rename"); },
  });
  await assert.rejects(
    runDemo({
      wallet: WALLET,
      chain: first,
      metadata: new FakeMetadata(),
      store: crashingStore,
      journal,
    }),
    /simulated crash after root manifest rename/,
  );

  const pending = clone(journal.operation);
  const pendingRevision = journal.revision;
  assert.equal(journal.clearCalls, 0);
  assert.equal(pendingRevision, 2);
  assert.equal(pending?.stage, "root");
  assert.equal(pending?.state, "broadcast");
  assert.equal(pending?.transactionHash, TRANSACTION_HASH.root);
  assert.equal(pending?.serializedTransaction, SERIALIZED.root);
  assert.equal((await stableStore.load()).registrations.root?.txHash, TRANSACTION_HASH.root);

  const resumed = first.resumedWithoutCrash();
  resumed.stopAfterRoot = true;
  await assert.rejects(
    runDemo({
      wallet: WALLET,
      chain: resumed,
      metadata: new FakeMetadata(),
      store: stableStore,
      journal,
    }),
    /stop after recovered root/,
  );

  assert.equal(resumed.prepareCounts.root, 0);
  assert.equal(resumed.broadcastTransactions.length, 0);
  assert.equal(resumed.confirmHashes.length, 0);
  assert.equal(journal.clearCalls, 1);
  assert.equal(journal.operation, null);
  assert.equal(journal.revision, pendingRevision + 1);
});

test("a corrupted persisted intent hash aborts before exact-byte broadcast", async () => {
  const store = await rootOnlyStore();
  const intent = await derivativeIntent({ stage: "child", parentIpId: ROOT });
  const pending = pendingOperation({ stage: "child", intent });
  pending.intent = { ...pending.intent, registrationName: "tampered-without-rehash" };
  const journal = new MemoryJournal({ revision: 1, operation: pending });
  const chain = new CrashableChain();

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata: new FakeMetadata(), store, journal }),
    /intent.*hash|does not match/i,
  );
  assert.equal(chain.broadcastTransactions.length, 0);
  assert.equal(chain.balanceReads, 0);
});

for (const crashAfter of ["broadcast", "confirm"] as const) {
  test(`depleted WIP cannot block exact child recovery after ${crashAfter}`, async () => {
    const store = await rootOnlyStore();
    const journal = new MemoryJournal();
    const first = new CrashableChain(crashAfter, "child");
    first.consumeBalancesOnBroadcast = true;
    await assert.rejects(
      runDemo({ wallet: WALLET, chain: first, metadata: new FakeMetadata(), store, journal }),
      /simulated crash/,
    );
    const pending = clone(journal.operation);
    assert.equal(pending?.stage, "child");

    const resumed = first.resumedWithoutCrash();
    const resumeMetadata = new FakeMetadata();
    resumeMetadata.failWith = "metadata must not run during child recovery";
    store.throwAfterSavingStage = "child";
    await assert.rejects(
      runDemo({ wallet: WALLET, chain: resumed, metadata: resumeMetadata, store, journal }),
      /simulated crash after child manifest rename/,
    );

    assert.equal(resumed.balanceReads, 0);
    assert.equal(resumed.gasPriceReads, 0);
    assert.equal(resumed.feeReadinessCalls, 0);
    assert.equal(resumed.prepareCounts.child, 0);
    assert.deepEqual(resumed.broadcastTransactions[0], {
      transactionHash: pending?.transactionHash,
      serializedTransaction: pending?.serializedTransaction,
    });
    assert.equal(resumed.confirmHashes[0], pending?.transactionHash);
    assert.equal(store.manifest.registrations.child?.txHash, pending?.transactionHash);
    assert.equal(resumeMetadata.calls, 0);
  });
}

for (const crashAfter of ["broadcast", "confirm"] as const) {
  test(`pending grandchild after ${crashAfter} completes with zero readiness or metadata reads`, async () => {
    const store = await throughChildStore();
    const journal = new MemoryJournal();
    const first = new CrashableChain(crashAfter, "grandchild");
    first.consumeBalancesOnBroadcast = true;
    await assert.rejects(
      runDemo({ wallet: WALLET, chain: first, metadata: new FakeMetadata(), store, journal }),
      /simulated crash/,
    );
    const pending = clone(journal.operation);
    assert.equal(pending?.stage, "grandchild");
    assert.equal(pending?.state, crashAfter === "broadcast" ? "prepared" : "broadcast");

    const chain = first.resumedWithoutCrash();
    const metadata = new FakeMetadata();
    metadata.failWith = "Pinata unavailable on resume";

    const result = await runDemo({ wallet: WALLET, chain, metadata, store, journal });

    assert.equal(result.status, "complete");
    assert.equal(chain.balanceReads, 0);
    assert.equal(chain.gasPriceReads, 0);
    assert.equal(chain.predictionCalls, 0);
    assert.equal(chain.feeReadinessCalls, 0);
    assert.equal(metadata.calls, 0);
    assert.equal(chain.prepareCounts.grandchild, 0);
    assert.deepEqual(chain.broadcastTransactions[0], {
      transactionHash: pending?.transactionHash,
      serializedTransaction: pending?.serializedTransaction,
    });
    assert.equal(chain.confirmHashes[0], pending?.transactionHash);
    assert.equal(result.registrations.grandchild?.txHash, pending?.transactionHash);
    assert.equal(journal.operation, null);
  });
}

test("recovered proof uses journal-bound fields, then run-config drift blocks new work", async () => {
  const store = await rootOnlyStore();
  const journalName = "journal-child-name";
  const journalPath = "fixtures/journal-child/SKILL.md";
  const baseIntent = await derivativeIntent({ stage: "child", parentIpId: ROOT });
  const intent: CanonicalOperationIntent = {
    ...baseIntent,
    registrationName: journalName,
    artifactPath: journalPath,
    metadata: baseIntent.metadata ? {
      ...baseIntent.metadata,
      artifactMediaHash: `0x${"9".repeat(64)}`,
    } : null,
    runConfigHash: `0x${"8".repeat(64)}`,
  };
  const journal = new MemoryJournal({
    revision: 1,
    operation: pendingOperation({ stage: "child", intent }),
  });
  const metadata = new FakeMetadata();
  metadata.failWith = "metadata must not run after drift";
  const chain = new CrashableChain();
  const changedDefinition: DemoSkillDefinition = {
    ...definition("child"),
    name: "changed-current-child-name",
    description: "Changed only to prove recovery does not consult current proof fields.",
    artifactPath: definition("grandchild").artifactPath,
  };
  const changedSkills = DEMO_SKILLS.map((value) =>
    value.stage === "child" ? changedDefinition : value,
  );

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store, journal, skills: changedSkills }),
    /Recovered pending transaction, but current run configuration differs/,
  );

  assert.equal(store.manifest.registrations.child?.name, journalName);
  assert.equal(store.manifest.registrations.child?.metadata.artifact.path, journalPath);
  assert.notEqual(store.manifest.registrations.child?.name, changedDefinition.name);
  assert.notEqual(
    store.manifest.registrations.child?.metadata.artifact.path,
    changedDefinition.artifactPath,
  );
  assert.equal(metadata.calls, 0);
  assert.equal(chain.balanceReads, 0);
  assert.equal(chain.feeReadinessCalls, 0);
  assert.equal(chain.prepareCounts.child, 0);
  assert.equal(journal.operation, null);
});

test("post-recovery work stays bound to the validated configuration snapshot", async () => {
  const store = await rootOnlyStore();
  const intent = await derivativeIntent({ stage: "child", parentIpId: ROOT });
  const journal = new MemoryJournal({
    revision: 1,
    operation: pendingOperation({ stage: "child", intent }),
  });
  const mutableSkills: DemoSkillDefinition[] = DEMO_SKILLS.map((value) => ({ ...value }));
  const originalGrandchild = { ...definition("grandchild", mutableSkills) };
  const changedGrandchild: DemoSkillDefinition = {
    ...originalGrandchild,
    name: "mutated-during-readiness",
    description: "This definition appeared only after pending recovery was validated.",
    artifactPath: definition("root", mutableSkills).artifactPath,
  };
  const chain = new CrashableChain();
  const getBalance = chain.getBalance.bind(chain);
  chain.getBalance = async () => {
    mutableSkills.splice(2, 1, changedGrandchild);
    return getBalance();
  };

  const result = await runDemo({
    wallet: WALLET,
    chain,
    metadata: new FakeMetadata(),
    store,
    journal,
    skills: mutableSkills,
  });

  assert.equal(result.status, "complete");
  assert.equal(result.registrations.grandchild?.name, originalGrandchild.name);
  assert.equal(
    result.registrations.grandchild?.metadata.artifact.path,
    originalGrandchild.artifactPath,
  );
  assert.notEqual(result.registrations.grandchild?.name, changedGrandchild.name);
});

test("insufficient WIP balance stops before Derivative prepare", async () => {
  const chain = new CrashableChain();
  chain.predictedFee = DEMO_ROOT_MINTING_FEE;
  chain.wipBalance = DEMO_ROOT_MINTING_FEE - 1n;
  chain.wipAllowance = DEMO_ROOT_MINTING_FEE;
  const metadata = new FakeMetadata();
  const journal = new MemoryJournal();
  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store: await rootOnlyStore(), journal }),
    /WIP balance.*required/i,
  );
  assert.equal(chain.feeReadinessCalls, 1);
  assert.equal(chain.prepareCounts.child, 0);
  assert.equal(chain.broadcastTransactions.length, 0);
  assert.equal(journal.operation, null);
});

test("insufficient WIP allowance stops before Derivative prepare", async () => {
  const chain = new CrashableChain();
  chain.predictedFee = DEMO_ROOT_MINTING_FEE;
  chain.wipBalance = DEMO_ROOT_MINTING_FEE;
  chain.wipAllowance = DEMO_ROOT_MINTING_FEE - 1n;
  const journal = new MemoryJournal();
  await assert.rejects(
    runDemo({
      wallet: WALLET,
      chain,
      metadata: new FakeMetadata(),
      store: await rootOnlyStore(),
      journal,
    }),
    /WIP allowance.*required/i,
  );
  assert.equal(chain.feeReadinessCalls, 1);
  assert.equal(chain.prepareCounts.child, 0);
  assert.equal(chain.broadcastTransactions.length, 0);
  assert.equal(journal.operation, null);
});

test("a complete manifest performs zero native, WIP, metadata, or prepare reads", async () => {
  const chain = new CrashableChain();
  const metadata = new FakeMetadata();
  const result = await runDemo({
    wallet: WALLET,
    chain,
    metadata,
    store: await completeStore(),
    journal: new MemoryJournal(),
  });
  assert.equal(result.status, "complete");
  assert.equal(chain.balanceReads, 0);
  assert.equal(chain.gasPriceReads, 0);
  assert.equal(chain.feeReadinessCalls, 0);
  assert.equal(metadata.calls, 0);
  assert.deepEqual(chain.prepareCounts, { collection: 0, root: 0, child: 0, grandchild: 0 });
});

test("without pending recovery, another wallet's manifest fails before readiness", async () => {
  const store = collectionOnlyStore();
  const chain = new CrashableChain();
  await assert.rejects(
    runDemo({ wallet: OTHER_WALLET, chain, metadata: new FakeMetadata(), store, journal: new MemoryJournal() }),
    /belongs to wallet/i,
  );
  assert.equal(chain.balanceReads, 0);
});

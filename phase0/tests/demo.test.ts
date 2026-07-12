import assert from "node:assert/strict";
import test from "node:test";

import {
  AENEID_CHAIN_ID,
  AENEID_FAUCET_URL,
  runDemo,
  type DemoChain,
  type DemoMetadataProvider,
} from "../src/demo";
import {
  createEmptyRegistrationManifest,
  type RegistrationManifest,
  type RegistrationStore,
} from "../src/registrations";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const COLLECTION = "0x00000000000000000000000000000000000000bb" as const;
const ROOT = "0x0000000000000000000000000000000000000001" as const;
const CHILD = "0x0000000000000000000000000000000000000002" as const;
const GRANDCHILD = "0x0000000000000000000000000000000000000003" as const;

function clone<T>(value: T): T {
  return structuredClone(value);
}

class MemoryStore implements RegistrationStore {
  loadCalls = 0;
  saveCalls = 0;
  snapshots: RegistrationManifest[] = [];

  constructor(public manifest = createEmptyRegistrationManifest()) {}

  async load(): Promise<RegistrationManifest> {
    this.loadCalls += 1;
    return clone(this.manifest);
  }

  async save(manifest: RegistrationManifest): Promise<void> {
    this.saveCalls += 1;
    this.manifest = clone(manifest);
    this.snapshots.push(clone(manifest));
  }
}

class FakeMetadata implements DemoMetadataProvider {
  stages: string[] = [];

  async prepare(input: { stage: string; artifactPath: string }) {
    this.stages.push(input.stage);
    const digit = input.stage === "root" ? "1" : input.stage === "child" ? "2" : "3";
    const hash = `0x${digit.repeat(64)}` as const;
    return {
      onchain: {
        ipMetadataURI: `https://example.test/${input.stage}/ip`,
        ipMetadataHash: hash,
        nftMetadataURI: `https://example.test/${input.stage}/nft`,
        nftMetadataHash: hash,
      },
      proof: {
        ip: { uri: `https://example.test/${input.stage}/ip`, hash },
        nft: { uri: `https://example.test/${input.stage}/nft`, hash },
        artifact: { path: input.artifactPath, mediaHash: hash, mediaType: "text/markdown" },
      },
    };
  }
}

class FakeChain implements DemoChain {
  writes: string[] = [];
  derivativeInputs: Array<{ parentIpId: string; licenseTermsId: bigint; maxMintingFee: bigint }> = [];
  failOn: "collection" | "root" | "child" | "grandchild" | null = null;

  constructor(
    public chainId: number = AENEID_CHAIN_ID,
    public balance: bigint = 1n,
    public predictedFee: bigint = 123n,
  ) {}

  async getChainId() {
    return this.chainId;
  }

  async getBalance() {
    return this.balance;
  }

  async createCollection() {
    this.writes.push("collection");
    if (this.failOn === "collection") throw new Error("collection failed");
    return { spgNftContract: COLLECTION, txHash: "0xcollection" as const };
  }

  async registerSkill() {
    this.writes.push("root");
    if (this.failOn === "root") throw new Error("root failed");
    return { ipId: ROOT, tokenId: 1n, txHash: "0xroot" as const, licenseTermsId: 7n };
  }

  async predictMintingLicenseFee() {
    return { tokenAmount: this.predictedFee };
  }

  async registerDerivative(input: {
    parentIpId: string;
    licenseTermsId: bigint;
    maxMintingFee: bigint;
  }) {
    const stage = input.parentIpId === ROOT ? "child" : "grandchild";
    this.writes.push(stage);
    this.derivativeInputs.push(input);
    if (this.failOn === stage) throw new Error(`${stage} failed`);
    return stage === "child"
      ? { ipId: CHILD, tokenId: 2n, txHash: "0xchild" as const }
      : { ipId: GRANDCHILD, tokenId: 3n, txHash: "0xgrandchild" as const };
  }
}

test("zero balance exits with faucet details before metadata, store, or writes", async () => {
  const chain = new FakeChain(AENEID_CHAIN_ID, 0n);
  const metadata = new FakeMetadata();
  const store = new MemoryStore();

  await assert.rejects(
    runDemo({ wallet: WALLET, chain, metadata, store }),
    (error: Error) => {
      assert.match(error.message, new RegExp(WALLET, "i"));
      assert.match(error.message, /Story Aeneid \(1315\)/);
      assert.match(error.message, new RegExp(AENEID_FAUCET_URL.replaceAll(".", "\\.")));
      return true;
    },
  );

  assert.deepEqual(chain.writes, []);
  assert.deepEqual(metadata.stages, []);
  assert.equal(store.loadCalls, 0);
  assert.equal(store.saveCalls, 0);
});

test("wrong chain exits before balance, metadata, store, or writes", async () => {
  const chain = new FakeChain(1514, 1n);
  let balanceCalls = 0;
  chain.getBalance = async () => {
    balanceCalls += 1;
    return 1n;
  };
  const metadata = new FakeMetadata();
  const store = new MemoryStore();

  await assert.rejects(runDemo({ wallet: WALLET, chain, metadata, store }), /expected Story Aeneid \(1315\).*1514/i);

  assert.equal(balanceCalls, 0);
  assert.deepEqual(chain.writes, []);
  assert.deepEqual(metadata.stages, []);
  assert.equal(store.loadCalls, 0);
  assert.equal(store.saveCalls, 0);
});

test("metadata verification failure rejects before any chain write or manifest save", async () => {
  const chain = new FakeChain();
  const store = new MemoryStore();
  const metadata: DemoMetadataProvider = {
    prepare: async () => {
      throw new Error("fetched metadata bytes do not match");
    },
  };

  await assert.rejects(runDemo({ wallet: WALLET, chain, metadata, store }), /bytes do not match/);

  assert.deepEqual(chain.writes, []);
  assert.equal(store.saveCalls, 0);
});

test("funded demo persists a root Skill and two-level Derivative chain", async () => {
  const chain = new FakeChain();
  const metadata = new FakeMetadata();
  const store = new MemoryStore();

  const result = await runDemo({ wallet: WALLET, chain, metadata, store });

  assert.deepEqual(chain.writes, ["collection", "root", "child", "grandchild"]);
  assert.deepEqual(metadata.stages, ["root", "child", "grandchild"]);
  assert.equal(result.status, "complete");
  assert.equal(result.wallet, WALLET);
  assert.equal(result.spgNftContract, COLLECTION);
  assert.equal(result.collectionTxHash, "0xcollection");
  assert.deepEqual(result.registrations.root?.parentIpIds, []);
  assert.deepEqual(result.registrations.child?.parentIpIds, [ROOT]);
  assert.deepEqual(result.registrations.grandchild?.parentIpIds, [CHILD]);
  assert.equal(result.registrations.root?.ipId, ROOT);
  assert.equal(result.registrations.child?.ipId, CHILD);
  assert.equal(result.registrations.grandchild?.ipId, GRANDCHILD);
  assert.equal(result.registrations.root?.tokenId, "1");
  assert.equal(result.registrations.child?.tokenId, "2");
  assert.equal(result.registrations.grandchild?.tokenId, "3");
  assert.equal(result.registrations.root?.licenseTermsId, "7");
  assert.equal(result.registrations.child?.licenseTermsId, "7");
  assert.equal(result.registrations.grandchild?.licenseTermsId, "7");
  assert.equal(result.registrations.child?.maxMintingFee, "123");
  assert.equal(result.registrations.grandchild?.maxMintingFee, "123");
  assert.equal(store.saveCalls, 4);
});

test("each Derivative receives the fee predicted immediately before it", async () => {
  const chain = new FakeChain();

  await runDemo({ wallet: WALLET, chain, metadata: new FakeMetadata(), store: new MemoryStore() });

  assert.deepEqual(chain.derivativeInputs.map(({ parentIpId, licenseTermsId, maxMintingFee }) => ({
    parentIpId,
    licenseTermsId,
    maxMintingFee,
  })), [
    { parentIpId: ROOT, licenseTermsId: 7n, maxMintingFee: 123n },
    { parentIpId: CHILD, licenseTermsId: 7n, maxMintingFee: 123n },
  ]);
});

test("a confirmed partial proof survives failure and rerun resumes only missing stages", async () => {
  const store = new MemoryStore();
  const firstChain = new FakeChain();
  firstChain.failOn = "child";

  await assert.rejects(
    runDemo({ wallet: WALLET, chain: firstChain, metadata: new FakeMetadata(), store }),
    /child failed/,
  );

  assert.equal(store.manifest.status, "partial");
  assert.equal(store.manifest.spgNftContract, COLLECTION);
  assert.equal(store.manifest.registrations.root?.ipId, ROOT);
  assert.equal(store.manifest.registrations.child, null);
  assert.equal(store.saveCalls, 2);

  const resumedChain = new FakeChain();
  const resumedMetadata = new FakeMetadata();
  const result = await runDemo({ wallet: WALLET, chain: resumedChain, metadata: resumedMetadata, store });

  assert.deepEqual(resumedChain.writes, ["child", "grandchild"]);
  assert.deepEqual(resumedMetadata.stages, ["child", "grandchild"]);
  assert.equal(result.status, "complete");
  assert.equal(result.registrations.root?.txHash, "0xroot");
  assert.equal(result.registrations.child?.txHash, "0xchild");
  assert.equal(result.registrations.grandchild?.txHash, "0xgrandchild");
});

for (const scenario of [
  { failOn: "root" as const, saves: 1, lastProof: "collection" },
  { failOn: "grandchild" as const, saves: 3, lastProof: "child" },
]) {
  test(`failure at ${scenario.failOn} keeps every earlier confirmed proof`, async () => {
    const store = new MemoryStore();
    const chain = new FakeChain();
    chain.failOn = scenario.failOn;

    await assert.rejects(
      runDemo({ wallet: WALLET, chain, metadata: new FakeMetadata(), store }),
      new RegExp(`${scenario.failOn} failed`),
    );

    assert.equal(store.saveCalls, scenario.saves);
    assert.equal(store.manifest.spgNftContract, COLLECTION);
    assert.equal(store.manifest.collectionTxHash, "0xcollection");
    if (scenario.lastProof === "child") {
      assert.equal(store.manifest.registrations.root?.txHash, "0xroot");
      assert.equal(store.manifest.registrations.child?.txHash, "0xchild");
      assert.equal(store.manifest.registrations.grandchild, null);
    } else {
      assert.equal(store.manifest.registrations.root, null);
    }
  });
}

test("a run refuses to resume another wallet's proof", async () => {
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = "0x00000000000000000000000000000000000000ff";
  manifest.spgNftContract = COLLECTION;
  manifest.collectionTxHash = "0xcollection";
  const store = new MemoryStore(manifest);

  await assert.rejects(
    runDemo({ wallet: WALLET, chain: new FakeChain(), metadata: new FakeMetadata(), store }),
    /belongs to wallet.*00ff/i,
  );
});

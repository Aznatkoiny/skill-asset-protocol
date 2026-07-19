import assert from "node:assert/strict";
import test from "node:test";

import { WIP_TOKEN_ADDRESS } from "@story-protocol/core-sdk";

import { buildCheckReport, type CheckChain } from "../src/check";
import {
  AENEID_CHAIN_ID,
  DEMO_ROOT_MINTING_FEE,
  type DerivativeFeeReadiness,
} from "../src/demo";
import {
  createEmptyRegistrationManifest,
  type DemoStage,
  type RegistrationManifest,
  type RegistrationProof,
  type RegistrationStore,
} from "../src/registrations";
import type {
  LeasedOperationJournal,
  OperationJournal,
  PendingOperation,
} from "../src/transactions";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const OTHER_WALLET = "0x00000000000000000000000000000000000000bb" as const;
const COLLECTION = "0x00000000000000000000000000000000000000cc" as const;
const WIP_SPENDER = "0x00000000000000000000000000000000000000dd" as const;
const HASH = `0x${"11".repeat(32)}` as const;
const IP_IDS = {
  root: "0x0000000000000000000000000000000000000011",
  child: "0x0000000000000000000000000000000000000022",
  grandchild: "0x0000000000000000000000000000000000000033",
} as const;

function proof(stage: DemoStage): RegistrationProof {
  const parentIpIds = stage === "root"
    ? []
    : [stage === "child" ? IP_IDS.root : IP_IDS.child];
  return {
    stage,
    kind: stage === "root" ? "Skill" : "Derivative",
    name: `${stage}-fixture`,
    ipId: IP_IDS[stage],
    tokenId: "1",
    txHash: HASH,
    licenseTermsId: "7",
    licenseTemplate: COLLECTION,
    parentIpIds,
    defaultMintingFee: stage === "root" ? "1000000000000000" : null,
    maxMintingFee: stage === "root" ? null : "1000000000000000",
    metadata: {
      ip: { uri: "https://gateway.pinata.cloud/ipfs/bafyipfixture123", hash: HASH },
      nft: { uri: "https://gateway.pinata.cloud/ipfs/bafynftfixture123", hash: HASH },
      artifact: { path: `fixtures/${stage}/SKILL.md`, mediaHash: HASH, mediaType: "text/markdown" },
    },
  };
}

function manifestThrough(stage?: DemoStage): RegistrationManifest {
  const manifest = createEmptyRegistrationManifest();
  const stages: DemoStage[] = stage === "grandchild"
    ? ["root", "child", "grandchild"]
    : stage === "child"
      ? ["root", "child"]
      : stage === "root"
        ? ["root"]
        : [];
  if (stage || stages.length > 0) {
    manifest.wallet = WALLET;
    manifest.spgNftContract = COLLECTION;
    manifest.collectionTxHash = HASH;
  }
  for (const value of stages) manifest.registrations[value] = proof(value);
  manifest.status = stages.length === 3 ? "complete" : stages.length > 0 || stage ? "partial" : "not-run";
  return manifest;
}

function collectionOnlyManifest(): RegistrationManifest {
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = WALLET;
  manifest.spgNftContract = COLLECTION;
  manifest.collectionTxHash = HASH;
  return manifest;
}

class MemoryStore implements RegistrationStore {
  saveCalls = 0;
  constructor(private readonly manifest: RegistrationManifest) {}
  async load() { return structuredClone(this.manifest); }
  async save() { this.saveCalls += 1; throw new Error("check must not save"); }
}

class MemoryJournal implements OperationJournal {
  saveCalls = 0;
  clearCalls = 0;
  leaseCalls = 0;
  constructor(private readonly operation: PendingOperation | null = null) {}
  async withExclusiveLease<T>(callback: (journal: LeasedOperationJournal) => Promise<T>): Promise<T> {
    this.leaseCalls += 1;
    return callback({
      load: async () => ({ revision: this.operation ? 1 : 0, operation: structuredClone(this.operation) }),
      save: async () => { this.saveCalls += 1; throw new Error("check must not save"); },
      clear: async () => { this.clearCalls += 1; throw new Error("check must not clear"); },
    });
  }
}

class FakeChain implements CheckChain {
  chainId: number = AENEID_CHAIN_ID;
  balance = 10n ** 20n;
  gasPrice = 1_000_000_000n;
  wipBalance = DEMO_ROOT_MINTING_FEE;
  wipAllowance = DEMO_ROOT_MINTING_FEE;
  chainReads = 0;
  balanceReads = 0;
  gasPriceReads = 0;
  wipReads = 0;
  async getChainId() { this.chainReads += 1; return this.chainId; }
  async getBalance() { this.balanceReads += 1; return this.balance; }
  async getGasPrice() { this.gasPriceReads += 1; return this.gasPrice; }
  async getDerivativeFeeReadiness(input: {
    wallet: `0x${string}`;
    currencyToken: `0x${string}`;
    requiredAmount: bigint;
  }): Promise<DerivativeFeeReadiness> {
    this.wipReads += 1;
    assert.equal(input.wallet, WALLET);
    assert.equal(input.currencyToken, WIP_TOKEN_ADDRESS);
    assert.equal(input.requiredAmount, DEMO_ROOT_MINTING_FEE);
    return {
      currencyToken: WIP_TOKEN_ADDRESS,
      spender: WIP_SPENDER,
      requiredAmount: DEMO_ROOT_MINTING_FEE,
      balance: this.wipBalance,
      allowance: this.wipAllowance,
    };
  }
}

function pending(stage: PendingOperation["stage"] = "child"): PendingOperation {
  return {
    schemaVersion: 1,
    operationId: "fixture-operation",
    stage,
    intent: {
      stage,
      chainId: AENEID_CHAIN_ID,
      wallet: WALLET,
      registrationName: null,
      artifactPath: null,
      spgNftContract: COLLECTION,
      parentIpId: IP_IDS.root,
      licenseTermsId: "7",
      licenseTemplate: COLLECTION,
      currencyToken: WIP_TOKEN_ADDRESS,
      defaultMintingFee: null,
      maxMintingFee: DEMO_ROOT_MINTING_FEE.toString(),
      metadata: null,
      runConfigHash: HASH,
    },
    intentHash: HASH,
    transactionHash: HASH,
    serializedTransaction: "0x11",
    state: "broadcast",
  };
}

async function report(manifest: RegistrationManifest, chain = new FakeChain(), journal = new MemoryJournal()) {
  const store = new MemoryStore(manifest);
  return {
    value: await buildCheckReport({ wallet: WALLET, chain, store, journal }),
    chain,
    journal,
    store,
  };
}

test("four missing writes read native gas once and defer WIP until a Derivative", async () => {
  const result = await report(manifestThrough());
  assert.equal(result.value.remainingNewWrites, 4);
  assert.equal(result.value.nativeGasReady, "yes");
  assert.equal(result.value.nextDerivativeWipReady, "not applicable until the next new Derivative");
  assert.equal(result.chain.balanceReads, 1);
  assert.equal(result.chain.gasPriceReads, 1);
  assert.equal(result.chain.wipReads, 0);
});

test("a confirmed collection leaves root next and performs no WIP read", async () => {
  const result = await report(collectionOnlyManifest());
  assert.equal(result.value.remainingNewWrites, 3);
  assert.equal(result.chain.wipReads, 0);
});

for (const [stage, remaining] of [["root", 2], ["child", 1]] as const) {
  test(`${stage}-confirmed state checks the next Derivative WIP domain exactly once`, async () => {
    const result = await report(manifestThrough(stage));
    assert.equal(result.value.remainingNewWrites, remaining);
    assert.equal(result.value.derivativeFeeToken, WIP_TOKEN_ADDRESS);
    assert.equal(result.value.configuredFeeEstimate, "0.001 WIP per Derivative");
    assert.equal(result.value.nextDerivativeWipReady, "yes");
    assert.equal(result.chain.wipReads, 1);
  });
}

test("native and WIP insufficiency remain independent diagnostics", async () => {
  const chain = new FakeChain();
  chain.balance = 1n;
  chain.wipBalance = 0n;
  const result = await report(manifestThrough("root"), chain);
  assert.equal(result.value.nativeGasReady, "no");
  assert.equal(result.value.nextDerivativeWipReady, "no");
  assert.equal(result.chain.balanceReads, 1);
  assert.equal(result.chain.wipReads, 1);
});

test("malformed WIP readiness fails closed", async () => {
  const chain = new FakeChain();
  chain.getDerivativeFeeReadiness = async () => ({
    currencyToken: WIP_TOKEN_ADDRESS,
    spender: "0x0000000000000000000000000000000000000000",
    requiredAmount: DEMO_ROOT_MINTING_FEE,
    balance: DEMO_ROOT_MINTING_FEE,
    allowance: DEMO_ROOT_MINTING_FEE,
  });
  await assert.rejects(report(manifestThrough("root"), chain), /malformed workflows spender/i);
});

test("a complete manifest performs zero native, gas, or WIP reads", async () => {
  const result = await report(manifestThrough("grandchild"));
  assert.equal(result.value.remainingNewWrites, 0);
  assert.equal(result.value.nativeIpBalance, "not read (no remaining new writes)");
  assert.equal(result.value.estimatedGasMinimum, "0 IP");
  assert.equal(result.value.nativeGasReady, "yes");
  assert.equal(result.chain.balanceReads, 0);
  assert.equal(result.chain.gasPriceReads, 0);
  assert.equal(result.chain.wipReads, 0);
});

test("pending exact-hash recovery defers every readiness read and never mutates state", async () => {
  const chain = new FakeChain();
  const journal = new MemoryJournal(pending());
  const result = await report(manifestThrough("root"), chain, journal);
  assert.equal(result.value.pendingRecovery, `required (child, ${HASH})`);
  assert.equal(result.value.nativeIpBalance, "deferred until exact-hash recovery");
  assert.equal(result.value.nextDerivativeWipReady, "deferred until exact-hash recovery");
  assert.equal(chain.chainReads, 0);
  assert.equal(chain.balanceReads, 0);
  assert.equal(chain.gasPriceReads, 0);
  assert.equal(chain.wipReads, 0);
  assert.equal(journal.saveCalls, 0);
  assert.equal(journal.clearCalls, 0);
  assert.equal(result.store.saveCalls, 0);
});

test("wrong chain and wallet mismatch reject before readiness", async () => {
  const wrongChain = new FakeChain();
  wrongChain.chainId = 1514;
  await assert.rejects(report(manifestThrough(), wrongChain), /Aeneid.*1315/i);
  assert.equal(wrongChain.balanceReads, 0);
  assert.equal(wrongChain.gasPriceReads, 0);

  const mismatched = manifestThrough("root");
  mismatched.wallet = OTHER_WALLET;
  const chain = new FakeChain();
  await assert.rejects(report(mismatched, chain), /another wallet/i);
  assert.equal(chain.balanceReads, 0);
  assert.equal(chain.gasPriceReads, 0);
  assert.equal(chain.wipReads, 0);
});

test("malformed manifests fail before chain readiness", async () => {
  const malformed = manifestThrough("root");
  malformed.registrations.root!.parentIpIds = [IP_IDS.child];
  const chain = new FakeChain();
  await assert.rejects(report(malformed, chain), /root.*parent/i);
  assert.equal(chain.chainReads, 0);
  assert.equal(chain.balanceReads, 0);
});

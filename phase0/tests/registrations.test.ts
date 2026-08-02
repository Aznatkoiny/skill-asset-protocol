import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  FileRegistrationStore,
  createEmptyRegistrationManifest,
  parseRegistrationManifest,
  type RegistrationProof,
} from "../src/registrations";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const SPG = "0x00000000000000000000000000000000000000bb" as const;
const LICENSE_TEMPLATE = "0x00000000000000000000000000000000000000cc" as const;
const TX_HASH = `0x${"1".repeat(64)}` as const;
const METADATA_HASH = `0x${"2".repeat(64)}` as const;

function proof(stage: "root" | "child" | "grandchild", ipId: `0x${string}`): RegistrationProof {
  return {
    stage,
    kind: stage === "root" ? "Skill" : "Derivative",
    name: stage,
    ipId,
    tokenId: stage === "root" ? "1" : stage === "child" ? "2" : "3",
    txHash: TX_HASH,
    licenseTermsId: "7",
    licenseTemplate: LICENSE_TEMPLATE,
    parentIpIds: [],
    defaultMintingFee: stage === "root" ? "1000000000000000" : null,
    maxMintingFee: stage === "root" ? null : "123",
    metadata: {
      ip: { uri: "https://example.test/ip", hash: METADATA_HASH },
      nft: { uri: "https://example.test/nft", hash: METADATA_HASH },
      artifact: { path: `fixtures/${stage}/SKILL.md`, mediaHash: METADATA_HASH, mediaType: "text/markdown" },
    },
  };
}

test("filesystem store atomically writes valid JSON and round-trips the schema", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-registrations-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const store = new FileRegistrationStore(path);
  const manifest = createEmptyRegistrationManifest();
  manifest.wallet = WALLET;
  manifest.status = "partial";
  manifest.spgNftContract = SPG;
  manifest.collectionTxHash = TX_HASH;

  await store.save(manifest);

  const raw = await readFile(path, "utf8");
  assert.deepEqual(JSON.parse(raw), manifest);
  assert.equal(raw.endsWith("\n"), true);
  assert.deepEqual(await store.load(), manifest);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("filesystem store returns the honest not-run schema when the artifact is absent", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-registrations-"));
  t.after(() => rm(directory, { recursive: true, force: true }));

  const manifest = await new FileRegistrationStore(join(directory, "registrations.json")).load();

  assert.deepEqual(manifest, createEmptyRegistrationManifest());
});

test("manifest save resolves only after file and directory fsync", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const events: string[] = [];
  const store = new FileRegistrationStore(join(directory, "registrations.json"), {
    afterTempSync: () => { events.push("temp-fsync"); },
    afterRename: () => { events.push("rename"); },
    afterDirectorySync: () => { events.push("directory-fsync"); },
  });
  await store.save(createEmptyRegistrationManifest());
  events.push("resolved");
  assert.deepEqual(events, ["temp-fsync", "rename", "directory-fsync", "resolved"]);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("crash after temp fsync preserves the previous complete manifest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const previous = createEmptyRegistrationManifest();
  await new FileRegistrationStore(path).save(previous);
  const previousBytes = await readFile(path);
  const next = createEmptyRegistrationManifest();
  next.wallet = WALLET;
  next.spgNftContract = SPG;
  next.collectionTxHash = TX_HASH;
  next.status = "partial";
  const crashing = new FileRegistrationStore(path, {
    afterTempSync: () => { throw new Error("simulated crash after temp fsync"); },
  });
  await assert.rejects(crashing.save(next), /simulated crash/);
  assert.deepEqual(await readFile(path), previousBytes);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("rename interruption exposes only a parseable complete manifest", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "phase0-durable-manifest-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "registrations.json");
  const next = createEmptyRegistrationManifest();
  next.wallet = WALLET;
  next.spgNftContract = SPG;
  next.collectionTxHash = TX_HASH;
  next.status = "partial";
  const crashing = new FileRegistrationStore(path, {
    afterRename: () => { throw new Error("simulated crash before directory fsync"); },
  });
  await assert.rejects(crashing.save(next), /simulated crash/);
  assert.deepEqual(await new FileRegistrationStore(path).load(), next);
  assert.deepEqual(await readdir(directory), ["registrations.json"]);
});

test("manifest parser rejects truthy malformed proofs instead of treating them as resumable", () => {
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = WALLET;
  manifest.spgNftContract = SPG;
  manifest.collectionTxHash = TX_HASH;
  manifest.registrations.root = {} as RegistrationProof;

  assert.throws(() => parseRegistrationManifest(manifest), /root\.stage/i);
});

test("manifest parser enforces status and exact Derivative parent edges", () => {
  const rootId = "0x0000000000000000000000000000000000000001" as const;
  const childId = "0x0000000000000000000000000000000000000002" as const;
  const grandchildId = "0x0000000000000000000000000000000000000003" as const;
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "complete";
  manifest.wallet = WALLET;
  manifest.spgNftContract = SPG;
  manifest.collectionTxHash = TX_HASH;
  manifest.registrations.root = proof("root", rootId);
  manifest.registrations.child = {
    ...proof("child", childId),
    parentIpIds: ["0x00000000000000000000000000000000000000ff"],
  };
  manifest.registrations.grandchild = { ...proof("grandchild", grandchildId), parentIpIds: [childId] };

  assert.throws(() => parseRegistrationManifest(manifest), /child\.parentIpIds.*root/i);

  manifest.registrations.child.parentIpIds = [rootId];
  manifest.registrations.grandchild = null;
  assert.throws(() => parseRegistrationManifest(manifest), /complete.*grandchild/i);
});

test("manifest parser requires an event-derived license template on every proof", () => {
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = WALLET;
  manifest.spgNftContract = SPG;
  manifest.collectionTxHash = TX_HASH;
  const root = proof("root", "0x0000000000000000000000000000000000000001");
  delete (root as Partial<RegistrationProof>).licenseTemplate;
  manifest.registrations.root = root;

  assert.throws(() => parseRegistrationManifest(manifest), /licenseTemplate/i);
});

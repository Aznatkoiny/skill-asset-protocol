import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  chmod,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test, { type TestContext } from "node:test";
import { keccak256 } from "viem";

import {
  FileOperationJournal,
  operationIntentHash,
  type CanonicalOperationIntent,
  type JournalSnapshot,
  type PendingOperation,
} from "../src/transactions";

const execFileAsync = promisify(execFile);
const SERIALIZED_TRANSACTION = `0x${"3".repeat(128)}` as const;

const INTENT: CanonicalOperationIntent = {
  stage: "root",
  chainId: 1315,
  wallet: "0x00000000000000000000000000000000000000aa",
  registrationName: "demo-research-skill",
  artifactPath: "fixtures/demo-base/SKILL.md",
  spgNftContract: "0x00000000000000000000000000000000000000bb",
  parentIpId: null,
  licenseTermsId: null,
  licenseTemplate: null,
  currencyToken: null,
  defaultMintingFee: null,
  maxMintingFee: null,
  metadata: {
    ipMetadataURI: "ipfs://root-ip-metadata",
    ipMetadataHash: `0x${"4".repeat(64)}`,
    nftMetadataURI: "ipfs://root-nft-metadata",
    nftMetadataHash: `0x${"5".repeat(64)}`,
    artifactMediaHash: `0x${"6".repeat(64)}`,
    artifactMediaType: "text/markdown",
  },
  runConfigHash: `0x${"7".repeat(64)}`,
};

const RECORD: PendingOperation = {
  schemaVersion: 1,
  operationId: "phase0:0x00000000000000000000000000000000000000aa:root",
  stage: "root",
  intent: INTENT,
  intentHash: operationIntentHash(INTENT),
  transactionHash: keccak256(SERIALIZED_TRANSACTION),
  serializedTransaction: SERIALIZED_TRANSACTION,
  state: "prepared",
};

const INTENT_HASH_MISMATCH: PendingOperation = {
  ...RECORD,
  intentHash: `0x${"0".repeat(64)}`,
};

const TRANSACTION_HASH_MISMATCH: PendingOperation = {
  ...RECORD,
  transactionHash: `0x${"2".repeat(64)}`,
};

async function temporaryJournal(t: TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "phase0-transaction-journal-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journalPath = join(directory, "pending-transactions.json");
  return { directory, journalPath, journal: new FileOperationJournal(journalPath) };
}

async function writeSnapshot(path: string, snapshot: JournalSnapshot, mode = 0o600) {
  await writeFile(path, `${JSON.stringify({ schemaVersion: 1, ...snapshot }, null, 2)}\n`, { mode });
  await chmod(path, mode);
}

function validLeaseOwner(overrides: Partial<{
  leaseId: string;
  hostname: string;
  pid: number;
  startedAtUtc: string;
}> = {}) {
  return {
    leaseId: "0123456789abcdef0123456789abcdef",
    hostname: hostname(),
    pid: 999_999,
    startedAtUtc: "2026-07-18T00:00:00.000Z",
    ...overrides,
  };
}

async function writeLock(path: string, owner: unknown) {
  await writeFile(`${path}.lock`, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  await chmod(`${path}.lock`, 0o600);
}

async function replaceLock(path: string, owner: unknown) {
  const replacement = `${path}.replacement`;
  await writeFile(replacement, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  await chmod(replacement, 0o600);
  await rename(replacement, `${path}.lock`);
}

test("journal lifecycle is newline-terminated, mode-0600, and leaves no temporary files", async (t) => {
  const { directory, journalPath, journal } = await temporaryJournal(t);

  await journal.withExclusiveLease(async (leased) => {
    const empty = await leased.load();
    assert.deepEqual(empty, { revision: 0, operation: null });
    const saved = await leased.save(RECORD, empty.revision);
    assert.equal(saved.revision, 1);
    assert.deepEqual(saved.operation, RECORD);
    const cleared = await leased.clear(RECORD.operationId, saved.revision);
    assert.deepEqual(cleared, { revision: 2, operation: null });
  });

  const journalStat = await stat(journalPath);
  assert.equal(journalStat.mode & 0o777, 0o600);
  assert.equal((await readFile(journalPath, "utf8")).endsWith("\n"), true);
  assert.deepEqual((await readdir(directory)).filter((name) => name.includes(".tmp")), []);
  assert.deepEqual((await readdir(directory)).filter((name) => name.endsWith(".lock")), []);
});

test("a second journal instance cannot enter a live exclusive lease", async (t) => {
  const { journalPath, journal } = await temporaryJournal(t);
  let release!: () => void;
  const paused = new Promise<void>((resolve) => { release = resolve; });
  let entered!: () => void;
  const didEnter = new Promise<void>((resolve) => { entered = resolve; });

  const first = journal.withExclusiveLease(async () => {
    entered();
    await paused;
  });
  await didEnter;

  await assert.rejects(
    new FileOperationJournal(journalPath).withExclusiveLease(async () => undefined),
    /Pending transaction journal is locked.*PID.*lease/i,
  );

  release();
  await first;
});

test("normal lease release never unlinks a replacement owner", async (t) => {
  const { directory, journalPath, journal } = await temporaryJournal(t);
  const replacementOwner = validLeaseOwner({
    leaseId: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    pid: process.pid,
    startedAtUtc: "2026-07-18T00:00:02.000Z",
  });

  await assert.rejects(
    journal.withExclusiveLease(async (leased) => {
      await leased.load();
      await replaceLock(journalPath, replacementOwner);
    }),
    /lease CAS failed.*restored/i,
  );

  assert.deepEqual(JSON.parse(await readFile(`${journalPath}.lock`, "utf8")), replacementOwner);
  assert.deepEqual((await readdir(directory)).filter((name) => name.endsWith(".claim")), []);
});

test("normal lease release removes only its claim when a new owner acquires the lock path", async (t) => {
  const { directory, journalPath } = await temporaryJournal(t);
  const newOwner = validLeaseOwner({
    leaseId: "cccccccccccccccccccccccccccccccc",
    pid: process.pid,
    startedAtUtc: "2026-07-18T00:00:03.000Z",
  });
  const journal = new FileOperationJournal(journalPath, {
    afterLeaseClaim: async () => writeLock(journalPath, newOwner),
  });

  await journal.withExclusiveLease(async (leased) => {
    assert.deepEqual(await leased.load(), { revision: 0, operation: null });
  });

  assert.deepEqual(JSON.parse(await readFile(`${journalPath}.lock`, "utf8")), newOwner);
  assert.deepEqual((await readdir(directory)).filter((name) => name.endsWith(".claim")), []);
});

test("save uses compare-and-swap revisions and preserves the winning snapshot", async (t) => {
  const { journalPath, journal } = await temporaryJournal(t);

  await journal.withExclusiveLease(async (leased) => {
    await leased.save(RECORD, 0);
    await assert.rejects(leased.save({ ...RECORD, state: "broadcast" }, 0), /stale.*revision/i);
    assert.deepEqual(await leased.load(), { revision: 1, operation: RECORD });
  });

  assert.equal(JSON.parse(await readFile(journalPath, "utf8")).revision, 1);
});

test("clear rejects the wrong operation ID and a stale revision", async (t) => {
  const { journal, journalPath } = await temporaryJournal(t);

  await journal.withExclusiveLease(async (leased) => {
    const saved = await leased.save(RECORD, 0);
    await assert.rejects(leased.clear("phase0:wrong", saved.revision), /operation ID/i);
    await assert.rejects(leased.clear(RECORD.operationId, 0), /stale.*revision/i);
    assert.deepEqual(await leased.load(), saved);
  });

  assert.equal(JSON.parse(await readFile(journalPath, "utf8")).revision, 1);
});

test("load rejects a journal whose permissions expose signed bytes", async (t) => {
  const { journal, journalPath } = await temporaryJournal(t);
  await writeSnapshot(journalPath, { revision: 1, operation: RECORD }, 0o644);

  await journal.withExclusiveLease(async (leased) => {
    await assert.rejects(leased.load(), /mode 0600/i);
  });
});

test("a crash after temporary fsync preserves the prior final snapshot and retry advances once", async (t) => {
  const { directory, journalPath, journal } = await temporaryJournal(t);
  await journal.withExclusiveLease(async (leased) => {
    await leased.save(RECORD, 0);
  });
  const previousBytes = await readFile(journalPath);

  const crashing = new FileOperationJournal(journalPath, {
    afterTemporarySync: () => { throw new Error("simulated crash after temporary fsync"); },
  });
  await assert.rejects(
    crashing.withExclusiveLease(async (leased) => {
      await leased.save({ ...RECORD, state: "broadcast" }, 1);
    }),
    /simulated crash/,
  );
  assert.deepEqual(await readFile(journalPath), previousBytes);
  assert.deepEqual((await readdir(directory)).filter((name) => name.includes(".tmp")), []);

  await new FileOperationJournal(journalPath).withExclusiveLease(async (leased) => {
    const saved = await leased.save({ ...RECORD, state: "broadcast" }, 1);
    assert.equal(saved.revision, 2);
  });
  assert.equal(JSON.parse(await readFile(journalPath, "utf8")).revision, 2);
  assert.deepEqual((await readdir(directory)).filter((name) => name.includes(".tmp")), []);
});

test("intent corruption fails on save and on load", async (t) => {
  const { journal, journalPath } = await temporaryJournal(t);

  await journal.withExclusiveLease(async (leased) => {
    await assert.rejects(leased.save(INTENT_HASH_MISMATCH, 0), /intent.*hash/i);
  });

  const changedIntent = { ...INTENT, registrationName: "changed-without-rehash" };
  await writeSnapshot(journalPath, {
    revision: 1,
    operation: { ...RECORD, intent: changedIntent },
  });
  await journal.withExclusiveLease(async (leased) => {
    await assert.rejects(leased.load(), /intent.*hash/i);
  });
});

test("serialized transaction bytes are bound to their keccak256 hash on save and load", async (t) => {
  const { journal, journalPath } = await temporaryJournal(t);

  await journal.withExclusiveLease(async (leased) => {
    await assert.rejects(leased.save(TRANSACTION_HASH_MISMATCH, 0), /transaction hash.*serialized transaction/i);
  });

  await writeSnapshot(journalPath, { revision: 1, operation: TRANSACTION_HASH_MISMATCH });
  await journal.withExclusiveLease(async (leased) => {
    await assert.rejects(leased.load(), /transaction hash.*serialized transaction/i);
  });
});

test("malformed hashes and signed transaction hex fail closed", async (t) => {
  const { journal } = await temporaryJournal(t);

  for (const operation of [
    { ...RECORD, intentHash: "0x12" as `0x${string}` },
    { ...RECORD, transactionHash: "0x12" as `0x${string}` },
    { ...RECORD, serializedTransaction: "0x123" as `0x${string}` },
    { ...RECORD, serializedTransaction: "0x" as `0x${string}` },
  ]) {
    await journal.withExclusiveLease(async (leased) => {
      await assert.rejects(leased.save(operation, 0), /hash|serialized transaction/i);
    });
  }
});

test("malformed and live lock owners fail closed without automatic deletion", async (t) => {
  const { journal, journalPath } = await temporaryJournal(t);

  await writeLock(journalPath, { pid: "not-a-pid" });
  await assert.rejects(journal.withExclusiveLease(async () => undefined), /lock owner.*malformed/i);
  await assert.rejects(
    journal.recoverStaleLock({
      expectedLeaseId: "0123456789abcdef0123456789abcdef",
    }),
    /lock owner.*malformed/i,
  );
  assert.equal(await stat(`${journalPath}.lock`).then(() => true), true);

  await writeLock(journalPath, validLeaseOwner({ pid: process.pid }));
  await assert.rejects(
    journal.recoverStaleLock({ expectedLeaseId: validLeaseOwner().leaseId }),
    /PID.*alive/i,
  );
  assert.equal(await stat(`${journalPath}.lock`).then(() => true), true);
});

test("explicit stale-lock recovery requires exact same-host identity and PID absence", async (t) => {
  const { journalPath } = await temporaryJournal(t);
  const journal = new FileOperationJournal(journalPath, { isProcessAlive: async () => false });
  const owner = validLeaseOwner();
  await writeLock(journalPath, owner);

  await assert.rejects(
    journal.recoverStaleLock({
      expectedLeaseId: "fedcba9876543210fedcba9876543210",
    }),
    /lease ID.*does not match/i,
  );
  await writeLock(journalPath, { ...owner, hostname: "different-host.example" });
  await assert.rejects(
    journal.recoverStaleLock({
      expectedLeaseId: owner.leaseId,
    }),
    /different host/i,
  );
  assert.equal(await stat(`${journalPath}.lock`).then(() => true), true);

  await writeLock(journalPath, owner);
  const recovering = new FileOperationJournal(journalPath, {
    isProcessAlive: async (pid) => {
      assert.equal(pid, owner.pid);
      return false;
    },
  });
  await recovering.recoverStaleLock({ expectedLeaseId: owner.leaseId });
  await assert.rejects(stat(`${journalPath}.lock`), (error: NodeJS.ErrnoException) => error.code === "ENOENT");
});

test("stale-lock recovery rereads immutable lease identity before unlink", async (t) => {
  const { journalPath } = await temporaryJournal(t);
  const staleOwner = validLeaseOwner();
  const replacementOwner = validLeaseOwner({
    leaseId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    pid: process.pid,
    startedAtUtc: "2026-07-18T00:00:01.000Z",
  });
  await writeLock(journalPath, staleOwner);

  const journal = new FileOperationJournal(journalPath, {
    isProcessAlive: async () => {
      await replaceLock(journalPath, replacementOwner);
      return false;
    },
  });

  await assert.rejects(
    journal.recoverStaleLock({ expectedLeaseId: staleOwner.leaseId }),
    /lock owner changed during recovery/i,
  );

  assert.deepEqual(JSON.parse(await readFile(`${journalPath}.lock`, "utf8")), replacementOwner);
});

test("stale recovery retains a mismatched claim without deleting a newly acquired lock", async (t) => {
  const { directory, journalPath } = await temporaryJournal(t);
  const staleOwner = validLeaseOwner();
  const movedReplacement = validLeaseOwner({
    leaseId: "dddddddddddddddddddddddddddddddd",
    pid: process.pid,
    startedAtUtc: "2026-07-18T00:00:04.000Z",
  });
  const newOwner = validLeaseOwner({
    leaseId: "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    pid: process.pid,
    startedAtUtc: "2026-07-18T00:00:05.000Z",
  });
  await writeLock(journalPath, staleOwner);
  const journal = new FileOperationJournal(journalPath, {
    isProcessAlive: async () => {
      await replaceLock(journalPath, movedReplacement);
      return false;
    },
    afterLeaseClaim: async () => writeLock(journalPath, newOwner),
  });

  await assert.rejects(
    journal.recoverStaleLock({ expectedLeaseId: staleOwner.leaseId }),
    /owner changed.*retained at/i,
  );

  assert.deepEqual(JSON.parse(await readFile(`${journalPath}.lock`, "utf8")), newOwner);
  const claims = (await readdir(directory)).filter((name) => name.endsWith(".claim"));
  assert.equal(claims.length, 1);
  assert.deepEqual(JSON.parse(await readFile(join(directory, claims[0]), "utf8")), movedReplacement);
});

test("git ignores every replayable journal path and tracks none", async () => {
  const repository = fileURLToPath(new URL("../../", import.meta.url));
  const paths = [
    "phase0/pending-transactions.json",
    "phase0/pending-transactions.json.audit.tmp",
    "phase0/pending-transactions.json.lock",
    "phase0/pending-transactions.json.lock.audit.claim",
  ];
  const ignored = await execFileAsync("git", ["check-ignore", "-v", ...paths], { cwd: repository });
  for (const path of paths) assert.match(ignored.stdout, new RegExp(path.replaceAll(".", "\\.")));

  const tracked = await execFileAsync("git", ["ls-files", ...paths], { cwd: repository });
  assert.equal(tracked.stdout, "");
});

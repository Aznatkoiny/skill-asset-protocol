import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import {
  canonicalChallengeEventStatement,
  canonicalRepositoryStatement,
  challengeEventStatementHash,
  deterministicConflictId,
  repositoryStatementHash,
  type ChallengeOpenedEvent,
  type RegistrationSubject,
  type RepositoryControlEvent,
} from "../src/attestations";
import { FileAttestationStore, writeAll } from "../src/attestation-store";

const IP_A = `0x${"a".repeat(40)}` as const;
const IP_B = `0x${"b".repeat(40)}` as const;
const ARTIFACT_HASH = `0x${"1".repeat(64)}` as const;
const NOW = "2026-07-18T12:00:00.000Z";

function subject(ipId: `0x${string}`, wallet: `0x${string}`): RegistrationSubject {
  return {
    registrationId: `eip155:1315:${ipId}`,
    ipId,
    wallet: wallet.toLowerCase() as `0x${string}`,
    artifactHash: ARTIFACT_HASH,
    declaredParentIpIds: [],
  };
}

async function fixture(t: test.TestContext, hooks?: ConstructorParameters<typeof FileAttestationStore>[1]["hooks"]) {
  const directory = await mkdtemp(join(tmpdir(), "phase0-attestation-store-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = privateKeyToAccount(generatePrivateKey());
  const second = privateKeyToAccount(generatePrivateKey());
  const a = subject(IP_A, first.address);
  const b = subject(IP_B, second.address);
  const path = resolve(directory, "attestations.jsonl");
  const store = new FileAttestationStore(path, { baseSubjects: [a, b], hooks });
  const base = {
    type: "challenge_opened" as const,
    eventId: "challenge-1",
    sequence: 1,
    occurredAt: NOW,
    conflictId: deterministicConflictId(a, b),
    challengedRegistrationId: a.registrationId,
    challengerRegistrationId: b.registrationId,
    challengerWallet: b.wallet,
    evidenceUris: ["https://example.com/evidence"],
    reason: "duplicate_bytes" as const,
    statementHash: ARTIFACT_HASH,
    signature: "0x00" as `0x${string}`,
  };
  const event: ChallengeOpenedEvent = {
    ...base,
    statementHash: challengeEventStatementHash(base),
    signature: await second.signMessage({ message: canonicalChallengeEventStatement({ ...base, statementHash: challengeEventStatementHash(base) }) }),
  };
  return { directory, path, store, event, a, b, first };
}

test("absent store loads empty and append is newline-terminated and replay-validated", async (t) => {
  const f = await fixture(t);
  assert.deepEqual(await f.store.load(), []);
  assert.equal(await f.store.nextSequence(), 1);
  await f.store.append(f.event);
  assert.deepEqual(await f.store.load(), [f.event]);
  const bytes = await readFile(f.path, "utf8");
  assert.ok(bytes.endsWith("\n"));
  assert.equal(bytes.trim().split("\n").length, 1);
});

test("sequence, duplicate ID, and malformed trailing bytes fail closed without successful append", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.store.append({ ...f.event, sequence: 2 }), /sequence must equal 1/);
  await f.store.append(f.event);
  const before = await readFile(f.path);
  await assert.rejects(f.store.append({ ...f.event, sequence: 2 }), /duplicate attestation event ID/);
  assert.deepEqual(await readFile(f.path), before);
  await writeFile(f.path, Buffer.concat([before, Buffer.from("{partial")]));
  await assert.rejects(f.store.load(), /malformed trailing fragment/);
});

test("fabricated repository event cannot append without verifier context", async (t) => {
  const f = await fixture(t);
  const challenge = {
    schemaVersion: 1 as const,
    subject: f.a,
    repositoryUrl: "https://github.com/example/skill",
    artifactCommitSha: "1".repeat(40),
    artifactPath: "skills/demo/SKILL.md",
    challengePath: "attestations/demo.json",
    nonce: `0x${"3".repeat(64)}` as `0x${string}`,
    issuedAt: "2026-07-18T10:00:00.000Z",
    expiresAt: "2026-07-18T14:00:00.000Z",
  };
  const event: RepositoryControlEvent = {
    type: "repository_control_verified",
    eventId: "repo-1",
    sequence: 1,
    occurredAt: NOW,
    subject: f.a,
    challenge,
    forgeObservation: {
      schemaVersion: 1,
      repositoryId: "demo",
      repositoryUrl: challenge.repositoryUrl,
      trustedRef: "refs/heads/main",
      proofCommitSha: "2".repeat(40),
      challengeNonce: challenge.nonce,
      observedAt: "2026-07-18T11:00:00.000Z",
      forgeSignerId: "forge-1",
      signature: "fabricated",
    },
    statementHash: repositoryStatementHash(challenge),
    signature: await f.first.signMessage({ message: canonicalRepositoryStatement(challenge) }),
  };
  await assert.rejects(f.store.append(event), /repository verifier context required/);
  await assert.rejects(readFile(f.path), /ENOENT/);
});

test("only one concurrent writer may hold the append lock", async (t) => {
  let entered!: () => void;
  const enteredPromise = new Promise<void>((resolveEntered) => { entered = resolveEntered; });
  let release!: () => void;
  const releasePromise = new Promise<void>((resolveRelease) => { release = resolveRelease; });
  const f = await fixture(t, { beforeAppendWrite: async () => { entered(); await releasePromise; } });
  const firstAppend = f.store.append(f.event);
  await enteredPromise;
  const contender = new FileAttestationStore(f.path, { baseSubjects: [f.a, f.b] });
  await assert.rejects(contender.append(f.event), /attestation store locked/);
  release();
  await firstAppend;
  assert.equal((await f.store.load()).length, 1);
});

test("crash-left lock requires exact token and absent PID for explicit recovery", async (t) => {
  const f = await fixture(t);
  const owner = {
    schemaVersion: 1,
    pid: 999_999,
    token: "0123456789abcdef0123456789abcdef",
    targetPath: f.path,
    acquiredAt: NOW,
  };
  await writeFile(`${f.path}.lock`, `${JSON.stringify(owner)}\n`, { mode: 0o600 });
  await assert.rejects(f.store.load(), /attestation store locked/);
  await assert.rejects(f.store.recoverStaleLock({ expectedToken: "f".repeat(32), isProcessAlive: () => false }), /does not match/);
  await assert.rejects(f.store.recoverStaleLock({ expectedToken: owner.token, isProcessAlive: () => true }), /still alive/);
  await f.store.recoverStaleLock({ expectedToken: owner.token, isProcessAlive: () => false });
  assert.deepEqual(await f.store.load(), []);
});

test("writeAll handles short writes and rejects zero or invalid progress", async () => {
  const source = Buffer.from("complete-record\n");
  const chunks: Buffer[] = [];
  await writeAll({
    async write(buffer, offset, length) {
      const count = Math.min(3, length);
      chunks.push(Buffer.from(buffer).subarray(offset, offset + count));
      return { bytesWritten: count };
    },
  }, source);
  assert.deepEqual(Buffer.concat(chunks), source);
  await assert.rejects(writeAll({ async write() { return { bytesWritten: 0 }; } }, source), /made no progress/);
  await assert.rejects(writeAll({ async write(_buffer, _offset, length) { return { bytesWritten: length + 1 }; } }, source), /invalid byte count/);
});

test("failed acquisition never deletes a replacement lock owner", async (t) => {
  let store!: FileAttestationStore;
  const f = await fixture(t, {
    afterLockCreated: async () => {
      await rename(`${f.path}.lock`, `${f.path}.lock.original`);
      await writeFile(`${f.path}.lock`, `${JSON.stringify({
        schemaVersion: 1,
        pid: 777_777,
        token: "f".repeat(32),
        targetPath: f.path,
        acquiredAt: NOW,
      })}\n`, { mode: 0o600 });
      throw new Error("injected failure after replacement");
    },
  });
  store = f.store;
  await assert.rejects(store.load(), /observed owner was retained/);
  const replacement = JSON.parse(await readFile(`${f.path}.lock`, "utf8"));
  assert.equal(replacement.token, "f".repeat(32));
});

test("event log rejects symlinks and non-owner-only modes", async (t) => {
  const f = await fixture(t);
  const victim = resolve(f.directory, "victim.jsonl");
  await writeFile(victim, "", { mode: 0o600 });
  await symlink(victim, f.path);
  await assert.rejects(f.store.load(), /must not be a symlink|non-symlink/);
  await rm(f.path);
  await writeFile(f.path, "", { mode: 0o644 });
  await chmod(f.path, 0o644);
  await assert.rejects(f.store.load(), /mode 0600/);
});

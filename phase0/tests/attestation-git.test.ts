import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as signBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync } from "node:child_process";
import test from "node:test";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import {
  canonicalRepositoryStatement,
  repositoryStatementHash,
  type ForgeObservationV1,
  type RegistrationSubject,
} from "../src/attestations";
import {
  createTrustedRepositoryResolver,
  loadLocalCheckoutMap,
} from "../src/attestation-config";
import {
  canonicalChallengeFileBytes,
  canonicalForgeObservationBytes,
  ExecGitReader,
  verifyRepositoryControl,
  type SignedRepositoryChallengeFileV1,
} from "../src/attestation-git";

const REPOSITORY_URL = "https://github.com/example/offline-skill";

function git(repo: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repo, ...args], {
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
  }).trim();
}

async function fixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "phase0-attestation-git-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  git(root, "init", "-b", "main");
  git(root, "config", "user.name", "Offline Test");
  git(root, "config", "user.email", "offline@example.invalid");
  git(root, "remote", "add", "origin", REPOSITORY_URL);
  const artifact = Buffer.from("# Demo Skill\n\nOffline evidence.\n", "utf8");
  await mkdir(join(root, "skills/demo"), { recursive: true });
  await writeFile(join(root, "skills/demo/SKILL.md"), artifact);
  git(root, "add", "skills/demo/SKILL.md");
  git(root, "commit", "-m", "add Skill bytes");
  const artifactCommit = git(root, "rev-parse", "HEAD");

  const wallet = privateKeyToAccount(generatePrivateKey());
  const ipId = `0x${"a".repeat(40)}` as const;
  const subject: RegistrationSubject = {
    registrationId: `eip155:1315:${ipId}`,
    ipId,
    wallet: wallet.address.toLowerCase() as `0x${string}`,
    artifactHash: `0x${createHash("sha256").update(artifact).digest("hex")}`,
    declaredParentIpIds: [],
  };
  const challenge = {
    schemaVersion: 1 as const,
    subject,
    repositoryUrl: REPOSITORY_URL,
    artifactCommitSha: artifactCommit,
    artifactPath: "skills/demo/SKILL.md",
    challengePath: "attestations/repository-control.json",
    nonce: `0x${"4".repeat(64)}` as `0x${string}`,
    issuedAt: "2026-07-18T10:00:00.000Z",
    expiresAt: "2026-07-18T14:00:00.000Z",
  };
  const signed: SignedRepositoryChallengeFileV1 = {
    challenge,
    statementHash: repositoryStatementHash(challenge),
    signature: await wallet.signMessage({ message: canonicalRepositoryStatement(challenge) }),
  };
  const challengeFile = canonicalChallengeFileBytes(signed);
  await mkdir(join(root, "attestations"));
  await writeFile(join(root, challenge.challengePath), challengeFile);
  git(root, "add", challenge.challengePath);
  git(root, "commit", "-m", "add signed repository challenge");
  const proofCommit = git(root, "rev-parse", "HEAD");

  const forge = generateKeyPairSync("ed25519");
  const unsignedObservation = {
    schemaVersion: 1 as const,
    repositoryId: "demo",
    repositoryUrl: REPOSITORY_URL,
    trustedRef: "refs/heads/main" as const,
    proofCommitSha: proofCommit,
    challengeNonce: challenge.nonce,
    observedAt: "2026-07-18T11:00:00.000Z",
    forgeSignerId: "forge-1",
  };
  const forgeObservation: ForgeObservationV1 = {
    ...unsignedObservation,
    signature: signBytes(null, canonicalForgeObservationBytes(unsignedObservation), forge.privateKey).toString("base64"),
  };
  const trustConfig = {
    schemaVersion: 1,
    repositories: [{
      repositoryId: "demo",
      repositoryUrl: REPOSITORY_URL,
      checkoutKey: "demo-checkout",
      trustedRef: "refs/heads/main",
      permittedForgeSignerIds: ["forge-1"],
    }],
  };
  const repositories = createTrustedRepositoryResolver({ trustConfig, checkoutPaths: { "demo-checkout": root } });
  const forgeSigners = { "forge-1": forge.publicKey.export({ type: "spki", format: "pem" }).toString() };
  return { root, artifactCommit, proofCommit, subject, challenge, challengeFile, forgeObservation, repositories, forgeSigners, trustConfig };
}

test("repository control verifies offline against exact artifact and challenge bytes", async (t) => {
  const f = await fixture(t);
  const event = await verifyRepositoryControl({
    challengeFile: f.challengeFile,
    forgeObservation: f.forgeObservation,
    eventId: "repository-1",
    sequence: 1,
    occurredAt: "2026-07-18T12:00:00.000Z",
    now: new Date("2026-07-18T12:30:00.000Z"),
    git: new ExecGitReader(),
    repositories: f.repositories,
    forgeSigners: f.forgeSigners,
  });
  assert.equal(event.type, "repository_control_verified");
  assert.equal(event.subject.artifactHash, f.subject.artifactHash);
});

test("repository verification rejects signed-binding and snapshot tampering", async (t) => {
  const f = await fixture(t);
  const base = {
    challengeFile: f.challengeFile,
    forgeObservation: f.forgeObservation,
    eventId: "repository-1",
    sequence: 1,
    occurredAt: "2026-07-18T12:00:00.000Z",
    now: new Date("2026-07-18T12:30:00.000Z"),
    git: new ExecGitReader(),
    repositories: f.repositories,
    forgeSigners: f.forgeSigners,
  };
  await assert.rejects(verifyRepositoryControl({ ...base, forgeObservation: { ...f.forgeObservation, challengeNonce: `0x${"5".repeat(64)}` } }), /signature is invalid|nonce mismatch/);
  await assert.rejects(verifyRepositoryControl({ ...base, forgeObservation: { ...f.forgeObservation, proofCommitSha: f.artifactCommit } }), /signature is invalid|does not match/);
  await assert.rejects(verifyRepositoryControl({ ...base, forgeSigners: {} }), /unknown/);
  const altered = Buffer.from(f.challengeFile);
  altered[altered.length - 2] ^= 1;
  await assert.rejects(verifyRepositoryControl({ ...base, challengeFile: altered }), /malformed|canonical|statement|signature/);
});

test("resolver rejects claimant-selected repositories before Git runs", async (t) => {
  const f = await fixture(t);
  let calls = 0;
  const gitReader = {
    commitExists: async () => { calls += 1; return true; },
    readBlob: async () => { calls += 1; return new Uint8Array(); },
    isAncestor: async () => { calls += 1; return true; },
    remoteUrl: async () => { calls += 1; return REPOSITORY_URL; },
  };
  await assert.rejects(verifyRepositoryControl({
    challengeFile: f.challengeFile,
    forgeObservation: { ...f.forgeObservation, repositoryId: "claimant-copy" },
    eventId: "repository-1",
    sequence: 1,
    occurredAt: "2026-07-18T12:00:00.000Z",
    now: new Date("2026-07-18T12:30:00.000Z"),
    git: gitReader,
    repositories: f.repositories,
    forgeSigners: f.forgeSigners,
  }), /not present|signature/);
  assert.equal(calls, 0);
});

test("local checkout mapping requires exact owner-only canonical configuration", async (t) => {
  const f = await fixture(t);
  const phase0Root = await mkdtemp(join(tmpdir(), "phase0-attestation-config-"));
  t.after(() => rm(phase0Root, { recursive: true, force: true }));
  const canonicalPhase0Root = await realpath(phase0Root);
  const mappingPath = join(canonicalPhase0Root, ".attestation-checkouts.local.json");
  await writeFile(mappingPath, `${JSON.stringify({ schemaVersion: 1, checkouts: { "demo-checkout": f.root } })}\n`, { mode: 0o600 });
  await chmod(mappingPath, 0o600);
  const loaded = await loadLocalCheckoutMap({ env: {}, phase0Root: canonicalPhase0Root, referencedCheckoutKeys: ["demo-checkout"] });
  assert.deepEqual(loaded, { "demo-checkout": f.root });
  assert.ok(Object.isFrozen(loaded));

  await chmod(mappingPath, 0o644);
  await assert.rejects(loadLocalCheckoutMap({ env: {}, phase0Root: canonicalPhase0Root, referencedCheckoutKeys: ["demo-checkout"] }), /mode 0600/);
  await chmod(mappingPath, 0o600);
  await assert.rejects(loadLocalCheckoutMap({ env: {}, phase0Root: canonicalPhase0Root, referencedCheckoutKeys: [] }), /exactly match/);
  await assert.rejects(loadLocalCheckoutMap({ env: { PHASE0_ATTESTATION_CHECKOUTS_FILE: "relative.json" }, phase0Root: canonicalPhase0Root, referencedCheckoutKeys: ["demo-checkout"] }), /absolute path/);
  await assert.rejects(loadLocalCheckoutMap({ env: { PHASE0_ATTESTATION_CHECKOUTS_FILE: join(canonicalPhase0Root, "tracked.json") }, phase0Root: canonicalPhase0Root, referencedCheckoutKeys: ["demo-checkout"] }), /exact ignored default/);
});

test("missing checkout mapping fails with an explicit unavailable error", async (t) => {
  const phase0Root = await mkdtemp(join(tmpdir(), "phase0-attestation-missing-"));
  t.after(() => rm(phase0Root, { recursive: true, force: true }));
  await assert.rejects(loadLocalCheckoutMap({ env: {}, phase0Root: await realpath(phase0Root), referencedCheckoutKeys: [] }), /repository snapshot mapping unavailable/);
});

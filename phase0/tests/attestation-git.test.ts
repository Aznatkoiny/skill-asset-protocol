import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as signBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, realpath, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
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
  verifyForgeObservation,
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
  const rootMetadata = await stat(root);
  const repositories = createTrustedRepositoryResolver({
    trustConfig,
    checkoutPaths: { "demo-checkout": { repositoryPath: root, device: rootMetadata.dev, inode: rootMetadata.ino } },
  });
  const forgeSigners = { "forge-1": forge.publicKey.export({ type: "spki", format: "pem" }).toString() };
  return { root, artifactCommit, proofCommit, subject, challenge, challengeFile, forge, forgeObservation, repositories, forgeSigners, trustConfig };
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

test("forge observation trust accepts only one canonical Ed25519 SPKI public key", async (t) => {
  const f = await fixture(t);
  const trusted = f.repositories.resolve("demo", REPOSITORY_URL);
  const { signature: _signature, ...unsignedObservation } = f.forgeObservation;
  const observationBytes = canonicalForgeObservationBytes(unsignedObservation);
  const canonicalPublicKey = f.forge.publicKey.export({ type: "spki", format: "pem" }).toString();
  const privateKey = f.forge.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const secondEd25519 = generateKeyPairSync("ed25519");
  const rsa512 = generateKeyPairSync("rsa", { modulusLength: 512 });
  const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ed448 = generateKeyPairSync("ed448");
  const signedBy = (signer: typeof f.forge.privateKey): ForgeObservationV1 => ({
    ...unsignedObservation,
    signature: signBytes(null, observationBytes, signer).toString("base64"),
  });
  const invalid = [
    { name: "weak RSA", key: rsa512.publicKey.export({ type: "spki", format: "pem" }).toString(), observation: signedBy(rsa512.privateKey) },
    { name: "RSA", key: rsa2048.publicKey.export({ type: "spki", format: "pem" }).toString(), observation: signedBy(rsa2048.privateKey) },
    { name: "Ed448", key: ed448.publicKey.export({ type: "spki", format: "pem" }).toString(), observation: signedBy(ed448.privateKey) },
    { name: "private PEM", key: privateKey, observation: f.forgeObservation },
    { name: "trailing whitespace", key: `${canonicalPublicKey}\n`, observation: f.forgeObservation },
    { name: "trailing text", key: `${canonicalPublicKey}trailing`, observation: f.forgeObservation },
    { name: "concatenated public PEM", key: canonicalPublicKey + secondEd25519.publicKey.export({ type: "spki", format: "pem" }).toString(), observation: f.forgeObservation },
    { name: "appended private PEM", key: canonicalPublicKey + privateKey, observation: f.forgeObservation },
  ];

  assert.doesNotThrow(() => verifyForgeObservation(f.forgeObservation, trusted, { "forge-1": canonicalPublicKey }));
  for (const variant of invalid) {
    assert.throws(
      () => verifyForgeObservation(variant.observation, trusted, { "forge-1": variant.key }),
      /canonical Ed25519 SPKI public key/,
      variant.name,
    );
  }
});

test("forge observation signatures must be canonical base64 encoding of exactly 64 bytes", async (t) => {
  const f = await fixture(t);
  const trusted = f.repositories.resolve("demo", REPOSITORY_URL);
  for (const length of [63, 65]) {
    assert.throws(
      () => verifyForgeObservation(
        { ...f.forgeObservation, signature: Buffer.alloc(length, 1).toString("base64") },
        trusted,
        f.forgeSigners,
      ),
      /exactly 64 bytes/,
    );
  }
});

test("forge observation trust rejects inherited signer entries and exotic map prototypes", async (t) => {
  const f = await fixture(t);
  const trusted = f.repositories.resolve("demo", REPOSITORY_URL);
  const canonicalPublicKey = f.forge.publicKey.export({ type: "spki", format: "pem" }).toString();
  Object.defineProperty(Object.prototype, "forge-1", {
    configurable: true,
    enumerable: false,
    value: canonicalPublicKey,
  });
  try {
    assert.throws(
      () => verifyForgeObservation(f.forgeObservation, trusted, {}),
      /own property/,
    );
  } finally {
    delete (Object.prototype as Record<string, unknown>)["forge-1"];
  }

  const inherited = Object.create({ "forge-1": canonicalPublicKey }) as Record<string, string>;
  assert.throws(
    () => verifyForgeObservation(f.forgeObservation, trusted, inherited),
    /plain or null-prototype record/,
  );
});

test("forge observation snapshots every own signer entry without invoking accessors", async (t) => {
  const f = await fixture(t);
  const trusted = f.repositories.resolve("demo", REPOSITORY_URL);
  const canonicalPublicKey = f.forge.publicKey.export({ type: "spki", format: "pem" }).toString();
  let getterCalls = 0;
  const accessorTrust = { "forge-1": canonicalPublicKey } as Record<string, string>;
  Object.defineProperty(accessorTrust, "unused-forge", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return canonicalPublicKey;
    },
  });

  assert.throws(
    () => verifyForgeObservation(f.forgeObservation, trusted, accessorTrust),
    /own enumerable data properties/,
  );
  assert.equal(getterCalls, 0);
  assert.throws(
    () => verifyForgeObservation(f.forgeObservation, trusted, {
      "forge-1": canonicalPublicKey,
      "unused-forge": "not-a-public-key",
    }),
    /canonical Ed25519 SPKI public key/,
  );

  const symbolTrust = { "forge-1": canonicalPublicKey } as Record<PropertyKey, string>;
  Object.defineProperty(symbolTrust, Symbol("unused-forge"), {
    enumerable: true,
    value: canonicalPublicKey,
  });
  assert.throws(
    () => verifyForgeObservation(
      f.forgeObservation,
      trusted,
      symbolTrust as Readonly<Record<string, string>>,
    ),
    /string identifier keys/,
  );
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
    repositoryIdentity: async () => { calls += 1; return { device: 1, inode: 1 }; },
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
  const checkoutMetadata = await stat(f.root);
  assert.deepEqual(loaded, {
    "demo-checkout": { repositoryPath: f.root, device: checkoutMetadata.dev, inode: checkoutMetadata.ino },
  });
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

test("checkout mapping rejects a symlink instead of following a swapped path", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "phase0-attestation-symlink-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const target = join(root, "target.json");
  await writeFile(target, '{"schemaVersion":1,"checkouts":{}}\n', { mode: 0o600 });
  await symlink(target, join(root, ".attestation-checkouts.local.json"));
  await assert.rejects(loadLocalCheckoutMap({ env: {}, phase0Root: root, referencedCheckoutKeys: [] }), /non-symlink regular file/);
});

test("Git verification ignores poisoned process environment, PATH, and replacement refs", async (t) => {
  const f = await fixture(t);
  await writeFile(join(f.root, "skills/demo/SKILL.md"), "tampered replacement bytes\n");
  git(f.root, "add", "skills/demo/SKILL.md");
  git(f.root, "commit", "-m", "replacement object not trusted");
  const replacementCommit = git(f.root, "rev-parse", "HEAD");
  git(f.root, "reset", "--hard", f.proofCommit);
  git(f.root, "replace", f.artifactCommit, replacementCommit);
  assert.match(git(f.root, "show", `${f.artifactCommit}:skills/demo/SKILL.md`), /tampered replacement bytes/);

  const poisoned: Record<string, string> = {
    PATH: "/definitely/not/a/git/path",
    GIT_DIR: "/attacker/git-dir",
    GIT_WORK_TREE: "/attacker/work-tree",
    GIT_OBJECT_DIRECTORY: "/attacker/objects",
    GIT_ALTERNATE_OBJECT_DIRECTORIES: "/attacker/alternates",
    GIT_NAMESPACE: "attacker",
    GIT_CONFIG_GLOBAL: "/attacker/global-config",
    GIT_CONFIG_SYSTEM: "/attacker/system-config",
    GIT_CONFIG_COUNT: "1",
    GIT_CONFIG_KEY_0: "core.sshCommand",
    GIT_CONFIG_VALUE_0: "/attacker/command",
  };
  const prior = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(poisoned)) {
    prior.set(key, process.env[key]);
    process.env[key] = value;
  }
  try {
    const event = await verifyRepositoryControl({
      challengeFile: f.challengeFile,
      forgeObservation: f.forgeObservation,
      eventId: "repository-poisoned-env",
      sequence: 1,
      occurredAt: "2026-07-18T12:00:00.000Z",
      now: new Date("2026-07-18T12:30:00.000Z"),
      git: new ExecGitReader(),
      repositories: f.repositories,
      forgeSigners: f.forgeSigners,
    });
    assert.equal(event.subject.artifactHash, f.subject.artifactHash);
  } finally {
    for (const [key, value] of prior) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});

test("ExecGitReader requires an absolute verifier-controlled executable", () => {
  assert.throws(() => new ExecGitReader({ gitExecutable: "git" }), /absolute Git executable/);
});

test("ExecGitReader rejects 41- and 63-character hexadecimal object names on every commit path", async (t) => {
  const f = await fixture(t);
  const reader = new ExecGitReader();
  for (const length of [41, 63]) {
    const invalid = "a".repeat(length);
    await assert.rejects(reader.commitExists(f.root, invalid), /not a full commit OID/);
    await assert.rejects(reader.readBlob(f.root, invalid, "skills/demo/SKILL.md"), /not a full commit OID/);
    await assert.rejects(reader.isAncestor(f.root, invalid, f.proofCommit), /not a full commit OID/);
    await assert.rejects(reader.isAncestor(f.root, f.artifactCommit, invalid), /not a full commit OID/);
  }
});

test("ExecGitReader requires the exact fully resolved OID in a SHA-256 repository", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "phase0-attestation-git-sha256-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const initialized = spawnSync("/usr/bin/git", ["-C", root, "init", "--object-format=sha256", "-b", "main"], {
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
  });
  if (initialized.status !== 0) {
    const detail = `${initialized.stdout}\n${initialized.stderr}`;
    if (/unknown option.*object-format|unknown hash algorithm.*sha256|unsupported.*sha256|sha256.*not supported/i.test(detail)) {
      t.skip("installed Git does not support SHA-256 repositories");
      return;
    }
    assert.fail(`SHA-256 repository initialization failed unexpectedly: ${detail}`);
  }

  git(root, "config", "user.name", "SHA-256 Test");
  git(root, "config", "user.email", "sha256@example.invalid");
  await writeFile(join(root, "artifact.txt"), "sha256 repository artifact\n");
  git(root, "add", "artifact.txt");
  git(root, "commit", "-m", "add SHA-256 artifact");
  const fullOid = git(root, "rev-parse", "HEAD");
  assert.equal(fullOid.length, 64);
  const prefix40 = fullOid.slice(0, 40);
  const prefix41 = fullOid.slice(0, 41);
  const reader = new ExecGitReader();

  assert.equal(await reader.commitExists(root, fullOid), true);
  assert.equal(await reader.commitExists(root, prefix40), false);
  await assert.rejects(reader.commitExists(root, prefix41), /not a full commit OID/);
  await assert.rejects(reader.readBlob(root, prefix40, "artifact.txt"), /exact full commit OID/);
  await assert.rejects(reader.readBlob(root, prefix41, "artifact.txt"), /not a full commit OID/);
  assert.equal(await reader.isAncestor(root, prefix40, fullOid), false);
  await assert.rejects(reader.isAncestor(root, prefix41, fullOid), /not a full commit OID/);
});

test("missing partial-clone objects fail without invoking a remote helper", async (t) => {
  const f = await fixture(t);
  const blobOid = git(f.root, "rev-parse", `${f.artifactCommit}:skills/demo/SKILL.md`);
  const objectPath = join(f.root, ".git", "objects", blobOid.slice(0, 2), blobOid.slice(2));
  await unlink(objectPath);
  const marker = join(f.root, "remote-helper-invoked");
  const helper = join(f.root, "remote-helper.sh");
  await writeFile(helper, `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o700 });
  await chmod(helper, 0o700);
  git(f.root, "config", "extensions.partialClone", "origin");
  git(f.root, "config", "remote.origin.promisor", "true");
  git(f.root, "config", "remote.origin.partialclonefilter", "blob:none");
  git(f.root, "remote", "set-url", "origin", `ext::${helper}`);
  await assert.rejects(new ExecGitReader().readBlob(f.root, f.artifactCommit, "skills/demo/SKILL.md"), /offline Git verification failed/);
  await assert.rejects(realpath(marker), /ENOENT/);
});

test("repository verification fails if checkout device/inode changes between Git operations", async (t) => {
  const f = await fixture(t);
  const delegate = new ExecGitReader();
  let identityChecks = 0;
  const changingIdentity = {
    repositoryIdentity: async (path: string) => {
      identityChecks += 1;
      const identity = await delegate.repositoryIdentity(path);
      return identityChecks === 1 ? identity : { ...identity, inode: identity.inode + 1 };
    },
    commitExists: delegate.commitExists.bind(delegate),
    readBlob: delegate.readBlob.bind(delegate),
    isAncestor: delegate.isAncestor.bind(delegate),
    remoteUrl: delegate.remoteUrl.bind(delegate),
  };
  await assert.rejects(verifyRepositoryControl({
    challengeFile: f.challengeFile,
    forgeObservation: f.forgeObservation,
    eventId: "repository-identity-drift",
    sequence: 1,
    occurredAt: "2026-07-18T12:00:00.000Z",
    now: new Date("2026-07-18T12:30:00.000Z"),
    git: changingIdentity,
    repositories: f.repositories,
    forgeSigners: f.forgeSigners,
  }), /filesystem identity changed/);
});

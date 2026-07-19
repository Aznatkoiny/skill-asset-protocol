import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as signBytes } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import { executeAttestationCommand, type AttestationRuntimePaths } from "../src/attestation-cli";
import {
  adminEventStatementHash,
  canonicalAdminEventStatement,
  canonicalChallengeEventStatement,
  canonicalOrganizationStatement,
  canonicalRepositoryStatement,
  challengeEventStatementHash,
  organizationStatementHash,
  repositoryStatementHash,
  type AttestationRevokedEvent,
  type ChallengeOpenedEvent,
  type ChallengeResolvedEvent,
  type OrganizationApprovedEvent,
} from "../src/attestations";
import { canonicalForgeObservationBytes, type GitReader } from "../src/attestation-git";
import { createEmptyRegistrationManifest, FileRegistrationStore, type RegistrationProof } from "../src/registrations";

const REPOSITORY_URL = "https://github.com/example/attestation-cli";
const NOW = new Date("2026-07-18T04:00:00.000Z");

function git(repositoryPath: string, ...args: string[]): string {
  return execFileSync("git", ["-C", repositoryPath, ...args], {
    encoding: "utf8",
    env: { ...process.env, GIT_CONFIG_NOSYSTEM: "1", GIT_TERMINAL_PROMPT: "0" },
  }).trim();
}

test("production repository command fails before Git for missing/insecure mapping and succeeds with canonical 0600 mapping", async (t) => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "phase0-attestation-cli-")));
  t.after(() => rm(root, { recursive: true, force: true }));
  const checkout = join(root, "checkout");
  await mkdir(checkout, { mode: 0o700 });
  git(checkout, "init", "-b", "main");
  git(checkout, "config", "user.name", "Offline CLI Test");
  git(checkout, "config", "user.email", "offline-cli@example.invalid");
  git(checkout, "remote", "add", "origin", REPOSITORY_URL);
  const artifact = Buffer.from("# CLI Skill\n\nExact offline bytes.\n");
  await mkdir(join(checkout, "skills/demo"), { recursive: true });
  await writeFile(join(checkout, "skills/demo/SKILL.md"), artifact);
  git(checkout, "add", "skills/demo/SKILL.md");
  git(checkout, "commit", "-m", "add CLI Skill bytes");
  const artifactCommitSha = git(checkout, "rev-parse", "HEAD");

  const wallet = privateKeyToAccount(generatePrivateKey());
  const ipId = `0x${"a".repeat(40)}` as const;
  const artifactHash = `0x${createHash("sha256").update(artifact).digest("hex")}` as `0x${string}`;
  const manifest = createEmptyRegistrationManifest();
  manifest.status = "partial";
  manifest.wallet = wallet.address.toLowerCase() as `0x${string}`;
  manifest.spgNftContract = `0x${"b".repeat(40)}`;
  manifest.collectionTxHash = `0x${"c".repeat(64)}`;
  manifest.registrations.root = {
    stage: "root",
    kind: "Skill",
    name: "CLI Skill",
    ipId,
    tokenId: "1",
    txHash: `0x${"d".repeat(64)}`,
    licenseTermsId: "1",
    licenseTemplate: `0x${"e".repeat(40)}`,
    parentIpIds: [],
    defaultMintingFee: "1",
    maxMintingFee: null,
    metadata: {
      ip: { uri: "https://example.invalid/ip", hash: `0x${"1".repeat(64)}` },
      nft: { uri: "https://example.invalid/nft", hash: `0x${"2".repeat(64)}` },
      artifact: { path: "skills/demo/SKILL.md", mediaHash: artifactHash, mediaType: "text/markdown" },
    },
  } satisfies RegistrationProof;
  const challengerIpId = `0x${"f".repeat(40)}` as const;
  manifest.registrations.child = {
    stage: "child",
    kind: "Derivative",
    name: "CLI Challenger Skill",
    ipId: challengerIpId,
    tokenId: "2",
    txHash: `0x${"4".repeat(64)}`,
    licenseTermsId: "1",
    licenseTemplate: `0x${"e".repeat(40)}`,
    parentIpIds: [ipId],
    defaultMintingFee: null,
    maxMintingFee: "1",
    metadata: {
      ip: { uri: "https://example.invalid/challenger-ip", hash: `0x${"5".repeat(64)}` },
      nft: { uri: "https://example.invalid/challenger-nft", hash: `0x${"6".repeat(64)}` },
      artifact: {
        path: "skills/challenger/SKILL.md",
        mediaHash: `0x${"7".repeat(64)}`,
        mediaType: "text/markdown",
      },
    },
  } satisfies RegistrationProof;

  const paths: AttestationRuntimePaths = {
    registrations: join(root, "registrations.json"),
    attestations: join(root, "attestations.jsonl"),
    organizations: join(root, "organization-signers.json"),
    admins: join(root, "attestation-admins.json"),
    repositories: join(root, "repository-trust.json"),
    forgeSigners: join(root, "forge-signers.json"),
  };
  await new FileRegistrationStore(paths.registrations).save(manifest);
  await writeFile(paths.organizations, '{"schemaVersion":1,"organizations":{}}\n');
  await writeFile(paths.admins, '{"schemaVersion":1,"admins":{}}\n');

  const challenge = {
    schemaVersion: 1 as const,
    subject: {
      registrationId: `eip155:1315:${ipId}` as const,
      ipId,
      wallet: manifest.wallet,
      artifactHash,
      declaredParentIpIds: [],
    },
    repositoryUrl: REPOSITORY_URL,
    artifactCommitSha,
    artifactPath: "skills/demo/SKILL.md",
    challengePath: "attestations/repository-control.json",
    nonce: `0x${"3".repeat(64)}` as `0x${string}`,
    issuedAt: "2026-07-18T00:00:00.000Z",
    expiresAt: "2026-07-18T06:00:00.000Z",
  };
  const challengeFile = {
    challenge,
    statementHash: repositoryStatementHash(challenge),
    signature: await wallet.signMessage({ message: canonicalRepositoryStatement(challenge) }),
  };
  await mkdir(join(checkout, "attestations"));
  await writeFile(join(checkout, challenge.challengePath), `${JSON.stringify(challengeFile)}\n`);
  git(checkout, "add", challenge.challengePath);
  git(checkout, "commit", "-m", "add CLI repository challenge");
  const proofCommitSha = git(checkout, "rev-parse", "HEAD");
  const forge = generateKeyPairSync("ed25519");
  const unsignedObservation = {
    schemaVersion: 1 as const,
    repositoryId: "demo",
    repositoryUrl: REPOSITORY_URL,
    trustedRef: "refs/heads/main" as const,
    proofCommitSha,
    challengeNonce: challenge.nonce,
    observedAt: "2026-07-18T01:00:00.000Z",
    forgeSignerId: "forge-1",
  };
  const forgeObservation = {
    ...unsignedObservation,
    signature: signBytes(null, canonicalForgeObservationBytes(unsignedObservation), forge.privateKey).toString("base64"),
  };
  await writeFile(paths.repositories, `${JSON.stringify({
    schemaVersion: 1,
    repositories: [{
      repositoryId: "demo",
      repositoryUrl: REPOSITORY_URL,
      checkoutKey: "demo-checkout",
      trustedRef: "refs/heads/main",
      permittedForgeSignerIds: ["forge-1"],
    }],
  })}\n`);
  await writeFile(paths.forgeSigners, `${JSON.stringify({
    schemaVersion: 1,
    forgeSigners: { "forge-1": forge.publicKey.export({ type: "spki", format: "pem" }).toString() },
  })}\n`);
  const bundlePath = join(root, "repository-bundle.json");
  const repositoryEventId = "repository-cli-\u0085\u202e1";
  await writeFile(bundlePath, `${JSON.stringify({
    schemaVersion: 1,
    eventId: repositoryEventId,
    sequence: 1,
    occurredAt: "2026-07-18T02:00:00.000Z",
    challengeFile,
    forgeObservation,
  })}\n`);

  let gitCalls = 0;
  const failIfCalled: GitReader = {
    repositoryIdentity: async () => { gitCalls += 1; throw new Error("Git must not run"); },
    commitExists: async () => { gitCalls += 1; throw new Error("Git must not run"); },
    readBlob: async () => { gitCalls += 1; throw new Error("Git must not run"); },
    isAncestor: async () => { gitCalls += 1; throw new Error("Git must not run"); },
    remoteUrl: async () => { gitCalls += 1; throw new Error("Git must not run"); },
  };
  await assert.rejects(executeAttestationCommand(
    "attestation-verify-repository",
    { bundle: bundlePath, json: true },
    () => undefined,
    { phase0Root: root, paths, env: {}, git: failIfCalled, now: () => NOW },
  ), /repository snapshot mapping unavailable/);
  assert.equal(gitCalls, 0);

  const mappingPath = join(root, ".attestation-checkouts.local.json");
  await writeFile(mappingPath, `${JSON.stringify({ schemaVersion: 1, checkouts: { "demo-checkout": checkout } })}\n`, { mode: 0o644 });
  await chmod(mappingPath, 0o644);
  await assert.rejects(executeAttestationCommand(
    "attestation-verify-repository",
    { bundle: bundlePath },
    () => undefined,
    { phase0Root: root, paths, env: {}, git: failIfCalled, now: () => NOW },
  ), /mode 0600/);
  assert.equal(gitCalls, 0);

  await chmod(mappingPath, 0o600);
  const canonicalForgePublicKey = forge.publicKey.export({ type: "spki", format: "pem" }).toString();
  const forgePrivateKey = forge.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const secondEd25519 = generateKeyPairSync("ed25519");
  const rsa512 = generateKeyPairSync("rsa", { modulusLength: 512 });
  const rsa2048 = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const ed448 = generateKeyPairSync("ed448");
  const observationBytes = canonicalForgeObservationBytes(unsignedObservation);
  const invalidForgeTrust = [
    { name: "weak RSA", key: rsa512.publicKey.export({ type: "spki", format: "pem" }).toString(), signature: signBytes(null, observationBytes, rsa512.privateKey).toString("base64") },
    { name: "RSA", key: rsa2048.publicKey.export({ type: "spki", format: "pem" }).toString(), signature: signBytes(null, observationBytes, rsa2048.privateKey).toString("base64") },
    { name: "Ed448", key: ed448.publicKey.export({ type: "spki", format: "pem" }).toString(), signature: signBytes(null, observationBytes, ed448.privateKey).toString("base64") },
    { name: "private PEM", key: forgePrivateKey, signature: forgeObservation.signature },
    { name: "trailing whitespace", key: `${canonicalForgePublicKey}\n`, signature: forgeObservation.signature },
    { name: "trailing text", key: `${canonicalForgePublicKey}trailing`, signature: forgeObservation.signature },
    { name: "concatenated public PEM", key: canonicalForgePublicKey + secondEd25519.publicKey.export({ type: "spki", format: "pem" }).toString(), signature: forgeObservation.signature },
    { name: "appended private PEM", key: canonicalForgePublicKey + forgePrivateKey, signature: forgeObservation.signature },
  ];
  for (const variant of invalidForgeTrust) {
    await writeFile(paths.forgeSigners, `${JSON.stringify({
      schemaVersion: 1,
      forgeSigners: { "forge-1": variant.key },
    })}\n`);
    await writeFile(bundlePath, `${JSON.stringify({
      schemaVersion: 1,
      eventId: repositoryEventId,
      sequence: 1,
      occurredAt: "2026-07-18T02:00:00.000Z",
      challengeFile,
      forgeObservation: { ...forgeObservation, signature: variant.signature },
    })}\n`);
    await assert.rejects(executeAttestationCommand(
      "attestation-verify-repository",
      { bundle: bundlePath },
      () => undefined,
      { phase0Root: root, paths, env: {}, git: failIfCalled, now: () => NOW },
    ), /canonical Ed25519 SPKI public key/, variant.name);
  }
  assert.equal(gitCalls, 0);

  await writeFile(paths.forgeSigners, `${JSON.stringify({
    schemaVersion: 1,
    forgeSigners: { "forge-1": canonicalForgePublicKey },
  })}\n`);
  await writeFile(bundlePath, `${JSON.stringify({
    schemaVersion: 1,
    eventId: repositoryEventId,
    sequence: 1,
    occurredAt: "2026-07-18T02:00:00.000Z",
    challengeFile,
    forgeObservation,
  })}\n`);
  const output: string[] = [];
  await executeAttestationCommand(
    "attestation-verify-repository",
    { bundle: bundlePath, json: true },
    (line) => output.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.equal(output.join("\n"), JSON.stringify({
    appended: repositoryEventId,
    type: "repository_control_verified",
  }, null, 2));
  const persisted = await readFile(paths.attestations, "utf8");
  assert.equal(JSON.parse(persisted).type, "repository_control_verified");

  const approver = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  await writeFile(paths.organizations, `${JSON.stringify({
    schemaVersion: 1,
    organizations: { "example-org": [approver.address.toLowerCase()] },
  })}\n`);
  await writeFile(paths.admins, `${JSON.stringify({
    schemaVersion: 1,
    admins: { "admin-1": admin.address.toLowerCase() },
  })}\n`);

  const unsignedApproval = {
    schemaVersion: 1 as const,
    subject: challenge.subject,
    organizationId: "example-org",
    approverWallet: approver.address.toLowerCase() as `0x${string}`,
    role: "ip_admin" as const,
    approvedAt: "2026-07-18T02:30:00.000Z",
  };
  const approval = {
    ...unsignedApproval,
    statementHash: organizationStatementHash(unsignedApproval),
    signature: await approver.signMessage({ message: canonicalOrganizationStatement(unsignedApproval) }),
  };
  const organizationEventId = "organization-cli-\u001b\u0085\u202e1";
  const organizationEvent: OrganizationApprovedEvent = {
    type: "organization_approved",
    eventId: organizationEventId,
    sequence: 2,
    occurredAt: "2026-07-18T03:00:00.000Z",
    subject: challenge.subject,
    approval,
  };
  const organizationBundle = join(root, "organization-bundle.json");
  await writeFile(organizationBundle, `${JSON.stringify(organizationEvent)}\n`);
  const organizationOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-verify-organization",
    { bundle: organizationBundle },
    (line) => organizationOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.deepEqual(organizationOutput, [
    'appended: "organization-cli-\\u001b\\u0085\\u202e1"; type: "organization_approved"',
  ]);

  const conflictId = "conflict-cli-\u001b\u0085\u202e1";
  const challengeEventId = "challenge-cli-\n\u009b\u20671";
  const challengerRegistrationId = `eip155:1315:${challengerIpId}` as const;
  const challengeBase = {
    type: "challenge_opened" as const,
    eventId: challengeEventId,
    sequence: 3,
    occurredAt: "2026-07-18T03:15:00.000Z",
    conflictId,
    challengedRegistrationId: challenge.subject.registrationId,
    challengerRegistrationId,
    challengerWallet: challenge.subject.wallet,
    evidenceUris: ["https://example.invalid/evidence"],
    reason: "misattributed_creator" as const,
    statementHash: artifactHash,
    signature: "0x00" as `0x${string}`,
  };
  const challengeHash = challengeEventStatementHash(challengeBase);
  const challengeEvent: ChallengeOpenedEvent = {
    ...challengeBase,
    statementHash: challengeHash,
    signature: await wallet.signMessage({
      message: canonicalChallengeEventStatement({ ...challengeBase, statementHash: challengeHash }),
    }),
  };
  const challengeBundle = join(root, "challenge-bundle.json");
  await writeFile(challengeBundle, `${JSON.stringify(challengeEvent)}\n`);
  const challengeOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-append-challenge",
    { bundle: challengeBundle },
    (line) => challengeOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.deepEqual(challengeOutput, [
    'appended: "challenge-cli-\\u000a\\u009b\\u20671"; type: "challenge_opened"',
  ]);

  const resolutionEventId = "resolution-cli-\r\u007f\u200f1";
  const resolutionBase = {
    type: "challenge_resolved" as const,
    eventId: resolutionEventId,
    sequence: 4,
    occurredAt: "2026-07-18T03:30:00.000Z",
    conflictId,
    outcome: "inconclusive" as const,
    rationale: "The signed evidence remains incomplete.",
    adminSignerId: "admin-1",
    statementHash: artifactHash,
    signature: "0x00" as `0x${string}`,
  };
  const resolutionHash = adminEventStatementHash(resolutionBase);
  const resolutionEvent: ChallengeResolvedEvent = {
    ...resolutionBase,
    statementHash: resolutionHash,
    signature: await admin.signMessage({
      message: canonicalAdminEventStatement({ ...resolutionBase, statementHash: resolutionHash }),
    }),
  };
  const resolutionBundle = join(root, "resolution-bundle.json");
  await writeFile(resolutionBundle, `${JSON.stringify(resolutionEvent)}\n`);
  const resolutionOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-resolve",
    { bundle: resolutionBundle },
    (line) => resolutionOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.deepEqual(resolutionOutput, [
    'appended: "resolution-cli-\\u000d\\u007f\\u200f1"; type: "challenge_resolved"',
  ]);

  const revocationEventId = "revocation-cli-\u0000\u009f\u061c1";
  const revocationBase = {
    type: "attestation_revoked" as const,
    eventId: revocationEventId,
    sequence: 5,
    occurredAt: "2026-07-18T03:45:00.000Z",
    registrationId: challenge.subject.registrationId,
    level: "organization_approved" as const,
    reason: "Organization evidence is no longer active.",
    adminSignerId: "admin-1",
    statementHash: artifactHash,
    signature: "0x00" as `0x${string}`,
  };
  const revocationHash = adminEventStatementHash(revocationBase);
  const revocationEvent: AttestationRevokedEvent = {
    ...revocationBase,
    statementHash: revocationHash,
    signature: await admin.signMessage({
      message: canonicalAdminEventStatement({ ...revocationBase, statementHash: revocationHash }),
    }),
  };
  const revocationBundle = join(root, "revocation-bundle.json");
  await writeFile(revocationBundle, `${JSON.stringify(revocationEvent)}\n`);
  const revocationOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-revoke",
    { bundle: revocationBundle },
    (line) => revocationOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.deepEqual(revocationOutput, [
    'appended: "revocation-cli-\\u0000\\u009f\\u061c1"; type: "attestation_revoked"',
  ]);

  const conflictsOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-conflicts",
    {},
    (line) => conflictsOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  assert.ok(conflictsOutput.includes('conflict: "conflict-cli-\\u001b\\u0085\\u202e1"'));
  assert.ok(conflictsOutput.includes('conflict events: "challenge-cli-\\u000a\\u009b\\u20671", "resolution-cli-\\u000d\\u007f\\u200f1"'));
  assert.ok(conflictsOutput.every((line) => !/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(line)));

  const conflictJsonOutput: string[] = [];
  await executeAttestationCommand(
    "attestation-conflicts",
    { json: true },
    (line) => conflictJsonOutput.push(line),
    { phase0Root: root, paths, env: {}, now: () => NOW },
  );
  const conflictJson = JSON.parse(conflictJsonOutput.join("\n"));
  assert.equal(conflictJson.conflicts[0].conflictId, conflictId);
  assert.deepEqual(conflictJson.conflicts[0].eventIds, [challengeEventId, resolutionEventId]);
});

for (const option of ["--repository-path", "--trusted-ref"] as const) {
  test(`production CLI rejects claimant option ${option} as unknown`, () => {
    const result = spawnSync(process.execPath, ["--import", "tsx", "src/index.ts", "attestation-status", option, "/tmp/claimant"], {
      cwd: new URL("..", import.meta.url),
      encoding: "utf8",
      env: { ...process.env, HTTP_PROXY: "", HTTPS_PROXY: "", ALL_PROXY: "" },
    });
    assert.notEqual(result.status, 0);
    assert.match(`${result.stdout}\n${result.stderr}`, /Unknown option/);
  });
}

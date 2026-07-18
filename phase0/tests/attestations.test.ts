import assert from "node:assert/strict";
import test from "node:test";

import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";

import {
  adminEventStatementHash,
  canonicalAdminEventStatement,
  canonicalChallengeEventStatement,
  canonicalOrganizationStatement,
  canonicalRepositoryStatement,
  challengeEventStatementHash,
  deterministicConflictId,
  displayAttestation,
  organizationStatementHash,
  parseAttestationEvent,
  parseForgeObservation,
  parseRepositoryChallenge,
  registrationSubjectsFromManifest,
  reduceAttestationEvents,
  repositoryStatementHash,
  verifyAdminEventSignature,
  verifyOrganizationApproval,
  type AttestationRevokedEvent,
  type ChallengeOpenedEvent,
  type ChallengeResolvedEvent,
  type OrganizationApprovedEvent,
  type RegistrationSubject,
  type RepositoryControlChallengeV1,
  type RepositoryControlEvent,
} from "../src/attestations";
import { renderAttestationStatus } from "../src/attestation-cli";
import { createEmptyRegistrationManifest } from "../src/registrations";

const HASH_A = `0x${"1".repeat(64)}` as const;
const HASH_B = `0x${"2".repeat(64)}` as const;
const IP_A = `0x${"a".repeat(40)}` as const;
const IP_B = `0x${"b".repeat(40)}` as const;
const NOW = "2026-07-18T12:00:00.000Z";

function subject(ipId: `0x${string}`, wallet: `0x${string}`, artifactHash = HASH_A): RegistrationSubject {
  return {
    registrationId: `eip155:1315:${ipId}`,
    ipId,
    wallet: wallet.toLowerCase() as `0x${string}`,
    artifactHash,
    declaredParentIpIds: [],
  };
}

function challengeFor(value: RegistrationSubject): RepositoryControlChallengeV1 {
  return {
    schemaVersion: 1,
    subject: value,
    repositoryUrl: "https://github.com/example/skill",
    artifactCommitSha: "1".repeat(40),
    artifactPath: "skills/demo/SKILL.md",
    challengePath: "attestations/demo.json",
    nonce: `0x${"3".repeat(64)}`,
    issuedAt: "2026-07-18T10:00:00.000Z",
    expiresAt: "2026-07-18T14:00:00.000Z",
  };
}

async function repositoryEvent(value: RegistrationSubject, account: ReturnType<typeof privateKeyToAccount>): Promise<RepositoryControlEvent> {
  const challenge = challengeFor(value);
  return {
    type: "repository_control_verified",
    eventId: "repo-1",
    sequence: 1,
    occurredAt: NOW,
    subject: value,
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
      signature: "test-signature",
    },
    statementHash: repositoryStatementHash(challenge),
    signature: await account.signMessage({ message: canonicalRepositoryStatement(challenge) }),
  };
}

test("canonical repository statement has fixed order and exactly one trailing newline", () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const statement = canonicalRepositoryStatement(challengeFor(subject(IP_A, account.address)));
  assert.equal(statement.split("\n")[0], "skill-asset-protocol/repository-control/v2");
  assert.match(statement, /\n\{"schemaVersion":2,"registrationId":"eip155:1315:/);
  assert.ok(statement.endsWith("\n"));
  assert.ok(!statement.endsWith("\n\n"));
});

test("wallet assertion is seeded only by base subjects", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const state = await reduceAttestationEvents([], { baseSubjects: [base] });
  assert.equal(state.registrations[base.registrationId].level, "wallet_asserted");
  assert.equal(state.registrations[base.registrationId].claim, "wallet registered these bytes and declared this ancestry");
  assert.equal(state.registrations[base.registrationId].safetyReviewStatus, "not_reviewed");
  assert.throws(() => parseAttestationEvent({ type: "wallet_asserted" }), /cannot be a sidecar/);
  assert.throws(
    () => parseAttestationEvent({ type: "attestation_revoked", level: "wallet_asserted" }),
    /unexpected or missing|cannot be revoked/,
  );
});

test("not-run manifests produce no base assertion and status JSON stays empty", async () => {
  assert.deepEqual(registrationSubjectsFromManifest(createEmptyRegistrationManifest()), []);
  const index = await reduceAttestationEvents([], { baseSubjects: [] });
  assert.deepEqual(JSON.parse(renderAttestationStatus(index, {
    artifactHash: `0x${"0".repeat(64)}`,
    json: true,
  })[0]), { registrations: [], conflicts: [] });
});

test("wallet-signed repository evidence requires the injected repository verifier", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const event = await repositoryEvent(base, account);
  await assert.rejects(reduceAttestationEvents([event], { baseSubjects: [base] }), /repository verifier context required/);
  const state = await reduceAttestationEvents([event], { baseSubjects: [base], repositoryVerifier: async () => undefined });
  assert.equal(state.registrations[base.registrationId].level, "repository_control_verified");
  assert.match(displayAttestation(state, base.registrationId).warnings.join("\n"), /does not prove current remote account ownership/);
});

test("tampered repository subject, statement, and signature fail closed", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const other = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const event = await repositoryEvent(base, account);
  const trust = { baseSubjects: [base], repositoryVerifier: async () => undefined };
  await assert.rejects(reduceAttestationEvents([{ ...event, statementHash: HASH_B }], trust), /statement hash mismatch/);
  await assert.rejects(reduceAttestationEvents([{ ...event, signature: await other.signMessage({ message: canonicalRepositoryStatement(event.challenge) }) }], trust), /does not recover/);
  await assert.rejects(reduceAttestationEvents([{ ...event, subject: { ...base, artifactHash: HASH_B } }], trust), /subject drift/);
});

test("organization approval requires repository evidence and an allow-listed signer", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repo = await repositoryEvent(base, account);
  const unsigned = {
    schemaVersion: 1 as const,
    subject: base,
    organizationId: "example-org",
    approverWallet: approver.address.toLowerCase() as `0x${string}`,
    role: "ip_admin" as const,
    approvedAt: NOW,
  };
  const approval = {
    ...unsigned,
    statementHash: organizationStatementHash(unsigned),
    signature: await approver.signMessage({ message: canonicalOrganizationStatement(unsigned) }),
  };
  const event: OrganizationApprovedEvent = {
    type: "organization_approved",
    eventId: "org-1",
    sequence: 2,
    occurredAt: NOW,
    subject: base,
    approval,
  };
  await assert.rejects(reduceAttestationEvents([{ ...event, sequence: 1 }], {
    baseSubjects: [base], organizationSigners: { "example-org": [unsigned.approverWallet] },
  }), /requires active repository evidence/);
  await assert.rejects(reduceAttestationEvents([repo, event], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
  }), /not allow-listed/);
  const state = await reduceAttestationEvents([repo, event], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
    organizationSigners: { "example-org": [unsigned.approverWallet] },
  });
  assert.equal(state.registrations[base.registrationId].level, "organization_approved");
});

test("organization approval rejects inherited signer entries and exotic trust-map prototypes", async () => {
  const creator = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const unsigned = {
    schemaVersion: 1 as const,
    subject: subject(IP_A, creator.address),
    organizationId: "example-org",
    approverWallet: approver.address.toLowerCase() as `0x${string}`,
    role: "ip_admin" as const,
    approvedAt: NOW,
  };
  const approval = {
    ...unsigned,
    statementHash: organizationStatementHash(unsigned),
    signature: await approver.signMessage({ message: canonicalOrganizationStatement(unsigned) }),
  };
  const trustedWallets = [unsigned.approverWallet] as const;

  Object.defineProperty(Object.prototype, "example-org", {
    configurable: true,
    enumerable: false,
    value: trustedWallets,
  });
  try {
    await assert.rejects(
      verifyOrganizationApproval(approval, {}),
      /own property/,
    );
  } finally {
    delete (Object.prototype as Record<string, unknown>)["example-org"];
  }

  const inherited = Object.create({ "example-org": trustedWallets }) as Record<string, readonly `0x${string}`[]>;
  await assert.rejects(
    verifyOrganizationApproval(approval, inherited),
    /plain or null-prototype record/,
  );

  const exotic = Object.assign(Object.create({ unrelated: true }), { "example-org": trustedWallets }) as Record<string, readonly `0x${string}`[]>;
  await assert.rejects(
    verifyOrganizationApproval(approval, exotic),
    /plain or null-prototype record/,
  );
});

test("organization approval rejects malformed own signer allow-lists before accepting a valid signature", async () => {
  const creator = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, creator.address);
  const repo = await repositoryEvent(base, creator);
  const unsigned = {
    schemaVersion: 1 as const,
    subject: base,
    organizationId: "example-org",
    approverWallet: approver.address.toLowerCase() as `0x${string}`,
    role: "ip_admin" as const,
    approvedAt: NOW,
  };
  const approval = {
    ...unsigned,
    statementHash: organizationStatementHash(unsigned),
    signature: await approver.signMessage({ message: canonicalOrganizationStatement(unsigned) }),
  };
  const event: OrganizationApprovedEvent = {
    type: "organization_approved",
    eventId: "organization-malformed-root",
    sequence: 2,
    occurredAt: NOW,
    subject: base,
    approval,
  };

  const inheritedPrototype = Object.create(Array.prototype) as Record<string, unknown>;
  inheritedPrototype[0] = unsigned.approverWallet;
  const inheritedEntry = [] as unknown[];
  inheritedEntry.length = 1;
  Object.setPrototypeOf(inheritedEntry, inheritedPrototype);
  const extraProperty = [unsigned.approverWallet] as unknown[] & { injected?: string };
  extraProperty.injected = unsigned.approverWallet;
  const malformedAllowLists: readonly [string, unknown][] = [
    ["string with a matching substring", unsigned.approverWallet],
    ["array-like object with includes", { 0: unsigned.approverWallet, length: 1, includes: () => true }],
    ["array with an inherited matching entry", inheritedEntry],
    ["array with a malformed address", [unsigned.approverWallet.toUpperCase()]],
    ["array with a non-string entry", [42]],
    ["array with a duplicate canonical address", [unsigned.approverWallet, unsigned.approverWallet]],
    ["array with an extra schema property", extraProperty],
  ];

  for (const [name, malformed] of malformedAllowLists) {
    const trust = { "example-org": malformed } as unknown as Record<string, readonly `0x${string}`[]>;
    await assert.rejects(
      verifyOrganizationApproval(approval, trust),
      /organization signer allow-list.*(?:array|canonical lowercase address|unique|own indexed entries|schema properties)/i,
      name,
    );
  }

  const malformedReducerTrust = {
    "example-org": unsigned.approverWallet,
  } as unknown as Record<string, readonly `0x${string}`[]>;
  await assert.rejects(
    reduceAttestationEvents([repo, event], {
      baseSubjects: [base],
      repositoryVerifier: async () => undefined,
      organizationSigners: malformedReducerTrust,
    }),
    /organization signer allow-list.*array/i,
  );
});

test("duplicate bytes under different wallets create a deterministic visible conflict", async () => {
  const first = privateKeyToAccount(generatePrivateKey());
  const second = privateKeyToAccount(generatePrivateKey());
  const a = subject(IP_A, first.address);
  const b = subject(IP_B, second.address);
  const forward = await reduceAttestationEvents([], { baseSubjects: [a, b] });
  const reverse = await reduceAttestationEvents([], { baseSubjects: [b, a] });
  assert.equal(forward.conflicts.length, 1);
  assert.equal(forward.conflicts[0].conflictId, deterministicConflictId(a, b));
  assert.deepEqual(forward.conflicts, reverse.conflicts);
  assert.equal(forward.registrations[a.registrationId].status, "challenged");
  assert.equal(forward.registrations[b.registrationId].status, "challenged");
});

test("signed challenges, resolutions, and revocations preserve history", async () => {
  const first = privateKeyToAccount(generatePrivateKey());
  const second = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  const a = subject(IP_A, first.address);
  const b = subject(IP_B, second.address);
  const repo = await repositoryEvent(a, first);
  const conflictId = deterministicConflictId(a, b);
  const challengeBase = {
    type: "challenge_opened" as const,
    eventId: "challenge-1",
    sequence: 2,
    occurredAt: NOW,
    conflictId,
    challengedRegistrationId: a.registrationId,
    challengerRegistrationId: b.registrationId,
    challengerWallet: b.wallet,
    evidenceUris: ["https://example.com/evidence"],
    reason: "duplicate_bytes" as const,
    statementHash: HASH_A,
    signature: "0x00" as `0x${string}`,
  };
  const challenge: ChallengeOpenedEvent = {
    ...challengeBase,
    statementHash: challengeEventStatementHash(challengeBase),
    signature: await second.signMessage({ message: canonicalChallengeEventStatement({ ...challengeBase, statementHash: challengeEventStatementHash(challengeBase) }) }),
  };
  const resolutionBase = {
    type: "challenge_resolved" as const,
    eventId: "resolution-1",
    sequence: 3,
    occurredAt: NOW,
    conflictId,
    outcome: "inconclusive" as const,
    rationale: "Evidence remains incomplete.",
    adminSignerId: "admin-1",
    statementHash: HASH_A,
    signature: "0x00" as `0x${string}`,
  };
  const resolution: ChallengeResolvedEvent = {
    ...resolutionBase,
    statementHash: adminEventStatementHash(resolutionBase),
    signature: await admin.signMessage({ message: canonicalAdminEventStatement({ ...resolutionBase, statementHash: adminEventStatementHash(resolutionBase) }) }),
  };
  const revocationBase = {
    type: "attestation_revoked" as const,
    eventId: "revoke-1",
    sequence: 4,
    occurredAt: NOW,
    registrationId: a.registrationId,
    level: "repository_control_verified" as const,
    reason: "Snapshot trust was withdrawn.",
    adminSignerId: "admin-1",
    statementHash: HASH_A,
    signature: "0x00" as `0x${string}`,
  };
  const revoked: AttestationRevokedEvent = {
    ...revocationBase,
    statementHash: adminEventStatementHash(revocationBase),
    signature: await admin.signMessage({ message: canonicalAdminEventStatement({ ...revocationBase, statementHash: adminEventStatementHash(revocationBase) }) }),
  };
  const state = await reduceAttestationEvents([repo, challenge, resolution, revoked], {
    baseSubjects: [a, b], repositoryVerifier: async () => undefined,
    adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` },
  });
  assert.equal(state.registrations[a.registrationId].level, "wallet_asserted");
  assert.equal(state.registrations[a.registrationId].status, "active");
  assert.equal(state.registrations[a.registrationId].revocations[0].level, "repository_control_verified");
  assert.equal(state.conflicts[0].outcome, "inconclusive");
  assert.equal(state.events.length, 4);
});

test("admin events reject inherited signer entries and exotic trust-map prototypes", async () => {
  const admin = privateKeyToAccount(generatePrivateKey());
  const eventBase = {
    type: "challenge_resolved" as const,
    eventId: "resolution-trust-map",
    sequence: 1,
    occurredAt: NOW,
    conflictId: "conflict-trust-map",
    outcome: "rejected" as const,
    rationale: "The signed resolution is valid; only verifier trust is under test.",
    adminSignerId: "admin-1",
    statementHash: HASH_A,
    signature: "0x00" as `0x${string}`,
  };
  const statementHash = adminEventStatementHash(eventBase);
  const event: ChallengeResolvedEvent = {
    ...eventBase,
    statementHash,
    signature: await admin.signMessage({
      message: canonicalAdminEventStatement({ ...eventBase, statementHash }),
    }),
  };
  const trustedWallet = admin.address.toLowerCase() as `0x${string}`;

  Object.defineProperty(Object.prototype, "admin-1", {
    configurable: true,
    enumerable: false,
    value: trustedWallet,
  });
  try {
    await assert.rejects(
      verifyAdminEventSignature(event, {}),
      /own property/,
    );
  } finally {
    delete (Object.prototype as Record<string, unknown>)["admin-1"];
  }

  const inherited = Object.create({ "admin-1": trustedWallet }) as Record<string, `0x${string}`>;
  await assert.rejects(
    verifyAdminEventSignature(event, inherited),
    /plain or null-prototype record/,
  );

  const exotic = Object.assign(Object.create({ unrelated: true }), { "admin-1": trustedWallet }) as Record<string, `0x${string}`>;
  await assert.rejects(
    verifyAdminEventSignature(event, exotic),
    /plain or null-prototype record/,
  );
});

test("sequence gaps, duplicate IDs, malformed normalized inputs, and overclaim text fail", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repo = await repositoryEvent(base, account);
  await assert.rejects(reduceAttestationEvents([{ ...repo, sequence: 2 }], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
  }), /contiguous/);
  await assert.rejects(reduceAttestationEvents([repo, { ...repo, sequence: 2 }], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
  }), /duplicate attestation event ID/);
  assert.throws(() => canonicalRepositoryStatement({ ...repo.challenge, repositoryUrl: "https://github.com/example/skill/" }), /normalized HTTPS/);
  const state = await reduceAttestationEvents([], { baseSubjects: [base] });
  const rendered = JSON.stringify(displayAttestation(state, base.registrationId)).toLowerCase();
  assert.doesNotMatch(rendered, /authored by|safe skill|proves originality|proves safety/);
});

test("repository attestations accept only exact 40- or 64-character lowercase commit OIDs", () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const challenge = challengeFor(subject(IP_A, account.address));
  const observation = {
    schemaVersion: 1 as const,
    repositoryId: "demo",
    repositoryUrl: challenge.repositoryUrl,
    trustedRef: "refs/heads/main" as const,
    proofCommitSha: "2".repeat(40),
    challengeNonce: challenge.nonce,
    observedAt: "2026-07-18T11:00:00.000Z",
    forgeSignerId: "forge-1",
    signature: "test-signature",
  };

  for (const length of [41, 63]) {
    assert.throws(
      () => parseRepositoryChallenge({ ...challenge, artifactCommitSha: "a".repeat(length) }),
      /lowercase full commit SHA/,
    );
    assert.throws(
      () => parseForgeObservation({ ...observation, proofCommitSha: "b".repeat(length) }),
      /lowercase full commit SHA/,
    );
  }
  assert.equal(parseRepositoryChallenge({ ...challenge, artifactCommitSha: "a".repeat(64) }).artifactCommitSha.length, 64);
  assert.equal(parseForgeObservation({ ...observation, proofCommitSha: "b".repeat(64) }).proofCommitSha.length, 64);
});

test("human status output uses explicit evidence-level language", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const index = await reduceAttestationEvents([], { baseSubjects: [base] });
  const output = renderAttestationStatus(index, { registrationId: base.registrationId }).join("\n");
  assert.match(output, /attestation: wallet_asserted/);
  assert.match(output, /claim: wallet registered these bytes and declared this ancestry/);
  assert.match(output, /safety review: not_reviewed/);
  assert.match(output, /warning: registration does not prove authorship, originality, legal ownership, or safety/);
});

test("valid signed challenge identifiers cannot forge human status lines or terminal controls", async () => {
  const challenged = privateKeyToAccount(generatePrivateKey());
  const challenger = privateKeyToAccount(generatePrivateKey());
  const a = subject(IP_A, challenged.address, HASH_A);
  const b = subject(IP_B, challenger.address, HASH_B);
  const conflictId = "conflict\"\\\rstatus: forged\u0000\u001b\u007f\u0085\u009f\u061c\u200e\u200f\u2028\u2029\u202a\u202e\u2066\u2069";
  const eventId = "event\"\\\nwarning: forged\u0001\u001b\u0080\u009b\u2028\u2029\u202d\u2067";
  const unsigned = {
    type: "challenge_opened" as const,
    eventId,
    sequence: 1,
    occurredAt: NOW,
    conflictId,
    challengedRegistrationId: a.registrationId,
    challengerRegistrationId: b.registrationId,
    challengerWallet: b.wallet,
    evidenceUris: ["https://example.com/signed-evidence"],
    reason: "misattributed_creator" as const,
    statementHash: HASH_A,
    signature: "0x00" as `0x${string}`,
  };
  const statementHash = challengeEventStatementHash(unsigned);
  const event: ChallengeOpenedEvent = {
    ...unsigned,
    statementHash,
    signature: await challenger.signMessage({
      message: canonicalChallengeEventStatement({ ...unsigned, statementHash }),
    }),
  };
  const index = await reduceAttestationEvents([event], { baseSubjects: [a, b] });

  const lines = renderAttestationStatus(index, { registrationId: a.registrationId });
  const renderedConflict = lines.find((line) => line.startsWith("conflict: "));
  const renderedEvents = lines.find((line) => line.startsWith("conflict events: "));
  assert.ok(renderedConflict?.startsWith('conflict: "'));
  assert.ok(renderedConflict?.endsWith('"'));
  assert.ok(renderedEvents?.startsWith('conflict events: "'));
  for (const escaped of ["\\\"", "\\\\", "\\u0000", "\\u001b", "\\u007f", "\\u0085", "\\u009f", "\\u061c", "\\u200e", "\\u200f", "\\u2028", "\\u2029", "\\u202a", "\\u202e", "\\u2066", "\\u2069"]) {
    assert.match(renderedConflict ?? "", new RegExp(escaped.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&")));
  }
  assert.ok(lines.every((line) => !/[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/u.test(line)));
  assert.equal(lines.filter((line) => line.startsWith("status: forged") || line.startsWith("warning: forged")).length, 0);

  const json = JSON.parse(renderAttestationStatus(index, { registrationId: a.registrationId, json: true })[0]);
  assert.equal(json.conflicts[0].conflictId, conflictId);
  assert.deepEqual(json.conflicts[0].eventIds, [eventId]);
});

test("human status output lists challenged registrations and every matching conflict deterministically", async () => {
  const first = privateKeyToAccount(generatePrivateKey());
  const second = privateKeyToAccount(generatePrivateKey());
  const a = subject(IP_A, first.address);
  const b = subject(IP_B, second.address);
  const forward = await reduceAttestationEvents([], { baseSubjects: [a, b] });
  const reverse = await reduceAttestationEvents([], { baseSubjects: [b, a] });
  const conflictId = deterministicConflictId(a, b);
  const lines = renderAttestationStatus(forward, { artifactHash: a.artifactHash });
  const reverseLines = renderAttestationStatus(reverse, { artifactHash: a.artifactHash });

  assert.deepEqual(lines, reverseLines);
  assert.deepEqual(
    lines.filter((line) => line.startsWith("registration: ")),
    [a.registrationId, b.registrationId].sort().map((id) => `registration: "${id}"`),
  );
  assert.equal(lines.filter((line) => line === "status: challenged").length, 2);
  assert.deepEqual(lines.slice(-8), [
    "conflicts: 1",
    `conflict: "${conflictId}"`,
    `conflict artifact hash: "${a.artifactHash}"`,
    "conflict status: open",
    "conflict reason: duplicate_bytes",
    "conflict outcome: (none)",
    `conflict registrations: ${[a.registrationId, b.registrationId].sort().map((id) => `"${id}"`).join(", ")}`,
    "conflict events: (none)",
  ]);

  const unsortedArrayIndex = {
    ...forward,
    conflicts: forward.conflicts.map((conflict) => ({
      ...conflict,
      registrationIds: [...conflict.registrationIds].reverse(),
      eventIds: ["event-z", "event-a"],
    })),
  };
  const unsortedArrayLines = renderAttestationStatus(unsortedArrayIndex, { artifactHash: a.artifactHash });
  assert.ok(unsortedArrayLines.includes(
    `conflict registrations: ${[a.registrationId, b.registrationId].sort().map((id) => `"${id}"`).join(", ")}`,
  ));
  assert.ok(unsortedArrayLines.includes('conflict events: "event-a", "event-z"'));

  const json = JSON.parse(renderAttestationStatus(forward, { artifactHash: a.artifactHash, json: true })[0]);
  assert.equal(json.registrations.length, 2);
  assert.ok(json.registrations.every((registration: { status: string }) => registration.status === "challenged"));
  assert.deepEqual(json.conflicts, forward.conflicts);
});

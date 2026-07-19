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
  organizationStatementHash,
  reduceAttestationEvents,
  repositoryStatementHash,
  type AttestationRevokedEvent,
  type ChallengeOpenedEvent,
  type ChallengeResolvedEvent,
  type OrganizationApprovedEvent,
  type RegistrationSubject,
  type RepositoryControlEvent,
} from "../src/attestations";

const IP_A = `0x${"a".repeat(40)}` as const;
const IP_B = `0x${"b".repeat(40)}` as const;
const HASH = `0x${"1".repeat(64)}` as const;
const T0 = "2026-07-18T00:00:00.000Z";
const T1 = "2026-07-18T01:00:00.000Z";
const T2 = "2026-07-18T02:00:00.000Z";
const T3 = "2026-07-18T03:00:00.000Z";
const T4 = "2026-07-18T04:00:00.000Z";

function subject(ipId: `0x${string}`, wallet: `0x${string}`): RegistrationSubject {
  return {
    registrationId: `eip155:1315:${ipId}`,
    ipId,
    wallet: wallet.toLowerCase() as `0x${string}`,
    artifactHash: HASH,
    declaredParentIpIds: [],
  };
}

async function repositoryEvent(input: {
  subject: RegistrationSubject;
  account: ReturnType<typeof privateKeyToAccount>;
  eventId: string;
  sequence: number;
  nonceDigit: string;
  occurredAt?: string;
  issuedAt?: string;
  observedAt?: string;
  expiresAt?: string;
}): Promise<RepositoryControlEvent> {
  const challenge = {
    schemaVersion: 1 as const,
    subject: input.subject,
    repositoryUrl: "https://github.com/example/adversarial",
    artifactCommitSha: "1".repeat(40),
    artifactPath: "skills/demo/SKILL.md",
    challengePath: `attestations/${input.nonceDigit}.json`,
    nonce: `0x${input.nonceDigit.repeat(64)}` as `0x${string}`,
    issuedAt: input.issuedAt ?? T0,
    expiresAt: input.expiresAt ?? T4,
  };
  return {
    type: "repository_control_verified",
    eventId: input.eventId,
    sequence: input.sequence,
    occurredAt: input.occurredAt ?? T1,
    subject: input.subject,
    challenge,
    forgeObservation: {
      schemaVersion: 1,
      repositoryId: "demo",
      repositoryUrl: challenge.repositoryUrl,
      trustedRef: "refs/heads/main",
      proofCommitSha: input.nonceDigit.repeat(40),
      challengeNonce: challenge.nonce,
      observedAt: input.observedAt ?? T1,
      forgeSignerId: "forge-1",
      signature: `forge-${input.nonceDigit}`,
    },
    statementHash: repositoryStatementHash(challenge),
    signature: await input.account.signMessage({ message: canonicalRepositoryStatement(challenge) }),
  };
}

async function revocation(input: {
  admin: ReturnType<typeof privateKeyToAccount>;
  registrationId: string;
  eventId: string;
  sequence: number;
  occurredAt: string;
}): Promise<AttestationRevokedEvent> {
  const base = {
    type: "attestation_revoked" as const,
    eventId: input.eventId,
    sequence: input.sequence,
    occurredAt: input.occurredAt,
    registrationId: input.registrationId,
    level: "repository_control_verified" as const,
    reason: "Verifier snapshot trust withdrawn.",
    adminSignerId: "admin-1",
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  const statementHash = adminEventStatementHash(base);
  return {
    ...base,
    statementHash,
    signature: await input.admin.signMessage({ message: canonicalAdminEventStatement({ ...base, statementHash }) }),
  };
}

async function organizationEvent(input: {
  subject: RegistrationSubject;
  approver: ReturnType<typeof privateKeyToAccount>;
  eventId: string;
  sequence: number;
  approvedAt: string;
  occurredAt: string;
}): Promise<OrganizationApprovedEvent> {
  const unsigned = {
    schemaVersion: 1 as const,
    subject: input.subject,
    organizationId: "example-org",
    approverWallet: input.approver.address.toLowerCase() as `0x${string}`,
    role: "ip_admin" as const,
    approvedAt: input.approvedAt,
  };
  const approval = {
    ...unsigned,
    statementHash: organizationStatementHash(unsigned),
    signature: await input.approver.signMessage({ message: canonicalOrganizationStatement(unsigned) }),
  };
  return {
    type: "organization_approved",
    eventId: input.eventId,
    sequence: input.sequence,
    occurredAt: input.occurredAt,
    subject: input.subject,
    approval,
  };
}

test("all signed semantic encodings are injective across adversarial delimiter redistribution", () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repositoryBase = {
    schemaVersion: 1 as const,
    subject: base,
    repositoryUrl: "https://github.com/example/adversarial",
    artifactCommitSha: "1".repeat(40),
    nonce: `0x${"2".repeat(64)}` as `0x${string}`,
    issuedAt: T0,
    expiresAt: T4,
  };
  const repositoryA = {
    ...repositoryBase,
    artifactPath: "a\nchallengePath=b",
    challengePath: "c",
  };
  const repositoryB = {
    ...repositoryBase,
    artifactPath: "a",
    challengePath: "b\nchallengePath=c",
  };
  assert.notEqual(canonicalRepositoryStatement(repositoryA), canonicalRepositoryStatement(repositoryB));

  const challengeBase = {
    type: "challenge_opened" as const,
    eventId: "challenge-1",
    sequence: 1,
    occurredAt: T1,
    conflictId: "conflict-1",
    challengedRegistrationId: base.registrationId,
    challengerRegistrationId: `eip155:1315:${IP_B}`,
    challengerWallet: `0x${"b".repeat(40)}` as `0x${string}`,
    reason: "duplicate_bytes" as const,
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  assert.notEqual(
    canonicalChallengeEventStatement({ ...challengeBase, evidenceUris: ["https://example.test/a,b", "https://example.test/c"] }),
    canonicalChallengeEventStatement({ ...challengeBase, evidenceUris: ["https://example.test/a", "https://example.test/b,c"] }),
  );

  const resolutionBase = {
    type: "challenge_resolved" as const,
    eventId: "resolution-1",
    sequence: 1,
    occurredAt: T1,
    adminSignerId: "admin-1",
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  const resolutionA: ChallengeResolvedEvent = {
    ...resolutionBase,
    conflictId: "x\noutcome=rejected\nrationale=y",
    outcome: "upheld",
    rationale: "z",
  };
  const resolutionB: ChallengeResolvedEvent = {
    ...resolutionBase,
    conflictId: "x",
    outcome: "rejected",
    rationale: "y\noutcome=upheld\nrationale=z",
  };
  assert.notEqual(canonicalAdminEventStatement(resolutionA), canonicalAdminEventStatement(resolutionB));

  const revocationBase = {
    type: "attestation_revoked" as const,
    sequence: 1,
    occurredAt: T1,
    registrationId: base.registrationId,
    level: "repository_control_verified" as const,
    adminSignerId: "admin-1",
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  const injectedPrefix = `x\nsequence=1\noccurredAt=${T1}\nregistrationId=${base.registrationId}\nlevel=repository_control_verified\nreason=y`;
  const revocationA: AttestationRevokedEvent = { ...revocationBase, eventId: injectedPrefix, reason: "z" };
  const revocationB: AttestationRevokedEvent = {
    ...revocationBase,
    eventId: "x",
    reason: `y\nsequence=1\noccurredAt=${T1}\nregistrationId=${base.registrationId}\nlevel=repository_control_verified\nreason=z`,
  };
  assert.notEqual(canonicalAdminEventStatement(revocationA), canonicalAdminEventStatement(revocationB));
});

test("stable repository and organization credentials cannot be replayed in fresh envelopes", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repo = await repositoryEvent({ subject: base, account, eventId: "repo-1", sequence: 1, nonceDigit: "2" });
  await assert.rejects(reduceAttestationEvents([repo, { ...repo, eventId: "repo-2", sequence: 2, occurredAt: T2 }], {
    baseSubjects: [base], repositoryVerifier: async () => undefined, now: new Date(T4),
  }), /repository (credential|statement|nonce|observation).*already consumed/i);

  const org = await organizationEvent({ subject: base, approver, eventId: "org-1", sequence: 2, approvedAt: T2, occurredAt: T2 });
  await assert.rejects(reduceAttestationEvents([repo, org, { ...org, eventId: "org-2", sequence: 3, occurredAt: T3 }], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
    organizationSigners: { "example-org": [org.approval.approverWallet] }, now: new Date(T4),
  }), /organization (credential|approval).*already consumed/i);
});

test("revocation permanently consumes old evidence while genuinely fresh credentials may reactivate", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repo = await repositoryEvent({ subject: base, account, eventId: "repo-1", sequence: 1, nonceDigit: "2" });
  const revoked = await revocation({ admin, registrationId: base.registrationId, eventId: "revoke-1", sequence: 2, occurredAt: T2 });
  const trust = {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
    adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` }, now: new Date(T4),
  };
  await assert.rejects(reduceAttestationEvents([repo, revoked, { ...repo, eventId: "repo-replay", sequence: 3, occurredAt: T3 }], trust), /already consumed/i);
  const fresh = await repositoryEvent({
    subject: base,
    account,
    eventId: "repo-fresh",
    sequence: 3,
    nonceDigit: "3",
    issuedAt: T3,
    observedAt: T3,
    occurredAt: T3,
  });
  const state = await reduceAttestationEvents([repo, revoked, fresh], trust);
  assert.equal(state.registrations[base.registrationId].level, "repository_control_verified");

  const approver = privateKeyToAccount(generatePrivateKey());
  const organization = await organizationEvent({
    subject: base,
    approver,
    eventId: "organization-before-revocation",
    sequence: 2,
    approvedAt: T2,
    occurredAt: T2,
  });
  const revocationAfterOrganization = await revocation({
    admin,
    registrationId: base.registrationId,
    eventId: "revoke-with-organization",
    sequence: 3,
    occurredAt: T3,
  });
  const freshAfterOrganization = await repositoryEvent({
    subject: base,
    account,
    eventId: "repo-fresh-after-organization",
    sequence: 4,
    nonceDigit: "4",
    issuedAt: T4,
    observedAt: T4,
    expiresAt: "2026-07-18T05:00:00.000Z",
    occurredAt: T4,
  });
  await assert.rejects(reduceAttestationEvents([
    repo,
    organization,
    revocationAfterOrganization,
    freshAfterOrganization,
    { ...organization, eventId: "old-organization-replay", sequence: 5, occurredAt: T4 },
  ], {
    ...trust,
    organizationSigners: { "example-org": [organization.approval.approverWallet] },
  }), /organization approval credential was already consumed/i);

  const freshOrganization = await organizationEvent({
    subject: base,
    approver,
    eventId: "organization-fresh-after-revocation",
    sequence: 5,
    approvedAt: T4,
    occurredAt: T4,
  });
  const organizationReactivated = await reduceAttestationEvents([
    repo,
    organization,
    revocationAfterOrganization,
    freshAfterOrganization,
    freshOrganization,
  ], {
    ...trust,
    organizationSigners: { "example-org": [organization.approval.approverWallet] },
  });
  assert.equal(organizationReactivated.registrations[base.registrationId].level, "organization_approved");
});

test("unused pre-revocation repository evidence cannot reactivate through a later envelope", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const active = await repositoryEvent({ subject: base, account, eventId: "repo-active", sequence: 1, nonceDigit: "2" });
  const revoked = await revocation({
    admin,
    registrationId: base.registrationId,
    eventId: "repo-revoked",
    sequence: 2,
    occurredAt: T2,
  });
  const staleButUnused = await repositoryEvent({
    subject: base,
    account,
    eventId: "repo-stale-unused",
    sequence: 3,
    nonceDigit: "3",
    issuedAt: T0,
    observedAt: T1,
    occurredAt: T3,
  });
  const staleChallengeWithFreshObservation = await repositoryEvent({
    subject: base,
    account,
    eventId: "repo-stale-challenge-fresh-observation",
    sequence: 3,
    nonceDigit: "4",
    issuedAt: T0,
    observedAt: T3,
    occurredAt: T3,
  });

  await assert.rejects(reduceAttestationEvents([active, revoked, staleButUnused], {
    baseSubjects: [base],
    repositoryVerifier: async () => undefined,
    adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` },
    now: new Date(T4),
  }), /repository reactivation.*strictly after.*revocation/i);
  await assert.rejects(reduceAttestationEvents([active, revoked, staleChallengeWithFreshObservation], {
    baseSubjects: [base],
    repositoryVerifier: async () => undefined,
    adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` },
    now: new Date(T4),
  }), /repository reactivation.*strictly after.*revocation/i);
});

test("unused pre-revocation organization approval cannot reactivate through a later envelope", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const repository = await repositoryEvent({ subject: base, account, eventId: "repo-active", sequence: 1, nonceDigit: "2" });
  const active = await organizationEvent({
    subject: base,
    approver,
    eventId: "organization-active",
    sequence: 2,
    approvedAt: T2,
    occurredAt: T2,
  });
  const revocationBase = {
    type: "attestation_revoked" as const,
    eventId: "organization-revoked",
    sequence: 3,
    occurredAt: T3,
    registrationId: base.registrationId,
    level: "organization_approved" as const,
    reason: "Organization approval withdrawn.",
    adminSignerId: "admin-1",
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  const revocationHash = adminEventStatementHash(revocationBase);
  const revoked: AttestationRevokedEvent = {
    ...revocationBase,
    statementHash: revocationHash,
    signature: await admin.signMessage({ message: canonicalAdminEventStatement({ ...revocationBase, statementHash: revocationHash }) }),
  };
  const staleButUnused = await organizationEvent({
    subject: base,
    approver,
    eventId: "organization-stale-unused",
    sequence: 4,
    approvedAt: "2026-07-18T02:30:00.000Z",
    occurredAt: T4,
  });

  await assert.rejects(reduceAttestationEvents([repository, active, revoked, staleButUnused], {
    baseSubjects: [base],
    repositoryVerifier: async () => undefined,
    organizationSigners: { "example-org": [approver.address.toLowerCase() as `0x${string}`] },
    adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` },
    now: new Date(T4),
  }), /organization reactivation.*strictly after.*revocation/i);
});

test("event chronology and causal approval/resolution ordering fail closed against an injected clock", async () => {
  const account = privateKeyToAccount(generatePrivateKey());
  const approver = privateKeyToAccount(generatePrivateKey());
  const admin = privateKeyToAccount(generatePrivateKey());
  const challenger = privateKeyToAccount(generatePrivateKey());
  const base = subject(IP_A, account.address);
  const second = subject(IP_B, challenger.address);
  const repo = await repositoryEvent({ subject: base, account, eventId: "repo-1", sequence: 1, nonceDigit: "2", occurredAt: T2 });
  const freshEarlier = await repositoryEvent({ subject: base, account, eventId: "repo-2", sequence: 2, nonceDigit: "3", occurredAt: T1 });
  await assert.rejects(reduceAttestationEvents([repo, freshEarlier], {
    baseSubjects: [base], repositoryVerifier: async () => undefined, now: new Date(T4),
  }), /occurredAt must be nondecreasing/i);

  const futureRepo = await repositoryEvent({ subject: base, account, eventId: "repo-future", sequence: 1, nonceDigit: "6", occurredAt: T4 });
  await assert.rejects(reduceAttestationEvents([futureRepo], {
    baseSubjects: [base], repositoryVerifier: async () => undefined, now: new Date(T3),
  }), /future-dated/i);

  const futureOrg = await organizationEvent({ subject: base, approver, eventId: "org-future", sequence: 2, approvedAt: T4, occurredAt: T3 });
  await assert.rejects(reduceAttestationEvents([repo, futureOrg], {
    baseSubjects: [base], repositoryVerifier: async () => undefined,
    organizationSigners: { "example-org": [futureOrg.approval.approverWallet] }, now: new Date(T3),
  }), /approvedAt.*envelope|future/i);

  const conflictId = deterministicConflictId(base, second);
  const resolutionBase = {
    type: "challenge_resolved" as const,
    eventId: "resolution-1",
    sequence: 1,
    occurredAt: T2,
    conflictId,
    outcome: "inconclusive" as const,
    rationale: "No signed challenge preceded this resolution.",
    adminSignerId: "admin-1",
    statementHash: HASH,
    signature: "0x00" as `0x${string}`,
  };
  const statementHash = adminEventStatementHash(resolutionBase);
  const resolution: ChallengeResolvedEvent = {
    ...resolutionBase,
    statementHash,
    signature: await admin.signMessage({ message: canonicalAdminEventStatement({ ...resolutionBase, statementHash }) }),
  };
  await assert.rejects(reduceAttestationEvents([resolution], {
    baseSubjects: [base, second], adminSigners: { "admin-1": admin.address.toLowerCase() as `0x${string}` }, now: new Date(T4),
  }), /resolution requires a preceding signed challenge/i);
});

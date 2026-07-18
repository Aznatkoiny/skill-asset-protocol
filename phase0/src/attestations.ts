import { createHash } from "node:crypto";

import { keccak256, stringToHex, verifyMessage } from "viem";

import type { RegistrationManifest } from "./registrations";

export type AttestationLevel =
  | "wallet_asserted"
  | "repository_control_verified"
  | "organization_approved";
export type AttestationStatus = "active" | "challenged";
export type SafetyReviewStatus = "not_reviewed" | "pending" | "approved" | "rejected";

export interface RegistrationSubject {
  registrationId: `eip155:1315:${string}`;
  ipId: `0x${string}`;
  wallet: `0x${string}`;
  artifactHash: `0x${string}`;
  declaredParentIpIds: `0x${string}`[];
}

export interface RepositoryControlChallengeV1 {
  schemaVersion: 1;
  subject: RegistrationSubject;
  repositoryUrl: string;
  artifactCommitSha: string;
  artifactPath: string;
  challengePath: string;
  nonce: `0x${string}`;
  issuedAt: string;
  expiresAt: string;
}

export interface OrganizationApprovalV1 {
  schemaVersion: 1;
  subject: RegistrationSubject;
  organizationId: string;
  approverWallet: `0x${string}`;
  role: "ip_admin" | "engineering_executive";
  approvedAt: string;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
}

export interface ForgeObservationV1 {
  schemaVersion: 1;
  repositoryId: string;
  repositoryUrl: string;
  trustedRef: `refs/heads/${string}` | `refs/remotes/${string}`;
  proofCommitSha: string;
  challengeNonce: `0x${string}`;
  observedAt: string;
  forgeSignerId: string;
  signature: string;
}

export type RepositoryControlEvent = {
  type: "repository_control_verified";
  eventId: string;
  sequence: number;
  occurredAt: string;
  subject: RegistrationSubject;
  challenge: RepositoryControlChallengeV1;
  forgeObservation: ForgeObservationV1;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
};

export type OrganizationApprovedEvent = {
  type: "organization_approved";
  eventId: string;
  sequence: number;
  occurredAt: string;
  subject: RegistrationSubject;
  approval: OrganizationApprovalV1;
};

export type ChallengeOpenedEvent = {
  type: "challenge_opened";
  eventId: string;
  sequence: number;
  occurredAt: string;
  conflictId: string;
  challengedRegistrationId: string;
  challengerRegistrationId: string;
  challengerWallet: `0x${string}`;
  evidenceUris: string[];
  reason: "duplicate_bytes" | "misattributed_creator" | "unauthorized_registration";
  statementHash: `0x${string}`;
  signature: `0x${string}`;
};

export type ChallengeResolvedEvent = {
  type: "challenge_resolved";
  eventId: string;
  sequence: number;
  occurredAt: string;
  conflictId: string;
  outcome: "upheld" | "rejected" | "inconclusive";
  rationale: string;
  adminSignerId: string;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
};

export type AttestationRevokedEvent = {
  type: "attestation_revoked";
  eventId: string;
  sequence: number;
  occurredAt: string;
  registrationId: string;
  level: Exclude<AttestationLevel, "wallet_asserted">;
  reason: string;
  adminSignerId: string;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
};

export type AttestationEvent =
  | RepositoryControlEvent
  | OrganizationApprovedEvent
  | ChallengeOpenedEvent
  | ChallengeResolvedEvent
  | AttestationRevokedEvent;

export interface AttestationRegistration {
  subject: RegistrationSubject;
  level: AttestationLevel;
  status: AttestationStatus;
  claim: string;
  safetyReviewStatus: SafetyReviewStatus;
  evidenceEventIds: readonly string[];
  revocations: readonly {
    level: Exclude<AttestationLevel, "wallet_asserted">;
    eventId: string;
    occurredAt: string;
    reason: string;
  }[];
}

export interface AttestationConflict {
  conflictId: string;
  artifactHash: `0x${string}` | null;
  registrationIds: readonly string[];
  status: "open" | "resolved";
  reason: ChallengeOpenedEvent["reason"];
  outcome: ChallengeResolvedEvent["outcome"] | null;
  eventIds: readonly string[];
}

export interface AttestationIndex {
  registrations: Readonly<Record<string, AttestationRegistration>>;
  conflicts: readonly AttestationConflict[];
  events: readonly AttestationEvent[];
}

const ADDRESS = /^0x[0-9a-f]{40}$/;
const HASH = /^0x[0-9a-f]{64}$/;
const COMMIT = /^[0-9a-f]{40,64}$/;
const NONCE = /^0x[0-9a-f]{64}$/;
const HEX_SIGNATURE = /^0x(?:[0-9a-fA-F]{2})+$/;
const REGISTRATION_ID = /^eip155:1315:0x[0-9a-f]{40}$/;
const IDENTIFIER = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const TRUSTED_REF = /^refs\/(?:heads|remotes)\/[A-Za-z0-9._\/-]+$/;

const SUBJECT_KEYS = [
  "registrationId",
  "ipId",
  "wallet",
  "artifactHash",
  "declaredParentIpIds",
] as const;
const CHALLENGE_KEYS = [
  "schemaVersion",
  "subject",
  "repositoryUrl",
  "artifactCommitSha",
  "artifactPath",
  "challengePath",
  "nonce",
  "issuedAt",
  "expiresAt",
] as const;
const FORGE_KEYS = [
  "schemaVersion",
  "repositoryId",
  "repositoryUrl",
  "trustedRef",
  "proofCommitSha",
  "challengeNonce",
  "observedAt",
  "forgeSignerId",
  "signature",
] as const;
const APPROVAL_KEYS = [
  "schemaVersion",
  "subject",
  "organizationId",
  "approverWallet",
  "role",
  "approvedAt",
  "statementHash",
  "signature",
] as const;

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

function assertTrustMap(value: unknown, label: string): asserts value is Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be a plain or null-prototype record`);
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${label} must be a plain or null-prototype record`);
  }
}

function nonempty(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim() !== value || value.length === 0) {
    throw new Error(`${label} must be a nonempty canonical string`);
  }
}

function iso(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error(`${label} must be a canonical UTC ISO-8601 timestamp`);
  }
}

function hash(value: unknown, label: string): asserts value is `0x${string}` {
  if (typeof value !== "string" || !HASH.test(value)) throw new Error(`${label} must be a lowercase 32-byte hash`);
}

function address(value: unknown, label: string): asserts value is `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value)) throw new Error(`${label} must be a lowercase address`);
}

function signature(value: unknown, label: string): asserts value is `0x${string}` {
  if (typeof value !== "string" || !HEX_SIGNATURE.test(value)) throw new Error(`${label} must be a hex signature`);
}

function relativePath(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.includes("\\") || value.includes("\0") || value.startsWith("/")) {
    throw new Error(`${label} must be a normalized relative POSIX path`);
  }
  const segments = value.split("/");
  if (segments.some((part) => part === "" || part === "." || part === "..")) {
    throw new Error(`${label} must be a normalized relative POSIX path`);
  }
}

export function normalizeRepositoryUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("repository URL must be normalized HTTPS");
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.port || parsed.search || parsed.hash) {
    throw new Error("repository URL must be normalized HTTPS");
  }
  if (!parsed.hostname || parsed.pathname === "/" || parsed.pathname.includes("//") || parsed.pathname.includes("/../")) {
    throw new Error("repository URL must be normalized HTTPS");
  }
  const path = parsed.pathname.replace(/\/$/, "");
  const normalized = `https://${parsed.hostname.toLowerCase()}${path}`;
  if (value !== normalized) throw new Error("repository URL must already be normalized HTTPS without a trailing slash");
  return normalized;
}

function parseSubject(value: unknown, label = "registration subject"): RegistrationSubject {
  const subject = record(value, label);
  exactKeys(subject, SUBJECT_KEYS, label);
  if (typeof subject.registrationId !== "string" || !REGISTRATION_ID.test(subject.registrationId)) {
    throw new Error(`${label}.registrationId must be an Aeneid CAIP registration ID`);
  }
  address(subject.ipId, `${label}.ipId`);
  if (subject.registrationId !== `eip155:1315:${subject.ipId}`) {
    throw new Error(`${label}.registrationId must identify its ipId`);
  }
  address(subject.wallet, `${label}.wallet`);
  hash(subject.artifactHash, `${label}.artifactHash`);
  if (!Array.isArray(subject.declaredParentIpIds)) throw new Error(`${label}.declaredParentIpIds must be an array`);
  const parents = subject.declaredParentIpIds.map((parent, index) => {
    address(parent, `${label}.declaredParentIpIds[${index}]`);
    return parent;
  });
  if (new Set(parents).size !== parents.length) throw new Error(`${label}.declaredParentIpIds must be unique`);
  return {
    registrationId: subject.registrationId as `eip155:1315:${string}`,
    ipId: subject.ipId,
    wallet: subject.wallet,
    artifactHash: subject.artifactHash,
    declaredParentIpIds: parents,
  };
}

export function parseRepositoryChallenge(value: unknown): RepositoryControlChallengeV1 {
  const challenge = record(value, "repository challenge");
  exactKeys(challenge, CHALLENGE_KEYS, "repository challenge");
  if (challenge.schemaVersion !== 1) throw new Error("repository challenge schemaVersion must be 1");
  const subject = parseSubject(challenge.subject, "repository challenge subject");
  nonempty(challenge.repositoryUrl, "repository challenge repositoryUrl");
  normalizeRepositoryUrl(challenge.repositoryUrl);
  if (typeof challenge.artifactCommitSha !== "string" || !COMMIT.test(challenge.artifactCommitSha)) {
    throw new Error("repository challenge artifactCommitSha must be a lowercase full commit SHA");
  }
  relativePath(challenge.artifactPath, "repository challenge artifactPath");
  relativePath(challenge.challengePath, "repository challenge challengePath");
  if (challenge.artifactPath === challenge.challengePath) throw new Error("artifact and challenge paths must differ");
  if (typeof challenge.nonce !== "string" || !NONCE.test(challenge.nonce)) {
    throw new Error("repository challenge nonce must be 32 lowercase bytes");
  }
  iso(challenge.issuedAt, "repository challenge issuedAt");
  iso(challenge.expiresAt, "repository challenge expiresAt");
  if (Date.parse(challenge.expiresAt) <= Date.parse(challenge.issuedAt)) {
    throw new Error("repository challenge must expire after it is issued");
  }
  return {
    schemaVersion: 1,
    subject,
    repositoryUrl: challenge.repositoryUrl,
    artifactCommitSha: challenge.artifactCommitSha,
    artifactPath: challenge.artifactPath,
    challengePath: challenge.challengePath,
    nonce: challenge.nonce as `0x${string}`,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  };
}

export function parseForgeObservation(value: unknown): ForgeObservationV1 {
  const observation = record(value, "forge observation");
  exactKeys(observation, FORGE_KEYS, "forge observation");
  if (observation.schemaVersion !== 1) throw new Error("forge observation schemaVersion must be 1");
  if (typeof observation.repositoryId !== "string" || !IDENTIFIER.test(observation.repositoryId)) {
    throw new Error("forge observation repositoryId is invalid");
  }
  nonempty(observation.repositoryUrl, "forge observation repositoryUrl");
  normalizeRepositoryUrl(observation.repositoryUrl);
  if (typeof observation.trustedRef !== "string" || !TRUSTED_REF.test(observation.trustedRef) || observation.trustedRef.includes("..")) {
    throw new Error("forge observation trustedRef must be a full trusted ref");
  }
  if (typeof observation.proofCommitSha !== "string" || !COMMIT.test(observation.proofCommitSha)) {
    throw new Error("forge observation proofCommitSha must be a lowercase full commit SHA");
  }
  if (typeof observation.challengeNonce !== "string" || !NONCE.test(observation.challengeNonce)) {
    throw new Error("forge observation challengeNonce must be 32 lowercase bytes");
  }
  iso(observation.observedAt, "forge observation observedAt");
  if (typeof observation.forgeSignerId !== "string" || !IDENTIFIER.test(observation.forgeSignerId)) {
    throw new Error("forge observation forgeSignerId is invalid");
  }
  nonempty(observation.signature, "forge observation signature");
  return observation as unknown as ForgeObservationV1;
}

function parseApproval(value: unknown): OrganizationApprovalV1 {
  const approval = record(value, "organization approval");
  exactKeys(approval, APPROVAL_KEYS, "organization approval");
  if (approval.schemaVersion !== 1) throw new Error("organization approval schemaVersion must be 1");
  const subject = parseSubject(approval.subject, "organization approval subject");
  if (typeof approval.organizationId !== "string" || !IDENTIFIER.test(approval.organizationId)) {
    throw new Error("organization approval organizationId must be normalized lowercase");
  }
  address(approval.approverWallet, "organization approval approverWallet");
  if (approval.role !== "ip_admin" && approval.role !== "engineering_executive") {
    throw new Error("organization approval role is invalid");
  }
  iso(approval.approvedAt, "organization approval approvedAt");
  hash(approval.statementHash, "organization approval statementHash");
  signature(approval.signature, "organization approval signature");
  return { ...approval, subject } as unknown as OrganizationApprovalV1;
}

function parseEventBase(event: Record<string, unknown>): void {
  nonempty(event.eventId, "attestation eventId");
  if (!Number.isSafeInteger(event.sequence) || (event.sequence as number) <= 0) {
    throw new Error("attestation sequence must be a positive integer");
  }
  iso(event.occurredAt, "attestation occurredAt");
}

export function parseAttestationEvent(value: unknown): AttestationEvent {
  const event = record(value, "attestation event");
  if (event.type === "wallet_asserted") throw new Error("wallet_asserted cannot be a sidecar event");
  if (event.type === "repository_control_verified") {
    exactKeys(event, ["type", "eventId", "sequence", "occurredAt", "subject", "challenge", "forgeObservation", "statementHash", "signature"], "repository event");
    parseEventBase(event);
    const subject = parseSubject(event.subject);
    const challenge = parseRepositoryChallenge(event.challenge);
    const forgeObservation = parseForgeObservation(event.forgeObservation);
    hash(event.statementHash, "repository event statementHash");
    signature(event.signature, "repository event signature");
    return { ...event, subject, challenge, forgeObservation } as unknown as RepositoryControlEvent;
  }
  if (event.type === "organization_approved") {
    exactKeys(event, ["type", "eventId", "sequence", "occurredAt", "subject", "approval"], "organization event");
    parseEventBase(event);
    return { ...event, subject: parseSubject(event.subject), approval: parseApproval(event.approval) } as unknown as OrganizationApprovedEvent;
  }
  if (event.type === "challenge_opened") {
    exactKeys(event, ["type", "eventId", "sequence", "occurredAt", "conflictId", "challengedRegistrationId", "challengerRegistrationId", "challengerWallet", "evidenceUris", "reason", "statementHash", "signature"], "challenge event");
    parseEventBase(event);
    nonempty(event.conflictId, "challenge conflictId");
    if (typeof event.challengedRegistrationId !== "string" || !REGISTRATION_ID.test(event.challengedRegistrationId)) throw new Error("challenged registration ID is invalid");
    if (typeof event.challengerRegistrationId !== "string" || !REGISTRATION_ID.test(event.challengerRegistrationId)) throw new Error("challenger registration ID is invalid");
    if (event.challengedRegistrationId === event.challengerRegistrationId) throw new Error("a registration cannot challenge itself");
    address(event.challengerWallet, "challenger wallet");
    if (!Array.isArray(event.evidenceUris)) throw new Error("challenge evidenceUris must be an array");
    const evidenceUris = event.evidenceUris.map((uri, index) => {
      nonempty(uri, `challenge evidenceUris[${index}]`);
      let parsed: URL;
      try { parsed = new URL(uri); } catch { throw new Error("challenge evidence URI is invalid"); }
      if (!new Set(["https:", "ipfs:"]).has(parsed.protocol)) throw new Error("challenge evidence URI must use HTTPS or IPFS");
      return uri;
    });
    if (new Set(evidenceUris).size !== evidenceUris.length) throw new Error("challenge evidenceUris must be unique");
    if (!(event.reason === "duplicate_bytes" || event.reason === "misattributed_creator" || event.reason === "unauthorized_registration")) throw new Error("challenge reason is invalid");
    hash(event.statementHash, "challenge statementHash");
    signature(event.signature, "challenge signature");
    return { ...event, evidenceUris } as unknown as ChallengeOpenedEvent;
  }
  if (event.type === "challenge_resolved") {
    exactKeys(event, ["type", "eventId", "sequence", "occurredAt", "conflictId", "outcome", "rationale", "adminSignerId", "statementHash", "signature"], "resolution event");
    parseEventBase(event);
    nonempty(event.conflictId, "resolution conflictId");
    if (!(event.outcome === "upheld" || event.outcome === "rejected" || event.outcome === "inconclusive")) throw new Error("resolution outcome is invalid");
    nonempty(event.rationale, "resolution rationale");
    if (typeof event.adminSignerId !== "string" || !IDENTIFIER.test(event.adminSignerId)) throw new Error("resolution adminSignerId is invalid");
    hash(event.statementHash, "resolution statementHash");
    signature(event.signature, "resolution signature");
    return event as unknown as ChallengeResolvedEvent;
  }
  if (event.type === "attestation_revoked") {
    exactKeys(event, ["type", "eventId", "sequence", "occurredAt", "registrationId", "level", "reason", "adminSignerId", "statementHash", "signature"], "revocation event");
    parseEventBase(event);
    if (typeof event.registrationId !== "string" || !REGISTRATION_ID.test(event.registrationId)) throw new Error("revocation registrationId is invalid");
    if (event.level === "wallet_asserted") throw new Error("wallet_asserted cannot be revoked");
    if (event.level !== "repository_control_verified" && event.level !== "organization_approved") throw new Error("revocation level is invalid");
    nonempty(event.reason, "revocation reason");
    if (typeof event.adminSignerId !== "string" || !IDENTIFIER.test(event.adminSignerId)) throw new Error("revocation adminSignerId is invalid");
    hash(event.statementHash, "revocation statementHash");
    signature(event.signature, "revocation signature");
    return event as unknown as AttestationRevokedEvent;
  }
  throw new Error("attestation event type is invalid");
}

function subjectEquals(a: RegistrationSubject, b: RegistrationSubject): boolean {
  return a.registrationId === b.registrationId
    && a.ipId === b.ipId
    && a.wallet === b.wallet
    && a.artifactHash === b.artifactHash
    && a.declaredParentIpIds.length === b.declaredParentIpIds.length
    && a.declaredParentIpIds.every((value, index) => value === b.declaredParentIpIds[index]);
}

export function canonicalRepositoryStatement(challengeValue: RepositoryControlChallengeV1): string {
  const challenge = parseRepositoryChallenge(challengeValue);
  return canonicalSignedJson("skill-asset-protocol/repository-control/v2", {
    schemaVersion: 2,
    registrationId: challenge.subject.registrationId,
    ipId: challenge.subject.ipId,
    wallet: challenge.subject.wallet,
    artifactSha256: challenge.subject.artifactHash,
    declaredParentIpIds: [...challenge.subject.declaredParentIpIds].sort(),
    repository: challenge.repositoryUrl,
    artifactCommit: challenge.artifactCommitSha,
    artifactPath: challenge.artifactPath,
    challengePath: challenge.challengePath,
    nonce: challenge.nonce,
    issuedAt: challenge.issuedAt,
    expiresAt: challenge.expiresAt,
  });
}

export function repositoryStatementHash(challenge: RepositoryControlChallengeV1): `0x${string}` {
  return keccak256(stringToHex(canonicalRepositoryStatement(challenge)));
}

export async function verifyRepositoryEventSignature(eventValue: RepositoryControlEvent): Promise<void> {
  const event = parseAttestationEvent(eventValue);
  if (event.type !== "repository_control_verified") throw new Error("repository event required");
  if (!subjectEquals(event.subject, event.challenge.subject)) throw new Error("repository event subject drift");
  const expectedHash = repositoryStatementHash(event.challenge);
  if (event.statementHash !== expectedHash) throw new Error("repository statement hash mismatch");
  const valid = await verifyMessage({
    address: event.subject.wallet,
    message: canonicalRepositoryStatement(event.challenge),
    signature: event.signature,
  });
  if (!valid) throw new Error("repository signature does not recover the subject wallet");
}

type UnsignedApproval = Omit<OrganizationApprovalV1, "statementHash" | "signature">;

export function canonicalOrganizationStatement(approvalValue: UnsignedApproval): string {
  const approval = parseApproval({
    ...approvalValue,
    statementHash: `0x${"0".repeat(64)}`,
    signature: "0x00",
  });
  return canonicalSignedJson("skill-asset-protocol/organization-approval/v2", {
    schemaVersion: 2,
    registrationId: approval.subject.registrationId,
    ipId: approval.subject.ipId,
    wallet: approval.subject.wallet,
    artifactSha256: approval.subject.artifactHash,
    declaredParentIpIds: [...approval.subject.declaredParentIpIds].sort(),
    organizationId: approval.organizationId,
    approverWallet: approval.approverWallet,
    role: approval.role,
    approvedAt: approval.approvedAt,
  });
}

export function organizationStatementHash(approval: UnsignedApproval): `0x${string}` {
  return keccak256(stringToHex(canonicalOrganizationStatement(approval)));
}

export async function verifyOrganizationApproval(
  approvalValue: OrganizationApprovalV1,
  organizationSigners: Readonly<Record<string, readonly `0x${string}`[]>>,
): Promise<void> {
  const approval = parseApproval(approvalValue);
  const unsigned: UnsignedApproval = {
    schemaVersion: approval.schemaVersion,
    subject: approval.subject,
    organizationId: approval.organizationId,
    approverWallet: approval.approverWallet,
    role: approval.role,
    approvedAt: approval.approvedAt,
  };
  if (approval.statementHash !== organizationStatementHash(unsigned)) throw new Error("organization statement hash mismatch");
  assertTrustMap(organizationSigners, "organization signer trust");
  if (!Object.hasOwn(organizationSigners, approval.organizationId)) {
    throw new Error("organization approver is not allow-listed; organization ID must be an own property of the trust map");
  }
  const trusted = organizationSigners[approval.organizationId];
  if (!trusted.includes(approval.approverWallet)) throw new Error("organization approver is not allow-listed");
  if (!await verifyMessage({ address: approval.approverWallet, message: canonicalOrganizationStatement(unsigned), signature: approval.signature })) {
    throw new Error("organization signature does not recover the approver wallet");
  }
}

function canonicalSignedJson(domain: string, payload: Record<string, unknown>): string {
  return `${domain}\n${JSON.stringify(payload)}\n`;
}

export function canonicalChallengeEventStatement(eventValue: ChallengeOpenedEvent): string {
  const event = parseAttestationEvent(eventValue);
  if (event.type !== "challenge_opened") throw new Error("challenge event required");
  return canonicalSignedJson("skill-asset-protocol/challenge-opened/v2", {
    schemaVersion: 2,
    eventId: event.eventId,
    sequence: event.sequence,
    occurredAt: event.occurredAt,
    conflictId: event.conflictId,
    challengedRegistrationId: event.challengedRegistrationId,
    challengerRegistrationId: event.challengerRegistrationId,
    challengerWallet: event.challengerWallet,
    evidenceUris: [...event.evidenceUris].sort(),
    reason: event.reason,
  });
}

export function canonicalAdminEventStatement(eventValue: ChallengeResolvedEvent | AttestationRevokedEvent): string {
  const event = parseAttestationEvent(eventValue);
  if (event.type === "challenge_resolved") {
    return canonicalSignedJson("skill-asset-protocol/challenge-resolved/v2", {
      schemaVersion: 2,
      eventId: event.eventId,
      sequence: event.sequence,
      occurredAt: event.occurredAt,
      conflictId: event.conflictId,
      outcome: event.outcome,
      rationale: event.rationale,
      adminSignerId: event.adminSignerId,
    });
  }
  if (event.type === "attestation_revoked") {
    return canonicalSignedJson("skill-asset-protocol/attestation-revoked/v2", {
      schemaVersion: 2,
      eventId: event.eventId,
      sequence: event.sequence,
      occurredAt: event.occurredAt,
      registrationId: event.registrationId,
      level: event.level,
      reason: event.reason,
      adminSignerId: event.adminSignerId,
    });
  }
  throw new Error("admin event required");
}

export function challengeEventStatementHash(event: ChallengeOpenedEvent): `0x${string}` {
  return keccak256(stringToHex(canonicalChallengeEventStatement(event)));
}

export function adminEventStatementHash(event: ChallengeResolvedEvent | AttestationRevokedEvent): `0x${string}` {
  return keccak256(stringToHex(canonicalAdminEventStatement(event)));
}

export async function verifyChallengeEventSignature(
  eventValue: ChallengeOpenedEvent,
  subjects: Readonly<Record<string, RegistrationSubject>>,
): Promise<void> {
  const event = parseAttestationEvent(eventValue);
  if (event.type !== "challenge_opened") throw new Error("challenge event required");
  const challenger = subjects[event.challengerRegistrationId];
  if (!challenger) throw new Error("challenger registration is unknown");
  if (!subjects[event.challengedRegistrationId]) throw new Error("challenged registration is unknown");
  if (challenger.wallet !== event.challengerWallet) throw new Error("challenger wallet does not match its registration");
  if (event.statementHash !== challengeEventStatementHash(event)) throw new Error("challenge statement hash mismatch");
  if (!await verifyMessage({ address: challenger.wallet, message: canonicalChallengeEventStatement(event), signature: event.signature })) {
    throw new Error("challenge signature does not recover the challenger wallet");
  }
}

export async function verifyAdminEventSignature(
  eventValue: ChallengeResolvedEvent | AttestationRevokedEvent,
  adminSigners: Readonly<Record<string, `0x${string}`>>,
): Promise<void> {
  const event = parseAttestationEvent(eventValue);
  if (event.type !== "challenge_resolved" && event.type !== "attestation_revoked") throw new Error("admin event required");
  assertTrustMap(adminSigners, "attestation admin trust");
  if (!Object.hasOwn(adminSigners, event.adminSignerId)) {
    throw new Error("admin signer is not provisioned; signer ID must be an own property of the trust map");
  }
  const signer = adminSigners[event.adminSignerId];
  if (!signer) throw new Error("admin signer is not provisioned");
  address(signer, "admin signer address");
  if (event.statementHash !== adminEventStatementHash(event)) throw new Error("admin statement hash mismatch");
  if (!await verifyMessage({ address: signer, message: canonicalAdminEventStatement(event), signature: event.signature })) {
    throw new Error("admin signature does not recover the provisioned wallet");
  }
}

export function registrationSubjectsFromManifest(manifest: RegistrationManifest): RegistrationSubject[] {
  if (manifest.status === "not-run") return [];
  if (!manifest.wallet) throw new Error("confirmed registration manifest wallet is required");
  return deepFreeze((Object.values(manifest.registrations).filter((proof) => proof !== null)).map((proof) => ({
    registrationId: `eip155:1315:${proof.ipId.toLowerCase()}` as `eip155:1315:${string}`,
    ipId: proof.ipId.toLowerCase() as `0x${string}`,
    wallet: manifest.wallet!.toLowerCase() as `0x${string}`,
    artifactHash: proof.metadata.artifact.mediaHash.toLowerCase() as `0x${string}`,
    declaredParentIpIds: proof.parentIpIds.map((parent) => parent.toLowerCase() as `0x${string}`),
  })));
}

export function deterministicConflictId(a: RegistrationSubject, b: RegistrationSubject): string {
  const [first, second] = [a.registrationId, b.registrationId].sort();
  return `sha256:${createHash("sha256").update(`${first}\n${second}`).digest("hex")}`;
}

const CLAIMS: Record<AttestationLevel, string> = {
  wallet_asserted: "wallet registered these bytes and declared this ancestry",
  repository_control_verified: "wallet signature and matching bytes were verified against a trusted forge observation and verifier-provisioned Git snapshot",
  organization_approved: "named organization signer approved the Skill and Creator relationship",
};

export async function reduceAttestationEvents(
  eventValues: readonly AttestationEvent[],
  trust: {
    organizationSigners?: Readonly<Record<string, readonly `0x${string}`[]>>;
    adminSigners?: Readonly<Record<string, `0x${string}`>>;
    baseSubjects?: readonly RegistrationSubject[];
    repositoryVerifier?: (event: RepositoryControlEvent) => Promise<void>;
    now?: Date;
  } = {},
): Promise<AttestationIndex> {
  const verifierNow = trust.now?.getTime();
  if (verifierNow !== undefined && !Number.isFinite(verifierNow)) throw new Error("attestation verifier clock is invalid");
  const subjects: Record<string, RegistrationSubject> = {};
  for (const raw of trust.baseSubjects ?? []) {
    const subject = parseSubject(raw, "base registration subject");
    if (subjects[subject.registrationId]) throw new Error(`duplicate base registration ${subject.registrationId}`);
    subjects[subject.registrationId] = subject;
  }

  const registrations: Record<string, AttestationRegistration & {
    repositoryActive: boolean;
    organizationActive: boolean;
    repositoryActivatedAt: number | null;
    organizationActivatedAt: number | null;
    repositoryRevokedAt: number | null;
    organizationRevokedAt: number | null;
  }> = {};
  for (const subject of Object.values(subjects)) {
    registrations[subject.registrationId] = {
      subject,
      level: "wallet_asserted",
      status: "active",
      claim: CLAIMS.wallet_asserted,
      safetyReviewStatus: "not_reviewed",
      evidenceEventIds: [],
      revocations: [],
      repositoryActive: false,
      organizationActive: false,
      repositoryActivatedAt: null,
      organizationActivatedAt: null,
      repositoryRevokedAt: null,
      organizationRevokedAt: null,
    };
  }

  const conflicts = new Map<string, AttestationConflict>();
  const byHash = new Map<string, RegistrationSubject[]>();
  for (const subject of Object.values(subjects)) {
    const group = byHash.get(subject.artifactHash) ?? [];
    for (const prior of group) {
      if (prior.wallet === subject.wallet) continue;
      const conflictId = deterministicConflictId(prior, subject);
      conflicts.set(conflictId, {
        conflictId,
        artifactHash: subject.artifactHash,
        registrationIds: [prior.registrationId, subject.registrationId].sort(),
        status: "open",
        reason: "duplicate_bytes",
        outcome: null,
        eventIds: [],
      });
    }
    group.push(subject);
    byHash.set(subject.artifactHash, group);
  }

  const parsedEvents: AttestationEvent[] = [];
  const eventIds = new Set<string>();
  const consumedRepositoryStatementHashes = new Set<string>();
  const consumedRepositoryNonces = new Set<string>();
  const consumedRepositorySignatures = new Set<string>();
  const consumedForgeObservations = new Set<string>();
  const consumedOrganizationStatementHashes = new Set<string>();
  const consumedOrganizationSignatures = new Set<string>();
  const challengeOpenedAt = new Map<string, number>();
  let priorOccurredAt: number | null = null;
  for (let index = 0; index < eventValues.length; index += 1) {
    const event = parseAttestationEvent(eventValues[index]);
    if (event.sequence !== index + 1) throw new Error(`attestation sequence must be contiguous at ${index + 1}`);
    if (eventIds.has(event.eventId)) throw new Error(`duplicate attestation event ID ${event.eventId}`);
    const occurredAt = Date.parse(event.occurredAt);
    if (priorOccurredAt !== null && occurredAt < priorOccurredAt) {
      throw new Error("attestation event occurredAt must be nondecreasing");
    }
    if (verifierNow !== undefined && occurredAt > verifierNow) throw new Error("attestation event occurredAt is future-dated");
    priorOccurredAt = occurredAt;
    eventIds.add(event.eventId);
    parsedEvents.push(event);

    if (event.type === "repository_control_verified") {
      const registration = registrations[event.subject.registrationId];
      if (!registration || !subjectEquals(registration.subject, event.subject)) throw new Error("repository event subject drift or unknown registration");
      const forgeCredential = JSON.stringify([
        event.forgeObservation.schemaVersion,
        event.forgeObservation.repositoryId,
        event.forgeObservation.repositoryUrl,
        event.forgeObservation.trustedRef,
        event.forgeObservation.proofCommitSha,
        event.forgeObservation.challengeNonce,
        event.forgeObservation.observedAt,
        event.forgeObservation.forgeSignerId,
        event.forgeObservation.signature,
      ]);
      if (consumedRepositoryStatementHashes.has(event.statementHash)
          || consumedRepositoryNonces.has(event.challenge.nonce)
          || consumedRepositorySignatures.has(event.signature)
          || consumedForgeObservations.has(forgeCredential)) {
        throw new Error("repository credential, statement, nonce, or forge observation was already consumed");
      }
      const challengeIssuedAt = Date.parse(event.challenge.issuedAt);
      const forgeObservedAt = Date.parse(event.forgeObservation.observedAt);
      if (registration.repositoryRevokedAt !== null
          && (challengeIssuedAt <= registration.repositoryRevokedAt
            || forgeObservedAt <= registration.repositoryRevokedAt)) {
        throw new Error("repository reactivation requires a signed challenge and forge observation strictly after the latest repository revocation");
      }
      await verifyRepositoryEventSignature(event);
      if (!trust.repositoryVerifier) throw new Error("repository verifier context required");
      await trust.repositoryVerifier(event);
      consumedRepositoryStatementHashes.add(event.statementHash);
      consumedRepositoryNonces.add(event.challenge.nonce);
      consumedRepositorySignatures.add(event.signature);
      consumedForgeObservations.add(forgeCredential);
      registration.repositoryActive = true;
      registration.repositoryActivatedAt = occurredAt;
      registration.evidenceEventIds = Object.freeze([...registration.evidenceEventIds, event.eventId]);
    } else if (event.type === "organization_approved") {
      const registration = registrations[event.subject.registrationId];
      if (!registration || !subjectEquals(registration.subject, event.subject) || !subjectEquals(event.subject, event.approval.subject)) throw new Error("organization event subject drift or unknown registration");
      if (!registration.repositoryActive) throw new Error("organization approval requires active repository evidence");
      if (consumedOrganizationStatementHashes.has(event.approval.statementHash)
          || consumedOrganizationSignatures.has(event.approval.signature)) {
        throw new Error("organization approval credential was already consumed");
      }
      const approvedAt = Date.parse(event.approval.approvedAt);
      if (registration.organizationRevokedAt !== null && approvedAt <= registration.organizationRevokedAt) {
        throw new Error("organization reactivation requires an approval strictly after the latest organization revocation");
      }
      if (approvedAt > occurredAt) throw new Error("organization approvedAt must not follow its event envelope");
      if (registration.repositoryActivatedAt === null || approvedAt < registration.repositoryActivatedAt) {
        throw new Error("organization approvedAt must not precede active repository evidence");
      }
      await verifyOrganizationApproval(event.approval, trust.organizationSigners ?? {});
      consumedOrganizationStatementHashes.add(event.approval.statementHash);
      consumedOrganizationSignatures.add(event.approval.signature);
      registration.organizationActive = true;
      registration.organizationActivatedAt = occurredAt;
      registration.evidenceEventIds = Object.freeze([...registration.evidenceEventIds, event.eventId]);
    } else if (event.type === "challenge_opened") {
      await verifyChallengeEventSignature(event, subjects);
      const priorChallenge = challengeOpenedAt.get(event.conflictId);
      if (priorChallenge === undefined || occurredAt < priorChallenge) challengeOpenedAt.set(event.conflictId, occurredAt);
      const existing = conflicts.get(event.conflictId);
      if (existing) {
        const ids = new Set(existing.registrationIds);
        if (!ids.has(event.challengedRegistrationId) || !ids.has(event.challengerRegistrationId)) {
          throw new Error("challenge registrations do not match the existing conflict");
        }
        if (existing.status === "resolved") throw new Error("resolved conflict cannot be reopened");
        conflicts.set(event.conflictId, { ...existing, eventIds: [...existing.eventIds, event.eventId] });
      } else {
        const challenged = subjects[event.challengedRegistrationId];
        const challenger = subjects[event.challengerRegistrationId];
        conflicts.set(event.conflictId, {
          conflictId: event.conflictId,
          artifactHash: challenged.artifactHash === challenger.artifactHash ? challenged.artifactHash : null,
          registrationIds: [event.challengedRegistrationId, event.challengerRegistrationId].sort(),
          status: "open",
          reason: event.reason,
          outcome: null,
          eventIds: [event.eventId],
        });
      }
    } else if (event.type === "challenge_resolved") {
      await verifyAdminEventSignature(event, trust.adminSigners ?? {});
      const conflict = conflicts.get(event.conflictId);
      if (!conflict) throw new Error("resolution targets an unknown conflict");
      const openedAt = challengeOpenedAt.get(event.conflictId);
      if (openedAt === undefined) throw new Error("resolution requires a preceding signed challenge");
      if (occurredAt < openedAt) throw new Error("resolution must follow its signed challenge");
      if (conflict.status === "resolved") throw new Error("conflict is already resolved");
      conflicts.set(event.conflictId, { ...conflict, status: "resolved", outcome: event.outcome, eventIds: [...conflict.eventIds, event.eventId] });
    } else {
      await verifyAdminEventSignature(event, trust.adminSigners ?? {});
      const registration = registrations[event.registrationId];
      if (!registration) throw new Error("revocation targets an unknown registration");
      if (event.level === "repository_control_verified") {
        if (!registration.repositoryActive) throw new Error("repository evidence is not active");
        if (registration.repositoryActivatedAt === null || occurredAt < registration.repositoryActivatedAt) throw new Error("revocation must follow active repository evidence");
        registration.repositoryActive = false;
        registration.organizationActive = false;
        registration.repositoryActivatedAt = null;
        registration.organizationActivatedAt = null;
        registration.repositoryRevokedAt = occurredAt;
        registration.organizationRevokedAt = occurredAt;
      } else {
        if (!registration.organizationActive) throw new Error("organization evidence is not active");
        if (registration.organizationActivatedAt === null || occurredAt < registration.organizationActivatedAt) throw new Error("revocation must follow active organization evidence");
        registration.organizationActive = false;
        registration.organizationActivatedAt = null;
        registration.organizationRevokedAt = occurredAt;
      }
      registration.revocations = Object.freeze([...registration.revocations, {
        level: event.level,
        eventId: event.eventId,
        occurredAt: event.occurredAt,
        reason: event.reason,
      }]);
    }
  }

  for (const registration of Object.values(registrations)) {
    registration.level = registration.organizationActive
      ? "organization_approved"
      : registration.repositoryActive ? "repository_control_verified" : "wallet_asserted";
    registration.claim = CLAIMS[registration.level];
  }
  for (const conflict of conflicts.values()) {
    if (conflict.status === "open") {
      for (const registrationId of conflict.registrationIds) {
        if (registrations[registrationId]) registrations[registrationId].status = "challenged";
      }
    }
  }

  const publicRegistrations = Object.fromEntries(Object.entries(registrations).map(([id, value]) => {
    const {
      repositoryActive: _repositoryActive,
      organizationActive: _organizationActive,
      repositoryActivatedAt: _repositoryActivatedAt,
      organizationActivatedAt: _organizationActivatedAt,
      repositoryRevokedAt: _repositoryRevokedAt,
      organizationRevokedAt: _organizationRevokedAt,
      ...publicValue
    } = value;
    return [id, deepFreeze(publicValue)];
  }));
  return deepFreeze({
    registrations: publicRegistrations,
    conflicts: [...conflicts.values()].sort((a, b) => a.conflictId.localeCompare(b.conflictId)),
    events: parsedEvents,
  });
}

export function displayAttestation(index: AttestationIndex, registrationId: string): {
  level: AttestationLevel;
  status: AttestationStatus;
  claim: string;
  safetyReviewStatus: SafetyReviewStatus;
  warnings: string[];
} {
  const registration = index.registrations[registrationId];
  if (!registration) throw new Error(`unknown registration ${registrationId}`);
  const warnings = [
    "registration does not prove authorship, originality, legal ownership, or safety",
    `Safety review: ${registration.safetyReviewStatus}; authorship attestation does not prove safety.`,
  ];
  if (registration.level === "repository_control_verified" || registration.level === "organization_approved") {
    warnings.push("Repository evidence relies on the named forge observer and snapshot; it does not prove current remote account ownership or continuing hosting.");
  }
  return deepFreeze({
    level: registration.level,
    status: registration.status,
    claim: registration.claim,
    safetyReviewStatus: registration.safetyReviewStatus,
    warnings,
  });
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { execFile } from "node:child_process";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute } from "node:path";

import {
  canonicalRepositoryStatement,
  normalizeRepositoryUrl,
  parseForgeObservation,
  parseRepositoryChallenge,
  repositoryStatementHash,
  verifyRepositoryEventSignature,
  type ForgeObservationV1,
  type RepositoryControlChallengeV1,
  type RepositoryControlEvent,
} from "./attestations";

export interface GitReader {
  repositoryIdentity(repositoryPath: string): Promise<{ device: number; inode: number }>;
  commitExists(repositoryPath: string, commitSha: string): Promise<boolean>;
  readBlob(repositoryPath: string, commitSha: string, relativePath: string): Promise<Uint8Array>;
  isAncestor(repositoryPath: string, ancestor: string, descendant: string): Promise<boolean>;
  remoteUrl(repositoryPath: string, remoteName: string): Promise<string>;
}

export interface TrustedRepository {
  repositoryId: string;
  repositoryUrl: string;
  repositoryPath: string;
  repositoryDevice: number;
  repositoryInode: number;
  trustedRef: `refs/heads/${string}` | `refs/remotes/${string}`;
  permittedForgeSignerIds: readonly string[];
}

export interface TrustedRepositoryResolver {
  resolve(repositoryId: string, normalizedRepositoryUrl: string): TrustedRepository;
}

export interface SignedRepositoryChallengeFileV1 {
  challenge: RepositoryControlChallengeV1;
  statementHash: `0x${string}`;
  signature: `0x${string}`;
}

const MINIMAL_GIT_ENVIRONMENT = Object.freeze({
  LANG: "C",
  LC_ALL: "C",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_COUNT: "0",
  GIT_ATTR_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0",
  GIT_NO_REPLACE_OBJECTS: "1",
  GIT_NO_LAZY_FETCH: "1",
});

const SAFE_GIT_CONFIG = [
  "-c", "protocol.allow=never",
  "-c", "core.fsmonitor=false",
  "-c", "maintenance.auto=false",
] as const;

function runGit(executable: string, args: readonly string[]): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    execFile(executable, [...SAFE_GIT_CONFIG, ...args], {
      encoding: "buffer",
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      env: MINIMAL_GIT_ENVIRONMENT,
    }, (error, stdout, stderr) => {
      if (error) {
        const detail = Buffer.from(stderr).toString("utf8").trim();
        reject(new Error(`offline Git verification failed${detail ? `: ${detail}` : ""}`, { cause: error }));
        return;
      }
      resolve(new Uint8Array(stdout));
    });
  });
}

function validRepositoryPath(value: string): void {
  if (!value || !value.startsWith("/") || value.includes("\0")) {
    throw new Error("trusted repository path must be an absolute path");
  }
}

function validObjectName(value: string, label: string): "commit" | "ref" {
  if (/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) return "commit";
  if (!/^refs\/(?:heads|remotes)\/[A-Za-z0-9._\/-]+$/.test(value) || value.includes("..")) {
    throw new Error(`${label} is not a full commit OID or configured trusted ref`);
  }
  return "ref";
}

function validRelativePath(value: string): void {
  if (!value || value.startsWith("/") || value.includes("\\") || value.includes("\0")) {
    throw new Error("Git blob path must be a normalized relative POSIX path");
  }
  if (value.split("/").some((segment) => segment === "" || segment === "." || segment === "..")) {
    throw new Error("Git blob path must be a normalized relative POSIX path");
  }
}

export class ExecGitReader implements GitReader {
  private readonly gitExecutable: string;

  constructor(options: { gitExecutable?: string } = {}) {
    this.gitExecutable = options.gitExecutable ?? "/usr/bin/git";
    if (!isAbsolute(this.gitExecutable)) throw new Error("an absolute Git executable path is required");
  }

  private run(args: readonly string[]): Promise<Uint8Array> {
    return runGit(this.gitExecutable, args);
  }

  private async resolvesToExactCommitOid(repositoryPath: string, commitOid: string): Promise<boolean> {
    try {
      const resolved = await this.run(["-C", repositoryPath, "rev-parse", "--verify", `${commitOid}^{commit}`]);
      return Buffer.from(resolved).toString("ascii").trim() === commitOid;
    } catch (error) {
      const cause = (error as Error & { cause?: { code?: string | number } }).cause;
      if (cause && typeof cause.code === "number") return false;
      throw error;
    }
  }

  async repositoryIdentity(repositoryPath: string): Promise<{ device: number; inode: number }> {
    validRepositoryPath(repositoryPath);
    const handle = await open(repositoryPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try {
      const metadata = await handle.stat();
      if (!metadata.isDirectory() || !Number.isSafeInteger(metadata.dev) || !Number.isSafeInteger(metadata.ino)) {
        throw new Error("trusted repository filesystem identity is unavailable");
      }
      return { device: metadata.dev, inode: metadata.ino };
    } finally {
      await handle.close();
    }
  }

  async commitExists(repositoryPath: string, commitSha: string): Promise<boolean> {
    validRepositoryPath(repositoryPath);
    const kind = validObjectName(commitSha, "Git commit");
    if (kind === "commit") return this.resolvesToExactCommitOid(repositoryPath, commitSha);
    try {
      await this.run(["-C", repositoryPath, "cat-file", "-e", `${commitSha}^{commit}`]);
      return true;
    } catch (error) {
      const cause = (error as Error & { cause?: { code?: string | number } }).cause;
      if (cause && typeof cause.code === "number") return false;
      throw error;
    }
  }

  async readBlob(repositoryPath: string, commitSha: string, relativePath: string): Promise<Uint8Array> {
    validRepositoryPath(repositoryPath);
    const kind = validObjectName(commitSha, "Git commit");
    if (kind !== "commit" || !await this.resolvesToExactCommitOid(repositoryPath, commitSha)) {
      throw new Error("Git blob commit is absent or not an exact full commit OID for this repository");
    }
    validRelativePath(relativePath);
    return this.run(["-C", repositoryPath, "show", `${commitSha}:${relativePath}`]);
  }

  async isAncestor(repositoryPath: string, ancestor: string, descendant: string): Promise<boolean> {
    validRepositoryPath(repositoryPath);
    const ancestorKind = validObjectName(ancestor, "Git ancestor");
    const descendantKind = validObjectName(descendant, "Git descendant");
    if (ancestorKind === "commit" && !await this.resolvesToExactCommitOid(repositoryPath, ancestor)) return false;
    if (descendantKind === "commit" && !await this.resolvesToExactCommitOid(repositoryPath, descendant)) return false;
    try {
      await this.run(["-C", repositoryPath, "merge-base", "--is-ancestor", ancestor, descendant]);
      return true;
    } catch (error) {
      const cause = (error as Error & { cause?: { code?: string | number } }).cause;
      if (cause?.code === 1) return false;
      throw error;
    }
  }

  async remoteUrl(repositoryPath: string, remoteName: string): Promise<string> {
    validRepositoryPath(repositoryPath);
    if (remoteName !== "origin") throw new Error("only the configured origin remote may be verified");
    const bytes = await this.run(["-C", repositoryPath, "remote", "get-url", remoteName]);
    return Buffer.from(bytes).toString("utf8").trim();
  }
}

export function canonicalChallengeFileBytes(input: SignedRepositoryChallengeFileV1): Uint8Array {
  const challenge = parseRepositoryChallenge(input.challenge);
  if (!/^0x[0-9a-f]{64}$/.test(input.statementHash)) throw new Error("challenge file statementHash must be lowercase");
  if (!/^0x(?:[0-9a-fA-F]{2})+$/.test(input.signature)) throw new Error("challenge file signature is malformed");
  const canonical = {
    challenge: {
      schemaVersion: challenge.schemaVersion,
      subject: {
        registrationId: challenge.subject.registrationId,
        ipId: challenge.subject.ipId,
        wallet: challenge.subject.wallet,
        artifactHash: challenge.subject.artifactHash,
        declaredParentIpIds: [...challenge.subject.declaredParentIpIds],
      },
      repositoryUrl: challenge.repositoryUrl,
      artifactCommitSha: challenge.artifactCommitSha,
      artifactPath: challenge.artifactPath,
      challengePath: challenge.challengePath,
      nonce: challenge.nonce,
      issuedAt: challenge.issuedAt,
      expiresAt: challenge.expiresAt,
    },
    statementHash: input.statementHash,
    signature: input.signature,
  };
  return Buffer.from(`${JSON.stringify(canonical)}\n`, "utf8");
}

export function parseSignedRepositoryChallengeFile(bytes: Uint8Array): SignedRepositoryChallengeFileV1 {
  const text = Buffer.from(bytes).toString("utf8");
  if (!text.endsWith("\n") || text.endsWith("\n\n") || text.slice(0, -1).includes("\n")) {
    throw new Error("repository challenge file must be canonical single-line JSON with exactly one trailing newline");
  }
  let value: unknown;
  try { value = JSON.parse(text); } catch (error) { throw new Error("repository challenge file contains malformed JSON", { cause: error }); }
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("repository challenge file must be an object");
  const object = value as Record<string, unknown>;
  const keys = Object.keys(object);
  if (keys.length !== 3 || keys[0] !== "challenge" || keys[1] !== "statementHash" || keys[2] !== "signature") {
    throw new Error("repository challenge file fields are missing, extra, or out of canonical order");
  }
  if (typeof object.statementHash !== "string" || typeof object.signature !== "string") throw new Error("repository challenge file signature fields are malformed");
  const parsed: SignedRepositoryChallengeFileV1 = {
    challenge: parseRepositoryChallenge(object.challenge),
    statementHash: object.statementHash as `0x${string}`,
    signature: object.signature as `0x${string}`,
  };
  const canonical = canonicalChallengeFileBytes(parsed);
  if (!Buffer.from(canonical).equals(Buffer.from(bytes))) throw new Error("repository challenge file is not canonical byte-for-byte");
  if (parsed.statementHash !== repositoryStatementHash(parsed.challenge)) throw new Error("repository challenge statement hash mismatch");
  return parsed;
}

export function canonicalForgeObservationBytes(
  observationValue: Omit<ForgeObservationV1, "signature">,
): Uint8Array {
  const observation = parseForgeObservation({ ...observationValue, signature: "placeholder" });
  const canonical = {
    schemaVersion: observation.schemaVersion,
    repositoryId: observation.repositoryId,
    repositoryUrl: observation.repositoryUrl,
    trustedRef: observation.trustedRef,
    proofCommitSha: observation.proofCommitSha,
    challengeNonce: observation.challengeNonce,
    observedAt: observation.observedAt,
    forgeSignerId: observation.forgeSignerId,
  };
  return Buffer.from(`${JSON.stringify(canonical)}\n`, "utf8");
}

export function normalizeForgePublicKey(value: unknown): string {
  const message = "forge signer public key must be exactly one canonical Ed25519 SPKI public key";
  if (typeof value !== "string") throw new Error(message);
  let publicKey;
  try {
    publicKey = createPublicKey(value);
  } catch (error) {
    throw new Error(message, { cause: error });
  }
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") {
    throw new Error(message);
  }
  const canonical = publicKey.export({ type: "spki", format: "pem" }).toString();
  if (value !== canonical) throw new Error(message);
  return canonical;
}

export function snapshotForgeSignerTrust(value: unknown): Readonly<Record<string, string>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("forge signer trust must be a plain or null-prototype record");
  }
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error("forge signer trust must be a plain or null-prototype record");
  }
  const snapshot: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== "string" || !/^[a-z0-9][a-z0-9._-]{0,127}$/.test(key)) {
      throw new Error("forge signer trust must use only string identifier keys");
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) {
      throw new Error("forge signer trust entries must be own enumerable data properties");
    }
    snapshot[key] = normalizeForgePublicKey(descriptor.value);
  }
  return Object.freeze(snapshot);
}

export function verifyForgeObservation(
  observationValue: ForgeObservationV1,
  trusted: TrustedRepository,
  forgeSigners: Readonly<Record<string, string>>,
): void {
  const observation = parseForgeObservation(observationValue);
  const trustedForgeSigners = snapshotForgeSignerTrust(forgeSigners);
  if (observation.repositoryId !== trusted.repositoryId
      || observation.repositoryUrl !== trusted.repositoryUrl
      || observation.trustedRef !== trusted.trustedRef) {
    throw new Error("forge observation does not match verifier-provisioned repository trust");
  }
  if (!trusted.permittedForgeSignerIds.includes(observation.forgeSignerId)) {
    throw new Error("forge signer is not permitted for this repository");
  }
  if (!Object.hasOwn(trustedForgeSigners, observation.forgeSignerId)) {
    throw new Error("forge signer is unknown; signer ID must be an own property of the trust map");
  }
  const canonicalPublicKey = trustedForgeSigners[observation.forgeSignerId];
  let signatureBytes: Buffer;
  try {
    signatureBytes = Buffer.from(observation.signature, "base64");
  } catch (error) {
    throw new Error("forge observation signature must be base64", { cause: error });
  }
  if (signatureBytes.length !== 64 || signatureBytes.toString("base64") !== observation.signature) {
    throw new Error("forge observation signature must be canonical base64 encoding of exactly 64 bytes");
  }
  const { signature: _signature, ...unsigned } = observation;
  if (!verifySignature(null, canonicalForgeObservationBytes(unsigned), canonicalPublicKey, signatureBytes)) {
    throw new Error("forge observation signature is invalid");
  }
}

function sha256(bytes: Uint8Array): `0x${string}` {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

async function assertTrustedRepositoryIdentity(git: GitReader, trusted: TrustedRepository): Promise<void> {
  const identity = await git.repositoryIdentity(trusted.repositoryPath);
  if (identity.device !== trusted.repositoryDevice || identity.inode !== trusted.repositoryInode) {
    throw new Error("trusted repository checkout filesystem identity changed during verification");
  }
}

async function verifyRepositorySnapshot(input: {
  event: RepositoryControlEvent;
  challengeFile: Uint8Array;
  now: Date;
  git: GitReader;
  repositories: TrustedRepositoryResolver;
  forgeSigners: Readonly<Record<string, string>>;
}): Promise<void> {
  const { event, now, git, repositories, forgeSigners } = input;
  await verifyRepositoryEventSignature(event);
  const signed = parseSignedRepositoryChallengeFile(input.challengeFile);
  if (signed.statementHash !== event.statementHash || signed.signature !== event.signature
      || JSON.stringify(signed.challenge) !== JSON.stringify(event.challenge)) {
    throw new Error("repository event does not match the exact signed challenge file");
  }
  const trusted = repositories.resolve(event.forgeObservation.repositoryId, event.challenge.repositoryUrl);
  verifyForgeObservation(event.forgeObservation, trusted, forgeSigners);
  if (event.forgeObservation.challengeNonce !== event.challenge.nonce) throw new Error("forge observation nonce mismatch");
  const issuedAt = Date.parse(event.challenge.issuedAt);
  const expiresAt = Date.parse(event.challenge.expiresAt);
  const observedAt = Date.parse(event.forgeObservation.observedAt);
  const occurredAt = Date.parse(event.occurredAt);
  if (observedAt < issuedAt || observedAt > expiresAt) throw new Error("repository challenge was not valid at observation time");
  if (occurredAt < observedAt) throw new Error("repository event occurred before the forge observation");
  if (occurredAt > now.getTime() || observedAt > now.getTime()) throw new Error("repository evidence is dated in the future");

  await assertTrustedRepositoryIdentity(git, trusted);
  const origin = normalizeRepositoryUrl(await git.remoteUrl(trusted.repositoryPath, "origin"));
  await assertTrustedRepositoryIdentity(git, trusted);
  if (origin !== trusted.repositoryUrl || origin !== event.challenge.repositoryUrl || origin !== event.forgeObservation.repositoryUrl) {
    throw new Error("trusted checkout origin does not match signed repository URL");
  }
  if (!await git.commitExists(trusted.repositoryPath, event.challenge.artifactCommitSha)) throw new Error("artifact commit is absent");
  await assertTrustedRepositoryIdentity(git, trusted);
  if (!await git.commitExists(trusted.repositoryPath, event.forgeObservation.proofCommitSha)) throw new Error("proof commit is absent");
  await assertTrustedRepositoryIdentity(git, trusted);
  if (!await git.commitExists(trusted.repositoryPath, trusted.trustedRef)) throw new Error("configured trusted ref is absent");
  await assertTrustedRepositoryIdentity(git, trusted);
  if (!await git.isAncestor(trusted.repositoryPath, event.challenge.artifactCommitSha, event.forgeObservation.proofCommitSha)) {
    throw new Error("proof commit does not descend from artifact commit");
  }
  await assertTrustedRepositoryIdentity(git, trusted);
  if (!await git.isAncestor(trusted.repositoryPath, event.forgeObservation.proofCommitSha, trusted.trustedRef)) {
    throw new Error("proof commit is not reachable from the configured trusted ref");
  }
  await assertTrustedRepositoryIdentity(git, trusted);
  const artifact = await git.readBlob(trusted.repositoryPath, event.challenge.artifactCommitSha, event.challenge.artifactPath);
  await assertTrustedRepositoryIdentity(git, trusted);
  if (sha256(artifact) !== event.subject.artifactHash) throw new Error("registered artifact hash does not match exact Git bytes");
  const challengeBlob = await git.readBlob(trusted.repositoryPath, event.forgeObservation.proofCommitSha, event.challenge.challengePath);
  await assertTrustedRepositoryIdentity(git, trusted);
  if (!Buffer.from(challengeBlob).equals(Buffer.from(input.challengeFile))) throw new Error("committed challenge bytes do not match the signed challenge file");
}

export async function verifyRepositoryControl(input: {
  challengeFile: Uint8Array;
  forgeObservation: ForgeObservationV1;
  eventId: string;
  sequence: number;
  occurredAt: string;
  now: Date;
  git: GitReader;
  repositories: TrustedRepositoryResolver;
  forgeSigners: Readonly<Record<string, string>>;
}): Promise<RepositoryControlEvent> {
  const signed = parseSignedRepositoryChallengeFile(input.challengeFile);
  const event: RepositoryControlEvent = {
    type: "repository_control_verified",
    eventId: input.eventId,
    sequence: input.sequence,
    occurredAt: input.occurredAt,
    subject: signed.challenge.subject,
    challenge: signed.challenge,
    forgeObservation: parseForgeObservation(input.forgeObservation),
    statementHash: signed.statementHash,
    signature: signed.signature,
  };
  await verifyRepositorySnapshot({ ...input, event });
  return event;
}

export async function reverifyRepositoryEvent(
  event: RepositoryControlEvent,
  context: {
    git: GitReader;
    repositories: TrustedRepositoryResolver;
    forgeSigners: Readonly<Record<string, string>>;
    now?: Date;
  },
): Promise<void> {
  const challengeFile = canonicalChallengeFileBytes({
    challenge: event.challenge,
    statementHash: event.statementHash,
    signature: event.signature,
  });
  await verifyRepositorySnapshot({ event, challengeFile, now: context.now ?? new Date(), ...context });
}

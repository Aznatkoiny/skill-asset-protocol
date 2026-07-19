import { createHash, randomBytes, randomUUID } from "node:crypto";
import {
  link,
  mkdir,
  open,
  rename,
  stat,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { hostname as localHostname } from "node:os";
import { dirname } from "node:path";
import { keccak256, type Hex } from "viem";

export type OperationStage = "collection" | "root" | "child" | "grandchild";
export type OperationState = "prepared" | "broadcast";

export interface CanonicalOperationIntent {
  stage: OperationStage;
  chainId: 1315;
  wallet: `0x${string}`;
  registrationName: string | null;
  artifactPath: string | null;
  spgNftContract: `0x${string}` | null;
  parentIpId: `0x${string}` | null;
  licenseTermsId: string | null;
  licenseTemplate: `0x${string}` | null;
  currencyToken: `0x${string}` | null;
  defaultMintingFee: string | null;
  maxMintingFee: string | null;
  metadata: {
    ipMetadataURI: string;
    ipMetadataHash: `0x${string}`;
    nftMetadataURI: string;
    nftMetadataHash: `0x${string}`;
    artifactMediaHash: `0x${string}`;
    artifactMediaType: string;
  } | null;
  runConfigHash: `0x${string}`;
}

export interface CanonicalRunConfigStage {
  stage: Exclude<OperationStage, "collection">;
  name: string;
  description: string;
  artifactPath: string;
  artifactSha256: `0x${string}`;
}

export interface CanonicalRunConfig {
  chainId: 1315;
  wallet: `0x${string}`;
  stages: readonly CanonicalRunConfigStage[];
}

export interface PendingOperation {
  schemaVersion: 1;
  operationId: string;
  stage: OperationStage;
  intent: CanonicalOperationIntent;
  intentHash: `0x${string}`;
  transactionHash: `0x${string}`;
  serializedTransaction: `0x${string}`;
  state: OperationState;
}

export interface JournalSnapshot {
  revision: number;
  operation: PendingOperation | null;
}

export interface LeasedOperationJournal {
  load(): Promise<JournalSnapshot>;
  save(operation: PendingOperation, expectedRevision: number): Promise<JournalSnapshot>;
  clear(operationId: string, expectedRevision: number): Promise<JournalSnapshot>;
}

export interface OperationJournal {
  withExclusiveLease<T>(callback: (journal: LeasedOperationJournal) => Promise<T>): Promise<T>;
}

interface JournalFile {
  schemaVersion: 1;
  revision: number;
  operation: PendingOperation | null;
}

interface LeaseOwner {
  leaseId: string;
  hostname: string;
  pid: number;
  startedAtUtc: string;
}

interface TransactionJournalTestDependencies {
  afterTemporarySync?(): void | Promise<void>;
  afterLeaseClaim?(candidatePath: string): void | Promise<void>;
  /** Test-only dependency seam; production construction omits this. */
  isProcessAlive?(pid: number): boolean | Promise<boolean>;
}

export interface StaleLockRecoveryInput {
  expectedLeaseId: string;
}

const OPERATION_STAGES = new Set<OperationStage>(["collection", "root", "child", "grandchild"]);
const OPERATION_STATES = new Set<OperationState>(["prepared", "broadcast"]);
const HASH_32 = /^0x[0-9a-f]{64}$/;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const SERIALIZED_TRANSACTION = /^0x(?:[0-9a-fA-F]{2})+$/;
const LEASE_ID = /^[0-9a-f]{32}$/;
const DECIMAL_INTEGER = /^(?:0|[1-9][0-9]*)$/;

const INTENT_KEYS = [
  "stage",
  "chainId",
  "wallet",
  "registrationName",
  "artifactPath",
  "spgNftContract",
  "parentIpId",
  "licenseTermsId",
  "licenseTemplate",
  "currencyToken",
  "defaultMintingFee",
  "maxMintingFee",
  "metadata",
  "runConfigHash",
] as const;

const METADATA_KEYS = [
  "ipMetadataURI",
  "ipMetadataHash",
  "nftMetadataURI",
  "nftMetadataHash",
  "artifactMediaHash",
  "artifactMediaType",
] as const;

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new Error(`${label} has unexpected, missing, or non-canonical fields`);
  }
}

function requireNonemptyString(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} must be a nonempty string`);
  }
}

function requireNullableString(value: unknown, label: string): asserts value is string | null {
  if (value !== null) requireNonemptyString(value, label);
}

function requireHash(value: unknown, label: string): asserts value is `0x${string}` {
  if (typeof value !== "string" || !HASH_32.test(value)) {
    throw new Error(`${label} must be a lowercase 32-byte hash`);
  }
}

function requireAddress(value: unknown, label: string): asserts value is `0x${string}` {
  if (typeof value !== "string" || !ADDRESS.test(value)) {
    throw new Error(`${label} must be a 20-byte address`);
  }
}

function requireNullableAddress(value: unknown, label: string): asserts value is `0x${string}` | null {
  if (value !== null) requireAddress(value, label);
}

function requireNullableDecimal(value: unknown, label: string): asserts value is string | null {
  if (value !== null && (typeof value !== "string" || !DECIMAL_INTEGER.test(value))) {
    throw new Error(`${label} must be a non-negative decimal integer string or null`);
  }
}

function validateMetadata(value: unknown): void {
  const metadata = asRecord(value, "Pending operation metadata");
  requireExactKeys(metadata, METADATA_KEYS, "Pending operation metadata");
  requireNonemptyString(metadata.ipMetadataURI, "IP metadata URI");
  requireHash(metadata.ipMetadataHash, "IP metadata hash");
  requireNonemptyString(metadata.nftMetadataURI, "NFT metadata URI");
  requireHash(metadata.nftMetadataHash, "NFT metadata hash");
  requireHash(metadata.artifactMediaHash, "Artifact media hash");
  requireNonemptyString(metadata.artifactMediaType, "Artifact media type");
}

function validateCanonicalIntent(value: unknown): asserts value is CanonicalOperationIntent {
  const intent = asRecord(value, "Pending operation intent");
  requireExactKeys(intent, INTENT_KEYS, "Pending operation intent");
  if (typeof intent.stage !== "string" || !OPERATION_STAGES.has(intent.stage as OperationStage)) {
    throw new Error("Pending operation intent stage is invalid");
  }
  if (intent.chainId !== 1315) throw new Error("Pending operation intent must target Story Aeneid (1315)");
  requireAddress(intent.wallet, "Pending operation wallet");
  requireNullableString(intent.registrationName, "Pending operation registration name");
  requireNullableString(intent.artifactPath, "Pending operation artifact path");
  requireNullableAddress(intent.spgNftContract, "Pending operation SPG collection");
  requireNullableAddress(intent.parentIpId, "Pending operation parent IP");
  requireNullableDecimal(intent.licenseTermsId, "Pending operation license terms ID");
  requireNullableAddress(intent.licenseTemplate, "Pending operation license template");
  requireNullableAddress(intent.currencyToken, "Pending operation currency token");
  requireNullableDecimal(intent.defaultMintingFee, "Pending operation default minting fee");
  requireNullableDecimal(intent.maxMintingFee, "Pending operation maximum minting fee");
  requireHash(intent.runConfigHash, "Pending operation run-config hash");

  if (intent.stage === "collection") {
    if (intent.registrationName !== null || intent.artifactPath !== null || intent.metadata !== null) {
      throw new Error("Collection intent must not contain registration or metadata fields");
    }
  } else {
    requireNonemptyString(intent.registrationName, "Pending operation registration name");
    requireNonemptyString(intent.artifactPath, "Pending operation artifact path");
    if (intent.metadata === null) throw new Error("Registration intent must contain metadata");
    validateMetadata(intent.metadata);
    requireAddress(intent.spgNftContract, "Pending operation SPG collection");
    if (intent.stage === "root") {
      if (intent.parentIpId !== null) throw new Error("Root intent must not contain a parent IP");
    } else {
      requireAddress(intent.parentIpId, "Derivative parent IP");
      requireNullableDecimal(intent.licenseTermsId, "Derivative license terms ID");
      if (intent.licenseTermsId === null) throw new Error("Derivative intent must contain a license terms ID");
      requireAddress(intent.licenseTemplate, "Derivative license template");
      requireAddress(intent.currencyToken, "Derivative currency token");
      if (intent.maxMintingFee === null) throw new Error("Derivative intent must contain a maximum minting fee");
    }
  }
}

function validatePendingOperation(value: unknown): asserts value is PendingOperation {
  const operation = asRecord(value, "Pending operation");
  requireExactKeys(
    operation,
    [
      "schemaVersion",
      "operationId",
      "stage",
      "intent",
      "intentHash",
      "transactionHash",
      "serializedTransaction",
      "state",
    ],
    "Pending operation",
  );
  if (operation.schemaVersion !== 1) throw new Error("Pending operation schema version must be 1");
  requireNonemptyString(operation.operationId, "Pending operation ID");
  if (typeof operation.stage !== "string" || !OPERATION_STAGES.has(operation.stage as OperationStage)) {
    throw new Error("Pending operation stage is invalid");
  }
  validateCanonicalIntent(operation.intent);
  if (operation.intent.stage !== operation.stage) {
    throw new Error("Pending operation stage does not match its intent stage");
  }
  requireHash(operation.intentHash, "Pending operation intent hash");
  const expectedIntentHash = operationIntentHash(operation.intent);
  if (operation.intentHash !== expectedIntentHash) {
    throw new Error("Pending operation intent hash does not match its canonical intent");
  }
  requireHash(operation.transactionHash, "Pending operation transaction hash");
  if (typeof operation.serializedTransaction !== "string"
      || !SERIALIZED_TRANSACTION.test(operation.serializedTransaction)) {
    throw new Error("Pending operation serialized transaction must be nonempty, even-length hex bytes");
  }
  const expectedTransactionHash = keccak256(operation.serializedTransaction as Hex);
  if (operation.transactionHash !== expectedTransactionHash) {
    throw new Error("Pending operation transaction hash does not match the serialized transaction");
  }
  if (typeof operation.state !== "string" || !OPERATION_STATES.has(operation.state as OperationState)) {
    throw new Error("Pending operation state is invalid");
  }
}

function validateJournalFile(value: unknown): asserts value is JournalFile {
  const journal = asRecord(value, "Pending transaction journal");
  requireExactKeys(journal, ["schemaVersion", "revision", "operation"], "Pending transaction journal");
  if (journal.schemaVersion !== 1) throw new Error("Pending transaction journal schema version must be 1");
  if (!Number.isSafeInteger(journal.revision) || (journal.revision as number) < 0) {
    throw new Error("Pending transaction journal revision must be a non-negative safe integer");
  }
  if (journal.operation !== null) validatePendingOperation(journal.operation);
}

function validateExpectedRevision(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("Expected journal revision must be a non-negative safe integer");
  }
}

function canonicalHash(value: unknown): `0x${string}` {
  const canonical = JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? { $bigint: item.toString() } : item,
  );
  if (canonical === undefined) throw new Error("Canonical hash input is not serializable");
  return `0x${createHash("sha256").update(canonical).digest("hex")}`;
}

export function operationIntentHash(value: unknown): `0x${string}` {
  return canonicalHash(value);
}

export function runConfigHash(value: CanonicalRunConfig): `0x${string}` {
  const config = asRecord(value, "Run configuration");
  requireExactKeys(config, ["chainId", "wallet", "stages"], "Run configuration");
  if (config.chainId !== 1315) throw new Error("Run configuration must target Story Aeneid (1315)");
  requireAddress(config.wallet, "Run-configuration wallet");
  if (!Array.isArray(config.stages) || config.stages.length !== 3) {
    throw new Error("Run configuration must contain root, child, and grandchild stages");
  }
  const expectedStages = ["root", "child", "grandchild"] as const;
  config.stages.forEach((value, index) => {
    const stage = asRecord(value, `Run-configuration ${expectedStages[index]} stage`);
    requireExactKeys(
      stage,
      ["stage", "name", "description", "artifactPath", "artifactSha256"],
      `Run-configuration ${expectedStages[index]} stage`,
    );
    if (stage.stage !== expectedStages[index]) {
      throw new Error(`Run configuration stage ${index + 1} must be ${expectedStages[index]}`);
    }
    requireNonemptyString(stage.name, "Run-configuration stage name");
    requireNonemptyString(stage.description, "Run-configuration stage description");
    requireNonemptyString(stage.artifactPath, "Run-configuration artifact path");
    requireHash(stage.artifactSha256, "Run-configuration artifact SHA-256");
  });
  return canonicalHash(value);
}

async function writeAll(handle: FileHandle, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.byteLength - offset) {
      throw new Error("Journal write made no progress or returned an invalid byte count");
    }
    offset += bytesWritten;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function parseJson(bytes: string, label: string): unknown {
  if (!bytes.endsWith("\n")) throw new Error(`${label} must end with one newline`);
  try {
    return JSON.parse(bytes);
  } catch (error) {
    throw new Error(`${label} contains malformed JSON`, { cause: error });
  }
}

function validateLeaseOwner(value: unknown): asserts value is LeaseOwner {
  const owner = asRecord(value, "Pending transaction journal lock owner");
  requireExactKeys(owner, ["leaseId", "hostname", "pid", "startedAtUtc"], "Pending transaction journal lock owner");
  if (typeof owner.leaseId !== "string" || !LEASE_ID.test(owner.leaseId)) {
    throw new Error("Pending transaction journal lock owner lease ID is malformed");
  }
  requireNonemptyString(owner.hostname, "Pending transaction journal lock owner hostname");
  if (!Number.isSafeInteger(owner.pid) || (owner.pid as number) <= 0) {
    throw new Error("Pending transaction journal lock owner PID is malformed");
  }
  if (typeof owner.startedAtUtc !== "string"
      || Number.isNaN(Date.parse(owner.startedAtUtc))
      || new Date(owner.startedAtUtc).toISOString() !== owner.startedAtUtc) {
    throw new Error("Pending transaction journal lock owner start time is malformed");
  }
}

async function readPrivateFile(path: string, label: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const fileStat = await handle.stat();
    if ((fileStat.mode & 0o777) !== 0o600) {
      throw new Error(`${label} must have mode 0600 before it can be read`);
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

async function processIsAlive(pid: number): Promise<boolean> {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ESRCH") return false;
    if (code === "EPERM") {
      throw new Error(`Cannot prove PID ${pid} is absent: process probe returned EPERM`, { cause: error });
    }
    throw new Error(`Cannot prove PID ${pid} is absent: process probe failed`, { cause: error });
  }
}

class FileLeasedOperationJournal implements LeasedOperationJournal {
  constructor(
    private readonly owner: FileOperationJournal,
    private readonly leaseId: string,
  ) {}

  load(): Promise<JournalSnapshot> {
    return this.owner.loadUnderLease(this.leaseId);
  }

  save(operation: PendingOperation, expectedRevision: number): Promise<JournalSnapshot> {
    return this.owner.saveUnderLease(this.leaseId, operation, expectedRevision);
  }

  clear(operationId: string, expectedRevision: number): Promise<JournalSnapshot> {
    return this.owner.clearUnderLease(this.leaseId, operationId, expectedRevision);
  }
}

export class FileOperationJournal implements OperationJournal {
  readonly path: string;
  readonly lockPath: string;

  constructor(path: string, private readonly hooks: TransactionJournalTestDependencies = {}) {
    if (!path) throw new Error("Pending transaction journal path is required");
    this.path = path;
    this.lockPath = `${path}.lock`;
  }

  async withExclusiveLease<T>(callback: (journal: LeasedOperationJournal) => Promise<T>): Promise<T> {
    await mkdir(dirname(this.path), { recursive: true });
    const owner: LeaseOwner = {
      leaseId: randomBytes(16).toString("hex"),
      hostname: localHostname(),
      pid: process.pid,
      startedAtUtc: new Date().toISOString(),
    };
    await this.acquireLease(owner);
    try {
      return await callback(new FileLeasedOperationJournal(this, owner.leaseId));
    } finally {
      await this.releaseLease(owner);
    }
  }

  async recoverStaleLock(input: StaleLockRecoveryInput): Promise<void> {
    if (!LEASE_ID.test(input.expectedLeaseId)) {
      throw new Error("Expected stale-lock lease ID must be exactly 128 lowercase bits");
    }
    const initial = await this.readLeaseOwner();
    if (initial.owner.leaseId !== input.expectedLeaseId) {
      throw new Error(
        `Recorded lease ID ${initial.owner.leaseId} does not match expected lease ID ${input.expectedLeaseId}`,
      );
    }
    if (initial.owner.hostname !== localHostname()) {
      throw new Error(
        `Pending transaction journal lock belongs to different host ${initial.owner.hostname}; current host is ${localHostname()}`,
      );
    }
    const alive = await (this.hooks.isProcessAlive ?? processIsAlive)(initial.owner.pid);
    if (typeof alive !== "boolean") {
      throw new Error(`Cannot prove PID ${initial.owner.pid} is absent: process probe returned no boolean proof`);
    }
    if (alive) {
      throw new Error(`Pending transaction journal lock PID ${initial.owner.pid} is still alive`);
    }

    await this.claimAndRemoveLease({
      expectedLeaseId: input.expectedLeaseId,
      expectedBytes: initial.bytes,
      mismatchMessage: "Pending transaction journal lock owner changed during recovery",
    });
  }

  async loadUnderLease(leaseId: string): Promise<JournalSnapshot> {
    await this.assertLeaseOwned(leaseId);
    return this.loadJournalFile();
  }

  async saveUnderLease(
    leaseId: string,
    operation: PendingOperation,
    expectedRevision: number,
  ): Promise<JournalSnapshot> {
    await this.assertLeaseOwned(leaseId);
    validatePendingOperation(operation);
    validateExpectedRevision(expectedRevision);
    const current = await this.loadJournalFile();
    if (current.revision !== expectedRevision) {
      throw new Error(
        `Pending transaction journal has stale CAS revision ${expectedRevision}; current revision is ${current.revision}`,
      );
    }
    const next = { revision: current.revision + 1, operation } satisfies JournalSnapshot;
    await this.writeJournalFile(next);
    return next;
  }

  async clearUnderLease(
    leaseId: string,
    operationId: string,
    expectedRevision: number,
  ): Promise<JournalSnapshot> {
    await this.assertLeaseOwned(leaseId);
    requireNonemptyString(operationId, "Pending operation ID to clear");
    validateExpectedRevision(expectedRevision);
    const current = await this.loadJournalFile();
    if (current.revision !== expectedRevision) {
      throw new Error(
        `Pending transaction journal has stale CAS revision ${expectedRevision}; current revision is ${current.revision}`,
      );
    }
    if (!current.operation || current.operation.operationId !== operationId) {
      throw new Error(`Pending transaction journal operation ID does not match ${operationId}`);
    }
    const next = { revision: current.revision + 1, operation: null } satisfies JournalSnapshot;
    await this.writeJournalFile(next);
    return next;
  }

  private async acquireLease(owner: LeaseOwner): Promise<void> {
    let handle: FileHandle | null = null;
    let created = false;
    try {
      try {
        handle = await open(this.lockPath, "wx", 0o600);
        created = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await this.readLeaseOwner();
        throw new Error(
          `Pending transaction journal is locked by host ${existing.owner.hostname}, PID ${existing.owner.pid}, lease ${existing.owner.leaseId}`,
          { cause: error },
        );
      }
      const bytes = Buffer.from(`${JSON.stringify(owner)}\n`, "utf8");
      await writeAll(handle, bytes);
      await handle.sync();
      await handle.close();
      handle = null;
      await syncDirectory(dirname(this.lockPath));
    } catch (error) {
      if (handle) await handle.close().catch(() => undefined);
      if (created) await unlink(this.lockPath).catch(() => undefined);
      throw error;
    }
  }

  private async releaseLease(owner: LeaseOwner): Promise<void> {
    await this.claimAndRemoveLease({
      expectedLeaseId: owner.leaseId,
      expectedBytes: `${JSON.stringify(owner)}\n`,
      mismatchMessage: `Pending transaction journal lease CAS failed for ${owner.leaseId}`,
    });
  }

  private async assertLeaseOwned(leaseId: string): Promise<void> {
    const existing = await this.readLeaseOwner();
    if (existing.owner.leaseId !== leaseId) {
      throw new Error("Pending transaction journal lease is no longer owned by this operation");
    }
  }

  private async claimAndRemoveLease(input: {
    expectedLeaseId: string;
    expectedBytes: string;
    mismatchMessage: string;
  }): Promise<void> {
    const candidatePath = `${this.lockPath}.${process.pid}.${randomUUID()}.claim`;
    await rename(this.lockPath, candidatePath);
    await this.hooks.afterLeaseClaim?.(candidatePath);

    let observed: { owner: LeaseOwner; bytes: string } | null = null;
    let validationError: unknown = null;
    try {
      observed = await this.readLeaseOwner(candidatePath);
    } catch (error) {
      validationError = error;
    }

    if (validationError
        || !observed
        || observed.owner.leaseId !== input.expectedLeaseId
        || observed.bytes !== input.expectedBytes) {
      const disposition = await this.restoreOrRetainClaim(candidatePath);
      throw new Error(`${input.mismatchMessage}; claimed owner was ${disposition}`, {
        cause: validationError ?? undefined,
      });
    }

    await unlink(candidatePath);
    await syncDirectory(dirname(this.lockPath));
  }

  private async restoreOrRetainClaim(candidatePath: string): Promise<"restored" | `retained at ${string}`> {
    try {
      await link(candidatePath, this.lockPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        return `retained at ${candidatePath}`;
      }
      throw new Error(`Unable to restore claimed journal lock; retained at ${candidatePath}`, { cause: error });
    }
    await unlink(candidatePath);
    await syncDirectory(dirname(this.lockPath));
    return "restored";
  }

  private async readLeaseOwner(path = this.lockPath): Promise<{ owner: LeaseOwner; bytes: string }> {
    let bytes: string;
    try {
      bytes = await readPrivateFile(path, "Pending transaction journal lock");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        throw new Error("Pending transaction journal lock does not exist", { cause: error });
      }
      throw error;
    }
    let parsed: unknown;
    try {
      parsed = parseJson(bytes, "Pending transaction journal lock owner");
      validateLeaseOwner(parsed);
    } catch (error) {
      throw new Error("Pending transaction journal lock owner is malformed", { cause: error });
    }
    return { owner: parsed, bytes };
  }

  private async loadJournalFile(): Promise<JournalSnapshot> {
    let bytes: string;
    try {
      bytes = await readPrivateFile(this.path, "Pending transaction journal");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return { revision: 0, operation: null };
      }
      throw error;
    }
    const parsed = parseJson(bytes, "Pending transaction journal");
    validateJournalFile(parsed);
    return { revision: parsed.revision, operation: parsed.operation };
  }

  private async writeJournalFile(snapshot: JournalSnapshot): Promise<void> {
    const file: JournalFile = { schemaVersion: 1, ...snapshot };
    validateJournalFile(file);
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const bytes = Buffer.from(`${JSON.stringify(file, null, 2)}\n`, "utf8");
    let handle: FileHandle | null = null;
    let renamed = false;
    try {
      handle = await open(temporaryPath, "wx", 0o600);
      await writeAll(handle, bytes);
      await handle.sync();
      await this.hooks.afterTemporarySync?.();
      await handle.close();
      handle = null;
      await rename(temporaryPath, this.path);
      renamed = true;
      await syncDirectory(dirname(this.path));
      const finalStat = await stat(this.path);
      if ((finalStat.mode & 0o777) !== 0o600) {
        throw new Error("Pending transaction journal must have mode 0600 after its durable write");
      }
    } catch (error) {
      if (handle) await handle.close().catch(() => undefined);
      if (!renamed) await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }
}

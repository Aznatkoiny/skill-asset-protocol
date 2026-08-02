import { randomUUID } from "node:crypto";
import {
  mkdir,
  open,
  readFile,
  rename,
  unlink,
  type FileHandle,
} from "node:fs/promises";
import { dirname } from "node:path";

export const REGISTRATION_SCHEMA_VERSION = 1 as const;
export const AENEID_NETWORK = {
  name: "Story Aeneid",
  chainId: 1315,
} as const;

export type DemoStage = "root" | "child" | "grandchild";
export type ManifestStatus = "not-run" | "partial" | "complete";

export interface MetadataPairProof {
  uri: string;
  hash: `0x${string}`;
}

export interface MetadataProof {
  ip: MetadataPairProof;
  nft: MetadataPairProof;
  artifact: {
    path: string;
    mediaHash: `0x${string}`;
    mediaType: string;
  };
}

export interface RegistrationProof {
  stage: DemoStage;
  kind: "Skill" | "Derivative";
  name: string;
  ipId: `0x${string}`;
  tokenId: string;
  txHash: `0x${string}`;
  licenseTermsId: string;
  licenseTemplate: `0x${string}`;
  parentIpIds: `0x${string}`[];
  defaultMintingFee: string | null;
  maxMintingFee: string | null;
  metadata: MetadataProof;
}

export interface RegistrationManifest {
  schemaVersion: typeof REGISTRATION_SCHEMA_VERSION;
  status: ManifestStatus;
  network: typeof AENEID_NETWORK;
  wallet: `0x${string}` | null;
  spgNftContract: `0x${string}` | null;
  collectionTxHash: `0x${string}` | null;
  registrations: Record<DemoStage, RegistrationProof | null>;
}

export interface RegistrationStore {
  load(): Promise<RegistrationManifest>;
  save(manifest: RegistrationManifest): Promise<void>;
}

export interface ManifestWriteHooks {
  afterTempSync?(): void | Promise<void>;
  afterRename?(): void | Promise<void>;
  afterDirectorySync?(): void | Promise<void>;
}

export function createEmptyRegistrationManifest(): RegistrationManifest {
  return {
    schemaVersion: REGISTRATION_SCHEMA_VERSION,
    status: "not-run",
    network: AENEID_NETWORK,
    wallet: null,
    spgNftContract: null,
    collectionTxHash: null,
    registrations: {
      root: null,
      child: null,
      grandchild: null,
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isAddress(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{40}$/.test(value);
}

function isHash(value: unknown): value is `0x${string}` {
  return typeof value === "string" && /^0x[0-9a-fA-F]{64}$/.test(value);
}

function isDecimal(value: unknown): value is string {
  return typeof value === "string" && /^(0|[1-9][0-9]*)$/.test(value);
}

function requireHttps(value: unknown, path: string): asserts value is string {
  if (typeof value !== "string") throw new Error(`${path} must be an HTTPS URL`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${path} must be an HTTPS URL`);
  }
  if (url.protocol !== "https:") throw new Error(`${path} must be an HTTPS URL`);
}

function validateMetadata(value: unknown, stage: DemoStage): asserts value is MetadataProof {
  if (!isRecord(value)) throw new Error(`${stage}.metadata must be an object`);
  for (const key of ["ip", "nft"] as const) {
    const pair = value[key];
    if (!isRecord(pair)) throw new Error(`${stage}.metadata.${key} must be an object`);
    requireHttps(pair.uri, `${stage}.metadata.${key}.uri`);
    if (!isHash(pair.hash)) throw new Error(`${stage}.metadata.${key}.hash must be a SHA-256 hash`);
  }
  const artifact = value.artifact;
  if (!isRecord(artifact)) throw new Error(`${stage}.metadata.artifact must be an object`);
  if (typeof artifact.path !== "string" || artifact.path.length === 0) {
    throw new Error(`${stage}.metadata.artifact.path must be a non-empty string`);
  }
  if (!isHash(artifact.mediaHash)) {
    throw new Error(`${stage}.metadata.artifact.mediaHash must be a SHA-256 hash`);
  }
  if (artifact.mediaType !== "text/markdown") {
    throw new Error(`${stage}.metadata.artifact.mediaType must be text/markdown`);
  }
}

function validateProof(value: unknown, stage: DemoStage): RegistrationProof | null {
  if (value === null) return null;
  if (!isRecord(value) || value.stage !== stage) throw new Error(`${stage}.stage must be ${stage}`);
  const expectedKind = stage === "root" ? "Skill" : "Derivative";
  if (value.kind !== expectedKind) throw new Error(`${stage}.kind must be ${expectedKind}`);
  if (typeof value.name !== "string" || value.name.length === 0) {
    throw new Error(`${stage}.name must be a non-empty string`);
  }
  if (!isAddress(value.ipId)) throw new Error(`${stage}.ipId must be a 20-byte address`);
  if (!isDecimal(value.tokenId)) throw new Error(`${stage}.tokenId must be a decimal string`);
  if (!isHash(value.txHash)) throw new Error(`${stage}.txHash must be a 32-byte hash`);
  if (!isDecimal(value.licenseTermsId)) {
    throw new Error(`${stage}.licenseTermsId must be a decimal string`);
  }
  if (!isAddress(value.licenseTemplate)) {
    throw new Error(`${stage}.licenseTemplate must be a 20-byte address`);
  }
  if (!Array.isArray(value.parentIpIds) || !value.parentIpIds.every(isAddress)) {
    throw new Error(`${stage}.parentIpIds must contain addresses`);
  }
  if (stage === "root") {
    if (value.parentIpIds.length !== 0) throw new Error("root.parentIpIds must be empty");
    if (!isDecimal(value.defaultMintingFee)) {
      throw new Error("root.defaultMintingFee must be a decimal string");
    }
    if (value.maxMintingFee !== null) throw new Error("root.maxMintingFee must be null");
  } else {
    if (value.parentIpIds.length !== 1) throw new Error(`${stage}.parentIpIds must contain one parent`);
    if (value.defaultMintingFee !== null) throw new Error(`${stage}.defaultMintingFee must be null`);
    if (!isDecimal(value.maxMintingFee)) {
      throw new Error(`${stage}.maxMintingFee must be a decimal string`);
    }
  }
  validateMetadata(value.metadata, stage);
  return value as unknown as RegistrationProof;
}

export function parseRegistrationManifest(value: unknown): RegistrationManifest {
  if (!isRecord(value) || value.schemaVersion !== REGISTRATION_SCHEMA_VERSION) {
    throw new Error(`registrations.json must use schemaVersion ${REGISTRATION_SCHEMA_VERSION}`);
  }
  if (!(["not-run", "partial", "complete"] as unknown[]).includes(value.status)) {
    throw new Error("registrations.json has an invalid status");
  }
  if (
    !isRecord(value.network)
    || value.network.chainId !== AENEID_NETWORK.chainId
    || value.network.name !== AENEID_NETWORK.name
  ) {
    throw new Error(`registrations.json must target Story Aeneid (${AENEID_NETWORK.chainId})`);
  }
  if (value.wallet !== null && !isAddress(value.wallet)) {
    throw new Error("registrations.json wallet must be an address or null");
  }
  if (value.spgNftContract !== null && !isAddress(value.spgNftContract)) {
    throw new Error("registrations.json spgNftContract must be an address or null");
  }
  if (value.collectionTxHash !== null && !isHash(value.collectionTxHash)) {
    throw new Error("registrations.json collectionTxHash must be a 32-byte hash or null");
  }
  if (!isRecord(value.registrations)) {
    throw new Error("registrations.json is missing registrations");
  }
  for (const stage of ["root", "child", "grandchild"] as const) {
    if (!(stage in value.registrations)) {
      throw new Error(`registrations.json is missing the ${stage} stage`);
    }
  }
  const root = validateProof(value.registrations.root, "root");
  const child = validateProof(value.registrations.child, "child");
  const grandchild = validateProof(value.registrations.grandchild, "grandchild");

  if ((value.spgNftContract === null) !== (value.collectionTxHash === null)) {
    throw new Error("registrations.json must persist the SPG contract and collection txHash together");
  }
  if (child && (!root || child.parentIpIds[0].toLowerCase() !== root.ipId.toLowerCase())) {
    throw new Error("child.parentIpIds must point to the root Skill");
  }
  if (grandchild && (!child || grandchild.parentIpIds[0].toLowerCase() !== child.ipId.toLowerCase())) {
    throw new Error("grandchild.parentIpIds must point to the child Derivative");
  }
  if (child && root && child.licenseTermsId !== root.licenseTermsId) {
    throw new Error("child.licenseTermsId must inherit the root license terms");
  }
  if (grandchild && child && grandchild.licenseTermsId !== child.licenseTermsId) {
    throw new Error("grandchild.licenseTermsId must inherit the child license terms");
  }
  if (child && root && child.licenseTemplate.toLowerCase() !== root.licenseTemplate.toLowerCase()) {
    throw new Error("child.licenseTemplate must inherit the root license template");
  }
  if (grandchild && child
      && grandchild.licenseTemplate.toLowerCase() !== child.licenseTemplate.toLowerCase()) {
    throw new Error("grandchild.licenseTemplate must inherit the child license template");
  }

  if (value.status === "not-run") {
    if (value.wallet || value.spgNftContract || value.collectionTxHash || root || child || grandchild) {
      throw new Error("not-run registrations.json cannot contain confirmed proof fields");
    }
  } else {
    if (!value.wallet || !value.spgNftContract || !value.collectionTxHash) {
      throw new Error(`${value.status} registrations.json must contain wallet and collection proof`);
    }
    if (value.status === "complete" && (!root || !child || !grandchild)) {
      throw new Error("complete registrations.json must contain root, child, and grandchild proofs");
    }
    if (value.status === "partial" && root && child && grandchild) {
      throw new Error("registrations.json with all stages must use complete status");
    }
  }
  return value as unknown as RegistrationManifest;
}

export class FileRegistrationStore implements RegistrationStore {
  constructor(
    private readonly path: string,
    private readonly hooks: ManifestWriteHooks = {},
  ) {}

  async load(): Promise<RegistrationManifest> {
    try {
      const raw = await readFile(this.path, "utf8");
      return parseRegistrationManifest(JSON.parse(raw) as unknown);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") {
        return createEmptyRegistrationManifest();
      }
      throw error;
    }
  }

  async save(manifest: RegistrationManifest): Promise<void> {
    parseRegistrationManifest(manifest);
    const directory = dirname(this.path);
    await mkdir(directory, { recursive: true });
    const temporaryPath = `${this.path}.${process.pid}.${randomUUID()}.tmp`;
    const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    let temporaryHandle: FileHandle | null = null;
    let renamed = false;
    try {
      temporaryHandle = await open(temporaryPath, "wx", 0o600);
      await writeAll(temporaryHandle, bytes);
      await temporaryHandle.sync();
      await this.hooks.afterTempSync?.();
      await temporaryHandle.close();
      temporaryHandle = null;
      await rename(temporaryPath, this.path);
      renamed = true;
      await this.hooks.afterRename?.();
      const directoryHandle = await open(directory, "r");
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
      await this.hooks.afterDirectorySync?.();
    } catch (error) {
      if (temporaryHandle) await temporaryHandle.close().catch(() => undefined);
      if (!renamed) await unlink(temporaryPath).catch(() => undefined);
      throw error;
    }
  }
}

async function writeAll(handle: FileHandle, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.byteLength - offset, offset);
    if (!Number.isSafeInteger(bytesWritten)
        || bytesWritten <= 0
        || bytesWritten > bytes.byteLength - offset) {
      throw new Error("Manifest temporary write made no progress or returned an invalid byte count");
    }
    offset += bytesWritten;
  }
}

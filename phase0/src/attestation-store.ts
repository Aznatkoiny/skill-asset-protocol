import { randomBytes, randomUUID } from "node:crypto";
import { link, mkdir, open, rename, stat, unlink, type FileHandle } from "node:fs/promises";
import { dirname } from "node:path";

import {
  parseAttestationEvent,
  reduceAttestationEvents,
  type AttestationEvent,
  type RegistrationSubject,
  type RepositoryControlEvent,
} from "./attestations";
import { reverifyRepositoryEvent, type GitReader, type TrustedRepositoryResolver } from "./attestation-git";

export interface AttestationRepositoryContext {
  repositories: TrustedRepositoryResolver;
  forgeSigners: Readonly<Record<string, string>>;
  git: GitReader;
}

export interface AttestationStoreOptions {
  baseSubjects: readonly RegistrationSubject[];
  organizationSigners?: Readonly<Record<string, readonly `0x${string}`[]>>;
  adminSigners?: Readonly<Record<string, `0x${string}`>>;
  repositories?: TrustedRepositoryResolver;
  forgeSigners?: Readonly<Record<string, string>>;
  git?: GitReader;
  repositoryContextLoader?: () => Promise<AttestationRepositoryContext>;
  hooks?: {
    afterLockCreated?(): void | Promise<void>;
    beforeAppendWrite?(): void | Promise<void>;
    afterLockClaim?(claimPath: string): void | Promise<void>;
  };
}

export interface AttestationLockMetadata {
  schemaVersion: 1;
  pid: number;
  token: string;
  targetPath: string;
  acquiredAt: string;
}

export interface WriteAllHandle {
  write(buffer: Uint8Array, offset: number, length: number, position: number | null): Promise<{ bytesWritten: number }>;
}

const LOCK_TOKEN = /^[0-9a-f]{32}$/;

export async function writeAll(handle: WriteAllHandle, bytes: Uint8Array): Promise<void> {
  let offset = 0;
  while (offset < bytes.byteLength) {
    const result = await handle.write(bytes, offset, bytes.byteLength - offset, null);
    const bytesWritten = result?.bytesWritten;
    if (!Number.isSafeInteger(bytesWritten) || bytesWritten <= 0 || bytesWritten > bytes.byteLength - offset) {
      throw new Error("attestation store write made no progress or returned an invalid byte count");
    }
    offset += bytesWritten;
  }
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, "r");
  try { await handle.sync(); } finally { await handle.close(); }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function parseLock(value: unknown): AttestationLockMetadata {
  const owner = object(value, "attestation store lock");
  const expected = ["schemaVersion", "pid", "token", "targetPath", "acquiredAt"];
  const actual = Object.keys(owner);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("attestation store lock fields are malformed");
  }
  if (owner.schemaVersion !== 1) throw new Error("attestation store lock schemaVersion must be 1");
  if (!Number.isSafeInteger(owner.pid) || (owner.pid as number) <= 0) throw new Error("attestation store lock PID is malformed");
  if (typeof owner.token !== "string" || !LOCK_TOKEN.test(owner.token)) throw new Error("attestation store lock token is malformed");
  if (typeof owner.targetPath !== "string" || !owner.targetPath.startsWith("/")) throw new Error("attestation store lock target path is malformed");
  if (typeof owner.acquiredAt !== "string" || Number.isNaN(Date.parse(owner.acquiredAt)) || new Date(owner.acquiredAt).toISOString() !== owner.acquiredAt) {
    throw new Error("attestation store lock timestamp is malformed");
  }
  return owner as unknown as AttestationLockMetadata;
}

async function readMode0600(path: string, label: string): Promise<string> {
  const handle = await open(path, "r");
  try {
    const metadata = await handle.stat();
    if ((metadata.mode & 0o777) !== 0o600) throw new Error(`${label} must have mode 0600`);
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

function parseJsonLine(line: string, index: number): AttestationEvent {
  try { return parseAttestationEvent(JSON.parse(line)); } catch (error) {
    throw new Error(`attestation log line ${index + 1} is malformed`, { cause: error });
  }
}

export class FileAttestationStore {
  readonly path: string;
  readonly lockPath: string;
  private readonly options: AttestationStoreOptions;

  constructor(path: string, options: AttestationStoreOptions) {
    if (!path.startsWith("/")) throw new Error("attestation store path must be absolute");
    if (!Array.isArray(options.baseSubjects)) throw new Error("attestation store requires verifier-provided base subjects");
    this.path = path;
    this.lockPath = `${path}.lock`;
    this.options = options;
  }

  async load(): Promise<AttestationEvent[]> {
    return this.withLock(() => this.loadUnlocked());
  }

  async nextSequence(): Promise<number> {
    return this.withLock(async () => (await this.loadUnlocked()).length + 1);
  }

  async append(eventValue: AttestationEvent): Promise<void> {
    await this.withLock(async () => {
      const events = await this.loadUnlocked();
      const event = parseAttestationEvent(eventValue);
      if (event.sequence !== events.length + 1) throw new Error(`attestation event sequence must equal ${events.length + 1}`);
      if (events.some((prior) => prior.eventId === event.eventId)) throw new Error(`duplicate attestation event ID ${event.eventId}`);
      const candidate = [...events, event];
      await this.validateEvents(candidate);
      await this.options.hooks?.beforeAppendWrite?.();
      await mkdir(dirname(this.path), { recursive: true });
      let handle: FileHandle | null = null;
      try {
        handle = await open(this.path, "a", 0o600);
        const bytes = Buffer.from(`${JSON.stringify(event)}\n`, "utf8");
        await writeAll(handle, bytes);
        await handle.sync();
      } finally {
        await handle?.close();
      }
      await syncDirectory(dirname(this.path));
      const replayed = await this.loadUnlocked();
      if (replayed.length !== candidate.length || replayed.at(-1)?.eventId !== event.eventId) {
        throw new Error("attestation append did not replay as the exact candidate event");
      }
    });
  }

  async readLockMetadata(): Promise<AttestationLockMetadata> {
    return (await this.readLock()).owner;
  }

  async recoverStaleLock(input: {
    expectedToken: string;
    isProcessAlive: (pid: number) => boolean | Promise<boolean>;
  }): Promise<void> {
    if (!LOCK_TOKEN.test(input.expectedToken)) throw new Error("expected lock token must be exactly 128 lowercase bits");
    const initial = await this.readLock();
    if (initial.owner.targetPath !== this.path) throw new Error("attestation store lock target path does not match this store");
    if (initial.owner.token !== input.expectedToken) throw new Error("recorded attestation lock token does not match the expected token");
    const alive = await input.isProcessAlive(initial.owner.pid);
    if (typeof alive !== "boolean") throw new Error(`cannot prove PID ${initial.owner.pid} is absent`);
    if (alive) throw new Error(`attestation store lock PID ${initial.owner.pid} is still alive`);
    await this.claimAndRemoveLock(initial.owner, initial.bytes, "attestation store lock changed during stale recovery");
  }

  private async repositoryContext(): Promise<AttestationRepositoryContext> {
    if (this.options.repositories && this.options.forgeSigners && this.options.git) {
      return { repositories: this.options.repositories, forgeSigners: this.options.forgeSigners, git: this.options.git };
    }
    if (this.options.repositoryContextLoader) return this.options.repositoryContextLoader();
    throw new Error("repository verifier context required");
  }

  private async validateEvents(events: readonly AttestationEvent[]): Promise<void> {
    const hasRepositoryEvidence = events.some((event) => event.type === "repository_control_verified");
    let context: AttestationRepositoryContext | null = null;
    if (hasRepositoryEvidence) context = await this.repositoryContext();
    await reduceAttestationEvents(events, {
      baseSubjects: this.options.baseSubjects,
      organizationSigners: this.options.organizationSigners,
      adminSigners: this.options.adminSigners,
      repositoryVerifier: context
        ? (event: RepositoryControlEvent) => reverifyRepositoryEvent(event, context!)
        : undefined,
    });
  }

  private async loadUnlocked(): Promise<AttestationEvent[]> {
    let bytes: string;
    try { bytes = await open(this.path, "r").then(async (handle) => {
      try { return await handle.readFile("utf8"); } finally { await handle.close(); }
    }); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw error;
    }
    if (bytes === "") return [];
    if (!bytes.endsWith("\n")) throw new Error("attestation log has a malformed trailing fragment");
    const lines = bytes.slice(0, -1).split("\n");
    if (lines.some((line) => line.length === 0)) throw new Error("attestation log contains an empty or malformed line");
    const events = lines.map(parseJsonLine);
    await this.validateEvents(events);
    return events;
  }

  private async withLock<T>(operation: () => Promise<T>): Promise<T> {
    await mkdir(dirname(this.path), { recursive: true });
    const owner: AttestationLockMetadata = {
      schemaVersion: 1,
      pid: process.pid,
      token: randomBytes(16).toString("hex"),
      targetPath: this.path,
      acquiredAt: new Date().toISOString(),
    };
    await this.acquireLock(owner);
    try { return await operation(); } finally { await this.releaseLock(owner); }
  }

  private async acquireLock(owner: AttestationLockMetadata): Promise<void> {
    let handle: FileHandle | null = null;
    let created = false;
    try {
      try {
        handle = await open(this.lockPath, "wx", 0o600);
        created = true;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
        const existing = await this.readLock();
        throw new Error(`attestation store locked by PID ${existing.owner.pid}, token ${existing.owner.token}`, { cause: error });
      }
      await writeAll(handle, Buffer.from(`${JSON.stringify(owner)}\n`, "utf8"));
      await handle.sync();
      await handle.close();
      handle = null;
      await syncDirectory(dirname(this.lockPath));
      await this.options.hooks?.afterLockCreated?.();
    } catch (error) {
      const unfinishedHandle = handle as FileHandle | null;
      if (unfinishedHandle) await unfinishedHandle.close().catch(() => undefined);
      if (created) await unlink(this.lockPath).catch(() => undefined);
      throw error;
    }
  }

  private async releaseLock(owner: AttestationLockMetadata): Promise<void> {
    await this.claimAndRemoveLock(owner, `${JSON.stringify(owner)}\n`, "attestation store lock ownership changed before release");
  }

  private async claimAndRemoveLock(owner: AttestationLockMetadata, expectedBytes: string, message: string): Promise<void> {
    const claimPath = `${this.lockPath}.${process.pid}.${randomUUID()}.claim`;
    await rename(this.lockPath, claimPath);
    await this.options.hooks?.afterLockClaim?.(claimPath);
    let observed: { owner: AttestationLockMetadata; bytes: string } | null = null;
    let failure: unknown = null;
    try { observed = await this.readLock(claimPath); } catch (error) { failure = error; }
    if (failure || !observed || observed.owner.token !== owner.token || observed.owner.targetPath !== owner.targetPath || observed.bytes !== expectedBytes) {
      let disposition = `retained at ${claimPath}`;
      try {
        await link(claimPath, this.lockPath);
        await unlink(claimPath);
        disposition = "restored";
        await syncDirectory(dirname(this.lockPath));
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
          throw new Error(`${message}; claim retained at ${claimPath}`, { cause: error });
        }
      }
      throw new Error(`${message}; claimed lock was ${disposition}`, { cause: failure ?? undefined });
    }
    await unlink(claimPath);
    await syncDirectory(dirname(this.lockPath));
  }

  private async readLock(path = this.lockPath): Promise<{ owner: AttestationLockMetadata; bytes: string }> {
    let bytes: string;
    try { bytes = await readMode0600(path, "attestation store lock"); } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("attestation store lock does not exist", { cause: error });
      throw error;
    }
    if (!bytes.endsWith("\n") || bytes.endsWith("\n\n")) throw new Error("attestation store lock is malformed");
    let value: unknown;
    try { value = JSON.parse(bytes); } catch (error) { throw new Error("attestation store lock is malformed", { cause: error }); }
    const owner = parseLock(value);
    if (owner.targetPath !== this.path) throw new Error("attestation store lock target path does not match this store");
    return { owner, bytes };
  }
}

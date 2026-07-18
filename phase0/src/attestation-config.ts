import { constants } from "node:fs";
import { open, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

import { normalizeRepositoryUrl } from "./attestations";
import type { TrustedRepository, TrustedRepositoryResolver } from "./attestation-git";

export interface LocalCheckoutMapV1 {
  schemaVersion: 1;
  checkouts: Record<string, string>;
}

interface FileMetadata {
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
  mode: number;
  uid: number;
  dev?: number;
  ino?: number;
}

interface SecureReadHandle {
  stat(): Promise<FileMetadata>;
  readFile(): Promise<string>;
  close(): Promise<void>;
}

export interface AttestationConfigFileSystem {
  realpath(path: string): Promise<string>;
  openNoFollow(path: string, kind: "file" | "directory"): Promise<SecureReadHandle>;
  currentUid(): number;
}

const NODE_FS: AttestationConfigFileSystem = {
  realpath,
  openNoFollow: async (path, kind) => {
    const directoryFlag = kind === "directory" ? constants.O_DIRECTORY : 0;
    const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | directoryFlag);
    return {
      stat: () => handle.stat(),
      readFile: () => handle.readFile("utf8"),
      close: () => handle.close(),
    };
  },
  currentUid: () => {
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("repository snapshot mapping requires an operating-system owner identity");
    return uid;
  },
};

const KEY = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const REF = /^refs\/(?:heads|remotes)\/[A-Za-z0-9._\/-]+$/;

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

function deepFreeze<T>(value: T): T {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return value;
  Object.freeze(value);
  for (const item of Object.values(value as Record<string, unknown>)) deepFreeze(item);
  return value;
}

function inside(path: string, root: string): boolean {
  const rel = relative(root, path);
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

export async function loadLocalCheckoutMap(input: {
  env: Readonly<Record<string, string | undefined>>;
  phase0Root: string;
  referencedCheckoutKeys: readonly string[];
  fs?: AttestationConfigFileSystem;
}): Promise<Readonly<Record<string, string>>> {
  const fs = input.fs ?? NODE_FS;
  if (!isAbsolute(input.phase0Root)) throw new Error("phase0Root must be an absolute canonical path");
  let canonicalRoot: string;
  try { canonicalRoot = await fs.realpath(input.phase0Root); } catch (error) {
    throw new Error("phase0Root must exist before repository verification", { cause: error });
  }
  if (resolve(input.phase0Root) !== canonicalRoot) throw new Error("phase0Root must be an absolute canonical path");
  const defaultPath = resolve(canonicalRoot, ".attestation-checkouts.local.json");
  const override = input.env.PHASE0_ATTESTATION_CHECKOUTS_FILE;
  if (override !== undefined && override.length === 0) throw new Error("PHASE0_ATTESTATION_CHECKOUTS_FILE must not be blank");
  if (override !== undefined && !isAbsolute(override)) throw new Error("PHASE0_ATTESTATION_CHECKOUTS_FILE must be an absolute path");
  const configPath = resolve(override ?? defaultPath);
  if (inside(configPath, canonicalRoot) && configPath !== defaultPath) {
    throw new Error("an in-repository checkout mapping override must equal the exact ignored default path");
  }

  let configHandle: SecureReadHandle;
  try { configHandle = await fs.openNoFollow(configPath, "file"); } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(`repository snapshot mapping unavailable: ${configPath}`, { cause: error });
    }
    throw new Error("repository snapshot mapping must be a non-symlink regular file", { cause: error });
  }
  let parsed: unknown;
  try {
    if (await fs.realpath(configPath) !== configPath) {
      throw new Error("repository snapshot mapping path must be canonical");
    }
    const metadata = await configHandle.stat();
    if (metadata.isSymbolicLink() || !metadata.isFile()) throw new Error("repository snapshot mapping must be a non-symlink regular file");
    if ((metadata.mode & 0o777) !== 0o600) throw new Error("repository snapshot mapping must have mode 0600");
    if (metadata.uid !== fs.currentUid()) throw new Error("repository snapshot mapping must be owned by the current user");
    try { parsed = JSON.parse(await configHandle.readFile()); } catch (error) {
      throw new Error("repository snapshot mapping contains malformed JSON", { cause: error });
    }
    const afterRead = await configHandle.stat();
    if ((metadata.dev !== undefined && afterRead.dev !== metadata.dev)
        || (metadata.ino !== undefined && afterRead.ino !== metadata.ino)) {
      throw new Error("repository snapshot mapping changed while it was being read");
    }
  } finally {
    await configHandle.close();
  }
  const config = object(parsed, "repository snapshot mapping");
  exactKeys(config, ["schemaVersion", "checkouts"], "repository snapshot mapping");
  if (config.schemaVersion !== 1) throw new Error("repository snapshot mapping schemaVersion must be 1");
  const checkouts = object(config.checkouts, "repository snapshot mapping checkouts");
  const expected = [...input.referencedCheckoutKeys];
  if (new Set(expected).size !== expected.length || expected.some((key) => !KEY.test(key))) throw new Error("tracked repository trust contains invalid checkout keys");
  const actual = Object.keys(checkouts);
  if (actual.some((key) => !KEY.test(key))) throw new Error("repository snapshot mapping contains an invalid checkout key");
  if (actual.length !== expected.length || [...actual].sort().some((key, index) => key !== [...expected].sort()[index])) {
    throw new Error("repository snapshot mapping keys must exactly match tracked repository trust");
  }

  const result: Record<string, string> = {};
  for (const key of actual) {
    const checkoutPath = checkouts[key];
    if (typeof checkoutPath !== "string" || !isAbsolute(checkoutPath) || resolve(checkoutPath) !== checkoutPath) {
      throw new Error(`checkout ${key} must use a canonical absolute path`);
    }
    let canonical: string;
    try { canonical = await fs.realpath(checkoutPath); } catch (error) {
      throw new Error(`checkout ${key} does not exist`, { cause: error });
    }
    if (canonical !== checkoutPath) throw new Error(`checkout ${key} must use its real canonical path`);
    let checkoutHandle: SecureReadHandle;
    try { checkoutHandle = await fs.openNoFollow(checkoutPath, "directory"); } catch (error) {
      throw new Error(`checkout ${key} must be a non-symlink directory`, { cause: error });
    }
    try {
      const checkoutMetadata = await checkoutHandle.stat();
      if (checkoutMetadata.isSymbolicLink() || !checkoutMetadata.isDirectory()) throw new Error(`checkout ${key} must be a directory`);
      if (checkoutMetadata.uid !== fs.currentUid()) throw new Error(`checkout ${key} must be owned by the current user`);
      if ((checkoutMetadata.mode & 0o022) !== 0) throw new Error(`checkout ${key} must not be group- or world-writable`);
      if (await fs.realpath(checkoutPath) !== checkoutPath) throw new Error(`checkout ${key} changed during validation`);
    } finally {
      await checkoutHandle.close();
    }
    result[key] = checkoutPath;
  }
  return deepFreeze(result);
}

export interface RepositoryTrustEntryV1 {
  repositoryId: string;
  repositoryUrl: string;
  checkoutKey: string;
  trustedRef: `refs/heads/${string}` | `refs/remotes/${string}`;
  permittedForgeSignerIds: string[];
}

export interface RepositoryTrustConfigV1 {
  schemaVersion: 1;
  repositories: RepositoryTrustEntryV1[];
}

export function referencedCheckoutKeys(trustConfig: unknown): string[] {
  return parseRepositoryTrustConfig(trustConfig).repositories.map((entry) => entry.checkoutKey).sort();
}

export function parseRepositoryTrustConfig(value: unknown): RepositoryTrustConfigV1 {
  const config = object(value, "repository trust config");
  exactKeys(config, ["schemaVersion", "repositories"], "repository trust config");
  if (config.schemaVersion !== 1 || !Array.isArray(config.repositories)) throw new Error("repository trust config schemaVersion/repositories are invalid");
  const seenRepositories = new Set<string>();
  const seenCheckoutKeys = new Set<string>();
  const repositories = config.repositories.map((entryValue, index) => {
    const entry = object(entryValue, `repository trust entry ${index}`);
    exactKeys(entry, ["repositoryId", "repositoryUrl", "checkoutKey", "trustedRef", "permittedForgeSignerIds"], `repository trust entry ${index}`);
    if (typeof entry.repositoryId !== "string" || !KEY.test(entry.repositoryId)) throw new Error("repositoryId is invalid");
    if (seenRepositories.has(entry.repositoryId)) throw new Error("repositoryId must be unique");
    seenRepositories.add(entry.repositoryId);
    if (typeof entry.repositoryUrl !== "string") throw new Error("repositoryUrl must be a normalized HTTPS URL");
    normalizeRepositoryUrl(entry.repositoryUrl);
    if (typeof entry.checkoutKey !== "string" || !KEY.test(entry.checkoutKey)) throw new Error("checkoutKey is invalid");
    if (seenCheckoutKeys.has(entry.checkoutKey)) throw new Error("checkoutKey must be unique");
    seenCheckoutKeys.add(entry.checkoutKey);
    if (typeof entry.trustedRef !== "string" || !REF.test(entry.trustedRef) || entry.trustedRef.includes("..")) throw new Error("trustedRef is invalid");
    if (!Array.isArray(entry.permittedForgeSignerIds) || entry.permittedForgeSignerIds.length === 0) throw new Error("permittedForgeSignerIds must be a nonempty array");
    const permitted = entry.permittedForgeSignerIds.map((id) => {
      if (typeof id !== "string" || !KEY.test(id)) throw new Error("forge signer ID is invalid");
      return id;
    });
    if (new Set(permitted).size !== permitted.length) throw new Error("forge signer IDs must be unique");
    return {
      repositoryId: entry.repositoryId,
      repositoryUrl: entry.repositoryUrl,
      checkoutKey: entry.checkoutKey,
      trustedRef: entry.trustedRef as RepositoryTrustEntryV1["trustedRef"],
      permittedForgeSignerIds: permitted,
    };
  });
  return deepFreeze({ schemaVersion: 1, repositories });
}

export function createTrustedRepositoryResolver(input: {
  trustConfig: unknown;
  checkoutPaths: Readonly<Record<string, string>>;
}): TrustedRepositoryResolver {
  const config = parseRepositoryTrustConfig(input.trustConfig);
  const configuredKeys = config.repositories.map((entry) => entry.checkoutKey).sort();
  const suppliedKeys = Object.keys(input.checkoutPaths).sort();
  if (configuredKeys.length !== suppliedKeys.length || configuredKeys.some((key, index) => key !== suppliedKeys[index])) {
    throw new Error("trusted repository checkout paths do not exactly match tracked trust configuration");
  }
  const repositories = new Map(config.repositories.map((entry) => {
    const repository: TrustedRepository = deepFreeze({
      repositoryId: entry.repositoryId,
      repositoryUrl: entry.repositoryUrl,
      repositoryPath: input.checkoutPaths[entry.checkoutKey],
      trustedRef: entry.trustedRef,
      permittedForgeSignerIds: [...entry.permittedForgeSignerIds],
    });
    return [entry.repositoryId, repository];
  }));
  return Object.freeze({
    resolve(repositoryId: string, normalizedRepositoryUrl: string): TrustedRepository {
      const repository = repositories.get(repositoryId);
      if (!repository || repository.repositoryUrl !== normalizedRepositoryUrl) {
        throw new Error("repository is not present in verifier-provisioned trust configuration");
      }
      return repository;
    },
  });
}

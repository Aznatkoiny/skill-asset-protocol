import { readFile, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import {
  compareOrdinalStrings,
  displayAttestation,
  parseAttestationEvent,
  reduceAttestationEvents,
  registrationSubjectsFromManifest,
  type AttestationConflict,
  type AttestationEvent,
  type AttestationIndex,
  type ForgeObservationV1,
  type RegistrationSubject,
} from "./attestations";
import {
  createTrustedRepositoryResolver,
  loadLocalCheckoutMap,
  parseRepositoryTrustConfig,
  referencedCheckoutKeys,
} from "./attestation-config";
import {
  canonicalChallengeFileBytes,
  ExecGitReader,
  normalizeForgePublicKey,
  verifyRepositoryControl,
  type GitReader,
  type SignedRepositoryChallengeFileV1,
} from "./attestation-git";
import {
  FileAttestationStore,
  type AttestationLockMetadata,
  type AttestationRepositoryContext,
} from "./attestation-store";
import { FileRegistrationStore } from "./registrations";
import { quoteTerminalText } from "./terminal";

export type AttestationCommand =
  | "attestation-status"
  | "attestation-verify-repository"
  | "attestation-verify-organization"
  | "attestation-append-challenge"
  | "attestation-resolve"
  | "attestation-conflicts"
  | "attestation-revoke"
  | "attestation-recover-lock";

export interface AttestationCommandOptions {
  artifactHash?: string;
  registrationId?: string;
  bundle?: string;
  lockToken?: string;
  json?: boolean;
}

const DEFAULT_PHASE0_ROOT = fileURLToPath(new URL("../", import.meta.url));
const DEFAULT_PATHS = {
  registrations: fileURLToPath(new URL("../registrations.json", import.meta.url)),
  attestations: fileURLToPath(new URL("../attestations.jsonl", import.meta.url)),
  organizations: fileURLToPath(new URL("../organization-signers.json", import.meta.url)),
  admins: fileURLToPath(new URL("../attestation-admins.json", import.meta.url)),
  repositories: fileURLToPath(new URL("../repository-trust.json", import.meta.url)),
  forgeSigners: fileURLToPath(new URL("../forge-signers.json", import.meta.url)),
};

export interface AttestationRuntimePaths {
  registrations: string;
  attestations: string;
  organizations: string;
  admins: string;
  repositories: string;
  forgeSigners: string;
}

export interface AttestationRuntimeInput {
  phase0Root?: string;
  paths?: AttestationRuntimePaths;
  env?: Readonly<Record<string, string | undefined>>;
  git?: GitReader;
  now?: () => Date;
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort(compareOrdinalStrings);
  const wanted = [...expected].sort(compareOrdinalStrings);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) throw new Error(`${label} has unexpected or missing fields`);
}

async function jsonFile(path: string, label: string): Promise<unknown> {
  try { return JSON.parse(await readFile(path, "utf8")); } catch (error) {
    throw new Error(`${label} could not be loaded`, { cause: error });
  }
}

function validateNoPrivateMaterial(value: unknown, label: string): void {
  const text = JSON.stringify(value);
  if (/private[_ -]?key|BEGIN [A-Z ]*PRIVATE KEY/i.test(text)) throw new Error(`${label} must never contain private key material`);
}

async function organizationSigners(path: string): Promise<Readonly<Record<string, readonly `0x${string}`[]>>> {
  const value = object(await jsonFile(path, "organization signer trust"), "organization signer trust");
  exactKeys(value, ["schemaVersion", "organizations"], "organization signer trust");
  if (value.schemaVersion !== 1) throw new Error("organization signer trust schemaVersion must be 1");
  const organizations = object(value.organizations, "organization signer allow-list");
  const result: Record<string, readonly `0x${string}`[]> = {};
  for (const [organizationId, walletsValue] of Object.entries(organizations)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(organizationId) || !Array.isArray(walletsValue)) throw new Error("organization signer allow-list is malformed");
    const wallets = walletsValue.map((wallet) => {
      if (typeof wallet !== "string" || !/^0x[0-9a-f]{40}$/.test(wallet)) throw new Error("organization signer must be a lowercase address");
      return wallet as `0x${string}`;
    });
    if (new Set(wallets).size !== wallets.length) throw new Error("organization signer addresses must be unique");
    result[organizationId] = Object.freeze(wallets);
  }
  validateNoPrivateMaterial(value, "organization signer trust");
  return Object.freeze(result);
}

async function adminSigners(path: string): Promise<Readonly<Record<string, `0x${string}`>>> {
  const value = object(await jsonFile(path, "attestation admin trust"), "attestation admin trust");
  exactKeys(value, ["schemaVersion", "admins"], "attestation admin trust");
  if (value.schemaVersion !== 1) throw new Error("attestation admin trust schemaVersion must be 1");
  const admins = object(value.admins, "attestation admins");
  const result: Record<string, `0x${string}`> = {};
  const wallets = new Set<string>();
  for (const [id, wallet] of Object.entries(admins)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(id) || typeof wallet !== "string" || !/^0x[0-9a-f]{40}$/.test(wallet)) throw new Error("attestation admin trust is malformed");
    if (wallets.has(wallet)) throw new Error("attestation admin addresses must be unique");
    wallets.add(wallet);
    result[id] = wallet as `0x${string}`;
  }
  validateNoPrivateMaterial(value, "attestation admin trust");
  return Object.freeze(result);
}

async function forgeSigners(path: string): Promise<Readonly<Record<string, string>>> {
  const value = object(await jsonFile(path, "forge signer trust"), "forge signer trust");
  exactKeys(value, ["schemaVersion", "forgeSigners"], "forge signer trust");
  if (value.schemaVersion !== 1) throw new Error("forge signer trust schemaVersion must be 1");
  const signers = object(value.forgeSigners, "forge signers");
  const result: Record<string, string> = {};
  for (const [id, publicKey] of Object.entries(signers)) {
    if (!/^[a-z0-9][a-z0-9._-]{0,127}$/.test(id)) throw new Error("forge signer trust is malformed");
    result[id] = normalizeForgePublicKey(publicKey);
  }
  validateNoPrivateMaterial(value, "forge signer trust");
  return Object.freeze(result);
}

export interface AttestationRuntime {
  store: FileAttestationStore;
  baseSubjects: readonly RegistrationSubject[];
  organizationSigners: Readonly<Record<string, readonly `0x${string}`[]>>;
  adminSigners: Readonly<Record<string, `0x${string}`>>;
  repositoryContext: () => Promise<AttestationRepositoryContext>;
  now: () => Date;
}

export async function createAttestationRuntime(input: AttestationRuntimeInput = {}): Promise<AttestationRuntime> {
  const selectedPaths = input.paths ?? DEFAULT_PATHS;
  const selectedRoot = input.phase0Root ?? DEFAULT_PHASE0_ROOT;
  const manifest = await new FileRegistrationStore(selectedPaths.registrations).load();
  const baseSubjects = registrationSubjectsFromManifest(manifest);
  const organizations = await organizationSigners(selectedPaths.organizations);
  const admins = await adminSigners(selectedPaths.admins);
  const now = input.now ?? (() => new Date());
  let contextPromise: Promise<AttestationRepositoryContext> | null = null;
  const repositoryContext = () => {
    contextPromise ??= (async () => {
      const trustValue = await jsonFile(selectedPaths.repositories, "repository trust");
      const trust = parseRepositoryTrustConfig(trustValue);
      const canonicalRoot = await realpath(selectedRoot);
      const checkoutPaths = await loadLocalCheckoutMap({
        env: input.env ?? process.env,
        phase0Root: canonicalRoot,
        referencedCheckoutKeys: referencedCheckoutKeys(trust),
      });
      return {
        repositories: createTrustedRepositoryResolver({ trustConfig: trust, checkoutPaths }),
        forgeSigners: await forgeSigners(selectedPaths.forgeSigners),
        git: input.git ?? new ExecGitReader(),
      };
    })();
    return contextPromise;
  };
  return {
    baseSubjects,
    organizationSigners: organizations,
    adminSigners: admins,
    repositoryContext,
    now,
    store: new FileAttestationStore(selectedPaths.attestations, {
      baseSubjects,
      organizationSigners: organizations,
      adminSigners: admins,
      repositoryContextLoader: repositoryContext,
      trackedEmptySeedPath: selectedPaths.attestations === DEFAULT_PATHS.attestations
        ? DEFAULT_PATHS.attestations
        : undefined,
      now,
    }),
  };
}

async function loadIndex(runtime: AttestationRuntime): Promise<AttestationIndex> {
  const events = await runtime.store.load();
  const now = runtime.now();
  let verifier: ((event: Extract<AttestationEvent, { type: "repository_control_verified" }>) => Promise<void>) | undefined;
  if (events.some((event) => event.type === "repository_control_verified")) {
    const context = await runtime.repositoryContext();
    const { reverifyRepositoryEvent } = await import("./attestation-git");
    verifier = (event) => reverifyRepositoryEvent(event, { ...context, now });
  }
  return reduceAttestationEvents(events, {
    baseSubjects: runtime.baseSubjects,
    organizationSigners: runtime.organizationSigners,
    adminSigners: runtime.adminSigners,
    repositoryVerifier: verifier,
    now,
  });
}

function statusPayload(index: AttestationIndex, options: AttestationCommandOptions): {
  registrations: unknown[];
  conflicts: AttestationConflict[];
} {
  if (options.artifactHash !== undefined && !/^0x[0-9a-f]{64}$/.test(options.artifactHash)) throw new Error("--artifact-hash must be a lowercase 32-byte hash");
  if (options.registrationId !== undefined && !/^eip155:1315:0x[0-9a-f]{40}$/.test(options.registrationId)) throw new Error("--registration-id must be an Aeneid registration ID");
  if (options.artifactHash !== undefined && options.registrationId !== undefined) throw new Error("choose only one of --artifact-hash or --registration-id");
  const selected = Object.entries(index.registrations).filter(([id, registration]) =>
    (options.artifactHash === undefined || registration.subject.artifactHash === options.artifactHash)
    && (options.registrationId === undefined || id === options.registrationId))
    .sort(([a], [b]) => compareOrdinalStrings(a, b));
  const ids = new Set(selected.map(([id]) => id));
  return {
    registrations: selected.map(([registrationId, registration]) => ({
      registrationId,
      subject: registration.subject,
      ...displayAttestation(index, registrationId),
      revocations: registration.revocations,
    })),
    conflicts: index.conflicts
      .filter((conflict) => conflict.registrationIds.some((id) => ids.has(id)))
      .sort((a, b) => compareOrdinalStrings(a.conflictId, b.conflictId)),
  };
}

function renderAttestationConflicts(conflictsValue: readonly AttestationConflict[]): string[] {
  const conflicts = [...conflictsValue].sort((a, b) => compareOrdinalStrings(a.conflictId, b.conflictId));
  const lines = [`conflicts: ${conflicts.length}`];
  for (const conflict of conflicts) {
    lines.push(`conflict: ${quoteTerminalText(conflict.conflictId)}`);
    lines.push(`conflict artifact hash: ${conflict.artifactHash === null ? "(none)" : quoteTerminalText(conflict.artifactHash)}`);
    lines.push(`conflict status: ${conflict.status}`);
    lines.push(`conflict reason: ${conflict.reason}`);
    lines.push(`conflict outcome: ${conflict.outcome ?? "(none)"}`);
    lines.push(`conflict registrations: ${[...conflict.registrationIds].sort(compareOrdinalStrings).map(quoteTerminalText).join(", ")}`);
    lines.push(`conflict events: ${conflict.eventIds.length > 0 ? [...conflict.eventIds].sort(compareOrdinalStrings).map(quoteTerminalText).join(", ") : "(none)"}`);
  }
  return lines;
}

function renderAppendSuccess(event: AttestationEvent, json: boolean): string[] {
  const payload = { appended: event.eventId, type: event.type };
  if (json) return [JSON.stringify(payload, null, 2)];
  return [`appended: ${quoteTerminalText(event.eventId)}; type: ${quoteTerminalText(event.type)}`];
}

function renderRecoveredLock(metadata: AttestationLockMetadata, json: boolean): string[] {
  const payload = { recovered: true, lock: metadata };
  if (json) return [JSON.stringify(payload, null, 2)];
  return [
    `recovered: true; lock pid: ${metadata.pid}; token: ${quoteTerminalText(metadata.token)}; target path: ${quoteTerminalText(metadata.targetPath)}; acquired at: ${quoteTerminalText(metadata.acquiredAt)}`,
  ];
}

export function renderAttestationStatus(index: AttestationIndex, options: AttestationCommandOptions = {}): string[] {
  const payload = statusPayload(index, options);
  if (options.json) return [JSON.stringify(payload, null, 2)];
  if (payload.registrations.length === 0) return ["No matching confirmed registrations.", "conflicts: 0"];
  const lines: string[] = [];
  for (const itemValue of payload.registrations) {
    const item = itemValue as ReturnType<typeof displayAttestation> & { registrationId: string };
    lines.push(`registration: ${quoteTerminalText(item.registrationId)}`);
    lines.push(`status: ${item.status}`);
    lines.push(`attestation: ${item.level}`);
    lines.push(`claim: ${item.claim}`);
    lines.push(`safety review: ${item.safetyReviewStatus}`);
    for (const warning of item.warnings) lines.push(`warning: ${warning}`);
  }
  lines.push(...renderAttestationConflicts(payload.conflicts));
  return lines;
}

async function readBundle(path: string): Promise<unknown> {
  if (!path.startsWith("/")) throw new Error("--bundle must be an absolute path");
  return jsonFile(path, "pre-signed attestation bundle");
}

async function appendTypedBundle(runtime: AttestationRuntime, bundlePath: string, expectedType: AttestationEvent["type"]): Promise<AttestationEvent> {
  const event = parseAttestationEvent(await readBundle(bundlePath));
  if (event.type !== expectedType) throw new Error(`bundle must contain a ${expectedType} event`);
  await runtime.store.append(event);
  return event;
}

function assertOnlyOptions(options: AttestationCommandOptions, permitted: readonly (keyof AttestationCommandOptions)[]): void {
  for (const [key, value] of Object.entries(options)) {
    if (value !== undefined && value !== false && !permitted.includes(key as keyof AttestationCommandOptions)) throw new Error(`option --${key.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} is not valid for this command`);
  }
}

export async function executeAttestationCommand(
  command: AttestationCommand,
  options: AttestationCommandOptions,
  log: (line: string) => void = console.log,
  runtimeInput: AttestationRuntimeInput = {},
): Promise<void> {
  const runtime = await createAttestationRuntime(runtimeInput);
  let lines: string[];
  if (command === "attestation-status") {
    assertOnlyOptions(options, ["artifactHash", "registrationId", "json"]);
    lines = renderAttestationStatus(await loadIndex(runtime), options);
  } else if (command === "attestation-conflicts") {
    assertOnlyOptions(options, ["json"]);
    const conflicts = (await loadIndex(runtime)).conflicts;
    lines = options.json
      ? [JSON.stringify({ conflicts }, null, 2)]
      : renderAttestationConflicts(conflicts);
  } else if (command === "attestation-verify-repository") {
    assertOnlyOptions(options, ["bundle", "json"]);
    if (!options.bundle) throw new Error("attestation-verify-repository requires --bundle <absolute-path>");
    const bundle = object(await readBundle(options.bundle), "repository attestation bundle");
    exactKeys(bundle, ["schemaVersion", "eventId", "sequence", "occurredAt", "challengeFile", "forgeObservation"], "repository attestation bundle");
    if (bundle.schemaVersion !== 1 || typeof bundle.eventId !== "string" || !Number.isSafeInteger(bundle.sequence) || typeof bundle.occurredAt !== "string") throw new Error("repository attestation bundle metadata is malformed");
    const signedFileObject = object(bundle.challengeFile, "signed challenge file");
    exactKeys(signedFileObject, ["challenge", "statementHash", "signature"], "signed challenge file");
    const signedFile = signedFileObject as unknown as SignedRepositoryChallengeFileV1;
    const context = await runtime.repositoryContext();
    const event = await verifyRepositoryControl({
      challengeFile: canonicalChallengeFileBytes(signedFile),
      forgeObservation: bundle.forgeObservation as ForgeObservationV1,
      eventId: bundle.eventId,
      sequence: bundle.sequence as number,
      occurredAt: bundle.occurredAt,
      now: runtime.now(),
      ...context,
    });
    await runtime.store.append(event);
    lines = renderAppendSuccess(event, Boolean(options.json));
  } else if (command === "attestation-verify-organization") {
    assertOnlyOptions(options, ["bundle", "json"]);
    if (!options.bundle) throw new Error("attestation-verify-organization requires --bundle <absolute-path>");
    const event = await appendTypedBundle(runtime, options.bundle, "organization_approved");
    lines = renderAppendSuccess(event, Boolean(options.json));
  } else if (command === "attestation-append-challenge") {
    assertOnlyOptions(options, ["bundle", "json"]);
    if (!options.bundle) throw new Error("attestation-append-challenge requires --bundle <absolute-path>");
    const event = await appendTypedBundle(runtime, options.bundle, "challenge_opened");
    lines = renderAppendSuccess(event, Boolean(options.json));
  } else if (command === "attestation-resolve") {
    assertOnlyOptions(options, ["bundle", "json"]);
    if (!options.bundle) throw new Error("attestation-resolve requires --bundle <absolute-path>");
    const event = await appendTypedBundle(runtime, options.bundle, "challenge_resolved");
    lines = renderAppendSuccess(event, Boolean(options.json));
  } else if (command === "attestation-revoke") {
    assertOnlyOptions(options, ["bundle", "json"]);
    if (!options.bundle) throw new Error("attestation-revoke requires --bundle <absolute-path>");
    const event = await appendTypedBundle(runtime, options.bundle, "attestation_revoked");
    lines = renderAppendSuccess(event, Boolean(options.json));
  } else {
    assertOnlyOptions(options, ["lockToken", "json"]);
    if (!options.lockToken) throw new Error("attestation-recover-lock requires --lock-token <exact-token>");
    const metadata = await runtime.store.readLockMetadata();
    const isProcessAlive = (pid: number): boolean => {
      try { process.kill(pid, 0); return true; } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
        throw new Error(`cannot prove PID ${pid} is absent`, { cause: error });
      }
    };
    await runtime.store.recoverStaleLock({ expectedToken: options.lockToken, isProcessAlive });
    lines = renderRecoveredLock(metadata, Boolean(options.json));
  }
  for (const line of lines) log(line);
}

// Pi client for the Wallet Kernel agent boundary. Pi knows one local bearer and
// fixed route names; it never receives wallet, payment, approval, or Spend
// Session authority.

import fs from "node:fs";
import crypto from "node:crypto";
import path from "node:path";

import type {
  AgentToolResult,
  AgentToolUpdateCallback,
  ExtensionAPI,
  ExtensionContext,
} from "@earendil-works/pi-coding-agent";

const DEFAULT_ORIGIN = "http://127.0.0.1:8402";
const DEFAULT_PROVIDER_NAME = "wallet-kernel";
const DEFAULT_MODEL_NAME = "wallet-kernel-model";
const DEFAULT_MODEL_ROUTE = "example-model";
const DEFAULT_SKILL_ROUTE = "example-skill";
const MAXIMUM_CREDENTIAL_BYTES = 256;
const MAXIMUM_TOOL_INPUT_BYTES = 262_144;
const MAXIMUM_RESPONSE_BYTES = 1_048_576;
const APPROVAL_WAIT_PREFERENCE = "wait=300";
const TOKEN_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const INSTANCE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;
const CREDENTIAL_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const RECEIPT_ID_PATTERN = /^[A-Za-z0-9:_-]{1,128}$/;
const HASH_PATTERN = /^[0-9a-f]{64}$/;
const REASON_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;
const ATOMIC_PATTERN = /^(0|[1-9][0-9]{0,77})$/;
const PURPOSE_PATTERN = /^[a-z][a-z0-9._-]{0,63}$/;
const EXPIRY_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TOOL_CALL_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

type PiEnvironment = Record<string, string | undefined>;
type PiCredential = Readonly<{
  agentInstanceId: string;
  schemaVersion: 1;
  token: string;
}>;
type FileSystem = Pick<typeof fs, "constants" | "openSync" | "fstatSync" | "readSync" | "closeSync">;
type InvokeSkillDetails = Readonly<{
  boundaryStatus: "returned" | "rejected" | "unavailable";
}>;

class PiBoundaryError extends Error {
  code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "PiBoundaryError";
    this.code = code;
  }
}

function fail(code: string, message: string): never {
  throw new PiBoundaryError(code, message);
}

function exactLoopbackOrigin(value: string | undefined): string {
  const candidate = value === undefined || value === "" ? DEFAULT_ORIGIN : value;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    fail("PI_KERNEL_ORIGIN_INVALID", "Wallet Kernel origin is invalid");
  }
  if (parsed.protocol !== "http:"
      || (parsed.hostname !== "127.0.0.1" && parsed.hostname !== "[::1]")
      || parsed.port === ""
      || parsed.username !== ""
      || parsed.password !== ""
      || parsed.pathname !== "/"
      || parsed.search !== ""
      || parsed.hash !== ""
      || candidate !== parsed.origin) {
    fail("PI_KERNEL_ORIGIN_INVALID", "Wallet Kernel origin must be one exact loopback origin");
  }
  return candidate;
}

function boundedToken(value: string | undefined, fallback: string, label: string): string {
  const candidate = value === undefined || value === "" ? fallback : value;
  if (!TOKEN_PATTERN.test(candidate)) {
    fail("PI_KERNEL_TOKEN_INVALID", `${label} must be one bounded token`);
  }
  return candidate;
}

function canonicalBase64url(value: unknown, bytes: number, pattern: RegExp): value is string {
  if (typeof value !== "string" || !pattern.test(value)) return false;
  const decoded = Buffer.from(value, "base64url");
  const valid = decoded.length === bytes && decoded.toString("base64url") === value;
  decoded.fill(0);
  return valid;
}

function validateCredential(value: unknown, text?: string): PiCredential {
  if (!value || typeof value !== "object" || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype) {
    fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential must be one object");
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 3
      || keys[0] !== "agentInstanceId"
      || keys[1] !== "schemaVersion"
      || keys[2] !== "token"
      || Reflect.ownKeys(record).length !== 3
      || record.schemaVersion !== 1
      || !canonicalBase64url(record.agentInstanceId, 16, INSTANCE_PATTERN)
      || !canonicalBase64url(record.token, 32, CREDENTIAL_TOKEN_PATTERN)) {
    fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential does not match the closed schema");
  }
  const credential = Object.freeze({
    agentInstanceId: record.agentInstanceId,
    schemaVersion: 1 as const,
    token: record.token,
  });
  const canonical = `{"agentInstanceId":"${credential.agentInstanceId}","schemaVersion":1,"token":"${credential.token}"}\n`;
  if (text !== undefined && text !== canonical) {
    fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential bytes are not canonical");
  }
  return credential;
}

function stableFileIdentity(stat: fs.BigIntStats) {
  return Object.freeze({
    device: stat.dev,
    inode: stat.ino,
    mode: stat.mode & 0o7777n,
    uid: stat.uid,
    nlink: stat.nlink,
    size: stat.size,
  });
}

export function readPiAgentCredential({
  filePath,
  fileSystem = fs,
  getuid = process.getuid,
}: {
  filePath: string;
  fileSystem?: FileSystem;
  getuid?: () => number;
}): PiCredential {
  const uid = typeof getuid === "function" ? getuid() : 0;
  if (!Number.isSafeInteger(uid) || uid <= 0) {
    fail("PI_AGENT_IDENTITY_INVALID", "Pi must run as one non-root OS identity");
  }
  if (typeof filePath !== "string" || !path.isAbsolute(filePath)
      || path.resolve(filePath) !== filePath) {
    fail("PI_AGENT_CREDENTIAL_PATH", "Agent credential path must be canonical and absolute");
  }
  const noFollow = fileSystem.constants.O_NOFOLLOW;
  if (!Number.isInteger(noFollow) || noFollow === 0) {
    fail("PI_AGENT_CREDENTIAL_OPEN", "O_NOFOLLOW is unavailable");
  }

  let descriptor: number;
  try {
    descriptor = fileSystem.openSync(
      filePath,
      fileSystem.constants.O_RDONLY | noFollow,
    );
  } catch {
    fail("PI_AGENT_CREDENTIAL_OPEN", "Agent credential could not be opened safely");
  }

  const bytes = Buffer.alloc(MAXIMUM_CREDENTIAL_BYTES + 1);
  try {
    let before: fs.BigIntStats;
    try {
      before = fileSystem.fstatSync(descriptor, { bigint: true }) as fs.BigIntStats;
    } catch {
      fail("PI_AGENT_CREDENTIAL_AUTHORITY", "Agent credential metadata is unavailable");
    }
    if (!before.isFile() || before.uid !== BigInt(uid)
        || (before.mode & 0o7777n) !== 0o600n
        || before.nlink !== 1n
        || before.size <= 0n
        || before.size > BigInt(MAXIMUM_CREDENTIAL_BYTES)) {
      fail("PI_AGENT_CREDENTIAL_AUTHORITY", "Agent credential authority is invalid");
    }

    let offset = 0;
    while (offset < bytes.length) {
      let count: number;
      try {
        count = fileSystem.readSync(
          descriptor,
          bytes,
          offset,
          bytes.length - offset,
          offset,
        );
      } catch {
        fail("PI_AGENT_CREDENTIAL_READ", "Agent credential could not be read");
      }
      if (count === 0) break;
      offset += count;
    }
    if (offset !== Number(before.size) || offset > MAXIMUM_CREDENTIAL_BYTES) {
      fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential size changed during read");
    }

    let after: fs.BigIntStats;
    try {
      after = fileSystem.fstatSync(descriptor, { bigint: true }) as fs.BigIntStats;
    } catch {
      fail("PI_AGENT_CREDENTIAL_AUTHORITY", "Agent credential metadata changed");
    }
    const beforeIdentity = stableFileIdentity(before);
    const afterIdentity = stableFileIdentity(after);
    if (Object.keys(beforeIdentity).some(
      (key) => beforeIdentity[key as keyof typeof beforeIdentity]
        !== afterIdentity[key as keyof typeof afterIdentity],
    )) {
      fail("PI_AGENT_CREDENTIAL_AUTHORITY", "Agent credential inode changed during read");
    }

    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(bytes.subarray(0, offset));
    } catch {
      fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential is not UTF-8");
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text.slice(0, -1));
    } catch {
      fail("PI_AGENT_CREDENTIAL_SCHEMA", "Agent credential is not canonical JSON");
    }
    return validateCredential(parsed, text);
  } finally {
    bytes.fill(0);
    try {
      fileSystem.closeSync(descriptor);
    } catch {
      // The held credential bytes have already been zeroed. A failed close is
      // terminal for activation and must not trigger a reopen.
      fail("PI_AGENT_CREDENTIAL_CLOSE", "Agent credential descriptor did not close");
    }
  }
}

export function loadPiExtensionConfiguration({
  env = process.env,
  readCredential = ({ filePath }: { filePath: string }) => readPiAgentCredential({ filePath }),
}: {
  env?: PiEnvironment;
  readCredential?: (input: { filePath: string }) => PiCredential;
} = {}) {
  // Validate every attacker-steerable network value before the bearer enters
  // memory. In particular, a hostile origin cannot cause a credential read.
  const origin = exactLoopbackOrigin(env.WALLET_KERNEL_ORIGIN);
  const providerName = boundedToken(
    env.WALLET_KERNEL_PROVIDER_NAME,
    DEFAULT_PROVIDER_NAME,
    "provider name",
  );
  const modelName = boundedToken(
    env.WALLET_KERNEL_MODEL_NAME,
    DEFAULT_MODEL_NAME,
    "model name",
  );
  const modelRoute = boundedToken(
    env.WALLET_KERNEL_MODEL_ROUTE,
    DEFAULT_MODEL_ROUTE,
    "model route",
  );
  const skillRoute = boundedToken(
    env.WALLET_KERNEL_SKILL_ROUTE,
    DEFAULT_SKILL_ROUTE,
    "Skill route",
  );
  const credentialPath = env.WALLET_KERNEL_AGENT_CREDENTIAL_FILE;
  if (typeof credentialPath !== "string" || credentialPath === ""
      || !path.isAbsolute(credentialPath)
      || path.resolve(credentialPath) !== credentialPath) {
    fail("PI_AGENT_CREDENTIAL_PATH", "Agent credential path must be canonical and absolute");
  }
  if (typeof readCredential !== "function") {
    fail("PI_AGENT_CREDENTIAL_READ", "Agent credential reader is invalid");
  }
  const credential = validateCredential(readCredential({ filePath: credentialPath }));
  return Object.freeze({
    origin,
    providerName,
    modelName,
    modelRoute,
    skillRoute,
    credential,
  });
}

function safeReason(value: unknown): string {
  return typeof value === "string" && REASON_PATTERN.test(value)
    ? value
    : "UNAVAILABLE";
}

function compactReceipt(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "receipt unavailable";
  }
  const receipt = value as Record<string, unknown>;
  if (typeof receipt.id !== "string" || !RECEIPT_ID_PATTERN.test(receipt.id)
      || typeof receipt.hash !== "string" || !HASH_PATTERN.test(receipt.hash)) {
    return "receipt unavailable";
  }
  return `receipt ${receipt.id} · sha256:${receipt.hash.slice(0, 12)}…`;
}

function safeOrigin(value: unknown): string {
  if (typeof value !== "string") return "seller unavailable";
  try {
    const parsed = new URL(value);
    const loopback = parsed.protocol === "http:"
      && (parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]")
      && parsed.port !== "";
    if ((parsed.protocol !== "https:" && !loopback)
        || parsed.username !== "" || parsed.password !== ""
        || parsed.pathname !== "/" || parsed.search !== "" || parsed.hash !== ""
        || parsed.origin !== value) {
      return "seller unavailable";
    }
    return value;
  } catch {
    return "seller unavailable";
  }
}

function completedResource(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const resource = value as Record<string, unknown>;
  if (typeof resource.body === "string") return resource.body;
  if (resource.body && typeof resource.body === "object" && !Array.isArray(resource.body)) {
    const body = resource.body as Record<string, unknown>;
    if (typeof body.output === "string") return body.output;
    try {
      return JSON.stringify(body);
    } catch {
      return null;
    }
  }
  return null;
}

function completedSummary(receiptValue: unknown): string {
  const compact = compactReceipt(receiptValue);
  if (!receiptValue || typeof receiptValue !== "object" || Array.isArray(receiptValue)) {
    return compact;
  }
  const receipt = receiptValue as Record<string, unknown>;
  const charged = typeof receipt.chargedAtomic === "string" && ATOMIC_PATTERN.test(receipt.chargedAtomic)
    ? receipt.chargedAtomic
    : "unavailable";
  const remaining = typeof receipt.remainingSessionAtomic === "string"
      && ATOMIC_PATTERN.test(receipt.remainingSessionAtomic)
    ? receipt.remainingSessionAtomic
    : "unavailable";
  const transaction = typeof receipt.transactionPrefix === "string"
      && /^0x[0-9a-f]{1,64}$/.test(receipt.transactionPrefix)
    ? receipt.transactionPrefix
    : "unavailable";
  return `${compact} · charged ${charged} atomic · remaining ${remaining} atomic · tx ${transaction}`;
}

function completedReplaySummary(outcome: Record<string, unknown>): string | null {
  if (outcome.terminalStatus !== "completed"
      || typeof outcome.requestId !== "string"
      || !RECEIPT_ID_PATTERN.test(outcome.requestId)
      || !outcome.projections || typeof outcome.projections !== "object"
      || Array.isArray(outcome.projections)
      || !outcome.receipt || typeof outcome.receipt !== "object"
      || Array.isArray(outcome.receipt)) {
    return null;
  }
  const projections = outcome.projections as Record<string, unknown>;
  const receipt = outcome.receipt as Record<string, unknown>;
  if (typeof receipt.id !== "string" || !RECEIPT_ID_PATTERN.test(receipt.id)
      || projections.request !== `/agent/v1/intents/${outcome.requestId}`
      || projections.receipt !== `/agent/v1/receipts/${receipt.id}`) {
    return null;
  }
  return `Completed replay: the charge is already recorded, provider output was not retained, and retrying this same call key will not spend again. Inspect ${projections.request} and ${projections.receipt}. ${compactReceipt(receipt)}`;
}

export function renderWalletKernelOutcome(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return "Wallet Kernel returned an unsupported outcome.";
  }
  const outcome = value as Record<string, unknown>;
  const receipt = compactReceipt(outcome.receipt);
  const reason = safeReason(outcome.reasonCode);
  switch (outcome.status) {
    case "completed": {
      const resource = completedResource(outcome.resource);
      if (resource === null) return "Wallet Kernel returned an unsupported outcome.";
      return `${resource}\n\n[completed · ${completedSummary(outcome.receipt)}]`;
    }
    case "completed_replay":
      return completedReplaySummary(outcome)
        ?? "Wallet Kernel returned an unsupported outcome.";
    case "payment_approval_required": {
      if (!outcome.approval || typeof outcome.approval !== "object"
          || Array.isArray(outcome.approval)) {
        return "Wallet Kernel returned an unsupported outcome.";
      }
      const approval = outcome.approval as Record<string, unknown>;
      const seller = safeOrigin(approval.sellerOrigin);
      const amount = typeof approval.amountAtomic === "string"
          && ATOMIC_PATTERN.test(approval.amountAtomic)
        ? approval.amountAtomic
        : "unavailable";
      const purpose = typeof approval.purposeLabel === "string"
          && PURPOSE_PATTERN.test(approval.purposeLabel)
        ? approval.purposeLabel
        : "purpose unavailable";
      const expiresAt = typeof approval.expiresAt === "string"
          && EXPIRY_PATTERN.test(approval.expiresAt)
          && Number.isFinite(Date.parse(approval.expiresAt))
        ? approval.expiresAt
        : "expiry unavailable";
      return `Approval required: ${seller} · ${amount} atomic · ${purpose} · expires ${expiresAt}. Retry the same tool call after an operator decision.`;
    }
    case "payment_denied":
      return `Payment denied: ${reason} · ${receipt}`;
    case "payment_rejected":
      return `Payment rejected or expired: ${reason} · ${receipt}`;
    case "payment_failed":
      return `Payment failed before settlement: ${reason} · ${receipt}`;
    case "payment_unresolved":
      return `Payment unresolved: ${reason} · ${receipt}`;
    case "upstream_failed":
      return `Upstream failed before payment: ${reason} · ${receipt}`;
    case "execution_failed":
      return `Execution failed after settlement: ${reason} · ${receipt}`;
    case "execution_unknown":
      return `Execution outcome unknown after settlement: ${reason} · ${receipt}`;
    case "refunded":
      return `Refunded: ${reason} · ${receipt}`;
    default:
      return "Wallet Kernel returned an unsupported outcome.";
  }
}

async function readBoundedOutcome(response: Response): Promise<unknown> {
  const contentType = response.headers.get("content-type") ?? "";
  if (!/^application\/json(?:;[ \t]*charset=[A-Za-z0-9._-]+)?$/i.test(contentType)) {
    fail("PI_KERNEL_RESPONSE_INVALID", "Wallet Kernel response is not JSON");
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > MAXIMUM_RESPONSE_BYTES) {
    fail("PI_KERNEL_RESPONSE_INVALID", "Wallet Kernel response is oversized");
  }
  try {
    return JSON.parse(text);
  } catch {
    fail("PI_KERNEL_RESPONSE_INVALID", "Wallet Kernel response is malformed");
  }
}

function agentToolText(
  text: string,
  boundaryStatus: InvokeSkillDetails["boundaryStatus"],
): AgentToolResult<InvokeSkillDetails> {
  return {
    content: [{ type: "text", text }],
    details: { boundaryStatus },
  };
}

function toolAgentCallId(toolCallId: string): string | null {
  if (!TOOL_CALL_ID_PATTERN.test(toolCallId)) return null;
  return crypto.createHash("sha256")
    .update("wallet-kernel.pi-tool-call.v1\0", "utf8")
    .update(toolCallId, "utf8")
    .digest("base64url");
}

function randomAgentCallId(): string {
  const bytes = crypto.randomBytes(32);
  try {
    return bytes.toString("base64url");
  } finally {
    bytes.fill(0);
  }
}

function exactHeader(headers: Record<string, string | null>, name: string): string | null {
  const matches = Object.entries(headers)
    .filter(([key]) => key.toLowerCase() === name)
    .map(([, value]) => value);
  return matches.length === 1 && typeof matches[0] === "string" ? matches[0] : null;
}

function replaceHeader(
  headers: Record<string, string | null>,
  name: string,
  value: string,
) {
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === name) delete headers[key];
  }
  headers[name] = value;
}

function throwIfAborted(signal: AbortSignal | undefined) {
  if (signal?.aborted) {
    throw new DOMException("Wallet Kernel call aborted", "AbortError");
  }
}

export default function activate(
  pi: ExtensionAPI,
  options: {
    env?: PiEnvironment;
    fetchFn?: typeof fetch;
    readCredential?: (input: { filePath: string }) => PiCredential;
  } = {},
) {
  const config = loadPiExtensionConfiguration({
    env: options.env,
    readCredential: options.readCredential,
  });
  const fetchFn = options.fetchFn ?? globalThis.fetch;
  if (!pi || typeof pi.registerProvider !== "function"
      || typeof pi.registerTool !== "function" || typeof pi.on !== "function"
      || typeof fetchFn !== "function") {
    fail("PI_EXTENSION_API_INVALID", "Pi extension API is unavailable");
  }
  const headers = Object.freeze({
    Authorization: `WalletKernelAgent ${config.credential.token}`,
    "Content-Type": "application/json",
    Prefer: APPROVAL_WAIT_PREFERENCE,
  });
  const walletAuthorization = headers.Authorization;
  let pendingModelCallId: string | null = null;

  pi.on("before_provider_headers", (event) => {
    if (exactHeader(event.headers, "authorization") !== walletAuthorization) return;
    pendingModelCallId ??= randomAgentCallId();
    replaceHeader(event.headers, "Prefer", APPROVAL_WAIT_PREFERENCE);
    replaceHeader(event.headers, "x-agent-call-id", pendingModelCallId);
  });
  pi.on("message_end", (event) => {
    const message = event.message;
    if (pendingModelCallId !== null
        && message.role === "assistant"
        && message.provider === config.providerName
        && message.model === config.modelName
        && message.stopReason !== "error"
        && message.stopReason !== "aborted") {
      pendingModelCallId = null;
    }
  });
  pi.on("agent_settled", () => {
    pendingModelCallId = null;
  });

  pi.registerProvider(config.providerName, {
    baseUrl: `${config.origin}/agent/v1/openai/${config.modelRoute}`,
    apiKey: "wallet-kernel-local",
    api: "openai-completions",
    authHeader: false,
    headers,
    models: [
      {
        id: config.modelName,
        name: config.modelName,
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128_000,
        maxTokens: 8_192,
        compat: { sendSessionAffinityHeaders: false },
      },
    ],
  });

  pi.registerTool({
    name: "invoke_skill",
    label: "Invoke Skill",
    description: "Invoke the fixed Skill route through the local Wallet Kernel.",
    parameters: {
      type: "object",
      properties: {
        input: { type: "string", description: "Input for the configured Skill" },
      },
      required: ["input"],
      additionalProperties: false,
    },
    async execute(
      toolCallId: string,
      params: { input: string },
      signal: AbortSignal | undefined,
      _onUpdate: AgentToolUpdateCallback<InvokeSkillDetails> | undefined,
      _ctx: ExtensionContext,
    ): Promise<AgentToolResult<InvokeSkillDetails>> {
      const agentCallId = typeof toolCallId === "string"
        ? toolAgentCallId(toolCallId)
        : null;
      if (agentCallId === null
          || !params || typeof params !== "object" || Array.isArray(params)
          || Reflect.ownKeys(params).length !== 1
          || typeof params.input !== "string"
          || Buffer.byteLength(params.input, "utf8") > MAXIMUM_TOOL_INPUT_BYTES) {
        return agentToolText("invoke_skill call rejected.", "rejected");
      }
      const requestHeaders = Object.freeze({
        ...headers,
        "x-agent-call-id": agentCallId,
      });
      for (let attempt = 0; attempt < 2; attempt += 1) {
        throwIfAborted(signal);
        try {
          const response = await fetchFn(
            `${config.origin}/agent/v1/invoke/${config.skillRoute}`,
            {
              method: "POST",
              headers: requestHeaders,
              body: JSON.stringify({ input: params.input }),
              signal,
            },
          );
          const outcome = await readBoundedOutcome(response);
          return agentToolText(renderWalletKernelOutcome(outcome), "returned");
        } catch {
          throwIfAborted(signal);
          if (attempt === 1) {
            return agentToolText(
              "Wallet Kernel unavailable after one same-key retry.",
              "unavailable",
            );
          }
        }
      }
      return agentToolText("Wallet Kernel unavailable after one same-key retry.", "unavailable");
    },
  });
}

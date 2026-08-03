import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";

import type {
  DemoMetadataProvider,
  DemoSkillDefinition,
  PreparedMetadata,
} from "./demo";
import type { DemoStage } from "./registrations";

export type StageMetadataUris = Partial<Record<DemoStage, {
  ip: string;
  nft: string;
}>>;

export interface HttpMetadataProviderOptions {
  fetcher?: typeof fetch;
  stageUris?: StageMetadataUris;
  pinataJwt?: string;
  publicGatewayBaseUrl?: string;
  signal?: AbortSignal;
}

const PINATA_PUBLIC_UPLOAD_URL = "https://uploads.pinata.cloud/v3/files";
const DEFAULT_PUBLIC_GATEWAY_BASE_URL = "https://gateway.pinata.cloud/ipfs/";
const STAGES: readonly DemoStage[] = ["root", "child", "grandchild"];

/** Total wall-clock budget for one upload or gateway verification, including its body. */
export const METADATA_HTTP_TIMEOUT_MS = 15_000;
/** Pinata's upload acknowledgement is JSON metadata, never an artifact body. */
export const PINATA_UPLOAD_RESPONSE_MAX_BYTES = 16 * 1024;
/** One sentinel byte distinguishes an exact gateway match from a chunked overflow. */
export const METADATA_VERIFICATION_OVERFLOW_PROBE_BYTES = 1;

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException("The operation was aborted", "AbortError");
}

async function withHttpDeadline<T>(
  label: string,
  callerSignal: AbortSignal | undefined,
  operation: (signal: AbortSignal) => Promise<T>,
): Promise<T> {
  const deadline = new AbortController();
  const timeoutError = new Error(`${label} timed out after ${METADATA_HTTP_TIMEOUT_MS} ms`);
  timeoutError.name = "TimeoutError";
  const timeout = setTimeout(() => deadline.abort(timeoutError), METADATA_HTTP_TIMEOUT_MS);
  const signal = callerSignal
    ? AbortSignal.any([callerSignal, deadline.signal])
    : deadline.signal;
  let onAbort: (() => void) | undefined;

  try {
    if (signal.aborted) throw abortReason(signal);
    const aborted = new Promise<never>((_resolve, reject) => {
      onAbort = () => reject(abortReason(signal));
      signal.addEventListener("abort", onAbort, { once: true });
    });
    return await Promise.race([operation(signal), aborted]);
  } finally {
    clearTimeout(timeout);
    if (onAbort) signal.removeEventListener("abort", onAbort);
  }
}

async function cancelReader(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  reason?: unknown,
): Promise<void> {
  try {
    await reader.cancel(reason);
  } catch {
    // Cancellation is best-effort; retain the bounded operation's sanitized error.
  }
}

async function readBoundedResponseBody(input: {
  response: Response;
  maxBytes: number;
  overflowProbeBytes?: number;
  label: string;
  signal: AbortSignal;
}): Promise<Uint8Array> {
  const overflowProbeBytes = input.overflowProbeBytes ?? 0;
  if (
    !Number.isSafeInteger(input.maxBytes)
    || input.maxBytes < 0
    || !Number.isSafeInteger(overflowProbeBytes)
    || overflowProbeBytes < 0
    || input.maxBytes > Number.MAX_SAFE_INTEGER - overflowProbeBytes
  ) {
    throw new Error("Metadata response byte limit is invalid");
  }
  if (input.signal.aborted) throw abortReason(input.signal);
  const readLimitBytes = input.maxBytes + overflowProbeBytes;
  const limitError = () => new Error(`${input.label} exceeds ${input.maxBytes}-byte limit`);
  const contentLength = input.response.headers.get("content-length");
  if (contentLength !== null) {
    if (!/^\d+$/.test(contentLength)) {
      throw new Error(`${input.label} has an invalid Content-Length`);
    }
    if (BigInt(contentLength) > BigInt(input.maxBytes)) throw limitError();
  }
  if (!input.response.body) return new Uint8Array();

  const reader = input.response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  const onAbort = () => {
    void cancelReader(reader, abortReason(input.signal));
  };
  input.signal.addEventListener("abort", onAbort, { once: true });

  try {
    while (true) {
      if (input.signal.aborted) throw abortReason(input.signal);
      let result: ReadableStreamReadResult<Uint8Array>;
      try {
        result = await reader.read();
      } catch {
        if (input.signal.aborted) throw abortReason(input.signal);
        throw new Error(`${input.label} could not be read`);
      }
      if (result.done) break;
      const chunk = result.value;
      if (chunk.byteLength > readLimitBytes - totalBytes) {
        await cancelReader(reader);
        throw limitError();
      }
      if (chunk.byteLength === 0) continue;
      chunks.push(chunk);
      totalBytes += chunk.byteLength;
      if (totalBytes > input.maxBytes) {
        await cancelReader(reader);
        throw limitError();
      }
    }
  } finally {
    input.signal.removeEventListener("abort", onAbort);
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

function sha256Hex(bytes: Uint8Array): `0x${string}` {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

function strictHttpsUrl(value: string, label: string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${label} must be a valid HTTPS URL`);
  }
  if (url.protocol !== "https:") throw new Error(`${label} must use HTTPS`);
  if (url.username || url.password) throw new Error(`${label} must not contain credentials`);
  if (url.search) throw new Error(`${label} must not contain a query`);
  if (url.hash) throw new Error(`${label} must not contain a fragment`);
  if (!/^https:\/\/[^/:?#]+(?:\/|$)/.test(value)) {
    throw new Error(`${label} must not contain an explicit port or malformed authority`);
  }
  return url;
}

function isAllowedPinataGatewayHost(hostname: string): boolean {
  return hostname === "gateway.pinata.cloud"
    || /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.mypinata\.cloud$/.test(hostname);
}

export function validatePublicGatewayBaseUrl(value: string): string {
  const url = strictHttpsUrl(value, "IPFS public gateway base URL");
  if (!isAllowedPinataGatewayHost(url.hostname)) {
    throw new Error("IPFS public gateway must use gateway.pinata.cloud or a mypinata.cloud subdomain");
  }
  if (url.pathname !== "/ipfs/") {
    throw new Error("IPFS public gateway path must be exactly /ipfs/");
  }
  return url.toString();
}

export function validateStageMetadataUri(
  value: string,
  gatewayBaseUrl: string,
  label: string,
): string {
  const base = new URL(validatePublicGatewayBaseUrl(gatewayBaseUrl));
  const url = strictHttpsUrl(value, label);
  if (url.origin !== base.origin) {
    throw new Error(`${label} origin must exactly match the configured public gateway`);
  }
  if (!url.pathname.startsWith(base.pathname)) {
    throw new Error(`${label} path must start with ${base.pathname}`);
  }
  const cid = url.pathname.slice(base.pathname.length);
  if (!/^b[a-z0-9]+$/.test(cid)) {
    throw new Error(`${label} must end in exactly one lowercase CID and no extra path`);
  }
  return url.toString();
}

async function pinPublicJson(input: {
  fetcher: typeof fetch;
  jwt: string;
  gatewayBaseUrl: string;
  name: string;
  bytes: Uint8Array;
  signal?: AbortSignal;
}): Promise<string> {
  const form = new FormData();
  form.set("network", "public");
  form.set("name", input.name);
  form.set("file", new Blob([Buffer.from(input.bytes)], { type: "application/json" }), input.name);
  return withHttpDeadline("Metadata pin request", input.signal, async (signal) => {
    let response: Response;
    try {
      response = await input.fetcher(PINATA_PUBLIC_UPLOAD_URL, {
        method: "POST",
        headers: { Authorization: `Bearer ${input.jwt}` },
        body: form,
        redirect: "error",
        signal,
      });
    } catch {
      if (signal.aborted) throw abortReason(signal);
      throw new Error("Metadata pin request failed");
    }
    if (signal.aborted) throw abortReason(signal);
    if (!response.ok) throw new Error(`Metadata pin failed (${response.status})`);
    const responseBytes = await readBoundedResponseBody({
      response,
      maxBytes: PINATA_UPLOAD_RESPONSE_MAX_BYTES,
      label: "Metadata pin response",
      signal,
    });
    let body: { data?: { cid?: string } };
    try {
      body = JSON.parse(Buffer.from(responseBytes).toString("utf8")) as typeof body;
    } catch {
      throw new Error("Metadata pin response is not valid JSON");
    }
    const cid = body?.data?.cid;
    if (!cid || !/^b[a-z0-9]+$/.test(cid)) {
      throw new Error("Pinata response is missing a public CID");
    }
    return new URL(
      cid,
      input.gatewayBaseUrl.endsWith("/") ? input.gatewayBaseUrl : `${input.gatewayBaseUrl}/`,
    ).toString();
  });
}

async function verifyExactBytes(
  fetcher: typeof fetch,
  uri: string,
  expectedBytes: Uint8Array,
  expectedHash: `0x${string}`,
  callerSignal?: AbortSignal,
): Promise<void> {
  await withHttpDeadline("Metadata fetch request", callerSignal, async (signal) => {
    let response: Response;
    try {
      response = await fetcher(uri, { redirect: "error", signal });
    } catch {
      if (signal.aborted) throw abortReason(signal);
      throw new Error(`Metadata fetch request failed for ${uri}`);
    }
    if (signal.aborted) throw abortReason(signal);
    if (!response.ok) {
      throw new Error(`Metadata fetch failed (${response.status}) for ${uri}`);
    }
    const fetched = await readBoundedResponseBody({
      response,
      maxBytes: expectedBytes.byteLength,
      overflowProbeBytes: METADATA_VERIFICATION_OVERFLOW_PROBE_BYTES,
      label: "Fetched metadata",
      signal,
    });
    if (!Buffer.from(fetched).equals(Buffer.from(expectedBytes))) {
      throw new Error(`Fetched metadata bytes do not match the serialized metadata for ${uri}`);
    }
    if (sha256Hex(fetched) !== expectedHash) {
      throw new Error(`Fetched metadata SHA-256 does not match the expected hash for ${uri}`);
    }
  });
}

function envStageUris(): StageMetadataUris {
  const configured: StageMetadataUris = {};
  for (const stage of STAGES) {
    const prefix = stage.toUpperCase();
    const ip = process.env[`${prefix}_IP_METADATA_URI`]?.trim();
    const nft = process.env[`${prefix}_NFT_METADATA_URI`]?.trim();
    if (ip || nft) configured[stage] = { ip: ip ?? "", nft: nft ?? "" };
  }
  return configured;
}

export class HttpMetadataProvider implements DemoMetadataProvider {
  private readonly fetcher: typeof fetch;
  private readonly rawStageUris: StageMetadataUris;
  private readonly pinataJwt?: string;
  private readonly rawPublicGatewayBaseUrl: string;
  private readonly signal?: AbortSignal;
  private validated?: { gatewayBaseUrl: string; stageUris: StageMetadataUris };

  constructor(options: HttpMetadataProviderOptions = {}) {
    this.fetcher = options.fetcher ?? fetch;
    this.rawStageUris = options.stageUris ?? envStageUris();
    this.pinataJwt = options.pinataJwt !== undefined
      ? options.pinataJwt.trim() || undefined
      : process.env.PINATA_JWT?.trim() || undefined;
    this.rawPublicGatewayBaseUrl = options.publicGatewayBaseUrl
      ?? process.env.IPFS_PUBLIC_GATEWAY_BASE_URL?.trim()
      ?? DEFAULT_PUBLIC_GATEWAY_BASE_URL;
    this.signal = options.signal;
  }

  private configuration(): { gatewayBaseUrl: string; stageUris: StageMetadataUris } {
    if (this.validated) return this.validated;
    const gatewayBaseUrl = validatePublicGatewayBaseUrl(this.rawPublicGatewayBaseUrl);
    const stageUris: StageMetadataUris = {};
    for (const stage of STAGES) {
      const pair = this.rawStageUris[stage];
      if (!pair) continue;
      if (!pair.ip || !pair.nft) {
        throw new Error(`${stage.toUpperCase()} metadata overrides must provide both IP and NFT URIs`);
      }
      stageUris[stage] = {
        ip: validateStageMetadataUri(pair.ip, gatewayBaseUrl, `${stage.toUpperCase()}_IP_METADATA_URI`),
        nft: validateStageMetadataUri(pair.nft, gatewayBaseUrl, `${stage.toUpperCase()}_NFT_METADATA_URI`),
      };
    }
    this.validated = { gatewayBaseUrl, stageUris };
    return this.validated;
  }

  async prepare(
    input: DemoSkillDefinition & { creatorAddress: `0x${string}` },
  ): Promise<PreparedMetadata> {
    const configuration = this.configuration();
    const artifactBytes = await readFile(input.artifactPath);
    const mediaHash = sha256Hex(artifactBytes);
    const ipMetadata = {
      title: input.name,
      description: input.description,
      createdAt: "0",
      ipType: "skill",
      creators: [
        { name: "creator", address: input.creatorAddress, contributionPercent: 100 },
      ],
      mediaHash,
      mediaType: "text/markdown",
    };
    const nftMetadata = { name: input.name, description: input.description };

    const ipBytes = Buffer.from(JSON.stringify(ipMetadata), "utf8");
    const nftBytes = Buffer.from(JSON.stringify(nftMetadata), "utf8");
    const ipMetadataHash = sha256Hex(ipBytes);
    const nftMetadataHash = sha256Hex(nftBytes);
    const override = configuration.stageUris[input.stage];
    if (!override && !this.pinataJwt) {
      throw new Error(`PINATA_JWT is required to publish durable metadata for ${input.stage}`);
    }

    const ipMetadataURI = override?.ip ?? await pinPublicJson({
      fetcher: this.fetcher,
      jwt: this.pinataJwt!,
      gatewayBaseUrl: configuration.gatewayBaseUrl,
      name: `${input.stage}-ip-metadata.json`,
      bytes: ipBytes,
      signal: this.signal,
    });
    const nftMetadataURI = override?.nft ?? await pinPublicJson({
      fetcher: this.fetcher,
      jwt: this.pinataJwt!,
      gatewayBaseUrl: configuration.gatewayBaseUrl,
      name: `${input.stage}-nft-metadata.json`,
      bytes: nftBytes,
      signal: this.signal,
    });

    await verifyExactBytes(this.fetcher, ipMetadataURI, ipBytes, ipMetadataHash, this.signal);
    await verifyExactBytes(this.fetcher, nftMetadataURI, nftBytes, nftMetadataHash, this.signal);

    const artifactPath = isAbsolute(input.artifactPath)
      ? relative(process.cwd(), input.artifactPath)
      : input.artifactPath;

    return {
      onchain: {
        ipMetadataURI,
        ipMetadataHash,
        nftMetadataURI,
        nftMetadataHash,
      },
      proof: {
        ip: { uri: ipMetadataURI, hash: ipMetadataHash },
        nft: { uri: nftMetadataURI, hash: nftMetadataHash },
        artifact: { path: artifactPath, mediaHash, mediaType: "text/markdown" },
      },
    };
  }
}

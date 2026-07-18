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
}

const PINATA_PUBLIC_UPLOAD_URL = "https://uploads.pinata.cloud/v3/files";
const DEFAULT_PUBLIC_GATEWAY_BASE_URL = "https://gateway.pinata.cloud/ipfs/";
const STAGES: readonly DemoStage[] = ["root", "child", "grandchild"];

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
}): Promise<string> {
  const form = new FormData();
  form.set("network", "public");
  form.set("name", input.name);
  form.set("file", new Blob([Buffer.from(input.bytes)], { type: "application/json" }), input.name);
  const response = await input.fetcher(PINATA_PUBLIC_UPLOAD_URL, {
    method: "POST",
    headers: { Authorization: `Bearer ${input.jwt}` },
    body: form,
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Metadata pin failed (${response.status})`);
  const body = await response.json() as { data?: { cid?: string } };
  const cid = body.data?.cid;
  if (!cid || !/^b[a-z0-9]+$/.test(cid)) {
    throw new Error("Pinata response is missing a public CID");
  }
  return new URL(
    cid,
    input.gatewayBaseUrl.endsWith("/") ? input.gatewayBaseUrl : `${input.gatewayBaseUrl}/`,
  ).toString();
}

async function verifyExactBytes(
  fetcher: typeof fetch,
  uri: string,
  expectedBytes: Uint8Array,
  expectedHash: `0x${string}`,
): Promise<void> {
  const response = await fetcher(uri, { redirect: "error" });
  if (!response.ok) {
    throw new Error(`Metadata fetch failed (${response.status}) for ${uri}`);
  }
  const fetched = new Uint8Array(await response.arrayBuffer());
  if (!Buffer.from(fetched).equals(Buffer.from(expectedBytes))) {
    throw new Error(`Fetched metadata bytes do not match the serialized metadata for ${uri}`);
  }
  if (sha256Hex(fetched) !== expectedHash) {
    throw new Error(`Fetched metadata SHA-256 does not match the expected hash for ${uri}`);
  }
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
    });
    const nftMetadataURI = override?.nft ?? await pinPublicJson({
      fetcher: this.fetcher,
      jwt: this.pinataJwt!,
      gatewayBaseUrl: configuration.gatewayBaseUrl,
      name: `${input.stage}-nft-metadata.json`,
      bytes: nftBytes,
    });

    await verifyExactBytes(this.fetcher, ipMetadataURI, ipBytes, ipMetadataHash);
    await verifyExactBytes(this.fetcher, nftMetadataURI, nftBytes, nftMetadataHash);

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

import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative } from "node:path";

import type {
  DemoMetadataProvider,
  DemoSkillDefinition,
  PreparedMetadata,
} from "./demo";

export interface HttpMetadataProviderOptions {
  fetcher?: typeof fetch;
  ipMetadataURI?: string;
  nftMetadataURI?: string;
}

function sha256Hex(bytes: Uint8Array): `0x${string}` {
  return `0x${createHash("sha256").update(bytes).digest("hex")}`;
}

function inlineHttpsUri(bytes: Uint8Array): string {
  const unpadded = Buffer.from(bytes).toString("base64url");
  const padding = (4 - (unpadded.length % 4)) % 4;
  return `https://httpbin.org/base64/${unpadded}${"=".repeat(padding)}`;
}

function requireHttps(uri: string, label: string): string {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error(`${label} must be a valid HTTPS URL`);
  }
  if (parsed.protocol !== "https:") {
    throw new Error(`${label} must use HTTPS`);
  }
  return parsed.toString();
}

async function verifyExactBytes(
  fetcher: typeof fetch,
  uri: string,
  expectedBytes: Uint8Array,
  expectedHash: `0x${string}`,
): Promise<void> {
  const response = await fetcher(uri);
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

export class HttpMetadataProvider implements DemoMetadataProvider {
  private readonly fetcher: typeof fetch;
  private readonly ipMetadataURI?: string;
  private readonly nftMetadataURI?: string;

  constructor(options: HttpMetadataProviderOptions = {}) {
    this.fetcher = options.fetcher ?? fetch;
    this.ipMetadataURI = options.ipMetadataURI ?? (process.env.IP_METADATA_URI?.trim() || undefined);
    this.nftMetadataURI = options.nftMetadataURI ?? (process.env.NFT_METADATA_URI?.trim() || undefined);
  }

  async prepare(
    input: DemoSkillDefinition & { creatorAddress: `0x${string}` },
  ): Promise<PreparedMetadata> {
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

    // Serialize each document exactly once. These exact bytes are encoded into the
    // default URI, hashed, fetched back, and compared before a Story write.
    const ipBytes = Buffer.from(JSON.stringify(ipMetadata), "utf8");
    const nftBytes = Buffer.from(JSON.stringify(nftMetadata), "utf8");
    const ipMetadataHash = sha256Hex(ipBytes);
    const nftMetadataHash = sha256Hex(nftBytes);
    const ipMetadataURI = requireHttps(
      this.ipMetadataURI ?? inlineHttpsUri(ipBytes),
      "IP_METADATA_URI",
    );
    const nftMetadataURI = requireHttps(
      this.nftMetadataURI ?? inlineHttpsUri(nftBytes),
      "NFT_METADATA_URI",
    );

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

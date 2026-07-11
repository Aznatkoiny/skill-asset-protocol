import { readFileSync } from "node:fs";
import { keccak256, toHex } from "viem";
import type { StoryClient } from "@story-protocol/core-sdk";

export interface SkillInput {
  name: string;
  description: string;
  creatorAddress: `0x${string}`;
  /** Optional path to the real SKILL.md / artifact — its content is hashed for provenance. */
  skillFile?: string;
}

/**
 * Build the IP + NFT metadata for a Skill and the on-chain {uri, hash} pairs the
 * register calls expect. `createdAt` is fixed so the metadata (and its hash) is
 * reproducible — do not inject a wall-clock time here.
 */
export function buildMetadata(client: StoryClient, input: SkillInput) {
  let contentHash: `0x${string}` | undefined;
  if (input.skillFile) {
    const content = readFileSync(input.skillFile, "utf8");
    contentHash = keccak256(toHex(content)); // fingerprint of the actual artifact
  }

  const ipMetadata = client.ipAsset.generateIpMetadata({
    title: input.name,
    description: input.description,
    createdAt: "0",
    ipType: "skill",
    creators: [
      { name: "creator", address: input.creatorAddress, contributionPercent: 100 },
    ],
    ...(contentHash ? { mediaHash: contentHash, mediaType: "text/markdown" } : {}),
  });

  const nftMetadata = { name: input.name, description: input.description };

  const onchain = {
    ipMetadataURI: process.env.IP_METADATA_URI || "ipfs://placeholder-ip-metadata",
    ipMetadataHash: keccak256(toHex(JSON.stringify(ipMetadata))),
    nftMetadataURI: process.env.NFT_METADATA_URI || "ipfs://placeholder-nft-metadata",
    nftMetadataHash: keccak256(toHex(JSON.stringify(nftMetadata))),
  };

  return { ipMetadata, nftMetadata, contentHash, onchain };
}

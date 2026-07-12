import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { HttpMetadataProvider } from "../src/metadata";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const ARTIFACT = "# Fixture Skill\n\nReturn one concise answer.\n";
const ARTIFACT_HASH = "0x316163c97d7669db8b33fc52d05d458318acec1aad98fc5515b2f0f508957912";
const IP_HASH = "0x6c42a18b50e58fbe307da28995b381d6c5690f7815070733946c20344b58bae9";
const NFT_HASH = "0xdb24ac9487196af7c830b213c8127f08b3b2c12eb2baeb1fcc6625281ab16098";
const IP_JSON = `{"title":"Fixture Skill","description":"fixture","createdAt":"0","ipType":"skill","creators":[{"name":"creator","address":"${WALLET}","contributionPercent":100}],"mediaHash":"${ARTIFACT_HASH}","mediaType":"text/markdown"}`;
const NFT_JSON = '{"name":"Fixture Skill","description":"fixture"}';

async function withArtifact(t: test.TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "phase0-metadata-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "SKILL.md");
  await writeFile(path, ARTIFACT, "utf8");
  return path;
}

function decodeHttpbin(input: string | URL | Request): Response {
  const url = new URL(String(input));
  assert.equal(url.origin, "https://httpbin.org");
  assert.match(url.pathname, /^\/base64\//);
  const encoded = url.pathname.slice("/base64/".length);
  if (encoded.length % 4 !== 0) return new Response("Incorrect Base64 data");
  return new Response(Buffer.from(encoded, "base64url"));
}

test("metadata HTTPS URIs decode to exact serialized bytes with Story SHA-256 hashes", async (t) => {
  const artifactPath = await withArtifact(t);
  const fetched: string[] = [];
  const provider = new HttpMetadataProvider({
    fetcher: async (input) => {
      fetched.push(String(input));
      return decodeHttpbin(input);
    },
  });

  const prepared = await provider.prepare({
    stage: "root",
    name: "Fixture Skill",
    description: "fixture",
    creatorAddress: WALLET,
    artifactPath,
  });

  assert.equal(prepared.proof.artifact.mediaHash, ARTIFACT_HASH);
  assert.equal(prepared.onchain.ipMetadataHash, IP_HASH);
  assert.equal(prepared.onchain.nftMetadataHash, NFT_HASH);
  assert.equal(prepared.proof.ip.hash, IP_HASH);
  assert.equal(prepared.proof.nft.hash, NFT_HASH);
  assert.equal(fetched.length, 2);
  assert.equal(Buffer.from(new URL(fetched[0]).pathname.slice("/base64/".length), "base64url").toString(), IP_JSON);
  assert.equal(Buffer.from(new URL(fetched[1]).pathname.slice("/base64/".length), "base64url").toString(), NFT_JSON);
});

test("altered fetched metadata bytes are rejected", async (t) => {
  const artifactPath = await withArtifact(t);
  const provider = new HttpMetadataProvider({
    fetcher: async () => new Response("altered"),
  });

  await assert.rejects(
    provider.prepare({
      stage: "root",
      name: "Fixture Skill",
      description: "fixture",
      creatorAddress: WALLET,
      artifactPath,
    }),
    /fetched metadata bytes do not match/i,
  );
});

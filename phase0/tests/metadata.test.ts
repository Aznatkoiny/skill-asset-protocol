import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import type { DemoStage } from "../src/registrations";
import { HttpMetadataProvider } from "../src/metadata";

const WALLET = "0x00000000000000000000000000000000000000aa" as const;
const ARTIFACT = "# Fixture Skill\n\nReturn one concise answer.\n";
const ARTIFACT_HASH = "0x316163c97d7669db8b33fc52d05d458318acec1aad98fc5515b2f0f508957912";
const IP_HASH = "0x6c42a18b50e58fbe307da28995b381d6c5690f7815070733946c20344b58bae9";
const NFT_HASH = "0xdb24ac9487196af7c830b213c8127f08b3b2c12eb2baeb1fcc6625281ab16098";
const UPLOAD_URL = "https://uploads.pinata.cloud/v3/files";
const DEFAULT_GATEWAY = "https://gateway.pinata.cloud/ipfs/";

const INVALID_STAGE_URIS = [
  "http://gateway.pinata.cloud/ipfs/bafyvalidcid123",
  "https://user:pass@gateway.pinata.cloud/ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123?download=1",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123#fragment",
  "https://gateway.pinata.cloud.evil/ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/not-ipfs/bafyvalidcid123",
  "https://gateway.pinata.cloud/ipfs/bafyvalidcid123/extra",
  "https://gateway.pinata.cloud/ipfs/%2e%2e/bafyvalidcid123",
] as const;

const INVALID_GATEWAY_BASES = [
  "http://gateway.pinata.cloud/ipfs/",
  "https://user:pass@gateway.pinata.cloud/ipfs/",
  "https://gateway.pinata.cloud:444/ipfs/",
  "https://gateway.pinata.cloud/ipfs/?query=1",
  "https://gateway.pinata.cloud/ipfs/#fragment",
  "https://gateway.pinata.cloud.evil/ipfs/",
  "https://evil-mypinata.cloud/ipfs/",
  "https://gateway.pinata.cloud/not-ipfs/",
  "https://gateway.pinata.cloud/ipfs/extra/",
] as const;

async function withArtifact(t: test.TestContext) {
  const directory = await mkdtemp(join(tmpdir(), "phase0-metadata-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const path = join(directory, "SKILL.md");
  await writeFile(path, ARTIFACT, "utf8");
  return path;
}

function input(artifactPath: string, stage: DemoStage = "root") {
  return {
    stage,
    name: "Fixture Skill",
    description: "fixture",
    creatorAddress: WALLET,
    artifactPath,
  };
}

function headerValue(headers: HeadersInit | undefined, name: string): string | null {
  return new Headers(headers).get(name);
}

test("default publication pins two exact byte documents and verifies them without credentials", async (t) => {
  const artifactPath = await withArtifact(t);
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const pinned = new Map<string, Uint8Array>();
  const cids = ["bafyipfixture123", "bafynftfixture456"];
  const provider = new HttpMetadataProvider({
    pinataJwt: "fixture-token",
    fetcher: async (request, init) => {
      const url = String(request);
      calls.push({ url, init });
      if (init?.method === "POST") {
        assert.equal(url, UPLOAD_URL);
        assert.equal(init.redirect, "error");
        assert.equal(headerValue(init.headers, "authorization"), "Bearer fixture-token");
        assert.ok(init.body instanceof FormData);
        assert.equal(init.body.get("network"), "public");
        const file = init.body.get("file");
        assert.ok(file instanceof Blob);
        const cid = cids[pinned.size];
        assert.ok(cid);
        pinned.set(`${DEFAULT_GATEWAY}${cid}`, new Uint8Array(await file.arrayBuffer()));
        return Response.json({ data: { cid } });
      }
      assert.equal(headerValue(init?.headers, "authorization"), null);
      assert.equal(init?.redirect, "error");
      const bytes = pinned.get(url);
      assert.ok(bytes, `unexpected gateway fetch ${url}`);
      return new Response(Buffer.from(bytes));
    },
  });

  const prepared = await provider.prepare(input(artifactPath));

  assert.equal(prepared.proof.artifact.mediaHash, ARTIFACT_HASH);
  assert.equal(prepared.onchain.ipMetadataHash, IP_HASH);
  assert.equal(prepared.onchain.nftMetadataHash, NFT_HASH);
  assert.equal(prepared.onchain.ipMetadataURI, `${DEFAULT_GATEWAY}${cids[0]}`);
  assert.equal(prepared.onchain.nftMetadataURI, `${DEFAULT_GATEWAY}${cids[1]}`);
  assert.equal(calls.filter((call) => call.init?.method === "POST").length, 2);
  assert.equal(calls.filter((call) => call.init?.method !== "POST").length, 2);
});

test("a root override cannot leak into child or grandchild", async (t) => {
  const artifactPath = await withArtifact(t);
  const rootIp = `${DEFAULT_GATEWAY}bafyrootip123`;
  const rootNft = `${DEFAULT_GATEWAY}bafyrootnft456`;
  let fetchCalls = 0;
  const provider = new HttpMetadataProvider({
    stageUris: { root: { ip: rootIp, nft: rootNft } },
    pinataJwt: "",
    fetcher: async (request) => {
      fetchCalls += 1;
      if (String(request) === rootIp) {
        return new Response(Buffer.from(JSON.stringify({
          title: "Fixture Skill",
          description: "fixture",
          createdAt: "0",
          ipType: "skill",
          creators: [{ name: "creator", address: WALLET, contributionPercent: 100 }],
          mediaHash: ARTIFACT_HASH,
          mediaType: "text/markdown",
        })));
      }
      if (String(request) === rootNft) {
        return new Response(Buffer.from(JSON.stringify({ name: "Fixture Skill", description: "fixture" })));
      }
      throw new Error(`unexpected fetch ${String(request)}`);
    },
  });

  await provider.prepare(input(artifactPath, "root"));
  assert.equal(fetchCalls, 2);
  await assert.rejects(provider.prepare(input(artifactPath, "child")), /PINATA_JWT.*child/i);
  await assert.rejects(provider.prepare(input(artifactPath, "grandchild")), /PINATA_JWT.*grandchild/i);
  assert.equal(fetchCalls, 2);
});

test("an incomplete stage override pair fails before any fetch", async (t) => {
  const artifactPath = await withArtifact(t);
  let fetchCalls = 0;
  const provider = new HttpMetadataProvider({
    stageUris: { root: { ip: `${DEFAULT_GATEWAY}bafyrootip123` } } as never,
    fetcher: async () => {
      fetchCalls += 1;
      throw new Error("must not fetch");
    },
  });

  await assert.rejects(provider.prepare(input(artifactPath)), /ROOT metadata overrides must provide both IP and NFT URIs/);
  assert.equal(fetchCalls, 0);
});

test("every configured stage pair is validated before the selected stage can fetch", async (t) => {
  const artifactPath = await withArtifact(t);
  let fetchCalls = 0;
  const provider = new HttpMetadataProvider({
    stageUris: {
      root: {
        ip: `${DEFAULT_GATEWAY}bafyrootip123`,
        nft: `${DEFAULT_GATEWAY}bafyrootnft456`,
      },
      child: {
        ip: "https://attacker.invalid/ipfs/bafychildip123",
        nft: "https://attacker.invalid/ipfs/bafychildnft456",
      },
    },
    fetcher: async () => {
      fetchCalls += 1;
      throw new Error("must not fetch");
    },
  });

  await assert.rejects(provider.prepare(input(artifactPath, "root")), /origin must exactly match/i);
  assert.equal(fetchCalls, 0);
});

for (const uri of INVALID_STAGE_URIS) {
  test(`invalid stage URI fails before fetch: ${uri}`, async (t) => {
    const artifactPath = await withArtifact(t);
    let fetchCalls = 0;
    const provider = new HttpMetadataProvider({
      stageUris: { root: { ip: uri, nft: uri } },
      fetcher: async () => {
        fetchCalls += 1;
        throw new Error("must not fetch");
      },
    });

    await assert.rejects(provider.prepare(input(artifactPath)));
    assert.equal(fetchCalls, 0);
  });
}

for (const gateway of INVALID_GATEWAY_BASES) {
  test(`invalid public gateway fails before upload: ${gateway}`, async (t) => {
    const artifactPath = await withArtifact(t);
    let fetchCalls = 0;
    const provider = new HttpMetadataProvider({
      publicGatewayBaseUrl: gateway,
      pinataJwt: "fixture-token",
      fetcher: async () => {
        fetchCalls += 1;
        throw new Error("must not fetch");
      },
    });

    await assert.rejects(provider.prepare(input(artifactPath)));
    assert.equal(fetchCalls, 0);
  });
}

test("a dedicated mypinata gateway accepts same-origin stage objects", async (t) => {
  const artifactPath = await withArtifact(t);
  const gateway = "https://team.mypinata.cloud/ipfs/";
  const ip = `${gateway}bafyrootip123`;
  const nft = `${gateway}bafyrootnft456`;
  const expected = new Map<string, string>([
    [ip, JSON.stringify({
      title: "Fixture Skill",
      description: "fixture",
      createdAt: "0",
      ipType: "skill",
      creators: [{ name: "creator", address: WALLET, contributionPercent: 100 }],
      mediaHash: ARTIFACT_HASH,
      mediaType: "text/markdown",
    })],
    [nft, JSON.stringify({ name: "Fixture Skill", description: "fixture" })],
  ]);
  const provider = new HttpMetadataProvider({
    publicGatewayBaseUrl: gateway,
    stageUris: { root: { ip, nft } },
    fetcher: async (request, init) => {
      assert.equal(headerValue(init?.headers, "authorization"), null);
      const bytes = expected.get(String(request));
      assert.ok(bytes);
      return new Response(Buffer.from(bytes));
    },
  });

  const prepared = await provider.prepare(input(artifactPath));
  assert.equal(prepared.onchain.ipMetadataURI, ip);
  assert.equal(prepared.onchain.nftMetadataURI, nft);
});

test("PINATA_UPLOAD_URL cannot redirect a JWT-bearing request", async (t) => {
  const artifactPath = await withArtifact(t);
  const original = process.env.PINATA_UPLOAD_URL;
  process.env.PINATA_UPLOAD_URL = "https://attacker.invalid/collect";
  t.after(() => {
    if (original === undefined) delete process.env.PINATA_UPLOAD_URL;
    else process.env.PINATA_UPLOAD_URL = original;
  });
  const posted: string[] = [];
  const pinned = new Map<string, Uint8Array>();
  const provider = new HttpMetadataProvider({
    pinataJwt: "fixture-token",
    fetcher: async (request, init) => {
      const url = String(request);
      if (init?.method === "POST") {
        posted.push(url);
        assert.ok(init.body instanceof FormData);
        const file = init.body.get("file");
        assert.ok(file instanceof Blob);
        const cid = `bafyignored${posted.length}`;
        pinned.set(`${DEFAULT_GATEWAY}${cid}`, new Uint8Array(await file.arrayBuffer()));
        return Response.json({ data: { cid } });
      }
      const bytes = pinned.get(url);
      assert.ok(bytes);
      return new Response(Buffer.from(bytes));
    },
  });

  await provider.prepare(input(artifactPath));
  assert.deepEqual(posted, [UPLOAD_URL, UPLOAD_URL]);
});

test("altered fetched metadata bytes are rejected", async (t) => {
  const artifactPath = await withArtifact(t);
  const ip = `${DEFAULT_GATEWAY}bafyrootip123`;
  const nft = `${DEFAULT_GATEWAY}bafyrootnft456`;
  const provider = new HttpMetadataProvider({
    stageUris: { root: { ip, nft } },
    fetcher: async () => new Response("altered"),
  });

  await assert.rejects(provider.prepare(input(artifactPath)), /fetched metadata bytes do not match/i);
});

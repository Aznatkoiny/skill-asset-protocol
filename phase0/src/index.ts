import { parseArgs } from "node:util";
import { formatEther, type Address } from "viem";
import { PILFlavor, WIP_TOKEN_ADDRESS, NativeRoyaltyPolicy } from "@story-protocol/core-sdk";
import { getAccount, getClient, getPublicClient, EXPLORER } from "./client";
import { buildMetadata } from "./metadata";

const { values: o, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    name: { type: "string" },
    description: { type: "string" },
    "skill-file": { type: "string" },
    "rev-share": { type: "string" }, // percent 0-100
    policy: { type: "string" }, // LAP | LRP
    "minting-fee": { type: "string" }, // wei
    spg: { type: "string" },
    symbol: { type: "string" },
    parent: { type: "string" }, // parent ipId for a derivative
    "license-terms-id": { type: "string" },
  },
});

const cmd = positionals[0];

function spgAddress(): Address {
  const spg = (o.spg ?? process.env.SPG_NFT_CONTRACT) as Address | undefined;
  if (!spg) throw new Error("No SPG collection. Run `npm run create-collection`, then set SPG_NFT_CONTRACT in .env (or pass --spg).");
  return spg;
}

async function check() {
  const account = getAccount();
  const bal = await getPublicClient().getBalance({ address: account.address });
  console.log("wallet      :", account.address);
  console.log("chain       : Story Aeneid (1315)");
  console.log("balance     :", formatEther(bal), "IP");
  console.log("SPG contract:", process.env.SPG_NFT_CONTRACT || "(none — run create-collection)");
  if (bal === 0n) console.log("\n⚠ Wallet has 0 IP. Fund it: https://aeneid.faucet.story.foundation/");
}

async function createCollection() {
  const client = getClient();
  const res = await client.nftClient.createNFTCollection({
    name: o.name ?? "Skills",
    symbol: o.symbol ?? "SKILL",
    isPublicMinting: true,
    mintOpen: true,
    mintFeeRecipient: getAccount().address,
    contractURI: "",
  });
  console.log("✓ SPG collection created");
  console.log("spgNftContract:", res.spgNftContract);
  console.log("txHash        :", res.txHash);
  console.log("\n→ add to .env:  SPG_NFT_CONTRACT=" + res.spgNftContract);
}

async function registerSkill() {
  if (!o.name) throw new Error("--name is required");
  const client = getClient();
  const revShare = Number(o["rev-share"] ?? "25");
  const policy = (o.policy ?? "LAP").toUpperCase() === "LRP" ? NativeRoyaltyPolicy.LRP : NativeRoyaltyPolicy.LAP;
  const mintingFee = BigInt(o["minting-fee"] ?? "0");

  const meta = buildMetadata(client, {
    name: o.name,
    description: o.description ?? "",
    creatorAddress: getAccount().address,
    skillFile: o["skill-file"],
  });

  const terms = PILFlavor.commercialRemix({
    defaultMintingFee: mintingFee,
    commercialRevShare: revShare, // percent 0-100
    currency: WIP_TOKEN_ADDRESS,
    royaltyPolicy: policy, // default LAP — protects originators against depth-dilution (spike 4)
  });

  const res = await client.ipAsset.mintAndRegisterIpAssetWithPilTerms({
    spgNftContract: spgAddress(),
    licenseTermsData: [{ terms }],
    ipMetadata: meta.onchain,
  });

  console.log("✓ Skill registered as a Story IP Asset");
  console.log("ipId          :", res.ipId);
  console.log("tokenId       :", res.tokenId?.toString());
  console.log("licenseTermsId:", res.licenseTermsIds?.[0]?.toString());
  console.log("revShare      :", revShare + "%", "| policy:", policy === NativeRoyaltyPolicy.LRP ? "LRP" : "LAP");
  if (meta.contentHash) console.log("skill content :", meta.contentHash, "(keccak256 of the artifact)");
  console.log("txHash        :", res.txHash);
  console.log("explorer      :", `${EXPLORER}/ipa/${res.ipId}`);
  console.log("\n→ to fork this Skill:  npm run register-derivative -- --parent " + res.ipId + " --license-terms-id " + res.licenseTermsIds?.[0]?.toString() + " --name \"<fork name>\"");
}

async function registerDerivative() {
  if (!o.name) throw new Error("--name is required");
  if (!o.parent) throw new Error("--parent <ipId> is required");
  if (!o["license-terms-id"]) throw new Error("--license-terms-id <id> is required (the parent's licenseTermsId)");
  const client = getClient();

  const meta = buildMetadata(client, {
    name: o.name,
    description: o.description ?? "",
    creatorAddress: getAccount().address,
    skillFile: o["skill-file"],
  });

  const res = await client.ipAsset.mintAndRegisterIpAndMakeDerivative({
    spgNftContract: spgAddress(),
    derivData: {
      parentIpIds: [o.parent as Address],
      licenseTermsIds: [BigInt(o["license-terms-id"])],
      maxMintingFee: 0n,
      maxRts: 100_000_000,
      maxRevenueShare: 100,
    },
    ipMetadata: meta.onchain,
  });

  console.log("✓ Derivative registered (owes royalties to its parent on-chain)");
  console.log("ipId    :", res.ipId);
  console.log("tokenId :", res.tokenId?.toString());
  console.log("parent  :", o.parent);
  console.log("txHash  :", res.txHash);
  console.log("explorer:", `${EXPLORER}/ipa/${res.ipId}`);
}

const commands: Record<string, () => Promise<void>> = {
  check,
  "create-collection": createCollection,
  "register-skill": registerSkill,
  "register-derivative": registerDerivative,
};

async function main() {
  const run = cmd ? commands[cmd] : undefined;
  if (!run) {
    console.log("Phase 0 — Story provenance CLI\n");
    console.log("commands:");
    console.log("  npm run check");
    console.log("  npm run create-collection [-- --name Skills --symbol SKILL]");
    console.log("  npm run register-skill -- --name \"<name>\" [--description \"..\"] [--skill-file path] [--rev-share 25] [--policy LAP|LRP]");
    console.log("  npm run register-derivative -- --parent <ipId> --license-terms-id <id> --name \"<name>\"");
    process.exit(cmd ? 1 : 0);
  }
  await run();
}

main().catch((err) => {
  console.error("\n✗ " + (err instanceof Error ? err.message : String(err)));
  process.exit(1);
});

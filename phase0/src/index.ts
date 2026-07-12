import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { formatEther, type Address } from "viem";

import { EXPLORER, getAccount, getClient, getPublicClient } from "./client";
import { runDemo } from "./demo";
import { HttpMetadataProvider } from "./metadata";
import { FileRegistrationStore } from "./registrations";
import {
  StoryChain,
} from "./story";

const { values: options, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    name: { type: "string" },
    description: { type: "string" },
    "skill-file": { type: "string" },
    "rev-share": { type: "string" },
    policy: { type: "string" },
    "minting-fee": { type: "string" },
    spg: { type: "string" },
    symbol: { type: "string" },
    parent: { type: "string" },
    "license-terms-id": { type: "string" },
  },
});

const command = positionals[0];
const registrationsPath = fileURLToPath(new URL("../registrations.json", import.meta.url));

function storyChain(): StoryChain {
  return new StoryChain({
    sdk: getClient(),
    publicClient: getPublicClient(),
  });
}

function requiredOption(name: keyof typeof options): string {
  const value = options[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`--${name} is required`);
  return value;
}

function spgAddress(): Address {
  const value = options.spg ?? process.env.SPG_NFT_CONTRACT;
  if (!value) {
    throw new Error(
      "No SPG collection. Run `npm run demo`, or run `npm run create-collection` and pass --spg/set SPG_NFT_CONTRACT.",
    );
  }
  return value as Address;
}

function royaltyPolicy(): "LAP" | "LRP" {
  const value = (options.policy ?? "LAP").toUpperCase();
  if (value !== "LAP" && value !== "LRP") throw new Error("--policy must be LAP or LRP");
  return value;
}

async function check() {
  const account = getAccount();
  const chain = storyChain();
  const chainId = await chain.getChainId();
  const balance = await chain.getBalance(account.address);
  console.log("wallet      :", account.address);
  console.log("chain       :", `Story Aeneid (${chainId})`);
  console.log("balance     :", formatEther(balance), "IP");
  console.log("SPG contract:", process.env.SPG_NFT_CONTRACT || "(none — npm run demo creates one)");
  if (balance === 0n) {
    console.log("\n⚠ Wallet has 0 IP. Fund it manually: https://aeneid.faucet.story.foundation/");
  }
  return { wallet: account.address, chainId, balance };
}

async function createCollection() {
  const account = getAccount();
  const result = await storyChain().createCollection({
    name: options.name ?? "Skills",
    symbol: options.symbol ?? "SKILL",
    mintFeeRecipient: account.address,
  });
  console.log("✓ SPG NFT collection created");
  console.log("spgNftContract:", result.spgNftContract);
  console.log("txHash        :", result.txHash);
  console.log("\n→ pass to advanced commands: --spg " + result.spgNftContract);
  return result;
}

async function registerSkill() {
  const account = getAccount();
  const name = requiredOption("name");
  const artifactPath = requiredOption("skill-file");
  const metadata = await new HttpMetadataProvider().prepare({
    stage: "root",
    name,
    description: options.description ?? "",
    creatorAddress: account.address,
    artifactPath,
  });
  const revShare = Number(options["rev-share"] ?? "25");
  const result = await storyChain().registerSkill({
    spgNftContract: spgAddress(),
    metadata: metadata.onchain,
    defaultMintingFee: BigInt(options["minting-fee"] ?? "0"),
    revShare,
    policy: royaltyPolicy(),
  });
  console.log("✓ Skill registered as a Story IP Asset");
  console.log("ipId          :", result.ipId);
  console.log("tokenId       :", result.tokenId.toString());
  console.log("licenseTermsId:", result.licenseTermsId.toString());
  console.log("artifact hash :", metadata.proof.artifact.mediaHash, "(SHA-256)");
  console.log("txHash        :", result.txHash);
  console.log("explorer      :", `${EXPLORER}/ipa/${result.ipId}`);
  return { ...result, metadata };
}

async function registerDerivative() {
  const account = getAccount();
  const name = requiredOption("name");
  const artifactPath = requiredOption("skill-file");
  const parentIpId = requiredOption("parent") as Address;
  const licenseTermsId = BigInt(requiredOption("license-terms-id"));
  const metadata = await new HttpMetadataProvider().prepare({
    stage: "child",
    name,
    description: options.description ?? "",
    creatorAddress: account.address,
    artifactPath,
  });
  const chain = storyChain();
  const predicted = await chain.predictMintingLicenseFee({
    licensorIpId: parentIpId,
    licenseTermsId,
    amount: 1,
  });
  const result = await chain.registerDerivative({
    spgNftContract: spgAddress(),
    parentIpId,
    licenseTermsId,
    maxMintingFee: predicted.tokenAmount,
    metadata: metadata.onchain,
  });
  console.log("✓ Derivative registered (declared parent on-chain)");
  console.log("ipId          :", result.ipId);
  console.log("tokenId       :", result.tokenId.toString());
  console.log("parentIpId    :", parentIpId);
  console.log("licenseTermsId:", licenseTermsId.toString());
  console.log("maxMintingFee :", predicted.tokenAmount.toString(), "(predicted explicit cap)");
  console.log("artifact hash :", metadata.proof.artifact.mediaHash, "(SHA-256)");
  console.log("txHash        :", result.txHash);
  console.log("explorer      :", `${EXPLORER}/ipa/${result.ipId}`);
  return { ...result, licenseTermsId, maxMintingFee: predicted.tokenAmount, metadata };
}

async function demo() {
  const account = getAccount();
  const manifest = await runDemo({
    wallet: account.address,
    chain: storyChain(),
    metadata: new HttpMetadataProvider(),
    store: new FileRegistrationStore(registrationsPath),
  });
  console.log("✓ Phase 0 provenance demo status:", manifest.status);
  console.log("wallet        :", manifest.wallet);
  console.log("spgNftContract:", manifest.spgNftContract);
  for (const stage of ["root", "child", "grandchild"] as const) {
    const registration = manifest.registrations[stage];
    console.log(`${stage.padEnd(10)}:`, registration?.ipId ?? "not registered");
  }
  console.log("proof artifact:", registrationsPath);
  return manifest;
}

const commands: Record<string, () => Promise<unknown>> = {
  check,
  demo,
  "create-collection": createCollection,
  "register-skill": registerSkill,
  "register-derivative": registerDerivative,
};

async function main() {
  const run = command ? commands[command] : undefined;
  if (!run) {
    console.log("Phase 0 — Story provenance CLI\n");
    console.log("commands:");
    console.log("  npm run demo");
    console.log("  npm run check");
    console.log("  npm run create-collection [-- --name Skills --symbol SKILL]");
    console.log("  npm run register-skill -- --spg <address> --name <name> --skill-file <path> [--rev-share 25] [--policy LAP|LRP]");
    console.log("  npm run register-derivative -- --spg <address> --parent <ipId> --license-terms-id <id> --name <name> --skill-file <path>");
    process.exit(command ? 1 : 0);
  }
  await run();
}

main().catch((error) => {
  console.error("\n✗ " + (error instanceof Error ? error.message : String(error)));
  process.exit(1);
});

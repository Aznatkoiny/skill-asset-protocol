import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

import { formatEther } from "viem";

import {
  getAccount,
  getClient,
  getPublicClient,
  getWalletClient,
} from "./client";
import { runDemo } from "./demo";
import { HttpMetadataProvider } from "./metadata";
import { FileRegistrationStore } from "./registrations";
import { StoryChain } from "./story";
import { FileOperationJournal } from "./transactions";

const { positionals } = parseArgs({ allowPositionals: true });
const command = positionals[0];
const registrationsPath = fileURLToPath(new URL("../registrations.json", import.meta.url));
const pendingTransactionsPath = fileURLToPath(
  new URL("../pending-transactions.json", import.meta.url),
);

function storyChain(): StoryChain {
  return new StoryChain({
    sdk: getClient(),
    wallet: getWalletClient(),
    publicClient: getPublicClient(),
  });
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

async function demo() {
  const account = getAccount();
  const journal = new FileOperationJournal(pendingTransactionsPath);
  const manifest = await journal.withExclusiveLease((leasedJournal) => runDemo({
    wallet: account.address,
    chain: storyChain(),
    metadata: new HttpMetadataProvider(),
    store: new FileRegistrationStore(registrationsPath),
    journal: leasedJournal,
  }));
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

const commands: Record<string, () => Promise<unknown>> = { check, demo };

async function main() {
  const run = command ? commands[command] : undefined;
  if (!run) {
    console.log("Phase 0 — Story provenance CLI\n");
    console.log("commands:");
    console.log("  npm run demo");
    console.log("  npm run check");
    process.exit(command ? 1 : 0);
  }
  await run();
}

main().catch((error) => {
  console.error("\n✗ " + (error instanceof Error ? error.message : String(error)));
  process.exit(1);
});

import "dotenv/config";
import { createPublicClient, defineChain, http } from "viem";
import { privateKeyToAccount, type Account } from "viem/accounts";
import { StoryClient, type StoryConfig } from "@story-protocol/core-sdk";

const RPC = process.env.RPC_PROVIDER_URL ?? "https://aeneid.storyrpc.io";

// Story Aeneid testnet (chainId 1315). Defined locally so the read path doesn't
// depend on an SDK chain export.
export const aeneidChain = defineChain({
  id: 1315,
  name: "Story Aeneid",
  nativeCurrency: { name: "IP", symbol: "IP", decimals: 18 },
  rpcUrls: { default: { http: [RPC] } },
});

export const EXPLORER = "https://aeneid.explorer.story.foundation";

export function getAccount(): Account {
  const pk = process.env.WALLET_PRIVATE_KEY;
  if (!pk) throw new Error("WALLET_PRIVATE_KEY missing — copy .env.example to .env and fill it in.");
  const hex = (pk.startsWith("0x") ? pk : `0x${pk}`) as `0x${string}`;
  return privateKeyToAccount(hex);
}

// Story SDK client (write path). chainId "aeneid" lets the SDK resolve its own
// contract addresses for the testnet.
export function getClient(): StoryClient {
  const config: StoryConfig = {
    account: getAccount(),
    transport: http(RPC),
    chainId: "aeneid",
  };
  return StoryClient.newClient(config);
}

// viem public client (read path: balances, etc.)
export function getPublicClient() {
  return createPublicClient({ chain: aeneidChain, transport: http(RPC) });
}

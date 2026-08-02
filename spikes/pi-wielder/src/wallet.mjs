// wallet.mjs — the Wielder's entire identity is one EOA private key.
//
// That is the point of ADR-0008 ("the Wielder is a wallet, not a harness"):
// no token custody, no chain reads, no Story SDK. Just a key that can sign
// EIP-3009 USDC transfer authorizations (see proxy.mjs).
//
// Real (testnet) mode: set PRIVATE_KEY in .env and fund the derived address
// with Base Sepolia USDC + ETH from the Coinbase CDP faucet (see RUNBOOK.md).
// Mock mode: a throwaway key is generated per process — signing is pure
// cryptography, so no funds, no network, no faucet are needed.

import { privateKeyToAccount, generatePrivateKey } from 'viem/accounts';

/** viem local account from the PRIVATE_KEY env var, or null if unset. */
export function accountFromEnv(env = process.env) {
  const pk = env.PRIVATE_KEY?.trim();
  if (!pk) return null;
  return privateKeyToAccount(pk.startsWith('0x') ? pk : `0x${pk}`);
}

/** A fresh, unfunded, in-memory account for explicitly injected offline settlement. */
export function throwawayAccount() {
  return privateKeyToAccount(generatePrivateKey());
}

/** Env account if present, else a throwaway (with a loud note so nobody is surprised). */
export function loadAccount(env = process.env) {
  const fromEnv = accountFromEnv(env);
  if (fromEnv) return fromEnv;
  const acct = throwawayAccount();
  console.error(`[wallet] no PRIVATE_KEY set — using throwaway account ${acct.address} (mock mode only)`);
  return acct;
}

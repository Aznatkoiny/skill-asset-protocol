# Phase 0 — Provenance (Story IP Assets + Derivatives)

The first real, shippable slice (ADR-0006, Phase 0). It establishes the
**provenance + fork-graph** that the whole moat rests on — *before* any payments,
agents, or settlement. Everything runs on **Story's Aeneid testnet**.

What it does:
- Register a **Skill** as a Story **IP Asset** with commercial-remix **PIL** license terms.
- Hash the actual skill artifact (`--skill-file`) into the on-chain record (content provenance).
- Register a **Derivative** (fork) that declares its parent on-chain, so royalties can flow later.

Royalty policy defaults to **LAP** (the originator keeps a share of *all* descendants regardless of
depth) — the answer to the spike-4 depth-dilution finding. Use `--policy LRP` for per-hop relative.
The LAP-vs-LRP decision is a real Phase-2 commitment (see `../docs/feasibility/prebuild-spikes.md`);
LAP is the safer default for the education vision.

## Setup

```bash
cd phase0
npm install
cp .env.example .env          # then edit .env
```

In `.env`, set `WALLET_PRIVATE_KEY` to a **throwaway** testnet key, then fund it:
- Faucet: https://aeneid.faucet.story.foundation/ (10 IP per claim)

```bash
npm run check                 # confirms wallet, chain, balance
```

## Usage

```bash
# 1. one-time: create an SPG NFT collection to mint Skills into
npm run create-collection
#    → copy the printed spgNftContract into .env as SPG_NFT_CONTRACT

# 2. register a Skill (here, hashing this repo's own CONTEXT.md as the artifact)
npm run register-skill -- --name "fin-modeling" --description "base financial-modeling skill" \
  --skill-file ../CONTEXT.md --rev-share 25
#    → prints ipId + licenseTermsId, and the exact command to fork it

# 3. register a Derivative (a student forking the school's Skill)
npm run register-derivative -- --parent <parentIpId> --license-terms-id <id> \
  --name "biotech-fin-modeling" --description "a fork specialised for biotech"
```

Each command prints an explorer link (`https://aeneid.explorer.story.foundation/ipa/<ipId>`) so you
can see the IP Asset and its parent/child links on-chain.

## What this proves (and what it deliberately doesn't)

**Proves:** a Skill and its fork lineage are registered on-chain with declared ancestry and license
terms — the provenance layer the marketplace moat depends on (ADR-0004).

**Out of scope for Phase 0** (later phases): the payment gate (x402), hidden hosted execution
(managed agent), and royalty *settlement* (the two-leg flow of ADR-0005). This slice intentionally
has no money movement.

## Notes
- Testnet only. Use a throwaway key.
- Metadata: if you don't set `IP_METADATA_URI` / `NFT_METADATA_URI`, placeholders are used — the
  on-chain content **hashes** are still real. For production, pin the metadata JSON to IPFS.
- SDK: `@story-protocol/core-sdk` v1.4.x. `commercialRevShare` is an integer **percent (0–100)**.

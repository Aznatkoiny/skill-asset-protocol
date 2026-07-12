# Tokenize Skills as Programmable IP on Story Protocol

**Status:** Accepted, updated 2026-06 (post-feasibility validation); amended 2026-07-11 (see Update)

## Context

The token must do three jobs at once: (1) tamper-proof **provenance** of who authored a Skill,
(2) trustless, programmable **multi-party royalty splits** (school / student / employer /
co-creators), and (3) a tradeable, fractional **royalty claim** on future invocation revenue.
It must also support **composable derivative flow-through** — a fork owes royalties to its whole
ancestry (credited per invocation, claimable on demand; see Update).

Hidden execution + per-call payment alone do NOT need a blockchain (Anthropic Managed Agents +
x402 already deliver that). But the three jobs above, plus cross-platform neutrality and a royalty
graph no single company adjudicates, do.

Story Protocol already ships exactly this: on-chain IP Assets, composable license terms, and a
royalty module where derivatives pay ancestors. It is live and audited.

## Decision

Represent each registered Skill as a **Story Protocol IP Asset**; use Story's license + royalty
modules for splits and composable derivative royalties; represent the tradeable royalty claim as a
Story royalty token. Build NEW only the genuinely novel layer — hidden hosted execution,
per-invocation metering, and the attestation bridge that feeds on-chain settlement.

## Considered options

- **Own contracts on a general L2 (Base / Solana)** — rejected: reinvents the provenance,
  licensing, and composable royalty graph Story already audits.
- **Own appchain / rollup** — rejected as premature: consensus, bridges, and liquidity overhead
  for a product with no users yet.

## Consequences

- We inherit Story's design opinions, roadmap risk, and its chain's liquidity + regulatory surface.
- We accept the regulatory exposure of a tradeable revenue claim (explicitly accepted for now —
  the goal is to trailblaze).
- Novel risk concentrates almost entirely in the **attestation bridge** (off-chain invocation →
  trusted on-chain settlement), which is the next open question.

## Update (post-feasibility validation, 2026-06)

Validated against live Story Protocol (chainId 1514, SDK v1.4.4). Confirmed real, with corrections —
full analysis in the project's internal feasibility study (2026-06, unpublished):

- Flow-through is **pull, not push**: ancestors accrue a claimable balance and must call
  `claimAllRevenue`; a permissionless **keeper** auto-claims on their behalf. "Automatically pays"
  was wrong — it is "credited, claimable on demand."
- Story mainnet royalties are denominated in **WIP** ($IP), not USDC — volatile and illiquid; payers
  take FX exposure. The USDC→WIP conversion is folded into the settlement bridge (ADR-0005).
- The **tradeable** royalty claim is almost certainly a **security** (Howey); a permissionless
  composable trading market is not available. Trading must be permissioned (ERC-3643 + ATS +
  transfer agent); claims are kept non-transferable in closed modes (ADR-0006).
- The "attestation bridge" is resolved as the **two-leg settlement** of ADR-0005.
- **2026-07-11:** Superseded on emphasis by ADR-0007 — the tradeable claim is underwritten
  optionality, not the goal ("the goal is to trailblaze" no longer stands); the regulatory
  exposure of tradeability is deferred with Phase 3, not accepted up front.

# Two-leg cross-chain settlement; off-chain execution credential

**Status:** Accepted, updated 2026-06 (pre-build spikes)

## Context

Feasibility validation (the project's internal feasibility study, 2026-06, unpublished) found
the literal ADR-0003 vision — one
payment that both gates execution *and* lands on Story's royalty contract — does **not** compose
with today's APIs:

- x402 settles **USDC on Base (8453)**; Story's Royalty Module accepts only **WIP on Story (1514)**.
- x402 pays an EOA via `transferWithAuthorization`, not Story's `payRoyaltyOnBehalf`; no x402
  facilitator supports chain 1514.
- Stacked per-hop fees (facilitator + Base gas + bridge + USDC→WIP swap slippage + Story gas + claim
  gas) dwarf a cents-level micro-royalty.
- Story flow-through is **pull-based** (ancestors must claim).

## Decision

Settle in **two decoupled legs**:

- **Leg 1 — synchronous gate (Base):** the Wielder pays USDC on Base via x402 (EIP-3009
  `transferWithAuthorization`, gasless). The settled **txHash is the single-use execution
  credential**, checked off-chain by the Collar. Settle the payment first (sub-second), release the
  credential, *then* run the agent asynchronously and stream output — never hold the x402 handshake
  open across the agent run (x402 `maxTimeoutSeconds` ~60s < cold agent start + loop).
- **Leg 2 — asynchronous settlement (Story):** an off-chain worker accrues payments in an auditable
  ledger and **batches** them per threshold/interval, bridges/swaps USDC(Base)→WIP(Story), calls
  `payRoyaltyOnBehalf`, and runs a permissionless **keeper** that auto-claims (`claimAllRevenue`)
  for ancestors so their revenue never silently piles up.

The execution credential is **off-chain**; do NOT mint a per-call on-chain License Token.

## Considered options

- **Single atomic on-chain payment-as-royalty** — rejected: physically impossible across Base↔Story.
- **Per-call on-chain License Token credential** — rejected: full tx + IP→WIP wrap + approve + block
  latency per cents-level call.
- **Story-side only (no x402)** — rejected: WIP-only, volatile $IP, no clean per-call USDC/fiat gate.

## Consequences

- Settlement is **eventually-consistent**, not atomic.
- Batching makes the Collar an **in-flight fund custodian** → FinCEN MSB exposure. Minimize custody:
  route in-flight value through a licensed facilitator/bridge and keep the Collar a non-custodial
  pass-through (see ADR-0006; the full regulatory analysis lives in the project's internal
  feasibility study, unpublished).
- A bridge stall leaves "execution done, ancestor unpaid" — needs reconciliation + sound Collar
  bookkeeping.
- **Re-verify before building:** that no x402 facilitator has added Story 1514; the CDP fee schedule;
  cold `sessions.create`→first-token latency; whether a License Token can serve as a non-burned
  off-chain entitlement. — **All four RESOLVED in the pre-build spikes; see Update.**

## Update (pre-build spikes resolved, 2026-06)

Spike results are recorded in the project's internal pre-build spike notes (unpublished). All four
confirm this ADR; none changed it.

- **x402 ↔ Story unchanged:** no facilitator supports chain 1514; x402 V2 "multi-chain" = more
  independent single-chain networks, not pay-on-Base-settle-on-Story; x402-exec is Base/X-Layer/BSC
  only. Two-leg stays mandatory. CDP facilitator fee: **first 1,000 settled payments/month free, then
  $0.001 each** (gas covered). A self-hosted facilitator *can* now dynamically register 1514, but
  that is a **non-solution** (still wrong token WIP-vs-USDC, wrong primitive, still custody). Watch
  **LayerZero** (joined the x402 Foundation) as a future cross-chain-settlement option.
- **Execution credential = x402 settled txHash (off-chain), confirmed.** A Story License Token is an
  ERC-721 that only authorizes *derivative registration* and burns on use; it can be held un-burned
  but confers no run right and has no native verification beyond ERC-721 ownership — wrong object,
  and per-call minting is on-chain WIP + gas + block latency. **License Tokens are scoped to Phase 0
  provenance / fork declaration only.**
- **Finality caveat (new):** the x402 "~200ms" is a Base **Flashblocks preconfirmation**, not hard
  finality; under congestion Base confirmation can take **10–28s**. The Collar must own its own
  txHash/nonce bookkeeping, set sane timeouts, and fund refunds from treasury (x402 is irreversible,
  no resubmit).
- **Latency (Leg 1 + run) is acceptable:** no Anthropic SLA (CMA beta), but the async-after-gate
  design holds. Mitigate with: persist `agent_id` (never create on the hot path), a small pre-warmed
  **session pool** (skip the ~2.4s `sessions.create`), stream-first, render progress off the **first
  event** (not the first answer token), and default interactive turns to `effort=low/medium`.
  Benchmark before committing latency budgets: `prototype/spike-cma-latency.mjs` (run with your key).

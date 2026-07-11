# Pre-build spikes — results

The four spikes the PRD gated the build on. **All resolved; none change the architecture.** Run
date: 2026-06. Sources cited in `findings.json` / the feasibility report; benchmark + experiment
scripts in `prototype/`.

## 1. Hosted-agent latency (Anthropic Managed Agents / CMA) — ✅ resolved, ship

No published latency SLA (CMA is beta). Realistic interactive path:

| Segment | Figure (mid-2026, observed/relative — not contractual) |
|---|---|
| `sessions.create` round-trip | ~2.4s (third-party prod measurement) — *skippable via session pool* |
| stream open + first send | ~0.6s (overlapping, stream-first) |
| model time-to-first-answer-token | ~0.5–2s at `effort=low`/no-thinking; up to ~21s at max-effort reasoning |
| sandbox cold-start | lazy, off the critical path (Anthropic: −60% p50 / −90% p95 TTFT after decoupling) |

**Verdict:** acceptable; the async-after-gate design is correct (CMA latency is post-gate).
**Build rules:** persist `agent_id` (never `agents.create` on the hot path); pre-warmed session pool
(depth ~1, cap ~2, 5-min age) to skip the ~2.4s; stream-first; render progress off the **first event**
(`session.status_running` / first `agent.thinking`), not the first answer token; default interactive
turns to `effort=low/medium`. **Benchmark with your own key before setting latency budgets:**
`prototype/spike-cma-latency.mjs`. Note CMA session cost ~$0.08/session-hour bounds idle pool cost.

## 2. x402 ↔ Story settlement — ✅ resolved, no change

The two-leg design (ADR-0005) **remains mandatory**. No x402 facilitator supports Story chain 1514;
x402 V2 "multi-chain" means more independent single-chain networks, not cross-chain settlement;
x402-exec is Base/X-Layer/BSC only. **CDP facilitator fee:** first 1,000 settled payments/month free,
then **$0.001/payment** (gas covered). New facts: a self-hosted facilitator can dynamically register
1514 but it is a **non-solution** (wrong token, wrong primitive, still custody); **LayerZero** joined
the x402 Foundation — watch as a future cross-chain-settlement path. **Finality caveat:** "~200ms" is
a Flashblocks preconfirmation, not finality; under congestion Base can take 10–28s → collar needs
timeouts + treasury-funded refunds (x402 is irreversible).

## 3. Execution credential — ✅ resolved, confirmed

**Use the x402 settled txHash as the off-chain, single-use, replay-proof credential.** Do **not** mint
a Story License Token per call: a License Token is an ERC-721 that only authorizes *derivative
registration* and burns on use; it can be held un-burned but confers no run right and has no native
verification beyond ERC-721 ownership, and per-call minting is on-chain WIP + gas + block latency.
**License Tokens are scoped to Phase 0 provenance / fork declaration.** (Re-verify Story-mainnet
WIP-only minting-fee rule at build time; true at SDK v1.4.4, 2026-03.)

## 4. Fork economics — ✅ resolved (one product decision left to you)

Run `node prototype/spike-fork-economics.mjs`.

- **Fork-killing threshold confirmed:** the latest forker keeps `(1 − inherit)` of net regardless of
  depth; forking beats going solo while `inherit < p_parent/p_fork`. Suggest the inherit default at
  the price-ratio and let Creators tune it.
- **Surprise — the dilution victim is the ORIGINAL creator, not the leaf.** With a flat per-hop
  inherit, the originator's share decays geometrically with depth (at 30%/hop: 30% → 9% → 2.7% →
  0.8% across depths 1–4). The school earns from *breadth* (direct forks), not *depth*.
- **OPEN PRODUCT DECISION (Phase 2):** Story **LRP** (per-hop relative — dilutes originators by depth)
  vs **LAP** (whole-ancestry absolute — protects the originator's share regardless of depth, but caps
  total downstream royalty). To be decided and ADR'd when royalty settlement is built.

## Net effect on the plan

No blocker surfaced. The architecture in ADR-0005 / ADR-0006 stands. The only unresolved item is the
LRP-vs-LAP **product** choice (#4), which is a Phase-2 decision and does **not** block Phase 0. Clear
to build Phase 0 (provenance).

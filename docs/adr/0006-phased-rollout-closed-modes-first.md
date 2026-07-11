# Phased rollout: closed modes first; tradeable claims are permissioned securities

**Status:** Accepted (2026-06-06), amended 2026-07-11

## Context

Feasibility validation (`docs/feasibility/report.md`) found:

- **Tradeable royalty claims are almost certainly securities** under Howey — and ADR-0004's
  live-evolution moat *strengthens* the "efforts of others" prong. The open, permissionless
  composable royalty market triggers the full securities stack (ERC-3643 allow-list, Reg D/A+/CF,
  SEC-registered ATS, transfer agent, KYC).
- **Off-platform behavioral cloning is the deepest strategic risk**, and it bites hardest in the
  open Marketplace, where a high-volume Skill's own paid outputs are the cheapest clone-training set.
- **Intra-org and Education are closed populations** with aligned incentives and the least cloning
  pressure; their co-held / forked claims can be structured as **non-transferable** contractual /
  deferred-comp / license-fee rights that sidestep securities treatment entirely.

## Decision

Launch in order of *safety*, not ambition:

- **Phase 0 — Provenance (all-Story):** register Skills as IP Assets + declared Derivatives.
  Establishes the provenance/derivative-graph moat regardless of how settlement evolves. Soundest
  step; ships immediately.
- **Phase 1 — Intra-org, then Education:** gate + run + off-chain metered ledger; claims
  **non-transferable** (outside securities law).
- **Phase 2 — On-chain batched royalty settlement** (ADR-0005 Leg 2) for the closed modes.
- **Phase 3 — Open Marketplace + tradeable claims, only when warranted, and permissioned:**
  ERC-3643 + a Reg exemption + registered ATS + transfer agent + KYC. Engage securities counsel
  *before* this phase.

## Consequences

- The headline "open composable royalty graph" is the **last** thing shipped, not the first.
- The derivative-royalty **mechanic** is available throughout; only the **tradeability** of a claim
  is gated behind the securities stack.
- Cloning risk is met first where it is weakest (closed modes), buying time to build live-evolution /
  live-data moats before facing the open market.

## Amendment (2026-07-11)

Emphasis reversed per ADR-0007. The phasing above stands; its framing does not:

- **Phase 1 is the terminal state by design.** The closed-mode compensation layer must be
  independently viable if Phases 2–3 never ship. Phases 2–3 are exercised only if warranted —
  they are no longer the point of the exercise (ADR-0007).
- **The open Marketplace is underwritten optionality, not the headline or the destination.** The
  Consequences above ("the headline … is the **last** thing shipped", "buying time … before facing
  the open market") record the pre-reframe emphasis: closed modes are no longer a waypoint toward
  the open market.
- **Education is demoted from the Phase-1 follow-on to deferred** ("Intra-org, then Education" no
  longer holds): it un-defers only if a re-run of the fork-economics spike, with "re-author with
  class knowledge ≈ free" as an explicit alternative branch, still shows a real forking incentive
  (ADR-0007).

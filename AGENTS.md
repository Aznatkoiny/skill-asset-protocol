# Agent instructions — Skill Asset Protocol

## Current assignment

**→ `docs/handoffs/2026-07-15-launch-week-handoff.md`** — read it first; it
lists the ordered agent-doable tasks and the human-only launch items, on
branch `codex/prd-execution`. (The 2026-07-11 handoff is complete —
see `docs/plans/2026-07-12-phase-a-findings.md`.)

## Repo orientation (durable)

This is a **design-and-spike repo**, not a product codebase. The product is a
compensation, attribution, and metering layer for authored AI Skills
("Carta for AI work artifacts") — see ADR-0007. Reading order for any new
session:

1. `CONTEXT.md` — the ubiquitous language. Use its terms exactly
   (Skill, Creator, Wielder, Beneficiary, Collar, Invocation, Derivative,
   Royalty claim). Definitions are load-bearing.
2. `docs/adr/` — 0001–0008; 0007 (terminal product) and 0008 (Wielder is a
   wallet) encode the 2026-07-11 reframe.
3. `docs/PRD.md` — the plan; its "What we have NOT validated" section is the
   honest ledger of open assumptions. Extend it, never delete from it.
4. `docs/plans/` — validated designs; `spikes/` and `prototype/` — executable
   evidence.

## Rules

- Never commit `.env` or any private key. `phase0/.env` holds a wallet key.
- No mainnet transactions, no real funds. Testnet only; wallet funding is a
  human step.
- Spike results go in the spike's own README; do not edit `CONTEXT.md`,
  `docs/PRD.md`, or `docs/adr/` without an explicit instruction — propose
  changes in your summary instead.
- Preserve the corpus's honesty discipline: measured numbers are labeled
  measured, hypotheses are labeled hypotheses, and a spike that didn't run
  says so.

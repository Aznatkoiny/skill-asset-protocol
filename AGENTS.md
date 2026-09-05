# Agent instructions — Skill Asset Protocol

## Start here

1. Identify the checkout before acting on a review, issue, or handoff. Record
   `git rev-parse --show-toplevel`, `git branch --show-current`,
   `git rev-parse HEAD`, and `git status --short`. Match findings to that code;
   branch names and commit IDs in dated plans describe their original bases.
   The user's current assignment determines the work, not an old task list.
2. Read [README.md](README.md) and the
   [approved Wallet Kernel design](docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md),
   including its 2026-08-02 approval-flow amendment. This remains a
   **design-and-spike repository**. Current commercial v1 is a customer-hosted
   **Agent Spend Control Plane**: the **Wallet Kernel** enforces spending
   policy, exact approvals, durable recovery, signed receipts, and
   reconciliation through a customer-owned wallet.
3. Read [document and evidence precedence](docs/evidence-precedence.md) before
   using historical claims, deciding what remains incomplete, or reporting
   release readiness. The July handoffs are historical records; they are not
   the current assignment. Offline implementation evidence does not clear a
   live or public-release gate.

## References by task

- For Wallet Kernel implementation, use the
  [implementation plan](docs/superpowers/plans/2026-07-31-agent-spend-control-plane.md)
  and the relevant package's current source, README, and tests. A plan checkbox
  or old passing test count is not evidence about the current checkout.
- For protocol or deferred Skill research, consult [CONTEXT.md](CONTEXT.md),
  [the earlier PRD](docs/PRD.md), and [ADRs](docs/adr/). Preserve their defined
  terms. Skill attribution, Creator compensation, Story settlement, and the
  marketplace are deferred expansion research, not Wallet Kernel v1
  acceptance requirements. The approved design defines the current Agent,
  Operator, Spend Intent, and Wallet Kernel roles.
- Use [docs/README.md](docs/README.md) to find current and historical documents.

## Rules

- Keep `.env`, private keys, wallet/CDP credentials, databases, receipt keys,
  and operator tokens out of Git, logs, and published artifacts.
- No mainnet transactions, no real funds. Testnet only; wallet funding is a
  human step. Paid provider or testnet runs must stay within the user's
  session authorization and the package's execution gates. Available keys
  and instructions in historical handoffs do not authorize a live run.
- Spike results go in the spike's own README; do not edit `CONTEXT.md`,
  `docs/PRD.md`, or `docs/adr/` without an explicit instruction — propose
  changes in your summary instead.
- Preserve the corpus's honesty discipline: measured numbers are labeled
  measured, hypotheses are labeled hypotheses, and a spike that didn't run
  says so. Retain invalid and quarantined evidence with its original status;
  support new claims with the required evidence for the exact code revision.

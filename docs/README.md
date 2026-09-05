# Documentation

Start with the repository [agent instructions](../AGENTS.md) for checkout
orientation and the [document and evidence precedence addendum](evidence-precedence.md)
when reconciling current work with historical plans or results.

## Current v1 product design

- [Agent Spend Control Plane — approved design](superpowers/specs/2026-07-31-agent-spend-control-plane-design.md)
  — the current wallet-native direction: a customer-hosted **Wallet Kernel**
  for x402 spending policy, exact approvals, signed receipts, and reconciliation.
- [Wallet Kernel implementation plan](superpowers/plans/2026-07-31-agent-spend-control-plane.md)
  — implementation detail and verification requirements; completion must be
  checked against the current source and evidence.
- [Spend-control pilot offer and discovery brief](pilots/2026-09-05-spend-control-pilot.md)
  — prepared for operator review; customer demand, terms, and live pilot
  outcomes remain unvalidated.

## Historical handoffs

These record earlier assignments and their dated results. They do not supply
the current task queue or authorization for live execution.

- [2026-07-11 premise-review follow-ups](handoffs/2026-07-11-codex-premise-review-followups.md)
- [2026-07-15 launch-week handoff and July 18 readiness ledger](handoffs/2026-07-15-launch-week-handoff.md)

## Deferred expansion research

- [Employer onboarding, retention, and monetization recommendations](product-onboarding-retention-and-monetization.md)
  — superseded for v1 and retained as research for a possible future Skill
  attribution and Creator-compensation module.

## Security

- [Dependency security audit](dependency-security-audit.md)

## Earlier protocol architecture decisions

These preserve the protocol's design history and terminology. For current v1
scope use the approved Wallet Kernel design above; this index does not amend
the protected PRD, CONTEXT, or ADR corpus.

- [ADR-0001 — Hosted invocation-rights](adr/0001-skills-as-hosted-invocation-rights.md)
- [ADR-0002 — Story programmable IP](adr/0002-tokenize-skills-as-programmable-ip-on-story.md)
- [ADR-0003 — Payment-gated execution](adr/0003-payment-gated-execution.md)
- [ADR-0004 — Economic and network moats](adr/0004-compete-on-moats-not-secrecy.md)
- [ADR-0005 — Two-leg settlement](adr/0005-two-leg-cross-chain-settlement.md)
- [ADR-0006 — Closed modes first](adr/0006-phased-rollout-closed-modes-first.md)
- [ADR-0007 — Closed-mode compensation as the terminal product](adr/0007-closed-mode-compensation-layer-as-terminal-product.md)
- [ADR-0008 — The Wielder is a wallet](adr/0008-the-wielder-is-a-wallet.md)

# Compete on economic & network moats, not Skill secrecy

## Context

Without TEE (tabled in ADR 0003), a hidden Skill's *behavior* can be partially reconstructed from
its outputs — prompt-extraction succeeded against ~97% of custom GPTs historically. Perfect secrecy
is unattainable in the near term, so secrecy cannot be the Creator's moat.

## Decision

The Creator's moat is **not** "they can't see it" but "even approximated, cloning isn't worth it."
We rely on:

- **Provenance** (the Story IP Asset) — only the registered original earns marketplace trust.
- **The derivative royalty graph** — the ecosystem of forks and royalties accrues to the original
  lineage; clones are orphans.
- **Reputation / routing** — invocations flow to the proven Creator, not an unknown clone.
- **Live evolution** — the hosted Skill keeps improving; a static reconstructed copy rots.

Ship the prototype without confidential execution. TEE is a later upgrade for high-value Skills.

## Considered options

- **Watermark + legal enforcement** — kept as a complement, not a foundation: enforcement is slow,
  costly, and jurisdiction-dependent.
- **Un-table TEE for hard secrecy now** — rejected: front-loads heavy infra (confidential GPUs,
  attestation) into an MVP with no users.

## Consequences

- A clone can capture some value at the margins; accepted.
- The protocol must invest early in what *does* create the moat: provenance UX, the derivative
  graph, and reputation/routing.
- The model works best for Skills whose value is in **continuous evolution, proprietary data
  hookups, or composability** — not static prompt cleverness, which is the easiest thing to clone.

## Update (post-feasibility validation, 2026-06)

The sharpest leakage vector is not prompt extraction but off-platform **behavioral cloning**. For
most Skills the *output* is the value, so a high-volume Skill's own paid invocations become a cheap
(~30×) distillation training set — the more successful the Skill, the more attractive the clone, and
v1 (no TEE) cannot prevent it, only out-evolve it. Watermarking is a forensic tripwire (cheap
paraphrase removes it ~100%), not a moat. Net: the moat defends the **marketplace** (liquidity,
provenance, declared-derivative royalties), **not an individual breakout Skill**. Manage it
economically — price below amortized clone cost, ship faster than the distill-and-redeploy cadence,
and bind value to things outputs can't carry (live tool/data access, fresh private context).
Closed modes (intra-org/education) face the least pressure → launch there first (ADR-0006). This is
externally validated: OWASP LLM07:2025 states the system prompt must not be treated as a security
control.

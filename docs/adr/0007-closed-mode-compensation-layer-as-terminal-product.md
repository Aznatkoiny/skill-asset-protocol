# The closed-mode compensation layer is the terminal product

**Status:** Accepted (2026-07-11)

## Context

An adversarial premise review (2026-07-11; six full-corpus readers, four premise critics) returned
a consistent verdict — "shaky, not broken" — and a consistent diagnosis: the corpus is honest but
**inverted**. The PRD leads with its weakest claims (the open-marketplace royalty story) and treats
its strongest asset (the off-chain metered ledger + co-held, non-transferable claims) as a stepping
stone. Four critiques of the marketplace frame survived steelmanning:

1. **Success is self-defeating in the open market.** A breakout Skill's own paid I/O pairs are a
   ~30×-cheaper distillation set — ADR-0004's own concession. The addressable middle (too dynamic
   to distill, not valuable enough to SaaS-ify) is unsized and may be empty.
2. **Hosting strips context-bound value.** Claude Code skills are context-bound; a hosted
   invocation that returns output only loses much of what makes them useful (see the ADR-0001
   amendment: hosting preserves artifact scarcity, not economic scarcity).
3. **Education mode has a free bypass.** Provenance cannot distinguish "forked the school's Skill"
   from "re-authored using what the class taught" — which is nearly free and pays the school
   nothing.
4. **The likeliest killer was dismissed, not analyzed.** A platform-native skill marketplace
   (Anthropic/OpenAI/GitHub) had no kill-criterion. The GPT Store (OpenAI, launched Jan 2024) is
   the base rate: platforms *do* ship native skill-adjacent marketplaces, and builder monetization
   was weak even with zero-friction distribution to a massive user base (research, 2026-07).

A fifth objection also survived — the co-held claim has no vesting/clawback/termination design
("when Sam quits") — but it indicts the closed-mode *design*, not the closed-mode *frame*; it is
absorbed as a design input below.

What survives the same review: the closed-mode kernel, **reframed as a compensation/attribution
instrument**. In an intra-org deployment the employer already possesses the Skill, so
clone-resistance (critiques 1–2) is irrelevant there; what is missing is the metering rail. And the
institutional behavior the rail serves is not hypothetical: Germany's **ArbEG** statutory inventor
remuneration, corporate **patent-award programs**, and university **tech-transfer revenue splits**
all demonstrate that institutions share invention upside with individual employees — none of them
has a metering rail for AI work artifacts.

## Decision

**The product is a compensation, attribution, and metering layer for authored AI Skills — "Carta
for AI work artifacts" — not a skill marketplace.**

- **Phase 1 is the terminal state by design.** The off-chain signed ledger + co-held
  non-transferable claims + Story provenance must be independently viable if Phases 2–3 never
  ship. On-chain settlement and tradeability are explicitly underwritten optionality, not the
  destination.
- The intra-org pitch leads with **compensation and retention** — the ArbEG / patent-award /
  tech-transfer shape — not royalty upside.
- The positioning against platforms is the asymmetry: platforms can ship a skill marketplace in a
  quarter (the GPT Store proves they will); they will never ship 409A-structured co-held
  compensation instruments. That asymmetry, plus cross-platform neutrality of provenance, is the
  moat.

## Considered options

- **Keep the marketplace as the headline and patch the critiques individually** — rejected: the
  four critiques compound in the open market and none is individually solved (distillation is
  conceded, the addressable middle is unsized, the platform incumbent is proven willing); leading
  with them means leading with the corpus's weakest claims.
- **Kill Phases 2–3 outright** — rejected: the mechanics (ledger schema, split logic, provenance
  graph) are identical in closed and open modes, so preserving the marketplace as optionality is
  nearly free, and deleting it forecloses upside the closed mode itself underwrites.

## Consequences

- **The open Marketplace becomes underwritten optionality**, not the identity. ADR-0006's phasing
  stands with its emphasis reversed: Phases 2–3 are exercised only if warranted, they are no longer
  the point of the exercise.
- **Phase-3 investment is deferred until closed-mode traction.** The securities stack (ERC-3643,
  ATS, transfer agent, KYC) is not built, and counsel is not engaged for it, before the closed mode
  has paying deployments.
- **Education mode is demoted** — deferred pending a re-run of the fork-economics spike whose
  alternative branch is "re-author with class knowledge ≈ free" (critique 3). If that branch
  holds, the school claim must be restructured (living school-maintained content, or direct
  school→employer licensing) or cut.
- The co-held claim inherits first-class design inputs the marketplace frame ignored: **vesting,
  clawback, and termination ("when Sam quits")** — tracked in the PRD's regulatory section.
- We have NOT validated that employers will buy this. The precedents show institutions *do* share
  invention upside under statute or policy; they do not show demand for a third-party metering
  rail. Design-partner interviews remain the open validation step.

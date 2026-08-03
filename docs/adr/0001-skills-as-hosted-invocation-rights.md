# Skills are sold as hosted invocation-rights, not as files

**Status:** Accepted, amended 2026-07-11

## Context

A **Skill** is plaintext (a `SKILL.md`, plugin, or agent definition) and therefore trivially
copyable. If we sold the artifact, the Creator earns a one-time fee and the buyer can copy it
infinitely — which is precisely the "hand it over once, capture none of the upside" outcome the
project exists to prevent.

## Decision

A Skill is **never handed over**. It executes inside a hosted agent runtime (e.g. an Anthropic
Managed Agent, OpenAI ChatKit workflow, or Vertex Agent Engine), and the **Wielder** acquires a
metered **Invocation-right** — permission to trigger runs and receive only the *output*, paying
per use. The tradeable asset is the royalty stream, not the artifact.

## Considered options

- **Artifact ownership (NFT of the file)** — rejected: copyable plaintext yields no per-use
  income and does not stop automation-displacement.
- **Attested license (file held locally, usage self-reported)** — rejected for the core flow:
  enforcement is honor-system; defeats the scarcity that funds the royalty.

## Consequences

- Skills must run as **hosted services**. Fully-local / offline execution is out of scope for the
  monetized path.
- The artifact stays scarce, but the residual leakage risk shifts from *file copying* to
  *output-channel distillation* (a Wielder reconstructing behavior from outputs). This must be
  managed separately — prompt hardening and/or TEE/confidential execution — and is an open
  question, not solved by this decision.

## Amendment (2026-07-11)

This decision has been over-read, including by us, and the amendment absorbs ADR-0004's concession
explicitly: hosting preserves **artifact** scarcity, not **economic** scarcity. The `SKILL.md` never
leaves the Collar, but for most Skills the *output is the value*, and a high-volume Skill's own paid
outputs are a cheap (~30×) behavioral-distillation training set. So the division of labor is:

- **The invocation-right protects the file.** Per-use payment and never-handing-over remain the
  mechanism — they stop artifact copying and make usage meterable.
- **The moats protect the economics** (ADR-0004): provenance, the derivative royalty graph,
  reputation/routing, live evolution — and, per that ADR's own update, they defend the marketplace
  as a whole, not an individual breakout Skill.

The 2026-07 premise review rated the open-market reading of this decision ("hosting keeps the
Creator's income safe") among the corpus's weakest claims, and it is one of the four critiques
behind the closed-mode reframe (ADR-0007). In closed modes the counterparty (the employer) already
*possesses* the Skill, so clone-resistance is irrelevant there; hosting's job narrows to what it
actually delivers — a single meterable execution point that feeds the compensation ledger.
"Never handed over" stands as the mechanism for the (now optional) open Marketplace; it is not,
anywhere, the thing that makes the Creator's economics safe.

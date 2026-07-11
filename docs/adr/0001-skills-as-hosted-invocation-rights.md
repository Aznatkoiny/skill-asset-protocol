# Skills are sold as hosted invocation-rights, not as files

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

# Payment-gated execution: payment is the meter, not a witness

**Status:** Accepted, updated 2026-06 (post-feasibility validation); clarified 2026-07-11 (Wielder-side qualifier per ADR-0008)

## Context

A Skill runs hidden off-chain; royalties settle on-chain. The intuitive design — "prove to the
chain that the secret Skill ran" — is impractical: you can't reveal the Skill to prove it executed,
outputs are reconstructable, and ZK-proving an LLM inference is not viable today.

## Decision

Invert the causality. **Payment is the metered event AND the precondition for execution.** A
per-invocation payment mints a single-use **execution credential** that the hosted runtime requires
before it will run the Skill. The chain witnesses the *payment*, never the Skill.

(Refined post-feasibility — see Update: the gating payment settles on **Base via x402** and yields a
**txHash credential** checked off-chain; on-chain royalty settlement on **Story** is a separate,
batched leg, not atomic with the gate.)

## Considered options

- **TEE-attested execution** — tabled as a future hardening layer (protects the Skill from the host
  and prevents run-without-charging), not the core mechanism.
- **Trusted-oracle attestation** — rejected: a central party that signs usage reports can
  under-report (skim) or over-report.

## Consequences

- Usage fraud on the money path is structurally impossible: no payment → no execution.
- Residual risks (to be handled later, primarily via the tabled TEE layer): a malicious host could
  accept payment and fail to run (mitigated near-term by refunds / reputation), and — without a TEE
  — the host operator can still see the Skill content.

## Update (post-feasibility validation, 2026-06)

The "usage fraud is structurally impossible / no trusted oracle" guarantee holds **only for the
synchronous, single-chain, atomic** case. The real architecture (ADR-0005) decouples the payment
gate (x402/USDC on Base) from on-chain royalty settlement (Story), with **off-chain batching**.
Consequence:

- The per-invocation **gate** stays **Wielder-side** trust-minimized — *no credential, no run*,
  enforced per call (the Wielder cannot obtain a run without a settled payment; from every other
  seat this is enforced by the Collar's own code and key custody — an ops SLO backed by a
  key-custody/rotation design, not an architectural property; see ADR-0008 and the PRD's
  Reliability targets).
- **Settlement** degrades from "structurally impossible to defraud" to an **auditable accumulator**:
  the Collar batches off-chain and could in principle mis-report or skim. Mitigations: signed,
  auditable invocation logs; on-chain published settlement batches for reconciliation; refund +
  reputation for accept-payment-but-fail-to-run; tabled TEE as the eventual structural fix.
- The **execution credential** is the x402 settled **txHash** (Collar-checked off-chain), NOT a
  per-call on-chain Story License Token (uneconomic at per-call cadence).

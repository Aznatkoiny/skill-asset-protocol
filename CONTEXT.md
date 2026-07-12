# Skill Asset Protocol (working name)

A compensation, attribution, and metering layer for authored **Skills**
(natively-digital work artifacts such as Claude Code skills, plugins, and agents) —
"Carta for AI work artifacts." **Creators** retain a durable, co-holdable economic
claim each time others use their Skill, instead of handing the value over once under
work-for-hire and capturing none of the upside. The closed modes (**Intra-org**;
**Education**, currently deferred pending the fork-economics re-run — ADR-0007) are
the product; the open **Marketplace** is one *future* mode —
underwritten optionality, not the identity (ADR-0007).

## Language

**Skill**:
A natively-digital, reusable work artifact that encodes specialized capability — e.g. a
Claude Code skill, plugin, or agent definition. The unit of value in this system.
_Avoid_: tool, script, prompt, asset (too generic)

**Creator**:
The party that authors a **Skill** and holds the residual economic claim on its use.
_Avoid_: author, developer, owner (ownership becomes ambiguous once tokenized)

**Wielder**:
The party that invokes a **Skill** to perform productive work. Need not be the party
that ultimately profits from that work. Any client that can pay is a Wielder: a wallet,
not a specific harness — Claude Code, Pi, a cron job, and curl are all Wielders. The
paying wallet may be funded by the **Beneficiary** — who wields and who funds the
payment remain distinct roles. The entire Wielder-side protocol footprint is "answer
HTTP 402 with a signed payment and retry" (ADR-0008).
_Avoid_: user (overloaded), operator, consumer, harness (a Wielder may be one, but need not be)

**Beneficiary**:
The party that realizes downstream economic value from a **Wielder**'s use of a **Skill**
(typically the employer). May or may not be the same party as the **Wielder**.
_Avoid_: employer, buyer, customer (each is just one instance of this role)

**Marketplace**:
The open venue where **Invocation-rights** to **Skills** are offered to any **Wielder** and
**Royalty claims** trade. The **Intra-org** and **Education** modes route the same primitives
privately; the Marketplace is the public one.
_Avoid_: store, exchange, platform

**Collar**:
The hosted gate wrapped around a **Skill**'s execution: the sole platform API-key holder,
the x402 resource server (it answers unpaid requests with HTTP 402 and checks the settled
payment as the **Execution credential**), and the off-chain meter that records every
**Invocation** and credits the royalty split. The single trusted component in the system —
the **Wielder** stays a thin payer precisely because the Collar absorbs the trust.
_Avoid_: gateway, proxy, middleware (each names a mechanism; the Collar is the trust boundary)

## Archetypes

The three distribution modes are all the same Creator → Wielder → Beneficiary shape,
collapsed differently:

- **Marketplace**: independent **Creator** → any **Wielder** (Wielder and Beneficiary are the same person)
- **Intra-org**: employee-**Creator** and employer **co-hold the Royalty claim** (replacing work-for-hire's 100/0); shared upside comes from *external* **Wielders** invoking the Skill — routed privately/directly in the closed modes, or via the open **Marketplace** if that mode ever ships
- **Education**: institution-**Creator** authors a base **Skill**; the student forks it into a **Derivative** they own (becoming a **Creator** themselves) and wields it at work; the employer-**Beneficiary** pays per **Invocation**, which splits to the student's **Derivative** and flows through to the school

## Relationships

- A **Skill** has exactly one **Creator** at origin (co-authorship is an open question).
- A **Wielder** invokes a **Skill**; that invocation is the event that should generate value flowing back to the **Creator**.
- A **Beneficiary** profits from the **Wielder**'s output and is the natural source of the funds that settle to the **Creator**.
- A **Derivative** **Skill** owes royalties to every **Skill** in its ancestry — credited per **Invocation**, claimable on demand (composable royalty flow-through).
- A **Royalty claim** attaches to a **Skill** and entitles its holder(s) to a share of that Skill's **Invocation** revenue.
- A **Royalty claim** may be co-held by multiple parties (e.g. an employee-**Creator** and their employer), so both earn from every external **Invocation**.

**Invocation**:
A single metered use of a **Skill** via its hosted execution. The billable event. The
Wielder receives the *output* of the Skill, never the Skill's content.
_Avoid_: call, request, run (use Invocation for the billable unit specifically)

**Invocation-right**:
What a Wielder acquires — permission to trigger **Invocations** of a **Skill**, priced
per use and exercised by paying (ADR-0008). It (not the artifact) is what gets
tokenized — and traded only in the open **Marketplace** mode (underwritten
optionality, ADR-0007).
_Avoid_: license (too broad), ownership

**Derivative**:
A **Skill** created by forking or building upon one or more existing **Skills**. Each
**Invocation** of a Derivative owes royalties to its ancestor Skills (credited per Invocation,
claimable on demand — see ADR-0005).
_Avoid_: fork, copy (copy implies the unauthorized duplication this system exists to prevent)

**Royalty claim**:
An entitlement to a share of a **Skill**'s future **Invocation** revenue. Co-holdable and
fractional. Transferability is mode-dependent: **non-transferable** in **Intra-org** /
**Education**; a permissioned, regulated security when tradeable in the open **Marketplace**
(see ADR-0006).
_Avoid_: dividend, share, equity

**Execution credential**:
A single-use authorization, minted by a **Wielder**'s per-**Invocation** payment, that the
hosted runtime requires before it will run a **Skill**. The link between payment and execution:
no credential, no run.
_Avoid_: token (overloaded), license, key

## Example dialogue

> **Dev:** "When a student runs the school's **Skill** at their employer, who pays?"
> **Domain expert:** "The employer — they're the **Beneficiary**. Each run is an **Invocation**, and the payment mints an **Execution credential** the runtime needs before it will run."
> **Dev:** "And the school gets all of it?"
> **Domain expert:** "No. The student forked the school's Skill into a **Derivative** they own, so the payment splits to the student and *flows through* to the school as the ancestor. The student holds a **Royalty claim** on their own Derivative — that's the asset they graduate with."
> **Dev:** "What stops the employer from copying the Skill and skipping payment?"
> **Domain expert:** "They never receive the Skill — only its output. And even an approximate clone can't claim provenance or tap the **Derivative** graph, so building one isn't worth it."

## Flagged ambiguities

- "tokenized asset" — RESOLVED in principle: the tradeable asset is the **Invocation-right** /
  royalty stream, NOT the Skill artifact. The artifact itself is never sold or handed over.
- "skill" — colloquially means a human ability; here it strictly means the digital artifact.
  Human capability is the *thing the artifact encodes*, not the Skill itself.
- Who **pays** vs. who **benefits** may be different parties; not yet pinned down.
- Hiding the Skill from the *host* (e.g. Anthropic) is NOT solved in v1 — the host processes the
  Skill in plaintext (no TEE), and `GET /v1/agents` echoes it to the key-holder. Accepted as a
  deferred trust boundary per ADR-0004; TEE is the tabled future hardening. The Skill IS hidden
  from the **Wielder**, who sees only the output.
- Settlement is **eventually-consistent**, not atomic: the per-**Invocation** payment gate and the
  on-chain royalty settlement are decoupled legs (ADR-0005). The gate is **Wielder-side**
  trust-minimized — the trusted component is the **Collar**; batched settlement is an "auditable
  accumulator" (ADR-0003 Update).
- Marketplace-vs-closed-mode identity — RESOLVED (2026-07): the closed modes ARE the product — a
  compensation/attribution layer that must be independently viable even if the open **Marketplace**
  never ships. The Marketplace is underwritten optionality, not the identity (ADR-0007).
- What fraction of the existing skill supply is **host-compatible** — i.e. loses little of its value
  when executed hosted, behind a **Collar**, rather than inside the caller's own context — is
  UNKNOWN and unmeasured. Context-bound skills (plausibly most Claude Code skills) may lose most of
  their value when hosted. Flagged, not resolved.

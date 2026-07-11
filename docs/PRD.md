# Skill Asset Protocol -- Product Requirements & Feasibility-Grounded Plan

*A settlement protocol that lets the Creators of authored AI Skills keep a durable, monetizable claim on every future use -- instead of handing the value over once.*

> **Status:** Derived from a structured design interview and an adversarial feasibility validation; see `CONTEXT.md`, `docs/adr/`, `docs/feasibility/report.md`, `docs/feasibility/findings.json`.
> **Feasibility verdict:** GO-WITH-CAVEATS. Every component is real and live on mid-2026 APIs; the idealized atomic loop does not compose and is rebuilt here as a decoupled, two-leg, batched, eventually-consistent settlement. **Confidence is high on every technical component and *medium* on regulatory**, and several load-bearing facts remain unmeasured -- see [What we have NOT validated](#what-we-have-not-validated).

## Table of Contents

1. [Executive Summary & Thesis](#executive-summary)
2. [Problem & Market](#problem--market)
3. [Product & User Experience](#product--user-experience)
4. [Technical Architecture (v1, honest)](#technical-architecture)
5. [Economic Design & Tokenomics](#economic-design)
6. [Regulatory & Compliance Strategy](#regulatory--compliance-strategy)
7. [Competitive Landscape & Moat](#competitive-landscape--moat)
8. [Go-to-Market & Rollout](#go-to-market--rollout)
9. [Team, Capital, Timeline & Kill-Criteria](#team-capital-timeline--kill-criteria)
10. [Risks & Open Questions](#risks--open-questions)
11. [What we have NOT validated](#what-we-have-not-validated)
12. [Roadmap & Milestones](#roadmap--milestones)

---

## Executive Summary

**Knowledge workers who build reusable AI Skills hand them to employers once and capture none of the recurring value — automating themselves out of the very upside they created. This protocol lets a Creator keep a durable, monetizable claim on every future use of a Skill instead of surrendering it for a one-time wage.** An authored Skill (a Claude Code skill, plugin, or agent definition) is a natively-digital asset whose value can be retained rather than transferred: it runs behind a hosted runtime that meters each use and hands the user only the *output*, never the Skill itself, while on-chain royalty tokens route a share of that metered revenue back to the Creator and through to any ancestors it was forked from.

What we are building is a settlement protocol around the **Invocation** — the billable, metered use of a Skill. A **Creator** authors a Skill; a **Wielder** invokes it for productive work; a **Beneficiary** (typically the employer) pays per Invocation and profits from the output. Each payment gates execution (no payment, no run) and accrues a royalty that splits among the holders of the Skill's **Royalty claim** — which can be co-held (e.g. employee plus employer) — and flows through the **Derivative** ancestry to every Skill a fork was built on. The Skill is registered as an IP Asset on Story Protocol with declared lineage, so provenance and the derivative-royalty graph are on-chain and auditable.

The protocol ships in **three modes**: **Marketplace** (independent Creator to any Wielder), **Intra-org** (employee-Creator and employer co-hold the claim, replacing work-for-hire 100/0, sharing upside from external invocations), and **Education** (a school authors a base Skill, a student forks it into a Derivative they own and wields it at work, the employer pays per Invocation, royalties split to the student and flow through to the school).

**Honest architecture:** the vision validates as real but does *not* compose into one atomic action. It is a **decoupled two-leg settlement**. Leg 1 is the gate — x402 settles gasless USDC on Base (chainId 8453); the replay-proof txHash is the single-use execution credential, checked off-chain so the Wielder pays first and the agent runs after. Leg 2 is royalties — an off-chain worker batches payments, bridges and swaps USDC into WIP on Story (chainId 1514), calls `payRoyaltyOnBehalf`, and runs a keeper that pull-claims for ancestors. Royalty flow-through is therefore **eventually-consistent and claimable**, not atomic per call. Do not attempt to make x402 settle directly to Story (wrong chain, wrong token, wrong primitive — see `docs/feasibility/report.md` §4.1).

**Go-to-market is closed modes first.** Intra-org and Education face the least cloning pressure, are on-platform by construction, and can keep Royalty claims **non-transferable**, which is the best available route to staying outside securities law — though not a guaranteed safe harbor, and one counsel must bless before Phase 1 ships. Phase 0 ships provenance immediately (register Skills as Story IP Assets and Derivatives); Phase 1 adds the gate, run, and an off-chain metered ledger; Phase 2 adds on-chain batched royalty settlement; Phase 3 opens the tradeable Marketplace — but only permissioned (ATS, transfer agent, exemption, KYC), with securities counsel engaged first, because tradeable claims are securities under Howey.

**The single most important strategic risk is off-platform behavioral cloning, and it sits below the chain.** Because the Wielder receives the output, and for most Skills the output *is* the value, a high-volume Skill is the cheapest thing to clone — its own paid input/output pairs are a roughly 30x-cheaper distillation set (`report.md` §5; ADR-0004 Update). Watermarking is a forensic tripwire, not a moat. The protocol defends the *marketplace* (liquidity, provenance, declared-derivative royalties), not an individual breakout Skill. The recommended response — **price below amortized clone cost, out-evolve via live updates, bind value to live tool and data access** — is load-bearing but rests on an *unmeasured* assumption: no source quantifies how fast a Skill must change to keep a distilled clone economically stale (`report.md` §7.7). We launch in the closed modes, where the pressure is lowest, partly to buy time to measure this.

---

## Problem & Market

### The displacement thesis

The premise is a specific, near-term labor shock, not a generic "AI is coming for jobs" claim. Knowledge workers are now encoding their hard-won expertise into **Skills** — Claude Code skills, plugins, agent definitions: natively-digital, reusable work artifacts that perform the work the human used to do. A Skill is plaintext (a `SKILL.md`, a plugin manifest, an agent prompt) and therefore trivially copyable (ADR-0001). The moment an employee hands one to an employer, the prevailing legal default — work-for-hire — assigns 100% of the value to the employer and 0% to the author. The worker has, in effect, paid to automate their own role and captured none of the resulting productivity gain. The faster and better they encode their expertise, the faster they erase their own bargaining position.

This is the asymmetry the protocol attacks. Today a Skill's value transfers **once** (a salary, a one-time sale, or simply unpaid output of employment) and then compounds for whoever holds the artifact. The protocol's thesis is that the durable, recurring value of an authored Skill should accrue, in part, to its **Creator** every time it is **wielded** — by converting "I built this and gave it away" into "I built this and hold a **Royalty claim** on its invocations." The unit of economic value is the *Invocation* (the metered, billable run), and the tradeable thing is the *Invocation-right* / royalty stream — never the artifact, which is never handed over (ADR-0001).

A necessary honesty caveat, because it bounds the whole market: the protocol defends the **marketplace and the provenance graph**, not any single breakout Skill. For most Skills the *output is the value*, and ADR-0001 hands the Wielder the output. A high-volume Skill is therefore the cheapest thing in the world to behaviorally clone — its own paid input/output pairs are a roughly 30x-cheaper distillation set. The moat is liquidity, declared-derivative royalties, live evolution, and binding value to live tool/data access — not secrecy or watermarking (which is a forensic tripwire, removable by paraphrase, not a moat; ADR-0004). This is why the displacement thesis is strongest in **closed populations** first, where cloning pressure is lowest.

### The three customer segments and their pain

The three modes are one shape — Creator → Wielder → Beneficiary — collapsed three ways (CONTEXT.md). Each has a distinct payer and a distinct pain.

**1. Independent Creators → any Wielder (Marketplace mode).**
A skilled author writes a genuinely valuable Skill and has exactly two bad options today: sell the file once (buyer copies it infinitely, author earns nothing further) or self-host it as a SaaS (build billing, auth, infra, and a metering pipeline from scratch). Their pain is the absence of a per-use monetization rail for a copyable artifact. *Who pays:* the **Wielder is the Beneficiary** — the person invoking the Skill profits directly from its output and pays per Invocation. This is the highest-pain, highest-incentive-to-clone, and most regulated segment (tradeable claims are securities), so it is sequenced **last** (ADR-0006).

**2. Employee-Creators + Employers (Intra-org mode).**
The employee who builds a Skill at work today gets work-for-hire's 100/0 split and watches their leverage evaporate. The employer's reciprocal pain is retention and incentive: their best people have every reason to hoard expertise, build Skills on the side, or leave. The mode replaces 100/0 with a **co-held Royalty claim** — employee and employer both hold a fractional, co-holdable claim on the Skill, and both earn from *external* invocations across the marketplace. The prototype makes this concrete (`recon`: Sam 50% + MegaCorp 50%, both paid on an external invocation). *Who pays:* an **external Wielder/Beneficiary** outside the org; the internal split is the alignment mechanism, not the revenue source. Claims here are kept **non-transferable**, the best available route to keeping the mode outside securities law (ADR-0006) — a reason it ships before the marketplace. **Assumption flagged:** whether mid-size employers will actually restructure work-for-hire IP terms into a co-held claim is *unvalidated* (R12, rated Medium-High); the design-partner LOIs that would prove it do not yet exist and are a Phase-0/1 gate (see [Team, Capital, Timeline & Kill-Criteria](#team-capital-timeline--kill-criteria)).

**3. Schools + Students + Employers (Education mode).**
A school teaches a capability but captures none of its graduates' downstream economic value; a student graduates with debt and a credential but no durable, owned, income-producing asset; an employer wants the capability but has no clean per-use rail to pay for it. The mode threads all three: the **school authors a base Skill**, the **student forks it into a Derivative they own** (becoming a Creator), and wields that Derivative at work. *Who pays:* the **employer is the Beneficiary** and pays per Invocation; royalties **split to the student's Derivative and flow through to the school** as an ancestor. The prototype's `biofin` (forks `finmod` at 30% inherit) shows the split. The asset the student graduates with is a real Royalty claim. **Open economics question:** the prototype flags a "fork-killing threshold" — at high ancestor-royalty rates forking stops being worth it; the right inherit-bps is *unresolved* and is the key economics experiment in `prototype/README.md` (verdict currently **TBD**). See [Economic Design](#economic-design).

### Why now

Four independent enablers crossed the line into "real and usable" in mid-2026 — the protocol was not buildable even a year earlier:

- **Managed agents let the collar hide the Skill from the Wielder — because the collar holds the sole API key, not because the platform keeps it secret.** Anthropic Managed Agents (CMA, beta `managed-agents-2026-04-01`) persist the system prompt and skills on the Agent object; the session *output* stream (`agent.message`/`thinking`/`tool_*`/`span.*`) never carries them, so a party who only sees output gets only the output (`report.md` §3 step 2; `findings.json` `/verdict/confirmed[1]`). **This is hiding from the WIELDER only.** The hiding property is a function of *who holds the platform API key*, not a platform secrecy feature: `GET /v1/agents` echoes the full system prompt verbatim to the key-holder, and Anthropic processes the Skill in plaintext (no TEE). It holds solely because the collar is the sole key-holder and never proxies `GET /v1/agents` (accepted per ADR-0004; CONTEXT.md lines 98–101). What this *enables* is monetizing a copyable plaintext artifact per-use — not because it is secret, but because the Wielder pays for outputs without receiving the artifact.
- **x402 is mature.** Coinbase's HTTP-402 stablecoin rail became a Linux Foundation / x402 Foundation standard (donated 2026-04-02), reached ~165M transactions and ~$50M cumulative volume by April 2026, and is backed by Stripe (x402 USDC-on-Base live Feb 2026), AWS Bedrock AgentCore, and Cloudflare (`findings.json` `/verdict/confirmed[2]`). It gives a clean per-invocation gate whose settled `txHash` is a replay-proof, single-use execution credential ("no credential, no run").
- **Story Protocol is live.** chainId 1514, SDK v1.4.4 — registers a Skill as an IP Asset with declared Derivative ancestry, mints co-holdable fractional royalty tokens, and supports derivative flow-through. The on-chain provenance and royalty graph the whole model depends on exists today (Phase 0 ships immediately, ADR-0006).
- **The supply side exploded.** Authored AI Skills (Claude Code skills, plugins, agent definitions) went from niche to a fast-growing artifact class — meaning there is now a large, growing population of Creators with real expertise to encode and a real fear of giving it away.

One honest caveat on timing: the literal vision — a single payment that both gates execution and atomically pays ancestors on Story — does **not** compose, because x402 settles USDC on Base while Story royalties need WIP on Story, with no facilitator bridging the two. It must be rebuilt as a decoupled, two-leg, batched, eventually-consistent settlement (ADR-0005). The components are real; the wiring is harder than the pitch.

### Directional market framing (ranges and logic, no false precision)

We deliberately avoid a fabricated TAM. The honest framing is a chain of logic plus a few hard, sourced numbers:

- **Demand for per-call machine payment exists and is growing.** x402's ~165M transactions / ~$50M cumulative volume by April 2026, across multiple facilitators since it became a Linux Foundation / x402 Foundation standard, demonstrates that per-call machine/agent payments are real and growing, not theoretical (`findings.json` `/validated[x402]/evidence` note: "protocol ~165M tx / $50M cumulative by Apr 2026; ~49% volume on non-Coinbase facilitators"). **Read this as evidence the *rail* is real and multi-vendor, not as a demand signal for skill-royalty payments specifically** — the bulk of x402 volume today is agent-infrastructure micropayments, not Skill royalties. Per-call economics are micropayment-grade (~200ms settle target, sub-cent Base fees) — the rail can carry cents-level invocations.
- **The serviceable wedge is the closed modes first.** Intra-org and education are bounded by the count of organizations and schools willing to restructure compensation/IP terms — an *assumption we have not validated* (R12) — not by a consumer funnel. This is a smaller, slower, enterprise-sales-shaped market, but it is the one with aligned incentives, lowest cloning pressure, and no securities overhead. It is where revenue is realistic in year one *if* the willingness-to-co-hold assumption holds.
- **The large, uncertain upside is the open marketplace**, which scales with the size of the authored-Skill economy and the willingness of Wielders to pay per use. This is genuinely large in principle and genuinely unproven in practice — and it is gated behind the securities stack (ATS, transfer agent, exemption, KYC) and the thinnest moat, so it should be underwritten as optionality, not as the base case.
- **No demand-side evidence yet.** The thesis that Beneficiaries will pay per-invocation for outputs they could in principle clone has **no pilot LOI, no pricing research, and no committed design partner today**. The only quantitative demand signal we cite is x402 aggregate volume, which is not skill-royalty demand. Treat demand validation as an explicit Phase-0/1 gate, not an established fact.
- **Known headwinds to discount into any model:** royalties accrue in WIP, and $IP traded around $0.37–0.60 in June 2026, ~97.5% below its $14.78 ATH, on thin ~$35–47M daily volume. Enterprises will not hold WIP, so FX/liquidity risk and a fiat/USDC→WIP on-ramp are costs the model must carry. Per-hop settlement fees force mandatory batching, which sets a price floor below which a micro-royalty is uneconomic.

The defensible claim is therefore *not* a dollar figure. It is: there is a real, painful, three-sided problem; the rails to address it became real in mid-2026; demand for per-call payment is empirically growing *in adjacent agent-infra use*; and the right way to size this is to win the closed modes (a tractable enterprise/education market, **subject to validating willingness-to-co-hold**) before betting the company on the open marketplace's larger-but-unproven upside.

### Who pays, in one view

| Mode | Creator | Wielder | Who pays (Beneficiary) | Royalty flow | Claim transferability |
|---|---|---|---|---|---|
| Marketplace | Independent author | Any buyer | The Wielder (Wielder = Beneficiary) | All to Creator (less protocol fee) | Tradeable → security (Phase 3) |
| Intra-org | Employee | External party | An external Wielder/Beneficiary | Split to co-held employee + employer | Non-transferable (best route outside securities law) |
| Education | School (base) + student (Derivative) | The student, at work | The student's employer | Split to student's Derivative, flows through to school | Non-transferable (best route outside securities law) |

### Co-authorship (open design question)

CONTEXT.md (line 46) states that a Skill has **exactly one Creator at origin** and explicitly flags **co-authorship as an open question**. v1 assumes single-Creator origin everywhere in this document. Teams that build a Skill jointly are not yet modeled: the co-held *Royalty claim* mechanic (employee+employer, student+school) can express multiple *holders* of a claim, but the question of multiple *originating authors* — how they split the claim at registration, how disputes resolve, and how a multi-author Skill declares ancestry — is unresolved and must be designed before Marketplace (where independent multi-Creator teams are likeliest). Until then, multi-author teams should designate a single registering Creator and split via the co-hold mechanic as a stopgap.

---

## Product & User Experience

This section walks the lived experience of each role in each of the three modes, then shows the one settlement loop they all share and where it visibly differs. The throughline: nobody touches a blockchain directly, nobody types "WIP," and no Wielder ever sees a Skill. The chain is plumbing; the product is a registration flow, a metered endpoint, and a balance that goes up.

Concrete cast, taken from the seeded prototype (`prototype/settlement-engine.mjs`) so every dollar figure below is one the engine actually produces:

| Skill | Mode | Price/Invocation | Ancestry | Royalty claim |
|---|---|---|---|---|
| `pdf-extract` | Marketplace | $10 | root | Dana (indie) 100% |
| `ledger-recon` | Intra-org | $20 | root | Sam 50% + MegaCorp 50% (co-held) |
| `fin-modeling` | Education | $5 | root | State U 100% |
| `biotech-fin-modeling` | Education | $25 | ↳ forks `fin-modeling` @ 30% flow-through | Mia 100% |

### The shape everyone shares: register → host → invoke+pay → output → accrue → claim

Before splitting by mode, here is the loop in plain terms, because all three modes are the same steps collapsed differently (CONTEXT.md, Archetypes).

1. **Register.** A Creator signs in, names a Skill, uploads the `SKILL.md` / plugin / agent definition, sets a per-Invocation price, and — if it's a fork — picks the parent and a flow-through rate. One click writes a Story IP Asset (and, for a fork, a declared Derivative with on-chain ancestry). The Creator sees a provenance card: "Registered. IP Asset 0x… · lineage: you → State U." This is **Phase 0** and ships first (ADR-0006); it is the soundest step in the whole loop (`report.md` §3, step 1).
2. **Host.** The artifact is pushed into a hosted runtime (an Anthropic Managed Agent) behind the collar, which is the sole API-key holder. From this moment the Skill is **never handed over to the Wielder** (ADR-0001). The Creator gets an Invocation endpoint and a price; the artifact is now a metered service, not a file. (**Phase 1.**)
3. **Invoke + pay.** A Wielder hits the endpoint. It returns `402 Payment Required`. The Wielder's client signs a gasless USDC payment on Base (x402, EIP-3009 `transferWithAuthorization`); the settled `txHash` is the single-use execution credential. The collar checks it off-chain — *no credential, no run* (ADR-0003) — and only then starts the agent. (**Phase 1.**)
4. **Receive output.** Payment settles in well under a second; the collar releases the credential, runs the agent asynchronously, and streams back **only the output** (ADR-0005 Leg 1). The Wielder never sees the system prompt or skill body; the session stream simply doesn't carry them (`report.md` §3, step 2). To the Wielder it feels exactly like calling any paid API. (**Phase 1.**)
5. **Accrue.** Each payment lands in an auditable off-chain ledger as a credited royalty balance, split by the claim table and flowed through the Derivative ancestry minus a protocol fee (the engine's `distribute()`, default 2.5%). (**Phase 1 — this is the off-chain ledger; nothing is on-chain yet.**)
6. **Claim / settle.** **In Phase 1, "claim" is a withdrawal against the off-chain auditable ledger, not an on-chain settlement.** On-chain settlement is **deferred to Phase 2**: a batched worker bridges/swaps USDC→WIP and calls `payRoyaltyOnBehalf` on Story, and a permissionless keeper auto-claims for ancestors so their balance never silently piles up (ADR-0005 Leg 2). Under the hood **flow-through is pull, not push**; the keeper hides the mechanic, but the *lag* between credited and on-chain-settled is real and surfaced (see caveat below).

The honest caveat the UX must absorb: settlement is **eventually-consistent, not atomic** (ADR-0005). Step 3 (the gate) is instant and trust-minimized; steps 5–6 (the on-chain split, Phase 2) are batched and lag. The keeper hides the *pull-not-push* mechanic, but it does **not** hide the *gap* between "credited" and "settled on-chain" — that gap is a real reconciliation surface that the protocol monitors as an operational alarm ("royalties credited vs. claimed"), and sophisticated buyers will notice it (R14). The product's job is to make the lag *tolerable and legible*: show a credited balance immediately, settle on-chain quietly in the background, and surface the on-chain batch as a reconciliation receipt — not to pretend the gap does not exist.

### Mode (a) — Marketplace: independent Creator → any Wielder

Here the Wielder and Beneficiary are the **same party** (CONTEXT.md). Cast: **Dana** (indie creator), **Acme** (wields `pdf-extract` for its own benefit).

- **Dana (Creator).** Registers `pdf-extract`, sets $10/Invocation, holds 100% of its royalty claim. Her dashboard shows: invocations today, gross, the 2.5% protocol fee, net to her, and a provenance badge proving she's the registered original. She does nothing per-call; she watches a balance climb and a "claim available" figure she can withdraw. Her real lever is iteration — she ships improvements, because a static clone of her outputs rots while the hosted original keeps evolving (ADR-0004). The product nudges this: changelog, "last updated," version-pinned provenance.
- **Acme (Wielder + Beneficiary).** Drops an API key / wallet into its tooling, calls the endpoint, pays $10, gets the extracted data. That's the entire experience — a paid API with a provenance link it can click to verify the Skill is the genuine, royalty-bearing original rather than an orphan clone.
- **Settlement Acme/Dana see.** Acme: a line item, "$10.00 — pdf-extract — txHash 0x…". Dana: "+$9.75 credited" (the engine routes $0.25 to treasury, $9.75 to Dana). No ancestry, so no flow-through — the simplest split in the system.

The honest framing for Marketplace, surfaced in the product's own positioning rather than hidden: this mode faces the **most** cloning pressure (a high-volume Skill's paid outputs are the cheapest distillation set, `report.md` §5; ADR-0004 Update). So the moat the UX sells here is the *marketplace itself* — liquidity, provenance, declared-derivative royalties, routing to the proven Creator — **not** a guarantee that any one breakout Skill is uncopyable. This is why Marketplace launches **last** (ADR-0006), and why its claims are the only ones that are tradeable.

### Mode (b) — Intra-org: employee-Creator and employer co-hold the claim

This replaces work-for-hire's 100/0 split. Sam builds `ledger-recon` on company time; instead of MegaCorp owning it outright, **Sam and MegaCorp co-hold the royalty claim 50/50**, and the upside they share comes from *external* Wielders invoking the Skill across the Marketplace (CONTEXT.md; ADR-0006). Cast: **Sam** (employee-Creator), **MegaCorp** (employer co-holder), **OtherCo** (external Wielder/Beneficiary).

- **Sam (Creator).** Registers `ledger-recon` at $20 inside the org workspace, and instead of the default 100%-to-creator claim, sets a co-held claim: `sam:5000, megacorp:5000` (the engine's `setRoyalty`, enforcing the split summing to 100%). Sam's view: "Your share 50% · Employer 50% · this is your durable claim, not a one-time deliverable." The emotional payload of the whole project lives here.
- **MegaCorp (employer / co-holder).** Sees the other half of the same claim plus governance: who can fork internal Skills, which are exposed externally, audit logs of every external Invocation. MegaCorp's incentive flips from "lock the work away" to "expose it so external invocations pay us both."
- **OtherCo (Wielder + Beneficiary).** Identical to Marketplace: `402` → pay $20 USDC → output. OtherCo neither knows nor cares that the claim behind the Skill is co-held.
- **Settlement Sam/MegaCorp see.** On OtherCo's $20 Invocation: $0.50 fee, $19.50 net, split $9.75 / $9.75. **Both** balances tick up on every external call (the prototype's `invoke recon otherco` makes this concrete).

Two product consequences that shape the UX heavily:
- **Claims are non-transferable here** (ADR-0006). Sam cannot sell his half on an open market; it's a contractual / deferred-comp right. This is deliberate — non-transferability is the best available route to keeping the claim outside securities law (no ATS, transfer agent, or KYC allow-list needed). The UX reflects it: a "claim" panel but **no "sell"/"list" button**. (Note the tax wrinkle: a co-held royalty claim structured as deferred comp carries 409A / constructive-receipt implications — see [Regulatory & Compliance Strategy](#regulatory--compliance-strategy) — that counsel must structure before launch.)
- A self-hosted sandbox is offered for regulated internal data, because the managed runtime is not ZDR/HIPAA-eligible and the host still sees the Skill in plaintext (`report.md` §3 step 2; ADR-0004). The product surfaces this as a data-residency toggle.

Closed population, aligned incentives, lowest cloning pressure — which is why Intra-org ships **first** in Phase 1 (ADR-0006).

### Mode (c) — Education: school authors a base Skill, student forks and owns the Derivative

The richest journey, because it spans years and produces an asset the student literally graduates with (CONTEXT.md example dialogue). Cast: **State U** (school-Creator of the base Skill), **Mia** (student → graduate, who forks it into a Derivative she owns and wields at work), **BioCorp** (Mia's employer, the Beneficiary who pays per Invocation).

- **State U (Creator of the base).** Registers `fin-modeling` at $5, holds 100% of its claim, and publishes it as forkable with a flow-through rate. State U's view is a *lineage* dashboard: every student Derivative descending from its base Skill, and royalties flowing up from all of them.
- **Mia (student → Creator).** Forks `fin-modeling` into `biotech-fin-modeling`, priced $25, with flow-through to her parent (the engine's `forkSkill(... inheritBps)`). The moment she forks, she becomes a Creator and holds 100% of *her* Derivative's claim. Her view: "You own biotech-fin-modeling · a share of each Invocation flows to State U · the rest is yours." This is the asset she walks out of school with.
- **BioCorp (Wielder + Beneficiary).** Mia uses her own Skill at work; **BioCorp pays per Invocation** because BioCorp is the Beneficiary. Same flow: `402` → pay $25 USDC → output. BioCorp sees a normal paid endpoint plus a provenance trail (Mia → State U) it can audit.
- **Settlement everyone sees (at the seeded 30% flow-through, which is *illustrative, not a recommended default* — see Economic Design).** On BioCorp's $25 Invocation, the engine produces: $0.625 protocol fee; of the $24.375 net, 30% ($7.31) flows up to State U as the ancestor, and Mia keeps $17.06. So **Mia ~$17, State U ~$7, per call** — the "does that split feel right?" experiment from `prototype/README.md`. Mia's dashboard: "+$17.06 (your claim)." State U's: "+$7.31 (flow-through from biotech-fin-modeling)."

Education is closed-population like Intra-org, so its claims are likewise **non-transferable** and ship in Phase 1 after Intra-org (ADR-0006). The open design question the UX must eventually answer is the **fork-killing threshold** (`prototype/README.md`, experiment 5, verdict **TBD**): if State U sets flow-through too high, forking stops being worth it for students and the lineage never grows. The product should expose flow-through as a *visible, tuned* dial with a live "what the student keeps vs. what flows up" preview at fork time.

### The UX gap: a non-transferable closed-mode claim vs. a (later) tradeable Marketplace claim

This is the single biggest experiential fork in the product, and it maps directly to a legal boundary (ADR-0006, CONTEXT.md).

**Closed-mode claim (Intra-org, Education — Phase 1, ships first).** The claim is a **balance and an entitlement, not an instrument.** What the holder sees and does:
- A claim panel: your %, co-holders or ancestors, accrued balance, claim/withdraw (**in Phase 1, withdraw against the off-chain ledger; on-chain settlement arrives in Phase 2**).
- **No "sell," no "list," no order book, no price chart.** Transfer is structurally disabled.
- Onboarding is just login — **no KYC, no accreditation gate, no securities disclosures**, on the basis that a non-transferable revenue-share right is the best available route outside Howey. (This is *medium-confidence*, not settled law — see Regulatory.)
- The mental model offered to Sam and Mia: "this is your durable, personal claim on future use — like deferred comp or a license fee that keeps paying," explicitly *not* "a tradeable security."

**Tradeable Marketplace claim (Phase 3 — ships last, only when warranted).** The same underlying royalty stream, but now an instrument that can change hands — which makes it **almost certainly a security** under Howey, and the live-evolution moat *strengthens* the "efforts of others" prong (ADR-0006; `report.md` §5). The UX is heavier by necessity:
- A **gated onboarding wall**: KYC, accreditation/eligibility checks, and an ERC-3643 allow-list.
- A **list-for-sale / transfer** flow that routes through a **registered ATS (e.g. Securitize) + transfer agent**, under a Reg D 506(c) / Reg A+ / CF exemption — *not* a one-click permissionless transfer.
- Secondary-market surfaces the closed mode deliberately omits: holders of record, transfer history, eligibility status per counterparty.

The crisp product line: **the derivative-royalty *mechanic* (fork, flow-through, co-hold, accrue, claim) is identical across all modes from Phase 1.** Only **tradeability** flips the experience from "a balance you withdraw" to "a regulated instrument you transfer through an ATS." The build sequence follows the risk: ship the simple, non-transferable, no-KYC closed-mode claim first; add the heavy, permissioned, KYC-gated tradeable claim last, with securities counsel engaged before that phase (ADR-0006).

---

## Technical Architecture

This is the **honest v1 design**: not the idealized loop where one payment both gates execution and atomically pays ancestors on Story, but the buildable one the feasibility validation supports — a **decoupled, two-leg, batched, eventually-consistent** settlement, fronted by a single trusted component (the *collar*) and anchored to two chains that each do the one job they are good at. Every claim below is grounded in `docs/feasibility/report.md` and the ADRs it produced (`docs/adr/0001`–`0006`).

The single load-bearing fact that shapes everything: **the gating payment cannot also be the on-chain royalty payment.** x402 settles a USDC transfer to an EOA on Base (eip155:8453); Story's Royalty Module needs `payRoyaltyOnBehalf(ipId, amount, token)` — a *contract call*, denominated in *WIP*, on *eip155:1514* — and no x402 facilitator supports chain 1514. Four independent mismatches (wrong chain, wrong token, wrong primitive, wrong EIP-3009 variant — `transferWithAuthorization` vs `receiveWithAuthorization`), each fatal on its own (`report.md` §4.1; ADR-0005). So: **two legs, always.**

### The collar

The collar is the one piece you build and the one piece everyone must trust. It is, simultaneously:

- **The sole Anthropic API-key holder.** This is forced, not chosen. There is no native "no credential, no run" gate on CMA, OpenAI, or Google; CMA's only mid-run control (`permission_policy: always_ask`) is a tool-approval gate keyed to the key-holder and cannot stop a turn from starting or spending tokens. Anthropic keys are workspace-scoped (full / read-only only), so you cannot mint a Wielder a key that permits `sessions.create` but forbids `GET /v1/agents`. The collar must therefore be the only key-holder and the entire gate (`report.md` §3 step 4; ADR-0003). **A direct economic consequence: the collar pays Anthropic for every run** — see [who bears the inference cost](#who-bears-the-inference-cost) in Economic Design.
- **The x402 resource server.** It issues the `402`, verifies and settles the payment, and treats the settled txHash as the execution credential (Leg 1).
- **The off-chain meter / ledger.** It accrues each settled invocation into an auditable ledger, then drives the batched Story settlement (Leg 2).

Because the collar is the sole key-holder and never proxies `GET /v1/agents`, the **Skill stays hidden from the Wielder (not from the host)** — the session output stream never carries the system prompt or skill bodies, only the output (ADR-0001; `report.md` §3 step 2). The Skill is **not** hidden from Anthropic, which processes it in plaintext (no TEE); that is an accepted v1 trust boundary, not a solved problem (ADR-0004; CONTEXT.md lines 98–101).

### Leg 1 — synchronous gate (Base, sub-second)

The per-invocation gate. Trust-minimized: no payment, no run, enforced on every call.

1. Wielder requests an invocation; collar returns **`HTTP 402` + `PAYMENT-REQUIRED`**.
2. Wielder signs **EIP-3009 `transferWithAuthorization`** (gasless USDC on Base, bytes32 nonce).
3. Collar calls the facilitator's **`/verify`** then **`/settle`**; gets back **`PAYMENT-RESPONSE {success, txHash, networkId}`**.
4. The settled **`txHash` is the single-use, replay-proof execution credential**, checked **off-chain** by the collar. Do **not** mint a per-call on-chain Story License Token — each mint drags an IP→WIP wrap + ERC-20 approve + block latency for a credential gating a call worth cents (`report.md` §3 step 3c; ADR-0005).

**Critical ordering: settle first, then run async.** The collar settles the payment (sub-second), releases the credential, and *then* invokes the agent asynchronously and streams the output. It must **never hold the x402 handshake open across the agent run** — x402's `maxTimeoutSeconds` is ~60s, shorter than a cold `sessions.create` plus the agent loop (ADR-0005; `report.md` Phase 1). The collar owns its own nonce/txHash bookkeeping; x402 does **not** safely resubmit after a settled-but-failed run, so accept-payment-but-fail-to-run is handled by the collar via refund / reputation, not by the protocol (`report.md` §3 step 3a). **Because x402/USDC payments are irreversible and have no chargebacks, a failed run after settled payment is a refund the collar must fund out of treasury** — see the reliability/refund target in [Team, Capital, Timeline & Kill-Criteria](#team-capital-timeline--kill-criteria).

### Leg 2 — asynchronous settlement (Story, batched, eventually-consistent) — **Phase 2, deferred**

The royalty path. This is where "the fork pays its ancestors" actually happens — **in accounting terms, credited and claimable on demand, not as one atomic on-chain action per invocation** (ADR-0002 Update; CONTEXT.md line 49). **This entire leg is Phase-2 work and is NOT in v1**; in v1 (Phase 1) royalties are credited and withdrawn against the off-chain ledger only.

An off-chain **settlement worker**:

1. Accrues each settled payment into the auditable ledger and **batches** by threshold/interval. Batching is mandatory: stacked per-hop fees (facilitator $0.001/tx after 1k/mo + Base gas + bridge fee + USDC→WIP swap slippage + Story gas + claim gas) can each exceed a cents-level micro-royalty (`report.md` §4.2; ADR-0005).
2. **Bridges/swaps USDC(Base) → WIP(Story)** via a licensed bridge (e.g. Stargate / Across / deBridge). WIP is the only mainnet-whitelisted royalty currency, and it is volatile and illiquid ($IP down ~97.5% from ATH), so fold the conversion into the bridge and fast-claim to limit FX exposure (`report.md` §4.1, risk register; ADR-0002 Update).
3. Calls **`payRoyaltyOnBehalf(ipId, amount, token)`** on Story's Royalty Module.
4. Runs a **permissionless keeper that auto-claims `claimAllRevenue`** for ancestors. Flow-through on Story is **PULL, not PUSH** — ancestors accrue a claimable balance and must claim it, or (e.g.) the school's revenue silently piles up. The keeper claims on their behalf (`report.md` §3 step 5; ADR-0002 Update; ADR-0005).
5. **Publishes the settlement batch on-chain** for reconciliation.

A bridge stall leaves "execution done, ancestor unpaid" — a reconciliation surface handled by the auditable ledger plus retry, with conservative batching windows (ADR-0005 Consequences). **The real USDC(Base)→WIP(Story) bridge cost and confirmation time are unmeasured** (`report.md` §7.4) and must be spiked before Phase 2.

### Story objects (the on-chain primitives)

All four are real, live, and audited on Story Protocol (chainId 1514, SDK v1.4.4); this is the soundest part of the design (`report.md` §3 step 1, §2):

- **IP Asset** — each registered Skill, created via `mintAndRegisterIpAssetWithPilTerms`. One real on-chain tx (Phase 0 ships this immediately).
- **PIL terms** — the license, via `PILFlavor.commercialRemix()`. Forks register as **declared Derivatives** with on-chain ancestry.
- **Fractional, co-holdable royalty tokens** — 100 per IP vault (1% granularity floor). Co-holdable by employee + employer (intra-org) or student + school (education) (ADR-0002; CONTEXT.md lines 41–42).
- **Flow-through** — **LAP** (Liquid Absolute Percentage, whole-ancestry) or **LRP** (Liquid Relative Percentage, direct-parents). Composable up the Derivative graph (`report.md` §3 step 5).

### Trust model

Two halves, with different guarantees — and being honest about the seam between them is the point (ADR-0003 Update; `report.md` §4.3):

- **The gate (Leg 1) stays trust-minimized.** No credential, no run, enforced per call. Usage fraud on the money path is structurally impossible at the gate.
- **Settlement (Leg 2) degrades to an auditable accumulator.** The off-chain batched meter that decides which invocations settle *is* the trusted oracle ADR-0003 originally rejected. The "fraud structurally impossible" guarantee held only for the synchronous, single-chain, atomic case that the cross-chain gap forces us to abandon. The collar could in principle mis-report or skim. Mitigations: signed, auditable invocation logs; on-chain published settlement batches for reconciliation; refund + reputation for accept-but-fail; **TEE tabled as the eventual structural fix**, not a v1 feature (ADR-0003 Update; ADR-0004).

This trust re-centralization is the price of the cross-chain reality. The collar is sole key-holder + in-flight custodian + off-chain meter — and the custody is itself the worst regulatory exposure (likely FinCEN MSB), so v1 minimizes it: keep the collar a non-custodial pass-through riding a hosted facilitator (Coinbase x402, which carries its own KYT/OFAC/licensing) and push in-flight value to a licensed bridge partner — look like a merchant on Stripe, not a money transmitter (`report.md` §4.3, risk register; ADR-0006). The full analysis is in [Regulatory & Compliance Strategy](#regulatory--compliance-strategy).

### What is v1 vs. deferred

| Capability | Phase | Status in v1 |
|---|---|---|
| Register Skills as Story IP Assets + declared Derivatives (provenance) | **Phase 0** | **v1** — ships immediately, soundest step |
| Collar as sole key-holder + x402 resource server; Leg 1 gate; off-chain metered ledger; closed modes (intra-org → education); claims **non-transferable** | **Phase 1** | **v1** |
| On-chain batched royalty settlement (Leg 2: bridge/swap → `payRoyaltyOnBehalf` → keeper `claimAllRevenue`) | **Phase 2** | **Deferred** to Phase 2 (the shared-loop "claim" is an off-chain-ledger withdrawal in v1) |
| TEE / confidential execution (hide Skill from host; structural fix for the accumulator) | later | **Deferred — tabled** |
| Open Marketplace + **tradeable** royalty claims (securities: ERC-3643 allow-list + Reg D 506(c)/Reg A+/CF + registered ATS like Securitize + transfer agent + KYC) | **Phase 3** | **Deferred** — counsel-gated; closed-mode claims stay non-transferable |

The derivative-royalty **mechanic** is available throughout; only the **tradeability** of a claim triggers the securities stack (ADR-0006). Chain split is permanent: **Story for IP / royalty / provenance, Base for the x402 gate.** Do not try to make x402 settle directly to Story (`report.md` §6; ADR-0005).

### End-to-end sequence (education mode; steps 7–12 are Phase-2-deferred)

1. **Register (Phase 0, Story).** School registers its base Skill as an IP Asset (`mintAndRegisterIpAssetWithPilTerms` + `commercialRemix`). Student forks it into a **Derivative** they own — a declared derivative with on-chain ancestry (ADR-0002; CONTEXT.md line 42).
2. **Host (Phase 1).** Collar holds the only Anthropic key; the Derivative lives on the persisted Agent object; the employer can invoke it but cannot read it.
3. **Gate — 402 (Phase 1).** Employer requests an Invocation; collar returns `402` + `PAYMENT-REQUIRED`.
4. **Pay (Phase 1, Leg 1, Base).** Employer signs EIP-3009 `transferWithAuthorization` (gasless USDC on Base).
5. **Settle + credential (Phase 1).** Collar runs `/verify` + `/settle`; the settled **txHash is the single-use execution credential**, checked off-chain.
6. **Run async (Phase 1).** Collar releases the handshake, then invokes the agent asynchronously and **streams only the output** to the employer — never the Skill, never holding the 402 open across the run.
7. **Meter (Phase 1).** Collar records the settled invocation in the auditable off-chain ledger (the accumulator); the split is **credited**, withdrawable off-chain.
8. **Batch (Phase 2).** Settlement worker batches accrued payments per threshold/interval.
9. **Bridge/swap (Phase 2).** USDC(Base) → WIP(Story) via the licensed bridge.
10. **Pay royalties on Story (Phase 2).** Worker calls `payRoyaltyOnBehalf` for the Derivative's IP vault; flow-through (LAP/LRP) credits the school as ancestor.
11. **Keeper claims (Phase 2).** Permissionless keeper calls `claimAllRevenue` for the student and the school.
12. **Publish (Phase 2).** Settlement batch is published on-chain for reconciliation.

Steps 3–7 are synchronous-gate + off-chain meter (Phase 1, v1). Steps 8–12 are asynchronous, batched, eventually-consistent on-chain settlement (Phase 2). That gap is the whole honesty of the v1 design.

### Component list

- **Collar** — sole Anthropic API-key holder; x402 resource server; off-chain meter/ledger; the entire execution gate and the single trusted component. Pays Anthropic per run.
- **x402 facilitator** (Coinbase CDP or equivalent) — `/verify` + `/settle` for Leg-1 USDC-on-Base payments; carries its own KYT/OFAC/licensing.
- **Managed agent runtime** (Anthropic CMA, beta; runtime abstracted so it is swappable) — Wielder-hidden hosted execution; returns output only. Not ZDR/HIPAA-eligible — use a self-hosted sandbox for regulated intra-org/education data.
- **Off-chain ledger** — signed, auditable invocation log; source of truth for batching and reconciliation.
- **Settlement worker (Phase 2)** — batches accrued payments; drives the bridge/swap and `payRoyaltyOnBehalf`.
- **Licensed bridge/swap (Phase 2)** (e.g. Stargate / Across / deBridge) — USDC(Base) → WIP(Story); absorbs in-flight custody to keep the collar a pass-through.
- **Permissionless keeper (Phase 2)** — auto-claims `claimAllRevenue` for ancestors.
- **Story Protocol contracts** — IP Asset registry, PIL/License module, Royalty Module (LAP/LRP), fractional co-holdable royalty tokens.
- **(Phase 3 only) Securities stack** — ERC-3643 allow-list token, registered ATS, transfer agent, KYC — required only when royalty claims become tradeable.

---

## Economic Design

The protocol moves real money on every **Invocation**, so the economics decide whether the loop is viable at all. The settlement topology is fixed by the feasibility verdict: a **decoupled two-leg flow** (ADR-0005). Leg 1 gates execution with x402 USDC on Base; Leg 2 (Phase 2) batches, bridges/swaps to WIP, and settles royalties on Story. Every parameter below is shaped by that topology and by one hard fact: **per-invocation on-chain settlement is fee-dominated, so batching is mandatory and a price floor is non-negotiable.**

The prototype at `prototype/settlement-engine.mjs` is the reference implementation of the split arithmetic; the numbers here are derived from it and from the per-hop fee schedule in `docs/feasibility/findings.json`. **Several inputs are unmeasured (`report.md` §7.4) — the models below are illustrative, not validated.**

### Who bears the inference cost

This is a load-bearing economic fact that must be stated plainly: **the collar is the sole Anthropic API-key holder, so the collar — not the Wielder — pays Anthropic for every run.** CMA runtime billing is **$0.08 per *active* session-hour, measured to the millisecond** (idle/rescheduling free), **plus standard per-token model costs (ITPM/OTPM) on top** (`findings.json` `/validated[managed-agents]/howItWorks` (c), `/evidence` note: "~$0.027 for a 20-min active run + tokens"). A short invocation's runtime cost is small, but the **per-token model cost is the dominant and variable COGS**, and for a verbose Skill it can be non-trivial relative to a $2–25 price.

The unit economics therefore have **three distinct cost layers the Wielder's USDC must cover**, in order:

```
Wielder USDC price  ≥  inference COGS (CMA runtime + model tokens, paid by collar to Anthropic)
                     +  settlement cost (Leg-1 facilitator/gas; Leg-2 bridge/swap/gas, amortized)
                     +  protocol fee (the 2.5% feeBps skim)
                     +  net royalty to Creator + ancestors
```

The 2.5% protocol fee is computed **on the price**; the inference cost is a **separate COGS the collar funds** and is *not* covered by the fee. **If a Skill is verbose and cheap, the collar can lose money on the run even while the fee looks healthy** — the fee is a percentage of price, but inference is a near-fixed dollar cost per call. The collar must therefore either (a) meter and pass through inference cost as a line item on top of the Creator's price, or (b) enforce a price floor high enough that inference COGS + settlement + fee + royalty all clear. **v1 recommendation: pass inference COGS through transparently** (Wielder pays price + metered inference), so the collar never eats inference and the Creator's price is purely "value of the Skill." The exact pass-through model is an open economic spike (the per-token cost is a function of the Skill's verbosity, which the Creator controls). Until it is modeled against real Skill token profiles, **the business unit economics are undefined** — see [Team, Capital, Timeline & Kill-Criteria](#team-capital-timeline--kill-criteria).

### Pricing: creator-set, above an enforced floor

Price is **set by the Creator** per Skill (`registerSkill({ price })`), denominated in USDC (the Leg-1 currency the Wielder actually pays). Creators know their Skill's value; the protocol does not.

But the Creator cannot price arbitrarily low, because every Invocation carries a **stack of per-hop fees** that does not shrink with price:

| Leg | Cost component | Incidence |
|---|---|---|
| Leg 1 (Base) | CDP facilitator fee ($0.001/tx after 1k/mo free tier) + Base settle gas | **per invocation** (unavoidable) |
| Leg 2 (Story, Phase 2) | bridge fee + USDC→WIP swap slippage (~0.5%) + Story gas + `claimAllRevenue` gas | **per batch** (amortizable) |

Source for the fee components: `findings.json` `/verdict/risks[5]`, `/composition/gaps[6]`. **The $0.001/tx facilitator fee and ~0.5% swap slippage are sourced; the real USDC→WIP bridge cost and confirmation time on Story mainnet are UNMEASURED (`report.md` §7.4).**

> **Illustrative model (inputs partially unmeasured).** Assuming an avg $5 invocation and slippage at 0.5% of batch notional, the amortized Leg-2 settlement cost per invocation falls as batch size grows:

| Batch size N | Leg-2 cost amortized / inv | Total settlement cost / inv |
|---|---|---|
| 1 (no batching) | $0.3650 | **$0.368** |
| 10 | $0.0590 | $0.062 |
| 100 | $0.0284 | $0.031 |
| 1000 | $0.0253 | $0.028 |

> This table is a **model built on partially-unmeasured inputs** (real bridge cost/latency is unspiked, `report.md` §7.4) — treat the numbers as directional, not as committed figures.

**Two conclusions:**

1. **Batching is structural, not an optimization.** At N=1 the per-hop fees would consume a cents-level micro-royalty entirely — negative unit economics. Only per-batch Leg-2 costs amortize; the Leg-1 facilitator fee is the irreducible floor. This is *why* ADR-0005 batches Leg 2.
2. **The price floor is the amortized settlement cost, marked up.** With aggressive batching the *settlement* floor sits near the low-cents range per invocation in the model above; **but the binding floor in practice is inference COGS** (see above), which a sub-dollar Skill cannot clear. **Single, coherent policy on the floor (resolving the prior contradiction):**
   - **Sub-floor Skills (priced below the live amortized settlement + inference floor) are accepted but stay in the Phase-1 off-chain-metered ledger** — credited and withdrawable off-chain — and are **not** promoted to on-chain Leg-2 settlement until aggregation pulls their effective cost under the floor. They are not rejected.
   - **Skills priced above the floor settle on-chain in Phase 2.**
   This replaces the earlier muddle ("reject sub-floor" vs. "sub-dollar lives off-chain") with one rule: **below the floor → off-chain ledger; above the floor → on-chain settlement.** A `$2–3` figure was cited previously as a "soft floor"; that number was an artifact of the illustrative table and is **not** a validated threshold — the real floor is computed live from measured inference COGS + amortized settlement cost, once spiked.

This floor compounds with the cloning economics (ADR-0004): price *below amortized clone cost* but *above amortized (settlement + inference) cost*. That window is the viable pricing band — **but "amortized clone cost" is itself unmeasured** (no source quantifies clone-distill economics or required evolution cadence, `report.md` §7.7), so "price below amortized clone cost" is a *direction*, not yet an actionable number. See [the clone-cost gap](#what-we-have-not-validated).

### Protocol fee

A flat **protocol fee in basis points, skimmed off the top before any royalty split** (`feeBps`, default **250 = 2.5%** in the engine). It is taken from the gross Invocation price into the treasury; the **net** flows down the ancestry:

```
fee = price × feeBps/10000        → treasury
net = price − fee                 → distributed to royalty holders + ancestors
```

2.5% is the prototype's default, not a benchmarked rate. It is *lower* than typical app-store take rates (Apple/Google 15–30%) and near card-processing rates (Stripe ~3%), which signals "infrastructure, not rent-extractor" — but **we have not shown that 2.5% covers protocol opex at closed-mode volumes.** Critically, the protocol fee is computed on *price* and does **not** cover the collar's inference COGS (which is passed through separately, above). At low volumes, 2.5% of a handful of $2–25 invocations may be a **floor that fails to cover opex, not a ceiling to negotiate down from.** The honest stance: **treat 2.5% as a starting default to validate against real opex, not a positioned competitive rate.** The prototype lets you crank it (`fee 4000`) to probe where the model feels extractive; the answer is that every basis point of fee competes with the royalty and the settlement floor for the same net. Whether 2.5% is sustainable is a Phase-1 unit-economics question, not a settled benchmark.

### Derivative flow-through and the inherit-bps fork-incentive threshold

A **Derivative** carries an `inheritBps` — the fraction of its *net* (post-fee) revenue that flows **up** to its parent(s) on every Invocation, recursing through the whole ancestry (`distribute()` in the engine; mirrors Story's LAP/LRP on-chain). The forker keeps `net × (1 − inheritBps)`; the ancestry collectively gets `net × inheritBps`.

The question the prototype was built to answer (`prototype/README.md` experiment 5) is the **fork-killing threshold**: at what ancestor cut does forking stop being worth it? **This is an OPEN question. The prototype's verdict is explicitly TBD** (`prototype/README.md` NOTES), and the report (§7) and the Phase-1 roadmap spike both list it as unresolved. The following is a **hypothesis to test, not a settled answer.**

> **Hypothesis (to validate against the engine and real fork behavior).** A first-pass model *suggests* a candidate neutral point at **`i* = p_parent / p_fork`** — the ancestor's price as a share of the fork's price — **under a "recoup-own-uplift" assumption.** The reasoning: a forker adds uplift `U = p_fork − p_parent`; flow-through taxes `inheritBps` of the *whole* fork price including the forker's own added value; the forker recoups exactly their own uplift when `net × (1 − i) = U × (1 − fee)`, which solves to `i* = 1 − U/p_fork = p_parent / p_fork`.

**The "recoup-own-uplift" premise is one defensible modeling choice, not a derived truth, and it is asserted rather than justified.** It deliberately **ignores** at least three things a real forker weighs: (1) the forker's **ongoing maintenance cost**, (2) the **option value of the parent's live evolution** (a benefit of *not* hiding ancestry), and (3) **demand elasticity** (whether the fork's price even holds at volume). A sophisticated reader should treat `i* = p_parent/p_fork` as a starting hypothesis whose only honest status today is "to be tested in `prototype/` experiment 5 and against observed fork rates." It is **not** a "clean, defensible answer."

Directionally, the model implies: below `i*`, forking is attractive and ancestors still earn; well above it, the rational move is to author fresh and never declare the parent — incentivizing the ancestry-hiding the graph exists to capture. Worked from the seed (`finmod` $5 → `biofin` $25), the hypothesis would put the neutral point at `i* = 5/25 = 2000 bps`. **The engine's seeded default fork `inheritBps` is 3000 (30%) — above that hypothesized neutral point. 30% is a fine *teaching seed* but should NOT be read as the recommended protocol default**; the GTM metrics track 3000 only because it is the prototype default to measure against, not because it is endorsed.

**Practical stance until the spike resolves:** rather than ship a flat protocol constant, **anchor the suggested `inheritBps` at the price-ratio hypothesis and let the Creator tune it with a live "student keeps vs. flows up" preview at fork time.** Guardrails: floor the suggestion at Story's 1% granularity (`findings.json` `/verdict/confirmed[4]`); flag anything well above the price ratio as "may discourage forking." The default is *not finalized* — the Phase-1 spike sets it.

**Deep chains compound the danger.** `inheritBps` applies at *every* hop, so a uniform rate `i` leaves the root creator `i^depth` of net:

| Depth | i=30% | i=50% | i=70% |
|---|---|---|---|
| 1 | 30.0% | 50.0% | 70.0% |
| 2 | 9.0% | 25.0% | 49.0% |
| 3 | 2.7% | 12.5% | 34.3% |

At 30% inherit, the original Creator three forks deep gets **2.7% — dust** (prototype experiment 4). **There is no single rate fair at every depth** — an inherent tension of multiplicative flow-through, and the strongest argument for a per-fork, price-ratio-anchored, *tunable* default rather than a flat constant. For Education, bias the school's base-Skill terms toward the higher end of the band, accepting that deep re-forks dilute the school's cut — the correct incentive (rewarding active improvement over rent on a stale base). **All of this is provisional pending the Phase-1 economics spike.**

### Co-held splits (employee/employer, student/school)

A **Royalty claim is co-holdable**: the engine models it as `royalty: [{partyId, bps}]` summing to 10000; on-chain this is Story's 100 fractional royalty tokens distributed across wallets (1% granularity, `findings.json` `/verdict/confirmed[4]`). This replaces work-for-hire's 100/0:

- **Intra-org** (`recon`): employee-Creator and employer co-hold, e.g. **50/50** (`sam` 5000 / `megacorp` 5000). Both earn from every *external* Invocation. The prototype's experiment 7 probes "where's the split an employer would actually sign." There is no protocol-mandated ratio; it is a *negotiated* term. A reasonable seed is 50/50.
- **Education** (`finmod` → `biofin`): the student owns their **Derivative outright** (`mia` 100% of `biofin`'s own claim), and the school earns as the **ancestor via flow-through**, not as a co-holder of the student's claim. The student "graduates with the asset"; the school's return rides the `inheritBps` on the base Skill.

**Critical constraint binding economics to the legal design (ADR-0006):** in Intra-org and Education, **co-held and forked claims must be NON-TRANSFERABLE.** Non-transferability is the **best available route** to keeping them outside securities treatment (structured as contractual / deferred-comp / license-fee rights, `findings.json` `/verdict/confirmed[7]`) — **but at medium confidence, not as a guaranteed safe harbor** (see Regulatory). The split *mechanics* are identical to the tradeable case; only transferability differs.

### WIP/FX exposure and mitigation

Royalties settle on Story in **WIP ($IP), the only mainnet-whitelisted royalty currency** — down ~97.5% from ATH and thinly liquid (`findings.json`, ADR-0002 Update). This injects FX/liquidity risk into the *settlement* leg even though the Wielder paid stable USDC:

- **The conversion happens inside Leg 2.** The USDC→WIP swap is folded into the bridge step, so the **Wielder and Beneficiary never touch WIP** — they pay USDC. An enterprise forced into involuntary $IP exposure is a dead deal.
- **The exposure window is between accrual and claim**, borne by the royalty holder whose WIP balance swings with $IP price.
- **Mitigation = fast-claim + hedge.** Run the keeper to `claimAllRevenue` promptly; convert claimed WIP back to USDC/stable on a tight cadence; for larger ancestors (a school), consider hedging. Size the batching window to balance fee amortization (wants larger batches) against FX exposure (wants faster settlement) — the same tension that sets the price floor.

### No native protocol token in v1

**Recommendation: do NOT introduce a native protocol token in v1.** The protocol already has the assets it needs, and they are better than a fresh token:

- **Unit of account is USDC** (what Wielders pay) — stable, liquid, what enterprises transact in.
- **The royalty/ownership asset is Story's native IP-Asset royalty tokens** — co-holdable, fractional, with built-in derivative flow-through. A protocol token would duplicate this with something strictly worse.
- **Settlement value is WIP**, already an FX headache to minimize — a second volatile native asset multiplies the FX surface for zero benefit.

A native token would add securities burden (a freely-traded value-accruing token is a textbook Howey security — the exact trap ADR-0006 routes around), bootstrapping burden (liquidity, market-making, distribution), and fills **no mechanism gap** (fee capture works as a USDC skim; Story provides chain security; Base provides the gate). **The moat is the marketplace, provenance graph, and declared-derivative royalties (ADR-0004) — not a token.** If a protocol-level incentive asset is ever warranted, it belongs no earlier than the open Marketplace phase, evaluated then.

### Deferred to Phase 3

All economics of a **tradeable royalty-claim secondary market** — price discovery, AMM vs. order-book, liquidity incentives — are **out of scope for v1** and deferred to Phase 3 (ADR-0006), where they arrive *permissioned*: ERC-3643 allow-list, Reg D 506(c)/Reg A+/CF exemption, SEC-registered ATS (e.g. Securitize) + transfer agent + KYC. Until then, claims are non-transferable and the only money that moves is per-Invocation USDC. Engage securities counsel before designing that market.

---

## Regulatory & Compliance Strategy

The regulatory verdict is **works-with-caveats at *medium* confidence: no fatal blocker, but the headline feature is the heaviest constraint, and no source squarely analyzes our exact fact pattern.** Two distinct regimes apply and must be analyzed separately — **securities law** (the tradeable royalty claim) and **money-transmission/AML** (the x402 settlement collar) — each with a different trigger and mitigation. The most important framing: **the derivative-royalty *mechanic* is fine; only the *tradeability* of a claim, and only *custody* of in-flight funds, trigger the expensive regimes** — and both are avoidable in the closed modes. **Because regulatory confidence is only medium, treat every "outside securities law" statement below as the best available route, not a settled safe harbor, and get counsel to bless the specific structures BEFORE Phase 1 ships.**

### Securities posture — the heaviest weight, but mode-dependent

A **tradeable, fractional royalty claim is almost certainly a security** under *SEC v. W.J. Howey*: (1) investment of money, (2) a common enterprise (a pooled, fractionalized claim on a revenue stream the platform and Creator operate), (3) an expectation of profit, (4) **from the essential efforts of others** — the Creator who maintains/evolves the Skill and the platform that hosts, meters, and settles. The Ninth Circuit's *SEC v. Barry* (2025) is on point: fractional interests in a cash-flow stream were securities *because* investors depended on a manager's ongoing efforts ([Skadden, "Howey's Still Here," Aug 2025](https://www.skadden.com/insights/publications/2025/08/howeys-still-here)). **Uncomfortable corollary: ADR-0004's live-evolution/network-moat thesis — the core competitive strategy — *strengthens* the "efforts of others" prong, not weakens it.**

The 2026 SEC thaw does **not** rescue these tokens. The March 17, 2026 crypto interpretation carves out only Digital Commodities, Digital Collectibles, and Digital Tools (non-transferable membership/credential/ticket), and states that "all devices and instruments that have the economic characteristics of a security are securities regardless of format or label" ([WilmerHale, Mar 2026](https://www.wilmerhale.com/en/insights/client-alerts/20260324-the-secs-new-framework-for-crypto-assets-under-howey)). A transferable token whose purpose is to pay holders a share of recurring revenue fits none of the three buckets. Putting the claim on Story does not change the analysis (Jan 2026 Corp Fin statement: "the technological format … does not alter its legal characterization"). Two cautions: the March interpretation is *non-binding staff guidance*, rescindable without APA rulemaking; and a globally-traded claim is a MiFID II "financial instrument" in the EU, triggering the Prospectus Regulation, licensed intermediaries, and MAR/CSDR.

**The best available route outside securities treatment is non-transferability — but it is not a guaranteed safe harbor, and the confidence is medium.** Be precise about what it does and does not buy you: non-transferability **defeats the secondary-market / "investment" narrative** (no resale, no liquidity event, no speculative buyer). It does **not**, on its own, defeat the **"efforts of others" prong**, which is satisfied by the platform's ongoing metering and evolution regardless of whether the claim can be transferred. The plausible — but **not certain** — conclusion is that a non-transferable, purely contractual revenue right, with no resale and structured as deferred comp / a license fee, sits outside securities treatment. **No regulatory source squarely analyzes the per-invocation, agent-to-agent collar fact pattern**, so this is an extrapolation. Counsel must bless the specific deferred-comp / license-fee structure **before Phase 1 ships** — this is a gate, not mere overhead.

- **Intra-org:** structure the employee+employer co-hold as **non-transferable deferred-compensation / contractual rights.** **But deferred comp is itself heavily regulated:** a co-held royalty claim that pays out over time implicates **IRC §409A** (deferred-compensation rules) and **constructive-receipt** doctrine — i.e., when the employee is taxed, and whether the structure triggers 409A penalties. The PRD's earlier "like deferred comp" framing is correct in spirit but understates that deferred comp is a regulated structure of its own. Counsel must address 409A / constructive receipt for the employee, not just Howey.
- **Education:** structure the student's Derivative-owned claim and the school flow-through as **non-transferable contractual license/royalty splits.** It becomes a security the *moment* those claims are tradeable — so do not make them tradeable in v1.

### Money-transmission / MSB — custody is the dividing line

The payment leg is **manageable, but the design of the collar is determinative.** Exposure turns entirely on **custody**:

- **Non-custodial pass-through riding a hosted facilitator** (Coinbase's x402 facilitator, carrying its own KYT/OFAC/state+federal licensing) → the platform looks like a **merchant using Stripe/PayPal, not a money transmitter, "absent unusual facts"** ([Braumiller/Mondaq, Dec 2025](https://www.braumillerlaw.com/activating-http-402-the-x402-protocol-and-legal-framework-for-internet-native-stablecoin-payments/)). This is the target posture.
- **Custodial collar** — omnibus wallets, fiat↔crypto conversion, or routing third-party payments as a business → "almost certainly" **money transmission requiring FinCEN MSB registration + multi-state money-transmitter licenses + a BSA/AML program** (12–24 months, multi-hundred-thousand-dollar).

The sharpest tension in the design: **the cross-chain two-leg settlement (ADR-0005) forces *someone* to hold value in-flight** (USDC on Base before WIP on Story), and in-flight holding is the exact MSB fact pattern. Mitigations, in order: (1) minimize custody — settle splits via smart contract / facilitator / issuer; (2) push unavoidable in-flight value to a **licensed bridge / facilitator / BaaS partner**; (3) keep the collar a non-custodial pass-through so the merchant-on-Stripe analogy holds. One clean adjacency: the **execution credential** is a *non-financial access token*, adding no money-transmission exposure **as long as it is never tradeable or redeemable for value** — which the design intends.

**Honest caveat (this is why confidence is medium):** no regulatory source squarely analyzes the per-invocation, agent-to-agent collar fact pattern; the merchant-vs-MSB conclusion is extrapolated from custody doctrine. A custodial collar *would* block launch; a non-custodial collar on a licensed facilitator is **manageable overhead**. Get counsel to bless the specific architecture before Phase 2 moves real money.

### KYC/AML and the GENIUS Act allocation

KYC/AML enters through **two doors**:

**Payment side — obligations fall on issuers, not merchants.** The GENIUS Act (enacted July 18, 2025; ~3-year transition to ~July 2028) regulates **payment-stablecoin *issuers***; AML/BSA/CIP/SAR/sanctions obligations land on the **issuer** (and any MSB-classified intermediary) — **not on a payer/payee for merely using a compliant stablecoin like USDC** ([Paul Hastings GENIUS Act guide](https://www.paulhastings.com/insights/crypto-policy-tracker/the-genius-act-a-comprehensive-guide-to-us-stablecoin-regulation)). The FinCEN proposed AML/CFT & sanctions rule (Fed. Reg., Apr 10, 2026) likewise targets *issuers* (exact covered-persons wording not directly verified — treat as such). **Net: a non-custodial collar pushes nearly all payment-side KYC/AML onto Coinbase and the issuer** — the single biggest reason the payment leg is not a blocker.

**Securities side — KYC re-enters because the claims are securities.** Once you reach tradeable claims: Reg D 506(c) requires accredited-investor verification; a transfer agent must hold each holder's real-world name and address (a wallet alone is insufficient); any registered ATS/broker-dealer runs full BSA/AML/CIP. The mechanism is an **allow-list token (ERC-3643 / BlackRock BUIDL model)**: a transfer cannot execute unless the recipient is pre-KYC'd and whitelisted ([Skadden, "Tokenized Securities," Apr 2026](https://www.skadden.com/insights/publications/2026/04/tokenized-securities)). This is why **tradeable claims are *permissioned*, never permissionless.**

### Phased compliance path

| Phase | What ships | Securities | MSB/AML | Launch gate? |
|---|---|---|---|---|
| **0 — Provenance** | Register Skills as IP Assets + Derivatives | None (no claim sold) | None (no money moves) | **No** — ships immediately |
| **1 — Intra-org → Education** | Gate + run + off-chain ledger; claims **non-transferable** | **Best route outside securities law (medium confidence)** — counsel must bless deferred-comp / license-fee structure incl. 409A **before launch** | Non-custodial collar on hosted facilitator → merchant-not-MSB | **Yes (soft):** counsel sign-off on the structure is a gate, not just overhead |
| **2 — On-chain batched settlement** | Two-leg USDC(Base)→WIP(Story), keeper auto-claim | Still non-transferable | **The real custody decision** — push in-flight value to a licensed partner; counsel blesses | Custody design is the gate |
| **3 — Open Marketplace + tradeable claims** | Permissioned tradeable claims | **Full securities stack** | Securities-side BSA/AML via ATS/broker-dealer | **Yes — securities counsel before this phase, non-negotiable** |

For **Phase 3**, the stack is well-trodden ([Skadden roundups](https://www.skadden.com/insights/publications/2026/04/tokenized-securities)): issuance via Reg D 506(c) (accredited, ERC-3643/BUIDL allow-list) or Reg A+ (up to $75M/yr, retail, ATS-tradeable) or Reg CF; secondary trading **only on an SEC-registered ATS** (e.g. Securitize, FINRA-approved May 2026) + a transfer agent. Reg S can reach non-US holders but has flowback problems; tokenization removes neither holding periods nor accredited-investor requirements.

### Bottom line for the build decision

**Nothing in the regulatory analysis hard-blocks Phases 0–1, but Phase 1 has a soft gate: counsel must bless the non-transferable deferred-comp / license-fee structure (including 409A) before it ships.** Both expensive regimes are *opt-in* — securities law via tradeability, MSB law via custody — and the recommended path defers both. The single hard gate is **Phase 3**, which requires the full permissioned securities stack and counsel engaged *before* you build it. The strategic implication aligns with the rest of the document: **build and launch the closed modes first** — they are where cloning pressure is lowest, incentives most aligned, and the law lets you move fastest, *provided counsel signs off on the closed-mode claim structure first.*

---

## Competitive Landscape & Moat

### Where we sit

We are not competing with the chains we build on. The Skill Asset Protocol is an **application layer** composing existing primitives — Story for IP/royalty/provenance, Base for the x402 gate, Anthropic Managed Agents (CMA) for **Wielder-hidden hosted execution** (hidden from the Wielder, not from the host) — into one product aimed at **monetizing the long-term value of authored Skills**. Nobody else assembles exactly this stack, but several projects occupy adjacent territory, and the closest threats are the platforms we build *on* adding the layer we supply.

| Project | What it does | Where we differ / the threat |
|---|---|---|
| **Story Protocol** (chainId 1514) | On-chain IP registry: IP Assets, PIL terms, co-holdable fractional royalty tokens, declared-derivative flow-through. | We **build on it** — Story is the ledger of *who owns what and who owes whom*; it has no execution gate, no Wielder-hidden runtime, no per-invocation meter. **Threat (platform-disintermediation):** Story could ship its own monetization/hosting/licensing UX and absorb the metering+gate layer we add. The platform our entire IP/royalty layer depends on is also the most capable disintermediator. Our hedge is the gate + collar + Skill-specific product and closed-mode GTM, none of which Story does today — but this is a real strategic dependency, not a moat. |
| **Agent-payment incumbents** (Skyfire, Payman, Nevermined/Catena, Coinbase's own x402 tooling) | Per-call/agent-to-agent payment rails, metering, and (some) settlement for AI agents. | These are the **nearest adjacents that could bolt royalty + provenance onto an existing rail.** Coinbase already owns the x402 facilitator we depend on; Skyfire/Payman/Nevermined already do agent metering and could add a Story-style royalty graph. **Honest defensibility:** every primitive is open, so the defensible thing is the *assembly* + the *closed-mode wedge* + the accumulated provenance/derivative graph — not a technical monopoly. We must out-execute on the Skill-specific product and lock in the graph before an incumbent generalizes into it. |
| **Virtuals Protocol** | Launchpad/marketplace for tokenized *autonomous agents* — bonding-curve speculation. | We tokenize the **royalty stream of an authored Skill**, not a speculative agent token. Our unit is a metered Invocation-right for human-directed work, settled per use — not a coin priced on sentiment. |
| **Olas / Autonolas** | Registry + staking for composable *autonomous agent services*. | Olas rewards agents for *running services autonomously*; we reward a **Creator each time a human Wielder invokes their Skill**, with declared-derivative flow-through. Different value event. |
| **Bittensor** | Incentive market for *machine intelligence*: subnets pay miners in TAO for scored model outputs. | Bittensor pays for *inference quality* in a competitive subnet; we pay the **author of a specific reusable Skill artifact** with provenance and a derivative graph. No shared base model, no peer-scoring. |
| **Sahara AI** | Provenance + revenue-share marketplace for AI *data and model assets*. | Closest in spirit, but the asset class is **data/models**, not executable authored Skills, and there is no hidden hosted *execution* gate — value flows from selling/licensing the asset, not metering each Wielder-hidden invocation. |
| **Managed-agent platforms** (Anthropic CMA, OpenAI, Google) | Host agents/Skills server-side; the Wielder gets the output, not the Skill. CMA keeps the Skill off the session-output stream — **hidden from the Wielder, not from the host** (the host processes it in plaintext; `GET /v1/agents` echoes it to the key-holder). | **Infrastructure we consume, not competitors.** None ships a native "no credential, no run" gate, a per-invocation meter, or a royalty/provenance layer (the gate is 100% our collar). We add the economic and ownership layer they omit. |

### The combination we ship

No single project combines all four — and the combination, not any one piece, is the product:

1. **Wielder-hidden hosted execution** — the Wielder receives only the output, never the Skill (ADR-0001, validated against CMA). *Hidden from the Wielder, not from the host* — the host (Anthropic) sees it in plaintext (ADR-0004).
2. **Per-invocation metering** with a payment-gated execution credential (x402 on Base; "no credential, no run").
3. **On-chain composable royalty** with declared-derivative flow-through (Story), co-holdable for the intra-org and education modes.
4. Focused specifically on **authored Skills as a monetizable asset class**, launched **closed-modes-first**.

That is a genuinely novel assembly. It is **not** a defensible *technical* monopoly — every primitive is open and reusable, and the two nearest threats (Story itself; agent-payment incumbents) could each generalize into it. The defensibility argument is therefore narrower than the pitch-deck version.

### The honest moat analysis

**The moat defends the marketplace, not a breakout Skill** (ADR-0004). Provenance (the Story IP Asset), the derivative-royalty graph, reputation/routing, and live evolution are real and compounding — but what they protect is the *network*: liquidity, trustworthy attribution, the fork-and-royalty ecosystem, routing of invocations to proven Creators. They do **not** protect an individual high-value Skill from being reconstructed.

**Off-platform behavioral cloning is when-not-if, not a risk to be "solved."** ADR-0001 hands the Wielder the output, and for most Skills the output *is* the value. A high-volume Skill is the *cheapest* thing to clone — its own paid I/O pairs are a ~30x-cheaper distillation set — and v1 (no TEE; host sees plaintext) cannot prevent this, only out-evolve it. Watermarking is a forensic tripwire removed by cheap paraphrase, not a moat (OWASP LLM07:2025: the system prompt is not a security control). The defense is **economic and operational**: price below amortized clone cost, ship live updates faster than distill-and-redeploy, and bind value to things an output stream cannot carry — live tool/data access and fresh private context. **Honest caveat: the efficacy of live-evolution as an anti-clone defense is *asserted by analogy and unmeasured* (`report.md` §7.7) — no source quantifies how fast a Skill must change to keep a clone stale.** Provenance gives clones the status of *orphans* (no lineage, no marketplace trust, no derivative royalties), protecting the marketplace's integrity even when it cannot protect a single asset.

**Launching closed modes first is itself a moat-timing advantage.** Intra-org and education are closed populations with aligned incentives, on-platform by construction, lowest cloning pressure (ADR-0006). Starting there is both the regulatory-safe path and a strategic sequencing of where the moat is weakest vs. strongest — and it buys time to *measure* the unmeasured live-evolution and clone-cost assumptions before facing the open market where cloning is cheapest.

**What we are not claiming.** Not that a Skill is unclonable, that watermarking deters, that the host cannot see the Skill, or that the royalty graph can be open and permissionlessly tradeable without becoming a regulated securities venue. The defensible position: a focused, novel *assembly* of real primitives; a *marketplace*-level network moat that compounds with provenance and liquidity; a sequencing discipline that meets cloning pressure where it is weakest first — held against the live risk that a platform we depend on, or an agent-payment incumbent, generalizes into the same assembly.

---

## Go-to-Market & Rollout

> **The wedge is Intra-org — as an assumption to validate, not an established market.** Lead with a company converting its internal Skills into co-owned revenue assets. Education is the second motion, seeded *inside* the intra-org beachhead. **The willingness of employers to co-hold royalty claims is UNVALIDATED (R12, Medium-High); securing design-partner LOIs is an explicit Phase-0/1 gate, not a backdrop.**

### Why Intra-org wins the wedge (and Education does not, yet)

Both closed modes are the right *place* to start — closed populations, aligned incentives, on-platform, lowest cloning pressure, and claims structurable as **non-transferable** rights that are the best route outside securities law (ADR-0006; report §6). The question is which closed mode is the sharpest *initial* wedge. Intra-org wins on five counts:

1. **One signature unlocks the whole loop.** Intra-org has a single decision-maker (the employer) who is simultaneously the **Beneficiary** (funds settlement), the **co-holder** of the claim, and the employer of the **Creator**. Education needs three independent parties (school, student, a different employer) — a three-sided cold start.
2. **The pain is acute, named, and on the buyer's desk.** From the employer's side, "why won't my best people leave the moment they've built the automation?" is a live 2026 retention problem. Intra-org reframes work-for-hire's 100/0 as a co-held claim where the employee keeps upside from *external* invocations.
3. **It exercises the riskiest machinery without the riskiest exposure.** External invocations force you to build and harden the real gate + meter + Leg-1 settlement (ADR-0005) — with claims non-transferable, so no securities stack. You stress the hard parts inside the safest regulatory envelope.
4. **Lower cloning pressure, by construction.** Intra-org Skills bind value to *fresh private context and live internal tool/data access* — exactly the recommended anti-clone posture (ADR-0004; report §5).
5. **It is the natural distribution channel for Education.** Land the employer, prove the co-held claim pays, and the *same* employer becomes the Beneficiary in an Education deal.

**Decision: ship Intra-org first. Education is Phase-1b, sold into the same accounts.** Both rest on the unvalidated willingness-to-co-hold assumption (R12).

### Ideal first customer profile (an assumption to test)

A **mid-size, AI-forward services or product firm (roughly 100–800 people) where authored Skills are the work product, internal mobility/retention is a board-level concern, and at least one team already ships Claude Code skills/plugins/agents internally.** **This profile and the firm-size band are a hypothesis, not validated market structure — there is no evidence yet that such firms will restructure work-for-hire IP terms (R12).** Concretely:

- **Buyer:** VP Eng / Head of Platform co-sponsored by Head of People/Talent; CFO is a stakeholder.
- **Pre-conditions that de-risk the build:** already an Anthropic API customer (CMA is beta, 300 create-req/min/org, not ZDR/HIPAA — non-regulated data first); comfortable funding settlement; willing to start with **non-transferable** co-held claims.
- **Avoid (for now):** regulated-data shops (CMA gap), Fortune-500 procurement, anyone needing tradeable claims day one, and firms whose Skills are static prompt cleverness (the most cloneable category, ADR-0004).
- **Validation gate:** signed design-partner LOIs confirming willingness-to-co-hold **before** committing to the Phase-1 build (see kill-criteria).

### Distribution and pricing/packaging

**Distribution — land via provenance, expand via the meter.** Phase 0 (Provenance) is a no-commitment top of funnel: any team can register Skills as Story IP Assets with declared ancestry today, for free, getting a tamper-proof provenance graph regardless of how settlement evolves. Expansion happens when a registered Skill takes external Invocations and the co-held claim begins paying.

**Packaging — three priced layers mapped to the phases:**

| Layer | What the customer gets | Phase | Monetization |
|---|---|---|---|
| **Provenance** | Register Skills + Derivatives on Story; on-chain ancestry; the moat substrate | 0 | Free / per-registration at-cost |
| **Gated runtime + meter** | Collar as sole key-holder; x402 gate (Leg 1); off-chain auditable ledger; co-held **non-transferable** claims; output-only to Wielders; **inference COGS passed through** | 1 | **Protocol take-rate per Invocation** (prototype default ~2.5%) **+ inference cost pass-through** |
| **On-chain settlement** | Batched Leg-2 USDC(Base)→WIP(Story) + keeper auto-claim; published batches | 2 | Same take-rate; settlement-ops/bridge cost passed through |

**Pricing guardrails dictated by the architecture** (full unit economics in [Economic Design](#economic-design)):

- **Per-Invocation price must sit above amortized (settlement + inference) cost.** Batching is mandatory; the collar pays Anthropic per run, so inference COGS is passed through. There is a live computed floor (real bridge cost unmeasured, `report.md` §7.4).
- **Per-Invocation price must also sit *below* amortized clone cost** — *but that figure is unmeasured* (`report.md` §7.7), so this is a direction, not a number.
- **Take-rate, not seat licensing**, computed on price; **inference is a separate pass-through, not covered by the take-rate.**
- **Quote and settle in USDC; never ask the buyer to touch $IP** — fold USDC→WIP into the bridge and fast-claim.

### Phase-to-GTM mapping (ADR-0006)

| ADR-0006 phase | GTM motion | Goal |
|---|---|---|
| **Phase 0 — Provenance** | Self-serve, free, viral. "Register your Skills, own your lineage." | Build the derivative graph; top-of-funnel; provenance as trust default. |
| **Phase 1 — Intra-org, then Education** | Founder-led design-partner sales to 3–5 ICP accounts **(target; none signed yet — R12)**. Co-held **non-transferable** claims; gate + run + off-chain meter. Education sold into the same accounts once intra-org pays. | Prove the loop pays Creators from external invocations; harden the collar inside the safest regulatory envelope. |
| **Phase 2 — On-chain batched settlement** | Expand within proven accounts. Turn the off-chain accumulator into on-chain settled, published batches; ride a licensed facilitator/bridge (merchant-on-Stripe). | Make settlement auditable; de-risk MSB exposure. |
| **Phase 3 — Open Marketplace + tradeable claims** | Permissioned launch, counsel-gated. ERC-3643 + Reg D 506(c)/Reg A+/CF + registered ATS + transfer agent + KYC. | Open the composable royalty market only when warranted — highest-cloning, full-securities surface, shipped last. |

The headline "open composable royalty graph" is the **last** thing shipped (ADR-0006). GTM sequences by *safety*, not ambition.

### Activation and retention metrics

Instrument register → fork → invoke → settle → claim, and track both sides of every co-held claim.

**Activation:** Skills registered (Phase-0 funnel); first external Invocation of a co-held Skill (true activation); time-to-first-royalty-credited; credential issuance rate (settled txHash → run, confirming "no credential, no run").

**Engagement / graph:** Invocations per Skill per week, external-vs-internal mix; Derivative forks per base Skill and ancestry depth; **realized inherit-bps vs. fork rate** — if forks collapse as inherit-bps rises you have found the (currently TBD) fork-killing threshold and should cap it. (Track the prototype default 3000 only as the *measurement baseline*, not an endorsed rate.)

**Monetization / settlement health:** royalties paid (Leg-2 settled, Phase 2) vs. royalties credited (off-chain ledger) — **the gap is the eventual-consistency lag and a tracked reconciliation surface, not a hidden detail** (R14); royalties claimed via keeper (unclaimed ancestor balance is an operational alarm); settlement-batch reconciliation rate; **per-invocation contribution margin = price − inference COGS − settlement cost − royalty** (the metric that tells you whether 2.5% + pass-through actually covers opex); protocol take-rate revenue per account.

**Retention:** earning Creators (non-zero credited claim in period); Beneficiary net revenue retention; co-held claim survival (both parties earning at 90/180 days); refund / failed-run rate (accept-payment-but-fail-to-run; keep near zero or reputation erodes — and each is a treasury-funded refund since x402 has no chargebacks).

---

## Team, Capital, Timeline & Kill-Criteria

This section gives the founder/investor-grade numbers the rest of the document implies. **The estimates are planning figures, not commitments; they assume a small senior team and are bounded by the unmeasured items in [What we have NOT validated](#what-we-have-not-validated).**

### Team & capital, per phase

| Phase | Core build | Indicative eng-effort | Non-eng spend | What this phase needs funded |
|---|---|---|---|---|
| **0 — Provenance** | Story registration + Derivative declaration + ancestry viewer | ~1–2 eng · ~1–2 months | Story gas (negligible) | A small pre-seed slice; ships on a 2-person team. The cheapest, soundest step. |
| **1 — Gate + run + off-chain meter** (Intra-org → Education) | Collar (sole key-holder, x402 resource server, off-chain signed ledger), pay-first-then-async orchestration, refund path, self-hosted sandbox option | ~2–4 eng · ~3–6 months | **Securities counsel for the non-transferable deferred-comp / 409A structure (a gate)**; design-partner sales | Seed round. The dominant *recurring* cost once live is **Anthropic inference COGS** (collar pays per run) + counsel. |
| **2 — On-chain batched settlement** | Settlement worker, bridge/swap integration, permissionless keeper, reconciliation, fast-claim/hedge | ~2–4 eng · ~3–5 months | MSB/custody counsel; licensed bridge/BaaS partner contracts | Seed-to-A. Custody design is the regulatory gate. |
| **3 — Open Marketplace + tradeable claims** | ERC-3643 allow-list, ATS integration (e.g. Securitize), transfer-agent + KYC wiring, routing/reputation | ~3–6 eng · ~6–9 months | **Securities counsel + exemption filing + ATS/transfer-agent fees (substantial)** | Series A+, and only when closed-mode traction warrants it. |

**Skills profile:** a backend/protocol engineer (x402 + Story + bridge), an applied-AI engineer (CMA orchestration, anti-extraction wrapper), a product/design hire for the provenance and claim UX, and **early access to securities + money-transmission counsel** (the two non-negotiable advisory lines). Treat counsel as a line item from Phase 1, not Phase 3.

### Reliability / refund targets

- **Failed-run-after-settled-payment rate < 0.5%** of paid invocations, with **automatic treasury-funded refund within one settlement cycle** (x402 is irreversible and has no chargebacks, so the collar funds every refund).
- **Gate leak rate (runs without a valid single-use credential) = 0** — a hard invariant, not a target.
- **Credited→on-chain-settled lag (Phase 2)** disclosed to customers and held under a published SLA window; unclaimed ancestor balance alarmed.

### Kill-criteria (falsifiable go/no-go)

Stop or restructure if any of these fire — investors should hold us to them:

1. **No design-partner LOI to co-hold within the Phase-0 window.** If, after the free Provenance funnel runs, **no ICP employer will sign an LOI to co-hold a royalty claim** (restructuring work-for-hire), the Intra-org wedge is invalidated (R12) — do not build Phase 1 on spec.
2. **Cold-start latency makes pay-first-then-async unusable.** If measured `sessions.create` → first-token latency (currently unmeasured, `report.md` §7.3) is so high or variable that the async UX is unacceptable and no pooling fix exists, the gate UX premise fails.
3. **Inference COGS exceeds defensible price.** If, against real Skill token profiles, **inference COGS + settlement cost routinely exceeds what Beneficiaries will pay** (i.e., contribution margin is negative at viable prices), the unit economics do not close.
4. **A breakout closed-mode Skill is cloned within weeks of launch with no economic counter.** If a high-value Skill is behaviorally cloned faster than live-evolution can stay ahead — and the unmeasured evolution-cadence defense (`report.md` §7.7) proves ineffective — even the closed-mode value prop is at risk; re-underwrite before Marketplace.
5. **Counsel cannot bless the non-transferable closed-mode structure.** If securities/409A counsel concludes the closed-mode claim is *not* outside securities treatment (medium-confidence today), the whole "launch closed first" sequencing must be reworked.
6. **Story / $IP existential degradation.** If Story sunsets or $IP liquidity collapses below a usable settlement threshold and no mitigation lands (see R15), the on-chain layer must be re-platformed or the protocol re-scoped.

---

## Risks & Open Questions

The feasibility study (`docs/feasibility/report.md`, `docs/feasibility/findings.json`) returns **GO-WITH-CAVEATS**: every primitive is real and live, but the idealized atomic loop does not compose, and the buildable version reshapes the risk surface. The single most important framing: **the closed modes dodge or defang most high-severity risks** — cloning pressure lowest, claims non-transferable (best route outside securities law, *medium confidence*), population bounded.

### Risk register

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **R1** | **Off-platform behavioral cloning** of a breakout Skill. ADR-0001 hands the Wielder the *output*; thousands of paid I/O pairs are a ~30×-cheaper distillation set. The moat defends the *marketplace*, not an individual Skill. | **High** (when-not-if for any breakout earner) | **High** — undermines the value prop at success; v1 (no TEE) cannot prevent it, only out-evolve it | Manage economically: live evolution (ship faster than distill-and-redeploy); bind value to live tool/data access + fresh context; price below amortized clone cost; anomaly detection; watermark/provenance as forensic backstop. **Caveat: evolution-cadence efficacy is unmeasured (§7.7).** Launch closed modes first. |
| **R2** | **MSB / money-transmitter classification.** The two-leg design makes the collar hold funds in-flight — the FinCEN MSB fact pattern. | **Medium-high** | **High** — 12–24mo, multi-$100K slog gating launch | Minimize/eliminate custody; non-custodial pass-through on a hosted facilitator; push in-flight value to a licensed bridge/BaaS partner; **counsel blesses the specific architecture** (no source squarely analyzes it). |
| **R3** | **Securities classification.** Tradeable royalty claims are securities under Howey; ADR-0004's moat *strengthens* the efforts-of-others prong; the March 2026 SEC interpretation does not carve out revenue-share tokens. | **High** (near-certain for tradeable) | **High for Marketplace; LOW / likely-outside-securities for intra-org/education if non-transferable — but MEDIUM confidence, NOT zero.** Non-transferability defeats the secondary-market/investment narrative, but the efforts-of-others prong is still satisfied by ongoing platform metering/evolution; **counsel sign-off required before Phase 1.** **Sub-risk: 409A / deferred-comp / constructive-receipt** for the employee's co-held claim. | Permissioned stack for Marketplace (ERC-3643 + Reg D/A+/CF + ATS + transfer agent + KYC). Keep closed-mode claims non-transferable; structure as deferred-comp/license-fee **with 409A addressed**; engage counsel before Phase 1, not just Phase 3. |
| **R4** | **Bridge-stall reconciliation** (Phase 2): execution done on Base, ancestors unpaid on Story. | **Medium** | **Medium** — eventually-consistent + reconciliation overhead; not loss-of-funds with sound bookkeeping | Auditable off-chain ledger; on-chain published batches; retry/reconciliation; refund/reputation; conservative batching windows. |
| **R5** | **Trusted-accumulator degradation.** ADR-0003's "fraud structurally impossible" degrades to "auditable accumulator" once batched + cross-chain; the collar could skim/mis-report at settlement. | **High** (structural) | **Medium** — gate stays trust-minimized; settlement trust reintroduced | Explicit in ADR-0003; signed/auditable logs; on-chain batch publication; refund/reputation; TEE as eventual fix. |
| **R6** | **Negative fee economics.** Stacked per-invocation fees can exceed a cents-level micro-royalty. | **High** at literal per-call; **low** once batched | **Medium** — forces batching + price floor | Mandatory batching; price above amortized settlement + inference cost. |
| **R7** | **$IP / WIP volatility + thin liquidity** ($IP ~−97.5% from ATH); WIP-only royalty currency forces involuntary $IP exposure on payers. | **High** (current market) | **Medium** — FX risk + enterprise friction | Fast-claim; hedge; fold USDC→WIP into the bridge; build a fiat/USDC→WIP on-ramp; monitor for USDC whitelisting (Spike 3). |
| **R8** | **Verbatim prompt extraction** via agentic steering. | **Medium** | **Medium** — leaks text, but ADR-0004 abandons secrecy as load-bearing | Taxonomy-aware wrapper cuts extraction ~18% (never eliminates); the moats, not secrecy. Accept residual per ADR-0004. |
| **R9** | **CMA beta churn**; not ZDR/HIPAA-eligible for regulated data. | **Medium** | **Medium** — integration rework; compliance gap | Abstract the runtime behind the collar (swappable host); self-hosted sandbox for regulated data; track release notes. |
| **R10** | **Rate-limit ceiling** (300 create-req/min/org). | **Low** (not a v1 blocker at low volume) | **Low-medium** at scale | Reuse long-lived sessions, queue, or shard. **Unverified:** clean buyer isolation in one long-lived session (Spike 6). |
| **R11** | **Recency risk in load-bearing facts** (a facilitator could add Story 1514; fees/whitelist/License-Token semantics could change). | **Low-medium** | **Low-medium** — could simplify (good) or invalidate (bad) | Re-verify all load-bearing facts immediately before building (Spikes). |

#### Product / market / adoption risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| **R12** | **No-pain-felt adoption / willingness-to-co-hold UNVALIDATED.** Asking an employer to co-hold a royalty claim instead of work-for-hire is a hard sell with no template, and the upside is *external* invocations that may not materialize. | **Medium-high** | **High** — without willing first employers, the recommended wedge has no demand side | Lead with the retention/incentive narrative, not a rights grab. **Validate with design-partner LOIs before building Phase 1 (a kill-criterion).** Education offers a more concrete exchange as the second motion. |
| **R13** | **Wrong-side marketplace cold start** — the open Marketplace needs Creators + Wielders + claim buyers at once, thinnest moat, full securities stack. | **Medium-high** for the open marketplace | **Medium** — a failed marketplace does not kill the closed modes | Sequence it last; bootstrap provenance value first (Phase 0). |
| **R14** | **Value-prop dilution from "eventually consistent."** The buildable reality (credited per invocation, claimable on demand, batched, FX-exposed) is weaker than "automatically pays ancestors every invocation"; sophisticated buyers notice the credited-vs-settled gap. | **Medium** | **Medium** — credibility erosion if oversold | Correct the language (done: "automatically credited, claimable on demand"); **surface the gap as a tracked reconciliation metric, do not hide it**; ship the keeper so ancestor revenue never silently piles up. |
| **R15** | **Single-host + single-IP-chain dependency.** The gate is the collar on CMA; all IP/royalty/provenance is on Story (thin, illiquid). **Story could also disintermediate by adding the monetization/hosting layer itself** (see Competitive Landscape). | **Low-medium** | **High** if it triggers | Keep the runtime swappable behind the collar; treat Story as the IP layer and Base as the gate (do not couple). **Concrete fallback to develop, not just "monitor":** provenance/ancestry is the most portable artifact — design the registration layer so the declared-derivative graph can be mirrored/exported to a more liquid chain or an off-chain notarization if Story sunsets or $IP liquidity collapses; settlement (WIP) is the hardest-coupled piece and would need re-platforming. Track Story health + $IP liquidity against the R15 kill-criterion. |
| **R16** | **Co-authorship unmodeled.** v1 assumes a single Creator at origin; multi-author Skills (CONTEXT.md line 46, flagged open) are unhandled. | **Medium** (likely in Marketplace) | **Medium** — disputes / unclear split for jointly-built Skills | Single-Creator origin in v1; multi-author teams use the co-hold mechanic as a stopgap; design true multi-Creator origin before Marketplace. |

### Pre-build re-verification spikes

Run **immediately before committing engineering.** The first four are the priority set (verdict, report §4.3 / §7).

1. **Benchmark cold `sessions.create` → first-token latency** (unmeasured, §7.3). Sizes the SLA and confirms pay-first-then-async (almost certainly required: x402 `maxTimeoutSeconds` ~60s < a managed-agent run). *Output: latency distribution the async design must absorb.* **Also feeds kill-criterion 2.**
2. **Confirm no x402 facilitator has added Story 1514** ([x402.org/ecosystem](https://www.x402.org/ecosystem)). *Output: confirm two-leg is still mandatory.*
3. **Confirm the CDP fee schedule + Story's WIP-only royalty whitelist** ([Story royalty docs](https://docs.story.foundation/concepts/royalty-module/overview)). USDC whitelisting would remove the swap leg and defang R7. *Output: confirmed unit-economics inputs.*
4. **Decide the credential primitive.** Confirm the x402 settled `txHash` suffices as the off-chain credential and that a Story License Token is *not* needed per call (uneconomic at per-call cadence). *Output: a decision.*

Secondary spikes (resolve before the relevant phase):

5. **Inference-COGS / price model** — model per-invocation Anthropic cost (CMA $0.08/active session-hour + per-token ITPM/OTPM) against real Skill token profiles to set the pass-through model and confirm contribution margin (feeds kill-criterion 3). *Currently undefined.*
6. **Leg-2 economics on real Story mainnet** — exact USDC(Base)→WIP(Story) bridge cost + confirmation time vs. generic quotes (Phase 2; §7.4).
7. **Long-lived-session isolation across buyers** — whether one CMA session cleanly isolates distinct buyers; likely one-session-per-buyer, reintroducing the ceiling (R10; §7.5).
8. **Fork-killing threshold (economics)** — run the `prototype/` engine (experiments 4–6) to **test** the `i* = p_parent/p_fork` *hypothesis*, find where forks collapse as inherit-bps rises, and where the fee feels extractive. **This spike exists precisely because the threshold is OPEN (TBD); it sets launch defaults — the closed form is a hypothesis to validate here, not a settled answer (see Economic Design).**
9. **`receiveWithAuthorization` on WIP / `RoyaltyModule.sol`** — contract-level read for any hypothetical direct-to-contract settlement (almost certainly absent; confirm).
10. **Live-evolution anti-clone efficacy** — load-bearing for the no-TEE defense; *asserted by analogy, unmeasured* (§7.7). No source quantifies required change cadence (R1; feeds kill-criterion 4).
11. **Off-platform Story enforcement** — real dispute/takedown outcomes for behavioral clones (on-chain provenance vs. off-chain courts) are undocumented (§7.8).
12. **Counsel sign-off on the collar architecture + closed-mode claim structure** — no regulatory source squarely analyzes the per-invocation agent-to-agent fact pattern; the MSB and the non-transferable-outside-Howey analyses are both extrapolated. **Get counsel to bless the architecture AND the deferred-comp/409A structure before launch** (R2, R3; feeds kill-criterion 5).

---

## What we have NOT validated

A single honest box, because the verdict is GO-**with-caveats** and several load-bearing facts could change the plan. **Regulatory is rated *medium* confidence overall; everything below is unmeasured or unverified as of mid-2026** (sourced to `report.md` §7 and `findings.json`).

- **Cold-start latency** (`sessions.create` → first token) — **unmeasured** (§7.3). Sizes the entire pay-first-then-async UX.
- **Real Leg-2 settlement cost & latency** (USDC(Base)→WIP(Story) bridge/swap on Story mainnet) — **unmeasured** (§7.4). The pricing-floor and batch-window models depend on it; the fee table in Economic Design is illustrative.
- **Inference unit economics** — the collar pays Anthropic per run; **no model yet ties Wielder price to inference COGS + settlement + fee + royalty.** Until spiked, **business unit economics are undefined.**
- **Live-evolution anti-clone efficacy** — **asserted by analogy, unmeasured** (§7.7). The load-bearing "price below amortized clone cost / out-evolve the clone" prescription rests on an unquantified assumption.
- **Off-platform clone enforcement** — real dispute/takedown outcomes for behavioral clones are **undocumented** (§7.8).
- **Long-lived-session buyer isolation** — **unverified** (§7.5); likely forces one-session-per-buyer, reintroducing the rate ceiling.
- **License Token as non-burned off-chain credential** — **unverified** (§7.1); treated as off-chain entitlement pending a spike.
- **Regulatory fact pattern** — **medium confidence; no source squarely analyzes the per-invocation agent-to-agent collar** (§7.2). Both the MSB merchant-not-transmitter posture and the non-transferable-outside-Howey conclusion are extrapolations counsel must bless.
- **Demand-side willingness-to-pay and willingness-to-co-hold** — **no LOI, no pilot, no pricing research** (R12). The only demand signal is x402 aggregate volume, which is agent-infra micropayments, not skill royalties.
- **Fork-killing threshold** — **OPEN / TBD** (`prototype/README.md`). The `i* = p_parent/p_fork` closed form is a hypothesis, not a result.
- **Co-authorship / multi-Creator origin** — **open design question** (CONTEXT.md line 46), unmodeled in v1.

Any of these could change the plan; the phased path is designed so the cheapest, soundest step (Provenance) ships first and the most-uncertain bets (Marketplace, tradeable claims) ship last, after these have been measured.

---

## Roadmap & Milestones

The build order is **safety-first, not ambition-first** (ADR-0006). Each phase ships a self-contained, defensible product, de-risks the next, and is gated by a small number of pre-build *spikes*. The atomic-payment, permissionless-trading, and hidden-from-host fantasies are out; everything below is the buildable loop (`report.md` §6).

**Two fixed chain decisions hold across all phases:** Story (chainId 1514, SDK v1.4.4) for IP, royalty, provenance; Base (8453) for the x402 gate. Do **not** make x402 settle directly onto Story — the two-leg split (ADR-0005) is permanent v1 architecture.

### The MVP (Phase 0 + a single-Skill slice of Phase 1)

The first shippable thing is **one intra-org Skill, registered for provenance, gated, run, and metered** — the thinnest vertical slice proving the core loop without touching anything regulated.

- **Provenance:** one Skill as a Story IP Asset (`mintAndRegisterIpAssetWithPilTerms` + `PILFlavor.commercialRemix()`), with at least one declared Derivative.
- **Gate + run:** collar as **sole Anthropic key-holder + x402 resource server**. `402` → EIP-3009 `transferWithAuthorization` (USDC on Base) → `/verify` + `/settle` → settled `txHash` **is** the single-use execution credential, checked **off-chain**. Settle first (sub-second), release credential, **then** run the agent asynchronously and stream only the output — never hold the x402 handshake across the run.
- **Meter:** an auditable off-chain ledger crediting each invocation's split (protocol fee → creator → flow-through), credited but **not** settled on-chain.
- **Claims non-transferable** — co-held employee/employer entitlement as a contractual/deferred-comp right (counsel-blessed structure).

**Why this slice:** it exercises payment-gating, Wielder-hidden execution, the derivative graph, and the recursive split while deferring the two hardest dependencies — on-chain cross-chain settlement and securities/custody law. **Skill content is hidden from the Wielder (the collar never proxies `GET /v1/agents`); the host (Anthropic) still sees it in plaintext, accepted per ADR-0004** — this is the correct, qualified framing the rest of the document follows.

### Phase 0 — Provenance (all-Story, ships immediately)

The soundest step, no broken seam. Register Skills as IP Assets; forks register as declared Derivatives with on-chain ancestry. Establishes the provenance/derivative-graph moat regardless of how settlement evolves; ships before any gating/payment code.

**Deliverables:** Skill → Story IP Asset registration; Derivative registration with declared ancestry (LAP/LRP per Skill); royalty-token vault per IP (100 tokens = 1%), co-holdable, minted **non-transferable** for closed modes; a read API/viewer over the ancestry graph.

**Success criteria:** a Skill + at least one multi-level Derivative chain registered on Story mainnet with verifiable ancestry; co-held tokens issued and queryable; registration cost/latency measured and acceptable.

**Spikes:** *None blocking* — Story registration is confirmed real and audited (§3 step 1). Optionally confirm the `PILFlavor` surface against SDK v1.4.4 before wiring. **GTM gate at this phase: secure at least one design-partner LOI to co-hold (kill-criterion 1) before committing Phase 1 build.**

### Phase 1 — Intra-org, then Education: gate + run + off-chain meter

Closed populations, lowest cloning pressure (ADR-0004 Update, ADR-0006). Claims **non-transferable** (best route outside the securities stack, *counsel-blessed*). Intra-org first; Education second.

**Deliverables:** collar service (sole key-holder, x402 resource server, off-chain credential bookkeeping); pay-first-then-run-async orchestration against CMA; auditable, **signed** off-chain invocation+settlement ledger; intra-org co-held accrual from *external* invocations; education fork-to-Derivative + flow-through-to-school crediting; self-hosted sandbox for regulated data; refund/reputation path for accept-payment-but-fail-to-run; **inference-COGS pass-through metering.**

**Success criteria:** no run without a valid single-use replay-proof credential; both intra-org co-holders earn from an external invocation; an education chain credits student-Derivative and school-ancestor correctly; signed, independently auditable ledger, no credential double-spend; usable p50/p95 latency; **positive per-invocation contribution margin after inference COGS** at design-partner prices.

**Spikes (each must pass before main build):** cold-start latency (§7.3); inference-COGS/price model (Spike 5); session isolation across buyers (§7.5); credential semantics (§7.1); **fork-killing threshold — run `prototype/` to *test* the `i* = p_parent/p_fork` hypothesis and pick launch defaults (it is OPEN, not solved).** **Legal gate: counsel sign-off on the non-transferable deferred-comp / 409A structure before launch.**

### Phase 2 — On-chain batched royalty settlement (ADR-0005 Leg 2)

Turn the off-chain accumulator into on-chain truth — **closed modes only.** Custody enters here, so engineer to *minimize* custody from day one.

**Deliverables:** async settlement worker (batches per threshold/interval); bridge/swap pipeline USDC(Base)→WIP(Story) via a licensed partner; `payRoyaltyOnBehalf` + **permissionless keeper** auto-claiming `claimAllRevenue` for ancestors; on-chain published batches; reconciliation for bridge stalls; fast-claim/hedge logic; collar as **non-custodial pass-through** on a hosted facilitator.

**Success criteria:** a batch settles on-chain to correct ancestors with zero unexplained drift vs. the signed ledger; keeper claims reliably with no manual intervention; per-invocation amortized settlement cost below the price floor; a simulated bridge stall is detected and reconciled without losing funds.

**Spikes:** Leg-2 economics on real Story mainnet (§7.4); re-verify recency-sensitive facts (§4.3); **MSB/custody legal read — counsel blesses the non-custodial pass-through before any in-flight value moves.**

### Phase 3 — Open Marketplace + tradeable claims (only when warranted, permissioned)

The headline "open composable royalty graph" ships **last** — thinnest moat, highest cloning incentive, full securities stack (ADR-0006). Enter only when closed-mode traction and live-evolution/live-data moats justify the open market.

**Deliverables:** tradeable Royalty claim as a **permissioned** security (ERC-3643 allow-list); an exemption path (Reg D 506(c) / Reg A+/CF); secondary trading only on a registered ATS (e.g. Securitize) + transfer agent + KYC; marketplace routing/reputation; economic anti-clone tooling (price-below-clone-cost guidance, live-evolution cadence, value-binding to live tool/data access).

**Success criteria:** a claim trades on a registered ATS between KYC'd, allow-listed parties with transfer-agent records; routing demonstrably favors provenance-verified originals over clones; no regulated activity outside the permissioned rails.

**Spikes / gates:** **engage securities counsel before this phase (hard gate);** off-platform clone-defense efficacy (§7.7, unmeasured — quantify before betting the Marketplace on it); off-platform enforcement reality (§7.8).

### Cross-phase tabled item

**TEE / confidential execution** remains tabled (ADR-0003, ADR-0004) as the eventual structural fix for both host-side secrecy and run-without-charging. Not on any phase's critical path; revisit for high-value Skills once the closed modes prove the model.
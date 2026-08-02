# Reframe & Pi-Wielder Spike — Design

*2026-07-11. Validated in a brainstorming session following an adversarial premise
review (11 agents: 6 readers over the full corpus, 4 premise critics, 1 memory
search). All four critics returned "shaky, not broken" and converged on the same
prescription. This document is the change spec for the doc reframe and the design
for the first Wielder-side spike.*

## 1. The verdict that drives this design

The premise review found the corpus honest but inverted: the PRD's **weakest
claims are the open-marketplace royalty story it leads with**, and its
**strongest asset is the part it treats as a stepping stone** — the off-chain
metered ledger plus co-held, non-transferable claims.

Objections that survived steelmanning:

1. **Success is self-defeating in the open market** — a breakout Skill's paid
   I/O pairs are a ~30x-cheaper distillation set (ADR-0004's own concession);
   the addressable middle (too dynamic to distill, not valuable enough to
   SaaS-ify) is unsized and may be empty.
2. **Claude Code skills are context-bound; hosting strips most of their value.**
3. **"When Sam quits" is undesigned** — no vesting/clawback/termination anywhere.
4. **Education mode has a free bypass** — provenance cannot distinguish "forked
   the school's Skill" from "re-authored using what the class taught," which is
   nearly free and pays the school nothing.
5. **The likeliest killer is dismissed, not analyzed** — a platform-native skill
   marketplace (Anthropic/OpenAI/GitHub). No kill-criterion covers it; the GPT
   Store precedent appears nowhere in the corpus.

What survives: the closed-mode kernel **reframed as a compensation/attribution
instrument** (the employer already possesses the Skill, so clone-resistance is
irrelevant there); neutral cross-platform provenance; the gate/settlement
engineering itself.

## 2. The reframe (decision)

**The product is a compensation, attribution, and metering layer for authored
AI Skills — "Carta for AI work artifacts" — not a skill marketplace.**

- **Phase 1 is the terminal state by design.** The off-chain signed ledger +
  co-held non-transferable claims + Story provenance must be independently
  viable if Phases 2–3 never ship. On-chain settlement and tradeability are
  explicitly underwritten optionality.
- Real-world precedent replaces the marketplace pitch: Germany's ArbEG statutory
  inventor remuneration, corporate patent-award programs, university
  tech-transfer revenue splits. Institutions demonstrably share invention
  upside with individuals; the missing piece is the metering rail.
- Platforms can ship a skill marketplace in a quarter; they will never ship
  409A-structured co-held compensation instruments. That asymmetry is the moat.

**The Wielder is a wallet, not a harness.** The Wielder-side protocol footprint
is exactly: *answer HTTP 402 with a signed USDC payment and retry.* No Story
SDK, no token custody, no chain reads client-side. The invocation-right is
exercised by paying, not held.

**Demand-side wedge: inference payments install the rail; skills ride it.**
BYO-wallet per-call payment for model APIs is live and growing (Router402,
tx402.ai, BlockRun ClawRouter; x402 at ~75M tx in the last 30 days as of
2026-07). The inference-payment leg is commoditizing — the differentiator is
the **unified meter**: one wallet whose ledger attributes inference calls AND
skill invocations, with royalty splits on the skill leg.

## 3. Document change spec

### 3.1 CONTEXT.md

- Rewrite the header paragraph: compensation/attribution protocol; the open
  Marketplace is one (future) mode, not the identity.
- **Wielder**: extend the definition — "any client that can pay: a wallet, not
  a specific harness. Claude Code, Pi, a cron job, and curl are all Wielders."
- **Add the missing term "Collar"** (used throughout the PRD, absent here):
  the sole platform-key holder, x402 resource server, and off-chain meter; the
  single trusted component.
- Update "Flagged ambiguities": mark the marketplace-vs-closed-mode identity
  question resolved (closed modes are the product); add "fraction of the skill
  supply that is host-compatible" as a new flagged unknown.
- Keep all existing role/relationship definitions otherwise intact.

### 3.2 docs/PRD.md

Rewrite the spine; preserve the honest tone, citations, and the
"What we have NOT validated" discipline (extend it, never delete it).

1. **Executive Summary**: lead with the compensation/attribution layer and
   "Phase 1 is the terminal state by design"; marketplace becomes underwritten
   optionality; add the demand-side wedge in one paragraph.
2. **Problem & Market**: add a *demand-side wedge* subsection (BYO-wallet
   inference payments as the rail; the Pi spike named as its validation
   experiment); add the **GPT Store precedent** (platforms do ship native
   skill-adjacent marketplaces; builder monetization demand was weak even with
   free distribution); add a **skill-depreciation subsection** (skill half-life
   vs. model release cadence; segment model-absorbable vs. live-access-bound).
3. **Product & UX**: education mode demoted — deferred pending a re-run
   fork-economics spike whose alternative branch is "re-author with class
   knowledge ≈ free"; note the school-claim restructure options (living
   school-maintained content, or direct school→employer licensing).
4. **Technical Architecture**: rename "trust-minimized" →
   **"Wielder-side trust-minimized"** everywhere; restate "gate-leak rate = 0"
   as an **ops SLO backed by a key-custody/rotation design**, not an
   architectural property; add the **beneficiary-verifiable meter** as a
   Phase-1 design requirement (Merkle-committed invocation log; root published
   with every Leg-2 batch so ancestors audit rather than trust); add a
   **committed TEE trigger** (any Skill exceeding a revenue threshold moves to
   confidential execution) replacing the thrice-tabled deferral.
5. **Economic Design**: note the unified meter across asset classes (inference
   pass-through and skill royalties are entries in the same ledger).
6. **Regulatory**: upgrade kill-criterion 5 from "counsel blesses" to
   "counsel **drafts the actual instrument**", resolving on-demand-withdrawal
   vs. 409A fixed-payment-events; add **vesting/clawback/termination ("when Sam
   quits")** as first-class design inputs for the co-held claim.
7. **Competitive Landscape**: reclassify managed-agent platforms from
   "infrastructure we consume, not competitors" to **"supplier AND likeliest
   disintermediator"**, with GPT Store as the base rate for platform timelines;
   add rows for **BlockRun ClawRouter** and **Router402/tx402.ai** (x402
   inference-payment incumbents; differentiation = the attribution/royalty
   meter, not payment).
8. **GTM**: intra-org pitch leads with compensation/retention, not royalty
   upside; education is a later motion.
9. **Kill-criteria**: add **#7 — platform-native skill marketplace announced**
   (Anthropic/OpenAI/GitHub), with a monitoring trigger and the stated
   counter-positioning (neutrality, cross-platform provenance,
   securities-barred mechanism, comp products platforms won't build).
10. **Risks**: add platform-native-marketplace and skill-depreciation risks;
    note inference-payment commoditization.
11. **Roadmap**: "Phase 1 terminal by design" stated; Phase 3 additionally
    gated on **compliance unit economics** (transfer-agent + ATS + KYC cost per
    claim vs. claim cash flow → a minimum-claim-size floor; if the floor
    excludes realistic claims, re-scope to pooled instruments or cut); add the
    **Pi-Wielder spike** to the spike list (thin-payer proof + measured x402
    payment-overhead latency).
12. **What we have NOT validated**: add — fraction of skill supply that is
    host-compatible; skill half-life; keep every existing item.

### 3.3 ADRs

- **Status headers on all six** existing ADRs (Accepted; note amendment dates).
- **ADR-0001 amendment**: absorb ADR-0004's concession explicitly — hosting
  preserves *artifact* scarcity, not *economic* scarcity; the invocation-right
  protects the file, the moats protect the economics.
- **New ADR-0007 — "The closed-mode compensation layer is the terminal
  product."** Decision, rationale (the four critiques), precedents (ArbEG,
  patent awards, tech transfer), consequences (marketplace = optionality;
  Phase-3 investment deferred until closed-mode traction).
- **New ADR-0008 — "The Wielder is a wallet, not a harness."** Thin-payer
  client decision; rejected alternatives (token-holding client, full protocol
  client); inference-as-wedge demand strategy; evidence (ClawRouter, Router402,
  x402 volume); consequence: validated by the Pi spike.

Cross-doc rule: PRD/ADR citations of "CONTEXT.md lines NN–NN" should be
converted to section references wherever a touched passage cites them.

## 4. Pi-Wielder spike (`spikes/pi-wielder/`)

**Goal**: prove "one wallet, two asset classes" end-to-end — Pi pays per-call
for model inference AND invokes one hosted Skill behind a mock collar, with a
unified attributed session ledger. Testnet-only; zero real money.

Components:

1. **Wallet** — viem `privateKeyToAccount`; Base Sepolia USDC (CDP faucet).
2. **Paying proxy** (~100 lines, Hono): OpenAI-compatible localhost endpoint;
   upstream fetch wrapped with `@x402/fetch` + `@x402/evm`. This proxy is the
   *entire* Wielder-side protocol footprint (proves ADR-0008 by construction).
3. **Mock collar** (Hono + x402 middleware, free facilitator
   `https://x402.org/facilitator`): 402-gates one hosted Skill (this repo's own
   `optimizing-claude-code-prompts`); settled txHash = single-use credential;
   runs the Skill via the Anthropic API; returns **output only**; credits the
   split into a signed ledger reusing `prototype/settlement-engine.mjs`
   `distribute()`.
4. **Mock inference gateway**: 402-gates OpenAI-compatible chat completions,
   proxying to real Anthropic/OpenAI APIs with local keys (no first-party API
   accepts x402; live gateways are mainnet-only resellers — we simulate one on
   testnet).
5. **Pi extension**: `registerProvider("x402", { baseUrl: proxy })`, an
   `invoke_skill` tool, and a session-ledger command
   (`claude/plan $… · gpt/implement $… · skill $… → creator split`).

**Modes**: `MOCK_FACILITATOR=1` for an offline end-to-end test (CI-able);
testnet mode against the real facilitator once the wallet is faucet-funded
(the only manual step).

**Demo scenario**: Claude plans, GPT implements, one skill invocation — one
wallet, three payees, unified ledger.

**Measurements to feed back into the PRD**: x402 payment overhead per call
(sign → verify → settle p50/p95), end-to-end skill-invocation latency,
ledger-split correctness against the prototype engine.

## 5. Execution order

1. This design doc, committed. ✅
2. Doc-reframe workflow: parallel writers (CONTEXT.md / PRD / ADRs) →
   adversarial checkers (stale-language sweep, cross-doc consistency,
   spec-faithfulness) → fixer. Commit.
3. Spike build (background agent), offline e2e green in mock mode. Commit.
4. Faucet-fund the test wallet (user) → run testnet demo → feed measurements
   into the PRD demand-side section.

Out of scope here (tracked from the review, still pending): funding the Aeneid
wallet and executing the Phase-0 write path; repairing and running
`spike-cma-latency.mjs`; the clone-economics spike; design-partner interviews.

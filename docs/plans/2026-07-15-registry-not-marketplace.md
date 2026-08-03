# Registry, not marketplace — protocol distribution strategy (2026-07-15)

*Consolidates a six-agent research sweep (five web/local researchers + one
synthesizer, adversarially cross-checked) run 2026-07-15 against the question:
"Can we build a crypto-enabled skills.sh? How do we distribute this as an
adoptable protocol like MCP/A2A?" All external facts are dated; re-verify
before publication — this space moves week to week.*

> **2026-07-17 accounting amendment:** The dated strategy below originally
> treated gross settled volume and payer-wallet counts as sufficient ranking
> signals. The implemented spike now uses the settlement-verifiable metric
> contract in this amendment. Settlement establishes that value moved; it does
> not establish independent demand, usefulness, authorship, originality, or
> safety. Where the dated research narrative conflicts with this amendment,
> this amendment controls public registry output.

## Verdict

The question splits in two, with opposite answers.

**Marketplace-as-product: no.** ADR-0007 (2026-07-11) decided this four days
ago: *"The product is a compensation, attribution, and metering layer for
authored AI Skills — 'Carta for AI work artifacts' — not a skill marketplace"*
(docs/adr/0007:41-42). All four steelmanned critiques that killed it bind a
crypto skills.sh specifically (0007:12-26): distillation self-defeat (a
breakout skill's paid I/O pairs are a ~30x-cheaper clone set; modeled
break-even 8 invocations *if* a clone ever passes fidelity gates —
spikes/clone-economics, N=6, not resolved), hosting strips context-bound
value, the free re-authoring bypass, and the platform-native marketplace
threat (KC7/R17; GPT Store base rate — and its second reading: builder
monetization was weak *even free*). Reopening ADR-0007 would require:
KC7 unfired, a specific answer to each critique, the Phase-3
compliance-arithmetic gate clearing (docs/PRD.md:780), and LOI-grade demand
evidence for open supply. None exists; the KC1 LOI itself is unsigned.

**Protocol distribution: yes — and ADR-0008 already did the hard part.** The
client footprint is "answer HTTP 402 and retry," so every harness is already a
compatible client (validated by construction: the pi live demo ran 2026-07-15,
8 paid calls, zero payment code in pi). The distribution play is the MCP
playbook applied to the Collar/ledger side.

**The version of the founder's idea that survives both:** a **settlement-gated
registry** — a thin index over the ledger + provenance graph Phases 0–1 build
anyway. A Skill becomes allow-listed after its first successful,
unrefunded, unrecycled settlement, but remains ineligible for public ranking
until classifier-verified independent use clears the amendment gate below.
No submission, no curation, no hosting decisions, no tradeable instruments.
This passes ADR-0007's own optionality test ("nearly free" when mechanics are
shared, 0007:61-63) because it is a read API over shared mechanics — provided
it is named and sequenced as a *protocol surface* (like MCP's registry, which
launched 10 months post-launch), never as the product.

## The empty slot, and who is closing in (all verified 2026-07-15)

**No one runs a paid marketplace for installable/portable agent skills with
royalties or on-chain attribution for authors** (on-chain attribution is
absent everywhere). Every adjacent piece exists in a silo:

| Who | What ships today | What's missing |
|---|---|---|
| skills.sh (Vercel, vercel-labs/skills, since 2026-01) | Free registry + `npx skills add`; ~9.6k on leaderboard of ~895k tracked; top skill ~2.5M installs; telemetry listing, no review | No payments, no attribution, no business model published. Owns the install rail; could flip monetization on overnight |
| Agent Bazaar (agent-bazaar.com) | 28+ hosted skills, per-call USDC via x402, Claude Code auto-discovery | No author comp/attribution; anonymous operator; unclear third-party publishing |
| MCP Hive (mcp-hive.com, launched 2026-07-12) | Newest provider-earnings loop ("providers earn per response"; 3 days old, payout mechanics unproven) | Hosted MCP tools, fiat monthly settlement, no attribution |
| Agent402 (agent402.tools, live 2026-06-12) | 403 tools + 101 skill packs, $0.05–$1.50, x402 on 8 networks, ~23k settled calls | One person. Proves the mechanics are a solo weekend — first-mover moat ≈ 0 |
| MuleRun (2025-12) / Agent37 (2025-12) | Creator rev-share (80–100% / 80/20), both **hosted** access | Fiat, no provenance; hosting confirms ADR-0001's leak logic |
| Agensi | *Claims* Stripe rev-share on installable SKILL.md files | Unproven — its own pages contradict each other (70% vs 80%); treat as vapor |
| Story Protocol | **Story Skills SDK (2026-05-06)**: IP registration, licensing, royalty policies as agent-usable skills | The one purpose-built on-chain royalty rail. PRD:514 already flags Story as "the most capable disintermediator" |
| Circle Agent Stack (2026-05-11) | Agent Wallets + Agent Marketplace (32 services / 349 endpoints), x402-adjacent | Enterprise services, not authored skills; no attribution |

Window estimate: **3–6 months** before someone credible (Vercel, Story,
Circle/Coinbase, or a funded team) wires x402 payments + attribution onto an
existing registry. Demand-side caution: the window is for **claiming the
standard, not for revenue** — the entire x402 economy is ~$24M/30d across ~75M
transactions (~$0.32 average; ~94k buyers / ~22k sellers; CoinDesk
2026-07-15), with Chainalysis flagging heavy meme-farming contamination in
historical counts and CoinDesk (2026-03-11) reporting micropayment demand "is
just not there yet."

Timing gift: the **x402 Foundation formally launched under the Linux
Foundation on 2026-07-14** (40 members; Visa, Mastercard, Amex, Stripe,
Ripple premier). Building on x402 now inherits that legitimacy for free.

## 2026-07-17 public registry metric contract

The registry consumes `SettlementMetricEventV1` records with required
settlement, Invocation, Skill, Creator/payee/payer wallet, gross/refund/recycle,
outcome, and UTC timestamp fields. Payer-supplied Beneficiary, relationship,
and cluster claims are retained only as audit warnings; they never determine a
public metric.

An operator-controlled `VerifiedBillingRegistryV1` classifies payer ownership.
Self-payment is derived before registry lookup. Direct reviewed entries classify
a payer as Creator-linked or independent and bind it to one Beneficiary and
billing-owner cluster; absent entries are unknown. This is explicit operator
trust, not proof of ultimate beneficial ownership.

Public output reports these fields separately: total settlements, successful
Invocations, settled failures, unresolved settlements, refunded settlements,
unique payer wallets, unique independent Beneficiaries, refund-adjusted net,
independent net, independence confidence, registry status, and counts for
`self_payment`, `linked_wallet`, `failed_invocation`,
`unresolved_settlement`, `refunded`, `recycled_value`, `sybil_cluster`, and
`unknown_relationship`.

Only successful, unrefunded, unrecycled settlements classified as independent
contribute to independent net. Events are ordered by settlement time and ID;
only the first accepted event in a billing-owner cluster can count. The first
registry stays allow-listed until at least two classifier-verified successful
independent Beneficiaries in distinct accepted clusters have positive
independent net. Eligible Skills sort by independent net, independent
Beneficiaries, successful Invocations, then Skill identifier.

## The adoption evidence: MCP vs A2A

Measured outcome (pypistats, 2026-07-15): `mcp` ≈ 295.5M downloads/month vs
`a2a-sdk` ≈ 11.3M — **~26x** — despite A2A having the larger logo roster.
(Python-only counts that include CI/bot traffic; the ratio is more
trustworthy than the absolutes.)

| Move | MCP (won) | A2A (logos without usage) |
|---|---|---|
| Launch | Complete adoption kit in one day (2024-11-25): spec + 2 SDKs + reference servers, **shipped working inside Claude Desktop**, with named adopters (Block, Apollo; Zed, Replit, Codeium, Sourcegraph) — no logo roster | Draft spec + 50 partner logos (2025-04-09), no shipped product |
| Namespace | MIT spec in vendor-neutral `modelcontextprotocol/`, never `anthropic/`; rival-co-maintained SDKs | Google-led, then donated |
| Foundation | Donated month 13 (2025-12-09, AAIF), **after** ~100M monthly downloads — ratification | Donated week ~10 (2025-06-23), **before** v1.0 — bought a coalition, not adoption |
| Growth engine | Mid-size AI editors (Cursor, Windsurf, Copilot agent mode) adopted first; OpenAI (2025-03-26) and Google (2025-04-09) ratified existing usage | 150+ orgs, 22k stars at year one; no named production customers |
| Registry | Month 10 (2025-09-08), open catalog, after organic supply | — |

AP2 (Google's payments protocol, 2025-09-16, 60+ partners) confirms the
pattern: 100+ logos, ~3 named deployments by 2026-04. x402's ~75M measured
transactions beat AP2's roster as a credibility asset.

**The rule: don't announce a standard without a paying deployment. Our
equivalent of Claude Desktop is one employer with a live collared skill and a
co-held claim — which is KC1.**

## The playbook, applied

1. **Adoption kit in one release**: Apache-2.0 spec + reference Collar
   middleware (Hono/Express) + the pi-wielder proxy as reference client + the
   offline zero-key demo. Every audience gets a working entry within an hour.
2. **Extension of incumbents, never a rival**: wrap Anthropic's SKILL.md
   format unmodified (Vercel indexed a format it doesn't own); settle on x402
   (LF-governed as of yesterday); register provenance on Story. One-line
   pitch: *attribution and metering once, payable from any 402-capable agent.*
3. **Neutral namespace now**: move the spec from the personal
   `Aznatkoiny/skill-asset-protocol` to a `skill-asset-protocol/` org with
   co-maintainer slots (even if empty for months). Costs a day; removes the
   single-founder governance objection before it's raised.
4. **Two named adopters before the word "standard"**: the KC1 design-partner
   employer (credibility anchor) + one x402 inference gateway speaking the
   Collar flow (distribution surface: Router402, BlockRun ClawRouter,
   tx402.ai). Without them we are running the A2A play.
5. **Mid-size ecosystem before giants**: gateway operators, OpenClaw/ClawHub
   maintainers, Smithery, Story devs — the campaign's week-of-living-in-replies
   already targets exactly these. Platforms ratify; they are not the ask.
6. **Listing = settlement-verifiable movement** (the Coinbase Bazaar mechanic): the
   anti-skills.sh. Their telemetry listing produced ~895k mostly-noise
   entries; settlement-gating produces a smaller index while the verified
   billing classifier and exclusions keep self-funded, linked, refunded,
   failed, unresolved, recycled, repeated-cluster, and unknown activity out of
   independent metrics.
7. **Discovery as an MCP server**: search → quote → pay (x402) → invoke in one
   agent tool-loop. x402 Bazaar, Nevermined, and MCP Hive all converged on MCP
   as the surface agents actually touch.
8. **Publish settlement-verifiable telemetry under the amendment contract**:
   report movement, outcomes, refunds, payer-wallet count, classifier-verified
   independent Beneficiaries, net amounts, confidence, status, and exclusions
   as separate fields. Never collapse them into a demand or quality claim.
9. **Sell attribution as security simultaneously**: signed immutable skill
   definitions + derivation graphs answer the documented registry
   supply-chain wound (Unit 42: five malicious ClawHub skills incl. macOS
   infostealers, 2026-02..05; Trail of Bits reportedly bypassed skills.sh's
   Snyk scanning via prompt injection). Buyers get wallet-attested registration
   and declared ancestry; authorship evidence and safety review are separate
   statuses. Creators get the claim substrate — the same primitive supports two
   distinct, explicitly bounded pitches.
10. **Donate late, like MCP and x402**: foundation paperwork before usage is
    pure distraction for a solo founder; revisit only on a credible fork
    threat.

## Sequence

| When | Do | Gate |
|---|---|---|
| Week 0 (now) | Execute the slipped launch — verified 2026-07-15 via `gh`: repo still private vs Day 0 = 07-14 — with a re-anchored Day 0 and design-partner conversations as metric #1; **instantiate KC7's monthly platform review with a named owner** (mandated PRD:647, currently uninstantiated) | — |
| Weeks 1–2 | Neutral GitHub org; package the adoption kit; finish pi-wielder as reference Wielder | Cheap, parallel |
| Weeks 2–6 | Land the two named adopters: the KC1 LOI + one x402 gateway; first settled mainnet payment through a collared skill, provenance on Story | The KC1 LOI is the hard gate for everything downstream |
| Weeks 6–10 | Ship **the Skill Asset Protocol registry** as an MCP server with settlement-verifiable listing + public telemetry dashboard | Only after organic supply exists; named registry, never marketplace |
| Months 3–4 | Attribution overlay on existing free registries (signed authorship + derivation records keyed to GitHub owner/repo); court ClawHub/Smithery — their malware problem is the sales wedge | — |
| Months 4–6+ | Phase-1 build per PRD | KC1 LOI signed + paying closed-mode deployment |

**Standing rule: a design-partner conversation outranks any protocol task.**
MCP won because a product people ran shipped on day one; ours is one employer
with a live collared skill.

## Risks recorded

- **KC7 fires** (when-not-if, R17): optionality written to zero that day; the
  registry survives because it indexes the closed-mode ledger. The monthly
  review has no named owner yet — a live compliance gap; it should watch
  Vercel and Story alongside Anthropic/OpenAI/GitHub.
- **Vercel monetizes skills.sh**: owns installer + telemetry. The paid-tier
  rumor is uncorroborated and disputed — treat it as false today; the live
  risk is Vercel's *option* to monetize later, and any overlay riding
  skills.sh telemetry is exposed to Vercel productizing it.
- **Story disintermediates**: Story Skills SDK is the only purpose-built
  on-chain royalty rail, and what it lacks versus this stack — no execution
  gate, no Wielder-hidden runtime, no per-invocation meter (PRD:514) — is
  buildable. Mitigation already specified (R15 exportable derivative graph,
  PRD:678) — make it real before deepening the dependency.
- **The A2A trap**: a spec launch without a paying flagship is a
  well-governed ghost town. Hence playbook #4.
- **Distillation remains unsolved** for any open supply; royalties on
  *installable* SKILL.md files stay an open research problem — everyone
  *verifiably* paying authors today does it by hosting.
- **Vocabulary/securities surface**: "crypto marketplace" framing invites
  exactly the banned vocabulary (earn/yield/tradeable); the registry ships
  under the compliance rules of the campaign kit, and nothing transferable
  exists before the PRD:780/786 gates.
- **Registry supply-chain bill comes due at v1**: signed, immutable
  definitions and provenance are launch requirements, not a verified tier
  later (MCP tool-poisoning CVEs, ClawHub infostealers, skills.sh scanner
  bypass are the base rate).

## What this doc does not decide

- It does **not** reopen ADR-0007. Marketplace stays underwritten optionality
  with unchanged gates.
- Registry build is **not** authorized before the KC1 LOI — weeks 6–10
  assume the LOI lands; if kill-criterion 1 fires instead, the registry dies
  with Phase 1 and the provenance layer stands alone.
- x402 volume quality (meme contamination) and skills.sh's paid-tier rumor
  are unverified beyond the citations above.
- The neutral-org move and adoption-kit packaging are recommended but not yet
  scheduled against the slipped campaign calendar — sequencing vs the
  re-anchored Day 0 is the founder's call.

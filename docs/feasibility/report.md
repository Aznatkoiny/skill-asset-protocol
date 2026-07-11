I have all the inputs I need. The CONTEXT.md confirms the line references (49, 95-96). Now I'll write the feasibility report.

# Skill Asset Protocol — Feasibility Report

*Prepared for: technical founder, build/no-build decision · Validation horizon: mid-2026 · Status of design under test: ADRs 0001–0004, v1 platform-native topology*

---

## 1. Bottom line up front

**Verdict: GO, with caveats.**

The Skill Asset Protocol is **feasible to build in mid-2026 with no fatal blocker** — every one of the five components validated at *works-with-caveats* (regulatory at *medium* confidence, the rest *high*). All four on-chain primitives the design needs are real, live, and audited on Story Protocol (chainId 1514, SDK v1.4.4 current as of Mar 2026); Anthropic Managed Agents (CMA, beta `managed-agents-2026-04-01`) genuinely hides the Skill from the Wielder in its session-output stream; and x402 is a clean, mature per-invocation gate that yields a replay-proof on-chain receipt. **But the literal ADR vision does *not* compose end-to-end.** The headline promise — *"a fork automatically pays its ancestors atomically on every invocation, via one payment that both gates execution and lands on Story's royalty contract"* — is physically impossible as stated, because x402 settles on the wrong chain (Base 8453), in the wrong token (USDC, not Story's WIP-only mainnet currency), via the wrong primitive (a transfer to an EOA, not the `payRoyaltyOnBehalf` contract call). The honest version is a **decoupled, two-leg, batched, eventually-consistent settlement** in which a collar custodies funds in-flight — and that custody is simultaneously the worst regulatory exposure (FinCEN MSB), the re-introduction of the very trusted accumulator ADR-0003 set out to eliminate, and the per-hop fee math that forces batching. Build it — but build the honest version, launch the closed (intra-org / education) modes first, and correct the atomicity language in ADR-0003 and CONTEXT.md lines 49 and 95-96. The deepest strategic risk sits *below* the chain entirely: ADR-0001 hands the Wielder the output, and for most Skills the output *is* the value, so a high-value Skill is the cheapest thing in the world to behaviorally clone — and your revenue volume is the cloner's free training set.

---

## 2. Per-component findings

| Component | Verdict | Key caveat | Confidence |
|---|---|---|---|
| **Managed Agents (CMA)** — host Skill server-side, hide from Wielder, gate per-invocation | works-with-caveats | Hiding is **key-custody-dependent, not a platform secrecy guarantee** (`GET /v1/agents/{id}` echoes the system prompt verbatim; Anthropic sees the Skill in plaintext, no TEE). **No native "no credential, no run" gate** exists on CMA, OpenAI, or Google — the gate is 100% your collar. Beta, not GA; 300 create-req/min/org ceiling; not ZDR/HIPAA-eligible. | high |
| **x402** — gate the call + receipt; settle to Story royalty contract | works-with-caveats | Part (a) gating+receipt is **solid**. Part (b) is the **broken seam**: x402 cannot settle onto Story (wrong chain, wrong token, pays an EOA not a function, no facilitator supports 1514). Forces a two-leg bridge architecture; CDP facilitator now charges $0.001/tx after 1k/mo. | high |
| **Story Protocol** — IP Asset, derivative flow-through, co-held royalty tokens, per-call credential | works-with-caveats | All four primitives are real, audited, on-chain. But flow-through is **PULL not PUSH** (ancestors must call `claimAllRevenue`); mainnet currency is **WIP only** (not USDC), $IP down ~97.5% from ATH; royalty-token granularity floor is 1%; **minting a License Token per LLM call is economically/latency-broken**. | high |
| **Leakage / moat (ADR-0004)** | works-with-caveats | ADR-0004 is **correct to abandon secrecy** (externally vindicated — OWASP LLM07:2025 says the system prompt is not a security control). But the threat is mis-named: the moat-killer is **off-platform behavioral cloning** of outputs, which the design does nothing about. Watermarking is a forensic tripwire, **not a moat** (SIRA ~100% removal). Moat defends the *marketplace*, not an individual breakout *Skill*. | high |
| **Regulatory (US)** | works-with-caveats | No fatal blocker, but **tradeable royalty claims are almost certainly securities** under Howey (March 2026 SEC interpretation does *not* carve out revenue-share tokens) → permissioned trading only (ERC-3643 + registered ATS + transfer agent). Custodial collar → likely **FinCEN MSB** (multi-state MTLs, 12–24 mo slog). Intra-org / education can stay non-securities if claims are non-transferable. | medium |

---

## 3. End-to-end composition walk-through

The settlement loop was traced step by step. It **does not compose end-to-end** as written; here is where each step holds and where it breaks.

| Step | Composes? | What actually happens |
|---|---|---|
| **1 — Register Skill on Story** | ✅ Yes | `mintAndRegisterIpAssetWithPilTerms` + `PILFlavor.commercialRemix()` is one real on-chain tx on Story mainnet. Forks register as declared Derivatives with on-chain ancestry. **The soundest step in the loop.** |
| **2 — Host behind managed agent, "content never leaves host"** | ⚠️ With correction | `{system, skills}` live on the persisted Agent object; the session output stream (`agent.message/thinking/tool_*/span.*`) never carries the prompt or skill bodies, so the Wielder cannot read the Skill. **But "content never leaves the host" is false against the host itself** — Anthropic processes the Skill in plaintext and `GET /v1/agents` echoes it to the key-holder. Hiding holds *only* because the collar is the sole key-holder and never proxies the agent-read. CONTEXT.md line 95–96 ("hidden from the host too") remains unsolved in v1. |
| **3a — Wielder pays, x402 gates + yields receipt** | ✅ Yes | Textbook x402 resource server: `402 + PAYMENT-REQUIRED` → EIP-3009 `transferWithAuthorization` (gasless, bytes32 nonce) → `/verify` + `/settle` → `PAYMENT-RESPONSE {success, txHash, networkId}`. The settled `txHash` **is** the single-use, replay-proof credential. *Caveat:* the protocol does **not** "safely resubmit" after a settled-but-failed run — the collar must do its own nonce/txHash bookkeeping. |
| **3b — Settle that SAME payment toward Story's royalty contract** | ❌ **Does not compose** | **The load-bearing break.** x402 settles a USDC transfer to an EOA on Base; Story needs `payRoyaltyOnBehalf(ipId, amount, token)` — a *contract call*, in *WIP*, on *eip155:1514*. x402 fails all three. The single payment that gates execution **cannot also be** the on-chain royalty payment. See §4. |
| **3c — Payment mints the execution credential** | ⚠️ Conditional | "Payment mints a credential" holds. "The credential is an on-chain Story License Token at per-call cadence" does **not** — each mint is a full on-chain tx dragging an IP→WIP wrap + ERC-20 approve + CometBFT block latency, for a credential gating an LLM call worth cents. Use the x402 `txHash` (or a collar-issued off-chain token) instead. |
| **4 — Collar verifies credential → invokes agent → returns only output** | ✅ Yes — and the gate **must** be your proxy | No native pre-execution gate on any of the three platforms. CMA's only mid-run gate (`permission_policy: always_ask`) is a tool-approval gate keyed to the key-holder, cannot stop a turn from starting/spending tokens; webhooks are after-the-fact. Anthropic keys are workspace-scoped (full/read-only only), so you *cannot* hand a Wielder a key that allows `sessions.create` but forbids `GET /v1/agents`. **The collar is structurally forced to be the sole key-holder and the entire gate.** This matches design intent. |
| **5 — Settlement: protocol fee, recursive royalty split, tradeable/co-held claims** | ⚠️ On-chain but PULL, batched, custodial | On-chain mechanics are real (LAP = whole ancestry, LRP = direct parents; 100 royalty tokens/vault = 1% each; co-holdable). But: **(i)** flow-through is *claimable*, not pushed — ancestors must call `claimAllRevenue` (needs a keeper or the school's revenue silently piles up); **(ii)** per-hop fees dwarf a micro-royalty → Story-side settlement **must** be batched; **(iii)** the two-leg design makes the collar an in-flight custodian. "A fork automatically pays its ancestors on every invocation" is true in *accounting* terms, eventually-consistent — **not** one atomic on-chain action per invocation. |

**Net composition result: `worksEndToEnd = false`, `criticalBlockers = []`.** No single blocker is fatal, but four high-severity gaps compound into one architectural reality (§4, §5).

---

## 4. The cross-chain settlement problem (the crux)

This is the likely make-or-break of the whole design, so it gets its own section.

### 4.1 Why x402 physically cannot settle onto Story

x402's `exact` scheme settles **a USDC token transfer to a `payTo` address on Base (eip155:8453)**. Story's Royalty Module requires **`payRoyaltyOnBehalf(ipId, amount, token)` — a contract function call, denominated in WIP (`0x1514…0000`, the *only* mainnet-whitelisted royalty currency), on eip155:1514.** Four independent mismatches, each sufficient on its own:

1. **Wrong chain.** No x402 facilitator (Coinbase CDP or any third party) supports Story 1514 as of mid-2026, and x402 settlement is **single-chain by design** — the transfer settles on the same chain it was signed for. There is no native cross-chain settlement. *(Sources: [docs.cdp.coinbase.com/x402/network-support](https://docs.cdp.coinbase.com/x402/network-support) — lists Base/Polygon/Arbitrum/World/Solana only; [x402.org/ecosystem](https://www.x402.org/ecosystem) — no Story facilitator.)*
2. **Wrong token.** Story whitelists **WIP only** on mainnet, not USDC. *(Source: [docs.story.foundation/concepts/royalty-module/overview](https://docs.story.foundation/concepts/royalty-module/overview).)*
3. **Wrong primitive.** x402 `exact` pays an **EOA/address**, not a function. Driving `payRoyaltyOnBehalf` inside settlement needs an x402-exec-class router/hook — and [nuwa-protocol/x402-exec](https://github.com/nuwa-protocol/x402-exec) is deployed **Base / X-Layer / BSC only, explicitly not cross-chain, never on Story**.
4. **Wrong authorization variant.** Even direct-to-contract settlement of EIP-3009 needs `receiveWithAuthorization`; x402 uses `transferWithAuthorization`, and WIP / `RoyaltyModule.sol` supporting `receiveWithAuthorization` is unverified (likely not the case).

An independent 2026 academic source ([A402, arXiv 2603.01179](https://arxiv.org/pdf/2603.01179)) names cross-chain payment/service split as a known open limitation that causes exactly this settlement delay and complexity — corroborating the seam adversarially.

### 4.2 The only realistic architecture: a decoupled two-leg loop

```
WIELDER
  │  (1) HTTP 402 + PAYMENT-REQUIRED
  ▼
COLLAR (x402 resource server, sole Anthropic key-holder)
  │
  ├── LEG 1  (synchronous, sub-second) ─────────────────────────────┐
  │   EIP-3009 transferWithAuthorization, USDC on Base              │
  │   /verify + /settle → settled txHash = single-use credential   │
  │   credential checked OFF-CHAIN → invoke CMA → return OUTPUT     │
  │                                                                  ▼
  │                                                          EXECUTION GATED
  │                                                          (no credential, no run)
  │
  └── LEG 2  (asynchronous, batched, eventually-consistent) ─────────┐
      settlement worker batches accrued payments per threshold/interval
      bridge/swap USDC(Base) → WIP(Story) via Stargate / Across / deBridge
      call payRoyaltyOnBehalf on Story (eip155:1514)
      permissionless keeper calls claimAllRevenue on ancestors' behalf
                                                                      ▼
                                                          ANCESTORS PAID (LATER)
```

**The two legs are decoupled.** Execution is gated by Leg-1 finality (sub-second); the royalty leg settles later (Across intent fills ~2–15s, canonical paths longer) and **in batches** — because per-hop fees (CDP facilitator $0.001/tx after 1k/mo + Base gas + bridge fee + USDC→WIP swap slippage + Story gas + claim gas) can each exceed a cents-level micro-royalty. *Batching is mandatory.*

### 4.3 The three things this forces you to accept

1. **Eventually-consistent, not atomic.** ADR-0002's "fork pays its ancestors atomically on every invocation" is achievable in *accounting* terms (claimable balance), not as one on-chain action. **Correct ADR-0002 / CONTEXT.md line 49: "automatically" → "automatically credited, claimable on demand."**
2. **The collar becomes an in-flight custodian** of Wielder funds on Base between Leg-1 (execution done) and Leg-2 (ancestors paid). A bridge stall means execution happened but the school is unpaid — a reconciliation surface. **And this is the exact fact pattern that "almost certainly" makes the collar a FinCEN MSB** ([Braumiller/Mondaq, Dec 2025](https://www.braumillerlaw.com/activating-http-402-the-x402-protocol-and-legal-framework-for-internet-native-stablecoin-payments/)): custody is the dividing line. The cross-chain workaround forces the same custody that creates the worst regulatory exposure.
3. **It re-centralizes the trust ADR-0003 tried to remove.** The off-chain batched meter that decides which invocations get settled **is** a trusted accumulator — exactly the oracle ADR-0003 rejected as able to under/over-report. ADR-0003's "usage fraud structurally impossible" holds only for the synchronous atomic case the cross-chain gap forces you to abandon. The guarantee degrades from *"structurally impossible to defraud"* to *"auditable accumulator."* **Make this explicit in ADR-0003.**

**Re-verify before building** (recency-sensitive): that no third-party x402 facilitator has added Story 1514 ([x402.org/ecosystem](https://www.x402.org/ecosystem)); the CDP fee schedule; that Story still whitelists WIP-only for royalties; and run a Leg-2 latency/fee spike on real Story mainnet.

---

## 5. Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| **Off-platform behavioral cloning of a breakout Skill** — output *is* the value (ADR-0001); a high-value, high-volume Skill needs only ~thousands of I/O pairs (~30× cheaper distillation), and your paid invocations supply them free. Moat defends the *marketplace*, not the *Skill*. | **High** (when-not-if, months) | **High** — undermines core value prop at success; v1 (no TEE) cannot prevent it | Live-evolution moving target + value-binding to non-output-carryable things (live tool/data access, fresh context, reputation) > pricing below clone-cost > anomaly detection > provenance graph > watermarking (tripwire only). Launch closed modes first. |
| **Collar custody → FinCEN MSB** classification | Medium-high (forced by two-leg unless architected around) | **High** — 12–24 mo, multi-$100K licensing slog that gates launch | Keep collar non-custodial on a hosted facilitator (Coinbase x402); settle splits via smart contract/issuer; push in-flight custody to a licensed bridge/BaaS partner. |
| **Tradeable royalty claims = securities** → full permissioned stack (ATS + transfer agent + KYC allow-list), contradicting "frictionless composable graph" | High (near-certain under Howey) | **High** for marketplace; **zero** for intra-org/education if non-transferable | ERC-3643 + Reg D 506(c)/Reg A+ + registered ATS ([Securitize](https://www.skadden.com/insights/publications/2026/04/tokenized-securities), FINRA-approved May 2026). Keep closed modes non-transferable. Defer tradeable claims to the last phase. |
| **Composition re-centralizes trust** — collar is sole key-holder + custodian + off-chain meter + (with Anthropic) sees the Skill | High (structural) | Medium — per-call gate stays trust-minimized; settlement trust reintroduced | Signed/auditable invocation logs; on-chain published settlement batches; refund/reputation for accept-but-fail; TEE as eventual fix. |
| **Cross-chain bridge stall** between Leg-1 and Leg-2 — execution done, ancestors unpaid | Medium | Medium — eventually-consistent + reconciliation overhead | Auditable off-chain ledger; retry/reconciliation; conservative batching windows. |
| **Stacked per-invocation fees exceed micro-royalty** | High at literal per-call; low once batched | Medium — forces batching + price floor | Mandatory batching; price above amortized settlement cost. |
| **$IP / WIP volatility + thin liquidity** — accrued value swings between accrual and claim; enterprise payers forced into involuntary $IP exposure | High ($IP ~−97.5% from ATH) | Medium — FX risk + enterprise friction | Fast-claim to limit WIP exposure window; build fiat/USDC→WIP on-ramp; monitor for USDC whitelisting. |
| **Verbatim system-prompt extraction** via agentic steering (runtime *is* a steerable agent) | Medium | Medium — leaks text, but ADR-0004 already abandons secrecy | Taxonomy-aware wrapper cuts extraction quality ~18% (never eliminates); real defense is the moats. |
| **CMA is beta, not GA**; not ZDR/HIPAA-eligible | Medium (beta churn) | Medium — rework + compliance gap for regulated data | Abstract the runtime behind the collar (swappable host); self-hosted sandbox for regulated data; track release notes. |
| **Recency risk in load-bearing facts** (a facilitator could add Story; fees, whitelist, License-Token semantics could change) | Low-medium | Low-medium — could simplify or invalidate parts | Re-verify the four recency items in §4.3 immediately before building. |

---

## 6. Recommended MVP path (routing around the blockers)

**Launch the closed modes first. They are the safest** — closed populations, aligned incentives, on-platform by construction, lowest cloning pressure — and they can structure co-held claims as **non-transferable contractual / deferred-comp / license-fee rights that sidestep securities treatment entirely** (no ATS, transfer agent, or allow-list needed for v1). The open Marketplace — thinnest moat, highest cloning incentive, full securities stack — comes **last**.

**Chain decision:** Story for IP / royalty / provenance (the only layer that models any of this); Base for the x402 gate. **Do not attempt to make x402 settle directly to Story** — accept the two-leg split as permanent v1 architecture.

### Phase 0 — Provenance (all-Story, ships immediately)
Register Skills as Story IP Assets via `mintAndRegisterIpAssetWithPilTerms` + `PILFlavor.commercialRemix()`; forks register as declared Derivatives with on-chain ancestry. This is the strongest part of the loop and establishes the provenance/derivative-graph moat regardless of how settlement evolves.

### Phase 1 — Gate + run + off-chain meter
Collar = **sole Anthropic key-holder + x402 resource server**. Flow: `402` → EIP-3009 `transferWithAuthorization` (USDC on Base) → `/verify` + `/settle` → settled `txHash` **is** the single-use credential (collar owns its own nonce/txHash bookkeeping; do **not** rely on protocol resubmit). **Settle payment first (sub-second), release the credential, *then* run the agent asynchronously and stream output — never hold the 402 handshake open across the agent run** (x402 `maxTimeoutSeconds` ~60s < cold `sessions.create` + agent loop). Credential is **off-chain-checked**; do **not** mint one Story License Token per call. Account royalties in an auditable off-chain ledger. Skill hidden from the Wielder (collar never proxies `GET /v1/agents`); document that the host still sees it (accepted per ADR-0004); use self-hosted sandbox config for regulated intra-org/education data (CMA is not ZDR/HIPAA).

### Phase 2 — On-chain royalty settlement (batched two-leg)
Async settlement worker batches accrued payments per threshold/interval, bridges/swaps USDC(Base)→WIP(Story) via Stargate/Across/deBridge, calls `payRoyaltyOnBehalf` on Story, and runs a **permissionless keeper that auto-claims `claimAllRevenue`** on ancestors' behalf (so the school's revenue never silently piles up). Publish settlement batches on-chain for reconciliation. **Minimize custody:** push in-flight value-holding to a licensed bridge/facilitator partner; keep the collar a non-custodial pass-through riding a hosted facilitator (Coinbase x402, which carries its own KYT/OFAC/licensing) so it looks like a merchant-on-Stripe, not an MSB.

### Phase 3 — Open Marketplace + tradeable claims (only when warranted)
Only here introduce tradeable Royalty claims — **permissioned**: ERC-3643 allow-list token, Reg D 506(c) to accredited (or Reg A+/CF for retail), secondary trading only on a registered ATS (e.g. Securitize) + transfer agent + KYC. **Engage securities counsel before this phase.**

### Doc corrections to make now
- **CONTEXT.md line 49 / ADR-0002:** "A Derivative … owes royalties … on each Invocation" → clarify *"automatically credited, claimable on demand (keeper auto-claims)."*
- **CONTEXT.md lines 95–96:** "hidden from the host too" → document as an *accepted v1 trust boundary* (host sees Skill; TEE tabled), not an open question the build solves.
- **ADR-0003:** make explicit that the "no trusted oracle / fraud structurally impossible" guarantee holds **only for the synchronous atomic case** and degrades to "auditable accumulator" once cross-chain batching is introduced.

---

## 7. Open questions to resolve before building

1. **License Token as non-burned per-call credential** — natively a License Token is an ERC-721 burned *only on derivative registration*. Whether it can be repurposed as a non-burned off-chain entitlement is **unverified** — needs a design spike. (Realistic path: use the x402 `txHash`, treat any License Token as a durable invocation-right metered off-chain.)
2. **Per-invocation agent-to-agent micropayment streams** — no regulatory source squarely analyzes this fact pattern; the MSB / merchant analysis is extrapolated. **Get counsel** to bless the specific collar architecture before launch.
3. **Cold-start latency** — real `sessions.create` → first `agent.message` (sandbox provisioning) is unmeasured. Benchmark before sizing SLAs.
4. **Leg-2 economics on real Story mainnet** — exact USDC(Base)→WIP(Story) bridge cost + confirmation time (vs. generic quotes) is unmeasured; needed to size the batching window and confirm micro-royalty economics.
5. **Long-lived-session isolation across buyers** — to dodge the 300 create-req/min/org ceiling you'll want to reuse sessions, but whether one session cleanly isolates distinct buyers (history accumulation, compaction cost) is unverified; likely one-session-per-buyer, which reintroduces the ceiling.
6. **`receiveWithAuthorization` on WIP / `RoyaltyModule.sol`** — would be needed for any hypothetical direct-to-contract settlement; needs a contract-level read on Story mainnet (almost certainly absent, but confirm).
7. **Live-evolution anti-clone efficacy** — the load-bearing assumption of the no-TEE defense (ship faster than the clone's distill-and-redeploy cadence) is *asserted by analogy, unmeasured*. No source quantifies how fast a Skill must change to keep a distilled clone economically stale.
8. **Off-platform Story enforcement** — the Royalty Module handles on-chain *declared* derivatives flawlessly, but real dispute/takedown outcomes for an *off-platform behavioral clone* (on-chain provenance meets off-chain courts) are undocumented.

---

### What does *not* work (stated plainly)

- **One payment cannot both gate execution and pay Story royalties.** This is the single hard architectural break. Two legs, always.
- **Per-invocation atomic royalty flow-through.** It is eventually-consistent, batched, and claimable — not atomic, not pushed.
- **Minting a Story License Token per LLM call.** Economically and latency-broken; the credential lives off-chain.
- **Hiding the Skill from the host.** v1 cannot; the host (Anthropic) sees it in plaintext. Accepted per ADR-0004; TEE is the tabled future fix.
- **A permissionless, frictionless tradeable royalty graph.** Tradeable claims are securities → permissioned trading only.
- **ADR-0003's "fraud structurally impossible" once cross-chain batching is in.** It degrades to an auditable trusted accumulator.
- **Defending an individual breakout Skill from off-platform cloning.** The moat protects the marketplace, not the asset, and v1 has no cryptographic answer — only economic and operational ones.

**None of these is fatal.** They are the difference between the ADR's idealized loop and the buildable one. Build the buildable one.
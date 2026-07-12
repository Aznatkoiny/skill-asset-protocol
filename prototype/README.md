# Prototype — settlement loop economics

> **Throwaway.** This exists to answer one question, then be deleted or absorbed.
> `settlement-engine.mjs` is the keeper (pure logic); `settlement-tui.mjs` is the disposable shell.

## The question

**Do the Skill Asset Protocol settlement economics actually create the incentives we claim?**
Specifically: when a Wielder pays per **Invocation**, does the recursive royalty split — protocol fee,
then composable flow-through up the **Derivative** ancestry to ancestors — distribute money in a way
that feels *fair and motivating* across all three modes (marketplace, intra-org co-ownership,
education)? Does payment-gating ("no credential, no run") hold? Push multi-level derivative chains,
extreme prices, and lopsided co-held claims through it and watch for "wait, that shouldn't happen."

This is a **logic** prototype — state and money flow, not UI.

## Run

```bash
node prototype/settlement-tui.mjs
```

In-memory only; nothing persists. `seed` resets to the demo scenario; `quit` exits.

## What's seeded

| Skill | Mode | Price | Ancestry | Royalty claim |
|---|---|---|---|---|
| `pdfx` | marketplace | $10 | root | dana 100% |
| `recon` | intra-org | $20 | root | sam 50% + megacorp 50% (co-held) |
| `finmod` | education | $5 | root | stateu 100% |
| `biofin` | education | $25 | ↳ finmod @ 30%↑ | mia 100% |

## Experiments worth running (the interesting moments)

1. `invoke biofin biocorp` — education flow-through. Mia keeps ~$17, State U gets ~$7 as ancestor. *Does that split feel right?*
2. `invoke recon otherco` — co-held claim. Sam **and** MegaCorp both earn from an external invocation. *This is the "benefits both" claim made concrete.*
3. `bypass pdfx acme` — the gate. Confirm there's no legal way to run without paying.
4. Build a 3-deep chain: `fork biofin mia deep-skill 40 5000` then `invoke deep-skill biocorp` — *does multi-level flow-through still feel fair, or does the original creator get dust?*
5. `inherit biofin 9000` then re-invoke — *what happens to the forker's incentive when ancestors take almost everything?* (Is there a fork-killing threshold?)
6. `fee 4000` — crank the protocol fee. *At what point does the model feel extractive?*
7. `royalty recon sam:9000,megacorp:1000` — shift the co-ownership. *Where's the split an employer would actually sign?*

## NOTES — the answer (from the pre-build economics spike)

Run `node prototype/spike-fork-economics.mjs` to reproduce. Verdict:

**1. HISTORICAL DETERMINISTIC MODEL RESULT — the fresh-uplift threshold matches the hypothesis
`i* = p_parent / p_fork`.** The leaf (latest forker) keeps `(1 − inherit)` of net *regardless of
chain depth*. Under this old assumption, forking beats authoring only the fresh uplift solo while
`inherit < p_parent/p_fork`: parent $5→fork $15 crosses at 33%; parent $15→fork $25 crosses at 60%.
The resulting price-ratio recommendation applies only to that modeled outside option; it is not
observed behavior and is superseded for Education by Note 4.

**2. The surprising finding — the dilution victim is the ORIGINAL creator, not the leaf.**
With a *flat per-hop* inherit, the originator's share decays geometrically with depth:
at 30%/hop the root (school) gets 30% → 9% → 2.7% → 0.8% across depths 1–4. The school earns well
from *direct* forks but is squeezed to dust in long lineages. The leaf is never squeezed.

**3. Design implication (for Phase 2 royalty policy).** This is exactly the **Story LAP vs LRP**
choice. A flat per-hop relative split (LRP-like) dilutes originators by depth. To protect the
originator's share against depth, use **LAP (whole-ancestry absolute)** — the root keeps a fixed %
of *all* descendants regardless of depth. Trade-off: LAP caps total downstream royalty, LRP lets it
compound per hop. Decision deferred to Phase 2; record as an ADR when committed.

**4. MODEL RESULT (2026-07-12) — the free re-author bypass supersedes Note 1 for Education only.**
Note 1 compared a declared Derivative with authoring only the fresh uplift. That historical A/B
outside option is not the Education choice surfaced by the premise review: a student-Creator can
re-author the whole $15 candidate using class knowledge, declare no lineage, and pay the school
nothing. This result supersedes Note 1's inherit recommendation for Education only; it does not
measure or revise Marketplace or Intra-org behavior.

The deterministic baseline holds candidate price, demand, quality, hosting cost, and inference cost
at parity: school root $5, declared or re-authored candidate $15, protocol fee 2.5%, amortized
re-author cost per Invocation $0, and Creator-captured lineage option value `V=$0`. The public engine
API produces these integer-cent results:

- The no-lineage re-authored root has ancestry `[]`. On one $15 Invocation the fee is $0.38, the
  student-Creator receives the full $14.62 net, and the school has no breakdown entry or payout.
- On the economic grid (0, then every integer percentage through 100%), 0 bps ties and every
  positive rate pays the school and makes free re-authoring strictly preferable. At 1%, the exact
  ancestor payout is $0.15. **No economically meaningful school-paying inherit survives this
  baseline.**
- A separate **local engine cent-rounding probe — not a protocol or economic threshold** finds that
  nominal 1–3 bps tie only because the school's payout rounds to $0.00; 4 bps pays $0.01 and loses
  when re-author cost is $0. The script also streams all 10,001 integer-bps cases to confirm every
  school-paying rate loses, without retaining or promoting those sub-1% rows as economic results.

This is deterministic settlement-engine arithmetic, not observed student choice, market demand, or
evolution behavior.

**5. LIVE-EVOLUTION OPTION VALUE — HYPOTHESIS, NOT MEASURED.** A declared Derivative survives when:

`ancestor payout <= net parity + amortized re-author cost per Invocation + Creator-captured lineage-only V`

Under the parity baseline above, that reduces to `ancestor payout <= V`. Equality is a tie, not a
strict preference. Exact engine payouts therefore set these minimum Creator-captured values:

| Inherit on $15 candidate | Ancestor payout | Minimum `V` not to lose |
|---:|---:|---:|
| 1% | $0.15 | $0.15 (tie) |
| 5% | $0.73 | $0.73 (tie) |
| 10% | $1.46 | $1.46 (tie) |
| 20% | $2.92 | $2.92 (tie) |
| 30% | $4.39 | $4.39 (tie) |

The seeded TUI's $25 / 30% analog has a $24.37 post-fee net and a $7.31 ancestor payout, so it needs
at least $7.31 of Creator-captured `V` merely to tie. The current engine does not deliver living
updates. `V` counts only if exclusive lineage value is captured by the Creator through price,
demand, or avoided maintenance — not when updates merely create value for the Beneficiary.

All `V` figures are modeled hypotheses. **Education remains deferred** unless exclusive living
updates, tool/data access, or support value is measured and made contractible, or the product uses
direct school→employer licensing instead of relying on student-declared lineage.

_No CONTEXT.md term change needed; this is an economic-policy finding, not a language one._

## MEASURED — CMA latency (claude-sonnet-4-6, trials=3, 2026-07-12)

First live run of `spike-cma-latency.mjs` (managed-agents beta):

- COLD (sessions.create on hot path): create p50 431ms; first event p50
  1139ms; **first answer token p50 2541ms** (min 1930 / max 2541); end_turn
  p50 2739ms.
- WARM (session reuse): stream setup p50 170ms; **send→first answer p50
  1534ms** (one 7730ms outlier of three trials — needs more samples).

Kill-criterion-2 reading: pay-then-run-async is comfortably usable — ~2.5s
cold to visible output on top of a ~0.8s testnet x402 gate (see
`spikes/pi-wielder/README.md`). n=3, one model, no effort sweep; treat as a
first bound, not a distribution. Reviewer caveat: the warm path assumes the
events stream tails rather than replays history; no near-zero samples
appeared (consistent with tailing), but the assumption is undocumented in
the API. Housekeeping: each bench run creates a throwaway managed-agents
environment + agent on the operator's account — archive/delete them in the
console when convenient (archiving is permanent).

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

**1. The fork-killing threshold is real and matches the hypothesis `i* = p_parent / p_fork`.**
The leaf (latest forker) keeps `(1 − inherit)` of net *regardless of chain depth*. Forking beats
authoring your uplift solo as long as `inherit < p_parent/p_fork`. Confirmed: parent $5→fork $15
crosses at 33%; parent $15→fork $25 crosses at 60%. **Recommended default: suggest inherit at the
price-ratio and let the Creator tune it; flag anything above as "may discourage forking."**

**2. The surprising finding — the dilution victim is the ORIGINAL creator, not the leaf.**
With a *flat per-hop* inherit, the originator's share decays geometrically with depth:
at 30%/hop the root (school) gets 30% → 9% → 2.7% → 0.8% across depths 1–4. The school earns well
from *direct* forks but is squeezed to dust in long lineages. The leaf is never squeezed.

**3. Design implication (for Phase 2 royalty policy).** This is exactly the **Story LAP vs LRP**
choice. A flat per-hop relative split (LRP-like) dilutes originators by depth. To protect the
originator's share against depth, use **LAP (whole-ancestry absolute)** — the root keeps a fixed %
of *all* descendants regardless of depth. Trade-off: LAP caps total downstream royalty, LRP lets it
compound per hop. Decision deferred to Phase 2; record as an ADR when committed.

_No CONTEXT.md term change needed; this is an economic-policy finding, not a language one._

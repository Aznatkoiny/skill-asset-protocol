# Phase A — verification findings & measurements (2026-07-12)

*Consolidates: adversarial review of Codex's six handoff commits, plus the
first live measurements for PRD kill-criteria 2 and 4. Detailed numbers live
in `prototype/README.md` and `spikes/clone-economics/README.md`; the fork
verdict in `prototype/README.md` NOTES (run `spike-fork-economics.mjs`).*

## Verdicts against the PRD kill-criteria

| KC | Question | Status after Phase A |
|---|---|---|
| 2 | Cold-start latency makes pay-then-run unusable? | **Does not fire** (first bound): cold ~2.5s to first answer token, warm ~1.5s (n=3, Sonnet). Composes with the measured ~0.8s testnet x402 gate into ~3.3s pay→output. |
| 4 | Breakout skill cloned with no economic counter? | **Split result** (N=6 only): fidelity FAILED for the clone (all critical gates), but the attack costs ~$1.58 with 8-invocation break-even — economics provide zero protection; fidelity difficulty is the only observed moat. Synthetic evolution overlay doubled the target–clone gap in one revision. High-N behavior unknown; do NOT cite as resolved. |
| — | Education mode (ADR-0007 deferral) | **Confirmed dead as designed**: with free re-authoring, every inherit rate > 0 is strictly dominated. Survival requires school-captured living value ≥ ancestor payout (measured minimum V per rate in the spike output). |

## Codex review outcome

Zero must-fix findings; all hard handoff constraints met (corpus untouched,
no secrets, pi-wielder untouched). Should-fix follow-ups, none blocking:

1. `phase0`: `IP_METADATA_URI`/`NFT_METADATA_URI` env overrides brick
   `npm run demo` — ignore or reject them in demo().
2. `phase0`: unfunded gate is `balance === 0n`; dust-funded wallets die
   mid-run with a raw revert — gate on an estimated minimum instead.
3. `phase0`: metadata URIs depend on httpbin.org durability — self-certifying
   by construction, but pin real content before mainnet-grade evidence.
4. `clone-economics`: small-N/small-H limitation now documented in README
   (done 2026-07-12); larger fixture sets needed before citing against KC4.
5. `cma-latency`: warm path assumes the events stream tails (not replays);
   document/guard — live n=3 data showed no replay artifacts.

Nits recorded in the review transcript (workflow `wf_ff6dac84-673`): epoch-zero
`createdAt` in provenance metadata, at-least-once crash window between confirm
and save, MemoryStore fake not exercising the manifest validator.

## Harness fixes applied during measurement (committed with this doc)

`spikes/clone-economics/src/experiment.mjs`: raw distillation output persisted
before validation; distillation prompt now states the public SKILL.md format;
extractor unwraps only whole-response fences; validator accepts any heading
level. Four failed runs before one green one — each failure documented in the
spike README.

## What Phase A leaves open

- High-N clone fidelity saturation (the real KC4 question).
- Aeneid write path — built, tested, waiting on wallet funding.
- Design-partner LOI (KC1) — the binding constraint on everything else.

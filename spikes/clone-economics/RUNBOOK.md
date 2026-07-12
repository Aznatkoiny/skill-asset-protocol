# RUNBOOK — explicitly gated live clone-economics run

The supported default is the offline proof:

```bash
npm run e2e
```

No live run was executed while building this spike. The procedure below is for
an operator who deliberately chooses to spend model credits and supplies a
current pricing snapshot.

## 1. Supply every live input

Copy `.env.example` to `.env`, fill it locally, then export it into the shell.
The CLI does not silently load `.env`.

```bash
set -a
source .env
set +a
```

Required live fields:

- `ALLOW_LIVE_LLM=1` and `MOCK_LLM=0` — explicit opt-in and non-mock mode.
- `ANTHROPIC_API_KEY` — never print it or commit `.env`.
- `MODEL`, `N`, `MAX_INPUT_TOKENS`, and `MAX_TOKENS` — all explicit; fixed
  fixtures support `1 ≤ N ≤ 6`. `MAX_INPUT_TOKENS` is an operator ceiling;
  the adapter uses UTF-8 byte length as a conservative tokenizer-unit upper
  bound and aborts before fetch when a request exceeds it.
- `INPUT_USD_PER_MILLION`, `OUTPUT_USD_PER_MILLION`, `PRICING_AS_OF`, and
  `PRICING_SOURCE` — operator-supplied current pricing, with a source URL or
  provider document name. The spike has no hard-coded claim that mock pricing
  is current.
- `MAX_RUN_COST_USD` — positive hard cap.
- `INVOCATION_PRICE_USD` — listed target Skill Invocation price used to model A;
  no x402 payment is settled by this harness.
- `CLONE_SERVING_COST_USD` — used only for modeled break-even.
- `DEPLOY_COST_USD` and `LABOR_COST_USD` — set to explicit estimates or `0` to
  record exclusion.

Before constructing the network adapter, the harness validates every required
field and precomputes a conservative maximum from request count,
`MAX_INPUT_TOKENS`, `MAX_TOKENS`, and both token rates. It aborts if that
maximum exceeds `MAX_RUN_COST_USD`.
During a run it also enforces cumulative measured provider spend. If a provider
response omits usage, that request's cost is `null`, never `$0`.

## 2. Run once

```bash
npm run real
```

The command writes ignored artifacts to `runs/live/report.json` and
`runs/live/report.md`. Inspect the report before drawing conclusions:

- Verify evidence labels distinguish measured provider usage from modeled pair
  acquisition.
- Compare target and clone absolute scores and critical-gate results first.
  Retention (`clone/target`) is secondary and can hide a weak target baseline.
- Treat `E_measure` as experiment overhead; it is not part of attacker build
  cost B.
- Check raw usage, normalized tokens, pricing snapshot, every request latency,
  sequential build time, and the parallel-acquisition lower bound.

## 3. N sweep

Run separate, capped experiments at the fixed supported sizes; keep model,
pricing, max tokens, repository inventory, and heldout set unchanged:

```bash
N=2 npm run real
N=4 npm run real
N=6 npm run real
```

Move or rename each ignored report between runs if you want to retain it. Plot:

- clone absolute score and critical-gate pass versus N;
- `D/A` and `B/A` versus N;
- break-even Invocations where `P - cloneServingCost > 0`;
- sequential build time and the parallel-acquisition lower bound.

## 4. Interpretation discipline

- `A=N×P` is **MODELED** paid-pair acquisition. The target provider's own model
  cost is reported separately and not added again to A.
- `D` is distillation provider spend. `E_tune` is zero only when no
  revision/selection attempt occurred. `C_deploy` and labor remain explicit.
- A ratio is undefined when `P=0`; break-even is undefined when clone serving
  margin is non-positive.
- A frozen clone falling behind one synthetic v2 overlay is not a Skill
  half-life estimate. Any recommended update interval is
  **HYPOTHESIS/EXTRAPOLATION** pending repeated dated revisions.
- Do not use this run to validate a corpus-wide `~30x` claim; matched-quality
  serving cost is a different, still-unmeasured quantity.

# RUNBOOK — explicitly gated live clone-economics run

The supported default is the offline proof:

```bash
npm run e2e
```

No live run was executed while building this spike. The procedure below is for
an operator who deliberately chooses to spend model credits and supplies a
current pricing snapshot.

## 1. Supply every bounded single-run live input

Copy `.env.example` to `.env`, fill it locally, then export it into the shell.
The CLI does not silently load `.env`.

```bash
set -a
source .env
set +a
```

Required bounded single-run live fields:

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

## 2. Run one bounded experiment

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

## 3. High-N sweep: preflight first

The preregistration is `fixtures/sweep-v1.json`: N=6,25,50,100; 30 held-out
fixtures; pair-order seeds 1701, 1702, and 1703; and distinct requested
distillation seeds 2701, 2702, and 2703. Pair-order seeds control only local
acquisition ordering. A high-N result is publishable only if a live adapter
reports all three requested distillation seeds as independently applied. The
current Anthropic adapter reports seed support as `unsupported`, so it may
produce explicitly uncontrolled evidence but cannot produce clone-fidelity,
defensibility, moat, break-even, or economics conclusions.

```bash
npm run fixtures:check
npm run sweep:preflight
npm run sweep:mock
```

These commands use no key, network, x402 payment, or provider spend.

## 4. Human-authorized live gate

The committed `fixtures/live-budget-v1.json` and
`fixtures/live-economics-v1.json` intentionally start with
`approvalStatus: "not_approved"` and null values. Before a live run, a human
must:

1. Verify the provider's current official pricing. In the budget snapshot,
   replace every null with the selected model, decimal-string prices,
   timestamped HTTPS source, and token caps, then set `approvalStatus` to
   `approved`.
2. Review and explicitly supply all four economic inputs in the economics
   snapshot: Invocation price, clone serving cost, deployment cost, and labor
   cost. Set its `approvalStatus` to `approved`.
3. Review the 1,713-call conservative request count from
   `npm run sweep:preflight`, then commit both approved snapshots and the
   unchanged `fixtures/sweep-v1.json`.

The sweep ignores environment-based model, pricing, token-cap, and economic
values. The committed files are its only execution contract.

Run `npm run sweep:preflight` again from that exact commit. It prints a
`live authorization: sha256:...` digest over the complete sweep config,
approved budget snapshot, and approved economics snapshot, plus the
conservative maximum cost. After reviewing the printed contract, the human
explicitly approves a maximum at or above the conservative estimate and copies
that exact digest:

```bash
export APPROVE_LIVE_SWEEP_SHA256='sha256:<exact digest printed by preflight>'
export MAX_SWEEP_COST_USD="$HUMAN_APPROVED_MAX_SWEEP_COST_USD"
export ALLOW_LIVE_LLM=1
```

Any change to N values, either seed family, model, prices, token caps,
economic inputs, or either approval snapshot changes the digest and
invalidates the old authorization.

Then, and only then, the operator may run:

```bash
npm run sweep:live
```

The command writes raw private output only under ignored `runs/` and writes a
sanitized candidate bundle to a new dated directory selected by its generated
experiment identifier under `evidence/`. Never overwrite a historical bundle.
Review and verify the candidate before staging; do not publish automatically.
An `unsupported` distillation-seed result remains useful only as
`stochastic_uncontrolled` evidence and must retain all conclusion suppressions.

## 5. Interpretation discipline

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

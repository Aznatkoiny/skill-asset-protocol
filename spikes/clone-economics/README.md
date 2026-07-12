# Clone-economics spike

> Throwaway logic prototype. Its purpose is to answer one question, not to become production code.

## Question

How cheaply can `N` paid input/output pairs from the
`optimizing-claude-code-prompts` **Skill** be distilled into a clone, and how
quickly would the original have to evolve to keep a frozen clone stale?

The offline experiment invokes the target Skill exactly `N` times against fixed
training inputs, gives a distiller only those `{input, output}` pairs, and scores
the target and clone on a disjoint heldout set with the same synthetic repository
context and executor settings. A deterministic v2 overlay then adds one material
target requirement and re-scores the updated target against the frozen v1 clone.

## One-command offline run

```bash
cd spikes/clone-economics
npm run e2e
```

`npm run e2e` forces `MOCK_LLM=1`, blanks model keys, replaces global network
access with a throwing function, writes reports only to temporary directories,
runs the experiment twice, byte-compares normalized JSON and Markdown, removes
the temporary outputs, and ends with `PASS — <n> checks green`.

## Architecture

1. `runExperiment()` reads the target `SKILL.md` and its reference at runtime,
   recording only their relative paths and SHA-256 hashes in reports.
2. Exactly `N` target Invocations generate training pairs.
3. The distillation payload contains only generic SKILL.md-authoring instructions
   plus the `N` pairs—no target/reference text, heldout data, rubric, IDs, tool
   traces, or distinctive target fingerprints.
4. Target, generated clone, and deliberately bad clone are scored with the same
   versioned deterministic contract rubric. Absolute scores and critical gates
   are primary; clone/target retention is secondary.
5. Economics separates modeled paid-pair acquisition (`A=N×P`), provider
   distillation (`D`), attack-side tuning (`E_tune`), deployment/labor, and final
   benchmark overhead (`E_measure`).
6. JSON and Markdown reports expose data hashes, scoring, raw/normalized usage,
   pricing provenance, costs, request/phase timings, and limitations.

## MOCK verdict

All values below are **SYNTHETIC canned evidence**, chosen to make the harness
auditable—not observations about a live model or market:

- `N=6`, `H=6`; target score `1.000`; good clone `0.900`, critical gates pass.
- Deliberately bad clone `0.200`, critical gates fail.
- Synthetic v2 updated target `1.000`; frozen clone `0.750`; stale-fidelity
  delta `0.250`.
- Listed Invocation price `$0.25`: modeled `A=$1.50`, `D=$0.30`, no tuning,
  deployment `$0.05`, labor explicitly excluded, so `B=$1.85`.
- `D/A=0.20`, `B/A=1.233333333333`, modeled break-even `10` Invocations at
  `$0.05` clone serving cost. Benchmark evaluation `$0.126` is excluded from B.

**LIVE RUN NOT EXECUTED — no key/explicit opt-in; no measured clone-economics result.**

## Files

| File | Role |
|---|---|
| `src/experiment.mjs` | Single public seam and phase orchestration |
| `src/adapters.mjs` | Separate canned mock and gated Anthropic live adapters |
| `src/scoring.mjs` | Versioned weighted deterministic fidelity contracts |
| `src/economics.mjs` | Acquisition/build/evaluation and break-even math |
| `src/reports.mjs` | Deterministic JSON and Markdown rendering |
| `run.mjs` | Thin mock/live CLI and report writer |
| `e2e.mjs` | Offline acceptance proof through `runExperiment()` only |
| `fixtures/` | Fixed train/heldout/v2 cases, synthetic repo/settings, mock transcript, good/bad clones |
| `RUNBOOK.md` | Explicitly gated live-run and N-sweep procedure |

## Limitations

- No live target Invocation, distillation, model evaluation, x402 settlement, or
  provider billing occurred. `A` is modeled from a listed Invocation price.
- Mock output quality, usage, costs, pricing, and latency are synthetic.
- Deterministic predicates test contract compliance, not semantic equivalence in
  every repository or task.
- One static v2 overlay cannot establish Skill half-life, real evolution
  efficacy, or a required update cadence. Any cadence statement is
  **HYPOTHESIS/EXTRAPOLATION** until repeated dated live runs exist.
- This spike does **not** validate the corpus-wide `~30x` statement. That refers
  to matched-quality serving cost and remains unmeasured here.

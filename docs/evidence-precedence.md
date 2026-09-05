# Document and evidence precedence

Orientation recorded 2026-09-05 against repository commit
`cf7d68aa1e234c115df314555db41e4d923ef8f3`. This is a reference baseline,
not an instruction to switch branches or reset a checkout. Record the actual
repository root, branch, HEAD, and working-tree status before reusing a review
or continuing a task. Verify that an affected file and behavior still exist;
an issue against an older checkout may already be fixed or retired.

This addendum resolves how to read current v1 work and earlier evidence. It
does not amend [CONTEXT.md](../CONTEXT.md), [the PRD](PRD.md), or [ADRs](adr/).
Changes to that protected corpus still require explicit instruction.

## Current work and historical context

Within repository documentation, use the following order:

1. **Current assignment:** the user's task and authorized scope. Historical
   task lists, branch instructions, and credential-dependent commands are
   records, not a standing assignment or permission to spend or publish.
2. **Current v1 scope:** the
   [approved 2026-07-31 Agent Spend Control Plane design](superpowers/specs/2026-07-31-agent-spend-control-plane-design.md),
   including its approved 2026-08-02 approval-flow amendment. V1 is the
   customer-hosted Wallet Kernel for policy, exact approval, recovery,
   signed receipts, and reconciliation. Its non-goals are boundaries, not
   missing features: Skill compensation, Story settlement, and marketplace
   work remain deferred research.
3. **Implementation and verification:** the
   [Wallet Kernel implementation plan](superpowers/plans/2026-07-31-agent-spend-control-plane.md)
   supplies detailed contracts. Check current source, package documentation,
   and fresh test results before asserting a contract is implemented. Plan
   completion, design approval, offline integration, live qualification, and
   release approval are distinct states.
4. **Empirical claims:** use the relevant retained evidence manifest, its
   permitted claims, and its recomputation checks ahead of older narrative
   summaries. A later document date or the word "measured" cannot expand
   what the evidence supports. Preserve historical and invalid records;
   write replacement measurements to a new dated bundle.
5. **Earlier doctrine and tasks:** the protected corpus preserves the
   authored-Skill compensation thesis and protocol terminology. The
   [July 11 handoff](handoffs/2026-07-11-codex-premise-review-followups.md) and
   [July 15 handoff with July 18 readiness results](handoffs/2026-07-15-launch-week-handoff.md)
   describe prior work. Their task queues and passing gates do not determine
   current Wallet Kernel v1 acceptance or authorize a new live run.

Use [README.md](../README.md) for the current project summary and
[site/README.md](../site/README.md) for website status. Source changes can
establish new implementation behavior; they cannot retroactively make an
old transaction or benchmark evidence of that behavior.

## Evidence corrections to carry forward

### Clone fidelity and economics

Earlier PRD and handoff prose describes the 2026-07-12 N=6 run as evidence
that fidelity protected the Skill, with an eight-invocation break-even.
The [retained manifest](../spikes/clone-economics/evidence/2026-07-12-n6-invalid/manifest.json)
classifies it as `INVALID_BENCHMARK_TARGET_FAILED`: the original target scored
0.400 and failed its own critical gates. The
[spike README](../spikes/clone-economics/README.md) suppresses clone quality,
fidelity-defense, moat, retention, and break-even conclusions. Four earlier
setup attempts lack normalized records, so total attack cost is incomplete.

Provider execution and returned usage remain historical observations;
paid-pair acquisition was modeled. There is no publishable high-N result.
The normalized bundle can be verified offline from `spikes/clone-economics`:

```bash
node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid
```

That verification recomputes retained metrics and checks the bundle's
integrity. It does not turn an invalid target into a valid benchmark or
re-score model answers: raw prompt and output text are deliberately excluded.

### Historical payment timing

The [2026-07-15 overhead manifest](../spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json)
marks the reported n=48 and p50/p95 values `historical_unreproducible`, with
`publication.allowed: false`. Per-call normalized samples were not retained.
Keep the figures as historical reports; exclude them from current performance
and launch claims. A replacement requires a separately authorized run and a
new evidence directory, not a relabeling of this aggregate.

### Historical settlement and the retired website

The [2026-07-12 receipt manifest](../spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json)
supports one successful Base Sepolia transfer of `250000` atomic test-USDC
units and the historical run log's Skill-leg label. It does not prove Skill
execution, royalty splits, current endpoint behavior, latency, customer
demand, or production readiness.

The browser-wallet invocation endpoint is retired in the current website
source. `/proof` is a static archive; `/` is an offline Wallet Kernel preview
candidate. See [site/README.md](../site/README.md). Older handoffs calling the
website a working paid endpoint do not describe this source, and a source
change is not evidence of deployment to the public domains.

## Live and release status

At the recorded baseline, current Wallet Kernel evidence is offline and
deterministic; CDP/testnet execution and Linux lifecycle qualification remain
not run or incomplete. See the
[current spend-control status](../spikes/pi-wielder/README.md#current-spend-control-status).
This addendum records no new integration pass, live run, funding, deployment,
or release qualification. Subsequent work must report each of those states
separately against its own code revision and evidence.

The approved design's verification, acceptance, and release sections remain
binding. Offline tests alone do not justify a live-product claim or clear the
pre-release website gate. Any authorized Base Sepolia run must retain a fresh,
immutable, recomputable evidence bundle with the exact code revision,
configuration digests, normalized events, and explicit testnet labels.
Mainnet and real funds remain outside v1; wallet funding remains a human step.

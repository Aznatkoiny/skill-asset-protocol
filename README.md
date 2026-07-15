![NEVER HANDED OVER — Skill Asset Protocol](assets/github-banner.png)

# Skill Asset Protocol

A compensation, attribution, and metering layer for authored AI **Skills** — "Carta for AI
work artifacts." Creators keep a durable economic claim each time others use their Skill,
instead of handing the value over once under work-for-hire.

This is a **research/spike repository**: design documents plus executable evidence, not a
product. Every claim below is labeled measured, modeled, or hypothesis.

**The manifesto is live — and it is a working protocol endpoint:
[neverhandedover.com](https://neverhandedover.com)** (also at
[skillassetprotocol.com](https://skillassetprotocol.com); source in [`site/`](site/)).

## The demo result

On 2026-07-12, one wallet paid per model call **and** per hosted-skill invocation over x402
(Base Sepolia, real facilitator, real USDC), landing both asset classes in one attributed
session ledger:

```
claude/plan $0.041 · skill $0.25 → creator $0.24375 / treasury $0.00625
```

On-chain balances reconciled to the cent (Wielder 20 → 19.668 USDC; sellers received exactly
0.332). Measured x402 payment overhead across 48 settled calls (2026-07-15, two model providers):
**p50 731 ms / p95 1206 ms per paid call** — facilitator verify/settle is nearly all of it
(p50 729 ms); the 402 roundtrip + EIP-3009 signature add ~2 ms.
Details and txHashes: [`spikes/pi-wielder/README.md`](spikes/pi-wielder/README.md).

## Try it offline — zero keys, zero funds

All four proofs run with no API keys, no network payments, and no wallet. Where a
`package-lock.json` exists, `npm ci` is the reproducible choice.

| Where | Commands | Proves |
|---|---|---|
| `spikes/pi-wielder` | `npm install && npm run e2e` | 20 checks: 402-first on every leg, no skill-content leak, replay rejection, exact split match |
| `spikes/clone-economics` | `npm run e2e` (no install) | 97 checks: deterministic clone-distillation harness, byte-identical reruns |
| `prototype` | `node spike-fork-economics.mjs` (no install) | 64 invariants: fork/royalty economics on the settlement engine |
| `phase0` | `npm install && npm test` | 18 tests: Story provenance registration against injected fakes |

## What's here

- **`CONTEXT.md`** — the ubiquitous language: Skill, Creator, Wielder, Beneficiary, Collar,
  Invocation, Derivative, Royalty claim.
- **`docs/adr/`** — 8 decision records, including 0007 (the closed-mode compensation layer is
  the terminal product) and 0008 (the Wielder is a wallet, not a harness).
- **`spikes/`** — pi-wielder (one wallet, two asset classes, unified ledger) and
  clone-economics (how cheaply can N paid outputs be distilled into a clone?).
- **`prototype/`** — the settlement engine (pure logic) plus fork-economics and CMA-latency
  spikes.
- **`phase0/`** — Story Protocol provenance: register a Skill as an IP Asset and declare
  Derivatives (Aeneid testnet only).
- **`.claude/skills/` and `.agents/skills/`** — the bundled example skill
  (`optimizing-claude-code-prompts`) is **intentionally public**. The protocol's claim is that
  a Wielder never receives the skill at runtime — output only — not that the skill is secret.
  The spikes host and meter this exact skill behind the Collar.

## Evidence status

The repo's discipline is to label every number:

- **Measured (real network, n=48 settled calls + a live pi session):** the runs above — real
  402 → sign → settle, real USDC per call, splits credited by the settlement engine, wallet
  reconciled on-chain to the cent; two failure modes documented (pay-then-fail, settled-but-rejected).
- **Measured (n=3, one model):** hosted-agent cold start — first answer token p50 ~2.5 s;
  pay-then-run-async reads as usable on top of the ~0.8 s testnet payment gate.
- **Measured (N=6, small fixtures):** the clone attack **failed on fidelity** — all 6 held-out
  cases failed critical gates — but modeled break-even is **8 invocations** if a clone ever
  passes. Cost is no defense; fidelity was. High-N behavior is **unknown**.
- **Modeled (deterministic arithmetic, not observed behavior):** education-mode flow-through
  is dominated by free re-authoring — every school-paying royalty rate loses at parity, so
  Education mode is deferred.
- **Validated arithmetically:** settlement splits, multi-level derivative flow-through, and
  payment gating ("no credential, no run") via the engine's invariants.

Unvalidated: that employers will buy this. Design-partner interviews remain the open step.

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Antony Zaki
([Aznatkoiny](https://github.com/Aznatkoiny)).

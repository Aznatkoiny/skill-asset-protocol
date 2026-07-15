# Pi-Wielder spike — one wallet, two asset classes

Design: [section 4 of the 2026-07-11 reframe & Pi-Wielder design](../../docs/plans/2026-07-11-reframe-and-pi-wielder-design.md).

## What this proves

A coding harness (Pi) pays **per-call for model inference** and **per-invocation
for a hosted Skill** from the **same wallet**, and every payment lands in **one
attributed session ledger** — with a royalty split on the skill leg computed by
the same settlement engine prototyped in `prototype/settlement-engine.mjs`:

```
claude/plan $0.041 · gpt/implement $0.087 · skill/optimizing-claude-code-prompts $0.25 → creator $0.24375 / treasury $0.00625
```

Three claims, each demonstrated end-to-end by `npm run e2e` (offline, zero
keys, zero funds):

1. **The Wielder is a wallet, not a harness (ADR-0008).** The *entire*
   Wielder-side protocol footprint is one file, `src/proxy.mjs`: answer
   HTTP 402 with a signed USDC `transferWithAuthorization` (EIP-3009) and
   retry. No Story SDK, no token custody, no chain reads. Pi itself contains
   zero payment code — its extension just points at a localhost baseUrl
   (precedent: BlockRun's ClawRouter does exactly this for OpenClaw on 8402).
2. **The unified meter is the differentiator.** Inference payments are
   commoditizing (Router402, tx402.ai, ClawRouter). What they don't have is
   the second asset class in the same ledger: skill invocations with royalty
   attribution. Here both legs are entries in one JSONL session ledger.
3. **The collar keeps the platform key.** The Wielder pays for an
   *invocation* and receives *output only*; the skill content
   (`.claude/skills/optimizing-claude-code-prompts/SKILL.md`) never leaves the
   collar process. The settled txHash is a single-use execution credential —
   replays are rejected ("no credential, no run", ADR-0003).

## Architecture

```
                                Pi (the harness — knows NOTHING about payments)
                                 │  .pi/extensions/x402.ts:
                                 │    provider "x402" → baseUrl localhost:8402/v1
                                 │    tool invoke_skill → localhost:8402/invoke/…
                                 │    command /ledger  → localhost:8402/ledger
                                 ▼
      ┌──────────────────────────────────────────────────────────┐
      │  src/proxy.mjs — THE WIELDER (= wallet + paying fetch)   │
      │  · viem account from PRIVATE_KEY (src/wallet.mjs)        │
      │  · on 402: sign EIP-3009 USDC auth → X-PAYMENT → retry   │
      │  · appends every paid call to the SESSION LEDGER (JSONL) │
      │    {ts, leg, label, amountUSDC, txHash, splits}          │
      └────────────┬─────────────────────────────┬───────────────┘
        /v1/* (leg: model)              /invoke/* (leg: skill)
                   ▼                             ▼
      ┌─────────────────────────┐   ┌──────────────────────────────────┐
      │ src/gateway.mjs         │   │ src/collar.mjs — MOCK COLLAR     │
      │ x402 inference reseller │   │ 402-gate → verify → settle →     │
      │ (simulated, testnet)    │   │ txHash = single-use credential → │
      │ 402-gate → claude-* to  │   │ run SKILL.md via Anthropic API   │
      │ Anthropic, gpt-* to     │   │ (output ONLY) → meter split via  │
      │ OpenAI (or MOCK_LLM)    │   │ prototype/settlement-engine.mjs  │
      └────────────┬────────────┘   └────────────┬─────────────────────┘
                   │      verify/settle          │
                   └───────────┬─────────────────┘
                               ▼
             x402 facilitator (Base Sepolia)
             · real:  https://x402.org/facilitator
             · MOCK_FACILITATOR=1: src/facilitator-mock.mjs — in-process;
               really verifies the EIP-712 signature, fakes only settlement
               (deterministic txHash preserves the replay property)
```

One wallet (top), two asset classes (the two sellers), three payees in the
demo scenario (inference reseller, skill creator, protocol treasury), one
ledger (in the proxy — where the wallet is, because the meter belongs to the
payer's session).

## How it maps to ADR-0008

ADR-0008 rejects the token-holding client and the full-protocol client. This
spike is the constructive proof: grep `src/proxy.mjs` — the only protocol
concepts in it are *HTTP 402*, *EIP-3009 signature*, and *retry*. Everything
skill-economic (credentials, royalty tables, `distribute()`, provenance)
lives seller-side behind the collar. If a cron job or `curl` replaced Pi
tomorrow, nothing in the protocol would notice: **any client that can pay is
a Wielder**.

## Run it

```bash
npm install
npm run e2e     # offline proof: MOCK_FACILITATOR=1 MOCK_LLM=1, no keys, no funds
```

The e2e boots facilitator-mock + collar + gateway + proxy on ephemeral ports,
drives all three legs through the proxy only, and asserts: 402-first on every
leg, no skill-content leak, replay rejection, exact split match against the
settlement engine, and prints the rendered ledger plus (mock) payment-overhead
timings.

For the real-facilitator testnet run and the live Pi demo, see
[RUNBOOK.md](./RUNBOOK.md).

## Files

| File | Role |
|---|---|
| `src/proxy.mjs` | The Wielder: paying proxy; the whole client-side protocol footprint |
| `src/wallet.mjs` | viem account from `PRIVATE_KEY`; throwaway key for mock mode |
| `src/gateway.mjs` | Simulated x402 inference reseller (OpenAI-compatible, 402-gated) |
| `src/collar.mjs` | Mock collar: hosts + gates the skill, meters splits via the settlement engine |
| `src/x402-seller.mjs` | Seller half of x402 v1 (`exact` scheme), hand-written Hono middleware |
| `src/facilitator-mock.mjs` | Offline facilitator: real signature verification, fake settlement |
| `src/ledger.mjs` | JSONL session ledger + `renderLedger()` |
| `pi-extension/x402.ts` | Pi extension: provider `x402`, tool `invoke_skill`, command `/ledger` |
| `e2e.mjs` | The offline proof (`npm run e2e`) |

## Deviations from the design's research notes

- **`@x402/*` packages not used.** The published `@x402/fetch` / `@x402/evm` /
  `@x402/hono` (v2.18.0) implement protocol **v2** — class-based scheme
  registries, CAIP-2 network ids, facilitator sync-on-start — while the free
  testnet facilitator speaks **v1**, and the sync-on-start network coupling
  breaks the zero-network mock mode. The design blesses the manual path
  ("shows the protocol plainly"); the v1 `exact` scheme is implemented by hand
  in `src/proxy.mjs` (buyer, ~40 protocol lines) and `src/x402-seller.mjs`
  (seller). Only `viem` is used for cryptography.
- **`distribute()` is not exported** by `prototype/settlement-engine.mjs` (it
  is an internal). The collar and the e2e drive it through the engine's public
  economic event `invoke()` and use the returned `breakdown` — same math,
  public API, and the e2e still asserts an *exact* match.
- **Engine amounts are atomic USDC** (6-decimal integers): the prototype
  rounds to 2 decimals, which is lossy for $0.25 micro-royalties; integers
  keep the split exact (250000 → creator 243750 / treasury 6250).

## Measured results — first real-network run (Base Sepolia, 2026-07-12)

Executed per RUNBOOK §1–2 with a Circle-faucet-funded Wielder wallet
(`0xdddf…053F`), the free `x402.org/facilitator`, and a real Anthropic key
(no OPENAI key was present, so the gpt leg was skipped — two paid legs, not
three). Everything below is on-chain-verifiable.

**Session ledger (real settlements):**

| leg | label | paid | txHash | split |
|---|---|---|---|---|
| model | claude/plan | $0.041 | `0x01daa723…38ff49` | — |
| skill | optimizing-claude-code-prompts | $0.25 | `0xaf1ba2fe…7af522` | creator $0.24375 / treasury $0.00625 |
| model | claude/plan2 (overhead capture) | $0.041 | — | — |

On-chain balance check after the session: Wielder 20 → **19.668** USDC;
sellers' address received exactly **0.332** — every cent accounted for.

**Measured x402 payment overhead (real facilitator, n=1 instrumented call):**
402-roundtrip **3.9 ms** · EIP-3009 sign **1.1 ms** · facilitator
verify+settle **776 ms** · **total ≈ 781 ms** per paid call. The facilitator
leg dominates; mainnet Base with Flashblocks claims ~200 ms, so testnet
numbers are likely an upper bound. End-to-end including inference: 6.7 s
(plan leg), 14.5 s (skill invocation — includes the hosted skill's own
model run).

**What this run proved beyond the offline e2e:** real 402 → sign → settle
against a live facilitator; real USDC moving on a public chain per call;
skill executed behind the Collar with output-only response; splits credited
per the settlement engine — the protocol's Phase-1 Leg-1 loop, end to end,
for $0.33 of play money.

## Measured results — overhead distribution + live pi session (2026-07-15)

**x402 payment overhead, n=48 settled calls** (29 claude + 19 gpt, real
`x402.org/facilitator`, Base Sepolia): **p50 731 ms · p95 1206 ms** (mean
830, min 487, max 1859). Decomposition: facilitator verify+settle p50 729 ms
(the whole story); 402-roundtrip p50 1.2 ms; EIP-3009 sign p50 0.9 ms.
End-to-end paid roundtrip including inference (green calls): claude p50
2.15 s / p95 3.94 s; gpt p50 1.47 s / p95 3.30 s. Wallet reconciled
on-chain to the cent: 19.299 → 16.129 USDC = one pi session ($0.287) +
29×$0.041 + 19×$0.087 + one settled-but-rejected call ($0.041).

**The gpt leg ran for the first time** (skipped 2026-07-12 for lack of a
key) — after fixing a real gateway bug the bench surfaced: newer OpenAI
models reject `max_tokens` (400 `unsupported_parameter`), so the gateway now
translates it to `max_completion_tokens`. The first 10 gpt attempts
**settled and then failed upstream** — $0.87 paid for ten 500s. Two
protocol observations worth keeping:

1. **Pay-then-fail is the buyer's risk under pay-first-then-run.** A seller
   bug after settlement costs the Wielder real money with no refund path in
   x402 v1. (Design note for the Collar: attempt-then-settle ordering, or a
   retry-credit convention.)
2. **Settled-but-rejected happens.** 1 of 50 calls settled on-chain but the
   facilitator's response to the seller failed, so the seller returned 402
   anyway — buyer charged, no output (confirmed by exact balance
   reconciliation). A second 402-after-signing did *not* settle. Testnet
   facilitator flake rate over this run: ~4% of calls errored mid-payment.

**Live pi session (same day):** unmodified pi v0.80.6 with the extension
paid 8 streaming calls ($0.328) through the proxy in a real agentic session
— one human prompt produced 7 paid model turns, a live datapoint that flat
per-call pricing amplifies agentic chattiness (relevant to the PRD's
pricing-model spike).

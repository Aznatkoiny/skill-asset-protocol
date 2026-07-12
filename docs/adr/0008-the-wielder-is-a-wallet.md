# The Wielder is a wallet, not a harness

**Status:** Accepted (2026-07-11)

## Context

Earlier drafts implicitly assumed a "protocol client" on the demand side: a harness that holds
tokens, reads Story state, and speaks the full protocol. That assumption is expensive exactly where
we can least afford it — demand-side adoption is the corpus's least-validated leg, and every
client-side SDK dependency shrinks the set of possible Wielders to harnesses we integrate by hand.

Meanwhile the payment substrate has matured without us (research, 2026-07):

- **x402 is a Linux Foundation standard.** The x402 Foundation launched 2026-04 with 20+ members
  (Google, Visa, Stripe, AWS, Mastercard, Circle, Microsoft, Shopify, Amex); ~75.4M transactions /
  ~$24.2M volume in the 30 days before 2026-07-11 (x402.org).
- **BYO-wallet per-call inference payment is live and growing:** Router402 (OpenRouter-like, USDC
  on Base, ~200ms settlement via Flashblocks), tx402.ai (20+ EU-hosted open models), BlockRun
  ClawRouter (a local proxy for OpenClaw that auto-generates a wallet and pays per LLM call; 55+
  models, Base + Solana, mainnet-only), and Cloudflare's Monetization Gateway (waitlist opened
  2026-07-01). All are third-party resellers — **no first-party OpenAI/Anthropic x402 support
  exists**.
- **Harnesses already externalize the endpoint.** Pi (earendil-works/pi, ~70k stars, MIT,
  TypeScript) is a minimal multi-provider coding agent with custom `baseUrl` support and
  mid-session model switching — and ships no wallet or x402 support. A harness like this becomes a
  Wielder by pointing its `baseUrl` at a paying proxy; nothing inside the harness needs to know
  the protocol exists.

## Decision

**The Wielder-side protocol footprint is exactly: answer HTTP 402 with a signed USDC payment and
retry.** No Story SDK, no token custody, no chain reads client-side. The invocation-right is
exercised by paying, not held. Claude Code, Pi, a cron job, and curl are all Wielders.

**Demand strategy — inference as the wedge.** BYO-wallet inference payment installs the
wallet-and-402 rail; skills ride the same rail. A Wielder that already pays per inference call
needs zero additional machinery to pay per skill invocation — the two legs differ only in what the
Collar does behind the gate (royalty splits vs pass-through).

## Considered options

- **Token-holding client** (Wielder custodies a license/royalty token; the Collar verifies
  on-chain holdings before running) — rejected: forces wallet custody plus chain reads into every
  harness; resurrects the per-call on-chain object ADR-0005 already rejected as uneconomic; and
  turns the invocation-right into a *held* asset, dragging the securities surface ADR-0006 walls
  off onto the demand side — where friction must be lowest.
- **Full protocol client** (harness-side SDK speaking Story + x402 + Collar APIs) — rejected:
  shrinks the addressable Wielder population to harnesses we integrate one by one; couples
  adoption to per-harness engineering; and duplicates state the Collar must own anyway — anything
  the client "knows" beyond pay-and-retry is something the Collar can no longer trust.

## Consequences

- **Validated by construction in the Pi-Wielder spike (`spikes/pi-wielder/`):** a ~100-line paying
  proxy in front of an unmodified-core Pi is the entire Wielder-side footprint — one wallet pays
  per-call for inference on two models AND one hosted Skill invocation, with a unified attributed
  session ledger. The spike's measured x402 payment overhead (sign → verify → settle p50/p95)
  feeds the demand-side analysis in the project's internal PRD (unpublished).
- **Competitive implication: inference payment is commoditizing.** Router402, tx402.ai, and
  ClawRouter already sell it; Cloudflare is entering. Payment cannot be the differentiator. The
  differentiator is the **unified attributed meter** — one wallet whose ledger attributes
  inference calls AND skill invocations, with royalty splits on the skill leg (analyzed in the
  competitive-landscape section of the project's internal PRD, unpublished).
- The Collar remains the single trusted component (it already was — ADR-0003/0005); this decision
  refuses to leak trust requirements to the client. "Trust-minimized" in this corpus means
  **Wielder-side** trust-minimized, nothing stronger.
- Cost of thinness: a payer this thin can verify nothing client-side — not splits, not provenance.
  Beneficiary auditability must therefore come from the Collar's published, Merkle-committed
  invocation log (a Phase-1 requirement in the project's internal PRD), not from the Wielder.
- Dependence on resellers is real: until a first-party API accepts x402, the inference leg rides
  third-party gateways (mainnet-only today), and the wedge's durability is unvalidated beyond the
  30-day volume snapshot above.

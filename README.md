# Skill Asset Protocol

## Agent Spend Control Plane

Give AI agents a wallet without giving them the keys.

The approved commercial direction is a customer-hosted **Agent Spend Control
Plane**. Its central module, the **Wallet Kernel**, turns an Agent's ordinary
HTTP request into a bounded Spend Intent, evaluates customer policy, obtains
exact human approval when required, signs only an authorized x402 payment through
a customer-owned wallet, and records a signed receipt for every outcome.

This remains a **design-and-spike repository**, not a production product. The
current Wallet Kernel evidence is offline and deterministic. The networked mode
is constrained by design to test USDC on Base Sepolia but has **not been run**;
mainnet and real funds are unsupported. See the
[approved design](docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md)
for the complete product, security, and acceptance boundaries.

The commercial v1 is spending policy, auditability, and reconciliation:

- customer-hosted policy enforcement and authoritative records;
- a customer-owned wallet, with CDP as the first adapter;
- default-deny budgets, allow-listed sellers, and exact one-time approvals;
- x402 v2 `exact` payments only;
- durable recovery and signed receipts for settled, failed, refunded, and
  unresolved outcomes.

It is not wallet custody, token trading, an inference reseller, or a
marketplace. Skill attribution and Creator compensation are deferred expansion
modules: they may later consume Wallet Kernel receipts, but they do not define
the v1 operator experience.

## Pre-release website candidate

The source in [`site/`](site/) is an offline, deterministic candidate preview of
the wallet-control product. It demonstrates policy loading, automatic allow,
deny, exact approval, deliberate retry, and an unsigned session projection. It
does not connect a wallet, sign a receipt, or broadcast a transaction.

The approved design's release gate remains binding: this candidate must not
replace the public homepage until the required implementation and fresh,
recomputable evidence qualify. The separate `/proof` route is a static archive
with one narrowly supported historical Base Sepolia receipt; the website no
longer exposes a wallet or paid invocation endpoint.

### Run the website locally

Use Node 22, then run from the repository root:

```bash
cd site
npm ci
npm run dev
```

Open <http://localhost:3000>. The homepage needs no environment file, account,
wallet, API key, network request, or payment.

## First commercial offer

The first paid offer is a customer-hosted design-partner pilot for one Pi
workflow, one customer-owned CDP testnet wallet, and one or more allow-listed
Base Sepolia x402 resource servers. The pilot adds customer-defined automatic
and approval-required policy, durable budgets and restart recovery, a local
operator console, signed receipt and reconciliation export, and a final control
review.

This pilot is intended to test whether an AI platform or gateway team will pay
for governed autonomous spending. That demand has not yet been validated.

## Evidence status

One public historical claim is supported by the retained evidence manifest:
on 2026-07-12, a successful Base Sepolia transaction transferred `250000`
atomic units (`0.25`) of test USDC, and the repository's historical run log
labels it as the Skill-leg settlement. See the
[receipt manifest](spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json).

That receipt does **not** prove current endpoint behavior, latency,
Royalty-claim split correctness, Skill execution output, independent demand, or
production readiness. A later aggregate timing summary is quarantined and is
not used in product claims because its normalized samples were not retained;
see its
[non-publishable manifest](spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json).

All current product-preview states and receipts are deterministic simulations.
A future testnet product claim requires a fresh, immutable, recomputable
evidence bundle as specified in the approved design.

## Try the existing proofs offline

The repository also retains earlier attribution, settlement, provenance, and
clone-economics research. These are inputs to the Wallet Kernel work or deferred
research; they are not proof that the commercial v1 is complete.

| Where | Command | Scope |
|---|---|---|
| `site` | `npm test` | Deterministic wallet-control preview and public-claim guards |
| `spikes/pi-wielder` | `npm ci && npm test && npm run e2e` | Offline wallet policy, x402, journal, receipt, and failure-path spike |
| `spikes/clone-economics` | `npm run e2e` | Deterministic clone-distillation research |
| `prototype` | `npm test` | Settlement and attribution accounting invariants |
| `phase0` | `npm ci && npm test` | Story provenance behavior against injected fakes |

These automated paths require no funded wallet or network payment. Follow each
directory's README for its exact environment and safety boundary.

## What's here

- **`docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md`**
  — the approved Wallet Kernel and commercial-pilot design.
- **`site/`** — the pre-release offline wallet-control candidate and a separate
  static historical proof archive.
- **`spikes/pi-wielder/`** — the hardened wallet, policy, x402, journal,
  receipt, refund, and reconciliation evidence that the Wallet Kernel will
  evolve from.
- **`CONTEXT.md` and `docs/adr/`** — the canonical protocol language and prior
  decisions. The compensation and attribution model remains longer-term
  research rather than the v1 product interface.
- **`prototype/`** — settlement and attribution accounting logic plus economic
  spikes.
- **`phase0/`** — Story Protocol provenance experiments on Aeneid testnet only.
- **`.claude/skills/` and `.agents/skills/`** — the intentionally public example
  Skill used by earlier spikes.

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2026 Antony Zaki
([Aznatkoiny](https://github.com/Aznatkoiny)).

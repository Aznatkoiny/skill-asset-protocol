# Pi-Wielder spike — Collar-authoritative Invocations

Design context: [Pi-Wielder design](../../docs/plans/2026-07-11-reframe-and-pi-wielder-design.md).

This is an executable design spike, not a production payment service. Its automated
proof is fully offline: an unfunded throwaway wallet signs x402 authorizations, an
injected mock verifies the signatures and synthesizes settlement, and canned model
responses avoid external APIs.

## Accounting authority

The Collar's append-only Invocation journal is authoritative for hosted Skill
Invocations. Payment and execution are independent state machines, so a settled
Invocation remains attached to its transaction when execution fails or a response is
lost. The journal freezes the complete x402 offer, atomically claims execution and
refund attempts, records accounting, and issues an Ed25519-signed terminal receipt.

The Wielder's `/ledger` endpoint is a session-local **receipt view**, not an
authoritative protocol ledger. For Skill legs it caches a receipt only after verifying
the signature against a separately pinned Collar public key and checking that the
receipt matches the current idempotency key, request hash, quote, payer, settlement,
transaction, terminal HTTP status, and gross amount. It renders finalized claims from
that receipt; it never calculates Royalty claims itself. Model legs have no Collar
receipt and remain local payment observations.

Mock receipts use an ephemeral Collar key unless paired persistent paths are supplied.
Mock transaction hashes and timings are synthetic protocol evidence. They are not
evidence of live funds, mainnet readiness, production custody, distributed locking, or
durable production key management.

## Wielder payment policy

The Wielder does not accept the first x402 offer blindly. Before signing, it requires
the exact Base Sepolia network (`84532`) and Base Sepolia USDC contract, a canonical
trusted seller route and payee, an exact resource and request-byte match, a fresh
bounded-time quote, a per-call cap, and remaining session budget. The policy rejects
numeric or coerced atomic amounts, unknown protocol fields, caller-supplied payment or
idempotency headers, ambiguous URL forms, and path-prefix confusion.

The caller's method, body bytes, and headers are captured once before the unpaid
request. Method and body bytes bind the policy hash and signed recovery; captured
headers are reused for the unpaid and paid requests but are not signed or covered by
the request hash. Redirects are disabled on both requests. Validated policy limits and
seller rules are snapshotted at construction. The trusted clock rejects backward
movement and rechecks age from both local receipt and server issue time after challenge
parsing and immediately before the paid retry.

Budget is synchronously reserved before signing. The exact authorization, signature,
and encoded `X-PAYMENT` value are stored before the one paid retry begins. A recovery
path can reuse those exact stored bytes after a local interruption; it never creates a
replacement signature. A changed second offer, another `402`, a lost retry response,
or missing/mismatched settlement evidence aborts without exposing the upstream body
and retains the amount as `unresolved`. Only exact response evidence or an injected
trusted reconciliation capability may advance that state.

An ordinary signer rejection before a signature is returned releases its unsigned
reservation. Any persistence failure after a signature return remains conservatively
`unresolved`. Trusted reconciliation callbacks cannot reenter a monetary transition,
and every monetary commit enforces non-negative, conserved session-budget counters.

This policy is an in-memory, one-process session control. Restarting the proxy loses
its policy snapshot, so this is not production spend enforcement and provides no
cross-restart budget guarantee. A durable deployment must persist and replay signed
authorizations, reject nonce and transaction reuse across workers, and reconcile every
unresolved reservation before it can advertise such a guarantee.

## What the offline proof demonstrates

`npm run e2e` exercises one wallet across two paid asset classes without opening a
socket:

1. Model inference and a hosted Skill both return an x402 `exact` challenge before
   execution.
2. The Wielder signs one EIP-3009 authorization per challenge and retries with the same
   Wielder-owned idempotency key after the local payment policy reserves budget.
3. The Collar records one authoritative external Invocation and returns derived output
   plus a signed receipt. The hosted `SKILL.md` bytes are read server-side and are not
   directly returned.
4. An exact terminal retry returns the same receipt without another settlement or Skill
   execution. Different request bytes under the same key return `409`.
5. A lost settlement response becomes `unresolved`; exact retries return `503` and do
   not verify, settle, or execute again until a trusted resolver advances it. The
   Wielder withholds the response body and retains the exact budget reservation.
6. The Wielder view contains canonical atomic-USDC strings. Finalized Skill claims are
   projected from the signed receipt; a failed full-gross hold produces no invented
   creator or treasury claim.

The displayed successful mock session currently looks like:

```text
claude/plan $0.041 [succeeded] · gpt/implement $0.087 [succeeded] · skill/optimizing-claude-code-prompts $0.25 [succeeded] → creator $0.24375 / treasury $0.00625
  session receipt total $0.378 across 3 settled calls, one wallet
```

This is a payer-side view across independent sellers. It is deliberately not described
as a unified authoritative ledger.

## Failure and refund semantics

- Settlement success is never erased by a later `400` or `500` execution outcome.
  Exact terminal replay preserves that HTTP status. An unknown Skill is rejected with
  `404` before the Collar offers or claims payment.
- If the Skill executor fails after settlement, the receipt records one full-gross
  `pending_cogs_reconciliation` hold. No Royalty or treasury claim is finalized.
- A response lost after the provider returns leaves the durable execution attempt
  `executing`; retries return `503` rather than call the provider twice.
- Settlement reconciliation accepts no caller-supplied transaction proof. An injected
  trusted resolver must return the exact settlement reference, payer, gross atomic
  amount, and transaction hash.
- Refund execution is also atomically claimed. An ambiguous or crashed external refund
  remains unresolved and is never executed a second time. A separate trusted refund
  resolver may confirm it.
- Refund v1 is intentionally narrow: only a settled terminal failure with one exact
  full-gross hold and no finalized claims is refundable. Confirmation must match payer,
  settlement reference, original transaction, and full gross. The signed revision
  supersedes the original receipt and carries balanced hold-reversal and refund entries.
- Provider and resolver exception details are replaced with stable public errors; API
  response bodies and secret-bearing exception strings are not copied into receipts.

## Architecture

```text
Pi or another HTTP client
          │
          ▼
src/proxy.mjs — Wielder wallet + paying fetch + local receipt view
          │
          ├── /v1/* ─────► src/gateway.mjs (model seller)
          │
          └── /invoke/* ─► src/collar.mjs (Skill seller)
                                  │
                                  ├── authoritative signed JSONL journal
                                  ├── server-side Skill artifact
                                  └── signed terminal receipt

Both sellers use an explicitly constructed facilitator transport.
Offline tests inject src/facilitator-mock.mjs; no arbitrary URL is accepted.
```

The proxy demonstrates the wallet-bound HTTP 402 transport shape contemplated by
ADR-0008 plus a conservative one-process payment policy, but it contains no Story SDK,
token custody, or Royalty calculator. It is not proof of the complete protocol,
cross-process spend enforcement, or production readiness.

## Run the verified path

```bash
npm install
npm test
npm run e2e
```

Expected current results are 141 offline unit/integration tests and 30 offline e2e
checks. Counts can increase as regressions are added; zero failures is the contract.
The e2e labels all timing output synthetic and uses in-process Hono requests only.

Focused commands:

```bash
npm run test:journal
npm run test:collar
npm run test:proxy
npm run test:policy
npm run test:payment
```

For standalone mock processes, persistent trust bootstrapping, and the intentionally
blocked live boundary, see [RUNBOOK.md](./RUNBOOK.md).

## Files

| File | Role |
|---|---|
| `src/invocation-journal.mjs` | Authoritative transition reducer, persistent signed JSONL, indexes, receipts, reconciliation, and refund claims |
| `src/collar.mjs` | Hosted Skill boundary, execution outcomes, receipts, settlement/refund operator routes |
| `src/x402-seller.mjs` | Seller x402 v1 `exact` middleware and approved transport constructors |
| `src/proxy.mjs` | Wielder wallet, paying fetch, pinned receipt verification, and local receipt view |
| `src/payment-policy.mjs` | Strict Base Sepolia offer validation, one-process reservation state, exact signed authorization recovery, and trusted reconciliation boundary |
| `src/ledger.mjs` | JSONL-capable Wielder receipt-view storage and rendering |
| `src/gateway.mjs` | Simulated x402 model reseller |
| `src/facilitator-mock.mjs` | Offline signature verification plus synthetic settlement |
| `pi-extension/x402.ts` | Manual Pi adapter for provider, Skill tool, and `/ledger` view |
| `e2e.mjs` | Fully in-process offline proof |

## Security and operational boundaries

- Base Sepolia only; no mainnet and no real funds in automated verification.
- Live facilitator construction accepts only the byte-exact approved HTTPS base and
  disables redirects for `/verify` and `/settle`.
- Live settlement requires paired absolute journal/private-key paths outside the
  checkout plus injected trusted settlement, refund-execution, and refund-resolution
  adapters. The standalone CLI intentionally provides no such live adapters and refuses
  to start live.
- Persistent files are regular non-symlink files with mode `0600`. Same-host writers use
  a signed hash chain, fsync, a process lease, and compare-and-swap transitions. This is
  not a distributed consensus mechanism.
- The proxy trusts an operator-pinned public key file and one SHA-256 key ID of its SPKI
  DER. A key ID or key embedded in a receipt cannot authenticate that receipt.
- The Pi extension is a manual demo adapter and is not compiled by this spike's test
  suite.
- Successful mock accounting currently passes zero execution and settlement COGS into
  the atomic allocator. That is explicit spike behavior, not a validated production
  margin model.

## Protocol implementation note

The published `@x402/*` packages evaluated for this spike implement a different
protocol/version shape than the free testnet facilitator used by the original research.
This spike therefore keeps the small x402 v1 buyer and seller boundaries explicit and
uses `viem` for EIP-712 signing and verification.

## Historical network evidence — not current verification

An earlier pre-journal version was exercised on Base Sepolia on 2026-07-12. That run
observed two paid legs (Claude and one Skill), 0.332 testnet USDC received in total, and
one instrumented payment-overhead sample of roughly 781 ms. The current
Collar-authoritative implementation was **not** rerun against live infrastructure in
this remediation, so those figures are historical context rather than evidence for the
current code.

A separate 2026-07-15 overhead summary is quarantined at
[`evidence/2026-07-15-overhead/manifest.json`](./evidence/2026-07-15-overhead/manifest.json)
with `evidenceStatus: historical_unreproducible`. Its sample count and percentiles must
not be used in public claims until a new authorized run retains per-call evidence.

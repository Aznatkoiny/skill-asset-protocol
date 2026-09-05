# Pi-Wielder spike - Agent Spend Control Plane

Design context: [Pi-Wielder design](../../docs/plans/2026-07-11-reframe-and-pi-wielder-design.md).

This is an executable design spike, not a production payment or custody service. Pi is
the **Wielder**. The Agent and Operator are local control-plane security roles: the
Agent may ask the Wallet Kernel to use an operator-approved route, while the Operator
sets policy, decides approvals, reconciles ambiguous outcomes, and reviews signed
receipts. Pi never receives the wallet signer, CDP credentials, operator bearer, or a
caller-selected destination capability.

The directory retains the earlier Collar-authoritative seller proof and now adds a
durable Wielder-side Wallet Kernel around it. The Kernel authenticates one enrolled Pi
instance, binds it to one Spend Session, evaluates immutable PolicyVersions, enforces
per-request, per-seller-session, session, and rolling-24-hour ceilings, persists intent
state before signing or retrying, and emits signed receipt revisions. The route map —
root-owned and manifest-covered in live mode — not Pi, selects the method and upstream
seller.

## Current spend-control status

| Mode | What has been exercised | Honest status |
|---|---|---|
| `offline-deterministic` | Real local child processes, SQLite authority, policy/approval paths, restart recovery, deterministic x402 settlement, Pi adapter path, signed per-session projections, and recomputable evidence | **Measured offline**; wallet, deployment, and OS isolation are explicitly simulated. No external provider or chain is contacted. |
| `cdp-testnet` | The prepared-release installer, privileged preflight, Kernel credential delivery, native listeners, and durable runtime composition have offline tests | **Not run.** Actual Linux/systemd lifecycle qualification remains incomplete. Both installed entrypoints stop with `LIVE_LAUNCH_NOT_READY` (exit 78); there is no override switch. |
| Mainnet | No mode, route, deployment, or evidence path exists | **Out of scope and unsupported.** No automated funding, mainnet transaction, or real-funds operation is allowed. |

An offline pass is not evidence of live isolation, CDP payment, wallet funding, or a
Base Sepolia transaction. The current implementation must not be used to reframe public
website claims until a fresh, human-authorized, externally anchored testnet evidence
bundle qualifies. Historical network results remain separately labeled below.
`run-evidence.mjs --mode base-sepolia-testnet` currently exits 2 with
`EVIDENCE_TESTNET_NOT_RUN`; it does not construct a real wallet adapter.

The control boundary is:

```text
Pi (Wielder; Pi-owned Agent credential)
              |
              v
loopback Agent API -> fixed route map -> Wallet Kernel -> CDP wallet adapter
                                          |                 (testnet only)
                                          +-> SQLite authority + budgets
                                          +-> approval queue
                                          +-> signed receipts/session projections

Operator CLI -> owner-only bearer -> Unix admin socket in live design
Operator console -> root socket-activated loopback listener -> one-time fragment
```

The automated proof is fully offline: an unfunded throwaway wallet signs deterministic
x402 authorizations, injected adapters verify and synthesize settlement, and canned
model responses avoid external APIs. Mock execution is fail-closed and remains the
default when `MOCK_LLM` is unset.

## Agent approval and call identity

Approval is asynchronous at the Agent boundary. Pi receives
`payment_approval_required` immediately, and the Operator decides through the separate
Operator interface. If approved, the Wielder repeats the ordinary request. Neither
the proxy nor Pi keeps the original HTTP request connected, polls for approval, or
performs an application-level automatic replay.

Each logical call carries a canonical 32-byte `x-agent-call-id`. It is only a durable
deduplication/correlation key, scoped beneath the authenticated Agent credential and
Kernel-owned Spend Session, then bound to the exact request fingerprint. It cannot
identify or authorize an Approval, wallet, seller, payee, amount, policy, payment
idempotency key, signature, or payment header, and the proxy never forwards it to the
seller. The approval continuation repeats the exact ordinary request and preferably
reuses its call ID when Pi retains it. A fresh continuation ID is also valid: while the
exact fingerprint remains retry-matchable, the Kernel atomically binds that ID as a
correlation alias to the active intent before signing. Changing the fingerprint under
an already bound ID fails closed, while another credential/session cannot use the key
to access the prior intent.

The only automatic same-key replay is one lower-level retry when the local Skill's
`fetch` throws or reading the response body fails. This lets a settled response loss
resolve to the existing receipt instead of spending twice. A received invalid content
type, malformed JSON, `payment_approval_required`, or any other application result is
never automatically retried. The model hook retains its call key across an error until
Pi reports a terminal outcome. Every later legitimate Skill or model call receives a
fresh key, even when its ordinary payload is identical to an earlier terminal call.
For an identical payload, that key creates a new intent only when no active
retry-matchable intent exists and the key has no prior binding or alias; otherwise it
resolves to the existing intent.

## Legacy Collar accounting authority

The Collar's append-only Invocation journal is authoritative for hosted Skill
Invocations. Payment and execution are independent state machines, so a settled
Invocation remains attached to its transaction when execution fails or a response is
lost. An unpaid x402 offer is not authority: the paywall holds at most 128 such offers
in process memory for at most 60 seconds. Only after the facilitator verifies the exact
signed authorization does the Collar append the Invocation, frozen offer, verified
payment-header digest, and signed payment claim. Durable replay accepts only that exact
authorization. Legacy journal entries without the digest are reverified instead of
being trusted implicitly. The journal then owns all signed, unresolved, settled,
execution, refund, and terminal state; pending-offer expiry never prunes that authority.
It atomically claims execution and refund attempts, records accounting, and issues an
Ed25519-signed terminal receipt.

This boundary deliberately fails closed across one restart window. If the Collar
restarts after returning `402` but before a verified retry is journaled, the old paid
retry receives `409` because no authoritative frozen offer exists. It is not submitted
to the facilitator and it cannot execute. The Wielder keeps that signed authorization
unresolved until an operator reconciles its nonce, then uses a new idempotency key.
Once verified state reaches the journal, the durable reconciliation and exact replay
rules apply.

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

## Legacy one-process Wielder payment policy

The Wielder does not accept the first x402 offer blindly. Before signing, it requires
the exact Base Sepolia network (`84532`) and Base Sepolia USDC contract, a canonical
trusted seller route and payee, an exact resource and request-byte match, a fresh
bounded-time quote, a per-call cap, and remaining session budget. The policy rejects
numeric or coerced atomic amounts, unknown protocol fields, caller-supplied payment or
idempotency headers, ambiguous URL forms, and path-prefix confusion.

The seller accepts only canonical `Idempotency-Key` values: 1-128 ASCII letters, digits,
periods, underscores, colons, or hyphens, beginning with a letter or digit. A new unpaid
key receives `503 PENDING_OFFER_CAPACITY` when all 128 pending slots are active; an
existing active key can still retrieve its exact frozen challenge. Expired unpaid slots
are the only offer state reclaimed by this admission control.

The standalone, non-authoritative paywall can consume an authorization only once. Before
verification it atomically claims the fixed network, asset, payer, and nonce for one
Idempotency-Key, with the exact payment-header hash bound to that owner. Cross-key and
alternate-encoding replays fail before another facilitator or handler call; a successful
claim remains through its frozen offer validity window in the same bounded TTL-scoped
admission state. Authorization times must match that frozen offer exactly. It cannot
replay lost output; durable terminal replay belongs to the Collar journal. Facilitator
verification succeeds only for the exact boolean `true`.

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

## What the legacy offline proof demonstrates

`npm run e2e` exercises one wallet across two paid asset classes without opening a
socket:

1. Model inference and a hosted Skill both return an x402 `exact` challenge before
   execution.
2. The Wielder signs one EIP-3009 authorization per challenge and retries with the same
   Wielder-owned idempotency key after the local payment policy reserves budget.
3. The Collar records one authoritative external Invocation and returns derived output
   plus a signed receipt. The Collar does not directly return or serialize the hosted
   Skill artifact. A narrow runtime guard rejects full or long exact artifact fragments.
   Model-output extraction can never be ruled out categorically; prompt-injection
   resistance remains adversarial test evidence, not a secrecy guarantee.
4. An exact terminal retry returns the same receipt without another settlement or Skill
   execution. Different request bytes under the same key return `409`.
5. A lost settlement response becomes `unresolved`; exact retries return `503` and do
   not verify, settle, or execute again until a trusted resolver advances it. The
   Wielder withholds the response body and retains the exact budget reservation.
6. The Wielder view contains canonical atomic-USDC strings. Finalized Skill claims are
   projected from the signed receipt; a failed full-gross hold produces no invented
   creator or treasury claim.

For the deterministic mock fixture, a 250,000-atomic-USDC gross Invocation allocates
756 to synthetic-config execution COGS, 1,000 to settlement cost, 6,250 to protocol
fee, 5,000 to refund reserve, and 236,994 to the Royalty pool. These are mock accounting
values, not observed live provider economics. If provider usage is missing, the settled
Invocation fails `COGS_UNKNOWN`, emits no output or Royalty credits, and holds full gross
in `pending_cogs_reconciliation` until trusted reconciliation or refund.

The complete payer-side mock session totals 378,000 atomic USDC across two model calls
and one hosted-Skill Invocation. It is deliberately not described as a unified
authoritative ledger.

The quoted execution catalog is immutable and versioned. Its initial rates are labeled
`synthetic_config`; they are proof fixtures rather than current provider pricing.

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

The new Wielder-side control plane is composed from `src/control-plane.mjs`. It keeps
Agent admission, Operator authority, policy decisions, wallet signing, and public
projections as separate capabilities. The deterministic acceptance runner supplies the
offline graph. `src/runtime/installed-service.mjs` verifies the installed process,
release, PID1 configuration, activation descriptor, and isolation report before
`installed-runtime.mjs` loads PID1-delivered credentials and composes the real authority,
wallet adapter, observer, Agent listener, and Operator transports. The executable gate
remains closed pending actual Linux lifecycle qualification. See [RUNBOOK §10](RUNBOOK.md#10-clean-install-bootstrap-and-the-intentional-live-block).

```text
Pi or another HTTP client (legacy Collar demonstration)
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

The legacy proxy demonstrates the wallet-bound HTTP 402 transport shape contemplated by
ADR-0008 plus a conservative one-process payment policy. The Wallet Kernel adds durable
cross-restart spend authority for the Pi Agent, but neither path contains a Story SDK,
token custody product, hosted policy authority, or Royalty calculator. This spike is not
proof of the complete protocol or production readiness.

## Run the verified path

Use a POSIX host and Node 24.18.1 or newer for deterministic development. The future
attested live release is stricter: it requires Linux/systemd and exactly Node 24.18.1.
From this directory, install the lockfile exactly and run the complete offline story:

```bash
npm ci
npm run verify:spend-control
```

The acceptance path starts real local child processes where the host permits loopback
listeners. Results are still **measured offline**: the wallet adapter and settlement are
deterministic, and identity/deployment isolation is marked simulated. A sandbox that
forbids local listeners may report those process checks as skipped; a skip is not a
passing live-host result.

Generate a fresh sanitized offline evidence bundle and keep its manifest digest outside
the bundle:

```bash
evidence_parent="$(mktemp -d /tmp/pi-wielder-evidence.XXXXXX)"
evidence_parent="$(cd "$evidence_parent" && pwd -P)"
npm run evidence:offline -- \
  --output "$evidence_parent/bundle" \
  --anchor-output "$evidence_parent/manifest.sha256"
manifest_sha256="$(tr -d '\n' < "$evidence_parent/manifest.sha256")"
npm run evidence:verify -- "$evidence_parent/bundle" \
  --expect-manifest-sha256 "$manifest_sha256"
npm run verify:no-secrets
```

The bundle contains exactly `manifest.json`, `events.jsonl`, `summary.json`,
`report.md`, and `README.md`. Verification requires the external manifest hash,
recomputes normalized events, verifies every per-session projection signature, and
requires the signed receipts to partition exactly once across those projections. It
never treats a hash read from inside the bundle as its trust anchor. Offline evidence records
`liveCdp`, `walletFunded`, and `testnetTransaction` as `not-run`.

Focused commands:

```bash
npm run test:journal
npm run test:collar
npm run test:proxy
npm run test:policy
npm run test:payment
npm run test:economics
npm run test:kernel
npm run test:systemd
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
| `src/runtime-boundaries.mjs` | Composed wall-clock deadlines plus streaming byte-limited body and JSON readers |
| `src/ledger.mjs` | JSONL-capable Wielder receipt-view storage and rendering |
| `src/gateway.mjs` | Fail-closed x402 model reseller with catalog, spend, and provider runtime bounds |
| `src/facilitator-mock.mjs` | Offline signature verification plus synthetic settlement |
| `pi-extension/x402.ts` | Manual Pi adapter for provider, Skill tool, and `/ledger` view |
| `e2e.mjs` | Fully in-process offline proof |
| `src/control-plane.mjs` | Wallet Kernel composition boundary for Agent and Operator apps; direct live composition fails closed |
| `src/kernel/wallet-kernel.mjs` | Coordinated intent, policy, approval, budget, payment, execution, reconciliation, and receipt authority |
| `src/spend-control-proxy.mjs` | Agent-authenticated fixed-route API used by Pi; no caller-selected destination or wallet capability |
| `src/operator/` | Owner-authenticated local API, CLI, and one-time browser-console launch flow |
| `src/adapters/` | Deterministic test wallet plus CDP testnet wallet and read-only Base Sepolia observation boundaries |
| `scripts/lib/spend-control-process-runner.mjs` | Reused real-process deterministic acceptance runner |
| `src/evidence-bundle.mjs` and `scripts/verify-evidence.mjs` | Sanitized five-file evidence builder and externally anchored independent verifier |
| `deploy/systemd/` and `scripts/preflight-live-deployment.mjs` | Root-owned deployment contract and explicit `LIVE_LAUNCH_NOT_READY` live gate |
| `scripts/install-live-deployment.mjs` | Verifies and seals a prepared, committed release and exact unit artifacts; never starts a service |
| `src/runtime/` | Installed bootstrap, PID1 credential loader, authority composition, and native listeners |

## Security and operational boundaries

Every body limit is enforced while chunks arrive, including when `Content-Length` is
absent. A declared oversize is rejected before the body is pulled. The Collar and its
default x402 middleware accept at most exactly 4,096 request bytes; 4,096 is accepted
and 4,097 is rejected before an offer. The model gateway and proxy model route accept
at most 1 MiB, while the proxy Skill route keeps the 4,096-byte contract. Buyer x402
challenges and facilitator JSON responses are capped at 64 KiB. Gateway provider JSON
and proxy upstream responses are capped at 1 MiB.

Default wall-clock bounds are 15 seconds for the unpaid buyer fetch, 30 seconds for
the signed paid retry, 5 seconds for x402/proxy request-body reads, 10 seconds for each
facilitator verify and settle operation, and 30 seconds for provider execution and
proxy upstream-response reads. The provider deadline includes both fetch and streamed
body consumption and cannot be configured above 30 seconds. Caller abort signals are
composed into child signals; an internal timeout never aborts the caller's controller.
Redirects remain disabled.

Before returning a gateway offer, the reseller validates a closed OpenAI-compatible
request contract: allowed model, non-empty canonical message roles and text parts,
function tools/calls/results, output-token bound, and provider-specific option types and
ranges. Malformed JSON, unknown fields, and unsupported shapes receive a stable `400`
without facilitator settlement or provider work. Anthropic options are either translated
explicitly or rejected; unsupported tool `strict` semantics are never silently dropped,
and system/developer-only input is rejected before it can translate to no provider message.

Timeout state follows the durable money boundary: an unpaid timeout creates no
reservation; a signed retry or facilitator ambiguity stays `unresolved` with budget
held; and a provider timeout after settlement finalizes a sanitized failed receipt,
unknown COGS, one full-gross reconciliation hold, no output, and no Royalty credits.
Raw transport and provider errors are not returned or journaled. The manual Pi tool
has no caller-selected Skill route: it invokes only the fixed, encoded
`optimizing-claude-code-prompts` path.
Withheld paid output and unsuccessful facilitator or provider response bodies are
cancelled without being consumed or exposed.

Live model execution requires the exact combination of `MOCK_LLM=0`,
`ALLOW_LIVE_PROVIDER=1`, live x402 settlement through the pinned approved facilitator,
a `human_verified` immutable catalog, its exact operator-approved
digest, a cumulative process-run spend cap covering at least the maximum worst-case
request across all allowed models, and the relevant provider key. Each live call reserves
its request's worst-case catalog cost after payment verification and before facilitator
settlement. Success commits actual provider usage, while an ambiguous or failed provider
outcome consumes the full reservation. Exhaustion therefore blocks settlement and
provider fetch for another paid retry. This in-memory cap resets on restart and is not
durable or cross-process. The committed catalog is `synthetic_config`, so default and
standalone gateway startup remain mock/fail-closed. Model allowlisting plus strict
input/output bounds run before an x402 offer; the conservative input bound adds a
1,024-token provider-framing reserve to the raw request-byte upper bound. Non-success
provider bodies are never consumed, and stable sanitized errors replace all provider
detail.

- Base Sepolia only; no mainnet and no real funds in automated verification.
- Live facilitator construction accepts only the byte-exact approved HTTPS base and
  disables redirects for `/verify` and `/settle`.
- A mock facilitator can authorize mock execution only. Both the Collar and gateway
  reject live-provider construction unless the authorized facilitator transport is live.
- Live settlement requires paired absolute journal/private-key paths outside the
  checkout plus injected trusted settlement, refund-execution, and refund-resolution
  adapters. The standalone CLI intentionally provides no such live adapters and refuses
  to start live.
- Persistent files are regular non-symlink files with mode `0600`. Same-host writers use
  a signed hash chain, fsync, a process lease, and compare-and-swap transitions. This is
  not a distributed consensus mechanism.
- The proxy trusts an operator-pinned public key file and one SHA-256 key ID of its SPKI
  DER. A key ID or key embedded in a receipt cannot authenticate that receipt.
- The Pi extension is pinned to Pi `0.80.6`; offline tests import its TypeScript,
  exercise the real five-argument tool ABI, and pin fixed model/Skill routes plus the
  single transport-loss same-key retry. Installing it into a Pi host remains manual.
- Successful mock accounting records synthetic-config provider usage and allocates
  execution COGS and settlement cost before the Royalty pool. It is executable evidence
  of ordering and conservation, not a validated production margin model or current
  provider-price claim.

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

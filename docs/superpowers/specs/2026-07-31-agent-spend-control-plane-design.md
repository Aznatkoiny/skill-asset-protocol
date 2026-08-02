# Agent Spend Control Plane — Design

- **Status:** Approved in design review on 2026-07-31
- **Approval-flow amendment:** Approved on 2026-08-02
- **Implementation base:** `codex/prd-execution` at
  `6f7006055cd14ca0b5c5961c7d0a3d09eff044ef`
- **Initial network:** Base Sepolia (`eip155:84532`)
- **Funding:** Test USDC only; no real funds or mainnet transactions

## 1. Summary

Build a customer-hosted **Agent Spend Control Plane** that gives an AI agent
bounded economic agency without giving the agent wallet custody or unrestricted
signing access.

Pi is the first reference client. The product's central module is a **Wallet
Kernel** evolved from the hardened Pi-Wielder proxy. It converts ordinary agent
HTTP requests into canonical Spend Intents, evaluates customer policy, obtains
human approval when required, signs only permitted x402 payments through a
customer-owned wallet, and maintains a durable signed receipt for every outcome.

The product is:

- wallet-native;
- on-chain anchored for payment settlement;
- off-chain executed for model and tool work;
- customer-hosted for policy enforcement and authoritative records;
- x402-only in v1;
- provider-neutral at its wallet seam, with CDP as the first adapter.

The commercial product is spending policy, auditability, and reconciliation. It
is not wallet custody, token trading, an inference reseller, or a marketplace.

## 2. Product decision

The first buyer is an AI platform or gateway team that needs to answer:

> Can our agents buy API resources autonomously while remaining inside explicit
> budgets, approved sellers, human escalation rules, and a complete audit trail?

The first paid offer is a customer-hosted design-partner pilot around one Pi
workflow, one customer-owned CDP wallet, and one or more Base Sepolia x402
resource servers.

Skill attribution and Creator compensation are deferred expansion modules. They
may later consume the Wallet Kernel's receipts, but they do not determine the v1
interface or operator experience.

## 3. Goals

1. Allow Pi to pay an approved x402 request automatically.
2. Deny an unapproved seller or over-budget request before any signature.
3. Queue an out-of-policy request for exact human approval.
4. Preserve monetary and approval state across process restart.
5. Produce a signed, independently verifiable receipt for every terminal outcome.
6. Reconcile ambiguous signed, settled, failed, and refunded operations without
   double-signing or inventing balance.
7. Keep wallet credentials, policy authority, and the authoritative journal in
   the customer environment.
8. Reuse the hardened request binding, budget conservation, receipt, refund, and
   reconciliation behavior already present on `codex/prd-execution`.

## 4. Non-goals

V1 does not include:

- Base mainnet or any real funds;
- arbitrary wallet transfers;
- token trading, swaps, bridging, staking, or yield;
- arbitrary smart-contract calls;
- Story registration or royalty settlement;
- Creator compensation or employer reward pools;
- an open Skill Marketplace or registry;
- wallet key export or product custody;
- multiple operators, SSO, SCIM, or organization RBAC;
- mobile approval;
- a hosted service that can authorize spending;
- raw prompt or model-output storage;
- x402 `upto` or non-EVM schemes; v1 supports x402 v2 `exact` only.

These exclusions are product and security boundaries, not unfinished acceptance
criteria.

## 5. Roles and authority

### Agent

Pi or another HTTP-capable client. It requests a resource and receives the
resource response, a stable denial, or an approval-required result. It cannot
access wallet credentials, construct payment headers, change policy, approve an
intent, or invoke a signing interface.

### Operator

The human authorized to apply policy versions, approve or deny pending intents,
inspect receipts, and initiate trusted reconciliation. In v1 there is exactly one
local operator authority.

### Customer wallet

A wallet inside the customer's own CDP project. CDP credentials stay inside the
customer's local or VPC deployment. The product does not receive or store a raw
private key.

### Wallet Kernel

The authoritative local module for intent, policy, budget, approval, payment,
execution outcome, refund, reconciliation, and receipt state.

### Resource server

An x402 v2 seller that returns a challenge for an approved HTTP resource and
provides canonical settlement evidence after payment.

## 6. Architecture and trust boundaries

```text
Pi or another agent
        | ordinary HTTP request
        v
Local Agent Adapter
        | canonical Spend Intent
        v
Wallet Kernel
  |-- Intent Builder
  |-- Policy Engine
  |-- Budget Ledger
  |-- Approval Queue
  |-- Durable Journal
  |-- x402 v2 Transport
  |-- Wallet Adapter
  `-- Receipt Signer
        | scoped x402 signing
        v
Customer-owned CDP wallet
        | test-USDC authorization
        v
x402 resource server
```

The authoritative path runs locally or in the customer's VPC. It does not depend
on a vendor-hosted dashboard. A later hosted dashboard may receive sanitized,
signed, read-only projections, but it cannot apply policy, approve an intent,
request a signature, or reconcile money.

The blockchain proves that value moved. It does not prove the agent's purpose,
the usefulness of returned output, policy compliance, execution success, or
refund entitlement. The Wallet Kernel's signed journal records those distinct
facts without collapsing them into a chain transaction.

## 7. External interfaces

### 7.1 Agent interface

The agent uses a loopback HTTP proxy. Pi points its model provider or tool URL at
that proxy and otherwise behaves as a normal HTTP client.

The proxy returns one of:

- the upstream resource response plus a compact local receipt reference;
- `payment_approval_required` with a request ID and expiry;
- a stable policy or protocol denial;
- a stable unresolved-payment or reconciliation error.

Every Agent execution request carries a stable, canonical 32-byte
`x-agent-call-id`. It is only a deduplication and correlation key. The proxy scopes it
beneath the authenticated Agent credential and resulting Spend Session, then binds it
to the exact ordinary-request fingerprint. Within that scope, reuse for a different
fingerprint fails closed; presenting the same key through another credential or session
cannot access the prior intent. The key cannot select or convey an Approval, wallet,
seller, payee, amount, PolicyVersion, Spend Session, payment idempotency key, payment
signature, or other spending authority, and it is never forwarded to the resource
server.

If an exact request arrives under a fresh call ID while a retry-matchable intent for
that fingerprint remains active, the Kernel atomically binds the fresh ID as a
correlation alias to the existing intent before any signing transition. It does not
create a second intent. A fresh ID creates a later legitimate identical intent only
when no active retry-matchable fingerprint exists and that ID has no prior binding or
alias.

The agent cannot supply `PAYMENT-SIGNATURE`, payment identity, idempotency, or
approval headers. The proxy exclusively owns those fields.

At startup, the local adapter opens a kernel-issued Spend Session bound to the
configured adapter identity, customer wallet, and active policy. Requests inherit
that opaque session identity; Pi cannot choose or replace it.

### 7.2 Operator interface

The operator uses a local CLI and loopback-only admin endpoint to:

- validate and apply a new policy version;
- list, approve, deny, or inspect pending intents;
- view wallet and budget status;
- inspect and verify signed receipts;
- initiate a trusted reconciliation attempt;
- export a sanitized receipt bundle.

Operator requests require a local operator credential. Agent traffic and
operator traffic use distinct routes and authorization middleware.

### 7.3 Wallet adapter interface

The wallet seam exposes only:

```text
walletIdentity() -> WalletIdentity
signX402Exact(authorizedPermit, paymentRequirements) -> SignedPayment
```

The adapter accepts an internal `AuthorizedPermit`, not an arbitrary signing
payload. It must prove that the network, asset, payer, payee, amount, request hash,
quote identity, expiry, and nonce match the permit exactly.

CDP is the first live-shaped adapter. A deterministic signer and a mock-settlement
adapter implement the same contract for offline verification.

## 8. Canonical domain records

The durable store contains explicit records rather than a generic event blob:

### SpendSession

A kernel-issued identifier bound to the local agent adapter, customer wallet,
creation time, lifecycle state, and session-budget accounting. The agent cannot
select or mutate the session identity.

### PolicyVersion

An immutable policy document, schema version, canonical hash, applied timestamp,
and predecessor hash.

### SpendIntent

The captured method, canonical URL, seller origin, resource path, body hash,
header allowlist hash, purpose label, kernel-issued session ID, correlation ID,
wallet, creation time, and kernel-issued idempotency key. Raw body bytes may exist
only in bounded process memory for the active request and are not journaled.

### PolicyDecision

Exactly one of `allow`, `approval_required`, or `deny`, bound to the Spend Intent,
policy version, challenge fingerprint, amount ceiling, and stable reason code.

### BudgetReservation

Canonical atomic-USDC amounts for reserved, committed, released, and unresolved
funds. Every transition must conserve non-negative integer atomic units.

### Approval

A one-time operator decision bound to the exact intent hash, challenge
fingerprint, amount ceiling, wallet, policy version, operator identity, and
expiry. An expired challenge or changed request requires a new approval.

### PaymentAttempt

The exact signed payment bytes, payment fingerprint, nonce, quote identity,
settlement evidence, transaction identity, and protocol timestamps.

### ExecutionOutcome

Success, failure, or unknown, including HTTP status, bounded metadata, response
hash when available, and no raw response body.

### Refund

The original transaction, requested amount, state, trusted evidence, refund
transaction when confirmed, and relationship to the held reservation. The buyer
kernel does not send an outbound refund; it records and reconciles a seller-side
refund.

### Reconciliation

An operator-triggered, capability-backed observation that can advance an
ambiguous state only when payer, payee, amount, nonce, request, and transaction
evidence match exactly.

### SignedReceipt

An Ed25519-signed terminal projection over the intent, policy, approval, payment,
execution, budget, refund, and reconciliation records. It never becomes the
source of authority for those records.

## 9. Policy model

Policy is a canonical JSON document validated against a closed schema. Unknown
fields fail validation. Applying a policy creates a new immutable PolicyVersion;
an active version is never edited in place.

V1 policy can constrain:

- exact CAIP-2 network (`eip155:84532`);
- exact Base Sepolia USDC asset;
- customer wallet identity;
- seller origin and optional resource-path prefix;
- allowed HTTP methods;
- maximum atomic USDC per request;
- maximum atomic USDC per seller per session;
- maximum atomic USDC for the complete session;
- maximum atomic USDC in a rolling 24-hour window;
- automatic-allow ceiling;
- human-approval ceiling;
- challenge and approval expiry;
- maximum concurrent pending approvals;
- default action.

The default action is `deny`. A request is `allow` only when every applicable
rule permits it and all budget ceilings have capacity. A request is
`approval_required` only when its seller and protocol shape are permitted but its
amount or resource rule explicitly allows operator escalation. Unsupported
network, asset, scheme, method, seller, or malformed challenge is always `deny`
and cannot be overridden by approval.

## 10. Modules

### Intent Builder

Captures the caller-owned request exactly once, creates the canonical request
hash and idempotency key, and prevents caller injection of kernel-owned headers.

### Policy Engine

A pure module with no network, database, clock, or wallet creation. It evaluates
an immutable input snapshot and returns a decision plus reason codes.

### Budget Ledger

Atomically reserves, commits, releases, or holds canonical atomic-USDC amounts.
It serializes monetary transitions through SQLite transactions and refuses any
transition that would make a counter negative or violate conservation.

### Approval Queue

Persists operator escalation without granting generic signing capability. An
approval is one-time and expires with its challenge.

### Wallet Adapter

Provides customer wallet identity and x402 signing only. The CDP adapter loads
customer-controlled CDP configuration from the process environment or a
customer-provisioned secret mount. Credentials are never written to SQLite,
receipts, logs, or exported projections.

### x402 v2 Transport

Owns the unpaid request, challenge parsing, exact validation, signature
construction, and one paid retry. V1 registers only the Base Sepolia EVM `exact`
scheme.

### Durable Journal

Uses local SQLite in WAL mode with full synchronous durability and a single
authoritative writer. Domain transitions and their canonical event-hash chain
commit in the same transaction. The database file and related side files must be
owner-only regular files on customer-controlled persistent storage.

### Receipt Signer

Uses a customer-local Ed25519 key stored outside the tracked checkout. It signs
terminal receipt projections and exposes the public key and key ID for
verification.

### Projection Exporter

Emits sanitized signed projections only when enabled. It has no import path and
cannot write to authoritative state.

## 11. Transaction lifecycle

```text
received
  -> challenged
  -> allowed | approval_pending | denied
  -> budget_reserved
  -> signed
  -> payment_unresolved | settled
  -> execution_succeeded | execution_failed | execution_unknown
  -> finalized | refund_pending | refunded | reconciliation_required
```

1. Persist the Spend Intent before contacting the seller.
2. Perform one bounded unpaid request.
3. Parse and validate the x402 v2 challenge against the exact request and policy
   boundary.
4. Persist the policy decision.
5. For `deny`, terminate without reservation or signature.
6. For `approval_required`, persist the challenge and immediately return
   `payment_approval_required`. Do not keep the Agent request connected and do not
   poll for a decision. Expiry terminates the approval; it does not create reusable
   authority.
7. For `allow`, atomically reserve the maximum amount. After an exact operator
   approval, the Wielder deliberately repeats the same ordinary request, preferably
   retaining its `x-agent-call-id`. If it arrives with a fresh call ID, the Kernel
   atomically binds that ID as an alias to the active exact fingerprint before any
   signing transition. It then revalidates the approved intent and atomically reserves
   the maximum amount.
8. Claim the one-time signing transition and call the Wallet Adapter.
9. Persist the exact signature and payment payload before any paid retry.
10. Perform exactly one paid retry.
11. Require response settlement evidence that matches the signed payment.
12. Persist execution outcome separately from settlement outcome.
13. Commit the actual charge, release unused reservation, or retain an unresolved
    hold as dictated by evidence.
14. Create and sign the terminal receipt only after the authoritative transition
    commits.

## 12. Failure and restart semantics

- Failure before signature persistence releases the reservation unless the
  signer may have returned a signature and persistence is ambiguous.
- Any uncertainty after a signature may exist retains the full reservation as
  unresolved.
- Missing response, timeout, or crash never causes a replacement signature or
  blind paid retry.
- An Agent-level response loss may repeat the exact request with the same
  `x-agent-call-id`; this resolves to the existing intent and cannot create a second
  signing path. A different request with that key fails closed.
- A settled payment followed by failed execution remains settled and enters
  `refund_pending` or `reconciliation_required`.
- An execution response without matching settlement evidence is withheld.
- A changed paid response, changed challenge, or second `402` is not accepted as
  success.
- Operator approval cannot bless an already-signed or settled operation.
- On startup, safe unsigned pending approvals remain pending. Any signed,
  payment-unresolved, settled-with-unknown-execution, or refund-unresolved record
  blocks new spending from the same wallet until exact reconciliation or a safe
  terminal transition completes.
- Recovery reuses persisted exact bytes and identities. It never reconstructs a
  signature from intent fields.

## 13. Operator and Pi experience

The pilot package contains the Wallet Kernel, CLI, Pi adapter, and a loopback-only
operator console.

### Setup

1. Provision customer CDP credentials and a Base Sepolia wallet in the customer
   environment.
2. Provision a local receipt-signing key and owner-only SQLite path.
3. Run preflight to verify network, wallet, asset, file permissions, schema, and
   policy.
4. Apply the initial policy version.
5. Start the kernel and point Pi at the loopback proxy.

### In-policy request

Pi receives the upstream response and a compact receipt summary: seller, charged
amount, remaining session budget, terminal state, transaction prefix, and receipt
ID.

### Approval-required request

Pi receives `payment_approval_required` with a request ID and expiry. The local
console shows seller, resource, request hash, amount ceiling, wallet, policy
mismatch, and expiry. The response is immediate: neither Pi nor the proxy keeps the
request connected, polls the approval, or performs an application-level automatic
retry. The operator approves once or denies. If approved, the Wielder makes a new
ordinary request with the exact prior fingerprint while the approval remains valid. It
should reuse the prior `x-agent-call-id` when retained, but a fresh ID is accepted: the
Kernel atomically records it as an alias to the active exact intent before signing. The
proxy resolves either form using the bound Agent credential, kernel-owned Spend
Session, request fingerprint, and idempotency mapping; Pi does not send an approval or
payment-idempotency header.

The sole automatic replay exception is inside the local Skill fetch: a thrown fetch or
a failure while reading the response body may trigger exactly one retry with the same
`x-agent-call-id`. A received response with an invalid content type, malformed JSON,
or any application result—including `payment_approval_required`—is not retryable.
This is transport-loss recovery, not approval handling or application-level retry. The
Kernel's durable deduplication means a settled response loss cannot spend twice. The
model-provider hook likewise retains one call key across an error until Pi reports a
terminal outcome; it does not poll or replay an approval response itself. A later
legitimate invocation uses a fresh `x-agent-call-id`; for an identical payload, it
creates a new Spend Intent only when no active retry-matchable intent or binding for
that fresh key exists.

### Local console

The console has four views:

- **Overview:** wallet, budget, reserved/unresolved amounts, and kernel health.
- **Policies:** active version, validation, and immutable history.
- **Approvals:** pending, approved, denied, and expired requests.
- **Receipts:** settled, failed, refunded, and unresolved operations.

There is no hosted write path and no raw prompt or output display.

## 14. Security and privacy requirements

- Agent and operator routes are separate.
- Admin routes bind to loopback by default and require a local operator credential.
- Redirects are disabled for unpaid and paid requests.
- Network, asset, scheme, seller, path, method, amount, nonce, request hash,
  challenge expiry, and response evidence are validated exactly.
- Request, challenge, facilitator, and upstream response bodies use streaming byte
  ceilings and total wall-clock deadlines.
- Database, receipt key, operator credential, and local configuration are
  owner-only regular files. Symlinks, wrong owner, or permissive modes fail closed.
- CDP and provider credentials remain in customer-controlled secret storage and
  are never persisted by the kernel.
- Logs and public errors use stable codes and remove provider exception detail.
- Raw prompts and outputs are not stored. Bounded hashes and status metadata are
  sufficient for receipts.
- Policy history is append-only.
- No `.env`, private key, wallet secret, database, receipt key, or operator token
  may be tracked by Git.

## 15. Verification strategy

### Pure tests

- canonical request and policy serialization;
- closed-schema rejection;
- policy decision matrices;
- approval exactness and expiry;
- atomic-USDC conservation;
- state-machine transition legality;
- receipt canonicalization and signature verification.

### Adapter contract tests

Every wallet adapter must prove:

- it refuses missing or mismatched AuthorizedPermits;
- it cannot alter payment fields;
- it never exposes key material;
- it returns canonical signer and payment evidence;
- the deterministic adapter and CDP adapter satisfy the same interface contract.

### Persistence and crash tests

Inject process failure immediately before and after every durable monetary
transition. Reopen the store and prove:

- no reservation disappears;
- no amount is committed twice;
- no second signature is requested;
- no settlement is replayed;
- no refund is invented;
- every nonterminal state is either safely resumable or blocks for reconciliation.

### Offline integration

Run the complete x402 v2 `exact` flow with deterministic wallet, facilitator,
seller, approval, execution failure, refund, and reconciliation adapters. No
socket, API key, funded wallet, or network is required.

### End-to-end

Run Pi through real child processes and exercise:

1. allowed automatic payment;
2. untrusted seller denial;
3. over-budget denial;
4. approval-required then approved request;
5. approval denial and expiry;
6. crash and restart at each money boundary;
7. settled execution failure;
8. unresolved settlement;
9. trusted reconciliation;
10. signed receipt verification from a fresh process.

### Manual Base Sepolia evidence

Only after offline gates pass, a human may fund a test wallet and authorize a
testnet run. The run writes a new immutable evidence directory:

```text
spikes/pi-wielder/evidence/YYYY-MM-DD-agent-spend-control-RUN_ID/
  manifest.json
  events.jsonl
  summary.json
  report.md
  README.md
```

The bundle must include hashes, exact code commit, configuration digests,
normalized per-request evidence, transaction links, recomputation instructions,
and explicit testnet labels. Aggregate prose without retained samples is not
publishable evidence.

## 16. Acceptance criteria

V1 is complete only when fresh verification proves all of the following:

1. Pi automatically pays an allowed x402 v2 `exact` request on the offline path.
2. An unapproved seller is denied before wallet-adapter invocation.
3. An over-budget request is denied before wallet-adapter invocation.
4. An escalatable request is persisted, approved by the operator, and paid only
   for the exact approved request and quote.
5. A denied or expired approval never reaches the signer.
6. Restart preserves policy, approvals, reservations, signatures, payment state,
   execution state, refunds, and receipts.
7. Restart never causes a second signature or settlement for the same attempt.
8. Every monetary transition conserves canonical atomic USDC.
9. Settled execution failure is distinguishable from unpaid failure and produces
   no invented successful output.
10. Every terminal outcome produces a verifiable signed receipt.
11. Every ambiguous outcome remains held until trusted reconciliation.
12. No raw prompt, output, wallet secret, CDP credential, or unredacted provider
    exception appears in the database, receipt, or logs.
13. Full automated verification uses no network and no funded wallet.
14. Any testnet claim is backed by a fresh recomputable evidence bundle.

## 17. Implementation and release boundary

Implementation begins from `codex/prd-execution`, not the older public spike on
`github-main`. Existing hardened journal, policy, receipt, refund, COGS, and
runtime-boundary tests remain regression requirements while modules are
extracted and deepened.

The public website and README are updated only after the new implementation and
evidence meet this spec. The quarantined historical `n=48` aggregate is not used
in product claims. A new testnet run, if authorized, must retain its normalized
evidence.

This design does not amend `CONTEXT.md`, `docs/PRD.md`, or `docs/adr/`. It is
consistent with ADR-0008's thin Wielder wallet boundary. Any later change to the
canonical product doctrine requires separate explicit instruction.

## 18. Commercial pilot boundary

The first commercial offer is a paid customer-hosted design-partner engagement,
not a self-service wallet or transaction take-rate business.

The pilot delivers:

- one customer-owned CDP testnet wallet integration;
- one Pi workflow;
- one or more allow-listed x402 testnet sellers;
- customer-defined automatic and approval-required policy;
- durable budgets and restart recovery;
- local operator console;
- signed receipt and reconciliation export;
- a final evidence and control review.

The pilot validates whether an AI platform team will pay for governed autonomous
spending and auditability. It does not validate mainnet custody, market demand for
Skill royalties, or a public marketplace.

## 19. Considered alternatives

### Wrap an existing agent-wallet CLI

Rejected as the core architecture. It reaches a demo quickly but makes policy,
recovery, and receipt semantics dependent on another product's command surface.
Wallet providers remain adapters rather than the product interface.

### Build custom smart-account contracts

Rejected for v1. It adds contract audits, recovery design, and wallet security
before buyer demand is proven, while duplicating managed wallet capability.

### Keep the existing in-memory proxy

Rejected for commercialization. It cannot guarantee budget or payment state
across restart and cannot safely support operator approval or production-shaped
reconciliation.

# Adversarial Review Remediation Design

**Status:** Approved direction; implementation planning follows after review of this written specification.

**Date:** 2026-07-17

## Goal

Bring the repository's public claims, experimental evidence, reference accounting,
runtime behavior, provenance language, and terminal Intra-org product into one
coherent and testable contract.

The terminal Intra-org product will use employer-funded internal Invocations. A
successful qualified internal Invocation creates an employer-sponsored **Invocation
award** for the employee-Creator. An external Wielder may create later Royalty-claim
upside, but external demand is no longer required for the employee-Creator to earn
compensation.

## Design principles

1. Stop unsupported public claims before expanding the implementation.
2. A benchmark is invalid unless its source target passes its own acceptance gate.
3. Every measured claim must be reproducible from a sanitized committed evidence
   bundle.
4. Money is represented in integer atomic units and must conserve exactly.
5. A settled payment is recorded even when execution fails or a seller response is
   lost.
6. The Collar owns authoritative Invocation and settlement accounting. Wielder-side
   ledgers are receipt views, not compensation ledgers.
7. Phase 0 attests registration by a wallet and declared ancestry. It does not prove
   authorship, originality, or safety without additional evidence.
8. Internal compensation must work without an external customer, real-funds custody
   by the platform, or Phase 2 on-chain settlement.
9. Existing testnet-only and no-private-key rules remain binding.
10. `CONTEXT.md`, `docs/PRD.md`, and `docs/adr/` are not edited during remediation
    implementation without explicit approval. Proposed canonical changes are kept in
    a reviewable amendment document until that approval is given.

## Scope decomposition

The remediation is organized into six conceptual projects. Execution is split more
finely so each implementation plan has one testable responsibility and can land without
requiring later plans to be complete.

1. Launch and evidence integrity.
2. Monetary accounting and settlement lifecycle.
3. Employer-funded internal Invocation flow.
4. Provenance and registration integrity.
5. Registry and public-demo truthfulness.
6. Canonical corpus alignment.

The projects execute in that order. Projects 1 and 2 are stop-the-line work. Project 3
tests the proposed terminal product as an accounting spike. Projects 4 and 5 harden
adjacent surfaces. Project 6 is a controlled documentation migration after the behavior
and evidence exist.

### Implementation-plan boundaries

1. Claims quarantine and tracked marketing corrections.
2. Clone-economics validity, larger fixtures, and durable evidence.
3. Phase-0 funding, crash-recovery, override, and metadata safety.
4. Atomic integer monetary kernel.
5. Authoritative Collar Invocation journal and signed receipts.
6. Wielder x402 payment policy.
7. COGS-aware quoting and execution.
8. Employer-funded internal Invocation spike.
9. Authorship attestation, duplicate detection, dispute, and revocation model.
10. Registry and public-demo corrections, gated on explicit approval for untracked
    `hf-space/` work.
11. Protected-corpus amendment proposal and, only after separate approval, canonical
    application.

## Project 1: Launch and evidence integrity

### Responsibilities

- Block clone-economics campaign copy until the benchmark has a valid target baseline
  and a genuinely larger training set.
- Correct tracked marketing statements that convert modeled values into paid or
  measured values.
- Correct the x402 handshake, Wielder/Collar roles, settlement counts, split-level
  reconciliation, and measurement dates.
- Replace absolute extraction language such as "the Skill never leaves" with the
  supportable claim that the artifact is not directly returned, while preserving
  adversarial extraction testing as a runtime requirement.
- Preserve prior results as historical evidence with their original labels; do not
  erase or silently rewrite them.
- Make live evidence independently inspectable without committing secrets, private
  prompts, or keys.

### Evidence bundle contract

Every live experiment bundle contains:

- `manifest.json`: experiment identifier, UTC timestamp, git commit, command, runtime
  versions, model/provider identifier, evidence label, configuration with secrets
  removed, and SHA-256 hashes for every other file.
- `samples.jsonl`: one normalized row per attempted sample, including success/failure,
  timing fields, usage fields, cost fields, and a stable sample identifier.
- `summary.json`: statistics recomputed from `samples.jsonl`; never hand-entered.
- `report.md`: human interpretation generated from `summary.json`, with explicit
  measured, modeled, synthetic, extrapolated, and unknown labels.
- `README.md`: reproduction command, privacy/redaction statement, and known limits.

Raw provider payloads that contain private content remain ignored. The committed
bundle contains only the normalized fields needed to reproduce the claims.

### Clone benchmark validity

A clone run may produce a report regardless of outcome, but it may not produce a
fidelity conclusion unless all of these conditions hold:

- the target meets the configured absolute-score threshold;
- the target passes every critical gate;
- training and held-out fixtures remain disjoint by identifier and normalized hash;
- a high-N run uses a preregistered sweep of `N=6,25,50,100`, at least 30 held-out
  fixtures, and three independent distillation seeds at each N; only the N=100 bound
  may be described as the repository's first high-N result;
- all attempted distillation runs and their provider cost are included in total attack
  cost;
- acquisition is labeled modeled unless actual paid Invocation receipts are present;
- labor, deployment, tuning, and measurement costs are reported separately when not
  included in the attacker-build total.

If the target fails, the verdict is `INVALID_BENCHMARK_TARGET_FAILED`. Clone-quality,
moat, and break-even conclusions are suppressed.

### Acceptance criteria

- No tracked launch copy says `$1.58 paid`, `six paid runs`, or equivalent.
- The clone campaign remains explicitly blocked until a valid larger-N result exists.
- A clean checkout can recompute every published p50, p95, cost, and sample count from
  committed normalized evidence.
- The clone offline suite passes both with and without an existing ignored `runs/`
  directory.
- Live provider spend for the preregistered high-N sweep remains a human approval gate.

## Project 2: Monetary accounting and settlement lifecycle

### Money representation

All monetary calculations use integer atomic units. The reference implementation uses
USDC's six-decimal unit and exposes formatting only at UI/report boundaries.

The following invariants are enforced after every allocation:

```text
gross = executionCost + settlementCost + protocolFee + royaltyPool + refundReserve
royaltyPool = sum(holderCredits) + sum(ancestorCredits)
internalGross = executionCost + protocolFee + refundReserve + invocationAward
sum(all debits) = sum(all credits)
gross >= 0
every component >= 0
```

Rounding remainders are assigned deterministically by stable recipient order. Negative,
non-finite, unsafe, or over-precision inputs are rejected before state changes.

### Authoritative lifecycle

The Collar persists one record per attempted Invocation. Execution state is independent
from the funding mechanism:

```text
requested
  -> quoted
  -> authorized
  -> executing
  -> succeeded | failed | cancelled

external payment: offered -> signed -> settled | rejected | unresolved
                  settled | unresolved -> refunded
internal budget:  allocated -> reserved -> consumed | released
```

`failed` is reachable after authorization or during execution. A payment that settles
but whose response is lost remains `unresolved` until reconciliation advances it. A
settled external payment remains attached to the Invocation even when execution fails.
No HTTP status deletes or suppresses a settled event.

External execution requires a settled payment credential. Internal execution requires
a valid reserved-budget credential. Neither path may execute from a quote alone.

Each record binds:

- Invocation identifier and idempotency key;
- Skill identifier and immutable version/hash;
- Wielder and Beneficiary identifiers appropriate to the mode;
- Creator, employer, cost center, and effective policy version when applicable;
- quote and currency;
- payment or budget-authorization reference;
- settlement transaction hash when x402 is used;
- execution outcome and failure class;
- model usage and execution COGS;
- protocol fee, settlement cost, refund reserve, and Royalty-claim credits;
- internal budget reservation and Invocation-award state when applicable;
- timestamps and a signed receipt hash.

The Wielder may cache signed receipts and render a session view, but it never supplies
authoritative splits. Split data comes from the Collar's signed receipt.

### External x402 policy

Before signing an x402 offer, a Wielder policy validates:

- exact supported network and asset contract;
- expected resource and trusted seller/payee;
- maximum per-call amount and remaining session budget;
- timeout and quote freshness;
- amount equality between the accepted quote and retry;
- one retry per authorization.

An offer that fails any check is rejected without signing.

### COGS treatment

The Skill's own model/tool execution cost is part of the quote and ledger. Royalty
credits are calculated only after execution cost, settlement cost, protocol fee, and
refund reserve are allocated. A successful Invocation with negative contribution
margin fails the product acceptance gate even when cash reconciliation succeeds.
Model and token limits are allow-listed, provider pricing is versioned with the quote,
and adversarial extraction tests verify the artifact is not directly serialized or
returned while avoiding any guarantee that model output can never reveal behavior.

### Acceptance criteria

- Property tests prove exact conservation across prices, fee rates, claim tables,
  ancestry depth, and rounding boundaries.
- Negative and non-finite prices cannot mutate state.
- A settled-then-500 fault creates a ledger record with the transaction hash and
  `failed` outcome.
- A lost seller response can be reconciled from the settlement reference without a
  duplicate debit.
- Wielder policy tests reject the wrong network, asset, payee, resource, amount,
  expired quote, and exhausted budget.
- Every successful hosted-Skill receipt includes actual or explicitly unknown COGS;
  unknown is never treated as zero.
- No accepted quote has negative worst-case contribution margin under its model and
  token limits.

## Project 3: Employer-funded internal Invocation flow

### Canonical mode

The employer is the Beneficiary and the source of compensation funds for internal
Invocations. The employee-Creator does not need an external customer to earn.

Because the protected corpus currently defines an external-Wielder-funded model, the
first implementation is an explicitly labeled accounting spike, not silent product
doctrine. It may become the canonical Phase-1 implementation only after Project 6's
amendment set receives separate approval.

Phase 1 avoids platform custody by using an employer-retained, approved Invocation
budget and a signed payable ledger rather than moving compensation funds through a
platform omnibus wallet. The budget is an authorization and accounting limit, not a
prepaid customer balance held by the Collar. Actual employee payment uses the
employer's payroll or accounts-payable rail at the schedule required by the
counsel-drafted instrument.

An internal Invocation award and an external Royalty claim are distinct events:

- An internal Invocation consumes employer budget and may create an employee
  compensation obligation under an employer plan.
- An external Invocation receives third-party revenue and distributes the royalty pool
  through the co-held Royalty claim.

`Invocation award` is a proposed ubiquitous-language term for the canonical amendment
set. Until that amendment is approved, this design uses it only to avoid mislabeling an
internal compensation allocation as external royalty revenue.

### Program and policy model

The employer compensation program moves through:

```text
draft -> approved -> active -> suspended
                           -> expired
```

Every active program references an immutable, effective-dated policy version defining
eligible Creators, Skills, Wielders, cost centers, award rate, per-Invocation and
per-period caps, vesting or earning rule, payment dates, termination treatment, and
required approvals. Policy changes apply prospectively; historical Invocation records
retain the policy version they used.

### Budget model

An employer account has:

- a currency;
- an approved budget limit for a defined period;
- allocated, reserved, consumed, and released atomic amounts;
- permitted Skills, Creators, Wielders, and cost centers;
- a maximum quote and maximum award per Invocation;
- an effective and expiry time;
- employer signer identity and signature.

Before execution, the Collar atomically reserves the quoted maximum. The reservation
is the internal-mode prerequisite for an Execution credential. On completion, the
Collar finalizes actual cost and releases the unused amount. On pre-execution failure,
the full reservation is released. On post-execution failure, unavoidable COGS remains
recorded and the unused reservation is released.

Budget amounts move through `allocated -> reserved -> consumed`; a failed or cheaper
Invocation releases unused reservation. The maximum reservation is:

```text
max execution COGS + platform/protocol fee + max Invocation award + refund reserve
```

The internal Execution credential is a signed, single-use, non-transferable record
binding the Invocation identifier, reservation identifier, Skill version, policy
version, expiry, and nonce. It is not redeemable for money and cannot be reused after
the reservation is consumed or released.

### Internal allocation

For a successful internal Invocation:

```text
employer gross payable
  - execution COGS
  - platform/protocol fee
  - refund reserve
  = employee-Creator Invocation award
```

The Invocation award moves through
`measured -> vesting_pending -> earned -> payable -> paid`; policies without vesting
skip `vesting_pending`. The effective policy and counsel-drafted compensation
instrument control the transition dates. A correction is an append-only reversal or
prospective adjustment; historical amounts are never silently overwritten. The
employer does not credit or pay a claim to itself for internal use; doing so would
create circular gross revenue and inflate compensation metrics. The employer's co-held
Royalty-claim share applies only to revenue from an external Beneficiary. External
Invocations, if later enabled, credit both co-holders according to the claim table.

A successful qualified Invocation may earn an award. A failed or cancelled Invocation
earns no award, although unavoidable execution COGS remains recorded. Creator-generated
self-Invocations require manager approval or are excluded by policy. Atomic concurrent
reservations, authorized Wielder and cost-center lists, caps, and idempotency prevent
budget races and trivial award farming.

### Trust and audit model

- The Collar signs an append-only Invocation receipt.
- Employer and employee receive the same receipt and periodic statement root.
- Monotonic sequence numbers expose gaps.
- A statement includes opening balance, reservations, releases, finalized charges,
  Invocation awards, employee payables, payments, reversals, refunds, and closing
  balance.
- Merkle inclusion proves that a disclosed record is in a statement. Sequence and
  cross-party receipt comparison provide the completeness signal; Merkle inclusion
  alone is never described as completeness proof.

### Pilot success criteria

- One employer configures and signs an internal budget.
- An authorized internal Wielder invokes a registered Skill.
- The Collar reserves budget, executes, records COGS, releases unused budget, and
  records the employee Invocation award without any external Wielder.
- Employer and employee independently verify the same signed receipt and statement.
- An unauthorized Wielder, expired budget, exceeded cap, repeated idempotency key,
  unapproved self-Invocation, and insufficient remaining budget all fail before
  execution.
- A counsel-drafted instrument and an actual employer payment through payroll/AP remain
  human launch gates; the software does not claim those gates are complete.
- No platform-held prepaid balance, employee wallet, Story royalty settlement,
  on-demand withdrawal, Marketplace, or tradeability enters this Phase-1 slice.
- The spike labels its result as accounting evidence only; it does not claim demand,
  employment-law, tax, securities, or custody validation.

## Project 4: Provenance and registration integrity

### Attestation levels

Registration surfaces use explicit evidence levels:

1. `wallet_asserted`: a wallet registered a content hash and declared ancestry.
2. `repository_control_verified`: the wallet is bound to a signed commit or repository
   owner challenge for the registered bytes.
3. `organization_approved`: an authorized organization signer approved the Skill and
   Creator relationship.

No level proves that a Skill is safe. Safety review is a separate status with separate
controls.

### Duplicate and dispute behavior

- Duplicate artifact hashes are visible, not silently accepted as independent
  originals.
- A later registrant cannot displace an earlier record merely by claiming authorship.
- A challenge references both registrations and records evidence, status, and outcome.
- Revocation marks an attestation invalid without deleting historical chain evidence.
- Declared Derivative ancestry remains distinguishable from verified repository history.

### Phase 0 reliability

Before any testnet transaction, Phase 0 verifies an estimated minimum balance. It
persists intent and transaction-submission identifiers before awaiting confirmation,
then reconciles chain state before retrying after a crash. Metadata defaults use a
durable pinned provider; environment overrides are stage-specific and verified against
the exact serialized bytes.

### Acceptance criteria

- Public APIs and UI never collapse `wallet_asserted` into `authored by`.
- Two wallets registering identical bytes produce a visible conflict record.
- A signed repository-control challenge can be verified offline.
- Resume after a simulated confirm-before-save crash performs no duplicate write.
- Dust funding fails preflight with the estimated required minimum.

## Project 5: Registry and public-demo truthfulness

`hf-space/` is pre-existing untracked user work. Its plan may specify corrections, but
no implementation edits, staging, or publication occur without explicit approval to
include that directory.

### Registry

The registry is described as settlement-verifiable, not unfakeable. Settlement proves
that value moved, not that demand was independent or that a Skill is useful or safe.

Ranking excludes:

- self-payments;
- known Creator/payee-linked wallets;
- refunded or failed Invocations;
- repeated Sybil-cluster activity;
- gross volume that is immediately recycled.

Public metrics report total settlements, successful Invocations, settled failures,
unique independent Beneficiaries, refund-adjusted net revenue, and confidence in payer
independence as separate fields. The first registry remains allow-listed until at least
two independent Beneficiaries have paid for successful Invocations.

### Public demo

- Intra-org is the default archetype.
- Education is labeled deferred because free re-authoring defeated the tested model.
- Marketplace is labeled Phase-3 optionality.
- The royalty visualizer subtracts costs and protocol fee before showing the claim pool.
- LAP/LRP policy is explicit; the visualizer does not silently substitute one for the
  other.
- A live 402 badge requires HTTP 402, supported x402 version, and a valid offer schema.
- Cached responses are visually and textually distinct from live responses.
- Inference-route measurements are not attributed to the hosted-Skill endpoint.
- Implemented credits are distinguished from future withdrawal or on-chain settlement.

### Acceptance criteria

- A self-funded Sybil fixture cannot rank as independent demand.
- The demo's displayed allocation exactly matches the accounting core.
- JSON 200 and JSON 500 responses cannot render as live 402 proof.
- Every public measurement links to a committed evidence manifest.

## Project 6: Canonical corpus alignment

This project begins only after Projects 1–5 establish the behavior and evidence.

It produces a proposed amendment set for explicit review covering:

- employer-funded internal Invocations as the terminal Intra-org billable event;
- internal budget authorization versus external x402 payment;
- internal Invocation awards versus the co-held external-revenue Royalty claim;
- the Collar as authoritative ledger and the Wielder ledger as a receipt view;
- gross-price allocation including COGS and reserves;
- wallet-attested registration versus verified authorship;
- contractual non-transferable claims versus transferable Story royalty tokens;
- settlement-verifiable registry language;
- corrected benchmark and evidence claims;
- Education's final deferred status.

The canonical amendment set includes a new ADR for employer-funded internal
Invocations. It supersedes the assumption that every Execution credential must arise
from a settled x402 payment, while preserving x402 and txHash credentials for external
Invocations. It also introduces the Invocation-award term and confines ADR-0005's
cross-chain/custody path to externally funded Invocations.

Closed-mode Phase 0 remains registration-only. It does not distribute native Story
royalty tokens while those tokens are transferable and the closed-mode entitlement is
required to be non-transferable.

Until explicit approval is given, the amendment set does not modify `CONTEXT.md`,
`docs/PRD.md`, or any ADR. After approval, those canonical files are updated together
in one coherence commit, preserving historical statements where needed and extending
the PRD's unvalidated ledger rather than deleting from it.

## Review-finding coverage

- Unsupported launch and extraction claims: Project 1.
- Invalid clone baseline, modeled cost presented as paid, high-N gate, and missing raw
  evidence: Project 1.
- Floating-point conservation failure, settled-failure omission, unsafe x402 offer
  acceptance, and missing COGS: Project 2.
- External-demand dependency, circular employer self-credit, custody ambiguity, and
  internal compensation funding: Project 3.
- Wallet assertion presented as authorship, duplicate registration, dust funding,
  confirm-before-save duplication, metadata durability, and override safety: Project 4.
- Wash-tradeable ranking, safety overclaim, incorrect demo allocation, deferred-mode
  default, live-402 validation, and evidence misattribution: Project 5.
- Protected-corpus contradictions and transferable Story tokens in a non-transferable
  closed mode: Project 6.

Every material adversarial-review finding maps to an implementation-plan boundary;
there is no uncovered remediation item in this design.

## Error handling and recovery

- All write operations use stable idempotency keys.
- Budget reservation and Invocation-record creation are atomic.
- Settlement reconciliation is retryable and never produces a second debit.
- Refunds are first-class ledger entries linked to the original Invocation.
- Unknown provider usage or cost remains `unknown`; it is never coerced to zero.
- Evidence generation fails closed when sample counts, required hashes, or source-target
  validity are incomplete.
- Provenance disputes append status changes; historical evidence is not destroyed.

## Testing strategy

Each implementation plan uses test-driven development and lands independently.

- Unit tests: money parsing, allocation, remainder policy, lifecycle transitions,
  budget reservations, signature verification, attestation levels, and ranking filters.
- Property tests: conservation, non-negativity, idempotency, and allocation totals.
- Fault injection: settlement success followed by HTTP 500, response loss, crash after
  chain confirmation, duplicate retry, expired budget, and missing usage.
- Contract tests: Collar signed receipt schema, Wielder policy, evidence manifest, and
  live-402 validation.
- End-to-end tests: external mock x402 Invocation and internal employer-budget
  Invocation, both reconciled into the authoritative Collar ledger.
- Fresh-checkout tests: every published metric recomputes from committed evidence.

No mainnet transaction, funded-wallet operation, social publication, or external
deployment is part of automated verification.

## Human-only gates

- Approve and publish marketing or social content.
- Supply any real key or fund any testnet wallet.
- Approve canonical edits to `CONTEXT.md`, `docs/PRD.md`, or ADRs.
- Obtain the design-partner agreement and counsel-drafted compensation instrument.
- Decide the real payroll/AP integration and payment schedule.
- Obtain employer HR, payroll, finance, security, privacy, tax, IP, employment, and
  payments approvals for a real employee pilot.
- Authorize any public deployment, repository transfer, or registry launch.
- Approve editing or adding the untracked `hf-space/` directory.

## Overall definition of done

The remediation is complete when:

1. Public claims are evidence-linked and correctly labeled.
2. Clone conclusions cannot publish from an invalid target baseline.
3. Accounting conserves integer atomic units under all tested allocations.
4. Every settled payment, including failure, appears in the authoritative ledger.
5. Internal employer-funded Invocations record employee Invocation awards without
   external demand or platform custody, and payroll/AP status is reconciled separately.
6. Registration claims state exactly which evidence level they establish.
7. Registry ranking resists the documented self-payment and Sybil fixtures.
8. The public demo matches implemented accounting and current product sequencing.
9. Canonical corpus amendments are approved and applied as a coherent set.
10. The worktree contains no tracked key, `.env`, raw private provider payload, or
    unlabeled synthetic result.

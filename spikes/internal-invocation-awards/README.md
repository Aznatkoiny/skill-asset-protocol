# SPIKE — deterministic accounting evidence only

This isolated Node spike demonstrates one employer-funded internal **Invocation**
accounting path. It uses no network, wallet, chain, API key, funded account, payroll
transfer, platform-held prepaid balance, or real money. Every key is a throwaway
Ed25519 key generated in memory for the current process, and the executor is an
injected fake. The demo installs a global `fetch` trap so an accidental network call
fails immediately.

This is executable design evidence, not product doctrine. It does not edit the
protected ubiquitous language, PRD, or ADR corpus.

## What the spike demonstrates

The example employer signs an immutable `EmployerBudgetAuthorizationV1` for a
denomination and period. Mutable reservation, consumption, and release counters live
in a separate `BudgetStateV1`; changing a signed authorization field invalidates its
signature. Effective and expiry times are checked at both reservation and Execution
start.

The accounting flow is:

```text
signed employer budget authorization
  -> atomically reserve quote maximum
  -> return exact unsigned Execution-credential payload
  -> caller signs that persisted payload
  -> atomically consume its nonce and start one execution attempt
  -> fake executor reports validated COGS
  -> shared atomic-money kernel partitions actual gross
  -> release unused reservation
  -> record employee-Creator Invocation award
  -> sign one receipt and one full economic statement
```

The successful example reserves `3.050000 USD`, records `0.700000 USD` execution
COGS, `0.025000 USD` protocol fee, `0.025000 USD` refund reserve, and a `2.000000
USD` Invocation award, then releases `0.300000 USD`. Actual gross is the exact sum of
reported COGS, the quote-final fee and reserve, and the authorized maximum award. All
persisted atomic amounts are non-negative decimal strings. Arithmetic converts them
to `bigint`; no floating-point value participates in money arithmetic.

The gross partition is imported from
`prototype/atomic-money.mjs#allocateInternalGross`. This spike does not implement a
second fee, remainder, or account-allocation formula. It consumes the kernel-returned
account-identified journal entries.

The result requires an authorized internal **Wielder**, but no external Wielder. It
creates neither an external **Royalty claim** credit nor a circular employer
self-credit. An internal Invocation award is proposed employer-compensation
accounting; it is distinct from external Invocation revenue distributed through a
co-held Royalty claim.

## Policy and lifecycle boundaries

Version 1 accepts only the immutable 100% residual award rule:

- `type: residual_after_execution_fee_and_reserve`
- `awardRateBps: 10000`
- `rateBase: post_cost_residual`
- `rounding: floor_atomic`

Variable award rates and any destination for non-award residual are not implemented.
Policy and budget authorization are immutable, effective-dated, expiry-bounded, and
denomination-neutral. A self Invocation is exactly one whose `creatorId` equals its
`wielderId`; its manager approval is a separate signed object, never a quote field.

The store is a serialized, single-process CAS demonstration. It is not a distributed
database lock. The engine uses exact global, budget, Invocation, reservation, and
execution-attempt revisions so one stale authorization or duplicate completion wins
at most once. It conservatively counts every earned award plus the maximum award of
every reserved, executing, or unresolved-held authorization against the period cap.
There is no automated award-reversal lifecycle in this v1 engine, so it never reduces
that exposure based on an unsupported reversal claim.

The tested pre-execution rejection set includes:

- inactive, not-yet-effective, expired, or malformed policy;
- expired, not-yet-effective, altered, self-signed-untrusted, or disallowed budget;
- malformed atomic amount, Skill hash, quote total, or credential nonce;
- unauthorized Skill, Creator, Wielder, Beneficiary, cost center, signer, or
  authorizer;
- unknown, embedded, or untrusted public-key material;
- insufficient remaining budget or exceeded per-Invocation or period award cap;
- stale budget/engine/record revision, duplicate idempotency key, nonce, reservation,
  or Invocation;
- missing, expired, mismatched, already-consumed, cancelled, or released Execution
  credential/reservation binding; and
- self Invocation without a trusted, policy-permitted, non-self manager approval.

Every failure before `executing` calls the executor zero times.

## Executor outcome discipline

The injected executor may return exactly one strict union member:

```text
succeeded(executionCostAtomic, outputHash)
failed_after_start(executionCostAtomic, failureClass)
unresolved_after_start(reason)
```

Successful and known post-start failures require a canonical atomic COGS string at or
below the quote maximum. A validated failure consumes exactly that unavoidable COGS,
releases the remainder, and creates no award.

A thrown executor, explicit unknown cost, unknown outcome kind, extra field, missing
cost, malformed cost/hash, or over-cap cost transitions to `unresolved` and
`held_unresolved`. The full original reservation remains held. The spike never
substitutes zero COGS, releases that hold, or creates an award automatically. Operator
reconciliation of an unresolved hold is a human-only future gate.

## Receipts and statements

Every terminal success, known failure, unresolved Execution, or pre-execution
cancellation receives one independent, monotonic receipt sequence. A trusted receipt
key ID selects the provisioned verification key; receipts and requests cannot inject
key material. Receipt canonical bytes bind the Invocation, reservation, Skill hash,
effective policy, outcome, atomic totals, kernel journal entries, and absence of an
external settlement.

Employer and employee verify the same signed receipt bytes. They also verify a
separate whole-statement signature that binds:

- identity, denomination, period, and payable opening balance;
- ordered receipt hashes and contiguous sequence bounds;
- reservation, release, charge, and earned-award audit totals;
- the complete payable-advance, reversal, and payment arrays;
- payable and non-payable reversal semantics; and
- the closing payable balance.

An earned-but-unpaid award is not yet payable. It affects
`earnedAwardTotalAtomic`, but does not enter `closingPayableAtomic` until a separately
authenticated payable-advance record is present. A reversal declares whether it
changes only earned accounting or an already-advanced payable balance. Payments
cannot exceed the authenticated payable balance.

The receipt inclusion root uses domain-separated binary SHA-256 leaves and internal
nodes. Odd levels duplicate the last node. The empty set has a fixed
domain-separated root. This is an inclusion root, not a completeness proof; sequence
continuity, the signed ordered hash list, and employer/employee comparison supply the
completeness signal. Individually signed receipts do not authenticate a mutable
statement shell—the trusted whole-statement signature and deterministic recomputation
are both required.

## Run the offline evidence

From this directory:

```bash
npm test
npm run demo
```

The test suite and demo use only Node built-ins and local source. The demo output is
labeled `SIMULATED ACCOUNTING, NO REAL FUNDS`, and the employee-Creator award is
reported as `earned, not paid`.

## Not validated and human-only gates

This spike does not validate demand, employer adoption, production persistence,
distributed concurrency, payroll, tax, employment law, securities treatment,
custody, banking, or actual payment. A counsel-drafted compensation instrument, an
employer agreement and approved program, production trust-key provisioning, operator
reconciliation procedures, and payment through the employer's payroll or
accounts-payable rail remain human-only gates. No automated path advances `payable`
to `paid`.

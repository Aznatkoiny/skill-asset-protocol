# Employer-Funded Internal Invocation Awards Spike Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an offline accounting spike proving that an employer-funded internal Invocation can reserve an approved budget, execute a registered Skill, record unavoidable COGS, and create an employee-Creator Invocation award without an external Wielder, platform custody, or real funds.

**Architecture:** Add an isolated Node ESM package under `spikes/internal-invocation-awards/`. Its pure state machine imports the shared `allocateInternalGross` boundary from `prototype/atomic-money.mjs`, serializes reservation and finalization compare-and-swap transitions, verifies signed single-use budget credentials, and emits append-only signed receipts and statements; an injected fake executor keeps every automated path offline. This remains explicitly labeled an accounting spike and does not change `CONTEXT.md`, `docs/PRD.md`, or any ADR.

**Tech Stack:** Node.js 20+, ECMAScript modules, built-in `node:test`, `node:assert/strict`, `node:crypto`, BigInt, JSONL.

---

## Prerequisite and shared accounting contract

Complete `docs/superpowers/plans/2026-07-17-atomic-money-kernel.md` first. This spike
must import, not reimplement, the kernel's internal partition:

```js
allocateInternalGross({
  grossAtomic,
  executionCostAtomic,
  protocolFeeAtomic,
  refundReserveAtomic,
  recipientId
})
```

It returns `grossAtomic`, `executionCostAtomic`, `protocolFeeAtomic`,
`refundReserveAtomic`, `invocationAwardAtomic`, one `awardCredit`, and account-identified
`journalEntries`; every amount is `bigint`. Local decimal-string helpers exist only at
the JSON boundary. They may not perform fee, award, remainder, or account allocation.

## File map

- Create `spikes/internal-invocation-awards/package.json` — isolated offline scripts.
- Create `spikes/internal-invocation-awards/src/schema.mjs` — frozen schema constants, decimal-string/BigInt boundary helpers, and validators.
- Create `spikes/internal-invocation-awards/src/budget.mjs` — budget reservation, shared-kernel finalization, release, caps, and revision checks.
- Create `spikes/internal-invocation-awards/src/credentials.mjs` — canonical signed internal Execution credentials and one-use nonce verification.
- Create `spikes/internal-invocation-awards/src/engine.mjs` — authoritative internal Invocation lifecycle and Invocation-award transitions.
- Create `spikes/internal-invocation-awards/src/store.mjs` — serialized in-memory transactions with revision compare-and-swap for the offline spike.
- Create `spikes/internal-invocation-awards/src/statements.mjs` — receipt and whole-statement canonicalization/signing/verification, sequence/root construction, and JSONL rendering.
- Create `spikes/internal-invocation-awards/test/budget.test.mjs` — policy, authorization, cap, expiry, and concurrency tests.
- Create `spikes/internal-invocation-awards/test/engine.test.mjs` — success, failure, farming, idempotency, and conservation tests.
- Create `spikes/internal-invocation-awards/test/statements.test.mjs` — employer/employee receipt and statement verification tests.
- Create `spikes/internal-invocation-awards/demo.mjs` — deterministic no-network proof run.
- Create `spikes/internal-invocation-awards/README.md` — scope, commands, evidence label, invariants, and human-only gates.

## Contract locked by this plan

All persisted atomic amounts are non-negative decimal strings. In-memory arithmetic converts them to `bigint`; no `number` participates in money arithmetic.

```js
// ProgramPolicyV1
{
  schemaVersion: 1,
  policyId: "policy-megacorp-ledger-recon",
  version: 1,
  status: "active", // draft | approved | active | suspended | expired
  currency: "USD",
  atomicScale: 6,
  employerId: "megacorp",
  effectiveAt: "2026-07-17T00:00:00.000Z",
  expiresAt: "2026-08-01T00:00:00.000Z",
  permittedSkillIds: ["ledger-recon"],
  permittedCreatorIds: ["sam"],
  permittedWielderIds: ["megacorp-internal-agent"],
  permittedCostCenters: ["platform-engineering"],
  maxQuoteAtomic: "4000000",
  awardRule: {
    type: "residual_after_execution_fee_and_reserve",
    awardRateBps: 10000,
    rateBase: "post_cost_residual",
    rounding: "floor_atomic"
  },
  maxAwardPerInvocationAtomic: "2000000",
  maxAwardPerPeriodAtomic: "100000000",
  selfInvocation: "manager_approval_required", // excluded | manager_approval_required
  permittedManagerSignerIds: ["manager-alex"],
  permittedCredentialAuthorizerIds: ["megacorp-collar-authorizer"],
  permittedFinanceSignerIds: ["megacorp-finance"],
  vestingRule: "none",
  paymentSchedule: "monthly_in_arrears",
  terminationTreatment: "earned_remains_payable_unearned_cancelled",
  paymentRail: "employer_payroll_or_ap"
}

// EmployerBudgetV1
{
  schemaVersion: 1,
  budgetId: "budget-megacorp-2026-07",
  policyId: "policy-megacorp-ledger-recon",
  policyVersion: 1,
  period: "2026-07",
  currency: "USD",
  allocatedAtomic: "1000000000",
  reservedAtomic: "0",
  consumedAtomic: "0",
  releasedAtomic: "0",
  revision: 0,
  signerId: "megacorp-finance",
  signature: TEST_SIGNATURE_BASE64
}

// InternalQuoteV1
{
  quoteId: "quote-inv-001",
  invocationId: "inv-001",
  idempotencyKey: "run-ledger-recon-001",
  skillId: "ledger-recon",
  skillVersionHash: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  creatorId: "sam",
  wielderId: "megacorp-internal-agent",
  beneficiaryId: "megacorp",
  costCenter: "platform-engineering",
  policyId: "policy-megacorp-ledger-recon",
  policyVersion: 1,
  maxExecutionCostAtomic: "1000000",
  protocolFeeAtomic: "25000",
  refundReserveAtomic: "25000",
  maxInvocationAwardAtomic: "2000000",
  maxGrossAtomic: "3050000",
  selfInvocationApproval: null,
  expiresAt: "2026-07-17T00:05:00.000Z"
}
```

For a self-Invocation, `selfInvocationApproval` is a signed object with exactly:
`schemaVersion`, `approvalId`, `managerSignerId`, `invocationId`, `creatorId`,
`policyId`, `policyVersion`, `issuedAt`, `expiresAt`, and `signature`. It is `null` for
non-self Invocations. The manager signature is Ed25519 over canonical JSON of all
fields except `signature`, in the order just listed. The engine resolves the manager
signer through its provisioned trust map and never accepts manager key material in the
approval or request.

`TEST_SIGNATURE_BASE64` is generated from a throwaway Ed25519 key pair inside each
test process. No signed budget contains public-key material; `signerId` resolves only
through engine-provisioned finance trust roots.

`maxGrossAtomic` must equal the other four maximum components. On successful finalization:

```text
internalGross = executionCost + protocolFee + refundReserve + invocationAward
reserved = internalGross + releasedUnused
sum(all debits) = sum(all credits)
```

The authoritative state values are:

```text
Invocation: requested -> quoted -> authorized -> executing -> succeeded | failed | unresolved | cancelled
Reservation: reserved -> executing -> consumed | released | held_unresolved
Budget: allocated -> reserved -> consumed | released; held_unresolved remains fully reserved
Award: measured -> vesting_pending -> earned -> payable -> paid
Program: draft -> approved -> active -> suspended | expired
```

Policies with `vestingRule: "none"` transition `measured -> earned`; no automated test or demo advances `payable -> paid` because payroll/AP is human-controlled.

Once the engine atomically enters `executing`, it treats the executor as having started.
The executor must return exactly one validated `ExecutorOutcomeV1`:

```ts
type ExecutorOutcomeV1 =
  | {
      kind: "succeeded";
      executionCostAtomic: string;
      outputHash: `sha256:${string}`;
    }
  | {
      kind: "failed_after_start";
      executionCostAtomic: string;
      failureClass: "provider_error" | "skill_error" | "invalid_output";
    }
  | {
      kind: "unresolved_after_start";
      reason: "executor_threw" | "malformed_outcome" | "cost_unknown";
    };
```

No object with unknown keys qualifies as a validated union member; the parser maps it
to the canonical unresolved sentinel. `succeeded` and `failed_after_start` require a
non-negative decimal `executionCostAtomic` at or below the quote maximum; success also
requires a lowercase SHA-256 output hash. A thrown executor, unknown outcome kind,
missing/invalid/out-of-cap execution cost, or explicit `unresolved_after_start` never
becomes zero cost. It CAS-finalizes the Invocation as `unresolved`, changes the
reservation to `held_unresolved`, leaves the entire maximum gross in `reservedAtomic`,
creates no award, releases nothing, and emits an append-only
`execution_cost_unresolved` event. The consumed nonce and idempotency binding remain in
place. This v1 spike has no automated release path from `held_unresolved`; operator
reconciliation is a human-only future gate.

### Task 1: Scaffold the spike and validate immutable policy/quote schemas

**Files:**
- Create: `spikes/internal-invocation-awards/package.json`
- Create: `spikes/internal-invocation-awards/src/schema.mjs`
- Create: `spikes/internal-invocation-awards/test/budget.test.mjs`

- [ ] **Step 1: Write failing schema tests**

Add tests that import `validatePolicy`, `validateQuote`, `toAtomic`, and `sumAtomic` and assert:

```js
assert.equal(toAtomic("3050000"), 3_050_000n);
assert.equal(sumAtomic(["1000000", "25000", "25000", "2000000"]), 3_050_000n);
assert.throws(() => toAtomic("-1"), /non-negative decimal string/);
assert.throws(() => toAtomic("1.5"), /non-negative decimal string/);
assert.throws(() => validatePolicy({ ...ACTIVE_POLICY, status: "draft" }, NOW), /must be active/);
assert.throws(
  () => validatePolicy({ ...ACTIVE_POLICY, awardRule: { ...ACTIVE_POLICY.awardRule, awardRateBps: 9000 } }, NOW),
  /unsupported award rule.*awardRateBps must equal 10000/,
);
assert.throws(() => validateQuote({ ...QUOTE, maxGrossAtomic: "3049999" }, ACTIVE_POLICY, NOW), /maxGrossAtomic.*3050000/);
assert.throws(() => validateQuote({ ...QUOTE, wielderId: "unknown-agent" }, ACTIVE_POLICY, NOW), /Wielder is not permitted/);
```

- [ ] **Step 2: Run the focused test and verify red**

Run: `cd spikes/internal-invocation-awards && node --test test/budget.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/schema.mjs`.

- [ ] **Step 3: Add the package and schema implementation**

Use this package contract:

```json
{
  "name": "internal-invocation-awards-spike",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "description": "Offline accounting spike for employer-funded internal Invocation awards; no real funds.",
  "scripts": {
    "test": "node --test test/*.test.mjs",
    "demo": "node demo.mjs"
  }
}
```

Implement and export these exact functions from `src/schema.mjs`:

```js
export const AWARD_STATES = Object.freeze(["measured", "vesting_pending", "earned", "payable", "paid"]);
export const INVOCATION_STATES = Object.freeze(["requested", "quoted", "authorized", "executing", "succeeded", "failed", "unresolved", "cancelled"]);

export function toAtomic(value) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error("atomic amount must be a non-negative decimal string");
  }
  return BigInt(value);
}

export function fromAtomic(value) {
  if (typeof value !== "bigint" || value < 0n) throw new Error("atomic amount must be a non-negative bigint");
  return value.toString();
}

export function sumAtomic(values) {
  return values.reduce((sum, value) => sum + toAtomic(value), 0n);
}

```

Also export `validatePolicy(policy, now)`, `validateQuote(quote, policy, now)`, and
`parseExecutorOutcome(value, quote)`.
The two validators must reject unknown keys, wrong schema versions,
expired/not-yet-effective policy, disallowed identifiers, invalid ISO timestamps,
Skill hashes outside `^sha256:[0-9a-f]{64}$`, and any quote component above the
effective policy cap. Each returns `Object.freeze(structuredClone(input))`; neither
mutates caller data.
`parseExecutorOutcome` implements the strict union above. It returns a frozen validated
success/failure outcome, and returns the frozen canonical
`{ kind: "unresolved_after_start", reason: "malformed_outcome" }` sentinel for every
unknown kind, unknown key, missing cost, malformed cost/hash, or cost above the quote
maximum. It never supplies a default cost.

This v1 spike accepts only the explicit immutable award rule shown above:
`type === "residual_after_execution_fee_and_reserve"`, `awardRateBps === 10000`,
`rateBase === "post_cost_residual"`, and `rounding === "floor_atomic"`. The kernel
therefore assigns 100% of the post-cost residual to the Invocation award, subject to
per-Invocation and period caps. Any other rate/type/base/rounding combination fails
closed before reservation; the v1 implementation must not silently ignore or accept a
different rate. Variable rates and the destination of any non-award residual remain
unvalidated/proposed and require a future effective-dated policy version plus a new
kernel contract; historical policy is never mutated.

- [ ] **Step 4: Run the schema tests and type-free syntax check**

Run: `cd spikes/internal-invocation-awards && npm test`

Expected: PASS with all schema assertions green, including rejection of
`awardRateBps: 9000`, and zero network access.

- [ ] **Step 5: Commit the schema slice**

```bash
git add spikes/internal-invocation-awards/package.json spikes/internal-invocation-awards/src/schema.mjs spikes/internal-invocation-awards/test/budget.test.mjs
git commit -m "spike: define internal Invocation award schemas"
```

### Task 2: Implement atomic budget reservation and release

**Files:**
- Create: `spikes/internal-invocation-awards/src/budget.mjs`
- Modify: `spikes/internal-invocation-awards/test/budget.test.mjs`

- [ ] **Step 1: Add failing budget tests**

Cover the exact API:

```js
const budget = createBudget(SIGNED_BUDGET, { trustedFinanceSigners: FINANCE_SIGNERS, policy: ACTIVE_POLICY, now: NOW });
const reserved = reserveBudget(budget, QUOTE, { expectedRevision: 0, reservationId: "res-001", now: NOW });
assert.equal(reserved.budget.reservedAtomic, "3050000");
assert.equal(reserved.budget.revision, 1);
assert.equal(reserved.reservation.state, "reserved");

assert.throws(
  () => reserveBudget(reserved.budget, QUOTE_2, { expectedRevision: 0, reservationId: "res-002", now: NOW }),
  /stale budget revision/,
);
assert.throws(() => reserveBudget(SMALL_BUDGET, QUOTE, { expectedRevision: 0, reservationId: "res-003", now: NOW }), /insufficient remaining budget/);

const finalized = finalizeReservation(reserved.budget, reserved.reservation, {
  grossAtomic: "2750000",
  executionCostAtomic: "700000",
  protocolFeeAtomic: "25000",
  refundReserveAtomic: "25000",
  recipientId: "sam"
});
assert.equal(finalized.budget.consumedAtomic, "2750000");
assert.equal(finalized.budget.releasedAtomic, "300000");
assert.equal(finalized.budget.reservedAtomic, "0");
```

Also assert full release before execution, partial release after a failed execution with unavoidable COGS, duplicate finalization rejection, and non-negativity/conservation after every transition.

Assert `finalized.allocation.invocationAwardAtomic === 2_000_000n` and
`finalized.allocation.awardCredit` equals `{ recipientId: "sam", amountAtomic:
2_000_000n }`. Assert its four `journalEntries` all debit
`employer:invocation-gross`, credit the provider/protocol/reserve/employee account IDs
returned by the kernel, and sum to `grossAtomic`; persist those returned entries
verbatim in the budget event. Add a source-boundary test that imports the same
`allocateInternalGross` export from `../../../prototype/atomic-money.mjs`; do not copy
its subtraction logic into the spike.

Generate the signer key in the test process. Add cases proving a self-signed budget
whose key is not in `FINANCE_SIGNERS`, a changed amount after signing, an unknown or
policy-disallowed `signerId`, an added self-declared `signerPublicKeyPem`, and an
expired policy version all fail before any reservation is created.

- [ ] **Step 2: Run the focused test and verify red**

Run: `cd spikes/internal-invocation-awards && node --test --test-name-pattern='budget|reservation' test/budget.test.mjs`

Expected: FAIL because `src/budget.mjs` does not exist.

- [ ] **Step 3: Implement the budget API**

Export these exact call contracts:

| Export | Input | Result |
| --- | --- | --- |
| `canonicalBudgetBytes(unsignedBudget)` | every `EmployerBudgetV1` field except `signature`, in the schema order above | UTF-8 canonical JSON bytes |
| `signBudget(unsignedBudget, privateKey)` | unsigned budget plus a throwaway test signer | frozen signed budget with a base64 Ed25519 signature and no public key field |
| `createBudget(signedBudget, { trustedFinanceSigners, policy, now })` | signed budget, provisioned `Record<signerId, trustedPublicKeyPem>`, and trusted policy | verified frozen budget state |
| `remainingAtomic(budget)` | verified budget | `allocatedAtomic - reservedAtomic - consumedAtomic` as `bigint` |
| `reserveBudget(budget, quote, { expectedRevision, reservationId, now })` | exact revision and active quote | `{ budget, reservation, event }` |
| `finalizeReservation(budget, reservation, actual)` | actual gross, execution cost, exact quote-final fee, reserve, and recipient | `{ budget, reservation, allocation, event }` |
| `releaseReservation(budget, reservation, { executionCostAtomic, reason })` | pre-execution cancellation or validated `failed_after_start` data | `{ budget, reservation, event }` |
| `holdUnresolvedReservation(budget, reservation, { reason })` | post-start execution whose actual COGS cannot be validated | `{ budget, reservation, event }` with unchanged budget amounts and `held_unresolved` state |

`createBudget` rejects every unknown field, resolves `signerId` only through
`trustedFinanceSigners`, requires the ID in `policy.permittedFinanceSignerIds`, and
verifies the signature. Embedded/self-reported key material is always invalid.

Every transition returns a new frozen budget plus an append-only event; it never
mutates its input. `reserveBudget` requires exact revision equality and reserves
`quote.maxGrossAtomic`. `finalizeReservation` converts validated persisted strings to
`bigint`, calls `allocateInternalGross` exactly once, enforces the kernel result's
`grossAtomic <= reserved`, requires the actual fee to equal the quote-final
`protocolFeeAtomic`, verifies COGS/reserve/award remain within their quote and policy
caps, marks the reservation consumed, increments revision, moves gross to consumed,
moves the remainder to the cumulative `releasedAtomic` audit counter, and subtracts
the entire reservation from `reservedAtomic`. The spendable invariant is
`remainingAtomic = allocatedAtomic - reservedAtomic - consumedAtomic`; released is a
cumulative flow counter and is not subtracted twice. `releaseReservation` records
unavoidable execution COGS only when `reason === "failed_after_start"` and the caller
supplies the validated executor-reported cost; all other components, including the
award, release. It has no branch for unknown post-start cost and may not accept a
defaulted zero. `held_unresolved` reservations are rejected by both release and award
finalization APIs.
`holdUnresolvedReservation` permits only the enumerated unresolved reasons, increments
the budget revision without changing allocated/reserved/consumed/released amounts, and
emits `execution_cost_unresolved`; it is idempotency-protected and cannot be called on a
pre-start reservation.

- [ ] **Step 4: Run all budget tests**

Run: `cd spikes/internal-invocation-awards && npm test`

Expected: PASS; stale revision, insufficient budget, caps, and release cases are green.

- [ ] **Step 5: Commit the budget slice**

```bash
git add spikes/internal-invocation-awards/src/budget.mjs spikes/internal-invocation-awards/test/budget.test.mjs
git commit -m "spike: reserve employer Invocation budgets atomically"
```

### Task 3: Add signed one-use credentials and the authoritative Invocation engine

**Files:**
- Create: `spikes/internal-invocation-awards/src/credentials.mjs`
- Create: `spikes/internal-invocation-awards/src/engine.mjs`
- Create: `spikes/internal-invocation-awards/src/store.mjs`
- Create: `spikes/internal-invocation-awards/test/engine.test.mjs`

- [ ] **Step 1: Write failing credential and lifecycle tests**

Generate Ed25519 keys at test runtime with `generateKeyPairSync("ed25519")`; do not commit any key. Assert:

```js
const credentialAuthorizers = {
  "megacorp-collar-authorizer": publicKey.export({ type: "spki", format: "pem" })
};
const store = new InMemoryEngineStore(createEngineState({
  signedBudget: SIGNED_BUDGET,
  policies: { "policy-megacorp-ledger-recon@1": ACTIVE_POLICY },
  financeSigners: FINANCE_SIGNERS,
  managerSigners: MANAGER_SIGNERS,
  credentialAuthorizers,
  now: NOW
}));
const signed = signCredential(CREDENTIAL_PAYLOAD, privateKey);
assert.equal(verifyCredential(signed, publicKey, NOW).invocationId, "inv-001");
assert.throws(() => verifyCredential({ ...signed, skillVersionHash: OTHER_HASH }, publicKey, NOW), /signature/);
assert.throws(() => verifyCredential(signed, publicKey, AFTER_EXPIRY), /expired/);

const authorized = await authorizeInternalInvocation({
  store,
  quote: QUOTE,
  expectedRevision: 0,
  expectedBudgetRevision: 0,
  reservationId: "res-001",
  credentialNonce: NONCE,
  credentialIssuedAt: NOW,
  credentialExpiresAt: FIVE_MINUTES_LATER,
  credentialAuthorizerId: "megacorp-collar-authorizer",
  managerApproval: null
});
assert.equal(authorized.reservation.state, "reserved");
const authorizedCredential = signCredential(authorized.credentialPayload, privateKey);
const executor = async () => ({
  kind: "succeeded",
  executionCostAtomic: "700000",
  outputHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
});
const result = await executeAuthorizedInvocation({
  store,
  quote: QUOTE,
  credential: authorizedCredential,
  executor,
  now: NOW
});
assert.equal(result.invocation.state, "succeeded");
assert.equal(result.award.amountAtomic, "2000000");
assert.equal(result.award.state, "earned");
assert.equal(result.invocation.externalRoyaltyCreditsAtomic, "0");
assert.equal(result.invocation.employerSelfCreditAtomic, "0");
await assert.rejects(
  executeAuthorizedInvocation({ store, quote: QUOTE, credential: authorizedCredential, executor, now: NOW }),
  /credential already consumed|idempotency key/,
);
```

Add rejection tests for unauthorized Wielder, expired budget, exceeded quote cap,
period award cap, repeated idempotency key, insufficient budget, self-Invocation
without manager approval, self-approval, manager not permitted by the policy, expired
manager approval, approval bound to another Invocation, and executor failure. Assert
every rejection before `executing` calls the executor zero times; post-execution
`failed_after_start` records the exact executor-reported COGS and creates no award.

Add table-driven executor-outcome tests:

1. `succeeded` with valid `executionCostAtomic` finalizes the kernel allocation and
   award.
2. `failed_after_start` with valid `executionCostAtomic` consumes only that COGS,
   releases the remaining reservation, and creates no award.
3. A thrown executor, explicit `unresolved_after_start`, unknown `kind`, missing cost,
   negative/decimal/non-string cost, cost above `maxExecutionCostAtomic`, unknown key,
   or malformed success `outputHash` transitions to `unresolved` plus
   `held_unresolved`.

For every case in item 3, assert the entire original reservation remains in
`budget.reservedAtomic`, `consumedAtomic` and `releasedAtomic` do not change, no award or
money journal entry exists, the nonce remains consumed, retry cannot execute, and an
`execution_cost_unresolved` event is appended. Explicitly prove none of those cases is
converted to `executionCostAtomic: "0"`.

Add sequencing tests proving: a correctly signed credential cannot execute against a
state with no persisted reservation; a reserved authorization cannot execute with a
missing credential; a credential for reservation A cannot execute reservation B; a
cancelled/released reservation rejects its previously signed credential; and signing
happens only after `authorizeInternalInvocation` returns the exact credential payload.
Generate a second Ed25519 key pair and prove an unknown authorizer ID, a signature made
by an untrusted key, an authorizer disallowed by the active policy, and a signed object
carrying a self-declared `publicKeyPem` all fail before the executor runs. No execution
API accepts a public key parameter.
For self-Invocation approval, add the same regression with a valid signature from an
unprovisioned manager and with an embedded manager key; neither may reserve budget.

Add an overlapping-Promise regression: start two
`authorizeInternalInvocation` calls against `expectedBudgetRevision: 0` before either
settles and await `Promise.allSettled`. Exactly one must fulfill, one must reject with
`stale engine revision`, and the final snapshot must contain one reservation and one
idempotency binding. Add the same race around duplicate execution start/finalization;
the executor and award finalizer run once. Finally, prove the period-cap exposure is
`earned non-reversed awards + maxInvocationAwardAtomic for every reserved, executing,
or held-unresolved
authorization` under that policy/version/period. Two reservations whose maximum
awards would exceed the period cap must not coexist even before either executes.

- [ ] **Step 2: Run engine tests and verify red**

Run: `cd spikes/internal-invocation-awards && node --test test/engine.test.mjs`

Expected: FAIL with missing `credentials.mjs`, `store.mjs`, or `engine.mjs`.

- [ ] **Step 3: Implement canonical credential signing**

`src/credentials.mjs` must canonicalize keys in this exact order:

```text
schemaVersion, credentialAuthorizerId, invocationId, reservationId, idempotencyKey, skillId,
skillVersionHash, policyId, policyVersion, nonce, issuedAt, expiresAt
```

Export `canonicalCredentialBytes(payload)`, `signCredential(payload, privateKey)`,
`verifyCredential(signed, trustedPublicKey, now)`, `canonicalManagerApprovalBytes(approval)`,
`signManagerApproval(approval, privateKey)`, and `verifyManagerApproval(approval, {
policy, quote, managerSigners, now })`. Signatures are base64 Ed25519 over UTF-8
canonical JSON. Credential verification rejects extra keys, invalid timestamps, bad
signatures, embedded/self-declared key material, and expiry. The engine compares the verified credential's
policy/version/hash/reservation bindings to the active inputs, then consumes the nonce
before execution. Manager verification requires an expected key for a
policy-permitted signer, rejects self-approval and mismatched/expired bindings, and
never reads a public key from the approval payload.

- [ ] **Step 4: Implement the engine**

Export:

```js
export function createEngineState({ signedBudget, policies, financeSigners, managerSigners, credentialAuthorizers, now }) {
  return Object.freeze({
    revision: 0,
    budget: createBudget(signedBudget, {
      trustedFinanceSigners: financeSigners,
      policy: policies[`${signedBudget.policyId}@${signedBudget.policyVersion}`],
      now
    }),
    policies,
    financeSigners,
    managerSigners,
    credentialAuthorizers,
    invocations: Object.freeze({}),
    reservations: Object.freeze({}),
    awards: Object.freeze({}),
    consumedNonces: Object.freeze({}),
    idempotency: Object.freeze({}),
    events: Object.freeze([])
  });
}

```

In `src/store.mjs`, export `InMemoryEngineStore`. `snapshot()` returns the current
frozen state. `transact(expectedRevision, transition)` queues transitions on one
private Promise tail, checks `expectedRevision` only after acquiring the queue,
requires the returned state's revision to be exactly current + 1, freezes it, and
publishes it atomically. A throwing transition leaves state/revision unchanged and
does not poison the queue. This is the spike's executable single-process CAS boundary;
the README must not imply it is a distributed database lock.

Also expose `transactRecord(recordId, expectedRecordRevision, transition)`. It acquires
the same queue, checks the named Invocation/reservation revision and immutable
`executionAttemptId` against the latest global snapshot, then applies one global
revision. This lets finalization coexist with unrelated reservations while preventing
two completions of the same execution attempt.

Export three lifecycle functions:

| Export | Contract |
| --- | --- |
| `authorizeInternalInvocation(input)` | Runs one store transaction that validates policy/quote, total award exposure, manager approval, idempotency, and expected revision; atomically persists reservation plus expected credential payload; returns `{ state, invocation, reservation, credentialPayload, events }` without executing or signing. |
| `cancelInternalAuthorization({ store, expectedRevision, reservationId, reason, now })` | Runs one transaction that releases a still-reserved authorization, appends `cancelled`, and makes every credential for that reservation unusable. |
| `executeAuthorizedInvocation(input)` | Transaction 1 verifies the already-persisted reservation/credential and atomically marks executing plus consumes nonce; it awaits the executor outside the lock; transaction 2 CAS-finalizes success, validated post-start failure, or unresolved hold exactly once. |

`authorizeInternalInvocation` takes the provisioned `store`, `expectedRevision`,
`expectedBudgetRevision`, `reservationId`, a
caller-generated lowercase 32-byte `credentialNonce`, issued/expiry times,
`credentialAuthorizerId`, and `managerApproval`. Non-self Invocations pass
`managerApproval: null`. It resolves the immutable effective-dated policy and manager
key from engine state, validates the quote, and enforces the period cap by summing prior non-reversed awards
plus the quote maximums of all reserved/executing/held-unresolved authorizations for the same
policy/version/period, verifies any required manager approval, atomically reserves,
stores the canonical credential payload, and creates requested/quoted/authorized
events. It never receives a private key and never signs a credential.

`createEngineState` is the only trust-root provisioning boundary. It validates and
deep-freezes immutable `policies: Record<policyId@version, ProgramPolicyV1>`,
`financeSigners`, `managerSigners`, and `credentialAuthorizers` maps, verifies the
signed budget through the finance map and policy allow-list, and rejects incomplete or
extra-key configuration. None of these maps comes from a quote, approval, credential,
or lifecycle call. Authorization requires manager/authorizer IDs in both the relevant
state map and the resolved policy allow-list, and binds the credential authorizer ID
into the canonical payload.

The caller signs only the exact returned payload. `executeAuthorizedInvocation`
resolves `credentialAuthorizerId` from the signed payload against the trusted map
already stored in engine state, verifies with that key, byte-compares
the verified canonical payload with the reserved record, requires the reservation to
still be `reserved`, consumes the nonce, emits executing, and awaits the injected
executor outside the store transaction. It then reacquires the store and uses
`transactRecord` on the persisted execution-attempt revision. It calls
`parseExecutorOutcome` on the return value. Only a validated success passes the
executor's reported COGS, derived actual gross, exact quote-final fee, reserve, and
Creator recipient to the shared kernel through `finalizeReservation`. A validated
`failed_after_start` passes its exact reported COGS to `releaseReservation` and creates
no award. A throw or any unresolved/malformed outcome calls
`holdUnresolvedReservation`; it does not invoke either monetary finalizer. Success
finalizes an award; validated failure records unavoidable COGS and releases unused
budget; unresolved cost holds the full reservation. It rejects any external
Royalty-claim or employer-self-credit input.
Corrections are new reversal/adjustment events; no event is overwritten.

The engine and statement layers consume `allocation.journalEntries` returned by
`allocateInternalGross`. They do not reconstruct debit/credit account IDs or monetary
entries from component fields.

- [ ] **Step 5: Run all tests**

Run: `cd spikes/internal-invocation-awards && npm test`

Expected: PASS, including failure-before-execution and post-execution-failure cases.

- [ ] **Step 6: Commit the engine slice**

```bash
git add spikes/internal-invocation-awards/src/credentials.mjs spikes/internal-invocation-awards/src/store.mjs spikes/internal-invocation-awards/src/engine.mjs spikes/internal-invocation-awards/test/engine.test.mjs
git commit -m "spike: execute budget-backed internal Invocations"
```

### Task 4: Produce identical signed receipts and statements for employer and employee

**Files:**
- Create: `spikes/internal-invocation-awards/src/statements.mjs`
- Create: `spikes/internal-invocation-awards/test/statements.test.mjs`

- [ ] **Step 1: Write failing receipt/statement tests**

Assert one successful receipt includes invocation, reservation, Skill hash, effective
policy, the kernel-returned account-identified journal entries, execution COGS, fee,
reserve, award, sequence, and no external settlement hash. Employer and employee
verify the same bytes and signature. Build a statement containing opening,
reservations, releases, charges, awards, reversals, payments, and closing balance;
assert contiguous sequences and a deterministic SHA-256 binary Merkle root. A gap from
sequence 1 to 3 must throw `statement sequence gap: expected 2, received 3`.
Also build an unresolved receipt and assert it contains the held reservation amount,
`executionCostStatus: "unresolved"`, no award, and no monetary journal entries; it may
not claim zero COGS or a released reservation.

Sign the entire built statement and verify the same canonical bytes as employer and
employee. Add one-at-a-time tamper cases for `statementId`, employer/Creator/period,
`openingAtomic`, each payment field and amount, each reversal field and amount,
reservation/release/charge/award/payment/reversal totals, `closingAtomic`, ordered
receipt hashes, receipt sequence bounds, and receipt Merkle root. Every mutation must
fail either the statement signature or deterministic recomputation. A valid set of
individually signed receipts with an unsigned or attacker-resigned statement is not
accepted by the trusted statement verifier.

- [ ] **Step 2: Run and verify red**

Run: `cd spikes/internal-invocation-awards && node --test test/statements.test.mjs`

Expected: FAIL because `src/statements.mjs` is absent.

- [ ] **Step 3: Implement receipt and statement functions**

Export these exact functions: `canonicalReceiptBytes(receipt)`,
`signReceipt(receipt, privateKey)`, `verifyReceipt(signedReceipt, publicKey)`,
`receiptHash(signedReceipt)`, `buildStatement({ statementId, employerId, creatorId,
period, openingAtomic, receipts, payments, reversals, statementSignerId })`,
`canonicalStatementBytes(unsignedStatement)`,
`signStatement(unsignedStatement, privateKey)`,
`verifyStatement(signedStatement, { signedReceipts, publicKey })`, and
`renderJsonl(events)`.
Canonicalizers return `Uint8Array`; hashes are lowercase `sha256:` strings; signers
return frozen objects with base64 Ed25519 signatures; verifiers return the validated
unsigned object; `renderJsonl` returns newline-terminated canonical JSON records.

`buildStatement` returns an unsigned frozen `StatementV1` with these canonical fields
in this exact order:

```text
schemaVersion, statementId, employerId, creatorId, period, currency, atomicScale,
openingAtomic, firstReceiptSequence, lastReceiptSequence, receiptHashes,
receiptMerkleRoot, reservationTotalAtomic, releaseTotalAtomic, chargeTotalAtomic,
awardTotalAtomic, reversals, reversalTotalAtomic, payments, paymentTotalAtomic,
closingAtomic, statementSignerId
```

Each payment is exactly `paymentId, amountAtomic, paidAt, railReference`; each reversal
is exactly `reversalId, receiptHash, amountAtomic, reason, occurredAt`. IDs are unique;
timestamps are UTC; amounts are non-negative decimal strings; payments sort by
`paymentId` and reversals by `reversalId`. `receiptHashes` are the ordered hashes of the
complete signed receipts at contiguous sequences. Totals are recomputed from signed
receipt events and the full payment/reversal arrays. Payable closing balance is exactly
`openingAtomic + awardTotalAtomic - reversalTotalAtomic - paymentTotalAtomic` and may
not be negative. Reservation, release, and charge totals remain separately signed audit
totals and are not silently folded into that payable equation.

`canonicalStatementBytes` rejects extra/missing keys and serializes every field above
except the final `signature`; it therefore authenticates the full economic statement,
not merely receipt leaves or their Merkle root. `signStatement` adds only the base64
Ed25519 `signature`. `verifyStatement` uses the caller-provisioned trusted public key,
first verifies that whole-statement signature, then independently verifies every
receipt signature/hash/sequence, recomputes the Merkle root, all totals, and closing
balance, and byte-compares the recomputed unsigned statement. It never trusts a public
key embedded in the statement.

Merkle leaves are the binary SHA-256 digest of each canonical signed receipt, sorted by contiguous sequence. Odd nodes duplicate the last hash. The signed statement calls this an inclusion root and explicitly does not call it completeness proof; sequence continuity, the authenticated receipt-hash list, and cross-party statement comparison supply the completeness signal.

- [ ] **Step 4: Run all tests**

Run: `cd spikes/internal-invocation-awards && npm test`

Expected: PASS with receipt-signature, whole-statement-signature, every economic-field
tamper, root-tamper, and sequence-gap rejection green.

- [ ] **Step 5: Commit the audit slice**

```bash
git add spikes/internal-invocation-awards/src/statements.mjs spikes/internal-invocation-awards/test/statements.test.mjs
git commit -m "spike: sign internal award receipts and statements"
```

### Task 5: Add the deterministic demonstration and honest spike report

**Files:**
- Create: `spikes/internal-invocation-awards/demo.mjs`
- Create: `spikes/internal-invocation-awards/README.md`

- [ ] **Step 1: Add the offline demo**

The demo generates throwaway Ed25519 keys in memory, activates the exact example
policy, allocates a simulated `$1,000.000000` employer accounting budget, calls
`authorizeInternalInvocation` to reserve `$3.050000`, signs only the returned
credential payload, and calls `executeAuthorizedInvocation` with a fake successful
executor returning `{ kind: "succeeded", executionCostAtomic: "700000",
outputHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }`. It records `$0.700000` COGS,
`$0.025000` protocol fee, `$0.025000` reserve,
and `$2.000000` Invocation award, releases `$0.300000`, verifies the same receipt for
employer and employee, builds and signs the full zero-opening statement, verifies its
receipt hashes/totals/closing balance for both parties, and prints:

```text
INTERNAL INVOCATION AWARD SPIKE — SIMULATED ACCOUNTING, NO REAL FUNDS
invocation inv-001: succeeded
reserved 3.050000 USD
consumed 2.750000 USD
released 0.300000 USD
employee-Creator Invocation award 2.000000 USD: earned, not paid
external Wielder required: no
external Royalty-claim credits: 0
platform-held balance: 0
receipt signature: verified by employer and employee
statement signature and economic totals: verified by employer and employee
RESULT: accounting path demonstrated; demand, payroll, tax, employment-law, securities, and custody validation remain not-run
```

- [ ] **Step 2: Document scope and human gates**

The README must state at the top: `SPIKE — deterministic accounting evidence only`. It must say no network, wallet, chain, API key, funded account, payroll transfer, or real money is used. It must distinguish the internal Invocation award from external Royalty-claim revenue, list every tested rejection, and state that counsel-drafted instrument, employer agreement, and payroll/AP payment are human-only gates.
It must also document the strict executor outcome union and state that thrown,
malformed, or unknown-cost post-start execution holds the full reservation as
unresolved; the spike never substitutes zero COGS, releases that hold, or creates an
award automatically.
Document that receipt signatures authenticate individual events while the separate
whole-statement signature authenticates opening balance, full payment/reversal arrays,
derived totals, closing balance, and ordered receipt hashes; a Merkle inclusion root by
itself does not authenticate or prove completeness of the surrounding statement.

- [ ] **Step 3: Run the complete verification**

Run: `cd spikes/internal-invocation-awards && npm test && npm run demo`

Expected: tests PASS; demo prints the exact accounting totals above and contains `NO REAL FUNDS` plus `not paid`.

Run: `! rg -n 'grossAtomic\s*-|protocolFeeAtomic\s*-|invocationAwardAtomic\s*=' spikes/internal-invocation-awards/src`

Expected: exit 0 and no duplicated allocation expression; gross partitioning appears
only in `prototype/atomic-money.mjs`.

- [ ] **Step 4: Confirm protected corpus and secrets are untouched**

Run: `git diff --exit-code -- CONTEXT.md docs/PRD.md docs/adr && ! git diff --cached --name-only | rg '(^|/)\.env$|private.*key'`

Expected: exit 0 and no output.

- [ ] **Step 5: Commit the completed spike**

```bash
git add spikes/internal-invocation-awards/demo.mjs spikes/internal-invocation-awards/README.md
git commit -m "docs: report internal Invocation award spike"
```

## Definition of done

- `npm test` and `npm run demo` pass with no network or secrets.
- The success path needs no external Wielder and creates no employer self-credit.
- Authorization reserves budget before credential signing; execution rejects absent, mismatched, consumed, cancelled, or released reservations.
- Execution resolves the payload's policy-permitted authorizer ID from engine-provisioned trust roots; it never accepts credential key material from the request.
- Reservation, consumption, release, COGS, fee, reserve, and award conserve atomic units exactly.
- Successful finalization uses `prototype/atomic-money.mjs#allocateInternalGross`; the spike contains no second allocation implementation.
- V1 accepts only the immutable 100%-residual award rule (`awardRateBps === 10000`); every other rate fails before reservation and is not silently ignored.
- Unauthorized, expired, capped, duplicate, self-farmed, and underfunded requests fail before execution.
- Serialized CAS permits only one reservation at a stale revision and only one finalization per execution attempt; reserved, executing, and held-unresolved maximum awards count toward the period cap.
- Successful and post-start failed outcomes require validated executor-reported COGS;
  failed execution earns no award while unavoidable COGS remains visible.
- Thrown, malformed, or unknown-cost post-start execution becomes an unresolved full
  reservation hold with no release, no award, and no zero-cost substitution.
- Employer and employee verify the same signed receipt and contiguous statement.
- Employer and employee verify one whole-statement signature binding opening balance,
  complete payments/reversals, every economic total, closing balance, and ordered
  receipt hashes; signed receipts alone cannot authenticate a mutable statement shell.
- The README labels the result `spike`, `simulated`, `no real funds`, and `accounting evidence only`.
- `CONTEXT.md`, `docs/PRD.md`, and `docs/adr/` remain unchanged.

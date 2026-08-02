# Protected Corpus Amendment Proposal — Employer-Funded Internal Invocations

**Status:** PROPOSED / NOT CANONICAL

**Date:** 2026-07-17

**Approval state:** Pending explicit user approval. No protected corpus file is changed by this proposal.

**Protected targets:** `CONTEXT.md`, `docs/PRD.md`, `docs/adr/0003-payment-gated-execution.md`, `docs/adr/0005-two-leg-cross-chain-settlement.md`, `docs/adr/0006-phased-rollout-closed-modes-first.md`, `docs/adr/0007-closed-mode-compensation-layer-as-terminal-product.md`, and `docs/adr/0008-the-wielder-is-a-wallet.md`.

## Why an amendment is proposed

The protected corpus currently makes external Wielder revenue the source of Intra-org compensation. That leaves the terminal compensation product dependent on an external customer and makes the central design-partner pitch read like an internal usage award even though the architecture does not fund one. The remediation design proposes a different terminal-mode accounting event: a successful qualified internal Invocation consumes an employer-approved budget and may create an employer-sponsored Invocation award for the employee-Creator. External Invocations remain optional later upside distributed through the co-held Royalty claim.

This proposal also aligns the corpus with seven evidence boundaries established by the adversarial review:

1. the Collar is the authoritative Invocation and settlement ledger;
2. gross price is allocated only after COGS, settlement cost, protocol fee, and refund reserve;
3. a settled failure remains recorded;
4. Phase 0 proves wallet registration and declared ancestry, not authorship, originality, or safety;
5. registry telemetry is settlement-verifiable, not unfakeable;
6. historical results without committed normalized samples are preserved but suppressed from publication;
7. post-start execution cost is never defaulted to zero: unknown cost holds the full reservation for reconciliation.

## Proposed decision summary

1. **Terminal Intra-org event.** The employer is the Beneficiary and compensation-fund source for internal Invocations. An authorized internal Wielder uses a signed, single-use budget credential issued by a provisioned policy-permitted credential authorizer. A successful qualified Invocation creates an employer-sponsored Invocation award for the employee-Creator under an effective-dated employer policy.
2. **No platform custody.** The approved budget is an authorization and accounting limit retained by the employer, not a prepaid balance held by the platform. Employee payment occurs through employer payroll or accounts payable under a counsel-drafted instrument.
3. **Two distinct entitlements.** An internal Invocation award is an employer compensation obligation. A Royalty claim is an entitlement to external Invocation revenue. The employer receives no self-credit on internal use.
4. **Two credential sources.** External Invocations retain a settled x402 payment credential bound to the settlement transaction hash. Internal Invocations use budget-reservation credentials signed by a provisioned credential authorizer whose identifier is permitted by the effective policy. Request-supplied keys are never trust roots. Neither executes from a quote alone.
5. **Accounting authority.** The Collar owns append-only authoritative records and signed receipts. A Wielder ledger is a receipt view and never supplies authoritative splits.
6. **Registration language.** Phase 0 starts at `wallet_asserted`. `repository_control_verified` means a trusted forge signer observed the wallet-signed challenge in the exact proof commit of a verifier-provisioned repository snapshot; it does not prove current remote-repository ownership or legal authorship. Organization approval is a separately signed higher evidence level. None is a safety review.
7. **Closed-mode chain boundary.** Phase 0 remains registration-only for closed modes. It does not distribute native transferable Story royalty tokens while the contractual closed-mode entitlement must remain non-transferable.
8. **Registry language.** Settlement proves value moved. Independent/linked payer classification comes only from a verifier-controlled billing registry; caller claims are audit-only, and unknown relationships remain allow-listed with low confidence. Settlement does not prove independent demand, quality, usefulness, authorship, originality, or safety.
9. **Evidence language.** Measured claims require a committed normalized evidence bundle. A pinned historical receipt proves only the documented transaction fields and the repository's historical label. Historical unreproducible results remain historical and non-publishable.
10. **Education.** Education remains deferred because free re-authoring dominated every positive tested inherit rate under the stated deterministic baseline. Only living school-maintained value or direct school-to-employer licensing remains eligible for a future experiment.
11. **Post-start cost uncertainty.** A successful or known failed-after-start internal Invocation must carry validated actual execution COGS. A thrown executor, malformed outcome, or unknown post-start COGS becomes `unresolved` with the full reservation `held_unresolved`; it creates no award and cannot be reported as zero-cost or automatically released.

## Proposed ubiquitous-language additions

### Invocation award

An **Invocation award** is an employer-sponsored compensation allocation created by a successful qualified internal Invocation under an approved, effective-dated employer policy. It is not external revenue, not a Royalty claim, not a transferable instrument, not an on-chain token, and not paid until the employer's payroll or accounts-payable process marks it paid.

### Internal Execution credential

An **internal Execution credential** is a signed, single-use, non-transferable authorization binding one Invocation, one employer-budget reservation, one immutable Skill version, one policy version, one credential-authorizer identifier, one expiry, and one nonce. Its signature must verify against the provisioned authorizer map and the authorizer identifier must be permitted by the effective policy; a request-supplied public key is ignored and rejected. It authorizes execution but is not money and cannot be redeemed or reused.

### Registration attestation

A **registration attestation** states the evidence attached to a Skill registration:

- `wallet_asserted`: a wallet registered a content hash and declared ancestry;
- `repository_control_verified`: a trusted forge signer observed the wallet-signed challenge and exact bytes in the named immutable proof commit of a verifier-provisioned repository snapshot;
- `organization_approved`: an authorized organization signer approved the Skill and Creator relationship.

Repository evidence does not establish current remote ownership or control; it establishes only the signed snapshot/commit observation above. Registration attestation does not prove originality, legal ownership, absence of prior art, or safety. Safety review is a separate status.

## Proposed `CONTEXT.md` amendment map

### Opening identity and archetypes

Replace the Intra-org funding sentence with:

> **Intra-org**: employee-Creator and employer co-hold the Royalty claim on external Invocation revenue. For internal use, the employer-Beneficiary authorizes an Invocation budget; a successful qualified internal Invocation may create an employer-sponsored Invocation award for the employee-Creator. Internal awards do not require external demand and do not credit the employer back to itself.

Preserve Marketplace as future optionality and Education as deferred.

### Wielder and Beneficiary

Add:

> An external Wielder proves authorization with a settled x402 payment credential. An internal Wielder proves authorization with an employer-budget credential signed by a provisioned policy-permitted credential authorizer. The Beneficiary funds the relevant path: an external Beneficiary funds external revenue; the employer-Beneficiary funds internal Invocation awards.

### Collar

Replace “off-chain meter” with:

> The Collar is the authoritative append-only Invocation, funding, execution, cost, and allocation ledger. It signs receipts delivered to the Wielder, Beneficiary, Creator, and employer as applicable. Wielder-side ledgers are receipt views, not compensation ledgers.

### Relationships

Add:

> A successful qualified internal Invocation may create an Invocation award under an employer policy. A successful externally funded Invocation may create Royalty-claim credits. These are separate events and are never reported as one revenue stream.

### Execution credential

Replace the payment-only definition with:

> A single-use authorization required before a Skill runs. External Invocations use a settled x402 payment reference; internal Invocations use an employer-budget reservation signed by a provisioned policy-permitted credential authorizer. Finance and manager approvals likewise resolve provisioned signer identifiers, never request-supplied public keys. No accepted quote alone authorizes execution.

### Flagged ambiguities

Add:

> Employer-funded internal compensation is an accounting and policy design until an employer agreement, counsel-drafted instrument, and payroll/AP integration exist. A successful accounting spike is not demand, tax, employment-law, securities, custody, or payment validation.

## Proposed `docs/PRD.md` amendment map

### Executive Summary

Replace the statement that both Intra-org co-holders earn only from external Invocations with:

> Intra-org compensation works without an external customer. The employer-Beneficiary authorizes a bounded internal Invocation budget. A successful qualified Invocation records actual COGS and fees and creates an employee-Creator Invocation award under the effective employer policy. External Wielders, if later enabled, create separate third-party revenue distributed through the employee/employer co-held Royalty claim.

### Shared product loop

Split `Invoke + pay` into two paths:

> **External path:** quote -> Wielder policy validation -> signed x402 authorization -> settlement -> external Execution credential -> execute -> authoritative receipt.
>
> **Internal path:** quote -> employer policy validation -> serialized compare-and-swap budget reservation -> credential payload returned -> provisioned policy-permitted authorizer signature -> atomic executing transition and nonce consumption -> execute outside the lock -> compare-and-swap outcome. Success with validated actual COGS finalizes the Invocation award and releases exact unused reservation. Known `failed_after_start` with validated actual COGS records that COGS, creates no award, and releases only the exact unused amount. A thrown executor, malformed outcome, or unknown post-start COGS becomes `unresolved`; the full reservation becomes `held_unresolved` for reconciliation, with no award, zero-cost substitution, or automated release.

Replace `Each payment lands in an auditable off-chain ledger` with:

> Every attempted Invocation lands in the Collar's append-only authoritative journal. Settled payments remain recorded when execution fails or a seller response is lost. Internal reservations record allocation, reservation, execution, consumption, exact release, unresolved hold, and award state independently of external settlement.

### Intra-org walkthrough

Use this normative example:

> MegaCorp approves a July budget for `ledger-recon`, Sam, named internal Wielders, the Platform Engineering cost center, and provisioned finance, manager, and credential-authorizer signer identifiers. The Collar serializes a compare-and-swap reservation of the maximum quoted COGS, fee, refund reserve, and award before execution. Reserved, executing, and held-unresolved maximum awards count toward the period cap. A successful Invocation with validated actual COGS finalizes exactly once, releases exact unused budget, and records Sam's Invocation award using kernel-returned account-identified journal entries. A known failed-after-start outcome records exact COGS and releases only its exact remainder; an unknown-cost outcome holds the full reservation and records no award. MegaCorp receives no employer self-credit. Sam and MegaCorp receive the same signed receipt. Payroll/AP payment remains a separate employer-controlled state.

Retain OtherCo only as the external optionality example. On an OtherCo Invocation, third-party revenue may be distributed to Sam and MegaCorp through the co-held Royalty claim.

### Architecture and trust model

Add the lifecycle contract:

```text
requested -> quoted -> authorized -> executing -> succeeded | failed | unresolved | cancelled
external: offered -> signed -> settled | rejected | unresolved -> refunded
internal reservation: allocated -> reserved -> executing -> consumed | released | held_unresolved
award: measured -> vesting_pending -> earned -> payable -> paid
```

State that monotonic sequence numbers plus cross-party receipt comparison provide a completeness signal; Merkle inclusion alone proves inclusion, not completeness.

### Economic design

Replace gross-to-royalty examples with:

```text
external gross = execution COGS + settlement cost + protocol fee + refund reserve + Royalty-claim pool
internal gross payable = execution COGS + protocol fee + refund reserve + Invocation award
```

All monetary calculations use integer atomic units, reject negative/non-finite/over-precision input, and assign rounding remainders deterministically. Consumers persist the accounting kernel's account-identified journal entries verbatim and do not reconstruct splits. Success and known failed-after-start outcomes require validated actual COGS. Unknown post-start COGS remains unknown, cannot be treated as zero, and keeps the full reservation `held_unresolved` until an authorized reconciliation path exists.

### Phase definitions

Clarify:

- Phase 0 closed mode: wallet-attested registration and declared ancestry only; no native transferable Story royalty-token distribution.
- Phase 1 terminal Intra-org: employer-retained budget authorization, internal Execution credential, authoritative Collar journal, signed receipts, Invocation-award payable ledger, employer payroll/AP payment.
- External x402 Invocation and co-held external Royalty-claim distribution: optional adjacent path, not required for internal compensation.
- Phase 2 Story settlement and Phase 3 tradeability: external-revenue optionality only.

### Registration, disputes, and registry trust inputs

Add:

> `wallet_asserted` verifies only the registering wallet's signature over declared bytes and ancestry. `repository_control_verified` additionally requires a verifier-provisioned repository snapshot, a trusted-ref proof commit containing the wallet-signed challenge bound to the artifact hash, and a signed observation from a provisioned forge signer. Replay revalidates both signatures and the snapshot bytes. This status does not prove current remote-repository ownership or legal authorship. Challenge opening requires the challenger's wallet signature; resolution and revocation require a provisioned admin trust root. Same-host storage serializes replay-plus-append under an exclusive lock and fails closed on an active lock.
>
> Registry relationship and payer-cluster classifications derive only from a verifier-controlled billing registry. Event-supplied Beneficiary, relationship, or cluster claims are retained for audit and ignored for ranking. An unknown payer remains allow-listed with low confidence; it cannot self-declare independence.

### Kill criteria and pilot acceptance

Replace the LOI-only success gate with two separate gates:

1. employer willingness to approve a policy, bounded Invocation budget, and counsel-drafted compensation instrument;
2. pilot evidence that authorized internal Invocations produce receipts and payroll/AP-reconcilable Invocation awards without platform custody.

External willingness to pay remains a separate optionality gate and cannot validate the internal compensation product.

## Proposed ADR amendment map

### ADR-0003 — payment-gated execution

Scope “no credential, no run” to both credential sources. Preserve x402 settlement as mandatory for externally funded execution. Add reserved-budget credentials signed by provisioned policy-permitted authorizers for internal execution. Reject request-supplied trust keys. Remove any implication that every credential must originate in a payment.

### ADR-0005 — two-leg cross-chain settlement

Constrain Base-to-Story cross-chain settlement and custody analysis to externally funded Invocation revenue. Internal Invocation awards stay in the employer's signed payable ledger and payroll/AP rail; they do not bridge or swap through Story.

### ADR-0006 — phased rollout

Define Phase 1 as the employer-funded internal compensation terminal state. Keep Phase 0 registration-only for closed modes. Preserve Phase 2/3 as external-revenue optionality.

### ADR-0007 — closed mode as terminal product

Replace external-demand dependence with employer-funded internal Invocations. Preserve compensation/retention positioning, non-transferability, counsel gate, vesting, clawback, termination, and “when Sam quits” requirements.

### ADR-0008 — the Wielder is a wallet, not a harness

Keep the thin-wallet decision for external Wielders. Add that an internal Wielder may be a non-wallet agent presenting an employer-budget credential signed by a provisioned policy-permitted authorizer through the same thin request/retry surface. The Collar remains authoritative in both modes.

## Proposed new ADR

# Employer-Funded Internal Invocations Create Invocation Awards

**Status:** Proposed

**Date:** 2026-07-17

### Context

The accepted corpus made Intra-org compensation depend on an external Wielder buying access to an employer-owned Skill. That contradicts the terminal compensation pitch: most internal Skills may never be exposed to an external Beneficiary, and an employer design partner could sign a co-hold agreement while the employee-Creator earns nothing. Treating the employer's own internal use as external royalty revenue would create circular self-credit and inflated revenue.

The product also must avoid platform custody, transferable closed-mode instruments, and dependence on Phase-2 Story settlement. Employers already operate payroll and accounts-payable rails and can approve bounded compensation budgets without transferring prepaid funds to the Collar.

### Decision

For a qualified internal Invocation, the employer is the Beneficiary and compensation-fund source. Before execution, the Collar validates an active effective-dated employer policy and serializes a compare-and-swap reservation of the maximum quoted amount from an employer-retained Invocation budget. A provisioned policy-permitted credential authorizer signs the single-use internal Execution credential, which binds the Invocation, reservation, Skill version, policy version, credential-authorizer identifier, expiry, and nonce. Finance, manager, and credential-authorizer keys are provisioned trust roots; request-supplied public keys are rejected. No quote alone authorizes execution.

On success with validated actual execution COGS, the Collar persists the accounting kernel's account-identified journal entries for COGS, protocol fee, refund reserve, and the employee-Creator Invocation award, then releases the exact unused reservation. It never reconstructs those entries in a consumer. A known `failed_after_start` outcome must carry validated actual COGS; it creates no award, records that exact unavoidable cost, and releases only the exact unused remainder. A thrown executor, malformed outcome, or unknown post-start COGS transitions the Invocation to `unresolved` and the full reservation to `held_unresolved` for reconciliation. It creates no award, records no invented monetary entry, substitutes no zero cost, and performs no automated release. Reserved, executing, and held-unresolved maximum awards count toward the period cap. The employer receives no self-credit.

Invocation-award states are `measured -> vesting_pending -> earned -> payable -> paid`; a no-vesting policy skips `vesting_pending`. Payroll/AP controls `payable -> paid`. Corrections are append-only reversals or prospective adjustments.

External Invocation revenue remains separate. An external Wielder uses x402 and a settled transaction reference; the external Royalty-claim pool may credit employee and employer co-holders. External demand is not required for an internal award.

The Collar is authoritative and signs append-only receipts. Employer and employee receive the same receipt and statement. Merkle roots prove inclusion; monotonic sequence numbers and cross-party receipt comparison provide the completeness signal.

### Consequences

- The terminal Intra-org product can compensate an employee-Creator without an external customer.
- Employer willingness to fund an internal program becomes the demand gate.
- The platform does not hold prepaid employer funds or pay employees.
- Payroll/AP, employment, tax, 409A, vesting, clawback, termination, and dispute terms remain human/counsel gates.
- Internal awards are not Royalty claims, securities, tokens, or on-chain settlement events.
- External x402 and Story settlement remain available optionality with their existing custody and compliance constraints.
- Self-Invocations require manager approval or exclusion, and caps/idempotency/authorized-Wielder lists prevent trivial award farming.
- Unknown post-start COGS reduces available budget and award-cap headroom through a full unresolved hold until authorized reconciliation; operational resolution remains unvalidated.

### Rejected alternatives

- **External Wielder revenue as the only Intra-org funding source:** rejected because it leaves compensation dependent on a second unvalidated market.
- **Employer pays itself and splits the gross:** rejected as circular revenue and metric inflation.
- **Platform prepaid omnibus balance:** rejected because it expands custody and money-transmission exposure.
- **One Story royalty token per internal Invocation:** rejected because it is unnecessary, transferable by default, and incompatible with the closed-mode contractual entitlement.
- **Unmetered discretionary bonus pool:** rejected because it removes the Invocation-level attribution and audit contract the product exists to supply.

## Historical statements and evidence preservation

- Do not erase the prior external-Wielder-funded Intra-org model. Mark it superseded by the approved amendment date if approval occurs.
- Preserve historical n=48 latency and clone results with their original dates and labels. If normalized samples are absent or target validity failed, retain the machine status `historical_unreproducible` and mark publication disallowed; do not fabricate evidence or silently restate them as measured.
- Preserve Education arithmetic as deterministic model evidence, not observed behavior.
- Extend the PRD's “What we have NOT validated” ledger; never delete prior open assumptions.

## Proposed additions to “What we have NOT validated”

1. Employer willingness to approve and fund an Invocation-award budget.
2. Counsel's treatment of the exact policy, earning, vesting, termination, and payroll/AP timing.
3. Whether qualified Invocation rules resist low-value repetition and manager-approved self-use abuse.
4. Whether employees trust Collar receipts and statement completeness enough for compensation.
5. Actual operational cost of payroll/AP reconciliation and disputes.
6. Whether verifier-provisioned repository-snapshot and organization-approval attestations improve adoption, and whether trusted forge/admin operation is sustainable.
7. Whether the verifier-controlled billing registry classifies independent Beneficiaries and payer clusters accurately enough for public registry ranking.
8. Any future external demand for paid Skill Invocations.
9. The authorized evidence, operator role, and dispute controls required to reconcile a `held_unresolved` reservation without inventing COGS or releasing value prematurely.

## Approval and application gate

This proposal does not change canonical doctrine. Its generation requires verified completion of all ten implementation-plan dependencies across Projects 1–5. Application requires one explicit user instruction approving the amendment set after that evidence is reviewed. Once approved, create a separate execution plan that updates all protected files in one coherence commit, runs link/terminology/contradiction scans, and preserves historical statements. Partial application is not allowed.

**Current decision:** pending explicit approval.

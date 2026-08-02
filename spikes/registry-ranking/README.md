# Settlement-verifiable registry ranking spike

SPIKE — synthetic registry-accounting evidence only. Settlement proves that value moved. It does not prove independent demand, usefulness, authorship, originality, or safety.

This offline spike tests whether a public registry can separate successful independent use from self-payment, Creator-linked payment, repeated billing clusters, failed or unresolved Invocations, refunds, recycled value, and unknown payer relationships. The fixture is synthetic. The verified billing registry is also synthetic and represents an operator-controlled trust input, not proof of ultimate beneficial ownership.

## Reproduce

Requires Node.js 20 or newer. No wallet, provider, network, or live service is used.

```bash
cd spikes/registry-ranking
npm test
npm run report
npm run report -- --json
```

## Event contract

Every `SettlementMetricEventV1` requires `schemaVersion`, settlement/Invocation/Skill identifiers, Creator/payee/payer wallets, untrusted payer claims, gross/refunded/recycled atomic-unit decimal strings, an outcome (`succeeded`, `failed`, or `unresolved`), and a canonical UTC settlement timestamp. Duplicate settlement IDs and duplicate successful Invocation IDs fail closed.

The event's `untrustedPayerClaims` are retained only for disagreement warnings. They never determine ranking or eligibility.

`VerifiedBillingRegistryV1` is supplied separately. Every canonical lowercase payer-wallet entry names a reviewed Beneficiary, billing-owner cluster, relationship (`linked` or `independent`), non-empty evidence reference, and review timestamp. The classifier always derives `self` when the payer equals the Creator or payee, uses the trusted registry for linked/independent ownership, and otherwise returns `unknown`.

## Reduction and exclusions

Events are ordered by `settledAt`, then `settlementId`, before the first accepted event in a billing cluster is selected. A settlement may record one or more stable exclusion reasons:

- `self_payment`
- `linked_wallet`
- `failed_invocation`
- `unresolved_settlement`
- `refunded`
- `recycled_value`
- `sybil_cluster`
- `unknown_relationship`

Only a successful, unrefunded, unrecycled event classified as independent can contribute to `independentNetAtomic`. A second payer wallet in an already accepted cluster is excluded as `sybil_cluster`. The reducer still reports raw settlement/outcome/refund/payer counts separately so the public view does not collapse movement, execution outcome, and independence into one number.

## Eligibility and sort order

A Skill is:

- `eligible` only after at least two classifier-verified successful independent Beneficiaries in distinct accepted clusters and positive independent net;
- `allow_listed` when any successful unrefunded/unrecycled settlement exists but the independent gate is unmet;
- `ineligible` otherwise.

Independence confidence is `low` for zero accepted clusters, `medium` for one, and `high` for at least two. Eligible Skills sort by independent net descending, independent Beneficiaries descending, successful Invocations descending, then Skill identifier ascending.

## Known limits

- Settlement verifies that value moved; it does not establish why it moved.
- The billing registry is operator-reviewed evidence, not cryptographic proof of ownership or independence.
- Multiple apparently independent entities can still coordinate outside the observable billing graph.
- Settlement metrics do not establish usefulness, quality, safety, authorship, originality, compliant distribution, or production readiness.
- This spike does not authorize a registry launch, public listing, payment, or transaction.

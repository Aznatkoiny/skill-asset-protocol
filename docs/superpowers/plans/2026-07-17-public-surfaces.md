# Registry and Public Demo Truthfulness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make registry metrics settlement-verifiable rather than “unfakeable,” reject self-funded/Sybil demand, and—under the recorded explicit approval to edit and add the untracked user work—make both `hf-space/` demos match the atomic accounting core and honest evidence status.

**Architecture:** Add an offline registry-ranking spike whose pure reducer separates settlements, successful Invocations, failures, independent Beneficiaries, refunds, recycling, and confidence. Public-demo allocations are generated—not reimplemented—from `prototype/atomic-money.mjs` into canonical checked fixtures, then copied byte-for-byte with SHA-256 integrity manifests into each independently deployable Gradio/static Space root; neither runtime reaches a sibling directory. A narrow immutable manifest records one independently rechecked historical Base Sepolia receipt and states exactly what it does not prove. The historical n=48 inference-route record remains at its immutable manifest path with `historical_unreproducible` status, so all p50/p95 publication is suppressed until a new authorized, dated, reproducible run exists.

**Tech Stack:** Node.js 20+, ESM, built-in `node:test`, BigInt atomic units, Python 3.12 `unittest`, Gradio, browser JavaScript modules, JSON fixtures, Markdown.

---

## Prerequisites and hard boundaries

Complete these plans first:

1. `docs/superpowers/plans/2026-07-17-claims-quarantine.md`
2. `docs/superpowers/plans/2026-07-17-atomic-money-kernel.md`

The required shared interfaces are:

- `prototype/atomic-money.mjs#allocateExternalGross({ grossAtomic, executionCostAtomic, settlementCostAtomic, protocolFeeBps, refundReserveAtomic, leafSkillId, skills })` — derives the external fee and Royalty-claim pool.
- `prototype/atomic-money.mjs#allocateInternalGross({ grossAtomic, executionCostAtomic, protocolFeeAtomic, refundReserveAtomic, recipientId })` — consumes the exact quote-final internal fee and derives the Invocation award.
- `prototype/atomic-money.mjs#formatUsdc(amountAtomic)` — the only display formatter. No public demo may duplicate any of this arithmetic.
- `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json` — immutable historical record with `evidenceStatus: "historical_unreproducible"` and `publication.allowed: false`.

**`hf-space/` APPROVAL STATUS:** `hf-space/` is pre-existing untracked user work. The
user's 2026-07-17 instruction to execute the approved remediation design authorizes
editing and adding the reviewed `hf-space/` files in this plan. That instruction does
not authorize deployment or publication. If this plan is reused outside that approved
execution, Tasks 1–3 may proceed, but Task 4 becomes a stop gate until the user again
approves editing and adding `hf-space/`. In every case, do not deploy a Space, push a
branch, make an HTTP publication call, or describe the demo as published.

## File map

Always in scope:

- Create `spikes/registry-ranking/package.json` — offline test scripts.
- Create `spikes/registry-ranking/src/metrics.mjs` — event validation, exclusion decisions, aggregation, eligibility, confidence, and ranking.
- Create `spikes/registry-ranking/test/metrics.test.mjs` — self-payment, related-wallet, Sybil, refund, failure, and honest-ranking tests.
- Create `spikes/registry-ranking/fixtures/settlements.json` — explicit synthetic fixture, labeled synthetic.
- Create `spikes/registry-ranking/fixtures/verified-billing-registry.json` — synthetic verifier-controlled payer relationships/clusters used only by the spike.
- Create `spikes/registry-ranking/README.md` — metric definitions, limits, and reproduction.
- Create `spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json` — narrow historical Base Sepolia receipt evidence for the already documented Skill-leg transaction.
- Modify `docs/plans/2026-07-15-registry-not-marketplace.md` — replace “unfakeable” and safety/demand overclaims; add allow-list and field contract.

Only after explicit `hf-space/` approval:

- Create `hf-space/scripts/generate-accounting-fixture.mjs` — imports `prototype/atomic-money.mjs` and writes the deterministic fixture.
- Create `hf-space/scripts/test-generate-accounting-fixture.mjs` — proves both internal and external scenarios use the shared core and conserve gross.
- Create `hf-space/scripts/package-space-fixtures.mjs` — copies canonical fixtures byte-for-byte into each standalone Space root and writes deterministic integrity manifests.
- Create `hf-space/scripts/test-package-space-fixtures.mjs` — proves packaged bytes/hashes and isolated-root loading.
- Create `hf-space/scripts/verify-local-scope.mjs` — enforces the exact reviewed `hf-space/` path allowlist before staging.
- Create `hf-space/shared/public-demo-allocation.json` — generated scenarios; never hand-edited.
- Create `hf-space/shared/evidence.json` — publication-safe evidence links and suppression status.
- Create `hf-space/gradio/demo_logic.py` — validates 402 responses and reads generated allocation/evidence fixtures.
- Create `hf-space/gradio/test_demo_logic.py` — Python standard-library tests.
- Create `hf-space/gradio/test_app_smoke.py` — imports and exercises the actual Gradio wiring with HTTP fully stubbed.
- Modify `hf-space/gradio/app.py` — use shared fixtures, correct mode/evidence/status language.
- Modify `hf-space/gradio/README.md` — implemented/future and evidence boundaries.
- Modify `hf-space/gradio/requirements.txt` — retain only the reviewed, pinned runtime dependency set; do not add publication tooling.
- Create `hf-space/gradio/data/public-demo-allocation.json` — byte-identical packaged allocation fixture available inside the Gradio Space root.
- Create `hf-space/gradio/data/evidence.json` — byte-identical packaged evidence fixture available inside the Gradio Space root.
- Create `hf-space/gradio/data/fixture-integrity.json` — deterministic hashes for the two packaged Gradio files.
- Create `hf-space/static/demo-logic.mjs` — validates 402 responses and renders shared fixtures without doing money math.
- Create `hf-space/static/test-demo-logic.mjs` — Node tests for 402 and fixture rendering.
- Create `hf-space/static/test-index-smoke.mjs` — parses the actual HTML into a DOM and mounts the actual module with stubbed fetch.
- Modify `hf-space/static/index.html` — use module, corrected modes, allocation, evidence, and labels.
- Modify `hf-space/static/README.md` — implemented/future and evidence boundaries.
- Create `hf-space/static/package.json` — pinned DOM-smoke dependency and offline test scripts; no deployment script.
- Create `hf-space/static/package-lock.json` — committed dependency resolution for the DOM smoke.
- Create `hf-space/static/data/public-demo-allocation.json` — byte-identical packaged allocation fixture available inside the static Space root.
- Create `hf-space/static/data/evidence.json` — byte-identical packaged evidence fixture available inside the static Space root.
- Create `hf-space/static/data/fixture-integrity.json` — deterministic hashes for the two packaged static files.

## Registry event and public metric contract

```js
// SettlementMetricEventV1 — every field is required.
{
  schemaVersion: 1,
  settlementId: "settlement-001",
  invocationId: "invocation-001",
  skillId: "ledger-recon",
  creatorWallet: "0x-lowercase-40-hex",
  payeeWallet: "0x-lowercase-40-hex",
  payerWallet: "0x-lowercase-40-hex",
  untrustedPayerClaims: {
    beneficiaryId: "otherco",
    payerClusterId: "cluster-otherco",
    relationship: "independent"
  },
  grossAtomic: "250000",
  refundedAtomic: "0",
  recycledAtomic: "0",
  outcome: "succeeded", // succeeded | failed | unresolved
  settledAt: "2026-07-17T00:00:00.000Z"
}

// PublicSkillMetricsV1
{
  schemaVersion: 1,
  skillId: "ledger-recon",
  totalSettlements: 7,
  successfulInvocations: 3,
  settledFailures: 2,
  unresolvedSettlements: 1,
  refundedSettlements: 1,
  uniquePayerWallets: 6,
  uniqueIndependentBeneficiaries: 2,
  refundAdjustedNetAtomic: "450000",
  independentNetAtomic: "400000",
  independenceConfidence: "high", // low | medium | high
  registryStatus: "eligible", // allow_listed | eligible | ineligible
  exclusionCounts: {
    self_payment: 1,
    linked_wallet: 1,
    failed_invocation: 2,
    unresolved_settlement: 1,
    refunded: 1,
    recycled_value: 1,
    sybil_cluster: 1,
    unknown_relationship: 1
  }
}
```

The event's payer claims are retained for audit but never drive a public metric. The
service injects a verifier-controlled classifier built from this schema:

```js
// VerifiedBillingRegistryV1
{
  schemaVersion: 1,
  entries: {
    "0x-lowercase-payer-wallet": {
      beneficiaryId: "otherco",
      payerClusterId: "verified-billing-owner:otherco",
      relationship: "independent", // linked | independent
      evidenceRef: "billing-review:otherco:2026-07-17",
      reviewedAt: "2026-07-17T00:00:00.000Z"
    }
  }
}

// DerivedPayerClassificationV1
{
  relationship: "independent", // self | linked | independent | unknown
  beneficiaryId: "otherco",
  payerClusterId: "verified-billing-owner:otherco",
  evidenceRef: "billing-review:otherco:2026-07-17"
}
```

Only successful, unrefunded, unrecycled events that the injected trusted classifier
derives as independent contribute to `independentNetAtomic`. The classifier derives
`self` when `payerWallet` equals either `creatorWallet` or `payeeWallet`, and `linked`
or independent payer ownership/clusters from the
verified billing registry, and `unknown` otherwise. Event claims never override a
derived result. Two derived records sharing a `payerClusterId` count as one independence
cluster even if their event claims differ. A Skill stays `allow_listed` until it has at
least two classifier-verified successful independent Beneficiaries in distinct
clusters. `unknown` never upgrades itself to independent. Sort eligible Skills by
`independentNetAtomic` descending, then independent Beneficiaries descending, then
successful Invocations descending, then `skillId` ascending.

Process events in `settledAt`, then `settlementId`, order before assigning the first
accepted event in a payer cluster; input array order never changes the result.
An independent classifier record requires a non-empty evidence reference, but the
registry remains an explicit operator trust input rather than proof of ultimate
beneficial ownership. Set
`independenceConfidence` to `low` for zero accepted independent clusters, `medium` for
one, and `high` for at least two. Set `registryStatus` to `eligible` only for at least
two successful independent Beneficiaries in distinct accepted clusters and positive
independent net; use `allow_listed` when any successful unrefunded/unrecycled
settlement exists but that gate is unmet, and `ineligible` otherwise.

### Task 1: Implement honest registry metrics and exclusion reasons

**Files:**
- Create `spikes/registry-ranking/package.json`
- Create `spikes/registry-ranking/src/metrics.mjs`
- Create `spikes/registry-ranking/test/metrics.test.mjs`
- Create `spikes/registry-ranking/fixtures/settlements.json`
- Create `spikes/registry-ranking/fixtures/verified-billing-registry.json`

- [ ] **Step 1: Write failing metric tests**

The fixture must contain exactly these synthetic cases:

1. Creator wallet pays its own Skill — `self_payment`.
2. A known Creator-linked wallet pays — `linked_wallet`.
3. Two payer wallets resolve through the trusted fixture to `cluster-sybil-a` — one cluster, not two Beneficiaries.
4. A settled Invocation fails — `failed_invocation`.
5. A settlement is unresolved — `unresolved_settlement`.
6. A successful payment is fully refunded — `refunded`.
7. Gross is immediately recycled — `recycled_value`.
8. Relationship is unknown — `unknown_relationship`.
9. OtherCo and ThirdCo each complete one successful independent Invocation from distinct clusters — eligible.

Assert:

```js
const classifier = createVerifiedBillingClassifier(verifiedBillingRegistry);
const metrics = computeSkillMetrics(events, { classifier });
assert.equal(metrics.totalSettlements, 10);
assert.equal(metrics.uniqueIndependentBeneficiaries, 2);
assert.equal(metrics.registryStatus, "eligible");
assert.equal(metrics.exclusionCounts.self_payment, 1);
assert.equal(metrics.exclusionCounts.sybil_cluster, 1);
assert.equal(metrics.independenceConfidence, "high");

const sybilOnly = computeSkillMetrics(events.filter((event) => SYBIL_SETTLEMENT_IDS.has(event.settlementId)), { classifier });
assert.equal(sybilOnly.registryStatus, "allow_listed");
assert.equal(sybilOnly.uniqueIndependentBeneficiaries, 1);
```

Also assert invalid atomic values, duplicate settlement IDs, duplicate invocation
success, refunded greater than gross, malformed trusted-registry evidence, and non-UTC
timestamps fail closed. Add spoof cases: an unregistered payer claims `independent`
with a unique beneficiary/cluster, and a trusted linked wallet claims independent.
Both claims are ignored; the first derives `unknown` and remains `allow_listed` with
`low` confidence, while the second is excluded as `linked_wallet`. Changing only
caller claim strings never changes metrics.

- [ ] **Step 2: Run and verify red**

Run: `cd spikes/registry-ranking && node --test test/metrics.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/metrics.mjs`.

- [ ] **Step 3: Implement the public metric API**

Use this package file:

```json
{
  "name": "registry-ranking-spike",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "description": "Offline settlement-verifiable registry ranking spike.",
  "scripts": {
    "test": "node --test test/*.test.mjs",
    "report": "node src/report.mjs fixtures/settlements.json fixtures/verified-billing-registry.json"
  }
}
```

Export `parseSettlementMetricEvent(value)`,
`createVerifiedBillingClassifier(registry)`, `exclusionReasons(event, classification,
{ seenIndependentClusters })`, `computeSkillMetrics(events, { classifier })`, and
`rankEligibleSkills(metrics)`. The parser returns a
frozen validated event; the exclusion function returns a stable sorted array of the
enumerated reason strings; the metric reducer returns `PublicSkillMetricsV1`; and the
ranker returns a new frozen array without mutating caller-owned metrics. The classifier
deep-freezes its validated operator-controlled registry, derives self-payments before
registry lookup, and returns `unknown` for every absent wallet. Metrics never read
`untrustedPayerClaims` except to emit a non-ranking audit warning when claims disagree.

All money parsing uses decimal strings and `bigint`. Preserve separate raw totals and independent totals. Return a frozen serializable result with decimal strings. Never infer quality, safety, usefulness, or demand from settlement alone.

- [ ] **Step 4: Run tests**

Run: `cd spikes/registry-ranking && npm test`

Expected: PASS; the self-funded/Sybil-only fixture remains `allow_listed`.

- [ ] **Step 5: Commit the metric slice**

```bash
git add spikes/registry-ranking/package.json spikes/registry-ranking/src/metrics.mjs spikes/registry-ranking/test/metrics.test.mjs spikes/registry-ranking/fixtures/settlements.json spikes/registry-ranking/fixtures/verified-billing-registry.json
git commit -m "spike: rank registry entries by independent settled use"
```

### Task 2: Add a reproducible report and honest registry documentation

**Files:**
- Create `spikes/registry-ranking/src/report.mjs`
- Create `spikes/registry-ranking/README.md`
- Modify `docs/plans/2026-07-15-registry-not-marketplace.md`

- [ ] **Step 1: Add a failing report snapshot test**

Extend `test/metrics.test.mjs` to call `renderRegistryReport` and require headings for total settlements, successful Invocations, settled failures, unresolved, refunds, unique independent Beneficiaries, net revenue, independence confidence, eligibility, and exclusions. Assert the report contains `settlement-verifiable` and does not contain `unfakeable`, `proof of demand`, `proves quality`, or `supply-chain safety`.

- [ ] **Step 2: Run and verify red**

Run: `cd spikes/registry-ranking && node --test --test-name-pattern='report' test/metrics.test.mjs`

Expected: FAIL because the renderer is absent.

- [ ] **Step 3: Implement the report and README**

`src/report.mjs` parses the settlement fixture plus the explicitly supplied trusted
billing-registry fixture, constructs the classifier once, groups by Skill, computes
metrics, ranks only eligible Skills, and prints stable JSON under `--json` or Markdown
otherwise. It never constructs classifications from event claims. README opening:

```text
SPIKE — synthetic registry-accounting evidence only. Settlement proves that value moved. It does not prove independent demand, usefulness, authorship, originality, or safety.
```

Document the exact schema, exclusion algorithm, sort order, allow-list threshold, command, and known limits.

- [ ] **Step 4: Correct the tracked registry plan**

Replace `unfakeable` with `settlement-verifiable`. Replace gross volume/unique-payer ranking with the public metric contract above. State that the first registry is allow-listed until two independent Beneficiaries have successful Invocations. Replace “buyers get supply-chain safety” with: `buyers get wallet-attested registration and declared ancestry; authorship evidence and safety review are separate statuses.` Preserve the dated research record by adding an amendment note rather than silently deleting its original context.

- [ ] **Step 5: Verify report and tracked wording**

Run: `cd spikes/registry-ranking && npm test && npm run report -- --json`

Expected: PASS; JSON includes all separate metrics and the eligible fixture has two independent Beneficiaries.

Run: `! rg -n '\bunfakeable\b|proof of demand|proves quality|supply-chain safety' docs/plans/2026-07-15-registry-not-marketplace.md spikes/registry-ranking`

Expected: exit 0 and no output.

- [ ] **Step 6: Commit the documented registry correction**

```bash
git add spikes/registry-ranking/src/report.mjs spikes/registry-ranking/README.md spikes/registry-ranking/test/metrics.test.mjs docs/plans/2026-07-15-registry-not-marketplace.md
git commit -m "docs: define settlement-verifiable registry metrics"
```

### Task 3: Commit narrow transaction evidence and lock the n=48 result out of publication

**Files:**
- Read: `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`
- Read: `spikes/pi-wielder/README.md`
- Create: `spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json`
- Create after approval in Task 4: `hf-space/shared/evidence.json`

- [ ] **Step 1: Verify the prerequisite tombstone**

Run:

```bash
node -e 'const m=require("./spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json"); if(m.evidenceStatus!=="historical_unreproducible"||m.publication.allowed!==false) process.exit(1)'
```

Expected: exit 0. If it fails or the file is absent, stop and complete the claims-quarantine plan; do not synthesize samples or copy p50/p95 into another file.

- [ ] **Step 2: Write the immutable historical transaction manifest**

Create `spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json`
with these exact rechecked receipt fields:

```json
{
  "schemaVersion": 1,
  "evidenceId": "base-sepolia-skill-settlement-2026-07-12",
  "evidenceStatus": "historical_transaction_receipt_verified",
  "network": {
    "name": "base-sepolia",
    "chainId": 84532
  },
  "transaction": {
    "txHash": "0xaf1ba2fe508ee9d6bfe0823e25a05fc8b05c8dbac007b40b7d36dbbe447af522",
    "status": "success",
    "blockNumber": 44053992,
    "blockHash": "0x7aad94c78a3c7a4eda90c70b510bd1f27a8b44d2c135d98a95473a561d48f56f",
    "blockTimestamp": "2026-07-12T17:11:12.000Z",
    "to": "0x036cbd53842c5426634e7929541ec2318f3dcf7e"
  },
  "usdcTransfer": {
    "from": "0xdddf065692ae373266a921f028ba6666a583053f",
    "to": "0x25005dfac23d4bc45c801eaeb6c8b5a2bab0f189",
    "amountAtomic": "250000"
  },
  "verification": {
    "method": "eth_getTransactionReceipt",
    "rpc": "https://sepolia.base.org",
    "verifiedOn": "2026-07-17",
    "repositorySourceCommit": "69e7c6c17ba92792e1e0a8fee15fc90efc998c84",
    "repositorySourcePath": "spikes/pi-wielder/README.md"
  },
  "publication": {
    "allowed": true,
    "publicClaim": "One successful Base Sepolia USDC transfer transaction exists; the repository's 2026-07-12 historical run log labels it as the Skill-leg settlement.",
    "doesNotProve": [
      "current endpoint behavior",
      "latency",
      "Royalty-claim split correctness",
      "Skill execution output",
      "independent demand",
      "production readiness"
    ]
  }
}
```

The manifest is evidence about the historical receipt plus the repository's historical
label—not direct proof that a hosted Skill produced output. Before committing, make one
read-only JSON-RPC call to `https://sepolia.base.org`: require `eth_chainId` to return
`0x14a34`, fetch the receipt by the exact transaction hash, and compare status, block
number, block hash, contract address, and the single USDC Transfer log against the
manifest. Fetch the referenced block and compare its timestamp too. If any field
differs, stop and report the mismatch; never send or sign a transaction.

- [ ] **Step 3: Define the only permitted public-demo evidence entries**

The later `hf-space/shared/evidence.json` must use:

```json
{
  "schemaVersion": 1,
  "historicalOverhead": {
    "manifestPath": "spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json",
    "evidenceStatus": "historical_unreproducible",
    "publicationAllowed": false,
    "publicText": "A historical 2026-07-15 inference-route run reported latency percentiles, but normalized samples were not retained. Percentiles are suppressed until a new dated reproducible run is authorized and committed."
  },
  "historicalSkillLegTransactions": [
    {
      "manifestPath": "spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json",
      "evidenceStatus": "historical_transaction_receipt_verified",
      "label": "one successful historical Base Sepolia USDC transfer; the 2026-07-12 repository log labels it as the Skill leg",
      "doesNotProve": [
        "current endpoint behavior",
        "latency",
        "Royalty-claim split correctness",
        "Skill execution output"
      ]
    }
  ]
}
```

Do not call `0x01daa723f23a6e2bbfb67b5077a25b37e6b97827b82013152c96da9d0638ff49` a Skill-endpoint settlement; the repository identifies it as a model-gateway payment. Any future rerun writes a new dated directory under `spikes/pi-wielder/evidence/`; it never overwrites or upgrades the 2026-07-15 manifest in place.

- [ ] **Step 4: Test and commit the narrow manifest**

Run:

```bash
node -e 'const m=require("./spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json"); if(m.network.chainId!==84532||m.transaction.status!=="success"||m.usdcTransfer.amountAtomic!=="250000"||m.publication.allowed!==true||m.publication.doesNotProve.length<6) process.exit(1)'
git add -- spikes/pi-wielder/evidence/2026-07-12-skill-settlement/manifest.json
git commit -m "docs: capture narrow Base Sepolia transaction evidence"
```

Expected: validation exits 0. The commit contains only the new manifest.

- [ ] **Step 5: Verify the recorded `hf-space/` approval applies**

For the current execution, cite the user's 2026-07-17 instruction to execute the
approved remediation design and continue. Confirm that no later instruction revoked
permission to edit or add `hf-space/`.

Expected: approval is present and Task 4 may begin. On a later reuse where that approval
is absent, ask: `Do you approve editing and adding the currently untracked hf-space/
directory for the reviewed demo corrections? I will not deploy or publish it.` Stop
with no `hf-space/` diff unless the answer is explicitly affirmative.

### Task 4: Generate one public-demo allocation fixture from the atomic core — approval required

**Gate:** Do not begin unless Task 3 received explicit approval.

**Files:**
- Create `hf-space/scripts/generate-accounting-fixture.mjs`
- Create `hf-space/scripts/test-generate-accounting-fixture.mjs`
- Create `hf-space/scripts/package-space-fixtures.mjs`
- Create `hf-space/scripts/test-package-space-fixtures.mjs`
- Create `hf-space/shared/public-demo-allocation.json`
- Create `hf-space/shared/evidence.json`
- Create `hf-space/gradio/data/public-demo-allocation.json`
- Create `hf-space/gradio/data/evidence.json`
- Create `hf-space/gradio/data/fixture-integrity.json`
- Create `hf-space/static/data/public-demo-allocation.json`
- Create `hf-space/static/data/evidence.json`
- Create `hf-space/static/data/fixture-integrity.json`

- [ ] **Step 1: Write a failing shared-core fixture test**

Import `buildFixture` from `generate-accounting-fixture.mjs`. Assert the default
scenario is `intra-org`; its `allocationKind` is `internal_invocation_award`; its only
Creator-directed credit is the employee-Creator award; Education and Marketplace use
`external_royalty_claim`; and every scenario reports `protocolFeeAtomic === "6250"`.
Assert each scenario serializes the exact account-identified `journalEntries` returned
by its kernel call, every entry has decimal-string `amountAtomic`, every entry debits
the kernel's expected gross source account, and the entry amounts sum exactly to
`grossAtomic === "250000"`. Assert the external scenarios report
`royaltyPoolAtomic === "193750"` while Intra-org reports
`invocationAwardAtomic === "193750"` and has no employer self-credit. Add a mutation
test proving the generator rejects a supplied or reconstructed journal entry that is
not present in the kernel result.

- [ ] **Step 2: Run and verify red**

Run: `node --test hf-space/scripts/test-generate-accounting-fixture.mjs`

Expected: FAIL because `generate-accounting-fixture.mjs` does not exist.

- [ ] **Step 3: Write the generator in check/write modes**

Import `allocateExternalGross`, `allocateInternalGross`, and `formatUsdc` from
`../../prototype/atomic-money.mjs`. Generate three scenarios with the same gross,
COGS, derived fee amount, and reserve inputs and explicit mode status:

```js
const SCENARIOS = [
  { id: "intra-org", allocationKind: "internal_invocation_award", status: "terminal_product_spike", label: "Intra-org — employer-funded internal Invocation award", policy: "internal_award" },
  { id: "education", allocationKind: "external_royalty_claim", status: "deferred", label: "Education — deferred after free re-authoring dominated the tested model", policy: "LRP" },
  { id: "marketplace", allocationKind: "external_royalty_claim", status: "phase_3_optionality", label: "Marketplace — Phase-3 optionality", policy: "LRP" }
];
const COMMON_INPUT = {
  grossAtomic: 250000n,
  executionCostAtomic: 50000n,
  refundReserveAtomic: 0n
};
const EXTERNAL_INPUT = {
  ...COMMON_INPUT,
  settlementCostAtomic: 0n,
  protocolFeeBps: 250
};
const INTERNAL_INPUT = {
  ...COMMON_INPUT,
  protocolFeeAtomic: 6250n
};
const EXTERNAL_SKILLS = {
  "derived-skill": {
    parentIds: ["source-skill"],
    inheritBps: 1500,
    holders: [{ recipientId: "derived-creator", bps: 10000 }]
  },
  "source-skill": {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: "source-creator", bps: 10000 }]
  }
};
```

Call `allocateExternalGross({ ...EXTERNAL_INPUT, leafSkillId: "derived-skill",
skills: EXTERNAL_SKILLS })` first and assert it derives `protocolFeeAtomic === 6250n`.
Pass that quote-final exact amount to `allocateInternalGross({ ...INTERNAL_INPUT,
recipientId: "employee-creator" })` for Intra-org. Call
`allocateExternalGross({ ...EXTERNAL_INPUT, leafSkillId: "derived-skill", skills:
EXTERNAL_SKILLS })` for Education and Marketplace. The external graph implements 15%
LRP at the one declared ancestry hop. Do not pass a precomputed Royalty pool or award
to either allocator; assert the external core derives `6250n` and both modes derive
`193750n` as their Royalty pool or Invocation award respectively.
For Intra-org, label the result illustrative until the internal-award amendment becomes
canonical and do not show an employer self-credit.

For every scenario, serialize `allocation.journalEntries` directly from the kernel
result, preserving entry order, `category`, `debitAccountId`, `creditAccountId`, and
`amountAtomic`. Do not infer account IDs from component names and do not rebuild the
journal in the generator, Python, or browser code. The generator fails if a returned
entry lacks an account ID, if the sum of entry amounts differs from gross, or if a
debit account differs from `employer:invocation-gross` for internal allocation or
`wielder:external-gross` for external allocation.

Export `buildFixture()`, `canonicalFixtureBytes(fixture)`, and `main(argv)`. Serialize
every `bigint` as a decimal string and use `formatUsdc` for display strings. Include
`generatedBy`, `corePath`, exact inputs, policy, status, allocations, and conservation
equation. Define `fixtureSha256` as SHA-256 over canonical JSON of the fixture with the
`fixtureSha256` field omitted; the checker recomputes that same preimage before comparing
whole-file bytes. `--write` writes a same-directory temporary file, fsyncs it, and
renames it over the target. `--check` only reads and regenerates in memory, then exits 1
with `public demo accounting fixture drift` if bytes differ.

- [ ] **Step 4: Generate and check the fixture**

Run: `node --test hf-space/scripts/test-generate-accounting-fixture.mjs && node hf-space/scripts/generate-accounting-fixture.mjs --write && node hf-space/scripts/generate-accounting-fixture.mjs --check`

Expected: PASS and exit 0. External scenarios satisfy `grossAtomic ===
executionCostAtomic + settlementCostAtomic + protocolFeeAtomic + refundReserveAtomic +
royaltyPoolAtomic`; Intra-org satisfies `grossAtomic === executionCostAtomic +
protocolFeeAtomic + refundReserveAtomic + invocationAwardAtomic`. In both cases, the
same equality is independently asserted from the kernel-returned `journalEntries`.

- [ ] **Step 5: Write the evidence fixture exactly as specified in Task 3**

Run: `node -e 'const e=require("./hf-space/shared/evidence.json"); if(e.historicalOverhead.publicationAllowed!==false||e.historicalSkillLegTransactions.length!==1) process.exit(1)'`

Expected: exit 0.

- [ ] **Step 6: Write a failing standalone-root packaging test**

`test-package-space-fixtures.mjs` imports `buildPackagePlan` and `main` from the absent
packager. It must assert:

- each root receives local `data/public-demo-allocation.json`, `data/evidence.json`, and
  `data/fixture-integrity.json`;
- each packaged fixture is byte-identical to its canonical `hf-space/shared/` source;
- both integrity manifests are byte-identical canonical JSON and contain the exact
  SHA-256 plus byte length of each packaged file;
- check mode succeeds when invoked from a different working directory;
- changing one byte in a temporary packaged copy or its hash makes check mode fail;
- no packaged loader/import/fetch path contains `../shared`, an absolute repository
  path, or a sibling Space root.

Run: `node --test hf-space/scripts/test-package-space-fixtures.mjs`

Expected: FAIL because `package-space-fixtures.mjs` does not exist.

- [ ] **Step 7: Implement deterministic packaged copies**

Export `buildPackagePlan({ canonicalRoot, spaceRoots })`,
`canonicalIntegrityBytes(value)`, and `main(argv)` from
`package-space-fixtures.mjs`. Resolve production source/target paths from
`import.meta.url`, never `cwd`. Read the canonical allocation/evidence files as raw
bytes and require one final newline. For each source compute lowercase
`sha256:<64-hex>` over those exact bytes and byte length. Use this manifest schema in
both roots:

```json
{
  "schemaVersion": 1,
  "generatedBy": "hf-space/scripts/package-space-fixtures.mjs",
  "files": {
    "evidence.json": {
      "sha256": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
      "bytes": 1
    },
    "public-demo-allocation.json": {
      "sha256": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
      "bytes": 1
    }
  }
}
```

The shown hashes/lengths illustrate shape only; generated values must match the exact
source bytes. Sort object keys canonically. `--write` uses same-directory temporary
files, full write loops, fsync, and rename for all six targets. `--check` performs no
write and compares all six complete byte sequences, failing with
`standalone Space fixture drift: ${relativePath}`. Neither mode accesses a network.

- [ ] **Step 8: Generate and verify every standalone-root package**

Run:

```bash
node --test hf-space/scripts/test-package-space-fixtures.mjs
node hf-space/scripts/package-space-fixtures.mjs --write
node hf-space/scripts/package-space-fixtures.mjs --check
! rg -n '\.\./shared|hf-space/(gradio|static)' hf-space/gradio/data hf-space/static/data
```

Expected: tests pass, all six generated files check byte-for-byte, and neither root
contains a sibling/repository-relative runtime dependency.

### Task 5: Make Gradio consume validated fixtures — approval required

**Files:**
- Create `hf-space/gradio/demo_logic.py`
- Create `hf-space/gradio/test_demo_logic.py`
- Create `hf-space/gradio/test_app_smoke.py`
- Modify `hf-space/gradio/app.py`
- Modify `hf-space/gradio/README.md`
- Modify `hf-space/gradio/requirements.txt`

- [ ] **Step 1: Write failing Python tests**

Using `unittest`, assert `validate_live_402(402, valid_body)` returns live, while JSON 200, JSON 500, unsupported x402 version, empty accepts, wrong scheme, invalid atomic amount, and missing payTo/asset return non-live with an error. Assert the default scenario is `intra-org`, Education status is `deferred`, Marketplace is `phase_3_optionality`, each scenario's displayed credits plus cost allocations conserve gross under its allocation kind, and evidence rendering contains neither `p50` nor `p95`.
The conservation assertion must sum only the serialized kernel `journalEntries`; it
must not construct entries or account IDs from display components.
Load fixtures only from `Path(__file__).resolve().parent / "data"`; verify both raw file
hashes/lengths against local `fixture-integrity.json` before JSON parsing. Tests copy
only the Gradio root into a temporary directory, import that copied module from a
different working directory, and prove it works without `hf-space/shared/`.

In `test_app_smoke.py`, patch `httpx.post` to raise if called, then import the actual
`app.py` with pinned Gradio/httpx installed. Assert import performs no network or
launch, `app.demo` is a `gr.Blocks`, and `demo.get_config_file()` contains the
Intra-org default plus dependency `api_name: "check_live_402"`. Replace the stub with a
fake valid 402 response, call the actual wired handler once, and require the returned
view model to be live; fake 200 and thrown request render non-live/cached status.

- [ ] **Step 2: Run and verify red**

Run: `python3 -B -m unittest hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py`

Expected: FAIL because `demo_logic.py` and revised app wiring are absent.

- [ ] **Step 3: Implement fixture-only logic**

`demo_logic.py` exports `load_allocation_fixture`, `load_evidence_fixture`, `validate_live_402`, `scenario_by_id`, and `render_allocation`. It performs no allocation arithmetic beyond summing parsed integer strings for a conservation assertion. `validate_live_402` requires status 402, x402 version 1, first offer scheme `exact`, network `base-sepolia`, decimal `maxAmountRequired`, and non-empty resource/payTo/asset.
It renders the kernel-returned debit/credit account IDs verbatim and rejects a fixture
whose entry amount sum or expected gross-source debit account fails validation.
Both loaders resolve only the local `data/` directory, hash the raw bytes before
parsing, require exact keys/length/hash from `fixture-integrity.json`, and fail with
`packaged fixture integrity mismatch: ${fileName}` on drift. They contain no fallback
to `../shared`, the repository root, or embedded fixture constants.

- [ ] **Step 4: Correct Gradio presentation**

Use Intra-org as default. Show Education and Marketplace statuses inline. Replace sliders that could create unverified math with the generated scenarios. Label the allocation `generated from prototype/atomic-money.mjs; synthetic accounting illustration`. Replace `claimable on demand` with `credited allocation shown; withdrawal and on-chain settlement are not implemented in this demo`. Display actual HTTP status and never call a malformed/non-402 JSON response live. Show only the single historical transaction manifest and its narrow repository-log label, plus the suppressed-evidence notice; remove all n=48 p50/p95 text and “two transactions from this exact endpoint.” Never call the historical receipt current hosted-Skill endpoint proof.
Refactor to `build_demo()` plus module-level `demo = build_demo()`; call `demo.launch()`
only under `if __name__ == "__main__"`. Wire the live button with
`api_name="check_live_402"`. Importing the module builds the UI from verified packaged
fixtures but performs no HTTP request and starts no server.

- [ ] **Step 5: Review and pin the existing runtime requirements**

Keep the pre-existing requirements file in scope and make its complete contents:

```text
gradio==6.20.0
httpx==0.28.1
```

Do not add `huggingface_hub`, deployment CLIs, tokens, repository URLs, post-install
scripts, or any publication dependency. Import both packages in the same Python
environment used for the tests and record their resolved versions in the local test
output; this review does not install, deploy, or publish anything.

- [ ] **Step 6: Run Gradio tests and fixture drift check**

Run:

```bash
python3 -c 'from importlib.metadata import version; assert version("gradio")=="6.20.0"; assert version("httpx")=="0.28.1"; print("gradio=6.20.0 httpx=0.28.1")'
python3 -B -m unittest hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py
node hf-space/scripts/generate-accounting-fixture.mjs --check
node hf-space/scripts/package-space-fixtures.mjs --check
```

Expected: version assertion and tests PASS; the actual app imports and one callback is
exercised entirely through HTTP stubs, with no server, network, or sibling fixture
access.

### Task 6: Make static demo consume the same fixtures — approval required

**Files:**
- Create `hf-space/static/demo-logic.mjs`
- Create `hf-space/static/test-demo-logic.mjs`
- Create `hf-space/static/test-index-smoke.mjs`
- Modify `hf-space/static/index.html`
- Modify `hf-space/static/README.md`
- Create `hf-space/static/package.json`
- Create `hf-space/static/package-lock.json`
- Create `hf-space/static/data/public-demo-allocation.json`
- Create `hf-space/static/data/evidence.json`
- Create `hf-space/static/data/fixture-integrity.json`

- [ ] **Step 1: Write failing JavaScript tests**

Mirror the Python validation matrix. Import the generated JSON using `readFileSync` in tests and assert `renderScenarioModel` returns display rows whose integer totals conserve gross. Assert no output string contains p50/p95 and default is Intra-org.
The rows come directly from serialized `journalEntries`; tests fail if browser logic
derives or substitutes any debit/credit account ID.
The fixture loader fetches only `./data/fixture-integrity.json`,
`./data/public-demo-allocation.json`, and `./data/evidence.json`, hashes the raw bytes
with injected Web Crypto before parsing, and fails on length/hash mismatch. A test
copies only the static root to a temporary directory and runs there with no sibling
fixture directory.

`test-index-smoke.mjs` must parse the actual `index.html` with pinned `linkedom`, install
that window/document plus stubbed `fetch` and Web Crypto on `globalThis`, then
dynamically import the actual production `demo-logic.mjs` entrypoint with no manual
`mountDemo` call. Await its exported `browserBootstrapPromise`. The fetch stub serves
only packaged local data and fake endpoint responses. Assert the actual DOM contains
the module script and required controls, automatic bootstrap marks the document mounted
exactly once, renders Intra-org by default, a click wired to a fake valid 402 renders
live, and fake 200/500 render non-live. Any unstubbed URL throws, proving no network
access. A separate import with no browser globals must leave
`browserBootstrapPromise === null` and perform no fetch.

- [ ] **Step 2: Run and verify red**

Run: `node --test hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs`

Expected: FAIL because `demo-logic.mjs`, DOM wiring, or pinned dependency is absent.

- [ ] **Step 3: Implement static fixture consumption**

Export `validateLive402`, `loadScenario`, `renderScenarioModel`, `mountDemo`, and
`browserBootstrapPromise`. Do no fee, COGS, ancestry, percentage, or rounding math in
browser code; display decimal strings already generated by the core. Use the module
script in `index.html` to load only hash-verified files beneath local `./data/`.
Validate conservation only by summing the kernel-returned journal entry amounts and
requiring the expected gross-source debit account for the selected allocation kind.
Implement `loadPackagedFixtures({ fetchImpl, cryptoImpl })`, which
fetches only the three local `./data/` resources, validates exact manifest keys,
lengths, and SHA-256 before JSON parsing, and returns frozen fixtures. No runtime path
contains `..`, `shared`, or the repository name.

- [ ] **Step 4: Correct static presentation**

Apply the same mode statuses, default, implemented/future language, live-402 validation,
one narrowly labeled historical transaction manifest, evidence suppression, and
no-arbitrary-slider behavior as Gradio. A fetch that returns JSON 200/500 must render
`live endpoint did not return a valid 402 offer`, never a green live badge.
The actual module exports async `mountDemo({ document, fetchImpl = fetch, cryptoImpl =
crypto })`, binds the real controls, loads verified local fixtures, and performs no
endpoint request until the user clicks. At module evaluation it guards
`typeof window !== "undefined" && typeof document !== "undefined"`; in a browser it
sets `browserBootstrapPromise` to a DOM-ready promise that invokes `mountDemo` exactly
once with production globals and renders a visible fatal state on rejection. Outside a
browser it sets the export to `null` and performs no fetch or DOM access. Duplicate
mount attempts fail or no-op without adding duplicate handlers. `index.html` contains exactly
`<script type="module" src="./demo-logic.mjs"></script>` and no inline duplicate logic.

- [ ] **Step 5: Pin and verify the DOM-smoke dependency**

Create:

```json
{
  "name": "skill-asset-protocol-static-space",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "scripts": {
    "test": "node --test test-demo-logic.mjs test-index-smoke.mjs"
  },
  "devDependencies": {
    "linkedom": "0.18.12"
  }
}
```

Run `cd hf-space/static && npm install --ignore-scripts` once to create the committed
lockfile, then `npm ci --ignore-scripts`. Do not add preinstall/postinstall, publish,
deploy, or upload scripts. Verify the exact direct version with:

```bash
node -e 'const p=require("./hf-space/static/node_modules/linkedom/package.json"); if(p.version!=="0.18.12") process.exit(1); console.log(`linkedom=${p.version}`)'
```

Expected: prints `linkedom=0.18.12`. Dependency installation is setup for the local
smoke only; it does not deploy or publish the Space.

- [ ] **Step 6: Run all public-surface tests**

Run:

```bash
cd spikes/registry-ranking && npm test
cd ../..
node hf-space/scripts/generate-accounting-fixture.mjs --check
node hf-space/scripts/package-space-fixtures.mjs --check
node --test hf-space/scripts/test-generate-accounting-fixture.mjs
node --test hf-space/scripts/test-package-space-fixtures.mjs
python3 -c 'from importlib.metadata import version; assert version("gradio")=="6.20.0"; assert version("httpx")=="0.28.1"'
python3 -B -m unittest hf-space/gradio/test_demo_logic.py
python3 -B -m unittest hf-space/gradio/test_app_smoke.py
node -e 'const p=require("./hf-space/static/node_modules/linkedom/package.json"); if(p.version!=="0.18.12") process.exit(1)'
cd hf-space/static && npm test
```

Expected: every command PASS; no network, provider, wallet, or deployment action occurs.

### Task 7: Verify boundaries and commit locally — approval required for `hf-space/`

**Files:** all files above, plus:
- Create `hf-space/scripts/verify-local-scope.mjs`

The complete reviewed `hf-space/` allowlist is exactly:

```text
hf-space/scripts/generate-accounting-fixture.mjs
hf-space/scripts/test-generate-accounting-fixture.mjs
hf-space/scripts/package-space-fixtures.mjs
hf-space/scripts/test-package-space-fixtures.mjs
hf-space/scripts/verify-local-scope.mjs
hf-space/shared/public-demo-allocation.json
hf-space/shared/evidence.json
hf-space/gradio/demo_logic.py
hf-space/gradio/test_demo_logic.py
hf-space/gradio/test_app_smoke.py
hf-space/gradio/app.py
hf-space/gradio/README.md
hf-space/gradio/requirements.txt
hf-space/gradio/data/public-demo-allocation.json
hf-space/gradio/data/evidence.json
hf-space/gradio/data/fixture-integrity.json
hf-space/static/demo-logic.mjs
hf-space/static/test-demo-logic.mjs
hf-space/static/test-index-smoke.mjs
hf-space/static/index.html
hf-space/static/README.md
hf-space/static/package.json
hf-space/static/package-lock.json
hf-space/static/data/public-demo-allocation.json
hf-space/static/data/evidence.json
hf-space/static/data/fixture-integrity.json
```

- [ ] **Step 1: Implement the exact-path scope guard**

`verify-local-scope.mjs` exports the frozen sorted constant
`HF_SPACE_ALLOWED_PATHS` containing exactly the 26 paths above. Its normal mode runs
`git status --porcelain=v1 --untracked-files=all -- hf-space`, parses every complete
status line, rejects rename/copy records, and fails on any path outside the allowlist
or any required allowlisted path absent from status. Its `--cached` mode runs
`git diff --cached --name-only -- hf-space` and requires the cached path set to equal
the allowlist exactly. Both modes print the sorted compared path set. Never collapse
an untracked directory to one path and never silently accept a directory path.

Run:

```bash
git status --short --untracked-files=all -- hf-space
node hf-space/scripts/verify-local-scope.mjs
```

Expected: the status output and guard contain exactly the 26 file paths above. Any
extra or missing path is a stop gate for review, not a reason to broaden the allowlist.

- [ ] **Step 2: Scan the exact public files and protected corpus**

Run:

```bash
! rg -n '\bp(50|95)\b|two real testnet settlements from this exact endpoint|claimable on demand|current hosted-Skill endpoint proof|\bunfakeable\b|supply-chain safety' hf-space/scripts/generate-accounting-fixture.mjs hf-space/scripts/test-generate-accounting-fixture.mjs hf-space/scripts/package-space-fixtures.mjs hf-space/scripts/test-package-space-fixtures.mjs hf-space/scripts/verify-local-scope.mjs hf-space/shared/public-demo-allocation.json hf-space/shared/evidence.json hf-space/gradio/demo_logic.py hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py hf-space/gradio/app.py hf-space/gradio/README.md hf-space/gradio/requirements.txt hf-space/gradio/data/public-demo-allocation.json hf-space/gradio/data/evidence.json hf-space/gradio/data/fixture-integrity.json hf-space/static/demo-logic.mjs hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs hf-space/static/index.html hf-space/static/README.md hf-space/static/package.json hf-space/static/package-lock.json hf-space/static/data/public-demo-allocation.json hf-space/static/data/evidence.json hf-space/static/data/fixture-integrity.json docs/plans/2026-07-15-registry-not-marketplace.md
git diff --exit-code -- CONTEXT.md docs/PRD.md docs/adr
```

Expected: exit 0 and no output. This scans untracked files directly; do not substitute
`git diff`, which omits untracked contents.

- [ ] **Step 3: Confirm no publication command, secret, or endpoint is present**

Run:

```bash
! rg -n 'huggingface-cli upload|hf upload|huggingface_hub|git push|gradio deploy|vercel deploy|netlify deploy|requests\.(post|put)|httpx\.(post|put).*huggingface|HF_TOKEN|HUGGING_FACE_HUB_TOKEN' hf-space/scripts/generate-accounting-fixture.mjs hf-space/scripts/test-generate-accounting-fixture.mjs hf-space/scripts/package-space-fixtures.mjs hf-space/scripts/test-package-space-fixtures.mjs hf-space/scripts/verify-local-scope.mjs hf-space/shared/public-demo-allocation.json hf-space/shared/evidence.json hf-space/gradio/demo_logic.py hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py hf-space/gradio/app.py hf-space/gradio/README.md hf-space/gradio/requirements.txt hf-space/gradio/data/public-demo-allocation.json hf-space/gradio/data/evidence.json hf-space/gradio/data/fixture-integrity.json hf-space/static/demo-logic.mjs hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs hf-space/static/index.html hf-space/static/README.md hf-space/static/package.json hf-space/static/package-lock.json hf-space/static/data/public-demo-allocation.json hf-space/static/data/evidence.json hf-space/static/data/fixture-integrity.json
```

Expected: exit 0 and no output. The scan reads the files themselves and therefore
covers untracked content.

- [ ] **Step 4: Stage any remaining registry work by exact file path**

Earlier task commits should normally leave this slice clean. If any planned registry
path remains modified, stage only the exact paths below—never either parent directory:

```bash
git add -- spikes/registry-ranking/package.json spikes/registry-ranking/src/metrics.mjs spikes/registry-ranking/src/report.mjs spikes/registry-ranking/test/metrics.test.mjs spikes/registry-ranking/fixtures/settlements.json spikes/registry-ranking/fixtures/verified-billing-registry.json spikes/registry-ranking/README.md docs/plans/2026-07-15-registry-not-marketplace.md
git diff --cached --name-only
git commit -m "spike: add settlement-verifiable registry ranking"
```

Expected: cached paths are a subset of that exact list and contain no `hf-space/`,
protected corpus, or unrelated file. If there is no remaining registry diff, skip the
commit instead of creating an empty one.

- [ ] **Step 5: Stage the approved demo by exact file path and commit locally**

Only if the explicit approval included adding `hf-space/`:

```bash
git add -- hf-space/scripts/generate-accounting-fixture.mjs hf-space/scripts/test-generate-accounting-fixture.mjs hf-space/scripts/package-space-fixtures.mjs hf-space/scripts/test-package-space-fixtures.mjs hf-space/scripts/verify-local-scope.mjs hf-space/shared/public-demo-allocation.json hf-space/shared/evidence.json hf-space/gradio/demo_logic.py hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py hf-space/gradio/app.py hf-space/gradio/README.md hf-space/gradio/requirements.txt hf-space/gradio/data/public-demo-allocation.json hf-space/gradio/data/evidence.json hf-space/gradio/data/fixture-integrity.json hf-space/static/demo-logic.mjs hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs hf-space/static/index.html hf-space/static/README.md hf-space/static/package.json hf-space/static/package-lock.json hf-space/static/data/public-demo-allocation.json hf-space/static/data/evidence.json hf-space/static/data/fixture-integrity.json
node hf-space/scripts/verify-local-scope.mjs --cached
git commit -m "fix: align public demo with verified accounting"
```

Expected: the cached scope guard reports exactly the 26 allowlisted paths before the
commit. Never stage `hf-space/` or any child directory as a directory argument. Do not
run `git push`, a Hugging Face upload, Vercel, Netlify, or any deploy command.

## Definition of done

- Self-payments, linked wallets, refunded/failed Invocations, recycling, and repeated Sybil clusters cannot count as independent demand; caller-supplied relationship claims cannot change classification.
- Registry output reports all required metrics separately and stays allow-listed until two independent Beneficiaries succeed.
- Tracked registry language says settlement-verifiable and does not imply quality, authorship, or safety.
- The historical transaction manifest pins one rechecked Base Sepolia receipt and limits its public claim to transaction existence plus the repository's historical Skill-leg label; it does not imply execution, latency, split correctness, or demand.
- If `hf-space/` approval is absent, no file beneath it is modified, staged, or committed.
- If approval is present, both demos consume the kernel-returned account-identified `journalEntries` from deterministic hash-verified copies packaged inside their own standalone roots, pass canonical and packaged drift checks, default to Intra-org, label Education and Marketplace honestly, reject JSON 200/500 as live 402, and distinguish credits from withdrawal/settlement.
- Gradio's actual app imports with pinned versions and a network stub; the static
  HTML/module mounts against a real test DOM with all fetches stubbed. Neither runtime
  references `hf-space/shared` or its sibling Space.
- The scope guard and cached-scope check prove that only the 26 reviewed `hf-space/` files are staged, including both roots' packaged fixtures, smoke tests, and pinned dependency files.
- The n=48 p50/p95 result remains historical and suppressed; no public surface treats it as reproducible.
- No deployment or publication occurs.
- `CONTEXT.md`, `docs/PRD.md`, and `docs/adr/` remain unchanged.

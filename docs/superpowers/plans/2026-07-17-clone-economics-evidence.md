# Clone Economics Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make clone-economics conclusions fail closed on an invalid target, support the preregistered N=6/25/50/100 experiment, and produce sanitized evidence bundles whose published metrics recompute from a clean checkout.

**Architecture:** The harness separates benchmark validity, fixture generation, sweep orchestration, seed semantics, budget enforcement, and evidence serialization into small dependency-free modules. A standalone target-baseline gate runs before clone work, and publication also requires the target benchmark inside every N=100 cell to remain valid; each N uses three preregistered replicates with separate pair-order and provider-distillation seeds. A provider that cannot honor the requested distillation seeds may produce explicitly uncontrolled evidence, but the publishable high-N gate fails and clone/economics conclusions stay suppressed. Live execution requires an exact authorization hash over the approved pricing/token-cap snapshot and sweep configuration plus an exact USD cap. Integer micro-USD preflight runs before adapter or fetch construction, every attempted provider call reserves worst-case spend before fetch, and any exact charge above authorization is fully accrued before a permanent overrun lock.

**Tech Stack:** Node.js 20+ ESM, `node:test`, SHA-256, JSON/JSONL, Markdown

---

## File map

- Create `spikes/clone-economics/src/validity.mjs`: target-baseline and conclusion gate.
- Create `spikes/clone-economics/tests/validity.test.mjs`: invalid/valid target contract tests.
- Modify `spikes/clone-economics/src/experiment.mjs`: use the validity result and suppress inadmissible conclusions.
- Modify `spikes/clone-economics/src/reports.mjs`: render an invalid-target verdict without clone, moat, or break-even conclusions.
- Modify `spikes/clone-economics/e2e.mjs`: preserve pre-existing ignored `runs/` content.
- Create `spikes/clone-economics/fixtures/fixture-catalog-v2.json`: preregistered fixture inputs.
- Create `spikes/clone-economics/scripts/generate-fixtures.mjs`: deterministic 100/30 fixture generator.
- Create generated `spikes/clone-economics/fixtures/train-v2.json` and `heldout-v2.json`: committed sweep fixtures.
- Create `spikes/clone-economics/src/fixture-set.mjs`: load and validate fixture identity/hash separation.
- Create `spikes/clone-economics/tests/fixture-set.test.mjs`: counts, hashes, disjointness, and determinism.
- Create `spikes/clone-economics/fixtures/sweep-v1.json`: immutable preregistration for N values and separate pair-order/provider-distillation replicate seeds.
- Create `spikes/clone-economics/fixtures/live-budget-v1.json`: committed pricing/token-cap contract, initially unapproved with no invented prices.
- Create `spikes/clone-economics/src/sweep.mjs`: preflight, seeded replicates, and live guard.
- Create `spikes/clone-economics/src/budget.mjs`: exact cap parsing, conservative request/cost estimation, and per-attempt reservations.
- Create `spikes/clone-economics/src/authorization.mjs`: canonical snapshot/config hashing for exact live approval.
- Create `spikes/clone-economics/sweep.mjs`: CLI entry point.
- Create `spikes/clone-economics/tests/sweep.test.mjs`: offline sweep and spend-gate tests.
- Create `spikes/clone-economics/tests/authorization.test.mjs` and `spikes/clone-economics/tests/fixtures/live-contract.mjs`: exact-hash and shared synthetic-contract tests.
- Create `spikes/clone-economics/tests/budget.test.mjs`: approved-snapshot, pre-construction, unknown-cost, and attempted-call accounting tests.
- Create `spikes/clone-economics/src/evidence.mjs`: normalized samples, summary recomputation, bundle hashing, and verification.
- Create `spikes/clone-economics/scripts/verify-bundle.mjs`: clean-checkout verifier.
- Create `spikes/clone-economics/scripts/import-legacy-run.mjs`: explicit-path, hash-locked sanitized importer for the ignored 2026-07-12 report.
- Create `spikes/clone-economics/tests/import-legacy-run.test.mjs`: byte-hash, no-output-on-failure, and normalization tests.
- Create `spikes/clone-economics/tests/evidence.test.mjs`: schema, hash, redaction, and metric recomputation tests.
- Create `spikes/clone-economics/evidence/2026-07-12-n6-invalid/{manifest.json,samples.jsonl,summary.json,report.md,README.md}`: committed historical invalid-benchmark bundle.
- Modify `spikes/clone-economics/package.json`, `.gitignore`, `README.md`, `RUNBOOK.md`, and `.env.example`: expose safe commands and state the human gates.

### Human-only boundary

No implementation or verification step in this plan may set `ALLOW_LIVE_LLM=1`, set a real `APPROVE_LIVE_SWEEP_SHA256`, call a provider, settle x402, fund a wallet, or publish a result. Task 7 documents the exact operator command, but a human must verify current pricing, choose the model and token caps, replace the committed `not_approved` budget snapshot with an `approved` snapshot, commit that review, approve the maximum spend, copy the exact printed authorization hash, and invoke the command. A generated live result is not automatically publishable; its target, independent-distillation-seed, and evidence gates still decide that.

### Task 1: Fail closed when the benchmark target fails

**Files:**
- Create: `spikes/clone-economics/src/validity.mjs`
- Create: `spikes/clone-economics/tests/validity.test.mjs`
- Modify: `spikes/clone-economics/src/experiment.mjs:159-270`
- Modify: `spikes/clone-economics/src/reports.mjs:11-75`
- Modify: `spikes/clone-economics/e2e.mjs:108-136,153-172`

- [ ] **Step 1: Write target-validity tests**

Create `spikes/clone-economics/tests/validity.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  INVALID_TARGET_VERDICT,
  assessBenchmark,
} from '../src/validity.mjs';

const score = (absoluteScore, criticalGatePass) => ({
  absoluteScore,
  criticalGatePass,
  passedThreshold: absoluteScore >= 0.8,
});

test('a failed target suppresses every clone and economics conclusion', () => {
  const result = assessBenchmark({
    threshold: 0.8,
    target: score(0.4, false),
  });
  assert.deepEqual(result, {
    valid: false,
    verdict: INVALID_TARGET_VERDICT,
    cloneConclusionAllowed: false,
    economicsConclusionAllowed: false,
    reason: 'Target score 0.400 is below 0.800 and target critical gates failed.',
  });
});

test('a passing target admits a clone result without deciding its meaning', () => {
  const result = assessBenchmark({
    threshold: 0.8,
    target: score(0.9, true),
  });
  assert.equal(result.valid, true);
  assert.equal(result.verdict, 'VALID_BENCHMARK');
  assert.equal(result.cloneConclusionAllowed, true);
  assert.equal(result.economicsConclusionAllowed, true);
});
```

- [ ] **Step 2: Run the focused test to verify it fails**

Run: `cd spikes/clone-economics && node --test tests/validity.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/validity.mjs`.

- [ ] **Step 3: Implement the validity contract**

Create `spikes/clone-economics/src/validity.mjs`:

```js
export const INVALID_TARGET_VERDICT = 'INVALID_BENCHMARK_TARGET_FAILED';

export function assessBenchmark({ threshold, target }) {
  const scoreFailed = target.absoluteScore < threshold;
  const gatesFailed = !target.criticalGatePass;
  if (scoreFailed || gatesFailed) {
    const failures = [
      scoreFailed ? `Target score ${target.absoluteScore.toFixed(3)} is below ${threshold.toFixed(3)}` : null,
      gatesFailed ? 'target critical gates failed' : null,
    ].filter(Boolean);
    return {
      valid: false,
      verdict: INVALID_TARGET_VERDICT,
      cloneConclusionAllowed: false,
      economicsConclusionAllowed: false,
      reason: `${failures.join(' and ')}.`,
    };
  }
  return {
    valid: true,
    verdict: 'VALID_BENCHMARK',
    cloneConclusionAllowed: true,
    economicsConclusionAllowed: true,
    reason: `Target met ${threshold.toFixed(3)} and every critical gate.`,
  };
}
```

- [ ] **Step 4: Run the validity tests**

Run: `cd spikes/clone-economics && node --test tests/validity.test.mjs`

Expected: PASS, 2 tests passed.

- [ ] **Step 5: Attach validity to every experiment report**

Import and call `assessBenchmark` immediately after `targetScore` and `cloneScore` are computed in `src/experiment.mjs`:

```js
const benchmark = assessBenchmark({
  threshold: FIDELITY_THRESHOLD,
  target: targetScore,
});
```

Add `benchmark` to the report beside `fidelity`. Replace the current `fidelity`
and `economics` literals with this complete field mapping so every existing
observation remains present while only interpretive fields are suppressed:

```js
const economicsEvidenceLabel = mode === 'mock'
  ? 'SYNTHETIC + MODELED'
  : `Provider cost ${providerUsageEvidence}; acquisition MODELED`;

benchmark,
fidelity: {
  evidenceLabel: mode === 'mock' ? 'SYNTHETIC' : 'MEASURED AGAINST DETERMINISTIC RUBRIC',
  rubricVersion: RUBRIC_VERSION,
  threshold: FIDELITY_THRESHOLD,
  target: targetScore,
  clone: cloneScore,
  retention: benchmark.cloneConclusionAllowed && targetScore.absoluteScore > 0
    ? rounded(cloneScore.absoluteScore / targetScore.absoluteScore)
    : null,
  badClone: badCloneScore,
  scoreDeterminism: { byteIdentical: scoringA === scoringB },
},
economics: {
  evidenceLabel: economicsEvidenceLabel,
  acquisitionFormula: economics.acquisitionFormula,
  acquisitionModeledUsd: economics.acquisitionModeledUsd,
  distillationProviderUsd: economics.distillationProviderUsd,
  tuningEvaluationUsd: economics.tuningEvaluationUsd,
  tuningNote: economics.tuningNote,
  deployCostUsd: economics.deployCostUsd,
  laborCostUsd: economics.laborCostUsd,
  laborCostTreatment: economics.laborCostTreatment,
  attackerBuildUsd: economics.attackerBuildUsd,
  measurementEvaluationUsd: economics.measurementEvaluationUsd,
  evaluationExcludedFromBuild: economics.evaluationExcludedFromBuild,
  distillationToAcquisition: economics.distillationToAcquisition,
  buildToAcquisition: economics.buildToAcquisition,
  breakEvenInvocations: benchmark.economicsConclusionAllowed
    ? economics.breakEvenInvocations
    : null,
  cloneServingCostUsd: economics.cloneServingCostUsd,
  providerCostsNotAddedToAcquisition: economics.providerCostsNotAddedToAcquisition,
  providerCostBreakdown: economics.providerCostBreakdown,
  zeroPriceProbe: economics.zeroPriceProbe,
  conclusionSuppressed: !benchmark.economicsConclusionAllowed,
},
```

Set live `claimStatus` to `benchmark.verdict` when invalid. Do not delete target/clone observations; suppression applies to interpretation.

- [ ] **Step 6: Render the invalid verdict explicitly**

At the start of `renderMarkdown`, compute:

```js
const conclusion = report.benchmark.valid
  ? 'The target passed its own gate; clone and economics interpretation may proceed.'
  : `**${report.benchmark.verdict}.** ${report.benchmark.reason} Clone quality, fidelity defense, moat, and break-even conclusions are suppressed.`;
```

Render `conclusion` immediately after the verdict. In the economics table, render `suppressed` rather than `undefined` for invalid break-even. Do not emit “clone failed,” “cost protects nothing,” or a fidelity-defense sentence from an invalid report.

- [ ] **Step 7: Update the offline e2e assertions**

Add assertions after the known-good mock score checks:

```js
eq(report.benchmark.verdict, 'VALID_BENCHMARK', 'passing target admits interpretation');

// The existing unknown transcript deliberately makes the target fail.
eq(unknown.report.benchmark.verdict, 'INVALID_BENCHMARK_TARGET_FAILED', 'failed target invalidates benchmark');
eq(unknown.report.fidelity.retention, null, 'invalid target suppresses retention');
eq(unknown.report.economics.breakEvenInvocations, null, 'invalid target suppresses break-even');
ok(unknown.markdownReport.includes('Clone quality, fidelity defense, moat, and break-even conclusions are suppressed'), 'invalid report states suppression');
```

- [ ] **Step 8: Run the offline tests**

Run:

```bash
cd spikes/clone-economics
node --test tests/validity.test.mjs
npm run e2e
```

Expected: validity tests PASS and e2e ends `PASS` with all prior checks plus the new validity checks green.

- [ ] **Step 9: Commit the target gate**

```bash
git add spikes/clone-economics/src/validity.mjs spikes/clone-economics/tests/validity.test.mjs spikes/clone-economics/src/experiment.mjs spikes/clone-economics/src/reports.mjs spikes/clone-economics/e2e.mjs
git commit -m "fix: invalidate clone conclusions on failed target"
```

### Task 2: Make offline e2e coexist with retained ignored runs

**Files:**
- Modify: `spikes/clone-economics/e2e.mjs:33-40,153-158`
- Create: `spikes/clone-economics/tests/e2e-coexistence.test.mjs`

- [ ] **Step 1: Write a regression test with a retained run marker**

Create `spikes/clone-economics/tests/e2e-coexistence.test.mjs`:

```js
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('offline e2e preserves an existing ignored runs directory', (t) => {
  const marker = path.join(root, 'runs', 'e2e-retained-marker.txt');
  fs.mkdirSync(path.dirname(marker), { recursive: true });
  fs.writeFileSync(marker, 'retain me\n');
  t.after(() => fs.rmSync(marker, { force: true }));
  const output = execFileSync(process.execPath, ['e2e.mjs'], {
    cwd: root,
    env: { ...process.env, MOCK_LLM: '1', ALLOW_LIVE_LLM: '0' },
    encoding: 'utf8',
  });
  assert.match(output, /PASS/);
  assert.equal(fs.readFileSync(marker, 'utf8'), 'retain me\n');
});
```

- [ ] **Step 2: Run it to verify the current assertion fails**

Run: `cd spikes/clone-economics && node --test tests/e2e-coexistence.test.mjs`

Expected: FAIL because `e2e.mjs` currently asserts that `runs/` does not exist.

- [ ] **Step 3: Replace the global absence assertion with a before/after snapshot**

Add this helper and snapshot near `outputA`/`outputB` in `e2e.mjs`:

```js
function treeSnapshot(directory) {
  if (!fs.existsSync(directory)) return [];
  return fs.readdirSync(directory, { recursive: true }).map(String).sort();
}
const retainedRuns = path.join(here, 'runs');
const runsBefore = treeSnapshot(retainedRuns);
```

Replace
`ok(!fs.existsSync(path.join(here, 'runs')), 'e2e leaves no run artifacts in the tree')`
with:

```js
eq(treeSnapshot(retainedRuns), runsBefore, 'e2e leaves pre-existing run artifacts unchanged');
```

- [ ] **Step 4: Run both e2e paths**

Run:

```bash
cd spikes/clone-economics
npm run e2e
node --test tests/e2e-coexistence.test.mjs
```

Expected: both PASS; pre-existing `runs/live/` files and the temporary marker remain unchanged during each run.

- [ ] **Step 5: Commit the coexistence fix**

```bash
git add spikes/clone-economics/e2e.mjs spikes/clone-economics/tests/e2e-coexistence.test.mjs
git commit -m "test: preserve retained clone run evidence"
```

### Task 3: Generate and validate the preregistered 100/30 fixture set

**Files:**
- Create: `spikes/clone-economics/fixtures/fixture-catalog-v2.json`
- Create: `spikes/clone-economics/scripts/generate-fixtures.mjs`
- Create: `spikes/clone-economics/fixtures/train-v2.json`
- Create: `spikes/clone-economics/fixtures/heldout-v2.json`
- Create: `spikes/clone-economics/src/fixture-set.mjs`
- Create: `spikes/clone-economics/tests/fixture-set.test.mjs`

- [ ] **Step 1: Write fixture-set contract tests**

Create `spikes/clone-economics/tests/fixture-set.test.mjs`:

```js
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { loadFixtureSet } from '../src/fixture-set.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('v2 fixtures contain 100 train and 30 disjoint heldout cases', () => {
  const fixtures = loadFixtureSet(root, 'v2');
  assert.equal(fixtures.train.length, 100);
  assert.equal(fixtures.heldout.length, 30);
  assert.equal(fixtures.disjoint, true);
  assert.equal(new Set(fixtures.train.map((x) => x.id)).size, 100);
  assert.equal(new Set(fixtures.heldout.map((x) => x.id)).size, 30);
  assert.equal(fixtures.heldout.every((x) => x.rubric && x.rubric.exactPaths.length === 1), true);
});

test('fixture generation is byte deterministic', () => {
  const train = fs.readFileSync(path.join(root, 'fixtures/train-v2.json'), 'utf8');
  const heldout = fs.readFileSync(path.join(root, 'fixtures/heldout-v2.json'), 'utf8');
  execFileSync(process.execPath, ['scripts/generate-fixtures.mjs', '--check'], { cwd: root });
  assert.equal(fs.readFileSync(path.join(root, 'fixtures/train-v2.json'), 'utf8'), train);
  assert.equal(fs.readFileSync(path.join(root, 'fixtures/heldout-v2.json'), 'utf8'), heldout);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd spikes/clone-economics && node --test tests/fixture-set.test.mjs`

Expected: FAIL because `src/fixture-set.mjs` and the v2 fixtures do not exist.

- [ ] **Step 3: Create the preregistered fixture catalog**

Create `fixtures/fixture-catalog-v2.json` with these exact domains; `trainDomains` and `heldoutDomains` must not share a path, command, or constraint:

```json
{
  "schemaVersion": 1,
  "fixtureSet": "v2",
  "trainDomains": [
    {"slug":"checkout","path":"@src/checkout/totals.ts","command":"npm test -- src/checkout/totals.test.ts","constraint":"preserve tax rounding exactly"},
    {"slug":"auth","path":"@src/auth/logout.ts","command":"npm test -- src/auth/logout.test.ts","constraint":"reuse the existing session invalidation path"},
    {"slug":"billing","path":"@src/billing/renewal.ts","command":"npm test -- src/billing/renewal.test.ts","constraint":"do not change invoice JSON"},
    {"slug":"worker","path":"@src/jobs/retry.ts","command":"npm test -- src/jobs/retry.test.ts","constraint":"keep retry attempts idempotent"},
    {"slug":"export","path":"@src/export/csv.ts","command":"npm test -- src/export/csv.test.ts","constraint":"add no new dependencies"},
    {"slug":"webhook","path":"@src/webhooks/verify.ts","command":"npm test -- src/webhooks/verify.test.ts","constraint":"reject invalid signatures without logging secrets"},
    {"slug":"search","path":"@src/search/query.ts","command":"npm test -- src/search/query.test.ts","constraint":"preserve the public query API"},
    {"slug":"profile","path":"@src/profile/update.ts","command":"npm test -- src/profile/update.test.ts","constraint":"leave unrelated profile fields untouched"},
    {"slug":"migration","path":"@src/db/migrations/042-orders.ts","command":"npm test -- src/db/migrations/042-orders.test.ts","constraint":"keep the migration reversible"},
    {"slug":"notifications","path":"@src/notifications/digest.ts","command":"npm test -- src/notifications/digest.test.ts","constraint":"send at most one digest per account"}
  ],
  "heldoutDomains": [
    {"slug":"cache","path":"@src/cache/invalidate.ts","command":"npm test -- src/cache/invalidate.test.ts","constraint":"keep the cache API backward-compatible"},
    {"slug":"session","path":"@src/session/timeout.ts","command":"npm test -- src/session/timeout.test.ts","constraint":"fix the root cause without suppressing the error"},
    {"slug":"report","path":"@src/reports/download.ts","command":"npm test -- src/reports/download.test.ts","constraint":"preserve the download response headers"},
    {"slug":"audit","path":"@src/audit/append.ts","command":"npm test -- src/audit/append.test.ts","constraint":"make audit entries append-only"},
    {"slug":"orders","path":"@src/orders/filter.ts","command":"npm test -- src/orders/filter.test.ts","constraint":"preserve the JSON response shape exactly"},
    {"slug":"upload","path":"@src/uploads/limits.ts","command":"npm test -- src/uploads/limits.test.ts","constraint":"reject oversized files before persistence"},
    {"slug":"flags","path":"@src/flags/evaluate.ts","command":"npm test -- src/flags/evaluate.test.ts","constraint":"keep evaluation deterministic"},
    {"slug":"tokens","path":"@src/tokens/rotate.ts","command":"npm test -- src/tokens/rotate.test.ts","constraint":"never log token material"},
    {"slug":"queue","path":"@src/queue/claim.ts","command":"npm test -- src/queue/claim.test.ts","constraint":"prevent two workers from claiming one job"},
    {"slug":"ledger","path":"@src/ledger/reconcile.ts","command":"npm test -- src/ledger/reconcile.test.ts","constraint":"do not mutate settled entries"}
  ],
  "trainTemplates": [
    {"mode":"Optimize","text":"Tighten the request for {slug} while preserving behavior."},
    {"mode":"Generate","text":"Write an implementation request for the {slug} change."},
    {"mode":"Diagnose","text":"The {slug} change spread beyond scope; rewrite the request to fix the root cause."},
    {"mode":"Spec","text":"Turn the broad {slug} idea into the next implementation specification."},
    {"mode":"Optimize","text":"Make the {slug} prompt explicit about verification and constraints."},
    {"mode":"Generate","text":"Ask for the smallest test-driven {slug} patch."},
    {"mode":"Diagnose","text":"The first {slug} attempt hid the error; produce a diagnostic request."},
    {"mode":"Spec","text":"Specify the {slug} behavior without starting implementation."},
    {"mode":"Optimize","text":"Remove ambiguity from this {slug} maintenance request."},
    {"mode":"Generate","text":"Create a repository-grounded request for {slug}."}
  ],
  "heldoutTemplates": [
    {"mode":"Optimize","text":"Optimize this {slug} request without breaking callers.","maxQuestions":0},
    {"mode":"Diagnose","text":"The {slug} implementation masked a failure; rewrite the request.","maxQuestions":0},
    {"mode":"Generate","text":"Generate the smallest verified change request for {slug}.","maxQuestions":0}
  ]
}
```

- [ ] **Step 4: Implement deterministic generation**

Create `scripts/generate-fixtures.mjs`. Generate IDs with
`` `tr-v2-${String(domainIndex + 1).padStart(2, '0')}-${String(templateIndex + 1).padStart(2, '0')}` ``
and the same expression with the `ho-v2` prefix. Each generated training row is:

```js
{
  id,
  mode: template.mode,
  input: `${template.text.replace('{slug}', domain.slug)} Use ${domain.path}; verify with ${domain.command}; ${domain.constraint}.`,
  expectedOutput: `${template.mode}\n${domain.path}\n${domain.command}\n${domain.constraint}\nShow the diff`,
}
```

Each held-out row uses the same input construction and this exact rubric:

```js
{
  expectedMode: template.mode,
  maxQuestions: template.maxQuestions,
  exactPaths: [{ value: domain.path, weight: 2, critical: true }],
  exactCommands: [{ value: domain.command, weight: 2, critical: true }],
  requiredAll: [{ value: domain.constraint, dimension: 'constraints', weight: 2, critical: true }],
  requiredAny: [{ values: ['Show the diff', 'Return the patch'], dimension: 'output', weight: 1, critical: false }],
  forbidden: [{ value: '[', dimension: 'grounding', weight: 1, critical: true }],
}
```

Write stable two-space JSON plus a trailing newline. With `--check`, generate in
memory and throw ``new Error(`Generated fixture drift: ${file}`)`` rather than
modifying either file.

- [ ] **Step 5: Implement fixture loading and disjointness validation**

Create `src/fixture-set.mjs` with exported `normalizedInputHash` and `loadFixtureSet`:

```js
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const normalizedInputHash = (value) => `sha256:${createHash('sha256')
  .update(value.trim().replace(/\s+/g, ' ').toLowerCase()).digest('hex')}`;

export function loadFixtureSet(root, name) {
  const train = JSON.parse(fs.readFileSync(path.join(root, `fixtures/train-${name}.json`), 'utf8'));
  const heldout = JSON.parse(fs.readFileSync(path.join(root, `fixtures/heldout-${name}.json`), 'utf8'));
  const decorate = (items) => items.map((item) => ({ ...item, inputHash: normalizedInputHash(item.input) }));
  const decoratedTrain = decorate(train);
  const decoratedHeldout = decorate(heldout);
  const trainIds = new Set(decoratedTrain.map((x) => x.id));
  const trainHashes = new Set(decoratedTrain.map((x) => x.inputHash));
  const disjoint = decoratedHeldout.every((x) => !trainIds.has(x.id) && !trainHashes.has(x.inputHash));
  if (!disjoint) throw new Error('Train and heldout fixtures must be disjoint by ID and normalized-input hash');
  return { train: decoratedTrain, heldout: decoratedHeldout, disjoint };
}
```

- [ ] **Step 6: Generate and verify the committed fixtures**

Run:

```bash
cd spikes/clone-economics
node scripts/generate-fixtures.mjs
node --test tests/fixture-set.test.mjs
```

Expected: `train-v2.json` has 100 rows, `heldout-v2.json` has 30 rows, and both tests PASS.

- [ ] **Step 7: Commit the preregistered fixture set**

```bash
git add spikes/clone-economics/fixtures/fixture-catalog-v2.json spikes/clone-economics/fixtures/train-v2.json spikes/clone-economics/fixtures/heldout-v2.json spikes/clone-economics/scripts/generate-fixtures.mjs spikes/clone-economics/src/fixture-set.mjs spikes/clone-economics/tests/fixture-set.test.mjs
git commit -m "feat: preregister larger clone fixture set"
```

### Task 4: Add the N sweep and live-spend gate

**Files:**
- Create: `spikes/clone-economics/fixtures/sweep-v1.json`
- Create: `spikes/clone-economics/fixtures/live-budget-v1.json`
- Create: `spikes/clone-economics/src/authorization.mjs`
- Create: `spikes/clone-economics/src/budget.mjs`
- Create: `spikes/clone-economics/src/sweep.mjs`
- Create: `spikes/clone-economics/sweep.mjs`
- Create: `spikes/clone-economics/tests/authorization.test.mjs`
- Create: `spikes/clone-economics/tests/budget.test.mjs`
- Create: `spikes/clone-economics/tests/fixtures/live-contract.mjs`
- Create: `spikes/clone-economics/tests/sweep.test.mjs`
- Modify: `spikes/clone-economics/src/experiment.mjs:91-157`
- Modify: `spikes/clone-economics/src/adapters.mjs:75-159`
- Modify: `spikes/clone-economics/package.json`

- [ ] **Step 1: Commit the sweep preregistration before orchestration code**

Create `fixtures/sweep-v1.json`:

```json
{
  "schemaVersion": 1,
  "experimentFamily": "clone-economics-high-n-v1",
  "fixtureSet": "v2",
  "nValues": [6, 25, 50, 100],
  "heldoutMinimum": 30,
  "replicates": [
    { "replicateId": "r1", "pairOrderSeed": 1701, "distillationSeed": 2701 },
    { "replicateId": "r2", "pairOrderSeed": 1702, "distillationSeed": 2702 },
    { "replicateId": "r3", "pairOrderSeed": 1703, "distillationSeed": 2703 }
  ],
  "highNDefinition": 100,
  "targetThreshold": 0.8,
  "requireAllTargetCriticalGates": true,
  "acquisitionTreatment": "modeled_unless_x402_receipts_attached",
  "attemptCostTreatment": "include_every_attempted_provider_call",
  "publicationRequiresValidTarget": true,
  "publicationRequiresIndependentDistillationSeeds": true
}
```

`pairOrderSeed` controls only deterministic acquisition-pair ordering.
`distillationSeed` is a distinct requested stochastic seed for the clone
distillation call. Neither may be relabeled as the other.

Commit this file by itself so later results cannot rewrite the preregistration:

```bash
git add spikes/clone-economics/fixtures/sweep-v1.json
git commit -m "docs: preregister clone high-N sweep"
```

- [ ] **Step 2: Commit the live budget contract in an explicitly unapproved state**

Create `fixtures/live-budget-v1.json` exactly as follows. Nulls are intentional:
the repository must not manufacture a current model, price, or token cap.

```json
{
  "schemaVersion": 1,
  "experimentFamily": "clone-economics-high-n-v1",
  "approvalStatus": "not_approved",
  "provider": "anthropic",
  "model": null,
  "pricing": {
    "currency": "USD",
    "unit": "per_million_tokens",
    "inputUsdPerMillionTokens": null,
    "outputUsdPerMillionTokens": null,
    "asOf": null,
    "source": null
  },
  "tokenCaps": {
    "maxInputTokens": null,
    "maxOutputTokens": null
  }
}
```

The offline schema reader permits this `not_approved` state so a clean checkout
can run tests and mock preflight. The live validator must reject it. Before any
human-run live sweep, a human must verify the provider's current model pricing,
replace every null, set `approvalStatus` to `approved`, and commit that reviewed
snapshot. Prices are decimal strings in live snapshots, never JSON numbers; the
implementation converts them to integer micro-USD without floating point.

Commit the initial contract separately:

```bash
git add spikes/clone-economics/fixtures/live-budget-v1.json
git commit -m "docs: add unapproved clone sweep budget contract"
```

- [ ] **Step 3: Write sweep contract tests**

Create `tests/sweep.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyHighNSeedValidity,
  seededOrder,
  validateSweepConfig,
} from '../src/sweep.mjs';

const config = {
  schemaVersion: 1,
  experimentFamily: 'clone-economics-high-n-v1',
  fixtureSet: 'v2',
  nValues: [6, 25, 50, 100],
  heldoutMinimum: 30,
  replicates: [
    { replicateId: 'r1', pairOrderSeed: 1701, distillationSeed: 2701 },
    { replicateId: 'r2', pairOrderSeed: 1702, distillationSeed: 2702 },
    { replicateId: 'r3', pairOrderSeed: 1703, distillationSeed: 2703 },
  ],
  highNDefinition: 100,
};

test('sweep contract requires the exact preregistered dimensions', () => {
  assert.doesNotThrow(() => validateSweepConfig(config, { trainCount: 100, heldoutCount: 30 }));
  assert.throws(() => validateSweepConfig({ ...config, nValues: [6, 100] }, { trainCount: 100, heldoutCount: 30 }), /N=6,25,50,100/);
});

test('three pair-order seeds are deterministic and distinct', () => {
  const rows = Array.from({ length: 100 }, (_, i) => `row-${i}`);
  const orders = config.replicates.map((replicate) => seededOrder(rows, replicate.pairOrderSeed));
  assert.deepEqual(orders[0], seededOrder(rows, 1701));
  assert.notDeepEqual(orders[0], orders[1]);
  assert.notDeepEqual(orders[1], orders[2]);
});

test('pair-order and distillation seeds are separate distinct contracts', () => {
  assert.deepEqual(config.replicates.map((x) => x.pairOrderSeed), [1701, 1702, 1703]);
  assert.deepEqual(config.replicates.map((x) => x.distillationSeed), [2701, 2702, 2703]);
  assert.equal(config.replicates.some((x) => x.pairOrderSeed === x.distillationSeed), false);
});

test('publishable high-N requires three adapter-confirmed distillation seeds', () => {
  const validBenchmark = { valid: true, verdict: 'VALID_BENCHMARK' };
  const invalidBenchmark = { valid: false, verdict: 'INVALID_BENCHMARK_TARGET_FAILED' };
  const honored = config.replicates.map((replicate) => ({
    n: 100,
    replicateId: replicate.replicateId,
    requestedDistillationSeed: replicate.distillationSeed,
    appliedDistillationSeed: replicate.distillationSeed,
    distillationSeedStatus: 'honored',
    status: 'complete',
    benchmark: validBenchmark,
  }));
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored,
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: true,
    reason: null,
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: [
      ...honored.slice(0, 2),
      { ...honored[2], appliedDistillationSeed: null, distillationSeedStatus: 'unsupported' },
    ],
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: false,
    reason: 'DISTILLATION_SEEDS_UNCONTROLLED',
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored.map((cell, index) =>
      index === 1 ? { ...cell, benchmark: invalidBenchmark } : cell),
    adapterMode: 'live',
    standaloneBenchmark: validBenchmark,
  }), {
    valid: false,
    reason: 'HIGH_N_TARGET_INVALID',
  });
  assert.deepEqual(classifyHighNSeedValidity({
    cells: honored,
    adapterMode: 'live',
    standaloneBenchmark: invalidBenchmark,
  }), {
    valid: false,
    reason: 'STANDALONE_TARGET_INVALID',
  });
});
```

- [ ] **Step 4: Write exact authorization, budget, and pre-construction tests**

Create `tests/authorization.test.mjs` with synthetic data only:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  liveAuthorizationHash,
  validateLiveApproval,
} from '../src/authorization.mjs';
import { approved, config } from './fixtures/live-contract.mjs';

test('live approval binds the exact canonical sweep and budget snapshot', () => {
  const authorizationHash = liveAuthorizationHash({ config, snapshot: approved });
  assert.match(authorizationHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(validateLiveApproval({
    APPROVE_LIVE_SWEEP_SHA256: authorizationHash,
    MAX_SWEEP_COST_USD: '50.000001',
  }, { config, snapshot: approved }), 50_000_001n);
});

test('a stale approval fails after any material snapshot or config change', () => {
  const stale = liveAuthorizationHash({ config, snapshot: approved });
  const mutations = [
    { config: { ...config, nValues: [6, 25, 50] }, snapshot: approved },
    { config: {
      ...config,
      replicates: config.replicates.map((x, index) =>
        index === 0 ? { ...x, distillationSeed: 9999 } : x),
    }, snapshot: approved },
    { config, snapshot: { ...approved, model: 'changed-model' } },
    { config, snapshot: {
      ...approved,
      pricing: { ...approved.pricing, inputUsdPerMillionTokens: '3.01' },
    } },
    { config, snapshot: {
      ...approved,
      tokenCaps: { ...approved.tokenCaps, maxOutputTokens: 2048 },
    } },
  ];
  for (const changed of mutations) {
    assert.throws(() => validateLiveApproval({
      APPROVE_LIVE_SWEEP_SHA256: stale,
      MAX_SWEEP_COST_USD: '50',
    }, changed), /stale or does not match/i);
  }
});

test('the old experiment-family token is never accepted as authorization', () => {
  assert.throws(() => validateLiveApproval({
    APPROVE_LIVE_SWEEP_SHA256: config.experimentFamily,
    MAX_SWEEP_COST_USD: '50',
  }, { config, snapshot: approved }), /sha256/);
});
```

Create `tests/fixtures/live-contract.mjs`:

```js
export const config = {
  schemaVersion: 1,
  experimentFamily: 'clone-economics-high-n-v1',
  fixtureSet: 'v2',
  nValues: [6, 25, 50, 100],
  heldoutMinimum: 30,
  replicates: [
    { replicateId: 'r1', pairOrderSeed: 1701, distillationSeed: 2701 },
    { replicateId: 'r2', pairOrderSeed: 1702, distillationSeed: 2702 },
    { replicateId: 'r3', pairOrderSeed: 1703, distillationSeed: 2703 },
  ],
  highNDefinition: 100,
  publicationRequiresIndependentDistillationSeeds: true,
};

export const approved = {
  schemaVersion: 1,
  experimentFamily: config.experimentFamily,
  approvalStatus: 'approved',
  provider: 'anthropic',
  model: 'synthetic-budget-test-model',
  pricing: {
    currency: 'USD',
    unit: 'per_million_tokens',
    inputUsdPerMillionTokens: '3.00',
    outputUsdPerMillionTokens: '15.00',
    asOf: '2026-07-17T00:00:00Z',
    source: 'https://example.invalid/synthetic-pricing-fixture',
  },
  tokenCaps: { maxInputTokens: 4096, maxOutputTokens: 1024 },
};
```

Import this fixture from both tests so authorization and cost calculations
cannot silently use different contracts.

Create `tests/budget.test.mjs`. The approved fixture below is synthetic test
data only; it must not replace `fixtures/live-budget-v1.json`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  calculateProviderCostMicroUsd,
  conservativeSweepRequestCount,
  createAttemptBudget,
  estimateLiveSweepMicroUsd,
  validateApprovedBudgetSnapshot,
} from '../src/budget.mjs';
import { liveAuthorizationHash } from '../src/authorization.mjs';
import { startLiveSweep } from '../src/sweep.mjs';
import { approved, config } from './fixtures/live-contract.mjs';

const counts = { trainCount: 100, heldoutCount: 30, v2Count: 2 };

test('live snapshot must be complete, approved, and match the experiment', () => {
  assert.doesNotThrow(() => validateApprovedBudgetSnapshot(approved, config));
  assert.throws(
    () => validateApprovedBudgetSnapshot({ ...approved, approvalStatus: 'not_approved' }, config),
    /not approved/i,
  );
  assert.throws(
    () => validateApprovedBudgetSnapshot({
      ...approved,
      pricing: { ...approved.pricing, inputUsdPerMillionTokens: null },
    }, config),
    /input pricing/i,
  );
});

test('preflight counts the target gate and every call in all 12 cells', () => {
  assert.equal(conservativeSweepRequestCount(config, counts), 1713);
  assert.equal(calculateProviderCostMicroUsd({
    inputTokens: 4096,
    outputTokens: 1024,
    snapshot: approved,
  }), 27_648n);
  assert.equal(estimateLiveSweepMicroUsd({ config, counts, snapshot: approved }), 47_361_024n);
});

test('an under-cap live request constructs neither adapter nor fetch', async () => {
  let adapterConstructions = 0;
  let fetchConstructions = 0;
  await assert.rejects(startLiveSweep({
    env: {
      APPROVE_LIVE_SWEEP_SHA256: liveAuthorizationHash({ config, snapshot: approved }),
      MAX_SWEEP_COST_USD: '47.00',
    },
    config,
    counts,
    snapshot: approved,
    fetchFactory() {
      fetchConstructions += 1;
      throw new Error('fetch must not be constructed');
    },
    adapterFactory() {
      adapterConstructions += 1;
      throw new Error('adapter must not be constructed');
    },
  }), /47\.361024.*47\.000000/);
  assert.equal(adapterConstructions, 0);
  assert.equal(fetchConstructions, 0);
});

test('every attempted call is reserved and the next over-cap call is refused', () => {
  const budget = createAttemptBudget({ capMicroUsd: 300n, worstCaseCallMicroUsd: 100n });
  const first = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'one' });
  budget.settleAttempt(first, { knownCostMicroUsd: 80n, success: true });
  const second = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'two' });
  budget.settleAttempt(second, { knownCostMicroUsd: 90n, success: false });
  const third = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'three' });
  budget.settleAttempt(third, { knownCostMicroUsd: 100n, success: true });
  assert.deepEqual(budget.state(), {
    attemptedCalls: 3,
    knownAccruedMicroUsd: 270n,
    outstandingReservedMicroUsd: 0n,
    lock: null,
  });
  assert.throws(
    () => budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'four' }),
    /would exceed.*cap/i,
  );
  assert.equal(budget.state().attemptedCalls, 3);
});

test('unknown cost locks its reservation and fails closed', () => {
  const budget = createAttemptBudget({ capMicroUsd: 200n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'distill', caseId: null });
  assert.throws(
    () => budget.settleAttempt(attempt, { knownCostMicroUsd: null, success: false }),
    /unknown live cost.*budget locked/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 0n,
    outstandingReservedMicroUsd: 100n,
    lock: { kind: 'unknown_cost', attemptId: attempt },
  });
  assert.throws(
    () => budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'blocked' }),
    /budget locked/i,
  );
});

test('above-token-cap usage records exact cost and permanently locks as budget_overrun', () => {
  const budget = createAttemptBudget({ capMicroUsd: 1_000n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'distill', caseId: null });
  assert.throws(
    () => budget.settleAttempt(attempt, {
      knownCostMicroUsd: 140n,
      success: false,
      budgetViolation: 'token_cap_exceeded',
    }),
    /budget_overrun.*token cap/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 140n,
    outstandingReservedMicroUsd: 0n,
    lock: { kind: 'budget_overrun', attemptId: attempt, reason: 'token_cap_exceeded' },
  });
  assert.throws(() => budget.reserveNextAttempt({ kind: 'blocked', caseId: null }), /budget_overrun/);
});

test('known provider cost above the human cap is accrued before permanent lock', () => {
  const budget = createAttemptBudget({ capMicroUsd: 100n, worstCaseCallMicroUsd: 100n });
  const attempt = budget.reserveNextAttempt({ kind: 'target-heldout', caseId: 'one' });
  assert.throws(
    () => budget.settleAttempt(attempt, { knownCostMicroUsd: 125n, success: true }),
    /budget_overrun.*human cap/i,
  );
  assert.deepEqual(budget.state(), {
    attemptedCalls: 1,
    knownAccruedMicroUsd: 125n,
    outstandingReservedMicroUsd: 0n,
    lock: { kind: 'budget_overrun', attemptId: attempt, reason: 'human_cap_exceeded' },
  });
  assert.throws(() => budget.reserveNextAttempt({ kind: 'blocked', caseId: null }), /budget_overrun/);
});
```

The 1,713-call estimate deliberately includes the 30-call standalone target
gate plus every current per-cell target/clone/control/evolution call. It is a
conservative preflight ceiling; a later optimization may make fewer calls but
must not lower this committed estimate without a new preregistration and test.

- [ ] **Step 5: Run the tests to verify they fail**

Run: `cd spikes/clone-economics && node --test tests/sweep.test.mjs tests/authorization.test.mjs tests/budget.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/sweep.mjs`,
`src/authorization.mjs`, or `src/budget.mjs`; no adapter or fetch factory runs.

- [ ] **Step 6: Implement the deterministic pair-order seed**

In `src/sweep.mjs`, use a local Mulberry32 PRNG and Fisher-Yates shuffle:

```js
function mulberry32(seed) {
  return () => {
    seed |= 0;
    seed = seed + 0x6D2B79F5 | 0;
    let t = Math.imul(seed ^ seed >>> 15, 1 | seed);
    t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t;
    return ((t ^ t >>> 14) >>> 0) / 4294967296;
  };
}

export function seededOrder(values, seed) {
  const result = [...values];
  const random = mulberry32(seed);
  for (let i = result.length - 1; i > 0; i -= 1) {
    const j = Math.floor(random() * (i + 1));
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}
```

Call this function only with `pairOrderSeed`. Document that it controls
acquisition-pair order and nothing about provider sampling. The separate
`distillationSeed` travels through the distillation adapter contract in Step 8.

- [ ] **Step 7: Implement config, approval, and exact budget validation**

```js
export function validateSweepConfig(config, counts) {
  if (JSON.stringify(config.nValues) !== JSON.stringify([6, 25, 50, 100])) {
    throw new Error('Sweep must use N=6,25,50,100');
  }
  if (!Array.isArray(config.replicates) || config.replicates.length !== 3) {
    throw new Error('Sweep must use exactly three preregistered replicates');
  }
  const ids = config.replicates.map((x) => x.replicateId);
  const pairOrderSeeds = config.replicates.map((x) => x.pairOrderSeed);
  const distillationSeeds = config.replicates.map((x) => x.distillationSeed);
  for (const [label, values] of [
    ['replicate IDs', ids],
    ['pair-order seeds', pairOrderSeeds],
    ['distillation seeds', distillationSeeds],
  ]) {
    if (new Set(values).size !== 3) throw new Error(`Sweep requires three distinct ${label}`);
  }
  if (![...pairOrderSeeds, ...distillationSeeds].every(Number.isSafeInteger)) {
    throw new Error('Sweep seeds must be safe integers');
  }
  if (counts.trainCount < 100 || counts.heldoutCount < 30) {
    throw new Error('Sweep requires at least 100 train and 30 heldout fixtures');
  }
}
```

In `src/authorization.mjs`, canonicalize by recursively sorting object keys
while retaining array order, then hash the complete validated objects:

```js
import { createHash } from 'node:crypto';

import { parseUsdToMicroUsd } from './budget.mjs';

function canonicalize(value) {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  throw new Error(`Unsupported authorization value type: ${typeof value}`);
}

export function liveAuthorizationHash({ config, snapshot }) {
  const canonical = JSON.stringify(canonicalize({
    authorizationSchemaVersion: 1,
    sweepConfig: config,
    liveBudgetSnapshot: snapshot,
  }));
  return `sha256:${createHash('sha256').update(canonical).digest('hex')}`;
}

export function validateLiveApproval(env, contract) {
  const supplied = env.APPROVE_LIVE_SWEEP_SHA256;
  if (typeof supplied !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(supplied)) {
    throw new Error('APPROVE_LIVE_SWEEP_SHA256 must be a lowercase sha256 digest');
  }
  const expected = liveAuthorizationHash(contract);
  if (supplied !== expected) {
    throw new Error(`Live approval is stale or does not match ${expected}`);
  }
  return parseUsdToMicroUsd(env.MAX_SWEEP_COST_USD, 'MAX_SWEEP_COST_USD');
}
```

`parseUsdToMicroUsd` accepts only a plain,
positive USD decimal with at most six fractional digits. It rejects exponent
notation, signs, commas, whitespace, `NaN`, `Infinity`, zero, and excess
precision; it returns a `bigint` number of micro-USD.

Implement these contracts in `src/budget.mjs`:

```js
const MICRO_USD_PER_USD = 1_000_000n;

export function parseUsdToMicroUsd(value, fieldName) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(value)) {
    throw new Error(`${fieldName} must be a positive plain USD decimal with at most six places`);
  }
  const [whole, fraction = ''] = value.split('.');
  const result = BigInt(whole) * MICRO_USD_PER_USD
    + BigInt(fraction.padEnd(6, '0'));
  if (result <= 0n) throw new Error(`${fieldName} must be positive`);
  return result;
}

const ceilDiv = (numerator, denominator) =>
  (numerator + denominator - 1n) / denominator;

export function calculateProviderCostMicroUsd({ inputTokens, outputTokens, snapshot }) {
  if (!Number.isSafeInteger(inputTokens) || inputTokens < 0
      || !Number.isSafeInteger(outputTokens) || outputTokens < 0) {
    throw new Error('Provider usage must contain non-negative safe integer token counts');
  }
  const inputPrice = parseUsdToMicroUsd(
    snapshot.pricing.inputUsdPerMillionTokens,
    'input pricing',
  );
  const outputPrice = parseUsdToMicroUsd(
    snapshot.pricing.outputUsdPerMillionTokens,
    'output pricing',
  );
  return ceilDiv(BigInt(inputTokens) * inputPrice, 1_000_000n)
    + ceilDiv(BigInt(outputTokens) * outputPrice, 1_000_000n);
}

export function exceedsCommittedTokenCaps({ inputTokens, outputTokens, snapshot }) {
  return inputTokens > snapshot.tokenCaps.maxInputTokens
    || outputTokens > snapshot.tokenCaps.maxOutputTokens;
}
```

Keep cost calculation and authorization validation separate: valid observed
usage is always priced exactly, while `exceedsCommittedTokenCaps` decides
whether that known charge also creates a permanent `budget_overrun` lock.

`validateBudgetSnapshotShape` accepts either the exact unapproved/null state or
a complete approved state. `validateApprovedBudgetSnapshot` additionally
requires all of the following before live use:

- schema version 1 and the exact experiment family;
- `approvalStatus: "approved"`;
- provider and model as nonempty strings;
- currency `USD` and unit `per_million_tokens`;
- positive plain-decimal input/output prices with at most six places;
- an ISO-8601 `asOf` timestamp and an HTTPS `source` URL;
- positive safe-integer input/output token caps.

Unknown, null, malformed, mismatched, or unapproved data fails closed. The live
adapter receives model, prices, and caps from this committed snapshot; high-N
live execution must not override them with environment values.

Implement the conservative count exactly:

```js
export function conservativeSweepRequestCount(config, counts) {
  const cells = config.nValues.flatMap((n) =>
    config.replicates.map(() => (
      n + 1 + counts.heldoutCount * 3 + counts.v2Count * 2
    )));
  return counts.heldoutCount + cells.reduce((sum, value) => sum + value, 0);
}

export function estimateLiveSweepMicroUsd({ config, counts, snapshot }) {
  validateApprovedBudgetSnapshot(snapshot, config);
  const perCall = calculateProviderCostMicroUsd({
    inputTokens: snapshot.tokenCaps.maxInputTokens,
    outputTokens: snapshot.tokenCaps.maxOutputTokens,
    snapshot,
  });
  return BigInt(conservativeSweepRequestCount(config, counts)) * perCall;
}
```

Use a formatter that renders integer micro-USD with exactly six decimal places
in errors. With the synthetic test snapshot, the worst case is 27,648
micro-USD per call and 47,361,024 micro-USD across 1,713 calls.

- [ ] **Step 8: Make experiment fixtures and pair order injectable**

Change `runExperiment` to accept `options.trainFixtures`,
`options.heldoutFixtures`, `options.pairOrderSeed`,
`options.requestedDistillationSeed`, `options.replicateId`, and
`options.fixtureSet`, falling back to the original v1 files for the old offline
e2e. Before selecting N, order the supplied training rows:

```js
const orderedTrain = options.pairOrderSeed === undefined
  ? trainFixtures
  : seededOrder(trainFixtures, options.pairOrderSeed);
const selectedTrain = orderedTrain.slice(0, N);
```

Include this exact seed schema in each report:

```js
seedContract: {
  replicateId: options.replicateId ?? null,
  pairOrderSeed: options.pairOrderSeed ?? null,
  pairOrderSeedStatus: options.pairOrderSeed === undefined ? 'not_requested' : 'honored_locally',
  requestedDistillationSeed: options.requestedDistillationSeed ?? null,
  appliedDistillationSeed: distilled.seed.appliedSeed,
  distillationSeedStatus: distilled.seed.status,
  distillationSeedMechanism: distilled.seed.mechanism,
}
```

Only the `distill` request receives `requestedDistillationSeed`; acquisition and
evaluation calls set it to null. Extend every adapter response with:

```js
seed: {
  requestedSeed: request.requestedDistillationSeed ?? null,
  appliedSeed: null,
  status: request.requestedDistillationSeed === undefined ? 'not_requested' : 'unsupported',
  mechanism: request.requestedDistillationSeed === undefined
    ? 'no_seed_requested'
    : 'provider_seed_not_supported_by_adapter',
}
```

`requestedSeed` and `appliedSeed` are safe integers or null; `status` is one of
`honored`, `unsupported`, `synthetic_honored`, or `not_requested`; `mechanism`
is a nonempty string.

An adapter may report `honored` only when it sent the requested integer through
a documented provider seed mechanism for that model/request and did not
silently substitute it. The current `LiveAnthropicAdapter` has no such request
field in this harness, so it reports `unsupported`, `appliedSeed: null`, and
`mechanism: 'provider_seed_not_supported_by_adapter'`; it must not pretend
pair-order determinism controls model sampling. The mock adapter reports
`synthetic_honored` and uses the requested value only to select deterministic
canned distillation output. Synthetic status never satisfies the live
publishability gate.

Extend `MockLlmAdapter` with an optional `outputFor` callback used only by the
offline v2 sweep. The callback receives the request identifier, not target bytes:

```js
constructor({ transcript, cloneSkillMd, outputFor = null }) {
  this.transcript = transcript;
  this.cloneSkillMd = cloneSkillMd;
  this.outputFor = outputFor;
  this.capturedRequests = [];
  this.records = [];
  this.attempts = [];
  this.pricing = transcript.pricing;
}

async invoke(request) {
  this.capturedRequests.push(structuredClone(request));
  const customOutput = this.outputFor?.(request);
  let output = typeof customOutput === 'string' ? customOutput : undefined;
  if (output === undefined) {
    if (request.kind === 'distill') output = this.cloneSkillMd;
    else if (request.kind === 'target-train') output = this.transcript.trainOutputs[request.caseId];
    else if (request.kind.endsWith('-v2-heldout')) {
      const profile = request.kind.startsWith('target-') ? 'target' : 'clone';
      output = this.transcript.v2Outputs[request.caseId]?.[profile];
    } else {
      const profile = request.kind === 'target-heldout'
        ? 'target'
        : request.kind === 'clone-heldout' ? 'clone' : 'bad';
      output = this.transcript.heldoutOutputs[request.caseId]?.[profile];
    }
  }
  if (typeof output !== 'string') {
    throw new Error(`Missing SYNTHETIC transcript output for ${request.kind}:${request.caseId ?? 'distill'}`);
  }
  // Continue with the existing usage-profile validation and normalized record
  // construction beginning at `const profile = this.transcript.usageProfiles`.
}
```

The mock sweep constructs maps from the v2 fixtures. Training requests return
their committed `expectedOutput`; target and clone held-out requests return:

```js
const compliantHeldoutOutput = (fixture) => [
  fixture.mode,
  fixture.rubric.exactPaths[0].value,
  fixture.rubric.exactCommands[0].value,
  fixture.rubric.requiredAll[0].value,
  'Show the diff',
].join('\n');
```

Immediately before each adapter return, construct seed evidence. The mock uses:

```js
const requestedSeed = request.kind === 'distill'
  ? request.requestedDistillationSeed ?? null
  : null;
const seed = requestedSeed === null
  ? { requestedSeed: null, appliedSeed: null, status: 'not_requested', mechanism: 'no_seed_requested' }
  : {
      requestedSeed,
      appliedSeed: requestedSeed,
      status: 'synthetic_honored',
      mechanism: 'deterministic_mock_fixture_selection',
    };
return { output, ...record, seed };
```

The live adapter uses the unsupported shape above unless its provider-specific
request builder has an implemented and tested seed field. Never infer
`honored` merely because outputs differ across calls.

`bad-clone-heldout` returns `Unscoped answer`; `distill` and v2-overlay requests
continue using the existing canned transcript. Never add `expectedOutput` or a
rubric to a live request payload.

- [ ] **Step 9: Guard and record every attempted provider call**

Implement `createAttemptBudget` in `src/budget.mjs`. Its
`reserveNextAttempt(metadata)` method must:

1. reject when any permanent `unknown_cost` or `budget_overrun` lock exists;
2. calculate `known accrued + outstanding reservations + worst next call`;
3. reject without incrementing the attempt count if that total exceeds the
   human cap;
4. otherwise increment `attemptedCalls`, retain one worst-case reservation, and
   return its opaque ID.

Its
`settleAttempt(id, { knownCostMicroUsd, success, budgetViolation = null })`
method has two distinct fail-closed paths:

- A null cost keeps the full reservation outstanding, sets the permanent lock
  `{ kind: 'unknown_cost', attemptId }`, and throws
  `Unknown live cost; budget locked`. Missing or malformed usage takes this
  path because no exact charge can be computed.
- A non-negative exact bigint cost always releases the reservation and adds the
  entire cost to `knownAccruedMicroUsd`, even when it exceeds the reservation,
  committed token caps, or human cap. If `budgetViolation ===
  'token_cap_exceeded'`, the cost exceeds its reservation, or cumulative known
  cost exceeds the human cap, persist
  `{ kind: 'budget_overrun', attemptId, reason }` and throw only after state is
  updated. Reason precedence is `token_cap_exceeded`, then
  `human_cap_exceeded`, then `reservation_exceeded`.

Both locks are permanent for the sweep and reject every later reservation.
Never relabel a known overrun as unknown, truncate it to the reservation, or
zero it because the response is rejected. `state()` returns exactly
`attemptedCalls`, `knownAccruedMicroUsd`, `outstandingReservedMicroUsd`, and
`lock` as asserted above.

The settlement branch inside `createAttemptBudget` is:

```js
function settleAttempt(attemptId, {
  knownCostMicroUsd,
  success,
  budgetViolation = null,
}) {
  const reservation = reservations.get(attemptId);
  if (!reservation) throw new Error(`Unknown or already-settled attempt ${attemptId}`);
  if (lock) throw new Error(`Budget permanently locked: ${lock.kind}`);
  if (knownCostMicroUsd === null) {
    lock = { kind: 'unknown_cost', attemptId };
    throw new Error('Unknown live cost; budget locked');
  }
  if (typeof knownCostMicroUsd !== 'bigint' || knownCostMicroUsd < 0n) {
    lock = { kind: 'unknown_cost', attemptId };
    throw new Error('Malformed live cost; budget locked as unknown_cost');
  }
  reservations.delete(attemptId);
  outstandingReservedMicroUsd -= reservation.amountMicroUsd;
  knownAccruedMicroUsd += knownCostMicroUsd;
  const reason = budgetViolation === 'token_cap_exceeded'
    ? 'token_cap_exceeded'
    : knownAccruedMicroUsd > capMicroUsd
      ? 'human_cap_exceeded'
      : knownCostMicroUsd > reservation.amountMicroUsd
        ? 'reservation_exceeded'
        : null;
  settled.set(attemptId, { knownCostMicroUsd, success });
  if (reason) {
    lock = { kind: 'budget_overrun', attemptId, reason };
    const label = reason.replaceAll('_', ' ');
    throw new Error(`budget_overrun: ${label}; exact cost was accrued`);
  }
}
```

Add `attempts` to both adapters. In the live adapter, perform local request-kind,
prompt-byte-upper-bound, and token-cap validation first. Immediately before the
actual `fetch` expression, call `budget.reserveNextAttempt`; there must be no
await, retry wrapper, or provider action between reservation and fetch. Use the
injected fetch function rather than global `fetch`.

After a provider response, require non-negative safe-integer input and output
usage and recompute exact cost with `calculateProviderCostMicroUsd` before
enforcing the committed token caps. The cost function prices any valid observed
usage; token caps define authorization, not whether the resulting bill is
knowable. If either observed count exceeds its cap, settle the exact cost with
`budgetViolation: 'token_cap_exceeded'`, retain the observed token counts and
cost in the failed attempt, permanently lock `budget_overrun`, and abort. Do
not trust a provider-supplied dollar field. Missing/malformed usage, or a
network/HTTP failure without valid usage, retains the reservation under
`unknown_cost`; a response with valid usage is settled as known even if the
request otherwise failed. Neither lock permits a later provider call.

Wrap every `invoke` body in `try/catch`; on success append the normalized
request ID/status/cost. On error append this sanitized attempt before rethrowing:

```js
this.attempts.push({
  attemptId: `${request.kind}:${request.caseId ?? 'distill'}:${this.attempts.length + 1}`,
  kind: request.kind,
  caseId: request.caseId ?? null,
  success: false,
  providerRequestId: null,
  latencyMs: performance.now() - started,
  inputTokens: observedUsage?.inputTokens ?? null,
  outputTokens: observedUsage?.outputTokens ?? null,
  providerCostMicroUsd: knownCostMicroUsd?.toString() ?? null,
  providerCostUsd: knownCostMicroUsd === null
    ? null
    : Number(knownCostMicroUsd) / 1_000_000,
  failureClass: error instanceof Error ? error.name : 'UnknownError',
});
throw error;
```

Set `providerCostUsd` from the exact micro-USD value only after settlement. On
both success and known-cost failure, persist the exact integer as base-10
`providerCostMicroUsd` and derive `providerCostUsd` only for display/aggregate
compatibility. On success append the normalized equivalent with `success:
true`. The attempt ID
and budget reservation ID must be correlated internally, but the reservation
does not expose request content. Never include prompt payload, output text, API
keys, serialized request bodies, or headers in `attempts`.

The catch path must not lose the original provider/cap error when settlement
also reports `unknown_cost` or `budget_overrun`. Record both failure classes in
a sanitized `AggregateError`, with the permanent-lock error first so the CLI
makes the stop condition obvious. Separate adapter tests must prove: missing
usage retains one reservation under `unknown_cost`; above-token usage records
the exact observed tokens/cost with no reservation under `budget_overrun`; a
known charge above the human cap is fully accrued under `budget_overrun`; and
all three cases make zero retry or subsequent provider calls.

- [ ] **Step 10: Implement sweep preflight and orchestration**

Export `startLiveSweep` from `src/sweep.mjs`. Its ordering is a security
contract:

1. validate fixture counts and the sweep preregistration;
2. validate the committed budget snapshot as approved;
3. compute the canonical snapshot/config authorization hash, require exact
   `APPROVE_LIVE_SWEEP_SHA256`, and parse the human cap to micro-USD;
4. calculate the 1,713-call worst-case estimate;
5. reject if the estimate exceeds the human cap;
6. validate `ALLOW_LIVE_LLM=1`;
7. create the attempt budget;
8. only then call `fetchFactory`, then `adapterFactory`, then `runSweep`.

No constructor, API-key-dependent object, fetch wrapper, output directory, or
provider request may be created in steps 1–6. Return the exact authorization
hash, parsed human cap, worst-case estimate, request count, per-call ceiling,
and budget state alongside the sweep result so the evidence bundle can
reconcile preflight and actual attempts. The test-only factories are dependency injection; the CLI supplies
`() => fetch` and a factory that creates `LiveAnthropicAdapter` from the
committed snapshot and budget guard.

`runSweep` must:

1. load and validate `sweep-v1.json` plus v2 fixtures;
2. accept the already-created adapter only after `startLiveSweep` completed its
   conservative count and cost checks;
3. run the target across all 30 held-out fixtures first and call the same
   `assessBenchmark({ threshold, target: targetScore })` used by each cell;
4. if that standalone `benchmark.valid` is false, write an invalid-target result
   and make zero distillation calls;
5. otherwise run all 12 `(N, replicate)` cells, passing `pairOrderSeed` only to
   local ordering and `distillationSeed` only to the adapter's distill request;
6. retain every successful and failed provider attempt in the returned `samples` array;
7. reconcile `samples.length`, adapter attempt count, and budget
   `attemptedCalls`, failing closed on any mismatch;
8. identify N=100 as computationally complete only after all three N=100 cells
   finish;
9. set `publishableHighN: true` only when the standalone target benchmark is
   valid, every N=100 cell's own `benchmark.valid` is true, and all three N=100
   cells have distinct requested seeds, matching applied seeds, and adapter
   status `honored` on a live adapter.

The target preflight return shape is exact:

```js
{
  experimentFamily,
  benchmark,
  targetScore,
  cells: [],
  samples,
  highNComplete: false,
}
```

Implement and export the high-N gate as a pure function so report rendering,
bundle generation, and tests cannot disagree:

```js
export function classifyHighNSeedValidity({ cells, adapterMode, standaloneBenchmark }) {
  const highN = cells.filter((cell) => cell.n === 100 && cell.status === 'complete');
  if (standaloneBenchmark?.valid !== true) {
    return { valid: false, reason: 'STANDALONE_TARGET_INVALID' };
  }
  if (highN.length !== 3) {
    return { valid: false, reason: 'HIGH_N_INCOMPLETE' };
  }
  if (highN.some((cell) => cell.benchmark?.valid !== true)) {
    return { valid: false, reason: 'HIGH_N_TARGET_INVALID' };
  }
  if (adapterMode !== 'live') {
    return { valid: false, reason: 'HIGH_N_NOT_LIVE' };
  }
  const requested = highN.map((cell) => cell.requestedDistillationSeed);
  const independentlyHonored = new Set(requested).size === 3
    && highN.every((cell) =>
      cell.distillationSeedStatus === 'honored'
      && cell.appliedDistillationSeed === cell.requestedDistillationSeed);
  return independentlyHonored
    ? { valid: true, reason: null }
    : { valid: false, reason: 'DISTILLATION_SEEDS_UNCONTROLLED' };
}
```

Mock cells use `synthetic_honored`; that proves orchestration determinism but
can never satisfy this publication gate.

Call this function exactly once after all cells finish and use its result for
`publishableHighN`, report suppression, and bundle metadata. A passing
standalone target never substitutes for a failed target inside one N=100 cell;
the regression above must keep all aggregate clone/economics conclusions
suppressed when any one cell is invalid.

When valid, each cell is:

```js
{
  n,
  replicateId,
  pairOrderSeed,
  requestedDistillationSeed,
  appliedDistillationSeed,
  distillationSeedStatus,
  distillationSeedMechanism,
  status: 'complete',
  benchmark: result.report.benchmark,
  targetAbsoluteScore: result.report.fidelity.target.absoluteScore,
  cloneAbsoluteScore: result.report.fidelity.clone.absoluteScore,
  cloneCriticalGatePass: result.report.fidelity.clone.criticalGatePass,
  providerCostUsd: result.report.usage.normalized.providerCostUsd,
}
```

If any selected provider reports `unsupported`, retain each cell and attempt as
`stochastic_uncontrolled` evidence, set
`publishableHighN: false`, set suppression reason
`DISTILLATION_SEEDS_UNCONTROLLED`, and render no aggregate clone fidelity,
defensibility, moat, break-even, or economics conclusion. Never call these
“independent seeded replicates.” A provider-support upgrade needs a new adapter
test proving the exact requested seed is sent and reported as applied.

Apply the same aggregate-conclusion suppression when the gate returns
`STANDALONE_TARGET_INVALID` or `HIGH_N_TARGET_INVALID`. Preserve the invalid
target observations and verdicts in the bundle; never average the two valid
N=100 cells around the invalid one or fall back to the standalone score.

- [ ] **Step 11: Add a CLI that defaults to preflight/mock**

Create `sweep.mjs` so `node sweep.mjs --preflight` validates config, fixture
counts, the 1,713-call formula, and the budget-snapshot shape without provider
construction. With the committed `not_approved` snapshot it prints
`live budget: not approved` and exits zero because offline readiness is intact;
it must not invent a dollar estimate or authorization hash from incomplete
pricing. With an approved snapshot, preflight prints the exact canonical line
`` `live authorization: ${liveAuthorizationHash({ config, snapshot })}` `` and
the conservative estimate, but still constructs no provider object and makes
no network request. `--mock` runs the offline sweep. `--live` loads the same
committed config and snapshot and delegates every gate, in order, to
`startLiveSweep`; the supplied hash must equal the line from the unchanged
approved files. Any missing mode flag exits with usage and no output directory
or network action.

Update `package.json` scripts:

```json
{
  "scripts": {
    "test": "node --test tests/*.test.mjs && npm run e2e",
    "fixtures:check": "node scripts/generate-fixtures.mjs --check",
    "sweep:preflight": "node sweep.mjs --preflight",
    "sweep:mock": "MOCK_LLM=1 ALLOW_LIVE_LLM=0 node sweep.mjs --mock",
    "sweep:live": "MOCK_LLM=0 node sweep.mjs --live"
  }
}
```

Keep the existing `e2e`, `run`, and `real` scripts.

- [ ] **Step 12: Run the sweep tests without network access**

Run:

```bash
cd spikes/clone-economics
node --test tests/sweep.test.mjs
node --test tests/authorization.test.mjs
node --test --test-name-pattern='budget|under-cap|attempted call|unknown cost|token cap|human cap' tests/budget.test.mjs
npm run sweep:preflight
npm run sweep:mock
```

Expected: all tests PASS; preflight reports 100 train, 30 heldout, 12 cells,
1,713 conservative live requests, and `live budget: not approved`; the
under-cap test reports zero adapter and fetch constructions; mock completes
with `networkAttempts=0` or the existing network-forbidden stub untouched. No
live environment variable is set.

- [ ] **Step 13: Commit sweep orchestration**

```bash
git add spikes/clone-economics/src/authorization.mjs spikes/clone-economics/src/budget.mjs spikes/clone-economics/src/sweep.mjs spikes/clone-economics/sweep.mjs spikes/clone-economics/tests/authorization.test.mjs spikes/clone-economics/tests/budget.test.mjs spikes/clone-economics/tests/sweep.test.mjs spikes/clone-economics/tests/fixtures/live-contract.mjs spikes/clone-economics/src/experiment.mjs spikes/clone-economics/src/adapters.mjs spikes/clone-economics/package.json spikes/clone-economics/package-lock.json
git commit -m "feat: add gated clone high-N sweep"
```

### Task 5: Build sanitized, hash-verifiable evidence bundles

**Files:**
- Create: `spikes/clone-economics/src/evidence.mjs`
- Create: `spikes/clone-economics/scripts/verify-bundle.mjs`
- Create: `spikes/clone-economics/tests/evidence.test.mjs`

- [ ] **Step 1: Write bundle tests**

Create `tests/evidence.test.mjs` with a temporary five-file bundle:

```js
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { recomputeSummary, verifyEvidenceBundle, writeEvidenceBundle } from '../src/evidence.mjs';

const samples = [
  { sampleId: 'run:target-heldout:a', phase: 'evaluation', profile: 'target', caseId: 'a', success: true, latencyMs: 10, inputTokens: 3, outputTokens: 2, providerCostUsd: 0.01, score: 0.9, criticalGatePass: true },
  { sampleId: 'run:clone-heldout:a', phase: 'evaluation', profile: 'clone', caseId: 'a', success: true, latencyMs: 30, inputTokens: 3, outputTokens: 2, providerCostUsd: 0.02, score: 0.7, criticalGatePass: false },
  { sampleId: 'run:distill:1', phase: 'distillation', profile: 'clone', caseId: null, success: false, latencyMs: 5, inputTokens: null, outputTokens: null, providerCostUsd: null, score: null, criticalGatePass: null, failureClass: 'ProviderError' },
];

test('bundle hashes and summary recompute from normalized samples', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-evidence-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  writeEvidenceBundle({
    outputDir: dir,
    manifest: { experimentId: 'fixture-run', evidenceLabel: 'SYNTHETIC', command: 'npm run sweep:mock' },
    samples,
    interpretation: 'Synthetic fixture bundle.',
    reproduction: 'node scripts/verify-bundle.mjs evidence/fixture-run',
  });
  const verified = verifyEvidenceBundle(dir);
  assert.equal(verified.valid, true);
  assert.equal(verified.summary.attemptedSamples, 3);
  assert.equal(verified.summary.failedSamples, 1);
  assert.equal(verified.summary.providerCostUsd, null);
  assert.equal(verified.summary.latencyMs.p50, 10);
  assert.equal(verified.summary.latencyMs.p95, 30);
});

test('redaction rejects private payload fields', () => {
  assert.throws(() => recomputeSummary([{ ...samples[0], prompt: 'private' }]), /forbidden sample field: prompt/);
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd spikes/clone-economics && node --test tests/evidence.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/evidence.mjs`.

- [ ] **Step 3: Define the exact normalized sample schema**

In `src/evidence.mjs`, accept only these keys:

```js
const SAMPLE_KEYS = new Set([
  'sampleId', 'phase', 'profile', 'caseId', 'n', 'replicateId',
  'pairOrderSeed', 'requestedDistillationSeed', 'appliedDistillationSeed',
  'distillationSeedStatus', 'distillationSeedMechanism',
  'success', 'latencyMs', 'inputTokens', 'outputTokens',
  'providerCostMicroUsd', 'providerCostUsd',
  'acquisitionCostUsd', 'acquisitionEvidence', 'score', 'criticalGatePass',
  'failureClass', 'providerRequestId',
]);
const FORBIDDEN_KEYS = new Set([
  'prompt', 'payload', 'output', 'rawResponse', 'apiKey', 'authorization',
  'headers', 'skillText', 'referenceText',
]);
```

Reject unknown or forbidden fields. Require a stable `sampleId`, finite non-negative known numeric values, and `null` for unknown usage/cost. `providerCostUsd: null` propagates to the aggregate cost; it never becomes zero.
For every live row with known usage, require `providerCostMicroUsd` to be a
base-10 non-negative integer string and recompute its value from observed
tokens plus the hash-verified pricing snapshot. A known overrun row therefore
remains exactly auditable even when its display-oriented `providerCostUsd`
value is rounded; unknown-cost rows require both cost fields to be null.

- [ ] **Step 4: Implement deterministic summary recomputation**

Use nearest-rank percentiles over successful finite latencies:

```js
const percentile = (values, p) => {
  if (values.length === 0) return null;
  const ordered = [...values].sort((a, b) => a - b);
  return ordered[Math.max(0, Math.ceil(p * ordered.length) - 1)];
};
```

Return:

```js
{
  attemptedSamples: samples.length,
  successfulSamples: samples.filter((x) => x.success).length,
  failedSamples: samples.filter((x) => !x.success).length,
  providerCostUsd: samples.every((x) => x.providerCostUsd !== null)
    ? rounded(sum(samples.map((x) => x.providerCostUsd)))
    : null,
  acquisition: {
    modeledUsd: rounded(sum(samples.map((x) => x.acquisitionCostUsd ?? 0))),
    evidence: [...new Set(samples.map((x) => x.acquisitionEvidence).filter(Boolean))].sort(),
  },
  latencyMs: { p50: percentile(latencies, 0.5), p95: percentile(latencies, 0.95) },
  fidelity: summarizeScoresByProfile(samples),
}
```

- [ ] **Step 5: Write files in hash-safe order**

`writeEvidenceBundle` writes, in order:

1. `samples.jsonl` — one stable-key JSON object per line;
2. `summary.json` — only `recomputeSummary(samples)`;
3. `report.md` — generated from summary and interpretation;
4. `README.md` — reproduction command, redaction statement, limitations;
5. `manifest.json` — written last, with SHA-256 for the previous four files.

The manifest schema is:

```js
{
  schemaVersion: 1,
  experimentId,
  recordedAtUtc,
  gitCommit,
  command,
  runtime: { node: process.version, platform: process.platform, arch: process.arch },
  modelProvider: manifest.modelProvider ?? null,
  model: manifest.model ?? null,
  evidenceLabel,
  sourceEvidence: manifest.sourceEvidence ?? null,
  liveBudget: manifest.liveBudget ?? null,
  configuration: sanitizedConfiguration,
  files: {
    'samples.jsonl': { sha256, bytes },
    'summary.json': { sha256, bytes },
    'report.md': { sha256, bytes },
    'README.md': { sha256, bytes },
  },
}
```

`recordedAtUtc` is an ISO-8601 instant for a newly executed run. It may be
`null` only for a hash-locked historical import whose source recorded no
timestamp; that bundle must instead carry a date-only label and
`sourceTimestamp: "not-recorded"` in sanitized configuration. Never invent
midnight precision.

For a live candidate, `liveBudget` is required and contains only the snapshot
path and SHA-256, exact `authorizationHash`, human cap, conservative estimate,
worst-case per-call amount, attempted-call count, known accrued cost, retained
reservation, and lock state. The verifier recomputes the authorization hash
from `configuration.sweepConfig` and the bytes parsed from the hash-verified
committed snapshot and requires an exact match.
`configuration.sweepConfig` must be the complete validated
`fixtures/sweep-v1.json` object—not a projection—because omitted publication
flags or seed fields would change what the human authorized. `sourceEvidence`,
when present for an imported
historical bundle, contains only `{ kind, sha256, bytes }`; paths are forbidden.
Serialize every micro-USD bigint as a base-10 string. The verifier hashes the
committed snapshot and requires it to match `snapshotSha256`; it also requires
the manifest attempted-call count to equal `samples.length`.

Do not read `.env`; caller-supplied configuration is allow-listed to model name,
N values, replicate IDs, pair-order seeds, requested/applied distillation-seed
evidence, token caps, the committed pricing snapshot, evidence labels, and
acquisition treatment.

- [ ] **Step 6: Implement strict verification**

`verifyEvidenceBundle(dir)` must hash all four files, parse JSONL, recompute the summary byte-for-byte, and fail if:

- a hash or byte count differs;
- a required file is absent;
- sample IDs repeat;
- a sample contains a forbidden field;
- `summary.json` differs from recomputation;
- `report.md` contains a numeric p50, p95, cost, or sample count that differs from `summary.json`.

Create `scripts/verify-bundle.mjs` that prints
`` `PASS — ${manifest.experimentId} recomputes from ${samples.length} normalized samples.` ``
and exits 0, or prints the exact verifier error and exits 1.

- [ ] **Step 7: Run evidence tests**

Run: `cd spikes/clone-economics && node --test tests/evidence.test.mjs`

Expected: PASS, 2 tests passed.

- [ ] **Step 8: Connect sweep output to the bundle writer**

After `runSweep` completes or invalidates the target, normalize all adapter
attempts and call `writeEvidenceBundle`. For live runs, add the committed budget
snapshot hash and final attempt-budget state to the manifest. Raw provider
responses and distilled Skill text remain under ignored `runs/`; the committed
candidate directory contains only allow-listed normalized rows.

When a provider call throws, write its failed row before rethrowing or advancing to the next configured cell. Set report limitations to include incomplete costs whenever any attempted row has `providerCostUsd: null`.

- [ ] **Step 9: Commit the evidence kernel**

```bash
git add spikes/clone-economics/src/evidence.mjs spikes/clone-economics/scripts/verify-bundle.mjs spikes/clone-economics/tests/evidence.test.mjs spikes/clone-economics/src/sweep.mjs spikes/clone-economics/sweep.mjs
git commit -m "feat: write reproducible clone evidence bundles"
```

### Task 6: Import the 2026-07-12 run as invalid historical evidence

**Files:**
- Create: `spikes/clone-economics/scripts/import-legacy-run.mjs`
- Create: `spikes/clone-economics/tests/import-legacy-run.test.mjs`
- Create: `spikes/clone-economics/evidence/2026-07-12-n6-invalid/manifest.json`
- Create: `spikes/clone-economics/evidence/2026-07-12-n6-invalid/samples.jsonl`
- Create: `spikes/clone-economics/evidence/2026-07-12-n6-invalid/summary.json`
- Create: `spikes/clone-economics/evidence/2026-07-12-n6-invalid/report.md`
- Create: `spikes/clone-economics/evidence/2026-07-12-n6-invalid/README.md`
- Modify: `spikes/clone-economics/README.md:89-121`
- Modify: `spikes/clone-economics/.gitignore`

- [ ] **Step 1: Write a hash-locked legacy importer and offline tests**

`scripts/import-legacy-run.mjs` must accept only named arguments
`--input`, `--expected-sha256`, and `--output`. Export these immutable source
facts:

```js
export const LEGACY_SOURCE_SHA256 =
  '0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212';
export const LEGACY_SOURCE_BYTES = 76_631;
```

Before parsing JSON or creating the output directory, require the CLI's
`--expected-sha256` to equal `LEGACY_SOURCE_SHA256`, read the input as bytes,
require the exact byte count, hash those bytes with SHA-256, and require an
exact digest match. Do not infer or search for `runs/live/report.json`; the
input path must be explicit. Then parse the verified bytes and assert these
historical facts:

```js
assert.equal(source.schemaVersion, 1);
assert.equal(source.mode, 'live');
assert.equal(source.dataset.N, 6);
assert.equal(source.fidelity.target.absoluteScore, 0.4);
assert.equal(source.fidelity.target.criticalGatePass, false);
assert.equal(source.economics.acquisitionModeledUsd, 1.5);
```

Join each `source.usage.raw` record to the corresponding per-case fidelity result. Map `target-heldout`, `clone-heldout`, and `bad-clone-heldout` to profiles; keep acquisition and distillation rows without scores. The importer must never copy prompt payloads, target bytes, reference bytes, provider response text, or `distilled-raw.txt`.

Export the pure `normalizeLegacyReport(source)` helper for tests. In
`tests/import-legacy-run.test.mjs`, cover the 29-row normalization with a
synthetic shape, all six historical assertions, forbidden-field absence, and
subprocess failure for (a) the wrong declared digest and (b) changed source
bytes. Both subprocess failures must occur before the requested output path is
created. The production CLI must also reject an output directory that already
exists rather than overwrite evidence.

Call `writeEvidenceBundle` with:

```js
{
  experimentId: '2026-07-12-n6-invalid',
  recordedAtUtc: null,
  gitCommit: 'historical-source-not-recorded',
  command: 'historical live command not retained exactly',
  modelProvider: 'Anthropic',
  model: source.usage.raw[0]?.model ?? null,
  evidenceLabel: 'HISTORICAL MIXED — INVALID BENCHMARK; acquisition MODELED',
  sourceEvidence: {
    kind: 'legacy-report-json',
    sha256: LEGACY_SOURCE_SHA256,
    bytes: LEGACY_SOURCE_BYTES,
  },
  configuration: {
    historicalRunDate: '2026-07-12',
    sourceTimestamp: 'not-recorded',
    nValues: [6],
    pairOrderSeeds: ['not-recorded'],
    requestedDistillationSeeds: ['not-recorded'],
    appliedDistillationSeeds: ['not-recorded'],
    acquisitionTreatment: 'modeled',
    attemptCoverage: 'successful fifth run only; four setup attempts have no normalized records',
  },
}
```

- [ ] **Step 2: Run importer tests and commit the importer kernel**

Run:

```bash
cd spikes/clone-economics
node --test tests/import-legacy-run.test.mjs
cd ../..
git add spikes/clone-economics/scripts/import-legacy-run.mjs spikes/clone-economics/tests/import-legacy-run.test.mjs
git commit -m "feat: add hash-locked legacy evidence importer"
```

Expected: tests PASS, both wrong-input cases leave no output directory, and the
commit contains no raw report or generated evidence.

- [ ] **Step 3: Generate from an explicit private copy in a clean worktree**

The ignored report exists only in the primary checkout, but implementation may
be running in a linked worktree such as `.worktrees/adversarial-remediation`.
Capture that active implementation root before creating the detached audit
worktree. Treat the primary checkout's absolute report path as read-only source
material: copy its exact bytes to a mode-0600 temporary file, verify the copy
independently, and pass only the temporary copy to the committed importer.
Never `cd` to, generate into, stage from, or commit from the primary checkout:

```bash
set -euo pipefail
implementation_root=$(git rev-parse --show-toplevel)
readonly implementation_root
readonly primary_checkout='/Users/antonyzaki/Documents/Repo/tokenized-assets'
readonly legacy_source="$primary_checkout/spikes/clone-economics/runs/live/report.json"

test "$(git -C "$implementation_root" rev-parse --show-toplevel)" = "$implementation_root"
git -C "$primary_checkout" worktree list --porcelain \
  | sed -n 's/^worktree //p' \
  | rg -Fx -- "$implementation_root"
git -C "$primary_checkout" check-ignore -q -- spikes/clone-economics/runs/live/report.json
test -f "$legacy_source"
test ! -L "$legacy_source"
test -f "$implementation_root/spikes/clone-economics/scripts/import-legacy-run.mjs"

audit_base=$(mktemp -d /private/tmp/tokenized-assets-legacy-audit.XXXXXX)
audit_worktree="$audit_base/worktree"
legacy_copy=$(mktemp /private/tmp/clone-economics-legacy.XXXXXX)
evidence_destination="$implementation_root/spikes/clone-economics/evidence/2026-07-12-n6-invalid"
case "$audit_base" in /private/tmp/tokenized-assets-legacy-audit.*) ;; *) exit 1 ;; esac
case "$audit_worktree" in "$audit_base"/worktree) ;; *) exit 1 ;; esac
case "$legacy_copy" in /private/tmp/clone-economics-legacy.*) ;; *) exit 1 ;; esac
case "$evidence_destination" in "$implementation_root"/*) ;; *) exit 1 ;; esac
test ! -e "$evidence_destination"

git -C "$implementation_root" worktree add --detach "$audit_worktree" HEAD
install -m 600 "$legacy_source" "$legacy_copy"
test "$(stat -f '%Lp' "$legacy_copy")" = 600
test "$(stat -f '%z' "$legacy_copy")" = 76631
test "$(shasum -a 256 "$legacy_copy" | cut -d ' ' -f 1)" = 0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212
cd "$audit_worktree/spikes/clone-economics"
env -u ANTHROPIC_API_KEY MOCK_LLM=1 ALLOW_LIVE_LLM=0 node scripts/import-legacy-run.mjs \
  --input "$legacy_copy" \
  --expected-sha256 0554779988164651bfe6b037c8b16054e009ee6bac76e61c90af331ac6e85212 \
  --output "$audit_base/evidence"
node scripts/verify-bundle.mjs "$audit_base/evidence"
```

Expected: the clean-worktree importer writes exactly five sanitized files,
reports 29 normalized samples, makes no provider call or x402 settlement, and
the manifest records the digest and byte count but no source path.

Copy only the five verified public files to the captured implementation
worktree, then return there before removing the detached audit worktree. The
primary checkout remains a read-only source throughout:

```bash
case "$evidence_destination" in "$implementation_root"/*) ;; *) exit 1 ;; esac
test ! -e "$evidence_destination"
install -d "$evidence_destination"
for name in manifest.json samples.jsonl summary.json report.md README.md; do
  test -f "$audit_base/evidence/$name"
  install -m 644 "$audit_base/evidence/$name" "$evidence_destination/$name"
done
cd "$implementation_root"
test "$(git rev-parse --show-toplevel)" = "$implementation_root"
git -C "$implementation_root" worktree remove "$audit_worktree"
case "$audit_base" in
  /private/tmp/tokenized-assets-legacy-audit.*) rm -rf -- "$audit_base" ;;
  *) echo 'Refusing unexpected temporary cleanup path' >&2; exit 1 ;;
esac
case "$legacy_copy" in
  /private/tmp/clone-economics-legacy.*) rm -f -- "$legacy_copy" ;;
  *) echo 'Refusing unexpected source-copy cleanup path' >&2; exit 1 ;;
esac
```

The guarded cleanup is required because the temporary source contains raw
provider output. If any earlier command fails, do not blindly rerun: inspect
the exact printed temporary paths, verify their prefixes, remove the worktree
with `git worktree remove`, then delete only those temporary paths.

- [ ] **Step 4: Mark evidence bundles as trackable while raw runs stay ignored**

Keep `runs/` in `.gitignore` and add explicit comments:

```gitignore
# Raw provider artifacts can contain private output and always remain local.
runs/

# Sanitized evidence bundles under evidence/ are intentionally tracked.
```

Do not add an `evidence/` ignore rule.

- [ ] **Step 5: Verify the bundle from its public seam**

Run: `cd spikes/clone-economics && node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid`

Expected: `PASS — 2026-07-12-n6-invalid recomputes from 29 normalized samples.`

- [ ] **Step 6: Scan the bundle for private fields and paths**

Run:

```bash
rg -n -i 'api[_-]?key|authorization|x-api-key|targetSkill|referenceText|distilled-raw|"prompt"|"payload"|"output"|/Users/|/private/tmp|runs/live' evidence/2026-07-12-n6-invalid
```

Expected: no matches.

- [ ] **Step 7: Replace the README conclusion with the invalid historical verdict**

Replace the existing measured-results section with:

````markdown
## Historical live run — invalid benchmark (2026-07-12)

The sanitized normalized evidence is committed at
`evidence/2026-07-12-n6-invalid/`. Provider execution and returned usage were
measured; the $1.50 acquisition component was modeled and no x402 acquisition
payment settled.

The target scored 0.400 and failed its own critical gates. Therefore the run's
verdict is `INVALID_BENCHMARK_TARGET_FAILED`: clone quality, fidelity defense,
moat, retention, and break-even conclusions are suppressed. Four earlier setup
attempts were described historically but did not retain normalized attempt
records, so total attack cost is also incomplete.

Verify the retained bundle offline:

```bash
node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid
```

No high-N conclusion exists. Only a valid target plus the preregistered
N=6/25/50/100 sweep, 30 held-out fixtures, and three live-adapter-confirmed,
independent distillation seeds at N=100 can produce a publishable high-N
result. Pair-order seeds alone do not establish independent model sampling.
````

- [ ] **Step 8: Commit the historical bundle**

```bash
git add spikes/clone-economics/evidence/2026-07-12-n6-invalid spikes/clone-economics/README.md spikes/clone-economics/.gitignore
git commit -m "docs: preserve invalid clone run as reproducible evidence"
```

### Task 7: Document the safe operator flow and full offline suite

**Files:**
- Modify: `spikes/clone-economics/RUNBOOK.md`
- Modify: `spikes/clone-economics/.env.example`
- Modify: `spikes/clone-economics/package.json`

- [ ] **Step 1: Replace the old N≤6 runbook sweep**

Document this sequence:

````markdown
## High-N sweep: preflight first

The preregistration is `fixtures/sweep-v1.json`: N=6,25,50,100; 30 held-out
fixtures; pair-order seeds 1701, 1702, and 1703; and distinct requested
distillation seeds 2701, 2702, and 2703. Pair-order seeds control only local
acquisition ordering. A high-N result is publishable only if a live adapter
reports all three requested distillation seeds as independently applied. The
current Anthropic adapter reports seed support as `unsupported`, so it may
produce explicitly uncontrolled evidence but cannot produce clone-fidelity,
defensibility, moat, break-even, or economics conclusions.

```bash
npm run fixtures:check
npm run sweep:preflight
npm run sweep:mock
```

These commands use no key, network, x402 payment, or provider spend.

## Human-authorized live gate

The committed `fixtures/live-budget-v1.json` intentionally starts with
`approvalStatus: "not_approved"` and null model, pricing, and token caps. Before
a live run, a human must verify the provider's current official pricing,
replace every null with the selected model, decimal-string prices, timestamped
HTTPS source, and token caps, set `approvalStatus` to `approved`, review the
1,713-call conservative estimate from `npm run sweep:preflight`, and commit the
snapshot and unchanged `fixtures/sweep-v1.json`. The sweep ignores
environment-based model/pricing/token-cap values; the committed files are its
only execution contract.

Run `npm run sweep:preflight` again from that exact commit. It prints a
`live authorization: sha256:...` digest over the complete sweep config and
approved budget snapshot. After reviewing the printed contract, the human
explicitly approves a maximum at or above the conservative estimate and copies
that exact digest:

```bash
export APPROVE_LIVE_SWEEP_SHA256='sha256:<exact digest printed by preflight>'
export MAX_SWEEP_COST_USD="$HUMAN_APPROVED_MAX_SWEEP_COST_USD"
export ALLOW_LIVE_LLM=1
```

Any change to N values, either seed family, model, prices, token caps, or the
approval snapshot changes the digest and invalidates the old authorization.

Then, and only then, the operator may run:

```bash
npm run sweep:live
```

The command writes raw private output only under ignored `runs/` and writes a
sanitized candidate bundle to a new dated directory selected by its generated
experiment identifier under `evidence/`. Never
overwrite a historical bundle. Review and verify the candidate before staging;
do not publish automatically. An `unsupported` distillation-seed result remains
useful only as `stochastic_uncontrolled` evidence and must retain all conclusion
suppressions.
````

- [ ] **Step 2: Add the approval variables to `.env.example`**

Append:

```dotenv
# High-N live sweep: set only after a human approves current pricing and spend.
# Model, pricing, and token caps come from committed fixtures/live-budget-v1.json.
APPROVE_LIVE_SWEEP_SHA256=
MAX_SWEEP_COST_USD=
ALLOW_LIVE_LLM=0
```

- [ ] **Step 3: Run the complete offline suite**

Run:

```bash
cd spikes/clone-economics
npm test
npm run fixtures:check
npm run sweep:preflight
npm run sweep:mock
node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid
```

Expected: every unit test and legacy e2e check passes; fixture check reports no
drift; preflight reports 100/30/12, 1,713 conservative requests, and the
committed budget as not approved; mock sweep makes zero network calls; the
historical bundle recomputes.

- [ ] **Step 4: Prove live execution still fails closed by default**

Run:

```bash
cd spikes/clone-economics
env -u APPROVE_LIVE_SWEEP_SHA256 -u MAX_SWEEP_COST_USD -u ANTHROPIC_API_KEY MOCK_LLM=0 ALLOW_LIVE_LLM=0 npm run sweep:live
```

Expected: nonzero exit at the first gate containing `Live budget snapshot must
be approved`; no fetch/adapter factory runs and no evidence directory is
created. The synthetic `authorization.test.mjs` separately proves that an
approved snapshot with a missing, malformed, family-token, or stale
`APPROVE_LIVE_SWEEP_SHA256` also fails before provider construction.

- [ ] **Step 5: Confirm no secret or raw provider artifact is tracked**

Run:

```bash
git ls-files | rg '(^|/)\.env$|runs/|distilled-raw|raw-provider'
```

Expected: no output.

- [ ] **Step 6: Commit operator documentation**

```bash
git add spikes/clone-economics/RUNBOOK.md spikes/clone-economics/.env.example spikes/clone-economics/package.json spikes/clone-economics/package-lock.json
git commit -m "docs: gate clone high-N provider spend"
```

- [ ] **Step 7: Report the remaining human gate exactly**

```text
The offline clone benchmark, fixture, sweep, budget, and evidence paths are
ready. No high-N provider run was executed. Publication remains blocked until a
human commits a current approved pricing/token-cap snapshot, reviews and copies
the exact config-plus-snapshot authorization hash, approves a cap at or above
the conservative estimate, and runs the live sweep. The target must pass its
own gate; all three N=100 cells must complete with distinct requested seeds
confirmed as applied by a live adapter; and the sanitized bundle must verify
from a clean checkout. The current Anthropic adapter reports distillation seeds
as unsupported, so its run cannot clear the publication gate.
```

# Claims Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop unsupported launch claims, preserve the unreproducible historical measurements honestly, and make future claim regressions fail an offline check.

**Architecture:** A dependency-free Node audit treats tracked launch copy as a publication boundary and rejects known unsupported phrasings. Historical clone and x402 results remain in place with explicit quarantine metadata; marketing drafts point to evidence status instead of turning modeled, invalid, or unreproducible results into measured claims. This plan changes tracked documentation and tests only: it does not post content, rerun a paid endpoint, spend provider funds, or edit `CONTEXT.md`, `docs/PRD.md`, or `docs/adr/`.

**Tech Stack:** Node.js 20+ (`node:test`, `node:fs`), Markdown, JSON

---

## File map

- Create `scripts/marketing-claims.mjs`: reusable claim-policy audit and CLI.
- Create `scripts/tests/marketing-claims.test.mjs`: offline regression tests for banned claims, quarantine notices, and tombstone shape.
- Create `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`: immutable historical tombstone; it deliberately contains no fabricated samples.
- Modify `spikes/pi-wielder/README.md`: quarantine the unreproducible distribution and point to the tombstone.
- Modify `docs/marketing/linkedin.md`: block the clone post and correct modeled cost, target validity, split, and extraction language.
- Modify `docs/marketing/x.md`: block clone copy; correct x402 roles, retry credential, reconciliation level, dates, and extraction language.
- Modify `docs/marketing/hn-and-demo.md`: remove unsupported clone and latency claims from the HN draft and demo script.
- Modify `docs/marketing/2026-07-13-campaign-plan.md`: replace stale scheduled publication actions with evidence gates while retaining the historical calendar.
- Modify `docs/handoffs/2026-07-15-launch-week-handoff.md`: mark the old n=48 distribution as historical and non-publishable; do not rewrite what happened.

### Human-only boundary

The implementation worker may edit and test drafts, but must not publish a post, update an already-published social post, invoke a live endpoint, authorize an LLM run, fund a wallet, or deploy a site. Corrections to already-published content are recommendations for the human operator.

### Task 1: Add a failing publication-boundary audit

**Files:**
- Create: `scripts/marketing-claims.mjs`
- Create: `scripts/tests/marketing-claims.test.mjs`

- [ ] **Step 1: Write the failing audit test**

Create `scripts/tests/marketing-claims.test.mjs` with the tracked publication surfaces and explicit rule IDs:

```js
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { auditFiles, readHistoricalTombstone } from '../marketing-claims.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const publicationFiles = [
  'docs/marketing/linkedin.md',
  'docs/marketing/x.md',
  'docs/marketing/hn-and-demo.md',
  'docs/marketing/2026-07-13-campaign-plan.md',
];

test('tracked publication drafts contain no quarantined claims', () => {
  assert.deepEqual(auditFiles(repoRoot, publicationFiles), []);
});

test('the pi overhead tombstone is historical, unreproducible, and sample-free', () => {
  const manifest = readHistoricalTombstone(repoRoot);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.experimentId, '2026-07-15-overhead');
  assert.equal(manifest.evidenceStatus, 'historical_unreproducible');
  assert.equal(manifest.publication.allowed, false);
  assert.equal(manifest.rawEvidence.normalizedSamplesCommitted, false);
  assert.equal(manifest.rawEvidence.recomputableFromCleanCheckout, false);
  assert.equal('samples' in manifest, false);
  assert.equal(
    fs.existsSync(path.join(repoRoot, 'spikes/pi-wielder/evidence/2026-07-15-overhead/samples.jsonl')),
    false,
  );
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `node --test scripts/tests/marketing-claims.test.mjs`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `scripts/marketing-claims.mjs`.

- [ ] **Step 3: Implement the minimal audit API and CLI**

Create `scripts/marketing-claims.mjs`:

```js
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLAIM_RULES = [
  { id: 'clone-paid-158', pattern: /(?:paid \$1\.58|\$1\.58 (?:bought|total)|six paid runs)/i },
  { id: 'invalid-clone-conclusion', pattern: /clone failed[\s\S]{0,80}(?:six|6)[\s\S]{0,40}fidelity|clone failed all (?:six|6)/i },
  { id: 'latency-unreproducible', pattern: /p50\s+731\s*ms|p95\s+1206\s*ms|n=48 settled calls/i },
  { id: 'absolute-extraction', pattern: /never (?:get|returns?|leaves|crosses)[\s\S]{0,60}\bskill\b|never (?:the )?skill|\bskill\b[\s\S]{0,40}never (?:leaves|crosses)/i },
  { id: 'txhash-as-retry-credential', pattern: /settlement txHash IS the credential|retries? .*carrying (?:it|the txHash)/i },
  { id: 'wielder-is-server', pattern: /server side.*proxy we call the Wielder|Wielder: enforce 402/i },
  { id: 'split-reconciled-onchain', pattern: /creator .*treasury.*reconciled on-chain|split.*reconciled on-chain/i },
];

export function auditText(file, text) {
  return CLAIM_RULES.flatMap(({ id, pattern }) => {
    const match = text.match(pattern);
    if (!match) return [];
    const line = text.slice(0, match.index).split('\n').length;
    return [{ file, line, rule: id, excerpt: match[0] }];
  });
}

export function auditFiles(repoRoot, relativePaths) {
  return relativePaths.flatMap((file) =>
    auditText(file, fs.readFileSync(path.join(repoRoot, file), 'utf8')),
  );
}

export function readHistoricalTombstone(repoRoot) {
  const file = path.join(
    repoRoot,
    'spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json',
  );
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

const invokedAsScript = process.argv[1]
  && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedAsScript) {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = [
    'docs/marketing/linkedin.md',
    'docs/marketing/x.md',
    'docs/marketing/hn-and-demo.md',
    'docs/marketing/2026-07-13-campaign-plan.md',
  ];
  const findings = auditFiles(repoRoot, files);
  if (findings.length > 0) {
    for (const item of findings) {
      console.error(`${item.file}:${item.line} [${item.rule}] ${item.excerpt}`);
    }
    process.exitCode = 1;
  } else {
    console.log(`PASS — ${files.length} publication drafts satisfy claim quarantine.`);
  }
}
```

- [ ] **Step 4: Run the test to expose the current claim violations**

Run: `node --test scripts/tests/marketing-claims.test.mjs`

Expected: FAIL. The first test reports findings including `clone-paid-158`, `latency-unreproducible`, and `absolute-extraction`; the tombstone test fails because the manifest does not exist yet.

- [ ] **Step 5: Commit the failing guard**

```bash
git add scripts/marketing-claims.mjs scripts/tests/marketing-claims.test.mjs
git commit -m "test: guard quarantined launch claims"
```

### Task 2: Preserve the n=48 result as an immutable historical tombstone

**Files:**
- Create: `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`
- Modify: `spikes/pi-wielder/README.md:168-181`
- Modify: `docs/handoffs/2026-07-15-launch-week-handoff.md:33-37`
- Test: `scripts/tests/marketing-claims.test.mjs`

- [ ] **Step 1: Create the exact tombstone manifest**

Create `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json` with no `samples` member and no adjacent `samples.jsonl`:

```json
{
  "schemaVersion": 1,
  "experimentId": "2026-07-15-overhead",
  "observedAt": "2026-07-15",
  "evidenceStatus": "historical_unreproducible",
  "evidenceLabel": "HISTORICAL SUMMARY ONLY — normalized samples were not retained",
  "source": {
    "repositoryPath": "spikes/pi-wielder/README.md",
    "runtime": "Base Sepolia testnet",
    "funding": "testnet USDC play money",
    "providerCountReported": 2
  },
  "historicalSummary": {
    "settledCallCountReported": 48,
    "paymentOverheadP50MsReported": 731,
    "paymentOverheadP95MsReported": 1206
  },
  "rawEvidence": {
    "normalizedSamplesCommitted": false,
    "recomputableFromCleanCheckout": false,
    "reason": "The repository retained only aggregate prose; per-call normalized timing rows and a hashed evidence manifest were not committed."
  },
  "publication": {
    "allowed": false,
    "reason": "Do not use the reported p50, p95, or n=48 in launch copy. A new authorized run must write a new dated evidence directory before publication."
  },
  "replacementPolicy": {
    "overwriteThisDirectory": false,
    "newRunDirectoryPattern": "spikes/pi-wielder/evidence/YYYY-MM-DD-overhead-RUN_ID",
    "requiredFiles": ["manifest.json", "samples.jsonl", "summary.json", "report.md", "README.md"]
  }
}
```

- [ ] **Step 2: Quarantine the README summary without erasing history**

Replace the `spikes/pi-wielder/README.md` n=48 heading and distribution prose with:

```markdown
## Historical overhead summary — quarantined (2026-07-15)

The 2026-07-15 run was previously summarized as 48 settled calls across two
providers. Its per-call normalized samples and evidence hashes were not retained,
so a clean checkout cannot recompute the reported distribution. The historical
aggregate is preserved in
`evidence/2026-07-15-overhead/manifest.json` with
`evidenceStatus: historical_unreproducible`.

**Publication status:** do not cite the historical sample count, p50, or p95 in
public copy. A future authorized testnet run must use a new dated evidence
directory and must never overwrite the tombstone. No rerun is performed by this
documentation change.
```

Keep the later failure-mode narrative (settled-then-500 and settled-but-rejected) below this section, but do not imply that the Wielder session ledger captured every settled failure.

- [ ] **Step 3: Correct the handoff status line**

Replace the old n=48 bullet in `docs/handoffs/2026-07-15-launch-week-handoff.md` with:

```markdown
1. **Pi-Wielder follow-up recorded, distribution quarantined** — the historical
   2026-07-15 aggregate did not retain normalized per-call samples, so its n/p50/p95
   are not publishable. See
   `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. A replacement
   testnet run is human-authorized work and must use a new dated evidence bundle.
```

- [ ] **Step 4: Run the tombstone test**

Run: `node --test --test-name-pattern='tombstone' scripts/tests/marketing-claims.test.mjs`

Expected: PASS with one test passing and the publication-draft test skipped by the name filter.

- [ ] **Step 5: Verify no fabricated normalized evidence exists**

Run: `find spikes/pi-wielder/evidence/2026-07-15-overhead -maxdepth 1 -type f -print`

Expected: exactly `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`.

- [ ] **Step 6: Commit the tombstone**

```bash
git add spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json spikes/pi-wielder/README.md docs/handoffs/2026-07-15-launch-week-handoff.md
git commit -m "docs: quarantine unreproducible overhead summary"
```

### Task 3: Quarantine the invalid clone campaign and correct its evidence labels

**Files:**
- Modify: `docs/marketing/linkedin.md:49-84`
- Modify: `docs/marketing/x.md:60-67,99-145,233-240,275,306-310`
- Modify: `docs/marketing/hn-and-demo.md:14-18,41-44,103-113`
- Modify: `docs/marketing/2026-07-13-campaign-plan.md:67-103,119-143`

- [ ] **Step 1: Add the same publication gate above every clone draft**

Insert this block immediately below each clone-post/thread heading in `linkedin.md`, `x.md`, and `hn-and-demo.md`:

```markdown
> **PUBLICATION BLOCKED — INVALID BENCHMARK.** The 2026-07-12 target scored
> 0.400 and failed its own critical gates, so clone-quality, fidelity-defense, and
> break-even conclusions are suppressed. Acquisition was modeled at $1.50; no
> x402 acquisition payments settled. Unblock only after
> `spikes/clone-economics` produces a valid N=100 result with committed normalized
> evidence and three live-adapter-confirmed independent distillation seeds.
```

- [ ] **Step 2: Replace the LinkedIn clone post with evidence-safe draft text**

Keep its target audience, first-comment links, and posting-context sections, but replace the post body with:

```markdown
> We ran a six-example clone-economics pilot against our own hosted Skill.
>
> The provider calls were live. The acquisition price was not: six examples at
> $0.25 each contributed a modeled $1.50, no x402 acquisition payments settled,
> and the measured distillation-provider cost was about $0.03. The resulting
> $1.58 attacker-build figure is therefore a modeled lower bound that excludes
> labor and several failed setup attempts, not money paid for six Invocations.
>
> More importantly, the benchmark target failed its own acceptance gate. That
> invalidates any conclusion about whether the clone failed, whether fidelity is
> a defense, or where break-even lands. We preserved the run as historical
> evidence and blocked this post rather than promote an answer the evaluator
> could not support.
>
> The next admissible result requires at least 30 held-out fixtures and a
> preregistered N=6/25/50/100 sweep with three live-adapter-confirmed independent
> distillation seeds.
> No high-N result exists yet.
```

Change the heading to `## Post 2 — Clone-economics benchmark: publication blocked` and the posting context to `Do not publish until the gate above is satisfied and a human approves revised copy.`

- [ ] **Step 3: Replace clone conclusions throughout X and HN copy**

Use the following compact paragraph wherever the old `$1.58`, six-gate, fidelity-defense, or eight-Invocation conclusion appears:

```markdown
The historical N=6 run used a modeled $1.50 acquisition cost and measured about
$0.03 of distillation-provider cost; no acquisition payment settled. Its target
failed the benchmark, so clone quality, fidelity defense, and break-even are
unknown. Publication remains blocked pending a valid preregistered N=100 run.
```

For the HN title list, replace option 2 with:

```markdown
2. `Show HN: An invalid clone benchmark and the gate we added after it`
```

Do not retain metaphors such as “failed all gates,” “wax figure,” “photograph,” or “cost protects nothing”; each asserts a conclusion the invalid target cannot support.

- [ ] **Step 4: Turn calendar publication actions into retained historical gates**

In both calendar tables in `docs/marketing/2026-07-13-campaign-plan.md`, keep the dates and prior events, but replace every Post 2 or clone-thread action with:

```markdown
**BLOCKED:** do not publish clone-economics copy. The N=6 target failed its own
acceptance gate; the required valid N=100 evidence bundle does not exist.
```

Add immediately above the revamped calendar:

```markdown
> **2026-07-17 evidence override:** all clone-economics publication steps below
> are historical schedule entries and are blocked. A calendar date never
> overrides an evidence gate.
```

- [ ] **Step 5: Check that modeled cost is never described as paid**

Run:

```bash
rg -n -i 'paid \$1\.58|\$1\.58 bought|six paid runs|clone failed all (six|6)|break-even.*8 invocations|fidelity.*defen' docs/marketing
```

Expected: no matches.

- [ ] **Step 6: Commit clone-copy quarantine**

```bash
git add docs/marketing/linkedin.md docs/marketing/x.md docs/marketing/hn-and-demo.md docs/marketing/2026-07-13-campaign-plan.md
git commit -m "docs: quarantine invalid clone campaign claims"
```

### Task 4: Suppress unreproducible latency and correct x402 accounting claims

**Files:**
- Modify: `docs/marketing/linkedin.md:177-190`
- Modify: `docs/marketing/x.md:43-58,149-202,233-263`
- Modify: `docs/marketing/hn-and-demo.md:33-50,139-157`
- Modify: `docs/marketing/2026-07-13-campaign-plan.md:88-101`
- Test: `scripts/tests/marketing-claims.test.mjs`

- [ ] **Step 1: Replace every public n=48 distribution with the tombstone status**

Use this exact wording in LinkedIn, X, HN, and campaign-plan draft surfaces:

```markdown
The 2026-07-15 overhead distribution is historical but not reproducible from a
clean checkout because normalized per-call samples were not retained. Its sample
count, p50, and p95 are quarantined from publication; see
`spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
measurement has been run.
```

Do not preserve the three numeric values elsewhere in those four marketing files.

- [ ] **Step 2: Correct the x402 handshake in the technical thread**

Replace steps 3–5 in `docs/marketing/x.md` with:

```markdown
**3/**
Step 2 — authorization.

The Wielder-side proxy validates the 402 offer and signs an EIP-3009
transferWithAuthorization for the exact permitted amount. The retry carries that
signed `X-PAYMENT` authorization, not a transaction hash.

**4/**
Step 3 — seller-side settlement.

The Collar's x402 paywall sends the signed authorization to the facilitator. The
facilitator verifies and settles on Base Sepolia before the hosted Skill runs. A
settlement transaction hash is evidence returned after settlement; it is not the
credential carried by the initial retry.

**5/**
Step 4 — execution and receipt.

After settlement, the Collar executes the hosted Skill and returns output plus a
receipt. The artifact file is not directly returned. Model-output extraction
remains an adversarial runtime risk, so this is not a secrecy guarantee.
```

- [ ] **Step 3: Correct Wielder and Collar responsibilities**

Replace the old server-side/Wielder paragraph with:

```markdown
The Wielder is the wallet plus paying client proxy. The Collar is seller-side: it
holds the platform key, enforces the payment gate, runs the hosted Skill, and
writes the seller ledger. The demo's Wielder ledger is a receipt view, not the
authoritative compensation ledger.
```

- [ ] **Step 4: Correct split-level reconciliation everywhere**

Replace statements that the Creator/treasury split reconciled on-chain with:

```markdown
The aggregate testnet USDC payment to the seller `payTo` address reconciled
on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
they were not separate on-chain transfers.
```

Retain the testnet/play-money label next to every payment amount.

- [ ] **Step 5: Correct measurement dates**

Where historical chronology is retained, label the first n=1 run `2026-07-12` and the now-quarantined distribution `2026-07-15`. Remove wording that attributes the distribution to July 12 or merges both dates into one measurement.

- [ ] **Step 6: Run the claims test**

Run: `node --test scripts/tests/marketing-claims.test.mjs`

Expected: the tombstone test passes; the publication audit may still fail only on absolute extraction phrasing addressed in Task 5. It must report no `clone-paid-158`, `latency-unreproducible`, `txhash-as-retry-credential`, `wielder-is-server`, or `split-reconciled-onchain` finding.

- [ ] **Step 7: Commit x402 and latency corrections**

```bash
git add docs/marketing/linkedin.md docs/marketing/x.md docs/marketing/hn-and-demo.md docs/marketing/2026-07-13-campaign-plan.md
git commit -m "docs: correct x402 and measurement claims"
```

### Task 5: Replace absolute extraction promises with the supportable boundary

**Files:**
- Modify: `docs/marketing/linkedin.md`
- Modify: `docs/marketing/x.md`
- Modify: `docs/marketing/hn-and-demo.md`
- Test: `scripts/tests/marketing-claims.test.mjs`

- [ ] **Step 1: Replace launch-copy absolute language**

Replace every variation of “you never get the Skill,” “never the Skill,” and “the Skill never crosses the wire” in the three marketing files with:

```text
the artifact file is not directly returned; model-output extraction remains an adversarial runtime risk
```

For captions limited by length, use:

```text
The artifact file is not directly returned. Extraction risk remains.
```

- [ ] **Step 2: Preserve raw historical protocol evidence unchanged**

Do not edit `docs/marketing/artifacts/raw-402-response-live.txt`. It is a captured historical response, not approved future copy. Add this note where the artifact is referenced in `docs/marketing/2026-07-13-campaign-plan.md`:

```markdown
The captured response preserves its original absolute description as historical
wire evidence. Do not reuse that description as current marketing copy.
```

- [ ] **Step 3: Run the focused audit**

Run: `node scripts/marketing-claims.mjs`

Expected: `PASS — 4 publication drafts satisfy claim quarantine.`

- [ ] **Step 4: Run the complete claims test**

Run: `node --test scripts/tests/marketing-claims.test.mjs`

Expected: PASS, 2 tests passed, 0 failed.

- [ ] **Step 5: Commit extraction-language corrections**

```bash
git add docs/marketing/linkedin.md docs/marketing/x.md docs/marketing/hn-and-demo.md docs/marketing/2026-07-13-campaign-plan.md
git commit -m "docs: bound hosted Skill extraction claims"
```

### Task 6: Final read-only verification and human handoff

**Files:**
- Verify only; no new file changes expected.

- [ ] **Step 1: Run the offline policy suite**

Run: `node --test scripts/tests/marketing-claims.test.mjs`

Expected: PASS, 2 tests passed, 0 failed; no network access, keys, funds, or deployment.

- [ ] **Step 2: Confirm the historical tombstone was not embellished**

Run:

```bash
node -e "const m=require('./spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json'); if(m.evidenceStatus!=='historical_unreproducible'||m.publication.allowed!==false||'samples' in m) process.exit(1); console.log('PASS — historical tombstone remains non-publishable and sample-free')"
```

Expected: `PASS — historical tombstone remains non-publishable and sample-free`.

- [ ] **Step 3: Confirm protected corpus files are untouched by this plan**

Run: `git diff bad032b -- CONTEXT.md docs/PRD.md docs/adr`

Expected: no output.

- [ ] **Step 4: Inspect the worktree without staging user files**

Run: `git status --short --branch`

Expected: this plan's tracked edits are committed; pre-existing untracked `docs/marketing-assets/` and `hf-space/` remain untracked and untouched.

- [ ] **Step 5: Record the human-only publication decision**

Hand off this exact status without posting anything:

```text
Tracked launch drafts now fail closed on modeled clone cost, invalid target
conclusions, unreproducible n=48 latency, incorrect x402 roles, off-chain splits,
and absolute extraction claims. Existing public posts, if any, require a human
correction decision. No social post, live rerun, wallet action, or deployment was
performed.
```

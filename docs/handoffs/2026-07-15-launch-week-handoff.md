# Handoff — launch-week state (2026-07-15)

Supersedes `2026-07-11-codex-premise-review-followups.md` (all four tasks
executed and committed by 2026-07-12; see `docs/plans/2026-07-12-phase-a-findings.md`).

## What has happened since the last handoff

- **Phase A measurements (2026-07-12):** KC2 does not fire at first bound
  (cold ~2.5 s / warm ~1.5 s, n=3); KC4 split result at N=6 ($1.58 attack,
  fidelity failed, modeled 8-invocation break-even — do NOT cite as
  resolved); Education fork-economics re-run negative (free re-authoring
  strictly dominates). All now fed back into `docs/PRD.md` (commit b6d4861).
- **Pi-Wielder spike executed:** offline e2e green; real Base Sepolia run
  2026-07-12 (~781 ms x402 overhead/call, n=1; splits reconciled on-chain);
  four gateway/extension fixes 2026-07-13 (SSE, OpenAI shapes); **live demo
  verified 2026-07-15** — unmodified pi v0.80.6 paid 8 streaming calls
  ($0.328) through the proxy. Remaining: p50/p95 at n≈30 incl. the gpt leg.
- **Public split + live site:** protocol at github.com/Aznatkoiny/skill-asset-protocol
  (Apache-2.0, **still private as of 2026-07-15**); production x402 endpoint
  live at neverhandedover.com/api/invoke/optimizing-claude-code-prompts
  (402-gates unpaid POSTs; verified). skillassetprotocol.com serves.
- **Campaign kit committed (ae09fd6) but Day 0 (07-14) slipped** — slip
  recorded and re-anchor proposed (Day 0 = Thu 07-16) in
  `docs/marketing/2026-07-13-campaign-plan.md` §2. Raw artifacts for X posts
  #1–2 pre-captured in `docs/marketing/artifacts/`.
- **Strategy:** `docs/plans/2026-07-15-registry-not-marketplace.md` —
  marketplace stays rejected (ADR-0007 holds); distribution runs the MCP
  playbook; settlement-gated registry is the compliant surface, gated on the
  KC1 LOI. **KC7 monthly review instantiated** with first review logged:
  `docs/ops/kc7-platform-marketplace-review.md`.

## Next tasks (agent-doable, in order)

1. **Pi-Wielder follow-up recorded, distribution quarantined** — the historical
   2026-07-15 aggregate did not retain normalized per-call samples, so its n/p50/p95
   are not publishable. See
   `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. A replacement
   testnet run is human-authorized work and must use a new dated evidence bundle.
2. **High-N clone-economics run** (`spikes/clone-economics/`) — required
   before any public copy leans on the N=6 result (LinkedIn Post 2, X
   clone-attack thread).
3. **phase0 should-fixes then Aeneid run:** dust-funding gate
   (`balance === 0n` → estimated minimum), confirm-to-save crash window,
   env-override brick, metadata pinning off httpbin — wallet funding itself
   is a human step.
4. **Adoption-kit packaging** (weeks 1–2 of the registry plan): neutral
   GitHub org, reference Collar middleware, one-command offline demo.

## Human-only (do not attempt)

- ~~Pre-flight + repo flip~~ **Done 2026-07-15 PM:** pre-flight PASSED
  (fresh clone, offline e2e green, secrets scan CLEAN), public repo synced
  (gateway fix + n=48 numbers, commit 84f8da4) and **flipped public**
  (verified logged-out). LinkedIn Post 1 had already shipped Mon 07-13;
  the revamped calendar (campaign-plan §2) anchors today = Day 2: Post 2 +
  X artifact #1 today, launch thread Thu 07-23, Show HN Tue 07-28.
- Still human-only: publish Post 2 + the artifact tweet; the daily X reply
  routine; design-partner LOI outreach (KC1 — the binding constraint on
  everything); counsel engagement (KC5 instrument; collar/MSB).
- Known asset defect: the committed public-repo banner reads "EST.2024"
  (contradicts the 2026-07-11 corpus) — needs an image edit before flip.
  `docs/marketing-assets/` (untracked) holds duplicates, one with a space in
  the filename ("github -banner.png").

## Rules (unchanged from AGENTS.md)

Never commit `.env`/keys; testnet only; measured stays labeled measured;
extend "What we have NOT validated", never delete from it.

## Adversarial-remediation readiness ledger (2026-07-18)

This is the mutable execution ledger required by
`docs/superpowers/plans/2026-07-17-corpus-amendment-proposal.md`. It records
readiness for Plans 1–10; it is not canonical product doctrine.

- Baseline: `754c9513e6973916e616a0e9a096a83827f137b8`
- Branch: `codex/adversarial-remediation`, isolated worktree
- Exact readiness commit: `fa9078f9379940fc7a17faf9da350466c9ea5617`
- Result: all ten automated prerequisite gates pass.
- Protected corpus:
  `git diff --exit-code 754c9513e6973916e616a0e9a096a83827f137b8..fa9078f9379940fc7a17faf9da350466c9ea5617 -- CONTEXT.md docs/PRD.md docs/adr`
  exited 0 with no output.
- Final readiness status: `## codex/adversarial-remediation`; index and worktree
  clean.

### Plan and commit inventory

| # | Prerequisite plan | Verified implementation tip(s) |
|---|---|---|
| 1 | `docs/superpowers/plans/2026-07-17-claims-quarantine.md` | `f651f7d83a5269ee8f77f7a157d84d005baadf69` |
| 2 | `docs/superpowers/plans/2026-07-17-clone-economics-evidence.md` | `9812dea4b759f2f768681eabbfe4029aba84a306`; bounded provider transport `412f012825145aebf9d8c0fd0c1e30fb0e3076b1`; locked ceilings `e2c92acb7fad483c56f53f898b3114380be8a47e` |
| 3 | `docs/superpowers/plans/2026-07-17-phase0-proof-safety.md` | `0b9ff1707857ac8517ab6e037cb4663792089656` |
| 4 | `docs/superpowers/plans/2026-07-17-atomic-money-kernel.md` | `a83294b5c13c9983eda800aa226988475dc57d2e` |
| 5 | `docs/superpowers/plans/2026-07-17-collar-invocation-journal.md` | `af2f455fd53fb85c08018444ce19a00b8db408dc`; integrated runtime `25c4af3f13748a0f7ffea5787858c5a4493f9217`; final runtime boundaries `ee19624851df696a5bf52ae6099814556ce37da6`, `64f5699ded687faf0c7aa4f2fda3b6c82204c913`, `4230ac47d556c0f944ce20116d20b875a24fc7fc`, `fa9078f9379940fc7a17faf9da350466c9ea5617` |
| 6 | `docs/superpowers/plans/2026-07-17-wielder-payment-policy.md` | `51abab0a3e9979c074df7b4413763798d4447e0e`; integrated runtime `25c4af3f13748a0f7ffea5787858c5a4493f9217`; bounded challenge/replay `cfac5b4f3879aae6ea0ba4e13de76340612e7ce3`, `64f5699ded687faf0c7aa4f2fda3b6c82204c913`, `4230ac47d556c0f944ce20116d20b875a24fc7fc`, `fa9078f9379940fc7a17faf9da350466c9ea5617` |
| 7 | `docs/superpowers/plans/2026-07-17-cogs-aware-execution.md` | `25c4af3f13748a0f7ffea5787858c5a4493f9217`; final runtime boundaries `ee19624851df696a5bf52ae6099814556ce37da6`, `64f5699ded687faf0c7aa4f2fda3b6c82204c913`, `4230ac47d556c0f944ce20116d20b875a24fc7fc`, `fa9078f9379940fc7a17faf9da350466c9ea5617` |
| 8 | `docs/superpowers/plans/2026-07-17-internal-invocation-awards-spike.md` | `d669c6d41d85ef065dc52397cee83d11ab08d4b0` |
| 9 | `docs/superpowers/plans/2026-07-17-authorship-attestation.md` | `ef42617f0bea5f0a4966ef56d08ba09966a537e1`; bounded metadata `0b9ff1707857ac8517ab6e037cb4663792089656`; corrected audit gate `eb227dc70c7b512e4416eb2a4be511a05deb21bf` |
| 10 | `docs/superpowers/plans/2026-07-17-public-surfaces.md` | `0779fa1a0bd39f28ca8fd18104d7bb21eb676006` |

Every listed commit is an ancestor of the exact readiness commit.

### Exact verification commands and results

Plan 1:

```bash
node scripts/marketing-claims.mjs
node --test scripts/tests/marketing-claims.test.mjs
node -e "const m=require('./spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json'); if(m.evidenceStatus!=='historical_unreproducible'||m.publication.allowed!==false||'samples' in m) process.exit(1)"
find spikes/pi-wielder/evidence/2026-07-15-overhead -maxdepth 1 -type f -print
git diff --exit-code bad032b -- CONTEXT.md docs/PRD.md docs/adr
git diff --exit-code bad032b -- docs/marketing/artifacts/raw-402-response-live.txt
```

Result: PASS. Four drafts pass quarantine, 2/2 regression tests pass, the tombstone
is sample-free and non-publishable, its directory contains only `manifest.json`,
the protected corpus is unchanged, and the historical raw capture is unchanged.

Plan 2:

```bash
cd spikes/clone-economics
npm test
npm run e2e
npm run fixtures:check
npm run sweep:preflight
npm run sweep:mock
node scripts/verify-bundle.mjs evidence/2026-07-12-n6-invalid
env -u APPROVE_LIVE_SWEEP_SHA256 -u MAX_SWEEP_COST_USD -u ANTHROPIC_API_KEY MOCK_LLM=0 ALLOW_LIVE_LLM=0 npm run sweep:live
! git ls-files | rg '(^|/)\.env$|runs/|distilled-raw|raw-provider'
```

Result: PASS with the deliberately negative live gate. Unit tests pass 97/97 and
e2e passes 106/106; fixtures have no drift; preflight reports 100 train, 30
heldout, 12 cells, and 1,713 conservative requests; mock runs 12/12 cells with
`networkAttempts=0` and `publishable high-N: false`; 29 retained historical
samples recompute. The live command exits nonzero at
`Live budget snapshot must be approved` before provider construction and writes
no evidence. The final tracked-artifact scan has no matches.

Plan 3:

```bash
cd phase0
npm test
npm run typecheck
node --import tsx --test --test-name-pattern='remaining new write|gas prices' tests/funding.test.ts
node --import tsx --test tests/transactions.test.ts
node --import tsx --test tests/story.test.ts
node --import tsx --test --test-name-pattern='resume after|intent-hash|manifest save|directory fsync|WIP balance|WIP allowance|Pinata unavailable|current run configuration' tests/demo.test.ts tests/registrations.test.ts tests/story.test.ts
node --import tsx --test tests/metadata.test.ts
git check-ignore -v .env pending-transactions.json pending-transactions.json.audit.tmp pending-transactions.json.lock registrations.json.audit.tmp
git ls-files .env pending-transactions.json pending-transactions.json.audit.tmp pending-transactions.json.lock registrations.json.audit.tmp
rg -n '1514|mainnet' src
```

Result: PASS. Full suite 187/187 and typecheck pass; focused funding 3/3,
transaction-journal 16/16, Story boundary 20/20, crash/WIP 8/8, and metadata
trust/path 34/34 pass. `registrations.json` remains `not-run` with null proof
fields. All five local paths are ignored and untracked; the network scan has no
configured mainnet target.

Plans 4–7 shared umbrella:

```bash
npm test --prefix prototype
npm test --prefix spikes/pi-wielder
npm run e2e --prefix spikes/pi-wielder
```

Result: PASS with local-loopback permission only: prototype 23/23, Pi 237/237,
and offline e2e 41/41. The e2e conserves
`250000 = 756 COGS + 1000 settlement + 6250 protocol fee + 5000 refund reserve + 236994 Royalty-claim pool`.
The full Pi suite also proves that both the Collar and gateway refuse live-provider
construction behind mock x402 settlement before any live executor or provider fetch.

Plan 4:

```bash
node --check prototype/atomic-money.mjs
rg -n "Math\.|parseFloat|toFixed|Number\(" prototype/atomic-money.mjs
rg -n "process\.env|PRIVATE_KEY|fetch\(|mainnet" prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs
```

Result: PASS: syntax exits 0; both negative scans return no matches; 152 external
and 20 internal allocation-matrix cases conserve integer atomic gross.

Plan 5:

```bash
npm run test:journal --prefix spikes/pi-wielder
node --test --test-name-pattern="settled-then-500" spikes/pi-wielder/tests/collar-failure.test.mjs
if git grep -I -q -E -e '-----END ([A-Z]+ )*PRIVATE KEY-----|PRIVATE_KEY[[:space:]]*=[[:space:]]*(0x)?[0-9a-fA-F]{64}' -- .; then
  false
else
  secret_scan_status=$?
  test "$secret_scan_status" -eq 1
fi
```

Result: PASS: journal 29/29, settled-then-500 1/1, and the tracked-secret scan
exits 0 with no output. The scan distinguishes a deliberate header-only test
sentinel from complete PEM material, emits no possible secret content, and fails
on a match or scan error.

Plan 6:

```bash
npm run test:payment --prefix spikes/pi-wielder
node --test --test-reporter=spec spikes/pi-wielder/tests/payment-policy.test.mjs
node --test --test-name-pattern="forbidden first offer|different request bytes|changed second offer" spikes/pi-wielder/tests/paying-fetch.test.mjs
rg -n "base-sepolia|84532|WIELDER_.*_USDC" spikes/pi-wielder/src spikes/pi-wielder/.env.example
git diff --check
! git ls-files | rg '(^|/)\.env$'
```

Result: PASS: payment tests 87/87, the named policy suite 51/51, forbidden/change
patterns 2/2, Base Sepolia/test-limit references only, clean diff, and no tracked
`.env`.

Plan 7:

```bash
npm run test:collar --prefix spikes/pi-wielder
npm run test:economics --prefix spikes/pi-wielder
node --test spikes/pi-wielder/tests/runtime-boundaries.test.mjs
node --test spikes/pi-wielder/tests/pi-extension-contract.test.mjs
node -e 'const m=require("./spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json"); if(m.evidenceStatus!=="historical_unreproducible"||m.publication.allowed!==false) process.exit(1)'
rg -n "status: 'unknown'|actualAtomic: null|chargedAtomic" spikes/pi-wielder/src/execution-economics.mjs spikes/pi-wielder/tests
```

Result: PASS: Collar 49/49, economics 36/36, runtime-boundary 5/5, extension
contract 1/1, tombstone remains non-publishable, and unknown COGS remains null
with the full reservation held.

Plan 8:

```bash
cd spikes/internal-invocation-awards
npm test
npm run demo
! rg -n 'grossAtomic\s*-|protocolFeeAtomic\s*-|invocationAwardAtomic\s*=' src
git diff --exit-code -- ../../CONTEXT.md ../../docs/PRD.md ../../docs/adr
```

Result: PASS: 86/86 tests and the exact deterministic demo pass. The demo says
`NO REAL FUNDS` and `not paid`; no duplicate allocation implementation or
protected-corpus diff exists. Reserved, executing, held-unresolved, and
vesting-pending exposure counts toward the signed period cap; only an
authenticated append-only reversal releases exposure.

Plan 9:

```bash
cd phase0
npm test
npm run typecheck
npm run attestation-status -- --artifact-hash 0x0000000000000000000000000000000000000000000000000000000000000000 --json
! rg -n -P '\bauthored by\b|(?<!not )\bproves? (?:originality|safety)\b|\bsafe Skill\b' src README.md
git check-ignore .attestation-checkouts.local.json
! git ls-files | rg 'attestation-checkouts\.local\.json$'
! rg -n '"repositoryPath"\s*:|/(Users|home)/|[A-Za-z]:\\\\' repository-trust.json organization-signers.json attestation-admins.json forge-signers.json
```

Result: PASS: Phase 0 187/187, typecheck, and the empty status response pass.
The affirmative-overclaim scan has no matches while required negative
disclaimers remain visible; the local checkout map is ignored/untracked and no
tracked trust-root file contains a machine path.

Plan 10:

```bash
cd spikes/registry-ranking
npm test
npm run report -- --json
cd ../..
node hf-space/scripts/generate-accounting-fixture.mjs --check
node hf-space/scripts/package-space-fixtures.mjs --check
node --test hf-space/scripts/test-generate-accounting-fixture.mjs
node --test hf-space/scripts/test-package-space-fixtures.mjs
uv run --with-requirements hf-space/gradio/requirements.txt -- python3 -c 'from importlib.metadata import version; assert version("gradio")=="6.20.0"; assert version("httpx")=="0.28.1"'
uv run --with-requirements hf-space/gradio/requirements.txt -- python3 -B -m unittest hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py
cd hf-space/static
node -e 'const p=require("./node_modules/linkedom/package.json"); if(p.version!=="0.18.12") process.exit(1)'
npm test
cd ../..
! rg -n '\bp(50|95)\b|two real testnet settlements from this exact endpoint|claimable on demand|current hosted-Skill endpoint proof|\bunfakeable\b|supply-chain safety' hf-space/scripts/generate-accounting-fixture.mjs hf-space/scripts/test-generate-accounting-fixture.mjs hf-space/scripts/package-space-fixtures.mjs hf-space/scripts/test-package-space-fixtures.mjs hf-space/scripts/verify-local-scope.mjs hf-space/shared/public-demo-allocation.json hf-space/shared/evidence.json hf-space/gradio/demo_logic.py hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py hf-space/gradio/app.py hf-space/gradio/README.md hf-space/gradio/requirements.txt hf-space/gradio/data/public-demo-allocation.json hf-space/gradio/data/evidence.json hf-space/gradio/data/fixture-integrity.json hf-space/static/demo-logic.mjs hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs hf-space/static/index.html hf-space/static/README.md hf-space/static/package.json hf-space/static/package-lock.json hf-space/static/data/public-demo-allocation.json hf-space/static/data/evidence.json hf-space/static/data/fixture-integrity.json docs/plans/2026-07-15-registry-not-marketplace.md
! rg -n 'huggingface-cli upload|hf upload|huggingface_hub|git push|gradio deploy|vercel deploy|netlify deploy|requests\.(post|put)|httpx\.(post|put).*huggingface|HF_TOKEN|HUGGING_FACE_HUB_TOKEN' hf-space/scripts/generate-accounting-fixture.mjs hf-space/scripts/test-generate-accounting-fixture.mjs hf-space/scripts/package-space-fixtures.mjs hf-space/scripts/test-package-space-fixtures.mjs hf-space/scripts/verify-local-scope.mjs hf-space/shared/public-demo-allocation.json hf-space/shared/evidence.json hf-space/gradio/demo_logic.py hf-space/gradio/test_demo_logic.py hf-space/gradio/test_app_smoke.py hf-space/gradio/app.py hf-space/gradio/README.md hf-space/gradio/requirements.txt hf-space/gradio/data/public-demo-allocation.json hf-space/gradio/data/evidence.json hf-space/gradio/data/fixture-integrity.json hf-space/static/demo-logic.mjs hf-space/static/test-demo-logic.mjs hf-space/static/test-index-smoke.mjs hf-space/static/index.html hf-space/static/README.md hf-space/static/package.json hf-space/static/package-lock.json hf-space/static/data/public-demo-allocation.json hf-space/static/data/evidence.json hf-space/static/data/fixture-integrity.json
node --input-type=module -e 'import { execFileSync } from "node:child_process"; import { HF_SPACE_ALLOWED_PATHS } from "./hf-space/scripts/verify-local-scope.mjs"; const tracked=execFileSync("git",["ls-files","--","hf-space"],{encoding:"utf8"}).trim().split("\n").filter(Boolean).sort(); if(tracked.length!==26||JSON.stringify(tracked)!==JSON.stringify(HF_SPACE_ALLOWED_PATHS)){console.error(JSON.stringify({tracked,allowed:HF_SPACE_ALLOWED_PATHS},null,2));process.exit(1)}'
git diff --exit-code 754c9513e6973916e616a0e9a096a83827f137b8..fa9078f9379940fc7a17faf9da350466c9ea5617 -- CONTEXT.md docs/PRD.md docs/adr
```

Result: PASS: registry 12/12, generator 4/4, packager 3/3, Gradio 16/16 with
exact pins, and static 9/9. Fixture bytes and integrity manifests match; the
branch contains exactly the reviewed 26 `hf-space/` paths. Claim-suppression,
publication-command, secret, endpoint, and protected-corpus scans pass. The
historical settlement manifest remains narrowly labeled; the n=48 manifest
remains `historical_unreproducible` with publication disabled.

### External and human-only states

- High-N live clone sweep: `not-run`; authorization and spend are not approved;
  all public clone conclusions remain blocked.
- Phase 0 Aeneid writes, wallet funding, WIP wrap/approval, Pinata upload, and
  private-key operations: `not-run`; wallet funding remains human-only.
- Live x402/provider/catalog execution: `not-run`; all live gates and
  `PRIVATE_KEY` were unset. Pi verification was offline/in-process with a
  throwaway unfunded wallet and local loopback only.
- Internal Invocation awards: synthetic accounting evidence only; no payroll,
  AP, custody, tax, counsel, employer agreement, or real-money action occurred.
- Public demos: local verification only; no upload, deployment, launch, social
  publication, or repository push occurred.
- Historical evidence: the 2026-07-15 n=48 aggregate remains
  `historical_unreproducible`; the 2026-07-12 Base Sepolia receipt is a
  read-only historical transaction observation and proves none of execution,
  latency, split correctness, independent demand, authorship, or safety.
- Test-harness incident: an earlier red test made one unpaid request to the fixed
  public endpoint because the legacy `httpx.post` path was not stubbed. It
  received HTTP 402. No payment, signature, wallet action, provider execution,
  deployment, or publication occurred. Both `httpx.post` and `httpx.stream`
  are now fail-closed in the test harness.
- Applying any protected-corpus amendment remains blocked on explicit user
  approval and a separate coherence plan.

This ledger commit is the Plan 11 ordering boundary. The non-canonical proposal
may be recreated only after this ledger is committed; its final creation commit
must be a descendant of this readiness record.

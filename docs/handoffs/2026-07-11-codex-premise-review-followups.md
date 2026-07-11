# Handoff: premise-review follow-ups (for Codex, branch `codex/prd-execution`)

*2026-07-11. From a Claude Code session that ran an adversarial premise review,
reframed the corpus, and built the first Wielder-side spike. You are picking up
the remaining agent-doable work.*

## Context in 60 seconds

This repo is the **Skill Asset Protocol** — as of today reframed (all docs
committed) from "skill marketplace with royalties" to **a compensation,
attribution, and metering layer for authored AI Skills ("Carta for AI work
artifacts")**. Phase 1 (off-chain signed ledger + co-held non-transferable
claims + Story provenance) is the terminal product by design; the open
Marketplace is underwritten optionality.

**Read these first, in order (do not skip):**
1. `docs/plans/2026-07-11-reframe-and-pi-wielder-design.md` — the decision + change spec
2. `docs/adr/0007-closed-mode-compensation-layer-as-terminal-product.md`
3. `docs/adr/0008-the-wielder-is-a-wallet.md`
4. `CONTEXT.md` — the ubiquitous language (Collar, Wielder, Invocation, …). Use
   these terms exactly; do not reintroduce marketplace-first framing anywhere.

Recent commits on this branch tell the story: `8ad9a1c` (corpus snapshot),
`1c85de7` (design doc), `d1e68b9` (pi-wielder spike, e2e green), `73cb5ca`
(reframed corpus, adversarially verified).

## Your tasks (in priority order)

### 1. Repair `prototype/spike-cma-latency.mjs`
The file is syntactically broken on disk — every quote is a literal `\"`
escape; `node --check` fails — while its header falsely claims it "was
syntax-verified with node --check". Fix the escaping globally, delete the false
claim from the header, verify with `node --check`. If `ANTHROPIC_API_KEY` is
available in the environment, run it and append the measured
`sessions.create` → first-token latency distribution to `prototype/README.md`
NOTES (this feeds PRD kill-criterion 2). If no key, stop after the repair and
say so — do not fabricate numbers.

### 2. Make the phase0 write path one command from funded-wallet to proof
`phase0/` compiles and its read path works, but the on-chain write path has
never executed (wallet holds 0 IP, no ipId/txHash recorded anywhere). Do NOT
fund the wallet (human step). Instead:
- Add a single `npm run demo` that runs create-collection → register-skill →
  register-derivative (multi-level chain), checks the balance first and exits
  with clear faucet instructions if unfunded.
- Persist resulting ipIds/txHashes/licenseTermsIds to a committed artifact
  (e.g. `phase0/registrations.json`) — later phases must consume the fork
  graph; console-only output is a known defect.
- Fix the hard-coded `maxMintingFee: 0n` in registerDerivative (forking a
  paid-mint parent currently reverts).
- Replace placeholder `ipfs://` metadata URIs with retrievable content (pin
  real metadata, or at minimum an HTTPS URI whose bytes match the on-chain
  hash) — unverifiable hashes are weak evidence in the very disputes
  provenance exists to win.
- Document plainly in `phase0/README.md` that this targets Aeneid testnet
  (1315) while the PRD's Phase-0 success criterion is mainnet (1514) — a known
  discrepancy, do not silently "fix" it by pointing at mainnet.

### 3. Build the clone-economics spike (`spikes/clone-economics/`)
The PRD's single most load-bearing unmeasured number (report.md §7.7; PRD
kill-criterion 4): how cheaply can a paid Skill's own I/O pairs be distilled
into a clone, and how fast must the original evolve to keep the clone stale?
Build a harness that: (a) generates N I/O pairs by invoking a target skill
(use `.claude/skills/optimizing-claude-code-prompts/` as the target), (b)
distills a clone by prompting a model with those pairs to author an equivalent
skill, (c) scores clone fidelity on held-out inputs, (d) reports cost ratio
(clone cost vs. N × invocation price). Requirements: offline mock mode
(`MOCK_LLM=1`, canned pairs) must run green with zero keys/network — follow
the pattern in `spikes/pi-wielder/` (README + RUNBOOK + e2e script). Real runs
only if keys are present.

### 4. Re-run fork economics with the free re-author branch
`prototype/spike-fork-economics.mjs` models the forker's alternative as
"author solo at fresh cost". The education mode was deferred today precisely
because the student's *real* alternative is "re-author using everything the
class taught" at near-zero cost (ADR-0007; PRD Mode (c) DEFERRED banner).
Extend the spike with that branch: alternative cost ≈ 0, no lineage declared,
school gets nothing. Find whether ANY `inheritBps` > 0 survives, and under
what assumptions (e.g. option value of the parent's live evolution). Append
results to `prototype/README.md` NOTES with the same honest verdict style
(TBD → measured).

## Hard constraints

- Work and commit on `codex/prd-execution` only; small commits, one task each.
- **Never** commit `.env` or any key (repo `.gitignore` covers it; keep it so).
- **No real money, no mainnet transactions.** Testnet only, and even testnet
  funding is a human step you must not attempt to automate.
- Do NOT edit the just-reframed corpus (`CONTEXT.md`, `docs/PRD.md`,
  `docs/adr/`) — record spike results in the spikes'/prototype's own READMEs;
  propose corpus edits in your final summary instead of making them.
- Do NOT touch `spikes/pi-wielder/` — it is done and committed (e2e: 20 checks
  green offline).

## Explicitly NOT yours (human-only, for context)

Faucet-funding either wallet (Base Sepolia for pi-wielder, Aeneid for phase0);
design-partner LOI conversations (PRD kill-criterion 1); securities/409A
counsel engagement.

## Suggested skills (installed under `.agents/skills/`)

- `tdd` — for the clone-economics harness and the phase0 demo runner.
- `prototype` — task 3 is a classic throwaway-prototype-to-answer-a-question.
- `ubiquitous-language` / `domain-modeling` — keep new code speaking
  CONTEXT.md's terms (Collar, Wielder, Invocation, Derivative, Royalty claim).

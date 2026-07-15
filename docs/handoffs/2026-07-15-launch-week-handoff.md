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

1. ~~x402 overhead distribution~~ **Done 2026-07-15:** p50 731 ms / p95
   1206 ms (n=48 settled, both legs); gateway `max_completion_tokens` fix;
   pay-then-fail + settled-but-rejected failure modes recorded in
   `spikes/pi-wielder/README.md`; PRD updated.
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

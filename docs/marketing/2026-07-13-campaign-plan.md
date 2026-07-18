# Launch campaign plan — Skill Asset Protocol / neverhandedover.com

*Drafted 2026-07-13. This is the strategy and calendar that ties together the three content
kits. It does not rewrite any piece — it places them:*

- `docs/marketing/linkedin.md` — LinkedIn Posts 1–5
- `docs/marketing/x.md` — three X threads (§1–3), engagement playbook (§4), standalone spacers (§5)
- `docs/marketing/hn-and-demo.md` — Show HN draft + prepared answers (§1), demo clip script (§2), launch-day runbook and measurement plan (§3)

*Compliance applies to every artifact and every reply, per the house rules in each kit: no
financial-upside language, and "testnet USDC (play money)" wherever the $0.25 demo appears.*

---

## 1. Strategy on a page: the inverted playbook

The standard launch playbook is: blast X for reach, submit to HN on day one, treat LinkedIn
as an afterthought. We invert all three, because our assets are inverted:

**LinkedIn is the broadcast channel — because the network is real and the buyer lives there.**
The ICP is VP Eng / Head of Platform at 100–800-person AI-forward firms, co-read by Head of
People and the CFO. That audience is in Antony's existing LinkedIn network, not following a
cold X account. So LinkedIn gets the full five-post series (`linkedin.md`), starting Day 0,
and it carries the only direct ask in the campaign: the design-partner ask in Post 3.

**X is a cold account that has to buy credibility with receipts before it broadcasts.**
Near-zero followers means threads posted on Day 0 land in a void. Instead the account spends
~a week living in other people's replies — x402, Base, Story Protocol, Claude Code, and
agent-payments conversations — answering real questions with measured numbers, per the
playbook in `x.md` §4. Only after that track record exists does the launch thread ship
(Day 7). Distribution on X comes from ecosystem accounts and builders quoting the work, and
they only quote names they've seen show up usefully.

**Show HN is the neutral-ground, high-leverage event — deliberately not Day 0.**
HN is where the claims get stress-tested by strangers with no reason to be kind, and where
the honesty ledger (kill-criteria, "What we have NOT validated", the invalid clone benchmark) is
worth the most. We go there only after the demo is battle-tested: a week of live paid
invocations, the fresh-machine clone-and-run verified again the night before, and the five
prepared answers (`hn-and-demo.md` §1) open in a tab. HN lands Day 9.

**The funnel.** Each channel feeds the next: LinkedIn starts buyer conversations → the X
warm-up recruits the ecosystem amplifiers who will carry the launch thread → HN stress-tests
the claims and sends technical readers to the repo and the live endpoint. Everything
terminates at the same two artifacts: neverhandedover.com and the Apache-2.0 repo.

**North-star metrics, in strict order** (measurement mechanics in `hn-and-demo.md` §3):

1. **Design-partner conversations started** — the only path to the thing we have NOT
   validated. Kill-criterion 1 hangs on this. One real conversation outranks everything
   below combined.
2. **On-chain demo invocations** (count + unique payers, from Base Sepolia receipts) —
   someone did the thing, not viewed the thing.
3. **Repo stars / forks / clones** — developer intent.
4. Everything else. Impressions, likes, follower counts, and HN points are explicitly not
   success metrics and are not tracked as such.

**Priority override:** a live design-partner conversation outranks any scheduled post. The
calendar slips before a conversation does.

---

## 2. Two-week calendar

Day 0 = **Tuesday 2026-07-14**: repo flip + soft launch. "Soft" means: repo public, site
verified live, LinkedIn Post 1 out — no X thread, no HN.

> **Revamp (2026-07-15, supersedes the 07-15 morning slip note and the table below).**
> What actually happened: **LinkedIn Post 1 shipped Mon 07-13** — but the repo flip did
> not, so Post 1's repo link 404'd for two days (verified: repo still private Wed 07-15,
> 0 stars). Tue 07-14 was silent; the x402 Foundation launched under the Linux Foundation
> that day. Re-anchor: **Post 1 day = Day 0 (Mon 07-13); today Wed 07-15 = Day 2.**
> Pre-flight ran 2026-07-15 and PASSED (fresh clone, offline e2e 20 checks green in
> 1.6 s, all four offline proofs pass, full-history secrets scan CLEAN).
>
> **Acknowledged kit overrides:** (a) x.md §4's "week 1 = reply only, post nothing
> original" is compressed — Post 1 already broke broadcast silence on 07-13, so the
> artifact cadence starts today; (b) Post 2's historical context preferred mid-week
> *morning*, but that scheduled action is now blocked by the evidence override below;
> (c) the launch thread's reply history is 8 calendar days / 6 active reply days
> (weekends rest) — start the reply routine today without fail.

> **2026-07-17 evidence override:** all clone-economics publication steps below
> are historical schedule entries and are blocked. A calendar date never
> overrides an evidence gate.

### Revamped calendar (Day 2 = Wed 07-15 → HN)

| Day | Date | Actions |
|---|---|---|
| 0 | Mon 07-13 | *(done)* LinkedIn Post 1 out, pinned. Repo flip did NOT happen — slip recorded. |
| 1 | Tue 07-14 | *(done)* Silent. x402 Foundation launches under the Linux Foundation — this week's reply-routine entry point. |
| **2** | **Wed 07-15 (today)** | ① **Repo public FIRST** (pre-flight passed; verify from a logged-out browser after the flip). ② Reply to any Post-1 comments that hit the 404 — factual correction in a reply, never silent. ③ **BLOCKED:** do not publish clone-economics copy. The N=6 target failed its own acceptance gate; the required valid N=100 evidence bundle does not exist. ④ **X artifact #1**: the raw 402 from the LIVE endpoint (`docs/marketing/artifacts/raw-402-response-live.txt` — production URL + its original absolute description in the payload; see the historical-wire note below); tweet text below. ⑤ Reply routine starts (x402-Foundation news as the entry; measured numbers, never a pitch). ⑥ Metrics table started (`hn-and-demo.md` §3 daily log). |
| 3 | Thu 07-16 | X artifact #2: the aggregate seller `payTo` transfer reconciled on-chain; the Creator/treasury credits remained off-chain (testnet, play money). Replies. |
| 4 | Fri 07-17 | X artifact #3: "What we have NOT validated" page, screenshotted. Light day. |
| 5–6 | Sat–Sun 07-18/19 | **Rest days** (Sun: optional 15 min of replies if a good conversation is live). |
| 7 | Mon 07-20 | X artifact #4: the kill-criteria arithmetic that killed education mode. Replies. |
| 8 | Tue 07-21 | **LinkedIn Post 3** (design-partner ask) ~8:30am ET + targeted reshares. **BLOCKED:** do not publish the historical overhead distribution; use the 2026-07-15 quarantine status below. |
| 9 | Wed 07-22 | **Record the demo clip** (`hn-and-demo.md` §2) — one week of live traffic since the flip; verify basescan links. X artifact #6: pay-then-fail receipt. Prep ecosystem tag reply; hand-verify org @handles. |
| 10 | Thu 07-23 | **X launch thread** (x.md §1, amended numbers) late morning, demo clip on tweet 1, pin, ecosystem tag reply first. Hours 1–3 live in replies. |
| 11 | Fri 07-24 | Thread aftercare. X spacer: the pi session ledger (single tweet — 48h thread spacing holds). |
| 12–13 | Sat–Sun 07-25/26 | **Rest days** (optional launch-thread reply sweep). |
| 14 | Mon 07-27 | X spacer: ~150-line Wielder proxy screenshot. Evening: **HN pre-flight** (re-run fresh-machine test, live 402 + paid invocation, five prepared answers open). |
| 15 | **Tue 07-28** | **LinkedIn Post 5** ~8:00am ET, cross-linked from the repo README. **Show HN** 8:30–10:00am ET (title 1, §1 text as first comment, runbook cadence). **X how-it-works thread** mid-morning (≥48h after launch thread ✓). *(Post 5's context prefers Thursday; staying paired with HN day matters more — if HN slips, both move to Thu 07-30.)* |
| 16 | Wed 07-29 | HN aftercare (hourly sweeps; log unanswerable critiques as corpus defects). X spacer: settled-but-rejected reconciliation — the honesty artifact while HN eyes are on the account. |
| 17 | Thu 07-30 | **BLOCKED:** do not publish clone-economics copy. The N=6 target failed its own acceptance gate; the required valid N=100 evidence bundle does not exist. **LinkedIn Post 4** (kill-criteria). **Day-7-after-launch-thread review**: count conversations that could become a design-partner LOI — the one derived number that matters. |

**Historical overhead artifact status:**

The 2026-07-15 overhead distribution is historical but not reproducible from a
clean checkout because normalized per-call samples were not retained. Its sample
count, p50, and p95 are quarantined from publication; see
`spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
measurement has been run.

**Accounting boundary for ledger artifacts:**

The aggregate testnet USDC payment to the seller `payTo` address reconciled
on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
they were not separate on-chain transfers.

Constraint check: repo flip before anything that links to it ✓ · ≥48h between threads (07-23 / 07-28 / 07-30) ✓ · launch thread + HN on Tue/Thu ✓ · weekends rest ✓ · demo clip after a week of live traffic ✓.

**Today's X artifact #1 tweet** (attach the live-endpoint 402 capture; ~250 chars, verify at post time; single tweet, no thread, no link — the artifact is the content):

The captured response preserves its original absolute description as historical
wire evidence. Do not reuse that description as current marketing copy.

> POST to a paid endpoint without paying and this is the reply: HTTP 402, with
> machine-readable terms — amount, network, asset, payTo. The retry carries a
> signed `X-PAYMENT` authorization; the settlement transaction hash is evidence
> returned afterward, not the retry credential. Base Sepolia testnet — play money.

**Standing daily items (every non-rest day, not repeated in the table):**

- **X reply routine, 30–45 min** — the daily engagement routine from `x.md` §4: saved
  searches, 3–5 conversations, replies with a receipt, never a pitch. This runs every working
  day of the campaign, before and after the X launch thread.
- **Metrics log** — append the day's numbers to the table in `hn-and-demo.md` §3
  (invocations, unique payers, stars/forks/clones, conversations started, unanswerable
  critiques).
- **LinkedIn comment tending** — reply to substantive comments on whichever posts are live.

**Original pre-slip table (superseded by the revamped calendar above, 2026-07-15 — its dates are no longer valid; kept for the per-day action detail the revamp references):**

| Day | Date | Actions |
|---|---|---|
| **−1** | Mon 07-13 (today) | Pre-flight checklist from `hn-and-demo.md` §3: LICENSE, README offline-e2e story, secrets scan, fresh-machine clone-and-run with zero keys/funds, live 402 check, both domains serving, compliance pass on every queued post. If the fresh-machine test fails, Day 0 slips — nothing else changes. |
| **0** | Tue 07-14 | **Repo public first** (runbook step 1), verify clone-and-run from a logged-out browser. **LinkedIn Post 1** ("Never handed over", `linkedin.md`) at ~8:30am ET, link in first comment, pin to profile. X: replies only. Log day-0 measurements. |
| **1** | Wed 07-15 | X build-in-public artifact #1: screenshot of the raw HTTP 402 response (`x.md` §4, week-2 list). Single tweet, no thread. |
| **2** | Thu 07-16 | **BLOCKED:** do not publish clone-economics copy. The N=6 target failed its own acceptance gate; the required valid N=100 evidence bundle does not exist. X artifact #2: the aggregate seller `payTo` transfer reconciled on-chain; the Creator/treasury credits remained off-chain (testnet, play money). |
| **3** | Fri 07-17 | X artifact #3: the "What we have NOT validated" page, screenshotted. Light day otherwise. |
| **4** | Sat 07-18 | **Rest day.** Nothing posted anywhere. No replies. |
| **5** | Sun 07-19 | **Rest day** (light): optional 15 min of X replies if a good conversation is live; otherwise nothing. |
| **6** | Mon 07-20 | X artifact #4: the kill-criteria arithmetic that killed education mode. **Record the final demo clip** per the script in `hn-and-demo.md` §2 (one unbroken terminal take, real latency left in, testnet/play-money captions) — recorded now, after a week of live traffic, so the clip shows the battle-tested system. Verify the basescan links in it resolve. Prep the ecosystem tag reply; verify every org @handle by hand (`x.md` §4 tag strategy). |
| **7** | Tue 07-21 | **LinkedIn Post 3** (retention / the design-partner ask) at ~8:30am ET, then reshare to specific VP Eng / Head of People contacts with one-line personal notes per its posting context. **X launch thread** (`x.md` §1) late morning, demo clip attached to tweet 1 (per runbook step 3), pin it, ecosystem tag reply as the first reply. Hours 1–3: live in the X replies — this window decides whether the thread travels. |
| **8** | Wed 07-22 | X spacer: the ~150-line Wielder proxy code screenshot (`x.md` §4 artifact list) — a natural bridge to tomorrow's technical thread. Evening: **HN pre-flight** — re-run the fresh-machine test, re-verify the live 402 and a paid invocation, open the five prepared answers (`hn-and-demo.md` §1) in a tab. |
| **9** | Thu 07-23 | **LinkedIn Post 5** (build story — the technical post HN readers will arrive at) at ~8:00am ET, cross-linked from the repo README. **Show HN** at 8:30–10:00am ET: submit neverhandedover.com with title 1, §1 text as immediate first comment. Responding cadence per runbook step 5 (hour 1: every substantive comment within ~15 min; then 30-min sweeps; then hourly). **X how-it-works thread** (`x.md` §3) mid-morning — written for the same technical crowd, 48h after the launch thread, quoting the pinned thread from its last tweet. End of day: link the best critical HN thread from the site/X ("the hardest question we got today"). |
| **10** | Fri 07-24 | HN aftercare: hourly sweeps while the thread is warm; log any critique we couldn't answer as a corpus defect. X spacer: one standalone from `x.md` §5 (suggest D — "The artifact file is not directly returned. Extraction risk remains."). |
| **11** | Sat 07-25 | **Rest day.** Nothing posted. |
| **12** | Sun 07-26 | **Rest day** (light): optional HN/X reply sweep only if threads are still live. |
| **13** | Mon 07-27 | **BLOCKED:** do not publish clone-economics copy. The N=6 target failed its own acceptance gate; the required valid N=100 evidence bundle does not exist. **LinkedIn Post 4** (kill-criteria / honesty post) — its context says week 2–3 mid-week and it's the let-it-sit-and-compound post, so sliding it to Wed 07-29 is equally fine. **Day-7-after-launch review:** count conversations that could become a design-partner LOI — the one derived number that matters (`hn-and-demo.md` §3). Remaining `x.md` §5 spacers (A, B, C, E, F) feed week 3+ as-needed. |

Reconciliation note: `hn-and-demo.md` §3 sequences repo → LinkedIn → X thread → HN as one
list. This plan keeps that ordering but stretches it across Days 0–9, per the inverted
playbook: steps 1–2 happen Day 0, step 3 (X thread) waits for the account's week of replies
(Day 7), steps 4–6 are HN day (Day 9). Within each day, the runbook's mechanics apply
unchanged.

---

## 3. Risk notes

**If a post flops: do nothing.** Cadence continues exactly as scheduled. No deleting, no
reposting, no "in case you missed it", no paying to boost. A single post is a sample of one,
and the metrics that matter (§1) are counted at day 7, not at hour 2. The one exception is a
factual error in a live post — correct it in a reply immediately, never silently.

**If HN turns hostile: engage the top critique honestly, never defensively.** Find the
highest-voted critical comment and answer it first, conceding whatever is valid in the first
sentence — the corpus was built for this (kill-criteria, the not-validated ledger, the invalid
clone benchmark). Use the five prepared answers in `hn-and-demo.md` §1 as the base; for the
known secondary flak (GPT Store, x402-volume-is-bots, "Anthropic will ship this"), use the
one-line stances at the end of that section. Reply to content, never to tone; do not chase
every commenter; never ask for votes. If the thread dies anyway, the end-of-day job stands:
log every critique we couldn't answer as a corpus defect to fix. A hostile thread that
surfaces a real hole is the measurement plan working.

**If a securities-adjacent question appears (any channel): use the prepared answer, never
improvise.** The full answer is Q1 in `hn-and-demo.md` §1 — deploy it verbatim on HN, or
compressed to its load-bearing points elsewhere: v1 claims are non-transferable by design
(no resale, no secondary market), structured as a deferred-comp / license-fee instrument; we
rate that route medium confidence, not a safe harbor, and a published kill-criterion covers
counsel failing to draft the actual instrument; the live demo is testnet play money and
nothing is being offered to anyone. Do not debate Howey ad hoc, do not soften the concession
(the answer opens with "mostly agreed" for a reason), and do not let the banned vocabulary
in — not even inside a quotation or rebuttal. If the question arrives in a DM or a
design-partner conversation, same answer, plus a pointer to the kill-criteria doc in the repo.

**Standing override, restated:** if any of this competes with a live design-partner
conversation, the conversation wins. That is metric #1; the calendar exists to produce it.

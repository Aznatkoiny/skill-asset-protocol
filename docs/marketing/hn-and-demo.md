# HN launch, demo clip, and launch-day runbook

*Drafted 2026-07-13. Voice: Antony posting personally. Every number below is from the corpus
(`docs/PRD.md`, `docs/plans/2026-07-12-phase-a-findings.md`, Phase-A measurements on Base
Sepolia, 2026-07-12). Compliance rule for every artifact in this file: the demo is testnet
play money and is described as such anywhere a reader might act on it. No financial-upside
language anywhere.*

---

## 1. Show HN draft

> **PUBLICATION BLOCKED — INVALID BENCHMARK.** The 2026-07-12 target scored
> 0.400 and failed its own critical gates, so clone-quality, fidelity-defense, and
> break-even conclusions are suppressed. Acquisition was modeled at $1.50; no
> x402 acquisition payments settled. Unblock only after
> `spikes/clone-economics` produces a valid N=100 result with committed normalized
> evidence and three live-adapter-confirmed independent distillation seeds.

### Title options (pick one; all under 80 chars)

1. `Show HN: A manifesto that is also a paid API endpoint (HTTP 402)`
2. `Show HN: An invalid clone benchmark and the gate we added after it`
3. `Show HN: Metering AI skills per invocation instead of handing them over`

Recommendation: title 1. It describes the artifact, not the thesis, and the artifact is the
novel thing. Title 2 remains blocked with the clone-economics copy until the evidence gate
above is satisfied and a human approves revised copy.

### Post text (submit as a text post with the URL, or as first comment — ~230 words)

> https://neverhandedover.com is a manifesto that is literally a paid endpoint. POST to it
> without payment and you get HTTP 402. Pay $0.25 in testnet USDC (play money, Base Sepolia)
> and the hosted Skill runs and streams you output. The artifact file is not directly
> returned; model-output extraction remains an adversarial runtime risk.
>
> The thesis: authored AI skills (Claude Code skills, plugins, agent definitions) are work
> artifacts, and work-for-hire's default split is 100/0 — employer gets everything, author
> gets salary. This is a compensation and attribution layer that meters use per invocation
> and splits the metered revenue to a co-held claim. Carta for AI work artifacts. The
> marketplace angle is future optionality, not the product.
>
> What we measured (testnet, 2026-07-12): one wallet paid per model call AND per Skill
> Invocation over x402. The first instrumented payment-overhead read was ~781 ms
> (n=1, Base Sepolia testnet, play money); hosted-agent cold start was ~2.5s to
> first token in a separate measurement. Ledger (testnet USDC, play money):
> claude/plan $0.041, Skill $0.25 → Creator $0.24375 / treasury $0.00625.
>
> The aggregate testnet USDC payment to the seller `payTo` address reconciled
> on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
> they were not separate on-chain transfers.
>
> The 2026-07-15 overhead distribution is historical but not reproducible from a
> clean checkout because normalized per-call samples were not retained. Its sample
> count, p50, and p95 are quarantined from publication; see
> `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
> measurement has been run.
>
> The historical N=6 run used a modeled $1.50 acquisition cost and measured about
> $0.03 of distillation-provider cost; no acquisition payment settled. Its target
> failed the benchmark, so clone quality, fidelity defense, and break-even are
> unknown. Publication remains blocked pending a valid preregistered N=100 run.
>
> We also documented two live failure modes: 10 calls that settled then 500'd ($0.87 of
> testnet USDC play money paid,
> no refund path in x402 v1 — our bug, published), and 1 of 50 that settled on-chain yet
> returned 402 — that one caught only by cent-exact wallet reconciliation.
>
> What is unproven: that employers will buy this. We published our kill-criteria and killed
> our own education mode with arithmetic.
>
> Code (Apache-2.0): https://github.com/Aznatkoiny/skill-asset-protocol — the end-to-end
> demo runs offline with zero API keys and zero funds.

Notes on register: no adjectives doing sales work, every claim has a number, and the invalid
clone benchmark plus lack of demand evidence are volunteered before anyone finds them. On
HN the honesty ledger IS the pitch.

### First-hour comment strategy: the 5 hardest questions, with prepared answers

Post these as replies, verbatim or trimmed. Never argue tone; concede fast and link the
"What we have NOT validated" section.

**Q1. "A claim on a revenue stream — you've built something securities law exists for."**

> Mostly agreed, and it shaped the whole build order. A *transferable* fractional claim on a
> revenue stream sits squarely in securities-law territory under Howey — the Ninth Circuit's
> SEC v. Barry (2025) is on point, and uncomfortably, our own live-evolution defense
> *strengthens* the "efforts of others" prong rather than weakening it. That is why v1 claims
> are non-transferable by design: no resale, no secondary market, structured as a
> deferred-comp / license-fee instrument. We rate that route medium confidence, not a safe
> harbor — no source squarely analyzes our exact fact pattern — and one of our published
> kill-criteria is that if counsel cannot draft the actual instrument (surviving 409A,
> specifying vesting and what happens when the employee quits), the sequencing gets reworked.
> The live demo is testnet play money; nothing is being offered to anyone.

**Q2. "Why blockchain at all? Postgres and Stripe do this."**

> For the closed intra-org mode, largely yes — and our Phase 1 is deliberately an off-chain
> signed ledger, viable even if the on-chain settlement phases never ship. The chain buys
> three specific things. The payment gate: x402 is an open Linux Foundation standard
> (~75M transactions in the last 30 days) that lets any wallet — including another agent —
> pay a URL with no account, no card-on-file, no chargebacks, at sub-second settlement;
> Stripe's card-and-account rails can't do machine-to-machine 25-cent calls without an
> onboarding relationship (Stripe itself now ships an x402 integration).
> Provenance: fork ancestry lives on a neutral registry (Story Protocol) that neither
> employer nor employee administers.
>
> The aggregate testnet USDC payment to the seller `payTo` address reconciled
> on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
> they were not separate on-chain transfers.
>
> We're explicit in the docs that the idealized atomic loop does not compose
> (wrong chain, wrong token, wrong primitive) and settlement is two-leg and
> eventually consistent.

**Q3. "A skill is a markdown file. Prompts are worthless; the model does the work."**

> A skill is plaintext and trivially copyable — that's the first ADR in the repo, not a
> gotcha. We don't sell secrecy: the artifact file is not directly returned and
> model-output extraction remains an adversarial runtime risk; the host sees the Skill in
> plaintext, and in the intra-org mode the employer already possesses it. What's for sale is
> attribution and metered compensation, the way Carta doesn't make cap tables secret. On
> "worthless": some skills are — each frontier model release absorbs packaged prompting, so a
> claim on that class decays on the model-release clock, and we say skill half-life is
> unmeasured. The class worth metering is bound to live tool/data access and ongoing
> maintenance, which an output stream can't carry.

**Q4. "Anyone can distill your skill from its own outputs for pennies. Your economics are dead."**

> The historical N=6 run used a modeled $1.50 acquisition cost and measured about
> $0.03 of distillation-provider cost; no acquisition payment settled. Its target
> failed the benchmark, so clone quality, fidelity defense, and break-even are
> unknown. Publication remains blocked pending a valid preregistered N=100 run.

**Q5. "Who would actually pay for this?"**

> Honestly: unvalidated, and it's the first line of our "not validated" ledger. No LOI, no
> pilot, no pricing research. Our published kill-criterion 1 is that if no design-partner
> employer signs an LOI to co-hold a claim within the Phase-0 window, we do not build
> Phase 1 on spec. The adjacent evidence: per-call machine payments are real (x402 did ~75M
> transactions in 30 days — but that's agent-infra micropayments, not skill compensation),
> and institutions durably sharing invention proceeds with employees has precedent — Germany's
> ArbEG statutory inventor remuneration, corporate patent-award programs, university
> tech-transfer splits. The missing piece has always been the metering rail. If nobody
> signs, we stop; that's what kill-criteria are for.

Secondary flak to expect, one-line stances: "GPT Store already failed at this" → agreed,
it's our stated base rate against the marketplace bet; the marketplace is optionality, the
compensation layer is the product. "x402 volume is bots" → we cite it as evidence the rail
works, explicitly not as demand for this. "Anthropic will just ship this" → kill-criterion 7,
monitored monthly; platforms won't ship 409A-structured co-held comp instruments.

---

## 2. Demo clip script (45–60s screen recording, no voiceover, big captions)

One continuous story: read → blocked → pay → output → receipt → off-chain split credits →
thesis. Captions in a large mono face, bottom third, one sentence max. Terminal at large
font size (18pt+).
Target total: **57s**.

| # | Sec | On screen | Caption text |
|---|-----|-----------|--------------|
| 1 | 0–6 (6s) | Slow scroll of neverhandedover.com — the manifesto text, ending on the URL bar | `This manifesto is a paid API endpoint.` |
| 2 | 6–13 (7s) | Terminal: `curl -X POST https://neverhandedover.com/...` → response renders, `HTTP/1.1 402 Payment Required` highlighted | `POST without payment → HTTP 402.` |
| 3 | 13–21 (8s) | Same terminal: client retries with x402 payment; a `$0.25` testnet USDC payment line and settle confirmation appear | `Pay $0.25 — testnet USDC. Play money.` |
| 4 | 21–31 (10s) | Skill output streams into the terminal, token by token (real speed; ~2.5s pause to first token left in — it is honest and reads as live) | `The artifact file is not directly returned. Extraction risk remains.` |
| 5 | 31–40 (9s) | Browser: the transaction on sepolia.basescan.org — highlight the transfer to the payTo address, cursor circles the amount | `Every invocation is an on-chain receipt.` |
| 6 | 40–49 (9s) | BaseScan, zoomed on the aggregate testnet USDC transfer to the seller `payTo` address; then the off-chain reference-ledger Creator/treasury credits | `Seller payment on-chain. Split credits off-chain.` |
| 7 | 49–57 (8s) | Cut to black. Two lines of text, then URLs fade in: `neverhandedover.com` / `github.com/Aznatkoiny/skill-asset-protocol` | `The artifact file is not directly returned. Extraction risk remains.` (line 2, smaller: `Testnet demo. Open source, Apache-2.0.`) |

Production notes:
- No music required; if any, something metronomic and quiet.
- Shots 2–4 are one unbroken terminal take — do not cut between 402 and output; the
  no-cut is the proof.
- If the 2026-07-12 take is used, keep its ~781 ms instrumented payment beat
  (n=1, Base Sepolia testnet, play money) and the ~2.5s cold start visible. Do not
  caption it with the quarantined 2026-07-15 distribution.
- Shot 6's caption carries the compliance load with shot 3: "testnet / play money" must be
  on screen in both the payment shot and the closing card.
- Export 1080p or better; the basescan and ledger text must be legible on a phone.

---

## 3. Launch-day runbook

### Pre-flight (the night before)

- [ ] Repo: LICENSE (Apache-2.0) present, README top section = the offline e2e story,
      secrets scan clean, issues enabled.
- [ ] Fresh-machine test: `git clone` → run the e2e demo with **zero keys, zero funds** on a
      box that has never seen the project. If this fails, do not launch.
- [ ] Live check: `curl -X POST` against neverhandedover.com returns 402; a paid testnet
      invocation completes; the basescan link in the demo clip still resolves.
- [ ] Both domains (neverhandedover.com, skillassetprotocol.com) serving; site links to
      repo, kill-criteria, and the "What we have NOT validated" ledger — HN will look for
      them within minutes.
- [ ] Compliance pass on every queued post: no financial-upside or income language; "testnet
      USDC (play money)" appears wherever the $0.25 demo is mentioned.
- [ ] The 5 prepared HN answers (§1 above) open in a tab.

### Launch sequence (a Tuesday, Wednesday, or Thursday)

1. **Repo public** — first, before anything links to it. Verify the clone-and-run works
   from a logged-out browser.
2. **LinkedIn post 1** — the personal founder post. Short, evidence-first, links to site +
   repo. LinkedIn warms slowly; posting it first gives it the day to travel while HN is live.
3. **X thread** — the demo clip as the first tweet, numbers in the body, repo link at the
   end. Tag the ecosystem accounts whose infrastructure is actually in the demo (x402,
   Base, Story Protocol) — infrastructure attribution, not reach-begging.
4. **HN submission** — weekday morning US: target **8:30–10:00am ET** (peak US-audience
   window; avoids the overnight queue and Friday/weekend dead zones). Submit the URL
   (neverhandedover.com) with the chosen title; post the §1 text immediately as a first
   comment. Never ask anyone to upvote, and don't share the direct HN link asking for
   support — HN penalizes voting-ring patterns.
5. **Responding cadence** — hour 1: at the keyboard, reply to every substantive top-level
   comment within ~15 minutes, using §1 answers as the base. Hours 2–4: sweep every 30
   minutes. Rest of day: hourly. Concede valid criticism in the first sentence of the reply;
   the corpus was built for that. Do not reply to tone, only to content.
6. **End of day** — pin or link the best critical HN thread from the site/X ("the hardest
   question we got today"), and log the day-0 measurements.

### Measurement plan (what counts, what doesn't)

Track **actions, not impressions**. Log daily for the first 7 days in a dated table
appended to this file:

| Metric | Source | Why it counts |
|---|---|---|
| Demo invocations (count, unique payers) | On-chain receipts to the payTo address on Base Sepolia — the meter is its own analytics | Someone did the thing, not viewed the thing |
| Repo stars + forks + clones | GitHub insights | Developer intent |
| Inbound DMs / emails / conversations started | LinkedIn, X, email | The only path to the thing we have NOT validated: a design-partner conversation |
| Substantive HN/X critiques we couldn't answer | Manual log | Each one is a corpus defect to fix |

Explicitly **not** tracked as success: impressions, likes, follower counts, HN points after
the fact. One derived number matters most at day 7: **conversations that could become a
design-partner LOI** — because kill-criterion 1 says that if none materialize in the
Phase-0 window, we do not build Phase 1 on spec.

### Daily log (started late — see slip note)

> **Slip note (recorded 2026-07-15):** the planned Day 0 (repo flip + Post 1 together,
> Tue 07-14) did not execute as designed. Post 1 shipped Mon 07-13 with the repo still
> private — its repo link 404'd for readers from Monday until the flip on Wed 07-15. No
> pre-flight was logged and this table was not started on time; the rows below are
> reconstructed from verifiable sources, with "not logged" where nothing was recorded.
> Day 0's ~$0.328 of testnet USDC play-money gateway-debugging spend is not logged
> per-call; on-chain receipts
> are pullable from basescan retroactively. All on-chain invocations to date are our own
> wallet (self-traffic): unique external payers = 0.

| Day | Date | Demo invocations (count / unique payers) | Repo stars / forks / clones | Conversations started | Critiques we couldn't answer |
|---|---|---|---|---|---|
| — | Sun 2026-07-12 | 3 / 1 (self — first real-network run: 2 model legs + 1 Skill, $0.332 of testnet USDC play money; aggregate seller payment reconciled on-chain) | n/a (repo private) | 0 | 0 |
| 0 | Mon 07-13 | self only, ~$0.328 of testnet USDC play money (gateway debugging; not logged per-call) | n/a (repo private — Post 1 link 404) | not logged | not logged |
| 1 | Tue 07-14 | 0 | n/a (repo private) | not logged | not logged |
| 2 | Wed 2026-07-15 | Self-traffic only. The overhead batch's sample count and distribution are quarantined under the historical tombstone; separate retained events include 1 smoke, 7 pi-session calls, and 1 settled-but-rejected call. Aggregate wallet reconciliation is not normalized latency evidence. | flip today — baseline 0 / 0 / 0; first insights readable tomorrow | fill at EOD | fill at EOD |

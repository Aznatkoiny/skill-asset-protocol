# X/Twitter Launch Kit — Skill Asset Protocol

Account: @[Antony's personal handle] — posting as a founder-builder, not a brand.
Constraint: cold account, near-zero followers. Distribution comes from ecosystem
amplification and quality, not reach. Every tweet is written to survive being
screenshotted out of context.

**House rules (defects if violated):**

- Never use: earn/earnings, invest/investment, financial "return(s)", passive income, yield, APY, token sale, tradeable, "security", "get paid while you sleep".
- Frame everything as: compensation infrastructure, attribution, metering, research, testnet demo.
- The demo runs on **testnet USDC — play money**. Say so anywhere a reader might act on it.
- Numbers only from the measured runs. If we didn't measure it, we don't tweet it.
- Verify all @handles and character counts at post time. Org accounts are named, never guessed.

---

## 1. Launch thread (10 tweets)

**1/**
We published a manifesto that is also a paid API.

POST to it without paying and you get HTTP 402.

Pay $0.25 in testnet USDC (play money) and it runs the skill and sends back the output. You never get the skill.

https://neverhandedover.com

**2/**
The thesis: AI Skills — the Claude Code skills, plugins, and agents people are authoring right now — are assets.

Work-for-hire's default is 100/0. Employer gets everything. Author gets salary.

Nobody negotiated that. It's just the default.

**3/**
Skill Asset Protocol meters use per Invocation and splits revenue to a claim co-held by author and org.

Carta for AI work artifacts.

The compensation and attribution layer is the product. A marketplace is future optionality, not the point.

**4/**
Receipts from the live demo (Base Sepolia, 2026-07-12 — testnet, play money):

One wallet paid per model call AND per Skill Invocation, over x402.

claude/plan $0.041 · Skill $0.25 → Creator $0.24375 / treasury $0.00625
(testnet USDC, play money)

The aggregate testnet USDC payment to the seller `payTo` address reconciled
on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
they were not separate on-chain transfers.

**5/**
The 2026-07-15 overhead distribution is historical but not reproducible from a
clean checkout because normalized per-call samples were not retained. Its sample
count, p50, and p95 are quarantined from publication; see
`spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
measurement has been run.

The hosted-agent cold start was ~2.5s to first token in a separate n=3
measurement.

**6/**
The historical N=6 run used a modeled $1.50 acquisition cost and measured about
$0.03 of distillation-provider cost; no acquisition payment settled. Its target
failed the benchmark, so clone quality, fidelity defense, and break-even are
unknown. Publication remains blocked pending a valid preregistered N=100 run.

**7/**
We published kill-criteria before launch and already used them on ourselves.

Our education mode died by arithmetic: free re-authoring dominates every royalty rate we modeled. So we killed it and published the math.

**8/**
There is a page on neverhandedover.com titled "What we have NOT validated."

The biggest entry: whether employers will buy this. We don't know yet.

It sits in writing, next to the claims we can back.

**9/**
None of this is built on hope. It's built on rails that already move volume:

· x402 — a Linux Foundation standard, ~75M transactions in the last 30 days
· Story Protocol for provenance
· Runs on Base

**10/**
Everything is open source, Apache-2.0:
github.com/Aznatkoiny/skill-asset-protocol

The manifesto that charges a testnet quarter (play money):
https://neverhandedover.com

If you author skills, this is about who gets credited and compensated for them.

---

## 2. Clone-attack thread — publication blocked

> **PUBLICATION BLOCKED — INVALID BENCHMARK.** The 2026-07-12 target scored
> 0.400 and failed its own critical gates, so clone-quality, fidelity-defense, and
> break-even conclusions are suppressed. Acquisition was modeled at $1.50; no
> x402 acquisition payments settled. Unblock only after
> `spikes/clone-economics` produces a valid N=100 result with committed normalized
> evidence and three live-adapter-confirmed independent distillation seeds.

The historical N=6 run used a modeled $1.50 acquisition cost and measured about
$0.03 of distillation-provider cost; no acquisition payment settled. Its target
failed the benchmark, so clone quality, fidelity defense, and break-even are
unknown. Publication remains blocked pending a valid preregistered N=100 run.

---

## 3. How-it-works thread (8 tweets, technical)

**1/**
How do you make a manifesto charge for POST requests?

The full x402 flow behind https://neverhandedover.com, with measured latency, in one thread. For people building agent payments.

**2/**
Step 1 — the refusal.

Client POSTs with no payment. Server answers HTTP 402 Payment Required, with the terms in the response: $0.25 USDC on Base Sepolia (testnet — play money) and the address to pay.

The status code finally has a job.

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

**6/**
Step 5 — output only.

The server runs the hosted skill and sends back the result. The skill artifact never crosses the wire.

That's the design constraint the whole protocol hangs on: metered use, never handover.

**7/**
The Wielder is the wallet plus paying client proxy. The Collar is seller-side: it
holds the platform key, enforces the payment gate, runs the hosted Skill, and
writes the seller ledger. The demo's Wielder ledger is a receipt view, not the
authoritative compensation ledger.

**8/**
The first instrumented payment-overhead read was ~781 ms (n=1, 2026-07-12;
Base Sepolia testnet, play money). Cold start was ~2.5s to first token in a
separate n=3 measurement.

The 2026-07-15 overhead distribution is historical but not reproducible from a
clean checkout because normalized per-call samples were not retained. Its sample
count, p50, and p95 are quarantined from publication; see
`spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
measurement has been run.

The aggregate testnet USDC payment to the seller `payTo` address reconciled
on-chain. The Creator/treasury amounts were off-chain reference-ledger credits;
they were not separate on-chain transfers.

Code, Apache-2.0:
github.com/Aznatkoiny/skill-asset-protocol

---

## 4. Engagement playbook — the cold-start two weeks

**The premise.** A cold account broadcasting threads is a radio tower with no power.
For the first two weeks, the account exists in other people's replies. Broadcasting
starts only after the account has a visible track record of showing up with numbers.
Amplification will come from ecosystem accounts and builders quoting the work —
that only happens if they've seen the name before launch day.

### Week 1 — reply only. Post nothing original.

Daily routine, 30–45 minutes:

1. Work through saved searches (below). Find 3–5 conversations where we have something measured to add.
2. Write replies that answer the actual question with a number or a receipt. No links to our stuff unless someone asks or the link is literally the answer.
3. Follow the people whose threads were worth replying to. Builders, not brands.
4. Log which conversations got traction in a scratch file — those communities get the launch-thread reply-tags later.

**Where the conversations are (saved searches to build):**

- **x402 ecosystem** — searches: "x402", "HTTP 402", "402 Payment Required", "facilitator". This is the home crowd; the how-it-works thread is written for them.
- **Base builders** — searches: "Base Sepolia", "onchain agents", Base ecosystem
  hashtags. They care about the aggregate seller `payTo` transfer reconciling
  on-chain while Creator/treasury credits remain off-chain.
- **Story Protocol / provenance** — searches: "Story Protocol", "IP provenance", "attribution onchain". They care about the authorship thesis.
- **Claude Code community** — searches: "Claude Code skills", "Claude plugins", "agent skills". These are the authors the protocol exists for. This is the most important room.
- **Agent-payments discourse** — searches: "agents paying agents", "agentic payments", "machine-to-machine payments", "pay per call". Broadest, noisiest; only reply where we have a measurement.

**What a high-value reply looks like.** Three rules: bring a receipt, answer the
question asked, never pitch.

Good (someone asks whether x402 latency is workable):
> The 2026-07-15 overhead distribution is historical but not reproducible from a
> clean checkout because normalized per-call samples were not retained. Its sample
> count, p50, and p95 are quarantined from publication; see
> `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
> measurement has been run.

Good (someone claims per-call pricing stops people cloning your agent):
> The historical N=6 run used a modeled $1.50 acquisition cost and measured about
> $0.03 of distillation-provider cost; no acquisition payment settled. Its target
> failed the benchmark, so clone quality, fidelity defense, and break-even are
> unknown. Publication remains blocked pending a valid preregistered N=100 run.

Good (Claude Code author asks who owns the skills they write at work):
> Under standard work-for-hire, the default is 100/0 — employer gets the artifact, author gets salary. We've been building infrastructure to meter use and split per invocation instead. Happy to share the numbers if useful.

Bad (any variation of): "Great point! We're building exactly this — check out [link]." Zero of these, ever.

### Week 2 — build-in-public, one artifact per day, keep replying.

Single tweets, not threads. One screenshot-sized artifact per day:

- Day 8: screenshot of the raw HTTP 402 response from the manifesto endpoint.
- Day 9: the ledger line — claude/plan $0.041 · Skill $0.25 → Creator $0.24375 /
  treasury $0.00625 (testnet USDC, play money). The aggregate testnet USDC
  payment to the seller `payTo` address reconciled on-chain. The Creator/treasury
  amounts were off-chain reference-ledger credits; they were not separate
  on-chain transfers.
- Day 10: the "What we have NOT validated" page, screenshotted.
- Day 11: the kill-criteria arithmetic that killed our education mode.
- Day 12: the ~150-line Wielder proxy, as a code screenshot.
- Day 13–14: rest the feed; replies only. Launch thread ships when the demo receipts are final.

**New artifacts (added 2026-07-15; slots per the revamped calendar in `2026-07-13-campaign-plan.md` §2; verify character counts at post time):**

- **Historical overhead distribution — quarantined (2026-07-15)** — artifact:
  the tombstone from `spikes/pi-wielder/README.md`.
  > The 2026-07-15 overhead distribution is historical but not reproducible from a
  > clean checkout because normalized per-call samples were not retained. Its sample
  > count, p50, and p95 are quarantined from publication; see
  > `spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json`. No replacement
  > measurement has been run.
- **The pay-then-fail receipt** — artifact: the ten-500s ledger excerpt.
  > We paid $0.87 in testnet USDC (play money) for ten HTTP 500s. Pay-first-then-run means a seller bug after settlement is the buyer's loss — x402 v1 has no refund path. Our bug, our dime. Fixed it, published the receipt. If you're building on 402 rails, design for pay-then-fail.
- **The settled-but-rejected reconciliation** — artifact: the balance-reconciliation lines.
  > 1 of 50 calls settled on-chain but the seller still answered 402 — the facilitator's reply to the seller failed mid-flight. Buyer charged, no output. We only caught it because the wallet reconciles to the cent (testnet, play money). The meter is its own audit trail.
- **The pi session ledger** — artifact: `docs/marketing/artifacts/session-ledger-render.txt` (note: the first of its 8 entries is our own pre-demo smoke test).
  > An unmodified coding agent (pi v0.80.6) paid its own way through our proxy: 7 streaming calls, $0.287 in testnet USDC (play money). One human prompt → 7 paid model turns. Flat per-call pricing meters agentic chattiness — a live datapoint we're feeding into pricing design.

Reply routine continues daily throughout. The ratio stays lopsided: for every original post, several substantive replies elsewhere.

### Launch sequencing

- **Day 0:** Launch thread. Pin it.
- **Day 0, first reply under the thread:** the ecosystem tag reply (see below).
- **Day 0, hours 1–3:** live in the replies. Every substantive response gets a substantive answer. This window decides whether the thread travels.
- **Day 2:** How-it-works thread. Quote or link the pinned launch thread from the last tweet.
- **Day 4–5:** **BLOCKED:** do not publish clone-economics copy. The N=6 target
  failed its own acceptance gate; the required valid N=100 evidence bundle does
  not exist.
- **Between threads:** the standalone tweets (section 5), one at a time, as spacers. Never two threads within 48 hours.

### Tag strategy

Tag org accounts in the **first reply** under the launch thread, not in tweet 1 —
tweet 1 stays clean for screenshots. Orgs to tag, **by name; Antony verifies every
handle at post time — do not trust autocomplete, do not invent handles:**

- x402 Foundation
- Base
- Story Protocol
- Coinbase Developer Platform

Template for the tag reply:
> Built on [x402 Foundation]'s standard, settled on [Base] testnet, provenance via [Story Protocol], developer rails from [Coinbase Developer Platform]. Demo is testnet USDC — play money. Receipts in the thread above.

Never cold-tag individuals. If an individual engaged during weeks 1–2, replying to
them or DM-ing the thread is fine; tagging strangers into a launch thread is not.

---

## 5. Standalone tweets (spacers, manifesto register)

**A.**
Work-for-hire defaults to 100/0. Not because anyone negotiated it — because nobody built the alternative.

**B.**
Most manifestos ask for your agreement. Ours asks for a quarter. (A testnet quarter. Play money.)

https://neverhandedover.com

**C.**
The historical N=6 run used a modeled $1.50 acquisition cost and measured about
$0.03 of distillation-provider cost; no acquisition payment settled. Its target
failed the benchmark, so clone quality, fidelity defense, and break-even are
unknown. Publication remains blocked pending a valid preregistered N=100 run.

**D.**
Output crosses the wire. The skill never does.

That single constraint is the whole protocol.

**E.**
The most useful page we published is the list of things we haven't proven. It's shorter than the manifesto and it was harder to write.

**F.**
We killed our own education mode with arithmetic: free re-authoring beats every royalty rate we modeled.

Publishing the math felt better than shipping the feature.

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

One wallet paid per model call AND per skill invocation, over x402.

claude/plan $0.041 · skill $0.25 → creator $0.24375 / treasury $0.00625

On-chain balances reconciled to the cent.

**5/**
The overhead of paying per call, measured across 48 settled calls:

· payment adds p50 731ms / p95 1206ms per call (n=48 settled calls)
· hosted-agent cold start: ~2.5s to first token (separate n=3 measurement)

Not free. Not prohibitive. Numbers you can build against.

**6/**
We attacked our own skill before launch.

$1.58 bought a clone distilled from its own outputs (the distillation step itself: $0.03).

The clone failed all 6 held-out fidelity gates.

Cost protects nothing. Fidelity and live evolution are the defense.

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

## 2. Clone-attack thread (7 tweets)

**1/**
We paid $1.58 to steal our own product.

Here's the experiment, the numbers, and the uncomfortable conclusion about what actually protects an AI skill.

**2/**
Setup: our skill is a paid endpoint. $0.25 per invocation in testnet USDC (play money), output only — the skill itself never crosses the wire.

The obvious attack: pay it, collect outputs, distill a clone, stop paying.

So we ran that attack against ourselves. N=6.

**3/**
The bill:

· total attack cost: $1.58
· the distillation step itself: $0.03

Three cents. The expensive part was buying our own outputs to distill from. If you think per-call pricing is a moat, that's the number that should bother you.

**4/**
The result: the clone failed all 6 held-out fidelity gates.

Every single one.

It resembled our skill the way a photo of a bridge resembles a bridge. You can look at it. You can't drive across it.

**5/**
We also modeled the case where a clone eventually passes the gates: break-even lands at 8 invocations.

Eight. If price is your only defense, anyone who can afford 8 calls can afford the attack.

**6/**
The conclusion we're publishing: cost protects nothing.

What holds up:

· fidelity — held-out gates a clone has to pass, not resemble
· live evolution — a skill that keeps changing is a moving target for distillation

**7/**
The honest caveat: N=6 is small. High-N behavior is unknown — someone patient, with hundreds of outputs, might distill a passing clone. We don't know yet.

The experiment is public so someone can prove us wrong:
github.com/Aznatkoiny/skill-asset-protocol

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
Step 2 — the signature.

The client signs an EIP-3009 transferWithAuthorization for the exact amount. Off-chain signature, no gas from the buyer, no custody handoff — just signed authorization to move $0.25 of testnet USDC.

**4/**
Step 3 — settlement.

The signed authorization goes to an x402 facilitator, which settles it on-chain. x402 is a Linux Foundation standard; the rails did ~75M transactions in the last 30 days.

We didn't build payment infrastructure. We built on it.

**5/**
Step 4 — the credential.

The settlement txHash IS the credential. The client retries the POST carrying it; the server verifies settlement on-chain and executes.

No API keys. No accounts. The receipt is the auth.

**6/**
Step 5 — output only.

The server runs the hosted skill and sends back the result. The skill artifact never crosses the wire.

That's the design constraint the whole protocol hangs on: metered use, never handover.

**7/**
All of the server side fits in a ~150-line proxy we call the Wielder: enforce 402, verify settlement, run the hosted skill, split revenue to the ledger.

150 lines, because the rails already exist.

**8/**
Measured (Base Sepolia, 2026-07-12 + 07-15, testnet):

· payment overhead p50 731ms / p95 1206ms (n=48 settled calls)
· cold start ~2.5s to first token
· $0.25/invocation → creator $0.24375 / treasury $0.00625, reconciled on-chain to the cent

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
- **Base builders** — searches: "Base Sepolia", "onchain agents", Base ecosystem hashtags. They care about the on-chain ledger reconciling to the cent.
- **Story Protocol / provenance** — searches: "Story Protocol", "IP provenance", "attribution onchain". They care about the authorship thesis.
- **Claude Code community** — searches: "Claude Code skills", "Claude plugins", "agent skills". These are the authors the protocol exists for. This is the most important room.
- **Agent-payments discourse** — searches: "agents paying agents", "agentic payments", "machine-to-machine payments", "pay per call". Broadest, noisiest; only reply where we have a measurement.

**What a high-value reply looks like.** Three rules: bring a receipt, answer the
question asked, never pitch.

Good (someone asks whether x402 latency is workable):
> We measured it across 48 settled calls on Base Sepolia: p50 731ms / p95 1206ms of payment overhead per call; cold start to first token on a hosted agent is ~2.5s (n=3). Fine for per-task pricing, painful inside a tight loop.

Good (someone claims per-call pricing stops people cloning your agent):
> We tested that against our own skill. $1.58 total to distill a clone from its outputs — the distillation step cost $0.03. The clone failed our 6 fidelity gates, but cost was never the thing protecting it. N=6, so high-N is still an open question.

Good (Claude Code author asks who owns the skills they write at work):
> Under standard work-for-hire, the default is 100/0 — employer gets the artifact, author gets salary. We've been building infrastructure to meter use and split per invocation instead. Happy to share the numbers if useful.

Bad (any variation of): "Great point! We're building exactly this — check out [link]." Zero of these, ever.

### Week 2 — build-in-public, one artifact per day, keep replying.

Single tweets, not threads. One screenshot-sized artifact per day:

- Day 8: screenshot of the raw HTTP 402 response from the manifesto endpoint.
- Day 9: the ledger line — claude/plan $0.041 · skill $0.25 → creator $0.24375 / treasury $0.00625 — with the note that it reconciled on-chain to the cent (testnet, play money).
- Day 10: the "What we have NOT validated" page, screenshotted.
- Day 11: the kill-criteria arithmetic that killed our education mode.
- Day 12: the ~150-line Wielder proxy, as a code screenshot.
- Day 13–14: rest the feed; replies only. Launch thread ships when the demo receipts are final.

**New artifacts (added 2026-07-15; slots per the revamped calendar in `2026-07-13-campaign-plan.md` §2; verify character counts at post time):**

- **The n=48 overhead distribution** — artifact: the distribution decomposition from `spikes/pi-wielder/README.md`.
  > x402 payment overhead, measured across 48 settled calls on Base Sepolia (testnet, play money), two model providers, real facilitator: p50 731ms · p95 1206ms. The facilitator verify+settle leg is the whole story (p50 729ms); the 402 roundtrip + signature add ~2ms. Wallet reconciled on-chain to the cent.
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
- **Day 4–5:** Clone-attack thread.
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
We paid $1.58 to clone our own skill. The clone failed all 6 fidelity gates.

Cost protects nothing. Fidelity and live evolution do.

**D.**
Output crosses the wire. The skill never does.

That single constraint is the whole protocol.

**E.**
The most useful page we published is the list of things we haven't proven. It's shorter than the manifesto and it was harder to write.

**F.**
We killed our own education mode with arithmetic: free re-authoring beats every royalty rate we modeled.

Publishing the math felt better than shipping the feature.

# LinkedIn Launch Series — Antony Zaki (personal account)

Five posts for the launch of the Skill Asset Protocol / neverhandedover.com.

**Rules baked into every post below:**
- Posts 1–3 contain zero crypto vocabulary; "a public test network" is the ceiling. Posts 4–5 may name x402 / testnet USDC / Base Sepolia because their audience is technical.
- Banned everywhere (compliance): earn/earnings, invest/investment, returns, passive income, yield, APY, token sale, tradeable, security, "get paid while you sleep." Framing is always: compensation infrastructure, attribution, metering, research, testnet demo.
- The demo is play money and is described as such anywhere a reader might act.
- Links go in the first comment (LinkedIn suppresses reach on posts with external links in the body).

---

## Post 1 — Launch: "Never handed over"

**Target audience:** the full network, with the hook aimed at VP Eng / Head of Platform at 100–800-person AI-forward firms.

### Post text

> Your best engineers are turning their expertise into AI skills right now. Claude Code skills, plugins, agent definitions.
>
> Then they hand them over. All of it.
>
> Work-for-hire has one default: the employer gets 100%, the author gets 0% plus salary. That was a tolerable deal when the work product was code that needed its author around to maintain it.
>
> An authored skill is different. It IS the expertise, packaged to run without the person. The better your people are at encoding what they know, the faster they automate away their own leverage.
>
> Nobody planned this. It's just the default, and defaults win when nobody is looking.
>
> I've spent the last months building the alternative: infrastructure that meters each use of a skill and splits the revenue to a claim the author holds jointly with the employer. Think Carta, but for AI work artifacts.
>
> It's live at neverhandedover.com, and the site is the demo. Reading is free.
> Running the hosted Skill costs a quarter in play money on a public test network
> — the artifact file is not directly returned; model-output extraction remains
> an adversarial runtime risk. That boundary is the architecture.
>
> What I have not proven: that employers will buy this. That's written on the site too, because a launch post that only lists what works is an ad, not evidence.
>
> If you run engineering or platform at a company where skills are becoming the work product, I want to hear how you're handling this. Link in the first comment.

### First comment

> The manifesto (it answers with a live meter, not a landing page): https://neverhandedover.com
>
> Everything is open source, Apache-2.0 — including what we have NOT validated: https://github.com/Aznatkoiny/skill-asset-protocol

### Posting context

Launch day, Tuesday–Thursday ~8:30am ET; pin to profile and leave it pinned through the series.

---

## Post 2 — Clone-economics benchmark: publication blocked

> **PUBLICATION BLOCKED — INVALID BENCHMARK.** The 2026-07-12 target scored
> 0.400 and failed its own critical gates, so clone quality, resistance to output imitation, and
> break-even conclusions are suppressed. Acquisition was modeled at $1.50; no
> x402 acquisition payments settled. Unblock only after
> `spikes/clone-economics` produces a valid N=100 result with committed normalized
> evidence and three live-adapter-confirmed independent distillation seeds.

**Target audience:** business readers broadly — the moat lesson travels beyond the ICP.

### Post text

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

### First comment

> The clone-attack harness, historical numbers, and invalid benchmark target are in the open-source repo: https://github.com/Aznatkoiny/skill-asset-protocol
>
> The hosted Skill used by the pilot is live (testnet, play money): https://neverhandedover.com

### Posting context

Do not publish until the gate above is satisfied and a human approves revised copy.

---

## Post 3 — The retention angle: a compensation instrument, not a marketplace

**Target audience:** the ICP directly — VP Eng / Head of Platform, co-read by Head of People and the CFO.

### Post text

> A retention question for engineering leaders: what happens to your best platform engineer's leverage the day after she ships the skill that automates her specialty?
>
> Under standard employment terms, the answer is: it transfers to you, completely, and she knows it.
>
> This is new. When the work product was a codebase, the author stayed valuable because the codebase needed her. An authored AI skill is designed not to need her. She built it; it runs without her; her comp doesn't change; her bargaining position gets worse with every improvement she ships.
>
> Rational people respond to that. They hold back the last 20%. They build the good version on the side. They leave and productize it. You have probably seen at least one of these already.
>
> Here's the thing: companies already know how to handle "employee creates durable value, company owns it." Germany has had statutory inventor remuneration for decades — employees are compensated by law when the employer uses their patent. Most large R&D shops run patent-award programs. Universities split tech-transfer proceeds with faculty. Nobody calls any of that radical.
>
> Skills have no equivalent, because there was no meter. You can't compensate per use if you can't count uses.
>
> That's what I built: metering for authored skills, plus a claim on each use that the author and the employer hold jointly. Not equity, not a bonus pool — a per-use compensation instrument, non-transferable by design, with an auditable count behind it. To the CFO it's deferred comp with a usage meter, and it costs nothing until the skill is actually used.
>
> Full honesty: no employer has signed yet. Whether companies will restructure work-for-hire terms this way is the open question, and it's listed as exactly that in our docs.
>
> I'm looking for 3–5 design partners — AI-forward firms, roughly 100–800 people, where skills are already the work product — to find out together. If that's you, or your Head of Platform, my DMs are open. Details in the first comment.

### First comment

> How the co-held claim and the meter work, including everything still unproven: https://neverhandedover.com
>
> If a design-partner conversation is easier over email: zaki.antony@gmail.com

### Posting context

Week 2, Tuesday morning; the post to reshare directly to specific VP Eng / Head of People contacts with a one-line personal note.

---

## Post 4 — The honesty post: kill-criteria and a feature killed by arithmetic

**Target audience:** founders, operators, and the diligence-minded — the credibility post that makes Posts 1–3 believable.

### Post text

> Two weeks before launch, we killed one of our three product modes. With arithmetic. In public.
>
> The mode was Education: a school authors a base skill, a student forks it into their own version, and a share of each use flows back to the school. Three-sided, elegant, everyone loved it on the whiteboard.
>
> Then we ran the adversarial branch we had been avoiding: what if the student doesn't fork the school's skill, and instead re-authors an equivalent one using what the class taught?
>
> Re-authoring is nearly free. So it dominates forking at EVERY royalty rate. Set the rate high and nobody forks; set it low and there's nothing to flow back. No number makes the mode work. The whiteboard was wrong, and one page of arithmetic proved it.
>
> So we deferred the mode and published the reasoning.
>
> The repo ships two documents I wish more launches included:
>
> 1. Kill-criteria. Falsifiable conditions under which we stop or restructure — including "no employer signs within the validation window" and "a platform ships this natively." Written down before launch, so we can't move the goalposts after.
>
> 2. A "What we have NOT validated" ledger. The biggest entry: we have not validated that employers will buy this. That is the load-bearing assumption of the whole company, and today it is an assumption.
>
> Why publish any of this? Not virtue. Selection. The design partners we want are the ones who read a list of open risks and lean in — they evaluate infrastructure for a living, and they know a pitch with no listed failure modes is hiding them.
>
> Also: a team that kills its own feature with arithmetic before launch is a team that won't ship you a fantasy after you've signed.
>
> Both documents are in the open-source repo. First comment.

### First comment

> Kill-criteria and the "What we have NOT validated" ledger, verbatim: https://github.com/Aznatkoiny/skill-asset-protocol
>
> The thing they're keeping honest: https://neverhandedover.com

### Posting context

Week 2–3, mid-week; resonates with founders and diligence-minded operators, so it's the one to let sit and compound rather than push.

---

## Post 5 — The build story: research → adversarial review → live endpoint

**Target audience:** engineering leaders; the technical-credibility post, and the only one that names the rails.

### Post text

> How we went from research question to a live paid endpoint — in three phases.
>
> The question: if authored AI Skills are assets, can you meter their use and split
> compensation per Invocation while not directly returning the artifact file and
> treating model-output extraction as an adversarial runtime risk?
>
> Phase 1 — research. Before product code, a findings document: what's real, what's vapor, what's unmeasured. x402, the HTTP 402 payment standard now under the Linux Foundation, turned out to be very real — ~75M transactions in the last 30 days. Story Protocol handles provenance. Several things we assumed were solved were not, and we wrote that down too.
>
> Phase 2 — adversarial review. We red-teamed our own PRD. This is where the Education mode died (free re-authoring beats every royalty rate — one page of arithmetic) and where the kill-criteria were written. The red-team output ships in the repo as a first-class artifact, not a postmortem.
>
> Phase 3 — the live endpoint. The manifesto site IS the system. POST without
> payment and you get an actual HTTP 402. Pay $0.25 in testnet USDC — play money,
> deliberately — and the hosted Skill runs and streams you the output. The
> artifact file is not directly returned; model-output extraction remains an
> adversarial runtime risk.
>
> Numbers from the first working demo on Base Sepolia (2026-07-12; testnet,
> play money), one wallet paying per model call AND per Skill Invocation:
>
> — Ledger (testnet USDC, play money): $0.041 for the model's planning call,
> $0.25 for the Skill Invocation
> — First instrumented payment-overhead read: ~781 ms (n=1, 2026-07-12;
> Base Sepolia testnet, play money)
> — Hosted-agent cold start: ~2.5s to first token
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
> Everything is Apache-2.0: the collar that holds the sole API key, the metering ledger, the clone-attack harness we ran against ourselves, the kill-criteria, the not-validated list.
>
> What's not proven: that anyone will buy it. The engineering works; the market is the experiment. If you want to poke at either, repo and live endpoint in the first comment.

### First comment

> Code, findings, red-team artifacts, clone harness (Apache-2.0): https://github.com/Aznatkoiny/skill-asset-protocol
>
> The live endpoint — bring play money only, it's a public test network: https://neverhandedover.com

### Posting context

Thursday morning at the end of launch week or early week 2; the post to cross-link from the repo README and any HN/X discussion, since it's the one technical readers will arrive at.

# Product onboarding, retention, and monetization recommendations

**Status:** Superseded for v1 on 2026-08-02
**Reviewed:** 2026-07-25
**Scope:** Repository, public site, offline proofs, accepted ADRs, and current market
benchmarks

> **Historical product research.** The employer attribution, governance, and
> reward program below is not the current v1 product or homepage direction. The
> approved v1 is the customer-hosted, wallet-native **Agent Spend Control
> Plane**, centered on a **Wallet Kernel** for x402 spending policy, exact human
> approval, signed receipts, and reconciliation. Skill attribution and Creator
> compensation are deferred expansion modules that may later consume Wallet
> Kernel receipts. See the
> [approved spend-control design](superpowers/specs/2026-07-31-agent-spend-control-plane-design.md).
>
> This document remains useful as a hypothesis ledger for that deferred
> expansion. Its buyer, pricing, roadmap, and homepage recommendations are not
> implementation commitments for v1.

## Superseded executive recommendation

Make the closed-mode product a **B2B attribution and compensation control plane for
employee-authored AI Skills**:

> Measure which reusable AI Skills create value inside an organization, preserve who
> created and maintains them, and turn trusted evidence into fair, configurable rewards.

The employer is the buyer. The employee-Creator is the emotional center. The Wielder
should keep using the tools they already use.

Monetize the control plane with an annual employer-paid program license, paid
implementation, and enterprise add-ons. Pass internal creator rewards through at 100%.
Keep x402, Story provenance, and external revenue sharing as optional infrastructure,
not as the first product or the primary source of revenue.

The immediate goal should be **three paid design-partner pilots**, not more protocol
surface area.

### The five decisions to make now

1. **Fund internal compensation with an employer-controlled periodic reward pool.**
   Invocation and outcome data should influence awards, but raw call count should not be
   the payout formula.
2. **Lead the product and site with the employer outcome.** Move the manifesto and
   testnet wallet proof to an evidence path.
3. **Offer a no-wallet, no-key sandbox that demonstrates the full loop:** import a Skill,
   record use by a second person, preview attribution, and close a reward period.
4. **Build the signed ledger, policy engine, creator portfolio, and monthly close before
   on-chain settlement or a marketplace.**
5. **Charge for the program, not participation or creator earnings.** Favor a platform
   fee per program or business unit, with generous included event volume.

## What is already strong

The project has unusually good foundations for an early research repository:

- It labels evidence as measured, modeled, or hypothesis and states plainly that employer
  demand is unvalidated ([root README](../README.md)).
- It has already made the correct strategic reframe: the closed compensation layer is
  the terminal product, while the marketplace is optional
  ([ADR-0007](adr/0007-closed-mode-compensation-layer-as-terminal-product.md)).
- It proves the thin payer, settlement arithmetic, provenance graph, and clone-economics
  questions with executable artifacts.
- The Pi-Wielder proof has a clear architecture and runbook
  ([Pi-Wielder README](../spikes/pi-wielder/README.md)).
- The offline clone and fork-economics paths run successfully without credentials. In
  this review, they passed 97 checks and 64 invariants respectively.
- The corpus records uncomfortable findings—paid failures, clone economics, context loss,
  securities exposure, and the Education bypass—instead of hiding them.

These are credibility assets. The next step is to organize them around a customer journey
rather than asking every newcomer to reconstruct the product thesis from the research
corpus.

## The core product gap

The accepted product direction, public experience, and funding model do not yet agree.

| Question | Current answer | Recommended answer |
|---|---|---|
| What is the product? | ADR-0007 says intra-org compensation; the site presents a sovereignty manifesto and a paid hosted Skill. | An employer-funded Skill attribution, governance, and reward program. |
| Who buys? | Not shown. The site speaks to an unspecified wallet holder. | Head of AI Platform / DevEx, with Total Rewards or IP Operations as co-owner. |
| Who receives value? | A one-time Wielder receives one output and receipt. | Admins get portfolio governance; Creators get durable evidence and rewards; Wielders get approved Skills in existing tools. |
| Where does compensation come from? | [CONTEXT.md](../CONTEXT.md) says intra-org upside comes from external Wielders, while the marketplace may never ship. | The employer funds an internal pool; genuine external revenue uses a separate revenue-share policy. |
| What is the billable product? | A 2.5% treasury split on a $0.25 Invocation in the demo. | Annual software license plus implementation and enterprise add-ons. |
| What makes users return? | No persistent account, history, catalog, dashboard, close, or notification loop. | Adoption, feedback, maintenance, monthly reward close, and audit loops. |

The funding contradiction is the most important product decision. A terminal intra-org
product cannot require a future external marketplace to produce the employee benefit it
promises.

## Recommended product contract

### Initial customer profile

Treat this as a hypothesis to validate, not a settled market fact:

- An AI-forward software, professional-services, or knowledge-work company.
- Roughly 100–2,000 employees, large enough to have reusable internal AI artifacts but
  small enough to run a design-partner program without a multi-year transformation.
- A centralized AI platform, developer-productivity, or automation team.
- A growing inventory of prompts, Skills, agents, plugins, or workflow automations.
- An existing innovation award, inventor award, bonus, or employee-recognition budget is
  a strong qualification signal.

The ideal buying group is:

| Role | Job to be done |
|---|---|
| Head of AI Platform / DevEx | Find, govern, distribute, and measure reusable AI Skills. |
| VP Engineering / CIO | Show AI productivity and retain high-leverage contributors. |
| Total Rewards / People | Run a consistent, budgeted creator-recognition program. |
| Legal / IP / Finance | Approve ownership, departure, dispute, and payout rules. |
| Employee-Creator | Prove authorship and impact; receive recognition or compensation. |
| Employee-Wielder | Use approved Skills with almost no new workflow. |

The creator is the beneficiary of the promise, but the employer has the budget and the
administrative problem.

### The minimum durable workflow

```text
Import → verify authorship → publish internally → use in existing tools
      → collect outcome evidence → review attribution → close reward period
      → notify Creator → improve/version Skill → more trusted reuse
```

The Phase-1 product should include:

1. **Organization workspace**
   - Organization, user, team, and role model.
   - SSO or directory identity for enterprise deployments.
   - Admin, policy reviewer, Creator, and viewer permissions.

2. **Skill registry**
   - Import from GitHub or a supported Skill directory.
   - Canonical Skill ID, version hash, Creator, co-Creators, maintainer, status, and
     lineage.
   - Review, approve, deprecate, transfer maintainership, and archive flows.
   - Searchable internal catalog with install or usage instructions.

3. **Organization-native meter**
   - Adapters for the customer's existing model gateway, agent runtime, or CLI.
   - No individual wallet for internal use.
   - Customer-hosted or VPC execution when repository or tool context is required.
   - x402 only at the external payment edge.

4. **Signed evidence ledger**
   - Durable, idempotent Invocation records.
   - Organization, Skill and version, Creator policy, Wielder or service identity,
     timestamp, success, latency, cost, outcome signal, source, and adjustment status.
   - Append-only policy and attribution history.
   - No raw prompt or output storage by default; support redaction, hashing, retention
     limits, and customer-controlled storage.

5. **Reward policy and close**
   - Fixed employer budget by month or quarter.
   - Configurable weights, caps, eligibility, vesting, clawback, termination, and
     co-authorship.
   - Provisional allocation, anomaly review, manager/HR approval, dispute workflow, and
     CSV/payroll export.
   - Plain-language creator statement explaining why an award was calculated.

6. **Creator and admin views**
   - Creator: adoption, repeat users, teams reached, feedback, versions, maintenance
     alerts, and provisional reward.
   - Admin: active portfolio, duplication, failures, outcome evidence, budget, policy,
     pending approvals, and audit export.

ADR-0007 already identifies vesting, clawback, and termination as first-class design
inputs. They should be part of the core domain model, not postponed until a marketplace.

## Resolve compensation without rewarding spam

Use an Invocation as an evidence event, not as a dollar counter.

The repository measured one human prompt producing seven paid agent turns
([Pi-Wielder results](../spikes/pi-wielder/README.md#measured-results--overhead-distribution--live-pi-session-2026-07-15)).
A literal per-call reward therefore favors chatty runtimes, creates unpredictable employer
cost, and is easy to game.

For internal use:

1. The employer commits a fixed reward budget for a period.
2. Successful uses create provisional evidence points.
3. The policy weights signals such as unique Wielders, second-team adoption, repeat use,
   accepted output, a linked downstream artifact, quality, and maintenance.
4. Caps and anomaly detection limit loops, retries, self-use, and synthetic traffic.
5. An authorized reviewer approves the close.
6. Payroll or the employer's reward system delivers the award.

For genuine external revenue, a separate policy can split actual collected revenue. Do
not mix an internal recognition award and an external royalty into one unexplained
balance.

This keeps the premise—Creators retain an economic claim on reuse—while making the
closed-mode product viable without a public marketplace.

## Onboarding review and enhancements

### 1. Align the first 15 seconds with the accepted product

The public site currently asks a visitor to absorb ten manifesto principles before the
interactive proof and then presents a wallet, faucet, and testnet payment flow
([site content](../site/app/content.ts),
[manifesto UI](../site/app/manifesto.tsx)). That is memorable brand work, but it does not
explain the employer workflow in ADR-0007.

Recommended homepage hierarchy:

1. **Outcome:** “Measure and reward the people who build the AI workflows your company
   reuses.”
2. **Proof:** a three-panel view of a registered Skill, verified team use, and creator
   award statement.
3. **Role paths:**
   - Employer: “Run a design-partner pilot.”
   - Creator: “See what your Skill portfolio could look like.”
   - Platform team: “Inspect the meter and event schema.”
4. **No-wallet interactive sandbox.**
5. **Technical receipts and manifesto.**

Keep “Never Handed Over” as a strong campaign or evidence page. It should not carry the
entire product onboarding job.

### 2. Replace the first paid experience with a truthful free one

At the time of this review, the public Skill promised to inspect a repository
and resolve actual files, patterns, and verification commands, while the hosted
API sent only text and no repository, files, search tools, or execution tools.
That mismatched paid endpoint was retired from the website on 2026-08-02; this
observation remains here as the rationale.

That means the paid first experience cannot reliably fulfill the Skill's defining
contract.

Choose one:

- Use a genuinely stateless demonstration Skill that is valuable from pasted input alone;
  or
- Let the user connect a repository or use a preloaded sample repository, and execute with
  the tools the Skill requires.

The recommended sandbox should use a seeded fictional company:

1. Choose or import a sample Skill.
2. Confirm its Creator and version.
3. Simulate use by three teammates.
4. Mark one result as accepted and link one sample pull request.
5. Show the creator-impact view and reward preview.

Only after that should an interested technical evaluator opt into the wallet/testnet
protocol proof.

### 3. Give each persona a first-five-minutes path

| Persona | First success | Target |
|---|---|---|
| Buyer | Completes the sandbox and sees a sample monthly close. | Under 3 minutes |
| Organization admin | Imports one Skill, sets a sample policy, and records use by a second person. | Under 10 minutes |
| Creator | Claims authorship and sees one attributed use and reward explanation. | Under 5 minutes |
| Technical evaluator | Runs every offline proof from one root command. | Under 5 minutes after install |
| Contributor | Finds current architecture, roadmap, issues, and verification commands. | Under 10 minutes |

### 4. Create a repository-wide paved road

The root currently has no workspace manifest, pinned Node version, CI workflow, or single
verification command. The four proofs require directory hopping, and
[`site/README.md`](../site/README.md) is still the generated Next.js starter text. The
site has required environment variables but no committed `.env.example`.

Recommended repository changes:

- Add pinned Node/npm versions.
- Add root commands such as `bootstrap`, `verify`, `demo:offline`, and `site:mock`.
- Use `npm ci` consistently where a lockfile exists.
- Add `site/.env.example` and a zero-key `dev:mock` mode.
- Add CI for offline proofs, Phase 0 tests/typecheck, and site lint/build/tests.
- Replace the deliberately failing `prototype` test script.
- Print an expected success transcript and elapsed time.
- Add `docs/START_HERE.md`, `docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, and
  `CONTRIBUTING.md`.
- Publish sanitized product requirements instead of repeatedly referring contributors to
  an unpublished PRD.

### 5. Make paid failures explicit and recoverable

The repository measured paid upstream failures and a settled-but-rejected
payment with no output. At the time of this review, the hosted route settled
before execution while its UI discarded some paid-failure state. The website
payment surface was retired on 2026-08-02 instead of carrying that behavior
forward.

Before encouraging repeat paid use:

- Preserve and display the receipt on every failure.
- Represent uncertain settlement as `payment_status: unknown`, not “nothing charged.”
- Add a durable idempotency key and Invocation state machine.
- Issue an automatic retry credit or refund after post-settlement failure.
- Validate configuration, input, and upstream readiness before authorization.
- Expose success rate, paid-without-output rate, refund time, and reconciliation errors.
- Do not show a declared split as if it were a completed payout. The current route settles
  to one `payTo` address and returns a static split; creator balances and reconciliation
  need their own ledger.

For future external payments, current x402 documentation also describes usage-capped and
batch-settlement schemes. Evaluate those instead of treating the prototype's v1 fixed-price
path as a permanent product constraint
([x402 seller quickstart](https://docs.x402.org/getting-started/quickstart-for-sellers)).

### 6. Add basic return actions

The current public output is ephemeral React state. Add:

- Saved Invocation and receipt history.
- Copy, download, rerun, feedback, and share actions.
- A next step after success.
- A design-partner/contact CTA.
- Funnel instrumentation from page view through repeat successful use.

## Retention: why organizations and people stay

The durable product is a set of reinforcing loops, not a payment handshake.

### Creator improvement loop

```text
Attributed use → outcome feedback → Creator sees impact → updates Skill
              → Wielders adopt the new version → more verified value
```

Build version-specific feedback, update prompts, release notes, adoption lift, and stale
dependency alerts.

### Team adoption loop

```text
One Creator publishes → teammate succeeds → internal proof spreads
                     → another team adopts → more Creators contribute
```

Build a searchable catalog, clear install instructions, featured Skills, related Skills,
team invitations, and cross-team milestones.

### Compensation ritual

```text
Monthly evidence → policy calculation → reviewer approval → creator statement
                 → reward delivered → continued contribution and maintenance
```

This is the most defensible retention loop because it becomes an operational program, not
a novelty dashboard. A monthly close, audit trail, payroll export, and dispute process make
the system costly to replace for legitimate reasons.

### Governance loop

```text
Portfolio evidence → identify valuable, duplicate, stale, or risky Skills
                   → assign action → improve portfolio quality → trust grows
```

Add owner-departure alerts, duplicate detection, deprecated-version use, policy exceptions,
and maintainership transfer.

### Return triggers

- Weekly Creator digest: new users, teams, feedback, milestone, and update prompt.
- Monthly admin impact and reward-close report.
- First-five-users and first-second-team milestones.
- Declining-success and stale-version alerts.
- New-version notification for Wielders.
- Quarterly portfolio and policy review.

Do not rely on a leaderboard alone. It will amplify popularity and gaming unless it is
quality-adjusted and reviewed.

## Metrics

### North star

Use **weekly verified uses of shared Skills in retained organizations**.

A verified use should be successful, performed by someone other than only the Creator,
and carry either an acceptance signal or a downstream outcome reference. Raw Invocation
count is a diagnostic, not the north star.

### Activation

- Visitor-to-sandbox-start and sandbox-completion rate.
- Sandbox-to-pilot-request rate.
- Time to first imported Skill.
- Time to first successful use by a second person.
- Percentage of workspaces that preview a reward policy.
- Percentage of pilot organizations activated within 14 days.

### Engagement and retention

- W1, W4, and W12 active-organization retention.
- Seven- and 28-day repeat-Wielder rate.
- Percentage of registered Skills used by at least two people and two teams.
- Verified uses per active organization.
- 30- and 90-day Skill survival.
- Monthly reward-close completion.
- Department expansion and invited-user conversion.

### Creator loop

- Active Creators per organization.
- Percentage receiving actionable feedback.
- Version update rate and adoption lift after update.
- Provisional, approved, and delivered compensation.
- Creator dashboard return rate.
- Perceived-recognition and intent-to-continue signals.

### Buyer value

- Estimated time or cost saved, with confidence level shown.
- Reward pool as a percentage of approved value.
- Duplicate or unowned Skills resolved.
- Pilot-to-paid conversion.
- Renewal and business-unit expansion.

### Reliability and trust

- Successful Invocation rate.
- Paid-without-output rate.
- Retry-credit or refund completion time.
- Ledger/payment reconciliation error rate.
- Attribution and policy dispute rate.
- p50/p95 time to first useful output.

Employee-retention impact will take months to establish. Early proxies are continued
Creator participation, update frequency, cross-team reuse, perceived recognition, and
intent-to-stay changes.

## Monetization

### Why the current take rate should not be the business

The prototype's 2.5% treasury fee yields $0.00625 on a $0.25 Invocation.

| Volume | Creator/payment volume | Protocol revenue |
|---:|---:|---:|
| 100,000 Invocations | $25,000 | $625 |
| 1,000,000 Invocations | $250,000 | $6,250 |
| 4,000,000 Invocations | $1,000,000 | $25,000 |
| 160,000,000 Invocations | $40,000,000 | $1,000,000 |

That is a poor base for enterprise implementation, security, support, and a compensation
workflow. It also creates the wrong optics: a creator-sovereignty product funds itself by
skimming creator rewards.

Payment settlement is becoming low-cost infrastructure. Coinbase currently lists its x402
facilitator at 1,000 free transactions per month and $0.001 thereafter
([official pricing](https://docs.cdp.coinbase.com/x402/core-concepts/facilitator)).
The attributed longitudinal ledger and policy workflow—not the payment handshake—must be
the premium.

### Recommended revenue model

#### 1. Annual enterprise program license

Charge the employer for:

- Skill registry and version/lineage system.
- Signed evidence ledger.
- Policy and reward-close workflow.
- Creator and administrator analytics.
- Audit, privacy, security, and export controls.

Price by program or business unit with unlimited employee participants. Include a generous
event allowance; use event overages only to cover material infrastructure cost.

This avoids penalizing adoption and matches an adjacent innovation-platform pattern.
Wazoku lists a $15,000-per-admin annual license with unlimited end users
([official pricing](https://www.wazoku.com/total-innovation-license/)).

#### 2. Paid implementation and managed program services

Offer:

- Skill inventory and data mapping.
- Event-source integration.
- Reward-policy design and workflow configuration.
- Identity, HRIS, and payroll export setup.
- Admin training and first-close support.

Wazoku separately lists enhanced onboarding at $5,450 and onboarding plus program setup at
$12,000, which supports treating implementation as real work rather than burying it in
software margin.

#### 3. Enterprise add-ons

- VPC, hybrid, or customer-managed data plane.
- SSO, SCIM, advanced RBAC, and longer audit retention.
- HRIS/payroll integrations.
- Custom policy packs and multi-jurisdiction workflows.
- SLA, premium support, and managed reconciliation.

#### 4. OEM or metering API

After the product works directly, sell the attributed meter to IP-management,
compensation, AI-gateway, or developer-platform vendors. This may become a strong channel
because those vendors already own buyer relationships but generally meter invention
milestones rather than runtime AI-asset use.

#### 5. Benchmark analytics, later

With explicit customer consent and strong aggregation thresholds, offer benchmarks for
Skill adoption, reward policy, creator concentration, maintenance, and reuse. This should
be an opt-in add-on only after enough customers make the data meaningful.

#### 6. External marketplace fee, deferred

If the product later supplies discovery, demand, collections, refunds, quality control,
and trust, test a 5–10% fee on external revenue. Do not charge that fee merely for wrapping
an endpoint in x402, and do not build tradeable claims without specialist legal advice.

### Pricing hypotheses to test

These are starting offers for design conversations, not validated prices:

| Offer | Hypothesis |
|---|---:|
| Founding design-partner pilot, 8–12 weeks | $10,000–$20,000 |
| Single-program annual license | $15,000–$30,000 |
| Multi-business-unit annual license | $40,000–$75,000 |
| Enterprise/private deployment | $75,000–$150,000+ |
| Implementation | $5,000–$15,000 |
| Managed program support | $2,000–$5,000/month |

Useful adjacent anchors as of the review date:

- AppColl lists Invention Manager at $350/month for 100 users, including award
  management, SSO, HR integration, workflows, and analytics
  ([official pricing](https://www.appcoll.com/corporation-product-pricing/)).
- Bonusly lists employee-recognition software at $30–$50 per user annually and explicitly
  separates the software subscription from rewards redeemed at face value
  ([official pricing](https://bonusly.com/pricing)).
- LangSmith combines a team subscription with metered usage and reserves hybrid,
  self-hosted, SSO, RBAC, and SLA capabilities for enterprise
  ([official pricing](https://www.langchain.com/pricing)).
- Stripe Billing lists 0.7% of billing volume or annual subscription tiers, an additional
  signal that mature metering infrastructure does not justify a 2.5% fee by itself
  ([official pricing](https://stripe.com/billing/pricing)).

These products are not exact competitors. They bound how buyers already purchase adjacent
innovation, recognition, observability, and billing workflows.

### What not to monetize first

- Do not charge Creators to register or see their own evidence.
- Do not take a percentage of an employer's internal reward pool.
- Do not make token sales or tradeable royalty claims the funding plan.
- Do not make the Education model a paid offer until its free re-authoring bypass has a
  measured counter.
- Do not rely on inference resale margin; the repository already recognizes it as
  commoditizing.

## Validation plan

### Customer discovery

Run 12–15 interviews across:

- AI Platform / Developer Productivity.
- Engineering or technology executives.
- Total Rewards / People Operations.
- IP Operations, Legal, or Finance.

Prioritize organizations that already operate an inventor, innovation, or recognition
program and already have a centralized AI gateway or internal Skill inventory.

Questions should test existing behavior, not solicit compliments:

- How are reusable AI workflows found, approved, and maintained today?
- Who gets credit when another team reuses one?
- Has lack of credit caused hoarding, duplicated work, or attrition risk?
- What budget funds inventor awards, spot bonuses, or innovation programs?
- Which evidence would make an award defensible?
- Who can approve policy and payment?
- What security or employment-law condition would stop a pilot?
- Would the company fund a pool even if no external customer ever invokes a Skill?

### Paid concierge pilot

Do not wait for a full platform:

1. Import a real Skill inventory.
2. Ingest signed or reconciled events from one existing runtime.
3. Produce creator and admin views, even if some operations are manual.
4. Run one policy preview and two monthly closes.
5. Export a payroll-ready or award-ready file.
6. Measure cross-team adoption, disputes, admin time, and Creator response.

### Decision gates

| Hypothesis | Pass signal | If it fails |
|---|---|---|
| Employers will pay for the rail. | Three pilots at $10,000 or more. | Stop protocol expansion; narrow or abandon the B2B thesis. |
| Internal compensation does not require marketplace revenue. | At least one pilot funds a real Creator pool. | Reposition as governance/analytics or target only commercialized Skills. |
| Usage evidence can approximate value. | Admins agree that the highest-scored Skills overlap materially with their independently selected high-value set. | Change signals and policy; do not automate payouts. |
| The buying group can form. | Each pilot has an AI-platform champion and a Total Rewards/IP owner. | Narrow to one buyer's problem and remove cross-functional scope. |
| Context-bound Skills can be instrumented usefully. | A meaningful share of one customer's real inventory produces reliable versioned events without losing its useful context. | Change the asset class or execution model. |
| The program creates a habit. | Two monthly closes complete and W4 verified use persists. | Diagnose workflow value before adding more integrations. |
| Annual value supports enterprise pricing. | Two pilots convert at $25,000+ ARR. | Reduce scope/cost or test an OEM model. |

These are product decision gates, not forecasts.

## Prioritized roadmap

### Now: 0–30 days

1. Write an ADR resolving the intra-org funding source and scoping “the Wielder is a
   wallet” to external payment flows.
2. Run the customer interviews and recruit paid design partners.
3. Rewrite the primary landing page around the employer outcome.
4. Add a no-wallet seeded sandbox and a clear pilot CTA.
5. Replace or properly tool-enable the current demo Skill.
6. Fix charged-failure receipt visibility and define retry-credit/refund semantics.
7. Add a root offline verification path and replace the site starter README.
8. Publish a public product overview, architecture, roadmap, and contribution path.

### Pilot: 31–90 days

1. Define the organization, Skill/version, event, policy, close, and dispute schemas.
2. Import Skills from one source and events from one real runtime.
3. Build a persistent signed ledger.
4. Deliver minimal Creator and admin views.
5. Run fixed-budget policy previews and CSV/payroll export.
6. Instrument activation, verified use, trust, and close metrics.
7. Complete the first paid pilot close.

### Productize: 91–180 days

1. Add multi-tenant workspaces, SSO, RBAC, and identity mapping.
2. Add the internal catalog, versioning, feedback, and maintainer workflows.
3. Add configurable policies, approvals, departures, and disputes.
4. Add reliability controls, idempotency, credits/refunds, and reconciliation.
5. Add weekly Creator and monthly admin return triggers.
6. Offer customer-hosted or VPC execution for context-sensitive Skills.
7. Convert pilots to annual contracts.

### Only after the gates pass

- Background or opt-in Story registration.
- Additional runtime adapters.
- OEM/API distribution.
- Opt-in benchmark analytics.
- External x402 monetization.
- Marketplace discovery or tradeable claims, subject to legal review.

### Explicitly defer

- Securities and transfer infrastructure.
- Open marketplace build-out.
- Education-mode commercialization.
- TEE investment for an unvalidated open market.
- More inference-reseller work that does not improve the attributed ledger.

## Bottom line

The premise is monetizable, but not primarily as a per-call royalty marketplace.

The commercially coherent product is the system an employer uses to answer:

- What reusable AI Skills do we have?
- Who created and maintains them?
- Which teams use them successfully?
- What value evidence can we defend?
- What policy determines recognition or compensation?
- What changed, who approved it, and what was paid?

If the project can make that monthly operating loop trustworthy and easy, the existing
wallet, provenance, and settlement work becomes valuable optional infrastructure. If it
cannot find three employers willing to pay for that loop, more protocol depth will not
solve the core problem.

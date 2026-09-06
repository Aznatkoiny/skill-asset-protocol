# Research agenda: useful work, bounded spending, earned compensation

Prepared 2026-09-06 against `4b2717b94c47151a26c8e70cbe5806aa5bfd277b` on `codex/wallet-kernel-lifecycle-qualification`. This is a proposed agenda, not experimental evidence. No model runs, payments, deployments, or outreach were performed. Primary sources were checked on this date; the literature review is bounded, not exhaustive.

## The question worth owning

**Under what conditions can an agent buy useful expertise, remain accountable to its funder, and sustain compensation for the people improving that expertise?**

This connects the archived authored-work philosophy to the current Wallet Kernel without assuming a marketplace, transferable claims, or blockchain settlement are necessary. The normative position—people should be able to negotiate participation in the value their work creates—is distinct from empirical claims about usefulness, attribution, demand, and copying. A transaction proves neither value delivered nor compensation deserved.

Repository grounding: [current product](../../README.md), [approved design](../superpowers/specs/2026-07-31-agent-spend-control-plane-design.md), [evidence precedence](../evidence-precedence.md), [archived principles](../../site/app/content.ts), and [earlier context](../../CONTEXT.md). The package now records **43/43 installed offline lifecycle checks at `3ef2dbc`**, with synthetic external providers; CDP/testnet execution remains unrun. This supports controlled experiments on authority and recovery, not demand or Skill economics. The [clone benchmark](../../spikes/clone-economics/evidence/2026-07-12-n6-invalid/manifest.json) is invalid, and [old latency aggregates](../../spikes/pi-wielder/evidence/2026-07-15-overhead/manifest.json) are quarantined. Neither supplies a prior measured effect or a reusable headline.

## Prioritized studies

### 1. When is buying a Skill better than giving the agent more compute?

**Hypothesis:** some authored Skills improve independently verified task success enough to cover their full incremental cost, including the context lost at a hosted boundary.

**Prior work / distinction:** [SkillsBench](https://arxiv.org/abs/2602.12670) already evaluates curated Skills against matched no-Skills conditions. [EcoAgent-Bench](https://arxiv.org/abs/2608.05519) already studies priced actions and budget-sensitive escalation. Our proposed contribution is the intersection: **authored capability purchased through a constrained interface, with complete cost accounting and a local-versus-hosted ablation**. Do not call generic Skill lift or budgeted tool choice new.

**Method and baselines:** start with a preregistered, stratified pilot of roughly 24 tasks with executable acceptance tests: repository work, structured document work, and a service with changing reference data. Compare no Skill, an expert-tuned free guide, the same Skill mounted locally, and that Skill accessed as an output-only service. Include a stronger-model/more-compute baseline and an oracle purchase selector. Give every arm the same total resource budget, count both buyer and seller compute, and sweep separately labeled synthetic fees. Report the joint frontier of verified success, total cost, latency, and context transferred; do not convert quality into dollars using an undisclosed reward weight.

**Falsification:** no hosted arm improves that frontier over the strongest accessible baseline; or gains exist only when private context/tools are granted that the proposed product cannot supply. A local Skill beating a base model does not rescue a hosted-service thesis.

**Publish:** “The context tax on paid agent expertise,” including negative task families and an estimated maximum affordable fee, not willingness-to-pay claims.

### 2. What does spending control cost in useful autonomy?

**Hypothesis:** durable exact authorization prevents unauthorized or duplicate payment while preserving most legitimate task completion at a useful approval burden.

**Prior work / distinction:** [AP2's authorization framework](https://ap2-protocol.org/ap2/agent_authorization/) already defines delegated mandates and constraints; [x402 v2](https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md) defines payment authorization and settlement. [AgentDojo](https://arxiv.org/abs/2406.13352) supplies a precedent for evaluating attacks alongside legitimate utility. The proposed addition is an empirical **authority–availability tradeoff across monetary crash boundaries**, not a claim to have invented agent authorization.

**Method and baselines:** replay matched legitimate requests and adversarial tool responses through prompt-only budgets, a conventional server-side quota/idempotency implementation, and Wallet Kernel. Include changed quotes, reused call IDs, repeated approvals, signer interruption, lost settlement response, settled execution failure, and stale authorization. Distinguish deterministic trace coverage from later model-driven choice. Measure unauthorized atomic units, duplicate signatures/payments, legitimate completion, unnecessary denial, approval count, unresolved capital-time, and recovery time. Also compare a centralized credit ledger under the same controls to identify which benefits require a wallet rail.

**Falsification:** one invariant-breaking trace falsifies its corresponding safety claim. Separately, a simpler quota/credit design matching safety and utility at lower operational cost weakens the product's differentiation. A system that denies everything earns no useful-autonomy result.

**Publish:** a portable fault corpus and safety/utility frontier. Keep simulated settlement, actual process lifecycle, and future externally anchored settlement results separate.

### 3. When is a clone cheaper than continued purchase—and for how long?

**Hypothesis:** a measurable subset of Skills remains cheaper to buy because reproducing and maintaining equivalent capability costs more than continued use.

**Prior work / distinction:** [Tramèr et al.](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/tramer) demonstrate model extraction through prediction APIs in their studied settings. [Gudibande et al.](https://arxiv.org/abs/2305.15717) show that persuasive imitation can fail to transfer task capability. Neither establishes today's economics for a particular Skill. Our proposed contribution is **quality-gated total replication cost under evolving tasks**, using only owned or explicitly permitted artifacts.

**Method and baselines:** first require the original to pass a frozen task-competence gate. Compare independent reimplementation from public instructions, example retrieval, prompt reconstruction from permitted outputs, and distillation at increasing acquisition budgets. Include a stronger unmodified model. Keep training/acquisition tasks separate from hidden tests; count unsuccessful attempts, development time, inference, hosting, and maintenance. Test static procedure, changing reference data, and live-access dependence separately. Freeze the model to isolate Skill updates; then change the model while holding Skill versions fixed to measure absorption. Do not attribute exclusive data access to clever prompt design.

**Falsification:** a replica passes all critical gates and a preregistered noninferiority margin at lower total cost within plausible usage/update horizons. If `N = acquisition_cost / (original_unit_cost − clone_unit_cost)` is reported, require a positive denominator, comparable quality, and explicit maintenance assumptions. Otherwise report no finite break-even, not an invented number.

**Publish:** distributions by Skill class and update cycle, including failed originals and failed clones. No universal secrecy or moat claim.

### 4. Can compensation follow contribution without rewarding artificial fragmentation?

**Hypothesis:** a contribution-sensitive payout rule can pay useful ancestors and maintainers while resisting redundant wrappers, false identities, and invocation inflation.

**Prior work / distinction:** [Data Shapley](https://proceedings.mlr.press/v97/ghorbani19c.html) evaluates training-data contribution; [Towards Replication-Robust Analytics Markets](https://arxiv.org/abs/2310.06000v4) explicitly addresses strategic replication. Transferring those ideas to interacting, stateful Skills is a research question: their assumptions and guarantees do not automatically carry over.

**Method and baselines:** build small, controlled Skill compositions with complements, substitutes, useful ancestors, and deliberately useless wrappers. Enumerate task-level interventions where feasible; otherwise sample coalitions with uncertainty. Compare fixed negotiated splits, invocation-proportional allocation, leave-one-component-out value, and a candidate marginal-contribution rule. Hold the beneficiary's total fee fixed. Add equivalent replicas and vary packaging/order; measure payout inflation, conservation, correlation with controlled incremental task value, and evaluation cost. Report any negative contribution rather than silently treating every ancestor as beneficial.

**Falsification:** an economically equivalent repackaging increases a claimant's combined payout without improving outcomes; genuinely complementary contributions are systematically missed; or measurement costs consume the available surplus. Finding a useful causal contribution does not decide the morally or contractually correct split.

**Publish:** “A receipt is not an attribution rule,” with an attack suite and explicit allocation assumptions. Compare signed database provenance with on-chain declarations before asserting a chain-specific benefit.

### 5. Does provenance guide agent purchases—or merely move the label bias?

**Hypothesis:** authenticated performance history helps budgeted buyers select reliable Skills and directs revenue toward continuing useful work, beyond branding or listing position.

**Prior work / distinction:** [Allouah et al.'s ACES study](https://arxiv.org/abs/2508.02630v3) reports model-dependent purchasing behavior, position effects, and sensitivity to endorsements. That directly challenges the assumption that agents naturally route value toward the best or original Creator. Our addition would distinguish **declared ancestry from verified task history in purchases of reproducible capability**.

**Method and baselines:** reuse the competent services from study 1. Randomize listing position, names, ancestry labels, and the visibility of genuine performance receipts independently of actual quality and price. Include anonymous offers, matched duplicates, deteriorating originals, and improved declared Derivatives. Compare model selectors with cheapest-qualified and empirical-reliability selectors. Let buyers abstain, use a free alternative, or spend elsewhere. Track verified task value per budget, revenue concentration, sensitivity to irrelevant labels, and how quickly revenue follows real maintenance improvements. Repeat across fixed model versions.

**Falsification:** provenance produces only a cosmetic premium without improved selection, repeatedly protects an inferior original, or is dominated by listing position. An autonomous selector's modeled demand is not evidence that employers will fund it or agree to royalty terms.

**Publish:** “Will agents pay the right Creator?” A negative result would favor explicit organizational agreements and transparent routing over marketplace mythology.

### 6. Which compensation arrangements will contributors and beneficiaries actually choose?

**Hypothesis:** at least one clearly specified arrangement improves contributors' willingness to share and maintain useful Skills while giving beneficiaries enough value to sustain the program.

**Method and baselines:** interview contributors and prospective funders separately, using concrete examples of work and reuse. Compare recognition alone, fixed commissioning, an employer-funded reward pool, and a negotiated share of external revenue. Keep internal reuse and external sales distinct. Record why each party accepts or rejects the terms, including maintenance obligations, portability, attribution disputes, and administrative effort. A subsequent mutually agreed pilot can observe actual participation and continued use. This is proposed human research; no participants have been contacted and no terms have been agreed.

**Falsification:** arrangements attractive to contributors are consistently unacceptable to funders, measured benefits do not justify administrative costs, or the arrangement reduces sharing and maintenance compared with a simpler baseline. Interview enthusiasm alone does not establish willingness to pay. Technical contribution estimates do not establish that participants regard a payout as legitimate.

**Publish:** a transparent account of preferences, disagreements, and observed behavior, with sampling and recruitment limitations. The existing [pilot brief](../pilots/2026-09-05-spend-control-pilot.md) addresses demand for spending controls; it does not validate demand for a separate creator-compensation program.

## First package to build and publish

Start with study 1's competent task/service set and study 2's deterministic fault corpus. The former tests whether there is surplus to govern; the latter tests the current product's ability to govern it. Only promote competent originals into study 3. Studies 4–5 should remain deferred compensation research and reuse those measured capabilities. Study 6's interview design can be prepared alongside this work; product demand and compensation legitimacy need their own evidence.

An immediate engineering article can explain what the twelve archived host qualification attempts revealed, separating application failures, host compatibility problems, and harness defects. Link the original failed attempts and the passing 43-check bundle, and state the installed offline scope. This is a retrospective engineering case study, not a benchmark of deployments in general. A second article can explain why authorization, payment, useful work, attribution, and agreed compensation are separate claims. New studies should begin with a published question and method, followed by results and corrections as evidence arrives.

Preregister task inclusion, primary endpoints, cost conventions, stopping rules, and noninferiority margins. Use paired seeds, task-clustered uncertainty, repeated runs, and strong baselines; choose final sample size from pilot variance rather than a convenient headline. Preserve task/version hashes, priced events, failed attempts, verifier outputs, and recomputation scripts. Keep held-out tests out of acquisition and tuning. Publish absolute quality alongside ratios and stratify by model and Skill class.

On the website, each study can have one clear question, the best counterargument, a stated test, and a result status. The useful philosophical promise is **to make authorship, authority, payment, and outcomes inspectable while testing whether the economics work**. “Creators deserve an agreement” is a value judgment; “our mechanism sustains their income” needs evidence. A strong research identity makes that separation visible.

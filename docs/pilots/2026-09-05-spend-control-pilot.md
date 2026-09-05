# Agent Spend Control pilot — offer and discovery brief

**Status:** Prepared for operator review on 2026-09-05. No outreach, customer
interview, price, commitment, pilot run, or customer result is recorded by this
document. Demand remains unvalidated.

**Scope authority:** the
[approved Wallet Kernel design](../superpowers/specs/2026-07-31-agent-spend-control-plane-design.md),
including its approval-flow amendment. Use the
[evidence precedence addendum](../evidence-precedence.md) to distinguish current
verification from historical results. Preparation began from repository commit
`cf7d68aa1e234c115df314555db41e4d923ef8f3`; a pilot must identify the exact
release it actually uses.

## Proposed offer

A paid, customer-hosted design-partner pilot for one Pi workflow, one
customer-owned CDP wallet, and one or more allow-listed Base Sepolia x402 v2
`exact` resource servers. The customer defines the spending limits, sellers,
and requests that require exact human approval. The pilot tests whether the
team can delegate that workflow while retaining spending control and a
verifiable record of outcomes.

Only test USDC is in scope. The Wallet Kernel, policy authority, credentials,
and authoritative records stay in the customer environment. One local
Operator applies policy, handles approvals, and initiates reconciliation.
Fee, duration, participant time, seller selection, and start date are unset;
they require an explicit scoped agreement before delivery is promised.

## Release prerequisites: #7 → #8 → #9

This brief clears no release gate. Record the evidence for each prerequisite
in order before starting a customer testnet pilot. The authorized qualification
run in #9 establishes release evidence; it is not itself a customer pilot or
demand validation.

| Gate | Required result | Evidence to review |
|---|---|---|
| [#7 — live composition](https://github.com/Aznatkoiny/skill-asset-protocol/issues/7) | Wallet Kernel live preflight, control-plane, and secret-delivery composition are implemented and verified. | Exact code revision, regression results, and composition checks. |
| [#8 — installed Linux qualification](https://github.com/Aznatkoiny/skill-asset-protocol/issues/8) | Installed startup, recovery, and cleanup pass on the required Linux/systemd host with exact Node 24.18.1. Failed starts leave the service stopped and the socket disabled. | Actual root/PID1 lifecycle evidence for the installed release. Skipped tests and mocked systemd results cannot satisfy this gate. |
| [#9 — fresh Base Sepolia evidence](https://github.com/Aznatkoiny/skill-asset-protocol/issues/9) | The authorized runner uses a customer-owned CDP testnet wallet and trusted observer, after explicit human funding and run-intent digest authorization. | A fresh immutable, recomputable, externally anchored evidence bundle for the qualified release, with normalized events and testnet labels. |

Preparation and separately authorized discovery can proceed while these gates
remain open. Customer execution requires its own approved configuration and
scope; a prior qualification run, available credentials, or this brief does
not authorize another payment. Public release remains subject to the approved
design's release boundary.

## Buyer and budget-owner hypotheses

These are hypotheses to test in discovery, not known customer roles.

| Role hypothesis | Possible responsibility | Evidence needed |
|---|---|---|
| AI platform or gateway lead | Owns a recurring workflow whose external resource purchases need controls. | A recent concrete example, current workaround, and an outcome that matters to the team. |
| Engineering or platform budget owner | Can allocate budget for the pilot and ongoing spending-control tooling. | Who makes that decision, which budget it uses, and the process for approving a scoped paid engagement. |
| Platform engineer acting as Operator | Can run the customer-hosted Kernel, set policy, review approvals, and reconcile outcomes. | A named responsible person and available operating time. |

The champion and budget owner may be the same person. Establish who owns the
workflow, who approves resource spending, and who can buy the pilot; do not
infer one authority from another.

## Discovery prompts

Use these in a separately authorized conversation. Start with existing
behavior before presenting the proposed solution.

1. Walk through the last workflow where an agent needed a paid external API
   resource. What ran, who owned it, and how was payment authorized?
2. What problem occurred, or what useful workflow was blocked? What happened
   most recently, how often does it recur, and what was the consequence?
3. How do you control sellers, spending limits, and exceptions today? Show a
   sanitized example of the workaround if available.
4. When a request times out after possible payment, how do you decide whether
   to retry and reconcile the charge? Who investigates, and how much work
   did the last investigation require?
5. Which existing controls work well enough that you would keep them? What
   specific gap would justify adding another component?
6. Who could operate a customer-hosted pilot, and who could approve paying
   for it? What evidence would each need to make that decision?
7. Is there one useful Pi workflow and an available x402 testnet seller that
   fit this scope? What would prevent testing them with a customer-owned CDP
   wallet and test USDC?
8. What measurable result would justify continuing after a pilot, and what
   result would make you stop? Agree the comparison baseline and decision
   date before claiming an improvement.

Record observed examples separately from expectations and interest. Capture
sanitized notes and source references with permission; exclude credentials,
raw prompts, and model outputs from the pilot record.

## Proposed deliverables and responsibilities

| Proposed deliverable | Project pilot lead | Customer / Operator |
|---|---|---|
| One Pi workflow connected to the qualified Wallet Kernel release | Supply the versioned package, setup guidance, and bounded integration. | Select the workflow and sellers; provide the customer host and its administrator. |
| One customer-owned CDP Base Sepolia wallet | Verify the configured wallet seam against the qualified release. | Provision and retain credentials; a human funds test USDC within the authorized run scope. |
| Customer-defined automatic, approval-required, and denied requests | Help express the chosen limits and demonstrate exact approval followed by deliberate retry. | Set the policy and spending ceilings; name the single Operator who applies policy and decides approvals. |
| Durable budgets, restart recovery, and reconciliation | Exercise the agreed allowed, denied, failure, and recovery scenarios; document gaps. | Provide operating time and initiate trusted reconciliation when required. |
| Local operator console and signed receipt/reconciliation export | Provide verification instructions and a sanitized evidence bundle. | Independently inspect receipts, held amounts, and the export against the selected workflow. |
| Final evidence and control review | Compare results with the agreed baseline and report limitations. | Have the workflow owner and budget owner decide whether to stop, revise, or continue. |

These are proposed pilot deliverables, not assertions that integration or
live qualification is complete. Mainnet, arbitrary transfers, additional
product modules, and a vendor-hosted spending authority are outside this
offer.

## Success, failure, and go/no-go decisions

**Before execution:** proceed only when #7, #8, and #9 have the required
passing evidence and the customer has identified the workflow, sellers,
Operator, budget owner, scope, commercial terms, operating time, and run
authorization. Record the decision and supporting artifacts. If prerequisites
or ownership are missing, keep the work in preparation/discovery.

**Technical success:** all mandatory design acceptance criteria apply. The
pilot must demonstrate the selected workflow, deny disallowed or over-budget
requests before signing, bind approval to the exact request, survive restart
without duplicate spending, and verify terminal receipts from a fresh process.
Execution failure must remain distinct from settlement. Ambiguous payments
retain their holds until trusted evidence resolves them; no test may invent a
refund or release uncertain funds to make the totals look complete.

**Practical success:** before the run, agree acceptable setup effort,
Operator effort, approval turnaround, and reconciliation usefulness against
the customer's current workaround. Values are unset until agreed. Record
both the baseline and observed result; missing measurements mean an outcome
is unassessed, not improved.

**Demand evidence:** a technical pass or positive feedback alone is
insufficient. Record whether the budget owner actually accepts a scoped paid
engagement or subsequent paid continuation, with the agreed terms and decision
reference. Record interest, willingness to discuss, agreement, and payment as
different outcomes. One customer's decision supports only that engagement;
it does not establish general market demand.

**Pause or stop:** pause execution on a failed control or release gate and
record the unresolved state. Stop or revise the offer if the customer has no
recurring problem, its existing controls are sufficient, no budget owner or
Operator is available, or the required workflow falls outside the approved
scope. At the final review, choose **stop**, **revise**, or **continue** with an
owner, evidence, and next decision date. A continuation never authorizes a
broader network or funding scope by implication.

## Outcome recording template

Complete one record per prospective pilot in a customer-approved location.
Link sanitized artifacts rather than copying sensitive material into Git.
Leave unknowns explicit.

```markdown
Record ID / date: unset
Stage: prepared | discovery | qualified, not run | pilot run | reviewed
Customer reference / permitted participants and roles: not collected
Workflow owner / Operator / budget owner: not established
Recent problem and source evidence: not collected
Current workaround / frequency / effort baseline: not collected
Proposed Pi workflow / allow-listed sellers: not selected
Customer host / CDP wallet reference (no credentials): not provisioned
Release commit / package digest: not selected
#7 result and evidence link: not reviewed
#8 installed-host result and evidence link: not reviewed
#9 qualification bundle and verification result: not reviewed
Proposed fee / duration / customer time: unset
Agreed terms / decision reference: none
Pilot policy/configuration digests / spending ceilings: unset
Human funding and exact run-intent authorization references: none
Agreed practical success thresholds / decision date: unset
Pilot run ID / immutable bundle / receipt verification: not run
Technical failures / held amounts / reconciliation status: not assessed
Measured practical results versus baseline: not assessed
Buyer outcome: unknown | declined | interested | scoped paid agreement | paid
Final decision: pending | stop | revise | continue
Reason / evidence / remaining uncertainty: unset
Next action / owner / date: unset
```

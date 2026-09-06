# Human Choice: agreed mission and website direction

Date: 2026-09-06. Status: the mission, hierarchy, initial research focus, and
opening website copy below were endorsed by the project owner in conversation.
The owner subsequently chose **Human Choice** as the umbrella name, explicitly
authorizing their own version after reviewing existing uses of the name. The
website architecture below is implemented as a local candidate in `site/`.

Repository reference: `4b2717b94c47151a26c8e70cbe5806aa5bfd277b`, branch
`codex/wallet-kernel-lifecycle-qualification`. This is a strategic direction
record. Technical acceptance and release remain governed by the
[approved Wallet Kernel design](../superpowers/specs/2026-07-31-agent-spend-control-plane-design.md)
and [evidence precedence](../evidence-precedence.md).

## Founding statement

> AI and automation should expand people's freedom to live lives they value.
>
> We build and study systems that increase human capability, preserve meaningful
> choice, and give people a say in how the benefits are shared.
>
> Progress means better possibilities for people—including more time, security,
> learning, creativity, and control over their lives.

Human flourishing is the purpose. Productivity is one way to support it. The
owner explicitly considers unchanged output with substantially more free time,
security, and control a success. People should have room to define a good life
for themselves; productivity is not a measure of a person's worth.

## Hierarchy for decisions

| Level | Meaning |
| --- | --- |
| Purpose | People have greater freedom to live lives they value. |
| Commitments | Capability, agency, and participation. |
| Outcomes | Changes in people's time, security, opportunities, knowledge, and control. |
| Mechanisms | Tools, agreements, payment systems, ownership arrangements, and protocols. |

**Capability** means people can accomplish more of what matters to them.
**Agency** means they can understand, direct, change, and refuse how automation
acts for them. **Participation** means they have a meaningful role in setting
terms and receiving benefits.

Ownership and compensation can support these commitments. Open sharing,
cooperation, and other arrangements may also do so. Choose mechanisms by their
effects on people and revise them when evidence warrants it. A receipt records
an event; it does not establish usefulness, a fair agreement, or human benefit.

Assess several outcomes rather than combining flourishing into one score.
Report who receives gains and who bears costs, including disagreements and
tradeoffs. Publish adverse findings and let them change the work.

## First focus and connection to the existing product

The initial research focus is **people whose expertise and daily work are being
reshaped by AI**. Investigate whether automation gives them useful capability,
recoverable time, and stronger choices, and what determines who receives those
gains.

This beneficiary focus is broader than the existing commercial buyer: an AI
platform or gateway team evaluating customer-hosted spending controls. Demand
from that buyer and benefit to affected people require separate evidence.

Wallet Kernel provides a concrete starting question:

> Can people delegate useful work to AI without taking on unacceptable financial
> risk or constant supervision?

Technical qualification establishes particular spending-control properties.
Research with people would be needed to establish practical comprehension,
oversight burden, useful delegation, and changes in their choices. Skill
experiments investigate capability; contributor compensation research
investigates participation. Each needs its own evidence.

## Website opening

The agreed working copy is:

> **Make room for a better human life.**
>
> We build and study AI systems that help people accomplish meaningful work, gain
> time, and retain control over their choices.
>
> Our research asks how the benefits of automation reach the people whose lives
> it changes.

Immediately follow the opening with one concrete project and its human
question. Show the project's actual state and bounded evidence. Readers should
be able to connect the ambition to something they can inspect.

The intended visitor journey is: recognize a human stake, understand a concrete
example, explore the larger question, inspect the evidence, and find a relevant
way to participate. Allow visitors to enter at any point.

## Working website architecture and aesthetic

Develop the earlier four-section proposal around this mission:

- **Principles:** the founding statement, the three commitments, difficult
  tradeoffs, and how the philosophy changes over time.
- **Research:** questions about people's outcomes, with methods, findings,
  limitations, evidence, and corrections when available.
- **Systems:** initially Wallet Kernel, explaining its intended user, behavior,
  evidence, limits, and connection to the mission.
- **About:** people, motivation, organizational identity, working methods, and
  ways to collaborate.

Use the homepage for orientation. Keep historical material accessible through
an archive with its original context and corrected evidence status.

Carry forward the proposed warm paper, dark ink, restrained ochre, readable
typography, and generous spacing. Pair thoughtful reading with diagrams and
working demonstrations that explain a real decision. Make the first screen
understandable before introducing protocol terminology. Exact visual treatment
and final navigation still need a complete page prototype.

The publishing model should connect **principles, questions, studies, findings,
evidence artifacts, and system versions**. A principle motivates a question; a
study investigates it; a finding makes a bounded claim supported or challenged
by evidence. Technical tests do not prove a normative principle.

## Research implications

The existing [proposed research agenda](../reviews/2026-09-06-agent-economy-research-agenda.md)
supplies technical and economic questions. Extend the program to examine lived
outcomes explicitly:

1. When automation saves effort, how much becomes time people can actually
   choose to use, and what conditions affect that outcome?
2. Which delegation controls improve understanding and useful autonomy at an
   acceptable supervision burden?
3. When does assistance build durable skill, and when does it increase
   dependence? Compare immediate performance with later learning and transfer.
4. Which agreements give contributors meaningful influence and benefits while
   sustaining useful collaboration?

These are proposed questions, not completed studies. Each project should state
whose circumstances it aims to improve, what improvement would look like, and
what evidence would make us reconsider the approach. Specify comparisons and
limitations before claiming impact.

## Identity decision and implementation

**Human Choice** is the chosen umbrella name. The owner explicitly directed us
to make their version after being informed of the existing HumanChoice site.
The principles and content were developed in this project conversation; that
other site was examined for naming context, not adopted as a methodology.

Wallet Kernel remains the concrete system name. Skill Asset Protocol remains
the repository name and historical context. The existing domain is retained in
metadata until a domain decision is made. Organizational form remains open.

The local website candidate implements Home, Principles, Research, four research
question pages, Systems with the existing deterministic Wallet Kernel sandbox,
and About. It preserves the historical `/proof` archive. The site uses original
English copy and an editorial visual design with warm paper, dark green ink,
serif headings, and restrained ochre accents.

Research outlines are labeled proposed. The time illustration is explicitly a
thought experiment. Wallet Kernel engineering evidence is linked to a fixed
revision and its offline scope; the local candidate retains the existing
product release boundary. See [site instructions](../../site/README.md) for
running and verifying the candidate.

## Publication decision

On 2026-09-06 the owner reviewed the private Human Choice website, approved
the rebrand and approach, and directed: “Let's publish on vercel.” In context,
this follows the agreed public launch as the next step and authorizes a
production website deployment to the existing Vercel project and its domains.

This later, explicit website-publication instruction supersedes the earlier
hold on replacing the public homepage for this mission, research, and offline
demonstration site. It does not assert that Wallet Kernel has met its live-use
acceptance criteria. Those implementation and evidence requirements remain
in effect; no payment execution, wallet funding, completed human study, or
commercial demand is inferred from publication. The Systems page states that
Wallet Kernel is not released for live use, and research pages remain proposed.

The accepted visual design, mission, and page structure are carried forward
from the private review. Publication uses the existing project and domain;
this decision does not select or acquire a new Human Choice domain.

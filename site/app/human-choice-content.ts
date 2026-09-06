export const repositoryUrl = 'https://github.com/Aznatkoiny/skill-asset-protocol';
export const evidenceRevision = '4b2717b94c47151a26c8e70cbe5806aa5bfd277b';
export const evidenceUrl = `${repositoryUrl}/tree/${evidenceRevision}/spikes/pi-wielder/evidence/2026-09-05-installed-offline-lifecycle`;
export const designUrl = `${repositoryUrl}/blob/${evidenceRevision}/docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md`;
export const discussionUrl = `${repositoryUrl}/issues`;

export const commitments = [
  { name: 'Capability', title: 'More of what matters.', description: 'Useful tools should expand what people can accomplish, learn, and create.', question: 'What can someone now do that matters to them?' },
  { name: 'Agency', title: 'A meaningful say.', description: 'People should be able to understand, direct, change, and refuse how automation acts for them.', question: 'Can someone understand the terms and change their mind?' },
  { name: 'Participation', title: 'A share in the possibilities.', description: 'People affected by automation should have a voice in its terms and how its benefits are shared.', question: 'Who receives the gains, and who bears the costs?' },
] as const;

export const questions = [
  {
    slug: 'time-recovered', number: '01', lens: 'Capability + agency',
    title: 'When AI saves time, who gets that time back?',
    summary: 'Follow the distance between a faster task and a better day.',
    why: 'A task can take less time without giving the person doing it any more freedom. We want to understand when saved effort becomes time people can actually choose to use.',
    expectation: 'Our working hypothesis is that control over workload and expectations affects whether time savings become a personal benefit.',
    method: 'Start with voluntary interviews and work diaries around a specific recurring task. A later, agreed pilot would compare the same workflow before and after AI assistance, including review, corrections, and coordination.',
    comparison: 'Compare total effort and task quality against the existing workflow. Track what happens to the time recovered, including extra work, learning, rest, and responsibilities outside work.',
    measures: ['Total effort, including review and rework', 'Time people can choose to use', 'Workload, quality, and perceived control', 'Differences between workers and teams'],
    reconsider: 'If a tool speeds up the task but raises total workload or reduces control, we would revise the tool or the working arrangement before calling it a human benefit.',
    next: 'Define one recurring workflow and prepare an interview and diary protocol.', related: 'meaningful-delegation',
  },
  {
    slug: 'meaningful-delegation', number: '02', lens: 'Agency',
    title: 'Can people delegate without giving up control?',
    summary: 'Study useful autonomy, understandable limits, and the burden of supervision.',
    why: 'Automation offers little freedom if someone must constantly watch it. Delegation should make room for other things while keeping authority understandable and limited.',
    expectation: 'Our working hypothesis is that explicit limits and approvals can support useful delegation at an acceptable supervision burden.',
    method: 'First compare legitimate and adversarial requests under several spending-control designs using an offline fault corpus. A separate study with people would test comprehension, review effort, and the ability to change or refuse a request.',
    comparison: 'Compare Wallet Kernel with a simpler quota and approval system. Measure legitimate task completion alongside unauthorized actions, unnecessary denials, recovery, and operator effort.',
    measures: ['Useful task completion', 'Unauthorized or duplicate spending', 'Understanding of delegated authority', 'Approval effort and recovery time'],
    reconsider: 'A simpler approach delivering comparable control with less effort would weaken the case for added complexity. A system that blocks every action would fail the usefulness test.',
    next: 'Prepare a comparative study using the existing offline engineering evidence.', related: 'time-recovered',
  },
  {
    slug: 'learning-and-dependence', number: '03', lens: 'Capability',
    title: 'Does AI assistance help us become more capable?',
    summary: 'Look beyond the immediate answer to learning, judgment, and lasting skill.',
    why: 'Finishing a task and developing the ability to do it are different outcomes. We want tools that help people build the capabilities they value, including knowing when to rely on assistance.',
    expectation: 'Our working hypothesis is that how assistance is offered affects later understanding and transfer to unfamiliar tasks.',
    method: 'Compare a complete generated answer, guided assistance, and an existing learning workflow on a bounded skill. Assess immediate results, explanation quality, and later performance on a different task with and without assistance.',
    comparison: 'Hold task difficulty and available time comparable. Account for prior experience and report immediate productivity separately from learning and independent performance.',
    measures: ['Immediate task quality and effort', 'Understanding and error detection', 'Later performance on unfamiliar tasks', 'Confidence compared with demonstrated ability'],
    reconsider: 'If short-term gains conceal weaker understanding or transfer, we would change the assistance design or narrow the claim about who it helps.',
    next: 'Choose a skill with independently assessable outcomes and define the comparison.', related: 'sharing-the-gains',
  },
  {
    slug: 'sharing-the-gains', number: '04', lens: 'Participation',
    title: 'What makes the benefits of automation worth sharing?',
    summary: 'Examine the agreements between contributors, users, and the people funding the work.',
    why: 'Expertise can become reusable through AI. The people contributing it and the people paying for its use may have different expectations about recognition, control, compensation, and maintenance.',
    expectation: 'Our working hypothesis is that explicit, understandable agreements can support useful collaboration and meaningful participation in its benefits.',
    method: 'Interview contributors and prospective funders separately using concrete examples. Compare open sharing, fixed commissions, employer reward pools, and negotiated revenue sharing. A later voluntary pilot would observe actual choices and continued participation.',
    comparison: 'Compare the value received and the effort required under each arrangement. Separate internal reuse from external sales and technical contribution estimates from what participants consider fair.',
    measures: ['Terms accepted or rejected by each party', 'Continued sharing and maintenance', 'Benefits received and administrative effort', 'Ability to renegotiate, leave, and resolve disputes'],
    reconsider: 'An arrangement that reduces collaboration or costs more to administer than it delivers should be simplified or abandoned. Interview enthusiasm alone would not establish demand.',
    next: 'Prepare examples and an interview protocol that gives each party an independent voice.', related: 'learning-and-dependence',
  },
] as const;

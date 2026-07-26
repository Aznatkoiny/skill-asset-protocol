export const SANDBOX_STAGES = [
  'ready',
  'registered',
  'used',
  'evidenced',
  'closed',
] as const;

export type SandboxStage = (typeof SANDBOX_STAGES)[number];

export interface SandboxState {
  stage: SandboxStage;
}

export type SandboxAction =
  | { type: 'IMPORT_SAMPLE' }
  | { type: 'SIMULATE_USES' }
  | { type: 'ATTACH_OUTCOME' }
  | { type: 'PREVIEW_CLOSE' }
  | { type: 'RESET' };

export interface DemoPerson {
  id: string;
  name: string;
  team: string;
  initials: string;
}

export interface DemoInvocation {
  id: string;
  idempotencyKey: string;
  wielder: DemoPerson;
  occurredAt: string;
  summary: string;
  status: 'Succeeded';
}

export const INITIAL_SANDBOX_STATE: SandboxState = { stage: 'ready' };

export const demoOrganization = {
  id: 'org_northstar',
  name: 'Northstar Systems',
  fictional: true,
  rewardPeriod: 'July 2026',
} as const;

export const demoCreator: DemoPerson = {
  id: 'person_maya',
  name: 'Maya Chen',
  team: 'AI Enablement',
  initials: 'MC',
};

export const demoSkill = {
  id: 'skill_pr_risk_brief',
  canonicalName: 'pull-request-risk-brief',
  displayName: 'Pull Request Risk Brief',
  description: 'Turns a pull-request diff into a rollout and risk brief.',
  version: '1.4.0',
  shortHash: '9c4a9d4e…f121',
  artifactHash:
    'sha256:9c4a9d4e8e9ee040f2ea8efae3e65a24ca56a6e0734dc6e7f5d9f023d471f121',
  source: 'northstar/ai-skills/skills/pull-request-risk-brief/SKILL.md',
  status: 'Approved',
  creator: demoCreator,
  maintainedAt: '2026-07-08',
} as const;

export const demoInvocations: readonly DemoInvocation[] = [
  {
    id: 'inv_alex',
    idempotencyKey: 'demo:pr-risk:1.4.0:alex',
    wielder: {
      id: 'person_alex',
      name: 'Alex Kim',
      team: 'AI Enablement',
      initials: 'AK',
    },
    occurredAt: 'Jul 18 · 10:02',
    summary: 'Checked rollout risk for a queue-worker change.',
    status: 'Succeeded',
  },
  {
    id: 'inv_nia',
    idempotencyKey: 'demo:pr-risk:1.4.0:nia',
    wielder: {
      id: 'person_nia',
      name: 'Nia Okafor',
      team: 'Payments',
      initials: 'NO',
    },
    occurredAt: 'Jul 21 · 12:41',
    summary: 'Reviewed refund idempotency before merge.',
    status: 'Succeeded',
  },
  {
    id: 'inv_luis',
    idempotencyKey: 'demo:pr-risk:1.4.0:luis',
    wielder: {
      id: 'person_luis',
      name: 'Luis Romero',
      team: 'Developer Experience',
      initials: 'LR',
    },
    occurredAt: 'Jul 23 · 11:18',
    summary: 'Prepared a migration rollout brief.',
    status: 'Succeeded',
  },
] as const;

export const demoOutcome = {
  invocationId: 'inv_nia',
  acceptedBy: 'Nia Okafor',
  artifact: 'northstar/payments-api#842',
  artifactTitle: 'Harden refund idempotency',
  kind: 'Pull request',
} as const;

export const rewardPolicy = {
  name: 'Shared Skill impact policy',
  poolMinor: 500_000,
  poolLabel: '$5,000',
  selectedSkillPoints: 86,
  portfolioPoints: 250,
  proposedAwardMinor: 172_000,
  proposedAwardLabel: '$1,720',
  maxSkillShareBps: 4_000,
  factors: [
    {
      label: '3 distinct successful Wielders',
      calculation: '3 × 4',
      points: 12,
    },
    {
      label: '2 teams outside the Creator team',
      calculation: '2 × 12',
      points: 24,
    },
    {
      label: '1 accepted result',
      calculation: '1 × 20',
      points: 20,
    },
    {
      label: '1 linked downstream artifact',
      calculation: '1 × 30',
      points: 30,
    },
  ],
} as const;

export const stageIndex = (stage: SandboxStage): number =>
  SANDBOX_STAGES.indexOf(stage);

export function sandboxReducer(
  state: SandboxState,
  action: SandboxAction,
): SandboxState {
  switch (action.type) {
    case 'IMPORT_SAMPLE':
      return state.stage === 'ready' ? { stage: 'registered' } : state;
    case 'SIMULATE_USES':
      return state.stage === 'registered' ? { stage: 'used' } : state;
    case 'ATTACH_OUTCOME':
      return state.stage === 'used' ? { stage: 'evidenced' } : state;
    case 'PREVIEW_CLOSE':
      return state.stage === 'evidenced' ? { stage: 'closed' } : state;
    case 'RESET':
      return INITIAL_SANDBOX_STATE;
    default:
      return state;
  }
}

export function sandboxView(state: SandboxState) {
  const index = stageIndex(state.stage);
  return {
    isRegistered: index >= stageIndex('registered'),
    invocations: index >= stageIndex('used') ? demoInvocations : [],
    hasOutcome: index >= stageIndex('evidenced'),
    hasClosePreview: index >= stageIndex('closed'),
  };
}

export function nextSandboxAction(stage: SandboxStage): {
  action: SandboxAction;
  label: string;
  note: string;
} | null {
  switch (stage) {
    case 'ready':
      return {
        action: { type: 'IMPORT_SAMPLE' },
        label: 'Import the sample Skill',
        note: 'Creates a local demo record. No repository is contacted.',
      };
    case 'registered':
      return {
        action: { type: 'SIMULATE_USES' },
        label: 'Simulate three teammate uses',
        note: 'Adds three idempotent, successful sample events.',
      };
    case 'used':
      return {
        action: { type: 'ATTACH_OUTCOME' },
        label: 'Accept one result + link its PR',
        note: 'Adds outcome evidence without storing prompt or output content.',
      };
    case 'evidenced':
      return {
        action: { type: 'PREVIEW_CLOSE' },
        label: 'Preview the July reward close',
        note: 'Applies a sample policy to a fixed employer-funded pool.',
      };
    case 'closed':
      return null;
  }
}

export const productProof = [
  {
    number: '01',
    eyebrow: 'Registry',
    title: 'Know what exists.',
    body: 'Import an approved Skill with its Creator, maintainer, version, and lineage intact.',
    sample: 'Pull Request Risk Brief · v1.4.0',
  },
  {
    number: '02',
    eyebrow: 'Evidence',
    title: 'Prove real reuse.',
    body: 'Record successful use inside existing tools, then attach acceptance and downstream outcomes.',
    sample: '3 Wielders · 2 teams · 1 linked PR',
  },
  {
    number: '03',
    eyebrow: 'Reward close',
    title: 'Reward contribution.',
    body: 'Apply a reviewable policy to a fixed employer-funded pool and export a plain-language statement.',
    sample: 'Provisional · reviewed · payroll-ready',
  },
] as const;

export const rolePaths = [
  {
    label: 'For AI platform teams',
    title: 'A governed portfolio, not a folder of prompts.',
    body: 'See adoption, versions, owners, failures, and duplicate work across the organization.',
  },
  {
    label: 'For Creators',
    title: 'Durable credit for work that keeps working.',
    body: 'See who reuses your Skill, where it creates value, and how the reward policy treats that evidence.',
  },
  {
    label: 'For Total Rewards',
    title: 'A defensible monthly close.',
    body: 'Set budgets and policy once, review exceptions, resolve disputes, and export approved awards.',
  },
] as const;

export const evidenceReceipts = [
  {
    value: '64',
    label: 'settlement invariants',
    detail: 'deterministic fork and reward arithmetic',
  },
  {
    value: '97',
    label: 'clone-harness checks',
    detail: 'offline, reproducible, and dependency-free',
  },
  {
    value: '48',
    label: 'settled x402 calls',
    detail: 'real testnet payment-overhead sample',
  },
] as const;

export const repositoryUrl =
  'https://github.com/Aznatkoiny/skill-asset-protocol';

export const defaultPilotUrl =
  'https://github.com/Aznatkoiny/skill-asset-protocol/issues/new?title=Design-partner%20pilot';

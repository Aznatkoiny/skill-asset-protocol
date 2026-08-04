export const productProof = [
  {
    number: '01',
    eyebrow: 'Spend Intent',
    title: 'Capture the exact request.',
    body: 'Turn an ordinary Agent HTTP request into a canonical intent bound to its session, seller, resource, amount, and purpose.',
    sample: 'Pi · call 0x8c0d…b811 · 0.08 test USDC',
  },
  {
    number: '02',
    eyebrow: 'Policy',
    title: 'Decide before signing.',
    body: 'Automatically allow, require exact human approval, or deny against immutable seller and budget rules.',
    sample: 'Default deny · exact seller · bounded session',
  },
  {
    number: '03',
    eyebrow: 'Planned receipt',
    title: 'Keep payment separate from outcome.',
    body: 'A release-gated flow can anchor settlement on-chain and preserve policy, approval, execution, refund, and reconciliation facts in a signed local receipt.',
    sample: 'Planned: one permit · one paid retry · one terminal receipt',
  },
] as const;

export const rolePaths = [
  {
    label: 'For AI platform teams',
    title: 'Economic agency with a hard boundary.',
    body: 'Give Agents approved buying power without exposing wallet credentials or a generic signing surface.',
  },
  {
    label: 'For operators',
    title: 'Exact approvals, not blanket access.',
    body: 'Review the seller, resource, request hash, amount ceiling, policy version, and expiry before authorizing once.',
  },
  {
    label: 'For security + finance',
    title: 'A durable answer for every cent.',
    body: 'Release-gated signed receipts will let teams inspect conserved budgets, ambiguous settlements, refunds, and reconciliation from customer-held records.',
  },
] as const;

export const evidenceReceipts = [
  {
    value: '84532',
    label: 'fixture network',
    detail: 'Base Sepolia config only; no broadcast or real funds',
  },
  {
    value: 'x402',
    label: 'release-gated payment rail',
    detail: 'settlement would bind network, asset, seller, request, and amount',
  },
  {
    value: 'UNSIGNED',
    label: 'browser artifact',
    detail: 'local projection only; not broadcast and not live evidence',
  },
] as const;

export const repositoryUrl =
  'https://github.com/Aznatkoiny/skill-asset-protocol';

export const spendControlDesignUrl = `${repositoryUrl}/blob/main/docs/superpowers/specs/2026-07-31-agent-spend-control-plane-design.md`;

export const defaultPilotUrl =
  'https://github.com/Aznatkoiny/skill-asset-protocol/issues/new?title=Agent%20Spend%20Control%20design-partner%20pilot';

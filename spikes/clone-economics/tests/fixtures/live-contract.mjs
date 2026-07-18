export const config = {
  schemaVersion: 1,
  experimentFamily: 'clone-economics-high-n-v1',
  fixtureSet: 'v2',
  nValues: [6, 25, 50, 100],
  heldoutMinimum: 30,
  replicates: [
    { replicateId: 'r1', pairOrderSeed: 1701, distillationSeed: 2701 },
    { replicateId: 'r2', pairOrderSeed: 1702, distillationSeed: 2702 },
    { replicateId: 'r3', pairOrderSeed: 1703, distillationSeed: 2703 },
  ],
  highNDefinition: 100,
  publicationRequiresIndependentDistillationSeeds: true,
};

export const approved = {
  schemaVersion: 1,
  experimentFamily: config.experimentFamily,
  approvalStatus: 'approved',
  provider: 'anthropic',
  model: 'synthetic-budget-test-model',
  pricing: {
    currency: 'USD',
    unit: 'per_million_tokens',
    inputUsdPerMillionTokens: '3.00',
    outputUsdPerMillionTokens: '15.00',
    asOf: '2026-07-17T00:00:00Z',
    source: 'https://example.invalid/synthetic-pricing-fixture',
  },
  tokenCaps: { maxInputTokens: 4096, maxOutputTokens: 1024 },
};

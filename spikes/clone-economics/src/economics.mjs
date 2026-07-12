const rounded = (value) => Number(value.toFixed(12));

function core({ N, invocationPriceUsd, cloneServingCostUsd, distillationProviderUsd, tuningEvaluationUsd, deployCostUsd, laborCostUsd }) {
  const acquisitionModeledUsd = rounded(N * invocationPriceUsd);
  const buildParts = [acquisitionModeledUsd, distillationProviderUsd, tuningEvaluationUsd, deployCostUsd, laborCostUsd];
  const attackerBuildUsd = buildParts.every((value) => Number.isFinite(value))
    ? rounded(buildParts.reduce((sum, value) => sum + value, 0))
    : null;
  const margin = invocationPriceUsd - cloneServingCostUsd;
  return {
    acquisitionModeledUsd,
    attackerBuildUsd,
    distillationToAcquisition: acquisitionModeledUsd > 0 && Number.isFinite(distillationProviderUsd) ? rounded(distillationProviderUsd / acquisitionModeledUsd) : null,
    buildToAcquisition: acquisitionModeledUsd > 0 && attackerBuildUsd !== null ? rounded(attackerBuildUsd / acquisitionModeledUsd) : null,
    breakEvenInvocations: margin > 0 && attackerBuildUsd !== null ? Math.ceil(attackerBuildUsd / margin) : null,
  };
}

export function computeEconomics(input) {
  const values = core(input);
  const zeroPriceProbe = core({ ...input, invocationPriceUsd: 0 });
  return {
    acquisitionFormula: 'A = N × listed Invocation price (MODELED; no x402 settlement in this spike)',
    acquisitionModeledUsd: values.acquisitionModeledUsd,
    distillationProviderUsd: input.distillationProviderUsd,
    tuningEvaluationUsd: input.tuningEvaluationUsd,
    tuningNote: input.tuningEvaluationUsd === 0 ? 'No tuning/revision attempt was performed.' : 'Attack-side tuning/revision cost included.',
    deployCostUsd: input.deployCostUsd,
    laborCostUsd: input.laborCostUsd,
    laborCostTreatment: input.laborCostUsd === 0 ? 'Explicitly excluded from this run.' : 'Operator-supplied input.',
    attackerBuildUsd: values.attackerBuildUsd,
    measurementEvaluationUsd: input.measurementEvaluationUsd,
    evaluationExcludedFromBuild: true,
    distillationToAcquisition: values.distillationToAcquisition,
    buildToAcquisition: values.buildToAcquisition,
    breakEvenInvocations: values.breakEvenInvocations,
    cloneServingCostUsd: input.cloneServingCostUsd,
    providerCostsNotAddedToAcquisition: true,
    providerCostBreakdown: input.providerCostBreakdown,
    zeroPriceProbe: {
      distillationToAcquisition: zeroPriceProbe.distillationToAcquisition,
      buildToAcquisition: zeroPriceProbe.buildToAcquisition,
      breakEvenInvocations: zeroPriceProbe.breakEvenInvocations,
    },
  };
}

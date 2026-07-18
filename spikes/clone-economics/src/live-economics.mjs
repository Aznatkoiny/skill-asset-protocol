const KEYS = [
  'schemaVersion',
  'experimentFamily',
  'approvalStatus',
  'invocationPriceUsd',
  'cloneServingCostUsd',
  'deployCostUsd',
  'laborCostUsd',
];

function exactObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Live economics must be an object');
  }
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...KEYS].sort())) {
    throw new Error('Live economics has unexpected or missing fields');
  }
}

export function validateLiveEconomicsShape(economics, config) {
  exactObject(economics);
  if (economics.schemaVersion !== 1) throw new Error('Live economics schemaVersion must be 1');
  if (economics.experimentFamily !== config.experimentFamily) {
    throw new Error('Live economics experiment family mismatch');
  }
  if (economics.approvalStatus === 'not_approved') {
    for (const field of KEYS.slice(3)) {
      if (economics[field] !== null) throw new Error('Unapproved live economics must retain exact null values');
    }
    return economics;
  }
  if (economics.approvalStatus !== 'approved') {
    throw new Error('Live economics approvalStatus must be approved or not_approved');
  }
  return validateApprovedLiveEconomics(economics, config);
}

export function validateApprovedLiveEconomics(economics, config) {
  exactObject(economics);
  if (economics.schemaVersion !== 1) throw new Error('Live economics schemaVersion must be 1');
  if (economics.experimentFamily !== config.experimentFamily) {
    throw new Error('Live economics experiment family mismatch');
  }
  if (economics.approvalStatus !== 'approved') {
    throw new Error('Live economics must be approved; current contract is not approved');
  }
  for (const field of KEYS.slice(3)) {
    if (!Number.isFinite(economics[field]) || economics[field] < 0) {
      throw new Error(`${field} must be a finite non-negative number`);
    }
  }
  return economics;
}

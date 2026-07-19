const MICRO_USD_PER_USD = 1_000_000n;

export function parseUsdToMicroUsd(value, fieldName) {
  if (typeof value !== 'string' || !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(value)) {
    throw new Error(`${fieldName} must be a positive plain USD decimal with at most six places`);
  }
  const [whole, fraction = ''] = value.split('.');
  const result = BigInt(whole) * MICRO_USD_PER_USD
    + BigInt(fraction.padEnd(6, '0'));
  if (result <= 0n) throw new Error(`${fieldName} must be positive`);
  return result;
}

export function formatMicroUsd(value) {
  if (typeof value !== 'bigint' || value < 0n) throw new Error('micro-USD value must be a non-negative bigint');
  return `${value / MICRO_USD_PER_USD}.${String(value % MICRO_USD_PER_USD).padStart(6, '0')}`;
}

const ceilDiv = (numerator, denominator) =>
  (numerator + denominator - 1n) / denominator;

export function calculateProviderCostMicroUsd({ inputTokens, outputTokens, snapshot }) {
  if (!Number.isSafeInteger(inputTokens) || inputTokens < 0
      || !Number.isSafeInteger(outputTokens) || outputTokens < 0) {
    throw new Error('Provider usage must contain non-negative safe integer token counts');
  }
  const inputPrice = parseUsdToMicroUsd(
    snapshot.pricing.inputUsdPerMillionTokens,
    'input pricing',
  );
  const outputPrice = parseUsdToMicroUsd(
    snapshot.pricing.outputUsdPerMillionTokens,
    'output pricing',
  );
  return ceilDiv(BigInt(inputTokens) * inputPrice, 1_000_000n)
    + ceilDiv(BigInt(outputTokens) * outputPrice, 1_000_000n);
}

export function exceedsCommittedTokenCaps({ inputTokens, outputTokens, snapshot }) {
  return inputTokens > snapshot.tokenCaps.maxInputTokens
    || outputTokens > snapshot.tokenCaps.maxOutputTokens;
}

function assertExactKeys(value, keys, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} has unexpected or missing fields`);
  }
}

export function validateBudgetSnapshotShape(snapshot, config = null) {
  assertExactKeys(snapshot, [
    'schemaVersion', 'experimentFamily', 'approvalStatus', 'provider', 'model', 'pricing', 'tokenCaps',
  ], 'Live budget snapshot');
  assertExactKeys(snapshot.pricing, [
    'currency', 'unit', 'inputUsdPerMillionTokens', 'outputUsdPerMillionTokens', 'asOf', 'source',
  ], 'Live budget pricing');
  assertExactKeys(snapshot.tokenCaps, ['maxInputTokens', 'maxOutputTokens'], 'Live budget token caps');
  if (snapshot.schemaVersion !== 1) throw new Error('Live budget snapshot schemaVersion must be 1');
  if (typeof snapshot.experimentFamily !== 'string' || snapshot.experimentFamily === '') {
    throw new Error('Live budget snapshot experiment family is required');
  }
  if (config && snapshot.experimentFamily !== config.experimentFamily) {
    throw new Error('Live budget snapshot experiment family does not match sweep config');
  }
  if (snapshot.approvalStatus === 'not_approved') {
    if (typeof snapshot.provider !== 'string' || snapshot.provider === '') {
      throw new Error('Unapproved budget provider is required');
    }
    const expectedNulls = [
      snapshot.model,
      snapshot.pricing.inputUsdPerMillionTokens,
      snapshot.pricing.outputUsdPerMillionTokens,
      snapshot.pricing.asOf,
      snapshot.pricing.source,
      snapshot.tokenCaps.maxInputTokens,
      snapshot.tokenCaps.maxOutputTokens,
    ];
    if (expectedNulls.some((value) => value !== null)
        || snapshot.pricing.currency !== 'USD'
        || snapshot.pricing.unit !== 'per_million_tokens') {
      throw new Error('Unapproved live budget snapshot must retain the exact null contract');
    }
    return snapshot;
  }
  if (snapshot.approvalStatus !== 'approved') {
    throw new Error('Live budget approvalStatus must be approved or not_approved');
  }
  validateApprovedBudgetSnapshot(snapshot, config ?? { experimentFamily: snapshot.experimentFamily });
  return snapshot;
}

export function validateApprovedBudgetSnapshot(snapshot, config) {
  if (!snapshot || snapshot.schemaVersion !== 1) throw new Error('Live budget snapshot schemaVersion must be 1');
  if (snapshot.experimentFamily !== config.experimentFamily) throw new Error('Live budget snapshot experiment family mismatch');
  if (snapshot.approvalStatus !== 'approved') {
    throw new Error('Live budget snapshot must be approved; current snapshot is not approved');
  }
  if (typeof snapshot.provider !== 'string' || snapshot.provider.trim() === '') throw new Error('Live budget provider is required');
  if (typeof snapshot.model !== 'string' || snapshot.model.trim() === '') throw new Error('Live budget model is required');
  if (snapshot.pricing?.currency !== 'USD') throw new Error('Live budget currency must be USD');
  if (snapshot.pricing?.unit !== 'per_million_tokens') throw new Error('Live budget unit must be per_million_tokens');
  parseUsdToMicroUsd(snapshot.pricing?.inputUsdPerMillionTokens, 'input pricing');
  parseUsdToMicroUsd(snapshot.pricing?.outputUsdPerMillionTokens, 'output pricing');
  if (typeof snapshot.pricing?.asOf !== 'string'
      || Number.isNaN(Date.parse(snapshot.pricing.asOf))
      || !/^\d{4}-\d{2}-\d{2}T/.test(snapshot.pricing.asOf)) {
    throw new Error('Live budget pricing asOf must be an ISO-8601 timestamp');
  }
  try {
    const source = new URL(snapshot.pricing.source);
    if (source.protocol !== 'https:') throw new Error('not HTTPS');
  } catch {
    throw new Error('Live budget pricing source must be an HTTPS URL');
  }
  for (const [name, value] of Object.entries({
    maxInputTokens: snapshot.tokenCaps?.maxInputTokens,
    maxOutputTokens: snapshot.tokenCaps?.maxOutputTokens,
  })) {
    if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${name} must be a positive safe integer`);
  }
  return snapshot;
}

export function conservativeSweepRequestCount(config, counts) {
  const cells = config.nValues.flatMap((n) =>
    config.replicates.map(() => (
      n + 1 + counts.heldoutCount * 3 + counts.v2Count * 2
    )));
  return counts.heldoutCount + cells.reduce((sum, value) => sum + value, 0);
}

export function estimateLiveSweepMicroUsd({ config, counts, snapshot }) {
  validateApprovedBudgetSnapshot(snapshot, config);
  const perCall = calculateProviderCostMicroUsd({
    inputTokens: snapshot.tokenCaps.maxInputTokens,
    outputTokens: snapshot.tokenCaps.maxOutputTokens,
    snapshot,
  });
  return BigInt(conservativeSweepRequestCount(config, counts)) * perCall;
}

export function createAttemptBudget({ capMicroUsd, worstCaseCallMicroUsd }) {
  if (typeof capMicroUsd !== 'bigint' || capMicroUsd <= 0n) throw new Error('capMicroUsd must be a positive bigint');
  if (typeof worstCaseCallMicroUsd !== 'bigint' || worstCaseCallMicroUsd <= 0n) {
    throw new Error('worstCaseCallMicroUsd must be a positive bigint');
  }
  let attemptedCalls = 0;
  let knownAccruedMicroUsd = 0n;
  let outstandingReservedMicroUsd = 0n;
  let lock = null;
  const reservations = new Map();
  const settled = new Map();

  function lockError() {
    return lock.kind === 'budget_overrun'
      ? new Error(`Budget permanently locked: budget_overrun (${lock.reason})`)
      : new Error(`Budget locked: ${lock.kind}`);
  }

  function reserveNextAttempt(metadata) {
    if (lock) throw lockError();
    const projected = knownAccruedMicroUsd + outstandingReservedMicroUsd + worstCaseCallMicroUsd;
    if (projected > capMicroUsd) {
      throw new Error(`Next live attempt would exceed human cap: ${formatMicroUsd(projected)} > ${formatMicroUsd(capMicroUsd)}`);
    }
    attemptedCalls += 1;
    const attemptId = `attempt-${String(attemptedCalls).padStart(6, '0')}`;
    reservations.set(attemptId, { amountMicroUsd: worstCaseCallMicroUsd, metadata: structuredClone(metadata) });
    outstandingReservedMicroUsd += worstCaseCallMicroUsd;
    return attemptId;
  }

  function settleAttempt(attemptId, {
    knownCostMicroUsd,
    success,
    budgetViolation = null,
  }) {
    const reservation = reservations.get(attemptId);
    if (!reservation) throw new Error(`Unknown or already-settled attempt ${attemptId}`);
    if (lock) throw new Error(`Budget permanently locked: ${lock.kind}`);
    if (knownCostMicroUsd === null) {
      lock = { kind: 'unknown_cost', attemptId };
      throw new Error('Unknown live cost; budget locked');
    }
    if (typeof knownCostMicroUsd !== 'bigint' || knownCostMicroUsd < 0n) {
      lock = { kind: 'unknown_cost', attemptId };
      throw new Error('Malformed live cost; budget locked as unknown_cost');
    }
    reservations.delete(attemptId);
    outstandingReservedMicroUsd -= reservation.amountMicroUsd;
    knownAccruedMicroUsd += knownCostMicroUsd;
    const reason = budgetViolation === 'token_cap_exceeded'
      ? 'token_cap_exceeded'
      : knownAccruedMicroUsd > capMicroUsd
        ? 'human_cap_exceeded'
        : knownCostMicroUsd > reservation.amountMicroUsd
          ? 'reservation_exceeded'
          : null;
    settled.set(attemptId, { knownCostMicroUsd, success });
    if (reason) {
      lock = { kind: 'budget_overrun', attemptId, reason };
      const label = reason.replaceAll('_', ' ');
      throw new Error(`budget_overrun: ${label}; exact cost was accrued`);
    }
  }

  function state() {
    return { attemptedCalls, knownAccruedMicroUsd, outstandingReservedMicroUsd, lock: lock ? { ...lock } : null };
  }

  return { reserveNextAttempt, settleAttempt, state };
}

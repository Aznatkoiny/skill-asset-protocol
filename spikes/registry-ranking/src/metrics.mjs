const EVENT_KEYS = Object.freeze([
  'creatorWallet',
  'grossAtomic',
  'invocationId',
  'outcome',
  'payeeWallet',
  'payerWallet',
  'recycledAtomic',
  'refundedAtomic',
  'schemaVersion',
  'settledAt',
  'settlementId',
  'skillId',
  'untrustedPayerClaims',
].sort());
const CLAIM_KEYS = Object.freeze([
  'beneficiaryId',
  'payerClusterId',
  'relationship',
].sort());
const REGISTRY_KEYS = Object.freeze(['entries', 'schemaVersion']);
const REGISTRY_ENTRY_KEYS = Object.freeze([
  'beneficiaryId',
  'evidenceRef',
  'payerClusterId',
  'relationship',
  'reviewedAt',
].sort());
const EXCLUSION_KEYS = Object.freeze([
  'self_payment',
  'linked_wallet',
  'failed_invocation',
  'unresolved_settlement',
  'refunded',
  'recycled_value',
  'sybil_cluster',
  'unknown_relationship',
]);
const WALLET_PATTERN = /^0x[0-9a-f]{40}$/;
const ATOMIC_PATTERN = /^(0|[1-9][0-9]*)$/;
const IDENTIFIER_PATTERN = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const OUTCOMES = new Set(['succeeded', 'failed', 'unresolved']);
const TRUSTED_RELATIONSHIPS = new Set(['linked', 'independent']);

function fail(message) {
  throw new TypeError(message);
}

function isPlainRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireRecord(value, label) {
  if (!isPlainRecord(value)) fail(`${label} must be a plain object`);
  return value;
}

function requireExactKeys(value, expected, label) {
  const actual = Object.keys(value).sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has invalid keys`);
  }
}

function snapshotExactDataRecord(value, expected, label) {
  requireRecord(value, label);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) {
    fail(`${label} must use only string keys`);
  }
  const actual = [...ownKeys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} has invalid keys`);
  }
  const snapshot = Object.create(null);
  for (const key of ownKeys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail(`${label} fields must be own enumerable data properties`);
    }
    snapshot[key] = descriptor.value;
  }
  return snapshot;
}

function requireIdentifier(value, label) {
  if (typeof value !== 'string' || !IDENTIFIER_PATTERN.test(value)) {
    fail(`${label} must be a canonical identifier`);
  }
  return value;
}

function requireUntrustedText(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 256
      || /[^\x20-\x7e]/.test(value)) {
    fail(`${label} must be non-empty bounded visible ASCII`);
  }
  return value;
}

function requireWallet(value, label) {
  if (typeof value !== 'string' || !WALLET_PATTERN.test(value)) {
    fail(`${label} must be a lowercase 40-hex wallet address`);
  }
  return value;
}

function requireAtomic(value, label) {
  if (typeof value !== 'string' || !ATOMIC_PATTERN.test(value)) {
    fail(`${label} must be a canonical non-negative decimal string`);
  }
  return BigInt(value);
}

function requireUtcTimestamp(value, label) {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)
      || Number.isNaN(Date.parse(value))
      || new Date(value).toISOString() !== value) {
    fail(`${label} must be a canonical UTC timestamp`);
  }
  return value;
}

function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

function validateClassification(value) {
  requireRecord(value, 'payer classification');
  requireExactKeys(
    value,
    ['beneficiaryId', 'evidenceRef', 'payerClusterId', 'relationship'],
    'payer classification',
  );
  if (!['self', 'linked', 'independent', 'unknown'].includes(value.relationship)) {
    fail('payer classification relationship is invalid');
  }
  if (value.relationship === 'linked' || value.relationship === 'independent') {
    requireIdentifier(value.beneficiaryId, 'payer classification beneficiaryId');
    requireIdentifier(value.payerClusterId, 'payer classification payerClusterId');
    requireUntrustedText(value.evidenceRef, 'payer classification evidenceRef');
  } else if (value.beneficiaryId !== null || value.payerClusterId !== null) {
    fail('self and unknown payer classifications must not claim an owner or cluster');
  }
  if (typeof value.evidenceRef !== 'string' || value.evidenceRef.length === 0) {
    fail('payer classification evidenceRef must be non-empty');
  }
  return deepFreeze({
    relationship: value.relationship,
    beneficiaryId: value.beneficiaryId,
    payerClusterId: value.payerClusterId,
    evidenceRef: value.evidenceRef,
  });
}

export function parseSettlementMetricEvent(value) {
  const event = snapshotExactDataRecord(value, EVENT_KEYS, 'SettlementMetricEventV1');
  if (event.schemaVersion !== 1) fail('SettlementMetricEventV1 schemaVersion must be 1');

  const claims = snapshotExactDataRecord(
    event.untrustedPayerClaims,
    CLAIM_KEYS,
    'untrustedPayerClaims',
  );
  const gross = requireAtomic(event.grossAtomic, 'grossAtomic');
  const refunded = requireAtomic(event.refundedAtomic, 'refundedAtomic');
  const recycled = requireAtomic(event.recycledAtomic, 'recycledAtomic');
  if (refunded > gross) fail('refundedAtomic must not exceed grossAtomic');
  if (recycled > gross) fail('recycledAtomic must not exceed grossAtomic');
  if (refunded + recycled > gross) {
    fail('refundedAtomic plus recycledAtomic must not exceed grossAtomic');
  }
  if (!OUTCOMES.has(event.outcome)) fail('outcome is invalid');

  return deepFreeze({
    schemaVersion: 1,
    settlementId: requireIdentifier(event.settlementId, 'settlementId'),
    invocationId: requireIdentifier(event.invocationId, 'invocationId'),
    skillId: requireIdentifier(event.skillId, 'skillId'),
    creatorWallet: requireWallet(event.creatorWallet, 'creatorWallet'),
    payeeWallet: requireWallet(event.payeeWallet, 'payeeWallet'),
    payerWallet: requireWallet(event.payerWallet, 'payerWallet'),
    untrustedPayerClaims: {
      beneficiaryId: requireUntrustedText(claims.beneficiaryId, 'untrustedPayerClaims.beneficiaryId'),
      payerClusterId: requireUntrustedText(claims.payerClusterId, 'untrustedPayerClaims.payerClusterId'),
      relationship: requireUntrustedText(claims.relationship, 'untrustedPayerClaims.relationship'),
    },
    grossAtomic: gross.toString(),
    refundedAtomic: refunded.toString(),
    recycledAtomic: recycled.toString(),
    outcome: event.outcome,
    settledAt: requireUtcTimestamp(event.settledAt, 'settledAt'),
  });
}

export function createVerifiedBillingClassifier(value) {
  const registry = requireRecord(value, 'VerifiedBillingRegistryV1');
  requireExactKeys(registry, REGISTRY_KEYS, 'VerifiedBillingRegistryV1');
  if (registry.schemaVersion !== 1) fail('VerifiedBillingRegistryV1 schemaVersion must be 1');
  const inputEntries = requireRecord(registry.entries, 'VerifiedBillingRegistryV1.entries');
  const entries = Object.create(null);

  for (const payerWallet of Object.keys(inputEntries).sort()) {
    requireWallet(payerWallet, 'verified billing registry wallet key');
    const input = requireRecord(
      inputEntries[payerWallet],
      `verified billing registry entry ${payerWallet}`,
    );
    requireExactKeys(input, REGISTRY_ENTRY_KEYS, `verified billing registry entry ${payerWallet}`);
    if (!TRUSTED_RELATIONSHIPS.has(input.relationship)) {
      fail(`verified billing registry entry ${payerWallet} relationship is invalid`);
    }
    entries[payerWallet] = {
      beneficiaryId: requireIdentifier(
        input.beneficiaryId,
        `verified billing registry entry ${payerWallet} beneficiaryId`,
      ),
      payerClusterId: requireIdentifier(
        input.payerClusterId,
        `verified billing registry entry ${payerWallet} payerClusterId`,
      ),
      relationship: input.relationship,
      evidenceRef: requireUntrustedText(
        input.evidenceRef,
        `verified billing registry entry ${payerWallet} evidenceRef`,
      ),
      reviewedAt: requireUtcTimestamp(
        input.reviewedAt,
        `verified billing registry entry ${payerWallet} reviewedAt`,
      ),
    };
  }
  const snapshot = deepFreeze({ schemaVersion: 1, entries });

  return Object.freeze(function classifyPayer(eventValue) {
    const event = parseSettlementMetricEvent(eventValue);
    if (event.payerWallet === event.creatorWallet || event.payerWallet === event.payeeWallet) {
      return validateClassification({
        relationship: 'self',
        beneficiaryId: null,
        payerClusterId: null,
        evidenceRef: 'derived:self-payment',
      });
    }
    if (!Object.hasOwn(snapshot.entries, event.payerWallet)) {
      return validateClassification({
        relationship: 'unknown',
        beneficiaryId: null,
        payerClusterId: null,
        evidenceRef: 'derived:no-verified-billing-record',
      });
    }
    const record = snapshot.entries[event.payerWallet];
    return validateClassification({
      relationship: record.relationship,
      beneficiaryId: record.beneficiaryId,
      payerClusterId: record.payerClusterId,
      evidenceRef: record.evidenceRef,
    });
  });
}

export function exclusionReasons(
  eventValue,
  classificationValue,
  { seenIndependentClusters } = {},
) {
  const event = parseSettlementMetricEvent(eventValue);
  const classification = validateClassification(classificationValue);
  if (!(seenIndependentClusters instanceof Set)) {
    fail('seenIndependentClusters must be a Set');
  }
  const reasons = [];
  if (classification.relationship === 'self') reasons.push('self_payment');
  if (classification.relationship === 'linked') reasons.push('linked_wallet');
  if (event.outcome === 'failed') reasons.push('failed_invocation');
  if (event.outcome === 'unresolved') reasons.push('unresolved_settlement');
  if (BigInt(event.refundedAtomic) > 0n) reasons.push('refunded');
  if (BigInt(event.recycledAtomic) > 0n) reasons.push('recycled_value');
  if (classification.relationship === 'unknown') reasons.push('unknown_relationship');
  if (classification.relationship === 'independent'
      && event.outcome === 'succeeded'
      && event.refundedAtomic === '0'
      && event.recycledAtomic === '0'
      && seenIndependentClusters.has(classification.payerClusterId)) {
    reasons.push('sybil_cluster');
  }
  return Object.freeze(reasons.sort());
}

function claimsDisagree(event, classification) {
  const claims = event.untrustedPayerClaims;
  return claims.relationship !== classification.relationship
    || claims.beneficiaryId !== classification.beneficiaryId
    || claims.payerClusterId !== classification.payerClusterId;
}

function compareEvents(left, right) {
  const time = left.settledAt.localeCompare(right.settledAt);
  return time || left.settlementId.localeCompare(right.settlementId);
}

export function computeSkillMetrics(eventValues, { classifier } = {}) {
  if (!Array.isArray(eventValues) || eventValues.length === 0) {
    fail('events must be a non-empty array');
  }
  if (typeof classifier !== 'function') fail('classifier must be an injected trusted function');
  const events = eventValues.map(parseSettlementMetricEvent).sort(compareEvents);
  const skillId = events[0].skillId;
  const settlementIds = new Set();
  const successfulInvocationIds = new Set();
  for (const event of events) {
    if (event.skillId !== skillId) fail('events for multiple Skills must be grouped before reduction');
    if (settlementIds.has(event.settlementId)) {
      fail(`duplicate settlement ID '${event.settlementId}'`);
    }
    settlementIds.add(event.settlementId);
    if (event.outcome === 'succeeded') {
      if (successfulInvocationIds.has(event.invocationId)) {
        fail(`duplicate successful Invocation '${event.invocationId}'`);
      }
      successfulInvocationIds.add(event.invocationId);
    }
  }

  const exclusionCounts = Object.fromEntries(EXCLUSION_KEYS.map((key) => [key, 0]));
  const seenIndependentClusters = new Set();
  const independentBeneficiaries = new Set();
  const uniquePayers = new Set();
  const auditWarnings = [];
  let refundAdjustedNet = 0n;
  let independentNet = 0n;
  let hasSuccessfulNetSettlement = false;

  for (const event of events) {
    uniquePayers.add(event.payerWallet);
    refundAdjustedNet += BigInt(event.grossAtomic)
      - BigInt(event.refundedAtomic)
      - BigInt(event.recycledAtomic);
    if (event.outcome === 'succeeded'
        && event.refundedAtomic === '0'
        && event.recycledAtomic === '0') {
      hasSuccessfulNetSettlement = true;
    }
    const classification = validateClassification(classifier(event));
    if (claimsDisagree(event, classification)) {
      auditWarnings.push(
        `${event.settlementId}: untrusted payer claims disagree with verified classification`,
      );
    }
    const reasons = exclusionReasons(event, classification, { seenIndependentClusters });
    for (const reason of reasons) exclusionCounts[reason] += 1;
    if (reasons.length === 0) {
      seenIndependentClusters.add(classification.payerClusterId);
      independentBeneficiaries.add(classification.beneficiaryId);
      independentNet += BigInt(event.grossAtomic);
    }
  }

  const independentClusterCount = seenIndependentClusters.size;
  const registryStatus = independentClusterCount >= 2
      && independentBeneficiaries.size >= 2
      && independentNet > 0n
    ? 'eligible'
    : hasSuccessfulNetSettlement
      ? 'allow_listed'
      : 'ineligible';
  const independenceConfidence = independentClusterCount >= 2
    ? 'high'
    : independentClusterCount === 1
      ? 'medium'
      : 'low';

  return deepFreeze({
    schemaVersion: 1,
    skillId,
    totalSettlements: events.length,
    successfulInvocations: events.filter((event) => event.outcome === 'succeeded').length,
    settledFailures: events.filter((event) => event.outcome === 'failed').length,
    unresolvedSettlements: events.filter((event) => event.outcome === 'unresolved').length,
    refundedSettlements: events.filter((event) => BigInt(event.refundedAtomic) > 0n).length,
    uniquePayerWallets: uniquePayers.size,
    uniqueIndependentBeneficiaries: independentBeneficiaries.size,
    refundAdjustedNetAtomic: refundAdjustedNet.toString(),
    independentNetAtomic: independentNet.toString(),
    independenceConfidence,
    registryStatus,
    exclusionCounts,
    auditWarnings,
  });
}

export function rankEligibleSkills(metricValues) {
  if (!Array.isArray(metricValues)) fail('metrics must be an array');
  return Object.freeze(
    metricValues
      .filter((metric) => metric?.registryStatus === 'eligible')
      .slice()
      .sort((left, right) => {
        const netDifference = BigInt(right.independentNetAtomic) - BigInt(left.independentNetAtomic);
        if (netDifference !== 0n) return netDifference > 0n ? 1 : -1;
        const beneficiaries = right.uniqueIndependentBeneficiaries
          - left.uniqueIndependentBeneficiaries;
        if (beneficiaries !== 0) return beneficiaries;
        const invocations = right.successfulInvocations - left.successfulInvocations;
        if (invocations !== 0) return invocations;
        return String(left.skillId).localeCompare(String(right.skillId));
      }),
  );
}

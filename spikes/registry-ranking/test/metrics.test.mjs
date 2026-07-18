import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  computeSkillMetrics,
  createVerifiedBillingClassifier,
  exclusionReasons,
  parseSettlementMetricEvent,
  rankEligibleSkills,
} from '../src/metrics.mjs';

const fixtureUrl = new URL('../fixtures/settlements.json', import.meta.url);
const registryUrl = new URL('../fixtures/verified-billing-registry.json', import.meta.url);
const events = JSON.parse(await readFile(fixtureUrl, 'utf8'));
const verifiedBillingRegistry = JSON.parse(await readFile(registryUrl, 'utf8'));
const classifier = createVerifiedBillingClassifier(verifiedBillingRegistry);
const SYBIL_SETTLEMENT_IDS = new Set([
  'settlement-003-otherco-a',
  'settlement-004-otherco-b',
]);

function clone(value) {
  return structuredClone(value);
}

test('fixture has ten settlements and exactly two accepted independent clusters', () => {
  const metrics = computeSkillMetrics(events, { classifier });

  assert.equal(metrics.totalSettlements, 10);
  assert.equal(metrics.successfulInvocations, 8);
  assert.equal(metrics.settledFailures, 1);
  assert.equal(metrics.unresolvedSettlements, 1);
  assert.equal(metrics.refundedSettlements, 1);
  assert.equal(metrics.uniquePayerWallets, 10);
  assert.equal(metrics.uniqueIndependentBeneficiaries, 2);
  assert.equal(metrics.independentNetAtomic, '500000');
  assert.equal(metrics.registryStatus, 'eligible');
  assert.equal(metrics.exclusionCounts.self_payment, 1);
  assert.equal(metrics.exclusionCounts.linked_wallet, 1);
  assert.equal(metrics.exclusionCounts.sybil_cluster, 1);
  assert.equal(metrics.exclusionCounts.failed_invocation, 1);
  assert.equal(metrics.exclusionCounts.unresolved_settlement, 1);
  assert.equal(metrics.exclusionCounts.refunded, 1);
  assert.equal(metrics.exclusionCounts.recycled_value, 1);
  assert.equal(metrics.exclusionCounts.unknown_relationship, 1);
  assert.equal(metrics.independenceConfidence, 'high');

  const sybilOnly = computeSkillMetrics(
    events.filter((event) => SYBIL_SETTLEMENT_IDS.has(event.settlementId)),
    { classifier },
  );
  assert.equal(sybilOnly.registryStatus, 'allow_listed');
  assert.equal(sybilOnly.uniqueIndependentBeneficiaries, 1);
  assert.equal(sybilOnly.independenceConfidence, 'medium');
});

test('classification ignores caller-supplied payer claims', () => {
  const unknown = events.find((event) => event.settlementId === 'settlement-009-unknown');
  const unknownMetrics = computeSkillMetrics([unknown], { classifier });
  assert.equal(unknownMetrics.registryStatus, 'allow_listed');
  assert.equal(unknownMetrics.uniqueIndependentBeneficiaries, 0);
  assert.equal(unknownMetrics.independenceConfidence, 'low');
  assert.deepEqual(unknownMetrics.exclusionCounts, {
    self_payment: 0,
    linked_wallet: 0,
    failed_invocation: 0,
    unresolved_settlement: 0,
    refunded: 0,
    recycled_value: 0,
    sybil_cluster: 0,
    unknown_relationship: 1,
  });

  const linked = events.find((event) => event.settlementId === 'settlement-002-linked');
  const linkedMetrics = computeSkillMetrics([linked], { classifier });
  assert.equal(linkedMetrics.registryStatus, 'allow_listed');
  assert.equal(linkedMetrics.exclusionCounts.linked_wallet, 1);

  const changedClaims = events.map((event) => ({
    ...clone(event),
    untrustedPayerClaims: {
      beneficiaryId: `spoof-${event.settlementId}`,
      payerClusterId: `spoof-cluster-${event.settlementId}`,
      relationship: 'independent',
    },
  }));
  const original = computeSkillMetrics(events, { classifier });
  const changed = computeSkillMetrics(changedClaims, { classifier });
  assert.deepEqual(
    { ...changed, auditWarnings: [] },
    { ...original, auditWarnings: [] },
  );
});

test('self classification wins before trusted registry lookup', () => {
  const self = events[0];
  const registry = clone(verifiedBillingRegistry);
  registry.entries[self.payerWallet] = {
    beneficiaryId: 'attacker-controlled-registry-row',
    payerClusterId: 'cluster-attacker',
    relationship: 'independent',
    evidenceRef: 'billing-review:attacker:2026-07-17',
    reviewedAt: '2026-07-17T00:00:00.000Z',
  };
  const localClassifier = createVerifiedBillingClassifier(registry);
  const classification = localClassifier(parseSettlementMetricEvent(self));
  assert.equal(classification.relationship, 'self');
  assert.deepEqual(
    exclusionReasons(self, classification, { seenIndependentClusters: new Set() }),
    ['self_payment'],
  );
});

test('cluster acceptance is independent of caller event order', () => {
  const forward = computeSkillMetrics(events, { classifier });
  const reverse = computeSkillMetrics([...events].reverse(), { classifier });
  assert.deepEqual(reverse, forward);
});

test('metric parser and reducer fail closed on malformed events', () => {
  const base = clone(events[0]);
  for (const [field, value] of [
    ['grossAtomic', '-1'],
    ['grossAtomic', '01'],
    ['grossAtomic', 250000],
    ['refundedAtomic', '250001'],
    ['recycledAtomic', '250001'],
    ['settledAt', '2026-07-17T00:00:00-04:00'],
    ['creatorWallet', '0xABCDEF'],
  ]) {
    const invalid = { ...clone(base), [field]: value };
    assert.throws(() => parseSettlementMetricEvent(invalid), /invalid|must|exceed/i, field);
  }

  assert.throws(
    () => computeSkillMetrics([base, { ...clone(base) }], { classifier }),
    /duplicate settlement/i,
  );
  assert.throws(
    () => computeSkillMetrics([
      base,
      {
        ...clone(events[1]),
        settlementId: 'settlement-unique',
        invocationId: base.invocationId,
      },
    ], { classifier }),
    /duplicate successful Invocation/i,
  );
});

test('trusted registry requires canonical direct evidence records', () => {
  const cases = [
    (() => {
      const value = clone(verifiedBillingRegistry);
      value.entries['0x4444444444444444444444444444444444444444'].evidenceRef = '';
      return value;
    })(),
    (() => {
      const value = clone(verifiedBillingRegistry);
      value.entries['0x4444444444444444444444444444444444444444'].reviewedAt = '2026-07-17';
      return value;
    })(),
    (() => {
      const value = clone(verifiedBillingRegistry);
      value.entries['0x4444444444444444444444444444444444444444'].relationship = 'self';
      return value;
    })(),
    (() => {
      const value = clone(verifiedBillingRegistry);
      value.entries['0x4444444444444444444444444444444444444444'].unexpected = true;
      return value;
    })(),
  ];
  for (const invalid of cases) {
    assert.throws(() => createVerifiedBillingClassifier(invalid), /registry|evidence|timestamp|keys/i);
  }
});

test('ranker is deterministic and leaves caller arrays untouched', () => {
  const ledger = computeSkillMetrics(events, { classifier });
  const second = Object.freeze({
    ...ledger,
    skillId: 'alpha-skill',
    independentNetAtomic: '750000',
  });
  const input = [ledger, second];
  const ranked = rankEligibleSkills(input);
  assert.deepEqual(ranked.map((metric) => metric.skillId), ['alpha-skill', 'ledger-recon']);
  assert.deepEqual(input.map((metric) => metric.skillId), ['ledger-recon', 'alpha-skill']);
  assert.ok(Object.isFrozen(ranked));
});

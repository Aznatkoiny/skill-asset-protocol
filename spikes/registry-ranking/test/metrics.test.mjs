import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

import {
  computeSkillMetrics,
  createVerifiedBillingClassifier,
  exclusionReasons,
  parseSettlementMetricEvent,
  rankEligibleSkills,
} from '../src/metrics.mjs';
import {
  buildRegistryReport,
  renderRegistryError,
  renderRegistryReport,
} from '../src/report.mjs';

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

test('settlement parser snapshots every own enumerable data field exactly once', () => {
  const eventTarget = clone(events[0]);
  const claimsTarget = eventTarget.untrustedPayerClaims;
  const eventDescriptors = new Map();
  const claimDescriptors = new Map();
  let eventReads = 0;
  let claimReads = 0;
  const claims = new Proxy(claimsTarget, {
    getOwnPropertyDescriptor(target, key) {
      claimDescriptors.set(key, (claimDescriptors.get(key) ?? 0) + 1);
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
    get(target, key, receiver) {
      claimReads += 1;
      return Reflect.get(target, key, receiver);
    },
  });
  eventTarget.untrustedPayerClaims = claims;
  const event = new Proxy(eventTarget, {
    getOwnPropertyDescriptor(target, key) {
      eventDescriptors.set(key, (eventDescriptors.get(key) ?? 0) + 1);
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
    get(target, key, receiver) {
      eventReads += 1;
      return Reflect.get(target, key, receiver);
    },
  });

  assert.equal(parseSettlementMetricEvent(event).settlementId, eventTarget.settlementId);
  assert.equal(eventReads, 0);
  assert.equal(claimReads, 0);
  assert.equal(eventDescriptors.size, 13);
  assert.equal(claimDescriptors.size, 3);
  assert.deepEqual([...eventDescriptors.values()], Array(eventDescriptors.size).fill(1));
  assert.deepEqual([...claimDescriptors.values()], Array(claimDescriptors.size).fill(1));

  let getterCalls = 0;
  const accessor = clone(events[0]);
  Object.defineProperty(accessor, 'settledAt', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return events[0].settledAt;
    },
  });
  assert.throws(() => parseSettlementMetricEvent(accessor), /own enumerable data properties/i);
  assert.equal(getterCalls, 0);

  const nestedAccessor = clone(events[0]);
  Object.defineProperty(nestedAccessor.untrustedPayerClaims, 'relationship', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'independent';
    },
  });
  assert.throws(() => parseSettlementMetricEvent(nestedAccessor), /own enumerable data properties/i);
  assert.equal(getterCalls, 0);

  const symbolField = clone(events[0]);
  symbolField[Symbol('unused')] = 'ignored-by-Object.keys';
  assert.throws(() => parseSettlementMetricEvent(symbolField), /string keys/i);

  const malformedUnusedClaim = clone(events[0]);
  malformedUnusedClaim.untrustedPayerClaims.beneficiaryId = '';
  assert.throws(() => parseSettlementMetricEvent(malformedUnusedClaim), /beneficiaryId/i);
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

test('report separates settlement-verifiable metrics from unsupported inferences', () => {
  const metrics = computeSkillMetrics(events, { classifier });
  const report = renderRegistryReport([metrics]);
  for (const heading of [
    'Total settlements',
    'Successful Invocations',
    'Settled failures',
    'Unresolved settlements',
    'Refunded settlements',
    'Unique independent Beneficiaries',
    'Refund-adjusted net',
    'Independent net',
    'Independence confidence',
    'Registry eligibility',
    'Exclusions',
  ]) {
    assert.match(report, new RegExp(heading));
  }
  assert.match(report, /settlement-verifiable/);
  const forbiddenClaims = new RegExp([
    `un${'fakeable'}`,
    `proof of ${'demand'}`,
    `proves ${'quality'}`,
    `supply-chain ${'safety'}`,
  ].join('|'), 'i');
  assert.doesNotMatch(report, forbiddenClaims);
});

test('report rejects duplicate settlement and successful Invocation IDs across Skills', () => {
  const base = clone(events[9]);
  assert.throws(
    () => buildRegistryReport([
      base,
      {
        ...clone(base),
        skillId: 'another-skill',
        invocationId: 'another-invocation',
      },
    ], verifiedBillingRegistry),
    /duplicate settlement/i,
  );
  assert.throws(
    () => buildRegistryReport([
      base,
      {
        ...clone(base),
        skillId: 'another-skill',
        settlementId: 'another-settlement',
      },
    ], verifiedBillingRegistry),
    /duplicate successful Invocation/i,
  );
});

test('report errors are deterministic quoted terminal-safe single lines', () => {
  const unsafe = 'quote" slash\\ c0\u0000 ansi\u001b c1\u0085\u009b bidi\u061c\u200e\u200f'
    + '\u202a\u202e\u2066\u2069\u206f line\u2028\u2029 high\ud800 low\udfff';
  const rendered = renderRegistryError(new Error(unsafe));
  assert.ok(rendered.startsWith('error: "'));
  assert.ok(rendered.endsWith('"'));
  assert.equal(rendered.split('\n').length, 1);
  assert.doesNotMatch(
    rendered,
    /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/u,
  );
  for (const token of [
    '\\"', '\\\\', '\\u0000', '\\u001b', '\\u0085', '\\u009b', '\\u061c',
    '\\u200e', '\\u200f', '\\u2028', '\\u2029', '\\u202a', '\\u202e',
    '\\u2066', '\\u2069', '\\u206f', '\\ud800', '\\udfff',
  ]) assert.ok(rendered.includes(token), token);
});

test('report CLI safely renders a malicious argv filename and preserves JSON output', () => {
  const cliPath = fileURLToPath(new URL('../src/report.mjs', import.meta.url));
  const rootUrl = new URL('../', import.meta.url);
  const hostilePath = 'missing-"\\\n\u001b\u0085\u202e.json';
  const failed = spawnSync(process.execPath, [cliPath, hostilePath, fileURLToPath(registryUrl)], {
    cwd: rootUrl,
    encoding: 'utf8',
  });
  assert.notEqual(failed.status, 0);
  assert.equal(failed.stdout, '');
  assert.ok(failed.stderr.startsWith('error: "'));
  assert.equal(failed.stderr.trimEnd().split('\n').length, 1);
  assert.doesNotMatch(
    failed.stderr,
    /[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u206f]/u,
  );
  for (const token of ['\\"', '\\\\', '\\u000a', '\\u001b', '\\u0085', '\\u202e']) {
    assert.ok(failed.stderr.includes(token), token);
  }

  const succeeded = spawnSync(
    process.execPath,
    [cliPath, fileURLToPath(fixtureUrl), fileURLToPath(registryUrl), '--json'],
    { cwd: rootUrl, encoding: 'utf8' },
  );
  assert.equal(succeeded.status, 0, succeeded.stderr);
  assert.equal(succeeded.stderr, '');
  const expectedJson = `${JSON.stringify(buildRegistryReport(events, verifiedBillingRegistry), null, 2)}\n`;
  assert.equal(succeeded.stdout, expectedJson);
});

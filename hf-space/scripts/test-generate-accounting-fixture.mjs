import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';

import {
  allocateExternalGross,
  allocateInternalGross,
} from '../../prototype/atomic-money.mjs';
import {
  buildFixture,
  canonicalFixtureBytes,
  serializeKernelAllocation,
} from './generate-accounting-fixture.mjs';

const EXTERNAL_SKILLS = {
  'derived-skill': {
    parentIds: ['source-skill'],
    inheritBps: 1500,
    holders: [{ recipientId: 'derived-creator', bps: 10000 }],
  },
  'source-skill': {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: 'source-creator', bps: 10000 }],
  },
};

function jsonSafe(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return value.map(jsonSafe);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, jsonSafe(child)]));
  }
  return value;
}

test('fixture derives all three scenarios from the shared accounting kernel', () => {
  const fixture = buildFixture();
  assert.equal(fixture.defaultScenarioId, 'intra-org');
  assert.equal(fixture.scenarios.length, 3);
  assert.deepEqual(fixture.scenarios.map((scenario) => scenario.id), [
    'intra-org',
    'education',
    'marketplace',
  ]);

  const internal = fixture.scenarios[0];
  assert.equal(internal.allocationKind, 'internal_invocation_award');
  assert.equal(internal.status, 'terminal_product_spike');
  assert.equal(internal.policy, 'internal_award');
  assert.equal(internal.protocolFeeAtomic, '6250');
  assert.equal(internal.invocationAwardAtomic, '193750');
  assert.equal(internal.royaltyPoolAtomic, null);
  assert.equal(internal.allocation.awardCredit.recipientId, 'employee-creator');
  assert.ok(!JSON.stringify(internal).includes('employer:self-credit'));

  for (const external of fixture.scenarios.slice(1)) {
    assert.equal(external.allocationKind, 'external_royalty_claim');
    assert.equal(external.policy, 'LRP');
    assert.equal(external.protocolFeeAtomic, '6250');
    assert.equal(external.royaltyPoolAtomic, '193750');
    assert.equal(external.invocationAwardAtomic, null);
  }
  assert.equal(fixture.scenarios[1].status, 'deferred');
  assert.equal(fixture.scenarios[2].status, 'phase_3_optionality');
});

test('serialized journal entries are exact kernel results and conserve gross', () => {
  const fixture = buildFixture();
  const externalKernel = allocateExternalGross({
    grossAtomic: 250000n,
    executionCostAtomic: 50000n,
    settlementCostAtomic: 0n,
    protocolFeeBps: 250,
    refundReserveAtomic: 0n,
    leafSkillId: 'derived-skill',
    skills: EXTERNAL_SKILLS,
  });
  const internalKernel = allocateInternalGross({
    grossAtomic: 250000n,
    executionCostAtomic: 50000n,
    protocolFeeAtomic: externalKernel.protocolFeeAtomic,
    refundReserveAtomic: 0n,
    recipientId: 'employee-creator',
  });

  assert.deepEqual(fixture.scenarios[0].allocation.journalEntries, jsonSafe(internalKernel.journalEntries));
  for (const scenario of fixture.scenarios.slice(1)) {
    assert.deepEqual(scenario.allocation.journalEntries, jsonSafe(externalKernel.journalEntries));
  }

  for (const scenario of fixture.scenarios) {
    assert.equal(scenario.grossAtomic, '250000');
    assert.equal(scenario.protocolFeeAtomic, '6250');
    assert.equal(scenario.journalEntryDisplayUsdc.length, scenario.allocation.journalEntries.length);
    const total = scenario.allocation.journalEntries.reduce((sum, entry) => {
      assert.match(entry.amountAtomic, /^(0|[1-9][0-9]*)$/);
      assert.equal(entry.debitAccountId, scenario.expectedGrossDebitAccountId);
      assert.equal(typeof entry.creditAccountId, 'string');
      return sum + BigInt(entry.amountAtomic);
    }, 0n);
    assert.equal(total, BigInt(scenario.grossAtomic));
  }
});

test('generator rejects a supplied journal entry not returned by the kernel', () => {
  const kernel = allocateInternalGross({
    grossAtomic: 250000n,
    executionCostAtomic: 50000n,
    protocolFeeAtomic: 6250n,
    refundReserveAtomic: 0n,
    recipientId: 'employee-creator',
  });
  const altered = kernel.journalEntries.map((entry) => ({ ...entry }));
  altered[0].creditAccountId = 'attacker:substitute';
  assert.throws(
    () => serializeKernelAllocation(kernel, {
      expectedGrossDebitAccountId: 'employer:invocation-gross',
      journalEntries: altered,
    }),
    /not the kernel-returned journal/i,
  );
});

test('fixture hash covers canonical fixture bytes with the hash field omitted', () => {
  const fixture = buildFixture();
  const { fixtureSha256, ...withoutHash } = fixture;
  const expected = `sha256:${createHash('sha256').update(canonicalFixtureBytes(withoutHash)).digest('hex')}`;
  assert.equal(fixtureSha256, expected);
  assert.ok(canonicalFixtureBytes(fixture).endsWith('\n'));
  assert.deepEqual(buildFixture(), fixture);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ATOMIC_PER_USDC,
  BPS_DENOMINATOR,
  ROYALTY_ALLOCATION_POLICY,
  allocateByBps,
  allocateByWeights,
  allocateExternalGross,
  allocateInternalGross,
  allocateRoyaltyGraph,
  assertAtomic,
  floorBps,
  formatUsdc,
  parseUsdc,
} from '../atomic-money.mjs';

test('parseUsdc converts exact display values to six-decimal atomic units', () => {
  assert.equal(ATOMIC_PER_USDC, 1_000_000n);
  assert.equal(BPS_DENOMINATOR, 10_000n);
  assert.equal(parseUsdc('0'), 0n);
  assert.equal(parseUsdc('0.000001'), 1n);
  assert.equal(parseUsdc('0.25'), 250_000n);
  assert.equal(parseUsdc('9007199254740991.123456'), 9_007_199_254_740_991_123_456n);
});

test('parseUsdc rejects every non-string, negative, exponent, and over-precision input', () => {
  for (const value of [
    '-1', '0.0000001', '1e-6', '', 0.25, 0, Number.NaN, Number.POSITIVE_INFINITY,
    -0.01, 9_007_199_254.740992, 1n, null,
  ]) {
    assert.throws(() => parseUsdc(value), (error) => error?.name === 'MoneyInputError');
  }
});

test('assertAtomic accepts only non-negative bigint values', () => {
  assert.equal(assertAtomic(0n), 0n);
  assert.equal(assertAtomic(7n), 7n);
  assert.throws(() => assertAtomic(-1n), /must be non-negative/);
  for (const value of [1, '1', null, undefined]) {
    assert.throws(() => assertAtomic(value), /must be a bigint/);
  }
});

test('formatUsdc is a canonical six-decimal serialization boundary', () => {
  assert.equal(formatUsdc(0n), '0.000000');
  assert.equal(formatUsdc(1n), '0.000001');
  assert.equal(formatUsdc(250_000n), '0.250000');
  assert.equal(formatUsdc(1_000_001n), '1.000001');
});

test('floorBps floors deterministically without using floating point', () => {
  assert.equal(floorBps(250_000n, 250), 6_250n);
  assert.equal(floorBps(1n, 5_000), 0n);
  assert.equal(floorBps(3n, 5_000), 1n);
  assert.throws(() => floorBps(1n, -1), /between 0 and 10000/);
  assert.throws(() => floorBps(1n, 10_001), /between 0 and 10000/);
  assert.throws(() => floorBps(1n, 1.5), /safe integer/);
});

test('allocateByWeights conserves atomic units and assigns remainder by stable key', () => {
  const shares = [
    { key: 'zoe', weight: 1 },
    { key: 'alice', weight: 1 },
    { key: 'mika', weight: 1 },
  ];
  assert.deepEqual(allocateByWeights(10_000n, shares), [
    { key: 'alice', amountAtomic: 3_334n },
    { key: 'mika', amountAtomic: 3_333n },
    { key: 'zoe', amountAtomic: 3_333n },
  ]);
  assert.deepEqual(allocateByWeights(1n, [...shares].reverse()), [
    { key: 'alice', amountAtomic: 1n },
    { key: 'mika', amountAtomic: 0n },
    { key: 'zoe', amountAtomic: 0n },
  ]);
});

test('allocateByBps requires one complete, unique 10000-bps claim table', () => {
  assert.deepEqual(allocateByBps(1n, [
    { key: 'creator', bps: 5_000 },
    { key: 'employer', bps: 5_000 },
  ]), [
    { key: 'creator', amountAtomic: 1n },
    { key: 'employer', amountAtomic: 0n },
  ]);
  assert.throws(
    () => allocateByBps(100n, [{ key: 'creator', bps: 9_999 }]),
    /sum to 10000/,
  );
  assert.throws(() => allocateByBps(100n, [
    { key: 'creator', bps: 5_000 },
    { key: 'creator', bps: 5_000 },
  ]), /duplicate allocation key/);
});

test('allocators reject unsafe values and do not mutate caller-owned frozen inputs', () => {
  const shares = Object.freeze([
    Object.freeze({ key: 'b', weight: 1 }),
    Object.freeze({ key: 'a', weight: 2 }),
  ]);
  allocateByWeights(7n, shares);
  assert.deepEqual(shares, [{ key: 'b', weight: 1 }, { key: 'a', weight: 2 }]);

  assert.throws(() => allocateByWeights(-1n, shares), /must be non-negative/);
  assert.throws(() => allocateByWeights(1, shares), /must be a bigint/);
  assert.throws(() => allocateByWeights(1n, [{ key: 'a', weight: -1 }]), /non-negative/);
  assert.throws(() => allocateByWeights(1n, [{ key: 'a', weight: 0 }]), /must be positive/);
});

const chain = (depth, inheritBps = 3_000) => Object.fromEntries(
  Array.from({ length: depth + 1 }, (_, index) => [`skill-${index}`, {
    parentIds: index === 0 ? [] : [`skill-${index - 1}`],
    inheritBps,
    holders: [{ recipientId: `creator-${index}`, bps: 10_000 }],
  }]),
);

test('allocateRoyaltyGraph conserves one-atomic remainders at every ancestry depth', () => {
  for (let depth = 0; depth <= 4; depth += 1) {
    for (const royaltyPoolAtomic of [0n, 1n, 2n, 9_999n, 250_001n]) {
      const result = allocateRoyaltyGraph({
        royaltyPoolAtomic,
        leafSkillId: `skill-${depth}`,
        skills: chain(depth),
      });
      assert.equal(result.allocationPolicy, ROYALTY_ALLOCATION_POLICY);
      assert.equal(
        result.credits.reduce((sum, credit) => sum + credit.amountAtomic, 0n),
        royaltyPoolAtomic,
      );
      assert.equal(
        result.holderCredits.reduce((sum, credit) => sum + credit.amountAtomic, 0n)
          + result.ancestorCredits.reduce((sum, credit) => sum + credit.amountAtomic, 0n),
        royaltyPoolAtomic,
      );
    }
  }
});

test('allocateRoyaltyGraph names the LRP-like policy and rejects unimplemented LAP allocation', () => {
  const result = allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'skill-0',
    skills: chain(0),
    allocationPolicy: 'lrp-per-hop-v1',
  });
  assert.equal(result.allocationPolicy, 'lrp-per-hop-v1');
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'skill-0',
    skills: chain(0),
    allocationPolicy: 'lap-whole-ancestry-v1',
  }), /unsupported royalty allocation policy/);
});

test('allocateRoyaltyGraph splits co-held claims in stable recipient order', () => {
  const result = allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'root',
    skills: {
      root: {
        parentIds: [],
        inheritBps: 0,
        holders: [
          { recipientId: 'employee', bps: 5_000 },
          { recipientId: 'employer', bps: 5_000 },
        ],
      },
    },
  });
  assert.deepEqual(result.credits, [
    {
      recipientId: 'employee', viaSkillId: 'root', depth: 0,
      kind: 'holder', amountAtomic: 1n,
    },
    {
      recipientId: 'employer', viaSkillId: 'root', depth: 0,
      kind: 'holder', amountAtomic: 0n,
    },
  ]);
});

test('allocateRoyaltyGraph rejects missing nodes, duplicate parents, and cycles at zero pools', () => {
  for (const royaltyPoolAtomic of [0n, 1n]) {
    assert.throws(() => allocateRoyaltyGraph({
      royaltyPoolAtomic,
      leafSkillId: 'missing',
      skills: {},
    }), /unknown Skill/);
    assert.throws(() => allocateRoyaltyGraph({
      royaltyPoolAtomic,
      leafSkillId: 'a',
      skills: {
        a: {
          parentIds: ['b'], inheritBps: 1_000,
          holders: [{ recipientId: 'a', bps: 10_000 }],
        },
        b: {
          parentIds: ['a'], inheritBps: 1_000,
          holders: [{ recipientId: 'b', bps: 10_000 }],
        },
      },
    }), /ancestry cycle/);
  }
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'leaf',
    skills: {
      leaf: {
        parentIds: ['root', 'root'], inheritBps: 1_000,
        holders: [{ recipientId: 'leaf', bps: 10_000 }],
      },
      root: {
        parentIds: [], inheritBps: 0,
        holders: [{ recipientId: 'root', bps: 10_000 }],
      },
    },
  }), /duplicate parent/);
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'skill-33',
    skills: chain(33),
  }), /maximum depth 32/);
});

test('shared ancestry cannot hide a path deeper than 32 behind validation memoization', () => {
  const holder = (recipientId) => [{ recipientId, bps: 10_000 }];
  const skills = {
    leaf: { parentIds: ['a-short', 'b-0'], inheritBps: 5_000, holders: holder('leaf') },
    'a-short': { parentIds: ['shared'], inheritBps: 10_000, holders: holder('a') },
    shared: { parentIds: ['suffix'], inheritBps: 10_000, holders: holder('shared') },
    suffix: { parentIds: [], inheritBps: 0, holders: holder('suffix') },
  };
  for (let index = 0; index <= 30; index += 1) {
    skills[`b-${index}`] = {
      parentIds: index === 30 ? ['shared'] : [`b-${index + 1}`],
      inheritBps: 10_000,
      holders: holder(`b-holder-${index}`),
    };
  }
  for (const royaltyPoolAtomic of [0n, 1n]) {
    assert.throws(() => allocateRoyaltyGraph({
      royaltyPoolAtomic,
      leafSkillId: 'leaf',
      skills,
    }), /maximum depth 32/);
  }
});

function expandingSharedDag(stages) {
  const holders = (recipientId) => [{ recipientId, bps: 10_000 }];
  const skills = {
    leaf: { parentIds: ['left-0', 'right-0'], inheritBps: 10_000, holders: holders('leaf') },
  };
  for (let index = 0; index < stages; index += 1) {
    const next = index === stages - 1 ? 'root' : `shared-${index}`;
    skills[`left-${index}`] = {
      parentIds: [next], inheritBps: 10_000, holders: holders(`left-holder-${index}`),
    };
    skills[`right-${index}`] = {
      parentIds: [next], inheritBps: 10_000, holders: holders(`right-holder-${index}`),
    };
    if (index < stages - 1) {
      skills[`shared-${index}`] = {
        parentIds: [`left-${index + 1}`, `right-${index + 1}`],
        inheritBps: 10_000,
        holders: holders(`shared-holder-${index}`),
      };
    }
  }
  skills.root = { parentIds: [], inheritBps: 0, holders: holders('root-holder') };
  return skills;
}

test('allocateRoyaltyGraph bounds repeated distribution visits in shared DAGs', () => {
  const skills = expandingSharedDag(11);
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n << 20n,
    leafSkillId: 'leaf',
    skills,
  }), /distribution exceeds maximum 1024 visits/);
});

test('allocateRoyaltyGraph leaves a deeply frozen claim graph unchanged', () => {
  const skills = Object.freeze({
    root: Object.freeze({
      parentIds: Object.freeze([]),
      inheritBps: 0,
      holders: Object.freeze([Object.freeze({ recipientId: 'creator', bps: 10_000 })]),
    }),
  });
  allocateRoyaltyGraph({ royaltyPoolAtomic: 0n, leafSkillId: 'root', skills });
  assert.deepEqual(skills, {
    root: { parentIds: [], inheritBps: 0, holders: [{ recipientId: 'creator', bps: 10_000 }] },
  });
});

test('allocateExternalGross subtracts costs, fee, and reserve before the Royalty pool', () => {
  const result = allocateExternalGross({
    grossAtomic: 250_000n,
    executionCostAtomic: 60_000n,
    settlementCostAtomic: 1_000n,
    protocolFeeBps: 250,
    refundReserveAtomic: 2_000n,
    leafSkillId: 'skill',
    skills: {
      skill: {
        parentIds: [],
        inheritBps: 0,
        holders: [{ recipientId: 'creator', bps: 10_000 }],
      },
    },
  });
  assert.equal(result.allocationPolicy, 'lrp-per-hop-v1');
  assert.equal(result.protocolFeeAtomic, 6_250n);
  assert.equal(result.royaltyPoolAtomic, 180_750n);
  assert.equal(result.holderCredits[0].amountAtomic, 180_750n);
  assert.equal(
    result.executionCostAtomic + result.settlementCostAtomic + result.protocolFeeAtomic
      + result.royaltyPoolAtomic + result.refundReserveAtomic,
    result.grossAtomic,
  );
  assert.deepEqual(
    result.journalEntries.map(({ debitAccountId, creditAccountId, amountAtomic }) => ({
      debitAccountId, creditAccountId, amountAtomic,
    })),
    [
      {
        debitAccountId: 'wielder:external-gross',
        creditAccountId: 'provider:execution',
        amountAtomic: 60_000n,
      },
      {
        debitAccountId: 'wielder:external-gross',
        creditAccountId: 'provider:settlement',
        amountAtomic: 1_000n,
      },
      {
        debitAccountId: 'wielder:external-gross',
        creditAccountId: 'protocol:treasury',
        amountAtomic: 6_250n,
      },
      {
        debitAccountId: 'wielder:external-gross',
        creditAccountId: 'reserve:refund',
        amountAtomic: 2_000n,
      },
      {
        debitAccountId: 'wielder:external-gross',
        creditAccountId: 'royalty:creator',
        amountAtomic: 180_750n,
      },
    ],
  );
});

test('allocateInternalGross leaves one exact employee Invocation award', () => {
  const result = allocateInternalGross({
    grossAtomic: 200_000n,
    executionCostAtomic: 50_000n,
    protocolFeeAtomic: 5_000n,
    refundReserveAtomic: 5_000n,
    recipientId: 'employee-1',
  });
  assert.deepEqual(result.awardCredit, { recipientId: 'employee-1', amountAtomic: 140_000n });
  assert.equal(
    result.executionCostAtomic + result.protocolFeeAtomic
      + result.refundReserveAtomic + result.invocationAwardAtomic,
    result.grossAtomic,
  );
  assert.deepEqual(result.journalEntries, [
    {
      category: 'execution-cogs', debitAccountId: 'employer:invocation-gross',
      creditAccountId: 'provider:execution', amountAtomic: 50_000n,
    },
    {
      category: 'protocol-fee', debitAccountId: 'employer:invocation-gross',
      creditAccountId: 'protocol:treasury', amountAtomic: 5_000n,
    },
    {
      category: 'refund-reserve', debitAccountId: 'employer:invocation-gross',
      creditAccountId: 'reserve:refund', amountAtomic: 5_000n,
    },
    {
      category: 'invocation-award', debitAccountId: 'employer:invocation-gross',
      creditAccountId: 'employee:employee-1', amountAtomic: 140_000n,
    },
  ]);
});

test('gross partitions reject insufficient, negative, and non-bigint monetary inputs', () => {
  const external = {
    grossAtomic: 100n,
    executionCostAtomic: 0n,
    settlementCostAtomic: 0n,
    protocolFeeBps: 0,
    refundReserveAtomic: 0n,
    leafSkillId: 'skill',
    skills: chain(0),
  };
  const internal = {
    grossAtomic: 100n,
    executionCostAtomic: 0n,
    protocolFeeAtomic: 0n,
    refundReserveAtomic: 0n,
    recipientId: 'employee',
  };

  assert.throws(() => allocateExternalGross({
    ...external, executionCostAtomic: 99n, protocolFeeBps: 250,
  }), /cannot cover costs/);
  assert.throws(() => allocateInternalGross({
    ...internal, executionCostAtomic: 101n,
  }), /cannot cover costs/);

  for (const field of [
    'grossAtomic', 'executionCostAtomic', 'settlementCostAtomic', 'refundReserveAtomic',
  ]) {
    assert.throws(() => allocateExternalGross({ ...external, [field]: -1n }), /non-negative/);
    assert.throws(() => allocateExternalGross({ ...external, [field]: 1 }), /must be a bigint/);
  }
  for (const field of [
    'grossAtomic', 'executionCostAtomic', 'protocolFeeAtomic', 'refundReserveAtomic',
  ]) {
    assert.throws(() => allocateInternalGross({ ...internal, [field]: -1n }), /non-negative/);
    assert.throws(() => allocateInternalGross({ ...internal, [field]: 1 }), /must be a bigint/);
  }
});

test('gross partitions accept frozen inputs without mutation and reject unsupported policy', () => {
  const external = Object.freeze({
    grossAtomic: 100n,
    executionCostAtomic: 0n,
    settlementCostAtomic: 0n,
    protocolFeeBps: 0,
    refundReserveAtomic: 0n,
    leafSkillId: 'skill-0',
    skills: Object.freeze({
      'skill-0': Object.freeze({
        parentIds: Object.freeze([]),
        inheritBps: 0,
        holders: Object.freeze([
          Object.freeze({ recipientId: 'creator', bps: 10_000 }),
        ]),
      }),
    }),
  });
  const internal = Object.freeze({
    grossAtomic: 100n,
    executionCostAtomic: 1n,
    protocolFeeAtomic: 2n,
    refundReserveAtomic: 3n,
    recipientId: 'employee',
  });

  allocateExternalGross(external);
  allocateInternalGross(internal);
  assert.equal(external.grossAtomic, 100n);
  assert.equal(internal.grossAtomic, 100n);
  assert.throws(() => allocateExternalGross({
    ...external,
    allocationPolicy: 'lap-whole-ancestry-v1',
  }), /unsupported royalty allocation policy/);
});

const branchingClaims = () => ({
  leaf: {
    parentIds: ['root-b', 'root-a'],
    inheritBps: 3_333,
    holders: [
      { recipientId: 'employee', bps: 3_333 },
      { recipientId: 'employer', bps: 6_667 },
    ],
  },
  'root-a': {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: 'alice', bps: 5_001 }, { recipientId: 'acme', bps: 4_999 }],
  },
  'root-b': {
    parentIds: [],
    inheritBps: 0,
    holders: [{ recipientId: 'bob', bps: 7_777 }, { recipientId: 'beta', bps: 2_223 }],
  },
});

function assertBalanced(result, expectedSourceAccount, grossAtomic) {
  const debits = result.journalEntries.map((entry) => ({
    accountId: entry.debitAccountId,
    amountAtomic: entry.amountAtomic,
  }));
  const credits = result.journalEntries.map((entry) => ({
    accountId: entry.creditAccountId,
    amountAtomic: entry.amountAtomic,
  }));
  const debitTotal = debits.reduce((sum, entry) => sum + entry.amountAtomic, 0n);
  const creditTotal = credits.reduce((sum, entry) => sum + entry.amountAtomic, 0n);
  assert.equal(debitTotal, grossAtomic);
  assert.equal(creditTotal, grossAtomic);
  assert.ok(debits.every((entry) => entry.accountId === expectedSourceAccount));
  assert.ok(credits.every((entry) => entry.accountId && entry.amountAtomic >= 0n));
}

test('152-case external matrix conserves gross across costs, claims, ancestry, and rounding', () => {
  let cases = 0;
  const claimGraphs = [
    { leafSkillId: 'skill-2', skills: chain(2) },
    { leafSkillId: 'leaf', skills: branchingClaims() },
  ];
  for (const grossAtomic of [250_001n, 1_000_003n]) {
    for (const executionCostAtomic of [0n, 17n]) {
      for (const settlementCostAtomic of [0n, 13n]) {
        for (const refundReserveAtomic of [0n, 11n]) {
          for (const protocolFeeBps of [0, 1, 250, 3_333]) {
            for (const graph of claimGraphs) {
              const result = allocateExternalGross({
                grossAtomic,
                executionCostAtomic,
                settlementCostAtomic,
                protocolFeeBps,
                refundReserveAtomic,
                ...graph,
              });
              assert.equal(
                result.executionCostAtomic + result.settlementCostAtomic
                  + result.protocolFeeAtomic + result.royaltyPoolAtomic
                  + result.refundReserveAtomic,
                grossAtomic,
              );
              assert.equal(
                result.credits.reduce((sum, credit) => sum + credit.amountAtomic, 0n),
                result.royaltyPoolAtomic,
              );
              assertBalanced(result, 'wielder:external-gross', grossAtomic);
              cases += 1;
            }
          }
        }
      }
    }
  }
  for (const grossAtomic of [0n, 1n, 2n]) {
    for (const protocolFeeBps of [0, 1, 250, 3_333]) {
      for (const graph of claimGraphs) {
        const result = allocateExternalGross({
          grossAtomic,
          executionCostAtomic: 0n,
          settlementCostAtomic: 0n,
          protocolFeeBps,
          refundReserveAtomic: 0n,
          ...graph,
        });
        assertBalanced(result, 'wielder:external-gross', grossAtomic);
        assert.ok(result.credits.every((credit) => credit.amountAtomic >= 0n));
        cases += 1;
      }
    }
  }
  assert.equal(cases, 152);
});

test('20-case internal matrix conserves employer gross at zero, dust, and large amounts', () => {
  let cases = 0;
  for (const grossAtomic of [0n, 1n, 2n, 250_001n]) {
    for (const executionCostAtomic of [0n, 1n]) {
      for (const protocolFeeAtomic of [0n, 1n]) {
        for (const refundReserveAtomic of [0n, 1n]) {
          if (executionCostAtomic + protocolFeeAtomic + refundReserveAtomic > grossAtomic) {
            continue;
          }
          const result = allocateInternalGross({
            grossAtomic,
            executionCostAtomic,
            protocolFeeAtomic,
            refundReserveAtomic,
            recipientId: 'employee',
          });
          assert.equal(
            result.executionCostAtomic + result.protocolFeeAtomic
              + result.refundReserveAtomic + result.invocationAwardAtomic,
            grossAtomic,
          );
          assertBalanced(result, 'employer:invocation-gross', grossAtomic);
          const awardEntries = result.journalEntries.filter(
            (entry) => entry.category === 'invocation-award',
          );
          assert.deepEqual(awardEntries, [{
            category: 'invocation-award',
            debitAccountId: 'employer:invocation-gross',
            creditAccountId: 'employee:employee',
            amountAtomic: result.invocationAwardAtomic,
          }]);
          cases += 1;
        }
      }
    }
  }
  assert.equal(cases, 20);
});

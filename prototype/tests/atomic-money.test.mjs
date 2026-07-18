import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ATOMIC_PER_USDC,
  BPS_DENOMINATOR,
  ROYALTY_ALLOCATION_POLICY,
  allocateByBps,
  allocateByWeights,
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

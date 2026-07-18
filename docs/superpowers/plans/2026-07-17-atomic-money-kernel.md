# Atomic Money Kernel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pure USDC atomic-unit allocation kernel that rejects unsafe inputs and proves exact conservation for external Royalty-claim and internal Invocation-award allocations.

**Architecture:** Add `prototype/atomic-money.mjs` as the single zero-dependency money boundary: parse display USDC once, calculate only with non-negative `bigint` atomic units, and format only at report/UI edges. The module owns deterministic weighted remainders, recursive Derivative ancestry allocation, and external/internal gross partitions; existing settlement and Collar consumers migrate in later plans so this plan can land as a focused, independently tested kernel.

**Tech Stack:** Node.js 20+, ECMAScript modules, built-in `node:test`, `node:assert/strict`, `bigint`; offline-only tests with no wallet, funds, provider key, or network access.

---

## File map and public contract

- Create `prototype/atomic-money.mjs`: parsing, formatting, basis-point math, deterministic allocation, ancestry traversal, and gross-partition functions.
- Create `prototype/tests/atomic-money.test.mjs`: boundary, conservation, remainder, ancestry, mutation-safety, and deterministic property-matrix tests.
- Modify `prototype/package.json`: replace the currently failing test command with the offline Node test command.
- Modify `prototype/README.md`: identify the new kernel as the future accounting source and label `settlement-engine.mjs` as an unmigrated historical consumer until the later runtime plans land.

All public monetary fields use `bigint` in process and decimal strings only when serialized. No public allocator accepts dollar floats.

### Task 1: Establish the atomic-USDC boundary

**Files:**
- Create: `prototype/atomic-money.mjs`
- Create: `prototype/tests/atomic-money.test.mjs`
- Modify: `prototype/package.json:6-9`

- [ ] **Step 1: Replace the currently failing package test command**

Change `prototype/package.json` to keep the existing package metadata and use these scripts:

```json
"scripts": {
  "test": "node --test tests/*.test.mjs",
  "test:fork-economics": "node spike-fork-economics.mjs"
}
```

- [ ] **Step 2: Write failing parse, validation, formatting, and basis-point tests**

Create `prototype/tests/atomic-money.test.mjs`:

```js
import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ATOMIC_PER_USDC,
  BPS_DENOMINATOR,
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
  for (const value of ['-1', '0.0000001', '1e-6', '', 0.25, 0, NaN, Infinity, -0.01, 9_007_199_254.740992, 1n, null]) {
    assert.throws(() => parseUsdc(value), (error) => error?.name === 'MoneyInputError');
  }
});

test('assertAtomic accepts only non-negative bigint values', () => {
  assert.equal(assertAtomic(0n), 0n);
  assert.equal(assertAtomic(7n), 7n);
  assert.throws(() => assertAtomic(-1n), /must be non-negative/);
  assert.throws(() => assertAtomic(1), /must be a bigint/);
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
});
```

- [ ] **Step 3: Run the test and verify the module is missing**

Run: `npm test --prefix prototype`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `prototype/atomic-money.mjs`.

- [ ] **Step 4: Implement the input boundary and basis-point primitive**

Create `prototype/atomic-money.mjs`:

```js
export const USDC_DECIMALS = 6;
export const ATOMIC_PER_USDC = 10n ** BigInt(USDC_DECIMALS);
export const BPS_DENOMINATOR = 10_000n;

export class MoneyInputError extends RangeError {
  constructor(code, message) {
    super(message);
    this.name = 'MoneyInputError';
    this.code = code;
  }
}

function fail(code, message) {
  throw new MoneyInputError(code, message);
}

export function assertAtomic(value, label = 'amountAtomic') {
  if (typeof value !== 'bigint') fail('ATOMIC_TYPE', `${label} must be a bigint`);
  if (value < 0n) fail('ATOMIC_NEGATIVE', `${label} must be non-negative`);
  return value;
}

export function assertBps(value, label = 'bps') {
  if (!Number.isSafeInteger(value)) fail('BPS_INTEGER', `${label} must be a safe integer`);
  if (value < 0 || value > 10_000) fail('BPS_RANGE', `${label} must be between 0 and 10000`);
  return BigInt(value);
}

export function parseUsdc(value, label = 'USDC amount') {
  if (typeof value !== 'string') fail('DISPLAY_TYPE', `${label} must be a decimal string`);
  const text = value.trim();

  const match = /^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/.exec(text);
  if (!match) fail('DISPLAY_FORMAT', `${label} must be a non-negative decimal with at most six fractional digits`);
  const whole = BigInt(match[1]);
  const fraction = BigInt((match[2] ?? '').padEnd(USDC_DECIMALS, '0') || '0');
  return whole * ATOMIC_PER_USDC + fraction;
}

export function formatUsdc(value) {
  const atomic = assertAtomic(value);
  const whole = atomic / ATOMIC_PER_USDC;
  const fraction = String(atomic % ATOMIC_PER_USDC).padStart(USDC_DECIMALS, '0');
  return `${whole}.${fraction}`;
}

export function floorBps(amountAtomic, bps) {
  return (assertAtomic(amountAtomic) * assertBps(bps)) / BPS_DENOMINATOR;
}
```

- [ ] **Step 5: Run the focused test and verify the boundary passes**

Run: `npm test --prefix prototype`

Expected: PASS, 5 tests and 0 failures. In particular, no JavaScript `number`
crosses the display-to-atomic boundary; callers must pass an exact decimal string.

- [ ] **Step 6: Commit the boundary**

```bash
git add prototype/package.json prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs
git commit -m "feat: add atomic USDC boundary"
```

### Task 2: Add deterministic weighted and basis-point allocation

**Files:**
- Modify: `prototype/atomic-money.mjs`
- Modify: `prototype/tests/atomic-money.test.mjs`

- [ ] **Step 1: Append failing deterministic-remainder tests**

Add these imports to the existing import list in `prototype/tests/atomic-money.test.mjs`:

```js
  allocateByBps,
  allocateByWeights,
```

Append:

```js
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
  assert.throws(() => allocateByBps(100n, [{ key: 'creator', bps: 9_999 }]), /sum to 10000/);
  assert.throws(() => allocateByBps(100n, [
    { key: 'creator', bps: 5_000 },
    { key: 'creator', bps: 5_000 },
  ]), /duplicate allocation key/);
});

test('allocators do not mutate caller-owned frozen inputs', () => {
  const shares = Object.freeze([
    Object.freeze({ key: 'b', weight: 1 }),
    Object.freeze({ key: 'a', weight: 2 }),
  ]);
  allocateByWeights(7n, shares);
  assert.deepEqual(shares, [{ key: 'b', weight: 1 }, { key: 'a', weight: 2 }]);
});
```

- [ ] **Step 2: Run the test and verify the allocators are undefined**

Run: `npm test --prefix prototype`

Expected: FAIL because `allocateByWeights` and `allocateByBps` are not exported.

- [ ] **Step 3: Implement stable weighted allocation**

Append to `prototype/atomic-money.mjs`:

```js
function weightToBigInt(value, label) {
  if (typeof value === 'bigint') {
    if (value < 0n) fail('WEIGHT_NEGATIVE', `${label} must be non-negative`);
    return value;
  }
  if (!Number.isSafeInteger(value) || value < 0) {
    fail('WEIGHT_INTEGER', `${label} must be a non-negative safe integer or bigint`);
  }
  return BigInt(value);
}

const compareKeys = (left, right) => left.key < right.key ? -1 : left.key > right.key ? 1 : 0;

export function allocateByWeights(amountAtomic, shares) {
  const amount = assertAtomic(amountAtomic);
  if (!Array.isArray(shares) || shares.length === 0) {
    fail('ALLOCATIONS_EMPTY', 'shares must contain at least one allocation');
  }

  const seen = new Set();
  const rows = shares.map((share, index) => {
    const key = String(share?.key ?? '');
    if (!key) fail('ALLOCATION_KEY', `shares[${index}].key must be non-empty`);
    if (seen.has(key)) fail('ALLOCATION_DUPLICATE', `duplicate allocation key '${key}'`);
    seen.add(key);
    return { key, weight: weightToBigInt(share.weight, `shares[${index}].weight`) };
  }).sort(compareKeys);

  const totalWeight = rows.reduce((sum, row) => sum + row.weight, 0n);
  if (totalWeight === 0n) fail('WEIGHTS_ZERO', 'at least one allocation weight must be positive');

  const allocations = rows.map((row) => ({
    key: row.key,
    weight: row.weight,
    amountAtomic: (amount * row.weight) / totalWeight,
  }));
  let remainder = amount - allocations.reduce((sum, row) => sum + row.amountAtomic, 0n);
  for (const row of allocations) {
    if (remainder === 0n) break;
    if (row.weight === 0n) continue;
    row.amountAtomic += 1n;
    remainder -= 1n;
  }
  if (remainder !== 0n) throw new Error('internal invariant: weighted remainder was not exhausted');
  return allocations.map(({ key, amountAtomic }) => ({ key, amountAtomic }));
}

export function allocateByBps(amountAtomic, shares) {
  if (!Array.isArray(shares) || shares.length === 0) {
    fail('ALLOCATIONS_EMPTY', 'shares must contain at least one allocation');
  }
  const normalized = shares.map((share, index) => ({
    key: share?.key,
    weight: assertBps(share?.bps, `shares[${index}].bps`),
  }));
  const total = normalized.reduce((sum, row) => sum + row.weight, 0n);
  if (total !== BPS_DENOMINATOR) fail('BPS_TOTAL', `basis-point allocations must sum to 10000 (got ${total})`);
  return allocateByWeights(amountAtomic, normalized);
}
```

- [ ] **Step 4: Run the test and verify deterministic conservation**

Run: `npm test --prefix prototype`

Expected: PASS, 8 tests and 0 failures.

- [ ] **Step 5: Commit the allocation primitive**

```bash
git add prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs
git commit -m "feat: conserve weighted atomic allocations"
```

### Task 3: Allocate a Royalty pool through Derivative ancestry

**Files:**
- Modify: `prototype/atomic-money.mjs`
- Modify: `prototype/tests/atomic-money.test.mjs`

- [ ] **Step 1: Append failing ancestry and cycle tests**

Add `allocateRoyaltyGraph` to the test import list, then append:

```js
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
    { recipientId: 'employee', viaSkillId: 'root', depth: 0, kind: 'holder', amountAtomic: 1n },
    { recipientId: 'employer', viaSkillId: 'root', depth: 0, kind: 'holder', amountAtomic: 0n },
  ]);
});

test('allocateRoyaltyGraph rejects missing nodes, duplicate parents, and cycles even at rounded-zero pools', () => {
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
        a: { parentIds: ['b'], inheritBps: 1_000, holders: [{ recipientId: 'a', bps: 10_000 }] },
        b: { parentIds: ['a'], inheritBps: 1_000, holders: [{ recipientId: 'b', bps: 10_000 }] },
      },
    }), /ancestry cycle/);
  }
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'leaf',
    skills: {
      leaf: { parentIds: ['root', 'root'], inheritBps: 1_000, holders: [{ recipientId: 'leaf', bps: 10_000 }] },
      root: { parentIds: [], inheritBps: 0, holders: [{ recipientId: 'root', bps: 10_000 }] },
    },
  }), /duplicate parent/);
  assert.throws(() => allocateRoyaltyGraph({
    royaltyPoolAtomic: 1n,
    leafSkillId: 'skill-33',
    skills: chain(33),
  }), /maximum depth 32/);
});

test('shared ancestry cannot hide a path deeper than 32 behind shallow validation memoization', () => {
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
```

- [ ] **Step 2: Run the tests and verify graph allocation is missing**

Run: `npm test --prefix prototype`

Expected: FAIL because `allocateRoyaltyGraph` is not exported.

- [ ] **Step 3: Implement recursive, deterministic ancestry allocation**

Append to `prototype/atomic-money.mjs`:

```js
export function allocateRoyaltyGraph({ royaltyPoolAtomic, leafSkillId, skills }) {
  const pool = assertAtomic(royaltyPoolAtomic, 'royaltyPoolAtomic');
  if (!skills || typeof skills !== 'object' || Array.isArray(skills)) {
    fail('SKILLS_TYPE', 'skills must be an object keyed by Skill identifier');
  }
  const credits = [];
  const visiting = new Set();

  const deepestValidatedDepth = new Map();
  const validating = new Set();
  const reachableNodes = new Set();
  function validateReachable(skillId, depth) {
    if (depth > 32) fail('ANCESTRY_DEPTH', 'Derivative ancestry exceeds maximum depth 32');
    if (validating.has(skillId)) fail('ANCESTRY_CYCLE', `ancestry cycle contains Skill '${skillId}'`);
    const priorDepth = deepestValidatedDepth.get(skillId);
    // A prior visit at an equal or greater depth had less remaining depth budget and
    // is safe to reuse. A deeper new path must be traversed again.
    if (priorDepth != null && priorDepth >= depth) return;
    const skill = skills[skillId];
    if (!skill) fail('SKILL_UNKNOWN', `unknown Skill '${skillId}'`);
    reachableNodes.add(skillId);
    if (reachableNodes.size > 128) fail('ANCESTRY_NODES', 'Derivative ancestry exceeds maximum 128 reachable Skills');
    validating.add(skillId);
    const parentIds = [...(skill.parentIds ?? [])].map(String).sort();
    if (new Set(parentIds).size !== parentIds.length) {
      fail('PARENT_DUPLICATE', `Skill '${skillId}' has a duplicate parent`);
    }
    if (parentIds.length) assertBps(skill.inheritBps, `${skillId}.inheritBps`);
    allocateByBps(0n, (skill.holders ?? []).map((holder) => ({
      key: holder.recipientId,
      bps: holder.bps,
    })));
    for (const parentId of parentIds) validateReachable(parentId, depth + 1);
    validating.delete(skillId);
    deepestValidatedDepth.set(skillId, Math.max(priorDepth ?? -1, depth));
  }
  validateReachable(String(leafSkillId), 0);

  function distribute(skillId, amountAtomic, depth) {
    if (depth > 32) fail('ANCESTRY_DEPTH', 'Derivative ancestry exceeds maximum depth 32');
    const skill = skills[skillId];
    if (!skill) fail('SKILL_UNKNOWN', `unknown Skill '${skillId}'`);
    if (visiting.has(skillId)) fail('ANCESTRY_CYCLE', `ancestry cycle contains Skill '${skillId}'`);
    visiting.add(skillId);

    const parentIds = [...(skill.parentIds ?? [])].map(String).sort();
    if (new Set(parentIds).size !== parentIds.length) {
      fail('PARENT_DUPLICATE', `Skill '${skillId}' has a duplicate parent`);
    }
    if (parentIds.length) assertBps(skill.inheritBps, `${skillId}.inheritBps`);
    const inheritBps = parentIds.length ? skill.inheritBps : 0;
    const ancestorPoolAtomic = parentIds.length ? floorBps(amountAtomic, inheritBps) : 0n;
    const ownPoolAtomic = amountAtomic - ancestorPoolAtomic;
    const holderRows = allocateByBps(ownPoolAtomic, (skill.holders ?? []).map((holder) => ({
      key: holder.recipientId,
      bps: holder.bps,
    })));
    for (const row of holderRows) {
      credits.push({
        recipientId: row.key,
        viaSkillId: skillId,
        depth,
        kind: depth === 0 ? 'holder' : 'ancestor',
        amountAtomic: row.amountAtomic,
      });
    }

    if (parentIds.length && ancestorPoolAtomic > 0n) {
      const parentRows = allocateByWeights(
        ancestorPoolAtomic,
        parentIds.map((parentId) => ({ key: parentId, weight: 1 })),
      );
      for (const row of parentRows) distribute(row.key, row.amountAtomic, depth + 1);
    }
    visiting.delete(skillId);
  }

  distribute(String(leafSkillId), pool, 0);
  const credited = credits.reduce((sum, credit) => sum + credit.amountAtomic, 0n);
  if (credited !== pool) throw new Error(`internal invariant: credits ${credited} do not equal Royalty pool ${pool}`);
  return {
    royaltyPoolAtomic: pool,
    credits,
    holderCredits: credits.filter((credit) => credit.kind === 'holder'),
    ancestorCredits: credits.filter((credit) => credit.kind === 'ancestor'),
  };
}
```

- [ ] **Step 4: Run the tests and verify ancestry conservation**

Run: `npm test --prefix prototype`

Expected: PASS, 12 tests and 0 failures.

- [ ] **Step 5: Commit the ancestry allocator**

```bash
git add prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs
git commit -m "feat: allocate atomic royalties through ancestry"
```

### Task 4: Partition external and internal gross amounts exactly

**Files:**
- Modify: `prototype/atomic-money.mjs`
- Modify: `prototype/tests/atomic-money.test.mjs`

- [ ] **Step 1: Append failing gross-partition and property-matrix tests**

Add `allocateExternalGross` and `allocateInternalGross` to the test import list, then append:

```js
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
  assert.equal(result.protocolFeeAtomic, 6_250n);
  assert.equal(result.royaltyPoolAtomic, 180_750n);
  assert.equal(result.holderCredits[0].amountAtomic, 180_750n);
  assert.equal(
    result.executionCostAtomic + result.settlementCostAtomic + result.protocolFeeAtomic
      + result.royaltyPoolAtomic + result.refundReserveAtomic,
    result.grossAtomic,
  );
  assert.deepEqual(result.journalEntries.map(({ debitAccountId, creditAccountId, amountAtomic }) => ({
    debitAccountId, creditAccountId, amountAtomic,
  })), [
    { debitAccountId: 'wielder:external-gross', creditAccountId: 'provider:execution', amountAtomic: 60_000n },
    { debitAccountId: 'wielder:external-gross', creditAccountId: 'provider:settlement', amountAtomic: 1_000n },
    { debitAccountId: 'wielder:external-gross', creditAccountId: 'protocol:treasury', amountAtomic: 6_250n },
    { debitAccountId: 'wielder:external-gross', creditAccountId: 'reserve:refund', amountAtomic: 2_000n },
    { debitAccountId: 'wielder:external-gross', creditAccountId: 'royalty:creator', amountAtomic: 180_750n },
  ]);
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
    { category: 'execution-cogs', debitAccountId: 'employer:invocation-gross', creditAccountId: 'provider:execution', amountAtomic: 50_000n },
    { category: 'protocol-fee', debitAccountId: 'employer:invocation-gross', creditAccountId: 'protocol:treasury', amountAtomic: 5_000n },
    { category: 'refund-reserve', debitAccountId: 'employer:invocation-gross', creditAccountId: 'reserve:refund', amountAtomic: 5_000n },
    { category: 'invocation-award', debitAccountId: 'employer:invocation-gross', creditAccountId: 'employee:employee-1', amountAtomic: 140_000n },
  ]);
});

test('gross partitions reject impossible economics before mutating inputs', () => {
  const input = Object.freeze({
    grossAtomic: 100n,
    executionCostAtomic: 99n,
    settlementCostAtomic: 0n,
    protocolFeeBps: 250,
    refundReserveAtomic: 0n,
    leafSkillId: 'skill',
    skills: Object.freeze({
      skill: Object.freeze({
        parentIds: Object.freeze([]),
        inheritBps: 0,
        holders: Object.freeze([{ recipientId: 'creator', bps: 10_000 }]),
      }),
    }),
  });
  assert.throws(() => allocateExternalGross(input), /cannot cover costs/);
  assert.equal(input.grossAtomic, 100n);
});

const branchingClaims = () => ({
  leaf: {
    parentIds: ['root-b', 'root-a'], inheritBps: 3_333,
    holders: [{ recipientId: 'employee', bps: 3_333 }, { recipientId: 'employer', bps: 6_667 }],
  },
  'root-a': {
    parentIds: [], inheritBps: 0,
    holders: [{ recipientId: 'alice', bps: 5_001 }, { recipientId: 'acme', bps: 4_999 }],
  },
  'root-b': {
    parentIds: [], inheritBps: 0,
    holders: [{ recipientId: 'bob', bps: 7_777 }, { recipientId: 'beta', bps: 2_223 }],
  },
});

function assertBalanced(result, expectedSourceAccount, grossAtomic) {
  const debitTotal = result.journalEntries.reduce((sum, entry) => sum + entry.amountAtomic, 0n);
  const creditTotal = result.journalEntries.reduce((sum, entry) => sum + entry.amountAtomic, 0n);
  assert.equal(debitTotal, grossAtomic);
  assert.equal(creditTotal, grossAtomic);
  assert.ok(result.journalEntries.every((entry) => entry.debitAccountId === expectedSourceAccount));
  assert.ok(result.journalEntries.every((entry) => entry.creditAccountId && entry.amountAtomic >= 0n));
}

test('deterministic matrix conserves gross and balanced entries across costs, co-holders, branching ancestry, and rounding', () => {
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
                grossAtomic, executionCostAtomic, settlementCostAtomic, protocolFeeBps,
                refundReserveAtomic, ...graph,
              });
              assert.equal(
                result.executionCostAtomic + result.settlementCostAtomic + result.protocolFeeAtomic
                  + result.royaltyPoolAtomic + result.refundReserveAtomic,
                grossAtomic,
              );
              assert.equal(result.credits.reduce((sum, credit) => sum + credit.amountAtomic, 0n), result.royaltyPoolAtomic);
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
```

- [ ] **Step 2: Run the tests and verify gross allocators are missing**

Run: `npm test --prefix prototype`

Expected: FAIL because `allocateExternalGross` and `allocateInternalGross` are not exported.

- [ ] **Step 3: Implement exact external and internal partitions**

Append to `prototype/atomic-money.mjs`:

```js
function requireCoveredGross(grossAtomic, components) {
  const required = components.reduce((sum, component) => sum + component, 0n);
  if (required > grossAtomic) {
    fail('GROSS_INSUFFICIENT', `gross ${grossAtomic} cannot cover costs and reserves ${required}`);
  }
  return grossAtomic - required;
}

function journalEntry(category, debitAccountId, creditAccountId, amountAtomic) {
  return { category, debitAccountId, creditAccountId, amountAtomic: assertAtomic(amountAtomic) };
}

export function allocateExternalGross({
  grossAtomic,
  executionCostAtomic,
  settlementCostAtomic,
  protocolFeeBps,
  refundReserveAtomic,
  leafSkillId,
  skills,
}) {
  const gross = assertAtomic(grossAtomic, 'grossAtomic');
  const executionCost = assertAtomic(executionCostAtomic, 'executionCostAtomic');
  const settlementCost = assertAtomic(settlementCostAtomic, 'settlementCostAtomic');
  const refundReserve = assertAtomic(refundReserveAtomic, 'refundReserveAtomic');
  const protocolFee = floorBps(gross, protocolFeeBps);
  const royaltyPool = requireCoveredGross(gross, [executionCost, settlementCost, protocolFee, refundReserve]);
  const royalty = allocateRoyaltyGraph({ royaltyPoolAtomic: royaltyPool, leafSkillId, skills });
  const debitAccountId = 'wielder:external-gross';
  const journalEntries = [
    journalEntry('execution-cogs', debitAccountId, 'provider:execution', executionCost),
    journalEntry('settlement-cogs', debitAccountId, 'provider:settlement', settlementCost),
    journalEntry('protocol-fee', debitAccountId, 'protocol:treasury', protocolFee),
    journalEntry('refund-reserve', debitAccountId, 'reserve:refund', refundReserve),
    ...royalty.credits.map((credit) => journalEntry(
      credit.kind === 'holder' ? 'royalty-holder' : 'royalty-ancestor',
      debitAccountId,
      `royalty:${credit.recipientId}`,
      credit.amountAtomic,
    )),
  ];
  return {
    grossAtomic: gross,
    executionCostAtomic: executionCost,
    settlementCostAtomic: settlementCost,
    protocolFeeAtomic: protocolFee,
    royaltyPoolAtomic: royaltyPool,
    refundReserveAtomic: refundReserve,
    credits: royalty.credits,
    holderCredits: royalty.holderCredits,
    ancestorCredits: royalty.ancestorCredits,
    journalEntries,
  };
}

export function allocateInternalGross({
  grossAtomic,
  executionCostAtomic,
  protocolFeeAtomic,
  refundReserveAtomic,
  recipientId,
}) {
  const gross = assertAtomic(grossAtomic, 'grossAtomic');
  const executionCost = assertAtomic(executionCostAtomic, 'executionCostAtomic');
  const protocolFee = assertAtomic(protocolFeeAtomic, 'protocolFeeAtomic');
  const refundReserve = assertAtomic(refundReserveAtomic, 'refundReserveAtomic');
  const invocationAward = requireCoveredGross(gross, [executionCost, protocolFee, refundReserve]);
  const recipient = String(recipientId ?? '');
  if (!recipient) fail('RECIPIENT_REQUIRED', 'recipientId must be non-empty');
  const debitAccountId = 'employer:invocation-gross';
  return {
    grossAtomic: gross,
    executionCostAtomic: executionCost,
    protocolFeeAtomic: protocolFee,
    refundReserveAtomic: refundReserve,
    invocationAwardAtomic: invocationAward,
    awardCredit: { recipientId: recipient, amountAtomic: invocationAward },
    journalEntries: [
      journalEntry('execution-cogs', debitAccountId, 'provider:execution', executionCost),
      journalEntry('protocol-fee', debitAccountId, 'protocol:treasury', protocolFee),
      journalEntry('refund-reserve', debitAccountId, 'reserve:refund', refundReserve),
      journalEntry('invocation-award', debitAccountId, `employee:${recipient}`, invocationAward),
    ],
  };
}
```

- [ ] **Step 4: Run the property matrix and verify exact conservation**

Run: `npm test --prefix prototype`

Expected: PASS, 16 tests and 0 failures; all 152 matrix cases conserve gross and
produce account-identified balanced entries whose Wielder debit equals every provider,
treasury, reserve, holder, and ancestor credit. The internal case similarly balances
the employer debit against provider, protocol, reserve, and employee-award credits.

- [ ] **Step 5: Run static syntax validation**

Run: `node --check prototype/atomic-money.mjs`

Expected: exit 0 with no output.

- [ ] **Step 6: Commit the gross allocators**

```bash
git add prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs
git commit -m "feat: partition external and internal gross amounts"
```

### Task 5: Document the migration boundary and verify the plan slice

**Files:**
- Modify: `prototype/README.md:1-23`

- [ ] **Step 1: Add an explicit migration-status section**

Insert after the opening blockquote in `prototype/README.md`:

```markdown
## Accounting kernel status

`atomic-money.mjs` is the tested accounting source for new work. It accepts USDC at
the display boundary, converts it to six-decimal atomic `bigint` values, and proves
exact gross and Royalty-pool conservation under deterministic remainder allocation.

`settlement-engine.mjs` and its TUI are historical prototype consumers that still use
display-number state. Do not use them for new receipts or public allocation figures.
The Collar and employer-budget plans migrate their runtime consumers to
`atomic-money.mjs`; historical results remain labeled as historical rather than being
silently recomputed.
```

- [ ] **Step 2: Run the complete offline kernel suite**

Run: `npm test --prefix prototype`

Expected: PASS, 16 tests and 0 failures.

- [ ] **Step 3: Confirm no floating-point operation exists in the new kernel**

Run: `rg -n "Math\.|parseFloat|toFixed|Number\(" prototype/atomic-money.mjs`

Expected: no matches. `parseUsdc` accepts decimal strings only and every allocation uses `bigint`.

- [ ] **Step 4: Confirm no environment, wallet, or network dependency entered the slice**

Run: `rg -n "process\.env|PRIVATE_KEY|fetch\(|mainnet" prototype/atomic-money.mjs prototype/tests/atomic-money.test.mjs`

Expected: no matches.

- [ ] **Step 5: Commit the migration boundary**

```bash
git add prototype/README.md
git commit -m "docs: mark atomic accounting migration boundary"
```

## Definition of done

- `prototype/atomic-money.mjs` is the only new public money kernel and exposes the exact contracts used by later plans:
  - `parseUsdc(value): bigint`
  - `formatUsdc(amountAtomic): string`
  - `allocateByWeights(amountAtomic, shares)`
  - `allocateByBps(amountAtomic, shares)`
  - `allocateRoyaltyGraph({ royaltyPoolAtomic, leafSkillId, skills })`
  - `allocateExternalGross({ grossAtomic, executionCostAtomic, settlementCostAtomic, protocolFeeBps, refundReserveAtomic, leafSkillId, skills })`
  - `allocateInternalGross({ grossAtomic, executionCostAtomic, protocolFeeAtomic, refundReserveAtomic, recipientId })`
- All calculation fields are `bigint`; JSON/report consumers must serialize them as decimal strings.
- The deterministic matrix covers 150 fee/price/depth cases plus explicit co-hold and remainder boundaries.
- Negative, non-finite, unsafe-number, over-precision, impossible-gross, duplicate-recipient, missing-node, and cyclic-ancestry inputs fail before caller-owned input changes.
- No mainnet, funded-wallet, provider, or network action is performed.

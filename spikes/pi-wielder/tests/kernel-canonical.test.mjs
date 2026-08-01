import assert from 'node:assert/strict';
import test from 'node:test';

import {
  KernelError,
  canonicalAtomic,
  canonicalEvmHash,
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  sha256,
} from '../src/kernel/canonical.mjs';

function assertKernelError(action, code) {
  assert.throws(action, (error) => {
    assert.equal(error instanceof KernelError, true);
    assert.equal(error.name, 'KernelError');
    assert.equal(error.code, code);
    return true;
  });
}

test('canonical JSON sorts object keys recursively without mutating input', () => {
  const input = Object.freeze({ z: 1, a: Object.freeze({ y: 2, b: 3 }) });

  assert.equal(canonicalJson(input), '{"a":{"b":3,"y":2},"z":1}');
  assert.deepEqual(input, { z: 1, a: { y: 2, b: 3 } });
  assert.equal(canonicalJson({ 2: 'two', 10: 'ten' }), '{"10":"ten","2":"two"}');
});

test('atomic USDC accepts canonical nonnegative decimal strings only', () => {
  const zero = canonicalAtomic('0', 'amount');
  const amount = canonicalAtomic('250000', 'amount');

  assert.deepEqual(zero, { text: '0', value: 0n });
  assert.deepEqual(amount, { text: '250000', value: 250000n });
  assert.equal(Object.isFrozen(zero), true);
  assert.equal(Object.isFrozen(amount), true);

  for (const value of [1, 1n, '', '01', '-1', '1.0', '1e6']) {
    assertKernelError(() => canonicalAtomic(value, 'amount'), 'ATOMIC_FORMAT');
  }
});

test('closed records accept only exact own enumerable data fields', () => {
  const source = { a: { nested: true } };
  const copy = exactRecord(source, ['a'], [], 'SHAPE', 'record');

  assert.deepEqual(copy, source);
  assert.notEqual(copy, source);
  assert.notEqual(copy.a, source.a);

  const inherited = Object.assign(Object.create({ inherited: true }), { a: 1 });
  const withSymbol = { a: 1, [Symbol('hidden')]: 2 };
  const nonenumerable = Object.defineProperty({ a: 1 }, 'hidden', {
    value: 2,
    enumerable: false,
  });
  let getterCalls = 0;
  const accessor = Object.defineProperty({}, 'a', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 1;
    },
  });

  for (const value of [
    { a: 1, b: 2 },
    {},
    inherited,
    Object.assign(Object.create(null), { a: 1 }),
    withSymbol,
    nonenumerable,
    accessor,
  ]) {
    assertKernelError(() => exactRecord(value, ['a'], [], 'SHAPE', 'record'), 'SHAPE');
  }
  assert.equal(getterCalls, 0);
});

test('sha256 hashes strings and bytes with an explicit lowercase prefix', () => {
  assert.match(sha256(Buffer.from('wallet-kernel')), /^sha256:[0-9a-f]{64}$/);
  assert.equal(sha256('wallet-kernel'), sha256(new Uint8Array(Buffer.from('wallet-kernel'))));

  for (const value of [null, 1, {}, new Uint16Array([1])]) {
    assertKernelError(() => sha256(value), 'HASH_INPUT');
  }
});

test('EVM hashes canonicalize once before comparison or persistence', () => {
  const upper = `0x${'AB'.repeat(32)}`;
  assert.equal(canonicalEvmHash(upper, 'transaction'), `0x${'ab'.repeat(32)}`);

  for (const value of ['', 'ab'.repeat(32), `0x${'ab'.repeat(31)}`, `0x${'gg'.repeat(32)}`]) {
    assertKernelError(() => canonicalEvmHash(value, 'transaction'), 'EVM_HASH_FORMAT');
  }
});

test('canonical JSON rejects values JSON would drop, coerce, or ambiguously encode', () => {
  let objectGetterCalls = 0;
  let arrayGetterCalls = 0;
  const objectAccessor = Object.defineProperty({}, 'getter', {
    enumerable: true,
    get() {
      objectGetterCalls += 1;
      return 'must not run';
    },
  });
  const arrayAccessor = Object.defineProperty([1], '0', {
    enumerable: true,
    get() {
      arrayGetterCalls += 1;
      return 'must not run';
    },
  });
  const cyclic = {};
  cyclic.self = cyclic;
  const customArray = [1];
  Object.setPrototypeOf(customArray, Object.create(Array.prototype));

  for (const value of [
    undefined,
    function functionValue() {},
    Symbol('x'),
    1n,
    Number.POSITIVE_INFINITY,
    Number.NaN,
    -0,
    1.5,
    Number.MAX_SAFE_INTEGER + 1,
    new Date('2026-07-31T00:00:00.000Z'),
    { dropped: undefined },
    { fn() {} },
    { symbol: Symbol('x') },
    { bigint: 1n },
    { infinity: Number.POSITIVE_INFINITY },
    { negativeZero: -0 },
    { date: new Date('2026-07-31T00:00:00.000Z') },
    { a: 1, [Symbol('hidden')]: 2 },
    Object.assign(Object.create(null), { a: 1 }),
    Object.defineProperty({ a: 1 }, 'hidden', { value: 2, enumerable: false }),
    objectAccessor,
    Object.defineProperty([1], 'hidden', { value: 2, enumerable: false }),
    arrayAccessor,
    Object.assign([1], { [Symbol('hidden')]: 2 }),
    Object.assign([1], { extra: 2 }),
    [1, , 3],
    customArray,
    cyclic,
  ]) {
    assertKernelError(() => canonicalJson(value), 'CANONICAL_TYPE');
  }

  assert.equal(objectGetterCalls, 0);
  assert.equal(arrayGetterCalls, 0);
});

test('canonical tokens enforce the bounded ASCII grammar', () => {
  assert.equal(canonicalToken('agent:alpha-1.2_name', 'agent id'), 'agent:alpha-1.2_name');
  assert.equal(canonicalToken('abcd', 'short token', 4), 'abcd');

  for (const value of ['', '-agent', 'agent space', 'abcde']) {
    const maximum = value === 'abcde' ? 4 : 200;
    assertKernelError(() => canonicalToken(value, 'token', maximum), 'TOKEN_FORMAT');
  }
});

test('canonical timestamps require an exact ISO roundtrip', () => {
  const timestamp = '2026-07-31T00:00:00.000Z';
  assert.equal(canonicalTimestamp(timestamp, 'created at'), timestamp);

  for (const value of [
    new Date(timestamp),
    '2026-07-31T00:00:00Z',
    '2026-07-30T20:00:00.000-04:00',
    'not-a-timestamp',
  ]) {
    assertKernelError(() => canonicalTimestamp(value, 'created at'), 'TIMESTAMP_FORMAT');
  }
});

test('frozen copies detach and recursively freeze nested values', () => {
  const source = { nested: { values: [1, { ready: true }] } };
  const copy = frozenCopy(source);

  assert.deepEqual(copy, source);
  assert.notEqual(copy, source);
  assert.notEqual(copy.nested, source.nested);
  assert.equal(Object.isFrozen(copy), true);
  assert.equal(Object.isFrozen(copy.nested), true);
  assert.equal(Object.isFrozen(copy.nested.values), true);
  assert.equal(Object.isFrozen(copy.nested.values[1]), true);
});

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

test('closed records reject unsafe nested data without invoking accessors', () => {
  let getterCalls = 0;
  const nestedAccessor = Object.defineProperty({}, 'secret', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'must not run';
    },
  });

  assertKernelError(
    () => exactRecord({ a: nestedAccessor }, ['a'], [], 'SHAPE', 'record'),
    'SHAPE',
  );
  assert.equal(getterCalls, 0);

  for (const nested of [new Date(), new Map(), { value: Symbol('hidden') }]) {
    assertKernelError(() => exactRecord({ a: nested }, ['a'], [], 'SHAPE', 'record'), 'SHAPE');
  }
});

test('canonical data boundaries reject proxies before invoking their traps', () => {
  let trapCalls = 0;
  const target = { value: 1 };
  const proxy = new Proxy(target, {
    get() {
      trapCalls += 1;
      return Reflect.get(...arguments);
    },
    getOwnPropertyDescriptor() {
      trapCalls += 1;
      return Reflect.getOwnPropertyDescriptor(...arguments);
    },
    getPrototypeOf() {
      trapCalls += 1;
      return Reflect.getPrototypeOf(...arguments);
    },
    ownKeys() {
      trapCalls += 1;
      return Reflect.ownKeys(...arguments);
    },
  });

  assertKernelError(() => exactRecord(proxy, ['value'], [], 'SHAPE', 'record'), 'SHAPE');
  assertKernelError(() => exactRecord({ value: proxy }, ['value'], [], 'SHAPE', 'record'), 'SHAPE');
  assertKernelError(() => canonicalJson(proxy), 'CANONICAL_TYPE');
  assertKernelError(() => frozenCopy(proxy), 'CANONICAL_TYPE');
  assert.equal(trapCalls, 0);
});

test('sha256 hashes strings and bytes with an explicit lowercase prefix', () => {
  assert.equal(
    sha256('abc'),
    'sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
  );
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

  for (const maximum of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, '4', null]) {
    assertKernelError(() => canonicalToken('a', 'token', maximum), 'TOKEN_FORMAT');
  }
});

test('canonical timestamps require an exact ISO roundtrip', () => {
  const timestamp = '2026-07-31T00:00:00.000Z';
  assert.equal(canonicalTimestamp(timestamp, 'created at'), timestamp);

  for (const value of [
    new Date(timestamp),
    '2026-07-31T00:00:00Z',
    '2026-07-30T20:00:00.000-04:00',
    '2025-02-29T00:00:00.000Z',
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

test('frozen copies reject nested accessors without invoking them', () => {
  let getterCalls = 0;
  const nestedAccessor = Object.defineProperty({}, 'secret', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return 'must not run';
    },
  });

  assertKernelError(() => frozenCopy({ nested: nestedAccessor }), 'CANONICAL_TYPE');
  assert.equal(getterCalls, 0);
});

test('frozen copies reject mutable or ambiguous object and array shapes', () => {
  const customArray = [1];
  Object.setPrototypeOf(customArray, Object.create(Array.prototype));

  for (const value of [
    new Date('2026-07-31T00:00:00.000Z'),
    new Map([['key', 'value']]),
    new Set(['value']),
    new Uint8Array([1]),
    Object.assign(Object.create(null), { value: 1 }),
    { value: Symbol('hidden') },
    { [Symbol('hidden')]: true },
    { fn() {} },
    Object.defineProperty({ visible: true }, 'hidden', { value: true, enumerable: false }),
    Object.defineProperty([1], 'hidden', { value: true, enumerable: false }),
    Object.assign([1], { extra: true }),
    Object.assign([1], { [Symbol('hidden')]: true }),
    [1, , 3],
    customArray,
  ]) {
    assertKernelError(() => frozenCopy(value), 'CANONICAL_TYPE');
  }
});

test('frozen copies preserve and freeze cyclic plain data graphs', () => {
  const source = { name: 'root' };
  const values = [source];
  source.self = source;
  source.values = values;
  values.push(values);

  const copy = frozenCopy(source);

  assert.notEqual(copy, source);
  assert.equal(copy.self, copy);
  assert.equal(copy.values[0], copy);
  assert.equal(copy.values[1], copy.values);
  assert.equal(Object.isFrozen(copy), true);
  assert.equal(Object.isFrozen(copy.values), true);
});

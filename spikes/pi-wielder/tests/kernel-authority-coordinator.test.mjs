import assert from 'node:assert/strict';
import test from 'node:test';

import { KernelError } from '../src/kernel/canonical.mjs';
import { createAuthorityMutationCoordinator } from '../src/kernel/authority-mutation-coordinator.mjs';

function assertRejectedCode(promise, code) {
  return assert.rejects(promise, (error) => {
    assert.equal(error instanceof KernelError, true);
    assert.equal(error.code, code);
    return true;
  });
}

test('exposes only one frozen runExclusive method and returns a synchronous result', async () => {
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {},
    markAuthorityUnhealthy() {},
  });

  assert.equal(Object.isFrozen(coordinator), true);
  assert.deepEqual(Reflect.ownKeys(coordinator), ['runExclusive']);
  assert.equal(typeof coordinator.runExclusive, 'function');
  assert.equal(coordinator.runExclusive.length, 1);
  assert.equal(await coordinator.runExclusive(() => 'done'), 'done');
});

test('accepts exactly one function without consulting admission for malformed calls', async () => {
  let gateChecks = 0;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      gateChecks += 1;
    },
    markAuthorityUnhealthy() {},
  });

  await assert.rejects(coordinator.runExclusive(), TypeError);
  await assert.rejects(coordinator.runExclusive(null), TypeError);
  await assert.rejects(coordinator.runExclusive(() => undefined, 'extra'), TypeError);
  assert.equal(gateChecks, 0);
});

test('runs callbacks in exact FIFO order and advances followers after an earlier throw', async () => {
  const trace = [];
  let gateChecks = 0;
  let second;
  let third;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      gateChecks += 1;
    },
    markAuthorityUnhealthy() {},
  });

  const first = coordinator.runExclusive(() => {
    trace.push('first:enter');
    second = coordinator.runExclusive(() => {
      trace.push('second:enter');
      trace.push('second:exit');
      return 'second-result';
    });
    third = coordinator.runExclusive(() => {
      trace.push('third:enter');
      trace.push('third:exit');
      return 'third-result';
    });
    trace.push('first:exit');
    throw new Error('first failed');
  });

  await assert.rejects(first, /first failed/);
  assert.equal(await second, 'second-result');
  assert.equal(await third, 'third-result');
  assert.equal(gateChecks, 3);
  assert.deepEqual(trace, [
    'first:enter',
    'first:exit',
    'second:enter',
    'second:exit',
    'third:enter',
    'third:exit',
  ]);
});

test('queued callbacks recheck a closed admission gate only at queue head and perform zero writes', async () => {
  const trace = [];
  const writes = [];
  let admissionOpen = true;
  let second;
  let third;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push(`gate:${admissionOpen ? 'open' : 'closed'}`);
      if (!admissionOpen) throw new KernelError('ADMISSION_CLOSED', 'admission is closed');
    },
    markAuthorityUnhealthy() {},
  });

  await coordinator.runExclusive(() => {
    trace.push('first:enter');
    second = coordinator.runExclusive(() => writes.push('second'));
    third = coordinator.runExclusive(() => writes.push('third'));
    admissionOpen = false;
    trace.push('first:closed-gate');
  });

  await assertRejectedCode(second, 'ADMISSION_CLOSED');
  await assertRejectedCode(third, 'ADMISSION_CLOSED');
  assert.deepEqual(writes, []);
  assert.deepEqual(trace, [
    'gate:open',
    'first:enter',
    'first:closed-gate',
    'gate:closed',
    'gate:closed',
  ]);
});

test('a returned Promise synchronously fail-stops authority before releasing a follower', async () => {
  const trace = [];
  const writes = [];
  let admissionOpen = true;
  let follower;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push(`gate:${admissionOpen ? 'open' : 'closed'}`);
      if (!admissionOpen) throw new KernelError('ADMISSION_CLOSED', 'admission is closed');
    },
    markAuthorityUnhealthy(reasonCode) {
      trace.push(`mark:${reasonCode}`);
      admissionOpen = false;
    },
  });

  const violating = coordinator.runExclusive(() => {
    trace.push('violating:enter');
    follower = coordinator.runExclusive(() => writes.push('follower'));
    trace.push('violating:return-promise');
    return Promise.resolve('escaped');
  });

  assert.deepEqual(trace, [
    'gate:open',
    'violating:enter',
    'violating:return-promise',
    'mark:AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
    'gate:closed',
  ]);
  await assertRejectedCode(violating, 'AUTHORITY_COORDINATOR_ASYNC_CALLBACK');
  await assertRejectedCode(follower, 'ADMISSION_CLOSED');
  assert.deepEqual(writes, []);
});

test('custom thenables are invariant violations while inert then data remains synchronous', async () => {
  const reasons = [];
  const customCoordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {},
    markAuthorityUnhealthy(reasonCode) {
      reasons.push(reasonCode);
    },
  });
  const customThenable = Object.freeze({
    then(resolve) {
      resolve('escaped');
    },
  });

  await assertRejectedCode(
    customCoordinator.runExclusive(() => customThenable),
    'AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
  );
  assert.deepEqual(reasons, ['AUTHORITY_COORDINATOR_ASYNC_CALLBACK']);

  const inert = Object.freeze({ then: null, value: 'synchronous' });
  const inertCoordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {},
    markAuthorityUnhealthy() {},
  });
  assert.equal(await inertCoordinator.runExclusive(() => inert), inert);
});

test('a native Promise cannot hide its async identity behind inert own then data', async () => {
  const reasons = [];
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {},
    markAuthorityUnhealthy(reasonCode) {
      reasons.push(reasonCode);
    },
  });
  const disguisedPromise = Promise.resolve('escaped');
  Object.defineProperty(disguisedPromise, 'then', {
    configurable: true,
    value: null,
  });

  await assertRejectedCode(
    coordinator.runExclusive(() => disguisedPromise),
    'AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
  );
  assert.deepEqual(reasons, ['AUTHORITY_COORDINATOR_ASYNC_CALLBACK']);
});

test('detects accessor and proxy thenable returns without invoking hostile traps', async () => {
  async function assertHostileReturn(resultFactory, getTrapCalls) {
    const reasons = [];
    const coordinator = createAuthorityMutationCoordinator({
      assertAdmissionOpen() {},
      markAuthorityUnhealthy(reasonCode) {
        reasons.push(reasonCode);
      },
    });

    await assertRejectedCode(
      coordinator.runExclusive(() => resultFactory()),
      'AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
    );
    assert.deepEqual(reasons, ['AUTHORITY_COORDINATOR_ASYNC_CALLBACK']);
    assert.equal(getTrapCalls(), 0);
  }

  let accessorCalls = 0;
  const accessorThenable = {};
  Object.defineProperty(accessorThenable, 'then', {
    get() {
      accessorCalls += 1;
      return () => undefined;
    },
  });
  await assertHostileReturn(() => accessorThenable, () => accessorCalls);

  let proxyTrapCalls = 0;
  const proxyThenable = new Proxy({ then() {} }, {
    get(target, property, receiver) {
      proxyTrapCalls += 1;
      return Reflect.get(target, property, receiver);
    },
    getOwnPropertyDescriptor(target, property) {
      proxyTrapCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      proxyTrapCalls += 1;
      return Reflect.getPrototypeOf(target);
    },
  });
  await assertHostileReturn(() => proxyThenable, () => proxyTrapCalls);

  const { proxy: revokedThenable, revoke } = Proxy.revocable({ then() {} }, {});
  revoke();
  await assertHostileReturn(() => revokedThenable, () => 0);

  let prototypeTrapCalls = 0;
  const proxyPrototype = new Proxy({ then() {} }, {
    getOwnPropertyDescriptor(target, property) {
      prototypeTrapCalls += 1;
      return Reflect.getOwnPropertyDescriptor(target, property);
    },
    getPrototypeOf(target) {
      prototypeTrapCalls += 1;
      return Reflect.getPrototypeOf(target);
    },
  });
  const inheritedProxyThenable = Object.create(proxyPrototype);
  await assertHostileReturn(() => inheritedProxyThenable, () => prototypeTrapCalls);
});

test('an async invariant remains internally fail-closed if the injected marker does not close the gate', async () => {
  const trace = [];
  const writes = [];
  let follower;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push('gate:open');
    },
    markAuthorityUnhealthy(reasonCode) {
      trace.push(`mark:${reasonCode}`);
    },
  });

  const violating = coordinator.runExclusive(() => {
    follower = coordinator.runExclusive(() => writes.push('follower'));
    return { then() {} };
  });

  await assertRejectedCode(violating, 'AUTHORITY_COORDINATOR_ASYNC_CALLBACK');
  await assertRejectedCode(follower, 'AUTHORITY_COORDINATOR_ASYNC_CALLBACK');
  assert.deepEqual(writes, []);
  assert.deepEqual(trace, [
    'gate:open',
    'mark:AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
    'gate:open',
  ]);
});

test('a throwing fail-stop hook is preserved as cause while the slot still releases fail-closed', async () => {
  const trace = [];
  const writes = [];
  const markerFailure = new Error('fail-stop hook failed');
  let follower;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push('gate:open');
    },
    markAuthorityUnhealthy(reasonCode) {
      trace.push(`mark:${reasonCode}`);
      throw markerFailure;
    },
  });

  const violating = coordinator.runExclusive(() => {
    follower = coordinator.runExclusive(() => writes.push('follower'));
    return Promise.resolve();
  });

  const [violatingResult, followerResult] = await Promise.allSettled([violating, follower]);
  for (const result of [violatingResult, followerResult]) {
    assert.equal(result.status, 'rejected');
    assert.equal(result.reason instanceof KernelError, true);
    assert.equal(result.reason.code, 'AUTHORITY_COORDINATOR_ASYNC_CALLBACK');
    assert.equal(result.reason.cause, markerFailure);
  }
  assert.deepEqual(writes, []);
  assert.deepEqual(trace, [
    'gate:open',
    'mark:AUTHORITY_COORDINATOR_ASYNC_CALLBACK',
    'gate:open',
  ]);
});

test('a mutation enqueued by the terminal fault hook waits for the receipt commit', async () => {
  const trace = [];
  let follower;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push('gate:open');
    },
    markAuthorityUnhealthy() {},
  });

  await coordinator.runExclusive(() => {
    trace.push('terminal:domain-committed');
    const postDomainPreReceiptFaultHook = () => {
      trace.push('fault-hook:enter');
      follower = coordinator.runExclusive(() => trace.push('follower:wrote'));
      trace.push('fault-hook:exit');
    };
    postDomainPreReceiptFaultHook();
    trace.push('terminal:receipt-committed');
  });
  await follower;

  assert.deepEqual(trace, [
    'gate:open',
    'terminal:domain-committed',
    'fault-hook:enter',
    'fault-hook:exit',
    'terminal:receipt-committed',
    'gate:open',
    'follower:wrote',
  ]);
});

test('a terminal fault hook can close admission synchronously before its queued follower advances', async () => {
  const trace = [];
  let admissionOpen = true;
  let follower;
  const coordinator = createAuthorityMutationCoordinator({
    assertAdmissionOpen() {
      trace.push(`gate:${admissionOpen ? 'open' : 'closed'}`);
      if (!admissionOpen) throw new KernelError('RECEIPT_PARITY_REQUIRED', 'receipt missing');
    },
    markAuthorityUnhealthy() {},
  });

  const terminal = coordinator.runExclusive(() => {
    trace.push('terminal:domain-committed');
    try {
      const postDomainPreReceiptFaultHook = () => {
        trace.push('fault-hook:enter');
        follower = coordinator.runExclusive(() => trace.push('follower:wrote'));
        throw new Error('receipt signing fault');
      };
      postDomainPreReceiptFaultHook();
      trace.push('terminal:receipt-committed');
    } catch (error) {
      admissionOpen = false;
      trace.push('terminal:admission-closed');
      throw error;
    }
  });

  await assert.rejects(terminal, /receipt signing fault/);
  await assertRejectedCode(follower, 'RECEIPT_PARITY_REQUIRED');
  assert.deepEqual(trace, [
    'gate:open',
    'terminal:domain-committed',
    'fault-hook:enter',
    'terminal:admission-closed',
    'gate:closed',
  ]);
});

test('rejects malformed dependency records without invoking accessors or proxies', () => {
  const valid = {
    assertAdmissionOpen() {},
    markAuthorityUnhealthy() {},
  };
  const missingGate = { ...valid };
  delete missingGate.assertAdmissionOpen;
  const missingFailStop = { ...valid };
  delete missingFailStop.markAuthorityUnhealthy;
  const accessor = { ...valid };
  let accessorCalls = 0;
  Object.defineProperty(accessor, 'assertAdmissionOpen', {
    enumerable: true,
    get() {
      accessorCalls += 1;
      return () => undefined;
    },
  });
  let proxyTrapCalls = 0;
  const proxy = new Proxy(valid, {
    get(target, property, receiver) {
      proxyTrapCalls += 1;
      return Reflect.get(target, property, receiver);
    },
    ownKeys(target) {
      proxyTrapCalls += 1;
      return Reflect.ownKeys(target);
    },
  });

  for (const options of [
    undefined,
    null,
    [],
    missingGate,
    missingFailStop,
    { ...valid, extra: true },
    { ...valid, assertAdmissionOpen: true },
    { ...valid, markAuthorityUnhealthy: true },
    accessor,
    proxy,
  ]) {
    assert.throws(() => createAuthorityMutationCoordinator(options), TypeError);
  }
  assert.equal(accessorCalls, 0);
  assert.equal(proxyTrapCalls, 0);
});

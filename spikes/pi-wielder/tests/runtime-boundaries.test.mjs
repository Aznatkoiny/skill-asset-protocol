import assert from 'node:assert/strict';
import test from 'node:test';

import {
  readBodyBytes,
  readJsonBody,
  RuntimeBoundaryError,
  withWallClockDeadline,
} from '../src/runtime-boundaries.mjs';

test('wall-clock deadline aborts an ignoring operation without aborting the caller signal', async () => {
  const caller = new AbortController();
  let operationSignal = null;
  const started = performance.now();

  await assert.rejects(() => withWallClockDeadline({
    signal: caller.signal,
    timeoutMs: 20,
    timeoutCode: 'TEST_TIMEOUT',
    timeoutMessage: 'test operation timed out',
    abortedCode: 'TEST_ABORTED',
    abortedMessage: 'test operation aborted',
  }, async (signal) => {
    operationSignal = signal;
    return new Promise(() => {});
  }), (error) => (
    error instanceof RuntimeBoundaryError
      && error.code === 'TEST_TIMEOUT'
      && error.message === 'test operation timed out'
  ));

  assert.equal(operationSignal.aborted, true);
  assert.equal(caller.signal.aborted, false);
  assert.ok(performance.now() - started < 500);
});

test('caller abort is composed into the operation without exposing its reason', async () => {
  const caller = new AbortController();
  let operationSignal = null;
  const pending = withWallClockDeadline({
    signal: caller.signal,
    timeoutMs: 1_000,
    timeoutCode: 'TEST_TIMEOUT',
    timeoutMessage: 'test operation timed out',
    abortedCode: 'TEST_ABORTED',
    abortedMessage: 'test operation aborted',
  }, async (signal) => {
    operationSignal = signal;
    return new Promise(() => {});
  });

  caller.abort(new Error('caller secret must not escape'));
  await assert.rejects(() => pending, (error) => (
    error instanceof RuntimeBoundaryError
      && error.code === 'TEST_ABORTED'
      && error.message === 'test operation aborted'
      && !error.message.includes('secret')
  ));
  assert.equal(operationSignal.aborted, true);
});

test('an already-aborted body signal cancels and rejects before starting a stalled read', async () => {
  const controller = new AbortController();
  controller.abort(new Error('caller secret must not escape'));

  let cancelled = false;
  let readCalls = 0;
  let releaseRead;
  const stalledRead = new Promise((resolve) => { releaseRead = resolve; });
  const reader = {
    async read() {
      readCalls += 1;
      return stalledRead;
    },
    async cancel() {
      cancelled = true;
      releaseRead({ done: true, value: undefined });
    },
    releaseLock() {},
  };
  const source = {
    headers: new Headers(),
    body: {
      getReader: () => reader,
      async cancel() {
        cancelled = true;
      },
    },
  };

  const observed = readBodyBytes(source, {
    maxBytes: 4,
    tooLargeCode: 'TEST_TOO_LARGE',
    tooLargeMessage: 'test body too large',
    readErrorCode: 'TEST_READ_ERROR',
    readErrorMessage: 'test body read failed',
    signal: controller.signal,
  }).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );

  await new Promise((resolve) => setImmediate(resolve));
  const cancelledBeforeRelease = cancelled;
  const readCallsBeforeRelease = readCalls;
  if (!cancelledBeforeRelease) releaseRead({ done: true, value: undefined });
  const result = await observed;

  assert.equal(cancelledBeforeRelease, true);
  assert.equal(readCallsBeforeRelease, 0);
  assert.ok(result.error instanceof RuntimeBoundaryError);
  assert.equal(result.error.code, 'TEST_READ_ERROR');
  assert.equal(result.error.message, 'test body read failed');
});

test('streaming byte ceiling accepts exactly the limit and cancels on the first excess chunk', async () => {
  const exact = new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2]));
      controller.enqueue(new Uint8Array([3, 4]));
      controller.close();
    },
  }));
  assert.deepEqual(await readBodyBytes(exact, {
    maxBytes: 4,
    tooLargeCode: 'TEST_TOO_LARGE',
    tooLargeMessage: 'test body too large',
    readErrorCode: 'TEST_READ_ERROR',
    readErrorMessage: 'test body read failed',
  }), Buffer.from([1, 2, 3, 4]));

  let cancelled = false;
  const oversized = new Response(new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.enqueue(new Uint8Array([4, 5]));
    },
    cancel() { cancelled = true; },
  }));
  await assert.rejects(() => readBodyBytes(oversized, {
    maxBytes: 4,
    tooLargeCode: 'TEST_TOO_LARGE',
    tooLargeMessage: 'test body too large',
    readErrorCode: 'TEST_READ_ERROR',
    readErrorMessage: 'test body read failed',
  }), (error) => error.code === 'TEST_TOO_LARGE' && error.message === 'test body too large');
  assert.equal(cancelled, true);
});

test('declared oversize is rejected before pulling and malformed JSON stays sanitized', async () => {
  let pulls = 0;
  const declaredOversize = new Response(new ReadableStream({
    pull(controller) {
      pulls += 1;
      controller.enqueue(new TextEncoder().encode('{}'));
      controller.close();
    },
  }), { headers: { 'content-length': '5' } });
  await assert.rejects(() => readBodyBytes(declaredOversize, {
    maxBytes: 4,
    tooLargeCode: 'TEST_TOO_LARGE',
    tooLargeMessage: 'test body too large',
    readErrorCode: 'TEST_READ_ERROR',
    readErrorMessage: 'test body read failed',
  }), (error) => error.code === 'TEST_TOO_LARGE');
  assert.equal(pulls, 0);

  await assert.rejects(() => readJsonBody(new Response('{secret-invalid-json'), {
    maxBytes: 64,
    tooLargeCode: 'TEST_TOO_LARGE',
    tooLargeMessage: 'test body too large',
    readErrorCode: 'TEST_READ_ERROR',
    readErrorMessage: 'test body read failed',
    jsonErrorCode: 'TEST_JSON',
    jsonErrorMessage: 'test response was not JSON',
  }), (error) => (
    error.code === 'TEST_JSON'
      && error.message === 'test response was not JSON'
      && !error.message.includes('secret')
  ));
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { assertLiveCleanupHost, cleanupLiveDeployment, runCleanupLiveDeployment } from '../scripts/cleanup-live-deployment.mjs';

const commands = ['disable wallet-kernel-console.socket', 'stop --no-block wallet-kernel-console.socket'];
function fixture() {
  const calls = [];
  return { calls, effects: { assertHost() {}, runSystemctl(args) { calls.push(args.join(' ')); } } };
}

test('an exact clean service result preserves socket activation for a normal restart', async () => {
  const f = fixture();
  const result = await cleanupLiveDeployment({ argv: [], environment: {
    PATH: '/usr/bin:/bin', WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env',
    SERVICE_RESULT: 'success', EXIT_CODE: 'exited', EXIT_STATUS: '0',
  } }, f.effects);
  assert.equal(result.status, 'preserved_after_clean_stop');
  assert.equal(result.execution, 'simulated');
  assert.equal(result.qualification, 'not_performed');
  assert.deepEqual(f.calls, []);
});

for (const status of [undefined, '', 'exit-code', 'signal', 'timeout', 'oom-kill', 'resources', 'Success', ' success', 'success ']) {
  test(`result ${JSON.stringify(status)} requests disable and asynchronous socket stop`, async () => {
    const f = fixture();
    const result = await cleanupLiveDeployment({ argv: [], environment: status === undefined ? {} : { SERVICE_RESULT: status } }, f.effects);
    assert.equal(result.status, 'cleanup_requested');
    assert.deepEqual(f.calls, commands);
    assert.equal(f.calls.some((call) => /\b(start|restart)\b/.test(call)), false);
    assert.equal(f.calls.some((call) => call.includes('wallet-kernel.service')), false);
  });
}

test('a failed disable cannot prevent the stop request, and errors contain no raw host detail', async () => {
  const f = fixture();
  f.effects.runSystemctl = (args) => {
    f.calls.push(args.join(' '));
    const error = new Error('private host path or response content');
    error.code = args[0] === 'disable' ? 'DISABLE_FAILED' : 'STOP_FAILED';
    throw error;
  };
  await assert.rejects(cleanupLiveDeployment({ argv: [], environment: { SERVICE_RESULT: 'exit-code' } }, f.effects), (error) => {
    assert.equal(error.code, 'DISABLE_FAILED');
    assert.equal(error.result.status, 'cleanup_failed');
    assert.deepEqual(error.result.attempts.map((attempt) => attempt.code), ['DISABLE_FAILED', 'STOP_FAILED']);
    assert.equal(JSON.stringify(error).includes('private'), false);
    return true;
  });
  assert.deepEqual(f.calls, commands);
});

test('unknown or malformed environment values cannot bypass fixed cleanup or expose their contents', async () => {
  for (const environment of [
    { SERVICE_RESULT: 'success', CDP_WALLET_SECRET: 'synthetic-never-export' },
    { SERVICE_RESULT: 'success', NODE_OPTIONS: '--import=/arbitrary.mjs' },
    { SERVICE_RESULT: 'success\n' }, { SERVICE_RESULT: null },
    Object.defineProperty({}, 'SERVICE_RESULT', { enumerable: true, get() { throw new Error('getter executed'); } }),
  ]) {
    const f = fixture();
    await assert.rejects(cleanupLiveDeployment({ argv: [], environment }, f.effects), (error) => {
      assert.equal(error.code, 'LIVE_CLEANUP_ENVIRONMENT');
      assert.equal(JSON.stringify(error).includes('synthetic-never-export'), false);
      assert.deepEqual(f.calls, commands);
      return true;
    });
  }
});

test('wrong arguments or a rejected host never reach command execution', async () => {
  const f = fixture();
  await assert.rejects(cleanupLiveDeployment({ argv: ['--unit', 'other.service'], environment: {} }, f.effects), {
    code: 'LIVE_CLEANUP_ARGUMENTS',
  });
  f.effects.assertHost = () => { const error = new Error('unsupported host'); error.code = 'LIVE_CLEANUP_HOST'; throw error; };
  await assert.rejects(cleanupLiveDeployment({ argv: [], environment: {} }, f.effects), { code: 'LIVE_CLEANUP_HOST' });
  assert.deepEqual(f.calls, []);
});

test('the CLI offers no host bypass and bounds diagnostics', async () => {
  const output = [];
  const errors = [];
  const status = await runCleanupLiveDeployment({ argv: ['--simulate'], environment: {},
    stdout: { write(value) { output.push(value); } }, stderr: { write(value) { errors.push(value); } } });
  assert.equal(status, 1);
  assert.deepEqual(output, []);
  assert.deepEqual(JSON.parse(errors[0]), { code: 'LIVE_CLEANUP_ARGUMENTS', result: null });
  if (process.platform !== 'linux' || process.getuid() !== 0 || process.version !== 'v24.18.1') {
    assert.throws(assertLiveCleanupHost, { code: 'LIVE_CLEANUP_HOST' });
  }
});

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';

import { observeQualificationRequest, waitForQualificationBarrier } from '../scripts/qualify-systemd-lifecycle.mjs';

const profile = { schemaVersion: 1, profile: 'offline-qualification' };
function child(t, source) {
  const processChild = spawn(process.execPath, ['--input-type=module', '--eval', source], {
    env: { PATH: '/usr/bin:/bin' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
  const request = observeQualificationRequest(processChild);
  t.after(async () => { if (!request.completion()) processChild.kill('SIGKILL'); await request.done; });
  return request;
}
const output = value => `process.stdout.write(${JSON.stringify(`${JSON.stringify(value)}\n`)});`;
const journal = kind => ({ journal: { lastEvent: { kind, routeId: 'qualification-signing-interruption' },
  counters: { providerOpens: 1, unpaidRequests: 0, signerCalls: 0, signaturesProduced: 0, paidRequests: 0 } } });

test('background completion waits for complete stdout and exposes only bounded public scalars', async t => {
  const value = { ...profile, code: 'QUALIFICATION_WORKER_INPUT', private: 'PRIVATE_OUTPUT_MARKER' };
  const bytes = `${JSON.stringify(value)}\n`;
  const request = child(t, `process.stderr.write('PRIVATE_STDERR_MARKER');
    process.stdout.write(${JSON.stringify(bytes.slice(0, 25))});
    setTimeout(() => { process.stdout.end(${JSON.stringify(bytes.slice(25))}); process.exitCode = 1; }, 10);`);
  const result = await request.done;
  assert.equal(result.exitCode, 1);
  assert.equal(result.childCode, 'QUALIFICATION_WORKER_INPUT');
  assert.equal(result.httpStatus, null);
  assert.equal(result.responseStatus, null);
  assert.equal(/PRIVATE_/.test(JSON.stringify(result)), false);
  assert.equal(request.completion(), result);
});

test('an HTTP rejection completed before the barrier fails promptly with its safe reason', async t => {
  const request = child(t, output({ ...profile, action: 'agent-request', role: 'agent',
    result: { httpStatus: 401, response: { code: 'AGENT_UNAUTHORIZED', resource: 'PRIVATE_BODY_MARKER' } } }));
  await request.done;
  const diagnostics = [];
  await assert.rejects(waitForQualificationBarrier({ barrier: 'signer_blocked', request,
    readSnapshot: () => journal('provider_opened'), writeDiagnostic: value => diagnostics.push(value) }),
  { code: 'QUALIFICATION_BACKGROUND_COMPLETED', childCode: 'AGENT_UNAUTHORIZED', status: 0 });
  assert.equal(diagnostics[0].httpStatus, 401);
  assert.equal(diagnostics[0].responseCode, 'AGENT_UNAUTHORIZED');
  assert.equal(diagnostics[1].lastEventKind, 'provider_opened');
  assert.equal(/PRIVATE_/.test(JSON.stringify(diagnostics)), false);
});

test('invalid and oversized child output never becomes a public diagnostic payload', async t => {
  for (const [source, expected] of [
    ["process.stdout.write('PRIVATE_NOT_JSON');", 'QUALIFICATION_BACKGROUND_OUTPUT'],
    ["process.stdout.write('S'.repeat(1048577));", 'QUALIFICATION_BACKGROUND_OUTPUT_BOUNDS'],
  ]) {
    const request = child(t, source);
    const result = await request.done;
    assert.equal(result.childCode, expected);
    assert.equal(result.responseCode, null);
    assert.equal(JSON.stringify(result).length < 512, true);
    assert.equal(JSON.stringify(result).includes('PRIVATE'), false);
  }
});

test('unrecognized status strings and invalid codes are dropped from completion diagnostics', async t => {
  const request = child(t, output({ ...profile, code: 'PRIVATE\nMESSAGE', action: 'agent-request', role: 'agent',
    result: { httpStatus: 999, response: { status: 'private_text', code: 'private_message' } } }));
  const result = await request.done;
  assert.equal(result.childCode, null);
  assert.equal(result.httpStatus, null);
  assert.equal(result.responseCode, null);
  assert.equal(result.responseStatus, null);
});

test('early approval and in-flight Kernel statuses retain their exact public names', async t => {
  for (const status of ['payment_approval_required', 'request_in_flight']) {
    const request = child(t, output({ ...profile, action: 'agent-request', role: 'agent',
      result: { httpStatus: 202, response: { status } } }));
    assert.equal((await request.done).responseStatus, status);
  }
});

test('transient snapshot errors do not replace an observed durable barrier', async t => {
  const request = child(t, 'setTimeout(() => {}, 30000);');
  let reads = 0;
  const expected = journal('signer_blocked');
  const result = await waitForQualificationBarrier({ barrier: 'signer_blocked', request, pollMs: 1,
    readSnapshot: () => { if (++reads === 1) throw Object.assign(new Error('PRIVATE'), { code: 'STORAGE_CHANGED' }); return expected; },
    writeDiagnostic: () => assert.fail('a successful barrier cannot emit failure diagnostics') });
  assert.equal(result, expected);
});

test('an observed barrier takes precedence over an already completed request', async t => {
  const request = child(t, output({ ...profile, code: 'QUALIFICATION_HTTP_TIMEOUT' }));
  await request.done;
  const expected = journal('signer_blocked');
  assert.equal(await waitForQualificationBarrier({ barrier: 'signer_blocked', request,
    readSnapshot: () => expected, writeDiagnostic: () => assert.fail('barrier was observed') }), expected);
});

test('a barrier timeout retains only the validated snapshot cause and last public journal observation', async t => {
  const request = child(t, 'setTimeout(() => {}, 30000);');
  const diagnostics = [];
  let reads = 0;
  await assert.rejects(waitForQualificationBarrier({ barrier: 'signer_blocked', request, timeout: 1000, pollMs: 1,
    readSnapshot: () => {
      if (++reads === 1) return journal('provider_opened');
      throw Object.assign(new Error('PRIVATE_EXCEPTION_MARKER'), {
        code: 'QUALIFICATION_COMMAND_FAILED', childCode: 'QUALIFICATION_SNAPSHOT_PAYMENT' });
    }, writeDiagnostic: value => diagnostics.push(value) }),
  { code: 'QUALIFICATION_TIMEOUT', childCode: 'QUALIFICATION_SNAPSHOT_PAYMENT', label: 'signer_blocked' });
  assert.deepEqual(diagnostics, [{ diagnostic: 'qualification-barrier-observation', barrier: 'signer_blocked',
    snapshotCode: 'QUALIFICATION_SNAPSHOT_PAYMENT', lastEventKind: 'provider_opened',
    lastEventRouteId: 'qualification-signing-interruption',
    counters: { providerOpens: 1, unpaidRequests: 0, signerCalls: 0, signaturesProduced: 0, paidRequests: 0 } }]);
  assert.equal(/PRIVATE_/.test(JSON.stringify(diagnostics)), false);
});

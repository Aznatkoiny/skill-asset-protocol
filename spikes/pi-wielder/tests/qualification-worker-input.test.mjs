import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import test from 'node:test';
import { setTimeout as pause } from 'node:timers/promises';

import { canonicalJson, sha256 } from '../src/kernel/canonical.mjs';

const workerUrl = new URL('../scripts/qualification-authority-worker.mjs', import.meta.url).href;
const payload = { routeId: 'qualification-signing-interruption',
  callId: Buffer.from(sha256('signing-interruption:').slice(7), 'hex').toString('base64url'), body: { qualification: true } };
const bytes = Buffer.from(`${canonicalJson(payload)}\n`);
const source = `import {readQualificationInput, validateQualificationPayload} from ${JSON.stringify(workerUrl)};
  try { validateQualificationPayload('agent-request', await readQualificationInput());
    process.stdout.write(JSON.stringify({accepted:true})); }
  catch(error) { process.stdout.write(JSON.stringify({code:error.code})); process.exitCode=1; }`;

function reader(t, setpriv = false) {
  const args = ['--input-type=module', '--eval', source];
  const child = spawn(setpriv ? '/usr/bin/setpriv' : process.execPath,
    setpriv ? ['--no-new-privs', '--', process.execPath, ...args] : args,
    { env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'pipe'] });
  let stdout = ''; let stderr = ''; let terminal = null;
  child.stdout.on('data', chunk => { stdout += chunk; });
  child.stderr.on('data', chunk => { stderr += chunk; });
  child.stdin.on('error', () => {}); // Oversized inputs may be rejected before the write completes.
  const done = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', code => { terminal = {code, stdout, stderr}; resolve(terminal); });
  });
  t.after(async () => { if (!terminal) child.kill('SIGKILL'); await done; });
  return { child, done, terminal: () => terminal };
}

test('setpriv stdin survives complete payload delivery before asynchronous EOF while the parent is busy', async t => {
  if (process.platform !== 'linux' || !fs.existsSync('/usr/bin/setpriv')) {
    t.skip('requires the real Linux setpriv executable'); return;
  }
  const request = reader(t, true);
  request.child.stdin.end(bytes);
  // Reproduces the installed harness's immediate synchronous snapshot command.
  // The prior fd0 read loop failed EAGAIN here after consuming all payload bytes.
  execFileSync(process.execPath, ['--input-type=module', '--eval',
    `import ${JSON.stringify(workerUrl)}; const end=Date.now()+150; while(Date.now()<end){}`],
  { env: { PATH: '/usr/bin:/bin' }, timeout: 5000, stdio: 'ignore' });
  assert.deepEqual(await request.done, { code: 0, stdout: '{"accepted":true}', stderr: '' });
});

test('fragmented input waits for actual EOF and never accepts a partial message', async t => {
  const request = reader(t);
  request.child.stdin.write(bytes.subarray(0, 60));
  await pause(30);
  assert.equal(request.terminal(), null);
  request.child.stdin.write(bytes.subarray(60));
  await pause(30);
  assert.equal(request.terminal(), null, 'complete JSON still requires EOF');
  request.child.stdin.end();
  assert.deepEqual(await request.done, { code: 0, stdout: '{"accepted":true}', stderr: '' });
});

test('the exact 16384-byte input limit remains accepted', async t => {
  const request = reader(t);
  request.child.stdin.end(Buffer.concat([Buffer.alloc(16384 - bytes.length, 0x20), bytes]));
  assert.deepEqual(await request.done, { code: 0, stdout: '{"accepted":true}', stderr: '' });
});

test('overflow, invalid UTF8, truncation, empty input, and schema drift preserve the same safe error', async t => {
  for (const input of [
    Buffer.concat([Buffer.alloc(16385 - bytes.length, 0x20), bytes]),
    Buffer.from([0xff]), Buffer.from('{"routeId":'), Buffer.alloc(0),
    Buffer.from(JSON.stringify({ ...payload, privateField: 'PRIVATE_INPUT_MARKER' })),
  ]) {
    const request = reader(t);
    request.child.stdin.end(input);
    assert.deepEqual(await request.done, { code: 1, stdout: '{"code":"QUALIFICATION_WORKER_INPUT"}', stderr: '' });
  }
});

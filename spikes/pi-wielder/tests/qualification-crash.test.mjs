import assert from 'node:assert/strict';
import { fork } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setTimeout as pause } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { readOfflineQualificationJournal } from '../src/runtime/qualification-clients.mjs';
import { qualificationCrashContext, readQualificationCrashSnapshot } from './fixtures/qualification-crash-worker.mjs';

const WORKER = fileURLToPath(new URL('./fixtures/qualification-crash-worker.mjs', import.meta.url));

function child(t, directory, scenario, phase) {
  const processChild = fork(WORKER, [directory, scenario, phase], {
    execPath:process.execPath, execArgv:[], env:{PATH:'/usr/bin:/bin'}, stdio:['ignore', 'ignore', 'pipe', 'ipc'],
  });
  const messages = [];
  let diagnostic = '';
  processChild.stderr.on('data', bytes => {if (diagnostic.length < 8192) diagnostic += bytes;});
  processChild.on('message', message => messages.push(message));
  let terminal;
  const exited = new Promise((resolve, reject) => {
    processChild.once('error', reject);
    processChild.once('exit', (code, signal) => {terminal = {code, signal}; resolve(terminal);});
  });
  t.after(async () => {
    if (!terminal) processChild.kill('SIGKILL');
    await exited;
  });
  return {process:processChild, exited, messages, diagnostic:() => diagnostic, terminal:() => terminal};
}

async function waitFor(label, operation, worker, timeout = 12000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) {
    const failed = worker.messages.find(message => message.type === 'failure');
    assert.equal(failed, undefined, `${label}: ${JSON.stringify(worker.messages)} ${worker.diagnostic()}`);
    const result = operation();
    if (result) return result;
    assert.equal(worker.terminal(), undefined, `${label}: child exited ${worker.diagnostic()}`);
    await pause(20);
  }
  assert.fail(`${label} timed out: ${worker.diagnostic()}`);
}

for (const [scenario, barrier, amount, signaturesProduced, paidRequests] of [
  ['signing-interruption', 'signer_blocked', '80000', 0, 0],
  ['retry-interruption', 'retry_blocked', '90000', 1, 1],
]) {
  test(`SIGKILL at durable ${barrier} preserves exact ${amount} hold without another signature or paid retry`,
    {timeout:30000}, async t => {
      const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'qualification-crash-'));
      fs.chmodSync(directory, 0o700);
      // Remove the fixture only after both real child processes have exited.
      const {config, pathTrust} = qualificationCrashContext(directory);
      const journal = () => readOfflineQualificationJournal({databasePath:config.databasePath, pathTrust});
      let first;
      let recovered;
      try {
        first = child(t, directory, scenario, 'crash');
        const initialReady = await waitFor('initial authority ready',
          () => first.messages.find(message => message.type === 'ready'), first);
        assert.equal(initialReady.scope, 'local-process-offline');
        const beforeJournal = await waitFor(`fsynced ${barrier}`, () => {
          const value = journal();
          const flushed = first.messages.find(message => message.type === 'durable-barrier');
          return value.lastEvent?.kind === barrier && flushed?.kind === barrier
            && flushed.eventHash === value.lastEvent.eventHash ? value : null;
        }, first);
        assert.equal(beforeJournal.lastEvent.routeId, `qualification-${scenario}`);
        assert.deepEqual(beforeJournal.counters, {providerOpens:1, unpaidRequests:1,
          signerCalls:1, signaturesProduced, paidRequests});
        assert.equal(first.messages.some(message => message.type === 'response'), false);
        const before = readQualificationCrashSnapshot(config.databasePath);
        assert.equal(before.intents.length, 1);
        assert.equal(before.intents[0].route_id, `qualification-${scenario}`);
        assert.equal(before.intents[0].state, scenario === 'signing-interruption' ? 'signing' : 'retrying');
        assert.equal(before.reservations.length, 1);
        assert.equal(before.reservations[0].reserved_atomic, amount);
        assert.equal(before.payments.length, 1);
        assert.equal(before.payments[0].intent_id, before.intents[0].id);
        assert.equal(before.payments[0].signed_at !== null, scenario === 'retry-interruption');
        assert.equal(first.process.kill('SIGKILL'), true);
        assert.deepEqual(await first.exited, {code:null, signal:'SIGKILL'});
        assert.deepEqual(journal(), beforeJournal, 'hard termination cannot append graceful-cleanup provider events');

        recovered = child(t, directory, scenario, 'recover');
        const recoveredReady = await waitFor('fresh process recovered authority',
          () => recovered.messages.find(message => message.type === 'ready'), recovered);
        assert.notEqual(recoveredReady.pid, initialReady.pid);
        assert.equal(recoveredReady.requestHash, initialReady.requestHash, 'retry uses the exact route/body/call ID');
        const response = await waitFor('recovered exact Agent retry',
          () => recovered.messages.find(message => message.type === 'response'), recovered);
        assert.deepEqual(await recovered.exited, {code:0, signal:null}, recovered.diagnostic());
        assert.equal(response.status, 503, JSON.stringify(response.body));
        assert.equal(response.body.status, 'payment_unresolved');
        const after = readQualificationCrashSnapshot(config.databasePath);
        assert.equal(after.intents.length, 1, 'same Agent call must retain its original Spend Intent');
        assert.equal(after.intents[0].id, before.intents[0].id);
        assert.equal(after.intents[0].session_id, before.intents[0].session_id);
        assert.equal(after.intents[0].state, 'unresolved');
        assert.deepEqual(after.reservations, [{intent_id:before.intents[0].id, state:'unresolved',
          reserved_atomic:'0', committed_atomic:'0', released_atomic:'0', unresolved_atomic:amount}]);
        assert.equal(after.outcomes.length, 1);
        assert.equal(after.outcomes[0].intent_id, before.intents[0].id);
        assert.equal(after.outcomes[0].status, 'payment_unresolved');
        assert.equal(after.payments.length, 1);
        for (const field of ['id', 'intent_id', 'payment_hash', 'payloadHash', 'headerHash', 'signatureHash',
          'signing_claimed_at', 'signed_at', 'retry_started_at']) {
          assert.equal(after.payments[0][field], before.payments[0][field], `${field} survives process loss exactly`);
        }
        if (scenario === 'retry-interruption') assert.match(after.payments[0].signatureHash, /^sha256:[0-9a-f]{64}$/);
        else assert.equal(after.payments[0].signatureHash, null);
        const afterJournal = journal();
        assert.deepEqual(afterJournal.events.slice(0, beforeJournal.events.length), beforeJournal.events);
        assert.deepEqual(afterJournal.events.slice(beforeJournal.events.length).map(event => event.kind), ['provider_opened']);
        assert.deepEqual(afterJournal.counters, {...beforeJournal.counters, providerOpens:2});
      } finally {
        for (const worker of [first, recovered].filter(Boolean)) {
          if (!worker.terminal()) worker.process.kill('SIGKILL');
          await worker.exited;
        }
        fs.rmSync(directory, {recursive:true, force:true});
      }
    });
}

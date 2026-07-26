import assert from 'node:assert/strict';
import test from 'node:test';

import {
  INITIAL_SANDBOX_STATE,
  SANDBOX_STAGES,
  demoCreator,
  demoInvocations,
  demoOutcome,
  demoSkill,
  rewardPolicy,
  sandboxReducer,
  sandboxView,
} from './sandbox-model.ts';

test('the fixture attributes one immutable Skill version to a Creator', () => {
  assert.equal(demoSkill.creator.id, demoCreator.id);
  assert.match(demoSkill.artifactHash, /^sha256:[a-f0-9]{64}$/);
  assert.equal(demoSkill.status, 'Approved');
});

test('all sample Wielders differ from the Creator and use unique idempotency keys', () => {
  assert.equal(demoInvocations.length, 3);
  assert.ok(
    demoInvocations.every(
      (invocation) => invocation.wielder.id !== demoCreator.id,
    ),
  );
  assert.equal(
    new Set(demoInvocations.map((invocation) => invocation.idempotencyKey))
      .size,
    3,
  );
});

test('the linked outcome belongs to a successful sample Invocation', () => {
  const invocation = demoInvocations.find(
    (item) => item.id === demoOutcome.invocationId,
  );
  assert.equal(invocation?.status, 'Succeeded');
});

test('the sandbox advances only through the intended ordered actions', () => {
  let state = INITIAL_SANDBOX_STATE;

  state = sandboxReducer(state, { type: 'SIMULATE_USES' });
  assert.equal(state.stage, 'ready');

  state = sandboxReducer(state, { type: 'IMPORT_SAMPLE' });
  assert.equal(state.stage, 'registered');

  state = sandboxReducer(state, { type: 'SIMULATE_USES' });
  assert.equal(state.stage, 'used');
  assert.equal(sandboxView(state).invocations.length, 3);

  state = sandboxReducer(state, { type: 'ATTACH_OUTCOME' });
  assert.equal(state.stage, 'evidenced');
  assert.equal(sandboxView(state).hasOutcome, true);

  state = sandboxReducer(state, { type: 'PREVIEW_CLOSE' });
  assert.equal(state.stage, 'closed');
  assert.equal(sandboxView(state).hasClosePreview, true);
  assert.deepEqual(
    SANDBOX_STAGES,
    ['ready', 'registered', 'used', 'evidenced', 'closed'],
  );
});

test('repeated actions are idempotent and reset restores the exact initial state', () => {
  const registered = sandboxReducer(INITIAL_SANDBOX_STATE, {
    type: 'IMPORT_SAMPLE',
  });
  const repeated = sandboxReducer(registered, { type: 'IMPORT_SAMPLE' });
  assert.deepEqual(repeated, registered);
  assert.deepEqual(
    sandboxReducer(repeated, { type: 'RESET' }),
    INITIAL_SANDBOX_STATE,
  );
});

test('the provisional award is bounded by the employer-funded pool', () => {
  assert.ok(rewardPolicy.proposedAwardMinor > 0);
  assert.ok(rewardPolicy.proposedAwardMinor <= rewardPolicy.poolMinor);
  assert.equal(
    rewardPolicy.factors.reduce((sum, factor) => sum + factor.points, 0),
    rewardPolicy.selectedSkillPoints,
  );
});

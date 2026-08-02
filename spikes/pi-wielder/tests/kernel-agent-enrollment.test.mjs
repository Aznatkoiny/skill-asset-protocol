import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { canonicalJson, KernelError, sha256 } from '../src/kernel/canonical.mjs';
import { createAgentEnrollmentRepository } from '../src/kernel/agent-enrollment.mjs';
import { openKernelStore } from '../src/kernel/sqlite-store.mjs';

const NOW = '2026-07-31T12:00:00.000Z';
const DESCRIPTOR = Object.freeze({
  schemaVersion: 1,
  agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA',
  credentialDigest: `sha256:${'ab'.repeat(32)}`,
  agentUid: '501',
  agentGid: '20',
});
const DESCRIPTOR_HASH = sha256(canonicalJson(DESCRIPTOR));
const OPERATOR_HASH = `sha256:${'cd'.repeat(32)}`;

function memoryStore() {
  return openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => NOW,
  });
}

function assertKernelError(operation, expectedCode) {
  assert.throws(operation, (error) => {
    assert.ok(error instanceof KernelError);
    assert.equal(error.code, expectedCode);
    return true;
  });
}

function enroll(enrollments, overrides = {}) {
  return enrollments.enroll({
    descriptor: DESCRIPTOR,
    expectedDescriptorHash: DESCRIPTOR_HASH,
    operatorIdHash: OPERATOR_HASH,
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
    ...overrides,
  });
}

function replacementDescriptor(overrides = {}) {
  return {
    ...DESCRIPTOR,
    agentInstanceId: 'AQEBAQEBAQEBAQEBAQEBAQ',
    credentialDigest: `sha256:${'12'.repeat(32)}`,
    ...overrides,
  };
}

test('enrolls one exact non-secret agent identity', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });

  const enrolled = enroll(enrollments);

  assert.equal(enrolled.enrollmentHash, DESCRIPTOR_HASH);
  assert.equal(enrolled.isolation, 'pending_verification');
  const replay = enroll(enrollments);
  assert.deepEqual(replay, enrolled);
  assert.equal(store.events().filter((row) => row.event_type === 'agent.enrolled').length, 1);
  const active = enrollments.active();
  assert.equal(active.credentialDigest, DESCRIPTOR.credentialDigest);
  assert.deepEqual(enrollments.get(DESCRIPTOR.agentInstanceId), active);
  assert.ok(Object.isFrozen(active));
});

test('revocation atomically removes enrollment authority and supersedes its attestation', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(enrollments);
  store.execForTest(`
    INSERT INTO policy_versions
      (id, schema_version, canonical_json, policy_hash, applied_at)
      VALUES ('policy-1', 1, '{}', 'policy-hash-1', '${NOW}');
    INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES ('session-1', 'pi:${DESCRIPTOR.agentInstanceId}',
       '0x1000000000000000000000000000000000000000', 'policy-1', 'open', '${NOW}');
    INSERT INTO agent_session_bindings
      (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
       state, created_at, last_seen_at)
      VALUES ('binding-1', '${DESCRIPTOR.agentInstanceId}', '${DESCRIPTOR.credentialDigest}',
       '${enrolled.enrollmentHash}', 'session-1', 'open', '${NOW}', '${NOW}');
    INSERT INTO isolation_attestations
      (id, report_hash, enrollment_hash, report_json, state,
       imported_by_operator_hash, probed_at, expires_at, imported_at)
      VALUES ('attestation-1', 'sha256:${'ef'.repeat(32)}', '${enrolled.enrollmentHash}',
       '{}', 'current', '${OPERATOR_HASH}', '${NOW}', '2026-08-01T12:00:00.000Z', '${NOW}');
    INSERT INTO spend_intents
      (id, request_id, session_id, enrollment_hash, route_id, method,
       request_url_hash, seller_origin, resource_path, body_hash,
       header_allowlist_hash, ordinary_fingerprint, purpose_label,
       correlation_id, idempotency_key, wallet_address, intent_hash,
       state, created_at, updated_at)
      VALUES ('intent-unresolved', 'request-unresolved', 'session-1',
       '${enrolled.enrollmentHash}', 'route-1', 'POST', 'url-hash',
       'https://seller.example', '/paid/infer', 'body-hash', 'header-hash',
       'fingerprint-unresolved', 'skill.invoke', 'correlation-unresolved',
       'wk_${'11'.repeat(32)}', '0x1000000000000000000000000000000000000000',
       'intent-hash-unresolved', 'unresolved', '${NOW}', '${NOW}');
    INSERT INTO budget_reservations
      (intent_id, session_id, seller_origin, reserved_atomic, committed_atomic,
       released_atomic, unresolved_atomic, state, updated_at)
      VALUES ('intent-unresolved', 'session-1', 'https://seller.example',
       '0', '0', '0', '50000', 'unresolved', '${NOW}');
  `);

  assertKernelError(() => enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: `sha256:${'00'.repeat(32)}`,
    operatorIdHash: OPERATOR_HASH,
  }), 'AGENT_ENROLLMENT_STALE');

  const revoked = enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });

  assert.deepEqual(revoked.boundSessionIds, ['session-1']);
  assert.equal(revoked.enrollment.state, 'revoked');
  assert.equal(enrollments.active(), null);
  assert.equal(store.readOne(
    'SELECT state FROM spend_sessions WHERE id = ?', ['session-1'],
  ).state, 'open');
  const unresolved = store.readOne(`SELECT state, unresolved_atomic
    FROM budget_reservations WHERE intent_id = ?`, ['intent-unresolved']);
  assert.equal(unresolved.state, 'unresolved');
  assert.equal(unresolved.unresolved_atomic, '50000');
  const attestation = store.readOne(
    'SELECT state, superseded_at FROM isolation_attestations WHERE id = ?',
    ['attestation-1'],
  );
  assert.equal(attestation.state, 'superseded');
  assert.equal(attestation.superseded_at, NOW);
  assert.equal(store.events().filter((row) => row.event_type === 'agent.revoked').length, 1);
  assert.equal(store.events().filter(
    (row) => row.event_type === 'isolation.attestation_superseded',
  ).length, 1);
});

test('descriptor and OS identity inputs are closed, canonical, and non-secret', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const invalidDescriptors = [
    [{ ...DESCRIPTOR, token: 'RAW_AGENT_TOKEN_SENTINEL' }, 'AGENT_DESCRIPTOR_SCHEMA'],
    [Object.fromEntries(Object.entries(DESCRIPTOR).filter(([key]) => key !== 'agentGid')),
      'AGENT_DESCRIPTOR_SCHEMA'],
    [{ ...DESCRIPTOR, schemaVersion: 2 }, 'AGENT_DESCRIPTOR_VERSION'],
    [{ ...DESCRIPTOR, agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAA' }, 'AGENT_INSTANCE_ID'],
    [{ ...DESCRIPTOR, agentInstanceId: 'AAAAAAAAAAAAAAAAAAAAAA==' }, 'AGENT_INSTANCE_ID'],
    [{ ...DESCRIPTOR, credentialDigest: `sha256:${'AB'.repeat(32)}` },
      'AGENT_CREDENTIAL_DIGEST'],
    [{ ...DESCRIPTOR, agentUid: '0501' }, 'AGENT_IDENTITY'],
    [{ ...DESCRIPTOR, agentUid: '0' }, 'AGENT_IDENTITY'],
    [{ ...DESCRIPTOR, agentUid: String(Number.MAX_SAFE_INTEGER + 1) }, 'AGENT_IDENTITY'],
    [{ ...DESCRIPTOR, agentGid: '0' }, 'AGENT_IDENTITY'],
  ];
  for (const [descriptor, code] of invalidDescriptors) {
    assertKernelError(() => enroll(enrollments, {
      descriptor,
      expectedDescriptorHash: sha256(canonicalJson(descriptor)),
    }), code);
  }

  let getterCalls = 0;
  const accessorDescriptor = { ...DESCRIPTOR };
  Object.defineProperty(accessorDescriptor, 'agentUid', {
    enumerable: true,
    get() {
      getterCalls += 1;
      return '501';
    },
  });
  assertKernelError(() => enroll(enrollments, {
    descriptor: accessorDescriptor,
    expectedDescriptorHash: DESCRIPTOR_HASH,
  }), 'AGENT_ENROLLMENT_SCHEMA');
  assert.equal(getterCalls, 0);

  assertKernelError(() => enroll(enrollments, {
    expectedDescriptorHash: `sha256:${'00'.repeat(32)}`,
  }), 'AGENT_DESCRIPTOR_HASH');
  assertKernelError(() => enroll(enrollments, { operatorIdHash: 'operator' }),
    'AGENT_ENROLLMENT_SCHEMA');
  assertKernelError(() => enroll(enrollments, { expectedAgentUid: 502 }),
    'AGENT_IDENTITY_MISMATCH');
  assertKernelError(() => enroll(enrollments, { kernelUid: 501 }),
    'AGENT_IDENTITY_NOT_ISOLATED');
  assert.equal(store.readOne('SELECT COUNT(*) AS count FROM agent_enrollments').count, 0n);
  assert.equal(JSON.stringify(store.events()).includes('RAW_AGENT_TOKEN_SENTINEL'), false);
});

test('deterministic same-UID enrollment is explicit, simulated, and exact replay is idempotent', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const first = enroll(enrollments, {
    mode: 'deterministic',
    kernelUid: 501,
    kernelGid: 20,
  });
  const replay = enroll(enrollments, {
    mode: 'deterministic',
    kernelUid: 501,
    kernelGid: 20,
  });

  assert.deepEqual(replay, first);
  assert.equal(first.isolation, 'simulated');
  assert.equal(store.readOne('SELECT COUNT(*) AS count FROM agent_enrollments').count, 1n);
  const events = store.events().filter((row) => row.event_type === 'agent.enrolled');
  assert.equal(events.length, 1);
  assert.equal(JSON.parse(events[0].data_json).isolation, 'simulated');

  assertKernelError(() => enroll(enrollments, {
    mode: 'deterministic',
    kernelUid: 502,
    kernelGid: 20,
  }), 'AGENT_DETERMINISTIC_FIXTURE');

  assertKernelError(() => enroll(enrollments, {
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 502,
  }), 'AGENT_ENROLLMENT_CONFLICT');

  const different = replacementDescriptor();
  assertKernelError(() => enroll(enrollments, {
    descriptor: different,
    expectedDescriptorHash: sha256(canonicalJson(different)),
    mode: 'deterministic',
    kernelUid: 501,
    kernelGid: 20,
  }), 'AGENT_ENROLLMENT_CONFLICT');
});

test('live enrollment permits the pinned macOS-compatible shared primary GID', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });

  const enrolled = enroll(enrollments, {
    mode: 'cdp-testnet',
    kernelUid: 502,
    kernelGid: 20,
    expectedAgentUid: 501,
    expectedAgentGid: 20,
  });

  assert.equal(enrolled.agentUid, '501');
  assert.equal(enrolled.agentGid, '20');
  assert.equal(enrolled.isolation, 'pending_verification');
});

test('revocation rejects a regressed Kernel clock without changing authority', (t) => {
  let clock = NOW;
  const store = openKernelStore({
    filePath: ':memory:',
    allowMemory: true,
    now: () => clock,
  });
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => clock });
  const enrolled = enroll(enrollments);
  const eventsBefore = store.events();
  clock = '2026-07-31T11:59:59.999Z';

  assertKernelError(() => enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  }), 'AGENT_ENROLLMENT_TIME');
  assert.equal(enrollments.active().enrollmentHash, enrolled.enrollmentHash);
  assert.deepEqual(store.events(), eventsBefore);
});

test('replacement enrollment waits for every revoked binding to close', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(enrollments);
  store.execForTest(`
    INSERT INTO policy_versions
      (id, schema_version, canonical_json, policy_hash, applied_at)
      VALUES ('policy-1', 1, '{}', 'policy-hash-1', '${NOW}');
    INSERT INTO spend_sessions
      (id, adapter_id, wallet_address, policy_version_id, state, created_at)
      VALUES ('session-1', 'pi:${DESCRIPTOR.agentInstanceId}',
       '0x1000000000000000000000000000000000000000', 'policy-1', 'open', '${NOW}');
    INSERT INTO agent_session_bindings
      (id, agent_instance_id, credential_digest, enrollment_hash, session_id,
       state, created_at, last_seen_at)
      VALUES ('binding-1', '${DESCRIPTOR.agentInstanceId}', '${DESCRIPTOR.credentialDigest}',
       '${enrolled.enrollmentHash}', 'session-1', 'open', '${NOW}', '${NOW}');
  `);
  enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  const different = replacementDescriptor();
  const replacementInput = {
    descriptor: different,
    expectedDescriptorHash: sha256(canonicalJson(different)),
  };

  assertKernelError(() => enroll(enrollments, replacementInput), 'AGENT_ENROLLMENT_BOUND');
  store.execForTest(`
    UPDATE agent_session_bindings
      SET state = 'closed' WHERE id = 'binding-1';
    UPDATE spend_sessions
      SET state = 'closed' WHERE id = 'session-1';
  `);
  assertKernelError(() => enroll(enrollments, replacementInput),
    'AGENT_ENROLLMENT_CORRUPTION');
  store.execForTest(`
    UPDATE agent_session_bindings
      SET closed_at = '${NOW}' WHERE id = 'binding-1';
    UPDATE spend_sessions
      SET closed_at = '${NOW}' WHERE id = 'session-1';
  `);
  const replacement = enroll(enrollments, replacementInput);
  assert.equal(replacement.enrollmentHash, replacementInput.expectedDescriptorHash);
  assert.equal(enrollments.active().agentInstanceId, different.agentInstanceId);
});

test('a current attestation forged onto a revoked epoch is semantic corruption', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(enrollments);
  enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  store.execForTest(`
    INSERT INTO isolation_attestations
      (id, report_hash, enrollment_hash, report_json, state,
       imported_by_operator_hash, probed_at, expires_at, imported_at)
      VALUES ('forged-current', 'sha256:${'34'.repeat(32)}', '${enrolled.enrollmentHash}',
       '{}', 'current', '${OPERATOR_HASH}', '${NOW}',
       '2026-08-01T12:00:00.000Z', '${NOW}');
  `);

  assertKernelError(() => enrollments.active(), 'AGENT_ENROLLMENT_CORRUPTION');
  const different = replacementDescriptor();
  assertKernelError(() => enroll(enrollments, {
    descriptor: different,
    expectedDescriptorHash: sha256(canonicalJson(different)),
  }), 'AGENT_ENROLLMENT_CORRUPTION');
});

test('active enrollment reads are one revocation-safe snapshot', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const revoker = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(revoker);
  let revocationWon = false;
  const winRevocation = () => {
    if (revocationWon) return;
    revocationWon = true;
    revoker.revoke({
      agentInstanceId: DESCRIPTOR.agentInstanceId,
      expectedEnrollmentHash: enrolled.enrollmentHash,
      operatorIdHash: OPERATOR_HASH,
    });
  };
  const racingStore = Object.freeze({
    ...store,
    transaction(operation) {
      winRevocation();
      return store.transaction(operation);
    },
    readAll(sql, parameters) {
      const rows = store.readAll(sql, parameters);
      if (/agent_enrollments WHERE state = 'active'/.test(sql)) winRevocation();
      return rows;
    },
  });
  const reader = createAgentEnrollmentRepository({ store: racingStore, now: () => NOW });

  assert.equal(reader.active(), null);
  assert.equal(revocationWon, true);
});

test('creation-event authority is exact and enrollment replay does not resample time', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  let clockCalls = 0;
  const enrollments = createAgentEnrollmentRepository({
    store,
    now: () => {
      clockCalls += 1;
      return clockCalls === 1 ? NOW : 'not-a-timestamp';
    },
  });
  const first = enroll(enrollments);
  assert.deepEqual(enroll(enrollments), first);
  assert.equal(clockCalls, 1);

  const event = store.readOne(`SELECT sequence, data_json FROM events
    WHERE event_type = ?`, ['agent.enrolled']);
  const data = JSON.parse(event.data_json);
  store.execForTest(`UPDATE events SET data_json = '${canonicalJson({
    ...data,
    injected: true,
  }).replaceAll("'", "''")}' WHERE sequence = ${event.sequence}`);
  assertKernelError(() => enrollments.get(DESCRIPTOR.agentInstanceId),
    'AGENT_ENROLLMENT_CORRUPTION');
});

test('a revoked historical epoch cannot be silently re-enrolled', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const enrollments = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(enrollments);
  enrollments.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });

  assertKernelError(() => enroll(enrollments), 'AGENT_REVOKED');
});

test('file-backed revoke survives reopen with history retained and no current attestation', (t) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-kernel-enrollment-'));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const filePath = path.join(directory, 'kernel.sqlite');
  const pathTrust = Object.freeze({
    mode: 'deterministic',
    trustedAncestor: directory,
    kernelUid: process.getuid(),
    agentUid: process.getuid(),
  });
  const firstStore = openKernelStore({ filePath, pathTrust, now: () => NOW });
  const first = createAgentEnrollmentRepository({ store: firstStore, now: () => NOW });
  const enrolled = enroll(first);
  firstStore.execForTest?.('SELECT 1');
  first.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  });
  firstStore.close();

  const reopenedStore = openKernelStore({ filePath, pathTrust, now: () => NOW });
  t.after(() => reopenedStore.close());
  const reopened = createAgentEnrollmentRepository({ store: reopenedStore, now: () => NOW });
  assert.equal(reopened.active(), null);
  assert.equal(reopened.get(DESCRIPTOR.agentInstanceId).state, 'revoked');
  assert.equal(reopenedStore.readAll(
    "SELECT id FROM isolation_attestations WHERE state = 'current'",
  ).length, 0);
  assert.equal(reopenedStore.events().filter((row) => row.event_type === 'agent.revoked').length, 1);
});

test('enrollment and revocation event faults roll back their whole authority mutation', (t) => {
  const store = memoryStore();
  t.after(() => store.close());
  const faultingStore = (eventType) => Object.freeze({
    ...store,
    within(token, operation) {
      return store.within(token, ({ db, appendEvent }) => operation({
        db,
        appendEvent(event) {
          if (event.eventType === eventType) throw new Error(`fault:${eventType}`);
          return appendEvent(event);
        },
      }));
    },
  });

  const failedEnrollments = createAgentEnrollmentRepository({
    store: faultingStore('agent.enrolled'),
    now: () => NOW,
  });
  assert.throws(() => enroll(failedEnrollments), /fault:agent\.enrolled/);
  assert.equal(store.readOne('SELECT COUNT(*) AS count FROM agent_enrollments').count, 0n);
  assert.equal(store.events().length, 0);

  const normal = createAgentEnrollmentRepository({ store, now: () => NOW });
  const enrolled = enroll(normal);
  store.execForTest(`INSERT INTO isolation_attestations
    (id, report_hash, enrollment_hash, report_json, state,
     imported_by_operator_hash, probed_at, expires_at, imported_at)
    VALUES ('attestation-rollback', 'sha256:${'ef'.repeat(32)}',
     '${enrolled.enrollmentHash}', '{}', 'current', '${OPERATOR_HASH}', '${NOW}',
     '2026-08-01T12:00:00.000Z', '${NOW}')`);
  const failedRevocations = createAgentEnrollmentRepository({
    store: faultingStore('agent.revoked'),
    now: () => NOW,
  });
  assert.throws(() => failedRevocations.revoke({
    agentInstanceId: DESCRIPTOR.agentInstanceId,
    expectedEnrollmentHash: enrolled.enrollmentHash,
    operatorIdHash: OPERATOR_HASH,
  }), /fault:agent\.revoked/);
  assert.equal(store.readOne(
    'SELECT state FROM agent_enrollments WHERE agent_instance_id = ?',
    [DESCRIPTOR.agentInstanceId],
  ).state, 'active');
  assert.equal(store.readOne(
    'SELECT state FROM isolation_attestations WHERE id = ?', ['attestation-rollback'],
  ).state, 'current');
  assert.equal(store.events().filter((row) => row.event_type === 'agent.revoked').length, 0);
  assert.equal(store.events().filter(
    (row) => row.event_type === 'isolation.attestation_superseded',
  ).length, 0);
});

import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from './canonical.mjs';

const HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const INSTANCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_-]{21}$/;

function fail(code, message) {
  throw new KernelError(code, message);
}

function canonicalHash(value, label, code = 'AGENT_ENROLLMENT_SCHEMA') {
  if (typeof value !== 'string' || !HASH_PATTERN.test(value)) {
    fail(code, `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function canonicalInstanceId(value) {
  if (typeof value !== 'string' || !INSTANCE_ID_PATTERN.test(value)) {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  let decoded;
  try {
    decoded = Buffer.from(value, 'base64url');
  } catch {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  if (decoded.length !== 16 || decoded.toString('base64url') !== value) {
    fail('AGENT_INSTANCE_ID', 'agent instance ID must be one canonical 16-byte identifier');
  }
  return value;
}

function canonicalIdentityText(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    fail('AGENT_IDENTITY', `${label} must be canonical nonzero decimal text`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0 || String(parsed) !== value) {
    fail('AGENT_IDENTITY', `${label} must round-trip through one safe integer`);
  }
  return Object.freeze({ text: value, value: parsed });
}

function positiveSafeIdentity(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail('AGENT_IDENTITY', `${label} must be one positive safe integer`);
  }
  return value;
}

function validateDescriptor(value) {
  const descriptor = exactRecord(value, [
    'schemaVersion',
    'agentInstanceId',
    'credentialDigest',
    'agentUid',
    'agentGid',
  ], [], 'AGENT_DESCRIPTOR_SCHEMA', 'agent enrollment descriptor');
  if (descriptor.schemaVersion !== 1) {
    fail('AGENT_DESCRIPTOR_VERSION', 'agent descriptor schemaVersion must equal 1');
  }
  const agentUid = canonicalIdentityText(descriptor.agentUid, 'agent UID');
  const agentGid = canonicalIdentityText(descriptor.agentGid, 'agent GID');
  return Object.freeze({
    schemaVersion: 1,
    agentInstanceId: canonicalInstanceId(descriptor.agentInstanceId),
    credentialDigest: canonicalHash(
      descriptor.credentialDigest,
      'agent credential digest',
      'AGENT_CREDENTIAL_DIGEST',
    ),
    agentUid: agentUid.text,
    agentGid: agentGid.text,
  });
}

function rowToEnrollment(row) {
  if (!row) return null;
  try {
    const descriptor = validateDescriptor({
      schemaVersion: 1,
      agentInstanceId: row.agent_instance_id,
      credentialDigest: row.credential_digest,
      agentUid: row.agent_uid,
      agentGid: row.agent_gid,
    });
    const enrollmentHash = canonicalHash(row.enrollment_hash, 'persisted enrollment hash');
    if (sha256(canonicalJson(descriptor)) !== enrollmentHash) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment hash changed');
    }
    const enrolledByOperatorHash = canonicalHash(
      row.enrolled_by_operator_hash,
      'persisted enrollment operator hash',
    );
    const enrolledAt = canonicalTimestamp(row.enrolled_at, 'persisted enrollment timestamp');
    const active = row.state === 'active';
    const revoked = row.state === 'revoked';
    if ((!active && !revoked)
        || (active && (row.revoked_by_operator_hash !== null || row.revoked_at !== null))
        || (revoked && (row.revoked_by_operator_hash === null || row.revoked_at === null))) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment lifecycle is invalid');
    }
    const revokedByOperatorHash = active
      ? null
      : canonicalHash(row.revoked_by_operator_hash, 'persisted revocation operator hash');
    const revokedAt = active
      ? null
      : canonicalTimestamp(row.revoked_at, 'persisted revocation timestamp');
    if (revokedAt !== null && Date.parse(revokedAt) < Date.parse(enrolledAt)) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted revocation predates enrollment');
    }
    return frozenCopy({
      agentInstanceId: descriptor.agentInstanceId,
      credentialDigest: descriptor.credentialDigest,
      enrollmentHash,
      agentUid: descriptor.agentUid,
      agentGid: descriptor.agentGid,
      state: row.state,
      enrolledByOperatorHash,
      enrolledAt,
      revokedByOperatorHash,
      revokedAt,
    });
  } catch (error) {
    if (error instanceof KernelError && error.code !== 'AGENT_ENROLLMENT_CORRUPTION') {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'persisted enrollment row is invalid');
    }
    throw error;
  }
}

function enrollmentIsolation(enrollment, eventRows) {
  if (!enrollment) return null;
  if (eventRows.length !== 1) {
    fail('AGENT_ENROLLMENT_CORRUPTION', 'enrollment must have exactly one creation event');
  }
  let data;
  try {
    data = JSON.parse(eventRows[0].data_json);
    data = exactRecord(data, [
      'enrollmentHash',
      'credentialDigest',
      'agentUid',
      'agentGid',
      'operatorIdHash',
      'isolation',
      'enrolledAt',
    ], [], 'AGENT_ENROLLMENT_CORRUPTION', 'enrollment creation event');
    if (canonicalJson(data) !== eventRows[0].data_json
        || canonicalHash(data.enrollmentHash, 'event enrollment hash')
          !== enrollment.enrollmentHash
        || canonicalHash(data.credentialDigest, 'event credential digest')
          !== enrollment.credentialDigest
        || canonicalIdentityText(data.agentUid, 'event agent UID').text !== enrollment.agentUid
        || canonicalIdentityText(data.agentGid, 'event agent GID').text !== enrollment.agentGid
        || canonicalHash(data.operatorIdHash, 'event operator hash')
          !== enrollment.enrolledByOperatorHash
        || canonicalTimestamp(data.enrolledAt, 'event enrolledAt') !== enrollment.enrolledAt
        || (data.isolation !== 'simulated' && data.isolation !== 'pending_verification')) {
      fail('AGENT_ENROLLMENT_CORRUPTION', 'enrollment creation event changed');
    }
  } catch (error) {
    if (error instanceof KernelError && error.code === 'AGENT_ENROLLMENT_CORRUPTION') throw error;
    fail('AGENT_ENROLLMENT_CORRUPTION', 'enrollment isolation label changed');
  }
  return data.isolation;
}

function withIsolation(enrollment, isolation) {
  if (!enrollment) return null;
  return frozenCopy({ ...enrollment, isolation });
}

export function createAgentEnrollmentRepository({ store, now }) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('agent enrollment repository requires a Wallet Kernel store');
  }
  if (typeof now !== 'function') throw new TypeError('agent enrollment repository requires a clock');

  const get = (agentInstanceId) => {
    const canonicalId = canonicalInstanceId(agentInstanceId);
    const enrollment = rowToEnrollment(store.readOne(
      'SELECT * FROM agent_enrollments WHERE agent_instance_id = ?',
      [canonicalId],
    ));
    if (!enrollment) return null;
    const eventRows = store.readAll(`SELECT data_json FROM events
      WHERE entity_type = ? AND entity_id = ? AND event_type = ?
      ORDER BY sequence`, ['agent_enrollment', canonicalId, 'agent.enrolled']);
    return withIsolation(enrollment, enrollmentIsolation(enrollment, eventRows));
  };

  const active = () => store.transaction((token) => store.within(token, ({ db }) => {
    const rows = db.prepare("SELECT * FROM agent_enrollments WHERE state = 'active'").all();
    if (rows.length > 1) fail('AGENT_ENROLLMENT_AMBIGUOUS', 'multiple active enrollments exist');
    const enrollment = rowToEnrollment(rows[0]);
    const currentAttestations = db.prepare(
      "SELECT enrollment_hash FROM isolation_attestations WHERE state = 'current'",
    ).all();
    if (currentAttestations.length > 1
        || currentAttestations.some((row) => row.enrollment_hash !== enrollment?.enrollmentHash)) {
      fail(
        'AGENT_ENROLLMENT_CORRUPTION',
        'current isolation attestation is not bound to the active enrollment',
      );
    }
    if (!enrollment) return null;
    const eventRows = db.prepare(`SELECT data_json FROM events
      WHERE entity_type = ? AND entity_id = ? AND event_type = ?
      ORDER BY sequence`).all(
      'agent_enrollment',
      enrollment.agentInstanceId,
      'agent.enrolled',
    );
    return withIsolation(enrollment, enrollmentIsolation(enrollment, eventRows));
  }));

  const enroll = (input) => {
    const record = exactRecord(input, [
      'descriptor',
      'expectedDescriptorHash',
      'operatorIdHash',
      'mode',
      'kernelUid',
      'kernelGid',
      'expectedAgentUid',
      'expectedAgentGid',
    ], [], 'AGENT_ENROLLMENT_SCHEMA', 'agent enrollment');
    const descriptor = validateDescriptor(record.descriptor);
    const expectedDescriptorHash = canonicalHash(
      record.expectedDescriptorHash,
      'expected descriptor hash',
      'AGENT_DESCRIPTOR_HASH',
    );
    const enrollmentHash = sha256(canonicalJson(descriptor));
    if (enrollmentHash !== expectedDescriptorHash) {
      fail('AGENT_DESCRIPTOR_HASH', 'agent descriptor hash does not match canonical descriptor');
    }
    const operatorIdHash = canonicalHash(record.operatorIdHash, 'operator ID hash');
    if (record.mode !== 'cdp-testnet' && record.mode !== 'deterministic') {
      fail('AGENT_ENROLLMENT_MODE', 'agent enrollment mode is invalid');
    }
    const kernelUid = positiveSafeIdentity(record.kernelUid, 'kernel UID');
    const kernelGid = positiveSafeIdentity(record.kernelGid, 'kernel GID');
    const expectedAgentUid = positiveSafeIdentity(record.expectedAgentUid, 'expected agent UID');
    const expectedAgentGid = positiveSafeIdentity(record.expectedAgentGid, 'expected agent GID');
    if (Number(descriptor.agentUid) !== expectedAgentUid
        || Number(descriptor.agentGid) !== expectedAgentGid) {
      fail('AGENT_IDENTITY_MISMATCH', 'descriptor identity differs from configured agent identity');
    }
    const agentUid = Number(descriptor.agentUid);
    const agentGid = Number(descriptor.agentGid);
    if (record.mode === 'cdp-testnet' && agentUid === kernelUid) {
      fail('AGENT_IDENTITY_NOT_ISOLATED', 'live agent UID must differ from kernel UID');
    }
    if (record.mode === 'deterministic'
        && (agentUid !== kernelUid || agentGid !== kernelGid)) {
      fail(
        'AGENT_DETERMINISTIC_FIXTURE',
        'deterministic enrollment requires one explicit same-identity fixture',
      );
    }
    const isolation = record.mode === 'deterministic' ? 'simulated' : 'pending_verification';

    return store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
      const existingRows = db.prepare('SELECT * FROM agent_enrollments ORDER BY rowid')
        .all().map(rowToEnrollment);
      const currentAttestations = db.prepare(`SELECT * FROM isolation_attestations
        WHERE state = 'current' ORDER BY id`).all();
      if (currentAttestations.length > 1) {
        fail('AGENT_ENROLLMENT_CORRUPTION', 'multiple current isolation attestations exist');
      }
      const activeEnrollment = existingRows.find((row) => row.state === 'active') ?? null;
      if (currentAttestations.some(
        (row) => row.enrollment_hash !== activeEnrollment?.enrollmentHash,
      )) {
        fail(
          'AGENT_ENROLLMENT_CORRUPTION',
          'current isolation attestation is not bound to the active enrollment',
        );
      }
      const exact = existingRows.find((row) => row.agentInstanceId === descriptor.agentInstanceId
        && row.credentialDigest === descriptor.credentialDigest
        && row.enrollmentHash === enrollmentHash
        && row.agentUid === descriptor.agentUid
        && row.agentGid === descriptor.agentGid
        && row.state === 'active');
      if (exact) {
        const eventRows = db.prepare(`SELECT data_json FROM events
          WHERE entity_type = ? AND entity_id = ? AND event_type = ?
          ORDER BY sequence`).all(
          'agent_enrollment',
          exact.agentInstanceId,
          'agent.enrolled',
        );
        const persistedIsolation = enrollmentIsolation(exact, eventRows);
        if (persistedIsolation !== isolation) {
          fail(
            'AGENT_ENROLLMENT_CONFLICT',
            'an enrollment cannot change its persisted isolation classification',
          );
        }
        return withIsolation(exact, persistedIsolation);
      }
      if (existingRows.some((row) => row.state === 'active')) {
        fail('AGENT_ENROLLMENT_CONFLICT', 'a different active agent enrollment already exists');
      }
      const historicalSame = existingRows.find((row) => row.agentInstanceId
          === descriptor.agentInstanceId
        || row.credentialDigest === descriptor.credentialDigest
        || row.enrollmentHash === enrollmentHash);
      if (historicalSame?.state === 'revoked'
          && historicalSame.agentInstanceId === descriptor.agentInstanceId
          && historicalSame.credentialDigest === descriptor.credentialDigest
          && historicalSame.enrollmentHash === enrollmentHash) {
        fail('AGENT_REVOKED', 'a revoked enrollment epoch cannot be reactivated');
      }
      if (historicalSame) {
        fail('AGENT_ENROLLMENT_CONFLICT', 'enrollment identity reuses historical authority');
      }
      const revokedBindings = db.prepare(`SELECT agent_session_bindings.session_id,
          agent_session_bindings.state AS binding_state,
          agent_session_bindings.closed_at AS binding_closed_at,
          spend_sessions.state AS session_state,
          spend_sessions.closed_at AS session_closed_at
        FROM agent_session_bindings
        JOIN agent_enrollments
          ON agent_enrollments.enrollment_hash = agent_session_bindings.enrollment_hash
        JOIN spend_sessions
          ON spend_sessions.id = agent_session_bindings.session_id
        WHERE agent_enrollments.state = 'revoked'
        ORDER BY agent_session_bindings.session_id`).all();
      for (const binding of revokedBindings) {
        const bindingClosed = binding.binding_state === 'closed';
        const sessionClosed = binding.session_state === 'closed';
        if (bindingClosed !== sessionClosed) {
          fail('AGENT_ENROLLMENT_CORRUPTION', 'revoked session and binding state disagree');
        }
        if (!bindingClosed) {
          fail(
            'AGENT_ENROLLMENT_BOUND',
            'replacement enrollment requires every revoked binding to be safely closed',
          );
        }
        let bindingClosedAt;
        let sessionClosedAt;
        try {
          bindingClosedAt = canonicalTimestamp(
            binding.binding_closed_at,
            'binding closedAt',
          );
          sessionClosedAt = canonicalTimestamp(binding.session_closed_at, 'session closedAt');
        } catch {
          fail('AGENT_ENROLLMENT_CORRUPTION', 'closed authority pair has invalid timestamps');
        }
        if (bindingClosedAt !== sessionClosedAt) {
          fail('AGENT_ENROLLMENT_CORRUPTION', 'closed authority pair timestamps disagree');
        }
      }
      const enrolledAt = canonicalTimestamp(now(), 'agent enrolledAt');
      db.prepare(`INSERT INTO agent_enrollments
        (agent_instance_id, credential_digest, enrollment_hash, agent_uid, agent_gid,
         state, enrolled_by_operator_hash, enrolled_at)
        VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`).run(
        descriptor.agentInstanceId,
        descriptor.credentialDigest,
        enrollmentHash,
        descriptor.agentUid,
        descriptor.agentGid,
        operatorIdHash,
        enrolledAt,
      );
      appendEvent({
        entityType: 'agent_enrollment',
        entityId: descriptor.agentInstanceId,
        eventType: 'agent.enrolled',
        data: {
          enrollmentHash,
          credentialDigest: descriptor.credentialDigest,
          agentUid: descriptor.agentUid,
          agentGid: descriptor.agentGid,
          operatorIdHash,
          isolation,
          enrolledAt,
        },
      });
      return withIsolation(rowToEnrollment(db.prepare(
        'SELECT * FROM agent_enrollments WHERE agent_instance_id = ?',
      ).get(descriptor.agentInstanceId)), isolation);
    }));
  };

  const revoke = (input) => {
    const record = exactRecord(input, [
      'agentInstanceId',
      'expectedEnrollmentHash',
      'operatorIdHash',
    ], [], 'AGENT_REVOCATION_SCHEMA', 'agent revocation');
    const agentInstanceId = canonicalInstanceId(record.agentInstanceId);
    const expectedEnrollmentHash = canonicalHash(
      record.expectedEnrollmentHash,
      'expected enrollment hash',
      'AGENT_ENROLLMENT_STALE',
    );
    const operatorIdHash = canonicalHash(record.operatorIdHash, 'operator ID hash');

    return store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
      const current = rowToEnrollment(db.prepare(
        'SELECT * FROM agent_enrollments WHERE agent_instance_id = ?',
      ).get(agentInstanceId));
      if (!current || current.state !== 'active') {
        fail('AGENT_REVOKED', 'agent enrollment is not active');
      }
      if (current.enrollmentHash !== expectedEnrollmentHash) {
        fail('AGENT_ENROLLMENT_STALE', 'active enrollment hash differs from confirmation');
      }
      const attestations = db.prepare(`SELECT * FROM isolation_attestations
        WHERE state = 'current' ORDER BY id`).all();
      if (attestations.length > 1
          || attestations.some((attestation) => attestation.enrollment_hash
            !== expectedEnrollmentHash)) {
        fail(
          'AGENT_ENROLLMENT_CORRUPTION',
          'current isolation attestation is not unique for the active enrollment',
        );
      }
      for (const attestation of attestations) {
        try {
          canonicalToken(attestation.id, 'isolation attestation ID');
          canonicalHash(attestation.report_hash, 'isolation report hash');
          canonicalHash(attestation.imported_by_operator_hash, 'attestation operator hash');
          canonicalTimestamp(attestation.probed_at, 'attestation probedAt');
          canonicalTimestamp(attestation.expires_at, 'attestation expiresAt');
          canonicalTimestamp(attestation.imported_at, 'attestation importedAt');
          const report = JSON.parse(attestation.report_json);
          if (canonicalJson(report) !== attestation.report_json
              || attestation.superseded_at !== null) {
            fail('AGENT_ENROLLMENT_CORRUPTION', 'current isolation attestation is invalid');
          }
        } catch (error) {
          if (error instanceof KernelError && error.code === 'AGENT_ENROLLMENT_CORRUPTION') {
            throw error;
          }
          fail('AGENT_ENROLLMENT_CORRUPTION', 'current isolation attestation is invalid');
        }
      }
      const boundSessionIds = db.prepare(`SELECT session_id
        FROM agent_session_bindings
        WHERE enrollment_hash = ? AND state = 'open'
        ORDER BY session_id`).all(expectedEnrollmentHash).map((row) => row.session_id);
      const revokedAt = canonicalTimestamp(now(), 'agent revokedAt');
      if (Date.parse(revokedAt) < Date.parse(current.enrolledAt)) {
        fail('AGENT_ENROLLMENT_TIME', 'agent revocation cannot predate enrollment');
      }
      const update = db.prepare(`UPDATE agent_enrollments
        SET state = 'revoked', revoked_by_operator_hash = ?, revoked_at = ?
        WHERE agent_instance_id = ? AND enrollment_hash = ? AND state = 'active'`).run(
        operatorIdHash,
        revokedAt,
        agentInstanceId,
        expectedEnrollmentHash,
      );
      if (update.changes !== 1n) {
        fail('AGENT_ENROLLMENT_STALE', 'active enrollment changed during revocation');
      }
      for (const attestation of attestations) {
        const superseded = db.prepare(`UPDATE isolation_attestations
          SET state = 'superseded', superseded_at = ?
          WHERE id = ? AND enrollment_hash = ? AND state = 'current'`).run(
          revokedAt,
          attestation.id,
          expectedEnrollmentHash,
        );
        if (superseded.changes !== 1n) {
          fail('AGENT_ENROLLMENT_CORRUPTION', 'isolation attestation changed during revocation');
        }
        appendEvent({
          entityType: 'isolation_attestation',
          entityId: attestation.id,
          eventType: 'isolation.attestation_superseded',
          data: {
            enrollmentHash: expectedEnrollmentHash,
            reportHash: attestation.report_hash,
            supersededAt: revokedAt,
            reasonCode: 'AGENT_REVOKED',
          },
        });
      }
      appendEvent({
        entityType: 'agent_enrollment',
        entityId: agentInstanceId,
        eventType: 'agent.revoked',
        data: {
          enrollmentHash: expectedEnrollmentHash,
          operatorIdHash,
          boundSessionIds,
          revokedAt,
        },
      });
      const revoked = rowToEnrollment(db.prepare(
        'SELECT * FROM agent_enrollments WHERE agent_instance_id = ?',
      ).get(agentInstanceId));
      const creationEvents = db.prepare(`SELECT data_json FROM events
        WHERE entity_type = ? AND entity_id = ? AND event_type = ?
        ORDER BY sequence`).all('agent_enrollment', agentInstanceId, 'agent.enrolled');
      return frozenCopy({
        enrollment: withIsolation(revoked, enrollmentIsolation(revoked, creationEvents)),
        boundSessionIds,
      });
    }));
  };

  return Object.freeze({ enroll, active, get, revoke });
}

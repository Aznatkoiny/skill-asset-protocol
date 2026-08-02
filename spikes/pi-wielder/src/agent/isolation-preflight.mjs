import {
  canonicalJson,
  canonicalTimestamp,
  canonicalToken,
  exactRecord,
  frozenCopy,
  KernelError,
  sha256,
} from '../kernel/canonical.mjs';

const HASH = /^sha256:[0-9a-f]{64}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]*$/;
const REPORT_MAXIMUM_BYTES = 16 * 1024;
const METADATA_DOMAIN = 'wallet-kernel/isolation-metadata/v1\0';
const PROBE_RESULTS = Object.freeze({
  authorityDirectory: 'EACCES',
  database: 'EACCES',
  operatorToken: 'EACCES',
  receiptKey: 'EACCES',
  kernelEnvironment: 'EACCES',
  agentCredential: 'READABLE',
  releaseTreeWrite: 'EACCES',
  dependencyTreeWrite: 'EACCES',
  serviceArtifactsWrite: 'EACCES',
  kernelEnvironmentParentWrite: 'EACCES',
});
const REPORT_FIELDS = Object.freeze([
  'schemaVersion', 'enrollmentHash', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid',
  'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
  'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
  'systemdEffectiveConfigHash', 'environmentMetadataHash', 'probeResults',
  'probedAt', 'expiresAt',
]);

function fail(code, message, cause) {
  throw new KernelError(code, message, cause ? { cause } : undefined);
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) {
    fail('ISOLATION_SCHEMA', `${label} must be one canonical SHA-256 hash`);
  }
  return value;
}

function numericIdentity(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail('ISOLATION_IDENTITY', `${label} must be one nonzero safe integer`);
  }
  return value;
}

function identityText(value, label) {
  if (typeof value !== 'string' || !POSITIVE_DECIMAL.test(value)) {
    fail('ISOLATION_IDENTITY', `${label} must be canonical nonzero decimal text`);
  }
  const numeric = Number(value);
  if (!Number.isSafeInteger(numeric) || String(numeric) !== value) {
    fail('ISOLATION_IDENTITY', `${label} must round-trip through one safe integer`);
  }
  return value;
}

function validateProjection(value, label, expectedUid, expectedDirectoryMode, expectedLeafMode) {
  const metadata = exactRecord(value, ['role', 'chain', 'leaf'], [],
    'ISOLATION_METADATA', `${label} metadata`);
  if (typeof metadata.role !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(metadata.role)
      || !Array.isArray(metadata.chain) || metadata.chain.length < 1 || metadata.chain.length > 64) {
    fail('ISOLATION_METADATA', `${label} metadata has an invalid role or chain`);
  }
  const parseItem = (item, itemLabel, depth, mode) => {
    const projection = exactRecord(item, [
      'role', 'depth', 'device', 'inode', 'uid', 'gid', 'mode',
    ], [], 'ISOLATION_METADATA', itemLabel);
    if (typeof projection.role !== 'string' || !/^[a-z][a-z-]{0,63}$/.test(projection.role)
        || projection.depth !== depth
        || typeof projection.device !== 'string' || !/^(0|[1-9][0-9]*)$/.test(projection.device)
        || typeof projection.inode !== 'string' || !/^[1-9][0-9]*$/.test(projection.inode)
        || projection.uid !== expectedUid || !Number.isSafeInteger(projection.gid)
        || projection.gid < 0 || projection.mode !== mode) {
      fail('ISOLATION_METADATA', `${itemLabel} ownership, order, or mode is invalid`);
    }
    return projection;
  };
  const chain = metadata.chain.map((item, index) => parseItem(
    item, `${label} ancestor`, index, expectedDirectoryMode,
  ));
  const leaf = parseItem(metadata.leaf, `${label} leaf`, chain.length, expectedLeafMode);
  return Object.freeze({ role: metadata.role, chain, leaf });
}

export function hashIsolationMetadata(value) {
  const metadata = exactRecord(value, ['role', 'chain', 'leaf'], [],
    'ISOLATION_METADATA', 'isolation metadata');
  return sha256(`${METADATA_DOMAIN}${canonicalJson(metadata)}`);
}

export function validateIsolationMetadata(value) {
  const input = exactRecord(value, [
    'kernelUid', 'kernelGid', 'agentUid', 'agentGid', 'authority', 'credential',
    'authorityInsideCredential', 'credentialInsideAuthority',
  ], [], 'ISOLATION_METADATA', 'isolation metadata input');
  const kernelUid = numericIdentity(input.kernelUid, 'Kernel UID');
  numericIdentity(input.kernelGid, 'Kernel GID');
  const agentUid = numericIdentity(input.agentUid, 'Agent UID');
  numericIdentity(input.agentGid, 'Agent GID');
  if (kernelUid === agentUid) fail('ISOLATION_IDENTITY', 'Kernel and Agent UIDs must be distinct');
  if (input.authorityInsideCredential !== false || input.credentialInsideAuthority !== false) {
    fail('ISOLATION_PATH_OVERLAP', 'authority and credential trees must be disjoint');
  }
  const authority = validateProjection(input.authority, 'authority', kernelUid, 0o700, 0o600);
  const credential = validateProjection(input.credential, 'credential', agentUid, 0o700, 0o600);
  const authorityNodes = new Set([
    ...authority.chain.map((item) => `${item.device}:${item.inode}`),
    `${authority.leaf.device}:${authority.leaf.inode}`,
  ]);
  if ([...credential.chain, credential.leaf]
    .some((item) => authorityNodes.has(`${item.device}:${item.inode}`))) {
    fail('ISOLATION_PATH_OVERLAP', 'authority and credential metadata share an inode');
  }
  return Object.freeze({
    kernelUid, kernelGid: input.kernelGid, agentUid, agentGid: input.agentGid,
    authorityMetadataHash: hashIsolationMetadata(authority),
    credentialMetadataHash: hashIsolationMetadata(credential),
  });
}

function validateReport(value) {
  const report = exactRecord(value, REPORT_FIELDS, [],
    'ISOLATION_SCHEMA', 'isolation report');
  if (report.schemaVersion !== 1) fail('ISOLATION_SCHEMA', 'isolation report schemaVersion must equal 1');
  canonicalHash(report.enrollmentHash, 'enrollment hash');
  for (const field of ['kernelUid', 'kernelGid', 'agentUid', 'agentGid']) {
    identityText(report[field], field);
  }
  if (report.kernelUid === report.agentUid) {
    fail('ISOLATION_IDENTITY', 'Kernel and Agent UIDs must be distinct');
  }
  for (const field of [
    'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
    'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash', 'environmentMetadataHash',
  ]) canonicalHash(report[field], field);
  const probes = exactRecord(report.probeResults, Object.keys(PROBE_RESULTS), [],
    'ISOLATION_SCHEMA', 'isolation probe results');
  for (const [name, expected] of Object.entries(PROBE_RESULTS)) {
    if (probes[name] !== expected) {
      fail('ISOLATION_PROBE_FAILED', `isolation probe ${name} did not prove the required result`);
    }
  }
  canonicalTimestamp(report.probedAt, 'isolation probedAt');
  canonicalTimestamp(report.expiresAt, 'isolation expiresAt');
  const interval = Date.parse(report.expiresAt) - Date.parse(report.probedAt);
  if (interval <= 0 || interval > 15 * 60 * 1000) {
    fail('ISOLATION_TIME', 'isolation report interval must be positive and at most 15 minutes');
  }
  return frozenCopy({ ...report, probeResults: probes });
}

export function validateIsolationReportBytes(bytes, options = {}) {
  if (!Buffer.isBuffer(bytes) && !(bytes instanceof Uint8Array)) {
    fail('ISOLATION_BYTES', 'isolation report must be supplied as bytes');
  }
  const copy = Buffer.from(bytes);
  if (copy.length < 3 || copy.length > REPORT_MAXIMUM_BYTES || copy.at(-1) !== 0x0a
      || copy.subarray(0, -1).includes(0x0a) || copy.includes(0x00)) {
    fail('ISOLATION_BYTES', 'isolation report bytes are not bounded canonical JSON plus newline');
  }
  let parsed;
  try {
    parsed = JSON.parse(copy.subarray(0, -1).toString('utf8'));
  } catch (cause) {
    fail('ISOLATION_BYTES', 'isolation report is not valid UTF-8 JSON', cause);
  }
  const report = validateReport(parsed);
  const canonical = canonicalJson(report);
  if (!copy.equals(Buffer.from(`${canonical}\n`, 'utf8'))) {
    fail('ISOLATION_BYTES', 'isolation report is not canonical JSON plus one newline');
  }
  const reportHash = sha256(canonical);
  if (options.expectedReportHash !== undefined
      && canonicalHash(options.expectedReportHash, 'expected report hash') !== reportHash) {
    fail('ISOLATION_HASH_MISMATCH', 'isolation report hash does not match the confirmation');
  }
  const bindings = [
    ['expectedEnrollmentHash', 'enrollmentHash'],
    ['expectedKernelUid', 'kernelUid'],
    ['expectedKernelGid', 'kernelGid'],
    ['expectedReleaseManifestHash', 'releaseManifestHash'],
    ['expectedAuthorityMetadataHash', 'authorityMetadataHash'],
  ];
  for (const [option, field] of bindings) {
    if (options[option] !== undefined && options[option] !== report[field]) {
      fail('ISOLATION_BINDING_MISMATCH', `isolation report ${field} does not match the expected binding`);
    }
  }
  if (typeof options.now === 'function') {
    const now = canonicalTimestamp(options.now(), 'isolation validation time');
    if (Date.parse(now) < Date.parse(report.probedAt)) {
      fail('ISOLATION_TIME', 'isolation report is not valid before probedAt');
    }
    if (Date.parse(now) >= Date.parse(report.expiresAt)) {
      fail('ISOLATION_EXPIRED', 'isolation report is expired');
    }
  }
  return Object.freeze({ report, reportHash });
}

function attestationResult(row) {
  return frozenCopy({
    id: row.id,
    reportHash: row.report_hash,
    enrollmentHash: row.enrollment_hash,
    authorityMetadataHash: JSON.parse(row.report_json).authorityMetadataHash,
    releaseManifestHash: JSON.parse(row.report_json).releaseManifestHash,
    probedAt: row.probed_at,
    expiresAt: row.expires_at,
    importedAt: row.imported_at,
    state: row.state,
  });
}

export function createIsolationAttestationRepository({ store, now, idFactory }) {
  if (!store || typeof store.transaction !== 'function' || typeof store.within !== 'function') {
    throw new TypeError('isolation attestation repository requires a Wallet Kernel store');
  }
  if (typeof now !== 'function' || typeof idFactory !== 'function') {
    throw new TypeError('isolation attestation repository requires clock and ID dependencies');
  }

  const importCurrent = ({ reportBytes, expectedReportHash, operatorIdHash }) => {
    const importedAt = canonicalTimestamp(now(), 'isolation import time');
    canonicalHash(operatorIdHash, 'operator identity hash');
    const { report, reportHash } = validateIsolationReportBytes(reportBytes, {
      expectedReportHash,
      now: () => importedAt,
    });
    return store.transaction((token) => store.within(token, ({ db, appendEvent }) => {
      const active = db.prepare("SELECT * FROM agent_enrollments WHERE state = 'active'").all();
      if (active.length !== 1) {
        fail('ISOLATION_ENROLLMENT', 'isolation import requires exactly one active enrollment');
      }
      const enrollment = active[0];
      if (report.enrollmentHash !== enrollment.enrollment_hash
          || report.agentUid !== enrollment.agent_uid
          || report.agentGid !== enrollment.agent_gid) {
        fail('ISOLATION_ENROLLMENT', 'isolation report does not match the active enrollment');
      }
      const replay = db.prepare('SELECT * FROM isolation_attestations WHERE report_hash = ?')
        .get(reportHash);
      if (replay) {
        if (replay.state !== 'current' || replay.enrollment_hash !== report.enrollmentHash
            || replay.imported_by_operator_hash !== operatorIdHash
            || replay.report_json !== canonicalJson(report)) {
          fail('ISOLATION_REPLAY_CONFLICT', 'isolation report replay conflicts with stored authority');
        }
        return attestationResult(replay);
      }
      const currentRows = db.prepare("SELECT * FROM isolation_attestations WHERE state = 'current'").all();
      if (currentRows.length > 1) fail('ISOLATION_CORRUPTION', 'multiple current isolation attestations exist');
      for (const previous of currentRows) {
        const update = db.prepare(`UPDATE isolation_attestations
          SET state = 'superseded', superseded_at = ? WHERE id = ? AND state = 'current'`)
          .run(importedAt, previous.id);
        if (update.changes !== 1n) fail('ISOLATION_STALE', 'current isolation attestation changed');
        appendEvent({
          entityType: 'isolation_attestation', entityId: previous.id,
          eventType: 'isolation.attestation_superseded',
          data: {
            enrollmentHash: previous.enrollment_hash,
            reportHash: previous.report_hash,
            supersededAt: importedAt,
            reasonCode: 'ATTESTATION_REPLACED',
          },
        });
      }
      const id = canonicalToken(idFactory(), 'isolation attestation ID');
      db.prepare(`INSERT INTO isolation_attestations
        (id, report_hash, enrollment_hash, report_json, state, imported_by_operator_hash,
         probed_at, expires_at, imported_at, superseded_at)
        VALUES (?, ?, ?, ?, 'current', ?, ?, ?, ?, NULL)`).run(
        id, reportHash, report.enrollmentHash, canonicalJson(report), operatorIdHash,
        report.probedAt, report.expiresAt, importedAt,
      );
      appendEvent({
        entityType: 'isolation_attestation', entityId: id,
        eventType: 'isolation.attestation_imported',
        data: {
          reportHash,
          enrollmentHash: report.enrollmentHash,
          authorityMetadataHash: report.authorityMetadataHash,
          releaseManifestHash: report.releaseManifestHash,
          operatorIdHash,
          probedAt: report.probedAt,
          expiresAt: report.expiresAt,
          importedAt,
        },
      });
      return attestationResult(db.prepare('SELECT * FROM isolation_attestations WHERE id = ?').get(id));
    }));
  };

  const currentFor = ({
    enrollmentHash, authorityMetadataHash, releaseManifestHash, expectedReportHash,
  }) => {
    canonicalHash(enrollmentHash, 'enrollment hash');
    canonicalHash(authorityMetadataHash, 'authority metadata hash');
    canonicalHash(releaseManifestHash, 'release manifest hash');
    canonicalHash(expectedReportHash, 'expected report hash');
    const readAt = canonicalTimestamp(now(), 'isolation read time');
    return store.transaction((token) => store.within(token, ({ db }) => {
      const rows = db.prepare("SELECT * FROM isolation_attestations WHERE state = 'current'").all();
      if (rows.length > 1) fail('ISOLATION_CORRUPTION', 'multiple current isolation attestations exist');
      if (rows.length === 0) return null;
      const row = rows[0];
      let report;
      try {
        report = validateReport(JSON.parse(row.report_json));
      } catch (cause) {
        fail('ISOLATION_CORRUPTION', 'stored isolation report is invalid', cause);
      }
      if (canonicalJson(report) !== row.report_json || sha256(row.report_json) !== row.report_hash
          || report.enrollmentHash !== row.enrollment_hash
          || row.report_hash !== expectedReportHash
          || report.enrollmentHash !== enrollmentHash
          || report.authorityMetadataHash !== authorityMetadataHash
          || report.releaseManifestHash !== releaseManifestHash
          || Date.parse(readAt) < Date.parse(report.probedAt)
          || Date.parse(readAt) >= Date.parse(report.expiresAt)) {
        return null;
      }
      const active = db.prepare("SELECT enrollment_hash FROM agent_enrollments WHERE state = 'active'").all();
      if (active.length !== 1 || active[0].enrollment_hash !== enrollmentHash) return null;
      return attestationResult(row);
    }));
  };

  return Object.freeze({ importCurrent, currentFor });
}

export const REQUIRED_ISOLATION_PROBE_RESULTS = PROBE_RESULTS;

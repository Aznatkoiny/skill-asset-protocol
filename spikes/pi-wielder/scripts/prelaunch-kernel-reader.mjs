#!/usr/bin/env node
// This file intentionally has built-in-only static imports. Project code may be
// dynamically imported only after the numeric identity drop has been verified.
import crypto from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const HASH = /^sha256:[0-9a-f]{64}$/;
const POSITIVE = /^[1-9][0-9]*$/;
const ALLOWED_REQUEST_FIELDS = Object.freeze([
  'nonce', 'parentPid', 'kernelUid', 'kernelGid', 'releaseRoot',
  'releaseManifestHash', 'authorityMetadataHash', 'probeResults', 'databasePath',
  'pathTrust', 'isolationReportPath', 'now',
]);

function fail(message) { throw new Error(message); }

function identity(value, label) {
  if (typeof value !== 'string' || !POSITIVE.test(value)
      || !Number.isSafeInteger(Number(value)) || String(Number(value)) !== value) {
    fail(`${label} must be canonical positive decimal text`);
  }
  return Number(value);
}

export function parseReaderArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 4
      || argv[0] !== '--kernel-uid' || argv[2] !== '--kernel-gid') {
    fail('prelaunch reader arguments do not match the closed schema');
  }
  return Object.freeze({
    kernelUid: identity(argv[1], 'Kernel UID'),
    kernelGid: identity(argv[3], 'Kernel GID'),
  });
}

export function assertReaderEnvironment(environment) {
  const names = Reflect.ownKeys(environment);
  // NODE_CHANNEL_FD is created by Node for the one intentional IPC descriptor.
  if (names.some((name) => typeof name !== 'string' || name !== 'NODE_CHANNEL_FD')) {
    fail('prelaunch reader inherited an unrecognized environment field');
  }
}

export function dropToKernelIdentity({ uid, gid, processApi = process }) {
  if (!Number.isSafeInteger(uid) || uid <= 0 || !Number.isSafeInteger(gid) || gid <= 0) {
    fail('prelaunch reader target identity is invalid');
  }
  if (typeof processApi.setgroups !== 'function' || typeof processApi.setgid !== 'function'
      || typeof processApi.setuid !== 'function') fail('prelaunch reader requires POSIX identity controls');
  processApi.setgroups([]);
  processApi.setgid(gid);
  processApi.setuid(uid);
  const groups = processApi.getgroups();
  const supplementary = groups.filter((group) => group !== gid);
  if (processApi.getuid() !== uid || processApi.geteuid?.() !== uid
      || processApi.getgid() !== gid || processApi.getegid?.() !== gid
      || supplementary.length !== 0) {
    fail('prelaunch reader did not drop to the exact empty-group Kernel identity');
  }
  return Object.freeze({ uid, gid });
}

export function validateReaderRequest(value, { nonce, parentPid, uid, gid }) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.getPrototypeOf(value) !== Object.prototype
      || Reflect.ownKeys(value).length !== ALLOWED_REQUEST_FIELDS.length
      || ALLOWED_REQUEST_FIELDS.some((field) => !Object.hasOwn(value, field))) {
    fail('prelaunch reader request fields do not match the closed schema');
  }
  for (const field of ALLOWED_REQUEST_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, 'value')) {
      fail('prelaunch reader request must contain only enumerable data fields');
    }
  }
  if (value.nonce !== nonce || value.parentPid !== parentPid
      || value.kernelUid !== String(uid) || value.kernelGid !== String(gid)
      || typeof value.releaseRoot !== 'string' || !path.isAbsolute(value.releaseRoot)
      || !HASH.test(value.releaseManifestHash) || !HASH.test(value.authorityMetadataHash)
      || !value.probeResults || typeof value.probeResults !== 'object'
      || typeof value.databasePath !== 'string' || !path.isAbsolute(value.databasePath)
      || typeof value.isolationReportPath !== 'string' || !path.isAbsolute(value.isolationReportPath)
      || !value.pathTrust || typeof value.pathTrust !== 'object'
      || typeof value.now !== 'string' || new Date(value.now).toISOString() !== value.now) {
    fail('prelaunch reader request binding is invalid');
  }
  const forbidden = /(?:database|token|credential|secret|key|listener|descriptor|socket)/i;
  const visit = (item) => {
    if (!item || typeof item !== 'object') return;
    for (const [key, child] of Object.entries(item)) {
      if (forbidden.test(key)) fail('prelaunch reader request names forbidden authority or secret data');
      visit(child);
    }
  };
  visit(value.probeResults);
  return value;
}

async function auditAuthorityAfterDrop(request) {
  const [sqlite, lockModule, storage, isolation, canonical] = await Promise.all([
    import('node:sqlite'),
    import('../src/kernel/authority-lock.mjs'),
    import('../src/kernel/secure-storage.mjs'),
    import('../src/agent/isolation-preflight.mjs'),
    import('../src/kernel/canonical.mjs'),
  ]);
  const pathTrust = Object.freeze({ ...request.pathTrust });
  const authority = lockModule.acquireAuthorityLock({
    databasePath: request.databasePath, role: 'prelaunch', pathTrust,
  });
  let database;
  try {
    database = new sqlite.DatabaseSync(request.databasePath, { readOnly: true, readBigInts: true });
    database.exec('PRAGMA query_only = ON; PRAGMA foreign_keys = ON; PRAGMA trusted_schema = OFF;');
    const enrollments = database.prepare("SELECT * FROM agent_enrollments WHERE state = 'active'").all();
    const attestations = database.prepare(
      "SELECT * FROM isolation_attestations WHERE state = 'current'",
    ).all();
    if (enrollments.length > 1 || attestations.length > 1) {
      fail('prelaunch authority contains ambiguous active identity state');
    }
    if (enrollments.length === 0) {
      if (attestations.length !== 0) fail('prelaunch recovery state retains a current attestation');
      const data = { status: 'recovery_only', releaseManifestHash: request.releaseManifestHash,
        authorityMetadataHash: request.authorityMetadataHash };
      return Object.freeze({ ...data,
        preflightDigest: canonical.sha256(`wallet-kernel/prelaunch-result/v1\0${canonical.canonicalJson(data)}`) });
    }
    if (attestations.length !== 1) fail('active enrollment requires one current isolation attestation');
    const enrollment = enrollments[0];
    const row = attestations[0];
    const reportBytes = storage.readPrivateInputFile(
      request.isolationReportPath, 'Wallet Kernel isolation report',
      { maximumBytes: 16 * 1024, pathTrust },
    );
    let validated;
    try {
      validated = isolation.validateIsolationReportBytes(reportBytes, {
        expectedReportHash: row.report_hash,
        expectedEnrollmentHash: enrollment.enrollment_hash,
        expectedKernelUid: request.kernelUid,
        expectedKernelGid: request.kernelGid,
        expectedReleaseManifestHash: request.releaseManifestHash,
        expectedAuthorityMetadataHash: request.authorityMetadataHash,
        now: () => request.now,
      });
    } finally { reportBytes.fill(0); }
    if (row.enrollment_hash !== enrollment.enrollment_hash
        || row.report_json !== canonical.canonicalJson(validated.report)
        || row.probed_at !== validated.report.probedAt || row.expires_at !== validated.report.expiresAt
        || canonical.canonicalJson(validated.report.probeResults)
          !== canonical.canonicalJson(request.probeResults)) {
      fail('prelaunch isolation authority differs from the fresh privileged probe');
    }
    const data = {
      status: 'verified', enrollmentHash: enrollment.enrollment_hash,
      reportHash: row.report_hash, releaseManifestHash: request.releaseManifestHash,
      authorityMetadataHash: request.authorityMetadataHash,
    };
    return Object.freeze({ ...data,
      preflightDigest: canonical.sha256(`wallet-kernel/prelaunch-result/v1\0${canonical.canonicalJson(data)}`) });
  } finally {
    database?.close();
    authority.close();
  }
}

export async function runDroppedReader({ argv, environment, processApi = process, dynamicAudit }) {
  const { kernelUid, kernelGid } = parseReaderArguments(argv);
  assertReaderEnvironment(environment);
  dropToKernelIdentity({ uid: kernelUid, gid: kernelGid, processApi });
  if (typeof dynamicAudit !== 'function') fail('prelaunch reader requires a post-drop audit');
  return dynamicAudit();
}

async function direct() {
  const parsed = parseReaderArguments(process.argv.slice(2));
  assertReaderEnvironment(process.env);
  dropToKernelIdentity({ uid: parsed.kernelUid, gid: parsed.kernelGid });
  const nonce = crypto.randomBytes(32).toString('base64url');
  process.send?.({ type: 'ready', nonce, pid: process.pid });
  let handled = false;
  process.on('message', async (request) => {
    if (handled) process.exit(1);
    handled = true;
    try {
      validateReaderRequest(request, {
        nonce, parentPid: process.ppid, uid: parsed.kernelUid, gid: parsed.kernelGid,
      });
      const result = await auditAuthorityAfterDrop(request);
      process.send?.({ type: 'result', nonce, result });
      process.exit(0);
    } catch {
      process.send?.({ type: 'failed', nonce, code: 'PRELAUNCH_READER_FAILED' });
      process.exit(1);
    }
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  direct().catch(() => { process.exitCode = 1; });
}

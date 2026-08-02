#!/usr/bin/env node
import { fork } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, canonicalTimestamp, exactRecord, sha256 } from '../src/kernel/canonical.mjs';
import {
  REQUIRED_ISOLATION_PROBE_RESULTS,
  validateIsolationReportBytes,
} from '../src/agent/isolation-preflight.mjs';

const WORKER = fileURLToPath(new URL('./agent-isolation-probe-worker.mjs', import.meta.url));
const HASH = /^sha256:[0-9a-f]{64}$/;
const CONFIG_FIELDS = Object.freeze([
  'schemaVersion', 'enrollmentHash', 'kernelUid', 'kernelGid', 'agentUid', 'agentGid',
  'authorityMetadataHash', 'credentialMetadataHash', 'releaseManifestHash',
  'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
  'systemdEffectiveConfigHash', 'environmentMetadataHash', 'credentialPath',
  'protectedReadPaths', 'writePaths', 'reportPath',
]);

function positiveText(value, label) {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)
      || !Number.isSafeInteger(Number(value)) || String(Number(value)) !== value) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function hash(value, label) {
  if (typeof value !== 'string' || !HASH.test(value)) throw new Error(`${label} is invalid`);
  return value;
}

function validateConfig(value) {
  const config = exactRecord(value, CONFIG_FIELDS, [],
    'ISOLATION_PREFLIGHT_CONFIG', 'isolation preflight config');
  if (config.schemaVersion !== 1) throw new Error('isolation preflight schemaVersion must equal 1');
  for (const field of ['kernelUid', 'kernelGid', 'agentUid', 'agentGid']) positiveText(config[field], field);
  if (config.kernelUid === config.agentUid) throw new Error('Kernel and Agent UIDs must differ');
  for (const field of [
    'enrollmentHash', 'authorityMetadataHash', 'credentialMetadataHash',
    'releaseManifestHash', 'releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
    'systemdEffectiveConfigHash', 'environmentMetadataHash',
  ]) hash(config[field], field);
  for (const field of ['credentialPath', 'reportPath']) {
    if (typeof config[field] !== 'string' || !path.isAbsolute(config[field])
        || path.resolve(config[field]) !== config[field]) throw new Error(`${field} is invalid`);
  }
  return config;
}

export function buildIsolationReport({ config: value, probeResults, now }) {
  const config = validateConfig(value);
  const probes = exactRecord(probeResults, Object.keys(REQUIRED_ISOLATION_PROBE_RESULTS), [],
    'ISOLATION_PROBE_RESULTS', 'isolation probe results');
  for (const [name, expected] of Object.entries(REQUIRED_ISOLATION_PROBE_RESULTS)) {
    if (probes[name] !== expected) throw new Error(`isolation probe ${name} failed closed`);
  }
  const probedAt = canonicalTimestamp(now(), 'isolation probe time');
  const expiresAt = new Date(Date.parse(probedAt) + 15 * 60 * 1000).toISOString();
  const report = Object.freeze({
    schemaVersion: 1,
    enrollmentHash: config.enrollmentHash,
    kernelUid: config.kernelUid,
    kernelGid: config.kernelGid,
    agentUid: config.agentUid,
    agentGid: config.agentGid,
    authorityMetadataHash: config.authorityMetadataHash,
    credentialMetadataHash: config.credentialMetadataHash,
    releaseManifestHash: config.releaseManifestHash,
    releaseTreeHash: config.releaseTreeHash,
    nodeExecutableHash: config.nodeExecutableHash,
    serviceArtifactsHash: config.serviceArtifactsHash,
    systemdEffectiveConfigHash: config.systemdEffectiveConfigHash,
    environmentMetadataHash: config.environmentMetadataHash,
    probeResults: probes,
    probedAt,
    expiresAt,
  });
  const reportHash = sha256(canonicalJson(report));
  const reportBytes = Buffer.from(`${canonicalJson(report)}\n`);
  validateIsolationReportBytes(reportBytes, {
    expectedReportHash: reportHash,
    expectedEnrollmentHash: config.enrollmentHash,
    expectedKernelUid: config.kernelUid,
    expectedKernelGid: config.kernelGid,
    expectedReleaseManifestHash: config.releaseManifestHash,
    now: () => probedAt,
  });
  return Object.freeze({ report, reportHash, reportBytes });
}

function spawnProbe(config, spawnImpl = fork) {
  return new Promise((resolve, reject) => {
    const child = spawnImpl(WORKER, [
      '--agent-uid', config.agentUid, '--agent-gid', config.agentGid,
    ], { execPath: process.execPath, env: {}, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    let settled = false;
    let sent = false;
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('isolation probe worker timed out'));
    }, 15_000);
    const finish = (operation) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      operation();
    };
    child.on('error', (error) => finish(() => reject(error)));
    child.on('message', (message) => {
      if (message?.type === 'ready' && !sent) {
        sent = true;
        child.send({
          credentialPath: config.credentialPath,
          protectedReadPaths: config.protectedReadPaths,
          writePaths: config.writePaths,
        });
      } else if (message?.type === 'result' && sent) {
        finish(() => resolve(message.probeResults));
      } else if (message?.type === 'failed') {
        finish(() => reject(new Error('isolation probe worker failed')));
      }
    });
    child.on('exit', (code) => {
      if (!settled) finish(() => reject(new Error(`isolation probe worker exited ${code}`)));
    });
  });
}

function publishReport({ reportPath, reportBytes, kernelUid, kernelGid, chown = fs.fchownSync }) {
  const parent = fs.lstatSync(path.dirname(reportPath));
  if (!parent.isDirectory() || parent.isSymbolicLink() || (parent.mode & 0o077) !== 0) {
    throw new Error('isolation report parent must be one private direct directory');
  }
  const descriptor = fs.openSync(reportPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o600);
  try {
    chown(descriptor, Number(kernelUid), Number(kernelGid));
    fs.writeFileSync(descriptor, reportBytes);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  const directory = fs.openSync(path.dirname(reportPath), fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
}

export async function runPrivilegedAgentIsolationPreflight({
  config: value, now = () => new Date().toISOString(), spawnImpl = fork, chown = fs.fchownSync,
}) {
  if (process.getuid?.() !== 0) throw new Error('privileged isolation preflight requires root');
  const config = validateConfig(value);
  const probeResults = await spawnProbe(config, spawnImpl);
  const built = buildIsolationReport({ config, probeResults, now });
  publishReport({ reportPath: config.reportPath, reportBytes: built.reportBytes,
    kernelUid: config.kernelUid, kernelGid: config.kernelGid, chown });
  return Object.freeze({ reportHash: built.reportHash });
}

function readConfig(filePath) {
  if (!path.isAbsolute(filePath)) throw new Error('preflight config path must be absolute');
  const bytes = fs.readFileSync(filePath);
  const value = JSON.parse(bytes.toString('utf8'));
  if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
    throw new Error('preflight config must be canonical JSON plus newline');
  }
  return value;
}

async function direct() {
  if (process.argv.length !== 4 || process.argv[2] !== '--config') {
    throw new Error('usage: preflight-agent-isolation.mjs --config ABSOLUTE_PATH');
  }
  const result = await runPrivilegedAgentIsolationPreflight({ config: readConfig(process.argv[3]) });
  process.stdout.write(`${result.reportHash}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  direct().catch((error) => {
    process.stderr.write(`isolation preflight failed: ${error?.code ?? 'ERROR'}\n`);
    process.exitCode = 1;
  });
}

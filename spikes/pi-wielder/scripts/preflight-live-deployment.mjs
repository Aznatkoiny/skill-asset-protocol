#!/usr/bin/env node
import { fork } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import {
  captureDeploymentIsolationMetadata,
  captureDeploymentAuthorityMetadata,
  deploymentRendererInput,
  readDeploymentConfig,
} from '../src/kernel/deployment.mjs';
import { inspectEffectiveSystemd } from './inspect-systemd-effective.mjs';
import { renderSystemdUnits } from './render-systemd-units.mjs';
import { probeAgentIsolation } from './preflight-agent-isolation.mjs';
import {
  assertClosedLoaderEnvironment,
  validateReleaseManifest,
  verifyReleaseIntegrity,
} from '../src/kernel/release-integrity.mjs';

const READER_RELATIVE = 'scripts/prelaunch-kernel-reader.mjs';

// The installed preflight, runtime, credential delivery and native listeners are
// composed below and in src/runtime/. Offline tests cannot qualify PID1, actual
// dropped identities or installed start/restart/cleanup. Keep both executable
// entrypoints closed until a reviewed release retains that Linux evidence.
export const LIVE_LAUNCH_GATE = Object.freeze({
  schemaVersion: 1,
  status: 'blocked',
  code: 'LIVE_LAUNCH_NOT_READY',
  exitStatus: 78,
  blockers: Object.freeze([
    'LIVE_SYSTEMD_LIFECYCLE_EVIDENCE_REQUIRED',
  ]),
});

export function parsePreflightArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 6
      || argv[0] !== '--release-manifest' || argv[2] !== '--kernel-uid'
      || argv[4] !== '--kernel-gid') {
    throw new Error('live preflight arguments do not match the closed schema');
  }
  const [manifestPath, uid, gid] = [argv[1], argv[3], argv[5]];
  if (!path.isAbsolute(manifestPath) || path.resolve(manifestPath) !== manifestPath
      || !/^[1-9][0-9]*$/.test(uid) || !/^[1-9][0-9]*$/.test(gid)
      || !Number.isSafeInteger(Number(uid)) || !Number.isSafeInteger(Number(gid))) {
    throw new Error('live preflight arguments contain invalid values');
  }
  return Object.freeze({ manifestPath, kernelUid: uid, kernelGid: gid });
}

export function readManifestOnce(manifestPath) {
  const descriptor = fs.openSync(manifestPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.uid !== 0 || (stat.mode & 0o022) !== 0
        || stat.size <= 0 || stat.size > 4 * 1024 * 1024) {
      throw new Error('release manifest must be one bounded regular file');
    }
    const bytes = fs.readFileSync(descriptor);
    const value = JSON.parse(bytes.toString('utf8'));
    if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
      throw new Error('release manifest must be canonical JSON plus newline');
    }
    return validateReleaseManifest(value);
  } finally { fs.closeSync(descriptor); }
}

export function assertRootPreflightEnvironment(environment) {
  const captured = assertClosedLoaderEnvironment(environment, {
    allowedWalletKernelFields: ['WALLET_KERNEL_ENV_FILE'],
  });
  const environmentPath = captured.WALLET_KERNEL_ENV_FILE;
  if (typeof environmentPath !== 'string' || !path.isAbsolute(environmentPath)
      || path.resolve(environmentPath) !== environmentPath || environmentPath.includes('\0')) {
    throw new Error('root preflight environment file pointer is invalid');
  }
  return captured;
}

function readerRoundTrip({ readerPath, nodePath, kernelUid, kernelGid, request }) {
  return new Promise((resolve, reject) => {
    const child = fork(readerPath, [
      '--kernel-uid', kernelUid, '--kernel-gid', kernelGid,
    ], { execPath: nodePath, env: {}, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
    let nonce;
    let sent = false;
    let settled = false;
    const timeout = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('prelaunch reader timed out'));
    }, 15_000);
    const finish = (fn) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeout);
      fn();
    };
    child.on('error', (error) => finish(() => reject(error)));
    child.on('message', (message) => {
      if (message?.type === 'ready' && typeof message.nonce === 'string' && !sent) {
        nonce = message.nonce;
        sent = true;
        child.send({ ...request, nonce, parentPid: process.pid,
          kernelUid, kernelGid });
      } else if (message?.type === 'result' && sent && message.nonce === nonce) {
        finish(() => resolve(message.result));
      } else if (message?.type === 'failed') {
        finish(() => reject(new Error('prelaunch reader failed')));
      }
    });
    child.on('exit', (code) => {
      if (!settled) finish(() => reject(new Error(`prelaunch reader exited ${code}`)));
    });
  });
}

export async function runPrivilegedLivePreflight({
  argv, environment, releasePaths, effectiveSystemd, readerRequest, spawnReader = readerRoundTrip,
}) {
  if (process.getuid?.() !== 0) throw new Error('live deployment preflight requires root');
  const parsed = parsePreflightArguments(argv);
  const closedEnvironment = assertRootPreflightEnvironment(environment);
  if (closedEnvironment.WALLET_KERNEL_ENV_FILE !== releasePaths.environmentPath) {
    throw new Error('root preflight environment pointer differs from the release input');
  }
  const manifest = readManifestOnce(parsed.manifestPath);
  if (manifest.kernelIdentity.uid !== parsed.kernelUid
      || manifest.kernelIdentity.gid !== parsed.kernelGid) {
    throw new Error('preflight numeric identity differs from the release manifest');
  }
  const verified = verifyReleaseIntegrity({
    mode: 'cdp-testnet', releaseRoot: path.dirname(parsed.manifestPath), manifest,
    expectedOwnerUid: 0, expectedKernelUid: parsed.kernelUid, expectedKernelGid: parsed.kernelGid,
    nodePath: process.execPath, nodeVersion: process.version,
    environmentPath: releasePaths.environmentPath,
    serviceArtifactPaths: releasePaths.serviceArtifactPaths,
  });
  if (Object.entries(manifest.systemd).some(([field, value]) => effectiveSystemd[field] !== value)) {
    throw new Error('fresh PID1 effective configuration differs from the release manifest');
  }
  const request = {
    releaseRoot: path.dirname(parsed.manifestPath),
    releaseManifestHash: verified.releaseManifestHash,
    authorityMetadataHash: readerRequest.authorityMetadataHash,
    credentialMetadataHash: readerRequest.credentialMetadataHash,
    phase: readerRequest.phase,
    probeResults: readerRequest.probeResults,
    databasePath: readerRequest.databasePath,
    pathTrust: readerRequest.pathTrust,
    isolationReportPath: readerRequest.isolationReportPath,
    now: readerRequest.now,
  };
  const result = await spawnReader({
    readerPath: path.join(path.dirname(parsed.manifestPath), READER_RELATIVE),
    nodePath: process.execPath, kernelUid: parsed.kernelUid, kernelGid: parsed.kernelGid,
    request,
  });
  return Object.freeze({ status: result.status, preflightDigest: result.preflightDigest,
    nonceHash: crypto.createHash('sha256').update(String(result.nonce ?? '')).digest('hex') });
}

export async function runInstalledLivePreflight({ argv, environment }, effects = {}) {
  const assertRoot = effects.assertRoot ?? (() => {
    if (process.platform !== 'linux' || process.getuid?.() !== 0 || process.geteuid?.() !== 0) {
      throw new Error('installed preflight requires Linux root');
    }
  });
  assertRoot();
  const parsed = parsePreflightArguments(argv);
  const closedEnvironment = assertRootPreflightEnvironment(environment);
  const releaseRoot = path.dirname(parsed.manifestPath);
  const config = (effects.readDeployment ?? readDeploymentConfig)(path.join(releaseRoot, 'deployment.json'));
  if (config.releaseRoot !== releaseRoot || config.kernelUid !== parsed.kernelUid
      || config.kernelGid !== parsed.kernelGid || config.nodePath !== process.execPath
      || config.environmentPath !== closedEnvironment.WALLET_KERNEL_ENV_FILE) {
    throw new Error('installed preflight inputs differ from public deployment');
  }
  const manifest = (effects.readManifest ?? readManifestOnce)(parsed.manifestPath);
  if (manifest.commit !== config.commit) throw new Error('installed commit differs from the release manifest');
  const serviceArtifactPaths = {
    'kernel-service': config.serviceOutputPath,
    'console-socket': config.socketOutputPath,
  };
  // Verify the complete installed tree before invoking any worker or querying
  // private-path metadata. All inputs here are public paths or immutable bytes.
  const release = (effects.verifyRelease ?? verifyReleaseIntegrity)({
    mode: 'cdp-testnet', releaseRoot, manifest, expectedOwnerUid: 0,
    expectedKernelUid: config.kernelUid, expectedKernelGid: config.kernelGid,
    nodePath: process.execPath, nodeVersion: process.version,
    environmentPath: config.environmentPath, serviceArtifactPaths,
  });
  const rendered = (effects.renderUnits ?? renderSystemdUnits)(deploymentRendererInput(config));
  const effectiveSystemd = await (effects.inspectSystemd ?? inspectEffectiveSystemd)({ expected: rendered.expectedEffectiveConfig });
  if (Object.entries(manifest.systemd).some(([field, value]) => effectiveSystemd[field] !== value)) {
    throw new Error('fresh PID1 configuration differs from the release manifest');
  }
  const authorityMetadataHash = (effects.captureAuthorityMetadata ?? captureDeploymentAuthorityMetadata)(config);
  const audit = (phase, probeResults, credentialMetadataHash) => (effects.auditReader ?? runPrivilegedLivePreflight)({
    argv, environment: closedEnvironment,
    releasePaths: { environmentPath: config.environmentPath, serviceArtifactPaths },
    effectiveSystemd,
    readerRequest: {
      phase, authorityMetadataHash, credentialMetadataHash, probeResults,
      databasePath: config.databasePath, isolationReportPath: config.isolationReportPath,
      pathTrust: { mode: 'cdp-testnet', trustedAncestor: config.trustedAncestor,
        kernelUid: Number(config.kernelUid), agentUid: Number(config.agentUid) },
      now: (effects.now ?? (() => new Date().toISOString()))(),
    },
  });
  const inspection = await audit('inspect', null, null);
  if (!['enrolled', 'recovery_only'].includes(inspection.status)
      || !/^sha256:[0-9a-f]{64}$/.test(inspection.preflightDigest)) {
    throw new Error('prelaunch reader returned an invalid inspection result');
  }
  if (inspection.status === 'recovery_only') return Object.freeze({ ...inspection, release });
  const metadata = (effects.captureMetadata ?? captureDeploymentIsolationMetadata)(config);
  if (metadata.authorityMetadataHash !== authorityMetadataHash) throw new Error('authority metadata changed during preflight');
  const probeName = `.wallet-kernel-preflight-${crypto.randomBytes(16).toString('hex')}`;
  const probeResults = await (effects.probeAgent ?? probeAgentIsolation)({
    agentUid: config.agentUid, agentGid: config.agentGid, credentialPath: config.agentCredentialPath,
    protectedReadPaths: {
      authorityDirectory: config.authorityRoot, database: config.databasePath,
      operatorToken: config.operatorTokenPath, receiptKey: config.receiptKeyPath,
      kernelEnvironment: config.environmentPath,
    },
    writePaths: {
      releaseTreeWrite: path.join(releaseRoot, probeName),
      dependencyTreeWrite: path.join(releaseRoot, 'node_modules', probeName),
      serviceArtifactsWrite: path.join(path.dirname(config.serviceOutputPath), probeName),
      kernelEnvironmentParentWrite: path.join(path.dirname(config.environmentPath), probeName),
    },
  });
  const afterProbe = (effects.captureMetadata ?? captureDeploymentIsolationMetadata)(config);
  if (afterProbe.authorityMetadataHash !== metadata.authorityMetadataHash
      || afterProbe.credentialMetadataHash !== metadata.credentialMetadataHash) {
    throw new Error('isolation metadata changed during dropped Agent probes');
  }
  const result = await audit('audit', probeResults, metadata.credentialMetadataHash);
  if (!['verified', 'recovery_only'].includes(result.status)
      || !/^sha256:[0-9a-f]{64}$/.test(result.preflightDigest)) {
    throw new Error('prelaunch reader returned an invalid admission result');
  }
  return Object.freeze({ ...result, release, status: result.status });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (LIVE_LAUNCH_GATE.status === 'blocked') {
    process.stderr.write(`${canonicalJson(LIVE_LAUNCH_GATE)}\n`);
    // EX_CONFIG with Restart=no prevents privileged restart storms.
    process.exitCode = LIVE_LAUNCH_GATE.exitStatus;
  } else {
    runInstalledLivePreflight({ argv: process.argv.slice(2), environment: process.env })
      .then(({ status, preflightDigest }) => process.stdout.write(`${canonicalJson({ status, preflightDigest })}\n`))
      .catch(() => {
        process.stderr.write('LIVE_PREFLIGHT_FAILED\n');
        process.exitCode = 1;
      });
  }
}

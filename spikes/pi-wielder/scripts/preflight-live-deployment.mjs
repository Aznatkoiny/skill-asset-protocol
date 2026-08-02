#!/usr/bin/env node
import { fork } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import {
  assertClosedLoaderEnvironment,
  validateReleaseManifest,
  verifyReleaseIntegrity,
} from '../src/kernel/release-integrity.mjs';

const READER_RELATIVE = 'scripts/prelaunch-kernel-reader.mjs';

// This is a deliberate, machine-readable release gate. The reusable preflight
// function is implemented and tested, but the installed process still lacks the
// reviewed composition that supplies its public release/systemd/probe inputs,
// loads secrets only after the root phase, and constructs the live control-plane
// dependencies. The future @hono/node-server listener adapters must also set
// `overrideGlobalObjects: false`; otherwise native fetch responses stop matching
// the platform Response constructor used by x402 validation. Keep the systemd
// service fail-closed until every blocker is replaced by tested production
// composition and Linux lifecycle evidence.
export const LIVE_LAUNCH_GATE = Object.freeze({
  schemaVersion: 1,
  status: 'blocked',
  code: 'LIVE_LAUNCH_NOT_READY',
  exitStatus: 78,
  blockers: Object.freeze([
    'LIVE_PREFLIGHT_COMPOSITION_REQUIRED',
    'CONTROL_PLANE_COMPOSITION_REQUIRED',
    'LIVE_SECRET_DELIVERY_COMPOSITION_REQUIRED',
    'LIVE_LISTENER_RESPONSE_COMPATIBILITY_REQUIRED',
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

function readManifestOnce(manifestPath) {
  const descriptor = fs.openSync(manifestPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > 4 * 1024 * 1024) {
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
  if (effectiveSystemd.effectiveConfigHash !== manifest.systemd.effectiveConfigHash) {
    throw new Error('fresh PID1 effective configuration differs from the release manifest');
  }
  const request = {
    releaseRoot: path.dirname(parsed.manifestPath),
    releaseManifestHash: verified.releaseManifestHash,
    authorityMetadataHash: readerRequest.authorityMetadataHash,
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

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write(`${canonicalJson(LIVE_LAUNCH_GATE)}\n`);
  // sysexits(3) EX_CONFIG. The blocked unit pins Restart=no so an intentional
  // preflight refusal cannot turn into a privileged restart storm.
  process.exitCode = LIVE_LAUNCH_GATE.exitStatus;
}

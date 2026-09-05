import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, KernelError } from '../kernel/canonical.mjs';
import {
  captureDeploymentAuthorityMetadata, deploymentRendererInput, readDeploymentConfig,
} from '../kernel/deployment.mjs';
import {
  assertClosedLoaderEnvironment, captureInheritedConsoleSocket, verifyReleaseIntegrity,
} from '../kernel/release-integrity.mjs';
import { readPrivateInputFile } from '../kernel/secure-storage.mjs';
import { validateIsolationReportBytes } from '../agent/isolation-preflight.mjs';
import { LIVE_LAUNCH_GATE, readManifestOnce } from '../../scripts/preflight-live-deployment.mjs';
import { inspectEffectiveSystemd } from '../../scripts/inspect-systemd-effective.mjs';
import { renderSystemdUnits } from '../../scripts/render-systemd-units.mjs';

const RELEASE_ROOT = fileURLToPath(new URL('../../', import.meta.url)).replace(/\/$/, '');

function fail(code, message) { throw new KernelError(code, message); }

export function inspectActivatedConsole(fd) {
  if (process.platform !== 'linux' || fd !== 3 || !fs.fstatSync(fd).isSocket()) {
    fail('SOCKET_ACTIVATION', 'console descriptor must be the Linux inherited socket');
  }
  const inode = fs.fstatSync(fd, { bigint: true }).ino.toString();
  const table = fs.readFileSync('/proc/self/net/tcp', 'utf8');
  if (table.length > 1024 * 1024) fail('SOCKET_ACTIVATION', 'socket table exceeds its bound');
  const matches = table.trim().split('\n').slice(1)
    .map((row) => row.trim().split(/\s+/)).filter((columns) => columns[9] === inode);
  if (matches.length !== 1 || matches[0][1] !== '0100007F:20D5' || matches[0][3] !== '0A') {
    fail('SOCKET_ACTIVATION', 'inherited descriptor is not the reserved listening console socket');
  }
  return { fd, family: 'AF_INET', type: 'SOCK_STREAM', listening: true,
    address: '127.0.0.1', port: 8405 };
}

export async function composeInstalledService({ environment, releaseRoot = RELEASE_ROOT }, effects = {}) {
  const processApi = effects.processApi ?? process;
  const config = (effects.readDeployment ?? readDeploymentConfig)(path.join(releaseRoot, 'deployment.json'));
  const uid = Number(config.kernelUid);
  const gid = Number(config.kernelGid);
  if (processApi.platform !== 'linux' || processApi.getuid() !== uid || processApi.geteuid() !== uid
      || processApi.getgid() !== gid || processApi.getegid() !== gid
      || processApi.getgroups().some((group) => group !== gid)) {
    fail('RUNTIME_IDENTITY', 'service must already run as the exact unprivileged Kernel identity');
  }
  if (releaseRoot !== config.releaseRoot || processApi.execPath !== config.nodePath
      || processApi.version !== 'v24.18.1') fail('RELEASE_VERIFY_INPUT', 'service runtime differs from public deployment');
  const captured = { ...environment };
  const activation = captureInheritedConsoleSocket({
    env: captured, processId: processApi.pid,
    inspectDescriptor: effects.inspectDescriptor ?? inspectActivatedConsole,
  });
  const closed = assertClosedLoaderEnvironment(captured, { allowedWalletKernelFields: ['WALLET_KERNEL_ENV_FILE'] });
  if (closed.WALLET_KERNEL_ENV_FILE !== config.environmentPath) fail('RELEASE_ENVIRONMENT', 'service environment pointer differs from deployment');
  const manifest = (effects.readManifest ?? readManifestOnce)(path.join(releaseRoot, 'manifest.json'));
  if (manifest.commit !== config.commit) fail('RELEASE_VERIFY_INPUT', 'installed commit differs from manifest');
  const release = (effects.verifyRelease ?? verifyReleaseIntegrity)({
    mode: 'cdp-testnet', releaseRoot, manifest, expectedOwnerUid: 0,
    expectedKernelUid: config.kernelUid, expectedKernelGid: config.kernelGid,
    nodePath: processApi.execPath, nodeVersion: processApi.version,
    environmentPath: config.environmentPath,
    serviceArtifactPaths: { 'kernel-service': config.serviceOutputPath, 'console-socket': config.socketOutputPath },
  });
  const expected = (effects.renderUnits ?? renderSystemdUnits)(deploymentRendererInput(config)).expectedEffectiveConfig;
  const effective = await (effects.inspectSystemd ?? inspectEffectiveSystemd)({ expected });
  if (Object.entries(manifest.systemd).some(([field, value]) => effective[field] !== value)) {
    fail('SYSTEMD_EFFECTIVE', 'PID1 configuration changed after privileged preflight');
  }
  const assertLiveAdmission = ({ enrollment }) => {
    const authorityMetadataHash = (effects.captureAuthorityMetadata ?? captureDeploymentAuthorityMetadata)(config);
    const bytes = (effects.readReport ?? readPrivateInputFile)(config.isolationReportPath, 'isolation report', {
      maximumBytes: 16 * 1024, checkoutRoot: releaseRoot,
      pathTrust: Object.freeze({ mode: 'cdp-testnet', trustedAncestor: config.trustedAncestor,
        kernelUid: uid, agentUid: Number(config.agentUid) }),
    });
    try {
      const result = validateIsolationReportBytes(bytes, {
        expectedEnrollmentHash: enrollment.enrollmentHash,
        expectedKernelUid: config.kernelUid, expectedKernelGid: config.kernelGid,
        expectedReleaseManifestHash: release.releaseManifestHash,
        expectedAuthorityMetadataHash: authorityMetadataHash,
        now: effects.now ?? (() => new Date().toISOString()),
      });
      for (const field of ['releaseTreeHash', 'nodeExecutableHash', 'serviceArtifactsHash',
        'systemdEffectiveConfigHash', 'environmentMetadataHash']) {
        if (result.report[field] !== release[field]) fail('ISOLATION_BINDING_MISMATCH', 'isolation report belongs to another deployment');
      }
      if (result.report.agentUid !== config.agentUid || result.report.agentGid !== config.agentGid) {
        fail('ISOLATION_BINDING_MISMATCH', 'isolation report belongs to another Agent identity');
      }
      return Object.freeze({ isolation: 'verified', ...result, authorityMetadataHash });
    } finally { bytes.fill(0); }
  };
  // Import the wallet/runtime graph only after public release and process facts
  // are verified. It opens the PID1 credential copy after repeating the UID check.
  const start = effects.startRuntime ?? (await import('./installed-runtime.mjs')).startInstalledControlPlane;
  return start({ environmentFilePath: config.environmentPath,
    credentialFilePath: '/run/credentials/wallet-kernel.service/wallet-kernel-environment',
    kernelUid: uid, kernelGid: gid, release, deployment: config,
    assertLiveAdmission, consoleActivation: activation,
  });
}

export async function runInstalledService() {
  // No environment flag or CLI switch can turn an unqualified release live.
  if (LIVE_LAUNCH_GATE.status === 'blocked') {
    process.stderr.write(`${canonicalJson(LIVE_LAUNCH_GATE)}\n`);
    process.exitCode = LIVE_LAUNCH_GATE.exitStatus;
    return;
  }
  let plane;
  try {
    plane = await composeInstalledService({ environment: process.env });
    const close = () => { void plane.close().catch(() => { process.exitCode = 1; }); };
    process.once('SIGTERM', close);
    process.once('SIGINT', close);
  } catch (error) {
    process.stderr.write(`${error instanceof KernelError ? error.code : 'RUNTIME_STARTUP_FAILED'}\n`);
    process.exitCode = 1;
  }
}

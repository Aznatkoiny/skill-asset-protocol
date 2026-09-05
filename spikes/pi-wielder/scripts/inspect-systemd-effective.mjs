#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson, exactRecord, frozenCopy, KernelError, sha256 } from '../src/kernel/canonical.mjs';

const MAXIMUM_OUTPUT = 64 * 1024;
const EFFECTIVE_DOMAIN = 'wallet-kernel/systemd-effective/v1\0';
export const COMMON_PROPERTIES = Object.freeze([
  'Id', 'LoadState', 'FragmentPath', 'DropInPaths', 'NeedDaemonReload', 'Transient',
  'UnitFileState',
]);
export const SERVICE_PROPERTIES = Object.freeze([
  ...COMMON_PROPERTIES, 'User', 'Group', 'SupplementaryGroups', 'Environment',
  'EnvironmentFiles', 'PassEnvironment', 'LoadCredential',
  'ExecStartPreEx', 'ExecStartEx', 'ExecStopPostEx', 'Restart', 'RestartUSec', 'RestartPreventExitStatus',
  'UMask', 'NoNewPrivileges',
  'CapabilityBoundingSet', 'AmbientCapabilities', 'ProtectSystem', 'ProtectHome',
  'PrivateTmp', 'PrivateDevices', 'ProtectKernelTunables', 'ProtectKernelModules',
  'ProtectControlGroups', 'LockPersonality', 'RestrictAddressFamilies', 'ReadWritePaths',
  'UnsetEnvironment', 'IPAddressAllow', 'IPAddressDeny', 'Requires', 'After',
]);
export const SOCKET_PROPERTIES = Object.freeze([
  ...COMMON_PROPERTIES, 'Listen', 'Accept', 'Triggers', 'FileDescriptorName', 'ReusePort',
]);

function fail(code, message, cause) {
  throw new KernelError(code, message, cause ? { cause } : undefined);
}

function sortedSet(value) {
  if (typeof value !== 'string' || /[\r\n\0]/.test(value)) fail('SYSTEMD_EFFECTIVE', 'systemd set is malformed');
  return value === '' ? [] : value.trim().split(/\s+/).sort();
}

export function parseSystemctlShow(output, properties, maximumBytes = MAXIMUM_OUTPUT) {
  if (typeof output !== 'string' || Buffer.byteLength(output) > maximumBytes || output.includes('\0')) {
    fail('SYSTEMD_OUTPUT', 'systemctl output is not bounded text');
  }
  if (!Array.isArray(properties) || new Set(properties).size !== properties.length) {
    fail('SYSTEMD_OUTPUT', 'systemctl property request is invalid');
  }
  const allowed = new Set(properties);
  const result = {};
  for (const line of output.split('\n')) {
    if (line === '') continue;
    const split = line.indexOf('=');
    if (split < 1) fail('SYSTEMD_OUTPUT', 'systemctl output contains a malformed line');
    const key = line.slice(0, split);
    if (!allowed.has(key)) fail('SYSTEMD_OUTPUT', 'systemctl output contains an unknown property');
    if (Object.hasOwn(result, key)) fail('SYSTEMD_OUTPUT', 'systemctl output contains a duplicate property');
    result[key] = line.slice(split + 1);
  }
  if (properties.some((property) => !Object.hasOwn(result, property))) {
    fail('SYSTEMD_OUTPUT', 'systemctl output is missing a requested property');
  }
  return result;
}

function parseExec(value, label) {
  if (typeof value !== 'string' || value.length > 8192 || /[\r\n\0]/.test(value)) {
    fail('SYSTEMD_EXEC', `${label} is malformed`);
  }
  // systemctl v255 prints runtime status even for a command that has never run.
  // Parse that closed record, but keep only configuration in the stable hash.
  const match = /^\{ path=([^ ;]+) ; argv\[\]=([^;]+?) ; flags=([^;]*?) ; start_time=\[([^\]\[;\x00-\x1f\x7f]{1,128})\] ; stop_time=\[([^\]\[;\x00-\x1f\x7f]{1,128})\] ; pid=(0|[1-9][0-9]*) ; code=(\(null\)|exited|killed|dumped|trapped|stopped|continued) ; status=((?:0|[1-9][0-9]*)(?:\/(?:[A-Z][A-Z0-9+-]*|0|[1-9][0-9]*))?) \}$/.exec(value);
  if (!match) fail('SYSTEMD_EXEC', `${label} has an unsupported structure`);
  if (!Number.isSafeInteger(Number(match[6])) || Number(match[6]) > 2_147_483_647
      || Number(match[8].split('/')[0]) > 2_147_483_647) {
    fail('SYSTEMD_EXEC', `${label} has invalid runtime status`);
  }
  const executable = match[1];
  const argv = match[2].trim().split(/\s+/);
  const flags = match[3].trim() === '' ? [] : match[3].trim().split(/\s+/).sort();
  if (!path.isAbsolute(executable) || argv[0] !== executable
      || argv.some((token) => token === '' || /[\r\n\0]/.test(token))) {
    fail('SYSTEMD_EXEC', `${label} executable or argv is invalid`);
  }
  return { executable, argv, flags };
}

function requireValue(actual, expected, label) {
  if (actual !== expected) fail('SYSTEMD_EFFECTIVE', `${label} differs from the rendered contract`);
}

function resolvedDependencies(value, mandatory, label) {
  const units = sortedSet(value);
  const unitName = /^(?:[A-Za-z0-9:_.@-]|\\x[0-9a-fA-F]{2})+\.(?:service|socket|device|mount|automount|swap|target|path|timer|slice|scope)$/;
  if (new Set(units).size !== units.length
      || units.some(unit => unit.length > 255 || !unitName.test(unit))
      || mandatory.some(unit => !units.includes(unit))) {
    fail('SYSTEMD_EFFECTIVE', `${label} has malformed or missing dependency edges`);
  }
  return units;
}

export function validateEffectiveProjection({ service, socket, expected }) {
  const serviceData = exactRecord(service, SERVICE_PROPERTIES, [],
    'SYSTEMD_EFFECTIVE', 'effective service');
  const socketData = exactRecord(socket, SOCKET_PROPERTIES, [],
    'SYSTEMD_EFFECTIVE', 'effective socket');
  const expectedData = exactRecord(expected, [
    'kernelUid', 'kernelGid', 'releaseRoot', 'nodePath', 'environmentPath',
    'servicePath', 'socketPath', 'readWritePaths',
  ], ['executionProfile'], 'SYSTEMD_EFFECTIVE', 'expected systemd configuration');
  if (Object.hasOwn(expectedData, 'executionProfile')
      && !['cdp-testnet', 'offline-qualification'].includes(expectedData.executionProfile)) {
    fail('SYSTEMD_EFFECTIVE', 'execution profile is not supported');
  }
  const qualification = expectedData.executionProfile === 'offline-qualification';
  for (const [data, unitId, fragment, state] of [
    [serviceData, 'wallet-kernel.service', expectedData.servicePath, 'static'],
    [socketData, 'wallet-kernel-console.socket', expectedData.socketPath, 'enabled'],
  ]) {
    requireValue(data.Id, unitId, `${unitId} Id`);
    requireValue(data.LoadState, 'loaded', `${unitId} LoadState`);
    requireValue(data.FragmentPath, fragment, `${unitId} FragmentPath`);
    requireValue(data.DropInPaths, '', `${unitId} DropInPaths`);
    requireValue(data.NeedDaemonReload, 'no', `${unitId} NeedDaemonReload`);
    requireValue(data.Transient, 'no', `${unitId} Transient`);
    requireValue(data.UnitFileState, state, `${unitId} UnitFileState`);
  }
  const preflight = parseExec(serviceData.ExecStartPreEx, 'ExecStartPreEx');
  const main = parseExec(serviceData.ExecStartEx, 'ExecStartEx');
  const cleanup = parseExec(serviceData.ExecStopPostEx, 'ExecStopPostEx');
  const expectedPreflight = [
    expectedData.nodePath, `${expectedData.releaseRoot}/scripts/preflight-live-deployment.mjs`,
    '--release-manifest', `${expectedData.releaseRoot}/manifest.json`,
    '--kernel-uid', expectedData.kernelUid, '--kernel-gid', expectedData.kernelGid,
  ];
  const expectedMain = [expectedData.nodePath, `${expectedData.releaseRoot}/src/control-plane.mjs`];
  const expectedCleanup = [expectedData.nodePath, `${expectedData.releaseRoot}/scripts/cleanup-live-deployment.mjs`];
  if (canonicalJson(preflight.argv) !== canonicalJson(expectedPreflight)
      || canonicalJson(preflight.flags) !== canonicalJson(['privileged'])
      || canonicalJson(main.argv) !== canonicalJson(expectedMain)
      || main.flags.length !== 0
      || canonicalJson(cleanup.argv) !== canonicalJson(expectedCleanup)
      || canonicalJson(cleanup.flags) !== canonicalJson(['privileged'])) {
    fail('SYSTEMD_EXEC', 'loaded executable argv or flags differ from the rendered contract');
  }
  const scalar = {
    User: expectedData.kernelUid, Group: expectedData.kernelGid, SupplementaryGroups: '',
    Environment: `WALLET_KERNEL_ENV_FILE=${expectedData.environmentPath}`,
    EnvironmentFiles: '', PassEnvironment: '',
    LoadCredential: `wallet-kernel-environment:${expectedData.environmentPath}`,
    Restart: 'no', RestartUSec: '2s', RestartPreventExitStatus: '',
    UMask: '0077', NoNewPrivileges: 'yes', CapabilityBoundingSet: '', AmbientCapabilities: '',
    ProtectSystem: 'strict', ProtectHome: 'yes', PrivateTmp: 'yes', PrivateDevices: 'yes',
    ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes', ProtectControlGroups: 'yes',
    // Socket Service= is not a systemd v255 D-Bus property. Its resolved Unit
    // Triggers relationship must bind the one exact service instead.
    LockPersonality: 'yes', Accept: 'no', Triggers: 'wallet-kernel.service',
    FileDescriptorName: 'wallet-kernel-console', ReusePort: 'no',
  };
  for (const [field, expectedValue] of Object.entries(scalar)) {
    const target = Object.hasOwn(serviceData, field) ? serviceData : socketData;
    requireValue(target[field], expectedValue, field);
  }
  const sets = {
    // systemctl v255 prints these a(iayu) fields as expanded CIDRs. These are
    // loaded configuration facts; lifecycle evidence must prove enforcement.
    IPAddressAllow: qualification ? ['127.0.0.0/8', '::1/128'] : [],
    IPAddressDeny: qualification ? ['0.0.0.0/0', '::/0'] : [],
    RestrictAddressFamilies: ['AF_INET', 'AF_INET6', 'AF_UNIX'],
    ReadWritePaths: [...expectedData.readWritePaths].sort(),
    UnsetEnvironment: [
      'NODE_OPTIONS', 'NODE_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG',
      'LD_PROFILE', 'GLIBC_TUNABLES', 'GCONV_PATH', 'PRIVATE_KEY', 'ANTHROPIC_API_KEY',
      'OPENAI_API_KEY', 'CDP_API_KEY_ID', 'CDP_API_KEY_SECRET', 'CDP_WALLET_SECRET',
      'CDP_WALLET_NAME', 'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL',
      'CREDENTIALS_DIRECTORY', 'HOME', 'LOGNAME', 'USER', 'SHELL', 'INVOCATION_ID',
      'JOURNAL_STREAM', 'SYSTEMD_EXEC_PID', 'MEMORY_PRESSURE_WATCH', 'MEMORY_PRESSURE_WRITE',
      'NOTIFY_SOCKET', 'WATCHDOG_PID', 'WATCHDOG_USEC', 'LISTEN_PIDFDID',
    ].sort(),
  };
  for (const [field, expectedSet] of Object.entries(sets)) {
    if (canonicalJson(sortedSet(serviceData[field])) !== canonicalJson(expectedSet)) {
      fail('SYSTEMD_EFFECTIVE', `${field} differs from the rendered contract`);
    }
  }
  if (!/^127\.0\.0\.1:8405 \(Stream\)$/.test(socketData.Listen)) {
    fail('SYSTEMD_EFFECTIVE', 'socket must contain exactly one loopback stream');
  }
  // PID1 adds default, journal, and mount dependencies. Require the template's
  // explicit edges and hash the entire resolved sets, so later drift still fails
  // the release-manifest comparison instead of disappearing during normalization.
  const dependencies = {
    Requires: resolvedDependencies(serviceData.Requires, ['wallet-kernel-console.socket'], 'Requires'),
    After: resolvedDependencies(serviceData.After,
      ['network-online.target', 'wallet-kernel-console.socket'], 'After'),
  };
  const normalized = {
    service: { ...serviceData, ExecStartPreEx: preflight, ExecStartEx: main, ExecStopPostEx: cleanup,
      IPAddressAllow: sets.IPAddressAllow, IPAddressDeny: sets.IPAddressDeny,
      RestrictAddressFamilies: sets.RestrictAddressFamilies,
      ReadWritePaths: sets.ReadWritePaths, UnsetEnvironment: sets.UnsetEnvironment,
      Requires: dependencies.Requires, After: dependencies.After },
    socket: socketData,
  };
  return Object.freeze({
    service: frozenCopy(serviceData), socket: frozenCopy(socketData),
    normalized: frozenCopy(normalized),
    effectiveConfigHash: sha256(`${EFFECTIVE_DOMAIN}${canonicalJson(normalized)}`),
  });
}

function assertSystemctl(systemctlPath) {
  if (systemctlPath !== '/usr/bin/systemctl') fail('SYSTEMD_BINARY', 'systemctl path must equal /usr/bin/systemctl');
  const stat = fs.lstatSync(systemctlPath, { bigint: true });
  if (!stat.isFile() || stat.isSymbolicLink() || Number(stat.uid) !== 0
      || (Number(stat.mode & 0o7777n) & 0o022) !== 0) {
    fail('SYSTEMD_BINARY', 'systemctl must be an immutable root-owned regular file');
  }
  const bytes = fs.readFileSync(systemctlPath);
  return {
    executablePathHash: sha256(`wallet-kernel/absolute-path/v1\0${systemctlPath}`),
    executableSha256: sha256(bytes),
  };
}

function show(systemctlPath, unit, properties) {
  const property = properties.join(',');
  const output = execFileSync(systemctlPath, [
    'show', '--all', '--no-pager', `--property=${property}`, unit,
  ], { encoding: 'utf8', maxBuffer: MAXIMUM_OUTPUT, env: { PATH: '/usr/bin:/bin' } });
  return parseSystemctlShow(output, properties);
}

export async function inspectEffectiveSystemd(input) {
  if (input?.integration === true && Object.keys(input).length === 1) {
    // Used only as a guard in the optional test; a real inspection requires exact expected data.
    fail('SYSTEMD_INTEGRATION_FIXTURE', 'live systemd inspection requires installed fixture paths and expected configuration');
  }
  const options = exactRecord(input, ['expected'], ['systemctlPath'],
    'SYSTEMD_INSPECT_INPUT', 'systemd inspection input');
  const systemctlPath = options.systemctlPath ?? '/usr/bin/systemctl';
  const binary = assertSystemctl(systemctlPath);
  const service = show(systemctlPath, 'wallet-kernel.service', SERVICE_PROPERTIES);
  const socket = show(systemctlPath, 'wallet-kernel-console.socket', SOCKET_PROPERTIES);
  const projection = validateEffectiveProjection({ service, socket, expected: options.expected });
  const manager = execFileSync(systemctlPath, [
    'show', '--all', '--no-pager', '--property=Version',
  ], { encoding: 'utf8', maxBuffer: 4096, env: { PATH: '/usr/bin:/bin' } });
  const managerVersion = parseSystemctlShow(manager, ['Version'], 4096).Version;
  const client = execFileSync(systemctlPath, ['--version'], {
    encoding: 'utf8', maxBuffer: 4096, env: { PATH: '/usr/bin:/bin' },
  }).split('\n')[0];
  if (!managerVersion || managerVersion.length > 256 || !client || client.length > 256) {
    fail('SYSTEMD_VERSION', 'systemd version metadata is invalid');
  }
  return Object.freeze({
    platform: process.platform,
    managerVersion,
    systemctlVersion: client,
    systemctlExecutablePathHash: binary.executablePathHash,
    systemctlExecutableSha256: binary.executableSha256,
    effectiveConfigHash: projection.effectiveConfigHash,
    projection: projection.normalized,
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.stderr.write('inspect-systemd-effective.mjs must be invoked through the privileged installer with an exact configuration\n');
  process.exitCode = 2;
}

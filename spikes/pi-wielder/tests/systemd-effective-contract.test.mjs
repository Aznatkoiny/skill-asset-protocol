import assert from 'node:assert/strict';
import test from 'node:test';

import {
  parseSystemctlShow,
  SOCKET_PROPERTIES,
  validateEffectiveProjection,
} from '../scripts/inspect-systemd-effective.mjs';

// Output format comes from systemd v255 systemctl-show.c, not a live lifecycle
// run: https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c#L1275-L1286
// The dependency examples include documented DefaultDependencies/PrivateTmp edges.
function fixture() {
  const expected = {
    kernelUid: '501', kernelGid: '502',
    releaseRoot: '/opt/wallet/releases/aaaaaaaa', nodePath: '/opt/node/bin/node',
    environmentPath: '/etc/wallet/kernel.env',
    servicePath: '/etc/systemd/system/wallet-kernel.service',
    socketPath: '/etc/systemd/system/wallet-kernel-console.socket',
    readWritePaths: ['/opt/wallet/authority', '/opt/wallet/evidence', '/opt/wallet/runtime', '/opt/wallet/outbox'],
  };
  return {
    expected,
    service: {
      Id: 'wallet-kernel.service', LoadState: 'loaded', FragmentPath: expected.servicePath,
      DropInPaths: '', NeedDaemonReload: 'no', Transient: 'no', UnitFileState: 'static',
      User: '501', Group: '502', SupplementaryGroups: '',
      Environment: `WALLET_KERNEL_ENV_FILE=${expected.environmentPath}`,
      EnvironmentFiles: '', PassEnvironment: '',
      LoadCredential: `wallet-kernel-environment:${expected.environmentPath}`,
      ExecStartPreEx: `{ path=${expected.nodePath} ; argv[]=${expected.nodePath} ${expected.releaseRoot}/scripts/preflight-live-deployment.mjs --release-manifest ${expected.releaseRoot}/manifest.json --kernel-uid 501 --kernel-gid 502 ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
      ExecStartEx: `{ path=${expected.nodePath} ; argv[]=${expected.nodePath} ${expected.releaseRoot}/src/control-plane.mjs ; flags= ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
      ExecStopPostEx: `{ path=${expected.nodePath} ; argv[]=${expected.nodePath} ${expected.releaseRoot}/scripts/cleanup-live-deployment.mjs ; flags=privileged ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
      Restart: 'no', RestartUSec: '2s', RestartPreventExitStatus: '',
      UMask: '0077', NoNewPrivileges: 'yes', CapabilityBoundingSet: '', AmbientCapabilities: '',
      ProtectSystem: 'strict', ProtectHome: 'yes', PrivateTmp: 'yes', PrivateDevices: 'yes',
      ProtectKernelTunables: 'yes', ProtectKernelModules: 'yes', ProtectControlGroups: 'yes',
      LockPersonality: 'yes', RestrictAddressFamilies: 'AF_UNIX AF_INET AF_INET6',
      ReadWritePaths: expected.readWritePaths.join(' '),
      IPAddressAllow: '', IPAddressDeny: '',
      UnsetEnvironment: 'NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE GLIBC_TUNABLES GCONV_PATH PRIVATE_KEY ANTHROPIC_API_KEY OPENAI_API_KEY CDP_API_KEY_ID CDP_API_KEY_SECRET CDP_WALLET_SECRET CDP_WALLET_NAME WALLET_KERNEL_BASE_SEPOLIA_RPC_URL CREDENTIALS_DIRECTORY HOME LOGNAME USER SHELL INVOCATION_ID JOURNAL_STREAM SYSTEMD_EXEC_PID MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC LISTEN_PIDFDID',
      Requires: 'sysinit.target wallet-kernel-console.socket',
      After: 'sysinit.target basic.target systemd-tmpfiles-setup.service systemd-journald.socket network-online.target wallet-kernel-console.socket',
    },
    socket: {
      Id: 'wallet-kernel-console.socket', LoadState: 'loaded', FragmentPath: expected.socketPath,
      DropInPaths: '', NeedDaemonReload: 'no', Transient: 'no', UnitFileState: 'enabled',
      Listen: '127.0.0.1:8405 (Stream)', Accept: 'no', Triggers: 'wallet-kernel.service',
      FileDescriptorName: 'wallet-kernel-console', ReusePort: 'no',
    },
  };
}

test('real systemctl execution status is accepted but never changes the stable configuration hash', () => {
  const input = fixture();
  const original = validateEffectiveProjection(input);
  for (const [code, status] of [['exited', '0'], ['killed', '15/TERM'], ['dumped', '11/SEGV']]) {
    const candidate = structuredClone(input);
    for (const field of ['ExecStartPreEx', 'ExecStartEx', 'ExecStopPostEx']) {
      candidate.service[field] = candidate.service[field]
        .replaceAll('[n/a]', '[Sat 2026-09-05 12:00:00 UTC]')
        .replace('pid=0', 'pid=4321').replace('code=(null)', `code=${code}`)
        .replace('status=0/0', `status=${status}`);
    }
    const result = validateEffectiveProjection(candidate);
    assert.equal(result.effectiveConfigHash, original.effectiveConfigHash);
    assert.deepEqual(Object.keys(result.normalized.service.ExecStartPreEx).sort(), ['argv', 'executable', 'flags']);
  }
});

test('systemctl execution records reject missing, excess, malformed, and multiple command fields', () => {
  for (const mutate of [
    value => value.replace(/ ; start_time=.*$/, ' ; }'),
    value => value.replace(' ; pid=0', ' ; extra=x ; pid=0'),
    value => value.replace('pid=0', 'pid=-1'),
    value => value.replace('pid=0', 'pid=9007199254740993'),
    value => value.replace('code=(null)', 'code=unexpected'),
    value => value.replace('status=0/0', 'status=NaN'),
    value => value.replace('[n/a]', `[${'x'.repeat(129)}]`),
    value => `${value} ${value}`,
  ]) {
    const candidate = fixture();
    candidate.service.ExecStartPreEx = mutate(candidate.service.ExecStartPreEx);
    assert.throws(() => validateEffectiveProjection(candidate), { code: 'SYSTEMD_EXEC' });
  }
});

test('real execution metadata does not relax the pinned executable, argument, or privilege contract', () => {
  for (const mutate of [
    value => value.replace('path=/opt/node/bin/node', 'path=/usr/bin/node'),
    value => value.replace('--kernel-uid 501', '--kernel-uid 0'),
    value => value.replace(' ; flags=', ' --extra ; flags='),
    value => value.replace('flags=privileged', 'flags=privileged ignore-failure'),
    value => value.replace('flags=privileged', 'flags='),
  ]) {
    const candidate = fixture();
    candidate.service.ExecStartPreEx = mutate(candidate.service.ExecStartPreEx);
    assert.throws(() => validateEffectiveProjection(candidate), { code: 'SYSTEMD_EXEC' });
  }
});

test('PID1 dependency sets keep mandatory template edges and hash every resolved edge', () => {
  const input = fixture();
  const original = validateEffectiveProjection(input);
  const reordered = structuredClone(input);
  for (const field of ['Requires', 'After']) {
    reordered.service[field] = reordered.service[field].split(' ').reverse().join(' ');
    assert.deepEqual(original.normalized.service[field], input.service[field].split(' ').sort());
  }
  assert.equal(validateEffectiveProjection(reordered).effectiveConfigHash, original.effectiveConfigHash);
  for (const [field, edge, remove] of [
    ['Requires', 'extra.mount', false], ['After', 'extra.mount', false],
    ['Requires', 'sysinit.target', true], ['After', 'systemd-tmpfiles-setup.service', true],
  ]) {
    const candidate = structuredClone(input);
    candidate.service[field] = remove
      ? candidate.service[field].split(' ').filter(value => value !== edge).join(' ')
      : `${candidate.service[field]} ${edge}`;
    assert.notEqual(validateEffectiveProjection(candidate).effectiveConfigHash, original.effectiveConfigHash);
  }
  for (const [field, edge] of [
    ['Requires', 'wallet-kernel-console.socket'],
    ['After', 'wallet-kernel-console.socket'], ['After', 'network-online.target'],
  ]) {
    const candidate = fixture();
    candidate.service[field] = candidate.service[field].split(' ').filter(value => value !== edge).join(' ');
    assert.throws(() => validateEffectiveProjection(candidate), { code: 'SYSTEMD_EFFECTIVE' });
  }
});

test('dependency projection rejects duplicate edges and malformed unit names', () => {
  for (const extra of ['sysinit.target', 'not-a-unit', 'extra.service;injected']) {
    const input = fixture();
    input.service.Requires += ` ${extra}`;
    assert.throws(() => validateEffectiveProjection(input), { code: 'SYSTEMD_EFFECTIVE' });
  }
});

test('v255 socket inspection binds the real Triggers property and never requests Service', () => {
  // The socket vtable has no Service property; the generic Unit vtable exposes
  // Triggers: https://github.com/systemd/systemd/blob/v255/src/core/dbus-unit.c#L810
  const input = fixture();
  assert.equal(SOCKET_PROPERTIES.includes('Service'), false);
  assert.equal(SOCKET_PROPERTIES.includes('Triggers'), true);
  const output = Object.entries(input.socket).map(([key, value]) => `${key}=${value}\n`).join('');
  input.socket = parseSystemctlShow(output, SOCKET_PROPERTIES);
  assert.doesNotThrow(() => validateEffectiveProjection(input));
  for (const value of ['', 'other.service', 'wallet-kernel.service other.service',
    'wallet-kernel.service wallet-kernel.service']) {
    assert.throws(() => validateEffectiveProjection({ ...input,
      socket: { ...input.socket, Triggers: value } }), { code: 'SYSTEMD_EFFECTIVE' });
  }
  const unsupported = { ...input.socket, Service: 'wallet-kernel.service' };
  delete unsupported.Triggers;
  assert.throws(() => validateEffectiveProjection({ ...input, socket: unsupported }),
    { code: 'SYSTEMD_EFFECTIVE' });
});

test('cleanup execution remains exact and privileged while runtime status stays unhashed', () => {
  for (const mutate of [
    value => '',
    value => value.replace('cleanup-live-deployment.mjs', 'other.mjs'),
    value => value.replace(' ; flags=', ' --extra ; flags='),
    value => value.replace('flags=privileged', 'flags='),
    value => value.replace('flags=privileged', 'flags=privileged ignore-failure'),
    value => `${value} ${value}`,
  ]) {
    const input = fixture();
    input.service.ExecStopPostEx = mutate(input.service.ExecStopPostEx);
    assert.throws(() => validateEffectiveProjection(input), { code: 'SYSTEMD_EXEC' });
  }
});

test('qualification requires the exact expanded v255 loopback-only IP access lists', () => {
  // CIDR expansion and printing are specified in v255 resource-control.xml and
  // systemctl-show.c; a loaded property is not proof of kernel BPF enforcement.
  // https://github.com/systemd/systemd/blob/v255/man/systemd.resource-control.xml#L727-L735
  // https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c#L1397-L1447
  const ordinary = fixture();
  const input = fixture();
  input.expected.executionProfile = 'offline-qualification';
  input.service.IPAddressAllow = '::1/128 127.0.0.0/8';
  input.service.IPAddressDeny = '::/0 0.0.0.0/0';
  const original = validateEffectiveProjection(input);
  assert.deepEqual(original.normalized.service.IPAddressAllow, ['127.0.0.0/8', '::1/128']);
  assert.deepEqual(original.normalized.service.IPAddressDeny, ['0.0.0.0/0', '::/0']);
  assert.notEqual(original.effectiveConfigHash, validateEffectiveProjection(ordinary).effectiveConfigHash);
  const reordered = structuredClone(input);
  for (const field of ['IPAddressAllow', 'IPAddressDeny']) {
    reordered.service[field] = reordered.service[field].split(' ').reverse().join(' ');
  }
  assert.equal(validateEffectiveProjection(reordered).effectiveConfigHash, original.effectiveConfigHash);
  for (const [field, value] of [
    ['IPAddressAllow', ''], ['IPAddressAllow', 'localhost'],
    ['IPAddressAllow', '127.0.0.0/8'], ['IPAddressAllow', '0.0.0.0/0 ::/0'],
    ['IPAddressAllow', '127.0.0.0/8 ::1/128 192.0.2.0/24'],
    ['IPAddressAllow', '127.0.0.0/8 ::1/128 ::1/128'],
    ['IPAddressDeny', ''], ['IPAddressDeny', 'any'], ['IPAddressDeny', '0.0.0.0/0'],
  ]) {
    assert.throws(() => validateEffectiveProjection({ ...input,
      service: { ...input.service, [field]: value } }), { code: 'SYSTEMD_EFFECTIVE' });
  }
  assert.throws(() => validateEffectiveProjection({ ...input, expected: ordinary.expected }),
    { code: 'SYSTEMD_EFFECTIVE' });
  assert.equal(validateEffectiveProjection({ ...ordinary,
    expected: { ...ordinary.expected, executionProfile: 'cdp-testnet' } }).effectiveConfigHash,
  validateEffectiveProjection(ordinary).effectiveConfigHash);
  for (const executionProfile of ['live', '', null, true]) {
    assert.throws(() => validateEffectiveProjection({ ...input,
      expected: { ...input.expected, executionProfile } }), { code: 'SYSTEMD_EFFECTIVE' });
  }
});

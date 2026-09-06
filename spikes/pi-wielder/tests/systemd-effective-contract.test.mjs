import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import test from 'node:test';

import {
  inspectEffectiveSystemd,
  parseSystemdCredentialProperties,
  parseSystemctlShow,
  SERVICE_PROPERTIES,
  SERVICE_SHOW_PROPERTIES,
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
      UnsetEnvironment: 'NODE_OPTIONS NODE_PATH LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT LD_DEBUG LD_PROFILE GLIBC_TUNABLES GCONV_PATH PRIVATE_KEY ANTHROPIC_API_KEY OPENAI_API_KEY CDP_API_KEY_ID CDP_API_KEY_SECRET CDP_WALLET_SECRET CDP_WALLET_NAME WALLET_KERNEL_BASE_SEPOLIA_RPC_URL CREDENTIALS_DIRECTORY HOME LOGNAME USER SHELL INVOCATION_ID JOURNAL_STREAM SYSTEMD_EXEC_PID MEMORY_PRESSURE_WATCH MEMORY_PRESSURE_WRITE NOTIFY_SOCKET WATCHDOG_PID WATCHDOG_USEC LISTEN_PIDFDID SGX_AESM_ADDR',
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

test('PID1 must remove the incidental SGX_AESM_ADDR variable observed on the installed host', () => {
  // Name-only diagnostics from run33991226160/job101373703167 identified this
  // field in both ExecStartPre and ExecStopPost. Application allowlists stay closed.
  const input = fixture();
  assert.ok(validateEffectiveProjection(input).normalized.service.UnsetEnvironment.includes('SGX_AESM_ADDR'));
  input.service.UnsetEnvironment = input.service.UnsetEnvironment.split(' ')
    .filter(name => name !== 'SGX_AESM_ADDR').join(' ');
  assert.throws(() => validateEffectiveProjection(input), { code: 'SYSTEMD_EFFECTIVE' });
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

test('v255 quoted escaped mount dependencies are decoded, retained, and protected against duplicate spellings', () => {
  // Actual PID1 output from qualification run33990002633/job101370429665.
  // String arrays use shell_maybe_quote(value, 0), which doubles backslashes:
  // https://github.com/systemd/systemd/blob/v255/src/shared/bus-print-properties.c#L217-L248
  // https://github.com/systemd/systemd/blob/v255/src/basic/escape.c#L510-L556
  const encoded = String.raw`"run-credentials-wallet\\x2dkernel.service.mount"`;
  const decoded = String.raw`run-credentials-wallet\x2dkernel.service.mount`;
  const input = fixture();
  const withoutMount = validateEffectiveProjection(input);
  input.service.After += ` ${encoded}`;
  const actual = validateEffectiveProjection(input);
  assert.ok(actual.normalized.service.After.includes(decoded));
  assert.equal(actual.normalized.service.After.includes(encoded), false);
  assert.notEqual(actual.effectiveConfigHash, withoutMount.effectiveConfigHash);
  const reordered = structuredClone(input);
  reordered.service.After = input.service.After.split(' ').reverse().join(' ');
  assert.equal(validateEffectiveProjection(reordered).effectiveConfigHash, actual.effectiveConfigHash);
  for (const duplicate of [encoded, decoded]) {
    assert.throws(() => validateEffectiveProjection({ ...input,
      service: { ...input.service, After: `${input.service.After} ${duplicate}` } }),
    { code: 'SYSTEMD_EFFECTIVE' });
  }
  for (const malformed of ['"unterminated.mount', '"extra.mount"trailing', '""',
    '"extra mount"', '"extra.mount";command', '$(command).mount',
    String.raw`"run-credentials-wallet\x2dkernel.service.mount"`,
    String.raw`"extra\\q2.mount"`, String.raw`"extra\\x2.mount"`,
    String.raw`"extra\\\\x20.mount"`]) {
    assert.throws(() => validateEffectiveProjection({ ...input,
      service: { ...input.service, After: `${input.service.After} ${malformed}` } }),
    { code: 'SYSTEMD_EFFECTIVE' });
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

function credentialReplies(environmentPath) {
  // Real busctl v255 get-property JSON envelopes, not a PID1 lifecycle claim:
  // https://github.com/systemd/systemd/blob/v255/src/busctl/busctl.c#L1983-L2019
  return {
    environmentFiles: '{"type":"a(sb)","data":[]}\n',
    loadCredential: `${JSON.stringify({ type: 'a(ss)',
      data: [['wallet-kernel-environment', environmentPath]] })}\n`,
  };
}

test('v255 typed credential properties preserve the exact complete projection despite text formatter omissions', () => {
  const input = fixture();
  const raw = { ...input.service, LoadCredential: '[unprintable]' };
  delete raw.EnvironmentFiles;
  const show = value => Object.entries(value).map(([key, entry]) => `${key}=${entry}\n`).join('');
  // v255 emits no empty EnvironmentFiles line; it cannot print LoadCredential.
  // https://github.com/systemd/systemd/blob/v255/src/systemctl/systemctl-show.c#L1168-L1184
  assert.throws(() => parseSystemctlShow(show(raw), SERVICE_PROPERTIES), { code: 'SYSTEMD_OUTPUT' });
  assert.deepEqual(SERVICE_PROPERTIES.filter(key => !SERVICE_SHOW_PROPERTIES.includes(key)),
    ['EnvironmentFiles', 'LoadCredential']);
  delete raw.LoadCredential;
  const fields = parseSystemctlShow(show(raw), SERVICE_SHOW_PROPERTIES);
  const typed = parseSystemdCredentialProperties(credentialReplies(input.expected.environmentPath),
    input.expected.environmentPath);
  assert.deepEqual(typed, { EnvironmentFiles: '', LoadCredential: input.service.LoadCredential });
  assert.equal(validateEffectiveProjection({ ...input, service: { ...fields, ...typed } }).effectiveConfigHash,
    validateEffectiveProjection(input).effectiveConfigHash);
  for (const key of SERVICE_SHOW_PROPERTIES) {
    const missing = { ...raw };
    delete missing[key];
    assert.throws(() => parseSystemctlShow(show(missing), SERVICE_SHOW_PROPERTIES), { code: 'SYSTEMD_OUTPUT' });
  }
});

test('typed credential replies reject absent, malformed, excess, duplicate, and mismatched values', () => {
  const environmentPath = fixture().expected.environmentPath;
  for (const malformed of ['', '[unprintable]', 'null', '[]', '{}',
    '{"type":"a(sb)","data":null}', '{"type":"as","data":[]}',
    '{"type":"a(sb)","data":[],"extra":true}',
    '{"type":"a(sb)","data":[["/etc/extra.env",false]],"data":[]}',
    '{"type":"a(sb)","data":[]}\n{"type":"a(sb)","data":[]}',
    `${' '.repeat(65536)}{"type":"a(sb)","data":[]}`, '\0']) {
    assert.throws(() => parseSystemdCredentialProperties({
      ...credentialReplies(environmentPath), environmentFiles: malformed,
    }, environmentPath), { code: 'SYSTEMD_DBUS_OUTPUT' });
  }
  for (const data of [[['/etc/extra.env', false]], [['/etc/optional.env', true]], ['malformed']]) {
    assert.throws(() => parseSystemdCredentialProperties({ ...credentialReplies(environmentPath),
      environmentFiles: JSON.stringify({ type: 'a(sb)', data }),
    }, environmentPath), { code: 'SYSTEMD_EFFECTIVE' });
  }
  for (const data of [[], [['wrong-id', environmentPath]], [['wallet-kernel-environment', '/tmp/other']],
    [['wallet-kernel-environment', environmentPath, 'extra']],
    [['wallet-kernel-environment', environmentPath], ['extra', '/tmp/extra']],
    [['wallet-kernel-environment', environmentPath], ['wallet-kernel-environment', environmentPath]],
    ['wallet-kernel-environment', environmentPath], [null]]) {
    assert.throws(() => parseSystemdCredentialProperties({ ...credentialReplies(environmentPath),
      loadCredential: JSON.stringify({ type: 'a(ss)', data }),
    }, environmentPath), { code: 'SYSTEMD_EFFECTIVE' });
  }
  for (const malformed of ['', '{"type":"a(sb)","data":[]}',
    '{"type":"a(ss)","data":[],"data":[["wallet-kernel-environment","/etc/wallet/kernel.env"]]}']) {
    assert.throws(() => parseSystemdCredentialProperties({ ...credentialReplies(environmentPath),
      loadCredential: malformed }, environmentPath), { code: 'SYSTEMD_DBUS_OUTPUT' });
  }
});

test('inspector uses fixed immutable busctl and bounded read-only queries without inheriting environment', async t => {
  const input = fixture();
  const calls = [];
  let mutableAncestor = false;
  const replies = credentialReplies(input.expected.environmentPath);
  t.mock.method(fs, 'lstatSync', location => ({
    uid: 0n, nlink: 1n, mode: mutableAncestor && location === '/usr' ? 0o40777n : 0o100755n,
    isFile: () => ['/usr/bin/systemctl', '/usr/bin/busctl'].includes(location),
    isDirectory: () => ['/', '/usr', '/usr/bin'].includes(location), isSymbolicLink: () => false,
  }));
  t.mock.method(fs, 'readFileSync', location => {
    assert.equal(location, '/usr/bin/systemctl');
    return Buffer.from('test-only systemctl bytes');
  });
  t.mock.method(childProcess, 'execFileSync', (executable, args, options) => {
    calls.push({ executable, args, options });
    if (executable === '/usr/bin/busctl') {
      assert.deepEqual(args.slice(0, -1), ['--system', '--no-pager', '--json=short', '--timeout=10',
        'get-property', 'org.freedesktop.systemd1',
        '/org/freedesktop/systemd1/unit/wallet_2dkernel_2eservice', 'org.freedesktop.systemd1.Service']);
      assert.deepEqual(options.env, { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' });
      assert.equal(options.timeout, 10000);
      assert.equal(options.maxBuffer, 65536);
      assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
      assert.ok(['EnvironmentFiles', 'LoadCredential'].includes(args.at(-1)));
      return args.at(-1) === 'EnvironmentFiles' ? replies.environmentFiles : replies.loadCredential;
    }
    assert.equal(executable, '/usr/bin/systemctl');
    if (args[0] === '--version') return 'systemd 255\n';
    if (args.at(-1) === '--property=Version') return 'Version=255\n';
    const service = args.at(-1) === 'wallet-kernel.service';
    const properties = service ? SERVICE_SHOW_PROPERTIES : SOCKET_PROPERTIES;
    assert.equal(args[3], `--property=${properties.join(',')}`);
    const values = service ? input.service : input.socket;
    return properties.map(key => `${key}=${values[key]}\n`).join('');
  });
  syncBuiltinESMExports();
  try {
    const actual = await inspectEffectiveSystemd({ expected: input.expected });
    assert.equal(actual.effectiveConfigHash, validateEffectiveProjection(input).effectiveConfigHash);
    assert.equal(calls.filter(call => call.executable === '/usr/bin/busctl').length, 2);
    calls.length = 0;
    mutableAncestor = true;
    await assert.rejects(inspectEffectiveSystemd({ expected: input.expected }), { code: 'SYSTEMD_BINARY' });
    assert.equal(calls.some(call => call.executable === '/usr/bin/busctl'), false);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
  }
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

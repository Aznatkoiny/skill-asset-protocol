import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import { KernelError } from '../src/kernel/canonical.mjs';
import { assertClosedLoaderEnvironment } from '../src/kernel/release-integrity.mjs';
import { cleanupEnvironmentDiagnostic, validateCleanupEnvironment } from '../scripts/cleanup-live-deployment.mjs';
import {
  assertRootPreflightEnvironment,
  preflightEnvironmentDiagnostic,
  preflightFailureDiagnostic,
} from '../scripts/preflight-live-deployment.mjs';

for (const [diagnostic, format] of [
  ['installed-preflight-environment', preflightEnvironmentDiagnostic],
  ['installed-cleanup-environment', cleanupEnvironmentDiagnostic],
]) {
  test(`${diagnostic} reads names without reading values or accessors`, () => {
    const environment = { WALLET_KERNEL_ENV_FILE: '/private/synthetic.env', PATH: 'synthetic-never-export' };
    Object.defineProperty(environment, 'UNEXPECTED_FIELD', {
      enumerable: true, get() { throw new Error('environment getter must never run'); },
    });
    Object.defineProperty(environment, Symbol('synthetic-private-symbol'), { value: 'synthetic-never-export' });
    assert.deepEqual(format(environment), {
      diagnostic, names: ['PATH', 'UNEXPECTED_FIELD', 'WALLET_KERNEL_ENV_FILE'],
    });
    assert.equal(JSON.stringify(format(environment)).includes('synthetic'), false);
  });

  test(`${diagnostic} bounds and filters public names`, () => {
    const environment = Object.fromEntries(Array.from({ length: 160 }, (_, index) => [
      `FIELD_${String(index).padStart(3, '0')}`, 'synthetic-never-export',
    ]));
    for (const name of ['lowercase', 'HAS SPACE', 'WITH\nCONTROL', '_PREFIX', 'A'.repeat(129)]) environment[name] = 'private';
    const result = format(environment);
    assert.equal(result.names.length, 128);
    assert.deepEqual(result.names, Array.from({ length: 128 }, (_, index) => `FIELD_${String(index).padStart(3, '0')}`));
    assert.equal(result.names.every(name => /^[A-Z][A-Z0-9_]{0,127}$/.test(name)), true);
    for (const invalid of [null, undefined, 'private', []]) assert.deepEqual(format(invalid), { diagnostic, names: [] });
  });
}

test('preflight failure exposes only a bounded KernelError domain code', () => {
  assert.deepEqual(preflightFailureDiagnostic(new KernelError('RELEASE_ENVIRONMENT', 'synthetic-never-export', {
    cause: new Error('private file contents'),
  })), { code: 'LIVE_PREFLIGHT_FAILED', causeCode: 'RELEASE_ENVIRONMENT' });
  const accessorError = new KernelError('RELEASE_ENVIRONMENT', 'private');
  Object.defineProperty(accessorError, 'code', { get() { throw new Error('code getter must never run'); } });
  for (const error of [
    new Error('synthetic-never-export'), { code: 'RELEASE_ENVIRONMENT', message: 'private' },
    new KernelError('UNKNOWN_PRIVATE_DATA', 'private'), new KernelError('RELEASE_\nPRIVATE', 'private'),
    new KernelError(`RELEASE_${'A'.repeat(128)}`, 'private'), accessorError, null,
  ]) assert.deepEqual(preflightFailureDiagnostic(error), { code: 'LIVE_PREFLIGHT_FAILED', causeCode: null });
});

test('diagnostic observation does not admit an unexpected environment field', () => {
  const environment = { PATH: '/usr/bin:/bin', WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env',
    UNEXPECTED_FIELD: 'synthetic-never-export' };
  assert.deepEqual(preflightEnvironmentDiagnostic(environment).names,
    ['PATH', 'UNEXPECTED_FIELD', 'WALLET_KERNEL_ENV_FILE']);
  assert.throws(() => assertRootPreflightEnvironment(environment), (error) => {
    assert.deepEqual(preflightFailureDiagnostic(error), { code: 'LIVE_PREFLIGHT_FAILED', causeCode: 'RELEASE_ENVIRONMENT' });
    return true;
  });
});

test('SGX_AESM_ADDR injection remains rejected by preflight, runtime loader, and cleanup validation', () => {
  const environment = { PATH: '/usr/bin:/bin', WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env',
    SGX_AESM_ADDR: 'synthetic-never-export' };
  assert.throws(() => assertRootPreflightEnvironment(environment), { code: 'RELEASE_ENVIRONMENT' });
  assert.throws(() => assertClosedLoaderEnvironment(environment, {
    allowedWalletKernelFields: ['WALLET_KERNEL_ENV_FILE'],
  }), { code: 'RELEASE_ENVIRONMENT' });
  assert.throws(() => validateCleanupEnvironment({ ...environment, SERVICE_RESULT: 'success' }),
    { code: 'LIVE_CLEANUP_ENVIRONMENT' });
});

test('CLI captures real Node process.env as plain data and still rejects injected fields', () => {
  const moduleUrl = new URL('../scripts/preflight-live-deployment.mjs', import.meta.url).href;
  const script = `
    import { assertRootPreflightEnvironment, capturePreflightProcessEnvironment }
      from ${JSON.stringify(moduleUrl)};
    const snapshot = capturePreflightProcessEnvironment();
    let code = null;
    try { assertRootPreflightEnvironment(snapshot); } catch (error) { code = error.code; }
    process.stdout.write(JSON.stringify({
      nativePrototypeIsPlain: Object.getPrototypeOf(process.env) === Object.prototype,
      snapshotIsPlain: Object.getPrototypeOf(snapshot) === Object.prototype,
      snapshotIsFrozen: Object.isFrozen(snapshot),
      sameNames: JSON.stringify(Object.keys(snapshot).sort()) === JSON.stringify(Object.keys(process.env).sort()),
      code,
    }));
  `;
  for (const injected of [false, true]) {
    const child = spawnSync(process.execPath, ['--input-type=module', '--eval', script], {
      encoding: 'utf8', timeout: 10_000, maxBuffer: 4096,
      env: { PATH: '/usr/bin:/bin', LANG: 'C', WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env',
        ...(injected ? { SGX_AESM_ADDR: 'synthetic-never-export' } : {}) },
    });
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stderr, '');
    assert.deepEqual(JSON.parse(child.stdout), {
      nativePrototypeIsPlain: false, snapshotIsPlain: true, snapshotIsFrozen: true, sameNames: true,
      code: injected ? 'RELEASE_ENVIRONMENT' : null,
    });
  }
});

test('trusted CLI capture does not relax caller getter or proxy validation', () => {
  const base = { PATH: '/usr/bin:/bin', WALLET_KERNEL_ENV_FILE: '/etc/wallet-kernel/kernel.env' };
  const getter = Object.defineProperty({ ...base }, 'LANG', {
    enumerable: true, get() { throw new Error('caller getter must never run'); },
  });
  const proxy = new Proxy(base, { ownKeys() { throw new Error('caller proxy must never run'); } });
  for (const environment of [getter, proxy]) {
    assert.throws(() => assertRootPreflightEnvironment(environment), { code: 'RELEASE_ENVIRONMENT' });
  }
});

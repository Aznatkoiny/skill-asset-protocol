import assert from 'node:assert/strict';
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

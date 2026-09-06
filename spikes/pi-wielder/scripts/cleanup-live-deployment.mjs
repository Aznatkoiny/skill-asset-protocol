#!/usr/bin/env node
// Keep this failure path independent of the release's application graph. A
// failed integrity/preflight check must not require importing that graph again.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const SOCKET = 'wallet-kernel-console.socket';
const COMMANDS = Object.freeze([
  Object.freeze(['disable', SOCKET]),
  Object.freeze(['stop', '--no-block', SOCKET]),
]);
const ENVIRONMENT_FIELDS = new Set([
  'PATH', 'LANG', 'LC_ALL', 'TZ', 'WALLET_KERNEL_ENV_FILE',
  'SERVICE_RESULT', 'EXIT_CODE', 'EXIT_STATUS',
]);

// Do not share an application import with this failure path. This diagnostic
// reads property names only and exposes neither values nor exception messages.
export function cleanupEnvironmentDiagnostic(environment) {
  const names = environment && typeof environment === 'object' && !Array.isArray(environment)
    ? Object.getOwnPropertyNames(environment).filter(name => /^[A-Z][A-Z0-9_]{0,127}$/.test(name)).sort().slice(0, 128)
    : [];
  return Object.freeze({ diagnostic: 'installed-cleanup-environment', names: Object.freeze(names) });
}

function failure(code) {
  const error = new Error('Wallet Kernel service cleanup did not complete');
  error.code = code;
  return error;
}

function publicCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,100}$/.test(error.code)
    ? error.code : 'LIVE_CLEANUP_FAILED';
}

function assertRootExecutable(location) {
  const parts = location.slice(1).split('/');
  if (!path.isAbsolute(location) || path.resolve(location) !== location || location.includes('\0')) {
    throw failure('LIVE_CLEANUP_BINARY');
  }
  let current = '/';
  for (const [index, component] of ['', ...parts].entries()) {
    if (component) current = path.join(current, component);
    const stat = fs.lstatSync(current);
    const leaf = index === parts.length;
    if (stat.uid !== 0 || stat.isSymbolicLink() || (stat.mode & 0o7022) !== 0
        || (leaf ? !stat.isFile() || stat.nlink !== 1 || (stat.mode & 0o111) === 0 : !stat.isDirectory())) {
      throw failure('LIVE_CLEANUP_BINARY');
    }
  }
}

export function assertLiveCleanupHost() {
  if (process.platform !== 'linux' || process.getuid?.() !== 0 || process.geteuid?.() !== 0
      || process.version !== 'v24.18.1') throw failure('LIVE_CLEANUP_HOST');
  assertRootExecutable(process.execPath);
}

export function validateCleanupEnvironment(environment) {
  if (!environment || typeof environment !== 'object' || Array.isArray(environment)) {
    throw failure('LIVE_CLEANUP_ENVIRONMENT');
  }
  const descriptors = Object.getOwnPropertyDescriptors(environment);
  for (const name of Reflect.ownKeys(descriptors)) {
    const descriptor = descriptors[name];
    if (typeof name !== 'string' || !ENVIRONMENT_FIELDS.has(name)
        || !descriptor.enumerable || !Object.hasOwn(descriptor, 'value')
        || typeof descriptor.value !== 'string' || descriptor.value.length > 4096
        || /[\x00-\x1f\x7f]/.test(descriptor.value)) throw failure('LIVE_CLEANUP_ENVIRONMENT');
  }
  const pointer = descriptors.WALLET_KERNEL_ENV_FILE?.value;
  if (pointer !== undefined && (!path.isAbsolute(pointer) || path.resolve(pointer) !== pointer)) {
    throw failure('LIVE_CLEANUP_ENVIRONMENT');
  }
  // No missing, unknown, or malformed value can select the clean-stop path.
  // These status values and the public pointer are never passed to systemctl.
  return Object.freeze({ cleanStop: descriptors.SERVICE_RESULT?.value === 'success' });
}

function runSystemctl(args) {
  if (!COMMANDS.some((candidate) => candidate.length === args.length
      && candidate.every((value, index) => value === args[index]))) throw failure('LIVE_CLEANUP_COMMAND');
  assertRootExecutable('/usr/bin/systemctl');
  execFileSync('/usr/bin/systemctl', args, {
    timeout: 10_000, maxBuffer: 4096, env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
}

/** Test effects never enter the command line, process environment, or unit file. */
export async function cleanupLiveDeployment({ argv, environment }, effects) {
  if (!Array.isArray(argv) || argv.length !== 0) throw failure('LIVE_CLEANUP_ARGUMENTS');
  if (effects !== undefined && (!effects || typeof effects !== 'object' || Array.isArray(effects)
      || Reflect.ownKeys(effects).some((name) => !['assertHost', 'runSystemctl'].includes(name)
        || typeof effects[name] !== 'function'))) throw failure('LIVE_CLEANUP_ARGUMENTS');
  (effects?.assertHost ?? assertLiveCleanupHost)();
  const execution = effects === undefined ? 'installed' : 'simulated';
  let originalError;
  try {
    if (validateCleanupEnvironment(environment).cleanStop) {
      return Object.freeze({ schemaVersion: 1, execution, status: 'preserved_after_clean_stop',
        qualification: 'not_performed', attempts: Object.freeze([]) });
    }
  } catch (error) {
    // An unexpected environment is itself a failure. Still request fixed, clean-
    // environment socket cleanup; never leave activation enabled for this reason.
    originalError = error;
  }
  const attempts = [];
  for (const args of COMMANDS) {
    try {
      await (effects?.runSystemctl ?? runSystemctl)([...args]);
      attempts.push(Object.freeze({ action: args.join(' '), status: 'requested' }));
    } catch (error) {
      originalError ??= error;
      attempts.push(Object.freeze({ action: args.join(' '), status: 'request_failed', code: publicCode(error) }));
    }
  }
  // ExecStopPost must not synchronously stop/wait for its own service (including
  // the socket's reverse dependency). The host supervisor checks final PID1 state.
  const result = Object.freeze({ schemaVersion: 1, execution,
    status: originalError ? 'cleanup_failed' : 'cleanup_requested', qualification: 'not_performed',
    attempts: Object.freeze(attempts) });
  if (originalError) {
    const error = failure(publicCode(originalError));
    error.result = result;
    throw error;
  }
  return result;
}

export async function runCleanupLiveDeployment({ argv, environment, stdout = process.stdout, stderr = process.stderr }) {
  stderr.write(`${JSON.stringify(cleanupEnvironmentDiagnostic(environment))}\n`);
  try {
    stdout.write(`${JSON.stringify(await cleanupLiveDeployment({ argv, environment }))}\n`);
    return 0;
  } catch (error) {
    stderr.write(`${JSON.stringify({ code: publicCode(error), result: error.result ?? null })}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCleanupLiveDeployment({ argv: process.argv.slice(2), environment: process.env });
}

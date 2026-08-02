import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

const ROOT = path.resolve(import.meta.dirname, '../..');
const PI_BIN = path.resolve(ROOT, 'node_modules/.bin/pi');
const EXTENSION = path.resolve(ROOT, 'pi-extension/x402.ts');
const TOTAL_DEADLINE_MS = 30_000;
const TERMINATION_GRACE_MS = 2_000;
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/u;
const PI_PROMPT_MODES = new Set(['tool', 'model']);
const PI_EXPECTED_OUTPUTS = new Set([
  'PI_APPROVAL_REQUIRED',
  'approval-required-error',
  'PI_WALLET_OK',
]);

function fail(code) {
  const error = new Error(code);
  error.code = code;
  throw error;
}

function canonicalPath(value, label, { executable = false } = {}) {
  if (typeof value !== 'string' || !path.isAbsolute(value)
      || path.resolve(value) !== value || value.includes('\0')) fail(label);
  const stat = fs.lstatSync(value, { bigint: true });
  if (stat.isSymbolicLink() || (executable ? !stat.isFile() : !(stat.isFile() || stat.isDirectory()))) {
    fail(label);
  }
  return value;
}

function repositoryPiExecutable() {
  const link = fs.lstatSync(PI_BIN, { bigint: true });
  const expected = path.resolve(
    ROOT,
    'node_modules/@earendil-works/pi-coding-agent/dist/cli.js',
  );
  const resolved = fs.realpathSync(PI_BIN);
  const target = fs.lstatSync(resolved, { bigint: true });
  if (!link.isSymbolicLink() || resolved !== expected || !target.isFile()) {
    fail('PI_EXECUTABLE_INVALID');
  }
  return PI_BIN;
}

function loopbackOrigin(value) {
  let parsed;
  try { parsed = new URL(value); } catch { fail('PI_KERNEL_ORIGIN_INVALID'); }
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1'
      || parsed.port === '' || parsed.pathname !== '/' || parsed.search !== ''
      || parsed.hash !== '' || parsed.origin !== value) fail('PI_KERNEL_ORIGIN_INVALID');
  return value;
}

function boundedToken(value, code) {
  if (typeof value !== 'string' || !TOKEN.test(value)) fail(code);
  return value;
}

function sha256(value) {
  return `sha256:${crypto.createHash('sha256').update(value).digest('hex')}`;
}

function childEnvironment() {
  const temporaryPiDirectory = canonicalPath(
    process.env.WALLET_KERNEL_FIXTURE_PI_DIRECTORY,
    'PI_DIRECTORY_INVALID',
  );
  const agentCredentialFile = canonicalPath(
    process.env.WALLET_KERNEL_AGENT_CREDENTIAL_FILE,
    'PI_AGENT_CREDENTIAL_PATH',
    { executable: true },
  );
  const loopbackOnlyPreload = canonicalPath(
    process.env.WALLET_KERNEL_FIXTURE_PRELOAD,
    'PI_PRELOAD_INVALID',
    { executable: true },
  );
  const egressLog = canonicalPath(
    process.env.WALLET_KERNEL_EGRESS_LOG_FILE,
    'PI_EGRESS_LOG_INVALID',
    { executable: true },
  );
  const origin = loopbackOrigin(process.env.WALLET_KERNEL_ORIGIN);
  return Object.freeze({
    LANG: 'C.UTF-8',
    PATH: path.dirname(process.execPath),
    PI_OFFLINE: '1',
    PI_CODING_AGENT_DIR: temporaryPiDirectory,
    WALLET_KERNEL_ORIGIN: origin,
    WALLET_KERNEL_AGENT_CREDENTIAL_FILE: agentCredentialFile,
    WALLET_KERNEL_PROVIDER_NAME: boundedToken(
      process.env.WALLET_KERNEL_PROVIDER_NAME ?? 'wallet-kernel-e2e',
      'PI_PROVIDER_INVALID',
    ),
    WALLET_KERNEL_MODEL_NAME: boundedToken(
      process.env.WALLET_KERNEL_MODEL_NAME ?? 'scripted-local',
      'PI_MODEL_INVALID',
    ),
    WALLET_KERNEL_MODEL_ROUTE: boundedToken(
      process.env.WALLET_KERNEL_MODEL_ROUTE ?? 'example-model',
      'PI_MODEL_ROUTE_INVALID',
    ),
    WALLET_KERNEL_SKILL_ROUTE: boundedToken(
      process.env.WALLET_KERNEL_SKILL_ROUTE ?? 'example-skill',
      'PI_SKILL_ROUTE_INVALID',
    ),
    WALLET_KERNEL_EGRESS_LOG_FILE: egressLog,
    NODE_OPTIONS: `--require=${loopbackOnlyPreload}`,
  });
}

function exactVersion(env) {
  const result = spawnSync(PI_BIN, ['--version'], {
    cwd: ROOT,
    env,
    encoding: 'utf8',
    timeout: 5_000,
  });
  if (result.status !== 0 || result.signal !== null
      || result.stderr !== '' || result.stdout.trim() !== '0.80.6') {
    fail('PI_VERSION_MISMATCH');
  }
  return '0.80.6';
}

function terminateGroup(child, signal) {
  if (!child.pid) return;
  try {
    process.kill(-child.pid, signal);
  } catch (error) {
    if (error?.code !== 'ESRCH') throw error;
  }
}

async function runPi() {
  repositoryPiExecutable();
  canonicalPath(EXTENSION, 'PI_EXTENSION_INVALID', { executable: true });
  const env = childEnvironment();
  const piVersion = exactVersion(env);
  const promptMode = process.env.WALLET_KERNEL_PI_PROMPT_MODE;
  const expectedOutput = process.env.WALLET_KERNEL_PI_EXPECTED_OUTPUT;
  if (!PI_PROMPT_MODES.has(promptMode) || !PI_EXPECTED_OUTPUTS.has(expectedOutput)) {
    fail('PI_EXPECTATION_INVALID');
  }
  const scriptedPrompt = promptMode === 'tool'
    ? 'Use invoke_skill once with input commercial acceptance, then report the final result.'
    : 'Report PI_WALLET_OK without invoking any tool.';
  const child = spawn(PI_BIN, [
    '-p', scriptedPrompt,
    '--no-session',
    '--no-context-files',
    '--no-skills',
    '--no-prompt-templates',
    '--no-themes',
    '--no-extensions',
    '--no-builtin-tools',
    '--no-approve',
    '--offline',
    '-e', EXTENSION,
    '--provider', 'wallet-kernel-e2e',
    '--model', 'scripted-local',
  ], {
    cwd: ROOT,
    env,
    detached: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  let stdoutBytes = 0;
  let stderrBytes = 0;
  const capture = (chunks, maximum, kind) => (chunk) => {
    const current = kind === 'stdout' ? stdoutBytes : stderrBytes;
    const next = current + chunk.length;
    if (next > maximum) {
      terminateGroup(child, 'SIGTERM');
      return;
    }
    chunks.push(chunk);
    if (kind === 'stdout') stdoutBytes = next;
    else stderrBytes = next;
  };
  child.stdout.on('data', capture(stdout, 2_097_152, 'stdout'));
  child.stderr.on('data', capture(stderr, 1_048_576, 'stderr'));

  let deadline;
  let grace;
  let deadlineExpired = false;
  const result = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
    deadline = setTimeout(() => {
      deadlineExpired = true;
      terminateGroup(child, 'SIGTERM');
      grace = setTimeout(() => terminateGroup(child, 'SIGKILL'), TERMINATION_GRACE_MS);
      grace.unref();
    }, TOTAL_DEADLINE_MS);
    deadline.unref();
  });
  clearTimeout(deadline);
  clearTimeout(grace);
  const stdoutBytesValue = Buffer.concat(stdout);
  const stderrBytesValue = Buffer.concat(stderr);
  const output = new TextDecoder('utf-8', { fatal: false }).decode(stdoutBytesValue);
  const errorOutput = new TextDecoder('utf-8', { fatal: false }).decode(stderrBytesValue);
  const outputObserved = output.includes('PI_WALLET_OK')
    ? 'PI_WALLET_OK'
    : output.includes('PI_APPROVAL_REQUIRED')
      ? 'PI_APPROVAL_REQUIRED'
      : /payment_approval_required|Approval required:|\b409 status code\b/u.test(errorOutput)
        ? 'approval-required-error'
        : 'missing';
  const rawExitCode = deadlineExpired ? 124 : (result.code ?? 1);
  const expectedExitCode = expectedOutput === 'approval-required-error' ? 1 : 0;
  const expectationMatched = !deadlineExpired && result.signal === null
    && rawExitCode === expectedExitCode && outputObserved === expectedOutput;
  const message = Object.freeze({
    type: 'result',
    exitCode: rawExitCode,
    signal: result.signal,
    piVersion,
    outputObserved,
    stdoutHash: sha256(stdoutBytesValue),
    stderrHash: sha256(stderrBytesValue),
    failureCode: expectationMatched
      ? null
      : (deadlineExpired ? 'PROCESS_DEADLINE' : 'PI_PROCESS_FAILED'),
  });
  stdoutBytesValue.fill(0);
  stderrBytesValue.fill(0);
  for (const chunk of stdout) chunk.fill(0);
  for (const chunk of stderr) chunk.fill(0);
  if (typeof process.send === 'function') process.send(message);
  if (!expectationMatched) process.stderr.write(`${message.failureCode}\n`);
  process.exitCode = message.exitCode;
  if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
}

try {
  await runPi();
} catch (error) {
  const code = typeof error?.code === 'string' ? error.code : 'PI_PROCESS_FAILED';
  if (typeof process.send === 'function') process.send({ type: 'fatal', code });
  process.stderr.write(`${code}\n`);
  process.exitCode = 1;
  if (typeof process.disconnect === 'function' && process.connected) process.disconnect();
}

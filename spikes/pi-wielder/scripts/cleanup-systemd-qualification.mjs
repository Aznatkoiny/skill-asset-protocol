#!/usr/bin/env node
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { deploymentRendererInput, readDeploymentConfig, validateDeploymentConfig } from '../src/kernel/deployment.mjs';
import { assertLiveCleanupHost } from './cleanup-live-deployment.mjs';
import { parseSystemctlShow } from './inspect-systemd-effective.mjs';
import { renderSystemdUnits } from './render-systemd-units.mjs';

const ROOT = '/opt/wallet-kernel-qualification';
const SERVICE = 'wallet-kernel.service';
const SOCKET = 'wallet-kernel-console.socket';
const SERVICE_PROPERTIES = ['Id', 'LoadState', 'FragmentPath', 'ExecStartEx', 'ExecStopPostEx', 'ActiveState', 'MainPID', 'Job'];
const SOCKET_PROPERTIES = ['Id', 'LoadState', 'FragmentPath', 'UnitFileState', 'ActiveState', 'Job'];
const COMMANDS = [['stop', SOCKET], ['stop', SERVICE], ['disable', SOCKET]];

function failure(code) {
  const error = new Error('Disposable Wallet Kernel qualification cleanup refused');
  error.code = code;
  return error;
}
function publicCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,100}$/.test(error.code)
    ? error.code : 'QUALIFICATION_CLEANUP_FAILED';
}

function assertAncestor(location, expectedOwnerUid, anchor = '/') {
  const relative = path.relative(anchor, location);
  if (relative === '..' || relative.startsWith('../') || path.isAbsolute(relative)) throw failure('QUALIFICATION_CLEANUP_OWNER');
  let current = anchor;
  for (const component of ['', ...relative.split('/').filter(Boolean)]) {
    current = path.join(current, component);
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== expectedOwnerUid
        || (stat.mode & 0o7022) !== 0) throw failure('QUALIFICATION_CLEANUP_OWNER');
  }
}

function readArtifact(location, expectedBytes, host) {
  assertAncestor(path.dirname(location), host.expectedOwnerUid, host.expectedOwnerUid === 0 ? '/' : host.qualificationRoot);
  const descriptor = fs.openSync(location, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(descriptor, { bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(host.expectedOwnerUid)
        || (before.mode & 0o7777n) !== 0o644n || before.size > 65_536n) throw failure('QUALIFICATION_CLEANUP_OWNER');
    const bytes = fs.readFileSync(descriptor);
    const after = fs.fstatSync(descriptor, { bigint: true });
    if (!bytes.equals(expectedBytes) || ['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']
      .some((field) => before[field] !== after[field])) throw failure('QUALIFICATION_CLEANUP_OWNER');
    return { stat: before, bytes };
  } finally { fs.closeSync(descriptor); }
}

function assertHost() {
  assertLiveCleanupHost();
  assertAncestor(ROOT, 0);
  return { qualificationRoot: ROOT, nodePath: process.execPath, expectedOwnerUid: 0,
    unitDirectory: '/etc/systemd/system', scriptPath: fileURLToPath(import.meta.url) };
}

function runSystemctl(args) {
  const shows = [[SERVICE, SERVICE_PROPERTIES], [SOCKET, SOCKET_PROPERTIES]].map(([unit, properties]) =>
    ['show', '--all', '--no-pager', `--property=${properties.join(',')}`, unit]);
  if (![...COMMANDS, ...shows, ['daemon-reload']].some((expected) => expected.length === args.length
      && expected.every((value, index) => value === args[index]))) throw failure('QUALIFICATION_CLEANUP_COMMAND');
  assertAncestor('/usr/bin', 0);
  const stat = fs.lstatSync('/usr/bin/systemctl');
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== 0 || stat.nlink !== 1
      || (stat.mode & 0o7022) !== 0 || (stat.mode & 0o111) === 0) throw failure('QUALIFICATION_CLEANUP_BINARY');
  return execFileSync('/usr/bin/systemctl', args, {
    encoding: 'utf8', timeout: 10_000, maxBuffer: 16_384,
    env: { PATH: '/usr/bin:/bin', LANG: 'C', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function commandMatches(text, argv, flags) {
  if (typeof text !== 'string' || text.length > 8192 || /[\r\n\0]/.test(text)) return false;
  const match = /^\{ path=([^ ;]+) ; argv\[\]=([^;]+?) ; flags=([^;]*?) ; /.exec(text);
  return Boolean(match && match[1] === argv[0] && match[2].trim() === argv.join(' ') && match[3].trim() === flags);
}

async function observe(run) {
  const rows = [];
  for (const [unit, properties] of [[SERVICE, SERVICE_PROPERTIES], [SOCKET, SOCKET_PROPERTIES]]) {
    rows.push(parseSystemctlShow(await run(['show', '--all', '--no-pager', `--property=${properties.join(',')}`, unit]), properties));
  }
  return { service: rows[0], socket: rows[1] };
}

function assertBindings(state, config) {
  for (const [unit, id, fragment] of [
    [state.service, SERVICE, config.serviceOutputPath], [state.socket, SOCKET, config.socketOutputPath],
  ]) {
    if (unit.Id !== id || unit.LoadState !== 'loaded' || unit.FragmentPath !== fragment) throw failure('QUALIFICATION_CLEANUP_OWNER');
  }
  if (!commandMatches(state.service.ExecStartEx, [config.nodePath, `${config.releaseRoot}/src/control-plane.mjs`], '')
      || !commandMatches(state.service.ExecStopPostEx,
        [config.nodePath, `${config.releaseRoot}/scripts/cleanup-live-deployment.mjs`], 'privileged')) {
    throw failure('QUALIFICATION_CLEANUP_OWNER');
  }
}

export function qualificationListenersClosed(config) {
  for (const location of ['/proc/net/tcp', '/proc/net/tcp6']) {
    const data = fs.readFileSync(location, 'utf8');
    if (data.length > 2_097_152) throw failure('QUALIFICATION_CLEANUP_LISTENERS');
    for (const row of data.trim().split('\n').slice(1)) {
      const fields = row.trim().split(/\s+/);
      if (fields[3] === '0A' && ['20D2', '20D5'].includes(fields[1]?.split(':').at(-1))) return false;
    }
  }
  const unix = fs.readFileSync('/proc/net/unix', 'utf8');
  if (unix.length > 2_097_152) throw failure('QUALIFICATION_CLEANUP_LISTENERS');
  return !unix.trim().split('\n').slice(1).some((row) => row.trim().split(/\s+/)[7] === config.operatorSocketPath);
}

function quiescent({ service, socket }) {
  return ['inactive', 'failed'].includes(service.ActiveState) && service.MainPID === '0' && service.Job === ''
    && socket.ActiveState === 'inactive' && socket.UnitFileState === 'disabled' && socket.Job === '';
}

/** Only the fixed disposable profile; injected results remain simulated. */
export async function cleanupSystemdQualification({ deploymentPath }, effects) {
  const defaults = { assertHost, readDeployment: readDeploymentConfig, render: renderSystemdUnits,
    runSystemctl, listenersClosed: qualificationListenersClosed,
    now: () => Date.now(), sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)) };
  if (effects !== undefined && (!effects || typeof effects !== 'object' || Array.isArray(effects)
      || Reflect.ownKeys(effects).some((name) => !Object.hasOwn(defaults, name)
        || typeof effects[name] !== 'function'))) throw failure('QUALIFICATION_CLEANUP_ARGUMENTS');
  const io = { ...defaults, ...effects };
  const host = io.assertHost();
  const config = validateDeploymentConfig(io.readDeployment(deploymentPath));
  if (config.executionProfile !== 'offline-qualification'
      || config.releaseRoot !== path.join(host.qualificationRoot, 'releases', config.commit)
      || deploymentPath !== path.join(config.releaseRoot, 'deployment.json')
      || config.nodePath !== path.join(host.qualificationRoot, 'node/bin/node') || config.nodePath !== host.nodePath
      || host.scriptPath !== path.join(config.releaseRoot, 'scripts/cleanup-systemd-qualification.mjs')
      || config.serviceOutputPath !== path.join(host.unitDirectory, SERVICE)
      || config.socketOutputPath !== path.join(host.unitDirectory, SOCKET)) throw failure('QUALIFICATION_CLEANUP_SCOPE');
  const rendered = io.render(deploymentRendererInput(config));
  const artifacts = [
    [config.serviceOutputPath, rendered.serviceBytes], [config.socketOutputPath, rendered.socketBytes],
  ].map(([location, bytes]) => ({ location, bytes, captured: readArtifact(location, bytes, host) }));
  assertBindings(await observe(io.runSystemctl), config);
  const attempts = [];
  let firstError;
  for (const args of COMMANDS) {
    try { await io.runSystemctl([...args]); attempts.push({ action: args.join(' '), status: 'completed' }); }
    catch (error) { firstError ??= error; attempts.push({ action: args.join(' '), status: 'failed', code: publicCode(error) }); }
  }
  const deadline = io.now() + 15_000;
  let stopped = false;
  for (let attempt = 0; attempt < 61; attempt += 1) {
    try {
      const state = await observe(io.runSystemctl);
      assertBindings(state, config);
      if (quiescent(state) && await io.listenersClosed(config)) { stopped = true; break; }
    } catch (error) {
      firstError ??= error;
      break;
    }
    if (io.now() >= deadline) break;
    await io.sleep(250);
  }
  if (!stopped) firstError ??= failure('QUALIFICATION_CLEANUP_NOT_QUIESCENT');
  if (firstError) {
    const error = failure(publicCode(firstError));
    error.attempts = attempts;
    throw error;
  }
  // Recheck both owned inodes before deleting either. Never remove an unrelated
  // replacement or mask failed stop/disable commands by deleting unit files.
  for (const item of artifacts) {
    const fresh = readArtifact(item.location, item.bytes, host);
    if (['dev', 'ino', 'mode', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']
      .some((field) => fresh.stat[field] !== item.captured.stat[field])) throw failure('QUALIFICATION_CLEANUP_OWNER');
  }
  for (const item of artifacts) {
    try { fs.unlinkSync(item.location); }
    catch (error) { firstError ??= error; }
  }
  try { await io.runSystemctl(['daemon-reload']); }
  catch (error) { firstError ??= error; }
  if (firstError) throw failure(publicCode(firstError));
  return Object.freeze({ schemaVersion: 1, execution: effects === undefined ? 'installed' : 'simulated',
    status: 'removed_after_quiescence', qualification: 'not_performed', attempts: Object.freeze(attempts) });
}

export async function runCleanupSystemdQualification({ argv, stdout = process.stdout, stderr = process.stderr }) {
  try {
    if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--deployment') throw failure('QUALIFICATION_CLEANUP_ARGUMENTS');
    stdout.write(`${JSON.stringify(await cleanupSystemdQualification({ deploymentPath: argv[1] }))}\n`);
    return 0;
  } catch (error) {
    stderr.write(`${JSON.stringify({ code: publicCode(error), attempts: error.attempts ?? [] })}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await runCleanupSystemdQualification({ argv: process.argv.slice(2) });
}

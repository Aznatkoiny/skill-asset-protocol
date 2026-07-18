import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const GIT_CONTEXT_KEYS = [
  'GIT_DIR',
  'GIT_WORK_TREE',
  'GIT_INDEX_FILE',
  'GIT_OBJECT_DIRECTORY',
  'GIT_COMMON_DIR',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
];

function cleanGitEnvironment() {
  const env = { ...process.env };
  for (const key of GIT_CONTEXT_KEYS) delete env[key];
  return env;
}

function runGit(repoRoot, args) {
  const result = spawnSync('git', args, {
    cwd: repoRoot,
    encoding: 'utf8',
    env: cleanGitEnvironment(),
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (result.error || result.status !== 0) {
    const detail = typeof result.stderr === 'string' ? result.stderr.trim() : '';
    throw new Error(`Unable to read exact committed git HEAD${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout.replace(/\r?\n$/, '');
}

export function readGitState(repoRoot) {
  if (typeof repoRoot !== 'string' || repoRoot === '') {
    throw new Error('Git repository root is required');
  }
  const resolved = path.resolve(repoRoot);
  let stat;
  try {
    stat = fs.lstatSync(resolved);
  } catch {
    throw new Error('Git repository root must be a real directory');
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) {
    throw new Error('Git repository root must be a real directory');
  }
  const gitCommit = runGit(resolved, ['rev-parse', '--verify', 'HEAD']);
  if (!/^[0-9a-f]{40}$/.test(gitCommit)) {
    throw new Error('Unable to read exact committed git HEAD');
  }
  const porcelain = runGit(resolved, ['status', '--porcelain=v1', '--untracked-files=all']);
  return {
    gitCommit,
    gitDirty: porcelain !== '',
    porcelain,
  };
}

export function assertLiveCheckoutClean(gitState) {
  if (!gitState || !/^[0-9a-f]{40}$/.test(gitState.gitCommit ?? '')
      || typeof gitState.gitDirty !== 'boolean') {
    throw new Error('Live sweep requires an exact captured git state');
  }
  if (gitState.gitDirty) {
    throw new Error('Live sweep requires a clean checkout before provider execution');
  }
  return gitState;
}

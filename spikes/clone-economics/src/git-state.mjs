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
  env.GIT_NO_REPLACE_OBJECTS = '1';
  return env;
}

function spawnGit(repoRoot, args, encoding = 'utf8') {
  const result = spawnSync('git', args, {
    cwd: repoRoot,
    encoding,
    env: cleanGitEnvironment(),
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  return result;
}

function runGit(repoRoot, args) {
  const result = spawnGit(repoRoot, args);
  if (result.error || result.status !== 0) {
    const detail = typeof result.stderr === 'string' ? result.stderr.trim() : '';
    throw new Error(`Unable to read exact committed git HEAD${detail ? `: ${detail}` : ''}`);
  }
  return result.stdout.replace(/\r?\n$/, '');
}

function safeRecordedCommit(value) {
  if (typeof value !== 'string' || !/^[0-9a-f]{40}$/.test(value)) {
    throw new Error('Recorded git commit does not resolve to a commit');
  }
  return value;
}

export function resolveGitCommit(repoRoot, recordedCommit) {
  const commit = safeRecordedCommit(recordedCommit);
  const result = spawnGit(repoRoot, ['cat-file', '-t', commit]);
  if (result.error || result.status !== 0 || result.stdout.trim() !== 'commit') {
    throw new Error('Recorded git commit does not resolve to a commit');
  }
  return commit;
}

export function gitRepositoryRoot(repoRoot) {
  const result = spawnGit(repoRoot, ['rev-parse', '--show-toplevel']);
  if (result.error || result.status !== 0) {
    throw new Error('Unable to resolve git repository root');
  }
  return path.resolve(result.stdout.replace(/\r?\n$/, ''));
}

export function readGitBlobAtCommit(repoRoot, recordedCommit, repositoryRelativePath) {
  const commit = resolveGitCommit(repoRoot, recordedCommit);
  if (typeof repositoryRelativePath !== 'string'
      || repositoryRelativePath.length === 0
      || repositoryRelativePath.length > 512
      || path.isAbsolute(repositoryRelativePath)
      || repositoryRelativePath.includes('\\')
      || repositoryRelativePath.split('/').includes('..')
      || !/^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(repositoryRelativePath)) {
    throw new Error('Expected a safe repository-relative committed blob path');
  }
  const tree = spawnGit(repoRoot, ['ls-tree', commit, '--', repositoryRelativePath]);
  if (tree.error || tree.status !== 0) {
    throw new Error('Unable to inspect committed blob');
  }
  const match = tree.stdout.match(/^100(?:644|755) blob ([0-9a-f]{40})\t(.+)\n?$/);
  if (!match || match[2] !== repositoryRelativePath) {
    throw new Error('Recorded tree path must resolve to one regular committed blob');
  }
  const blob = spawnGit(repoRoot, ['cat-file', 'blob', match[1]], null);
  if (blob.error || blob.status !== 0 || !Buffer.isBuffer(blob.stdout)) {
    throw new Error('Unable to read committed blob');
  }
  return blob.stdout;
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

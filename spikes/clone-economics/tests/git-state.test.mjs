import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  assertLiveCheckoutClean,
  readGitBlobAtCommit,
  readGitState,
  resolveGitCommit,
} from '../src/git-state.mjs';

function git(cwd, args) {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    shell: false,
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

function committedRepo(t, name = 'repo') {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-git-state-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  const repo = path.join(parent, name);
  fs.mkdirSync(repo);
  git(repo, ['init']);
  git(repo, ['config', 'user.name', 'Evidence Test']);
  git(repo, ['config', 'user.email', 'evidence@example.invalid']);
  fs.writeFileSync(path.join(repo, 'tracked.txt'), 'committed\n');
  git(repo, ['add', 'tracked.txt']);
  git(repo, ['commit', '-m', 'fixture']);
  return { parent, repo };
}

test('readGitState captures an exact clean 40-hex commit', (t) => {
  const { repo } = committedRepo(t);
  const expected = git(repo, ['rev-parse', '--verify', 'HEAD']);
  assert.deepEqual(readGitState(repo), {
    gitCommit: expected,
    gitDirty: false,
    porcelain: '',
  });
  assert.match(expected, /^[0-9a-f]{40}$/);
});

test('readGitState includes tracked changes and untracked files', (t) => {
  const { repo } = committedRepo(t);
  fs.appendFileSync(path.join(repo, 'tracked.txt'), 'dirty\n');
  fs.writeFileSync(path.join(repo, 'untracked.txt'), 'untracked\n');
  const state = readGitState(repo);
  assert.equal(state.gitDirty, true);
  assert.equal(state.porcelain, ' M tracked.txt\n?? untracked.txt');
});

test('readGitState passes metacharacter paths as argv without command execution', (t) => {
  const { parent, repo } = committedRepo(t, 'repo;touch injected-marker');
  const marker = path.join(parent, 'injected-marker');
  assert.match(readGitState(repo).gitCommit, /^[0-9a-f]{40}$/);
  assert.equal(fs.existsSync(marker), false);
});

test('readGitState rejects repositories without an exact HEAD identity', (t) => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'clone-git-empty-'));
  t.after(() => fs.rmSync(parent, { recursive: true, force: true }));
  git(parent, ['init']);
  assert.throws(() => readGitState(parent), /exact committed git HEAD/i);
});

test('live checkout gate rejects a captured dirty state', () => {
  assert.throws(
    () => assertLiveCheckoutClean({ gitCommit: 'a'.repeat(40), gitDirty: true, porcelain: '?? untracked' }),
    /clean checkout before provider execution/,
  );
  assert.doesNotThrow(
    () => assertLiveCheckoutClean({ gitCommit: 'a'.repeat(40), gitDirty: false, porcelain: '' }),
  );
});

test('recorded commit resolution rejects nonexistent object IDs', (t) => {
  const { repo } = committedRepo(t);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  assert.equal(resolveGitCommit(repo, commit), commit);
  assert.throws(
    () => resolveGitCommit(repo, '0'.repeat(40)),
    /recorded git commit does not resolve to a commit/i,
  );
});

test('committed blobs are read from the recorded tree, not the working copy', (t) => {
  const { repo } = committedRepo(t);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(repo, 'tracked.txt'), 'working-copy-only\n');
  assert.equal(readGitBlobAtCommit(repo, commit, 'tracked.txt').toString('utf8'), 'committed\n');
  assert.throws(
    () => readGitBlobAtCommit(repo, commit, '../outside.txt'),
    /repository-relative committed blob path/i,
  );
});

test('commit replacement refs cannot change recorded-tree bytes', (t) => {
  const { repo } = committedRepo(t);
  const recordedCommit = git(repo, ['rev-parse', 'HEAD']);
  fs.writeFileSync(path.join(repo, 'tracked.txt'), 'replacement-commit\n');
  git(repo, ['add', 'tracked.txt']);
  git(repo, ['commit', '-m', 'replacement commit']);
  const replacementCommit = git(repo, ['rev-parse', 'HEAD']);
  git(repo, ['replace', recordedCommit, replacementCommit]);

  assert.equal(
    readGitBlobAtCommit(repo, recordedCommit, 'tracked.txt').toString('utf8'),
    'committed\n',
  );
});

test('blob replacement refs cannot change recorded-tree bytes', (t) => {
  const { repo } = committedRepo(t);
  const recordedCommit = git(repo, ['rev-parse', 'HEAD']);
  const recordedBlob = git(repo, ['rev-parse', 'HEAD:tracked.txt']);
  const replacementPath = path.join(repo, 'replacement.txt');
  fs.writeFileSync(replacementPath, 'replacement-blob\n');
  const replacementBlob = git(repo, ['hash-object', '-w', 'replacement.txt']);
  git(repo, ['replace', recordedBlob, replacementBlob]);

  assert.equal(
    readGitBlobAtCommit(repo, recordedCommit, 'tracked.txt').toString('utf8'),
    'committed\n',
  );
});

test('blob-to-commit replacement refs cannot forge commit resolution', (t) => {
  const { repo } = committedRepo(t);
  const commit = git(repo, ['rev-parse', 'HEAD']);
  const blob = git(repo, ['rev-parse', 'HEAD:tracked.txt']);
  git(repo, ['update-ref', `refs/replace/${blob}`, commit]);
  assert.throws(
    () => resolveGitCommit(repo, blob),
    /recorded git commit does not resolve to a commit/i,
  );
});

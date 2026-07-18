import { promisify } from 'node:util';
import { execFile } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const execFileAsync = promisify(execFile);
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = join(SCRIPT_DIRECTORY, '..', '..');

export const HF_SPACE_ALLOWED_PATHS = Object.freeze([
  'hf-space/scripts/generate-accounting-fixture.mjs',
  'hf-space/scripts/test-generate-accounting-fixture.mjs',
  'hf-space/scripts/package-space-fixtures.mjs',
  'hf-space/scripts/test-package-space-fixtures.mjs',
  'hf-space/scripts/verify-local-scope.mjs',
  'hf-space/shared/public-demo-allocation.json',
  'hf-space/shared/evidence.json',
  'hf-space/gradio/demo_logic.py',
  'hf-space/gradio/test_demo_logic.py',
  'hf-space/gradio/test_app_smoke.py',
  'hf-space/gradio/app.py',
  'hf-space/gradio/README.md',
  'hf-space/gradio/requirements.txt',
  'hf-space/gradio/data/public-demo-allocation.json',
  'hf-space/gradio/data/evidence.json',
  'hf-space/gradio/data/fixture-integrity.json',
  'hf-space/static/demo-logic.mjs',
  'hf-space/static/test-demo-logic.mjs',
  'hf-space/static/test-index-smoke.mjs',
  'hf-space/static/index.html',
  'hf-space/static/README.md',
  'hf-space/static/package.json',
  'hf-space/static/package-lock.json',
  'hf-space/static/data/public-demo-allocation.json',
  'hf-space/static/data/evidence.json',
  'hf-space/static/data/fixture-integrity.json',
].sort());

function requireExactScope(paths, mode) {
  const sorted = [...paths].sort();
  const duplicates = sorted.filter((path, index) => index > 0 && path === sorted[index - 1]);
  if (duplicates.length > 0) throw new Error(`${mode} scope contains duplicate paths`);
  const allowed = new Set(HF_SPACE_ALLOWED_PATHS);
  const actual = new Set(sorted);
  const extra = sorted.filter((path) => !allowed.has(path));
  const missing = HF_SPACE_ALLOWED_PATHS.filter((path) => !actual.has(path));
  if (extra.length > 0 || missing.length > 0) {
    throw new Error(
      `${mode} hf-space scope mismatch; extra=[${extra.join(', ')}] missing=[${missing.join(', ')}]`,
    );
  }
  return Object.freeze(sorted);
}

function parseStatus(stdout) {
  if (!stdout) return [];
  const lines = stdout.endsWith('\n') ? stdout.slice(0, -1).split('\n') : stdout.split('\n');
  return lines.map((line) => {
    if (line.length < 4 || line[2] !== ' ') throw new Error('malformed git status line');
    const status = line.slice(0, 2);
    const path = line.slice(3);
    if (/[RC]/.test(status) || path.includes(' -> ')) {
      throw new Error('rename/copy records are not allowed in hf-space scope');
    }
    if (!path.startsWith('hf-space/') || path.endsWith('/') || path.startsWith('"')) {
      throw new Error(`unsupported hf-space status path: ${path}`);
    }
    return path;
  });
}

async function normalPaths() {
  const { stdout } = await execFileAsync(
    'git',
    ['status', '--porcelain=v1', '--untracked-files=all', '--', 'hf-space'],
    { cwd: REPOSITORY_ROOT, encoding: 'utf8', maxBuffer: 1_000_000 },
  );
  return parseStatus(stdout);
}

async function cachedPaths() {
  const { stdout } = await execFileAsync(
    'git',
    ['diff', '--cached', '--name-only', '-z', '--', 'hf-space'],
    { cwd: REPOSITORY_ROOT, encoding: 'utf8', maxBuffer: 1_000_000 },
  );
  if (!stdout) return [];
  if (!stdout.endsWith('\0')) throw new Error('malformed cached path output');
  const paths = stdout.slice(0, -1).split('\0');
  for (const path of paths) {
    if (!path.startsWith('hf-space/') || path.endsWith('/')) {
      throw new Error(`unsupported cached hf-space path: ${path}`);
    }
  }
  return paths;
}

export async function main(argv = process.argv.slice(2)) {
  if (argv.length > 1 || (argv.length === 1 && argv[0] !== '--cached')) {
    throw new TypeError('usage: verify-local-scope.mjs [--cached]');
  }
  const mode = argv[0] === '--cached' ? 'cached' : 'working-tree';
  const paths = requireExactScope(
    mode === 'cached' ? await cachedPaths() : await normalPaths(),
    mode,
  );
  process.stdout.write(`${paths.join('\n')}\n`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

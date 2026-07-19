import { createHash, randomUUID } from 'node:crypto';
import {
  mkdir,
  open,
  readFile,
  rename,
  unlink,
} from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const HF_SPACE_ROOT = join(SCRIPT_DIRECTORY, '..');
const PRODUCTION_CONFIGURATION = Object.freeze({
  canonicalRoot: join(HF_SPACE_ROOT, 'shared'),
  spaceRoots: Object.freeze([
    join(HF_SPACE_ROOT, 'gradio'),
    join(HF_SPACE_ROOT, 'static'),
  ]),
});
const FIXTURE_NAMES = Object.freeze(['evidence.json', 'public-demo-allocation.json']);

function canonicalize(value) {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value).sort().map((key) => [key, canonicalize(value[key])]),
    );
  }
  return value;
}

export function canonicalIntegrityBytes(value) {
  return `${JSON.stringify(canonicalize(value), null, 2)}\n`;
}

function requireConfiguration({ canonicalRoot, spaceRoots }) {
  if (typeof canonicalRoot !== 'string' || canonicalRoot.length === 0) {
    throw new TypeError('canonicalRoot must be a non-empty path');
  }
  if (!Array.isArray(spaceRoots) || spaceRoots.length !== 2
      || spaceRoots.some((root) => typeof root !== 'string' || root.length === 0)
      || new Set(spaceRoots).size !== spaceRoots.length) {
    throw new TypeError('spaceRoots must contain two distinct paths');
  }
  return { canonicalRoot, spaceRoots: [...spaceRoots] };
}

export async function buildPackagePlan(configuration = PRODUCTION_CONFIGURATION) {
  const { canonicalRoot, spaceRoots } = requireConfiguration(configuration);
  const canonicalFiles = Object.create(null);
  for (const fileName of FIXTURE_NAMES) {
    const bytes = await readFile(join(canonicalRoot, fileName));
    if (bytes.length === 0 || bytes[bytes.length - 1] !== 0x0a) {
      throw new Error(`canonical fixture must end with one newline: ${fileName}`);
    }
    if (bytes.length > 1 && bytes[bytes.length - 2] === 0x0a) {
      throw new Error(`canonical fixture must end with one newline: ${fileName}`);
    }
    canonicalFiles[fileName] = bytes;
  }
  const integrity = {
    schemaVersion: 1,
    generatedBy: 'hf-space/scripts/package-space-fixtures.mjs',
    files: Object.fromEntries(FIXTURE_NAMES.map((fileName) => [
      fileName,
      {
        sha256: `sha256:${createHash('sha256').update(canonicalFiles[fileName]).digest('hex')}`,
        bytes: canonicalFiles[fileName].length,
      },
    ])),
  };
  const integrityBytes = Buffer.from(canonicalIntegrityBytes(integrity), 'utf8');
  const plan = [];
  for (const spaceRoot of spaceRoots) {
    const rootName = basename(spaceRoot);
    for (const fileName of FIXTURE_NAMES) {
      plan.push(Object.freeze({
        spaceRoot,
        targetPath: join(spaceRoot, 'data', fileName),
        relativePath: `${rootName}/data/${fileName}`,
        bytes: canonicalFiles[fileName],
      }));
    }
    plan.push(Object.freeze({
      spaceRoot,
      targetPath: join(spaceRoot, 'data', 'fixture-integrity.json'),
      relativePath: `${rootName}/data/fixture-integrity.json`,
      bytes: integrityBytes,
    }));
  }
  return Object.freeze(plan);
}

async function writeFully(handle, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset);
    if (bytesWritten <= 0) throw new Error('short write while packaging fixtures');
    offset += bytesWritten;
  }
}

async function writePlan(plan) {
  const prepared = [];
  try {
    for (const item of plan) {
      await mkdir(dirname(item.targetPath), { recursive: true });
      const temporaryPath = `${item.targetPath}.tmp-${process.pid}-${randomUUID()}`;
      const handle = await open(temporaryPath, 'wx', 0o600);
      try {
        await writeFully(handle, item.bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      prepared.push({ temporaryPath, targetPath: item.targetPath });
    }
    for (const item of prepared) await rename(item.temporaryPath, item.targetPath);
  } catch (error) {
    await Promise.all(prepared.map(({ temporaryPath }) => unlink(temporaryPath).catch(() => {})));
    throw error;
  }
}

async function checkPlan(plan) {
  for (const item of plan) {
    const actual = await readFile(item.targetPath).catch(() => null);
    if (!actual || !actual.equals(item.bytes)) {
      throw new Error(`standalone Space fixture drift: ${item.relativePath}`);
    }
  }
}

export async function main(argv = process.argv.slice(2), configuration = PRODUCTION_CONFIGURATION) {
  if (argv.length !== 1 || !['--write', '--check'].includes(argv[0])) {
    throw new TypeError('usage: package-space-fixtures.mjs --write|--check');
  }
  const plan = await buildPackagePlan(configuration);
  if (argv[0] === '--write') await writePlan(plan);
  else await checkPlan(plan);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

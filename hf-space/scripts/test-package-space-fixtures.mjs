import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  mkdtemp,
  mkdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';

import {
  buildPackagePlan,
  canonicalIntegrityBytes,
  main,
} from './package-space-fixtures.mjs';

const productionShared = new URL('../shared/', import.meta.url);

async function temporaryPackageRoots() {
  const root = await mkdtemp(join(tmpdir(), 'space-package-test-'));
  const canonicalRoot = join(root, 'shared');
  const spaceRoots = [join(root, 'gradio'), join(root, 'static')];
  await mkdir(canonicalRoot, { recursive: true });
  for (const fileName of ['public-demo-allocation.json', 'evidence.json']) {
    await writeFile(
      join(canonicalRoot, fileName),
      await readFile(new URL(fileName, productionShared)),
    );
  }
  return { root, canonicalRoot, spaceRoots };
}

test('packager writes byte-identical fixtures and deterministic integrity manifests', async (t) => {
  const temporary = await temporaryPackageRoots();
  t.after(() => rm(temporary.root, { recursive: true, force: true }));
  const configuration = {
    canonicalRoot: temporary.canonicalRoot,
    spaceRoots: temporary.spaceRoots,
  };
  const plan = await buildPackagePlan(configuration);
  assert.equal(plan.length, 6);
  assert.deepEqual(
    plan.map((item) => item.relativePath).sort(),
    [
      'gradio/data/evidence.json',
      'gradio/data/fixture-integrity.json',
      'gradio/data/public-demo-allocation.json',
      'static/data/evidence.json',
      'static/data/fixture-integrity.json',
      'static/data/public-demo-allocation.json',
    ],
  );

  await main(['--write'], configuration);
  await main(['--check'], configuration);

  for (const spaceRoot of temporary.spaceRoots) {
    for (const fileName of ['public-demo-allocation.json', 'evidence.json']) {
      assert.deepEqual(
        await readFile(join(spaceRoot, 'data', fileName)),
        await readFile(join(temporary.canonicalRoot, fileName)),
      );
    }
  }
  const gradioManifest = await readFile(join(temporary.spaceRoots[0], 'data', 'fixture-integrity.json'));
  const staticManifest = await readFile(join(temporary.spaceRoots[1], 'data', 'fixture-integrity.json'));
  assert.deepEqual(gradioManifest, staticManifest);
  const parsed = JSON.parse(gradioManifest);
  assert.deepEqual(Object.keys(parsed.files), ['evidence.json', 'public-demo-allocation.json']);
  for (const [fileName, metadata] of Object.entries(parsed.files)) {
    const bytes = await readFile(join(temporary.canonicalRoot, fileName));
    assert.equal(metadata.bytes, bytes.length);
    assert.equal(
      metadata.sha256,
      `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
    );
  }
  assert.deepEqual(Buffer.from(canonicalIntegrityBytes(parsed)), gradioManifest);
});

test('check mode is cwd-independent and fails on fixture or manifest drift', async (t) => {
  const temporary = await temporaryPackageRoots();
  t.after(() => rm(temporary.root, { recursive: true, force: true }));
  const configuration = {
    canonicalRoot: temporary.canonicalRoot,
    spaceRoots: temporary.spaceRoots,
  };
  await main(['--write'], configuration);
  const originalCwd = process.cwd();
  try {
    process.chdir(tmpdir());
    await main(['--check'], configuration);
  } finally {
    process.chdir(originalCwd);
  }

  const allocationPath = join(temporary.spaceRoots[0], 'data', 'public-demo-allocation.json');
  const originalAllocation = await readFile(allocationPath);
  await writeFile(allocationPath, Buffer.concat([originalAllocation, Buffer.from(' ')]));
  await assert.rejects(() => main(['--check'], configuration), /standalone Space fixture drift/);
  await writeFile(allocationPath, originalAllocation);

  const manifestPath = join(temporary.spaceRoots[1], 'data', 'fixture-integrity.json');
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
  manifest.files['evidence.json'].sha256 = `sha256:${'0'.repeat(64)}`;
  await writeFile(manifestPath, canonicalIntegrityBytes(manifest));
  await assert.rejects(() => main(['--check'], configuration), /standalone Space fixture drift/);
});

test('packaging plan has no sibling or repository-relative runtime dependency', async (t) => {
  const temporary = await temporaryPackageRoots();
  t.after(() => rm(temporary.root, { recursive: true, force: true }));
  const plan = await buildPackagePlan({
    canonicalRoot: temporary.canonicalRoot,
    spaceRoots: temporary.spaceRoots,
  });
  for (const item of plan) {
    assert.ok(['gradio', 'static'].includes(basename(item.spaceRoot)));
    assert.doesNotMatch(item.relativePath, /\.\.|shared|hf-space/i);
    assert.doesNotMatch(item.bytes.toString('utf8'), /\.\.\/shared|hf-space\/(gradio|static)/i);
  }
});

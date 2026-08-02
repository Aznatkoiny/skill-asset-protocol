#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import { buildReleaseManifest } from '../src/kernel/release-integrity.mjs';

function readCanonicalInput(filePath) {
  if (typeof filePath !== 'string' || !path.isAbsolute(filePath) || path.resolve(filePath) !== filePath) {
    throw new Error('manifest build input path must be canonical and absolute');
  }
  const descriptor = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size <= 0 || stat.size > 64 * 1024) {
      throw new Error('manifest build input must be one bounded regular file');
    }
    const bytes = fs.readFileSync(descriptor);
    const value = JSON.parse(bytes.toString('utf8'));
    if (!bytes.equals(Buffer.from(`${canonicalJson(value)}\n`))) {
      throw new Error('manifest build input must be canonical JSON plus one newline');
    }
    return value;
  } finally { fs.closeSync(descriptor); }
}

export function writeReleaseManifestExclusive({ manifestPath, manifest }) {
  if (typeof manifestPath !== 'string' || !path.isAbsolute(manifestPath)
      || path.resolve(manifestPath) !== manifestPath) {
    throw new Error('release manifest output path must be canonical and absolute');
  }
  const bytes = Buffer.from(`${canonicalJson(manifest)}\n`);
  const descriptor = fs.openSync(manifestPath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW,
    0o644);
  try {
    fs.writeFileSync(descriptor, bytes);
    fs.fsyncSync(descriptor);
  } finally { fs.closeSync(descriptor); }
  const parent = fs.openSync(path.dirname(manifestPath),
    fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW);
  try { fs.fsyncSync(parent); } finally { fs.closeSync(parent); }
  return bytes.length;
}

export function runBuildReleaseManifest({ argv, stdout = process.stdout, stderr = process.stderr }) {
  try {
    if (!Array.isArray(argv) || argv.length !== 2 || argv[0] !== '--input') {
      throw new Error('usage: build-release-manifest.mjs --input ABSOLUTE_CANONICAL_JSON');
    }
    if (process.getuid?.() !== 0 && process.env.WALLET_KERNEL_DETERMINISTIC_BUILD !== '1') {
      throw new Error('live release manifest creation requires root');
    }
    const input = readCanonicalInput(argv[1]);
    const manifest = buildReleaseManifest(input);
    writeReleaseManifestExclusive({ manifestPath: input.manifestPath, manifest });
    stdout.write(`${manifest.releaseTreeHash}\n`);
    return 0;
  } catch (error) {
    stderr.write(`release manifest build failed: ${error?.code ?? 'ERROR'}\n`);
    return 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = runBuildReleaseManifest({ argv: process.argv.slice(2) });
}

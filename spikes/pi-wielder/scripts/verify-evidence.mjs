#!/usr/bin/env node

import path from 'node:path';
import { pathToFileURL } from 'node:url';

import { canonicalJson } from '../src/kernel/canonical.mjs';
import {
  EvidenceError,
  verifyEvidenceBundle,
} from '../src/evidence-bundle.mjs';

function failArguments() {
  const error = new Error(
    'usage: verify-evidence.mjs DIRECTORY --expect-manifest-sha256 64-lowercase-hex',
  );
  error.code = 'EVIDENCE_CLI_ARGUMENTS';
  throw error;
}

export function parseVerifyEvidenceArguments(argv) {
  if (!Array.isArray(argv) || argv.length !== 3 || argv[1] !== '--expect-manifest-sha256'
      || typeof argv[0] !== 'string' || argv[0].length === 0
      || typeof argv[2] !== 'string' || !/^[0-9a-f]{64}$/.test(argv[2])) {
    failArguments();
  }
  return Object.freeze({
    directory: path.resolve(argv[0]),
    expectedManifestSha256: argv[2],
  });
}

export function main(argv = process.argv.slice(2)) {
  try {
    const options = parseVerifyEvidenceArguments(argv);
    const result = verifyEvidenceBundle(options.directory, options);
    process.stdout.write(`${canonicalJson(result)}\n`);
    return 0;
  } catch (error) {
    const code = error instanceof EvidenceError || typeof error?.code === 'string'
      ? error.code
      : 'EVIDENCE_INTERNAL';
    process.stderr.write(`${canonicalJson({ valid: false, code })}\n`);
    return code === 'EVIDENCE_CLI_ARGUMENTS' ? 2 : 1;
  }
}

const invokedPath = process.argv[1] ? pathToFileURL(path.resolve(process.argv[1])).href : null;
if (invokedPath === import.meta.url) process.exitCode = main();

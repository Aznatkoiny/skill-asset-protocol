import path from 'node:path';

import { verifyEvidenceBundle } from '../src/evidence.mjs';

const input = process.argv[2];
if (!input || process.argv.length !== 3) {
  console.error('Usage: node scripts/verify-bundle.mjs <evidence-directory>');
  process.exitCode = 1;
} else {
  try {
    const verified = verifyEvidenceBundle(path.resolve(input));
    console.log(`PASS — ${verified.manifest.experimentId} recomputes from ${verified.samples.length} normalized samples.`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}

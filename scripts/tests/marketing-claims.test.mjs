import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { auditFiles, readHistoricalTombstone } from '../marketing-claims.mjs';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const publicationFiles = [
  'docs/marketing/linkedin.md',
  'docs/marketing/x.md',
  'docs/marketing/hn-and-demo.md',
  'docs/marketing/2026-07-13-campaign-plan.md',
];

test('tracked publication drafts contain no quarantined claims', () => {
  assert.deepEqual(auditFiles(repoRoot, publicationFiles), []);
});

test('the pi overhead tombstone is historical, unreproducible, and sample-free', () => {
  const manifest = readHistoricalTombstone(repoRoot);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.experimentId, '2026-07-15-overhead');
  assert.equal(manifest.evidenceStatus, 'historical_unreproducible');
  assert.equal(manifest.publication.allowed, false);
  assert.equal(manifest.rawEvidence.normalizedSamplesCommitted, false);
  assert.equal(manifest.rawEvidence.recomputableFromCleanCheckout, false);
  assert.equal('samples' in manifest, false);
  assert.equal(
    fs.existsSync(path.join(repoRoot, 'spikes/pi-wielder/evidence/2026-07-15-overhead/samples.jsonl')),
    false,
  );
});

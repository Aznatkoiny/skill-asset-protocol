import assert from 'node:assert/strict';
import test from 'node:test';

import { assertArtifactNotSerialized } from '../src/artifact-boundary.mjs';

const artifact = 'A'.repeat(220) + '\nSECRET-RULE\n' + 'B'.repeat(220);

test('rejects the full artifact and long exact boundary fragments', () => {
  assert.throws(
    () => assertArtifactNotSerialized({ output: artifact, artifact }),
    /direct artifact serialization/,
  );
  assert.throws(
    () => assertArtifactNotSerialized({ output: artifact.slice(0, 220), artifact }),
    /direct artifact serialization/,
  );
  assert.throws(
    () => assertArtifactNotSerialized({ output: artifact.slice(-220), artifact }),
    /direct artifact serialization/,
  );
});

test('permits ordinary derived output and states the limit of the check', () => {
  assert.equal(assertArtifactNotSerialized({
    output: 'A concise optimized prompt derived from the Skill behavior.', artifact,
  }), true);
});

test('requires direct string inputs and rejects inherited boundary fields', () => {
  assert.throws(
    () => assertArtifactNotSerialized({ output: Buffer.from('derived'), artifact }),
    /exact string inputs/,
  );
  assert.throws(
    () => assertArtifactNotSerialized(Object.assign(Object.create({ output: artifact }), { artifact })),
    /exact plain object/,
  );
});

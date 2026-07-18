import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const normalizedInputHash = (value) => `sha256:${createHash('sha256')
  .update(value.trim().replace(/\s+/g, ' ').toLowerCase()).digest('hex')}`;

export function loadFixtureSet(root, name) {
  const train = JSON.parse(fs.readFileSync(path.join(root, `fixtures/train-${name}.json`), 'utf8'));
  const heldout = JSON.parse(fs.readFileSync(path.join(root, `fixtures/heldout-${name}.json`), 'utf8'));
  const decorate = (items) => items.map((item) => ({ ...item, inputHash: normalizedInputHash(item.input) }));
  const decoratedTrain = decorate(train);
  const decoratedHeldout = decorate(heldout);
  const trainIds = new Set(decoratedTrain.map((x) => x.id));
  const trainHashes = new Set(decoratedTrain.map((x) => x.inputHash));
  const disjoint = decoratedHeldout.every((x) => !trainIds.has(x.id) && !trainHashes.has(x.inputHash));
  if (!disjoint) throw new Error('Train and heldout fixtures must be disjoint by ID and normalized-input hash');
  return { train: decoratedTrain, heldout: decoratedHeldout, disjoint };
}

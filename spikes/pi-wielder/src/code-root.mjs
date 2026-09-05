import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Code is forbidden private storage, in either the source or installed layout. */
export function codeBoundaryRoot(packageRoot = fileURLToPath(new URL('../', import.meta.url))) {
  const root = fs.realpathSync(packageRoot);
  return path.basename(root) === 'pi-wielder'
      && path.basename(path.dirname(root)) === 'spikes'
    ? path.resolve(root, '../..')
    : root;
}

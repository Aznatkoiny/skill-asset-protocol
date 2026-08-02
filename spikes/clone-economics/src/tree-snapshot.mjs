import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function treeSnapshot(directory) {
  if (!fs.existsSync(directory)) return [];
  const entries = [];

  function visit(current, relative) {
    const stats = fs.lstatSync(current);
    if (stats.isSymbolicLink()) {
      const target = fs.readlinkSync(current);
      entries.push({ path: relative, type: 'symlink', bytes: Buffer.byteLength(target), sha256: sha256(target) });
      return;
    }
    if (stats.isDirectory()) {
      if (relative) entries.push({ path: relative, type: 'directory' });
      for (const name of fs.readdirSync(current).sort()) {
        visit(path.join(current, name), relative ? `${relative}/${name}` : name);
      }
      return;
    }
    if (!stats.isFile()) throw new Error(`Unsupported retained-run entry type: ${relative}`);
    const bytes = fs.readFileSync(current);
    entries.push({ path: relative, type: 'file', bytes: bytes.length, sha256: sha256(bytes) });
  }

  visit(directory, '');
  return entries;
}

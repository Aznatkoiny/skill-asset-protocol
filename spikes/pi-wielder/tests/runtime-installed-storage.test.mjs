import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { codeBoundaryRoot } from '../src/code-root.mjs';

test('code boundary retains the whole checkout but only an installed release directory', (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-code-boundary-'));
  t.after(() => fs.rmSync(root, {recursive:true, force:true}));
  const checkoutPackage = path.join(root, 'checkout/spikes/pi-wielder');
  const installedPackage = path.join(root, 'releases/commit');
  fs.mkdirSync(checkoutPackage, {recursive:true});
  fs.mkdirSync(installedPackage, {recursive:true});
  assert.equal(codeBoundaryRoot(checkoutPackage), path.join(root, 'checkout'));
  assert.equal(codeBoundaryRoot(installedPackage), installedPackage);
});

test('installed secure storage opens sibling authority but refuses private files within its release', async (t) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-installed-storage-'));
  fs.chmodSync(root, 0o700);
  t.after(() => fs.rmSync(root, {recursive:true, force:true}));
  const release = path.join(root, 'releases/commit');
  const source = path.join(release, 'src');
  fs.mkdirSync(path.join(source, 'kernel'), {recursive:true});
  for (const moduleName of ['code-root.mjs', 'kernel/secure-storage.mjs', 'kernel/trusted-path.mjs', 'kernel/canonical.mjs']) {
    fs.copyFileSync(fileURLToPath(new URL(`../src/${moduleName}`, import.meta.url)), path.join(source, moduleName));
  }
  const storage = await import(pathToFileURL(path.join(source, 'kernel/secure-storage.mjs')));
  const authority = path.join(root, 'authority');
  fs.mkdirSync(authority, {mode:0o700});
  const pathTrust = Object.freeze({mode:'deterministic', trustedAncestor:root,
    kernelUid:process.getuid(), agentUid:process.getuid()});
  const database = path.join(authority, 'kernel.sqlite');
  assert.equal(storage.preparePrivateFile(database, 'database', {pathTrust}), database);
  assert.ok(storage.preflightSqliteFiles(database, {pathTrust}));
  const key = path.join(authority, 'key');
  const initialized = storage.loadOrInitializePrivateFile({filePath:key, label:'key', pathTrust,
    createBytes:()=>Buffer.from('synthetic'), validateBytes:bytes=>bytes.toString()});
  assert.equal(initialized, 'synthetic');
  assert.equal(storage.readPrivateInputFile(key, 'key', {pathTrust}).toString(), 'synthetic');
  const internal = path.join(release, 'private');
  fs.mkdirSync(internal, {mode:0o700});
  assert.throws(() => storage.preparePrivateFile(path.join(internal, 'key'), 'key', {pathTrust}), /outside the checkout/u);
  assert.throws(() => storage.preflightSqliteFiles(path.join(internal, 'kernel.sqlite'), {pathTrust}), /outside the checkout/u);
  assert.throws(() => storage.loadOrInitializePrivateFile({filePath:path.join(internal, 'key'), label:'key',
    pathTrust, createBytes:()=>Buffer.from('synthetic'), validateBytes:bytes=>bytes.toString()}), /outside the checkout/u);
});

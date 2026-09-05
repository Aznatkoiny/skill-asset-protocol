import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import {
  INSTALLED_CREDENTIAL_PATH,
  loadDeliveredEnvironment,
  parseDeliveredEnvironment,
  validatePid1CredentialMount,
} from '../src/runtime/secret-delivery.mjs';

const SOURCE = '/etc/wallet-kernel/kernel.env';
const SECRET = 'synthetic-credential-sentinel';
const document = () => Buffer.from([
  'WALLET_KERNEL_MODE=cdp-testnet', `WALLET_KERNEL_ENV_FILE=${SOURCE}`,
  'CDP_API_KEY_ID=synthetic-id', `CDP_API_KEY_SECRET=${SECRET}`,
  'CDP_WALLET_SECRET=synthetic-wallet', 'CDP_WALLET_NAME=pilot-wallet',
  'WALLET_KERNEL_BASE_SEPOLIA_RPC_URL=https://rpc.example/private?key=synthetic', '',
].join('\n'));

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kernel-credential-runtime-'));
  fs.chmodSync(directory, 0o700);
  const credentialFilePath = path.join(directory, 'wallet-kernel-environment');
  fs.writeFileSync(credentialFilePath, document(), {mode: 0o400});
  t.after(() => fs.rmSync(directory, {recursive:true, force:true}));
  return {credentialFilePath, environmentFilePath:SOURCE, kernelUid:process.getuid(), kernelGid:process.getgid()};
}

test('closed delivery parser preserves inert literal values and never expands a shell', () => {
  const bytes = document().toString().replace(SECRET, '${HOME};$(touch sentinel)`literal`');
  const value = parseDeliveredEnvironment(Buffer.from(bytes), SOURCE);
  assert.equal(value.CDP_API_KEY_SECRET, '${HOME};$(touch sentinel)`literal`');
  assert.equal(Object.isFrozen(value), true);
  for (const suffix of ['PRIVATE_KEY=forbidden\n', 'NODE_OPTIONS=forbidden\n',
    'CDP_API_KEY_SECRET=duplicate\n', 'export CDP_WALLET_NAME=forbidden\n',
    'WALLET_KERNEL_UNKNOWN=forbidden\n']) {
    assert.throws(() => parseDeliveredEnvironment(Buffer.concat([document(),Buffer.from(suffix)]), SOURCE));
  }
  assert.throws(() => parseDeliveredEnvironment(document(), '/wrong/source'));
  assert.throws(() => parseDeliveredEnvironment(Buffer.from('invalid\xff', 'latin1'), SOURCE));
});

test('wrong or root process identity refuses before touching delivered credentials', (t) => {
  const input = fixture(t);
  let opens = 0;
  t.mock.method(fs, 'openSync', () => {opens++; throw Error('file must not be opened');});
  assert.throws(() => loadDeliveredEnvironment({...input, kernelUid:0}), {code:'RUNTIME_KERNEL_IDENTITY'});
  assert.throws(() => loadDeliveredEnvironment({...input, kernelUid:input.kernelUid+1}), {code:'RUNTIME_KERNEL_IDENTITY'});
  assert.equal(opens, 0);
});

test('PID1 credential is read under the exact UID without reading source or changing process.env', (t) => {
  const input = fixture(t);
  // Model the already-dropped supplementary-group state. No host identity is changed.
  t.mock.method(process, 'getgroups', () => [input.kernelGid]);
  const original = fs.openSync;
  let sourceOpens = 0;
  t.mock.method(fs, 'openSync', (...args) => {
    if (args[0] === SOURCE) {sourceOpens++; throw Error('root source must stay closed');}
    return original(...args);
  });
  const before = process.env.CDP_API_KEY_SECRET;
  const value = loadDeliveredEnvironment(input);
  assert.equal(value.CDP_API_KEY_SECRET, SECRET);
  assert.equal(sourceOpens, 0);
  assert.equal(process.env.CDP_API_KEY_SECRET, before);
});

test('delivered files reject symlinks, hard links, permissions, directories and malformed contents without secret diagnostics', (t) => {
  const input = fixture(t);
  t.mock.method(process, 'getgroups', () => [input.kernelGid]);
  for (const mode of [0o644,0o440,0o200]) {
    fs.chmodSync(input.credentialFilePath, mode);
    assert.throws(() => loadDeliveredEnvironment(input), error => {
      assert.equal(error.code, 'RUNTIME_CREDENTIAL_INVALID');
      assert.equal(String(error).includes(SECRET), false); return true;
    });
  }
  fs.chmodSync(input.credentialFilePath, 0o600);
  const linked = `${input.credentialFilePath}.link`;
  fs.linkSync(input.credentialFilePath, linked);
  assert.throws(() => loadDeliveredEnvironment(input));
  fs.unlinkSync(linked);
  fs.renameSync(input.credentialFilePath, linked);
  fs.symlinkSync(linked,input.credentialFilePath);
  assert.throws(() => loadDeliveredEnvironment(input));
  fs.unlinkSync(input.credentialFilePath);
  fs.mkdirSync(input.credentialFilePath,{mode:0o700});
  assert.throws(() => loadDeliveredEnvironment(input));
});

test('an unexpected supplementary group refuses credential access', (t) => {
  const input = fixture(t);
  t.mock.method(process, 'getgroups', () => [input.kernelGid, input.kernelGid+1]);
  assert.throws(() => loadDeliveredEnvironment(input), {code:'RUNTIME_KERNEL_IDENTITY'});
});

test('PID1 ACL delivery is accepted only on its exact read-only memory mount', () => {
  const mount = '77 1 0:88 / /run/credentials/wallet-kernel.service ro,nosuid,nodev,noexec - tmpfs tmpfs rw,size=1024k\n';
  assert.equal(validatePid1CredentialMount(mount, '77', '77'), '77');
  assert.equal(validatePid1CredentialMount(mount.replace('tmpfs tmpfs', 'ramfs ramfs'), '77', '77'), '77');
  for (const altered of [mount.replace(' ro,', ' rw,'), mount.replace('tmpfs tmpfs', 'ext4 /dev/sda'),
    mount.replace('wallet-kernel.service', 'other.service'), mount + mount]) {
    assert.throws(() => validatePid1CredentialMount(altered, '77', '77'));
  }
  assert.throws(() => validatePid1CredentialMount(mount, '77', '78'));
});

test('normal root ACL delivery and chown fallback use the mount proof before reading bytes', (t) => {
  // Model kernel metadata only; this does not create a mount or claim host ACL isolation.
  const kernelUid = process.getuid();
  const kernelGid = process.getgid();
  t.mock.method(process, 'getgroups', () => [kernelGid]);
  let style = 'acl';
  let mounted = true;
  let reads = 0;
  const bytes = document();
  const paths = new Map();
  let nextFd = 30;
  t.mock.method(fs, 'openSync', (location) => {
    const match = /^\/proc\/self\/fd\/(\d+)\/(.+)$/u.exec(location);
    const resolved = match ? path.join(paths.get(Number(match[1])), match[2]) : location;
    paths.set(nextFd, resolved);
    return nextFd++;
  });
  t.mock.method(fs, 'closeSync', (fd) => paths.delete(fd));
  t.mock.method(fs, 'fstatSync', (fd) => {
    const target = paths.get(fd);
    const leaf = target === INSTALLED_CREDENTIAL_PATH;
    const privateParent = target === path.dirname(INSTALLED_CREDENTIAL_PATH);
    const owner = style === 'chown' && (leaf || privateParent) ? BigInt(kernelUid) : 0n;
    const group = style === 'chown' && (leaf || privateParent) ? BigInt(kernelGid) : 0n;
    return {uid:owner, gid:group, mode: leaf ? (style === 'acl' ? 0o440n : 0o400n)
      : privateParent ? (style === 'acl' ? 0o550n : 0o500n) : 0o755n,
      dev:1n, ino:BigInt(fd), nlink:1n, size:leaf ? BigInt(bytes.length) : 0n,
      mtimeNs:1n, ctimeNs:1n, isFile:()=>leaf, isDirectory:()=>!leaf};
  });
  t.mock.method(fs, 'readFileSync', (location) => {
    if (location === '/proc/self/mountinfo') return `77 1 0:88 / /run/credentials/wallet-kernel.service ${mounted ? 'ro' : 'rw'} - tmpfs tmpfs rw\n`;
    if (location.startsWith('/proc/self/fdinfo/')) return 'mnt_id:\t77\n';
    assert.fail('root source must never be read');
  });
  t.mock.method(fs, 'readSync', (_fd, destination, offset, length, position) => {
    reads++;
    return bytes.copy(destination, offset, position, position + length);
  });
  const input = {environmentFilePath:SOURCE, kernelUid, kernelGid};
  assert.equal(loadDeliveredEnvironment(input).CDP_API_KEY_SECRET, SECRET);
  style = 'chown';
  assert.equal(loadDeliveredEnvironment(input).CDP_API_KEY_SECRET, SECRET);
  mounted = false;
  const previousReads = reads;
  assert.throws(() => loadDeliveredEnvironment(input));
  assert.equal(reads, previousReads);
  style = 'acl';
  mounted = true;
  assert.throws(() => loadDeliveredEnvironment({...input, credentialFilePath:'/tmp/arbitrary-copy'}));
});

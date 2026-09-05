import assert from 'node:assert/strict';
import test from 'node:test';

import { validateReaderRequest } from '../scripts/prelaunch-kernel-reader.mjs';
import { REQUIRED_ISOLATION_PROBE_RESULTS } from '../src/agent/isolation-preflight.mjs';

const binding = Object.freeze({ nonce: 'reader-nonce', parentPid: 7, uid: 501, gid: 20 });
const hash = `sha256:${'1'.repeat(64)}`;

function request(probeResults = { ...REQUIRED_ISOLATION_PROBE_RESULTS }) {
  return {
    nonce: binding.nonce, parentPid: binding.parentPid,
    kernelUid: String(binding.uid), kernelGid: String(binding.gid),
    releaseRoot: '/opt/wallet/releases/current', releaseManifestHash: hash,
    authorityMetadataHash: hash, credentialMetadataHash: hash, probeResults,
    databasePath: '/opt/wallet/authority/kernel.sqlite',
    pathTrust: { mode: 'cdp-testnet', trustedAncestor: '/opt/wallet', kernelUid: 501, agentUid: 502 },
    isolationReportPath: '/opt/wallet/authority/isolation.json',
    now: '2026-09-05T12:00:00.000Z',
  };
}

test('reader accepts the complete shared isolation-result contract without secret payloads', () => {
  const value = request();
  assert.equal(validateReaderRequest(value, binding), value);
  assert.deepEqual(value.probeResults, REQUIRED_ISOLATION_PROBE_RESULTS);
});

test('reader inspection requires no credential metadata or fabricated probe results', () => {
  const value = { ...request(null), phase: 'inspect', credentialMetadataHash: null };
  assert.equal(validateReaderRequest(value, binding), value);
  for (const overrides of [
    { probeResults: { ...REQUIRED_ISOLATION_PROBE_RESULTS } },
    { probeResults: {} }, { credentialMetadataHash: hash },
    { credentialMetadataHash: '' },
  ]) {
    assert.throws(() => validateReaderRequest({ ...value, ...overrides }, binding), /inspection/);
  }
});

test('reader audit requires a current credential hash and an exact probe map', () => {
  const value = { ...request(), phase: 'audit' };
  assert.equal(validateReaderRequest(value, binding), value);
  for (const credentialMetadataHash of [null, '', 'sha256:old', true]) {
    assert.throws(() => validateReaderRequest({ ...value, credentialMetadataHash }, binding), /credential/);
  }
  const missing = { ...value };
  delete missing.credentialMetadataHash;
  assert.throws(() => validateReaderRequest(missing, binding), /fields/);
  assert.throws(() => validateReaderRequest({ ...value, probeResults: null }, binding), /probe results/);
  for (const phase of ['unknown', '', null, undefined]) {
    assert.throws(() => validateReaderRequest({ ...value, phase }, binding), /phase/);
  }
});

test('reader rejects missing, excess, nested, and symbol probe data', () => {
  const missing = { ...REQUIRED_ISOLATION_PROBE_RESULTS };
  delete missing.database;
  for (const probeResults of [
    {}, missing,
    { ...REQUIRED_ISOLATION_PROBE_RESULTS, diagnostic: 'extra' },
    { ...REQUIRED_ISOLATION_PROBE_RESULTS, receiptKeyPath: '/private/secret' },
    { ...REQUIRED_ISOLATION_PROBE_RESULTS, database: { result: 'EACCES' } },
    { ...REQUIRED_ISOLATION_PROBE_RESULTS, [Symbol('extra')]: 'extra' },
  ]) {
    assert.throws(() => validateReaderRequest(request(probeResults), binding), /probe results/);
  }
});

test('reader accepts only each probe label\'s exact required result', () => {
  for (const [field, expected] of Object.entries(REQUIRED_ISOLATION_PROBE_RESULTS)) {
    for (const result of [expected === 'EACCES' ? 'READABLE' : 'EACCES', 'EPERM', true, null]) {
      assert.throws(() => validateReaderRequest(request({
        ...REQUIRED_ISOLATION_PROBE_RESULTS, [field]: result,
      }), binding), /probe results/);
    }
  }
});

test('reader rejects non-data probe maps without invoking accessors or proxy traps', () => {
  let reads = 0;
  const accessor = { ...REQUIRED_ISOLATION_PROBE_RESULTS };
  Object.defineProperty(accessor, 'database', {
    enumerable: true, get() { reads += 1; return 'EACCES'; },
  });
  const proxy = new Proxy({ ...REQUIRED_ISOLATION_PROBE_RESULTS }, {
    getPrototypeOf() { reads += 1; return Object.prototype; },
  });
  const hidden = { ...REQUIRED_ISOLATION_PROBE_RESULTS };
  Object.defineProperty(hidden, 'database', { enumerable: false, value: 'EACCES' });
  for (const probeResults of [
    accessor, proxy, hidden, [], Object.create(REQUIRED_ISOLATION_PROBE_RESULTS),
  ]) {
    assert.throws(() => validateReaderRequest(request(probeResults), binding), /probe results/);
  }
  assert.equal(reads, 0);
});
